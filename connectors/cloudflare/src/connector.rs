//! Cloudflare connector implementation.

use std::sync::OnceLock;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcp_manifest::{ConnectorManifest, ManifestApprovalMode, OperationSection};
use fcp_prelude::{
    ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier, ConnectorId,
    ConnectorMetrics, EventCaps, FcpConnector, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, HealthSnapshot, Introspection, InvokeRequest, InvokeResponse, OperationId,
    OperationInfo, SelfCheckReport, SessionId, ShutdownRequest, SimulateRequest, SimulateResponse,
    SubscribeRequest, SubscribeResponse, UnsubscribeRequest,
};
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::Url;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::info;

use crate::client::CloudflareClient;
use crate::types::{CloudflareAuth, CreateDnsRecord, UpdateDnsRecord};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/cloudflare_connector_verification.sh";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/cloudflare_connector/<timestamp>";
const CLOUDFLARE_ALLOWED_HOSTS: &[&str] = &["api.cloudflare.com"];

const OP_ZONES_LIST: &str = "cloudflare.zones.list";
const OP_HEALTH: &str = "cloudflare.health";
const OP_DNS_LIST: &str = "cloudflare.dns.list_records";
const OP_DNS_CREATE: &str = "cloudflare.dns.create_record";
const OP_DNS_UPDATE: &str = "cloudflare.dns.update_record";
const OP_DNS_DELETE: &str = "cloudflare.dns.delete_record";
const OP_WORKERS_LIST: &str = "cloudflare.workers.list";
const OP_WORKERS_GET: &str = "cloudflare.workers.get";
const OP_WORKERS_DEPLOY: &str = "cloudflare.workers.deploy";
const OP_WORKERS_DELETE: &str = "cloudflare.workers.delete";
const OP_PAGES_LIST: &str = "cloudflare.pages.list_projects";
const OP_PAGES_DEPLOY: &str = "cloudflare.pages.create_deployment";
const OP_KV_GET: &str = "cloudflare.kv.get";
const OP_KV_PUT: &str = "cloudflare.kv.put";
const OP_KV_DELETE: &str = "cloudflare.kv.delete";
const OPERATION_ORDER: [&str; 15] = [
    OP_ZONES_LIST,
    OP_HEALTH,
    OP_DNS_LIST,
    OP_DNS_CREATE,
    OP_DNS_UPDATE,
    OP_DNS_DELETE,
    OP_WORKERS_LIST,
    OP_WORKERS_GET,
    OP_WORKERS_DEPLOY,
    OP_WORKERS_DELETE,
    OP_PAGES_LIST,
    OP_PAGES_DEPLOY,
    OP_KV_GET,
    OP_KV_PUT,
    OP_KV_DELETE,
];

const CAP_ZONES_READ: &str = "cloudflare.zones.read";
const CAP_DNS_READ: &str = "cloudflare.dns.read";
const CAP_DNS_WRITE: &str = "cloudflare.dns.write";
const CAP_WORKERS_READ: &str = "cloudflare.workers.read";
const CAP_WORKERS_WRITE: &str = "cloudflare.workers.write";
const CAP_PAGES_READ: &str = "cloudflare.pages.read";
const CAP_PAGES_WRITE: &str = "cloudflare.pages.write";
const CAP_KV_READ: &str = "cloudflare.kv.read";
const CAP_KV_WRITE: &str = "cloudflare.kv.write";

#[derive(Clone, serde::Deserialize)]
pub struct CloudflareConfig {
    #[serde(default = "default_base_url")]
    pub base_url: String,
    pub account_id: String,
    #[serde(flatten)]
    pub auth: CloudflareAuth,
    #[serde(default)]
    pub retry: HttpRetryConfig,
    #[serde(default = "default_timeout_ms")]
    pub request_timeout_ms: u64,
}
fn default_base_url() -> String {
    "https://api.cloudflare.com/client/v4".into()
}
const fn default_timeout_ms() -> u64 {
    30_000
}

impl std::fmt::Debug for CloudflareConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareConfig")
            .field("base_url", &self.base_url)
            .field("account_id", &self.account_id)
            .field("auth", &self.auth)
            .finish()
    }
}

impl CloudflareConfig {
    fn validate(&self) -> Result<(), String> {
        if self.account_id.is_empty() {
            return Err("account_id is required".into());
        }
        if self.base_url.is_empty() {
            return Err("base_url cannot be empty".into());
        }
        if self.request_timeout_ms == 0 {
            return Err("request_timeout_ms must be greater than zero".into());
        }
        let (network_ok, network_message) = base_url_policy(&self.base_url);
        if !network_ok {
            return Err(network_message);
        }
        match &self.auth {
            CloudflareAuth::ApiKey { api_key, email }
                if !api_key.trim().is_empty() && email.trim().is_empty() =>
            {
                return Err(
                    "email is required when using api_key mode with configured key material".into(),
                );
            }
            _ => {}
        }
        Ok(())
    }

    fn from_value(val: serde_json::Value) -> FcpResult<Self> {
        let mut config: Self =
            serde_json::from_value(val).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid configuration: {e}"),
            })?;
        config.base_url = config.base_url.trim().to_string();
        config.account_id = config.account_id.trim().to_string();
        match &mut config.auth {
            CloudflareAuth::ApiToken {
                api_token: token_material,
            } => {
                *token_material = token_material.trim().to_string();
            }
            CloudflareAuth::ApiKey {
                api_key: key_material,
                email,
            } => {
                *key_material = key_material.trim().to_string();
                *email = email.trim().to_string();
            }
        }
        config.validate().map_err(|e| FcpError::InvalidRequest {
            code: 1001,
            message: e,
        })?;
        Ok(config)
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let (network_ok, network_message) = base_url_policy(&self.base_url);

        ProvisioningReadiness {
            auth_mode: self.auth.auth_mode(),
            flags: ReadinessFlags {
                uses_legacy_global_key: self.auth.is_legacy_global_key(),
                secret_material_configured: !self.auth.is_secretless(),
                requires_credential_injection: self.auth.is_secretless(),
                account_id_configured: !self.account_id.trim().is_empty(),
                network_ok,
            },
            network_message,
            base_url: self.base_url.clone(),
            allowed_hosts: CLOUDFLARE_ALLOWED_HOSTS.to_vec(),
            account_scope_hint: "Workers, Pages, and KV calls must target the same Cloudflare account_id used during configure.",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct ProvisioningReadiness {
    auth_mode: &'static str,
    flags: ReadinessFlags,
    network_message: String,
    base_url: String,
    allowed_hosts: Vec<&'static str>,
    account_scope_hint: &'static str,
}

/// Boolean readiness flags bundled for the provisioning report.
#[derive(Debug, Clone, Serialize)]
struct ReadinessFlags {
    uses_legacy_global_key: bool,
    secret_material_configured: bool,
    requires_credential_injection: bool,
    account_id_configured: bool,
    network_ok: bool,
}

#[derive(Debug, Clone, Serialize)]
struct OperatorGuidance {
    prerequisites: Vec<&'static str>,
    dedicated_environment: &'static str,
    redaction_rules: Vec<&'static str>,
    common_remediation: Vec<RemediationHint>,
    rerun_commands: Vec<&'static str>,
    artifact_root_hint: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct RemediationHint {
    code: &'static str,
    symptom: &'static str,
    action: &'static str,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DoctorStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorResult {
    pub ready: bool,
    pub status: DoctorStatus,
    pub checks: Vec<DoctorCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provisioning: Option<ProvisioningReadiness>,
    operator_guidance: OperatorGuidance,
}

#[derive(Debug, Clone, Serialize)]
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
        let status = if checks.iter().any(|check| check.critical && !check.passed) {
            DoctorStatus::Unhealthy
        } else if checks.iter().any(|check| !check.passed) {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };
        Self {
            ready,
            status,
            checks,
            provisioning,
            operator_guidance: operator_guidance(),
        }
    }

    const fn status_label(&self) -> &'static str {
        match self.status {
            DoctorStatus::Healthy => "healthy",
            DoctorStatus::Degraded => "degraded",
            DoctorStatus::Unhealthy => "unhealthy",
        }
    }
}

fn is_local_test_host(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host.ends_with(".localhost")
}

fn base_url_policy(base_url: &str) -> (bool, String) {
    let parsed = match Url::parse(base_url) {
        Ok(url) => url,
        Err(error) => return (false, format!("base_url must be an absolute URL: {error}")),
    };

    let Some(host) = parsed.host_str() else {
        return (false, "base_url must include a host".into());
    };

    if is_local_test_host(host) {
        return (
            true,
            format!("localhost test endpoint accepted for verification: {base_url}"),
        );
    }

    let mut problems = Vec::new();
    if parsed.scheme() != "https" {
        problems.push(format!("scheme must be https, got {}", parsed.scheme()));
    }
    if !CLOUDFLARE_ALLOWED_HOSTS.contains(&host) {
        problems.push(format!(
            "host must be one of {CLOUDFLARE_ALLOWED_HOSTS:?}, got {host}"
        ));
    }
    if !parsed.path().starts_with("/client/v4") {
        problems.push(format!(
            "path should start with /client/v4, got {}",
            parsed.path()
        ));
    }

    if problems.is_empty() {
        (true, "Cloudflare production API endpoint accepted".into())
    } else {
        (false, problems.join("; "))
    }
}

fn operator_guidance() -> OperatorGuidance {
    OperatorGuidance {
        prerequisites: vec![
            "Create a disposable Cloudflare account or staging account for verification.",
            "Use a non-production zone, Pages project, Workers script name, and KV namespace for mutation tests.",
            "Provision a scoped API token with only the services you intend to exercise; avoid the legacy global API key unless required.",
        ],
        dedicated_environment: "Use a staging-only Cloudflare account_id and zone. DNS delete, Workers delete, and KV delete operations are dangerous and should never target production during verification.",
        redaction_rules: vec![
            "Never log api_token or api_key values.",
            "Treat X-Auth-Email plus X-Auth-Key as sensitive when paired; avoid printing both together in diagnostics.",
            "Do not paste real zone IDs, account IDs, or Pages deployment URLs from private environments into shared transcripts unless they are already public.",
        ],
        common_remediation: vec![
            RemediationHint {
                code: "token_scope_invalid",
                symptom: "self_check returns token_inactive or invoke returns 401/403",
                action: "Create a scoped API token for the required services and rerun self_check. Zone reads need Zone:Read; DNS mutations need DNS:Edit; Workers/Pages/KV mutations need the corresponding account-level edit scopes.",
            },
            RemediationHint {
                code: "account_scope_mismatch",
                symptom: "Workers, Pages, or KV calls return 403/404 while zone reads succeed",
                action: "Verify account_id points at the account that owns the Workers, Pages, and KV resources. Zone IDs alone are not sufficient for account-scoped endpoints.",
            },
            RemediationHint {
                code: "network_constraints_invalid",
                symptom: "doctor/self_check reports invalid network policy",
                action: "Use https://api.cloudflare.com/client/v4 in production or a localhost-only mock endpoint during verification. Do not point the connector at arbitrary external hosts.",
            },
            RemediationHint {
                code: "credential_injection_required",
                symptom: "auth mode is configured but secret material is intentionally omitted",
                action: "Inject Authorization or X-Auth-* headers at runtime via the host/egress proxy, then rerun self_check before invoking mutation operations.",
            },
            RemediationHint {
                code: "zone_or_record_not_found",
                symptom: "DNS mutation returns resource not found",
                action: "Run cloudflare.zones.list first, then cloudflare.dns.list_records for the target zone to confirm zone_id and record_id before retrying a mutation.",
            },
        ],
        rerun_commands: vec![
            "scripts/e2e/cloudflare_connector_verification.sh",
            "rch exec -- cargo run -p fwc -- manifest fix connectors/cloudflare/manifest.toml --check --json",
            "rch exec -- cargo test -p fcp-cloudflare --test integration -- --nocapture",
            "rch exec -- cargo clippy -p fcp-cloudflare --all-targets -- -D warnings",
        ],
        artifact_root_hint: ARTIFACT_ROOT_HINT,
    }
}

#[derive(Debug)]
pub struct CloudflareConnector {
    base: BaseConnector,
    config: Option<CloudflareConfig>,
    client: Option<CloudflareClient>,
    runtime: Option<ConnectorRuntime>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl CloudflareConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.cloudflare")),
            config: None,
            client: None,
            runtime: None,
            started_at: Instant::now(),
            verifier: None,
        }
    }

    /// Stable connector instance identity used for bound capability-token verification.
    #[must_use]
    pub fn instance_id(&self) -> &fcp_prelude::InstanceId {
        &self.base.instance_id
    }

    fn manifest_hash() -> String {
        let mut h = Sha256::new();
        h.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(h.finalize()))
    }

    pub fn doctor(&self) -> DoctorResult {
        let provisioning = self
            .config
            .as_ref()
            .map(CloudflareConfig::provisioning_readiness);
        let mut checks = Vec::new();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: if self.config.is_some() {
                None
            } else {
                Some("Not configured; run configure before handshake or invoke".into())
            },
            critical: true,
        });
        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            passed: self.client.is_some(),
            message: if self.client.is_some() {
                None
            } else {
                Some("HTTP client not initialized; re-run configure".into())
            },
            critical: true,
        });
        checks.push(DoctorCheck {
            name: "runtime_initialized".into(),
            passed: self.runtime.is_some(),
            message: if self.runtime.is_some() {
                None
            } else {
                Some("ConnectorRuntime not initialized; re-run configure".into())
            },
            critical: true,
        });
        if let Some(readiness) = &provisioning {
            checks.push(DoctorCheck {
                name: "network_constraints".into(),
                passed: readiness.flags.network_ok,
                message: Some(readiness.network_message.clone()),
                critical: true,
            });
            checks.push(DoctorCheck {
                name: "account_id".into(),
                passed: readiness.flags.account_id_configured,
                message: Some(if readiness.flags.account_id_configured {
                    "Cloudflare account_id configured".into()
                } else {
                    "account_id missing; Workers, Pages, and KV cannot resolve account-scoped endpoints".into()
                }),
                critical: true,
            });
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                passed: true,
                message: Some(format!("Auth mode: {}", readiness.auth_mode)),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "secret_material".into(),
                passed: readiness.flags.secret_material_configured,
                message: Some(if readiness.flags.secret_material_configured {
                    "Credential material configured directly".into()
                } else {
                    "Secret material omitted; host or egress proxy must inject headers at runtime"
                        .into()
                }),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "recommended_auth".into(),
                passed: !readiness.flags.uses_legacy_global_key,
                message: Some(if readiness.flags.uses_legacy_global_key {
                    "Global API key is legacy and broad; prefer scoped API tokens for operator verification".into()
                } else {
                    "Scoped API token mode configured".into()
                }),
                critical: false,
            });
        }
        let result = DoctorResult::from_checks(checks, provisioning);
        let failed_checks = result.checks.iter().filter(|check| !check.passed).count();
        info!(
            event = "cloudflare.provisioning.doctor",
            status = result.status_label(),
            check_count = result.checks.len(),
            failed_checks,
            "Cloudflare doctor checks completed"
        );
        result
    }

    fn attach_self_check_details(
        mut report: SelfCheckReport,
        provisioning: Option<&ProvisioningReadiness>,
    ) -> SelfCheckReport {
        report.details = Some(json!({
            "provisioning": provisioning,
            "operator_guidance": operator_guidance(),
            "manifest_hash": Self::manifest_hash(),
            "verification_script": VERIFICATION_SCRIPT_PATH,
            "artifact_root_hint": ARTIFACT_ROOT_HINT,
        }));
        report
    }

    fn require_str<'a>(input: &'a serde_json::Value, key: &str) -> FcpResult<&'a str> {
        let value =
            input
                .get(key)
                .and_then(|v| v.as_str())
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1005,
                    message: format!("Missing: {key}"),
                })?;
        if value.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: format!("Field '{key}' must not be empty"),
            });
        }
        Ok(value)
    }

    fn optional_bool(input: &serde_json::Value, key: &str) -> FcpResult<Option<bool>> {
        input.get(key).map_or(Ok(None), |value| {
            value
                .as_bool()
                .map(Some)
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1005,
                    message: format!("Field '{key}' must be a boolean"),
                })
        })
    }

    fn optional_u32(input: &serde_json::Value, key: &str) -> FcpResult<Option<u32>> {
        match input.get(key) {
            None => Ok(None),
            Some(serde_json::Value::Number(number)) => {
                let raw = number.as_u64().ok_or_else(|| FcpError::InvalidRequest {
                    code: 1005,
                    message: format!("Field '{key}' must be a non-negative integer"),
                })?;
                let parsed = u32::try_from(raw).map_err(|_| FcpError::InvalidRequest {
                    code: 1005,
                    message: format!("Field '{key}' must fit within u32"),
                })?;
                Ok(Some(parsed))
            }
            Some(_) => Err(FcpError::InvalidRequest {
                code: 1005,
                message: format!("Field '{key}' must be a non-negative integer"),
            }),
        }
    }

    fn optional_u16(input: &serde_json::Value, key: &str) -> FcpResult<Option<u16>> {
        match input.get(key) {
            None => Ok(None),
            Some(serde_json::Value::Number(number)) => {
                let raw = number.as_u64().ok_or_else(|| FcpError::InvalidRequest {
                    code: 1005,
                    message: format!("Field '{key}' must be a non-negative integer"),
                })?;
                let parsed = u16::try_from(raw).map_err(|_| FcpError::InvalidRequest {
                    code: 1005,
                    message: format!("Field '{key}' must fit within u16"),
                })?;
                Ok(Some(parsed))
            }
            Some(_) => Err(FcpError::InvalidRequest {
                code: 1005,
                message: format!("Field '{key}' must be a non-negative integer"),
            }),
        }
    }

    fn optional_string(input: &serde_json::Value, key: &str) -> FcpResult<Option<String>> {
        match input.get(key) {
            None => Ok(None),
            Some(serde_json::Value::String(value)) => {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(trimmed.to_string()))
                }
            }
            Some(_) => Err(FcpError::InvalidRequest {
                code: 1005,
                message: format!("Field '{key}' must be a string"),
            }),
        }
    }
}

impl Default for CloudflareConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn typed_operations_info() -> Vec<OperationInfo> {
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
        .expect("embedded Cloudflare manifest should validate");
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

fcp_core::impl_fcp_sealed!(CloudflareConnector);

#[async_trait]
impl FcpConnector for CloudflareConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let cf = CloudflareConfig::from_value(config)?;
        let provisioning = cf.provisioning_readiness();
        let timeout = Duration::from_millis(cf.request_timeout_ms);
        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default().with_request_timeout(timeout),
        ));
        let client = CloudflareClient::new(
            &cf.base_url,
            cf.auth.clone(),
            &cf.account_id,
            cf.retry.clone(),
            timeout,
        )
        .map_err(|e| FcpError::Internal {
            message: format!("Client init: {e}"),
        })?;
        self.client = Some(client);
        self.config = Some(cf);
        self.verifier = None;
        self.base.set_configured(true);
        self.base.set_handshaken(false);
        info!(
            event = "cloudflare.provisioning.configure",
            auth_mode = provisioning.auth_mode,
            auth_label = self
                .config
                .as_ref()
                .map_or("unknown", |cfg| cfg.auth.redacted_label()),
            network_ok = provisioning.flags.network_ok,
            requires_credential_injection = provisioning.flags.requires_credential_injection,
            uses_legacy_global_key = provisioning.flags.uses_legacy_global_key,
            base_url = %provisioning.base_url,
            "Configured Cloudflare connector"
        );
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        self.base.set_handshaken(true);
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));
        let caps = req
            .capabilities_requested
            .into_iter()
            .map(|c| CapabilityGrant {
                capability: c,
                operation: None,
            })
            .collect();
        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted: caps,
            session_id: SessionId::new(),
            manifest_hash: Self::manifest_hash(),
            nonce: req.nonce,
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
            .map(CloudflareConfig::provisioning_readiness);
        let mut snap = match &provisioning {
            Some(readiness) if !readiness.flags.network_ok => {
                HealthSnapshot::error("network constraints invalid")
            }
            Some(readiness) if readiness.flags.requires_credential_injection => {
                HealthSnapshot::degraded("credential injection required")
            }
            Some(_) => HealthSnapshot::ready(),
            None => HealthSnapshot::degraded("not configured"),
        };
        snap.uptime_ms = u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        snap.details = Some(json!({
            "configured": self.config.is_some(),
            "handshaken": self.base.handshaken.load(Ordering::Acquire),
            "provisioning": provisioning,
            "operator_guidance": operator_guidance(),
            "manifest_hash": Self::manifest_hash(),
            "verification_script": VERIFICATION_SCRIPT_PATH,
        }));
        snap
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(config) = &self.config else {
            return Ok(Self::attach_self_check_details(
                SelfCheckReport::degraded("not_configured", "Connector is not configured"),
                None,
            ));
        };
        let provisioning = config.provisioning_readiness();

        if !provisioning.flags.network_ok {
            return Ok(Self::attach_self_check_details(
                SelfCheckReport::failed(
                    "network_constraints_invalid",
                    provisioning.network_message.clone(),
                ),
                Some(&provisioning),
            ));
        }

        let Some(client) = &self.client else {
            return Ok(Self::attach_self_check_details(
                SelfCheckReport::failed(
                    "client_missing",
                    "Cloudflare HTTP client not initialized; re-run configure",
                ),
                Some(&provisioning),
            ));
        };
        let Some(runtime) = &self.runtime else {
            return Ok(Self::attach_self_check_details(
                SelfCheckReport::failed(
                    "runtime_missing",
                    "ConnectorRuntime not initialized; re-run configure",
                ),
                Some(&provisioning),
            ));
        };

        if provisioning.flags.requires_credential_injection {
            return Ok(Self::attach_self_check_details(
                SelfCheckReport::degraded(
                    "credential_injection_required",
                    "Credential material is intentionally omitted; inject Authorization or X-Auth-* headers at runtime before re-running self_check",
                ),
                Some(&provisioning),
            ));
        }

        let report = match client.health_check(runtime).await {
            Ok(v) if v.status == "active" => SelfCheckReport::ok(),
            Ok(v) => SelfCheckReport::degraded(
                "token_inactive",
                format!(
                    "Cloudflare token status is '{}' - verify token scope and account binding",
                    v.status
                ),
            ),
            Err(error) if error.is_retryable() => {
                SelfCheckReport::degraded("self_check_retryable", error.to_string())
            }
            Err(error) => SelfCheckReport::failed("self_check_failed", error.to_string()),
        };
        let report = Self::attach_self_check_details(report, Some(&provisioning));
        info!(
            event = "cloudflare.provisioning.self_check",
            status = ?report.status,
            reason_code = report.reason_code.as_deref().unwrap_or("ok"),
            "Cloudflare self_check completed"
        );
        Ok(report)
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        Ok(SimulateResponse::allowed(req.id))
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        if let Some(runtime) = &self.runtime {
            runtime.shutdown();
        }
        self.runtime = None;
        self.client = None;
        self.config = None;
        self.verifier = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: typed_operations_info(),
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

    async fn subscribe(&self, _req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }
    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Err(FcpError::StreamingNotSupported)
    }
}

impl CloudflareConnector {
    #[allow(clippy::too_many_lines)]
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();
        if let Some(verifier) = &self.verifier {
            let cap = match operation {
                OP_ZONES_LIST | OP_HEALTH => CapabilityId::from_static(CAP_ZONES_READ),
                OP_DNS_LIST => CapabilityId::from_static(CAP_DNS_READ),
                OP_DNS_CREATE | OP_DNS_UPDATE | OP_DNS_DELETE => {
                    CapabilityId::from_static(CAP_DNS_WRITE)
                }
                OP_WORKERS_LIST | OP_WORKERS_GET => CapabilityId::from_static(CAP_WORKERS_READ),
                OP_WORKERS_DEPLOY | OP_WORKERS_DELETE => {
                    CapabilityId::from_static(CAP_WORKERS_WRITE)
                }
                OP_PAGES_LIST => CapabilityId::from_static(CAP_PAGES_READ),
                OP_PAGES_DEPLOY => CapabilityId::from_static(CAP_PAGES_WRITE),
                OP_KV_GET => CapabilityId::from_static(CAP_KV_READ),
                OP_KV_PUT | OP_KV_DELETE => CapabilityId::from_static(CAP_KV_WRITE),
                _ => {
                    return Err(FcpError::InvalidRequest {
                        code: 1004,
                        message: format!("Unknown operation: {operation}"),
                    });
                }
            };
            let configured_account_id = self
                .config
                .as_ref()
                .map(|config| config.account_id.as_str())
                .unwrap_or_default();
            let resource_uris =
                resource_uris_for_operation(operation, &req.input, configured_account_id)?;
            verifier.verify_bound(req.capability_token, &cap, &req.operation, &resource_uris)?;
        } else {
            return Err(FcpError::Internal {
                message: "connector ready state missing capability verifier".into(),
            });
        }

        let runtime = self.runtime.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing runtime".into(),
        })?;
        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing Cloudflare client".into(),
        })?;

        let output = match operation {
            OP_ZONES_LIST => {
                let z = client
                    .list_zones(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&z).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_HEALTH => {
                let i = client
                    .health_check(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({"status": i.status, "token_id": i.id, "healthy": i.status == "active"})
            }
            OP_DNS_LIST => {
                let zid = Self::require_str(&req.input, "zone_id")?;
                let r = client
                    .list_dns_records(runtime, zid)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&r).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_DNS_CREATE => {
                let zid = Self::require_str(&req.input, "zone_id")?;
                let rec = CreateDnsRecord {
                    record_type: Self::require_str(&req.input, "type")?.into(),
                    name: Self::require_str(&req.input, "name")?.into(),
                    content: Self::require_str(&req.input, "content")?.into(),
                    proxied: Self::optional_bool(&req.input, "proxied")?,
                    ttl: Self::optional_u32(&req.input, "ttl")?,
                    priority: Self::optional_u16(&req.input, "priority")?,
                    comment: Self::optional_string(&req.input, "comment")?,
                };
                let r = client
                    .create_dns_record(runtime, zid, &rec)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&r).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_DNS_UPDATE => {
                let zid = Self::require_str(&req.input, "zone_id")?;
                let rid = Self::require_str(&req.input, "record_id")?;
                let rec = UpdateDnsRecord {
                    record_type: Self::require_str(&req.input, "type")?.into(),
                    name: Self::require_str(&req.input, "name")?.into(),
                    content: Self::require_str(&req.input, "content")?.into(),
                    proxied: Self::optional_bool(&req.input, "proxied")?,
                    ttl: Self::optional_u32(&req.input, "ttl")?,
                    comment: Self::optional_string(&req.input, "comment")?,
                };
                let r = client
                    .update_dns_record(runtime, zid, rid, &rec)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&r).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_DNS_DELETE => {
                let zid = Self::require_str(&req.input, "zone_id")?;
                let rid = Self::require_str(&req.input, "record_id")?;
                client
                    .delete_dns_record(runtime, zid, rid)
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_WORKERS_LIST => {
                let w = client
                    .list_workers(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&w).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_WORKERS_GET => {
                let n = Self::require_str(&req.input, "script_name")?;
                let w = client
                    .get_worker(runtime, n)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&w).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_WORKERS_DEPLOY => {
                let n = Self::require_str(&req.input, "script_name")?;
                let c = Self::require_str(&req.input, "script_content")?;
                let r = client
                    .deploy_worker(runtime, n, c)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&r).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_WORKERS_DELETE => {
                let n = Self::require_str(&req.input, "script_name")?;
                client
                    .delete_worker(runtime, n)
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_PAGES_LIST => {
                let p = client
                    .list_pages_projects(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&p).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_PAGES_DEPLOY => {
                let p = Self::require_str(&req.input, "project_name")?;
                let b = Self::require_str(&req.input, "branch")?;
                let r = client
                    .create_pages_deployment(runtime, p, b)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&r).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_KV_GET => {
                let ns = Self::require_str(&req.input, "namespace_id")?;
                let k = Self::require_str(&req.input, "key")?;
                let v = client
                    .kv_get(runtime, ns, k)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({"value": v})
            }
            OP_KV_PUT => {
                let ns = Self::require_str(&req.input, "namespace_id")?;
                let k = Self::require_str(&req.input, "key")?;
                let v = Self::require_str(&req.input, "value")?;
                client
                    .kv_put(runtime, ns, k, v)
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_KV_DELETE => {
                let ns = Self::require_str(&req.input, "namespace_id")?;
                let k = Self::require_str(&req.input, "key")?;
                client
                    .kv_delete(runtime, ns, k)
                    .await
                    .map_err(|e| e.to_fcp_error())?
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

fn resource_uris_for_operation(
    operation: &str,
    input: &serde_json::Value,
    configured_account_id: &str,
) -> FcpResult<Vec<String>> {
    let account_id = (!configured_account_id.trim().is_empty()).then_some(configured_account_id);
    let account_prefix = |account: &str| format!("cloudflare://accounts/{account}");

    let uris = match operation {
        OP_ZONES_LIST | OP_HEALTH => Vec::new(),
        OP_DNS_LIST => {
            let zone_id = CloudflareConnector::require_str(input, "zone_id")?;
            vec![format!("cloudflare://zones/{zone_id}/dns_records")]
        }
        OP_DNS_CREATE => {
            let zone_id = CloudflareConnector::require_str(input, "zone_id")?;
            let name = CloudflareConnector::require_str(input, "name")?;
            vec![format!("cloudflare://zones/{zone_id}/dns_records/{name}")]
        }
        OP_DNS_UPDATE | OP_DNS_DELETE => {
            let zone_id = CloudflareConnector::require_str(input, "zone_id")?;
            let record_id = CloudflareConnector::require_str(input, "record_id")?;
            vec![format!(
                "cloudflare://zones/{zone_id}/dns_records/{record_id}"
            )]
        }
        OP_WORKERS_LIST => account_id
            .map(|account| vec![format!("{}/workers/scripts", account_prefix(account))])
            .unwrap_or_default(),
        OP_WORKERS_GET | OP_WORKERS_DELETE | OP_WORKERS_DEPLOY => {
            let script_name = CloudflareConnector::require_str(input, "script_name")?;
            account_id
                .map(|account| {
                    vec![format!(
                        "{}/workers/scripts/{script_name}",
                        account_prefix(account)
                    )]
                })
                .unwrap_or_default()
        }
        OP_PAGES_LIST => account_id
            .map(|account| vec![format!("{}/pages/projects", account_prefix(account))])
            .unwrap_or_default(),
        OP_PAGES_DEPLOY => {
            let project_name = CloudflareConnector::require_str(input, "project_name")?;
            account_id
                .map(|account| {
                    vec![format!(
                        "{}/pages/projects/{project_name}/deployments",
                        account_prefix(account)
                    )]
                })
                .unwrap_or_default()
        }
        OP_KV_GET | OP_KV_PUT | OP_KV_DELETE => {
            let namespace_id = CloudflareConnector::require_str(input, "namespace_id")?;
            let key = CloudflareConnector::require_str(input, "key")?;
            account_id
                .map(|account| {
                    vec![format!(
                        "{}/kv/namespaces/{namespace_id}/values/{key}",
                        account_prefix(account)
                    )]
                })
                .unwrap_or_default()
        }
        _ => Vec::new(),
    };

    Ok(uris)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration as ChronoDuration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_manifest::ConnectorManifest;
    use fcp_prelude::{CapabilityConstraints, CapabilityToken, RequestId, SafetyTier, ZoneId};

    fn tc() -> serde_json::Value {
        json!({"mode": "api_token", "api_token": "t", "account_id": "a"})
    }

    fn handshake_req(host_public_key: [u8; 32]) -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key,
            nonce: [0u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_ZONES_READ),
                CapabilityId::from_static(CAP_DNS_READ),
                CapabilityId::from_static(CAP_DNS_WRITE),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        }
    }

    fn capability_for_operation(op: &'static str) -> &'static str {
        match op {
            OP_DNS_LIST => CAP_DNS_READ,
            OP_DNS_CREATE | OP_DNS_UPDATE | OP_DNS_DELETE => CAP_DNS_WRITE,
            OP_WORKERS_LIST | OP_WORKERS_GET => CAP_WORKERS_READ,
            OP_WORKERS_DEPLOY | OP_WORKERS_DELETE => CAP_WORKERS_WRITE,
            OP_PAGES_LIST => CAP_PAGES_READ,
            OP_PAGES_DEPLOY => CAP_PAGES_WRITE,
            OP_KV_GET => CAP_KV_READ,
            OP_KV_PUT | OP_KV_DELETE => CAP_KV_WRITE,
            _ => CAP_ZONES_READ,
        }
    }

    fn signed_capability_token(
        signing_key: &Ed25519SigningKey,
        instance_id: &str,
        op: &'static str,
    ) -> CapabilityToken {
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
        let now = Utc::now();
        let raw = CapabilityTokenBuilder::new()
            .capability_id(capability_for_operation(op))
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[op])
            .issuer("node:test")
            .target_instance(instance_id)
            .validity(now, now + ChronoDuration::hours(1))
            .try_constraints_cbor(&cbor)
            .expect("constraints CBOR should validate")
            .sign(signing_key)
            .expect("capability token should sign");
        CapabilityToken::from_raw(raw)
    }

    fn invoke_req(
        op: &'static str,
        input: serde_json::Value,
        capability_token: CapabilityToken,
    ) -> InvokeRequest {
        InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("r1"),
            connector_id: ConnectorId::from_static("fcp.cloudflare"),
            operation: OperationId::from_static(op),
            zone_id: ZoneId::work(),
            input,
            capability_token,
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: vec![],
        }
    }

    #[test]
    fn new_ok() {
        assert!(CloudflareConnector::new().config.is_none());
    }
    #[test]
    fn default_ok() {
        assert!(CloudflareConnector::default().config.is_none());
    }
    #[test]
    fn manifest_hash_stable() {
        assert_eq!(
            CloudflareConnector::manifest_hash(),
            CloudflareConnector::manifest_hash()
        );
    }
    #[test]
    fn configure_valid() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = CloudflareConnector::new();
                c.configure(tc()).await
            })
            .unwrap()
            .is_ok()
        );
    }
    #[test]
    fn configure_empty_account() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = CloudflareConnector::new();
                c.configure(json!({"mode":"api_token","api_token":"t","account_id":""}))
                    .await
            })
            .unwrap()
            .is_err()
        );
    }
    #[test]
    fn configure_whitespace_account_rejected() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = CloudflareConnector::new();
                c.configure(json!({"mode":"api_token","api_token":"t","account_id":"   "}))
                    .await
            })
            .unwrap()
            .is_err()
        );
    }
    #[test]
    fn configure_trims_account_id_base_url_and_email() {
        let configured = fcp_async_core::runtime::block_on_sync(async {
            let mut c = CloudflareConnector::new();
            c.configure(json!({
                "mode":"api_key",
                "api_key":" test-key ",
                "email":" ops@example.com ",
                "account_id":" account-123 ",
                "base_url":" https://api.cloudflare.com/client/v4 "
            }))
            .await
            .map(|()| c)
        })
        .unwrap()
        .unwrap();
        let config = configured.config.as_ref().unwrap();
        assert_eq!(config.account_id, "account-123");
        assert_eq!(config.base_url, "https://api.cloudflare.com/client/v4");
        assert!(
            matches!(&config.auth, CloudflareAuth::ApiKey { .. }),
            "expected api_key auth"
        );
        if let CloudflareAuth::ApiKey { api_key, email } = &config.auth {
            assert_eq!(api_key, "test-key");
            assert_eq!(email, "ops@example.com");
        }
    }

    #[test]
    fn configure_trims_api_token_material() {
        let configured = fcp_async_core::runtime::block_on_sync(async {
            let mut c = CloudflareConnector::new();
            c.configure(json!({
                "mode":"api_token",
                "api_token":" token-123 ",
                "account_id":" account-123 ",
                "base_url":" https://api.cloudflare.com/client/v4 "
            }))
            .await
            .map(|()| c)
        })
        .unwrap()
        .unwrap();
        let auth = &configured.config.as_ref().unwrap().auth;
        assert!(
            matches!(auth, CloudflareAuth::ApiToken { .. }),
            "expected api_token auth"
        );
        if let CloudflareAuth::ApiToken { api_token } = auth {
            assert_eq!(api_token, "token-123");
        }
    }

    #[test]
    fn configure_zero_request_timeout_rejected() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = CloudflareConnector::new();
                c.configure(json!({
                    "mode":"api_token",
                    "api_token":"t",
                    "account_id":"a",
                    "request_timeout_ms":0
                }))
                .await
            })
            .unwrap()
            .is_err()
        );
    }
    #[test]
    fn configure_rejects_invalid_network_constraints() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = CloudflareConnector::new();
                c.configure(json!({
                    "mode":"api_token",
                    "api_token":"t",
                    "account_id":"a",
                    "base_url":"http://api.cloudflare.com/client/v4"
                }))
                .await
            })
            .unwrap()
            .is_err()
        );
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = CloudflareConnector::new();
                c.configure(json!({
                    "mode":"api_token",
                    "api_token":"t",
                    "account_id":"a",
                    "base_url":"https://evil.example.com/client/v4"
                }))
                .await
            })
            .unwrap()
            .is_err()
        );
    }
    #[test]
    fn configure_api_key_requires_email_when_key_present() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = CloudflareConnector::new();
                c.configure(json!({
                    "mode":"api_key",
                    "api_key":"k",
                    "email":"   ",
                    "account_id":"a"
                }))
                .await
            })
            .unwrap()
            .is_err()
        );
    }
    #[test]
    fn configure_bad() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = CloudflareConnector::new();
                c.configure(json!("bad")).await
            })
            .unwrap()
            .is_err()
        );
    }
    #[test]
    fn doctor_unconfigured() {
        assert!(!CloudflareConnector::new().doctor().ready);
    }
    #[test]
    fn doctor_configured() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = CloudflareConnector::new();
                c.configure(tc()).await.unwrap();
                c.doctor()
            })
            .unwrap()
            .ready
        );
    }
    #[test]
    fn introspect_ops() {
        let operations = CloudflareConnector::new().introspect().operations;
        let op_ids: Vec<_> = operations.iter().map(|op| op.id.as_str()).collect();

        assert_eq!(operations.len(), OPERATION_ORDER.len());
        assert_eq!(op_ids, OPERATION_ORDER);
    }

    fn strict_cloudflare_manifest() -> Result<ConnectorManifest, String> {
        ConnectorManifest::parse_str(MANIFEST_TOML).map_err(|error| error.to_string())
    }

    #[test]
    fn runtime_operation_catalog_matches_manifest_metadata() -> Result<(), String> {
        let manifest = strict_cloudflare_manifest()?;
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
    fn operations_info_json_exposes_manifest_approval_modes() {
        let result = serde_json::to_value(CloudflareConnector::new().introspect()).unwrap();
        let ops = result["operations"].as_array().unwrap();

        let dns_delete = ops
            .iter()
            .find(|op| op["id"].as_str() == Some(OP_DNS_DELETE))
            .unwrap();
        let workers_delete = ops
            .iter()
            .find(|op| op["id"].as_str() == Some(OP_WORKERS_DELETE))
            .unwrap();
        let kv_delete = ops
            .iter()
            .find(|op| op["id"].as_str() == Some(OP_KV_DELETE))
            .unwrap();

        assert_eq!(dns_delete["requires_approval"], "interactive");
        assert_eq!(workers_delete["requires_approval"], "interactive");
        assert_eq!(kv_delete["requires_approval"], "interactive");
    }

    #[test]
    fn introspect_exposes_typed_schemas_for_key_operations() {
        let introspection = CloudflareConnector::new().introspect();
        let zones = introspection
            .operations
            .iter()
            .find(|op| op.id.as_str() == OP_ZONES_LIST)
            .unwrap();
        assert_eq!(
            zones.output_schema["items"]["required"],
            json!(["id", "name", "status"])
        );

        let health = introspection
            .operations
            .iter()
            .find(|op| op.id.as_str() == OP_HEALTH)
            .unwrap();
        assert_eq!(
            health.output_schema["properties"]["healthy"]["type"],
            "boolean"
        );
        assert!(health.description.is_some());

        let kv_get = introspection
            .operations
            .iter()
            .find(|op| op.id.as_str() == OP_KV_GET)
            .unwrap();
        assert_eq!(kv_get.output_schema["required"], json!(["value"]));
        assert_eq!(
            kv_get.output_schema["properties"]["value"]["type"],
            "string"
        );
    }
    #[test]
    fn ops_all_have_hints() {
        for op in typed_operations_info() {
            assert!(!op.ai_hints.when_to_use.is_empty(), "{}", op.id);
        }
    }
    #[test]
    fn dangerous_ops_need_approval() {
        for op in typed_operations_info() {
            if op.safety_tier == SafetyTier::Dangerous {
                assert!(op.requires_approval.is_some(), "{}", op.id);
            }
        }
    }
    #[test]
    fn invoke_unknown() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = CloudflareConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req([0u8; 32])).await.unwrap();
                c.invoke(invoke_req(
                    "cf.nope",
                    json!({}),
                    CapabilityToken::test_token(),
                ))
                .await
            })
            .unwrap()
            .is_err()
        );
    }
    #[test]
    fn invoke_missing_zone() {
        let error = fcp_async_core::runtime::block_on_sync(async {
            let mut c = CloudflareConnector::new();
            let signing_key = Ed25519SigningKey::generate();
            c.configure(tc()).await.unwrap();
            c.handshake(handshake_req(signing_key.verifying_key().to_bytes()))
                .await
                .unwrap();
            c.invoke(invoke_req(
                OP_DNS_LIST,
                json!({}),
                signed_capability_token(&signing_key, c.instance_id().as_str(), OP_DNS_LIST),
            ))
            .await
        })
        .unwrap()
        .expect_err("missing zone_id should be rejected");
        assert!(matches!(error, FcpError::InvalidRequest { .. }));
        assert!(error.to_string().contains("Missing: zone_id"));
    }

    #[test]
    fn resource_uris_bind_dns_and_account_scoped_operations() {
        let dns_uris = resource_uris_for_operation(
            OP_DNS_UPDATE,
            &json!({"zone_id":"zone-123","record_id":"rec-456"}),
            "acc123",
        )
        .unwrap();
        assert_eq!(
            dns_uris,
            vec!["cloudflare://zones/zone-123/dns_records/rec-456"]
        );

        let worker_uris = resource_uris_for_operation(
            OP_WORKERS_GET,
            &json!({"script_name":"worker-a"}),
            "acc123",
        )
        .unwrap();
        assert_eq!(
            worker_uris,
            vec!["cloudflare://accounts/acc123/workers/scripts/worker-a"]
        );
    }
    #[test]
    fn invoke_dns_create_rejects_invalid_optional_numeric_field() {
        let error = fcp_async_core::runtime::block_on_sync(async {
            let mut c = CloudflareConnector::new();
            let signing_key = Ed25519SigningKey::generate();
            c.configure(tc()).await.unwrap();
            c.handshake(handshake_req(signing_key.verifying_key().to_bytes()))
                .await
                .unwrap();
            c.invoke(invoke_req(
                OP_DNS_CREATE,
                json!({
                    "zone_id": "zone-123",
                    "type": "A",
                    "name": "example.com",
                    "content": "1.2.3.4",
                    "ttl": -1
                }),
                signed_capability_token(&signing_key, c.instance_id().as_str(), OP_DNS_CREATE),
            ))
            .await
        })
        .unwrap()
        .expect_err("negative ttl should be rejected");
        assert!(matches!(error, FcpError::InvalidRequest { .. }));
        assert!(
            error
                .to_string()
                .contains("Field 'ttl' must be a non-negative integer")
        );
    }
    #[test]
    fn invoke_dns_update_rejects_invalid_optional_field_types() {
        let error = fcp_async_core::runtime::block_on_sync(async {
            let mut c = CloudflareConnector::new();
            let signing_key = Ed25519SigningKey::generate();
            c.configure(tc()).await.unwrap();
            c.handshake(handshake_req(signing_key.verifying_key().to_bytes()))
                .await
                .unwrap();
            c.invoke(invoke_req(
                OP_DNS_UPDATE,
                json!({
                    "zone_id": "zone-123",
                    "record_id": "rec-456",
                    "type": "A",
                    "name": "example.com",
                    "content": "1.2.3.4",
                    "proxied": "true"
                }),
                signed_capability_token(&signing_key, c.instance_id().as_str(), OP_DNS_UPDATE),
            ))
            .await
        })
        .unwrap()
        .expect_err("string proxied should be rejected");
        assert!(matches!(error, FcpError::InvalidRequest { .. }));
        assert!(
            error
                .to_string()
                .contains("Field 'proxied' must be a boolean")
        );
    }
    #[test]
    fn simulate_ok() {
        let r = fcp_async_core::runtime::block_on_sync(async {
            CloudflareConnector::new()
                .simulate(SimulateRequest::new(
                    ConnectorId::from_static("fcp.cloudflare"),
                    OperationId::from_static(OP_ZONES_LIST),
                    ZoneId::work(),
                    json!({}),
                    CapabilityToken::test_token(),
                ))
                .await
        })
        .unwrap()
        .unwrap();
        assert!(r.would_succeed);
    }
    #[test]
    fn subscribe_unsupported() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                CloudflareConnector::new()
                    .subscribe(SubscribeRequest {
                        r#type: "subscribe".into(),
                        id: RequestId::new("sub1"),
                        topics: vec![],
                        since: None,
                        max_events_per_sec: None,
                        batch_ms: None,
                        window_size: None,
                        capability_token: None,
                    })
                    .await
            })
            .unwrap()
            .is_err()
        );
    }
    #[test]
    fn shutdown_ok() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut c = CloudflareConnector::new();
            c.configure(tc()).await.unwrap();
            c.shutdown(ShutdownRequest {
                r#type: "shutdown".into(),
                deadline_ms: 10_000,
                drain: false,
                reason: None,
            })
            .await
            .unwrap();
        })
        .unwrap();
    }
    #[test]
    fn handshake_ok() {
        let r = fcp_async_core::runtime::block_on_sync(async {
            let mut c = CloudflareConnector::new();
            c.configure(tc()).await.unwrap();
            c.handshake(handshake_req([0u8; 32])).await.unwrap()
        })
        .unwrap();
        assert_eq!(r.status, "accepted");
        assert_eq!(r.capabilities_granted.len(), 3);
    }
    #[test]
    fn require_str_ok() {
        assert_eq!(
            CloudflareConnector::require_str(&json!({"k":"v"}), "k").unwrap(),
            "v"
        );
    }
    #[test]
    fn require_str_miss() {
        assert!(CloudflareConnector::require_str(&json!({}), "k").is_err());
    }
    #[test]
    fn require_str_empty() {
        assert!(CloudflareConnector::require_str(&json!({"k": ""}), "k").is_err());
        assert!(CloudflareConnector::require_str(&json!({"k": "  "}), "k").is_err());
    }
    #[test]
    fn api_key_auth() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = CloudflareConnector::new();
                c.configure(json!({"mode":"api_key","api_key":"k","email":"u@e","account_id":"a"}))
                    .await
            })
            .unwrap()
            .is_ok()
        );
    }
    #[test]
    fn health_unconfigured() {
        let h = fcp_async_core::runtime::block_on_sync(async {
            CloudflareConnector::new().health().await
        })
        .unwrap();
        assert!(matches!(h.status, fcp_core::HealthState::Degraded { .. }));
    }
    #[test]
    fn health_configured() {
        let h = fcp_async_core::runtime::block_on_sync(async {
            let mut c = CloudflareConnector::new();
            c.configure(tc()).await.unwrap();
            c.health().await
        })
        .unwrap();
        assert!(matches!(h.status, fcp_core::HealthState::Ready));
    }
}
