//! GCP connector implementation.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcp_prelude::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, ConnectorMetrics, EventCaps, FcpConnector, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, HealthSnapshot, IdempotencyClass, Introspection, InvokeRequest,
    InvokeResponse, OperationId, OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId,
    ShutdownRequest, SimulateRequest, SimulateResponse, SubscribeRequest, SubscribeResponse,
    UnsubscribeRequest,
};
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::Url;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::info;

use crate::client::GcpClient;
use crate::types::GcpAuth;

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/gcp_connector_verification.sh";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/gcp_connector/<timestamp>";
const COMPUTE_API_HOST: &str = "compute.googleapis.com";
const STORAGE_API_HOST: &str = "storage.googleapis.com";
const RUN_API_HOST: &str = "run.googleapis.com";
const CRM_API_HOST: &str = "cloudresourcemanager.googleapis.com";
const GCP_ALLOWED_HOSTS: &[&str] = &[
    COMPUTE_API_HOST,
    STORAGE_API_HOST,
    RUN_API_HOST,
    CRM_API_HOST,
];

// ── Operation IDs ──
const OP_COMPUTE_LIST_INSTANCES: &str = "gcp.compute.list_instances";
const OP_COMPUTE_GET_INSTANCE: &str = "gcp.compute.get_instance";
const OP_COMPUTE_START_INSTANCE: &str = "gcp.compute.start_instance";
const OP_COMPUTE_STOP_INSTANCE: &str = "gcp.compute.stop_instance";
const OP_COMPUTE_DELETE_INSTANCE: &str = "gcp.compute.delete_instance";
const OP_STORAGE_LIST_OBJECTS: &str = "gcp.storage.list_objects";
const OP_STORAGE_GET_OBJECT: &str = "gcp.storage.get_object";
const OP_STORAGE_UPLOAD_OBJECT: &str = "gcp.storage.upload_object";
const OP_STORAGE_DELETE_OBJECT: &str = "gcp.storage.delete_object";
const OP_RUN_LIST_SERVICES: &str = "gcp.run.list_services";
const OP_RUN_DEPLOY_SERVICE: &str = "gcp.run.deploy_service";
const OP_RUN_DELETE_SERVICE: &str = "gcp.run.delete_service";
const OP_PROJECTS_GET: &str = "gcp.projects.get";
const OP_HEALTH: &str = "gcp.health";

// ── Capability IDs ──
const CAP_COMPUTE_READ: &str = "gcp.compute.read";
const CAP_COMPUTE_WRITE: &str = "gcp.compute.write";
const CAP_STORAGE_READ: &str = "gcp.storage.read";
const CAP_STORAGE_WRITE: &str = "gcp.storage.write";
const CAP_RUN_READ: &str = "gcp.run.read";
const CAP_RUN_WRITE: &str = "gcp.run.write";
const CAP_IAM_READ: &str = "gcp.iam.read";

#[derive(Clone, serde::Deserialize)]
pub struct GcpConfig {
    pub project_id: String,
    #[serde(flatten)]
    pub auth: GcpAuth,
    #[serde(default)]
    pub retry: HttpRetryConfig,
    #[serde(default = "default_timeout_ms")]
    pub request_timeout_ms: u64,
    /// Override base URL for Compute Engine (testing).
    pub compute_base_url: Option<String>,
    /// Override base URL for Cloud Storage (testing).
    pub storage_base_url: Option<String>,
    /// Override base URL for Cloud Run (testing).
    pub run_base_url: Option<String>,
    /// Override base URL for Cloud Resource Manager (testing).
    pub crm_base_url: Option<String>,
}

const fn default_timeout_ms() -> u64 {
    30_000
}

impl std::fmt::Debug for GcpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcpConfig")
            .field("project_id", &self.project_id)
            .field("auth", &self.auth)
            .finish_non_exhaustive()
    }
}

impl GcpConfig {
    fn validate(&self) -> Result<(), String> {
        if self.project_id.trim().is_empty() {
            return Err("project_id is required".into());
        }
        if self.request_timeout_ms == 0 {
            return Err("request_timeout_ms must be > 0".into());
        }
        // Service-account mode is supported via JWT bearer auth.
        // Key validation happens in GcpClient::new().
        let readiness = self.provisioning_readiness();
        if !readiness.network_ok {
            return Err(readiness.network_message);
        }
        Ok(())
    }

    fn from_value(val: serde_json::Value) -> FcpResult<Self> {
        let mut config: Self =
            serde_json::from_value(val).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid configuration: {e}"),
            })?;
        config.project_id = config.project_id.trim().to_string();
        config.validate().map_err(|e| FcpError::InvalidRequest {
            code: 1001,
            message: e,
        })?;
        Ok(config)
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let service_endpoints = vec![
            endpoint_policy("compute", self.compute_base_url.as_deref(), COMPUTE_API_HOST),
            endpoint_policy("storage", self.storage_base_url.as_deref(), STORAGE_API_HOST),
            endpoint_policy("run", self.run_base_url.as_deref(), RUN_API_HOST),
            endpoint_policy("crm", self.crm_base_url.as_deref(), CRM_API_HOST),
        ];
        let network_ok = service_endpoints.iter().all(|endpoint| endpoint.ok);
        let network_message = if network_ok {
            format!(
                "Validated {} GCP API endpoint policies",
                service_endpoints.len()
            )
        } else {
            service_endpoints
                .iter()
                .filter(|endpoint| !endpoint.ok)
                .map(|endpoint| format!("{}: {}", endpoint.service, endpoint.message))
                .collect::<Vec<_>>()
                .join("; ")
        };

        ProvisioningReadiness {
            auth_mode: self.auth.auth_mode(),
            uses_service_account: self.auth.is_service_account(),
            secret_material_configured: !self.auth.is_secretless(),
            requires_credential_injection: self.auth.is_secretless(),
            project_id_configured: !self.project_id.trim().is_empty(),
            network_ok,
            network_message,
            allowed_hosts: GCP_ALLOWED_HOSTS.to_vec(),
            service_endpoints,
            project_scope_hint: "All GCP API calls target the configured project_id. Ensure the credentials have appropriate IAM permissions for the target project.",
        }
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize)]
struct ProvisioningReadiness {
    auth_mode: &'static str,
    uses_service_account: bool,
    secret_material_configured: bool,
    requires_credential_injection: bool,
    project_id_configured: bool,
    network_ok: bool,
    network_message: String,
    allowed_hosts: Vec<&'static str>,
    service_endpoints: Vec<EndpointReadiness>,
    project_scope_hint: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct EndpointReadiness {
    service: &'static str,
    expected_host: &'static str,
    override_configured: bool,
    ok: bool,
    message: String,
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
    verification_script: &'static str,
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
            verification_script: VERIFICATION_SCRIPT_PATH,
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

fn normalize_policy_host(host: &str) -> String {
    host.trim()
        .trim_end_matches('.')
        .trim_matches(|c| c == '[' || c == ']')
        .to_ascii_lowercase()
}

fn is_local_test_host(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host == "::1" || host.ends_with(".localhost")
}

fn endpoint_policy(
    service: &'static str,
    base_url: Option<&str>,
    expected_host: &'static str,
) -> EndpointReadiness {
    let Some(base_url) = base_url else {
        return EndpointReadiness {
            service,
            expected_host,
            override_configured: false,
            ok: true,
            message: format!("Using default {service} GCP API endpoint ({expected_host})"),
        };
    };

    let parsed = match Url::parse(base_url) {
        Ok(url) => url,
        Err(error) => {
            return EndpointReadiness {
                service,
                expected_host,
                override_configured: true,
                ok: false,
                message: format!("base_url must be an absolute URL: {error}"),
            };
        }
    };

    let Some(host) = parsed.host_str() else {
        return EndpointReadiness {
            service,
            expected_host,
            override_configured: true,
            ok: false,
            message: "base_url must include a host".into(),
        };
    };

    let normalized_host = normalize_policy_host(host);
    let mut problems = Vec::new();
    if parsed.query().is_some() || parsed.fragment().is_some() {
        problems.push("query string and fragment are not allowed".to_string());
    }

    if is_local_test_host(&normalized_host) {
        if !matches!(parsed.scheme(), "http" | "https") {
            problems.push(format!(
                "scheme must be http or https for local test endpoint, got {}",
                parsed.scheme()
            ));
        }
        return EndpointReadiness {
            service,
            expected_host,
            override_configured: true,
            ok: problems.is_empty(),
            message: if problems.is_empty() {
                format!("localhost test endpoint accepted for {service} verification: {base_url}")
            } else {
                problems.join("; ")
            },
        };
    }

    if parsed.scheme() != "https" {
        problems.push(format!("scheme must be https, got {}", parsed.scheme()));
    }
    if normalized_host != expected_host {
        problems.push(format!(
            "host must be {expected_host}, got {normalized_host}"
        ));
    }
    if !matches!(parsed.path(), "" | "/") {
        problems.push(format!(
            "path must be empty for {service} base_url, got {}",
            parsed.path()
        ));
    }

    EndpointReadiness {
        service,
        expected_host,
        override_configured: true,
        ok: problems.is_empty(),
        message: if problems.is_empty() {
            format!("{service} GCP API endpoint accepted")
        } else {
            problems.join("; ")
        },
    }
}

fn operator_guidance() -> OperatorGuidance {
    OperatorGuidance {
        prerequisites: vec![
            "Create a dedicated GCP project for verification testing.",
            "Provision a service account with only the IAM roles you intend to exercise.",
            "Use non-production Compute instances, Cloud Storage buckets, and Cloud Run services for mutation tests.",
        ],
        dedicated_environment: "Use a staging-only GCP project_id. Instance delete, object delete, and service delete operations are dangerous and should never target production during verification.",
        redaction_rules: vec![
            "Never log access_token or private_key values.",
            "Do not paste real project IDs, service account emails, or bucket names from private environments into shared transcripts.",
        ],
        common_remediation: vec![
            RemediationHint {
                code: "iam_permission_denied",
                symptom: "self_check or invoke returns 403",
                action: "Grant the service account the required IAM roles: compute.viewer for read ops, compute.instanceAdmin for write ops, storage.objectViewer/Creator/Admin for storage, run.viewer/admin for Cloud Run.",
            },
            RemediationHint {
                code: "project_not_found",
                symptom: "invoke returns 404 for project-scoped calls",
                action: "Verify project_id matches an active GCP project and the credentials belong to that project.",
            },
            RemediationHint {
                code: "credential_injection_required",
                symptom: "auth mode is configured but secret material is intentionally omitted",
                action: "Inject Authorization header at runtime via the host/egress proxy, then rerun self_check before invoking mutation operations.",
            },
        ],
        rerun_commands: vec![
            "scripts/e2e/gcp_connector_verification.sh",
            "rch exec -- cargo run -q -p fwc -- manifest fix connectors/gcp/manifest.toml --check --json",
            "rch exec -- cargo test -p fcp-gcp --test integration -- --nocapture",
            "rch exec -- cargo test -p fcp-e2e --features gcp --test gcp_compliance_e2e -- --nocapture",
            "rch exec -- cargo clippy -p fcp-gcp --all-targets -- -D warnings",
        ],
        artifact_root_hint: ARTIFACT_ROOT_HINT,
    }
}

#[derive(Debug)]
pub struct GcpConnector {
    base: BaseConnector,
    config: Option<GcpConfig>,
    client: Option<GcpClient>,
    runtime: Option<ConnectorRuntime>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl GcpConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.gcp")),
            config: None,
            client: None,
            runtime: None,
            started_at: Instant::now(),
            verifier: None,
        }
    }

    fn manifest_hash() -> String {
        let mut h = Sha256::new();
        h.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(h.finalize()))
    }

    pub fn doctor(&self) -> DoctorResult {
        let provisioning = self.config.as_ref().map(GcpConfig::provisioning_readiness);
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
                passed: readiness.network_ok,
                message: Some(readiness.network_message.clone()),
                critical: true,
            });
            checks.push(DoctorCheck {
                name: "project_id".into(),
                passed: readiness.project_id_configured,
                message: Some(if readiness.project_id_configured {
                    "GCP project_id configured".into()
                } else {
                    "project_id missing; API calls cannot resolve project-scoped endpoints".into()
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
                passed: readiness.secret_material_configured,
                message: Some(if readiness.secret_material_configured {
                    "Credential material configured directly".into()
                } else {
                    "Secret material omitted; host or egress proxy must inject headers at runtime"
                        .into()
                }),
                critical: false,
            });
        }
        let result = DoctorResult::from_checks(checks, provisioning);
        let failed_checks = result.checks.iter().filter(|check| !check.passed).count();
        info!(
            event = "gcp.provisioning.doctor",
            status = result.status_label(),
            check_count = result.checks.len(),
            failed_checks,
            "GCP doctor checks completed"
        );
        result
    }

    #[allow(clippy::needless_pass_by_value)]
    fn attach_self_check_details(
        mut report: SelfCheckReport,
        provisioning: Option<ProvisioningReadiness>,
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
}

impl Default for GcpConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(clippy::too_many_lines)]
fn operations_info() -> Vec<OperationInfo> {
    let hint = |when: &str,
                mistakes: Vec<String>,
                examples: Vec<String>,
                related: Vec<&'static str>|
     -> AgentHint {
        AgentHint {
            when_to_use: when.into(),
            common_mistakes: mistakes,
            examples,
            related: related.into_iter().map(CapabilityId::from_static).collect(),
        }
    };
    vec![
        // ── Compute Engine ──
        OperationInfo {
            id: OperationId::from_static(OP_COMPUTE_LIST_INSTANCES),
            summary: "List Compute Engine instances in a zone".into(),
            description: None,
            input_schema: json!({"type":"object","required":["zone"]}),
            output_schema: json!({"type":"array"}),
            capability: CapabilityId::from_static(CAP_COMPUTE_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "List VMs in a zone",
                vec!["Specify zone like us-central1-a".into()],
                vec![],
                vec![CAP_COMPUTE_WRITE],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_COMPUTE_GET_INSTANCE),
            summary: "Get a Compute Engine instance".into(),
            description: None,
            input_schema: json!({"type":"object","required":["zone","instance"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_COMPUTE_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "Get details of a specific VM",
                vec![],
                vec![],
                vec![CAP_COMPUTE_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_COMPUTE_START_INSTANCE),
            summary: "Start a Compute Engine instance".into(),
            description: None,
            input_schema: json!({"type":"object","required":["zone","instance"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_COMPUTE_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Start a stopped VM",
                vec!["VM must be in TERMINATED state".into()],
                vec![],
                vec![CAP_COMPUTE_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_COMPUTE_STOP_INSTANCE),
            summary: "Stop a Compute Engine instance".into(),
            description: None,
            input_schema: json!({"type":"object","required":["zone","instance"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_COMPUTE_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Stop a running VM",
                vec!["VM must be in RUNNING state".into()],
                vec![],
                vec![CAP_COMPUTE_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_COMPUTE_DELETE_INSTANCE),
            summary: "Delete a Compute Engine instance".into(),
            description: None,
            input_schema: json!({"type":"object","required":["zone","instance"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_COMPUTE_WRITE),
            risk_level: RiskLevel::Critical,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Permanently delete a VM (irreversible)",
                vec!["Verify instance name first".into()],
                vec![],
                vec![CAP_COMPUTE_READ],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        // ── Cloud Storage ──
        OperationInfo {
            id: OperationId::from_static(OP_STORAGE_LIST_OBJECTS),
            summary: "List objects in a Cloud Storage bucket".into(),
            description: None,
            input_schema: json!({"type":"object","required":["bucket"]}),
            output_schema: json!({"type":"array"}),
            capability: CapabilityId::from_static(CAP_STORAGE_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "List files in a bucket",
                vec![],
                vec![],
                vec![CAP_STORAGE_WRITE],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_STORAGE_GET_OBJECT),
            summary: "Get metadata for a Cloud Storage object".into(),
            description: None,
            input_schema: json!({"type":"object","required":["bucket","object"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_STORAGE_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "Get object metadata",
                vec![],
                vec![],
                vec![CAP_STORAGE_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_STORAGE_UPLOAD_OBJECT),
            summary: "Upload an object to Cloud Storage".into(),
            description: None,
            input_schema: json!({"type":"object","required":["bucket","object","content"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_STORAGE_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Upload a file to a bucket",
                vec!["Overwrites existing objects with same name".into()],
                vec![],
                vec![CAP_STORAGE_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_STORAGE_DELETE_OBJECT),
            summary: "Delete a Cloud Storage object".into(),
            description: None,
            input_schema: json!({"type":"object","required":["bucket","object"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_STORAGE_WRITE),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Remove object from bucket (irreversible unless versioned)",
                vec!["Verify object name first".into()],
                vec![],
                vec![CAP_STORAGE_READ],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        // ── Cloud Run ──
        OperationInfo {
            id: OperationId::from_static(OP_RUN_LIST_SERVICES),
            summary: "List Cloud Run services".into(),
            description: None,
            input_schema: json!({"type":"object","required":["location"]}),
            output_schema: json!({"type":"array"}),
            capability: CapabilityId::from_static(CAP_RUN_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "List deployed Cloud Run services",
                vec![],
                vec![],
                vec![CAP_RUN_WRITE],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_RUN_DEPLOY_SERVICE),
            summary: "Deploy a Cloud Run service".into(),
            description: None,
            input_schema: json!({"type":"object","required":["location","service_id","image"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_RUN_WRITE),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Deploy container image to Cloud Run",
                vec!["Image must be in a registry accessible to the project".into()],
                vec![],
                vec![CAP_RUN_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_RUN_DELETE_SERVICE),
            summary: "Delete a Cloud Run service".into(),
            description: None,
            input_schema: json!({"type":"object","required":["location","service"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_RUN_WRITE),
            risk_level: RiskLevel::Critical,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Permanently delete a Cloud Run service (irreversible)",
                vec!["Verify service name first".into()],
                vec![],
                vec![CAP_RUN_READ],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        // ── Projects ──
        OperationInfo {
            id: OperationId::from_static(OP_PROJECTS_GET),
            summary: "Get project information".into(),
            description: None,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_IAM_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint("Get GCP project metadata", vec![], vec![], vec![]),
            rate_limit: None,
            requires_approval: None,
        },
        // ── Health ──
        OperationInfo {
            id: OperationId::from_static(OP_HEALTH),
            summary: "Check GCP API health".into(),
            description: None,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_IAM_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Check credentials and API connectivity",
                vec![],
                vec![],
                vec![],
            ),
            rate_limit: None,
            requires_approval: None,
        },
    ]
}

fcp_core::impl_fcp_sealed!(GcpConnector);

#[async_trait]
impl FcpConnector for GcpConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let cfg = GcpConfig::from_value(config)?;
        let provisioning = cfg.provisioning_readiness();
        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(cfg.request_timeout_ms)),
        ));
        let client = GcpClient::new(
            &cfg.project_id,
            cfg.auth.clone(),
            cfg.retry.clone(),
            cfg.compute_base_url.as_deref(),
            cfg.storage_base_url.as_deref(),
            cfg.run_base_url.as_deref(),
            cfg.crm_base_url.as_deref(),
        )
        .await
        .map_err(|e| FcpError::Internal {
            message: format!("Client init: {e}"),
        })?;
        self.client = Some(client);
        self.config = Some(cfg);
        self.verifier = None;
        self.base.set_configured(true);
        self.base.set_handshaken(false);
        info!(
            event = "gcp.provisioning.configure",
            auth_mode = provisioning.auth_mode,
            network_ok = provisioning.network_ok,
            requires_credential_injection = provisioning.requires_credential_injection,
            "Configured GCP connector"
        );
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        self.base.set_handshaken(true);
        let verifier_instance_id = req
            .requested_instance_id
            .clone()
            .unwrap_or_else(|| self.base.instance_id.clone());
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            verifier_instance_id,
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
        let provisioning = self.config.as_ref().map(GcpConfig::provisioning_readiness);
        let mut snap = match &provisioning {
            Some(readiness) if !readiness.network_ok => {
                HealthSnapshot::error("network constraints invalid")
            }
            Some(readiness) if readiness.requires_credential_injection => {
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
            "artifact_root_hint": ARTIFACT_ROOT_HINT,
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

        if !provisioning.network_ok {
            return Ok(Self::attach_self_check_details(
                SelfCheckReport::failed(
                    "network_constraints_invalid",
                    provisioning.network_message.clone(),
                ),
                Some(provisioning),
            ));
        }

        let Some(_client) = &self.client else {
            return Ok(Self::attach_self_check_details(
                SelfCheckReport::failed(
                    "client_missing",
                    "GCP HTTP client not initialized; re-run configure",
                ),
                Some(provisioning),
            ));
        };
        let Some(_runtime) = &self.runtime else {
            return Ok(Self::attach_self_check_details(
                SelfCheckReport::failed(
                    "runtime_missing",
                    "ConnectorRuntime not initialized; re-run configure",
                ),
                Some(provisioning),
            ));
        };

        if provisioning.requires_credential_injection {
            return Ok(Self::attach_self_check_details(
                SelfCheckReport::degraded(
                    "credential_injection_required",
                    "Credential material is intentionally omitted; inject Authorization header at runtime before re-running self_check",
                ),
                Some(provisioning),
            ));
        }

        // For real health check we would call get_project, but for self_check
        // we verify the credentials are present and config is valid.
        let report = match _client.get_project(_runtime).await {
            Ok(proj) => {
                let state = proj.lifecycle_state.as_deref().unwrap_or("UNKNOWN");
                if state == "ACTIVE" {
                    SelfCheckReport::ok()
                } else {
                    SelfCheckReport::degraded(
                        "project_inactive",
                        format!(
                            "GCP project lifecycle state is '{state}' - verify project is active"
                        ),
                    )
                }
            }
            Err(error) if error.is_retryable() => {
                SelfCheckReport::degraded("self_check_retryable", error.to_string())
            }
            Err(error) => SelfCheckReport::failed("self_check_failed", error.to_string()),
        };
        let report = Self::attach_self_check_details(report, Some(provisioning));
        info!(
            event = "gcp.provisioning.self_check",
            status = ?report.status,
            reason_code = report.reason_code.as_deref().unwrap_or("ok"),
            "GCP self_check completed"
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

    async fn subscribe(&self, _req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }
    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Err(FcpError::StreamingNotSupported)
    }
}

impl GcpConnector {
    #[allow(clippy::too_many_lines)]
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();
        if let Some(verifier) = &self.verifier {
            let cap = match operation {
                OP_COMPUTE_LIST_INSTANCES | OP_COMPUTE_GET_INSTANCE => {
                    CapabilityId::from_static(CAP_COMPUTE_READ)
                }
                OP_COMPUTE_START_INSTANCE
                | OP_COMPUTE_STOP_INSTANCE
                | OP_COMPUTE_DELETE_INSTANCE => CapabilityId::from_static(CAP_COMPUTE_WRITE),
                OP_STORAGE_LIST_OBJECTS | OP_STORAGE_GET_OBJECT => {
                    CapabilityId::from_static(CAP_STORAGE_READ)
                }
                OP_STORAGE_UPLOAD_OBJECT | OP_STORAGE_DELETE_OBJECT => {
                    CapabilityId::from_static(CAP_STORAGE_WRITE)
                }
                OP_RUN_LIST_SERVICES => CapabilityId::from_static(CAP_RUN_READ),
                OP_RUN_DEPLOY_SERVICE | OP_RUN_DELETE_SERVICE => {
                    CapabilityId::from_static(CAP_RUN_WRITE)
                }
                OP_PROJECTS_GET | OP_HEALTH => CapabilityId::from_static(CAP_IAM_READ),
                _ => {
                    return Err(FcpError::InvalidRequest {
                        code: 1004,
                        message: format!("Unknown operation: {operation}"),
                    });
                }
            };
            // dja9u.1.a: verify_bound returns CapabilityToken<BoundVerified>;
            // discarded here because invoke has no downstream that consumes
            // the typestate yet, but the call enforces the typestate handoff.
            let _bound = verifier.verify_bound(req.capability_token, &cap, &req.operation, &[])?;
        } else {
            return Err(FcpError::Internal {
                message: "connector ready state missing capability verifier".into(),
            });
        }

        let runtime = self.runtime.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing runtime".into(),
        })?;
        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing GCP client".into(),
        })?;

        let output = match operation {
            OP_COMPUTE_LIST_INSTANCES => {
                let zone = Self::require_str(&req.input, "zone")?;
                let instances = client
                    .list_instances(runtime, zone)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&instances).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_COMPUTE_GET_INSTANCE => {
                let zone = Self::require_str(&req.input, "zone")?;
                let instance = Self::require_str(&req.input, "instance")?;
                let inst = client
                    .get_instance(runtime, zone, instance)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&inst).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_COMPUTE_START_INSTANCE => {
                let zone = Self::require_str(&req.input, "zone")?;
                let instance = Self::require_str(&req.input, "instance")?;
                client
                    .start_instance(runtime, zone, instance)
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_COMPUTE_STOP_INSTANCE => {
                let zone = Self::require_str(&req.input, "zone")?;
                let instance = Self::require_str(&req.input, "instance")?;
                client
                    .stop_instance(runtime, zone, instance)
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_COMPUTE_DELETE_INSTANCE => {
                let zone = Self::require_str(&req.input, "zone")?;
                let instance = Self::require_str(&req.input, "instance")?;
                client
                    .delete_instance(runtime, zone, instance)
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_STORAGE_LIST_OBJECTS => {
                let bucket = Self::require_str(&req.input, "bucket")?;
                let objects = client
                    .list_objects(runtime, bucket)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&objects).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_STORAGE_GET_OBJECT => {
                let bucket = Self::require_str(&req.input, "bucket")?;
                let object = Self::require_str(&req.input, "object")?;
                let obj = client
                    .get_object(runtime, bucket, object)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&obj).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_STORAGE_UPLOAD_OBJECT => {
                let bucket = Self::require_str(&req.input, "bucket")?;
                let object = Self::require_str(&req.input, "object")?;
                let content = Self::require_str(&req.input, "content")?;
                let content_type = req.input.get("content_type").and_then(|v| v.as_str());
                let obj = client
                    .upload_object(runtime, bucket, object, content, content_type)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&obj).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_STORAGE_DELETE_OBJECT => {
                let bucket = Self::require_str(&req.input, "bucket")?;
                let object = Self::require_str(&req.input, "object")?;
                client
                    .delete_object(runtime, bucket, object)
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_RUN_LIST_SERVICES => {
                let location = Self::require_str(&req.input, "location")?;
                let services = client
                    .list_services(runtime, location)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&services).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_RUN_DEPLOY_SERVICE => {
                let location = Self::require_str(&req.input, "location")?;
                let service_id = Self::require_str(&req.input, "service_id")?;
                let image = Self::require_str(&req.input, "image")?;
                let svc = client
                    .deploy_service(runtime, location, service_id, image)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&svc).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_RUN_DELETE_SERVICE => {
                let location = Self::require_str(&req.input, "location")?;
                let service = Self::require_str(&req.input, "service")?;
                client
                    .delete_service(runtime, location, service)
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_PROJECTS_GET => {
                let proj = client
                    .get_project(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&proj).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_HEALTH => {
                let proj = client
                    .get_project(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({
                    "healthy": proj.lifecycle_state.as_deref() == Some("ACTIVE"),
                    "project_id": proj.project_id,
                    "lifecycle_state": proj.lifecycle_state,
                })
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

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_prelude::{CapabilityToken, RequestId, ZoneId};

    fn tc() -> serde_json::Value {
        json!({"mode": "access_token", "access_token": "ya29.test", "project_id": "test-project"})
    }

    fn handshake_req() -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [0u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_COMPUTE_READ),
                CapabilityId::from_static(CAP_COMPUTE_WRITE),
                CapabilityId::from_static(CAP_STORAGE_READ),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        }
    }

    fn invoke_req(op: &'static str, input: serde_json::Value) -> InvokeRequest {
        InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("r1"),
            connector_id: ConnectorId::from_static("fcp.gcp"),
            operation: OperationId::from_static(op),
            zone_id: ZoneId::work(),
            input,
            capability_token: CapabilityToken::test_token(),
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
        assert!(GcpConnector::new().config.is_none());
    }

    #[test]
    fn default_ok() {
        assert!(GcpConnector::default().config.is_none());
    }

    #[test]
    fn manifest_hash_stable() {
        assert_eq!(GcpConnector::manifest_hash(), GcpConnector::manifest_hash());
    }

    #[test]
    fn configure_valid() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = GcpConnector::new();
                c.configure(tc()).await
            })
            .unwrap()
            .is_ok()
        );
    }

    #[test]
    fn configure_empty_project() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = GcpConnector::new();
                c.configure(json!({"mode":"access_token","access_token":"t","project_id":""}))
                    .await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn configure_whitespace_project_is_rejected() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = GcpConnector::new();
                c.configure(json!({"mode":"access_token","access_token":"t","project_id":"   "}))
                    .await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn configure_zero_request_timeout_is_rejected() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = GcpConnector::new();
                c.configure(json!({
                    "mode":"access_token",
                    "access_token":"t",
                    "project_id":"test-project",
                    "request_timeout_ms": 0
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
                let mut c = GcpConnector::new();
                c.configure(json!("bad")).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn doctor_unconfigured() {
        assert!(!GcpConnector::new().doctor().ready);
    }

    #[test]
    fn doctor_configured() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = GcpConnector::new();
                c.configure(tc()).await.unwrap();
                c.doctor()
            })
            .unwrap()
            .ready
        );
    }

    #[test]
    fn introspect_ops() {
        assert_eq!(GcpConnector::new().introspect().operations.len(), 14);
    }

    #[test]
    fn ops_all_have_hints() {
        for op in operations_info() {
            assert!(!op.ai_hints.when_to_use.is_empty(), "{}", op.id);
        }
    }

    #[test]
    fn dangerous_ops_need_approval() {
        for op in operations_info() {
            if op.safety_tier == SafetyTier::Dangerous {
                assert!(op.requires_approval.is_some(), "{}", op.id);
            }
        }
    }

    #[test]
    fn safe_ops_have_no_approval() {
        for op in operations_info() {
            if op.safety_tier == SafetyTier::Safe {
                assert!(op.requires_approval.is_none(), "{}", op.id);
            }
        }
    }

    #[test]
    fn invoke_unknown() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = GcpConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req("gcp.nope", json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_missing_zone() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = GcpConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_COMPUTE_LIST_INSTANCES, json!({})))
                    .await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_missing_bucket() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = GcpConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_STORAGE_LIST_OBJECTS, json!({})))
                    .await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn simulate_ok() {
        let r = fcp_async_core::runtime::block_on_sync(async {
            GcpConnector::new()
                .simulate(SimulateRequest::new(
                    ConnectorId::from_static("fcp.gcp"),
                    OperationId::from_static(OP_COMPUTE_LIST_INSTANCES),
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
                GcpConnector::new()
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
            let mut c = GcpConnector::new();
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
            let mut c = GcpConnector::new();
            c.configure(tc()).await.unwrap();
            c.handshake(handshake_req()).await.unwrap()
        })
        .unwrap();
        assert_eq!(r.status, "accepted");
        assert_eq!(r.capabilities_granted.len(), 3);
    }

    #[test]
    fn require_str_ok() {
        assert_eq!(
            GcpConnector::require_str(&json!({"k": "v"}), "k").unwrap(),
            "v"
        );
    }

    #[test]
    fn require_str_miss() {
        assert!(GcpConnector::require_str(&json!({}), "k").is_err());
    }

    #[test]
    fn require_str_empty() {
        assert!(GcpConnector::require_str(&json!({"k": ""}), "k").is_err());
        assert!(GcpConnector::require_str(&json!({"k": "  "}), "k").is_err());
    }

    #[test]
    fn service_account_auth_rejects_invalid_pem() {
        let result = fcp_async_core::runtime::block_on_sync(async {
            let mut c = GcpConnector::new();
            c.configure(json!({
                "mode": "service_account",
                "client_email": "svc@proj.iam.gserviceaccount.com",
                "private_key": "not-a-valid-pem",
                "project_id": "proj"
            }))
            .await
        })
        .unwrap();
        // Client init wraps GcpError::Config as FcpError::Internal
        match result {
            Err(err) => {
                let msg = err.to_string();
                assert!(
                    msg.contains("private key"),
                    "error should mention private key: {msg}"
                );
            }
            other => panic!("expected error for bad PEM, got {other:?}"),
        }
    }

    #[test]
    fn service_account_auth_accepts_valid_key() {
        use rsa::pkcs8::EncodePrivateKey;
        let mut rng = rand::thread_rng();
        let key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("key gen");
        let pem = key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .expect("PEM")
            .to_string();

        let result = fcp_async_core::runtime::block_on_sync(async {
            let mut c = GcpConnector::new();
            c.configure(json!({
                "mode": "service_account",
                "client_email": "svc@proj.iam.gserviceaccount.com",
                "private_key": pem,
                "project_id": "proj"
            }))
            .await
        })
        .unwrap();
        assert!(
            result.is_ok(),
            "valid service-account key should configure successfully"
        );
    }

    #[test]
    fn health_unconfigured() {
        let h =
            fcp_async_core::runtime::block_on_sync(async { GcpConnector::new().health().await })
                .unwrap();
        assert!(matches!(h.status, fcp_core::HealthState::Degraded { .. }));
    }

    #[test]
    fn health_configured() {
        let h = fcp_async_core::runtime::block_on_sync(async {
            let mut c = GcpConnector::new();
            c.configure(tc()).await.unwrap();
            c.health().await
        })
        .unwrap();
        assert!(matches!(h.status, fcp_core::HealthState::Ready));
    }

    #[test]
    fn doctor_has_all_checks() {
        let d = fcp_async_core::runtime::block_on_sync(async {
            let mut c = GcpConnector::new();
            c.configure(tc()).await.unwrap();
            c.doctor()
        })
        .unwrap();
        assert!(d.checks.len() >= 7);
        let names: Vec<&str> = d.checks.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"configuration"));
        assert!(names.contains(&"client_initialized"));
        assert!(names.contains(&"project_id"));
        assert!(names.contains(&"auth_mode"));
    }

    #[test]
    fn self_check_unconfigured() {
        let r = fcp_async_core::runtime::block_on_sync(async {
            GcpConnector::new().self_check().await
        })
        .unwrap()
        .unwrap();
        assert_eq!(r.reason_code.as_deref(), Some("not_configured"));
    }

    #[test]
    fn endpoint_policy_default() {
        let policy = endpoint_policy("compute", &None, COMPUTE_API_HOST);
        assert!(policy.ok);
        assert!(!policy.override_configured);
        assert!(policy.message.contains("default"));
    }

    #[test]
    fn endpoint_policy_localhost() {
        let policy = endpoint_policy(
            "storage",
            &Some("http://localhost:8080".into()),
            STORAGE_API_HOST,
        );
        assert!(policy.ok);
        assert!(policy.message.contains("localhost"));
    }

    #[test]
    fn endpoint_policy_invalid_scheme() {
        let policy = endpoint_policy(
            "compute",
            &Some("http://compute.googleapis.com".into()),
            COMPUTE_API_HOST,
        );
        assert!(!policy.ok);
        assert!(policy.message.contains("scheme must be https"));
    }

    #[test]
    fn endpoint_policy_valid() {
        let policy = endpoint_policy(
            "compute",
            &Some("https://compute.googleapis.com".into()),
            COMPUTE_API_HOST,
        );
        assert!(policy.ok);
    }

    #[test]
    fn endpoint_policy_rejects_pathful_google_api_override() {
        let policy = endpoint_policy(
            "compute",
            &Some("https://compute.googleapis.com/compute/v1".into()),
            COMPUTE_API_HOST,
        );
        assert!(!policy.ok);
        assert!(policy.message.contains("path must be empty"));
    }

    #[test]
    fn endpoint_policy_wrong_service_host() {
        let policy = endpoint_policy(
            "storage",
            &Some("https://compute.googleapis.com".into()),
            STORAGE_API_HOST,
        );
        assert!(!policy.ok);
        assert!(policy.message.contains(STORAGE_API_HOST));
    }

    #[test]
    fn provisioning_readiness_rejects_invalid_auxiliary_endpoint() {
        let config = GcpConfig {
            project_id: "test-project".into(),
            auth: GcpAuth::AccessToken {
                access_token: "ya29.test".into(),
            },
            retry: HttpRetryConfig::default(),
            request_timeout_ms: default_timeout_ms(),
            compute_base_url: None,
            storage_base_url: Some("https://compute.googleapis.com".into()),
            run_base_url: None,
            crm_base_url: None,
        };

        let readiness = config.provisioning_readiness();
        assert!(!readiness.network_ok);
        assert!(readiness.network_message.contains("storage"));
        assert!(
            readiness
                .service_endpoints
                .iter()
                .any(|endpoint| endpoint.service == "storage" && !endpoint.ok)
        );
    }

    #[test]
    fn config_validation_rejects_invalid_auxiliary_endpoint() {
        let config = GcpConfig {
            project_id: "test-project".into(),
            auth: GcpAuth::AccessToken {
                access_token: "ya29.test".into(),
            },
            retry: HttpRetryConfig::default(),
            request_timeout_ms: default_timeout_ms(),
            compute_base_url: None,
            storage_base_url: Some("https://compute.googleapis.com".into()),
            run_base_url: None,
            crm_base_url: None,
        };

        let err = config
            .validate()
            .expect_err("cross-wired endpoint must be rejected");
        assert!(err.contains("storage"));
    }

    #[test]
    fn health_details_include_guidance_and_verification_metadata() {
        let details = fcp_async_core::runtime::block_on_sync(async {
            GcpConnector::new()
                .health()
                .await
                .details
                .expect("health details")
        })
        .unwrap();
        assert!(details["operator_guidance"]["prerequisites"].is_array());
        assert_eq!(
            details["verification_script"],
            "scripts/e2e/gcp_connector_verification.sh"
        );
        assert_eq!(
            details["artifact_root_hint"],
            "artifacts/e2e/gcp_connector/<timestamp>"
        );
    }

    #[test]
    fn operations_count() {
        assert_eq!(operations_info().len(), 14);
    }

    #[test]
    fn operation_ids_unique() {
        let ops = operations_info();
        let mut ids: Vec<&str> = ops.iter().map(|o| o.id.as_str()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 14);
    }

    #[test]
    fn compute_ops_use_compute_caps() {
        let ops = operations_info();
        for op in &ops {
            if op.id.as_str().starts_with("gcp.compute.") {
                assert!(
                    op.capability.as_str().starts_with("gcp.compute."),
                    "op {} has capability {}",
                    op.id,
                    op.capability
                );
            }
        }
    }

    #[test]
    fn storage_ops_use_storage_caps() {
        let ops = operations_info();
        for op in &ops {
            if op.id.as_str().starts_with("gcp.storage.") {
                assert!(
                    op.capability.as_str().starts_with("gcp.storage."),
                    "op {} has capability {}",
                    op.id,
                    op.capability
                );
            }
        }
    }

    #[test]
    fn run_ops_use_run_caps() {
        let ops = operations_info();
        for op in &ops {
            if op.id.as_str().starts_with("gcp.run.") {
                assert!(
                    op.capability.as_str().starts_with("gcp.run."),
                    "op {} has capability {}",
                    op.id,
                    op.capability
                );
            }
        }
    }

    #[test]
    fn invoke_not_configured_fails() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let c = GcpConnector::new();
                c.invoke(invoke_req(
                    OP_COMPUTE_LIST_INSTANCES,
                    json!({"zone": "us-central1-a"}),
                ))
                .await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn event_caps_no_streaming() {
        let intro = GcpConnector::new().introspect();
        let caps = intro.event_caps.unwrap();
        assert!(!caps.streaming);
        assert!(!caps.replay);
    }

    #[test]
    fn connector_id() {
        let c = GcpConnector::new();
        assert_eq!(c.id().as_str(), "fcp.gcp");
    }

    #[test]
    fn handshake_grants_all_requested() {
        let r = fcp_async_core::runtime::block_on_sync(async {
            let mut c = GcpConnector::new();
            c.configure(tc()).await.unwrap();
            let mut req = handshake_req();
            req.capabilities_requested = vec![
                CapabilityId::from_static(CAP_COMPUTE_READ),
                CapabilityId::from_static(CAP_STORAGE_READ),
                CapabilityId::from_static(CAP_RUN_READ),
                CapabilityId::from_static(CAP_IAM_READ),
            ];
            c.handshake(req).await.unwrap()
        })
        .unwrap();
        assert_eq!(r.capabilities_granted.len(), 4);
    }

    #[test]
    fn doctor_unconfigured_is_unhealthy() {
        let d = GcpConnector::new().doctor();
        assert!(!d.ready);
        assert!(matches!(d.status, DoctorStatus::Unhealthy));
    }

    #[test]
    fn manifest_hash_not_empty() {
        let hash = GcpConnector::manifest_hash();
        assert!(hash.starts_with("sha256:"));
        assert!(hash.len() > 10);
    }
}
