//! Docker Hub connector implementation.

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

use crate::client::DockerHubClient;
use crate::types::{CreateRepositoryRequest, DockerHubAuth};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const DOCKERHUB_ALLOWED_HOSTS: &[&str] = &["hub.docker.com"];

const OP_REPOS_LIST: &str = "dockerhub.repos.list";
const OP_REPOS_GET: &str = "dockerhub.repos.get";
const OP_REPOS_CREATE: &str = "dockerhub.repos.create";
const OP_REPOS_DELETE: &str = "dockerhub.repos.delete";
const OP_TAGS_LIST: &str = "dockerhub.tags.list";
const OP_TAGS_GET: &str = "dockerhub.tags.get";
const OP_TAGS_DELETE: &str = "dockerhub.tags.delete";
const OP_ORGS_LIST: &str = "dockerhub.orgs.list";
const OP_HEALTH: &str = "dockerhub.health";

const CAP_REPOS_READ: &str = "dockerhub.repos.read";
const CAP_REPOS_WRITE: &str = "dockerhub.repos.write";
const CAP_ORGS_READ: &str = "dockerhub.orgs.read";

#[derive(Clone, serde::Deserialize)]
pub struct DockerHubConfig {
    #[serde(default = "default_base_url")]
    pub base_url: String,
    #[serde(flatten)]
    pub auth: DockerHubAuth,
    #[serde(default)]
    pub retry: HttpRetryConfig,
    #[serde(default = "default_timeout_ms")]
    pub request_timeout_ms: u64,
    /// Default namespace for listing repos (usually Docker Hub username).
    #[serde(default)]
    pub namespace: Option<String>,
}
fn default_base_url() -> String {
    "https://hub.docker.com".into()
}
const fn default_timeout_ms() -> u64 {
    30_000
}

impl std::fmt::Debug for DockerHubConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DockerHubConfig")
            .field("base_url", &self.base_url)
            .field("auth", &self.auth)
            .field("retry", &self.retry)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .field("namespace", &self.namespace)
            .finish()
    }
}

impl DockerHubConfig {
    fn validate(&self) -> Result<(), String> {
        if self.base_url.is_empty() {
            return Err("base_url cannot be empty".into());
        }
        Ok(())
    }

    fn from_value(val: serde_json::Value) -> FcpResult<Self> {
        let config: Self = serde_json::from_value(val).map_err(|e| FcpError::InvalidRequest {
            code: 1001,
            message: format!("Invalid configuration: {e}"),
        })?;
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
            credential_material_configured: !self.auth.is_secretless(),
            requires_credential_injection: self.auth.is_secretless(),
            network_ok,
            network_message,
            base_url: self.base_url.clone(),
            allowed_hosts: DOCKERHUB_ALLOWED_HOSTS.to_vec(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct ProvisioningReadiness {
    auth_mode: &'static str,
    credential_material_configured: bool,
    requires_credential_injection: bool,
    network_ok: bool,
    network_message: String,
    base_url: String,
    allowed_hosts: Vec<&'static str>,
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
            format!("localhost test endpoint accepted: {base_url}"),
        );
    }

    let mut problems = Vec::new();
    if parsed.scheme() != "https" {
        problems.push(format!("scheme must be https, got {}", parsed.scheme()));
    }
    if !DOCKERHUB_ALLOWED_HOSTS.contains(&host) {
        problems.push(format!(
            "host must be one of {DOCKERHUB_ALLOWED_HOSTS:?}, got {host}"
        ));
    }

    if problems.is_empty() {
        (true, "Docker Hub production API endpoint accepted".into())
    } else {
        (false, problems.join("; "))
    }
}

#[derive(Debug)]
pub struct DockerHubConnector {
    base: BaseConnector,
    config: Option<DockerHubConfig>,
    client: Option<DockerHubClient>,
    runtime: Option<ConnectorRuntime>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl DockerHubConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.dockerhub")),
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
            .map(DockerHubConfig::provisioning_readiness);
        let mut checks = Vec::new();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: if self.config.is_some() {
                None
            } else {
                Some("Not configured; run configure first".into())
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
                name: "auth_mode".into(),
                passed: true,
                message: Some(format!("Auth mode: {}", readiness.auth_mode)),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "credential_material".into(),
                passed: readiness.credential_material_configured,
                message: Some(if readiness.credential_material_configured {
                    "Credential material configured".into()
                } else {
                    "Credentials omitted; inject at runtime".into()
                }),
                critical: false,
            });
        }
        DoctorResult::from_checks(checks, provisioning)
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

    fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
        let capability = match operation {
            OP_REPOS_LIST | OP_REPOS_GET | OP_TAGS_LIST | OP_TAGS_GET | OP_HEALTH => CAP_REPOS_READ,
            OP_REPOS_CREATE | OP_REPOS_DELETE | OP_TAGS_DELETE => CAP_REPOS_WRITE,
            OP_ORGS_LIST => CAP_ORGS_READ,
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };
        Ok(CapabilityId::from_static(capability))
    }
}

impl Default for DockerHubConnector {
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
        OperationInfo {
            id: OperationId::from_static(OP_REPOS_LIST),
            summary: "List repositories".into(),
            description: None,
            input_schema: json!({"type":"object","required":["namespace"]}),
            output_schema: json!({"type":"array"}),
            capability: CapabilityId::from_static(CAP_REPOS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "List Docker Hub repos for a namespace",
                vec!["Requires namespace (username or org)".into()],
                vec![],
                vec![CAP_REPOS_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_REPOS_GET),
            summary: "Get repository details".into(),
            description: None,
            input_schema: json!({"type":"object","required":["namespace","name"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_REPOS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "Get details for a specific repository",
                vec![],
                vec![],
                vec![CAP_REPOS_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_REPOS_CREATE),
            summary: "Create a repository".into(),
            description: None,
            input_schema: json!({"type":"object","required":["namespace","name"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_REPOS_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Create new Docker Hub repository",
                vec![],
                vec![],
                vec![CAP_REPOS_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_REPOS_DELETE),
            summary: "Delete a repository".into(),
            description: None,
            input_schema: json!({"type":"object","required":["namespace","name"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_REPOS_WRITE),
            risk_level: RiskLevel::Critical,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Permanently delete repo and all tags",
                vec!["Irreversible".into()],
                vec![],
                vec![CAP_REPOS_READ],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        OperationInfo {
            id: OperationId::from_static(OP_TAGS_LIST),
            summary: "List tags for a repository".into(),
            description: None,
            input_schema: json!({"type":"object","required":["namespace","name"]}),
            output_schema: json!({"type":"array"}),
            capability: CapabilityId::from_static(CAP_REPOS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "List all tags for a repo",
                vec![],
                vec![],
                vec![CAP_REPOS_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_TAGS_GET),
            summary: "Get tag details".into(),
            description: None,
            input_schema: json!({"type":"object","required":["namespace","name","tag"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_REPOS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "Get details for a specific tag",
                vec![],
                vec![],
                vec![CAP_REPOS_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_TAGS_DELETE),
            summary: "Delete a tag".into(),
            description: None,
            input_schema: json!({"type":"object","required":["namespace","name","tag"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_REPOS_WRITE),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Delete a tag from a repository",
                vec!["Pulls targeting this tag will fail".into()],
                vec![],
                vec![CAP_REPOS_READ],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        OperationInfo {
            id: OperationId::from_static(OP_ORGS_LIST),
            summary: "List organizations".into(),
            description: None,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"array"}),
            capability: CapabilityId::from_static(CAP_ORGS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "List user's Docker Hub organizations",
                vec![],
                vec![],
                vec![],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_HEALTH),
            summary: "Verify API credentials".into(),
            description: None,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_REPOS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint("Check Docker Hub credentials", vec![], vec![], vec![]),
            rate_limit: None,
            requires_approval: None,
        },
    ]
}

fcp_core::impl_fcp_sealed!(DockerHubConnector);

#[async_trait]
impl FcpConnector for DockerHubConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let cfg = DockerHubConfig::from_value(config)?;
        let runtime = ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(cfg.request_timeout_ms)),
        );
        let mut client = DockerHubClient::new(&cfg.base_url, cfg.auth.clone(), cfg.retry.clone())
            .map_err(|e| FcpError::Internal {
            message: format!("Client init: {e}"),
        })?;

        // If credentials-based auth, attempt login to get JWT
        if matches!(cfg.auth, DockerHubAuth::Credentials { .. }) && !cfg.auth.is_secretless() {
            let _ = client.login(&runtime).await; // Best-effort login
        }

        self.runtime = Some(runtime);
        self.client = Some(client);
        self.config = Some(cfg);
        self.verifier = None;
        self.base.set_configured(true);
        self.base.set_handshaken(false);
        info!(
            event = "dockerhub.configure",
            "Configured Docker Hub connector"
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
            .map(DockerHubConfig::provisioning_readiness);
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
            "manifest_hash": Self::manifest_hash(),
        }));
        snap
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(config) = &self.config else {
            return Ok(SelfCheckReport::degraded(
                "not_configured",
                "Connector is not configured",
            ));
        };
        let provisioning = config.provisioning_readiness();

        if !provisioning.network_ok {
            return Ok(SelfCheckReport::failed(
                "network_constraints_invalid",
                provisioning.network_message.clone(),
            ));
        }

        let Some(client) = &self.client else {
            return Ok(SelfCheckReport::failed(
                "client_missing",
                "HTTP client not initialized",
            ));
        };
        let Some(runtime) = &self.runtime else {
            return Ok(SelfCheckReport::failed(
                "runtime_missing",
                "ConnectorRuntime not initialized",
            ));
        };

        if provisioning.requires_credential_injection {
            return Ok(SelfCheckReport::degraded(
                "credential_injection_required",
                "Credentials omitted; inject at runtime",
            ));
        }

        let report = match client.health_check(runtime).await {
            Ok(_user) => SelfCheckReport::ok(),
            Err(error) if error.is_retryable() => {
                SelfCheckReport::degraded("self_check_retryable", error.to_string())
            }
            Err(error) => SelfCheckReport::failed("self_check_failed", error.to_string()),
        };
        Ok(report)
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        let capability = match Self::required_capability(req.operation.as_str()) {
            Ok(capability) => capability,
            Err(error) => {
                return Ok(SimulateResponse::denied(
                    req.id,
                    error.to_string(),
                    error.error_code(),
                ));
            }
        };

        if self.config.is_none() || self.client.is_none() || self.runtime.is_none() {
            return Ok(SimulateResponse::denied(
                req.id,
                "Connector is not configured",
                FcpError::NotConfigured.error_code(),
            ));
        }

        let Some(verifier) = &self.verifier else {
            return Ok(SimulateResponse::denied(
                req.id,
                "Connector handshake not completed",
                FcpError::NotHandshaken.error_code(),
            ));
        };

        if let Err(error) =
            verifier.verify_bound(req.capability_token, &capability, &req.operation, &[])
        {
            let mut response =
                SimulateResponse::denied(req.id, error.to_string(), error.error_code());
            if error.error_code() == "FCP-3001" {
                response =
                    response.with_missing_capabilities(vec![capability.as_str().to_string()]);
            }
            return Ok(response);
        }

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

impl DockerHubConnector {
    #[allow(clippy::too_many_lines)]
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();
        if let Some(verifier) = &self.verifier {
            let cap = Self::required_capability(operation)?;
            verifier.verify_bound(req.capability_token, &cap, &req.operation, &[])?;
        } else {
            return Err(FcpError::Internal {
                message: "connector ready state missing capability verifier".into(),
            });
        }

        let runtime = self.runtime.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing runtime".into(),
        })?;
        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing Docker Hub client".into(),
        })?;

        let output = match operation {
            OP_REPOS_LIST => {
                let namespace = Self::require_str(&req.input, "namespace")?;
                let repos = client
                    .list_repos(runtime, namespace)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&repos).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_REPOS_GET => {
                let namespace = Self::require_str(&req.input, "namespace")?;
                let name = Self::require_str(&req.input, "name")?;
                let repo = client
                    .get_repo(runtime, namespace, name)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&repo).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_REPOS_CREATE => {
                let namespace = Self::require_str(&req.input, "namespace")?;
                let name = Self::require_str(&req.input, "name")?;
                let create_req = CreateRepositoryRequest {
                    namespace: namespace.into(),
                    name: name.into(),
                    description: req
                        .input
                        .get("description")
                        .and_then(serde_json::Value::as_str)
                        .map(String::from),
                    is_private: req
                        .input
                        .get("is_private")
                        .and_then(serde_json::Value::as_bool),
                    full_description: req
                        .input
                        .get("full_description")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                };
                let repo = client
                    .create_repo(runtime, &create_req)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&repo).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_REPOS_DELETE => {
                let namespace = Self::require_str(&req.input, "namespace")?;
                let name = Self::require_str(&req.input, "name")?;
                client
                    .delete_repo(runtime, namespace, name)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({"deleted": true, "namespace": namespace, "name": name})
            }
            OP_TAGS_LIST => {
                let namespace = Self::require_str(&req.input, "namespace")?;
                let name = Self::require_str(&req.input, "name")?;
                let tags = client
                    .list_tags(runtime, namespace, name)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&tags).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_TAGS_GET => {
                let namespace = Self::require_str(&req.input, "namespace")?;
                let name = Self::require_str(&req.input, "name")?;
                let tag = Self::require_str(&req.input, "tag")?;
                let result = client
                    .get_tag(runtime, namespace, name, tag)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&result).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_TAGS_DELETE => {
                let namespace = Self::require_str(&req.input, "namespace")?;
                let name = Self::require_str(&req.input, "name")?;
                let tag = Self::require_str(&req.input, "tag")?;
                client
                    .delete_tag(runtime, namespace, name, tag)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({"deleted": true, "namespace": namespace, "name": name, "tag": tag})
            }
            OP_ORGS_LIST => {
                let orgs = client
                    .list_orgs(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&orgs).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_HEALTH => {
                let user = client
                    .health_check(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({"healthy": true, "user_id": user.id, "username": user.username})
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
    use chrono::{Duration as ChronoDuration, Utc};
    use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
    use fcp_prelude::{CapabilityConstraints, CapabilityToken, ZoneId};

    use super::*;

    type TestCapability = CapabilityToken;

    fn handshake_request(
        host_public_key: [u8; 32],
        capabilities_requested: Vec<CapabilityId>,
    ) -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key,
            nonce: [7u8; 32],
            capabilities_requested,
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        }
    }

    fn capability_token(
        signing_key: &Ed25519SigningKey,
        capability: &'static str,
        operation: &'static str,
        instance_id: &str,
    ) -> CapabilityToken {
        let now = Utc::now();
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
        let raw = CapabilityTokenBuilder::new()
            .capability_id(capability)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[operation])
            .issuer("node:test")
            .validity(now, now + ChronoDuration::hours(1))
            .target_instance(instance_id)
            .try_constraints_cbor(&cbor)
            .expect("constraints CBOR should validate")
            .sign(signing_key)
            .expect("token should sign");
        CapabilityToken::from_raw(raw)
    }

    fn configure_and_handshake(
        connector: &mut DockerHubConnector,
        capabilities_requested: Vec<CapabilityId>,
    ) -> Ed25519SigningKey {
        fcp_async_core::runtime::block_on_sync(connector.configure(json!({
            "mode": "token",
            "access_token": "fixture-pat-value",
            "base_url": "http://localhost:8080"
        })))
        .expect("configure future should complete")
        .expect("configure should succeed");

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        fcp_async_core::runtime::block_on_sync(connector.handshake(handshake_request(
            verifying_key.to_bytes(),
            capabilities_requested,
        )))
        .expect("handshake future should complete")
        .expect("handshake should succeed");
        signing_key
    }

    #[test]
    fn connector_id() {
        let c = DockerHubConnector::new();
        assert_eq!(c.id().as_str(), "fcp.dockerhub");
    }

    #[test]
    fn default_matches_new() {
        let c1 = DockerHubConnector::new();
        let c2 = DockerHubConnector::default();
        assert_eq!(c1.id(), c2.id());
    }

    #[test]
    fn operations_info_count() {
        let ops = operations_info();
        assert_eq!(ops.len(), 9);
    }

    #[test]
    fn operations_have_unique_ids() {
        let ops = operations_info();
        let mut ids: Vec<_> = ops.iter().map(|o| o.id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 9);
    }

    #[test]
    fn repos_list_is_safe() {
        let ops = operations_info();
        let op = ops.iter().find(|o| o.id.as_str() == OP_REPOS_LIST).unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Safe);
        assert_eq!(op.risk_level, RiskLevel::Low);
    }

    #[test]
    fn repos_delete_is_dangerous() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|o| o.id.as_str() == OP_REPOS_DELETE)
            .unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Dangerous);
        assert_eq!(op.risk_level, RiskLevel::Critical);
        assert_eq!(op.requires_approval, Some(ApprovalMode::Interactive));
    }

    #[test]
    fn repos_create_is_risky() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|o| o.id.as_str() == OP_REPOS_CREATE)
            .unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Risky);
        assert_eq!(op.risk_level, RiskLevel::Medium);
    }

    #[test]
    fn tags_delete_is_dangerous() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|o| o.id.as_str() == OP_TAGS_DELETE)
            .unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Dangerous);
        assert_eq!(op.requires_approval, Some(ApprovalMode::Interactive));
    }

    #[test]
    fn tags_list_is_safe() {
        let ops = operations_info();
        let op = ops.iter().find(|o| o.id.as_str() == OP_TAGS_LIST).unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Safe);
        assert_eq!(op.risk_level, RiskLevel::Low);
    }

    #[test]
    fn orgs_list_is_safe() {
        let ops = operations_info();
        let op = ops.iter().find(|o| o.id.as_str() == OP_ORGS_LIST).unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Safe);
        assert_eq!(op.capability, CapabilityId::from_static(CAP_ORGS_READ));
    }

    #[test]
    fn health_op_is_safe() {
        let ops = operations_info();
        let op = ops.iter().find(|o| o.id.as_str() == OP_HEALTH).unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Safe);
        assert_eq!(op.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn introspect_returns_operations() {
        let c = DockerHubConnector::new();
        let intro = c.introspect();
        assert_eq!(intro.operations.len(), 9);
        assert!(intro.events.is_empty());
    }

    #[test]
    fn introspect_event_caps() {
        let c = DockerHubConnector::new();
        let intro = c.introspect();
        let ec = intro.event_caps.unwrap();
        assert!(!ec.streaming);
        assert!(!ec.replay);
    }

    #[test]
    fn doctor_unconfigured_is_unhealthy() {
        let c = DockerHubConnector::new();
        let result = c.doctor();
        assert!(!result.ready);
        assert!(matches!(result.status, DoctorStatus::Unhealthy));
    }

    #[test]
    fn manifest_hash_is_deterministic() {
        let h1 = DockerHubConnector::manifest_hash();
        let h2 = DockerHubConnector::manifest_hash();
        assert_eq!(h1, h2);
        assert!(h1.starts_with("sha256:"));
    }

    #[test]
    fn base_url_policy_accepts_production() {
        let (ok, _msg) = base_url_policy("https://hub.docker.com");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_rejects_http() {
        let (ok, msg) = base_url_policy("http://hub.docker.com");
        assert!(!ok);
        assert!(msg.contains("https"));
    }

    #[test]
    fn base_url_policy_accepts_localhost() {
        let (ok, _msg) = base_url_policy("http://localhost:8080");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_rejects_unknown_host() {
        let (ok, msg) = base_url_policy("https://evil.example.com");
        assert!(!ok);
        assert!(msg.contains("evil.example.com"));
    }

    #[test]
    fn config_validates_empty_base_url() {
        let val = serde_json::json!({
            "mode": "token",
            "access_token": "tok",
            "base_url": ""
        });
        let result = DockerHubConfig::from_value(val);
        assert!(result.is_err());
    }

    #[test]
    fn config_from_value_valid_token() {
        let val = serde_json::json!({
            "mode": "token",
            "access_token": "fixture-pat-value",
            "base_url": "https://hub.docker.com"
        });
        let config = DockerHubConfig::from_value(val).unwrap();
        assert_eq!(config.base_url, "https://hub.docker.com");
        assert!(!config.auth.is_secretless());
    }

    #[test]
    fn config_from_value_valid_credentials() {
        let val = serde_json::json!({
            "mode": "credentials",
            "username": "user",
            "password": "pass",
            "base_url": "https://hub.docker.com"
        });
        let config = DockerHubConfig::from_value(val).unwrap();
        assert_eq!(config.auth.auth_mode(), "credentials");
    }

    #[test]
    fn config_default_base_url() {
        let val = serde_json::json!({
            "mode": "token",
            "access_token": "fixture-pat-value"
        });
        let config = DockerHubConfig::from_value(val).unwrap();
        assert_eq!(config.base_url, "https://hub.docker.com");
    }

    #[test]
    fn provisioning_readiness_with_token() {
        let val = serde_json::json!({
            "mode": "token",
            "access_token": "fixture-pat-value"
        });
        let config = DockerHubConfig::from_value(val).unwrap();
        let readiness = config.provisioning_readiness();
        assert!(readiness.credential_material_configured);
        assert!(!readiness.requires_credential_injection);
        assert!(readiness.network_ok);
    }

    #[test]
    fn provisioning_readiness_without_token() {
        let val = serde_json::json!({
            "mode": "token",
            "access_token": ""
        });
        let config = DockerHubConfig::from_value(val).unwrap();
        let readiness = config.provisioning_readiness();
        assert!(!readiness.credential_material_configured);
        assert!(readiness.requires_credential_injection);
    }

    #[test]
    fn require_str_missing_key() {
        let input = json!({});
        let result = DockerHubConnector::require_str(&input, "namespace");
        assert!(result.is_err());
    }

    #[test]
    fn require_str_present() {
        let input = json!({"namespace": "myuser"});
        let result = DockerHubConnector::require_str(&input, "namespace");
        assert_eq!(result.unwrap(), "myuser");
    }

    #[test]
    fn require_str_empty() {
        assert!(DockerHubConnector::require_str(&json!({"k": ""}), "k").is_err());
        assert!(DockerHubConnector::require_str(&json!({"k": "  "}), "k").is_err());
    }

    #[test]
    fn health_configured_but_secretless() {
        let c = DockerHubConnector::new();
        let snap = fcp_async_core::runtime::block_on_sync(c.health()).unwrap();
        assert_eq!(snap.status.as_str(), "degraded");
    }

    #[test]
    fn self_check_unconfigured() {
        let c = DockerHubConnector::new();
        let report = fcp_async_core::runtime::block_on_sync(c.self_check())
            .unwrap()
            .unwrap();
        assert_eq!(report.reason_code.as_deref(), Some("not_configured"));
    }

    #[test]
    fn simulate_returns_allowed() {
        let mut c = DockerHubConnector::new();
        let signing_key =
            configure_and_handshake(&mut c, vec![CapabilityId::from_static(CAP_REPOS_READ)]);
        let capability: TestCapability = capability_token(
            &signing_key,
            CAP_REPOS_READ,
            OP_REPOS_LIST,
            c.base.instance_id.as_str(),
        );
        let req = SimulateRequest::new(
            ConnectorId::from_static("fcp.dockerhub"),
            OperationId::from_static(OP_REPOS_LIST),
            ZoneId::try_from("z:work".to_string()).unwrap(),
            json!({}),
            capability,
        );
        let req_id = req.id.clone();
        let resp = fcp_async_core::runtime::block_on_sync(c.simulate(req))
            .unwrap()
            .unwrap();
        assert_eq!(resp.id, req_id);
        assert!(resp.would_succeed);
    }

    #[test]
    fn simulate_denies_wrong_operation_token() {
        let mut c = DockerHubConnector::new();
        let signing_key =
            configure_and_handshake(&mut c, vec![CapabilityId::from_static(CAP_REPOS_READ)]);
        let capability: TestCapability = capability_token(
            &signing_key,
            CAP_REPOS_READ,
            OP_TAGS_LIST,
            c.base.instance_id.as_str(),
        );
        let req = SimulateRequest::new(
            ConnectorId::from_static("fcp.dockerhub"),
            OperationId::from_static(OP_REPOS_LIST),
            ZoneId::try_from("z:work".to_string()).unwrap(),
            json!({}),
            capability,
        );

        let resp = fcp_async_core::runtime::block_on_sync(c.simulate(req))
            .unwrap()
            .unwrap();

        assert!(!resp.would_succeed);
        assert_eq!(resp.denial_code.as_deref(), Some("FCP-3003"));
    }

    #[test]
    fn simulate_denies_before_configure() {
        let c = DockerHubConnector::new();
        let req = SimulateRequest::new(
            ConnectorId::from_static("fcp.dockerhub"),
            OperationId::from_static(OP_REPOS_LIST),
            ZoneId::try_from("z:work".to_string()).unwrap(),
            json!({}),
            CapabilityToken::test_token(),
        );

        let resp = fcp_async_core::runtime::block_on_sync(c.simulate(req))
            .unwrap()
            .unwrap();

        assert!(!resp.would_succeed);
        assert_eq!(resp.denial_code.as_deref(), Some("FCP-5002"));
    }

    #[test]
    fn shutdown_clears_state() {
        let mut c = DockerHubConnector::new();
        let req = ShutdownRequest {
            r#type: "shutdown".into(),
            deadline_ms: 5000,
            drain: false,
            reason: Some("test".into()),
        };
        let result = fcp_async_core::runtime::block_on_sync(c.shutdown(req)).unwrap();
        assert!(result.is_ok());
        assert!(!c.base.configured.load(Ordering::Acquire));
    }

    #[test]
    fn metrics_initial_state() {
        let c = DockerHubConnector::new();
        let m = c.metrics();
        assert_eq!(m.requests_total, 0);
        assert_eq!(m.requests_error, 0);
    }

    #[test]
    fn repos_get_is_safe() {
        let ops = operations_info();
        let op = ops.iter().find(|o| o.id.as_str() == OP_REPOS_GET).unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Safe);
    }

    #[test]
    fn tags_get_is_safe() {
        let ops = operations_info();
        let op = ops.iter().find(|o| o.id.as_str() == OP_TAGS_GET).unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Safe);
    }
}
