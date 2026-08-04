//! CircleCI connector implementation.

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcp_manifest::{ConnectorManifest, ManifestApprovalMode, OperationSection};
use fcp_prelude::{
    ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier, ConnectorId,
    EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse, HealthSnapshot,
    Introspection, InvokeRequest, InvokeResponse, OperationId, OperationInfo, SelfCheckReport,
    SessionId, ShutdownRequest, SimulateRequest, SimulateResponse,
};
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::prelude::*;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::Url;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{client::CircleCiClient, error::Error as CircleCiError};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

// Operation IDs
const OP_PIPELINES_LIST: &str = "circleci.pipelines.list";
const OP_PIPELINES_GET: &str = "circleci.pipelines.get";
const OP_PIPELINES_TRIGGER: &str = "circleci.pipelines.trigger";
const OP_WORKFLOWS_LIST: &str = "circleci.workflows.list";
const OP_WORKFLOWS_GET: &str = "circleci.workflows.get";
const OP_WORKFLOWS_CANCEL: &str = "circleci.workflows.cancel";
const OP_WORKFLOWS_RERUN: &str = "circleci.workflows.rerun";
const OP_JOBS_LIST: &str = "circleci.jobs.list";
const OP_JOBS_GET: &str = "circleci.jobs.get";
const OP_PROJECTS_LIST: &str = "circleci.projects.list";
const OP_HEALTH: &str = "circleci.health";
const OPERATION_ORDER: [&str; 11] = [
    OP_PIPELINES_LIST,
    OP_PIPELINES_GET,
    OP_PIPELINES_TRIGGER,
    OP_WORKFLOWS_LIST,
    OP_WORKFLOWS_GET,
    OP_WORKFLOWS_CANCEL,
    OP_WORKFLOWS_RERUN,
    OP_JOBS_LIST,
    OP_JOBS_GET,
    OP_PROJECTS_LIST,
    OP_HEALTH,
];

// Capability IDs
const CAP_PIPELINES_READ: &str = "circleci.pipelines.read";
const CAP_PIPELINES_WRITE: &str = "circleci.pipelines.write";
const CAP_WORKFLOWS_READ: &str = "circleci.workflows.read";
const CAP_WORKFLOWS_WRITE: &str = "circleci.workflows.write";
const CAP_JOBS_READ: &str = "circleci.jobs.read";
const CAP_PROJECTS_READ: &str = "circleci.projects.read";

/// CircleCI connector configuration.
#[derive(Clone, Deserialize)]
struct CircleCiConfig {
    #[serde(default = "default_base_url")]
    base_url: String,
    api_token: String,
    #[serde(default)]
    retry: HttpRetryConfig,
    #[serde(default = "default_request_timeout_ms")]
    request_timeout_ms: u64,
}

impl std::fmt::Debug for CircleCiConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CircleCiConfig")
            .field("base_url", &self.base_url)
            .field("api_token", &"[REDACTED]")
            .field("retry", &self.retry)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

fn default_base_url() -> String {
    "https://circleci.com/api/v2".into()
}

const fn default_request_timeout_ms() -> u64 {
    30_000
}

const HOSTED_CIRCLECI_HOST: &str = "circleci.com";

impl CircleCiConfig {
    fn validate(mut self) -> Result<Self, String> {
        self.base_url = self.base_url.trim().trim_end_matches('/').to_string();
        if self.base_url.is_empty() {
            return Err("base_url must not be empty".into());
        }
        if self.request_timeout_ms == 0 {
            return Err("request_timeout_ms must be greater than 0".into());
        }

        let parsed = Url::parse(&self.base_url)
            .map_err(|error| format!("base_url must be a valid URL: {error}"))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| "base_url must include a host".to_string())?;
        let is_local_test_host = matches!(host, "localhost" | "127.0.0.1");

        match parsed.scheme() {
            "https" => Ok(self),
            "http" if is_local_test_host => Ok(self),
            scheme => Err(format!(
                "base_url must use https unless targeting a localhost test override (found scheme {scheme})"
            )),
        }
    }
}

fn base_url_manifest_alignment(base_url: &str) -> (bool, String) {
    let Ok(parsed) = Url::parse(base_url) else {
        return (false, format!("Invalid base_url: {base_url}"));
    };
    let Some(host) = parsed.host_str() else {
        return (false, format!("base_url {base_url} is missing a host"));
    };

    if host == HOSTED_CIRCLECI_HOST {
        return (
            true,
            "Base URL matches the hosted CircleCI SaaS API policy.".into(),
        );
    }
    if matches!(host, "localhost" | "127.0.0.1") {
        return (
            true,
            "Base URL uses a localhost test override outside production policy.".into(),
        );
    }

    (
        false,
        format!(
            "Base URL host {host} is outside the first-slice manifest network policy ({HOSTED_CIRCLECI_HOST})."
        ),
    )
}

fn classify_self_check_error(error: &CircleCiError) -> (&'static str, bool) {
    match error {
        CircleCiError::RateLimited { .. } => ("circleci_rate_limited", true),
        CircleCiError::Unauthorized(_) => ("invalid_api_token", false),
        CircleCiError::Api { status: 403, .. } => ("permissions_or_scope_missing", false),
        CircleCiError::Api { status: 404, .. } => ("circleci_resource_not_found", false),
        CircleCiError::Api { status, .. } if (500..=599).contains(status) => {
            ("circleci_api_retryable", true)
        }
        CircleCiError::Http(_) | CircleCiError::Async(_) => ("self_check_retryable", true),
        CircleCiError::Json(_) => ("response_decode_failed", false),
        CircleCiError::Config(_) => ("config_invalid", false),
        CircleCiError::InvalidInput(_) => ("invalid_input", false),
        CircleCiError::Api { .. } => ("self_check_failed", false),
    }
}

fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
    let capability = match operation {
        OP_PIPELINES_LIST | OP_PIPELINES_GET => CAP_PIPELINES_READ,
        OP_PIPELINES_TRIGGER => CAP_PIPELINES_WRITE,
        OP_WORKFLOWS_LIST | OP_WORKFLOWS_GET => CAP_WORKFLOWS_READ,
        OP_WORKFLOWS_CANCEL | OP_WORKFLOWS_RERUN => CAP_WORKFLOWS_WRITE,
        OP_JOBS_LIST | OP_JOBS_GET => CAP_JOBS_READ,
        OP_PROJECTS_LIST | OP_HEALTH => CAP_PROJECTS_READ,
        _ => {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: format!("Unknown operation: {operation}"),
            });
        }
    };
    Ok(CapabilityId::from_static(capability))
}

// Doctor types
#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorResult {
    pub passed: bool,
    pub checks: Vec<DoctorCheck>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorCheck {
    name: String,
    passed: bool,
    message: Option<String>,
    critical: bool,
}

impl DoctorResult {
    fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let passed = checks.iter().filter(|c| c.critical).all(|c| c.passed);
        Self { passed, checks }
    }
}

/// CircleCI connector state.
#[derive(Debug)]
pub struct CircleCiConnector {
    base: BaseConnector,
    config: Option<CircleCiConfig>,
    client: Option<CircleCiClient>,
    runtime: Option<ConnectorRuntime>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl CircleCiConnector {
    /// Create a new connector instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.circleci")),
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
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    /// Run connector diagnostics.
    pub fn doctor(&self) -> DoctorResult {
        let mut checks = Vec::new();

        let configured = self.config.is_some();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: configured,
            message: Some(if configured {
                "Configuration loaded".into()
            } else {
                "Not configured - run configure first".into()
            }),
            critical: true,
        });

        let client_ok = self.client.is_some();
        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            passed: client_ok,
            message: Some(if client_ok {
                "HTTP client initialized".into()
            } else {
                "HTTP client missing; re-run configure".into()
            }),
            critical: true,
        });

        let runtime_ok = self.runtime.is_some();
        checks.push(DoctorCheck {
            name: "runtime".into(),
            passed: runtime_ok,
            message: Some(if runtime_ok {
                "ConnectorRuntime initialized".into()
            } else {
                "Runtime missing".into()
            }),
            critical: true,
        });

        if let Some(config) = &self.config {
            let (host_ok, host_message) = base_url_manifest_alignment(&config.base_url);
            checks.push(DoctorCheck {
                name: "network_constraints".into(),
                passed: host_ok,
                message: Some(host_message),
                critical: true,
            });
            checks.push(DoctorCheck {
                name: "request_timeout_ms".into(),
                passed: config.request_timeout_ms > 0,
                message: Some(format!(
                    "HTTP client timeout is configured to {} ms",
                    config.request_timeout_ms
                )),
                critical: true,
            });

            let secretless = self.client.as_ref().is_some_and(|c| c.is_secretless());
            checks.push(DoctorCheck {
                name: "credential_mode".into(),
                passed: !secretless,
                message: Some(if secretless {
                    "Credential injection required via egress proxy before live health verification can pass".into()
                } else {
                    "API token configured".into()
                }),
                critical: false,
            });
        }

        DoctorResult::from_checks(checks)
    }
}

impl Default for CircleCiConnector {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the typed operations catalog.
pub fn operations_info() -> Vec<OperationInfo> {
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
        .expect("embedded CircleCI manifest should validate");
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
    Some(ApprovalMode::from(mode))
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

fcp_core::impl_fcp_sealed!(CircleCiConnector);

#[async_trait]
impl FcpConnector for CircleCiConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config: CircleCiConfig =
            serde_json::from_value(config).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid CircleCI config: {e}"),
            })?;
        let config = config
            .validate()
            .map_err(|message| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid CircleCI config: {message}"),
            })?;

        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(config.request_timeout_ms)),
        ));

        let client = CircleCiClient::new(
            &config.base_url,
            &config.api_token,
            config.retry.clone(),
            config.request_timeout_ms,
        )
        .map_err(|e| FcpError::Internal {
            message: format!("Failed to create CircleCI client: {e}"),
        })?;

        self.client = Some(client);
        self.config = Some(config);
        self.base.set_configured(true);
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        self.base.set_handshaken(true);
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let capabilities_granted = req
            .capabilities_requested
            .into_iter()
            .map(|cap| CapabilityGrant {
                capability: cap,
                operation: None,
            })
            .collect();

        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
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
        let mut snapshot = if let Some(config) = self.config.as_ref() {
            let credential_injection_required = self
                .client
                .as_ref()
                .is_some_and(|client| client.is_secretless());
            let (manifest_network_policy_aligned, manifest_network_policy_message) =
                base_url_manifest_alignment(&config.base_url);

            let mut snapshot = if credential_injection_required {
                HealthSnapshot::degraded("credential injection required")
            } else if manifest_network_policy_aligned {
                HealthSnapshot::ready()
            } else {
                HealthSnapshot::degraded("base_url outside manifest policy")
            };
            snapshot.details = Some(json!({
                "configured": true,
                "client_initialized": self.client.is_some(),
                "base_url": config.base_url.as_str(),
                "request_timeout_ms": config.request_timeout_ms,
                "auth_mode": if credential_injection_required { "credential_injection" } else { "api_token" },
                "credential_injection_required": credential_injection_required,
                "manifest_network_policy_aligned": manifest_network_policy_aligned,
                "manifest_network_policy_message": manifest_network_policy_message,
            }));
            snapshot
        } else {
            let mut snapshot = HealthSnapshot::degraded("not configured");
            snapshot.details = Some(json!({
                "configured": false,
                "client_initialized": false,
            }));
            snapshot
        };
        snapshot.uptime_ms =
            u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        snapshot
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(client) = &self.client else {
            return Ok(SelfCheckReport::degraded(
                "not_configured",
                "Connector is not configured",
            ));
        };

        let (manifest_network_policy_aligned, manifest_network_policy_message) =
            base_url_manifest_alignment(client.base_url());
        if !manifest_network_policy_aligned {
            let mut report = SelfCheckReport::degraded(
                "base_url_outside_manifest_policy",
                manifest_network_policy_message,
            );
            report.details = Some(json!({
                "base_url": client.base_url(),
                "auth_mode": if client.is_secretless() { "credential_injection" } else { "api_token" },
                "manifest_network_policy_aligned": manifest_network_policy_aligned,
            }));
            return Ok(report);
        }

        if client.is_secretless() {
            let mut report = SelfCheckReport::degraded(
                "credential_injection_required",
                "Configured with empty token; egress proxy injection required",
            );
            report.details = Some(json!({
                "base_url": client.base_url(),
                "auth_mode": "credential_injection",
                "manifest_network_policy_aligned": manifest_network_policy_aligned,
            }));
            return Ok(report);
        }

        match client.health_check().await {
            Ok(()) => {
                let mut report = SelfCheckReport::ok();
                report.details = Some(json!({
                    "base_url": client.base_url(),
                    "auth_mode": "api_token",
                    "manifest_network_policy_aligned": manifest_network_policy_aligned,
                }));
                Ok(report)
            }
            Err(error) => {
                let (reason_code, degraded) = classify_self_check_error(&error);
                let mut report = if degraded {
                    SelfCheckReport::degraded(reason_code, error.to_string())
                } else {
                    SelfCheckReport::failed(reason_code, error.to_string())
                };
                report.details = Some(json!({
                    "base_url": client.base_url(),
                    "auth_mode": "api_token",
                    "manifest_network_policy_aligned": manifest_network_policy_aligned,
                }));
                Ok(report)
            }
        }
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        let required_cap = match required_capability(req.operation.as_str()) {
            Ok(capability) => capability,
            Err(error) => {
                return Ok(SimulateResponse::denied(
                    req.id,
                    error.to_string(),
                    error.error_code(),
                ));
            }
        };
        if self.client.is_none() || self.runtime.is_none() {
            return Ok(SimulateResponse::denied(
                req.id,
                "Connector is not configured",
                FcpError::NotConfigured.error_code(),
            ));
        }
        let Some(verifier) = self.verifier.as_ref() else {
            return Ok(SimulateResponse::denied(
                req.id,
                "Connector handshake not completed",
                FcpError::NotHandshaken.error_code(),
            ));
        };
        if let Err(error) =
            verifier.verify_bound(req.capability_token, &required_cap, &req.operation, &[])
        {
            let mut response =
                SimulateResponse::denied(req.id, error.to_string(), error.error_code());
            if error.error_code() == "FCP-3001" {
                response =
                    response.with_missing_capabilities(vec![required_cap.as_str().to_string()]);
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

impl CircleCiConnector {
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();

        let verifier = self.verifier.as_ref().ok_or(FcpError::Internal {
            message: "Capability verifier missing after successful handshake".into(),
        })?;
        let required_cap = required_capability(operation)?;
        verifier.verify_bound(req.capability_token, &required_cap, &req.operation, &[])?;

        let runtime = self.runtime.as_ref().ok_or(FcpError::Internal {
            message: "Connector runtime missing after configure".into(),
        })?;
        let client = self.client.as_ref().ok_or(FcpError::Internal {
            message: "CircleCI client missing after configure".into(),
        })?;

        let output = match operation {
            OP_PIPELINES_LIST => {
                let project_slug = req
                    .input
                    .get("project_slug")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'project_slug' field".into(),
                    })?;
                let page_cursor = req.input.get("page_token").and_then(|v| v.as_str());
                let resp = client
                    .list_pipelines(runtime, project_slug, page_cursor)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("JSON serialization error: {e}"),
                })?
            }
            OP_PIPELINES_GET => {
                let pipeline_id = req
                    .input
                    .get("pipeline_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'pipeline_id' field".into(),
                    })?;
                let resp = client
                    .get_pipeline(runtime, pipeline_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("JSON serialization error: {e}"),
                })?
            }
            OP_PIPELINES_TRIGGER => {
                let project_slug = req
                    .input
                    .get("project_slug")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'project_slug' field".into(),
                    })?;
                let mut body = json!({});
                if let Some(branch) = req.input.get("branch").and_then(|v| v.as_str()) {
                    body["branch"] = json!(branch);
                }
                if let Some(tag) = req.input.get("tag").and_then(|v| v.as_str()) {
                    body["tag"] = json!(tag);
                }
                if let Some(params) = req.input.get("parameters") {
                    body["parameters"] = params.clone();
                }
                let resp = client
                    .trigger_pipeline(runtime, project_slug, &body)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("JSON serialization error: {e}"),
                })?
            }
            OP_WORKFLOWS_LIST => {
                let pipeline_id = req
                    .input
                    .get("pipeline_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'pipeline_id' field".into(),
                    })?;
                let page_cursor = req.input.get("page_token").and_then(|v| v.as_str());
                let resp = client
                    .list_workflows(runtime, pipeline_id, page_cursor)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("JSON serialization error: {e}"),
                })?
            }
            OP_WORKFLOWS_GET => {
                let workflow_id = req
                    .input
                    .get("workflow_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'workflow_id' field".into(),
                    })?;
                let resp = client
                    .get_workflow(runtime, workflow_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("JSON serialization error: {e}"),
                })?
            }
            OP_WORKFLOWS_CANCEL => {
                let workflow_id = req
                    .input
                    .get("workflow_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'workflow_id' field".into(),
                    })?;
                let resp = client
                    .cancel_workflow(runtime, workflow_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("JSON serialization error: {e}"),
                })?
            }
            OP_WORKFLOWS_RERUN => {
                let workflow_id = req
                    .input
                    .get("workflow_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'workflow_id' field".into(),
                    })?;
                let from_failed = req
                    .input
                    .get("from_failed")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let resp = client
                    .rerun_workflow(runtime, workflow_id, from_failed)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("JSON serialization error: {e}"),
                })?
            }
            OP_JOBS_LIST => {
                let workflow_id = req
                    .input
                    .get("workflow_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'workflow_id' field".into(),
                    })?;
                let page_cursor = req.input.get("page_token").and_then(|v| v.as_str());
                let resp = client
                    .list_jobs(runtime, workflow_id, page_cursor)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("JSON serialization error: {e}"),
                })?
            }
            OP_JOBS_GET => {
                let project_slug = req
                    .input
                    .get("project_slug")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'project_slug' field".into(),
                    })?;
                let job_number = req.input.get("job_number").and_then(|v| v.as_u64()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing or invalid 'job_number' field".into(),
                    },
                )?;
                let resp = client
                    .get_job(runtime, project_slug, job_number)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("JSON serialization error: {e}"),
                })?
            }
            OP_PROJECTS_LIST => {
                let page_cursor = req.input.get("page_token").and_then(|v| v.as_str());
                let resp = client
                    .list_projects(runtime, page_cursor)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("JSON serialization error: {e}"),
                })?
            }
            OP_HEALTH => {
                client.health_check().await.map_err(|e| e.to_fcp_error())?;
                json!({ "status": "ok" })
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
    use fcp_prelude::{IdempotencyClass, RiskLevel, SafetyTier};
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread::{self, JoinHandle};

    #[derive(Clone, Copy)]
    struct ResponseSpec {
        status: u16,
        headers: &'static [(&'static str, &'static str)],
        body: &'static str,
    }

    impl ResponseSpec {
        const fn json(status: u16, body: &'static str) -> Self {
            Self {
                status,
                headers: &[("content-type", "application/json")],
                body,
            }
        }

        const fn with_headers(
            status: u16,
            headers: &'static [(&'static str, &'static str)],
            body: &'static str,
        ) -> Self {
            Self {
                status,
                headers,
                body,
            }
        }
    }

    #[derive(Debug)]
    struct RequestObservation {
        request_line: String,
    }

    struct LoopbackFixture {
        base_url: String,
        handle: Option<JoinHandle<Vec<RequestObservation>>>,
    }

    impl LoopbackFixture {
        fn start(responses: Vec<ResponseSpec>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
            let address = listener.local_addr().expect("read listener address");
            let handle = thread::spawn(move || {
                responses
                    .into_iter()
                    .map(|response| {
                        let (stream, _) = listener.accept().expect("accept request");
                        handle_request(stream, response)
                    })
                    .collect()
            });

            Self {
                base_url: format!("http://{address}"),
                handle: Some(handle),
            }
        }

        fn base_url(&self) -> &str {
            &self.base_url
        }

        fn join(mut self) -> Vec<RequestObservation> {
            self.handle
                .take()
                .expect("loopback handle present")
                .join()
                .expect("loopback thread completed")
        }
    }

    fn handle_request(mut stream: TcpStream, response: ResponseSpec) -> RequestObservation {
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set request read timeout");
        let raw = read_http_request(&mut stream);
        let header_end = find_header_end(&raw).expect("request contains header terminator");
        let request = String::from_utf8_lossy(&raw[..header_end]);
        let request_line = request.lines().next().unwrap_or_default().to_string();

        write_response(&mut stream, response);

        RequestObservation { request_line }
    }

    fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let bytes_read = stream.read(&mut buffer).expect("read request");
            assert!(bytes_read > 0, "request should not close early");
            request.extend_from_slice(&buffer[..bytes_read]);
            if let Some(header_end) = find_header_end(&request) {
                let expected_body_len = content_length(&request[..header_end]);
                let body_bytes = request.len().saturating_sub(header_end + 4);
                if body_bytes >= expected_body_len {
                    return request;
                }
            }
        }
    }

    fn find_header_end(request: &[u8]) -> Option<usize> {
        request.windows(4).position(|window| window == b"\r\n\r\n")
    }

    fn content_length(headers: &[u8]) -> usize {
        let text = String::from_utf8_lossy(headers);
        text.lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0)
    }

    fn write_response(stream: &mut TcpStream, response: ResponseSpec) {
        write!(
            stream,
            "HTTP/1.1 {} {}\r\nconnection: close\r\ncontent-length: {}\r\n",
            response.status,
            status_reason(response.status),
            response.body.len()
        )
        .expect("write response status");
        for (name, value) in response.headers {
            write!(stream, "{name}: {value}\r\n").expect("write response header");
        }
        write!(stream, "\r\n{}", response.body).expect("write response body");
    }

    const fn status_reason(status: u16) -> &'static str {
        match status {
            200 => "OK",
            401 => "Unauthorized",
            429 => "Too Many Requests",
            _ => "Status",
        }
    }

    fn all_caps() -> Vec<CapabilityId> {
        vec![
            CapabilityId::from_static(CAP_PIPELINES_READ),
            CapabilityId::from_static(CAP_PIPELINES_WRITE),
            CapabilityId::from_static(CAP_WORKFLOWS_READ),
            CapabilityId::from_static(CAP_WORKFLOWS_WRITE),
            CapabilityId::from_static(CAP_JOBS_READ),
            CapabilityId::from_static(CAP_PROJECTS_READ),
        ]
    }

    fn base_handshake() -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [0u8; 32],
            capabilities_requested: all_caps(),
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        }
    }

    fn base_invoke(connector_id: &ConnectorId, operation: &'static str) -> InvokeRequest {
        InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("req_1"),
            connector_id: connector_id.clone(),
            operation: OperationId::from_static(operation),
            zone_id: ZoneId::work(),
            input: serde_json::json!({}),
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        }
    }

    const EXPECTED_MANIFEST_SCHEMA_OPS: &[&str] = &[
        OP_PROJECTS_LIST,
        OP_PIPELINES_LIST,
        OP_PIPELINES_GET,
        OP_PIPELINES_TRIGGER,
        OP_WORKFLOWS_LIST,
        OP_WORKFLOWS_GET,
        OP_WORKFLOWS_CANCEL,
        OP_WORKFLOWS_RERUN,
        OP_JOBS_LIST,
        OP_JOBS_GET,
        OP_HEALTH,
    ];

    fn circleci_manifest() -> Result<toml::Value, String> {
        toml::from_str(MANIFEST_TOML)
            .map_err(|err| format!("CircleCI manifest TOML should parse: {err}"))
    }

    fn manifest_operations(
        manifest: &toml::Value,
    ) -> Result<&toml::map::Map<String, toml::Value>, String> {
        manifest
            .get("provides")
            .and_then(|provides| provides.get("operations"))
            .and_then(toml::Value::as_table)
            .ok_or_else(|| "manifest should declare operation tables".to_owned())
    }

    fn operation_schema(
        manifest: &toml::Value,
        operation_id: &str,
        field: &str,
    ) -> Result<serde_json::Value, String> {
        let schema = manifest_operations(manifest)?
            .get(operation_id)
            .and_then(toml::Value::as_table)
            .and_then(|operation| operation.get(field))
            .ok_or_else(|| format!("{operation_id} should declare {field}"))?;
        if schema.as_table().is_none_or(toml::map::Map::is_empty) {
            return Err(format!(
                "{operation_id}.{field} should be a non-empty schema table"
            ));
        }
        serde_json::to_value(schema)
            .map_err(|err| format!("{operation_id}.{field} should convert to JSON: {err}"))
    }

    fn validator_for(schema: &serde_json::Value) -> Result<jsonschema::Validator, String> {
        jsonschema::Validator::new(schema)
            .map_err(|err| format!("manifest operation schema should compile: {err}"))
    }

    fn assert_schema_accepts(
        schema: &serde_json::Value,
        payload: &serde_json::Value,
    ) -> Result<(), String> {
        let validator = validator_for(schema)?;
        let errors = validator
            .iter_errors(payload)
            .map(|error| error.to_string())
            .collect::<Vec<_>>();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "schema should accept {payload}; errors: {errors:?}"
            ))
        }
    }

    fn assert_schema_rejects(
        schema: &serde_json::Value,
        payload: &serde_json::Value,
    ) -> Result<(), String> {
        let validator = validator_for(schema)?;
        if validator.iter_errors(payload).next().is_some() {
            Ok(())
        } else {
            Err(format!("schema should reject {payload}"))
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = CircleCiConnector::new();
        let result = connector.handshake(base_handshake()).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_valid() {
        let mut connector = CircleCiConnector::new();
        let config = json!({ "api_token": "test_token" });
        let result = connector.configure(config).await;
        assert!(result.is_ok());
        assert!(connector.config.is_some());
        assert!(connector.client.is_some());
        assert!(connector.runtime.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_missing_fields() {
        let mut connector = CircleCiConnector::new();
        let result = connector.configure(json!({})).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_before_configure() {
        let connector = CircleCiConnector::new();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Degraded { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_after_configure() {
        let mut connector = CircleCiConnector::new();
        connector
            .configure(json!({ "api_token": "tok" }))
            .await
            .unwrap();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Ready));
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_secretless_mode_is_degraded() {
        let mut connector = CircleCiConnector::new();
        connector
            .configure(json!({ "api_token": "" }))
            .await
            .unwrap();
        let health = connector.health().await;
        assert!(matches!(
            health.status,
            HealthState::Degraded { ref reason } if reason == "credential injection required"
        ));
        assert_eq!(
            health
                .details
                .as_ref()
                .and_then(|details| details.get("credential_injection_required"))
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn test_doctor_before_configure() {
        let connector = CircleCiConnector::new();
        let report = connector.doctor();
        assert!(!report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_after_configure() {
        let mut connector = CircleCiConnector::new();
        connector
            .configure(json!({ "api_token": "tok" }))
            .await
            .unwrap();
        let report = connector.doctor();
        assert!(report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_custom_host_reports_manifest_policy_failure() {
        let mut connector = CircleCiConnector::new();
        connector
            .configure(json!({
                "api_token": "tok",
                "base_url": "https://custom.circleci.example/api/v2"
            }))
            .await
            .unwrap();
        let report = connector.doctor();
        let network_check = report
            .checks
            .iter()
            .find(|check| check.name == "network_constraints")
            .unwrap();
        assert!(!network_check.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_before_configure() {
        let connector = CircleCiConnector::new();
        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_secretless_reason_code() {
        let mut connector = CircleCiConnector::new();
        connector
            .configure(json!({ "api_token": "" }))
            .await
            .unwrap();
        let report = connector.self_check().await.unwrap();
        assert_eq!(
            report.reason_code.as_deref(),
            Some("credential_injection_required")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_invalid_token_reason_code() {
        let fixture = LoopbackFixture::start(vec![ResponseSpec::json(401, "")]);

        let mut connector = CircleCiConnector::new();
        connector
            .configure(json!({
                "api_token": "bad",
                "base_url": fixture.base_url()
            }))
            .await
            .unwrap();
        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Failed);
        assert_eq!(report.reason_code.as_deref(), Some("invalid_api_token"));
        let observations = fixture.join();
        assert_eq!(observations[0].request_line, "GET /me HTTP/1.1");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_rate_limited_reason_code() {
        let fixture = LoopbackFixture::start(vec![ResponseSpec::with_headers(
            429,
            &[("retry-after", "2")],
            "",
        )]);

        let mut connector = CircleCiConnector::new();
        connector
            .configure(json!({
                "api_token": "tok",
                "base_url": fixture.base_url()
            }))
            .await
            .unwrap();
        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
        assert_eq!(report.reason_code.as_deref(), Some("circleci_rate_limited"));
        let observations = fixture.join();
        assert_eq!(observations[0].request_line, "GET /me HTTP/1.1");
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate() {
        let connector = CircleCiConnector::new();
        let req = SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(OP_PIPELINES_LIST),
            ZoneId::work(),
            json!({}),
            CapabilityToken::test_token(),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(!resp.would_succeed);
        assert_eq!(resp.denial_code, Some(FcpError::NotConfigured.error_code()));
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_checks_capability_token() {
        let mut connector = CircleCiConnector::new();
        connector
            .configure(json!({ "api_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(OP_PIPELINES_LIST),
            ZoneId::work(),
            json!({}),
            CapabilityToken::test_token(),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(!resp.would_succeed);
    }

    #[test]
    fn test_introspection_operations() {
        let connector = CircleCiConnector::new();
        let intro = connector.introspect();
        let ops: Vec<&str> = intro.operations.iter().map(|o| o.id.as_str()).collect();

        assert_eq!(intro.operations.len(), OPERATION_ORDER.len());
        assert_eq!(ops, OPERATION_ORDER);
    }

    fn strict_circleci_manifest() -> Result<ConnectorManifest, String> {
        ConnectorManifest::parse_str(MANIFEST_TOML).map_err(|error| error.to_string())
    }

    #[test]
    fn runtime_operation_catalog_matches_manifest_metadata() -> Result<(), String> {
        let manifest = strict_circleci_manifest()?;
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
        let result = serde_json::to_value(CircleCiConnector::new().introspect()).unwrap();
        let ops = result["operations"].as_array().unwrap();

        let trigger = ops
            .iter()
            .find(|op| op["id"].as_str() == Some(OP_PIPELINES_TRIGGER))
            .unwrap();
        let cancel = ops
            .iter()
            .find(|op| op["id"].as_str() == Some(OP_WORKFLOWS_CANCEL))
            .unwrap();
        let rerun = ops
            .iter()
            .find(|op| op["id"].as_str() == Some(OP_WORKFLOWS_RERUN))
            .unwrap();

        assert_eq!(trigger["requires_approval"], "policy");
        assert_eq!(cancel["requires_approval"], "none");
        assert_eq!(rerun["requires_approval"], "policy");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn manifest_operation_schemas_compile_and_validate_core_payloads() -> Result<(), String> {
        let manifest = circleci_manifest()?;
        let operations = manifest_operations(&manifest)?;
        let operation_catalog = operations_info();

        for operation_id in EXPECTED_MANIFEST_SCHEMA_OPS {
            assert!(
                operations.contains_key(*operation_id),
                "manifest should declare operation {operation_id}"
            );
            let operation = operation_catalog
                .iter()
                .find(|operation| operation.id.as_str() == *operation_id)
                .ok_or_else(|| format!("operation catalog should declare {operation_id}"))?;
            for field in ["input_schema", "output_schema"] {
                let schema = operation_schema(&manifest, operation_id, field)?;
                let _validator = validator_for(&schema)?;
            }
            assert_eq!(
                operation.input_schema,
                operation_schema(&manifest, operation_id, "input_schema")?,
                "{operation_id} input schema should match manifest"
            );
            assert_eq!(
                operation.output_schema,
                operation_schema(&manifest, operation_id, "output_schema")?,
                "{operation_id} output schema should match manifest"
            );
        }

        for operation in operation_catalog {
            let _input_validator = validator_for(&operation.input_schema)?;
            let _output_validator = validator_for(&operation.output_schema)?;
        }

        let projects_input = operation_schema(&manifest, OP_PROJECTS_LIST, "input_schema")?;
        assert_schema_accepts(&projects_input, &json!({}))?;
        assert_schema_accepts(&projects_input, &json!({"page_token": "next"}))?;
        assert_schema_rejects(&projects_input, &json!({"page_token": 4}))?;
        assert_schema_rejects(&projects_input, &json!({"extra": true}))?;

        for operation_id in [OP_PIPELINES_LIST, OP_PIPELINES_TRIGGER] {
            let input = operation_schema(&manifest, operation_id, "input_schema")?;
            assert_schema_accepts(&input, &json!({"project_slug": "gh/org/repo"}))?;
            assert_schema_rejects(&input, &json!({}))?;
            assert_schema_rejects(&input, &json!({"project_slug": 4}))?;
            assert_schema_rejects(
                &input,
                &json!({"project_slug": "gh/org/repo", "extra": true}),
            )?;
        }

        let pipelines_list_input = operation_schema(&manifest, OP_PIPELINES_LIST, "input_schema")?;
        assert_schema_accepts(
            &pipelines_list_input,
            &json!({"project_slug": "gh/org/repo", "page_token": "next"}),
        )?;

        let trigger_input = operation_schema(&manifest, OP_PIPELINES_TRIGGER, "input_schema")?;
        assert_schema_accepts(
            &trigger_input,
            &json!({
                "project_slug": "gh/org/repo",
                "branch": "main",
                "parameters": {"deploy": true}
            }),
        )?;
        assert_schema_rejects(
            &trigger_input,
            &json!({"project_slug": "gh/org/repo", "parameters": ["bad"]}),
        )?;

        for operation_id in [OP_PIPELINES_GET, OP_WORKFLOWS_LIST] {
            let input = operation_schema(&manifest, operation_id, "input_schema")?;
            assert_schema_accepts(&input, &json!({"pipeline_id": "pipeline-1"}))?;
            assert_schema_rejects(&input, &json!({}))?;
            assert_schema_rejects(&input, &json!({"pipeline_id": 4}))?;
            assert_schema_rejects(&input, &json!({"pipeline_id": "pipeline-1", "extra": true}))?;
        }

        let workflows_list_input = operation_schema(&manifest, OP_WORKFLOWS_LIST, "input_schema")?;
        assert_schema_accepts(
            &workflows_list_input,
            &json!({"pipeline_id": "pipeline-1", "page_token": "next"}),
        )?;

        for operation_id in [
            OP_WORKFLOWS_GET,
            OP_WORKFLOWS_CANCEL,
            OP_WORKFLOWS_RERUN,
            OP_JOBS_LIST,
        ] {
            let input = operation_schema(&manifest, operation_id, "input_schema")?;
            assert_schema_accepts(&input, &json!({"workflow_id": "workflow-1"}))?;
            assert_schema_rejects(&input, &json!({}))?;
            assert_schema_rejects(&input, &json!({"workflow_id": 4}))?;
            assert_schema_rejects(&input, &json!({"workflow_id": "workflow-1", "extra": true}))?;
        }

        let rerun_input = operation_schema(&manifest, OP_WORKFLOWS_RERUN, "input_schema")?;
        assert_schema_accepts(
            &rerun_input,
            &json!({"workflow_id": "workflow-1", "from_failed": true}),
        )?;
        assert_schema_rejects(
            &rerun_input,
            &json!({"workflow_id": "workflow-1", "from_failed": "yes"}),
        )?;

        let jobs_list_input = operation_schema(&manifest, OP_JOBS_LIST, "input_schema")?;
        assert_schema_accepts(
            &jobs_list_input,
            &json!({"workflow_id": "workflow-1", "page_token": "next"}),
        )?;

        let jobs_get_input = operation_schema(&manifest, OP_JOBS_GET, "input_schema")?;
        assert_schema_accepts(
            &jobs_get_input,
            &json!({"project_slug": "gh/org/repo", "job_number": 0}),
        )?;
        assert_schema_rejects(&jobs_get_input, &json!({"project_slug": "gh/org/repo"}))?;
        assert_schema_rejects(
            &jobs_get_input,
            &json!({"project_slug": "gh/org/repo", "job_number": -1}),
        )?;
        assert_schema_rejects(
            &jobs_get_input,
            &json!({"project_slug": "gh/org/repo", "job_number": 1.5}),
        )?;
        assert_schema_rejects(
            &jobs_get_input,
            &json!({"project_slug": "gh/org/repo", "job_number": 1, "extra": true}),
        )?;

        let health_input = operation_schema(&manifest, OP_HEALTH, "input_schema")?;
        assert_schema_accepts(&health_input, &json!({}))?;
        assert_schema_rejects(&health_input, &json!({"extra": true}))?;

        for operation_id in [
            OP_PROJECTS_LIST,
            OP_PIPELINES_LIST,
            OP_WORKFLOWS_LIST,
            OP_JOBS_LIST,
        ] {
            let output = operation_schema(&manifest, operation_id, "output_schema")?;
            assert_schema_accepts(&output, &json!({"items": []}))?;
            assert_schema_accepts(&output, &json!({"items": [], "next_page_token": null}))?;
            assert_schema_accepts(&output, &json!({"items": [], "next_page_token": "next"}))?;
            assert_schema_rejects(&output, &json!({}))?;
            assert_schema_rejects(&output, &json!({"items": [], "next_page_token": 7}))?;
            assert_schema_rejects(&output, &json!({"items": [], "extra": true}))?;
        }

        for operation_id in [OP_PIPELINES_GET, OP_PIPELINES_TRIGGER] {
            let output = operation_schema(&manifest, operation_id, "output_schema")?;
            assert_schema_accepts(
                &output,
                &json!({"id": "pipeline-1", "state": "created", "number": 1}),
            )?;
            assert_schema_rejects(&output, &json!({"id": "pipeline-1", "state": "created"}))?;
            assert_schema_rejects(
                &output,
                &json!({"id": "pipeline-1", "state": "created", "number": -1}),
            )?;
        }

        let workflow_output = operation_schema(&manifest, OP_WORKFLOWS_GET, "output_schema")?;
        assert_schema_accepts(
            &workflow_output,
            &json!({"id": "workflow-1", "name": "build", "status": "success"}),
        )?;
        assert_schema_rejects(
            &workflow_output,
            &json!({"id": "workflow-1", "name": "build"}),
        )?;

        let job_output = operation_schema(&manifest, OP_JOBS_GET, "output_schema")?;
        assert_schema_accepts(
            &job_output,
            &json!({"id": "job-1", "name": "test", "status": "success"}),
        )?;
        assert_schema_rejects(&job_output, &json!({"id": "job-1", "name": "test"}))?;

        for operation_id in [OP_WORKFLOWS_CANCEL, OP_WORKFLOWS_RERUN] {
            let output = operation_schema(&manifest, operation_id, "output_schema")?;
            assert_schema_accepts(&output, &json!({"message": "ok"}))?;
            assert_schema_rejects(&output, &json!({}))?;
            assert_schema_rejects(&output, &json!({"message": "ok", "extra": true}))?;
        }

        let health_output = operation_schema(&manifest, OP_HEALTH, "output_schema")?;
        assert_schema_accepts(&health_output, &json!({"status": "ok"}))?;
        assert_schema_rejects(&health_output, &json!({"status": "degraded"}))?;
        assert_schema_rejects(&health_output, &json!({"status": "ok", "extra": true}))?;

        Ok(())
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_unknown_operation() {
        let mut connector = CircleCiConnector::new();
        connector
            .configure(json!({ "api_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), "circleci.nonexistent");
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_configure() {
        let connector = CircleCiConnector::new();
        let req = base_invoke(connector.id(), OP_PIPELINES_LIST);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_project_slug() {
        let mut connector = CircleCiConnector::new();
        connector
            .configure(json!({ "api_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_PIPELINES_LIST);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_pipeline_id() {
        let mut connector = CircleCiConnector::new();
        connector
            .configure(json!({ "api_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_PIPELINES_GET);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_workflow_id_for_cancel() {
        let mut connector = CircleCiConnector::new();
        connector
            .configure(json!({ "api_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_WORKFLOWS_CANCEL);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_operations_have_ai_hints() {
        let ops = operations_info();
        for op in &ops {
            assert!(!op.ai_hints.when_to_use.is_empty());
        }
    }

    #[test]
    fn test_pipelines_trigger_is_risky() {
        let ops = operations_info();
        let trigger = ops
            .iter()
            .find(|op| op.id.as_str() == OP_PIPELINES_TRIGGER)
            .unwrap();
        assert_eq!(trigger.safety_tier, SafetyTier::Risky);
        assert_eq!(trigger.risk_level, RiskLevel::High);
        assert_eq!(trigger.idempotency, IdempotencyClass::BestEffort);
        assert_eq!(trigger.requires_approval, Some(ApprovalMode::Policy));
    }

    #[test]
    fn test_pipelines_list_is_safe() {
        let ops = operations_info();
        let list = ops
            .iter()
            .find(|op| op.id.as_str() == OP_PIPELINES_LIST)
            .unwrap();
        assert_eq!(list.safety_tier, SafetyTier::Safe);
        assert_eq!(list.risk_level, RiskLevel::Low);
        assert_eq!(list.idempotency, IdempotencyClass::None);
    }

    #[test]
    fn test_workflows_cancel_is_risky() {
        let ops = operations_info();
        let cancel = ops
            .iter()
            .find(|op| op.id.as_str() == OP_WORKFLOWS_CANCEL)
            .unwrap();
        assert_eq!(cancel.safety_tier, SafetyTier::Risky);
        assert_eq!(cancel.risk_level, RiskLevel::Medium);
    }

    #[test]
    fn test_workflows_rerun_requires_policy_approval() {
        let ops = operations_info();
        let rerun = ops
            .iter()
            .find(|op| op.id.as_str() == OP_WORKFLOWS_RERUN)
            .unwrap();
        assert_eq!(rerun.idempotency, IdempotencyClass::BestEffort);
        assert_eq!(rerun.requires_approval, Some(ApprovalMode::Policy));
    }

    #[test]
    fn test_manifest_hash_deterministic() {
        let hash1 = CircleCiConnector::manifest_hash();
        let hash2 = CircleCiConnector::manifest_hash();
        assert_eq!(hash1, hash2);
        assert!(hash1.starts_with("sha256:"));
    }

    #[test]
    fn test_streaming_not_supported() {
        let connector = CircleCiConnector::new();
        let intro = connector.introspect();
        assert!(!intro.event_caps.as_ref().unwrap().streaming);
    }

    #[test]
    fn test_connector_id() {
        let connector = CircleCiConnector::new();
        assert_eq!(connector.id().as_str(), "fcp.circleci");
    }

    #[test]
    fn test_default_impl() {
        let connector = CircleCiConnector::default();
        assert_eq!(connector.id().as_str(), "fcp.circleci");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_custom_base_url() {
        let mut connector = CircleCiConnector::new();
        let config = json!({
            "api_token": "tok",
            "base_url": "https://custom.circleci.com/api/v2"
        });
        let result = connector.configure(config).await;
        assert!(result.is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_zero_timeout() {
        let mut connector = CircleCiConnector::new();
        let result = connector
            .configure(json!({
                "api_token": "tok",
                "request_timeout_ms": 0
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake_grants_all_caps() {
        let mut connector = CircleCiConnector::new();
        let resp = connector.handshake(base_handshake()).await.unwrap();
        assert_eq!(resp.capabilities_granted.len(), 6);
    }

    #[fcp_async_core::runtime::test]
    async fn test_shutdown() {
        let mut connector = CircleCiConnector::new();
        connector
            .configure(json!({ "api_token": "tok" }))
            .await
            .unwrap();
        let result = connector
            .shutdown(ShutdownRequest {
                r#type: "shutdown".into(),
                deadline_ms: 5000,
                drain: false,
                reason: Some("test".into()),
            })
            .await;
        assert!(result.is_ok());
    }
}
