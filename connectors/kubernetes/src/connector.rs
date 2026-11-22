//! FCP Kubernetes Connector implementation.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use fcp_prelude::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityId, ConnectorId, CredentialId, FcpError,
    FcpResult, HandshakeRequest, HealthSnapshot, IdempotencyClass, InvokeRequest, InvokeResponse,
    OperationId, OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SimulateRequest,
    SimulateResponse, ZoneId,
};
use fcp_sdk::prelude::{OperationContractSet, StandaloneSession};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, KubernetesAuth, KubernetesClient},
    error::KubernetesError,
    zone::OperationCategory,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const MAX_NATIVE_RESPONSE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_INVOCATION_TIMEOUT_MS: u64 = 60_000;

fn operation_contracts() -> FcpResult<&'static OperationContractSet> {
    static CONTRACTS: OnceLock<FcpResult<OperationContractSet>> = OnceLock::new();
    CONTRACTS
        .get_or_init(|| OperationContractSet::from_manifest_toml(MANIFEST_TOML))
        .as_ref()
        .map_err(Clone::clone)
}

fn encode<T: Serialize>(value: &T) -> FcpResult<serde_json::Value> {
    serde_json::to_value(value).map_err(|_| FcpError::Internal {
        message: "Unable to encode Kubernetes protocol response".into(),
    })
}

fn interrupted_invocation() -> FcpError {
    FcpError::External {
        service: "kubernetes".into(),
        message:
            "Invocation deadline exhausted or execution cancelled; provider outcome may be unknown"
                .into(),
        status_code: None,
        retryable: false,
        retry_after: None,
    }
}

/// Parsed and validated Kubernetes connector configuration.
#[derive(Debug, Clone)]
struct KubernetesConfig {
    auth: KubernetesAuth,
    base_url: String,
    policy: KubernetesAccessPolicy,
}

#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
struct KubernetesAccessPolicy {
    allowed_namespaces: Option<BTreeSet<String>>,
    allow_write_operations: bool,
    allow_pod_exec: bool,
    allow_exec_into_system_namespaces: bool,
    allow_untrusted_exec_targets: bool,
    allow_shell_exec: bool,
    exec_required_pod_labels: BTreeMap<String, String>,
}

impl KubernetesAccessPolicy {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let allow_write_operations = params
            .get("allow_write_operations")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let allow_pod_exec = params
            .get("allow_pod_exec")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let allow_exec_into_system_namespaces = params
            .get("allow_exec_into_system_namespaces")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let allow_untrusted_exec_targets = params
            .get("allow_untrusted_exec_targets")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let allow_shell_exec = params
            .get("allow_shell_exec")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);

        let allowed_namespaces = parse_string_set(params, "allowed_namespaces")?;
        let exec_required_pod_labels = parse_string_map(params, "exec_required_pod_labels")?
            .unwrap_or_else(default_exec_required_labels);

        if (allow_write_operations || allow_pod_exec) && allowed_namespaces.is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message:
                    "allowed_namespaces must be configured before enabling write or exec operations"
                        .into(),
            });
        }

        Ok(Self {
            allowed_namespaces,
            allow_write_operations,
            allow_pod_exec,
            allow_exec_into_system_namespaces,
            allow_untrusted_exec_targets,
            allow_shell_exec,
            exec_required_pod_labels,
        })
    }

    fn enforce_namespace_scope(
        &self,
        namespace: &str,
        operation: &str,
    ) -> Result<(), KubernetesError> {
        let Some(allowed) = &self.allowed_namespaces else {
            return Ok(());
        };
        if allowed.contains(namespace) {
            return Ok(());
        }
        Err(KubernetesError::PolicyDenied(format!(
            "{operation} is not permitted in namespace '{namespace}'; allowed_namespaces={}",
            join_namespaces(allowed)
        )))
    }
}

impl KubernetesConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let bearer_token = params
            .get("bearer_token")
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

        let auth = match (bearer_token, credential_id) {
            (Some(key), None) => KubernetesAuth::BearerToken(key),
            (None, Some(cred_id)) => KubernetesAuth::CredentialId(cred_id),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide exactly one of bearer_token or credential_id".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing bearer_token or credential_id in configuration".into(),
                });
            }
        };

        let base_url = params
            .get("base_url")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(DEFAULT_BASE_URL)
            .to_string();

        let policy = KubernetesAccessPolicy::from_params(params)?;

        Ok(Self {
            auth,
            base_url,
            policy,
        })
    }

    const fn auth_mode(&self) -> &'static str {
        match &self.auth {
            KubernetesAuth::BearerToken(_) => "bearer_token",
            KubernetesAuth::CredentialId(_) => "credential_id",
        }
    }

    const fn rate_limit_profile(&self) -> &'static str {
        match &self.auth {
            KubernetesAuth::BearerToken(_) => "bearer_token: cluster-level rate limiting",
            KubernetesAuth::CredentialId(_) => {
                "credential_id: authenticated via egress proxy injection"
            }
        }
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let (network_ok, network_message) = base_url_policy(&self.base_url);

        ProvisioningReadiness {
            auth_mode: self.auth_mode(),
            bearer_token_configured: matches!(self.auth, KubernetesAuth::BearerToken(_)),
            credential_id_configured: self.auth.is_secretless(),
            requires_credential_injection: self.auth.is_secretless(),
            network_ok,
            network_message,
            rate_limit_profile: self.rate_limit_profile(),
            base_url: self.base_url.clone(),
            write_operations_enabled: self.policy.allow_write_operations,
            pod_exec_enabled: self.policy.allow_pod_exec,
            namespace_scope: self
                .policy
                .allowed_namespaces
                .as_ref()
                .map(|values| values.iter().cloned().collect()),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct ProvisioningReadiness {
    auth_mode: &'static str,
    bearer_token_configured: bool,
    credential_id_configured: bool,
    requires_credential_injection: bool,
    network_ok: bool,
    network_message: String,
    rate_limit_profile: &'static str,
    base_url: String,
    write_operations_enabled: bool,
    pod_exec_enabled: bool,
    namespace_scope: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorResult {
    status: DoctorStatus,
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum DoctorStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

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

/// FCP Kubernetes Connector.
pub struct KubernetesConnector {
    base: BaseConnector,
    config: Option<KubernetesConfig>,
    client: Option<Arc<KubernetesClient>>,
    authority: Option<StandaloneSession>,
    configured_zone: Option<ZoneId>,
    started_at: Instant,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl KubernetesConnector {
    /// Create a new Kubernetes connector.
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.kubernetes")),
            config: None,
            client: None,
            authority: None,
            configured_zone: None,
            started_at: Instant::now(),
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for KubernetesConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl KubernetesConnector {
    fn session_established(&self) -> bool {
        self.base.handshaken.load(Ordering::Acquire)
            && self
                .authority
                .as_ref()
                .is_some_and(StandaloneSession::is_established)
    }

    fn invalidate_session(&mut self) {
        self.base.set_handshaken(false);
        if let Some(authority) = self.authority.as_mut() {
            authority.invalidate();
            self.base.instance_id = authority.instance_id().clone();
        } else {
            self.base.instance_id = fcp_prelude::InstanceId::new();
        }
    }

    fn clear_configuration(&mut self) {
        self.invalidate_session();
        self.base.set_configured(false);
        if let Some(client) = self.client.take() {
            client.shutdown();
        }
        self.config = None;
        self.authority = None;
        self.configured_zone = None;
    }

    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        // Failed replacement attempts also revoke the previous credentials and
        // instance. No old grant survives a partial lifecycle transition.
        self.clear_configuration();
        let config = KubernetesConfig::from_params(&params)?;
        let provisioning = config.provisioning_readiness();
        if !provisioning.network_ok {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: provisioning.network_message,
            });
        }
        operation_contracts()?;
        let authority = StandaloneSession::new(MANIFEST_TOML)?;
        info!(auth = %config.auth.redacted_label(), "Configuring Kubernetes connector");

        let client = KubernetesClient::new(config.auth.clone(), Some(&config.base_url))
            .map_err(|e| e.to_fcp_error())?;

        self.base.instance_id = authority.instance_id().clone();
        self.authority = Some(authority);
        self.client = Some(Arc::new(client));
        self.config = Some(config);
        self.base.set_configured(true);
        Ok(json!({ "status": "configured" }))
    }

    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        self.invalidate_session();
        if self.config.is_none() || self.client.is_none() {
            return Err(FcpError::NotConfigured);
        }
        let mut request: HandshakeRequest =
            serde_json::from_value(params).map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "Invalid FCP handshake request".into(),
            })?;
        if !matches!(request.zone.as_str(), "z:infra" | "z:work")
            || self
                .configured_zone
                .as_ref()
                .is_some_and(|zone| zone != &request.zone)
        {
            return Err(FcpError::CapabilityDenied {
                capability: "kubernetes.handshake".into(),
                reason: "Kubernetes requires an allowed target zone matching the configured session; reconfigure before changing zones".into(),
            });
        }
        let available = self.handshake_capabilities();
        request
            .capabilities_requested
            .retain(|capability| available.contains(&capability.as_str()));
        let zone = request.zone.clone();
        let authority = self.authority.as_mut().ok_or(FcpError::NotConfigured)?;
        let result = authority.handshake(request);
        self.base.instance_id = authority.instance_id().clone();
        let mut response = encode(&result?)?;
        self.configured_zone = Some(zone);
        self.base.set_handshaken(true);
        response["protocol_version"] = json!("2.0");
        response["connector_id"] = json!(self.base.id);
        response["instance_id"] = json!(self.base.instance_id);
        Ok(response)
    }

    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.config.is_some();
        let handshaken = self.session_established();
        let mut snapshot = if configured && handshaken && self.client.is_some() {
            HealthSnapshot::ready()
        } else if configured {
            HealthSnapshot::degraded("not handshaken")
        } else {
            HealthSnapshot::degraded("not configured")
        };
        snapshot.uptime_ms =
            u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        snapshot.details = Some(json!({
            "configured": configured,
            "handshaken": handshaken,
            "instance_id": self.base.instance_id,
            "readiness_scope": "configured local client and negotiated authority; not a live Kubernetes health proof",
            "requests": self.request_count.load(Ordering::Relaxed),
            "errors": self.error_count.load(Ordering::Relaxed),
        }));
        encode(&snapshot)
    }

    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();

        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: if self.config.is_none() {
                Some("Not configured -- call configure first".into())
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

        let handshaken = self.session_established();
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

        if let Some(config) = &self.config {
            let readiness = config.provisioning_readiness();
            checks.push(DoctorCheck {
                name: "network_constraints".into(),
                passed: readiness.network_ok,
                message: Some(readiness.network_message),
                critical: true,
            });
        }

        let result = DoctorResult::from_checks(checks);
        Ok(serde_json::to_value(result).unwrap_or(json!({"status": "error"})))
    }

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

        if self.client.is_none() {
            let mut report = SelfCheckReport::failed(
                "client_missing",
                "API client not initialized; re-run configure",
            );
            report.details = Some(json!({ "provisioning": readiness }));
            return Self::serialize_self_check_report(report);
        }

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

    fn serialize_self_check_report(report: SelfCheckReport) -> FcpResult<serde_json::Value> {
        info!(
            event = "kubernetes.provisioning.self_check",
            status = ?report.status,
            reason_code = ?report.reason_code,
            "Kubernetes self-check completed"
        );

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }

    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.kubernetes",
            "version": "0.1.0",
            "operations": serde_json::to_value(operations_info()).unwrap_or_default(),
            "events": [],
            "resource_types": [],
            "event_caps": fcp_prelude::EventCaps::default(),
        }))
    }

    #[instrument(skip(self, params))]
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let started_at = Instant::now();
        let result = self.invoke_inner(params, started_at).await;
        self.request_count.fetch_add(1, Ordering::Relaxed);
        if result.is_err() {
            self.error_count.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    async fn invoke_inner(
        &self,
        params: serde_json::Value,
        started_at: Instant,
    ) -> FcpResult<serde_json::Value> {
        self.base.check_ready()?;
        let request: InvokeRequest =
            serde_json::from_value(params).map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "Invalid FCP invoke request".into(),
            })?;
        if request.r#type != "invoke"
            || request.id.0.is_empty()
            || !request.input.is_object()
            || request.deadline_ms == Some(0)
        {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Invocation requires a typed request, non-empty ID, object input and nonzero deadline".into(),
            });
        }
        let budget = Duration::from_millis(
            request
                .deadline_ms
                .unwrap_or(MAX_INVOCATION_TIMEOUT_MS)
                .min(MAX_INVOCATION_TIMEOUT_MS),
        );
        let resources = self.prepare_operation(&request.operation, &request.input)?;
        let witness = self
            .authority
            .as_ref()
            .ok_or(FcpError::NotHandshaken)?
            .admit_bounded(&request, &resources, MAX_NATIVE_RESPONSE_BYTES)?;
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let remaining = budget.saturating_sub(started_at.elapsed());
        if remaining.is_zero() {
            return Err(interrupted_invocation());
        }
        let context = client.invocation_context(remaining);
        let result = context
            .run(self.dispatch_operation(client, request.operation.as_str(), &request.input))
            .await
            .map_err(|_| interrupted_invocation())?;
        let response = match result {
            Ok(output) => InvokeResponse::ok(request.id.clone(), output),
            Err(error) => InvokeResponse::error(request.id.clone(), error),
        };
        operation_contracts()?.validate_response(&request.operation, &request.id, &response)?;
        if started_at.elapsed() >= budget || context.is_cancelled() {
            return Err(interrupted_invocation());
        }
        witness.finish_response(&response)?;
        match response {
            InvokeResponse {
                error: Some(error), ..
            } => Err(error),
            response => encode(&response),
        }
    }

    async fn dispatch_operation(
        &self,
        client: &KubernetesClient,
        operation: &str,
        input: &serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let result = match operation {
            "kubernetes.list_pods" => self.op_list_pods(client, &input).await,
            "kubernetes.get_pod" => self.op_get_pod(client, &input).await,
            "kubernetes.create_pod" => self.op_create_pod(client, &input).await,
            "kubernetes.delete_pod" => self.op_delete_pod(client, &input).await,
            "kubernetes.get_pod_logs" => self.op_get_pod_logs(client, &input).await,
            "kubernetes.stream_pod_logs" => self.op_stream_pod_logs(client, &input).await,
            "kubernetes.list_deployments" => self.op_list_deployments(client, &input).await,
            "kubernetes.get_deployment" => self.op_get_deployment(client, &input).await,
            "kubernetes.apply_deployment" => self.op_apply_deployment(client, &input).await,
            "kubernetes.scale_deployment" => self.op_scale_deployment(client, &input).await,
            "kubernetes.delete_deployment" => self.op_delete_deployment(client, &input).await,
            "kubernetes.rollout_restart" => self.op_rollout_restart(client, &input).await,
            "kubernetes.get_service" => self.op_get_service(client, &input).await,
            "kubernetes.list_services" => self.op_list_services(client, &input).await,
            "kubernetes.get_configmap" => self.op_get_configmap(client, &input).await,
            "kubernetes.update_configmap" => self.op_update_configmap(client, &input).await,
            "kubernetes.get_secret" => self.op_get_secret(client, &input).await,
            "kubernetes.watch_events" => self.op_watch_events(client, &input).await,
            "kubernetes.exec" => self.op_exec(client, &input).await,
            "kubernetes.configmap.list" => self.op_configmap_list(client, &input).await,
            "kubernetes.configmap.get" => self.op_configmap_get(client, &input).await,
            "kubernetes.configmap.create" => self.op_configmap_create(client, &input).await,
            "kubernetes.configmap.update" => self.op_configmap_update(client, &input).await,
            "kubernetes.configmap.delete" => self.op_configmap_delete(client, &input).await,
            "kubernetes.secret.list" => self.op_secret_list(client, &input).await,
            "kubernetes.secret.get" => self.op_secret_get(client, &input).await,
            "kubernetes.secret.create" => self.op_secret_create(client, &input).await,
            "kubernetes.secret.delete" => self.op_secret_delete(client, &input).await,
            "kubernetes.rollout.status" => self.op_rollout_status(client, &input).await,
            "kubernetes.rollout.history" => self.op_rollout_history(client, &input).await,
            "kubernetes.rollout.rollback" => self.op_rollout_rollback(client, &input).await,
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1002,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };

        result.map_err(|error| error.to_fcp_error())
    }

    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let request: SimulateRequest =
            serde_json::from_value(params).map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "Invalid FCP simulate request".into(),
            })?;
        if request.r#type != "simulate" || request.id.0.is_empty() || !request.input.is_object() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Simulation requires a typed request, non-empty ID and object input"
                    .into(),
            });
        }
        let authorization = self
            .prepare_operation(&request.operation, &request.input)
            .and_then(|resources| {
                self.authority
                    .as_ref()
                    .ok_or(FcpError::NotHandshaken)?
                    .authorize(
                        &request.connector_id,
                        &request.zone_id,
                        &request.operation,
                        request.capability_token,
                        &resources,
                    )
                    .map(drop)
            });
        encode(&match authorization {
            Ok(()) => SimulateResponse::allowed(request.id),
            Err(error) => {
                SimulateResponse::denied(request.id, error.to_string(), error.error_code())
            }
        })
    }

    pub async fn handle_shutdown(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        self.clear_configuration();
        let request: fcp_prelude::ShutdownRequest =
            serde_json::from_value(params).map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "Invalid FCP shutdown request".into(),
            })?;
        if request.r#type != "shutdown" {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Shutdown requires type shutdown".into(),
            });
        }
        info!("Kubernetes connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }

    async fn op_list_pods(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let label_selector = input
            .get("label_selector")
            .and_then(serde_json::Value::as_str);
        let field_selector = input
            .get("field_selector")
            .and_then(serde_json::Value::as_str);
        let resp = client
            .list_pods(namespace, label_selector, field_selector)
            .await?;
        let items = resp.get("items").cloned().unwrap_or(json!([]));
        Ok(json!({ "pods": items }))
    }

    async fn op_get_pod(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let name = require_str(input, "name")?;
        let resp = client.get_pod(namespace, name).await?;
        Ok(json!({ "pod": resp }))
    }

    async fn op_delete_pod(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let name = require_str(input, "name")?;
        let grace_period = input
            .get("grace_period_seconds")
            .and_then(serde_json::Value::as_u64);
        let _resp = client.delete_pod(namespace, name, grace_period).await?;
        Ok(json!({ "deleted": true }))
    }

    async fn op_create_pod(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let name = require_str(input, "name")?;
        let spec = input.get("spec").ok_or_else(|| KubernetesError::Api {
            status_code: 400,
            message: "Missing required field: spec".into(),
        })?;
        validate_pod_spec(spec, "pod spec")?;
        let labels = input
            .get("labels")
            .cloned()
            .unwrap_or(serde_json::Value::Null);

        let mut body = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": name,
                "namespace": namespace,
            },
            "spec": spec,
        });
        if !labels.is_null() {
            body["metadata"]["labels"] = labels;
        }
        let resp = client.create_pod(namespace, &body).await?;
        Ok(json!({ "pod": resp }))
    }

    async fn op_get_pod_logs(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let name = require_str(input, "name")?;
        let container = input.get("container").and_then(serde_json::Value::as_str);
        let tail_lines = input.get("tail_lines").and_then(serde_json::Value::as_u64);
        let since_seconds = input
            .get("since_seconds")
            .and_then(serde_json::Value::as_u64);
        let logs = client
            .get_pod_logs(namespace, name, container, tail_lines, since_seconds)
            .await?;
        Ok(json!({ "logs": logs }))
    }

    async fn op_stream_pod_logs(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let name = require_str(input, "name")?;
        let container = input.get("container").and_then(serde_json::Value::as_str);
        let tail_lines = input.get("tail_lines").and_then(serde_json::Value::as_u64);
        let log_line = client
            .stream_pod_logs(namespace, name, container, tail_lines)
            .await?;
        Ok(json!({ "log_line": log_line }))
    }

    async fn op_list_deployments(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let label_selector = input
            .get("label_selector")
            .and_then(serde_json::Value::as_str);
        let resp = client.list_deployments(namespace, label_selector).await?;
        let items = resp.get("items").cloned().unwrap_or(json!([]));
        Ok(json!({ "deployments": items }))
    }

    async fn op_get_deployment(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let name = require_str(input, "name")?;
        let resp = client.get_deployment(namespace, name).await?;
        Ok(json!({ "deployment": resp }))
    }

    async fn op_apply_deployment(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let name = require_str(input, "name")?;
        let spec = input.get("spec").ok_or_else(|| KubernetesError::Api {
            status_code: 400,
            message: "Missing required field: spec".into(),
        })?;
        validate_deployment_spec(spec)?;
        let labels = input
            .get("labels")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let update = input
            .get("update")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);

        let mut body = json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": name,
                "namespace": namespace,
            },
            "spec": spec,
        });
        if !labels.is_null() {
            body["metadata"]["labels"] = labels;
        }
        let resp = client
            .apply_deployment(namespace, Some(name), &body, update)
            .await?;
        Ok(json!({ "deployment": resp }))
    }

    async fn op_delete_deployment(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let name = require_str(input, "name")?;
        let _resp = client.delete_deployment(namespace, name).await?;
        Ok(json!({ "deleted": true }))
    }

    async fn op_scale_deployment(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let name = require_str(input, "name")?;
        let replicas = input
            .get("replicas")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| KubernetesError::Api {
                status_code: 400,
                message: "Missing required field: replicas (must be an integer)".into(),
            })?;
        #[allow(clippy::cast_possible_truncation)]
        let replicas_u32 = replicas as u32;
        let resp = client
            .scale_deployment(namespace, name, replicas_u32)
            .await?;
        Ok(json!({ "deployment": resp }))
    }

    async fn op_rollout_restart(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let name = require_str(input, "name")?;
        let resp = client.rollout_restart(namespace, name).await?;
        Ok(json!({ "deployment": resp }))
    }

    async fn op_get_service(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let name = require_str(input, "name")?;
        let resp = client.get_service(namespace, name).await?;
        Ok(json!({ "service": resp }))
    }

    async fn op_list_services(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let label_selector = input
            .get("label_selector")
            .and_then(serde_json::Value::as_str);
        let resp = client.list_services(namespace, label_selector).await?;
        let items = resp.get("items").cloned().unwrap_or(json!([]));
        Ok(json!({ "services": items }))
    }

    async fn op_get_configmap(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let name = require_str(input, "name")?;
        let resp = client.get_configmap(namespace, name).await?;
        Ok(json!({ "configmap": resp }))
    }

    async fn op_update_configmap(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let name = require_str(input, "name")?;
        let data = input.get("data").ok_or_else(|| KubernetesError::Api {
            status_code: 400,
            message: "Missing required field: data".into(),
        })?;
        let resp = client.update_configmap(namespace, name, data).await?;
        Ok(json!({ "configmap": resp }))
    }

    async fn op_get_secret(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let name = require_str(input, "name")?;
        let resp = client.get_secret(namespace, name).await?;

        let unmask = input
            .get("unmask")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);

        if unmask {
            Ok(json!({ "secret": resp }))
        } else {
            let mut redacted = resp;
            if let Some(obj) = redacted.as_object_mut() {
                if let Some(data) = obj.get("data") {
                    let keys: Vec<String> = data
                        .as_object()
                        .map(|d| d.keys().cloned().collect())
                        .unwrap_or_default();
                    obj.insert("data_keys".to_string(), json!(keys));
                    obj.remove("data");
                }
            }
            Ok(json!({ "secret": redacted }))
        }
    }

    async fn op_watch_events(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let field_selector = input
            .get("field_selector")
            .and_then(serde_json::Value::as_str);
        let resource_version = input
            .get("resource_version")
            .and_then(serde_json::Value::as_str);
        let resp = client
            .list_events(namespace, field_selector, resource_version)
            .await?;
        let items = resp.get("items").cloned().unwrap_or(json!([]));
        Ok(json!({ "events": items }))
    }

    // ── Feature 2: Exec ──────────────────────────────────────────────

    async fn op_exec(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let name = require_str(input, "name")?;
        let container = input.get("container").and_then(serde_json::Value::as_str);
        let command = input
            .get("command")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| KubernetesError::Api {
                status_code: 400,
                message: "Missing required field: command (must be an array of strings)".into(),
            })?;
        let mut command_strs: Vec<String> = Vec::with_capacity(command.len());
        for (i, item) in command.iter().enumerate() {
            match item.as_str() {
                Some(s) => command_strs.push(s.to_string()),
                None => {
                    return Err(KubernetesError::Api {
                        status_code: 400,
                        message: format!(
                            "command[{i}] must be a string, got {}",
                            item_type_name(item)
                        ),
                    });
                }
            }
        }
        if command_strs.is_empty() {
            return Err(KubernetesError::Api {
                status_code: 400,
                message: "command array must contain at least one string element".into(),
            });
        }
        self.validate_exec_request(client, namespace, name, container, &command_strs)
            .await?;
        let resp = client
            .exec_in_pod(namespace, name, container, &command_strs)
            .await?;
        Ok(json!({ "exec_result": resp }))
    }

    // ── Feature 3: ConfigMap CRUD ────────────────────────────────────

    async fn op_configmap_list(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let label_selector = input
            .get("label_selector")
            .and_then(serde_json::Value::as_str);
        let resp = client.list_configmaps(namespace, label_selector).await?;
        let items = resp.get("items").cloned().unwrap_or(json!([]));
        Ok(json!({ "configmaps": items }))
    }

    async fn op_configmap_get(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let name = require_str(input, "name")?;
        let resp = client.get_configmap(namespace, name).await?;
        Ok(json!({ "configmap": resp }))
    }

    async fn op_configmap_create(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let name = require_str(input, "name")?;
        let data = input.get("data").ok_or_else(|| KubernetesError::Api {
            status_code: 400,
            message: "Missing required field: data".into(),
        })?;
        let labels = input
            .get("labels")
            .cloned()
            .unwrap_or(serde_json::Value::Null);

        let mut body = json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": name,
                "namespace": namespace,
            },
            "data": data,
        });
        if !labels.is_null() {
            body["metadata"]["labels"] = labels;
        }
        let resp = client.create_configmap(namespace, &body).await?;
        Ok(json!({ "configmap": resp }))
    }

    async fn op_configmap_update(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let name = require_str(input, "name")?;
        let data = input.get("data").ok_or_else(|| KubernetesError::Api {
            status_code: 400,
            message: "Missing required field: data".into(),
        })?;
        let resp = client.update_configmap(namespace, name, data).await?;
        Ok(json!({ "configmap": resp }))
    }

    async fn op_configmap_delete(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let name = require_str(input, "name")?;
        let _resp = client.delete_configmap(namespace, name).await?;
        Ok(json!({ "deleted": true }))
    }

    // ── Feature 3: Secret CRUD ───────────────────────────────────────

    async fn op_secret_list(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let label_selector = input
            .get("label_selector")
            .and_then(serde_json::Value::as_str);
        let resp = client.list_secrets(namespace, label_selector).await?;
        // Strip secret data from list results -- metadata only
        let items = resp.get("items").cloned().unwrap_or(json!([]));
        let sanitized: Vec<serde_json::Value> = items
            .as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .map(|item| {
                let mut s = item.clone();
                if let Some(obj) = s.as_object_mut() {
                    obj.remove("data");
                }
                s
            })
            .collect();
        Ok(json!({ "secrets": sanitized }))
    }

    async fn op_secret_get(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let name = require_str(input, "name")?;
        let resp = client.get_secret(namespace, name).await?;
        Ok(json!({ "secret": resp }))
    }

    async fn op_secret_create(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let name = require_str(input, "name")?;
        let data = input.get("data").ok_or_else(|| KubernetesError::Api {
            status_code: 400,
            message: "Missing required field: data".into(),
        })?;
        let secret_type = input
            .get("type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("Opaque");
        let labels = input
            .get("labels")
            .cloned()
            .unwrap_or(serde_json::Value::Null);

        let mut body = json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": name,
                "namespace": namespace,
            },
            "type": secret_type,
            "data": data,
        });
        if !labels.is_null() {
            body["metadata"]["labels"] = labels;
        }
        let resp = client.create_secret(namespace, &body).await?;
        Ok(json!({ "secret": resp }))
    }

    async fn op_secret_delete(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let name = require_str(input, "name")?;
        let _resp = client.delete_secret(namespace, name).await?;
        Ok(json!({ "deleted": true }))
    }

    // ── Rollout operations ──────────────────────────────────────

    async fn op_rollout_status(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let name = require_str(input, "name")?;
        let deploy = client.get_rollout_status(namespace, name).await?;
        let status = deploy.get("status").cloned().unwrap_or(json!({}));

        let replicas = status
            .get("replicas")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let updated = status
            .get("updatedReplicas")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let ready = status
            .get("readyReplicas")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let available = status
            .get("availableReplicas")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let unavailable = status
            .get("unavailableReplicas")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let generation = status.get("observedGeneration").and_then(|v| v.as_u64());
        let conditions = status.get("conditions").cloned();
        let rollout_complete =
            replicas == updated && replicas == available && unavailable.unwrap_or(0) == 0;

        Ok(json!({
            "rollout_status": {
                "deployment_name": name,
                "namespace": namespace,
                "replicas": replicas,
                "updated_replicas": updated,
                "ready_replicas": ready,
                "available_replicas": available,
                "unavailable_replicas": unavailable,
                "observed_generation": generation,
                "conditions": conditions,
                "rollout_complete": rollout_complete,
            }
        }))
    }

    async fn op_rollout_history(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let name = require_str(input, "name")?;
        let rs_list = client.get_rollout_history(namespace, name).await?;
        let items = rs_list
            .get("items")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let revisions: Vec<serde_json::Value> = items
            .iter()
            .map(|rs| {
                let revision = rs
                    .get("metadata")
                    .and_then(|m| m.get("annotations"))
                    .and_then(|a| a.get("deployment.kubernetes.io/revision"))
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<u64>().ok());
                let rs_name = rs
                    .get("metadata")
                    .and_then(|m| m.get("name"))
                    .and_then(|v| v.as_str());
                let created = rs
                    .get("metadata")
                    .and_then(|m| m.get("creationTimestamp"))
                    .and_then(|v| v.as_str());
                let replicas = rs
                    .get("spec")
                    .and_then(|s| s.get("replicas"))
                    .and_then(|v| v.as_u64())
                    .and_then(|v| u32::try_from(v).ok());
                let image = rs
                    .get("spec")
                    .and_then(|s| s.get("template"))
                    .and_then(|t| t.get("spec"))
                    .and_then(|s| s.get("containers"))
                    .and_then(|c| c.as_array())
                    .and_then(|arr| arr.first())
                    .and_then(|c| c.get("image"))
                    .and_then(|v| v.as_str());
                let labels = rs.get("metadata").and_then(|m| m.get("labels")).cloned();
                json!({
                    "revision": revision,
                    "name": rs_name,
                    "creation_timestamp": created,
                    "replicas": replicas,
                    "image": image,
                    "labels": labels,
                })
            })
            .collect();

        Ok(json!({ "revisions": revisions }))
    }

    async fn op_rollout_rollback(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let name = require_str(input, "name")?;
        let template = input.get("template").ok_or(KubernetesError::Api {
            status_code: 400,
            message: "Missing required field: template".into(),
        })?;
        validate_template_spec(template, "rollout template")?;
        let result = client.rollout_rollback(namespace, name, template).await?;
        Ok(json!({ "deployment": result }))
    }

    fn prepare_operation(
        &self,
        operation: &OperationId,
        input: &serde_json::Value,
    ) -> FcpResult<Vec<String>> {
        self.base.check_ready()?;
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        operation_contracts()?.validate_input(operation, input)?;
        self.authorize_operation(operation.as_str(), input)
            .map_err(|error| error.to_fcp_error())?;
        let namespace = require_str(input, "namespace").map_err(|error| error.to_fcp_error())?;
        validate_resource_name(namespace, "namespace", false)?;
        let (collection, named, subresource) = match operation.as_str() {
            "kubernetes.list_pods" => ("pods", false, ""),
            "kubernetes.get_pod" | "kubernetes.create_pod" | "kubernetes.delete_pod" => {
                ("pods", true, "")
            }
            "kubernetes.get_pod_logs" | "kubernetes.stream_pod_logs" => ("pods", true, "/log"),
            "kubernetes.exec" => ("pods", true, "/exec"),
            "kubernetes.list_deployments" => ("deployments", false, ""),
            "kubernetes.scale_deployment" => ("deployments", true, "/scale"),
            "kubernetes.get_deployment"
            | "kubernetes.apply_deployment"
            | "kubernetes.delete_deployment"
            | "kubernetes.rollout_restart"
            | "kubernetes.rollout.status"
            | "kubernetes.rollout.history"
            | "kubernetes.rollout.rollback" => ("deployments", true, ""),
            "kubernetes.list_services" => ("services", false, ""),
            "kubernetes.get_service" => ("services", true, ""),
            "kubernetes.configmap.list" => ("configmaps", false, ""),
            "kubernetes.get_configmap"
            | "kubernetes.update_configmap"
            | "kubernetes.configmap.get"
            | "kubernetes.configmap.create"
            | "kubernetes.configmap.update"
            | "kubernetes.configmap.delete" => ("configmaps", true, ""),
            "kubernetes.secret.list" => ("secrets", false, ""),
            "kubernetes.get_secret"
            | "kubernetes.secret.get"
            | "kubernetes.secret.create"
            | "kubernetes.secret.delete" => ("secrets", true, ""),
            "kubernetes.watch_events" => ("events", false, ""),
            _ => {
                return Err(FcpError::OperationNotGranted {
                    operation: operation.as_str().into(),
                });
            }
        };
        let cluster = utf8_percent_encode(config.base_url.trim_end_matches('/'), NON_ALPHANUMERIC);
        let mut resource =
            format!("kubernetes://cluster/{cluster}/namespaces/{namespace}/{collection}");
        if named {
            let name = require_str(input, "name").map_err(|error| error.to_fcp_error())?;
            validate_resource_name(name, "name", true)?;
            resource.push('/');
            resource.push_str(name);
            resource.push_str(subresource);
        }
        if let Some(container) = input.get("container") {
            let container = container.as_str().ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "container must be a DNS label".into(),
            })?;
            validate_resource_name(container, "container", false)?;
        }
        for field in [
            "replicas",
            "grace_period_seconds",
            "tail_lines",
            "since_seconds",
        ] {
            if let Some(value) = input.get(field) {
                let number = value.as_u64().ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("{field} must be a nonnegative integer"),
                })?;
                if field == "replicas" && number > u64::from(u32::MAX) {
                    return Err(FcpError::InvalidRequest {
                        code: 1003,
                        message: "replicas exceeds the supported range".into(),
                    });
                }
            }
        }
        let invalid = |error: KubernetesError| error.to_fcp_error();
        match operation.as_str() {
            "kubernetes.create_pod" => {
                validate_pod_spec(&input["spec"], "pod spec").map_err(invalid)?
            }
            "kubernetes.apply_deployment" => {
                validate_deployment_spec(&input["spec"]).map_err(invalid)?
            }
            "kubernetes.rollout.rollback" => {
                validate_template_spec(&input["template"], "rollout template").map_err(invalid)?
            }
            "kubernetes.exec" => {
                let command: Vec<String> = serde_json::from_value(input["command"].clone())
                    .map_err(|_| FcpError::InvalidRequest {
                        code: 1003,
                        message: "command must be a nonempty array of strings".into(),
                    })?;
                if command.is_empty() || command[0].trim().is_empty() {
                    return Err(FcpError::InvalidRequest {
                        code: 1003,
                        message: "command must name an executable".into(),
                    });
                }
                if (is_system_namespace(namespace)
                    && !config.policy.allow_exec_into_system_namespaces)
                    || (command_uses_shell(&command) && !config.policy.allow_shell_exec)
                {
                    return Err(KubernetesError::PolicyDenied(
                        "Exec target or command is not permitted by the configured policy".into(),
                    )
                    .to_fcp_error());
                }
            }
            _ => {}
        }
        Ok(vec![resource])
    }

    fn handshake_capabilities(&self) -> Vec<&'static str> {
        let Some(config) = &self.config else {
            return vec!["kubernetes.read", "kubernetes.secrets"];
        };

        let mut capabilities = vec!["kubernetes.read", "kubernetes.secrets"];
        if config.policy.allow_write_operations {
            capabilities.push("kubernetes.write");
        }
        if config.policy.allow_write_operations || config.policy.allow_pod_exec {
            capabilities.push("kubernetes.admin");
        }
        capabilities
    }

    fn authorize_operation(
        &self,
        operation: &str,
        input: &serde_json::Value,
    ) -> Result<(), KubernetesError> {
        let Some(config) = &self.config else {
            return Ok(());
        };

        if let Some(namespace) = input.get("namespace").and_then(serde_json::Value::as_str) {
            config
                .policy
                .enforce_namespace_scope(namespace, operation)?;
        }

        match OperationCategory::classify(operation) {
            Some(OperationCategory::Exec) if !config.policy.allow_pod_exec => {
                Err(KubernetesError::PolicyDenied(
                    "kubernetes.exec is disabled until configure sets allow_pod_exec=true".into(),
                ))
            }
            Some(
                OperationCategory::Write | OperationCategory::Deploy | OperationCategory::Delete,
            ) if !config.policy.allow_write_operations => Err(KubernetesError::PolicyDenied(
                format!("{operation} is disabled until configure sets allow_write_operations=true"),
            )),
            Some(OperationCategory::Secret)
                if is_secret_mutation(operation) && !config.policy.allow_write_operations =>
            {
                Err(KubernetesError::PolicyDenied(format!(
                    "{operation} is disabled until configure sets allow_write_operations=true"
                )))
            }
            _ => Ok(()),
        }
    }

    async fn validate_exec_request(
        &self,
        client: &KubernetesClient,
        namespace: &str,
        name: &str,
        container: Option<&str>,
        command: &[String],
    ) -> Result<(), KubernetesError> {
        let Some(config) = &self.config else {
            return Ok(());
        };
        let policy = &config.policy;

        if is_system_namespace(namespace) && !policy.allow_exec_into_system_namespaces {
            return Err(KubernetesError::PolicyDenied(format!(
                "kubernetes.exec is blocked in system namespace '{namespace}'"
            )));
        }

        if command_uses_shell(command) && !policy.allow_shell_exec {
            return Err(KubernetesError::PolicyDenied(
                "kubernetes.exec refuses shell trampolines until configure sets allow_shell_exec=true"
                    .into(),
            ));
        }

        let pod = client.get_pod(namespace, name).await?;
        validate_exec_target_pod(&pod, container)?;

        if !policy.allow_untrusted_exec_targets {
            enforce_exec_target_labels(&pod, &policy.exec_required_pod_labels)?;
        }

        Ok(())
    }
}

/// A route and its authorization resource must name the same Kubernetes object.
/// Reject normalization, query syntax, escapes and whitespace before admission.
fn validate_resource_name(value: &str, field: &str, subdomain: bool) -> FcpResult<()> {
    let valid_label = |label: &str| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    };
    let valid = if subdomain {
        value.len() <= 253 && value.split('.').all(valid_label)
    } else {
        valid_label(value)
    };
    if valid {
        Ok(())
    } else {
        Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must be a valid Kubernetes resource name"),
        })
    }
}

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, KubernetesError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| KubernetesError::InvalidInput(format!("Missing required field: {field}")))
}

fn parse_string_set(
    params: &serde_json::Value,
    field: &str,
) -> FcpResult<Option<BTreeSet<String>>> {
    let Some(raw) = params.get(field) else {
        return Ok(None);
    };
    let values = raw.as_array().ok_or_else(|| FcpError::InvalidRequest {
        code: 1003,
        message: format!("{field} must be an array of namespace strings"),
    })?;

    let mut parsed = BTreeSet::new();
    for (idx, value) in values.iter().enumerate() {
        let namespace = value.as_str().ok_or_else(|| FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field}[{idx}] must be a string"),
        })?;
        let namespace = namespace.trim();
        if namespace.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("{field}[{idx}] must not be empty"),
            });
        }
        parsed.insert(namespace.to_string());
    }

    if parsed.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must contain at least one namespace"),
        });
    }

    Ok(Some(parsed))
}

fn parse_string_map(
    params: &serde_json::Value,
    field: &str,
) -> FcpResult<Option<BTreeMap<String, String>>> {
    let Some(raw) = params.get(field) else {
        return Ok(None);
    };
    let values = raw.as_object().ok_or_else(|| FcpError::InvalidRequest {
        code: 1003,
        message: format!("{field} must be an object of string:string label pairs"),
    })?;

    let mut parsed = BTreeMap::new();
    for (key, value) in values {
        let trimmed_key = key.trim();
        let parsed_value = value.as_str().ok_or_else(|| FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field}.{key} must be a string"),
        })?;
        let trimmed_value = parsed_value.trim();
        if trimmed_key.is_empty() || trimmed_value.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("{field} keys and values must not be empty"),
            });
        }
        parsed.insert(trimmed_key.to_string(), trimmed_value.to_string());
    }

    Ok(Some(parsed))
}

fn default_exec_required_labels() -> BTreeMap<String, String> {
    BTreeMap::from([(
        "fcp.flywheel.ai/exec-approved".to_string(),
        "true".to_string(),
    )])
}

fn join_namespaces(namespaces: &BTreeSet<String>) -> String {
    namespaces.iter().cloned().collect::<Vec<_>>().join(",")
}

// NOTE: the four helpers below match on `&str` literals via `matches!`.
// They MUST remain non-const on the current nightly toolchain —
// `str` equality inside `const fn` still requires unstable const-trait
// support and breaks `fcp-e2e` builds (bead flywheel_connectors-q0y8h,
// prior fix in f8712801). If a future rustfmt sweep or "make everything
// const" refactor adds `const` back, the compiler surfaces
// `E0658: cannot match on 'str' in constant functions` and the entire
// `fcp-e2e` dev-dependency graph fails to build. Leave these as `fn`.
fn is_secret_mutation(operation: &str) -> bool {
    matches!(
        operation,
        "kubernetes.secret.create" | "kubernetes.secret.delete"
    )
}

fn is_system_namespace(namespace: &str) -> bool {
    matches!(namespace, "kube-system" | "kube-public" | "kube-node-lease")
}

fn command_uses_shell(command: &[String]) -> bool {
    if command.is_empty() {
        return false;
    }

    let first = command_binary_name(&command[0]);
    if is_shell_binary(first) {
        return true;
    }

    first == "env" && command.len() > 1 && is_shell_binary(command_binary_name(&command[1]))
}

fn command_binary_name(binary: &str) -> &str {
    binary.rsplit('/').next().unwrap_or(binary)
}

fn is_shell_binary(binary: &str) -> bool {
    matches!(
        binary,
        "sh" | "bash"
            | "dash"
            | "ash"
            | "zsh"
            | "ksh"
            | "fish"
            | "python"
            | "python3"
            | "perl"
            | "ruby"
            | "node"
            | "cmd"
            | "powershell"
            | "pwsh"
    )
}

fn validate_deployment_spec(spec: &serde_json::Value) -> Result<(), KubernetesError> {
    let template_spec = spec.pointer("/template/spec").ok_or_else(|| {
        KubernetesError::InvalidInput("deployment spec.template.spec is required".into())
    })?;
    validate_pod_spec(template_spec, "deployment spec.template.spec")
}

fn validate_template_spec(
    template: &serde_json::Value,
    context: &str,
) -> Result<(), KubernetesError> {
    let pod_spec = template
        .get("spec")
        .ok_or_else(|| KubernetesError::InvalidInput(format!("{context}.spec is required")))?;
    validate_pod_spec(pod_spec, &format!("{context}.spec"))
}

fn validate_pod_spec(spec: &serde_json::Value, context: &str) -> Result<(), KubernetesError> {
    let spec_obj = spec
        .as_object()
        .ok_or_else(|| KubernetesError::InvalidInput(format!("{context} must be an object")))?;

    for field in ["hostNetwork", "hostPID", "hostIPC", "shareProcessNamespace"] {
        if spec_obj
            .get(field)
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            return Err(KubernetesError::InvalidInput(format!(
                "{context}.{field} must not be enabled"
            )));
        }
    }

    for field in ["serviceAccountName", "serviceAccount", "nodeName"] {
        if spec_obj
            .get(field)
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| !value.trim().is_empty())
        {
            return Err(KubernetesError::InvalidInput(format!(
                "{context}.{field} must not be set"
            )));
        }
    }

    if spec_obj
        .get("automountServiceAccountToken")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return Err(KubernetesError::InvalidInput(format!(
            "{context}.automountServiceAccountToken must not be true"
        )));
    }

    if let Some(volumes) = spec_obj
        .get("volumes")
        .and_then(serde_json::Value::as_array)
    {
        for (idx, volume) in volumes.iter().enumerate() {
            if volume.get("hostPath").is_some() {
                return Err(KubernetesError::InvalidInput(format!(
                    "{context}.volumes[{idx}].hostPath is forbidden"
                )));
            }
            if volume
                .pointer("/projected/sources")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|sources| {
                    sources
                        .iter()
                        .any(|source| source.get("serviceAccountToken").is_some())
                })
            {
                return Err(KubernetesError::InvalidInput(format!(
                    "{context}.volumes[{idx}] must not project serviceAccountToken"
                )));
            }
        }
    }

    validate_container_group(spec_obj.get("containers"), context, "containers")?;
    validate_container_group(spec_obj.get("initContainers"), context, "initContainers")?;

    Ok(())
}

fn validate_container_group(
    group: Option<&serde_json::Value>,
    context: &str,
    field: &str,
) -> Result<(), KubernetesError> {
    let Some(group) = group else {
        if field == "containers" {
            return Err(KubernetesError::InvalidInput(format!(
                "{context}.containers must contain at least one container"
            )));
        }
        return Ok(());
    };

    let containers = group.as_array().ok_or_else(|| {
        KubernetesError::InvalidInput(format!("{context}.{field} must be an array"))
    })?;
    if field == "containers" && containers.is_empty() {
        return Err(KubernetesError::InvalidInput(format!(
            "{context}.containers must contain at least one container"
        )));
    }

    for (idx, container) in containers.iter().enumerate() {
        validate_container_spec(container, context, field, idx)?;
    }
    Ok(())
}

fn validate_container_spec(
    container: &serde_json::Value,
    context: &str,
    field: &str,
    idx: usize,
) -> Result<(), KubernetesError> {
    let container_obj = container.as_object().ok_or_else(|| {
        KubernetesError::InvalidInput(format!("{context}.{field}[{idx}] must be an object"))
    })?;
    validate_named_image_field(container_obj, context, field, idx, "name")?;
    validate_named_image_field(container_obj, context, field, idx, "image")?;

    if let Some(ports) = container_obj
        .get("ports")
        .and_then(serde_json::Value::as_array)
    {
        for (port_idx, port) in ports.iter().enumerate() {
            if port
                .get("hostPort")
                .and_then(serde_json::Value::as_u64)
                .is_some()
            {
                return Err(KubernetesError::InvalidInput(format!(
                    "{context}.{field}[{idx}].ports[{port_idx}].hostPort is forbidden"
                )));
            }
        }
    }

    if let Some(security_context) = container_obj.get("securityContext") {
        if security_context
            .get("privileged")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            return Err(KubernetesError::InvalidInput(format!(
                "{context}.{field}[{idx}].securityContext.privileged must not be true"
            )));
        }
        if security_context
            .get("allowPrivilegeEscalation")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            return Err(KubernetesError::InvalidInput(format!(
                "{context}.{field}[{idx}].securityContext.allowPrivilegeEscalation must not be true"
            )));
        }
        if security_context
            .pointer("/capabilities/add")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|caps| !caps.is_empty())
        {
            return Err(KubernetesError::InvalidInput(format!(
                "{context}.{field}[{idx}].securityContext.capabilities.add must be empty"
            )));
        }
    }

    Ok(())
}

fn validate_named_image_field(
    container: &serde_json::Map<String, serde_json::Value>,
    context: &str,
    field: &str,
    idx: usize,
    target_field: &str,
) -> Result<(), KubernetesError> {
    if container
        .get(target_field)
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| !value.trim().is_empty())
    {
        return Ok(());
    }

    Err(KubernetesError::InvalidInput(format!(
        "{context}.{field}[{idx}].{target_field} must be a non-empty string"
    )))
}

fn validate_exec_target_pod(
    pod: &serde_json::Value,
    container: Option<&str>,
) -> Result<(), KubernetesError> {
    let Some(spec_obj) = pod.get("spec").and_then(serde_json::Value::as_object) else {
        return Err(KubernetesError::PolicyDenied(
            "kubernetes.exec target pod did not include a pod spec".into(),
        ));
    };

    for field in ["hostNetwork", "hostPID", "hostIPC"] {
        if spec_obj
            .get(field)
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            return Err(KubernetesError::PolicyDenied(format!(
                "kubernetes.exec refuses target pods with {field}=true"
            )));
        }
    }

    if let Some(volumes) = spec_obj
        .get("volumes")
        .and_then(serde_json::Value::as_array)
    {
        for volume in volumes {
            if volume.get("hostPath").is_some() {
                return Err(KubernetesError::PolicyDenied(
                    "kubernetes.exec refuses target pods mounting hostPath".into(),
                ));
            }
        }
    }

    let containers = spec_obj
        .get("containers")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            KubernetesError::PolicyDenied(
                "kubernetes.exec target pod must include at least one container".into(),
            )
        })?;
    if containers.is_empty() {
        return Err(KubernetesError::PolicyDenied(
            "kubernetes.exec target pod must include at least one container".into(),
        ));
    }

    for (idx, pod_container) in containers.iter().enumerate() {
        if let Some(security_context) = pod_container.get("securityContext") {
            if security_context
                .get("privileged")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
            {
                return Err(KubernetesError::PolicyDenied(format!(
                    "kubernetes.exec refuses target container[{idx}] because it is privileged"
                )));
            }
            if security_context
                .get("allowPrivilegeEscalation")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
            {
                return Err(KubernetesError::PolicyDenied(format!(
                    "kubernetes.exec refuses target container[{idx}] because allowPrivilegeEscalation=true"
                )));
            }
        }
    }

    if let Some(container_name) = container {
        if !containers.iter().any(|candidate| {
            candidate
                .get("name")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|value| value == container_name)
        }) {
            return Err(KubernetesError::PolicyDenied(format!(
                "kubernetes.exec target pod does not have container '{container_name}'"
            )));
        }
    } else if containers.len() > 1 {
        return Err(KubernetesError::PolicyDenied(
            "kubernetes.exec requires an explicit container for multi-container pods".into(),
        ));
    }

    Ok(())
}

fn enforce_exec_target_labels(
    pod: &serde_json::Value,
    required_labels: &BTreeMap<String, String>,
) -> Result<(), KubernetesError> {
    let labels = pod
        .pointer("/metadata/labels")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            KubernetesError::PolicyDenied(
                "kubernetes.exec target pod is missing metadata.labels".into(),
            )
        })?;

    for (key, expected) in required_labels {
        let actual = labels
            .get(key)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                KubernetesError::PolicyDenied(format!(
                    "kubernetes.exec target pod is missing required label '{key}={expected}'"
                ))
            })?;
        if actual != expected {
            return Err(KubernetesError::PolicyDenied(format!(
                "kubernetes.exec target pod label '{key}' must equal '{expected}', got '{actual}'"
            )));
        }
    }

    Ok(())
}

/// Human-readable type name for a JSON value (used in error messages).
const fn item_type_name(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

fn is_local_test_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "::1"
        || host == "[::1]"
}

fn base_url_policy(base_url: &str) -> (bool, String) {
    let Ok(parsed) = Url::parse(base_url) else {
        return (
            false,
            "base_url must be an absolute URL with a scheme and host".into(),
        );
    };

    let Some(host_part) = parsed.host_str() else {
        return (false, "base_url must include a host".into());
    };

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return (false, "base_url must not include userinfo".into());
    }

    if parsed.query().is_some() {
        return (false, "base_url must not include query parameters".into());
    }

    if parsed.fragment().is_some() {
        return (false, "base_url must not include a fragment".into());
    }

    let scheme = parsed.scheme();
    if scheme != "https" && scheme != "http" {
        return (false, "base_url scheme must be http or https".into());
    }

    let host_lower = host_part.to_ascii_lowercase();
    let local = is_local_test_host(host_part);
    let allowed_host = host_lower == "kubernetes.default.svc"
        || host_lower.as_bytes().ends_with(b".svc")
        || host_lower.as_bytes().ends_with(b".svc.cluster.local")
        || local;
    let secure_or_local = scheme == "https" || local;

    if !secure_or_local {
        return (
            false,
            format!("base_url must use https for non-local hosts (got {scheme}://{host_part})"),
        );
    }

    if !allowed_host {
        return (
            true,
            format!(
                "base_url accepted: custom host {host_part} (not a standard in-cluster endpoint)"
            ),
        );
    }

    (true, format!("base_url accepted: {host_part}"))
}

fn operations_info() -> Vec<OperationInfo> {
    vec![
        op_info(
            "kubernetes.list_pods",
            "List pods in a namespace",
            json!({
                "type": "object",
                "required": ["namespace"],
                "properties": {
                    "namespace": { "type": "string" },
                    "label_selector": { "type": "string" },
                    "field_selector": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["pods"],
                "properties": { "pods": { "type": "array" } }
            }),
            "kubernetes.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List pods in a namespace, optionally filtered by labels.".into(),
                common_mistakes: vec!["Not using label selectors on large namespaces".into()],
                examples: vec![
                    r#"{"namespace": "production", "label_selector": "app=api-server"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("kubernetes.get_pod"),
                    CapabilityId::from_static("kubernetes.get_deployment"),
                ],
            },
        ),
        op_info(
            "kubernetes.get_pod",
            "Get a pod by name",
            json!({
                "type": "object",
                "required": ["namespace", "name"],
                "properties": {
                    "namespace": { "type": "string" },
                    "name": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["pod"],
                "properties": { "pod": { "type": "object" } }
            }),
            "kubernetes.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Retrieve details about a specific pod.".into(),
                common_mistakes: vec![
                    "Forgetting to specify namespace (defaults to 'default')".into(),
                ],
                examples: vec![
                    r#"{"namespace": "production", "name": "api-server-5f4b8c9-x7k2p"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("kubernetes.list_pods"),
                    CapabilityId::from_static("kubernetes.get_pod_logs"),
                ],
            },
        ),
        op_info(
            "kubernetes.delete_pod",
            "Delete a pod",
            json!({
                "type": "object",
                "required": ["namespace", "name"],
                "properties": {
                    "namespace": { "type": "string" },
                    "name": { "type": "string" },
                    "grace_period_seconds": { "type": "integer" }
                }
            }),
            json!({
                "type": "object",
                "required": ["deleted"],
                "properties": { "deleted": { "type": "boolean" } }
            }),
            "kubernetes.admin",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::BestEffort,
            AgentHint {
                when_to_use: "Force-delete a pod to trigger rescheduling.".into(),
                common_mistakes: vec![
                    "Deleting pods managed by a Deployment (they respawn)".into(),
                    "Using grace_period_seconds=0 on stateful pods".into(),
                ],
                examples: vec![
                    r#"{"namespace": "production", "name": "api-server-5f4b8c9-x7k2p"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("kubernetes.get_pod"),
                    CapabilityId::from_static("kubernetes.scale_deployment"),
                ],
            },
        ),
        op_info(
            "kubernetes.create_pod",
            "Create a pod",
            json!({
                "type": "object",
                "required": ["namespace", "name", "spec"],
                "properties": {
                    "namespace": { "type": "string" },
                    "name": { "type": "string" },
                    "spec": { "type": "object" },
                    "labels": { "type": "object" }
                }
            }),
            json!({
                "type": "object",
                "required": ["pod"],
                "properties": { "pod": { "type": "object" } }
            }),
            "kubernetes.admin",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Create a new pod in a namespace.".into(),
                common_mistakes: vec![
                    "Creating standalone pods instead of using Deployments".into(),
                    "Not specifying resource requests/limits".into(),
                ],
                examples: vec![
                    r#"{"namespace": "default", "name": "debug-pod", "spec": {"containers": [{"name": "debug", "image": "busybox"}]}}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("kubernetes.get_pod"),
                    CapabilityId::from_static("kubernetes.delete_pod"),
                ],
            },
        ),
        op_info(
            "kubernetes.get_pod_logs",
            "Retrieve logs from a pod",
            json!({
                "type": "object",
                "required": ["namespace", "name"],
                "properties": {
                    "namespace": { "type": "string" },
                    "name": { "type": "string" },
                    "container": { "type": "string" },
                    "tail_lines": { "type": "integer" },
                    "since_seconds": { "type": "integer" }
                }
            }),
            json!({
                "type": "object",
                "required": ["logs"],
                "properties": { "logs": { "type": "string" } }
            }),
            "kubernetes.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Read container logs from a pod.".into(),
                common_mistakes: vec![
                    "Not specifying container in multi-container pods".into(),
                    "Requesting unbounded logs on high-throughput pods".into(),
                ],
                examples: vec![
                    r#"{"namespace": "production", "name": "api-server-5f4b8c9-x7k2p", "tail_lines": 100}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("kubernetes.get_pod"),
                    CapabilityId::from_static("kubernetes.stream_pod_logs"),
                ],
            },
        ),
        op_info(
            "kubernetes.stream_pod_logs",
            "Stream live logs from a pod",
            json!({
                "type": "object",
                "required": ["namespace", "name"],
                "properties": {
                    "namespace": { "type": "string" },
                    "name": { "type": "string" },
                    "container": { "type": "string" },
                    "tail_lines": { "type": "integer" }
                }
            }),
            json!({
                "type": "object",
                "required": ["log_line"],
                "properties": { "log_line": { "type": "string" } }
            }),
            "kubernetes.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Follow live log output from a pod container.".into(),
                common_mistakes: vec![
                    "Not specifying container in multi-container pods".into(),
                ],
                examples: vec![
                    r#"{"namespace": "production", "name": "api-server-5f4b8c9-x7k2p", "tail_lines": 50}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("kubernetes.get_pod_logs"),
                    CapabilityId::from_static("kubernetes.watch_events"),
                ],
            },
        ),
        op_info(
            "kubernetes.list_deployments",
            "List deployments in a namespace",
            json!({
                "type": "object",
                "required": ["namespace"],
                "properties": {
                    "namespace": { "type": "string" },
                    "label_selector": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["deployments"],
                "properties": { "deployments": { "type": "array" } }
            }),
            "kubernetes.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List all deployments in a namespace.".into(),
                common_mistakes: vec![],
                examples: vec![r#"{"namespace": "production"}"#.into()],
                related: vec![
                    CapabilityId::from_static("kubernetes.get_deployment"),
                    CapabilityId::from_static("kubernetes.scale_deployment"),
                ],
            },
        ),
        op_info(
            "kubernetes.get_deployment",
            "Get a deployment by name",
            json!({
                "type": "object",
                "required": ["namespace", "name"],
                "properties": {
                    "namespace": { "type": "string" },
                    "name": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["deployment"],
                "properties": { "deployment": { "type": "object" } }
            }),
            "kubernetes.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Retrieve details about a specific deployment.".into(),
                common_mistakes: vec![],
                examples: vec![
                    r#"{"namespace": "production", "name": "api-server"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("kubernetes.list_deployments"),
                    CapabilityId::from_static("kubernetes.scale_deployment"),
                ],
            },
        ),
        op_info(
            "kubernetes.apply_deployment",
            "Create or update a deployment",
            json!({
                "type": "object",
                "required": ["namespace", "name", "spec"],
                "properties": {
                    "namespace": { "type": "string" },
                    "name": { "type": "string" },
                    "spec": { "type": "object" },
                    "labels": { "type": "object" },
                    "update": { "type": "boolean" }
                }
            }),
            json!({
                "type": "object",
                "required": ["deployment"],
                "properties": { "deployment": { "type": "object" } }
            }),
            "kubernetes.admin",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::BestEffort,
            AgentHint {
                when_to_use: "Create a new deployment or update an existing one.".into(),
                common_mistakes: vec![
                    "Forgetting to include selector.matchLabels matching pod template labels".into(),
                    "Setting update=true for a non-existent deployment (use update=false for creation)".into(),
                ],
                examples: vec![
                    r#"{"namespace": "default", "name": "web-app", "spec": {"replicas": 3, "selector": {"matchLabels": {"app": "web"}}, "template": {"metadata": {"labels": {"app": "web"}}, "spec": {"containers": [{"name": "web", "image": "nginx:1.25"}]}}}}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("kubernetes.get_deployment"),
                    CapabilityId::from_static("kubernetes.delete_deployment"),
                ],
            },
        ),
        op_info(
            "kubernetes.delete_deployment",
            "Delete a deployment",
            json!({
                "type": "object",
                "required": ["namespace", "name"],
                "properties": {
                    "namespace": { "type": "string" },
                    "name": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["deleted"],
                "properties": { "deleted": { "type": "boolean" } }
            }),
            "kubernetes.admin",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::BestEffort,
            AgentHint {
                when_to_use: "Delete a deployment and its associated ReplicaSets and pods.".into(),
                common_mistakes: vec![
                    "Deleting a deployment without confirming it can be safely removed".into(),
                    "Not cleaning up associated PVCs or ConfigMaps".into(),
                ],
                examples: vec![
                    r#"{"namespace": "default", "name": "old-web-app"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("kubernetes.get_deployment"),
                    CapabilityId::from_static("kubernetes.apply_deployment"),
                ],
            },
        ),
        op_info(
            "kubernetes.scale_deployment",
            "Scale a deployment",
            json!({
                "type": "object",
                "required": ["namespace", "name", "replicas"],
                "properties": {
                    "namespace": { "type": "string" },
                    "name": { "type": "string" },
                    "replicas": { "type": "integer" }
                }
            }),
            json!({
                "type": "object",
                "required": ["deployment"],
                "properties": { "deployment": { "type": "object" } }
            }),
            "kubernetes.write",
            RiskLevel::High,
            SafetyTier::Risky,
            IdempotencyClass::BestEffort,
            AgentHint {
                when_to_use: "Scale a deployment up or down.".into(),
                common_mistakes: vec![
                    "Scaling to 0 unintentionally".into(),
                    "Not checking HPA before manual scaling".into(),
                ],
                examples: vec![
                    r#"{"namespace": "production", "name": "api-server", "replicas": 3}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("kubernetes.get_deployment"),
                    CapabilityId::from_static("kubernetes.rollout_restart"),
                ],
            },
        ),
        op_info(
            "kubernetes.rollout_restart",
            "Trigger a rolling restart",
            json!({
                "type": "object",
                "required": ["namespace", "name"],
                "properties": {
                    "namespace": { "type": "string" },
                    "name": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["deployment"],
                "properties": { "deployment": { "type": "object" } }
            }),
            "kubernetes.write",
            RiskLevel::High,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Restart all pods in a deployment with zero downtime.".into(),
                common_mistakes: vec!["Restarting during an active rollout".into()],
                examples: vec![
                    r#"{"namespace": "production", "name": "api-server"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("kubernetes.scale_deployment"),
                    CapabilityId::from_static("kubernetes.get_deployment"),
                ],
            },
        ),
        op_info(
            "kubernetes.get_service",
            "Get a service by name",
            json!({
                "type": "object",
                "required": ["namespace", "name"],
                "properties": {
                    "namespace": { "type": "string" },
                    "name": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["service"],
                "properties": { "service": { "type": "object" } }
            }),
            "kubernetes.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Retrieve details about a Kubernetes service.".into(),
                common_mistakes: vec![],
                examples: vec![
                    r#"{"namespace": "production", "name": "api-server"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("kubernetes.list_services"),
                    CapabilityId::from_static("kubernetes.list_pods"),
                ],
            },
        ),
        op_info(
            "kubernetes.list_services",
            "List services in a namespace",
            json!({
                "type": "object",
                "required": ["namespace"],
                "properties": {
                    "namespace": { "type": "string" },
                    "label_selector": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["services"],
                "properties": { "services": { "type": "array" } }
            }),
            "kubernetes.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List all services in a namespace.".into(),
                common_mistakes: vec![],
                examples: vec![r#"{"namespace": "production"}"#.into()],
                related: vec![
                    CapabilityId::from_static("kubernetes.get_service"),
                    CapabilityId::from_static("kubernetes.list_pods"),
                ],
            },
        ),
        op_info(
            "kubernetes.get_configmap",
            "Get a ConfigMap by name",
            json!({
                "type": "object",
                "required": ["namespace", "name"],
                "properties": {
                    "namespace": { "type": "string" },
                    "name": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["configmap"],
                "properties": { "configmap": { "type": "object" } }
            }),
            "kubernetes.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Read configuration data from a ConfigMap.".into(),
                common_mistakes: vec![],
                examples: vec![
                    r#"{"namespace": "production", "name": "app-config"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("kubernetes.update_configmap"),
                    CapabilityId::from_static("kubernetes.get_secret"),
                ],
            },
        ),
        op_info(
            "kubernetes.update_configmap",
            "Update a ConfigMap",
            json!({
                "type": "object",
                "required": ["namespace", "name", "data"],
                "properties": {
                    "namespace": { "type": "string" },
                    "name": { "type": "string" },
                    "data": { "type": "object" }
                }
            }),
            json!({
                "type": "object",
                "required": ["configmap"],
                "properties": { "configmap": { "type": "object" } }
            }),
            "kubernetes.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::BestEffort,
            AgentHint {
                when_to_use: "Update configuration data in a ConfigMap.".into(),
                common_mistakes: vec![
                    "Overwriting all data instead of merging".into(),
                    "Not restarting pods that consume the ConfigMap".into(),
                ],
                examples: vec![
                    r#"{"namespace": "production", "name": "app-config", "data": {"LOG_LEVEL": "debug"}}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("kubernetes.get_configmap"),
                    CapabilityId::from_static("kubernetes.rollout_restart"),
                ],
            },
        ),
        op_info(
            "kubernetes.get_secret",
            "Get a Secret by name (redacted by default)",
            json!({
                "type": "object",
                "required": ["namespace", "name"],
                "properties": {
                    "namespace": { "type": "string" },
                    "name": { "type": "string" },
                    "unmask": { "type": "boolean" }
                }
            }),
            json!({
                "type": "object",
                "required": ["secret"],
                "properties": { "secret": { "type": "object" } }
            }),
            "kubernetes.secrets",
            RiskLevel::High,
            SafetyTier::Risky,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Read a Kubernetes secret (metadata only by default).".into(),
                common_mistakes: vec![
                    "Logging or exposing secret data".into(),
                    "Not setting unmask=false for audit-only reads".into(),
                ],
                examples: vec![
                    r#"{"namespace": "production", "name": "db-credentials"}"#.into(),
                ],
                related: vec![CapabilityId::from_static("kubernetes.get_configmap")],
            },
        ),
        op_info(
            "kubernetes.watch_events",
            "Watch events in a namespace",
            json!({
                "type": "object",
                "required": ["namespace"],
                "properties": {
                    "namespace": { "type": "string" },
                    "field_selector": { "type": "string" },
                    "resource_version": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["events"],
                "properties": { "events": { "type": "array" } }
            }),
            "kubernetes.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Stream cluster events for monitoring or debugging.".into(),
                common_mistakes: vec![
                    "Not handling resourceVersion for reconnection".into(),
                ],
                examples: vec![r#"{"namespace": "production"}"#.into()],
                related: vec![CapabilityId::from_static("kubernetes.stream_pod_logs")],
            },
        ),
        // ── Feature 2: Exec ──────────────────────────────────────────
        op_info(
            "kubernetes.exec",
            "Execute a command in a pod container",
            json!({
                "type": "object",
                "required": ["namespace", "name", "command"],
                "properties": {
                    "namespace": { "type": "string" },
                    "name": { "type": "string" },
                    "container": { "type": "string" },
                    "command": { "type": "array", "items": { "type": "string" } }
                }
            }),
            json!({
                "type": "object",
                "required": ["exec_result"],
                "properties": { "exec_result": { "type": "object" } }
            }),
            "kubernetes.admin",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Run a command inside a running pod container for debugging or maintenance.".into(),
                common_mistakes: vec![
                    "Running destructive commands without confirmation".into(),
                    "Not specifying container in multi-container pods".into(),
                    "Using exec for tasks that should be done via Deployments".into(),
                ],
                examples: vec![
                    r#"{"namespace": "default", "name": "debug-pod", "command": ["ls", "-la", "/app"]}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("kubernetes.get_pod"),
                    CapabilityId::from_static("kubernetes.get_pod_logs"),
                ],
            },
        ),
        // ── Feature 3: ConfigMap CRUD ────────────────────────────────
        op_info(
            "kubernetes.configmap.list",
            "List configmaps in a namespace",
            json!({
                "type": "object",
                "required": ["namespace"],
                "properties": {
                    "namespace": { "type": "string" },
                    "label_selector": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["configmaps"],
                "properties": { "configmaps": { "type": "array" } }
            }),
            "kubernetes.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List all configmaps in a namespace.".into(),
                common_mistakes: vec![],
                examples: vec![r#"{"namespace": "production"}"#.into()],
                related: vec![
                    CapabilityId::from_static("kubernetes.configmap.get"),
                    CapabilityId::from_static("kubernetes.configmap.create"),
                ],
            },
        ),
        op_info(
            "kubernetes.configmap.get",
            "Get a configmap by name",
            json!({
                "type": "object",
                "required": ["namespace", "name"],
                "properties": {
                    "namespace": { "type": "string" },
                    "name": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["configmap"],
                "properties": { "configmap": { "type": "object" } }
            }),
            "kubernetes.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Retrieve a specific configmap by name.".into(),
                common_mistakes: vec![],
                examples: vec![
                    r#"{"namespace": "production", "name": "app-config"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("kubernetes.configmap.list"),
                    CapabilityId::from_static("kubernetes.configmap.update"),
                ],
            },
        ),
        op_info(
            "kubernetes.configmap.create",
            "Create a configmap",
            json!({
                "type": "object",
                "required": ["namespace", "name", "data"],
                "properties": {
                    "namespace": { "type": "string" },
                    "name": { "type": "string" },
                    "data": { "type": "object" },
                    "labels": { "type": "object" }
                }
            }),
            json!({
                "type": "object",
                "required": ["configmap"],
                "properties": { "configmap": { "type": "object" } }
            }),
            "kubernetes.admin",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Create a new configmap in a namespace.".into(),
                common_mistakes: vec![
                    "Creating duplicate configmaps with the same name".into(),
                ],
                examples: vec![
                    r#"{"namespace": "default", "name": "app-config", "data": {"LOG_LEVEL": "info"}}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("kubernetes.configmap.get"),
                    CapabilityId::from_static("kubernetes.configmap.update"),
                ],
            },
        ),
        op_info(
            "kubernetes.configmap.update",
            "Update a configmap",
            json!({
                "type": "object",
                "required": ["namespace", "name", "data"],
                "properties": {
                    "namespace": { "type": "string" },
                    "name": { "type": "string" },
                    "data": { "type": "object" }
                }
            }),
            json!({
                "type": "object",
                "required": ["configmap"],
                "properties": { "configmap": { "type": "object" } }
            }),
            "kubernetes.write",
            RiskLevel::Medium,
            SafetyTier::Dangerous,
            IdempotencyClass::BestEffort,
            AgentHint {
                when_to_use: "Update configuration data in an existing configmap.".into(),
                common_mistakes: vec![
                    "Overwriting all data instead of merging".into(),
                    "Not restarting pods that consume the configmap".into(),
                ],
                examples: vec![
                    r#"{"namespace": "production", "name": "app-config", "data": {"LOG_LEVEL": "debug"}}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("kubernetes.configmap.get"),
                    CapabilityId::from_static("kubernetes.rollout_restart"),
                ],
            },
        ),
        op_info(
            "kubernetes.configmap.delete",
            "Delete a configmap",
            json!({
                "type": "object",
                "required": ["namespace", "name"],
                "properties": {
                    "namespace": { "type": "string" },
                    "name": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["deleted"],
                "properties": { "deleted": { "type": "boolean" } }
            }),
            "kubernetes.admin",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::BestEffort,
            AgentHint {
                when_to_use: "Delete a configmap from a namespace.".into(),
                common_mistakes: vec![
                    "Deleting a configmap still referenced by running pods".into(),
                ],
                examples: vec![
                    r#"{"namespace": "default", "name": "old-config"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("kubernetes.configmap.get"),
                    CapabilityId::from_static("kubernetes.configmap.list"),
                ],
            },
        ),
        // ── Feature 3: Secret CRUD ───────────────────────────────────
        op_info(
            "kubernetes.secret.list",
            "List secrets in a namespace (metadata only)",
            json!({
                "type": "object",
                "required": ["namespace"],
                "properties": {
                    "namespace": { "type": "string" },
                    "label_selector": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["secrets"],
                "properties": { "secrets": { "type": "array" } }
            }),
            "kubernetes.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List secrets in a namespace (returns metadata only, no secret data).".into(),
                common_mistakes: vec![],
                examples: vec![r#"{"namespace": "production"}"#.into()],
                related: vec![
                    CapabilityId::from_static("kubernetes.secret.get"),
                    CapabilityId::from_static("kubernetes.secret.create"),
                ],
            },
        ),
        op_info(
            "kubernetes.secret.get",
            "Get a secret by name (reveals secret data)",
            json!({
                "type": "object",
                "required": ["namespace", "name"],
                "properties": {
                    "namespace": { "type": "string" },
                    "name": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["secret"],
                "properties": { "secret": { "type": "object" } }
            }),
            "kubernetes.secrets",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Read a Kubernetes secret including its data (base64-encoded values).".into(),
                common_mistakes: vec![
                    "Logging or exposing secret data".into(),
                    "Not base64-decoding the values".into(),
                ],
                examples: vec![
                    r#"{"namespace": "production", "name": "db-credentials"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("kubernetes.secret.list"),
                    CapabilityId::from_static("kubernetes.secret.create"),
                ],
            },
        ),
        op_info(
            "kubernetes.secret.create",
            "Create a secret",
            json!({
                "type": "object",
                "required": ["namespace", "name", "data"],
                "properties": {
                    "namespace": { "type": "string" },
                    "name": { "type": "string" },
                    "data": { "type": "object" },
                    "type": { "type": "string" },
                    "labels": { "type": "object" }
                }
            }),
            json!({
                "type": "object",
                "required": ["secret"],
                "properties": { "secret": { "type": "object" } }
            }),
            "kubernetes.secrets",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Create a new Kubernetes secret.".into(),
                common_mistakes: vec![
                    "Not base64-encoding secret values".into(),
                    "Creating duplicate secrets with the same name".into(),
                ],
                examples: vec![
                    r#"{"namespace": "default", "name": "db-creds", "data": {"username": "YWRtaW4=", "password": "c2VjcmV0"}}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("kubernetes.secret.get"),
                    CapabilityId::from_static("kubernetes.secret.delete"),
                ],
            },
        ),
        op_info(
            "kubernetes.secret.delete",
            "Delete a secret",
            json!({
                "type": "object",
                "required": ["namespace", "name"],
                "properties": {
                    "namespace": { "type": "string" },
                    "name": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["deleted"],
                "properties": { "deleted": { "type": "boolean" } }
            }),
            "kubernetes.secrets",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::BestEffort,
            AgentHint {
                when_to_use: "Delete a secret from a namespace.".into(),
                common_mistakes: vec![
                    "Deleting a secret still referenced by running pods".into(),
                ],
                examples: vec![
                    r#"{"namespace": "default", "name": "old-credentials"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("kubernetes.secret.get"),
                    CapabilityId::from_static("kubernetes.secret.list"),
                ],
            },
        ),
        // ── Feature 4: Rollout monitoring ──────────────────────────────
        op_info(
            "kubernetes.rollout.status",
            "Get rollout status for a deployment",
            json!({
                "type": "object",
                "required": ["namespace", "name"],
                "properties": {
                    "namespace": { "type": "string" },
                    "name": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["rollout_status"],
                "properties": { "rollout_status": { "type": "object" } }
            }),
            "kubernetes.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Check rollout progress for a deployment (replica counts, conditions, completion).".into(),
                common_mistakes: vec![
                    "Polling too frequently during a slow rollout".into(),
                ],
                examples: vec![
                    r#"{"namespace": "production", "name": "api-server"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("kubernetes.rollout.history"),
                    CapabilityId::from_static("kubernetes.rollout.rollback"),
                    CapabilityId::from_static("kubernetes.rollout_restart"),
                ],
            },
        ),
        op_info(
            "kubernetes.rollout.history",
            "Get rollout revision history for a deployment",
            json!({
                "type": "object",
                "required": ["namespace", "name"],
                "properties": {
                    "namespace": { "type": "string" },
                    "name": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["revisions"],
                "properties": { "revisions": { "type": "array" } }
            }),
            "kubernetes.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List previous rollout revisions (ReplicaSets) for a deployment.".into(),
                common_mistakes: vec![
                    "Assuming revision numbers are contiguous".into(),
                ],
                examples: vec![
                    r#"{"namespace": "production", "name": "api-server"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("kubernetes.rollout.status"),
                    CapabilityId::from_static("kubernetes.rollout.rollback"),
                ],
            },
        ),
        op_info(
            "kubernetes.rollout.rollback",
            "Rollback a deployment to a previous revision",
            json!({
                "type": "object",
                "required": ["namespace", "name", "template"],
                "properties": {
                    "namespace": { "type": "string" },
                    "name": { "type": "string" },
                    "template": { "type": "object" }
                }
            }),
            json!({
                "type": "object",
                "required": ["deployment"],
                "properties": { "deployment": { "type": "object" } }
            }),
            "kubernetes.write",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::BestEffort,
            AgentHint {
                when_to_use: "Rollback a deployment by patching its pod template to a previous revision.".into(),
                common_mistakes: vec![
                    "Rolling back without checking current rollout status first".into(),
                    "Not specifying the correct template from rollout history".into(),
                ],
                examples: vec![
                    r#"{"namespace": "production", "name": "api-server", "template": {"spec": {"containers": [{"name": "api", "image": "api:v1.2.3"}]}}}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("kubernetes.rollout.status"),
                    CapabilityId::from_static("kubernetes.rollout.history"),
                ],
            },
        ),
    ]
}

#[allow(clippy::fn_params_excessive_bools)]
#[allow(clippy::too_many_arguments)]
fn op_info(
    id: &'static str,
    summary: &str,
    input_schema: serde_json::Value,
    output_schema: serde_json::Value,
    capability: &'static str,
    risk_level: RiskLevel,
    safety_tier: SafetyTier,
    idempotency: IdempotencyClass,
    ai_hints: AgentHint,
) -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static(id),
        summary: summary.into(),
        input_schema,
        output_schema,
        capability: CapabilityId::from_static(capability),
        risk_level,
        description: None,
        rate_limit: None,
        requires_approval: approval_for_operation(id),
        safety_tier,
        idempotency,
        ai_hints,
    }
}

// MUST remain non-const: matches on `&str` literals via a string
// switch. See the block comment above `is_secret_mutation` for the
// full toolchain rationale (bead flywheel_connectors-q0y8h).
fn approval_for_operation(operation_id: &str) -> Option<ApprovalMode> {
    match operation_id {
        "kubernetes.delete_pod"
        | "kubernetes.create_pod"
        | "kubernetes.apply_deployment"
        | "kubernetes.delete_deployment"
        | "kubernetes.get_secret"
        | "kubernetes.rollout_restart"
        | "kubernetes.scale_deployment"
        | "kubernetes.exec"
        | "kubernetes.configmap.create"
        | "kubernetes.configmap.update"
        | "kubernetes.configmap.delete"
        | "kubernetes.secret.get"
        | "kubernetes.secret.create"
        | "kubernetes.secret.delete"
        | "kubernetes.rollout.rollback" => Some(ApprovalMode::Interactive),
        "kubernetes.update_configmap" => Some(ApprovalMode::Policy),
        "kubernetes.list_services"
        | "kubernetes.get_configmap"
        | "kubernetes.get_deployment"
        | "kubernetes.get_pod"
        | "kubernetes.get_pod_logs"
        | "kubernetes.get_service"
        | "kubernetes.list_deployments"
        | "kubernetes.list_pods"
        | "kubernetes.stream_pod_logs"
        | "kubernetes.watch_events"
        | "kubernetes.configmap.list"
        | "kubernetes.configmap.get"
        | "kubernetes.secret.list"
        | "kubernetes.rollout.status"
        | "kubernetes.rollout.history" => Some(ApprovalMode::None),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialize `operations_info()` to JSON for backward-compatible test assertions.
    fn operations_info_json() -> serde_json::Value {
        serde_json::to_value(operations_info()).unwrap()
    }

    #[test]
    fn config_from_bearer_token() {
        let config =
            KubernetesConfig::from_params(&json!({"bearer_token": "test-k8s-token"})).unwrap();
        assert!(matches!(config.auth, KubernetesAuth::BearerToken(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let config = KubernetesConfig::from_params(
            &json!({"credential_id": "550e8400-e29b-41d4-a716-446655440000"}),
        )
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let config = KubernetesConfig::from_params(
            &json!({"bearer_token": "tok", "base_url": "https://k8s.example.com"}),
        )
        .unwrap();
        assert_eq!(config.base_url, "https://k8s.example.com");
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        assert!(KubernetesConfig::from_params(&json!({"bearer_token": "tok", "credential_id": "550e8400-e29b-41d4-a716-446655440000"})).is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        assert!(KubernetesConfig::from_params(&json!({})).is_err());
    }

    #[test]
    fn config_rejects_empty_bearer_token() {
        assert!(KubernetesConfig::from_params(&json!({"bearer_token": ""})).is_err());
    }

    #[test]
    fn config_rejects_whitespace_bearer_token() {
        assert!(KubernetesConfig::from_params(&json!({"bearer_token": "   "})).is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        assert!(KubernetesConfig::from_params(&json!({"credential_id": 12345})).is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        assert!(KubernetesConfig::from_params(&json!({"credential_id": "not-a-uuid"})).is_err());
    }

    #[test]
    fn config_rejects_write_enable_without_namespace_scope() {
        assert!(
            KubernetesConfig::from_params(&json!({
                "bearer_token": "tok",
                "allow_write_operations": true
            }))
            .is_err()
        );
    }

    #[test]
    fn config_rejects_exec_enable_without_namespace_scope() {
        assert!(
            KubernetesConfig::from_params(&json!({
                "bearer_token": "tok",
                "allow_pod_exec": true
            }))
            .is_err()
        );
    }

    #[test]
    fn config_accepts_namespace_scope_for_write_and_exec() {
        let config = KubernetesConfig::from_params(&json!({
            "bearer_token": "tok",
            "allow_write_operations": true,
            "allow_pod_exec": true,
            "allowed_namespaces": ["default", "production"]
        }))
        .unwrap();
        assert!(config.policy.allow_write_operations);
        assert!(config.policy.allow_pod_exec);
        assert_eq!(
            config
                .policy
                .allowed_namespaces
                .as_ref()
                .unwrap()
                .iter()
                .cloned()
                .collect::<Vec<_>>(),
            vec!["default".to_string(), "production".to_string()]
        );
    }

    #[test]
    fn config_trims_bearer_token() {
        let config =
            KubernetesConfig::from_params(&json!({"bearer_token": "  my-token  "})).unwrap();
        let token = match &config.auth {
            KubernetesAuth::BearerToken(t) => Some(t.as_str()),
            KubernetesAuth::CredentialId(_) => None,
        };
        assert_eq!(token, Some("my-token"));
    }

    #[test]
    fn require_str_present() {
        assert_eq!(
            require_str(&json!({"namespace": "default"}), "namespace").unwrap(),
            "default"
        );
    }

    #[test]
    fn require_str_missing() {
        assert!(require_str(&json!({}), "namespace").is_err());
    }

    #[test]
    fn require_str_not_string() {
        assert!(require_str(&json!({"namespace": 42}), "namespace").is_err());
    }

    #[test]
    fn require_str_null_value() {
        assert!(require_str(&json!({"namespace": null}), "namespace").is_err());
    }

    #[test]
    fn require_str_boolean_value() {
        assert!(require_str(&json!({"namespace": true}), "namespace").is_err());
    }

    #[test]
    fn operations_info_has_31_operations() {
        assert_eq!(operations_info().len(), 31);
    }

    #[test]
    fn dangerous_operations_expose_approval_modes() {
        let ops = operations_info();
        let create_pod = ops
            .iter()
            .find(|op| op.id.as_ref() == "kubernetes.create_pod")
            .unwrap();
        let exec = ops
            .iter()
            .find(|op| op.id.as_ref() == "kubernetes.exec")
            .unwrap();
        let update_configmap = ops
            .iter()
            .find(|op| op.id.as_ref() == "kubernetes.update_configmap")
            .unwrap();
        let list_pods = ops
            .iter()
            .find(|op| op.id.as_ref() == "kubernetes.list_pods")
            .unwrap();

        assert_eq!(
            create_pod.requires_approval,
            Some(ApprovalMode::Interactive)
        );
        assert_eq!(exec.requires_approval, Some(ApprovalMode::Interactive));
        assert_eq!(
            update_configmap.requires_approval,
            Some(ApprovalMode::Policy)
        );
        assert_eq!(list_pods.requires_approval, Some(ApprovalMode::None));
    }

    #[test]
    fn operations_all_have_required_fields() {
        for op in operations_info_json().as_array().unwrap() {
            assert!(op.get("id").is_some());
            assert!(op.get("summary").is_some());
            assert!(op.get("capability").is_some());
            assert!(op.get("risk_level").is_some());
            assert!(op.get("safety_tier").is_some());
        }
    }

    #[test]
    fn operations_ids_are_unique() {
        let ops = operations_info_json();
        let ids: Vec<&str> = ops
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        let mut unique = ids.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(ids.len(), unique.len());
    }

    #[test]
    fn operations_risk_levels_valid() {
        let valid = ["low", "medium", "high"];
        for op in operations_info_json().as_array().unwrap() {
            let rl = op["risk_level"].as_str().unwrap();
            assert!(valid.contains(&rl), "invalid risk_level: {rl}");
        }
    }

    #[test]
    fn operations_safety_tiers_valid() {
        let valid = ["safe", "risky", "dangerous"];
        for op in operations_info_json().as_array().unwrap() {
            let st = op["safety_tier"].as_str().unwrap();
            assert!(valid.contains(&st), "invalid safety_tier: {st}");
        }
    }

    #[test]
    fn read_operations_are_safe() {
        for op in operations_info_json().as_array().unwrap() {
            if op["capability"].as_str().unwrap() == "kubernetes.read" {
                assert_eq!(op["safety_tier"], "safe");
                assert_eq!(op["risk_level"], "low");
            }
        }
    }

    #[test]
    fn operations_contain_all_manifest_ids() {
        let ops = operations_info_json();
        let ids: Vec<&str> = ops
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        for expected in &[
            "kubernetes.list_pods",
            "kubernetes.get_pod",
            "kubernetes.create_pod",
            "kubernetes.delete_pod",
            "kubernetes.get_pod_logs",
            "kubernetes.stream_pod_logs",
            "kubernetes.list_deployments",
            "kubernetes.get_deployment",
            "kubernetes.apply_deployment",
            "kubernetes.delete_deployment",
            "kubernetes.scale_deployment",
            "kubernetes.rollout_restart",
            "kubernetes.get_service",
            "kubernetes.list_services",
            "kubernetes.get_configmap",
            "kubernetes.update_configmap",
            "kubernetes.get_secret",
            "kubernetes.watch_events",
            "kubernetes.exec",
            "kubernetes.configmap.list",
            "kubernetes.configmap.get",
            "kubernetes.configmap.create",
            "kubernetes.configmap.update",
            "kubernetes.configmap.delete",
            "kubernetes.secret.list",
            "kubernetes.secret.get",
            "kubernetes.secret.create",
            "kubernetes.secret.delete",
            "kubernetes.rollout.status",
            "kubernetes.rollout.history",
            "kubernetes.rollout.rollback",
        ] {
            assert!(ids.contains(expected), "missing: {expected}");
        }
    }

    #[test]
    fn operations_all_have_idempotency() {
        for op in operations_info_json().as_array().unwrap() {
            assert!(op.get("idempotency").is_some());
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
        assert_eq!(
            DoctorResult::from_checks(checks).status,
            DoctorStatus::Healthy
        );
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
        assert_eq!(
            DoctorResult::from_checks(checks).status,
            DoctorStatus::Degraded
        );
    }

    #[test]
    fn doctor_result_unhealthy_when_critical_fails() {
        let checks = vec![DoctorCheck {
            name: "config".into(),
            passed: false,
            message: Some("not configured".into()),
            critical: true,
        }];
        assert_eq!(
            DoctorResult::from_checks(checks).status,
            DoctorStatus::Unhealthy
        );
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
    }

    #[test]
    fn doctor_result_empty_checks() {
        assert_eq!(
            DoctorResult::from_checks(vec![]).status,
            DoctorStatus::Healthy
        );
    }

    #[test]
    fn connector_default() {
        let c = KubernetesConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.authority.is_none());
        assert!(!c.session_established());
    }

    #[test]
    fn delete_pod_is_dangerous() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.delete_pod")
            .unwrap();
        assert_eq!(op["risk_level"], "high");
        assert_eq!(op["safety_tier"], "dangerous");
        assert_eq!(op["capability"], "kubernetes.admin");
    }

    #[test]
    fn scale_deployment_is_risky() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.scale_deployment")
            .unwrap();
        assert_eq!(op["risk_level"], "high");
        assert_eq!(op["safety_tier"], "risky");
    }

    #[test]
    fn get_secret_uses_secrets_capability() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.get_secret")
            .unwrap();
        assert_eq!(op["capability"], "kubernetes.secrets");
        assert_eq!(op["risk_level"], "high");
    }

    #[test]
    fn rollout_restart_uses_write_capability() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.rollout_restart")
            .unwrap();
        assert_eq!(op["capability"], "kubernetes.write");
        assert_eq!(op["idempotency"], "none");
    }

    #[test]
    fn update_configmap_is_risky() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.update_configmap")
            .unwrap();
        assert_eq!(op["risk_level"], "medium");
        assert_eq!(op["safety_tier"], "risky");
    }

    #[test]
    fn watch_events_is_safe() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.watch_events")
            .unwrap();
        assert_eq!(op["risk_level"], "low");
        assert_eq!(op["safety_tier"], "safe");
    }

    #[test]
    fn connector_new_has_zero_counters() {
        let c = KubernetesConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn operations_list_pods_capability() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.list_pods")
            .unwrap();
        assert_eq!(op["capability"], "kubernetes.read");
    }

    #[test]
    fn operations_get_pod_capability() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.get_pod")
            .unwrap();
        assert_eq!(op["capability"], "kubernetes.read");
    }

    #[test]
    fn operations_get_configmap_capability() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.get_configmap")
            .unwrap();
        assert_eq!(op["capability"], "kubernetes.read");
    }

    #[test]
    fn operations_update_configmap_capability() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.update_configmap")
            .unwrap();
        assert_eq!(op["capability"], "kubernetes.write");
    }

    #[test]
    fn operations_get_service_capability() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.get_service")
            .unwrap();
        assert_eq!(op["capability"], "kubernetes.read");
    }

    #[test]
    fn operations_all_have_summary() {
        for op in operations_info_json().as_array().unwrap() {
            let summary = op["summary"].as_str().unwrap();
            assert!(!summary.is_empty(), "op {:?} has empty summary", op["id"]);
        }
    }

    #[test]
    fn doctor_result_multiple_critical_failures() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: false,
                message: Some("fail 1".into()),
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: Some("fail 2".into()),
                critical: true,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
        assert_eq!(r.checks.len(), 2);
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
            message: Some("warn".into()),
            critical: false,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["message"], "warn");
    }

    #[test]
    fn doctor_status_serde_roundtrip() {
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
        let s: DoctorStatus = serde_json::from_value(json!("degraded")).unwrap();
        assert_eq!(s, DoctorStatus::Degraded);
        let s: DoctorStatus = serde_json::from_value(json!("unhealthy")).unwrap();
        assert_eq!(s, DoctorStatus::Unhealthy);
    }

    #[test]
    fn require_str_empty_string_is_ok() {
        assert_eq!(
            require_str(&json!({"namespace": ""}), "namespace").unwrap(),
            ""
        );
    }

    #[test]
    fn operations_get_pod_logs_capability() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.get_pod_logs")
            .unwrap();
        assert_eq!(op["capability"], "kubernetes.read");
        assert_eq!(op["risk_level"], "low");
    }

    #[test]
    fn operations_stream_pod_logs_capability() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.stream_pod_logs")
            .unwrap();
        assert_eq!(op["capability"], "kubernetes.read");
    }

    #[test]
    fn operations_list_deployments_capability() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.list_deployments")
            .unwrap();
        assert_eq!(op["capability"], "kubernetes.read");
    }

    #[test]
    fn operations_get_deployment_capability() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.get_deployment")
            .unwrap();
        assert_eq!(op["capability"], "kubernetes.read");
    }

    #[test]
    fn operations_scale_deployment_idempotency() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.scale_deployment")
            .unwrap();
        assert_eq!(op["idempotency"], "best_effort");
    }

    #[test]
    fn operations_delete_pod_idempotency() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.delete_pod")
            .unwrap();
        assert_eq!(op["idempotency"], "best_effort");
    }

    #[test]
    fn operations_watch_events_capability() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.watch_events")
            .unwrap();
        assert_eq!(op["capability"], "kubernetes.read");
    }

    #[test]
    fn operations_write_ops_have_correct_capability() {
        let write_ops = [
            "kubernetes.scale_deployment",
            "kubernetes.rollout_restart",
            "kubernetes.update_configmap",
            "kubernetes.configmap.update",
            "kubernetes.rollout.rollback",
        ];
        for op in operations_info_json().as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            let cap = op["capability"].as_str().unwrap();
            if write_ops.contains(&id) {
                assert_eq!(
                    cap, "kubernetes.write",
                    "op {id} should use kubernetes.write"
                );
            }
        }
    }

    #[test]
    fn require_str_object_value() {
        assert!(require_str(&json!({"namespace": {"nested": true}}), "namespace").is_err());
    }

    #[test]
    fn require_str_float_value() {
        assert!(require_str(&json!({"namespace": 1.23}), "namespace").is_err());
    }

    #[test]
    fn require_str_array_value() {
        assert!(require_str(&json!({"namespace": ["a", "b"]}), "namespace").is_err());
    }

    #[test]
    fn operations_all_capabilities_prefixed() {
        for op in operations_info_json().as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            assert!(
                cap.starts_with("kubernetes."),
                "op {:?} capability {cap} should start with kubernetes.",
                op["id"]
            );
        }
    }

    #[test]
    fn doctor_status_copy_eq() {
        let a = DoctorStatus::Healthy;
        let b = a;
        assert_eq!(a, b);
        let c = DoctorStatus::Unhealthy;
        assert_ne!(a, c);
    }

    // ── provisioning_readiness ────────────────────────────────────

    #[test]
    fn provisioning_readiness_bearer_token_mode() {
        let config = KubernetesConfig::from_params(&json!({"bearer_token": "test-token"})).unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "bearer_token");
        assert!(readiness.bearer_token_configured);
        assert!(!readiness.credential_id_configured);
        assert!(!readiness.requires_credential_injection);
        assert!(readiness.network_ok);
    }

    #[test]
    fn provisioning_readiness_credential_id_mode() {
        let config = KubernetesConfig::from_params(
            &json!({"credential_id": "550e8400-e29b-41d4-a716-446655440000"}),
        )
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "credential_id");
        assert!(!readiness.bearer_token_configured);
        assert!(readiness.credential_id_configured);
        assert!(readiness.requires_credential_injection);
        assert!(readiness.network_ok);
        assert_eq!(
            readiness.rate_limit_profile,
            "credential_id: authenticated via egress proxy injection"
        );
    }

    #[test]
    fn provisioning_readiness_custom_base_url() {
        let config = KubernetesConfig::from_params(
            &json!({"bearer_token": "tok", "base_url": "https://k8s.example.com"}),
        )
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(readiness.network_ok);
        assert!(readiness.network_message.contains("custom host"));
        assert_eq!(readiness.base_url, "https://k8s.example.com");
    }

    #[test]
    fn provisioning_readiness_serializes() {
        let config = KubernetesConfig::from_params(&json!({"bearer_token": "test-token"})).unwrap();
        let readiness = config.provisioning_readiness();
        let v = serde_json::to_value(&readiness).unwrap();
        assert_eq!(v["auth_mode"], "bearer_token");
        assert_eq!(v["bearer_token_configured"], true);
        assert_eq!(v["credential_id_configured"], false);
        assert!(v["network_message"].as_str().is_some());
    }

    // ── base_url_policy ───────────────────────────────────────────

    #[test]
    fn base_url_policy_accepts_default_in_cluster() {
        let (ok, message) = base_url_policy("https://kubernetes.default.svc");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_localhost() {
        let (ok, _) = base_url_policy("http://localhost:6443");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_rejects_http_non_local() {
        let (ok, message) = base_url_policy("http://k8s.example.com");
        assert!(!ok);
        assert!(message.contains("must use https"));
    }

    #[test]
    fn base_url_policy_accepts_svc_cluster_local() {
        let (ok, message) = base_url_policy("https://api.kube-system.svc.cluster.local");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_custom_proxy_path() {
        let (ok, message) = base_url_policy("https://proxy.example.com/k8s/api");
        assert!(ok);
        assert!(message.contains("custom host"));
    }

    #[test]
    fn base_url_policy_rejects_userinfo() {
        let (ok, message) = base_url_policy("https://kubernetes.default.svc@evil.example.com");
        assert!(!ok);
        assert!(message.contains("userinfo"));
    }

    #[test]
    fn base_url_policy_rejects_query_parameters() {
        let (ok, message) = base_url_policy("https://k8s.example.com?prefix=/api/v1");
        assert!(!ok);
        assert!(message.contains("query"));
    }

    #[test]
    fn base_url_policy_rejects_fragments() {
        let (ok, message) = base_url_policy("https://k8s.example.com#fragment");
        assert!(!ok);
        assert!(message.contains("fragment"));
    }

    #[test]
    fn base_url_policy_rejects_non_http_scheme_for_localhost() {
        let (ok, message) = base_url_policy("ftp://localhost:6443");
        assert!(!ok);
        assert!(message.contains("http or https"));
    }

    // ── new operations: create_pod, apply_deployment, delete_deployment, list_services ──

    #[test]
    fn create_pod_is_dangerous() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.create_pod")
            .unwrap();
        assert_eq!(op["risk_level"], "high");
        assert_eq!(op["safety_tier"], "dangerous");
        assert_eq!(op["capability"], "kubernetes.admin");
        assert_eq!(op["idempotency"], "none");
    }

    #[test]
    fn apply_deployment_is_dangerous() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.apply_deployment")
            .unwrap();
        assert_eq!(op["risk_level"], "high");
        assert_eq!(op["safety_tier"], "dangerous");
        assert_eq!(op["capability"], "kubernetes.admin");
        assert_eq!(op["idempotency"], "best_effort");
    }

    #[test]
    fn delete_deployment_is_dangerous() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.delete_deployment")
            .unwrap();
        assert_eq!(op["risk_level"], "high");
        assert_eq!(op["safety_tier"], "dangerous");
        assert_eq!(op["capability"], "kubernetes.admin");
        assert_eq!(op["idempotency"], "best_effort");
    }

    #[test]
    fn list_services_is_safe() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.list_services")
            .unwrap();
        assert_eq!(op["risk_level"], "low");
        assert_eq!(op["safety_tier"], "safe");
        assert_eq!(op["capability"], "kubernetes.read");
        assert_eq!(op["idempotency"], "strict");
    }

    fn has_required_field(op: &serde_json::Value, field: &str) -> bool {
        op["input_schema"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str() == Some(field))
    }

    #[test]
    fn operations_create_pod_has_input_schema() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.create_pod")
            .unwrap();
        assert!(has_required_field(op, "namespace"));
        assert!(has_required_field(op, "name"));
        assert!(has_required_field(op, "spec"));
    }

    #[test]
    fn operations_apply_deployment_has_input_schema() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.apply_deployment")
            .unwrap();
        assert!(has_required_field(op, "namespace"));
        assert!(has_required_field(op, "name"));
        assert!(has_required_field(op, "spec"));
    }

    #[test]
    fn operations_delete_deployment_has_input_schema() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.delete_deployment")
            .unwrap();
        assert!(has_required_field(op, "namespace"));
        assert!(has_required_field(op, "name"));
    }

    #[test]
    fn operations_list_services_has_input_schema() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.list_services")
            .unwrap();
        assert!(has_required_field(op, "namespace"));
    }

    #[test]
    fn operations_admin_ops_have_correct_capability() {
        for op in operations_info_json().as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            let cap = op["capability"].as_str().unwrap();
            if id == "kubernetes.create_pod"
                || id == "kubernetes.apply_deployment"
                || id == "kubernetes.delete_deployment"
                || id == "kubernetes.delete_pod"
                || id == "kubernetes.exec"
                || id == "kubernetes.configmap.create"
                || id == "kubernetes.configmap.delete"
            {
                assert_eq!(
                    cap, "kubernetes.admin",
                    "op {id} should use kubernetes.admin"
                );
            }
        }
    }

    // ── New operations: exec, configmap.*, secret.* ──────────────────

    #[test]
    fn exec_is_dangerous() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.exec")
            .unwrap();
        assert_eq!(op["risk_level"], "high");
        assert_eq!(op["safety_tier"], "dangerous");
        assert_eq!(op["capability"], "kubernetes.admin");
        assert_eq!(op["idempotency"], "none");
    }

    #[test]
    fn exec_has_input_schema() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.exec")
            .unwrap();
        assert!(has_required_field(op, "namespace"));
        assert!(has_required_field(op, "name"));
        assert!(has_required_field(op, "command"));
    }

    #[test]
    fn configmap_list_is_safe() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.configmap.list")
            .unwrap();
        assert_eq!(op["risk_level"], "low");
        assert_eq!(op["safety_tier"], "safe");
        assert_eq!(op["capability"], "kubernetes.read");
        assert_eq!(op["idempotency"], "strict");
    }

    #[test]
    fn configmap_get_is_safe() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.configmap.get")
            .unwrap();
        assert_eq!(op["risk_level"], "low");
        assert_eq!(op["safety_tier"], "safe");
        assert_eq!(op["capability"], "kubernetes.read");
    }

    #[test]
    fn configmap_create_is_dangerous() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.configmap.create")
            .unwrap();
        assert_eq!(op["risk_level"], "high");
        assert_eq!(op["safety_tier"], "dangerous");
        assert_eq!(op["capability"], "kubernetes.admin");
        assert_eq!(op["idempotency"], "none");
    }

    #[test]
    fn configmap_update_is_dangerous() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.configmap.update")
            .unwrap();
        assert_eq!(op["risk_level"], "medium");
        assert_eq!(op["safety_tier"], "dangerous");
        assert_eq!(op["capability"], "kubernetes.write");
    }

    #[test]
    fn configmap_delete_is_dangerous() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.configmap.delete")
            .unwrap();
        assert_eq!(op["risk_level"], "high");
        assert_eq!(op["safety_tier"], "dangerous");
        assert_eq!(op["capability"], "kubernetes.admin");
        assert_eq!(op["idempotency"], "best_effort");
    }

    #[test]
    fn secret_list_is_safe() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.secret.list")
            .unwrap();
        assert_eq!(op["risk_level"], "low");
        assert_eq!(op["safety_tier"], "safe");
        assert_eq!(op["capability"], "kubernetes.read");
        assert_eq!(op["idempotency"], "strict");
    }

    #[test]
    fn secret_get_is_dangerous() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.secret.get")
            .unwrap();
        assert_eq!(op["risk_level"], "high");
        assert_eq!(op["safety_tier"], "dangerous");
        assert_eq!(op["capability"], "kubernetes.secrets");
    }

    #[test]
    fn secret_create_is_dangerous() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.secret.create")
            .unwrap();
        assert_eq!(op["risk_level"], "high");
        assert_eq!(op["safety_tier"], "dangerous");
        assert_eq!(op["capability"], "kubernetes.secrets");
        assert_eq!(op["idempotency"], "none");
    }

    #[test]
    fn secret_delete_is_dangerous() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.secret.delete")
            .unwrap();
        assert_eq!(op["risk_level"], "high");
        assert_eq!(op["safety_tier"], "dangerous");
        assert_eq!(op["capability"], "kubernetes.secrets");
        assert_eq!(op["idempotency"], "best_effort");
    }

    #[test]
    fn configmap_create_has_input_schema() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.configmap.create")
            .unwrap();
        assert!(has_required_field(op, "namespace"));
        assert!(has_required_field(op, "name"));
        assert!(has_required_field(op, "data"));
    }

    #[test]
    fn secret_create_has_input_schema() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.secret.create")
            .unwrap();
        assert!(has_required_field(op, "namespace"));
        assert!(has_required_field(op, "name"));
        assert!(has_required_field(op, "data"));
    }

    #[test]
    fn new_ops_all_have_ai_hints() {
        let ops = operations_info_json();
        for id in &[
            "kubernetes.exec",
            "kubernetes.configmap.list",
            "kubernetes.configmap.get",
            "kubernetes.configmap.create",
            "kubernetes.configmap.update",
            "kubernetes.configmap.delete",
            "kubernetes.secret.list",
            "kubernetes.secret.get",
            "kubernetes.secret.create",
            "kubernetes.secret.delete",
        ] {
            let has_ai_hints = ops
                .as_array()
                .unwrap()
                .iter()
                .any(|op| op["id"].as_str() == Some(id) && op.get("ai_hints").is_some());
            assert!(has_ai_hints, "op {id} missing ai_hints");
        }
    }

    #[test]
    fn new_read_ops_are_safe() {
        let ops = operations_info_json();
        for id in &[
            "kubernetes.configmap.list",
            "kubernetes.configmap.get",
            "kubernetes.secret.list",
        ] {
            let op = ops
                .as_array()
                .unwrap()
                .iter()
                .find(|o| o["id"].as_str() == Some(id))
                .unwrap();
            assert_eq!(op["safety_tier"], "safe", "op {id} should be safe");
            assert_eq!(op["risk_level"], "low", "op {id} should be low risk");
        }
    }
}
