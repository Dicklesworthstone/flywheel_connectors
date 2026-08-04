//! FCP `Roam Research` Connector implementation.

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_manifest::{ConnectorManifest, ManifestApprovalMode};
use fcp_prelude::{
    ApprovalMode, BaseConnector, ConnectorId, CredentialId, FcpError, FcpResult, OperationId,
    OperationInfo, ProvisioningRecipe, ProvisioningStep, ProvisioningStepType, RecipeId,
    SelfCheckReport, StepId,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, RoamAuth, RoamClient},
    error::RoamError,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/roam_connector_verification.sh";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/roam_connector/<timestamp>";
const OP_PAGES_LIST: &str = "roam.pages.list";
const OP_PAGES_GET: &str = "roam.pages.get";
const OP_BLOCKS_LIST: &str = "roam.blocks.list";
const OP_BLOCKS_CREATE: &str = "roam.blocks.create";
const OPERATION_ORDER: [&str; 4] = [
    OP_PAGES_LIST,
    OP_PAGES_GET,
    OP_BLOCKS_LIST,
    OP_BLOCKS_CREATE,
];
const VERIFY_COMMANDS: [&str; 10] = [
    "scripts/e2e/roam_connector_verification.sh",
    "rch exec -- env RUSTUP_TOOLCHAIN=nightly-2026-02-19 cargo run -q -p fwc -- manifest fix connectors/roam/manifest.toml --check --json",
    "rch exec -- env RUSTUP_TOOLCHAIN=nightly-2026-02-19 cargo fmt --manifest-path connectors/roam/Cargo.toml --check",
    "rch exec -- env RUSTUP_TOOLCHAIN=nightly-2026-02-19 cargo check -p fcp-roam --all-targets",
    "rch exec -- env RUSTUP_TOOLCHAIN=nightly-2026-02-19 cargo test -p fcp-roam --test integration health_unconfigured_includes_guidance -- --nocapture",
    "rch exec -- env RUSTUP_TOOLCHAIN=nightly-2026-02-19 cargo test -p fcp-roam --test integration doctor_unconfigured_reports_operator_guidance -- --nocapture",
    "rch exec -- env RUSTUP_TOOLCHAIN=nightly-2026-02-19 cargo test -p fcp-roam --test integration self_check_ready_with_mock_roam_api_and_evidence -- --nocapture",
    "rch exec -- env RUSTUP_TOOLCHAIN=nightly-2026-02-19 cargo test -p fcp-roam --test integration self_check_retryable_roam_failure_reports_degraded -- --nocapture",
    "rch exec -- env RUSTUP_TOOLCHAIN=nightly-2026-02-19 cargo test -p fcp-roam --test integration introspection_emits_v3_compliance_evidence -- --nocapture",
    "rch exec -- env RUSTUP_TOOLCHAIN=nightly-2026-02-19 cargo clippy -p fcp-roam --all-targets -- -D warnings",
];

/// Default graph name when none is provided.
const DEFAULT_GRAPH_NAME: &str = "default";

/// Parsed and validated `Roam Research` connector configuration.
#[derive(Debug, Clone)]
struct RoamConfig {
    auth: RoamAuth,
    base_url: String,
    graph_name: String,
}

impl RoamConfig {
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
            (Some(token), None) => RoamAuth::BearerToken(token),
            (None, Some(cred_id)) => RoamAuth::CredentialId(cred_id),
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

        let graph_name = params
            .get("graph_name")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .unwrap_or(DEFAULT_GRAPH_NAME)
            .to_string();

        Ok(Self {
            auth,
            base_url,
            graph_name,
        })
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let (network_ok, network_message) = base_url_policy(&self.base_url);

        ProvisioningReadiness {
            auth_mode: match &self.auth {
                RoamAuth::BearerToken(_) => "bearer_token",
                RoamAuth::CredentialId(_) => "credential_id",
            },
            token_configured: matches!(&self.auth, RoamAuth::BearerToken(_)),
            credential_id_configured: self.auth.is_secretless(),
            requires_credential_injection: self.auth.is_secretless(),
            network_ok,
            network_message,
            base_url: self.base_url.clone(),
            graph_name: self.graph_name.clone(),
            pages_surface: true,
            blocks_surface: true,
            write_surface: true,
            local_override_allowed: true,
            host_policy_guidance: "Production verification must target https://api.roamresearch.com/api/graph. Localhost overrides are allowed only for deterministic bridge-style verification fixtures.",
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
    graph_name: String,
    pages_surface: bool,
    blocks_surface: bool,
    write_surface: bool,
    local_override_allowed: bool,
    host_policy_guidance: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct OperatorGuidance {
    prerequisites: Vec<&'static str>,
    dedicated_environment: &'static str,
    redaction_rules: Vec<&'static str>,
    limitations: Vec<&'static str>,
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

/// Doctor check result.
#[derive(Debug, Clone, Serialize)]
struct DoctorResult {
    ready: bool,
    status: DoctorStatus,
    checks: Vec<DoctorCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provisioning: Option<ProvisioningReadiness>,
    operator_guidance: OperatorGuidance,
    verification_script: &'static str,
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
        Self::from_checks_with_provisioning(checks, None)
    }

    #[must_use]
    fn from_checks_with_provisioning(
        checks: Vec<DoctorCheck>,
        provisioning: Option<ProvisioningReadiness>,
    ) -> Self {
        let ready = checks
            .iter()
            .filter(|check| check.critical)
            .all(|check| check.passed);
        let status = if checks.iter().any(|c| c.critical && !c.passed) {
            DoctorStatus::Unhealthy
        } else if checks.iter().any(|c| !c.passed) {
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
}

fn operator_guidance() -> OperatorGuidance {
    OperatorGuidance {
        prerequisites: vec![
            "Use a disposable Roam graph or localhost fixture before running verification.",
            "Provide exactly one auth source: a Roam bearer token for live probes or a credential_id when host-side injection is available.",
            "Seed deterministic pages and block trees before running write-oriented coverage so evidence stays reviewable.",
        ],
        dedicated_environment: "Prefer a disposable graph behind the official API or a localhost bridge fixture. Block creation mutates graph state, so never aim this harness at a live personal knowledge base without explicit approval.",
        redaction_rules: vec![
            "Never print raw Roam bearer tokens or injected credential material.",
            "Treat graph names, page titles, block content, and query responses as potentially sensitive knowledge-base data.",
            "If a localhost or internal base_url override is used, capture it in the evidence bundle but redact internal hostnames before sharing artifacts.",
        ],
        limitations: vec![
            "This connector only covers page listing, page lookup, block listing, and block creation.",
            "It does not expose Roam templates, graph settings, user/account administration, or streaming updates.",
            "Credential-id mode can validate policy shape but cannot prove live reachability until the host injects concrete secret material.",
        ],
        common_remediation: vec![
            RemediationHint {
                code: "network_constraints_invalid",
                symptom: "health or self_check reports that the configured base_url violates Roam host policy",
                action: "Use https://api.roamresearch.com/api/graph or a localhost test override that mirrors the Roam graph API.",
            },
            RemediationHint {
                code: "credential_injection_required",
                symptom: "self_check cannot perform a live probe because only credential_id is configured",
                action: "Inject a concrete Roam bearer token through the host or proxy, then rerun self_check and the verification script.",
            },
            RemediationHint {
                code: "auth_invalid",
                symptom: "the Roam API returns 401 or 403 during self_check",
                action: "Verify the token still grants access to the target graph and that the graph_name is correct.",
            },
            RemediationHint {
                code: "self_check_retryable",
                symptom: "the live Roam probe failed with rate limiting, timeout, or transient 5xx errors",
                action: "Wait for the upstream to recover or use a localhost verification stub before rerunning verification.",
            },
        ],
        rerun_commands: VERIFY_COMMANDS.to_vec(),
        artifact_root_hint: ARTIFACT_ROOT_HINT,
    }
}

/// FCP `Roam Research` Connector.
pub struct RoamConnector {
    base: Arc<BaseConnector>,
    config: Option<RoamConfig>,
    client: Option<Arc<RoamClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl RoamConnector {
    /// Create a new `Roam Research` connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("roam"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    fn doctor(&self) -> DoctorResult {
        let provisioning = self.config.as_ref().map(RoamConfig::provisioning_readiness);
        let handshaken = self.session_id.is_some();
        let mut checks = vec![
            DoctorCheck {
                name: "configuration".into(),
                passed: self.config.is_some(),
                message: self.config.as_ref().map_or_else(
                    || Some("Not configured; call configure before handshake or invoke".into()),
                    |config| {
                        Some(format!(
                            "Configured for Roam graph {} via {}",
                            config.graph_name,
                            config.auth.redacted_label()
                        ))
                    },
                ),
                critical: true,
            },
            DoctorCheck {
                name: "client_initialized".into(),
                passed: self.client.is_some(),
                message: if self.client.is_some() {
                    None
                } else {
                    Some("API client not initialized; re-run configure".into())
                },
                critical: true,
            },
            DoctorCheck {
                name: "handshake".into(),
                passed: handshaken,
                message: if handshaken {
                    None
                } else {
                    Some("Handshake not completed".into())
                },
                critical: false,
            },
        ];

        if let Some(readiness) = &provisioning {
            checks.push(DoctorCheck {
                name: "endpoint_policy".into(),
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
                name: "secret_material".into(),
                passed: readiness.token_configured,
                message: Some(if readiness.token_configured {
                    "Concrete Roam bearer token configured".into()
                } else {
                    "Secretless credential_id mode requires host-side secret injection before live verification".into()
                }),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "graph_scope".into(),
                passed: true,
                message: Some(
                    "Connector scope: page listing, page lookup, block listing, and block creation"
                        .into(),
                ),
                critical: false,
            });
        }

        DoctorResult::from_checks_with_provisioning(checks, provisioning)
    }

    fn attach_self_check_details(
        &self,
        mut report: SelfCheckReport,
        provisioning: Option<&ProvisioningReadiness>,
        live_probe: Option<&serde_json::Value>,
    ) -> SelfCheckReport {
        report.details = Some(json!({
            "configured": self.config.is_some(),
            "client_initialized": self.client.is_some(),
            "handshaken": self.session_id.is_some(),
            "manifest_hash": Self::manifest_hash(),
            "verification_script": VERIFICATION_SCRIPT_PATH,
            "artifact_root_hint": ARTIFACT_ROOT_HINT,
            "provisioning": provisioning,
            "live_probe": live_probe,
            "operator_guidance": operator_guidance(),
        }));
        report
    }
}

impl Default for RoamConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl RoamConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = RoamConfig::from_params(&params)?;
        info!(
            auth = %config.auth.redacted_label(),
            base_url = %config.base_url,
            graph = %config.graph_name,
            "Configuring Roam Research connector"
        );

        let client = RoamClient::new(
            config.auth.clone(),
            &config.graph_name,
            Some(&config.base_url),
        )
        .map_err(|e| e.to_fcp_error())?;

        self.client = Some(Arc::new(client));
        self.config = Some(config);
        self.session_id = None;
        self.base.set_configured(true);
        self.base.set_handshaken(false);
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
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing session_id".into(),
            })?
            .to_string();

        self.session_id = Some(session_id);
        self.base.set_handshaken(true);

        Ok(json!({
            "protocol_version": "2.0",
            "connector_id": "fcp.roam",
            "connector_version": "0.1.0",
            "capabilities": [
                "roam.pages.read",
                "roam.blocks.read",
                "roam.blocks.write"
            ]
        }))
    }

    /// Handle the `health` method.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.config.is_some();
        let client_initialized = self.client.is_some();
        let handshaken = self.session_id.is_some();
        let provisioning = self.config.as_ref().map(RoamConfig::provisioning_readiness);
        let ready = configured
            && client_initialized
            && handshaken
            && provisioning
                .as_ref()
                .is_none_or(|readiness| readiness.network_ok);

        let status = if ready {
            "healthy"
        } else if configured {
            "degraded"
        } else {
            "unconfigured"
        };

        Ok(json!({
            "status": status,
            "configured": configured,
            "client_initialized": client_initialized,
            "handshaken": handshaken,
            "ready": ready,
            "requests": self.request_count.load(Ordering::Relaxed),
            "errors": self.error_count.load(Ordering::Relaxed),
            "details": {
                "manifest_hash": Self::manifest_hash(),
                "verification_script": VERIFICATION_SCRIPT_PATH,
                "artifact_root_hint": ARTIFACT_ROOT_HINT,
                "provisioning": provisioning,
                "operator_guidance": operator_guidance(),
            }
        }))
    }

    /// Handle the `doctor` method.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let result = self.doctor();
        Ok(serde_json::to_value(result).unwrap_or_else(|_| json!({"status": "error"})))
    }

    /// Handle the `self_check` method.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let provisioning = self.config.as_ref().map(RoamConfig::provisioning_readiness);
        let report = match (&self.config, &self.client, provisioning.as_ref()) {
            (None, _, _) | (_, None, _) => self.attach_self_check_details(
                SelfCheckReport::degraded("not_configured", "Connector is not configured"),
                provisioning.as_ref(),
                None,
            ),
            (Some(_), Some(_), Some(readiness)) if !readiness.network_ok => {
                self.attach_self_check_details(
                    SelfCheckReport::failed(
                        "network_constraints_invalid",
                        readiness.network_message.clone(),
                    ),
                    provisioning.as_ref(),
                    None,
                )
            }
            (Some(_), Some(_), Some(readiness)) if readiness.requires_credential_injection => {
                self.attach_self_check_details(
                    SelfCheckReport::degraded(
                        "credential_injection_required",
                        "credential_id mode requires host-side Roam secret injection; skipping live probe",
                    ),
                    provisioning.as_ref(),
                    None,
                )
            }
            (Some(config), Some(client), Some(_)) => match client.list_pages().await {
                Ok(response) => {
                    let page_count = response
                        .get("pages")
                        .and_then(serde_json::Value::as_array)
                        .map_or(0, std::vec::Vec::len);
                    let live_probe = json!({
                        "probe": "roam.pages.list",
                        "base_url": config.base_url.clone(),
                        "graph_name": config.graph_name.clone(),
                        "page_count": page_count,
                        "response": response,
                    });
                    self.attach_self_check_details(
                        SelfCheckReport::ok(),
                        provisioning.as_ref(),
                        Some(&live_probe),
                    )
                }
                Err(RoamError::Unauthorized | RoamError::Forbidden) => {
                    self.attach_self_check_details(
                        SelfCheckReport::failed(
                            "auth_invalid",
                            "Roam credentials were rejected by the live probe",
                        ),
                        provisioning.as_ref(),
                        None,
                    )
                }
                Err(error) if error.is_retryable() => {
                    let live_probe = json!({
                        "probe": "roam.pages.list",
                        "base_url": config.base_url.clone(),
                        "graph_name": config.graph_name.clone(),
                        "retryable": true,
                        "retry_after_ms": error.retry_after().map(|duration| duration.as_millis() as u64),
                        "error": error.to_string(),
                    });
                    self.attach_self_check_details(
                        SelfCheckReport::degraded("self_check_retryable", error.to_string()),
                        provisioning.as_ref(),
                        Some(&live_probe),
                    )
                }
                Err(error) => self.attach_self_check_details(
                    SelfCheckReport::failed("self_check_failed", error.to_string()),
                    provisioning.as_ref(),
                    None,
                ),
            },
            (Some(_), Some(_), None) => self.attach_self_check_details(
                SelfCheckReport::failed(
                    "provisioning_unavailable",
                    "Provisioning readiness could not be computed",
                ),
                None,
                None,
            ),
        };
        Self::serialize_self_check_report(report)
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let ops = introspect_operations()?;
        Ok(json!({
            "connector_id": "fcp.roam",
            "version": "0.1.0",
            "operations": ops,
            "manifest_hash": Self::manifest_hash(),
            "verification_script": VERIFICATION_SCRIPT_PATH,
            "artifact_root_hint": ARTIFACT_ROOT_HINT,
            "provisioning": self.config.as_ref().map(RoamConfig::provisioning_readiness),
            "operator_guidance": operator_guidance(),
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
            "roam.pages.list" => self.invoke_pages_list(client).await,
            "roam.pages.get" => self.invoke_pages_get(client, &input).await,
            "roam.blocks.list" => self.invoke_blocks_list(client, &input).await,
            "roam.blocks.create" => self.invoke_blocks_create(client, &input).await,
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

        let allowed = operations_info().as_array().is_some_and(|ops| {
            ops.iter()
                .any(|o| o.get("id").and_then(serde_json::Value::as_str) == Some(operation))
        });

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
        info!("Roam Research connector shutting down");
        if let Some(client) = &self.client {
            client.shutdown();
        }
        self.client = None;
        self.config = None;
        self.session_id = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    async fn invoke_pages_list(&self, client: &RoamClient) -> Result<serde_json::Value, RoamError> {
        let data = client.list_pages().await?;
        Ok(data)
    }

    async fn invoke_pages_get(
        &self,
        client: &RoamClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RoamError> {
        let title = require_str(input, "title")?;
        let data = client.get_page(title).await?;
        Ok(data)
    }

    async fn invoke_blocks_list(
        &self,
        client: &RoamClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RoamError> {
        let page_uid = require_str(input, "page_uid")?;
        let data = client.list_blocks(page_uid).await?;
        Ok(data)
    }

    async fn invoke_blocks_create(
        &self,
        client: &RoamClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RoamError> {
        let page_uid = require_str(input, "page_uid")?;
        let content = require_str(input, "content")?;
        let data = client.create_block(page_uid, content).await?;
        Ok(data)
    }

    fn serialize_self_check_report(report: SelfCheckReport) -> FcpResult<serde_json::Value> {
        info!(
            event = "roam.provisioning.self_check",
            status = ?report.status,
            reason_code = ?report.reason_code,
            "Roam Research self-check completed"
        );

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, RoamError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| RoamError::InvalidInput(format!("Missing required field: {field}")))
}

/// Build the provisioning recipe for the Roam Research connector.
pub fn provisioning_recipe() -> ProvisioningRecipe {
    ProvisioningRecipe::new(
        RecipeId::new("roam.api_token"),
        "1",
        "Provision Roam Research connector with an API token",
    )
    .with_step(ProvisioningStep::new(
        StepId::new("open_settings"),
        ProvisioningStepType::OpenUrl {
            url: "https://roamresearch.com/#/app/developer".into(),
        },
    ))
    .with_step(
        ProvisioningStep::new(
            StepId::new("enter_token"),
            ProvisioningStepType::PromptSecret {
                message: "Paste your Roam Research API token".into(),
            },
        )
        .depends_on(StepId::new("open_settings")),
    )
    .with_step(
        ProvisioningStep::new(
            StepId::new("store_token"),
            ProvisioningStepType::StoreSecret {
                key: "access_token".into(),
                value_from: StepId::new("enter_token"),
                scope: "connector:fcp.roam".into(),
            },
        )
        .depends_on(StepId::new("enter_token")),
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
    let allowed_host = host.eq_ignore_ascii_case("api.roamresearch.com") || local;
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
                "Endpoint must use https and api.roamresearch.com (localhost/127.0.0.1/::1 allowed for tests): {base_url}"
            ),
        )
    }
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

/// Build typed operations info for introspection.
fn typed_operations_info() -> FcpResult<Vec<OperationInfo>> {
    Ok(ordered_manifest_operations()?
        .into_iter()
        .map(|(id, operation)| operation_info_from_manifest(id, &operation))
        .collect())
}

/// Build the operations info for introspection (JSON format for simulate).
fn operations_info() -> Value {
    static OPERATIONS: OnceLock<Value> = OnceLock::new();
    OPERATIONS
        .get_or_init(|| {
            Value::Array(
                introspect_operations()
                    .expect("embedded Roam manifest should validate for introspection"),
            )
        })
        .clone()
}

fn ordered_manifest_operations() -> FcpResult<Vec<(String, fcp_manifest::OperationSection)>> {
    let manifest =
        ConnectorManifest::parse_str(MANIFEST_TOML).map_err(|error| FcpError::Internal {
            message: format!("Embedded Roam manifest is invalid: {error}"),
        })?;
    let mut operations: Vec<_> = manifest.provides.operations.into_iter().collect();
    operations.sort_by(|(left, _), (right, _)| {
        let left_index = operation_order(left);
        let right_index = operation_order(right);
        left_index.cmp(&right_index).then_with(|| left.cmp(right))
    });
    Ok(operations)
}

fn introspect_operations() -> FcpResult<Vec<Value>> {
    Ok(ordered_manifest_operations()?
        .into_iter()
        .map(|(id, operation)| {
            let operation_info = operation_info_from_manifest(id, &operation);
            introspect_operation_from_manifest(operation_info, &operation)
        })
        .collect())
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

fn introspect_operation_from_manifest(
    operation_info: OperationInfo,
    operation: &fcp_manifest::OperationSection,
) -> Value {
    let mut metadata =
        serde_json::to_value(operation_info).expect("Roam operation metadata should serialize");
    metadata["requires_approval"] = json!(operation.requires_approval);
    metadata["revocation_freshness"] = json!(operation.revocation_freshness);
    if let Some(network_constraints) = &operation.network_constraints {
        metadata["network_constraints"] = json!(network_constraints);
    }
    metadata
}

fn operation_info_from_manifest(
    id: String,
    operation: &fcp_manifest::OperationSection,
) -> OperationInfo {
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

    fn strict_roam_manifest() -> Result<ConnectorManifest, String> {
        ConnectorManifest::parse_str(MANIFEST_TOML)
            .map_err(|err| format!("Roam manifest should parse with strict schema: {err}"))
    }

    #[test]
    fn config_from_access_token() {
        let config = RoamConfig::from_params(&json!({
            "access_token": "test-token",
        }))
        .unwrap();
        assert!(matches!(config.auth, RoamAuth::BearerToken(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
        assert_eq!(config.graph_name, DEFAULT_GRAPH_NAME);
    }

    #[test]
    fn config_from_credential_id() {
        let config = RoamConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let config = RoamConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "http://localhost:12345",
        }))
        .unwrap();
        assert_eq!(config.base_url, "http://localhost:12345");
    }

    #[test]
    fn config_custom_graph_name() {
        let config = RoamConfig::from_params(&json!({
            "access_token": "tok",
            "graph_name": "my-research",
        }))
        .unwrap();
        assert_eq!(config.graph_name, "my-research");
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = RoamConfig::from_params(&json!({
            "access_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = RoamConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_access_token() {
        let result = RoamConfig::from_params(&json!({
            "access_token": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_access_token() {
        let result = RoamConfig::from_params(&json!({
            "access_token": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = RoamConfig::from_params(&json!({
            "credential_id": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = RoamConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_trims_access_token() {
        let config = RoamConfig::from_params(&json!({ "access_token": "  tok_test  " })).unwrap();
        match &config.auth {
            RoamAuth::BearerToken(t) => assert_eq!(t, "tok_test"),
            RoamAuth::CredentialId(_) => panic!("expected BearerToken"),
        }
    }

    #[test]
    fn config_empty_graph_name_uses_default() {
        let config = RoamConfig::from_params(&json!({
            "access_token": "tok",
            "graph_name": "",
        }))
        .unwrap();
        assert_eq!(config.graph_name, DEFAULT_GRAPH_NAME);
    }

    #[test]
    fn config_whitespace_graph_name_uses_default() {
        let config = RoamConfig::from_params(&json!({
            "access_token": "tok",
            "graph_name": "   ",
        }))
        .unwrap();
        assert_eq!(config.graph_name, DEFAULT_GRAPH_NAME);
    }

    #[test]
    fn require_str_present() {
        let input = json!({"title": "Daily Notes"});
        assert_eq!(require_str(&input, "title").unwrap(), "Daily Notes");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "title").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"title": 42});
        assert!(require_str(&input, "title").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"title": null});
        assert!(require_str(&input, "title").is_err());
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"title": true});
        assert!(require_str(&input, "title").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"title": ["a", "b"]});
        assert!(require_str(&input, "title").is_err());
    }

    #[test]
    fn require_str_empty_string() {
        let input = json!({"title": ""});
        assert_eq!(require_str(&input, "title").unwrap(), "");
    }

    #[test]
    fn operations_info_has_4_operations() {
        let ops = operations_info();
        let arr = ops.as_array().unwrap();
        assert_eq!(arr.len(), 4);
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
        assert_eq!(ids, OPERATION_ORDER.to_vec());
    }

    #[test]
    fn runtime_operation_catalog_matches_manifest_metadata() -> Result<(), String> {
        let manifest = strict_roam_manifest()?;
        let operation_catalog =
            typed_operations_info().map_err(|err| format!("typed operation catalog: {err}"))?;
        let operation_metadata = operations_info();
        let runtime_operations = operation_metadata
            .as_array()
            .ok_or_else(|| "runtime operations should serialize as an array".to_owned())?;

        let catalog_ids: Vec<&str> = operation_catalog
            .iter()
            .map(|operation| operation.id.as_str())
            .collect();
        let metadata_ids: Vec<&str> = runtime_operations
            .iter()
            .filter_map(|operation| operation["id"].as_str())
            .collect();

        assert_eq!(catalog_ids, OPERATION_ORDER.to_vec());
        assert_eq!(metadata_ids, OPERATION_ORDER.to_vec());
        assert_eq!(manifest.provides.operations.len(), OPERATION_ORDER.len());

        for operation in operation_catalog {
            let operation_id = operation.id.as_str();
            let manifest_operation = manifest
                .provides
                .operations
                .get(operation_id)
                .ok_or_else(|| format!("manifest should declare {operation_id}"))?;
            let metadata = runtime_operations
                .iter()
                .find(|candidate| candidate["id"].as_str() == Some(operation_id))
                .ok_or_else(|| format!("runtime metadata should declare {operation_id}"))?;

            assert_eq!(operation.summary, manifest_operation.description);
            assert_eq!(
                operation.description.as_ref(),
                Some(&manifest_operation.description)
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
                operation.ai_hints.when_to_use,
                manifest_operation.ai_hints.when_to_use
            );
            assert_eq!(
                operation.ai_hints.common_mistakes,
                manifest_operation.ai_hints.common_mistakes
            );
            assert_eq!(
                operation.ai_hints.examples,
                manifest_operation.ai_hints.examples
            );
            assert_eq!(
                operation.ai_hints.related,
                manifest_operation.ai_hints.related
            );
            assert_eq!(
                metadata["requires_approval"],
                json!(manifest_operation.requires_approval)
            );
            assert_eq!(
                metadata["revocation_freshness"],
                json!(manifest_operation.revocation_freshness)
            );
            assert!(
                manifest_operation.network_constraints.is_some(),
                "{operation_id} should declare manifest network constraints"
            );
            assert_eq!(
                metadata["network_constraints"],
                json!(manifest_operation.network_constraints.as_ref().unwrap())
            );
        }

        Ok(())
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
    fn operations_write_ops_are_not_safe() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            #[allow(clippy::case_sensitive_file_extension_comparisons)]
            if cap.ends_with(".write") {
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
    fn operations_pages_list_capability() {
        let ops = operations_info();
        let pages_list = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "roam.pages.list")
            .unwrap();
        assert_eq!(pages_list["capability"], "roam.pages.read");
    }

    #[test]
    fn operations_blocks_create_capability() {
        let ops = operations_info();
        let bc = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "roam.blocks.create")
            .unwrap();
        assert_eq!(bc["capability"], "roam.blocks.write");
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
    fn doctor_check_skip_serializing_message_none() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let v = serde_json::to_string(&check).unwrap();
        assert!(!v.contains("message"));
    }

    #[test]
    fn doctor_check_serializes_message_some() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("failed".into()),
            critical: true,
        };
        let v = serde_json::to_string(&check).unwrap();
        assert!(v.contains("failed"));
    }

    #[test]
    fn connector_default() {
        let c = RoamConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_new_has_zero_counters() {
        let c = RoamConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn default_graph_name_value() {
        assert_eq!(DEFAULT_GRAPH_NAME, "default");
    }

    #[test]
    fn config_graph_name_trimmed() {
        let config = RoamConfig::from_params(&json!({
            "access_token": "tok",
            "graph_name": "  my-graph  ",
        }))
        .unwrap();
        assert_eq!(config.graph_name, "my-graph");
    }

    #[test]
    fn config_debug_shows_auth() {
        let config = RoamConfig::from_params(&json!({
            "access_token": "tok123",
        }))
        .unwrap();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("RoamConfig"));
        assert!(!dbg.contains("tok123"));
    }

    #[test]
    fn config_clone() {
        let config = RoamConfig::from_params(&json!({
            "access_token": "tok",
            "graph_name": "my-graph",
        }))
        .unwrap();
        let cloned = config.clone();
        assert_eq!(cloned.graph_name, "my-graph");
        assert_eq!(cloned.base_url, config.base_url);
    }

    #[test]
    fn require_str_empty_object() {
        let input = json!({});
        assert!(require_str(&input, "page_uid").is_err());
    }

    #[test]
    fn require_str_object_value() {
        let input = json!({"title": {"nested": true}});
        assert!(require_str(&input, "title").is_err());
    }

    #[test]
    fn require_str_float_value() {
        let input = json!({"title": 9.876});
        assert!(require_str(&input, "title").is_err());
    }

    #[test]
    fn operations_blocks_list_capability() {
        let ops = operations_info();
        let bl = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "roam.blocks.list")
            .unwrap();
        assert_eq!(bl["capability"], "roam.blocks.read");
    }

    #[test]
    fn operations_pages_get_capability() {
        let ops = operations_info();
        let pg = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "roam.pages.get")
            .unwrap();
        assert_eq!(pg["capability"], "roam.pages.read");
    }

    #[test]
    fn operations_all_have_summary() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let summary = op["summary"].as_str().unwrap();
            assert!(!summary.is_empty(), "op {:?} has empty summary", op["id"]);
        }
    }

    #[test]
    fn operations_blocks_create_is_not_strict_idempotent() {
        let ops = operations_info();
        let bc = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "roam.blocks.create")
            .unwrap();
        assert_eq!(bc["idempotency"], "none");
    }

    #[test]
    fn doctor_status_serde_roundtrip() {
        let healthy = serde_json::to_value(DoctorStatus::Healthy).unwrap();
        assert_eq!(healthy, "healthy");
        let degraded = serde_json::to_value(DoctorStatus::Degraded).unwrap();
        assert_eq!(degraded, "degraded");
        let unhealthy = serde_json::to_value(DoctorStatus::Unhealthy).unwrap();
        assert_eq!(unhealthy, "unhealthy");
    }

    #[test]
    fn doctor_status_deserialize() {
        let h: DoctorStatus = serde_json::from_value(json!("healthy")).unwrap();
        assert_eq!(h, DoctorStatus::Healthy);
        let d: DoctorStatus = serde_json::from_value(json!("degraded")).unwrap();
        assert_eq!(d, DoctorStatus::Degraded);
    }

    #[test]
    fn doctor_result_preserves_check_count() {
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
            DoctorCheck {
                name: "c".into(),
                passed: false,
                message: Some("x".into()),
                critical: false,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.checks.len(), 3);
        assert_eq!(r.status, DoctorStatus::Degraded);
    }

    // ── Provisioning tests ────────────────────────────────────────

    #[test]
    fn provisioning_readiness_bearer_token_mode() {
        let config = RoamConfig::from_params(&json!({
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
        let config = RoamConfig::from_params(&json!({
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
        let config = RoamConfig::from_params(&json!({
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
    fn provisioning_readiness_custom_base_url_rejected() {
        let config = RoamConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://evil.example.com",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(!readiness.network_ok);
        assert!(readiness.network_message.contains("api.roamresearch.com"));
    }

    #[test]
    fn provisioning_recipe_has_3_steps() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.id.as_str(), "roam.api_token");
        assert_eq!(recipe.version, "1");
        assert_eq!(recipe.steps.len(), 3);
    }

    #[test]
    fn provisioning_recipe_step_order() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.steps[0].id.as_str(), "open_settings");
        assert_eq!(recipe.steps[1].id.as_str(), "enter_token");
        assert_eq!(recipe.steps[2].id.as_str(), "store_token");
    }

    #[test]
    fn provisioning_recipe_step_dependencies() {
        let recipe = provisioning_recipe();
        assert!(recipe.steps[0].depends_on.is_empty());
        assert_eq!(recipe.steps[1].depends_on.len(), 1);
        assert_eq!(recipe.steps[1].depends_on[0].as_str(), "open_settings");
        assert_eq!(recipe.steps[2].depends_on.len(), 1);
        assert_eq!(recipe.steps[2].depends_on[0].as_str(), "enter_token");
    }

    #[test]
    fn provisioning_recipe_serializes() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        assert_eq!(v["id"], "roam.api_token");
        assert_eq!(v["steps"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn provisioning_recipe_description() {
        let recipe = provisioning_recipe();
        assert!(recipe.description.contains("Roam Research"));
        assert!(recipe.description.contains("API token"));
    }

    #[test]
    fn provisioning_recipe_first_step_is_open_url() {
        let recipe = provisioning_recipe();
        assert!(matches!(
            &recipe.steps[0].kind,
            ProvisioningStepType::OpenUrl { url } if url.contains("roamresearch.com")
        ));
    }

    #[test]
    fn provisioning_recipe_second_step_is_prompt_secret() {
        let recipe = provisioning_recipe();
        assert!(matches!(
            &recipe.steps[1].kind,
            ProvisioningStepType::PromptSecret { message } if message.contains("API token")
        ));
    }

    #[test]
    fn provisioning_recipe_third_step_is_store_secret() {
        let recipe = provisioning_recipe();
        assert!(matches!(
            &recipe.steps[2].kind,
            ProvisioningStepType::StoreSecret { key, scope, .. }
                if key == "access_token" && scope.contains("roam")
        ));
    }

    #[test]
    fn base_url_policy_accepts_roam_https() {
        let (ok, message) = base_url_policy("https://api.roamresearch.com/api/graph");
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
        let (ok, message) = base_url_policy("http://api.roamresearch.com/api/graph");
        assert!(!ok);
        assert!(message.contains("must use https"));
    }

    #[test]
    fn base_url_policy_rejects_unknown_host() {
        let (ok, message) = base_url_policy("https://evil.example.com");
        assert!(!ok);
        assert!(message.contains("api.roamresearch.com"));
    }

    #[test]
    fn base_url_policy_rejects_invalid_url() {
        let (ok, message) = base_url_policy("not a url");
        assert!(!ok);
        assert!(message.contains("could not be parsed"));
    }

    #[test]
    fn is_local_test_host_valid_values() {
        assert!(is_local_test_host("localhost"));
        assert!(is_local_test_host("127.0.0.1"));
        assert!(is_local_test_host("::1"));
        assert!(!is_local_test_host("example.com"));
        assert!(!is_local_test_host("api.roamresearch.com"));
    }

    #[test]
    fn provisioning_readiness_localhost_base_url() {
        let config = RoamConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "http://localhost:8080",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(readiness.network_ok);
        assert!(readiness.network_message.contains("accepted"));
    }
}
