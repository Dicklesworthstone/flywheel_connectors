//! Coda connector implementation.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcp_prelude::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    HealthSnapshot, IdempotencyClass, InstanceId, Introspection, InvokeRequest, InvokeResponse,
    OperationId, OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId, ShutdownRequest,
    SimulateRequest, SimulateResponse,
};
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::prelude::*;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::client::CodaClient;
use crate::error::CodaError;
use crate::types::{Doc, MutationStatus};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const CODA_BASE_URL: &str = "https://coda.io/apis/v1";
const CODA_HOST: &str = "coda.io";
const CODA_IMPLEMENTATION_STATUS: &str = "first_slice";
const CODA_BINDING_MODEL: &str = "single_workspace";
const CODA_AUTH_MODEL: &str = "bearer_api_token";
const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/coda_connector_verification.sh";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/coda_connector/<timestamp>";
const VERIFY_COMMANDS: [&str; 7] = [
    "scripts/e2e/coda_connector_verification.sh",
    "RCH_FORCE_REMOTE=1 rch exec -- cargo run -q -p fwc -- manifest fix connectors/coda/manifest.toml --check --json",
    "RCH_FORCE_REMOTE=1 rch exec -- cargo check -p fcp-coda --all-targets",
    "cargo fmt --manifest-path connectors/coda/Cargo.toml --check",
    "RCH_FORCE_REMOTE=1 rch exec -- cargo test -p fcp-coda --test integration -- --nocapture",
    "RCH_FORCE_REMOTE=1 rch exec -- cargo test -p fcp-coda",
    "RCH_FORCE_REMOTE=1 rch exec -- cargo clippy -p fcp-coda --all-targets -- -D warnings",
];

// Operation IDs
const OP_ACCOUNT_WHOAMI: &str = "coda.account.whoami";
const OP_DOCS_LIST: &str = "coda.docs.list";
const OP_DOCS_GET: &str = "coda.docs.get";
const OP_PAGES_LIST: &str = "coda.pages.list";
const OP_PAGES_GET: &str = "coda.pages.get";
const OP_TABLES_LIST: &str = "coda.tables.list";
const OP_TABLES_GET: &str = "coda.tables.get";
const OP_COLUMNS_LIST: &str = "coda.columns.list";
const OP_ROWS_LIST: &str = "coda.rows.list";
const OP_ROWS_GET: &str = "coda.rows.get";
const OP_ROWS_UPSERT: &str = "coda.rows.upsert";
const OP_ROWS_DELETE: &str = "coda.rows.delete";
const OP_FORMULAS_LIST: &str = "coda.formulas.list";
const OP_FORMULAS_GET: &str = "coda.formulas.get";
const OP_CONTROLS_LIST: &str = "coda.controls.list";
const OP_CONTROLS_GET: &str = "coda.controls.get";
const OP_MUTATIONS_GET_STATUS: &str = "coda.mutations.get_status";
const OP_HEALTH: &str = "coda.health";

// Capability IDs
const CAP_ACCOUNT_READ: &str = "coda.account.read";
const CAP_DOCS_READ: &str = "coda.docs.read";
const CAP_TABLES_READ: &str = "coda.tables.read";
const CAP_ROWS_READ: &str = "coda.rows.read";
const CAP_ROWS_WRITE: &str = "coda.rows.write";
const CAP_FORMULAS_READ: &str = "coda.formulas.read";
const CAP_CONTROLS_READ: &str = "coda.controls.read";
const CAP_MUTATIONS_READ: &str = "coda.mutations.read";

/// Coda connector configuration.
#[derive(Clone, Deserialize)]
struct CodaConfig {
    #[serde(default = "default_base_url")]
    base_url: String,
    workspace_id: String,
    #[serde(default)]
    allowed_doc_ids: Vec<String>,
    api_token: String,
    #[serde(default)]
    retry: HttpRetryConfig,
    #[serde(default = "default_request_timeout_ms")]
    request_timeout_ms: u64,
    #[serde(default = "default_mutation_poll_interval_ms")]
    mutation_poll_interval_ms: u64,
    #[serde(default = "default_mutation_deadline_ms")]
    mutation_deadline_ms: u64,
}

impl std::fmt::Debug for CodaConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodaConfig")
            .field("base_url", &self.base_url)
            .field("workspace_id", &self.workspace_id)
            .field("allowed_doc_ids", &self.allowed_doc_ids)
            .field("api_token", &"[REDACTED]")
            .field("retry", &self.retry)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .field("mutation_poll_interval_ms", &self.mutation_poll_interval_ms)
            .field("mutation_deadline_ms", &self.mutation_deadline_ms)
            .finish()
    }
}

fn default_base_url() -> String {
    CODA_BASE_URL.into()
}

const fn default_request_timeout_ms() -> u64 {
    30_000
}

const fn default_mutation_poll_interval_ms() -> u64 {
    1_000
}

const fn default_mutation_deadline_ms() -> u64 {
    30_000
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1")
}

impl CodaConfig {
    fn validate(&self) -> Result<(), String> {
        if self.workspace_id.is_empty() {
            return Err("workspace_id is required".into());
        }
        if self.api_token.is_empty() {
            return Err("api_token is required".into());
        }
        if self.request_timeout_ms == 0 {
            return Err("request_timeout_ms must be greater than 0".into());
        }
        if self.mutation_poll_interval_ms == 0 {
            return Err("mutation_poll_interval_ms must be greater than 0".into());
        }
        if self.mutation_deadline_ms == 0 {
            return Err("mutation_deadline_ms must be greater than 0".into());
        }

        let parsed = reqwest::Url::parse(&self.base_url)
            .map_err(|err| format!("base_url must be a valid absolute URL: {err}"))?;
        let Some(host) = parsed.host_str() else {
            return Err("base_url must include a hostname".into());
        };
        let local_test_host = is_local_test_host(host);
        if parsed.scheme() != "https" && !(parsed.scheme() == "http" && local_test_host) {
            return Err(
                "base_url must use https unless targeting a localhost test override".into(),
            );
        }
        let host_ok = host == CODA_HOST || local_test_host;
        if !host_ok {
            return Err(format!(
                "base_url host must be {CODA_HOST} or localhost for tests"
            ));
        }
        if host == CODA_HOST && parsed.path() != "/apis/v1" {
            return Err("base_url must use the /apis/v1 path".into());
        }

        if self
            .allowed_doc_ids
            .iter()
            .any(|doc_id| doc_id.trim().is_empty())
        {
            return Err("allowed_doc_ids must not contain empty values".into());
        }

        Ok(())
    }

    fn from_value(value: serde_json::Value) -> FcpResult<Self> {
        let mut config: Self =
            serde_json::from_value(value).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid Coda config: {e}"),
            })?;
        config.base_url = config.base_url.trim().trim_end_matches('/').to_owned();
        if config.base_url.is_empty() {
            config.base_url = default_base_url();
        }
        config.workspace_id = config.workspace_id.trim().to_owned();
        config.api_token = config.api_token.trim().to_owned();
        config.allowed_doc_ids = config
            .allowed_doc_ids
            .into_iter()
            .map(|doc_id| doc_id.trim().to_owned())
            .filter(|doc_id| !doc_id.is_empty())
            .collect();
        config.validate().map_err(|e| FcpError::InvalidRequest {
            code: 1001,
            message: format!("Invalid Coda config: {e}"),
        })?;
        Ok(config)
    }
}

// Doctor types
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
        let passed = checks.iter().filter(|c| c.critical).all(|c| c.passed);
        Self {
            ready: passed,
            passed,
            checks,
            provisioning,
            operator_guidance: operator_guidance(),
            verification_script: VERIFICATION_SCRIPT_PATH,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
struct RetryReadiness {
    max_retries: u32,
    initial_delay_ms: u64,
    max_delay_ms: u64,
    jitter_enabled: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
struct ProvisioningReadiness {
    base_url: String,
    auth_mode: &'static str,
    workspace_id: String,
    allowed_doc_ids: Vec<String>,
    request_timeout_ms: u64,
    mutation_poll_interval_ms: u64,
    mutation_deadline_ms: u64,
    retry: RetryReadiness,
    authenticated_identity_probe: &'static str,
    risky_mutations: Vec<&'static str>,
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

fn auth_mode_label(config: &CodaConfig) -> &'static str {
    if config.api_token.is_empty() {
        "proxy_injected"
    } else {
        "bearer_api_token"
    }
}

fn operator_guidance() -> OperatorGuidance {
    OperatorGuidance {
        prerequisites: vec![
            "Use a disposable Coda workspace and doc set, or a localhost mock server, before running the verification bundle.",
            "Bind the connector to exactly one workspace_id and make sure every verification doc is either in that workspace or explicitly listed in allowed_doc_ids.",
            "Treat rows.upsert and rows.delete as live document mutations unless you are running against a localhost mock override.",
        ],
        dedicated_environment: "Prefer a disposable Coda workspace or a localhost mock server. Avoid running verification against production docs unless the resulting row edits and deletions are acceptable.",
        redaction_rules: vec![
            "Redact API tokens, Authorization headers, request IDs, and copied HTTP logs before sharing evidence.",
            "Treat login IDs, workspace IDs, doc IDs, row IDs, browser links, and doc names as potentially sensitive operational metadata.",
            "If verification touches a real workspace, sanitize document titles, table names, formula values, and row contents in archived artifacts.",
        ],
        limitations: vec![
            "One connector instance is bound to one configured workspace boundary; multi-workspace aggregation is intentionally out of scope.",
            "The current slice supports read-heavy doc/table inspection plus row upsert and deletion with mutation-status polling.",
            "Doc governance, page content mutation, button execution, publishing, automations, and analytics remain out of scope.",
        ],
        common_remediation: vec![
            RemediationHint {
                code: "not_configured",
                symptom: "health or self_check reports that the connector is not configured",
                action: "Configure workspace_id, api_token, timeout, retry, and mutation polling settings, then rerun self_check.",
            },
            RemediationHint {
                code: "coda_auth_rejected",
                symptom: "self_check fails with HTTP 401/403 or an unauthorized error from Coda",
                action: "Replace the API token, confirm it still resolves GET /whoami, and rerun the verification script.",
            },
            RemediationHint {
                code: "workspace_mismatch",
                symptom: "self_check reports that the token workspace does not match the configured workspace_id",
                action: "Update workspace_id to the workspace returned by GET /whoami or switch to a token that belongs to the intended workspace.",
            },
            RemediationHint {
                code: "doc_allowlist_violation",
                symptom: "doc reads or mutations reject a doc_id as outside the configured allowlist",
                action: "Add the target doc to allowed_doc_ids or rerun verification against a doc that is already inside the configured allowlist.",
            },
            RemediationHint {
                code: "self_check_retryable",
                symptom: "self_check reports a timeout, rate limit, or temporary 5xx from Coda",
                action: "Wait for the upstream to recover or increase request_timeout_ms and retry settings for the environment before rerunning verification.",
            },
            RemediationHint {
                code: "network_constraints_invalid",
                symptom: "doctor reports that base_url falls outside the live Coda host or localhost test override rules",
                action: "Use https://coda.io/apis/v1 for live verification or an http://localhost / http://127.0.0.1 override for deterministic mock-server tests.",
            },
        ],
        rerun_commands: VERIFY_COMMANDS.to_vec(),
        artifact_root_hint: ARTIFACT_ROOT_HINT,
    }
}

fn contract_details(config: Option<&CodaConfig>) -> serde_json::Value {
    let credential_mode = config.map_or("unconfigured", auth_mode_label);

    json!({
        "implementation": {
            "api": "coda_rest_v1",
            "status": CODA_IMPLEMENTATION_STATUS,
            "notes": [
                "The connector targets the Coda REST API for one configured workspace boundary.",
                "Asynchronous writes are tracked through requestId and mutationStatus polling."
            ],
        },
        "auth_boundary": {
            "binding": CODA_BINDING_MODEL,
            "token_type": CODA_AUTH_MODEL,
            "credential_mode": credential_mode,
            "base_url": config.map(|cfg| cfg.base_url.clone()),
            "workspace_id": config.map(|cfg| cfg.workspace_id.clone()),
            "allowed_doc_ids": config.map(|cfg| cfg.allowed_doc_ids.clone()).unwrap_or_default(),
            "doc_scope_narrowing_enabled": config.is_some_and(|cfg| !cfg.allowed_doc_ids.is_empty()),
            "multi_workspace_supported": false,
            "credential_id_supported": false,
        },
        "service_inventory": {
            "account": [OP_ACCOUNT_WHOAMI],
            "docs": [OP_DOCS_LIST, OP_DOCS_GET],
            "pages": [OP_PAGES_LIST, OP_PAGES_GET],
            "tables": [OP_TABLES_LIST, OP_TABLES_GET, OP_COLUMNS_LIST],
            "rows": [OP_ROWS_LIST, OP_ROWS_GET, OP_ROWS_UPSERT, OP_ROWS_DELETE],
            "formulas": [OP_FORMULAS_LIST, OP_FORMULAS_GET],
            "controls": [OP_CONTROLS_LIST, OP_CONTROLS_GET],
            "mutations": [OP_MUTATIONS_GET_STATUS],
        },
        "non_goals": [
            "Doc create, update, delete, and governance flows",
            "Folder CRUD, permissions, publishing, analytics, and automations",
            "Page content mutation, push-button execution, and multi-workspace aggregation"
        ]
    })
}

fn require_str<'a>(input: &'a serde_json::Value, key: &str) -> FcpResult<&'a str> {
    let value = input
        .get(key)
        .and_then(|value| value.as_str())
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: format!("Missing '{key}' field"),
        })?;
    if value.trim().is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("Field '{key}' must not be empty"),
        });
    }
    Ok(value)
}

/// Coda connector state.
#[derive(Debug)]
pub struct CodaConnector {
    base: BaseConnector,
    config: Option<CodaConfig>,
    client: Option<CodaClient>,
    runtime: Option<ConnectorRuntime>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl CodaConnector {
    /// Create a new connector instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.coda")),
            config: None,
            client: None,
            runtime: None,
            started_at: Instant::now(),
            verifier: None,
        }
    }

    /// Stable connector instance identity used for bound capability-token verification.
    #[must_use]
    pub fn instance_id(&self) -> &InstanceId {
        &self.base.instance_id
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    fn provisioning_readiness(&self) -> Option<ProvisioningReadiness> {
        self.config.as_ref().map(|config| ProvisioningReadiness {
            base_url: config.base_url.clone(),
            auth_mode: auth_mode_label(config),
            workspace_id: config.workspace_id.clone(),
            allowed_doc_ids: config.allowed_doc_ids.clone(),
            request_timeout_ms: config.request_timeout_ms,
            mutation_poll_interval_ms: config.mutation_poll_interval_ms,
            mutation_deadline_ms: config.mutation_deadline_ms,
            retry: RetryReadiness {
                max_retries: config.retry.max_retries,
                initial_delay_ms: config.retry.initial_delay_ms,
                max_delay_ms: config.retry.max_delay_ms,
                jitter_enabled: config.retry.jitter_enabled,
            },
            authenticated_identity_probe: "GET /whoami",
            risky_mutations: vec![OP_ROWS_UPSERT, OP_ROWS_DELETE],
        })
    }

    fn attach_self_check_details(
        &self,
        mut report: SelfCheckReport,
        live_probe: Option<&serde_json::Value>,
    ) -> SelfCheckReport {
        report.details = Some(json!({
            "configured": self.config.is_some(),
            "client_initialized": self.client.is_some(),
            "runtime_initialized": self.runtime.is_some(),
            "handshaken": self.base.handshaken.load(Ordering::Acquire),
            "manifest_hash": Self::manifest_hash(),
            "verification_script": VERIFICATION_SCRIPT_PATH,
            "artifact_root_hint": ARTIFACT_ROOT_HINT,
            "provisioning": self.provisioning_readiness(),
            "operator_guidance": operator_guidance(),
            "live_probe": live_probe,
            "contract": contract_details(self.config.as_ref()),
        }));
        report
    }

    /// Run connector diagnostics.
    #[allow(clippy::too_many_lines)]
    pub fn doctor(&self) -> DoctorResult {
        let mut checks = Vec::new();
        let provisioning = self.provisioning_readiness();

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

        let handshaken = self.base.handshaken.load(Ordering::Acquire);
        checks.push(DoctorCheck {
            name: "handshake".into(),
            passed: handshaken,
            message: Some(if handshaken {
                "Handshake completed".into()
            } else {
                "Handshake not completed".into()
            }),
            critical: false,
        });

        if let Some(config) = &self.config {
            checks.push(DoctorCheck {
                name: "base_url".into(),
                passed: true,
                message: Some(format!("Base URL: {}", config.base_url)),
                critical: false,
            });
            let (network_ok, network_message) = match reqwest::Url::parse(&config.base_url) {
                Ok(url) => {
                    let host = url.host_str().unwrap_or_default();
                    let local_test_host = is_local_test_host(host);
                    let scheme_ok = url.scheme() == "https"
                        || (url.scheme() == "http" && local_test_host);
                    let host_ok = host == CODA_HOST || local_test_host;
                    let path_ok = host != CODA_HOST || url.path() == "/apis/v1";
                    let passed = scheme_ok && host_ok && path_ok;
                    let message = if passed {
                        if local_test_host {
                            "Base URL uses a localhost test override for deterministic verification"
                                .into()
                        } else {
                            "Base URL matches the live Coda host and /apis/v1 path".into()
                        }
                    } else {
                        format!(
                            "Base URL {} must resolve to https://coda.io/apis/v1 or an http://localhost test override",
                            config.base_url
                        )
                    };
                    (passed, message)
                }
                Err(err) => (false, format!("Failed to parse base_url: {err}")),
            };
            checks.push(DoctorCheck {
                name: "network_constraints".into(),
                passed: network_ok,
                message: Some(network_message),
                critical: true,
            });
            checks.push(DoctorCheck {
                name: "workspace_scope".into(),
                passed: true,
                message: Some(format!(
                    "Workspace-bound to {} with {} explicitly allowed doc(s)",
                    config.workspace_id,
                    config.allowed_doc_ids.len()
                )),
                critical: true,
            });
            checks.push(DoctorCheck {
                name: "credential_mode".into(),
                passed: !config.api_token.is_empty(),
                message: Some(if config.api_token.is_empty() {
                    "Credential injection would be required for this configuration".into()
                } else {
                    "Bearer API token configured".into()
                }),
                critical: true,
            });
            checks.push(DoctorCheck {
                name: "auth_boundary".into(),
                passed: true,
                message: Some(
                    "Uses one bearer token for one workspace boundary; multi-workspace and document-governance flows are intentionally out of scope."
                        .into(),
                ),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "service_inventory".into(),
                passed: true,
                message: Some(
                    "Supported today: workspace-scoped docs/pages/tables/rows/formulas/controls reads plus row upsert/delete with mutation-status tracking."
                        .into(),
                ),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "mutation_tracking".into(),
                passed: true,
                message: Some(format!(
                    "Asynchronous writes poll mutationStatus every {}ms with a {}ms deadline.",
                    config.mutation_poll_interval_ms, config.mutation_deadline_ms
                )),
                critical: false,
            });
        }

        DoctorResult::from_checks(checks, provisioning)
    }
}

impl Default for CodaConnector {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the typed operations catalog.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn operations_info() -> Vec<OperationInfo> {
    let hint = |when: &str, mistakes: Vec<String>, related: Vec<&'static str>| -> AgentHint {
        AgentHint {
            when_to_use: when.into(),
            common_mistakes: mistakes,
            examples: Vec::new(),
            related: related.into_iter().map(CapabilityId::from_static).collect(),
        }
    };

    vec![
        OperationInfo {
            id: OperationId::from_static(OP_ACCOUNT_WHOAMI),
            summary: "Inspect token identity".into(),
            description: Some("Read authenticated user info and workspace binding from Coda.".into()),
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_ACCOUNT_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint("Use to validate the configured token and workspace boundary.", vec![], vec![CAP_DOCS_READ]),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_DOCS_LIST),
            summary: "List workspace docs".into(),
            description: Some("List docs visible to the configured token within the configured workspace boundary.".into()),
            input_schema: json!({"type":"object","properties":{"limit":{"type":"integer"},"page_token":{"type":"string"},"query":{"type":"string"}}}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_DOCS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint("Use for workspace-scoped doc discovery.", vec!["Only docs in the configured workspace should be returned.".into()], vec![CAP_ACCOUNT_READ]),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_DOCS_GET),
            summary: "Get doc metadata".into(),
            description: Some("Fetch one document and verify it belongs to the configured workspace.".into()),
            input_schema: json!({"type":"object","required":["doc_id"],"properties":{"doc_id":{"type":"string"}}}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_DOCS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint("Use to inspect one doc's metadata and workspace binding.", vec!["doc_id must be a stable doc ID.".into()], vec![CAP_DOCS_READ]),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_PAGES_LIST),
            summary: "List pages".into(),
            description: Some("List pages in one scoped Coda document.".into()),
            input_schema: json!({"type":"object","required":["doc_id"],"properties":{"doc_id":{"type":"string"},"limit":{"type":"integer"},"page_token":{"type":"string"}}}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_DOCS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint("Use for doc structure discovery.", vec![], vec![CAP_DOCS_READ]),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_PAGES_GET),
            summary: "Get page".into(),
            description: Some("Fetch one page by page ID or name inside a scoped doc.".into()),
            input_schema: json!({"type":"object","required":["doc_id","page_id_or_name"],"properties":{"doc_id":{"type":"string"},"page_id_or_name":{"type":"string"}}}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_DOCS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint("Use to inspect one page.", vec!["Stable page IDs are preferred over names.".into()], vec![CAP_DOCS_READ]),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_TABLES_LIST),
            summary: "List tables".into(),
            description: Some("List tables and views in one scoped Coda document.".into()),
            input_schema: json!({"type":"object","required":["doc_id"],"properties":{"doc_id":{"type":"string"},"limit":{"type":"integer"},"page_token":{"type":"string"}}}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_TABLES_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint("Use to discover tables before row reads or writes.", vec![], vec![CAP_ROWS_READ]),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_TABLES_GET),
            summary: "Get table".into(),
            description: Some("Fetch one table or view by stable identifier.".into()),
            input_schema: json!({"type":"object","required":["doc_id","table_id_or_name"],"properties":{"doc_id":{"type":"string"},"table_id_or_name":{"type":"string"}}}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_TABLES_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint("Use to inspect one table or view.", vec!["Stable table IDs are preferred over names.".into()], vec![CAP_ROWS_READ]),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_COLUMNS_LIST),
            summary: "List columns".into(),
            description: Some("List columns for a base table or view.".into()),
            input_schema: json!({"type":"object","required":["doc_id","table_id_or_name"],"properties":{"doc_id":{"type":"string"},"table_id_or_name":{"type":"string"},"limit":{"type":"integer"},"page_token":{"type":"string"}}}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_TABLES_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint("Use before row writes to learn stable column IDs.", vec![], vec![CAP_ROWS_WRITE]),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_ROWS_LIST),
            summary: "List rows".into(),
            description: Some("List rows in a scoped Coda table or view.".into()),
            input_schema: json!({"type":"object","required":["doc_id","table_id_or_name"],"properties":{"doc_id":{"type":"string"},"table_id_or_name":{"type":"string"},"limit":{"type":"integer"},"page_token":{"type":"string"},"query":{"type":"string"}}}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_ROWS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint("Use for row enumeration and filtered reads.", vec!["Table names and row names are fragile; prefer stable IDs.".into()], vec![CAP_TABLES_READ]),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_ROWS_GET),
            summary: "Get row".into(),
            description: Some("Fetch one row by stable row ID or fallback row name.".into()),
            input_schema: json!({"type":"object","required":["doc_id","table_id_or_name","row_id_or_name"],"properties":{"doc_id":{"type":"string"},"table_id_or_name":{"type":"string"},"row_id_or_name":{"type":"string"}}}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_ROWS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint("Use for point lookup of one row.", vec!["Prefer stable row IDs over row names.".into()], vec![CAP_ROWS_READ]),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_ROWS_UPSERT),
            summary: "Upsert rows".into(),
            description: Some("Insert or update rows and wait for Coda mutation completion.".into()),
            input_schema: json!({"type":"object","required":["doc_id","table_id_or_name","rows"],"properties":{"doc_id":{"type":"string"},"table_id_or_name":{"type":"string"},"rows":{"type":"array"},"key_columns":{"type":"array","items":{"type":"string"}}}}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_ROWS_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: hint("Use to insert or update rows in a base table.", vec!["Coda may update multiple rows when key_columns match more than one record.".into()], vec![CAP_ROWS_READ, CAP_MUTATIONS_READ]),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        OperationInfo {
            id: OperationId::from_static(OP_ROWS_DELETE),
            summary: "Delete rows".into(),
            description: Some("Delete rows by stable row ID and wait for mutation completion.".into()),
            input_schema: json!({"type":"object","required":["doc_id","table_id_or_name","row_ids"],"properties":{"doc_id":{"type":"string"},"table_id_or_name":{"type":"string"},"row_ids":{"type":"array","items":{"type":"string"}}}}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_ROWS_WRITE),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint("Use for destructive row deletion after explicit confirmation.", vec!["Stable row IDs are required for destructive operations.".into()], vec![CAP_ROWS_READ, CAP_MUTATIONS_READ]),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        OperationInfo {
            id: OperationId::from_static(OP_FORMULAS_LIST),
            summary: "List formulas".into(),
            description: Some("List named formulas in a scoped document.".into()),
            input_schema: json!({"type":"object","required":["doc_id"],"properties":{"doc_id":{"type":"string"},"limit":{"type":"integer"},"page_token":{"type":"string"}}}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_FORMULAS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint("Use for formula discovery.", vec![], vec![CAP_DOCS_READ]),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_FORMULAS_GET),
            summary: "Get formula".into(),
            description: Some("Fetch a named formula by ID or name.".into()),
            input_schema: json!({"type":"object","required":["doc_id","formula_id_or_name"],"properties":{"doc_id":{"type":"string"},"formula_id_or_name":{"type":"string"}}}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_FORMULAS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint("Use for point lookup of one formula.", vec!["Stable IDs are preferred over names.".into()], vec![CAP_FORMULAS_READ]),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_CONTROLS_LIST),
            summary: "List controls".into(),
            description: Some("List controls exposed in a scoped Coda document.".into()),
            input_schema: json!({"type":"object","required":["doc_id"],"properties":{"doc_id":{"type":"string"},"limit":{"type":"integer"},"page_token":{"type":"string"}}}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_CONTROLS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint("Use to inspect the doc's exposed controls without executing buttons.", vec![], vec![CAP_DOCS_READ]),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_CONTROLS_GET),
            summary: "Get control".into(),
            description: Some("Fetch a single control by ID or name.".into()),
            input_schema: json!({"type":"object","required":["doc_id","control_id_or_name"],"properties":{"doc_id":{"type":"string"},"control_id_or_name":{"type":"string"}}}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_CONTROLS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint("Use to inspect one control's current value and metadata.", vec!["Button execution is intentionally out of scope.".into()], vec![CAP_CONTROLS_READ]),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_MUTATIONS_GET_STATUS),
            summary: "Get mutation status".into(),
            description: Some("Poll Coda for completion of an asynchronous write.".into()),
            input_schema: json!({"type":"object","required":["request_id"],"properties":{"request_id":{"type":"string"}}}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_MUTATIONS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint("Use after rows.upsert or rows.delete when you need the terminal mutation outcome.", vec![], vec![CAP_ROWS_WRITE]),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_HEALTH),
            summary: "Check connector health".into(),
            description: Some("Verify token reachability and workspace binding.".into()),
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_ACCOUNT_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint("Use before real Coda operations to validate auth and scope.", vec![], vec![CAP_ACCOUNT_READ]),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
    ]
}

fcp_core::impl_fcp_sealed!(CodaConnector);

#[async_trait]
impl FcpConnector for CodaConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config = CodaConfig::from_value(config)?;
        let runtime = ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(config.request_timeout_ms)),
        );
        let client = CodaClient::new(
            &config.base_url,
            &config.api_token,
            config.request_timeout_ms,
            config.retry.clone(),
        )
        .map_err(|e| FcpError::Internal {
            message: format!("Failed to create Coda client: {e}"),
        })?;

        self.runtime = Some(runtime);
        self.client = Some(client);
        self.config = Some(config);
        self.verifier = None;
        self.base.set_configured(true);
        self.base.set_handshaken(false);
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
        let mut snapshot = if self.config.is_some() {
            HealthSnapshot::ready()
        } else {
            HealthSnapshot::degraded("not configured")
        };
        snapshot.uptime_ms =
            u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        snapshot.details = Some(json!({
            "configured": self.config.is_some(),
            "client_initialized": self.client.is_some(),
            "runtime_initialized": self.runtime.is_some(),
            "handshaken": self.base.handshaken.load(Ordering::Acquire),
            "base_url": self.config.as_ref().map(|config| config.base_url.clone()),
            "workspace_id": self.config.as_ref().map(|config| config.workspace_id.clone()),
            "verification_script": VERIFICATION_SCRIPT_PATH,
            "artifact_root_hint": ARTIFACT_ROOT_HINT,
            "provisioning": self.provisioning_readiness(),
            "operator_guidance": operator_guidance(),
            "manifest_hash": Self::manifest_hash(),
            "contract": contract_details(self.config.as_ref()),
        }));
        snapshot
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(config) = &self.config else {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::degraded("not_configured", "Connector is not configured"),
                Some(&json!({
                    "ready": false,
                    "reason": "configure with workspace_id and api_token before self_check",
                })),
            ));
        };
        let Some(client) = &self.client else {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::failed("client_missing", "Coda client is not initialized"),
                Some(&json!({
                    "ready": false,
                    "reason": "client_missing",
                })),
            ));
        };
        let Some(runtime) = &self.runtime else {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::failed("runtime_missing", "Connector runtime is not initialized"),
                Some(&json!({
                    "ready": false,
                    "reason": "runtime_missing",
                })),
            ));
        };

        match client.whoami(runtime).await {
            Ok(user) if user.workspace.id != config.workspace_id => {
                let current_workspace_id = user.workspace.id.clone();
                Ok(self.attach_self_check_details(
                    SelfCheckReport::failed(
                        "workspace_mismatch",
                        format!(
                            "Configured workspace {} does not match token workspace {}",
                            config.workspace_id, current_workspace_id
                        ),
                    ),
                    Some(&json!({
                        "ready": false,
                        "base_url": config.base_url.clone(),
                        "configured_workspace_id": config.workspace_id.clone(),
                        "current_workspace_id": current_workspace_id,
                        "token_scoped": user.scoped,
                        "whoami": user,
                    })),
                ))
            }
            Ok(user) => {
                let current_workspace_id = user.workspace.id.clone();
                Ok(self.attach_self_check_details(
                    SelfCheckReport::ok(),
                    Some(&json!({
                        "ready": true,
                        "base_url": config.base_url.clone(),
                        "configured_workspace_id": config.workspace_id.clone(),
                        "current_workspace_id": current_workspace_id,
                        "token_scoped": user.scoped,
                        "whoami": user,
                    })),
                ))
            }
            Err(err) => {
                let retryable = err.is_retryable();
                let auth_rejected = matches!(
                    &err,
                    CodaError::Unauthorized(_)
                        | CodaError::Api {
                            status: 401 | 403,
                            ..
                        }
                );
                let reason_code = if retryable {
                    "self_check_retryable"
                } else if auth_rejected {
                    "coda_auth_rejected"
                } else {
                    "self_check_failed"
                };
                let report = if retryable {
                    SelfCheckReport::degraded(reason_code, err.to_string())
                } else {
                    SelfCheckReport::failed(reason_code, err.to_string())
                };
                Ok(self.attach_self_check_details(
                    report,
                    Some(&json!({
                        "ready": false,
                        "base_url": config.base_url.clone(),
                        "retryable": retryable,
                        "error": err.to_string(),
                    })),
                ))
            }
        }
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
        self.client = None;
        self.config = None;
        self.runtime = None;
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

impl CodaConnector {
    fn required_capability(operation: &str) -> Option<CapabilityId> {
        Some(match operation {
            OP_ACCOUNT_WHOAMI | OP_HEALTH => CapabilityId::from_static(CAP_ACCOUNT_READ),
            OP_DOCS_LIST | OP_DOCS_GET | OP_PAGES_LIST | OP_PAGES_GET => {
                CapabilityId::from_static(CAP_DOCS_READ)
            }
            OP_TABLES_LIST | OP_TABLES_GET | OP_COLUMNS_LIST => {
                CapabilityId::from_static(CAP_TABLES_READ)
            }
            OP_ROWS_LIST | OP_ROWS_GET => CapabilityId::from_static(CAP_ROWS_READ),
            OP_ROWS_UPSERT | OP_ROWS_DELETE => CapabilityId::from_static(CAP_ROWS_WRITE),
            OP_FORMULAS_LIST | OP_FORMULAS_GET => CapabilityId::from_static(CAP_FORMULAS_READ),
            OP_CONTROLS_LIST | OP_CONTROLS_GET => CapabilityId::from_static(CAP_CONTROLS_READ),
            OP_MUTATIONS_GET_STATUS => CapabilityId::from_static(CAP_MUTATIONS_READ),
            _ => return None,
        })
    }

    fn ensure_doc_id_allowed(config: &CodaConfig, doc_id: &str) -> FcpResult<()> {
        if !config.allowed_doc_ids.is_empty()
            && !config
                .allowed_doc_ids
                .iter()
                .any(|allowed| allowed == doc_id)
        {
            return Err(FcpError::Unauthorized {
                code: 2001,
                message: format!("Doc {doc_id} is outside the configured allowlist"),
            });
        }
        Ok(())
    }

    fn ensure_doc_scope(config: &CodaConfig, doc: &Doc) -> FcpResult<()> {
        Self::ensure_doc_id_allowed(config, &doc.id)?;
        match doc.workspace_id.as_deref() {
            Some(workspace_id) if workspace_id == config.workspace_id => Ok(()),
            Some(workspace_id) => Err(FcpError::Unauthorized {
                code: 2001,
                message: format!(
                    "Doc {} belongs to workspace {}, expected {}",
                    doc.id, workspace_id, config.workspace_id
                ),
            }),
            None => Err(FcpError::Unauthorized {
                code: 2001,
                message: format!(
                    "Doc {} did not include a workspaceId; refusing cross-workspace access",
                    doc.id
                ),
            }),
        }
    }

    async fn scoped_doc(
        &self,
        runtime: &ConnectorRuntime,
        client: &CodaClient,
        config: &CodaConfig,
        doc_id: &str,
    ) -> FcpResult<Doc> {
        Self::ensure_doc_id_allowed(config, doc_id)?;
        let doc = client
            .get_doc(runtime, doc_id)
            .await
            .map_err(|e| e.to_fcp_error())?;
        Self::ensure_doc_scope(config, &doc)?;
        Ok(doc)
    }

    async fn wait_for_mutation(
        &self,
        runtime: &ConnectorRuntime,
        client: &CodaClient,
        config: &CodaConfig,
        request_id: &str,
    ) -> FcpResult<MutationStatus> {
        let started = Instant::now();
        let ctx = runtime.request_context();
        loop {
            let status = client
                .get_mutation_status(runtime, request_id)
                .await
                .map_err(|e| e.to_fcp_error())?;
            if status.completed {
                return Ok(status);
            }
            if started.elapsed() >= Duration::from_millis(config.mutation_deadline_ms) {
                return Err(FcpError::External {
                    service: "coda".into(),
                    message: format!(
                        "Mutation {request_id} did not complete within {}ms",
                        config.mutation_deadline_ms
                    ),
                    status_code: None,
                    retryable: true,
                    retry_after: Some(Duration::from_millis(config.mutation_poll_interval_ms)),
                });
            }
            ctx.sleep(Duration::from_millis(config.mutation_poll_interval_ms))
                .await
                .map_err(|err| FcpError::Internal {
                    message: format!("Failed while waiting for Coda mutation completion: {err}"),
                })?;
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();

        let verifier = self.verifier.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Capability verifier missing after successful handshake".into(),
        })?;
        let required_cap =
            Self::required_capability(operation).ok_or_else(|| FcpError::InvalidRequest {
                code: 1004,
                message: format!("Unknown operation: {operation}"),
            })?;
        // dja9u.1.a: verify_bound returns CapabilityToken<BoundVerified>;
        // discarded here because invoke has no downstream that consumes
        // the typestate yet, but the call enforces the typestate handoff.
        let _bound =
            verifier.verify_bound(req.capability_token, &required_cap, &req.operation, &[])?;

        let config = self.config.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Connector config missing after configure".into(),
        })?;
        let runtime = self.runtime.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Connector runtime missing after configure".into(),
        })?;
        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Coda client missing after configure".into(),
        })?;

        let output = match operation {
            OP_ACCOUNT_WHOAMI => {
                let user = client.whoami(runtime).await.map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(user).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize whoami response: {e}"),
                })?
            }
            OP_DOCS_LIST => {
                let limit = req
                    .input
                    .get("limit")
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|v| u32::try_from(v).ok());
                let page_token = req.input.get("page_token").and_then(|v| v.as_str());
                let query = req.input.get("query").and_then(|v| v.as_str());
                let mut resp = client
                    .list_docs(
                        runtime,
                        Some(&config.workspace_id),
                        limit,
                        page_token,
                        query,
                    )
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                if !config.allowed_doc_ids.is_empty() {
                    resp.items.retain(|doc| {
                        config
                            .allowed_doc_ids
                            .iter()
                            .any(|allowed| allowed == &doc.id)
                    });
                }
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize docs: {e}"),
                })?
            }
            OP_DOCS_GET => {
                let doc_id = require_str(&req.input, "doc_id")?;
                let doc = self.scoped_doc(runtime, client, config, doc_id).await?;
                serde_json::to_value(doc).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize doc: {e}"),
                })?
            }
            OP_PAGES_LIST => {
                let doc_id = require_str(&req.input, "doc_id")?;
                self.scoped_doc(runtime, client, config, doc_id).await?;
                let limit = req
                    .input
                    .get("limit")
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|v| u32::try_from(v).ok());
                let page_token = req.input.get("page_token").and_then(|v| v.as_str());
                let resp = client
                    .list_pages(runtime, doc_id, limit, page_token)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize pages: {e}"),
                })?
            }
            OP_PAGES_GET => {
                let doc_id = require_str(&req.input, "doc_id")?;
                let page_id_or_name = require_str(&req.input, "page_id_or_name")?;
                self.scoped_doc(runtime, client, config, doc_id).await?;
                let resp = client
                    .get_page(runtime, doc_id, page_id_or_name)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize page: {e}"),
                })?
            }
            OP_TABLES_LIST => {
                let doc_id = require_str(&req.input, "doc_id")?;
                self.scoped_doc(runtime, client, config, doc_id).await?;
                let limit = req
                    .input
                    .get("limit")
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|v| u32::try_from(v).ok());
                let page_token = req.input.get("page_token").and_then(|v| v.as_str());
                let resp = client
                    .list_tables(runtime, doc_id, limit, page_token)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize tables: {e}"),
                })?
            }
            OP_TABLES_GET => {
                let doc_id = require_str(&req.input, "doc_id")?;
                let table_id_or_name = require_str(&req.input, "table_id_or_name")?;
                self.scoped_doc(runtime, client, config, doc_id).await?;
                let resp = client
                    .get_table(runtime, doc_id, table_id_or_name)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize table: {e}"),
                })?
            }
            OP_COLUMNS_LIST => {
                let doc_id = require_str(&req.input, "doc_id")?;
                let table_id_or_name = require_str(&req.input, "table_id_or_name")?;
                self.scoped_doc(runtime, client, config, doc_id).await?;
                let limit = req
                    .input
                    .get("limit")
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|v| u32::try_from(v).ok());
                let page_token = req.input.get("page_token").and_then(|v| v.as_str());
                let resp = client
                    .list_columns(runtime, doc_id, table_id_or_name, limit, page_token)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize columns: {e}"),
                })?
            }
            OP_ROWS_LIST => {
                let doc_id = require_str(&req.input, "doc_id")?;
                let table_id = require_str(&req.input, "table_id_or_name")?;
                self.scoped_doc(runtime, client, config, doc_id).await?;
                let limit = req
                    .input
                    .get("limit")
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|v| u32::try_from(v).ok());
                let page_token = req.input.get("page_token").and_then(|v| v.as_str());
                let query = req.input.get("query").and_then(|v| v.as_str());
                let resp = client
                    .list_rows(runtime, doc_id, table_id, limit, page_token, query)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize rows: {e}"),
                })?
            }
            OP_ROWS_GET => {
                let doc_id = require_str(&req.input, "doc_id")?;
                let table_id = require_str(&req.input, "table_id_or_name")?;
                let row_id = require_str(&req.input, "row_id_or_name")?;
                self.scoped_doc(runtime, client, config, doc_id).await?;
                let resp = client
                    .get_row(runtime, doc_id, table_id, row_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize row: {e}"),
                })?
            }
            OP_ROWS_UPSERT => {
                let doc_id = require_str(&req.input, "doc_id")?;
                let table_id = require_str(&req.input, "table_id_or_name")?;
                self.scoped_doc(runtime, client, config, doc_id).await?;
                let rows = req.input.get("rows").ok_or_else(|| FcpError::InvalidRequest {
                    code: 1005,
                    message: "Missing 'rows' field".into(),
                })?;

                let key_columns = req.input.get("key_columns");
                let mut body = json!({ "rows": rows });
                if let Some(kc) = key_columns {
                    body["keyColumns"] = kc.clone();
                }

                let queued = client
                    .upsert_rows(runtime, doc_id, table_id, &body)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                let mutation = self
                    .wait_for_mutation(runtime, client, config, &queued.request_id)
                    .await?;
                serde_json::to_value(json!({
                    "queued": queued,
                    "mutation": mutation,
                }))
                .map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize upsert response: {e}"),
                })?
            }
            OP_ROWS_DELETE => {
                let doc_id = require_str(&req.input, "doc_id")?;
                let table_id = require_str(&req.input, "table_id_or_name")?;
                self.scoped_doc(runtime, client, config, doc_id).await?;
                let row_ids: Vec<String> = req
                    .input
                    .get("row_ids")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing or invalid 'row_ids' field".into(),
                    })?;

                let queued = client
                    .delete_rows(runtime, doc_id, table_id, &row_ids)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                let mutation = self
                    .wait_for_mutation(runtime, client, config, &queued.request_id)
                    .await?;
                serde_json::to_value(json!({
                    "queued": queued,
                    "mutation": mutation,
                }))
                .map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize delete response: {e}"),
                })?
            }
            OP_FORMULAS_LIST => {
                let doc_id = require_str(&req.input, "doc_id")?;
                self.scoped_doc(runtime, client, config, doc_id).await?;
                let limit = req
                    .input
                    .get("limit")
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|v| u32::try_from(v).ok());
                let page_token = req.input.get("page_token").and_then(|v| v.as_str());
                let resp = client
                    .list_formulas(runtime, doc_id, limit, page_token)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize formulas: {e}"),
                })?
            }
            OP_FORMULAS_GET => {
                let doc_id = require_str(&req.input, "doc_id")?;
                let formula_id_or_name = require_str(&req.input, "formula_id_or_name")?;
                self.scoped_doc(runtime, client, config, doc_id).await?;
                let resp = client
                    .get_formula(runtime, doc_id, formula_id_or_name)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize formula: {e}"),
                })?
            }
            OP_CONTROLS_LIST => {
                let doc_id = require_str(&req.input, "doc_id")?;
                self.scoped_doc(runtime, client, config, doc_id).await?;
                let limit = req
                    .input
                    .get("limit")
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|v| u32::try_from(v).ok());
                let page_token = req.input.get("page_token").and_then(|v| v.as_str());
                let resp = client
                    .list_controls(runtime, doc_id, limit, page_token)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize controls: {e}"),
                })?
            }
            OP_CONTROLS_GET => {
                let doc_id = require_str(&req.input, "doc_id")?;
                let control_id_or_name = require_str(&req.input, "control_id_or_name")?;
                self.scoped_doc(runtime, client, config, doc_id).await?;
                let resp = client
                    .get_control(runtime, doc_id, control_id_or_name)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize control: {e}"),
                })?
            }
            OP_MUTATIONS_GET_STATUS => {
                let request_id = require_str(&req.input, "request_id")?;
                let resp = client
                    .get_mutation_status(runtime, request_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize mutation status: {e}"),
                })?
            }
            OP_HEALTH => {
                let whoami = client
                    .health_check(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({
                    "status": "ok",
                    "workspace_match": whoami.workspace.id == config.workspace_id,
                    "whoami": whoami,
                })
            }
            _ => unreachable!("unknown operation already handled"),
        };

        Ok(InvokeResponse::ok(req.id, output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> serde_json::Value {
        json!({
            "workspace_id": "ws-123",
            "api_token": "tok",
        })
    }

    fn base_handshake() -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [0u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_ACCOUNT_READ),
                CapabilityId::from_static(CAP_DOCS_READ),
                CapabilityId::from_static(CAP_TABLES_READ),
                CapabilityId::from_static(CAP_ROWS_READ),
                CapabilityId::from_static(CAP_ROWS_WRITE),
                CapabilityId::from_static(CAP_FORMULAS_READ),
                CapabilityId::from_static(CAP_CONTROLS_READ),
                CapabilityId::from_static(CAP_MUTATIONS_READ),
            ],
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

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = CodaConnector::new();
        let result = connector.handshake(base_handshake()).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_valid() {
        let mut connector = CodaConnector::new();
        let result = connector.configure(test_config()).await;
        assert!(result.is_ok());
        assert!(connector.config.is_some());
        assert!(connector.client.is_some());
        assert!(connector.runtime.is_some());
        assert!(connector.verifier.is_none());
        assert!(!connector.base.handshaken.load(Ordering::Acquire));
    }

    #[fcp_async_core::runtime::test]
    async fn test_reconfigure_clears_handshake_state() {
        let mut connector = CodaConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        assert!(connector.base.handshaken.load(Ordering::Acquire));
        assert!(connector.verifier.is_some());

        connector.configure(test_config()).await.unwrap();
        assert!(!connector.base.handshaken.load(Ordering::Acquire));
        assert!(connector.verifier.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_missing_fields() {
        let mut connector = CodaConnector::new();
        let result = connector.configure(json!({})).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_non_coda_host() {
        let mut connector = CodaConnector::new();
        let result = connector
            .configure(json!({
                "workspace_id": "ws-123",
                "api_token": "tok",
                "base_url": "https://example.com/apis/v1"
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_accepts_localhost_http_for_tests() {
        let mut connector = CodaConnector::new();
        let result = connector
            .configure(json!({
                "workspace_id": "ws-123",
                "api_token": "tok",
                "base_url": "http://127.0.0.1:9999"
            }))
            .await;
        assert!(result.is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_after_configure() {
        let mut connector = CodaConnector::new();
        connector.configure(test_config()).await.unwrap();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Ready));
        assert!(
            health
                .details
                .as_ref()
                .and_then(|details| details.get("verification_script"))
                .is_some()
        );
    }

    #[test]
    fn test_doctor_before_configure() {
        let connector = CodaConnector::new();
        let report = connector.doctor();
        assert!(!report.ready);
        assert!(!report.passed);
        assert_eq!(report.verification_script, VERIFICATION_SCRIPT_PATH);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_after_configure() {
        let mut connector = CodaConnector::new();
        connector.configure(test_config()).await.unwrap();
        let report = connector.doctor();
        assert!(report.ready);
        assert!(report.passed);
        assert!(report.provisioning.is_some());
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.name == "network_constraints")
        );
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.name == "auth_boundary")
        );
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.name == "service_inventory")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_before_configure() {
        let connector = CodaConnector::new();
        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
        assert!(
            report
                .details
                .as_ref()
                .and_then(|details| details.get("verification_script"))
                .is_some()
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_shutdown_clears_runtime_state() {
        let mut connector = CodaConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();

        connector
            .shutdown(ShutdownRequest {
                r#type: "shutdown".into(),
                deadline_ms: 1_000,
                drain: false,
                reason: Some("test".into()),
            })
            .await
            .unwrap();

        assert!(connector.config.is_none());
        assert!(connector.client.is_none());
        assert!(connector.runtime.is_none());
        assert!(connector.verifier.is_none());
        assert!(!connector.base.configured.load(Ordering::Acquire));
        assert!(!connector.base.handshaken.load(Ordering::Acquire));
        assert!(matches!(
            connector.health().await.status,
            HealthState::Degraded { .. }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate() {
        let connector = CodaConnector::new();
        let req = SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(OP_DOCS_LIST),
            ZoneId::work(),
            json!({}),
            CapabilityToken::test_token(),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(resp.would_succeed);
    }

    #[test]
    fn test_introspection_operations() {
        let connector = CodaConnector::new();
        let intro = connector.introspect();
        assert_eq!(intro.operations.len(), 18);
        for op_id in &[
            OP_ACCOUNT_WHOAMI,
            OP_DOCS_LIST,
            OP_DOCS_GET,
            OP_PAGES_LIST,
            OP_PAGES_GET,
            OP_TABLES_LIST,
            OP_TABLES_GET,
            OP_COLUMNS_LIST,
            OP_ROWS_LIST,
            OP_ROWS_GET,
            OP_ROWS_UPSERT,
            OP_ROWS_DELETE,
            OP_FORMULAS_LIST,
            OP_FORMULAS_GET,
            OP_CONTROLS_LIST,
            OP_CONTROLS_GET,
            OP_MUTATIONS_GET_STATUS,
            OP_HEALTH,
        ] {
            assert!(
                intro.operations.iter().any(|op| op.id.as_str() == *op_id),
                "Missing operation: {op_id}"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_unknown_operation() {
        let mut connector = CodaConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), "coda.nonexistent");
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_configure() {
        let connector = CodaConnector::new();
        let req = base_invoke(connector.id(), OP_DOCS_LIST);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_docs_get_missing_id() {
        let mut connector = CodaConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_DOCS_GET);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_pages_get_missing_page_id() {
        let mut connector = CodaConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let mut req = base_invoke(connector.id(), OP_PAGES_GET);
        req.input = json!({"doc_id":"doc-123"});
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_pages_list_missing_doc_id() {
        let mut connector = CodaConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_PAGES_LIST);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_tables_list_missing_doc_id() {
        let mut connector = CodaConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_TABLES_LIST);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_rows_list_missing_fields() {
        let mut connector = CodaConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_ROWS_LIST);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_rows_get_missing_fields() {
        let mut connector = CodaConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_ROWS_GET);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_rows_upsert_missing_fields() {
        let mut connector = CodaConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_ROWS_UPSERT);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_rows_delete_missing_fields() {
        let mut connector = CodaConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_ROWS_DELETE);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_operations_info_count() {
        let ops = operations_info();
        assert_eq!(ops.len(), 18);
    }

    #[test]
    fn test_operations_have_ai_hints() {
        let ops = operations_info();
        for op in &ops {
            assert!(!op.ai_hints.when_to_use.is_empty());
        }
    }

    #[test]
    fn test_account_whoami_is_safe() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_ACCOUNT_WHOAMI)
            .unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Safe);
        assert_eq!(op.risk_level, RiskLevel::Low);
    }

    #[test]
    fn test_rows_upsert_is_risky_best_effort() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_ROWS_UPSERT)
            .unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Risky);
        assert_eq!(op.idempotency, IdempotencyClass::BestEffort);
        assert_eq!(op.requires_approval, Some(ApprovalMode::Interactive));
    }

    #[test]
    fn test_rows_delete_is_dangerous() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_ROWS_DELETE)
            .unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Dangerous);
        assert_eq!(op.risk_level, RiskLevel::High);
        assert_eq!(op.requires_approval, Some(ApprovalMode::Interactive));
    }

    #[test]
    fn test_read_operations_are_strict() {
        let ops = operations_info();
        for op in ops {
            if !matches!(op.id.as_str(), OP_ROWS_UPSERT) && op.safety_tier == SafetyTier::Safe {
                assert_eq!(op.idempotency, IdempotencyClass::Strict, "{}", op.id);
            }
        }
    }

    #[test]
    fn test_manifest_hash_deterministic() {
        let hash1 = CodaConnector::manifest_hash();
        let hash2 = CodaConnector::manifest_hash();
        assert_eq!(hash1, hash2);
        assert!(hash1.starts_with("sha256:"));
    }

    #[test]
    fn test_streaming_not_supported() {
        let connector = CodaConnector::new();
        let intro = connector.introspect();
        assert!(!intro.event_caps.as_ref().unwrap().streaming);
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_before_handshake_returns_not_handshaken() {
        let mut connector = CodaConnector::new();
        connector.configure(test_config()).await.unwrap();
        let result = connector
            .invoke(base_invoke(connector.id(), OP_DOCS_LIST))
            .await;
        assert!(matches!(result, Err(FcpError::NotHandshaken)));
    }

    #[test]
    fn debug_redacts_config_secrets() {
        let config = CodaConfig {
            base_url: default_base_url(),
            workspace_id: "ws-123".into(),
            allowed_doc_ids: vec!["doc-1".into()],
            api_token: "super_secret_token".into(),
            retry: HttpRetryConfig::default(),
            request_timeout_ms: default_request_timeout_ms(),
            mutation_poll_interval_ms: default_mutation_poll_interval_ms(),
            mutation_deadline_ms: default_mutation_deadline_ms(),
        };
        let debug_output = format!("{config:?}");
        assert!(
            !debug_output.contains("super_secret_token"),
            "Debug output must not contain the raw api_token"
        );
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug output should show [REDACTED] for sensitive fields"
        );
    }

    #[test]
    fn test_health_operation_is_safe() {
        let ops = operations_info();
        let op = ops.iter().find(|op| op.id.as_str() == OP_HEALTH).unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Safe);
        assert_eq!(op.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn test_connector_default() {
        let connector = CodaConnector::default();
        assert_eq!(connector.id().as_str(), "fcp.coda");
    }

    #[test]
    fn test_capability_mapping() {
        let ops = operations_info();
        for op in &ops {
            let cap_str = op.capability.as_str();
            assert!(
                cap_str.starts_with("coda."),
                "Capability {cap_str} should start with 'coda.'"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_custom_base_url() {
        let mut connector = CodaConnector::new();
        let config = json!({
            "workspace_id": "ws-123",
            "api_token": "tok",
            "base_url": "https://localhost/apis/v1"
        });
        let result = connector.configure(config).await;
        assert!(result.is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_custom_timeout() {
        let mut connector = CodaConnector::new();
        let config = json!({
            "workspace_id": "ws-123",
            "api_token": "tok",
            "request_timeout_ms": 60000
        });
        let result = connector.configure(config).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_formulas_list_capability() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_FORMULAS_LIST)
            .unwrap();
        assert_eq!(op.capability, CapabilityId::from_static(CAP_FORMULAS_READ));
    }

    #[test]
    fn test_tables_list_capability() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_TABLES_LIST)
            .unwrap();
        assert_eq!(op.capability, CapabilityId::from_static(CAP_TABLES_READ));
    }

    #[test]
    fn test_rows_list_capability() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_ROWS_LIST)
            .unwrap();
        assert_eq!(op.capability, CapabilityId::from_static(CAP_ROWS_READ));
    }

    #[test]
    fn test_controls_list_capability() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_CONTROLS_LIST)
            .unwrap();
        assert_eq!(op.capability, CapabilityId::from_static(CAP_CONTROLS_READ));
    }
}
