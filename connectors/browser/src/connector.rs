//! FCP Browser Connector implementation.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

use fcp_manifest::{ConnectorManifest, ManifestApprovalMode, OperationSection};
use fcp_prelude::ApprovalScope::Execution;
use fcp_prelude::{
    ApprovalMode, ApprovalToken, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken,
    CapabilityVerifier, ConnectorId, CredentialId, EventCaps, FcpError, FcpResult,
    HandshakeRequest, HandshakeResponse, Introspection, OperationId, OperationInfo,
    SelfCheckReport, SessionId, SimulateRequest, SimulateResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::{info, instrument};

use crate::{
    client::{
        BrowserAuth, BrowserClient, BrowserLauncherConfig, BrowserLauncherMode,
        DEFAULT_BROWSER_URL, browser_control_contract_descriptor,
    },
    error::BrowserError,
    types::{Cookie, ProxyConfig},
};

#[derive(Debug, Clone)]
struct ExecutionApprovalContext {
    token_id: String,
}

/// Validated configuration for the Browser connector.
struct BrowserConfig {
    auth: BrowserAuth,
    browser_url: String,
    rust_owned_launcher: Option<BrowserLauncherConfig>,
}

const BROWSER_CONTROL_HOST_ALLOWLIST: &[&str] = &[
    "localhost",
    "127.0.0.1",
    "::1",
    "*.browser.mesh.internal",
    "*.browser.flywheel.internal",
];

const BROWSER_SANDBOX_PROFILE: &str = "strict";
const BROWSER_SANDBOX_MEMORY_MB: u32 = 1024;
const BROWSER_SANDBOX_CPU_PERCENT: u8 = 75;
const BROWSER_SANDBOX_WALL_CLOCK_TIMEOUT_MS: u64 = 300_000;
const BROWSER_SANDBOX_DENY_EXEC: bool = true;
const BROWSER_SANDBOX_DENY_PTRACE: bool = true;
const READABLE_CONTENT_DEFAULT_MAX_CHARS: usize = 200_000;
const READABLE_CONTENT_ABSOLUTE_MAX_CHARS: usize = 1_000_000;
const DOCUMENT_TEXT_EXTRACTION_CAP_CHARS: usize = 200_000;
const DOCUMENT_RENDER_PIXEL_CAP: usize = 4_000_000;
const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const OPERATION_ORDER: &[&str] = &[
    "browser.navigate",
    "browser.screenshot",
    "browser.render_pdf",
    "browser.extract_text",
    "browser.extract_links",
    "browser.wait_for_selector",
    "browser.click",
    "browser.fill_form",
    "browser.evaluate_js",
    "browser.get_cookies",
    "browser.set_cookies",
    "browser.session.save",
    "browser.session.restore",
    "browser.session.describe",
    "browser.set_proxy",
    "browser.clear_proxy",
];

#[derive(Debug, Clone, Serialize)]
struct BrowserNetworkGuardProfile {
    allowed_host_patterns: &'static [&'static str],
    require_https_for_non_loopback: bool,
    allow_http_for_loopback: bool,
}

#[derive(Debug, Clone, Serialize)]
struct BrowserExecutionPlannerProfile {
    memory_mb: u32,
    cpu_percent: u8,
    wall_clock_timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
struct BrowserPlacementProfile {
    sandbox_profile: &'static str,
    sandbox_deny_exec: bool,
    sandbox_deny_ptrace: bool,
    network_guard: BrowserNetworkGuardProfile,
    execution_planner: BrowserExecutionPlannerProfile,
}

impl BrowserConfig {
    /// Parse and validate configuration from FCP params.
    ///
    /// Browser auth is optional: no auth, `api_key`, or `credential_id`.
    /// Cannot supply both `api_key` and `credential_id`.
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let api_key = params
            .get("api_key")
            .and_then(|v| v.as_str())
            .map(String::from);
        let credential_id = match params.get("credential_id") {
            Some(value) => {
                let raw = value.as_str().ok_or(FcpError::InvalidRequest {
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
            (Some(key), None) => BrowserAuth::ApiKey(key),
            (None, Some(cid)) => BrowserAuth::CredentialId(cid),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Supply at most one of `api_key` or `credential_id`, not both".into(),
                });
            }
            (None, None) => BrowserAuth::None,
        };

        let browser_url = params
            .get("browser_url")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_BROWSER_URL)
            .to_string();
        validate_browser_control_endpoint_url(&browser_url)?;
        let rust_owned_launcher = parse_rust_owned_launcher_config(params)?;

        Ok(Self {
            auth,
            browser_url,
            rust_owned_launcher,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BrowserSessionStatePayload {
    schema_version: u32,
    captured_at: u64,
    domain: Option<String>,
    cookies: Vec<Cookie>,
}

#[derive(Debug, Clone)]
struct BrowserSessionStateObjectRecord {
    state_object_id: String,
    prev_state_object_id: Option<String>,
    seq: u64,
    lease_seq: u64,
    lease_object_id: String,
    payload_cbor: Vec<u8>,
    payload: BrowserSessionStatePayload,
}

#[derive(Debug, Default)]
struct BrowserSessionMeshStore {
    head_state_object_id: Option<String>,
    objects: BTreeMap<String, BrowserSessionStateObjectRecord>,
    last_seq: u64,
    last_lease_seq: u64,
}

/// Structured readiness diagnostic for the doctor command.
#[derive(Debug, Serialize, Deserialize)]
struct DoctorResult {
    status: DoctorStatus,
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DoctorCheck {
    name: String,
    status: DoctorStatus,
    message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum DoctorStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// FCP Browser Connector.
pub struct BrowserConnector {
    base: Arc<BaseConnector>,
    config: Option<BrowserConfig>,
    client: Option<BrowserClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
    session_store: Mutex<BrowserSessionMeshStore>,
}

impl BrowserConnector {
    /// Create a new Browser connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("fcp.browser"))),
            config: None,
            client: None,
            verifier: None,
            session_id: None,
            session_store: Mutex::new(BrowserSessionMeshStore::default()),
        }
    }

    /// Connector instance ID used for bound capability-token verification.
    #[must_use]
    pub fn instance_id(&self) -> &str {
        self.base.instance_id.as_str()
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    /// Handle configure method.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = BrowserConfig::from_params(&params)?;

        let mut client = BrowserClient::new_with_auth(config.auth.clone())
            .map_err(|e| FcpError::Internal {
                message: format!("Failed to create HTTP client: {e}"),
            })?
            .with_browser_url(&config.browser_url)
            .continue_direct_cdp_manager_from(self.client.as_ref());
        if let Some(launcher_config) = config.rust_owned_launcher.clone() {
            client = client
                .with_rust_owned_launcher(launcher_config)
                .map_err(|e| FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid rust_owned_launcher config: {e}"),
                })?;
        }

        info!(auth = %config.auth.redacted_label(), "Browser connector configured");

        self.config = Some(config);
        self.client = Some(client);
        self.base.set_configured(true);

        Ok(json!({ "status": "configured" }))
    }

    /// Handle handshake method.
    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid handshake request: {e}"),
            })?;

        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let session_id = SessionId::new();
        self.session_id = Some(session_id.clone());
        self.base.set_handshaken(true);

        let capabilities_granted: Vec<CapabilityGrant> = req
            .capabilities_requested
            .into_iter()
            .map(|cap| CapabilityGrant {
                capability: cap,
                operation: None,
            })
            .collect();

        let response = HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id,
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
        };

        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    /// Handle health check.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.client.is_some();
        let metrics = self.base.metrics();
        let placement_profile =
            serde_json::to_value(browser_placement_profile()).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize browser placement profile: {e}"),
            })?;
        let mut health = json!({
            "status": if configured { "healthy" } else { "not_configured" },
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            },
            "placement_profile": placement_profile,
            "browser_control_contract": browser_control_contract_descriptor(),
        });
        if let Some(config) = &self.config {
            let (allowlisted, host) = match reqwest::Url::parse(&config.browser_url) {
                Ok(url) => {
                    let host = url.host_str().unwrap_or("unknown");
                    (is_browser_control_host_allowlisted(host), host.to_string())
                }
                Err(_) => (false, "invalid".to_string()),
            };
            health["auth_mode"] = json!(config.auth.redacted_label());
            health["browser_url"] = json!(config.browser_url);
            health["network_guard"] = json!({
                "control_plane_host": host,
                "allowlisted": allowlisted,
            });
        }
        if let Some(client) = &self.client {
            if let Some(descriptor) =
                client
                    .rust_owned_launcher_descriptor()
                    .map_err(|e| FcpError::Internal {
                        message: format!("Failed to inspect rust-owned launcher: {e}"),
                    })?
            {
                health["rust_owned_launcher"] = descriptor;
            }
        }
        Ok(health)
    }

    /// Handle doctor readiness check.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();

        // 1. Configuration
        checks.push(if self.config.is_some() {
            DoctorCheck {
                name: "configuration".into(),
                status: DoctorStatus::Healthy,
                message: "Connector is configured".into(),
            }
        } else {
            DoctorCheck {
                name: "configuration".into(),
                status: DoctorStatus::Unhealthy,
                message: "Connector is not configured – call `configure` first".into(),
            }
        });

        // 2. Client initialized
        checks.push(if self.client.is_some() {
            DoctorCheck {
                name: "client_initialized".into(),
                status: DoctorStatus::Healthy,
                message: "HTTP client is ready".into(),
            }
        } else {
            DoctorCheck {
                name: "client_initialized".into(),
                status: DoctorStatus::Unhealthy,
                message: "HTTP client is not initialized".into(),
            }
        });

        // 3. Browser URL
        if let Some(config) = &self.config {
            checks.push(DoctorCheck {
                name: "base_url".into(),
                status: DoctorStatus::Healthy,
                message: format!("Browser URL: {}", config.browser_url),
            });
        } else {
            checks.push(DoctorCheck {
                name: "base_url".into(),
                status: DoctorStatus::Unhealthy,
                message: "Browser URL not set (not configured)".into(),
            });
        }

        // 4. Auth mode
        if let Some(config) = &self.config {
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                status: DoctorStatus::Healthy,
                message: format!("Auth: {}", config.auth.redacted_label()),
            });
        } else {
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                status: DoctorStatus::Unhealthy,
                message: "Auth mode not set (not configured)".into(),
            });
        }

        // 5. Network guard constraints
        if let Some(config) = &self.config {
            let network_guard_check = match reqwest::Url::parse(&config.browser_url) {
                Ok(url) => match url.host_str() {
                    Some(host) => {
                        let allowlisted = is_browser_control_host_allowlisted(host);
                        let https_or_loopback = url.scheme() == "https" || is_loopback_host(host);
                        if allowlisted && https_or_loopback {
                            DoctorCheck {
                                name: "network_constraints".into(),
                                status: DoctorStatus::Healthy,
                                message: format!(
                                    "Network guard allowlist satisfied for control host '{host}'"
                                ),
                            }
                        } else {
                            DoctorCheck {
                                name: "network_constraints".into(),
                                status: DoctorStatus::Unhealthy,
                                message: format!(
                                    "Control host '{host}' violates allowlist or HTTPS policy"
                                ),
                            }
                        }
                    }
                    None => DoctorCheck {
                        name: "network_constraints".into(),
                        status: DoctorStatus::Unhealthy,
                        message: "Browser URL is missing a host".into(),
                    },
                },
                Err(err) => DoctorCheck {
                    name: "network_constraints".into(),
                    status: DoctorStatus::Unhealthy,
                    message: format!("Invalid browser URL for network guard checks: {err}"),
                },
            };
            checks.push(network_guard_check);
        } else {
            checks.push(DoctorCheck {
                name: "network_constraints".into(),
                status: DoctorStatus::Unhealthy,
                message: "Cannot assess – not configured".into(),
            });
        }

        // 6. Sandbox profile
        let placement_profile = browser_placement_profile();
        checks.push(DoctorCheck {
            name: "sandbox_profile".into(),
            status: if placement_profile.sandbox_profile == "strict"
                && placement_profile.sandbox_deny_exec
                && placement_profile.sandbox_deny_ptrace
            {
                DoctorStatus::Healthy
            } else {
                DoctorStatus::Unhealthy
            },
            message: format!(
                "profile={}, deny_exec={}, deny_ptrace={}",
                placement_profile.sandbox_profile,
                placement_profile.sandbox_deny_exec,
                placement_profile.sandbox_deny_ptrace
            ),
        });

        // 7. Execution planner requirements
        let planner = placement_profile.execution_planner;
        checks.push(DoctorCheck {
            name: "execution_planner_resources".into(),
            status: if planner.memory_mb > 0
                && planner.cpu_percent > 0
                && planner.wall_clock_timeout_ms > 0
            {
                DoctorStatus::Healthy
            } else {
                DoctorStatus::Unhealthy
            },
            message: format!(
                "memory_mb={}, cpu_percent={}, wall_clock_timeout_ms={}",
                planner.memory_mb, planner.cpu_percent, planner.wall_clock_timeout_ms
            ),
        });

        // 8. Credential injection
        if let Some(config) = &self.config {
            if config.auth.is_secretless() {
                checks.push(DoctorCheck {
                    name: "credential_injection".into(),
                    status: DoctorStatus::Healthy,
                    message: "Secretless mode – egress proxy will inject credentials".into(),
                });
            } else {
                checks.push(DoctorCheck {
                    name: "credential_injection".into(),
                    status: DoctorStatus::Healthy,
                    message: "Direct auth mode – no proxy injection needed".into(),
                });
            }
        } else {
            checks.push(DoctorCheck {
                name: "credential_injection".into(),
                status: DoctorStatus::Unhealthy,
                message: "Cannot assess – not configured".into(),
            });
        }

        let overall = if checks.iter().any(|c| c.status == DoctorStatus::Unhealthy) {
            DoctorStatus::Unhealthy
        } else if checks.iter().any(|c| c.status == DoctorStatus::Degraded) {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };

        let result = DoctorResult {
            status: overall,
            checks,
        };

        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize doctor result: {e}"),
        })
    }

    /// Handle self-check connectivity probe.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(client) = &self.client else {
            let report =
                SelfCheckReport::failed("not_configured", "Connector is not configured yet");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        // In credential_id mode, we can't verify connectivity without the egress proxy
        if let Some(config) = &self.config {
            if config.auth.is_secretless() {
                let report = SelfCheckReport::degraded(
                    "credential_injection_required",
                    "Configured with credential_id; egress proxy injection required for checks",
                );
                return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize self-check report: {e}"),
                });
            }
        }

        let report = match client.health_check().await {
            Ok(()) => SelfCheckReport::ok(),
            Err(err) => {
                if err.is_retryable() {
                    SelfCheckReport::degraded("self_check_retryable", err.to_string())
                } else {
                    SelfCheckReport::failed("self_check_failed", err.to_string())
                }
            }
        };

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }

    /// Handle introspect method.
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

    /// Handle simulate method.
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let req: SimulateRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid simulate request: {e}"),
            })?;

        let response = SimulateResponse::allowed(req.id);
        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    /// Handle invoke method.
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let result = self.handle_invoke_internal(params).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn handle_invoke_internal(
        &self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let operation =
            params
                .get("operation")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing operation".into(),
                })?;

        let input = params.get("input").cloned().unwrap_or(json!({}));

        let token_value = params
            .get("capability_token")
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing capability_token".into(),
            })?;

        let token: CapabilityToken =
            serde_json::from_value(token_value.clone()).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid capability_token format: {e}"),
            })?;

        let op_id: OperationId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid operation ID format".into(),
        })?;
        let intro = self.handle_introspect().await?;
        let cap_str = intro
            .get("operations")
            .and_then(|ops| ops.as_array())
            .and_then(|ops| {
                ops.iter()
                    .find(|o| o.get("id").and_then(|id| id.as_str()) == Some(operation))
            })
            .and_then(|op| op.get("capability"))
            .and_then(|cap| cap.as_str())
            .ok_or_else(|| FcpError::OperationNotGranted {
                operation: operation.into(),
            })?;

        let cap_id: CapabilityId = cap_str.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid capability ID format".into(),
        })?;

        if let Some(verifier) = &self.verifier {
            // dja9u.1.a: verify_bound returns CapabilityToken<BoundVerified>;
            // discarded here because invoke has no downstream that consumes
            // the typestate yet, but the call enforces the typestate handoff.
            let _bound = verifier.verify_bound(token, &cap_id, &op_id, &[])?;
        } else {
            return Err(FcpError::NotConfigured);
        }

        let execution_approval = Self::require_execution_approval(operation, &input, &params)?;

        match operation {
            "browser.navigate" => self.invoke_navigate(input).await,
            "browser.screenshot" => self.invoke_screenshot(input).await,
            "browser.render_pdf" => self.invoke_render_pdf(input).await,
            "browser.extract_text" => self.invoke_extract_text(input).await,
            "browser.extract_links" => self.invoke_extract_links(input).await,
            "browser.wait_for_selector" => self.invoke_wait_for_selector(input).await,
            "browser.click" => self.invoke_click(input).await,
            "browser.fill_form" => {
                self.invoke_fill_form(input, execution_approval.as_ref())
                    .await
            }
            "browser.evaluate_js" => {
                self.invoke_evaluate_js(input, execution_approval.as_ref())
                    .await
            }
            "browser.get_cookies" => {
                self.invoke_get_cookies(input, execution_approval.as_ref())
                    .await
            }
            "browser.set_cookies" => {
                self.invoke_set_cookies(input, execution_approval.as_ref())
                    .await
            }
            "browser.session.save" => {
                self.invoke_session_save(input, execution_approval.as_ref())
                    .await
            }
            "browser.session.restore" => {
                self.invoke_session_restore(input, execution_approval.as_ref())
                    .await
            }
            "browser.session.describe" => self.invoke_session_describe(input).await,
            "browser.set_proxy" => {
                self.invoke_set_proxy(input, execution_approval.as_ref())
                    .await
            }
            "browser.clear_proxy" => {
                self.invoke_clear_proxy(input, execution_approval.as_ref())
                    .await
            }
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    fn require_execution_approval(
        operation: &str,
        input: &serde_json::Value,
        params: &serde_json::Value,
    ) -> FcpResult<Option<ExecutionApprovalContext>> {
        if !requires_execution_approval(operation) {
            return Ok(None);
        }

        let approval_value = params
            .get("approval_token")
            .ok_or(FcpError::CapabilityDenied {
                capability: operation.to_string(),
                reason: format!(
                    "Operation '{operation}' requires an ApprovalToken with execution scope"
                ),
            })?;

        let approval: ApprovalToken =
            serde_json::from_value(approval_value.clone()).map_err(|e| {
                FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid approval_token format: {e}"),
                }
            })?;

        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        if !approval.is_valid(now_ms) {
            return Err(FcpError::CapabilityDenied {
                capability: operation.to_string(),
                reason: "approval_token is expired or not yet valid".into(),
            });
        }

        let Execution(scope) = &approval.scope else {
            return Err(FcpError::CapabilityDenied {
                capability: operation.to_string(),
                reason: "approval_token must use execution scope".into(),
            });
        };

        if scope.connector_id != "fcp.browser" {
            return Err(FcpError::CapabilityDenied {
                capability: operation.to_string(),
                reason: "approval_token connector_id does not match fcp.browser".into(),
            });
        }

        if !operation_pattern_matches(&scope.method_pattern, operation) {
            return Err(FcpError::CapabilityDenied {
                capability: operation.to_string(),
                reason: "approval_token execution scope does not allow this operation".into(),
            });
        }

        if scope.request_object_id.is_some() || scope.input_hash.is_some() {
            return Err(FcpError::CapabilityDenied {
                capability: operation.to_string(),
                reason: "approval_token binds request_object_id/input_hash, unsupported in direct connector invocation".into(),
            });
        }

        if !scope.input_constraints.is_empty()
            && !scope
                .input_constraints
                .iter()
                .all(|constraint| input.pointer(&constraint.pointer) == Some(&constraint.expected))
        {
            return Err(FcpError::CapabilityDenied {
                capability: operation.to_string(),
                reason: "approval_token input constraints do not match this invocation".into(),
            });
        }

        Ok(Some(ExecutionApprovalContext {
            token_id: approval.token_id,
        }))
    }

    // -- Operation implementations --

    async fn invoke_navigate(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let url = require_str(&input, "url")?;
        let wait_until = input.get("wait_until").and_then(|v| v.as_str());
        let timeout_ms = input.get("timeout_ms").and_then(|v| v.as_u64());
        let user_agent = input.get("user_agent").and_then(|v| v.as_str());
        let result = client
            .navigate(url, wait_until, timeout_ms, user_agent)
            .await
            .map_err(|e: BrowserError| e.to_fcp_error())?;
        Ok(json!({ "url": result.url, "status": result.status, "title": result.title }))
    }

    async fn invoke_screenshot(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let selector = input.get("selector").and_then(|v| v.as_str());
        let full_page = input.get("full_page").and_then(|v| v.as_bool());
        let format = input.get("format").and_then(|v| v.as_str());
        let quality = input
            .get("quality")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let result = client
            .screenshot(selector, full_page, format, quality)
            .await
            .map_err(|e: BrowserError| e.to_fcp_error())?;
        Ok(
            json!({ "image_data": result.image_data, "width": result.width, "height": result.height }),
        )
    }

    async fn invoke_render_pdf(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let format = input.get("format").and_then(|v| v.as_str());
        let landscape = input.get("landscape").and_then(|v| v.as_bool());
        let print_background = input.get("print_background").and_then(|v| v.as_bool());
        let max_pages = parse_optional_u32_field(&input, "max_pages")?;
        let result = client
            .render_pdf(format, landscape, print_background)
            .await
            .map_err(|e: BrowserError| e.to_fcp_error())?;
        if let Some(max_pages) = max_pages
            && result.page_count > max_pages
        {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "Rendered PDF page_count {} exceeds max_pages {max_pages}",
                    result.page_count
                ),
            });
        }
        Ok(json!({
            "pdf_data": result.pdf_data,
            "page_count": result.page_count,
            "external_content": external_content_metadata("rendered_pdf"),
            "document_extraction": document_extraction_deferral_metadata(),
        }))
    }

    async fn invoke_extract_text(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let selector = input.get("selector").and_then(|v| v.as_str());
        let include_hidden = input.get("include_hidden").and_then(|v| v.as_bool());
        let output_mode = parse_readable_output_mode(&input)?;
        let max_chars = parse_readable_max_chars(&input)?;
        let result = client
            .extract_text(selector, include_hidden)
            .await
            .map_err(|e: BrowserError| e.to_fcp_error())?;
        let readable = prepare_readable_content(&result.text, max_chars, output_mode);
        Ok(json!({
            "text": readable.text,
            "word_count": result.word_count,
            "output_mode": readable.output_mode.as_str(),
            "guardrails": readable.guardrails,
            "external_content": external_content_metadata("page_text"),
            "readability": readability_metadata(readable.output_mode),
        }))
    }

    async fn invoke_extract_links(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let selector = input.get("selector").and_then(|v| v.as_str());
        let result = client
            .extract_links(selector)
            .await
            .map_err(|e: BrowserError| e.to_fcp_error())?;
        Ok(json!({ "links": result.links }))
    }

    async fn invoke_wait_for_selector(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let selector = require_str(&input, "selector")?;
        let state = input.get("state").and_then(|v| v.as_str());
        let timeout_ms = input.get("timeout_ms").and_then(|v| v.as_u64());
        let result = client
            .wait_for_selector(selector, state, timeout_ms)
            .await
            .map_err(|e: BrowserError| e.to_fcp_error())?;
        Ok(json!({ "found": result.found }))
    }

    async fn invoke_click(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let selector = require_str(&input, "selector")?;
        let timeout_ms = input.get("timeout_ms").and_then(|v| v.as_u64());
        let result = client
            .click(selector, timeout_ms)
            .await
            .map_err(|e: BrowserError| e.to_fcp_error())?;
        Ok(json!({ "clicked": result.clicked, "navigation_url": result.navigation_url }))
    }

    async fn invoke_fill_form(
        &self,
        input: serde_json::Value,
        execution_approval: Option<&ExecutionApprovalContext>,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let fields = input.get("fields").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing required field: fields".into(),
        })?;
        let submit_selector = input.get("submit_selector").and_then(|v| v.as_str());
        let result = client
            .fill_form(fields, submit_selector)
            .await
            .map_err(|e: BrowserError| e.to_fcp_error())?;
        Ok(json!({
            "filled_count": result.filled_count,
            "submitted": result.submitted,
            "audit": dangerous_operation_audit("browser.fill_form", true, execution_approval),
        }))
    }

    async fn invoke_evaluate_js(
        &self,
        input: serde_json::Value,
        execution_approval: Option<&ExecutionApprovalContext>,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let expression = require_str(&input, "expression")?;
        let result = client
            .evaluate_js(expression)
            .await
            .map_err(|e: BrowserError| e.to_fcp_error())?;
        Ok(json!({
            "result": result.result,
            "audit": dangerous_operation_audit("browser.evaluate_js", true, execution_approval),
        }))
    }

    async fn invoke_get_cookies(
        &self,
        input: serde_json::Value,
        execution_approval: Option<&ExecutionApprovalContext>,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let domain = input.get("domain").and_then(|v| v.as_str());
        let cookies = client
            .get_cookies(domain)
            .await
            .map_err(|e: BrowserError| e.to_fcp_error())?;
        Ok(json!({
            "cookies": cookies,
            "audit": dangerous_operation_audit("browser.get_cookies", false, execution_approval),
        }))
    }

    async fn invoke_set_cookies(
        &self,
        input: serde_json::Value,
        execution_approval: Option<&ExecutionApprovalContext>,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let cookies_value = input.get("cookies").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing required field: cookies".into(),
        })?;
        let cookies: Vec<Cookie> = serde_json::from_value(cookies_value.clone()).map_err(|e| {
            FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid cookies format: {e}"),
            }
        })?;
        let count = client
            .set_cookies(&cookies)
            .await
            .map_err(|e: BrowserError| e.to_fcp_error())?;
        Ok(json!({
            "set_count": count,
            "audit": dangerous_operation_audit("browser.set_cookies", true, execution_approval),
        }))
    }

    async fn invoke_set_proxy(
        &self,
        input: serde_json::Value,
        execution_approval: Option<&ExecutionApprovalContext>,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let server = require_str(&input, "server")?;
        let bypass_list = input
            .get("bypass_list")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .map(|v| {
                        v.as_str().ok_or(FcpError::InvalidRequest {
                            code: 1003,
                            message: "bypass_list values must be strings".into(),
                        })
                    })
                    .collect::<FcpResult<Vec<_>>>()
                    .map(|entries| entries.into_iter().map(str::to_string).collect::<Vec<_>>())
            })
            .transpose()?;
        let username = input
            .get("username")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let password = input
            .get("password")
            .and_then(|v| v.as_str())
            .map(str::to_string);

        let proxy = ProxyConfig {
            server: server.to_string(),
            bypass_list,
            username,
            password,
        };

        let result = client
            .set_proxy(&proxy)
            .await
            .map_err(|e: BrowserError| e.to_fcp_error())?;
        Ok(json!({
            "enabled": result.enabled,
            "mode": result.mode,
            "server": result.server,
            "audit": dangerous_operation_audit("browser.set_proxy", true, execution_approval),
        }))
    }

    async fn invoke_clear_proxy(
        &self,
        _input: serde_json::Value,
        execution_approval: Option<&ExecutionApprovalContext>,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let result = client
            .clear_proxy()
            .await
            .map_err(|e: BrowserError| e.to_fcp_error())?;
        Ok(json!({
            "enabled": result.enabled,
            "mode": result.mode,
            "server": result.server,
            "audit": dangerous_operation_audit("browser.clear_proxy", true, execution_approval),
        }))
    }

    async fn invoke_session_save(
        &self,
        input: serde_json::Value,
        execution_approval: Option<&ExecutionApprovalContext>,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let domain = input
            .get("domain")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let lease_seq = parse_required_u64_field(&input, "lease_seq")?;
        let lease_object_id = require_str(&input, "lease_object_id")?.to_string();

        let cookies = client
            .session_save_cookies(domain.as_deref())
            .await
            .map_err(|e: BrowserError| e.to_fcp_error())?;

        let payload = BrowserSessionStatePayload {
            schema_version: 1,
            captured_at: current_unix_timestamp_secs(),
            domain: domain.clone(),
            cookies,
        };
        let payload_cbor =
            fcp_cbor::to_canonical_cbor(&payload).map_err(|e| FcpError::Internal {
                message: format!("Failed to encode browser session payload: {e}"),
            })?;

        let mut store = self.session_store.lock().map_err(|_| FcpError::Internal {
            message: "session state store mutex poisoned".into(),
        })?;
        if lease_seq < store.last_lease_seq {
            return Err(FcpError::Conflict {
                message: format!(
                    "stale lease_seq for browser session state: current={}, incoming={lease_seq}",
                    store.last_lease_seq
                ),
            });
        }

        let prev_state_object_id = store.head_state_object_id.clone();
        let seq = if store.head_state_object_id.is_some() {
            store.last_seq.saturating_add(1)
        } else {
            0
        };
        let state_object_id = derive_session_state_object_id(
            prev_state_object_id.as_deref(),
            lease_seq,
            &lease_object_id,
            &payload_cbor,
        );

        let record = BrowserSessionStateObjectRecord {
            state_object_id: state_object_id.clone(),
            prev_state_object_id: prev_state_object_id.clone(),
            seq,
            lease_seq,
            lease_object_id: lease_object_id.clone(),
            payload_cbor: payload_cbor.clone(),
            payload,
        };
        let cookie_count = record.payload.cookies.len();
        let captured_at = record.payload.captured_at;

        store.objects.insert(state_object_id.clone(), record);
        store.head_state_object_id = Some(state_object_id.clone());
        store.last_seq = seq;
        store.last_lease_seq = lease_seq;
        drop(store);

        client
            .record_direct_cdp_session_object(
                "browser.session.save",
                &state_object_id,
                lease_seq,
                domain.as_deref(),
            )
            .map_err(|e: BrowserError| e.to_fcp_error())?;

        Ok(json!({
            "state_object_id": state_object_id,
            "prev_state_object_id": prev_state_object_id,
            "seq": seq,
            "lease_seq": lease_seq,
            "lease_object_id": lease_object_id,
            "cookie_count": cookie_count,
            "payload_cbor_size": payload_cbor.len(),
            "captured_at": captured_at,
            "domain": domain,
            "audit": dangerous_operation_audit("browser.session.save", true, execution_approval),
        }))
    }

    async fn invoke_session_restore(
        &self,
        input: serde_json::Value,
        execution_approval: Option<&ExecutionApprovalContext>,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let requested_state_object_id = input
            .get("state_object_id")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let lease_seq = parse_required_u64_field(&input, "lease_seq")?;
        let lease_object_id = require_str(&input, "lease_object_id")?.to_string();

        let record = {
            let mut store = self.session_store.lock().map_err(|_| FcpError::Internal {
                message: "session state store mutex poisoned".into(),
            })?;
            if lease_seq < store.last_lease_seq {
                return Err(FcpError::Conflict {
                    message: format!(
                        "stale lease_seq for browser session state: current={}, incoming={lease_seq}",
                        store.last_lease_seq
                    ),
                });
            }

            let state_object_id = match requested_state_object_id {
                Some(ref id) => id.clone(),
                None => store
                    .head_state_object_id
                    .clone()
                    .ok_or(FcpError::InvalidRequest {
                        code: 1003,
                        message: "No saved browser session state available".into(),
                    })?,
            };
            let record =
                store
                    .objects
                    .get(&state_object_id)
                    .cloned()
                    .ok_or(FcpError::InvalidRequest {
                        code: 1003,
                        message: format!(
                            "Unknown browser session state object_id: {state_object_id}"
                        ),
                    })?;
            store.last_lease_seq = lease_seq;
            record
        };

        let restored_count = client
            .session_restore_cookies(&record.payload.cookies)
            .await
            .map_err(|e: BrowserError| e.to_fcp_error())?;

        client
            .record_direct_cdp_session_object(
                "browser.session.restore",
                &record.state_object_id,
                lease_seq,
                record.payload.domain.as_deref(),
            )
            .map_err(|e: BrowserError| e.to_fcp_error())?;

        Ok(json!({
            "state_object_id": record.state_object_id,
            "restored_count": restored_count,
            "cookie_count": record.payload.cookies.len(),
            "seq": record.seq,
            "saved_lease_seq": record.lease_seq,
            "lease_seq": lease_seq,
            "lease_object_id": lease_object_id,
            "captured_at": record.payload.captured_at,
            "domain": record.payload.domain,
            "audit": dangerous_operation_audit("browser.session.restore", true, execution_approval),
        }))
    }

    async fn invoke_session_describe(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let requested_state_object_id = input
            .get("state_object_id")
            .and_then(|v| v.as_str())
            .map(str::to_string);

        let (record, is_head) =
            {
                let store = self.session_store.lock().map_err(|_| FcpError::Internal {
                    message: "session state store mutex poisoned".into(),
                })?;
                let state_object_id = match requested_state_object_id {
                    Some(ref id) => id.clone(),
                    None => store
                        .head_state_object_id
                        .clone()
                        .ok_or(FcpError::InvalidRequest {
                            code: 1003,
                            message: "No saved browser session state available".into(),
                        })?,
                };
                let record = store.objects.get(&state_object_id).cloned().ok_or(
                    FcpError::InvalidRequest {
                        code: 1003,
                        message: format!(
                            "Unknown browser session state object_id: {state_object_id}"
                        ),
                    },
                )?;
                let is_head =
                    store.head_state_object_id.as_deref() == Some(state_object_id.as_str());
                drop(store);
                (record, is_head)
            };

        if let Some(client) = self.client.as_ref() {
            client
                .record_direct_cdp_session_object(
                    "browser.session.describe",
                    &record.state_object_id,
                    record.lease_seq,
                    record.payload.domain.as_deref(),
                )
                .map_err(|e: BrowserError| e.to_fcp_error())?;
        }

        Ok(json!({
            "state_object_id": record.state_object_id,
            "prev_state_object_id": record.prev_state_object_id,
            "seq": record.seq,
            "lease_seq": record.lease_seq,
            "lease_object_id": record.lease_object_id,
            "cookie_count": record.payload.cookies.len(),
            "captured_at": record.payload.captured_at,
            "domain": record.payload.domain,
            "payload_cbor_size": record.payload_cbor.len(),
            "is_head": is_head,
        }))
    }

    /// Handle shutdown.
    pub async fn handle_shutdown(
        &self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Browser connector shutting down");
        if let Some(client) = self.client.as_ref() {
            client.shutdown();
        }
        Ok(json!({ "status": "shutdown" }))
    }

    #[cfg(feature = "test-support")]
    pub fn direct_cdp_manager_events_jsonl_for_test(&self) -> FcpResult<String> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        client
            .direct_cdp_manager_events_jsonl()
            .map_err(|err| err.to_fcp_error())
    }
}

impl Default for BrowserConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required field: {field}"),
        })
}

fn requires_execution_approval(operation: &str) -> bool {
    matches!(
        operation,
        "browser.evaluate_js"
            | "browser.fill_form"
            | "browser.get_cookies"
            | "browser.set_cookies"
            | "browser.session.save"
            | "browser.session.restore"
            | "browser.set_proxy"
            | "browser.clear_proxy"
    )
}

fn parse_required_u64_field(input: &serde_json::Value, field: &str) -> FcpResult<u64> {
    input
        .get(field)
        .and_then(|v| v.as_u64())
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required field: {field}"),
        })
}

fn parse_optional_u32_field(input: &serde_json::Value, field: &str) -> FcpResult<Option<u32>> {
    let Some(value) = input.get(field) else {
        return Ok(None);
    };
    let raw = value.as_u64().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: format!("{field} must be a positive integer"),
    })?;
    if raw == 0 {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must be greater than zero"),
        });
    }
    u32::try_from(raw)
        .map(Some)
        .map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} is too large"),
        })
}

fn current_unix_timestamp_secs() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadableOutputMode {
    Text,
    Markdown,
}

impl ReadableOutputMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Markdown => "markdown",
        }
    }
}

#[derive(Debug)]
struct PreparedReadableContent {
    text: String,
    output_mode: ReadableOutputMode,
    guardrails: serde_json::Value,
}

fn parse_readable_output_mode(input: &serde_json::Value) -> FcpResult<ReadableOutputMode> {
    match input.get("output_mode").and_then(|value| value.as_str()) {
        None | Some("text") => Ok(ReadableOutputMode::Text),
        Some("markdown") => Ok(ReadableOutputMode::Markdown),
        Some(other) => Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Unsupported output_mode `{other}`; expected `text` or `markdown`"),
        }),
    }
}

fn parse_readable_max_chars(input: &serde_json::Value) -> FcpResult<usize> {
    let Some(value) = input.get("max_chars") else {
        return Ok(READABLE_CONTENT_DEFAULT_MAX_CHARS);
    };
    let raw = value.as_u64().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "max_chars must be a positive integer".into(),
    })?;
    if raw == 0 {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "max_chars must be greater than zero".into(),
        });
    }
    let max_chars = usize::try_from(raw).map_err(|_| FcpError::InvalidRequest {
        code: 1003,
        message: "max_chars is too large for this platform".into(),
    })?;
    if max_chars > READABLE_CONTENT_ABSOLUTE_MAX_CHARS {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "max_chars {max_chars} exceeds absolute cap {READABLE_CONTENT_ABSOLUTE_MAX_CHARS}"
            ),
        });
    }
    Ok(max_chars)
}

fn prepare_readable_content(
    raw_text: &str,
    max_chars: usize,
    output_mode: ReadableOutputMode,
) -> PreparedReadableContent {
    let (sanitized, stripped_invisible_chars) = strip_invisible_unicode(raw_text);
    let original_chars = sanitized.chars().count();
    let (bounded, truncated) = truncate_to_char_limit(&sanitized, max_chars);
    let text = match output_mode {
        ReadableOutputMode::Text => bounded,
        ReadableOutputMode::Markdown => plain_text_to_markdown(&bounded),
    };
    PreparedReadableContent {
        text,
        output_mode,
        guardrails: json!({
            "html_cap_chars": READABLE_CONTENT_ABSOLUTE_MAX_CHARS,
            "default_text_cap_chars": READABLE_CONTENT_DEFAULT_MAX_CHARS,
            "requested_max_chars": max_chars,
            "original_chars_after_unicode_strip": original_chars,
            "stripped_invisible_chars": stripped_invisible_chars,
            "truncated": truncated,
            "deep_html_nesting_policy": "raw_html_not_accepted_by_connector",
            "raw_html_sanitization": "browser_control_worker_extracts_active_page_text; connector strips invisible Unicode and bounds text output",
        }),
    }
}

fn strip_invisible_unicode(input: &str) -> (String, usize) {
    let mut stripped = 0;
    let output = input
        .chars()
        .filter(|ch| {
            if is_invisible_unicode(*ch) {
                stripped += 1;
                false
            } else {
                true
            }
        })
        .collect();
    (output, stripped)
}

const fn is_invisible_unicode(ch: char) -> bool {
    matches!(
        ch,
        '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{206F}' | '\u{FEFF}'
    )
}

fn truncate_to_char_limit(input: &str, max_chars: usize) -> (String, bool) {
    let mut chars = input.chars();
    let bounded: String = chars.by_ref().take(max_chars).collect();
    let truncated = chars.next().is_some();
    (bounded, truncated)
}

fn plain_text_to_markdown(input: &str) -> String {
    let mut markdown = String::new();
    for line in input.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if !markdown.is_empty() {
            markdown.push_str("\n\n");
        }
        markdown.push_str(line);
    }
    markdown
}

fn external_content_metadata(kind: &'static str) -> serde_json::Value {
    json!({
        "untrusted": true,
        "source": "browser",
        "kind": kind,
        "taint": "tainted",
        "origin_zone": "z:public",
    })
}

fn readability_metadata(output_mode: ReadableOutputMode) -> serde_json::Value {
    json!({
        "decision": "adopted_for_active_page_text",
        "engine": "fcp_browser_control_extract_text",
        "output_mode": output_mode.as_str(),
        "html_readability_parser": "deferred_until_raw_html_fetch_or_shared_document_extraction_helper_exists",
        "no_interpreted_runtime_dependency": true,
    })
}

fn document_extraction_deferral_metadata() -> serde_json::Value {
    json!({
        "decision": "deferred",
        "reason": "browser.render_pdf exports the active page; local PDF/document text extraction needs a self-contained Rust extractor or shared FCP document helper",
        "pdf_text_cap_chars": DOCUMENT_TEXT_EXTRACTION_CAP_CHARS,
        "render_pixel_cap": DOCUMENT_RENDER_PIXEL_CAP,
        "dependency_missing_degrade_path": "not_applicable_no_optional_renderer_dependency",
    })
}

fn browser_placement_profile() -> BrowserPlacementProfile {
    BrowserPlacementProfile {
        sandbox_profile: BROWSER_SANDBOX_PROFILE,
        sandbox_deny_exec: BROWSER_SANDBOX_DENY_EXEC,
        sandbox_deny_ptrace: BROWSER_SANDBOX_DENY_PTRACE,
        network_guard: BrowserNetworkGuardProfile {
            allowed_host_patterns: BROWSER_CONTROL_HOST_ALLOWLIST,
            require_https_for_non_loopback: true,
            allow_http_for_loopback: true,
        },
        execution_planner: BrowserExecutionPlannerProfile {
            memory_mb: BROWSER_SANDBOX_MEMORY_MB,
            cpu_percent: BROWSER_SANDBOX_CPU_PERCENT,
            wall_clock_timeout_ms: BROWSER_SANDBOX_WALL_CLOCK_TIMEOUT_MS,
        },
    }
}

fn parse_rust_owned_launcher_config(
    params: &serde_json::Value,
) -> FcpResult<Option<BrowserLauncherConfig>> {
    let Some(value) = params.get("rust_owned_launcher") else {
        return Ok(None);
    };

    if value.as_bool() == Some(false) {
        return Ok(None);
    }

    let (mode, browser_binary_path, readiness_timeout_ms) = if value.as_bool() == Some(true) {
        (
            BrowserLauncherMode::Native,
            None,
            crate::client::RUST_LAUNCHER_DEFAULT_READINESS_TIMEOUT_MS,
        )
    } else {
        let object = value.as_object().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "rust_owned_launcher must be a boolean or object".into(),
        })?;
        let enabled = object
            .get("enabled")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true);
        if !enabled {
            return Ok(None);
        }
        let mode = match object
            .get("mode")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("native")
        {
            "native" => BrowserLauncherMode::Native,
            "fixture" => BrowserLauncherMode::Fixture,
            other => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!(
                        "rust_owned_launcher.mode must be native or fixture, got {other}"
                    ),
                });
            }
        };
        let browser_binary_path = match object.get("browser_binary_path") {
            Some(value) => Some(
                value
                    .as_str()
                    .ok_or(FcpError::InvalidRequest {
                        code: 1003,
                        message: "rust_owned_launcher.browser_binary_path must be a string".into(),
                    })?
                    .to_string(),
            ),
            None => None,
        };
        let readiness_timeout_ms = object
            .get("readiness_timeout_ms")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(crate::client::RUST_LAUNCHER_DEFAULT_READINESS_TIMEOUT_MS);
        (mode, browser_binary_path, readiness_timeout_ms)
    };

    match mode {
        BrowserLauncherMode::Native => {
            BrowserLauncherConfig::native(browser_binary_path, readiness_timeout_ms)
                .map(Some)
                .map_err(|e| FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid rust_owned_launcher config: {e}"),
                })
        }
        BrowserLauncherMode::Fixture => {
            Ok(Some(BrowserLauncherConfig::fixture(readiness_timeout_ms)))
        }
    }
}

fn validate_browser_control_endpoint_url(browser_url: &str) -> FcpResult<()> {
    let parsed = reqwest::Url::parse(browser_url).map_err(|e| FcpError::InvalidRequest {
        code: 1003,
        message: format!("browser_url must be an absolute URL: {e}"),
    })?;
    let redacted_url = redact_browser_endpoint_url(&parsed);

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("browser_url must not include userinfo ({redacted_url})"),
        });
    }

    if parsed.query().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("browser_url must not include query parameters ({redacted_url})"),
        });
    }

    if parsed.fragment().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("browser_url must not include a URL fragment ({redacted_url})"),
        });
    }

    let host = parsed.host_str().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "browser_url must include a host".into(),
    })?;

    if !is_browser_control_host_allowlisted(host) {
        return Err(FcpError::ResourceNotAllowed {
            resource: format!("browser.control_plane.host:{host}"),
        });
    }

    if matches!(parsed.scheme(), "ws" | "wss") {
        if parsed.scheme() == "wss" {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "direct Chrome DevTools WebSocket browser_url must use ws:// loopback transport until TLS WebSocket support is wired ({redacted_url})"
                ),
            });
        }

        if !is_direct_cdp_page_websocket_endpoint(&parsed) {
            let message = if is_direct_cdp_websocket_endpoint(&parsed) {
                format!(
                    "direct Chrome DevTools WebSocket browser_url must target a page endpoint under /devtools/page/<target-id> ({redacted_url})"
                )
            } else {
                format!(
                    "browser_url WebSocket endpoints must be direct Chrome DevTools page endpoints under /devtools/page/<target-id> ({redacted_url})"
                )
            };
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message,
            });
        }

        if !is_loopback_host(host) {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "direct Chrome DevTools WebSocket browser_url must use a loopback host (got host '{host}')"
                ),
            });
        }

        return Ok(());
    }

    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "browser_url scheme must be http, https, or ws for loopback direct Chrome DevTools page endpoints"
                .into(),
        });
    }

    if is_chrome_cdp_discovery_path(parsed.path()) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "browser_url points at a raw Chrome DevTools discovery endpoint ({redacted_url}); configure the FCP browser-control base URL"
            ),
        });
    }

    if parsed.scheme() == "http" && !is_loopback_host(host) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "browser_url must use https for non-loopback hosts (got host '{host}')"
            ),
        });
    }

    Ok(())
}

fn redact_browser_endpoint_url(parsed: &reqwest::Url) -> String {
    let mut redacted = parsed.clone();
    let _ = redacted.set_username("");
    let _ = redacted.set_password(None);
    redacted.set_query(None);
    redacted.set_fragment(None);
    redacted.to_string()
}

fn is_direct_cdp_websocket_endpoint(parsed: &reqwest::Url) -> bool {
    if !matches!(parsed.scheme(), "ws" | "wss") {
        return false;
    }

    let Some(mut segments) = parsed.path_segments() else {
        return false;
    };
    let Some("devtools") = segments.next() else {
        return false;
    };
    let Some(kind) = segments.next() else {
        return false;
    };
    if !matches!(
        kind,
        "browser" | "page" | "worker" | "shared_worker" | "service_worker"
    ) {
        return false;
    }
    let Some(target_id) = segments.next() else {
        return false;
    };
    !target_id.is_empty() && segments.next().is_none()
}

fn is_direct_cdp_page_websocket_endpoint(parsed: &reqwest::Url) -> bool {
    if !matches!(parsed.scheme(), "ws" | "wss") {
        return false;
    }

    let Some(mut segments) = parsed.path_segments() else {
        return false;
    };
    let Some("devtools") = segments.next() else {
        return false;
    };
    let Some("page") = segments.next() else {
        return false;
    };
    let Some(target_id) = segments.next() else {
        return false;
    };
    !target_id.is_empty() && segments.next().is_none()
}

fn is_chrome_cdp_discovery_path(path: &str) -> bool {
    path == "/json" || path.starts_with("/json/")
}

fn is_browser_control_host_allowlisted(host: &str) -> bool {
    let normalized = host.to_ascii_lowercase();
    BROWSER_CONTROL_HOST_ALLOWLIST
        .iter()
        .any(|pattern| host_matches_pattern(&normalized, pattern))
}

fn is_loopback_host(host: &str) -> bool {
    let normalized = host.to_ascii_lowercase();
    matches!(normalized.as_str(), "localhost" | "127.0.0.1" | "::1")
}

fn host_matches_pattern(host: &str, pattern: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    if let Some(suffix) = pattern.strip_prefix("*.") {
        host == suffix
            || (host.len() > suffix.len()
                && host.ends_with(suffix)
                && host.as_bytes()[host.len() - suffix.len() - 1] == b'.')
    } else {
        host == pattern
    }
}

fn derive_session_state_object_id(
    prev_state_object_id: Option<&str>,
    lease_seq: u64,
    lease_object_id: &str,
    payload_cbor: &[u8],
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"fcp.browser.session_state.v1");
    if let Some(prev) = prev_state_object_id {
        hasher.update(prev.as_bytes());
    }
    hasher.update(&lease_seq.to_le_bytes());
    hasher.update(lease_object_id.as_bytes());
    hasher.update(payload_cbor);
    hasher.finalize().to_hex().to_string()
}

fn operation_pattern_matches(pattern: &str, operation: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        operation.starts_with(prefix)
    } else {
        pattern == operation
    }
}

fn dangerous_operation_audit(
    operation: &str,
    side_effect: bool,
    execution_approval: Option<&ExecutionApprovalContext>,
) -> serde_json::Value {
    json!({
        "operation": operation,
        "dangerous": true,
        "side_effect": side_effect,
        "approval_token_id": execution_approval.map(|ctx| ctx.token_id.clone()),
        "timestamp": chrono::Utc::now().to_rfc3339(),
    })
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
        .expect("embedded Browser manifest should validate");
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_prelude::CapabilityConstraints;
    use std::{
        io::{BufRead, BufReader, Read, Write},
        net::{TcpListener, TcpStream},
        path::PathBuf,
        thread::{self, JoinHandle},
        time::Duration as StdDuration,
    };

    struct TestControlResponse {
        method: &'static str,
        path: &'static str,
        status: u16,
        body: Vec<u8>,
        content_type: &'static str,
    }

    impl TestControlResponse {
        fn json(
            method: &'static str,
            path: &'static str,
            status: u16,
            body: impl serde::Serialize,
        ) -> Self {
            Self {
                method,
                path,
                status,
                body: serde_json::to_vec(&body).expect("serialize response json"),
                content_type: "application/json",
            }
        }

        fn text(method: &'static str, path: &'static str, status: u16, body: &str) -> Self {
            Self {
                method,
                path,
                status,
                body: body.as_bytes().to_vec(),
                content_type: "text/plain; charset=utf-8",
            }
        }
    }

    struct TestControlServer {
        base_url: String,
        _handle: JoinHandle<()>,
    }

    impl TestControlServer {
        fn respond(response: TestControlResponse) -> Self {
            Self::respond_sequence(vec![response])
        }

        fn respond_sequence(responses: Vec<TestControlResponse>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
            let base_url = format!("http://{}", listener.local_addr().expect("local address"));
            let handle = thread::spawn(move || {
                for response in responses {
                    let (stream, _) = listener.accept().expect("accept browser client request");
                    handle_test_control_request(stream, &response);
                }
            });
            Self {
                base_url,
                _handle: handle,
            }
        }

        fn uri(&self) -> String {
            self.base_url.clone()
        }
    }

    fn handle_test_control_request(mut stream: TcpStream, response: &TestControlResponse) {
        stream
            .set_read_timeout(Some(StdDuration::from_secs(5)))
            .expect("set read timeout");
        let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));

        let mut request_line = String::new();
        reader
            .read_line(&mut request_line)
            .expect("read request line");
        let mut parts = request_line.split_whitespace();
        let method = parts.next().expect("request method");
        let raw_path = parts.next().expect("request target");
        let path = raw_path.split('?').next().expect("request path");
        assert_eq!(method, response.method);
        assert_eq!(path, response.path);

        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).expect("read header line");
            if line == "\r\n" || line.is_empty() {
                break;
            }
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().expect("content-length parses");
            }
        }
        if content_length > 0 {
            let mut body = vec![0; content_length];
            reader.read_exact(&mut body).expect("read request body");
        }

        let status_text = match response.status {
            404 => "Not Found",
            _ => "OK",
        };
        write!(
            stream,
            "HTTP/1.1 {} {}\r\ncontent-type: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            response.status,
            status_text,
            response.content_type,
            response.body.len(),
        )
        .expect("write response header");
        if stream.write_all(&response.body).is_ok() {
            let _ = stream.flush();
        }
    }

    fn test_constraints_cbor() -> Vec<u8> {
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
        cbor
    }

    fn generate_valid_token(
        signing_key: &Ed25519SigningKey,
        instance_id: &str,
        cap: &str,
        op: &str,
    ) -> CapabilityToken {
        let now = Utc::now();
        let cose = CapabilityTokenBuilder::new()
            .capability_id(cap)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[op])
            .issuer("node:test")
            .target_instance(instance_id)
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&test_constraints_cbor())
            .expect("constraints CBOR should validate")
            .sign(signing_key)
            .unwrap();
        CapabilityToken::from_raw(cose)
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = BrowserConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["browser.navigate"]
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "accepted");
    }

    #[test]
    fn handshake_manifest_hash_tracks_bundled_manifest() {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        let expected = format!("sha256:{}", hex::encode(hasher.finalize()));

        assert_eq!(BrowserConnector::manifest_hash(), expected);
        assert_ne!(
            BrowserConnector::manifest_hash(),
            "sha256:browser-connector-v1"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = BrowserConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = BrowserConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["browser.navigate"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(
            &signing_key,
            connector.base.instance_id.as_str(),
            "browser.navigate",
            "browser.navigate",
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "browser.navigate",
                "input": { "url": "https://example.com" },
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_field() {
        let mut connector = BrowserConnector::new();
        connector
            .handle_configure(json!({
                "browser_url": "http://localhost:9999"
            }))
            .await
            .unwrap();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["browser.click"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(
            &signing_key,
            connector.base.instance_id.as_str(),
            "browser.interact",
            "browser.click",
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "browser.click",
                "input": {},
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("selector")),
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn readable_content_strips_invisible_unicode() {
        let (sanitized, stripped) = strip_invisible_unicode("hel\u{200B}lo\u{202E} world");

        assert_eq!(sanitized, "hello world");
        assert_eq!(stripped, 2);
    }

    #[test]
    fn readable_content_truncates_after_unicode_strip() {
        let prepared = prepare_readable_content("a\u{200B}bcdef", 3, ReadableOutputMode::Text);

        assert_eq!(prepared.text, "abc");
        assert_eq!(prepared.guardrails["stripped_invisible_chars"], 1);
        assert_eq!(prepared.guardrails["truncated"], true);
        assert_eq!(prepared.guardrails["requested_max_chars"], 3);
    }

    #[test]
    fn readable_content_markdown_mode_normalizes_paragraphs() {
        let prepared = prepare_readable_content(
            " First paragraph \n\n Second paragraph ",
            100,
            ReadableOutputMode::Markdown,
        );

        assert_eq!(prepared.text, "First paragraph\n\nSecond paragraph");
        assert_eq!(prepared.output_mode, ReadableOutputMode::Markdown);
    }

    #[test]
    fn readable_content_rejects_oversized_requested_cap() {
        let err = parse_readable_max_chars(&json!({
            "max_chars": READABLE_CONTENT_ABSOLUTE_MAX_CHARS + 1
        }))
        .unwrap_err();

        assert!(format!("{err}").contains("exceeds absolute cap"));
    }

    #[test]
    fn document_extraction_deferral_metadata_pins_fcp_decision() {
        let metadata = document_extraction_deferral_metadata();

        assert_eq!(metadata["decision"], "deferred");
        assert_eq!(
            metadata["pdf_text_cap_chars"],
            DOCUMENT_TEXT_EXTRACTION_CAP_CHARS
        );
        assert_eq!(metadata["render_pixel_cap"], DOCUMENT_RENDER_PIXEL_CAP);
        assert!(
            metadata["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("self-contained Rust extractor"))
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_all_operations() {
        let connector = BrowserConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert_eq!(op_ids, OPERATION_ORDER);
        assert!(op_ids.contains(&"browser.navigate"));
        assert!(op_ids.contains(&"browser.screenshot"));
        assert!(op_ids.contains(&"browser.render_pdf"));
        assert!(op_ids.contains(&"browser.extract_text"));
        assert!(op_ids.contains(&"browser.extract_links"));
        assert!(op_ids.contains(&"browser.wait_for_selector"));
        assert!(op_ids.contains(&"browser.click"));
        assert!(op_ids.contains(&"browser.fill_form"));
        assert!(op_ids.contains(&"browser.evaluate_js"));
        assert!(op_ids.contains(&"browser.get_cookies"));
        assert!(op_ids.contains(&"browser.set_cookies"));
        assert!(op_ids.contains(&"browser.session.save"));
        assert!(op_ids.contains(&"browser.session.restore"));
        assert!(op_ids.contains(&"browser.session.describe"));
        assert!(op_ids.contains(&"browser.set_proxy"));
        assert!(op_ids.contains(&"browser.clear_proxy"));
        assert_eq!(ops.len(), OPERATION_ORDER.len());
    }

    #[test]
    fn runtime_operation_catalog_matches_manifest_metadata() {
        let manifest =
            ConnectorManifest::parse_str(MANIFEST_TOML).expect("manifest should validate");
        let operations = typed_operations_info();
        let ids: Vec<_> = operations
            .iter()
            .map(|operation| operation.id.as_str())
            .collect();

        assert_eq!(ids, OPERATION_ORDER);
        assert_eq!(operations.len(), manifest.provides.operations.len());

        for operation in operations {
            let manifest_operation = manifest
                .provides
                .operations
                .get(operation.id.as_str())
                .expect("runtime operation should exist in manifest");

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
                serde_json::to_value(&operation.ai_hints).unwrap(),
                serde_json::to_value(&manifest_operation.ai_hints).unwrap()
            );
            assert_eq!(
                serde_json::to_value(&operation.rate_limit).unwrap(),
                serde_json::to_value(
                    manifest_operation
                        .rate_limit
                        .as_ref()
                        .map(|rate_limit| &rate_limit.0)
                )
                .unwrap()
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn introspection_serializes_typed_operation_catalog() {
        let connector = BrowserConnector::new();
        let introspection = connector.handle_introspect().await.unwrap();

        assert_eq!(
            introspection["operations"],
            serde_json::to_value(typed_operations_info()).unwrap()
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspected_operations_have_control_contract_mapping() {
        let connector = BrowserConnector::new();
        let introspection = connector.handle_introspect().await.unwrap();
        let ops = introspection["operations"].as_array().unwrap();
        let descriptor = browser_control_contract_descriptor();
        let connector_operations = descriptor["connector_operations"].as_array().unwrap();

        for op in ops {
            let id = op["id"].as_str().unwrap();
            assert!(
                connector_operations
                    .iter()
                    .any(|operation| operation["id"] == id),
                "missing browser-control mapping for {id}"
            );
        }

        let worker_operations = descriptor["operations"].as_array().unwrap();
        for mapping in connector_operations {
            let mapping_kind = mapping["mapping"].as_str().unwrap();
            let worker_operation_ids = mapping["worker_operation_ids"].as_array().unwrap();
            if mapping_kind == "connector_state" {
                assert!(worker_operation_ids.is_empty());
                continue;
            }
            assert!(
                !worker_operation_ids.is_empty(),
                "{} must name worker primitive dependencies",
                mapping["id"].as_str().unwrap()
            );
            for worker_id in worker_operation_ids {
                let worker_id = worker_id.as_str().unwrap();
                assert!(
                    worker_operations
                        .iter()
                        .any(|operation| operation["id"] == worker_id),
                    "{} references unknown worker operation {worker_id}",
                    mapping["id"].as_str().unwrap()
                );
            }
        }
    }

    // ── Provisioning automation tests ─────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_configure_no_auth() {
        let mut connector = BrowserConnector::new();
        let result = connector.handle_configure(json!({})).await.unwrap();
        assert_eq!(result["status"], "configured");
        assert!(connector.client.is_some());
        assert!(connector.config.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_api_key() {
        let mut connector = BrowserConnector::new();
        let result = connector
            .handle_configure(json!({ "api_key": "browser-secret" }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_credential_id() {
        let mut connector = BrowserConnector::new();
        let cid = uuid::Uuid::new_v4().to_string();
        let result = connector
            .handle_configure(json!({ "credential_id": cid }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
        assert!(connector.config.as_ref().unwrap().auth.is_secretless());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_both_auth_modes() {
        let mut connector = BrowserConnector::new();
        let cid = uuid::Uuid::new_v4().to_string();
        let result = connector
            .handle_configure(json!({
                "api_key": "browser-secret",
                "credential_id": cid
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("not both"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_custom_browser_url() {
        let mut connector = BrowserConnector::new();
        let result = connector
            .handle_configure(json!({
                "browser_url": "https://control.browser.flywheel.internal:9222"
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
        let config = connector.config.as_ref().unwrap();
        assert_eq!(
            config.browser_url,
            "https://control.browser.flywheel.internal:9222"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_disallowed_browser_url_host() {
        let mut connector = BrowserConnector::new();
        let result = connector
            .handle_configure(json!({
                "browser_url": "https://evil.example.net:9222"
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::ResourceNotAllowed { resource } => {
                assert!(resource.contains("browser.control_plane.host"));
            }
            e => panic!("Expected ResourceNotAllowed, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_http_on_non_loopback_host() {
        let mut connector = BrowserConnector::new();
        let result = connector
            .handle_configure(json!({
                "browser_url": "http://control.browser.flywheel.internal:9222"
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("must use https"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_raw_chrome_cdp_discovery_url() {
        let mut connector = BrowserConnector::new();
        let result = connector
            .handle_configure(json!({
                "browser_url": "http://localhost:9222/json/version"
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("raw Chrome DevTools discovery"));
                assert!(message.contains("http://localhost:9222/json/version"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_accepts_loopback_direct_cdp_page_websocket_url() {
        let mut connector = BrowserConnector::new();
        connector
            .handle_configure(json!({
                "browser_url": "ws://localhost:9222/devtools/page/target-1"
            }))
            .await
            .unwrap();

        let health = connector.handle_health().await.unwrap();
        assert_eq!(
            health["browser_url"],
            "ws://localhost:9222/devtools/page/target-1"
        );
        assert_eq!(health["network_guard"]["allowlisted"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn test_connector_shutdown_clears_direct_cdp_manager_without_raw_identifiers() {
        let mut connector = BrowserConnector::new();
        connector
            .handle_configure(json!({
                "browser_url": "ws://localhost:9222/devtools/page/shutdown-target-secret"
            }))
            .await
            .unwrap();

        let client = connector
            .client
            .as_ref()
            .expect("configured browser client");
        let object_hash = client
            .record_direct_cdp_session_object(
                "browser.session.save",
                "state-object-secret",
                12,
                Some("private.example.test"),
            )
            .unwrap()
            .expect("direct CDP session object hash");
        assert_eq!(object_hash.len(), 16);

        let before_shutdown = client.direct_cdp_manager_events_jsonl().unwrap();
        assert!(before_shutdown.contains("\"event_kind\":\"session_object_recorded\""));
        assert!(!before_shutdown.contains("shutdown-target-secret"));
        assert!(!before_shutdown.contains("state-object-secret"));
        assert!(!before_shutdown.contains("private.example.test"));

        let shutdown = connector.handle_shutdown(json!({})).await.unwrap();
        assert_eq!(shutdown["status"], "shutdown");

        let rejected = client
            .record_direct_cdp_session_object(
                "browser.session.save",
                "post-shutdown-state-secret",
                13,
                Some("after-shutdown.example.test"),
            )
            .unwrap_err();
        assert!(format!("{rejected}").contains("manager is shut down"));

        let after_shutdown = client.direct_cdp_manager_events_jsonl().unwrap();
        assert!(after_shutdown.contains("\"event_kind\":\"manager_shutdown\""));
        assert!(
            after_shutdown
                .contains("\"cleanup_result\":\"targets_and_sessions_cleared_no_orphan\"")
        );
        assert!(
            after_shutdown.contains("\"cancellation_checkpoint\":\"shutdown_signal_observed\"")
        );
        assert!(!after_shutdown.contains("shutdown-target-secret"));
        assert!(!after_shutdown.contains("state-object-secret"));
        assert!(!after_shutdown.contains("private.example.test"));
        assert!(!after_shutdown.contains("post-shutdown-state-secret"));
        assert!(!after_shutdown.contains("after-shutdown.example.test"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_direct_cdp_session_describe_records_manager_state_without_network() {
        let mut connector = BrowserConnector::new();
        connector
            .handle_configure(json!({
                "browser_url": "ws://localhost:9222/devtools/page/session-describe-target-secret"
            }))
            .await
            .unwrap();

        let payload = BrowserSessionStatePayload {
            schema_version: 1,
            captured_at: current_unix_timestamp_secs(),
            domain: Some("private.example.test".into()),
            cookies: vec![Cookie {
                name: "session".into(),
                value: "secret-cookie-value".into(),
                domain: Some("private.example.test".into()),
                path: Some("/".into()),
                expires: None,
                http_only: Some(true),
                secure: Some(true),
                same_site: Some("Lax".into()),
            }],
        };
        let payload_cbor = fcp_cbor::to_canonical_cbor(&payload).unwrap();
        let state_object_id = "state-object-secret-describe".to_string();
        {
            let mut store = connector.session_store.lock().unwrap();
            store.objects.insert(
                state_object_id.clone(),
                BrowserSessionStateObjectRecord {
                    state_object_id: state_object_id.clone(),
                    prev_state_object_id: None,
                    seq: 0,
                    lease_seq: 42,
                    lease_object_id: "lease-object-secret-describe".into(),
                    payload_cbor: payload_cbor.clone(),
                    payload,
                },
            );
            store.head_state_object_id = Some(state_object_id.clone());
            store.last_seq = 0;
            store.last_lease_seq = 42;
        }

        let described = connector
            .invoke_session_describe(json!({ "state_object_id": state_object_id }))
            .await
            .unwrap();

        assert_eq!(described["cookie_count"], 1);
        assert_eq!(described["lease_seq"], 42);
        assert_eq!(described["is_head"], true);
        let jsonl = connector
            .client
            .as_ref()
            .unwrap()
            .direct_cdp_manager_events_jsonl()
            .unwrap();
        assert!(jsonl.contains("\"operation_id\":\"browser.session.describe\""));
        assert!(jsonl.contains("\"event_kind\":\"session_object_recorded\""));
        assert!(jsonl.contains("\"session_lease_seq\":42"));
        assert!(jsonl.contains("\"session_object_id_hash\":\"blake3:"));
        assert!(!jsonl.contains("session-describe-target-secret"));
        assert!(!jsonl.contains("state-object-secret-describe"));
        assert!(!jsonl.contains("lease-object-secret-describe"));
        assert!(!jsonl.contains("private.example.test"));
        assert!(!jsonl.contains("secret-cookie-value"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_unsupported_direct_cdp_websocket_urls() {
        for (browser_url, expected) in [
            (
                "wss://localhost:9222/devtools/page/target-1",
                "must use ws:// loopback",
            ),
            (
                "ws://control.browser.flywheel.internal:9222/devtools/page/target-1",
                "must use a loopback host",
            ),
            (
                "ws://localhost:9222/devtools/browser/browser-1",
                "must target a page endpoint",
            ),
            (
                "ws://localhost:9222/devtools/service_worker/sw-1",
                "must target a page endpoint",
            ),
            (
                "ws://localhost:9222/fcp-control",
                "must be direct Chrome DevTools page endpoints",
            ),
        ] {
            let mut connector = BrowserConnector::new();
            let result = connector
                .handle_configure(json!({ "browser_url": browser_url }))
                .await;
            assert!(result.is_err(), "{browser_url} should be rejected");
            match result.unwrap_err() {
                FcpError::InvalidRequest { message, .. } => {
                    assert!(
                        message.contains(expected),
                        "{browser_url} should fail with {expected}, got {message}"
                    );
                }
                e => panic!("Expected InvalidRequest, got: {e:?}"),
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_disallowed_direct_cdp_host() {
        let mut connector = BrowserConnector::new();
        let result = connector
            .handle_configure(json!({
                "browser_url": "ws://evil.example.net:9222/devtools/page/target-1"
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::ResourceNotAllowed { resource } => {
                assert!(resource.contains("browser.control_plane.host"));
            }
            e => panic!("Expected ResourceNotAllowed, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_browser_url_userinfo_query_and_fragment() {
        for (browser_url, expected) in [
            (
                "https://user:private-value@control.browser.flywheel.internal:9222",
                "must not include userinfo",
            ),
            (
                "https://control.browser.flywheel.internal:9222?query=private-value",
                "must not include query parameters",
            ),
            (
                "https://control.browser.flywheel.internal:9222#private-value",
                "must not include a URL fragment",
            ),
            (
                "ws://user:private-value@localhost:9222/devtools/page/target-1",
                "must not include userinfo",
            ),
            (
                "ws://localhost:9222/devtools/page/target-1?token=private-value",
                "must not include query parameters",
            ),
            (
                "ws://localhost:9222/devtools/page/target-1#private-value",
                "must not include a URL fragment",
            ),
        ] {
            let mut connector = BrowserConnector::new();
            let result = connector
                .handle_configure(json!({ "browser_url": browser_url }))
                .await;
            assert!(result.is_err());
            match result.unwrap_err() {
                FcpError::InvalidRequest { message, .. } => {
                    assert!(message.contains(expected));
                    assert!(!message.contains("private-value"));
                    assert!(!message.contains("query=private-value"));
                }
                e => panic!("Expected InvalidRequest, got: {e:?}"),
            }
        }
    }

    #[test]
    fn browser_endpoint_policy_identifies_direct_cdp_websocket_shapes() {
        let direct =
            reqwest::Url::parse("wss://localhost:9222/devtools/browser/browser-target").unwrap();
        assert!(is_direct_cdp_websocket_endpoint(&direct));
        assert!(!is_direct_cdp_page_websocket_endpoint(&direct));

        let page = reqwest::Url::parse("ws://localhost:9222/devtools/page/page-target").unwrap();
        assert!(is_direct_cdp_websocket_endpoint(&page));
        assert!(is_direct_cdp_page_websocket_endpoint(&page));

        let worker =
            reqwest::Url::parse("ws://localhost:9222/devtools/service_worker/sw-target").unwrap();
        assert!(is_direct_cdp_websocket_endpoint(&worker));
        assert!(!is_direct_cdp_page_websocket_endpoint(&worker));

        let missing_target = reqwest::Url::parse("ws://localhost:9222/devtools/page/").unwrap();
        assert!(!is_direct_cdp_websocket_endpoint(&missing_target));
        assert!(!is_direct_cdp_page_websocket_endpoint(&missing_target));

        let non_cdp_ws = reqwest::Url::parse("ws://localhost:9222/fcp-control").unwrap();
        assert!(!is_direct_cdp_websocket_endpoint(&non_cdp_ws));
        assert!(!is_direct_cdp_page_websocket_endpoint(&non_cdp_ws));
    }

    #[test]
    fn browser_endpoint_redaction_strips_userinfo_query_and_fragment() {
        let parsed = reqwest::Url::parse(
            "https://user:private-value@control.browser.flywheel.internal:9222/json/version?query=private-value#frag",
        )
        .unwrap();
        let redacted = redact_browser_endpoint_url(&parsed);

        assert_eq!(
            redacted,
            "https://control.browser.flywheel.internal:9222/json/version"
        );
        assert!(!redacted.contains("user"));
        assert!(!redacted.contains("private-value"));
        assert!(!redacted.contains("query"));
        assert!(!redacted.contains("frag"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_includes_auth_info() {
        let mut connector = BrowserConnector::new();
        connector
            .handle_configure(json!({ "api_key": "test-key" }))
            .await
            .unwrap();
        let health = connector.handle_health().await.unwrap();
        assert_eq!(health["status"], "healthy");
        assert!(health["auth_mode"].as_str().unwrap().contains("api_key"));
        assert!(health["browser_url"].as_str().is_some());
        assert_eq!(health["placement_profile"]["sandbox_profile"], "strict");
        assert_eq!(
            health["placement_profile"]["execution_planner"]["memory_mb"],
            1024
        );
        assert_eq!(health["network_guard"]["allowlisted"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_not_configured() {
        let connector = BrowserConnector::new();
        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "unhealthy");
        let checks = result["checks"].as_array().unwrap();
        assert_eq!(checks.len(), 8);
        assert_eq!(checks[0]["name"], "configuration");
        assert_eq!(checks[0]["status"], "unhealthy");
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured_healthy() {
        let mut connector = BrowserConnector::new();
        connector.handle_configure(json!({})).await.unwrap();
        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "healthy");
        let checks = result["checks"].as_array().unwrap();
        assert_eq!(checks.len(), 8);
        for check in checks {
            assert_eq!(check["status"], "healthy");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_credential_id_mode() {
        let mut connector = BrowserConnector::new();
        let cid = uuid::Uuid::new_v4().to_string();
        connector
            .handle_configure(json!({ "credential_id": cid }))
            .await
            .unwrap();
        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "healthy");
        let checks = result["checks"].as_array().unwrap();
        let cred_check = checks
            .iter()
            .find(|c| c["name"] == "credential_injection")
            .unwrap();
        assert_eq!(cred_check["status"], "healthy");
        assert!(
            cred_check["message"]
                .as_str()
                .unwrap()
                .contains("Secretless")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_not_configured() {
        let connector = BrowserConnector::new();
        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "failed");
        assert_eq!(result["reason_code"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_credential_id_degraded() {
        let mut connector = BrowserConnector::new();
        let cid = uuid::Uuid::new_v4().to_string();
        connector
            .handle_configure(json!({ "credential_id": cid }))
            .await
            .unwrap();
        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "degraded");
        assert_eq!(result["reason_code"], "credential_injection_required");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_accepts_fcp_browser_control_plane_health() {
        let server = TestControlServer::respond(TestControlResponse::json(
            "GET",
            "/health",
            200,
            browser_control_contract_descriptor(),
        ));

        let mut connector = BrowserConnector::new();
        connector
            .handle_configure(json!({ "browser_url": server.uri() }))
            .await
            .unwrap();

        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "ok");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_rejects_raw_chrome_cdp_endpoint() {
        let server = TestControlServer::respond_sequence(vec![
            TestControlResponse::text("GET", "/health", 404, "not found"),
            TestControlResponse::json(
                "GET",
                "/json/version",
                200,
                json!({
                    "Browser": "Chrome/123.0.0.0",
                    "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/browser/abc"
                }),
            ),
        ]);

        let mut connector = BrowserConnector::new();
        connector
            .handle_configure(json!({ "browser_url": server.uri() }))
            .await
            .unwrap();

        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "failed");
        assert_eq!(result["reason_code"], "self_check_failed");
        assert!(
            result["message"]
                .as_str()
                .unwrap()
                .contains("raw Chrome DevTools endpoint")
        );
    }

    #[test]
    fn manifest_interface_hash_is_deterministic() {
        let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("manifest.toml");
        if !manifest_path.exists() {
            eprintln!("manifest.toml missing; skipping interface_hash check");
            return;
        }

        let raw = std::fs::read_to_string(&manifest_path).expect("read manifest");
        let manifest = ConnectorManifest::parse_str(&raw).expect("manifest should validate");
        let computed = manifest
            .compute_interface_hash()
            .expect("interface hash computes");

        let expected_hash = "blake3-256:fcp.interface.v2:3a47308a4d0ff45ad64dcc688000bc79edb1bc2cee800160be681c069debd83a";
        assert_eq!(computed.to_string(), expected_hash);
    }

    // ── require_str sync tests ──────────────────────────────────────

    #[test]
    fn require_str_extracts_value() {
        let input = json!({"url": "https://example.com", "selector": "#main"});
        assert_eq!(require_str(&input, "url").unwrap(), "https://example.com");
        assert_eq!(require_str(&input, "selector").unwrap(), "#main");
    }

    #[test]
    fn require_str_missing_field() {
        let input = json!({"url": "https://example.com"});
        let err = require_str(&input, "selector").unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("selector")),
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn require_str_non_string_field() {
        let input = json!({"count": 42});
        assert!(require_str(&input, "count").is_err());
    }

    #[test]
    fn require_str_null_field() {
        let input = json!({"field": null});
        assert!(require_str(&input, "field").is_err());
    }

    #[test]
    fn require_str_float_value() {
        let input = json!({"val": 1.23});
        assert!(require_str(&input, "val").is_err());
    }

    #[test]
    fn require_str_object_value() {
        let input = json!({"val": {"nested": true}});
        assert!(require_str(&input, "val").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"val": [1, 2, 3]});
        assert!(require_str(&input, "val").is_err());
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"val": true});
        assert!(require_str(&input, "val").is_err());
    }

    #[test]
    fn require_str_nested_object_value() {
        let input = json!({"val": {"a": {"b": "c"}}});
        assert!(require_str(&input, "val").is_err());
    }

    #[test]
    fn require_str_empty_string_returns_ok() {
        let input = json!({"val": ""});
        assert_eq!(require_str(&input, "val").unwrap(), "");
    }

    #[test]
    fn require_str_error_code_is_1003() {
        let input = json!({});
        match require_str(&input, "x").unwrap_err() {
            FcpError::InvalidRequest { code, .. } => assert_eq!(code, 1003),
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    // ── parse_required_u64_field sync tests ─────────────────────────

    #[test]
    fn parse_required_u64_extracts_value() {
        let input = json!({"timeout": 5000});
        assert_eq!(parse_required_u64_field(&input, "timeout").unwrap(), 5000);
    }

    #[test]
    fn parse_required_u64_missing_field() {
        let input = json!({});
        assert!(parse_required_u64_field(&input, "timeout").is_err());
    }

    #[test]
    fn parse_required_u64_string_value() {
        let input = json!({"timeout": "5000"});
        assert!(parse_required_u64_field(&input, "timeout").is_err());
    }

    #[test]
    fn parse_required_u64_null_value() {
        let input = json!({"timeout": null});
        assert!(parse_required_u64_field(&input, "timeout").is_err());
    }

    // ── requires_execution_approval sync tests ──────────────────────

    #[test]
    fn requires_execution_approval_js() {
        assert!(requires_execution_approval("browser.evaluate_js"));
    }

    #[test]
    fn requires_execution_approval_fill_form() {
        assert!(requires_execution_approval("browser.fill_form"));
    }

    #[test]
    fn requires_execution_approval_cookies() {
        assert!(requires_execution_approval("browser.get_cookies"));
        assert!(requires_execution_approval("browser.set_cookies"));
    }

    #[test]
    fn requires_execution_approval_session() {
        assert!(requires_execution_approval("browser.session.save"));
        assert!(requires_execution_approval("browser.session.restore"));
    }

    #[test]
    fn requires_execution_approval_proxy() {
        assert!(requires_execution_approval("browser.set_proxy"));
        assert!(requires_execution_approval("browser.clear_proxy"));
    }

    #[test]
    fn does_not_require_execution_approval_navigate() {
        assert!(!requires_execution_approval("browser.navigate"));
    }

    #[test]
    fn does_not_require_execution_approval_screenshot() {
        assert!(!requires_execution_approval("browser.screenshot"));
    }

    // ── DoctorResult / DoctorCheck / DoctorStatus serde ─────────────

    #[test]
    fn doctor_result_serde_roundtrip() {
        let r = DoctorResult {
            status: DoctorStatus::Healthy,
            checks: vec![DoctorCheck {
                name: "config".into(),
                status: DoctorStatus::Healthy,
                message: "ok".into(),
            }],
        };
        let v = serde_json::to_value(&r).unwrap();
        let r2: DoctorResult = serde_json::from_value(v).unwrap();
        assert_eq!(r2.checks.len(), 1);
    }

    #[test]
    fn doctor_result_debug() {
        let r = DoctorResult {
            status: DoctorStatus::Healthy,
            checks: vec![],
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("DoctorResult"));
    }

    #[test]
    fn doctor_check_serde_roundtrip() {
        let c = DoctorCheck {
            name: "auth".into(),
            status: DoctorStatus::Healthy,
            message: "valid".into(),
        };
        let s = serde_json::to_string(&c).unwrap();
        let c2: DoctorCheck = serde_json::from_str(&s).unwrap();
        assert_eq!(c2.name, "auth");
        assert_eq!(c2.message, "valid");
    }

    #[test]
    fn doctor_check_debug() {
        let c = DoctorCheck {
            name: "dbgcheck".into(),
            status: DoctorStatus::Degraded,
            message: "warn".into(),
        };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("dbgcheck"));
    }

    #[test]
    fn doctor_status_serde_all_variants() {
        for status in [
            DoctorStatus::Healthy,
            DoctorStatus::Degraded,
            DoctorStatus::Unhealthy,
        ] {
            let v = serde_json::to_value(status).unwrap();
            let back: DoctorStatus = serde_json::from_value(v).unwrap();
            assert_eq!(back, status);
        }
    }

    #[test]
    fn doctor_status_debug() {
        let dbg = format!("{:?}", DoctorStatus::Unhealthy);
        assert!(dbg.contains("Unhealthy"));
    }

    #[test]
    fn doctor_status_copy() {
        let s = DoctorStatus::Degraded;
        let s2 = s;
        assert_eq!(s, s2);
    }

    #[test]
    fn doctor_status_eq_ne() {
        assert_eq!(DoctorStatus::Healthy, DoctorStatus::Healthy);
        assert_ne!(DoctorStatus::Healthy, DoctorStatus::Degraded);
        assert_ne!(DoctorStatus::Degraded, DoctorStatus::Unhealthy);
    }

    // ── Sandbox constants tests ─────────────────────────────────────

    #[test]
    fn sandbox_profile_is_strict() {
        assert_eq!(BROWSER_SANDBOX_PROFILE, "strict");
    }

    #[test]
    fn sandbox_memory_is_1024() {
        assert_eq!(BROWSER_SANDBOX_MEMORY_MB, 1024);
    }

    #[test]
    fn sandbox_deny_exec_is_true() {
        assert!(BROWSER_SANDBOX_DENY_EXEC);
    }

    #[test]
    fn sandbox_deny_ptrace_is_true() {
        assert!(BROWSER_SANDBOX_DENY_PTRACE);
    }
}
