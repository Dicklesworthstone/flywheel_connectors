//! Square connector implementation.

use std::{
    sync::{OnceLock, atomic::Ordering},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use fcp_manifest::{ConnectorManifest, ManifestApprovalMode, OperationSection};
use fcp_prelude::{
    ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier, ConnectorId,
    EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse, HealthSnapshot,
    InstanceId, Introspection, InvokeRequest, InvokeResponse, OperationId, OperationInfo,
    SelfCheckReport, SessionId, ShutdownRequest, SimulateRequest, SimulateResponse,
};
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::prelude::*;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{client::SquareClient, error::SquareError, types::*};

#[cfg(test)]
use fcp_prelude::{IdempotencyClass, RiskLevel, SafetyTier};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const SQUARE_IMPLEMENTATION_STATUS: &str = "first_slice";
const SQUARE_BINDING_MODEL: &str = "merchant_scoped_seller_token";
const SQUARE_AUTH_MODEL: &str = "bearer_token_or_proxy_injected";
const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/square_connector_verification.sh";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/square_connector/<timestamp>";
const VERIFY_COMMANDS: [&str; 7] = [
    "scripts/e2e/square_connector_verification.sh",
    "fwc manifest fix connectors/square/manifest.toml --check --json",
    "rch exec -- cargo fmt --manifest-path connectors/square/Cargo.toml --check",
    "rch exec -- cargo check -p fcp-square --all-targets",
    "rch exec -- cargo test -p fcp-square --test integration -- --nocapture",
    "rch exec -- cargo test -p fcp-square -- --nocapture",
    "rch exec -- cargo clippy -p fcp-square --all-targets -- -D warnings",
];
const SQUARE_PRODUCTION_BASE_URL: &str = "https://connect.squareup.com/v2";
#[cfg(test)]
const SQUARE_SANDBOX_BASE_URL: &str = "https://connect.squareupsandbox.com/v2";
const SQUARE_ALLOWED_HOSTS: [&str; 2] = ["connect.squareup.com", "connect.squareupsandbox.com"];

// Operation IDs
const OP_PAYMENTS_LIST: &str = "square.payments.list";
const OP_PAYMENTS_GET: &str = "square.payments.get";
const OP_PAYMENTS_CREATE: &str = "square.payments.create";
const OP_PAYMENTS_REFUND: &str = "square.payments.refund";
const OP_ORDERS_LIST: &str = "square.orders.list";
const OP_ORDERS_GET: &str = "square.orders.get";
const OP_ORDERS_CREATE: &str = "square.orders.create";
const OP_CATALOG_LIST: &str = "square.catalog.list";
const OP_CUSTOMERS_LIST: &str = "square.customers.list";
const OP_CUSTOMERS_GET: &str = "square.customers.get";
const OP_LOCATIONS_LIST: &str = "square.locations.list";
const OP_HEALTH: &str = "square.health";
const OPERATION_ORDER: &[&str] = &[
    OP_PAYMENTS_LIST,
    OP_PAYMENTS_GET,
    OP_PAYMENTS_CREATE,
    OP_PAYMENTS_REFUND,
    OP_ORDERS_LIST,
    OP_ORDERS_GET,
    OP_ORDERS_CREATE,
    OP_CATALOG_LIST,
    OP_CUSTOMERS_LIST,
    OP_CUSTOMERS_GET,
    OP_LOCATIONS_LIST,
    OP_HEALTH,
];

// Capability IDs
const CAP_PAYMENTS_READ: &str = "square.payments.read";
const CAP_PAYMENTS_WRITE: &str = "square.payments.write";
const CAP_ORDERS_READ: &str = "square.orders.read";
const CAP_ORDERS_WRITE: &str = "square.orders.write";
const CAP_CATALOG_READ: &str = "square.catalog.read";
const CAP_CUSTOMERS_READ: &str = "square.customers.read";
const CAP_LOCATIONS_READ: &str = "square.locations.read";

/// Square connector configuration.
#[derive(Clone, Deserialize)]
struct SquareConfig {
    #[serde(default = "default_base_url")]
    base_url: String,
    access_token: String,
    #[serde(default)]
    retry: HttpRetryConfig,
    #[serde(default = "default_request_timeout_ms")]
    request_timeout_ms: u64,
}

impl std::fmt::Debug for SquareConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SquareConfig")
            .field("base_url", &self.base_url)
            .field("access_token", &"[REDACTED]")
            .field("retry", &self.retry)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

fn default_base_url() -> String {
    SQUARE_PRODUCTION_BASE_URL.into()
}

const fn default_request_timeout_ms() -> u64 {
    30_000
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1") || host.ends_with(".localhost")
}

fn normalize_square_base_url(base_url: &str) -> Result<String, String> {
    let parsed =
        reqwest::Url::parse(base_url).map_err(|e| format!("Invalid Square base_url: {e}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "Square base_url must include a host".to_string())?;
    let local_test_host = is_local_test_host(host);

    if !SQUARE_ALLOWED_HOSTS.contains(&host) && !local_test_host {
        return Err(format!(
            "Square base_url host must be connect.squareup.com, connect.squareupsandbox.com, or localhost for deterministic tests; got {host}"
        ));
    }
    if local_test_host {
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(
                "Square localhost test overrides must use http or https with a concrete port"
                    .into(),
            );
        }
    } else {
        if parsed.scheme() != "https" {
            return Err(
                "Square base_url must use https unless targeting a localhost test override".into(),
            );
        }
        if parsed.port_or_known_default() != Some(443) {
            return Err("Square base_url must use port 443".into());
        }
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err("Square base_url must not include query parameters or fragments".into());
    }
    let path = parsed.path().trim_end_matches('/');
    if path != "/v2" {
        return Err(format!(
            "Square base_url must be https://{host}/v2 for the selected environment"
        ));
    }

    if local_test_host {
        let authority = match parsed.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_string(),
        };
        Ok(format!("{}://{authority}/v2", parsed.scheme()))
    } else {
        Ok(format!("https://{host}/v2"))
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
    request_timeout_ms: u64,
    retry: RetryReadiness,
    merchant_scoped: bool,
    authenticated_identity_probe: &'static str,
    risky_mutations: Vec<&'static str>,
    read_inventory: Vec<&'static str>,
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

fn auth_mode_label(config: &SquareConfig) -> &'static str {
    if config.access_token.is_empty() {
        "proxy_injected"
    } else {
        "bearer_token"
    }
}

fn operator_guidance() -> OperatorGuidance {
    OperatorGuidance {
        prerequisites: vec![
            "Use a dedicated Square Sandbox seller account or a localhost deterministic HTTP override before running the verification bundle against payment or order mutations.",
            "Provision a bearer token that can read locations, payments, orders, catalog objects, and customers for the same seller boundary the connector will operate inside.",
            "Treat square.payments.create, square.payments.refund, and square.orders.create as real merchant mutations unless you are pointed at a localhost deterministic HTTP server.",
        ],
        dedicated_environment: "Prefer a Square Sandbox seller with disposable customers, locations, and catalog fixtures. Use localhost-only overrides for deterministic local HTTP verification and never point the closeout bundle at a production seller unless the resulting mutations are explicitly acceptable.",
        redaction_rules: vec![
            "Redact bearer tokens, Authorization headers, idempotency keys, and any copied request or response bodies before sharing artifacts.",
            "Treat payment IDs, refund IDs, order IDs, location IDs, customer IDs, receipt URLs, and business names as sensitive merchant data.",
            "If a live sandbox seller is used, sanitize location names, business metadata, and any customer-facing notes captured in payment or order artifacts.",
        ],
        limitations: vec![
            "One connector instance is bound to one Square seller token boundary; there is no cross-merchant brokering or automatic OAuth installation in this slice.",
            "Webhook ingestion, streaming events, invoice workflows, inventory adjustments, and customer mutation flows remain out of scope.",
            "Location scope still matters inside one seller boundary: order search requires explicit location_ids and many downstream workflows rely on locations returned by the readiness probe.",
        ],
        common_remediation: vec![
            RemediationHint {
                code: "not_configured",
                symptom: "health or self_check reports that the connector is not configured",
                action: "Configure base_url, token injection mode, timeout, and retry settings, then rerun the verification bundle.",
            },
            RemediationHint {
                code: "credential_injection_required",
                symptom: "self_check reports that an egress proxy must inject credentials",
                action: "Run the connector behind the expected credential-injection path or provide a direct Square bearer token for deterministic verification.",
            },
            RemediationHint {
                code: "square_auth_rejected",
                symptom: "Square returns HTTP 401 during health or self_check",
                action: "Replace the bearer token, confirm it matches the configured production or sandbox environment, and rerun self_check.",
            },
            RemediationHint {
                code: "square_permission_denied",
                symptom: "Square returns HTTP 403 for location or commerce inventory probes",
                action: "Grant the missing seller permissions for locations, payments, orders, catalog, and customer reads to the token, then rerun the bundle.",
            },
            RemediationHint {
                code: "square_locations_missing",
                symptom: "self_check succeeds technically but returns zero visible locations",
                action: "Verify the token is installed for the intended seller, confirm at least one active location exists, and rerun the verification bundle.",
            },
            RemediationHint {
                code: "self_check_retryable",
                symptom: "self_check degrades on timeout, rate limit, or temporary 5xx responses",
                action: "Respect Retry-After when present, widen retry or timeout settings for the environment, then rerun the verification bundle.",
            },
            RemediationHint {
                code: "network_constraints_invalid",
                symptom: "doctor reports that base_url falls outside the accepted Square hosts",
                action: "Use https://connect.squareup.com/v2 or https://connect.squareupsandbox.com/v2 for live verification, or a localhost /v2 override for deterministic local HTTP tests.",
            },
        ],
        rerun_commands: VERIFY_COMMANDS.to_vec(),
        artifact_root_hint: ARTIFACT_ROOT_HINT,
    }
}

fn contract_details(config: Option<&SquareConfig>) -> serde_json::Value {
    let credential_mode = config.map_or("unconfigured", auth_mode_label);

    json!({
        "connector_id": "fcp.square",
        "implementation_status": {
            "status": SQUARE_IMPLEMENTATION_STATUS,
            "binding_model": SQUARE_BINDING_MODEL,
            "auth_model": SQUARE_AUTH_MODEL,
        },
        "scope": {
            "credential_mode": credential_mode,
            "base_url": config.map(|cfg| cfg.base_url.clone()),
            "merchant_boundary": "Provider-enforced seller boundary; the connector does not broker multiple merchants from one instance.",
            "location_boundary": "Locations are discovered through the readiness probe and still gate order and payment workflows inside one seller boundary.",
            "localhost_test_override_supported": true,
        },
        "service_inventory": {
            "payments": [OP_PAYMENTS_LIST, OP_PAYMENTS_GET, OP_PAYMENTS_CREATE, OP_PAYMENTS_REFUND],
            "orders": [OP_ORDERS_LIST, OP_ORDERS_GET, OP_ORDERS_CREATE],
            "catalog": [OP_CATALOG_LIST],
            "customers": [OP_CUSTOMERS_LIST, OP_CUSTOMERS_GET],
            "locations": [OP_LOCATIONS_LIST, OP_HEALTH],
        },
        "non_goals": [
            "oauth_install",
            "token_refresh",
            "webhook_ingest",
            "invoice_workflows",
            "inventory_adjustment",
            "customer_mutation",
        ],
    })
}

/// Square connector state.
#[derive(Debug)]
pub struct SquareConnector {
    base: BaseConnector,
    config: Option<SquareConfig>,
    client: Option<SquareClient>,
    runtime: Option<ConnectorRuntime>,
    retry_config: HttpRetryConfig,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl SquareConnector {
    /// Create a new connector instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.square")),
            config: None,
            client: None,
            runtime: None,
            retry_config: HttpRetryConfig::default(),
            started_at: Instant::now(),
            verifier: None,
        }
    }

    /// Return this connector instance id for bound capability-token tests.
    #[must_use]
    pub const fn instance_id(&self) -> &InstanceId {
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
            request_timeout_ms: config.request_timeout_ms,
            retry: RetryReadiness {
                max_retries: config.retry.max_retries,
                initial_delay_ms: config.retry.initial_delay_ms,
                max_delay_ms: config.retry.max_delay_ms,
                jitter_enabled: config.retry.jitter_enabled,
            },
            merchant_scoped: true,
            authenticated_identity_probe: "GET /locations",
            risky_mutations: vec![OP_PAYMENTS_CREATE, OP_PAYMENTS_REFUND, OP_ORDERS_CREATE],
            read_inventory: vec![
                OP_LOCATIONS_LIST,
                OP_PAYMENTS_LIST,
                OP_ORDERS_LIST,
                OP_CATALOG_LIST,
                OP_CUSTOMERS_LIST,
            ],
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
            let scheme = if config.base_url.starts_with("https://") {
                "https"
            } else {
                "http"
            };
            checks.push(DoctorCheck {
                name: "base_url".into(),
                passed: true,
                message: Some(format!("Base URL ({scheme}): {}", config.base_url)),
                critical: false,
            });

            let normalized_base_url = normalize_square_base_url(&config.base_url);
            let network_ok = normalized_base_url.is_ok();
            checks.push(DoctorCheck {
                name: "network_constraints".into(),
                passed: network_ok,
                message: Some(match normalized_base_url {
                    Ok(base_url) => {
                        if is_local_test_host(host_from_base_url(&base_url)) {
                            format!(
                                "Base URL matches a localhost test override for deterministic verification: {base_url}"
                            )
                        } else {
                            format!("Base URL matches required Square REST base: {base_url}")
                        }
                    }
                    Err(err) => err,
                }),
                critical: true,
            });

            let secretless = self.client.as_ref().is_some_and(|c| c.is_secretless());
            checks.push(DoctorCheck {
                name: "credential_mode".into(),
                passed: !secretless,
                message: Some(if secretless {
                    "Credential injection required via egress proxy".into()
                } else {
                    "Bearer access token configured".into()
                }),
                critical: false,
            });

            checks.push(DoctorCheck {
                name: "timeout_budget".into(),
                passed: config.request_timeout_ms > 0,
                message: Some(format!(
                    "Request timeout budget set to {}ms",
                    config.request_timeout_ms
                )),
                critical: true,
            });
            checks.push(DoctorCheck {
                name: "retry_policy".into(),
                passed: true,
                message: Some(format!(
                    "Retry policy: max_retries={}, initial_delay_ms={}, max_delay_ms={}, jitter_enabled={}",
                    config.retry.max_retries,
                    config.retry.initial_delay_ms,
                    config.retry.max_delay_ms,
                    config.retry.jitter_enabled
                )),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "auth_boundary".into(),
                passed: true,
                message: Some(
                    "Square access is scoped to one seller token boundary; the connector does not span multiple merchants from one instance."
                        .into(),
                ),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "location_scope".into(),
                passed: true,
                message: Some(
                    "Location visibility is part of readiness. Orders require explicit location_ids and payment workflows may still depend on the seller's visible locations."
                        .into(),
                ),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "service_inventory".into(),
                passed: true,
                message: Some(
                    "Supported today: payments, refunds, orders, catalog reads, customer reads, location discovery, and readiness probes."
                        .into(),
                ),
                critical: false,
            });
        }

        DoctorResult::from_checks(checks, provisioning)
    }
}

impl Default for SquareConnector {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the typed operations catalog from the strict manifest.
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
        .expect("embedded Square manifest should validate");
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

fcp_core::impl_fcp_sealed!(SquareConnector);

#[async_trait]
impl FcpConnector for SquareConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let mut config: SquareConfig =
            serde_json::from_value(config).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid Square config: {e}"),
            })?;
        if config.request_timeout_ms == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "Square request_timeout_ms must be greater than 0".into(),
            });
        }
        {
            let SquareConfig {
                access_token: auth_slot,
                ..
            } = &mut config;
            let raw_auth = std::mem::take(auth_slot);
            auth_slot.push_str(raw_auth.trim());
        }
        config.base_url = normalize_square_base_url(&config.base_url).map_err(|message| {
            FcpError::InvalidRequest {
                code: 1001,
                message,
            }
        })?;

        self.retry_config = config.retry.clone();
        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(config.request_timeout_ms)),
        ));

        let client =
            SquareClient::new(&config.base_url, &config.access_token, config.retry.clone())
                .map_err(|e| FcpError::Internal {
                    message: format!("Failed to create Square client: {e}"),
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
        let provisioning = self.provisioning_readiness();
        let mut snapshot = match &self.client {
            None if self.config.is_none() => HealthSnapshot::degraded("not configured"),
            None => HealthSnapshot::error("Square client not initialized"),
            Some(_) if self.runtime.is_none() => HealthSnapshot::error("runtime not initialized"),
            Some(client) if client.is_secretless() => {
                HealthSnapshot::degraded("credential injection required")
            }
            Some(_) => HealthSnapshot::ready(),
        };
        snapshot.uptime_ms =
            u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        snapshot.details = Some(json!({
            "configured": self.config.is_some(),
            "client_initialized": self.client.is_some(),
            "runtime_initialized": self.runtime.is_some(),
            "handshaken": self.base.handshaken.load(Ordering::Acquire),
            "manifest_hash": Self::manifest_hash(),
            "verification_script": VERIFICATION_SCRIPT_PATH,
            "artifact_root_hint": ARTIFACT_ROOT_HINT,
            "provisioning": provisioning,
            "operator_guidance": operator_guidance(),
            "contract": contract_details(self.config.as_ref()),
        }));
        snapshot
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(client) = &self.client else {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::degraded("not_configured", "Connector is not configured"),
                Some(&json!({
                    "configured": false,
                })),
            ));
        };

        let Some(runtime) = &self.runtime else {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::failed("runtime_missing", "Connector runtime is not initialized"),
                Some(&json!({
                    "api_base_url": client.base_url(),
                })),
            ));
        };

        if client.is_secretless() {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::degraded(
                    "credential_injection_required",
                    "Configured with empty token; egress proxy injection required",
                ),
                Some(&json!({
                    "api_base_url": client.base_url(),
                    "credential_mode": "proxy_injected",
                })),
            ));
        }

        match client.list_locations(runtime).await {
            Ok(locations) => {
                let live_probe = json!({
                    "api_reachable": true,
                    "api_base_url": client.base_url(),
                    "location_count": locations.locations.len(),
                    "location_ids": locations
                        .locations
                        .iter()
                        .filter_map(|location| location.id.clone())
                        .collect::<Vec<_>>(),
                    "location_names": locations
                        .locations
                        .iter()
                        .filter_map(|location| location.name.clone())
                        .collect::<Vec<_>>(),
                });

                if locations.locations.is_empty() {
                    Ok(self.attach_self_check_details(
                        SelfCheckReport::degraded(
                            "square_locations_missing",
                            "Square returned zero visible locations for the configured seller token",
                        ),
                        Some(&live_probe),
                    ))
                } else {
                    Ok(self.attach_self_check_details(SelfCheckReport::ok(), Some(&live_probe)))
                }
            }
            Err(SquareError::Unauthorized(message)) => Ok(self.attach_self_check_details(
                SelfCheckReport::failed("square_auth_rejected", message),
                Some(&json!({
                    "api_base_url": client.base_url(),
                    "api_reachable": false,
                })),
            )),
            Err(SquareError::Api { code: 403, message }) => Ok(self.attach_self_check_details(
                SelfCheckReport::failed("square_permission_denied", message),
                Some(&json!({
                    "api_base_url": client.base_url(),
                    "api_reachable": false,
                    "status_code": 403,
                })),
            )),
            Err(err) if err.is_retryable() => Ok(self.attach_self_check_details(
                SelfCheckReport::degraded("self_check_retryable", err.to_string()),
                Some(&json!({
                    "api_base_url": client.base_url(),
                    "api_reachable": false,
                })),
            )),
            Err(err) => Ok(self.attach_self_check_details(
                SelfCheckReport::failed("self_check_failed", err.to_string()),
                Some(&json!({
                    "api_base_url": client.base_url(),
                    "api_reachable": false,
                })),
            )),
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

impl SquareConnector {
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();

        let verifier = self.verifier.as_ref().ok_or(FcpError::Internal {
            message: "Capability verifier missing after successful handshake".into(),
        })?;
        let required_cap = match operation {
            OP_PAYMENTS_LIST | OP_PAYMENTS_GET => CapabilityId::from_static(CAP_PAYMENTS_READ),
            OP_PAYMENTS_CREATE | OP_PAYMENTS_REFUND => {
                CapabilityId::from_static(CAP_PAYMENTS_WRITE)
            }
            OP_ORDERS_LIST | OP_ORDERS_GET => CapabilityId::from_static(CAP_ORDERS_READ),
            OP_ORDERS_CREATE => CapabilityId::from_static(CAP_ORDERS_WRITE),
            OP_CATALOG_LIST => CapabilityId::from_static(CAP_CATALOG_READ),
            OP_CUSTOMERS_LIST | OP_CUSTOMERS_GET => CapabilityId::from_static(CAP_CUSTOMERS_READ),
            OP_LOCATIONS_LIST | OP_HEALTH => CapabilityId::from_static(CAP_LOCATIONS_READ),
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };
        let _bound =
            verifier.verify_bound(req.capability_token, &required_cap, &req.operation, &[])?;

        let runtime = self.runtime.as_ref().ok_or(FcpError::Internal {
            message: "Connector runtime missing after configure".into(),
        })?;
        let client = self.client.as_ref().ok_or(FcpError::Internal {
            message: "Square client missing after configure".into(),
        })?;

        let output = match operation {
            OP_PAYMENTS_LIST => {
                let cursor = req.input.get("cursor").and_then(|v| v.as_str());
                let location_id = req.input.get("location_id").and_then(|v| v.as_str());
                let list = client
                    .list_payments(runtime, cursor, location_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(list).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize: {e}"),
                })?
            }
            OP_PAYMENTS_GET => {
                let payment_id = req.input.get("payment_id").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'payment_id' field".into(),
                    },
                )?;
                let resp = client
                    .get_payment(runtime, payment_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize: {e}"),
                })?
            }
            OP_PAYMENTS_CREATE => {
                let source_id = req.input.get("source_id").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'source_id' field".into(),
                    },
                )?;
                let idempotency_key = req
                    .input
                    .get("idempotency_key")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'idempotency_key' field".into(),
                    })?;
                let amount_money_val =
                    req.input
                        .get("amount_money")
                        .ok_or(FcpError::InvalidRequest {
                            code: 1005,
                            message: "Missing 'amount_money' field".into(),
                        })?;
                let amount_money: Money = serde_json::from_value(amount_money_val.clone())
                    .map_err(|e| FcpError::InvalidRequest {
                        code: 1005,
                        message: format!("Invalid 'amount_money': {e}"),
                    })?;

                let create_req = CreatePaymentRequest {
                    source_id: source_id.to_string(),
                    idempotency_key: idempotency_key.to_string(),
                    amount_money,
                    location_id: req
                        .input
                        .get("location_id")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    customer_id: req
                        .input
                        .get("customer_id")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    note: req
                        .input
                        .get("note")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                };

                let resp = client
                    .create_payment(runtime, &create_req)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize: {e}"),
                })?
            }
            OP_PAYMENTS_REFUND => {
                let idempotency_key = req
                    .input
                    .get("idempotency_key")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'idempotency_key' field".into(),
                    })?;
                let payment_id = req.input.get("payment_id").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'payment_id' field".into(),
                    },
                )?;
                let amount_money_val =
                    req.input
                        .get("amount_money")
                        .ok_or(FcpError::InvalidRequest {
                            code: 1005,
                            message: "Missing 'amount_money' field".into(),
                        })?;
                let amount_money: Money = serde_json::from_value(amount_money_val.clone())
                    .map_err(|e| FcpError::InvalidRequest {
                        code: 1005,
                        message: format!("Invalid 'amount_money': {e}"),
                    })?;

                let refund_req = RefundPaymentRequest {
                    idempotency_key: idempotency_key.to_string(),
                    payment_id: payment_id.to_string(),
                    amount_money,
                    reason: req
                        .input
                        .get("reason")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                };

                let resp = client
                    .refund_payment(runtime, &refund_req)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize: {e}"),
                })?
            }
            OP_ORDERS_LIST => {
                let location_ids_val =
                    req.input
                        .get("location_ids")
                        .ok_or(FcpError::InvalidRequest {
                            code: 1005,
                            message: "Missing 'location_ids' field".into(),
                        })?;
                let location_ids: Vec<String> = serde_json::from_value(location_ids_val.clone())
                    .map_err(|e| FcpError::InvalidRequest {
                        code: 1005,
                        message: format!("Invalid 'location_ids': {e}"),
                    })?;
                let cursor = req.input.get("cursor").and_then(|v| v.as_str());

                let list = client
                    .list_orders(runtime, &location_ids, cursor)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(list).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize: {e}"),
                })?
            }
            OP_ORDERS_GET => {
                let order_id = req.input.get("order_id").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'order_id' field".into(),
                    },
                )?;
                let resp = client
                    .get_order(runtime, order_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize: {e}"),
                })?
            }
            OP_ORDERS_CREATE => {
                let location_id = req
                    .input
                    .get("location_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'location_id' field".into(),
                    })?;
                let line_items_val =
                    req.input
                        .get("line_items")
                        .ok_or(FcpError::InvalidRequest {
                            code: 1005,
                            message: "Missing 'line_items' field".into(),
                        })?;
                let line_items: Vec<OrderLineItemInput> =
                    serde_json::from_value(line_items_val.clone()).map_err(|e| {
                        FcpError::InvalidRequest {
                            code: 1005,
                            message: format!("Invalid 'line_items': {e}"),
                        }
                    })?;

                let create_req = CreateOrderRequest {
                    order: OrderInput {
                        location_id: location_id.to_string(),
                        line_items,
                    },
                    idempotency_key: req
                        .input
                        .get("idempotency_key")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                };

                let resp = client
                    .create_order(runtime, &create_req)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize: {e}"),
                })?
            }
            OP_CATALOG_LIST => {
                let cursor = req.input.get("cursor").and_then(|v| v.as_str());
                let types = req.input.get("types").and_then(|v| v.as_str());
                let list = client
                    .list_catalog(runtime, cursor, types)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(list).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize: {e}"),
                })?
            }
            OP_CUSTOMERS_LIST => {
                let cursor = req.input.get("cursor").and_then(|v| v.as_str());
                let list = client
                    .list_customers(runtime, cursor)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(list).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize: {e}"),
                })?
            }
            OP_CUSTOMERS_GET => {
                let customer_id = req
                    .input
                    .get("customer_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'customer_id' field".into(),
                    })?;
                let resp = client
                    .get_customer(runtime, customer_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize: {e}"),
                })?
            }
            OP_LOCATIONS_LIST => {
                let list = client
                    .list_locations(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(list).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize: {e}"),
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

fn host_from_base_url(base_url: &str) -> &str {
    base_url
        .split("://")
        .nth(1)
        .unwrap_or("")
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use fcp_manifest::ConnectorManifest;

    fn all_caps() -> Vec<CapabilityId> {
        vec![
            CapabilityId::from_static(CAP_PAYMENTS_READ),
            CapabilityId::from_static(CAP_PAYMENTS_WRITE),
            CapabilityId::from_static(CAP_ORDERS_READ),
            CapabilityId::from_static(CAP_ORDERS_WRITE),
            CapabilityId::from_static(CAP_CATALOG_READ),
            CapabilityId::from_static(CAP_CUSTOMERS_READ),
            CapabilityId::from_static(CAP_LOCATIONS_READ),
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

    fn test_config() -> serde_json::Value {
        json!({
            "access_token": "test_square_token"
        })
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = SquareConnector::new();
        let result = connector.handshake(base_handshake()).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_valid() {
        let mut connector = SquareConnector::new();
        let result = connector.configure(test_config()).await;
        assert!(result.is_ok());
        assert!(connector.config.is_some());
        assert!(connector.client.is_some());
        assert!(connector.runtime.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_missing_fields() {
        let mut connector = SquareConnector::new();
        let result = connector.configure(json!({})).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_before_configure() {
        let connector = SquareConnector::new();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Degraded { .. }));
        let details = health.details.expect("health details");
        assert_eq!(details["verification_script"], VERIFICATION_SCRIPT_PATH);
        assert_eq!(details["artifact_root_hint"], ARTIFACT_ROOT_HINT);
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_after_configure() {
        let mut connector = SquareConnector::new();
        connector.configure(test_config()).await.unwrap();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Ready));
    }

    #[test]
    fn test_doctor_before_configure() {
        let connector = SquareConnector::new();
        let report = connector.doctor();
        assert!(!report.ready);
        assert!(!report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_after_configure() {
        let mut connector = SquareConnector::new();
        connector.configure(test_config()).await.unwrap();
        let report = connector.doctor();
        assert!(report.ready);
        assert!(report.passed);
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.name == "network_constraints" && check.passed)
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_accepts_sandbox_base_url() {
        let mut connector = SquareConnector::new();
        connector
            .configure(json!({
                "base_url": SQUARE_SANDBOX_BASE_URL,
                "access_token": "test_square_token"
            }))
            .await
            .unwrap();
        let report = connector.doctor();
        assert!(report.ready);
        assert!(report.passed);
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.name == "network_constraints" && check.passed)
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_accepts_localhost_test_override() {
        let mut connector = SquareConnector::new();
        connector
            .configure(json!({
                "base_url": "http://127.0.0.1:8080/v2",
                "access_token": "test_square_token"
            }))
            .await
            .unwrap();
        let report = connector.doctor();
        assert!(report.ready);
        assert!(report.checks.iter().any(|check| {
            check.name == "network_constraints"
                && check
                    .message
                    .as_deref()
                    .is_some_and(|message| message.contains("localhost test override"))
        }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_http_base_url() {
        let mut connector = SquareConnector::new();
        let err = connector
            .configure(json!({
                "base_url": "http://connect.squareup.com/v2",
                "access_token": "test_square_token"
            }))
            .await
            .unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_zero_timeout() {
        let mut connector = SquareConnector::new();
        let err = connector
            .configure(json!({
                "access_token": "test_square_token",
                "request_timeout_ms": 0
            }))
            .await
            .unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_missing_v2_base_path() {
        let mut connector = SquareConnector::new();
        let err = connector
            .configure(json!({
                "base_url": "https://connect.squareup.com",
                "access_token": "test_square_token"
            }))
            .await
            .unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_normalizes_trailing_slash_on_base_url() {
        let mut connector = SquareConnector::new();
        connector
            .configure(json!({
                "base_url": "https://connect.squareupsandbox.com/v2/",
                "access_token": "test_square_token"
            }))
            .await
            .unwrap();
        let report = connector.doctor();
        assert!(report.passed);
        assert!(report.checks.iter().any(|check| check.name == "base_url"
            && check.message.as_deref()
                == Some("Base URL (https): https://connect.squareupsandbox.com/v2")));
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_before_configure() {
        let connector = SquareConnector::new();
        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
        let details = report.details.expect("self_check details");
        assert_eq!(details["verification_script"], VERIFICATION_SCRIPT_PATH);
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate() {
        let connector = SquareConnector::new();
        let req = SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(OP_PAYMENTS_LIST),
            ZoneId::work(),
            json!({}),
            CapabilityToken::test_token(),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(resp.would_succeed);
    }

    #[test]
    fn test_introspection_operations() {
        let connector = SquareConnector::new();
        let intro = connector.introspect();
        assert_eq!(intro.operations.len(), 12);
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_PAYMENTS_LIST)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_PAYMENTS_GET)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_PAYMENTS_CREATE)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_PAYMENTS_REFUND)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_ORDERS_LIST)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_ORDERS_GET)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_ORDERS_CREATE)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_CATALOG_LIST)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_CUSTOMERS_LIST)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_CUSTOMERS_GET)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_LOCATIONS_LIST)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_HEALTH)
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_unknown_operation() {
        let mut connector = SquareConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), "square.nonexistent");
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_configure() {
        let connector = SquareConnector::new();
        let req = base_invoke(connector.id(), OP_PAYMENTS_LIST);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_before_handshake_returns_not_handshaken() {
        let mut connector = SquareConnector::new();
        connector.configure(test_config()).await.unwrap();
        let result = connector
            .invoke(base_invoke(connector.id(), OP_PAYMENTS_LIST))
            .await;
        assert!(matches!(result, Err(FcpError::NotHandshaken)));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_payments_get_missing_id() {
        let mut connector = SquareConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_PAYMENTS_GET);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_payments_create_missing_source_id() {
        let mut connector = SquareConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_PAYMENTS_CREATE);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_refund_missing_fields() {
        let mut connector = SquareConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_PAYMENTS_REFUND);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_orders_list_missing_location_ids() {
        let mut connector = SquareConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_ORDERS_LIST);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_orders_get_missing_id() {
        let mut connector = SquareConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_ORDERS_GET);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_orders_create_missing_fields() {
        let mut connector = SquareConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_ORDERS_CREATE);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_customers_get_missing_id() {
        let mut connector = SquareConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_CUSTOMERS_GET);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_operations_info_count() {
        let ops = operations_info();
        assert_eq!(ops.len(), OPERATION_ORDER.len());
    }

    #[test]
    fn test_operations_have_ai_hints() {
        let ops = operations_info();
        for op in &ops {
            assert!(!op.ai_hints.when_to_use.is_empty());
        }
    }

    #[test]
    fn test_payments_list_is_safe() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_PAYMENTS_LIST)
            .unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Safe);
        assert_eq!(op.risk_level, RiskLevel::Low);
        assert_eq!(op.idempotency, IdempotencyClass::Strict);
        assert_eq!(op.requires_approval, None);
    }

    #[test]
    fn test_payments_create_is_risky_high() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_PAYMENTS_CREATE)
            .unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Risky);
        assert_eq!(op.risk_level, RiskLevel::High);
        assert_eq!(op.idempotency, IdempotencyClass::Strict);
        assert_eq!(op.requires_approval, Some(ApprovalMode::Interactive));
    }

    #[test]
    fn test_payments_refund_is_risky_high() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_PAYMENTS_REFUND)
            .unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Risky);
        assert_eq!(op.risk_level, RiskLevel::High);
        assert_eq!(op.requires_approval, Some(ApprovalMode::Interactive));
    }

    #[test]
    fn test_orders_create_contract_semantics() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_ORDERS_CREATE)
            .unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Risky);
        assert_eq!(op.risk_level, RiskLevel::Medium);
        assert_eq!(op.idempotency, IdempotencyClass::BestEffort);
        assert_eq!(op.requires_approval, Some(ApprovalMode::Interactive));
    }

    #[test]
    fn test_manifest_hash_deterministic() {
        let hash1 = SquareConnector::manifest_hash();
        let hash2 = SquareConnector::manifest_hash();
        assert_eq!(hash1, hash2);
        assert!(hash1.starts_with("sha256:"));
    }

    #[test]
    fn manifest_interface_hash_is_deterministic() {
        let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("manifest.toml");
        if !manifest_path.exists() {
            eprintln!("manifest.toml missing; skipping interface_hash check");
            return;
        }

        let raw = std::fs::read_to_string(&manifest_path).expect("read manifest");
        let manifest = ConnectorManifest::parse_str_unchecked(&raw).expect("parse unchecked");
        let computed = manifest
            .compute_interface_hash()
            .expect("compute interface hash");
        assert_eq!(
            manifest.manifest.interface_hash, computed,
            "update connectors/square/manifest.toml interface_hash to {computed}"
        );

        let manifest2 = ConnectorManifest::parse_str(&raw).expect("manifest should validate");
        let computed2 = manifest2
            .compute_interface_hash()
            .expect("compute interface hash");
        assert_eq!(computed, computed2);
    }

    #[test]
    fn runtime_operation_catalog_matches_manifest_metadata() {
        let manifest =
            ConnectorManifest::parse_str(MANIFEST_TOML).expect("manifest should validate");
        let operations = operations_info();
        assert_eq!(operations.len(), OPERATION_ORDER.len());

        for (index, operation) in operations.iter().enumerate() {
            assert_eq!(operation.id.as_str(), OPERATION_ORDER[index]);
            let manifest_operation = manifest
                .provides
                .operations
                .get(operation.id.as_str())
                .expect("runtime operation should come from manifest");
            assert_eq!(operation.summary, manifest_operation.description);
            assert_eq!(
                operation.description.as_ref(),
                Some(&manifest_operation.description)
            );
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
            let runtime_rate_limit = operation
                .rate_limit
                .as_ref()
                .map(serde_json::to_value)
                .transpose()
                .expect("runtime rate limit should serialize");
            let manifest_rate_limit = manifest_operation
                .rate_limit
                .as_ref()
                .map(|rate_limit| serde_json::to_value(&rate_limit.0))
                .transpose()
                .expect("manifest rate limit should serialize");
            assert_eq!(runtime_rate_limit, manifest_rate_limit);
        }
    }

    #[test]
    fn manifest_schema_is_runtime_introspection_schema() {
        let manifest =
            ConnectorManifest::parse_str(MANIFEST_TOML).expect("manifest should validate");
        for operation in operations_info() {
            let manifest_operation = manifest
                .provides
                .operations
                .get(operation.id.as_str())
                .expect("runtime operation should come from manifest");
            assert_eq!(operation.input_schema, manifest_operation.input_schema);
            assert_eq!(operation.output_schema, manifest_operation.output_schema);
        }
    }

    #[test]
    fn test_streaming_not_supported() {
        let connector = SquareConnector::new();
        let intro = connector.introspect();
        assert!(!intro.event_caps.as_ref().unwrap().streaming);
    }

    #[test]
    fn debug_redacts_config_secrets() {
        let config = SquareConfig {
            base_url: default_base_url(),
            access_token: "secret_square_token".into(),
            retry: HttpRetryConfig::default(),
            request_timeout_ms: default_request_timeout_ms(),
        };
        let debug_output = format!("{config:?}");
        assert!(!debug_output.contains("secret_square_token"));
        assert!(debug_output.contains("[REDACTED]"));
    }

    #[test]
    fn test_health_op_is_safe_with_strict_idempotency() {
        let ops = operations_info();
        let op = ops.iter().find(|op| op.id.as_str() == OP_HEALTH).unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Safe);
        assert_eq!(op.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn test_default_connector() {
        let connector = SquareConnector::default();
        assert_eq!(connector.id().as_str(), "fcp.square");
    }

    #[test]
    fn test_capability_mapping() {
        let ops = operations_info();
        let payments_list = ops
            .iter()
            .find(|op| op.id.as_str() == OP_PAYMENTS_LIST)
            .unwrap();
        assert_eq!(payments_list.capability.as_str(), CAP_PAYMENTS_READ);

        let payments_create = ops
            .iter()
            .find(|op| op.id.as_str() == OP_PAYMENTS_CREATE)
            .unwrap();
        assert_eq!(payments_create.capability.as_str(), CAP_PAYMENTS_WRITE);

        let orders_list = ops
            .iter()
            .find(|op| op.id.as_str() == OP_ORDERS_LIST)
            .unwrap();
        assert_eq!(orders_list.capability.as_str(), CAP_ORDERS_READ);

        let catalog = ops
            .iter()
            .find(|op| op.id.as_str() == OP_CATALOG_LIST)
            .unwrap();
        assert_eq!(catalog.capability.as_str(), CAP_CATALOG_READ);

        let customers = ops
            .iter()
            .find(|op| op.id.as_str() == OP_CUSTOMERS_LIST)
            .unwrap();
        assert_eq!(customers.capability.as_str(), CAP_CUSTOMERS_READ);

        let locations = ops
            .iter()
            .find(|op| op.id.as_str() == OP_LOCATIONS_LIST)
            .unwrap();
        assert_eq!(locations.capability.as_str(), CAP_LOCATIONS_READ);

        let health = ops.iter().find(|op| op.id.as_str() == OP_HEALTH).unwrap();
        assert_eq!(health.capability.as_str(), CAP_LOCATIONS_READ);
    }

    #[test]
    fn test_orders_create_is_risky() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_ORDERS_CREATE)
            .unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Risky);
        assert_eq!(op.risk_level, RiskLevel::Medium);
        assert_eq!(op.idempotency, IdempotencyClass::BestEffort);
        assert_eq!(op.requires_approval, Some(ApprovalMode::Interactive));
    }
}
