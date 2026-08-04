//! Hacker News connector implementation.

use std::sync::OnceLock;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcp_manifest::{ConnectorManifest, ManifestApprovalMode, OperationSection};
use fcp_prelude::{
    ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier, ConnectorId,
    EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse, HealthSnapshot,
    InstanceId, Introspection, InvokeRequest, InvokeResponse, OperationId, OperationInfo,
    ResourceTypeInfo, SelfCheckReport, SessionId, ShutdownRequest, SimulateRequest,
    SimulateResponse,
};
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::prelude::*;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::client::HackerNewsClient;
use crate::error::HackerNewsError;

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const DEFAULT_BASE_URL: &str = "https://hacker-news.firebaseio.com/v0";

// Operation IDs
const OP_ITEM_GET: &str = "hackernews.item.get";
const OP_USER_GET: &str = "hackernews.user.get";
const OP_TOP_STORIES: &str = "hackernews.top_stories";
const OP_NEW_STORIES: &str = "hackernews.new_stories";
const OP_BEST_STORIES: &str = "hackernews.best_stories";
const OP_ASK_STORIES: &str = "hackernews.ask_stories";
const OP_SHOW_STORIES: &str = "hackernews.show_stories";
const OP_JOB_STORIES: &str = "hackernews.job_stories";
const OP_HEALTH: &str = "hackernews.health";
const OPERATION_ORDER: [&str; 9] = [
    OP_ITEM_GET,
    OP_USER_GET,
    OP_TOP_STORIES,
    OP_NEW_STORIES,
    OP_BEST_STORIES,
    OP_ASK_STORIES,
    OP_SHOW_STORIES,
    OP_JOB_STORIES,
    OP_HEALTH,
];

// Capability IDs
const CAP_READ: &str = "hackernews.read";
const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/hackernews_connector_verification.sh";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/hackernews_connector/<timestamp>";
const VERIFY_COMMANDS: [&str; 11] = [
    "scripts/e2e/hackernews_connector_verification.sh",
    "rch exec -- env RUSTUP_TOOLCHAIN=nightly-2026-02-19 cargo run -q -p fwc -- manifest fix connectors/hackernews/manifest.toml --check --json",
    "rch exec -- env RUSTUP_TOOLCHAIN=nightly-2026-02-19 cargo fmt --manifest-path connectors/hackernews/Cargo.toml --check",
    "rch exec -- env RUSTUP_TOOLCHAIN=nightly-2026-02-19 cargo check -p fcp-hackernews --all-targets",
    "rch exec -- env RUSTUP_TOOLCHAIN=nightly-2026-02-19 cargo test -p fcp-hackernews --test integration health_unconfigured_includes_guidance -- --nocapture",
    "rch exec -- env RUSTUP_TOOLCHAIN=nightly-2026-02-19 cargo test -p fcp-hackernews --test integration doctor_unconfigured_reports_operator_guidance -- --nocapture",
    "rch exec -- env RUSTUP_TOOLCHAIN=nightly-2026-02-19 cargo test -p fcp-hackernews --test integration self_check_ready_with_public_probe_and_evidence -- --nocapture",
    "rch exec -- env RUSTUP_TOOLCHAIN=nightly-2026-02-19 cargo test -p fcp-hackernews --test integration self_check_retryable_api_failure_reports_degraded -- --nocapture",
    "rch exec -- env RUSTUP_TOOLCHAIN=nightly-2026-02-19 cargo test -p fcp-hackernews --test integration invoke_item_get_preserves_public_item_evidence -- --nocapture",
    "rch exec -- env RUSTUP_TOOLCHAIN=nightly-2026-02-19 cargo test -p fcp-hackernews --test integration introspection_emits_v3_compliance_evidence -- --nocapture",
    "rch exec -- env RUSTUP_TOOLCHAIN=nightly-2026-02-19 cargo clippy -p fcp-hackernews --all-targets -- -D warnings",
];

/// Hacker News connector configuration.
/// Auth is optional since HN API is entirely public.
#[derive(Clone, Deserialize)]
struct HackerNewsConfig {
    /// Optional custom base URL (defaults to Firebase HN API).
    #[serde(default)]
    base_url: Option<String>,
    #[serde(default)]
    retry: HttpRetryConfig,
    #[serde(default = "default_request_timeout_ms")]
    request_timeout_ms: u64,
}

impl std::fmt::Debug for HackerNewsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HackerNewsConfig")
            .field("base_url", &self.base_url)
            .field("retry", &self.retry)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

const fn default_request_timeout_ms() -> u64 {
    30_000
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
    provider: &'static str,
    base_url: String,
    auth_mode: &'static str,
    request_timeout_ms: u64,
    retry: RetryReadiness,
    item_lookup: bool,
    user_lookup: bool,
    feed_snapshots: Vec<&'static str>,
    search_supported: bool,
    write_supported: bool,
    streaming_supported: bool,
    comment_tree_expansion_supported: bool,
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

/// Hacker News connector state.
#[derive(Debug)]
pub struct HackerNewsConnector {
    base: BaseConnector,
    config: Option<HackerNewsConfig>,
    client: Option<HackerNewsClient>,
    runtime: Option<ConnectorRuntime>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl HackerNewsConnector {
    /// Create a new connector instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.hackernews")),
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

    fn resolved_base_url(&self) -> Option<String> {
        self.client
            .as_ref()
            .map(|client| client.base_url().to_string())
            .or_else(|| {
                self.config.as_ref().map(|config| {
                    config
                        .base_url
                        .as_deref()
                        .unwrap_or(DEFAULT_BASE_URL)
                        .trim_end_matches('/')
                        .to_string()
                })
            })
    }

    fn provisioning_readiness(&self) -> Option<ProvisioningReadiness> {
        self.config.as_ref().map(|config| ProvisioningReadiness {
            provider: "hacker_news_firebase",
            base_url: self
                .resolved_base_url()
                .unwrap_or_else(|| DEFAULT_BASE_URL.to_string()),
            auth_mode: "anonymous_public_api",
            request_timeout_ms: config.request_timeout_ms,
            retry: RetryReadiness {
                max_retries: config.retry.max_retries,
                initial_delay_ms: config.retry.initial_delay_ms,
                max_delay_ms: config.retry.max_delay_ms,
                jitter_enabled: config.retry.jitter_enabled,
            },
            item_lookup: true,
            user_lookup: true,
            feed_snapshots: vec!["top", "new", "best", "ask", "show", "job"],
            search_supported: false,
            write_supported: false,
            streaming_supported: false,
            comment_tree_expansion_supported: false,
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
            "live_probe": live_probe,
            "operator_guidance": operator_guidance(),
        }));
        report
    }

    fn health_probe_details(
        client: &HackerNewsClient,
        retryable: bool,
        error: Option<&str>,
        retry_after_ms: Option<u64>,
    ) -> serde_json::Value {
        let base_url = client.base_url();
        json!({
            "base_url": base_url,
            "health_endpoint": format!("{base_url}/topstories.json"),
            "auth_mode": "anonymous_public_api",
            "surface_mode": "public_read_only",
            "search_supported": false,
            "write_supported": false,
            "retryable": retryable,
            "error": error,
            "retry_after_ms": retry_after_ms,
        })
    }

    /// Run connector diagnostics.
    pub fn doctor(&self) -> DoctorResult {
        let provisioning = self.provisioning_readiness();
        let mut checks = Vec::new();

        // Configuration is always "passed" since HN has no required auth
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

        checks.push(DoctorCheck {
            name: "auth".into(),
            passed: true,
            message: Some("No authentication required (public API)".into()),
            critical: false,
        });

        if let Some(client) = &self.client {
            checks.push(DoctorCheck {
                name: "base_url".into(),
                passed: true,
                message: Some(format!("Base URL: {}", client.base_url())),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "read_only_surface".into(),
                passed: true,
                message: Some(
                    "Public read-only surface: items, users, ranked feeds, and health".into(),
                ),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "search_surface".into(),
                passed: true,
                message: Some(
                    "Algolia search is intentionally unsupported in the first slice".into(),
                ),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "write_surface".into(),
                passed: true,
                message: Some("No authenticated write or moderation surface is exposed".into()),
                critical: false,
            });
        }

        DoctorResult::from_checks(checks, provisioning)
    }
}

impl Default for HackerNewsConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn operator_guidance() -> OperatorGuidance {
    OperatorGuidance {
        prerequisites: vec![
            "Use the public Firebase Hacker News API or a localhost mock override for verification.",
            "Treat this connector as read-only: item reads, user reads, feed snapshots, and health only.",
            "If you override base_url during verification, capture the override in the evidence bundle and keep it on the Firebase host or localhost.",
        ],
        dedicated_environment: "Prefer public HN data or a disposable localhost mock server. No authenticated YC or moderator environment is required.",
        redaction_rules: vec![
            "If verification uses a private mirror, redact the override hostname before sharing artifacts.",
            "Avoid publishing unnecessary raw user `about` fields or copied item text outside the owning team.",
            "Do not attach unrelated request traces from shared verification environments.",
        ],
        limitations: vec![
            "Algolia search is intentionally unsupported in the first slice.",
            "No submit, vote, favorite, reply, login, moderation, or admin workflows are exposed.",
            "Comments are only reachable through item.get; recursive thread expansion and live subscriptions are out of scope.",
        ],
        common_remediation: vec![
            RemediationHint {
                code: "not_configured",
                symptom: "health or self_check reports that the connector is not configured",
                action: "Configure base_url only if needed, plus timeout and retry settings, then rerun self_check.",
            },
            RemediationHint {
                code: "runtime_missing",
                symptom: "self_check reports that the connector runtime is not initialized",
                action: "Re-run configure so ConnectorRuntime and the HTTP client are both initialized before verification.",
            },
            RemediationHint {
                code: "self_check_retryable",
                symptom: "public API probe failed with rate limiting, timeout, or transient 5xx",
                action: "Wait for the upstream to recover or relax retry and timeout settings, then rerun the verification script.",
            },
            RemediationHint {
                code: "self_check_failed",
                symptom: "self_check reports a non-retryable API or deserialization failure",
                action: "Verify the base_url still points at a Firebase-compatible Hacker News endpoint and inspect the captured live_probe error details.",
            },
        ],
        rerun_commands: VERIFY_COMMANDS.to_vec(),
        artifact_root_hint: ARTIFACT_ROOT_HINT,
    }
}

fn item_output_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "required": [
            "id",
            "type",
            "by",
            "time",
            "text",
            "dead",
            "parent",
            "poll",
            "kids",
            "url",
            "score",
            "title",
            "parts",
            "descendants",
            "deleted"
        ],
        "additionalProperties": false,
        "properties": {
            "id": { "type": "integer", "minimum": 0 },
            "type": { "type": ["string", "null"] },
            "by": { "type": ["string", "null"] },
            "time": { "type": ["integer", "null"], "minimum": 0 },
            "text": { "type": ["string", "null"] },
            "dead": { "type": "boolean" },
            "parent": { "type": ["integer", "null"], "minimum": 0 },
            "poll": { "type": ["integer", "null"], "minimum": 0 },
            "kids": {
                "type": "array",
                "items": { "type": "integer", "minimum": 0 }
            },
            "url": { "type": ["string", "null"] },
            "score": { "type": ["integer", "null"] },
            "title": { "type": ["string", "null"] },
            "parts": {
                "type": "array",
                "items": { "type": "integer", "minimum": 0 }
            },
            "descendants": { "type": ["integer", "null"], "minimum": 0 },
            "deleted": { "type": "boolean" }
        }
    })
}

fn user_output_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "required": ["id", "created", "karma", "about", "submitted"],
        "additionalProperties": false,
        "properties": {
            "id": { "type": "string", "minLength": 1 },
            "created": { "type": "integer", "minimum": 0 },
            "karma": { "type": "integer" },
            "about": { "type": ["string", "null"] },
            "submitted": {
                "type": "array",
                "items": { "type": "integer", "minimum": 0 }
            }
        }
    })
}

fn feed_output_schema() -> serde_json::Value {
    json!({
        "type": "array",
        "items": { "type": "integer", "minimum": 0 }
    })
}

fn hackernews_resource_types() -> Vec<ResourceTypeInfo> {
    vec![
        ResourceTypeInfo {
            name: "hackernews.item".into(),
            uri_pattern: "hackernews://items/{item_id}".into(),
            schema: item_output_schema(),
        },
        ResourceTypeInfo {
            name: "hackernews.user".into(),
            uri_pattern: "hackernews://users/{username}".into(),
            schema: user_output_schema(),
        },
        ResourceTypeInfo {
            name: "hackernews.feed_snapshot".into(),
            uri_pattern: "hackernews://feeds/{feed_name}".into(),
            schema: json!({
                "type": "object",
                "required": ["feed", "item_ids"],
                "additionalProperties": false,
                "properties": {
                    "feed": {
                        "type": "string",
                        "enum": ["top", "new", "best", "ask", "show", "job"]
                    },
                    "item_ids": feed_output_schema()
                }
            }),
        },
    ]
}

/// Build the typed operations catalog from the embedded manifest.
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
        .expect("embedded Hacker News manifest should parse");
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

fcp_core::impl_fcp_sealed!(HackerNewsConnector);

#[async_trait]
impl FcpConnector for HackerNewsConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config: HackerNewsConfig =
            serde_json::from_value(config).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid HackerNews config: {e}"),
            })?;

        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(config.request_timeout_ms)),
        ));

        let client = HackerNewsClient::new(config.base_url.as_deref(), config.retry.clone())
            .map_err(|e| FcpError::Internal {
                message: format!("Failed to create HN client: {e}"),
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
            None => HealthSnapshot::error("client not initialized"),
            Some(_) if self.runtime.is_none() => HealthSnapshot::error("runtime not initialized"),
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
        }));
        snapshot
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(client) = &self.client else {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::degraded("not_configured", "Connector is not configured"),
                None,
            ));
        };
        if self.runtime.is_none() {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::failed("runtime_missing", "Connector runtime is not initialized"),
                None,
            ));
        };

        match client.health_check().await {
            Ok(()) => {
                let live_probe = Self::health_probe_details(client, false, None, None);
                Ok(self.attach_self_check_details(SelfCheckReport::ok(), Some(&live_probe)))
            }
            Err(HackerNewsError::RateLimited { retry_after_ms }) => {
                let message = format!("Rate limited, retry after {retry_after_ms}ms");
                let live_probe =
                    Self::health_probe_details(client, true, Some(&message), Some(retry_after_ms));
                Ok(self.attach_self_check_details(
                    SelfCheckReport::degraded("self_check_retryable", message),
                    Some(&live_probe),
                ))
            }
            Err(error) if error.is_retryable() => {
                let error_text = error.to_string();
                let live_probe = Self::health_probe_details(client, true, Some(&error_text), None);
                Ok(self.attach_self_check_details(
                    SelfCheckReport::degraded("self_check_retryable", error_text),
                    Some(&live_probe),
                ))
            }
            Err(error) => {
                let error_text = error.to_string();
                let live_probe = Self::health_probe_details(client, false, Some(&error_text), None);
                Ok(self.attach_self_check_details(
                    SelfCheckReport::failed("self_check_failed", error_text),
                    Some(&live_probe),
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
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: operations_info(),
            events: Vec::new(),
            resource_types: hackernews_resource_types(),
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

impl HackerNewsConnector {
    /// Apply an optional limit to a list of IDs.
    fn apply_limit(ids: Vec<u64>, limit: Option<u64>) -> Vec<u64> {
        match limit {
            Some(n) => ids.into_iter().take(n as usize).collect(),
            None => ids,
        }
    }

    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();

        let verifier = self.verifier.as_ref().ok_or(FcpError::Internal {
            message: "Capability verifier missing after successful handshake".into(),
        })?;
        // All HN operations require the read capability
        let required_cap = match operation {
            OP_ITEM_GET | OP_USER_GET | OP_TOP_STORIES | OP_NEW_STORIES | OP_BEST_STORIES
            | OP_ASK_STORIES | OP_SHOW_STORIES | OP_JOB_STORIES | OP_HEALTH => {
                CapabilityId::from_static(CAP_READ)
            }
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };
        // dja9u.1.b: typestate handoff via verify_bound.
        let _bound =
            verifier.verify_bound(req.capability_token, &required_cap, &req.operation, &[])?;

        let runtime = self.runtime.as_ref().ok_or(FcpError::Internal {
            message: "Connector runtime missing after configure".into(),
        })?;
        let client = self.client.as_ref().ok_or(FcpError::Internal {
            message: "HN client missing after configure".into(),
        })?;

        let output = match operation {
            OP_ITEM_GET => {
                let id = req.input.get("id").and_then(|v| v.as_u64()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing or invalid 'id' field (must be integer)".into(),
                    },
                )?;
                let item = client
                    .get_item(runtime, id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(item).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize item: {e}"),
                })?
            }
            OP_USER_GET => {
                let username = req.input.get("username").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'username' field".into(),
                    },
                )?;
                let user = client
                    .get_user(runtime, username)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(user).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize user: {e}"),
                })?
            }
            OP_TOP_STORIES => {
                let limit = req.input.get("limit").and_then(|v| v.as_u64());
                let ids = client
                    .top_stories(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!(Self::apply_limit(ids, limit))
            }
            OP_NEW_STORIES => {
                let limit = req.input.get("limit").and_then(|v| v.as_u64());
                let ids = client
                    .new_stories(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!(Self::apply_limit(ids, limit))
            }
            OP_BEST_STORIES => {
                let limit = req.input.get("limit").and_then(|v| v.as_u64());
                let ids = client
                    .best_stories(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!(Self::apply_limit(ids, limit))
            }
            OP_ASK_STORIES => {
                let limit = req.input.get("limit").and_then(|v| v.as_u64());
                let ids = client
                    .ask_stories(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!(Self::apply_limit(ids, limit))
            }
            OP_SHOW_STORIES => {
                let limit = req.input.get("limit").and_then(|v| v.as_u64());
                let ids = client
                    .show_stories(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!(Self::apply_limit(ids, limit))
            }
            OP_JOB_STORIES => {
                let limit = req.input.get("limit").and_then(|v| v.as_u64());
                let ids = client
                    .job_stories(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!(Self::apply_limit(ids, limit))
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
    use fcp_prelude::{IdempotencyClass, RiskLevel, SafetyTier};

    use super::*;

    const EXPECTED_MANIFEST_SCHEMA_OPS: [&str; 9] = [
        OP_ITEM_GET,
        OP_USER_GET,
        OP_TOP_STORIES,
        OP_NEW_STORIES,
        OP_BEST_STORIES,
        OP_ASK_STORIES,
        OP_SHOW_STORIES,
        OP_JOB_STORIES,
        OP_HEALTH,
    ];

    fn base_handshake() -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [0u8; 32],
            capabilities_requested: vec![CapabilityId::from_static(CAP_READ)],
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
        json!({})
    }

    fn hackernews_manifest() -> Result<toml::Value, String> {
        toml::from_str(MANIFEST_TOML)
            .map_err(|err| format!("Hacker News manifest TOML should parse: {err}"))
    }

    fn strict_hackernews_manifest() -> Result<ConnectorManifest, String> {
        let manifest =
            ConnectorManifest::parse_str(MANIFEST_TOML).map_err(|error| error.to_string())?;
        manifest.validate().map_err(|error| error.to_string())?;
        Ok(manifest)
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
        let mut connector = HackerNewsConnector::new();
        let result = connector.handshake(base_handshake()).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_empty() {
        let mut connector = HackerNewsConnector::new();
        let result = connector.configure(test_config()).await;
        assert!(result.is_ok());
        assert!(connector.config.is_some());
        assert!(connector.client.is_some());
        assert!(connector.runtime.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_custom_url() {
        let mut connector = HackerNewsConnector::new();
        let result = connector
            .configure(json!({
                "base_url": "http://localhost:8080/v0"
            }))
            .await;
        assert!(result.is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_before_configure() {
        let connector = HackerNewsConnector::new();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Degraded { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_after_configure() {
        let mut connector = HackerNewsConnector::new();
        connector.configure(test_config()).await.unwrap();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Ready));
    }

    #[test]
    fn test_doctor_before_configure() {
        let connector = HackerNewsConnector::new();
        let report = connector.doctor();
        assert!(!report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_after_configure() {
        let mut connector = HackerNewsConnector::new();
        connector.configure(test_config()).await.unwrap();
        let report = connector.doctor();
        assert!(report.passed);
        // Verify auth check says no auth required
        let auth_check = report.checks.iter().find(|c| c.name == "auth").unwrap();
        assert!(auth_check.passed);
        assert!(
            auth_check
                .message
                .as_ref()
                .unwrap()
                .contains("No authentication")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_before_configure() {
        let connector = HackerNewsConnector::new();
        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate() {
        let connector = HackerNewsConnector::new();
        let req = SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(OP_ITEM_GET),
            ZoneId::work(),
            json!({}),
            CapabilityToken::test_token(),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(resp.would_succeed);
    }

    #[test]
    fn test_introspection_operations() {
        let connector = HackerNewsConnector::new();
        let intro = connector.introspect();
        assert_eq!(intro.operations.len(), 9);
        for op_name in &[
            OP_ITEM_GET,
            OP_USER_GET,
            OP_TOP_STORIES,
            OP_NEW_STORIES,
            OP_BEST_STORIES,
            OP_ASK_STORIES,
            OP_SHOW_STORIES,
            OP_JOB_STORIES,
            OP_HEALTH,
        ] {
            assert!(
                intro.operations.iter().any(|op| op.id.as_str() == *op_name),
                "Missing operation: {op_name}"
            );
        }
    }

    #[test]
    fn test_introspection_resource_inventory() {
        let intro = HackerNewsConnector::new().introspect();
        let names: Vec<&str> = intro
            .resource_types
            .iter()
            .map(|resource| resource.name.as_str())
            .collect();
        assert!(names.contains(&"hackernews.item"));
        assert!(names.contains(&"hackernews.user"));
        assert!(names.contains(&"hackernews.feed_snapshot"));
    }

    #[test]
    fn test_introspection_keeps_auth_caps_none() {
        let intro = HackerNewsConnector::new().introspect();
        assert!(intro.auth_caps.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_unknown_operation() {
        let mut connector = HackerNewsConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), "hackernews.nonexistent");
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_configure() {
        let connector = HackerNewsConnector::new();
        let req = base_invoke(connector.id(), OP_ITEM_GET);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_id_field() {
        let mut connector = HackerNewsConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_ITEM_GET);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_username_field() {
        let mut connector = HackerNewsConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_USER_GET);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_operations_info_count() {
        let ops = operations_info();
        assert_eq!(ops.len(), 9);
    }

    #[test]
    fn runtime_operation_catalog_matches_manifest_metadata() -> Result<(), String> {
        let manifest = strict_hackernews_manifest()?;
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
                serde_json::to_value(&operation.ai_hints).expect("serialize runtime hints"),
                serde_json::to_value(&manifest_operation.ai_hints)
                    .expect("serialize manifest hints")
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
    fn manifest_operation_schemas_compile_and_validate_core_payloads() -> Result<(), String> {
        let manifest = hackernews_manifest()?;
        let operations = manifest_operations(&manifest)?;

        for operation_id in EXPECTED_MANIFEST_SCHEMA_OPS {
            assert!(
                operations.contains_key(operation_id),
                "manifest should declare operation {operation_id}"
            );
            for field in ["input_schema", "output_schema"] {
                let schema = operation_schema(&manifest, operation_id, field)?;
                let _validator = validator_for(&schema)?;
            }
        }

        for operation in operations_info() {
            let _input_validator = validator_for(&operation.input_schema)?;
            let _output_validator = validator_for(&operation.output_schema)?;
        }

        let item_input = operation_schema(&manifest, OP_ITEM_GET, "input_schema")?;
        assert_schema_accepts(&item_input, &json!({"id": 8863}))?;
        assert_schema_rejects(&item_input, &json!({}))?;
        assert_schema_rejects(&item_input, &json!({"id": "8863"}))?;
        assert_schema_rejects(&item_input, &json!({"id": 8863, "extra": true}))?;

        let item_output = operation_schema(&manifest, OP_ITEM_GET, "output_schema")?;
        assert_schema_accepts(
            &item_output,
            &json!({
                "id": 8863,
                "type": "story",
                "by": "dhouston",
                "time": 1175714200,
                "text": null,
                "dead": false,
                "parent": null,
                "poll": null,
                "kids": [8952, 9224],
                "url": "http://www.getdropbox.com",
                "score": 111,
                "title": "My YC app: Dropbox",
                "parts": [],
                "descendants": 71,
                "deleted": false
            }),
        )?;
        assert_schema_rejects(
            &item_output,
            &json!({
                "id": 8863,
                "type": "story",
                "by": "dhouston",
                "time": 1175714200,
                "text": null,
                "dead": false,
                "parent": null,
                "poll": null,
                "kids": [],
                "url": "http://www.getdropbox.com",
                "score": 111,
                "title": "My YC app: Dropbox",
                "parts": [],
                "descendants": 71,
                "deleted": false,
                "extra": true
            }),
        )?;

        let user_input = operation_schema(&manifest, OP_USER_GET, "input_schema")?;
        assert_schema_accepts(&user_input, &json!({"username": "jl"}))?;
        assert_schema_rejects(&user_input, &json!({"username": ""}))?;
        assert_schema_rejects(&user_input, &json!({"username": "jl", "extra": true}))?;

        let user_output = operation_schema(&manifest, OP_USER_GET, "output_schema")?;
        assert_schema_accepts(
            &user_output,
            &json!({
                "id": "jl",
                "created": 1173923446,
                "karma": 2937,
                "about": null,
                "submitted": [8265435, 8168423]
            }),
        )?;
        assert_schema_rejects(&user_output, &json!({"id": "jl", "karma": 2937}))?;

        let feed_input = operation_schema(&manifest, OP_TOP_STORIES, "input_schema")?;
        assert_schema_accepts(&feed_input, &json!({}))?;
        assert_schema_accepts(&feed_input, &json!({"limit": 0}))?;
        assert_schema_rejects(&feed_input, &json!({"limit": -1}))?;
        assert_schema_rejects(&feed_input, &json!({"limit": 10, "extra": true}))?;

        let feed_output = operation_schema(&manifest, OP_TOP_STORIES, "output_schema")?;
        assert_schema_accepts(&feed_output, &json!([8863, 2921983]))?;
        assert_schema_rejects(&feed_output, &json!([8863, "2921983"]))?;

        let health_input = operation_schema(&manifest, OP_HEALTH, "input_schema")?;
        assert_schema_accepts(&health_input, &json!({}))?;
        assert_schema_rejects(&health_input, &json!({"probe": true}))?;

        let health_output = operation_schema(&manifest, OP_HEALTH, "output_schema")?;
        assert_schema_accepts(&health_output, &json!({"status": "ok"}))?;
        assert_schema_rejects(&health_output, &json!({"status": "degraded"}))?;
        assert_schema_rejects(&health_output, &json!({"status": "ok", "extra": true}))?;

        Ok(())
    }

    #[test]
    fn test_operations_have_ai_hints() {
        let ops = operations_info();
        for op in &ops {
            assert!(!op.ai_hints.when_to_use.is_empty());
        }
    }

    #[test]
    fn test_all_ops_are_safe() {
        let ops = operations_info();
        for op in &ops {
            assert_eq!(
                op.safety_tier,
                SafetyTier::Safe,
                "Op {} should be Safe",
                op.id.as_str()
            );
            assert_eq!(
                op.risk_level,
                RiskLevel::Low,
                "Op {} should be Low risk",
                op.id.as_str()
            );
        }
    }

    #[test]
    fn test_item_get_is_strict_idempotent() {
        let ops = operations_info();
        let item_get = ops.iter().find(|op| op.id.as_str() == OP_ITEM_GET).unwrap();
        assert_eq!(item_get.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn test_user_get_is_strict_idempotent() {
        let ops = operations_info();
        let user_get = ops.iter().find(|op| op.id.as_str() == OP_USER_GET).unwrap();
        assert_eq!(user_get.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn test_story_lists_are_none_idempotent() -> Result<(), String> {
        let ops = operations_info();
        for name in &[
            OP_TOP_STORIES,
            OP_NEW_STORIES,
            OP_BEST_STORIES,
            OP_ASK_STORIES,
            OP_SHOW_STORIES,
            OP_JOB_STORIES,
        ] {
            let op = ops
                .iter()
                .find(|o| o.id.as_str() == *name)
                .ok_or_else(|| format!("Missing op: {name}"))?;
            assert_eq!(
                op.idempotency,
                IdempotencyClass::None,
                "Op {name} should be None idempotency"
            );
        }
        Ok(())
    }

    #[test]
    fn test_health_is_strict_idempotent() {
        let ops = operations_info();
        let health = ops.iter().find(|op| op.id.as_str() == OP_HEALTH).unwrap();
        assert_eq!(health.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn test_manifest_hash_deterministic() {
        let hash1 = HackerNewsConnector::manifest_hash();
        let hash2 = HackerNewsConnector::manifest_hash();
        assert_eq!(hash1, hash2);
        assert!(hash1.starts_with("sha256:"));
    }

    #[test]
    fn test_streaming_not_supported() {
        let connector = HackerNewsConnector::new();
        let intro = connector.introspect();
        assert!(!intro.event_caps.as_ref().unwrap().streaming);
        assert!(intro.events.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_before_handshake_returns_not_handshaken() {
        let mut connector = HackerNewsConnector::new();
        connector.configure(test_config()).await.unwrap();
        let result = connector
            .invoke(base_invoke(connector.id(), OP_ITEM_GET))
            .await;
        assert!(matches!(result, Err(FcpError::NotHandshaken)));
    }

    #[test]
    fn test_all_ops_use_read_capability() {
        let ops = operations_info();
        for op in &ops {
            assert_eq!(
                op.capability.as_str(),
                CAP_READ,
                "Op {} should use hackernews.read capability",
                op.id.as_str()
            );
        }
    }

    #[test]
    fn test_no_approval_required() {
        let ops = operations_info();
        for op in &ops {
            assert_eq!(
                op.requires_approval,
                None,
                "Op {} should not require approval",
                op.id.as_str()
            );
        }
    }

    #[test]
    fn test_connector_id() {
        let connector = HackerNewsConnector::new();
        assert_eq!(connector.id().as_str(), "fcp.hackernews");
    }

    #[test]
    fn test_default_impl() {
        let connector = HackerNewsConnector::default();
        assert_eq!(connector.id().as_str(), "fcp.hackernews");
    }

    #[test]
    fn test_apply_limit() {
        let ids = vec![1, 2, 3, 4, 5];
        assert_eq!(
            HackerNewsConnector::apply_limit(ids.clone(), Some(3)),
            vec![1, 2, 3]
        );
        assert_eq!(
            HackerNewsConnector::apply_limit(ids.clone(), None),
            vec![1, 2, 3, 4, 5]
        );
        assert_eq!(
            HackerNewsConnector::apply_limit(ids, Some(10)),
            vec![1, 2, 3, 4, 5]
        );
    }

    #[test]
    fn test_apply_limit_zero() {
        let ids = vec![1, 2, 3];
        let result = HackerNewsConnector::apply_limit(ids, Some(0));
        assert!(result.is_empty());
    }
}
