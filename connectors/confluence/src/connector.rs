//! Confluence connector implementation.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcp_prelude::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    HealthSnapshot, IdempotencyClass, Introspection, InvokeRequest, InvokeResponse, OperationId,
    OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId, ShutdownRequest,
    SimulateRequest, SimulateResponse,
};
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::prelude::*;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::client::ConfluenceClient;

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

// Operation IDs
const OP_SPACES_LIST: &str = "confluence.spaces.list";
const OP_SPACES_GET: &str = "confluence.spaces.get";
const OP_PAGES_LIST: &str = "confluence.pages.list";
const OP_PAGES_GET: &str = "confluence.pages.get";
const OP_PAGES_CREATE: &str = "confluence.pages.create";
const OP_PAGES_UPDATE: &str = "confluence.pages.update";
const OP_PAGES_DELETE: &str = "confluence.pages.delete";
const OP_SEARCH: &str = "confluence.search";
const OP_HEALTH: &str = "confluence.health";

// Capability IDs
const CAP_SPACES_READ: &str = "confluence.spaces.read";
const CAP_PAGES_READ: &str = "confluence.pages.read";
const CAP_PAGES_WRITE: &str = "confluence.pages.write";

/// Confluence connector configuration.
#[derive(Clone, Deserialize)]
struct ConfluenceConfig {
    /// Base URL, e.g. `"https://myinstance.atlassian.net/wiki"`
    base_url: String,
    email: String,
    api_token: String,
    #[serde(default)]
    retry: HttpRetryConfig,
    #[serde(default = "default_request_timeout_ms")]
    request_timeout_ms: u64,
}

impl std::fmt::Debug for ConfluenceConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfluenceConfig")
            .field("base_url", &self.base_url)
            .field("email", &self.email)
            .field("api_token", &"[REDACTED]")
            .field("retry", &self.retry)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

const fn default_request_timeout_ms() -> u64 {
    30_000
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

/// Confluence connector state.
#[derive(Debug)]
pub struct ConfluenceConnector {
    base: BaseConnector,
    config: Option<ConfluenceConfig>,
    client: Option<ConfluenceClient>,
    runtime: Option<ConnectorRuntime>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl ConfluenceConnector {
    /// Create a new connector instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.confluence")),
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
            let host_part = config
                .base_url
                .split("://")
                .nth(1)
                .unwrap_or("")
                .split('/')
                .next()
                .unwrap_or("")
                .split(':')
                .next()
                .unwrap_or("");
            let host_ok = host_part == "localhost"
                || host_part == "127.0.0.1"
                || host_part.ends_with(".atlassian.net");
            checks.push(DoctorCheck {
                name: "network_constraints".into(),
                passed: host_ok,
                message: Some(if host_ok {
                    "Base URL matches allowed host (*.atlassian.net)".into()
                } else {
                    format!("Base URL {} does not match allowed hosts", config.base_url)
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
                    "API token configured".into()
                }),
                critical: false,
            });
        }

        DoctorResult::from_checks(checks)
    }
}

impl Default for ConfluenceConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
    let capability = match operation {
        OP_SPACES_LIST | OP_SPACES_GET | OP_HEALTH => CapabilityId::from_static(CAP_SPACES_READ),
        OP_PAGES_LIST | OP_PAGES_GET | OP_SEARCH => CapabilityId::from_static(CAP_PAGES_READ),
        OP_PAGES_CREATE | OP_PAGES_UPDATE | OP_PAGES_DELETE => {
            CapabilityId::from_static(CAP_PAGES_WRITE)
        }
        _ => {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: format!("Unknown operation: {operation}"),
            });
        }
    };
    Ok(capability)
}

/// Build the typed operations catalog.
pub fn operations_info() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static(OP_SPACES_LIST),
            summary: "List Confluence spaces".into(),
            description: Some("Returns a paginated list of spaces".into()),
            input_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "start": { "type": "integer", "minimum": 0, "default": 0 },
                    "limit": { "type": "integer", "minimum": 1, "default": 25 }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["results", "size"],
                "additionalProperties": false,
                "properties": {
                    "results": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["id", "key", "name"],
                            "additionalProperties": true
                        }
                    },
                    "start": { "type": "integer", "minimum": 0 },
                    "limit": { "type": "integer", "minimum": 0 },
                    "size": { "type": "integer", "minimum": 0 },
                    "_links": { "type": "object", "additionalProperties": true }
                }
            }),
            capability: CapabilityId::from_static(CAP_SPACES_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to list available Confluence spaces".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_SPACES_GET)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_SPACES_GET),
            summary: "Get a space by key".into(),
            description: Some("Returns details for a specific space".into()),
            input_schema: json!({
                "type": "object",
                "required": ["space_key"],
                "additionalProperties": false,
                "properties": {
                    "space_key": {
                        "type": "string",
                        "minLength": 1,
                        "pattern": "^[^/\\\\]+$",
                        "not": { "enum": [".", ".."] },
                        "description": "Space key (e.g., DEV)"
                    }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["id", "key", "name"],
                "additionalProperties": false,
                "properties": {
                    "id": { "type": "string" },
                    "key": { "type": "string" },
                    "name": { "type": "string" },
                    "type": { "type": "string" },
                    "status": { "type": "string" },
                    "description": { "type": "object", "additionalProperties": true },
                    "_links": { "type": "object", "additionalProperties": true }
                }
            }),
            capability: CapabilityId::from_static(CAP_SPACES_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need details about a specific Confluence space".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_SPACES_LIST)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_PAGES_LIST),
            summary: "List pages in a space".into(),
            description: Some("Returns a paginated list of pages in a space".into()),
            input_schema: json!({
                "type": "object",
                "required": ["space_key"],
                "additionalProperties": false,
                "properties": {
                    "space_key": {
                        "type": "string",
                        "minLength": 1,
                        "pattern": "^[^/\\\\]+$",
                        "not": { "enum": [".", ".."] },
                        "description": "Space key"
                    },
                    "start": { "type": "integer", "minimum": 0, "default": 0 },
                    "limit": { "type": "integer", "minimum": 1, "default": 25 }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["results", "size"],
                "additionalProperties": false,
                "properties": {
                    "results": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["id", "title"],
                            "additionalProperties": true
                        }
                    },
                    "start": { "type": "integer", "minimum": 0 },
                    "limit": { "type": "integer", "minimum": 0 },
                    "size": { "type": "integer", "minimum": 0 },
                    "_links": { "type": "object", "additionalProperties": true }
                }
            }),
            capability: CapabilityId::from_static(CAP_PAGES_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to list pages in a Confluence space".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_PAGES_GET)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_PAGES_GET),
            summary: "Get a page by ID".into(),
            description: Some("Returns full content of a specific page".into()),
            input_schema: json!({
                "type": "object",
                "required": ["page_id"],
                "additionalProperties": false,
                "properties": {
                    "page_id": {
                        "type": "string",
                        "minLength": 1,
                        "pattern": "^[^/\\\\]+$",
                        "not": { "enum": [".", ".."] },
                        "description": "Page ID"
                    }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["id", "title"],
                "additionalProperties": false,
                "properties": {
                    "id": { "type": "string" },
                    "title": { "type": "string" },
                    "type": { "type": "string" },
                    "status": { "type": "string" },
                    "space": { "type": "object", "additionalProperties": true },
                    "version": { "type": "object", "additionalProperties": true },
                    "body": { "type": "object", "additionalProperties": true },
                    "_links": { "type": "object", "additionalProperties": true }
                }
            }),
            capability: CapabilityId::from_static(CAP_PAGES_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need the full content of a specific page".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_PAGES_LIST)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_PAGES_CREATE),
            summary: "Create a new page".into(),
            description: Some("Creates a new Confluence page in a space".into()),
            input_schema: json!({
                "type": "object",
                "required": ["space_key", "title", "body"],
                "additionalProperties": false,
                "properties": {
                    "space_key": {
                        "type": "string",
                        "minLength": 1,
                        "pattern": "^[^/\\\\]+$",
                        "not": { "enum": [".", ".."] },
                        "description": "Space key to create page in"
                    },
                    "title": { "type": "string", "minLength": 1, "description": "Page title" },
                    "body": {
                        "type": "string",
                        "minLength": 1,
                        "description": "Page body in Confluence storage format (XHTML)"
                    },
                    "parent_id": {
                        "type": "string",
                        "minLength": 1,
                        "pattern": "^[^/\\\\]+$",
                        "not": { "enum": [".", ".."] },
                        "description": "Optional parent page ID"
                    }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["id", "title"],
                "additionalProperties": false,
                "properties": {
                    "id": { "type": "string" },
                    "title": { "type": "string" },
                    "type": { "type": "string" },
                    "status": { "type": "string" },
                    "space": { "type": "object", "additionalProperties": true },
                    "version": { "type": "object", "additionalProperties": true },
                    "body": { "type": "object", "additionalProperties": true },
                    "_links": { "type": "object", "additionalProperties": true }
                }
            }),
            capability: CapabilityId::from_static(CAP_PAGES_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "When you need to create a new wiki page".into(),
                common_mistakes: vec![
                    "Body must be in Confluence storage format (XHTML), not Markdown".into(),
                    "Duplicate retries can still create ambiguous results; page title is not a safe deduplication key".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_PAGES_UPDATE)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_PAGES_UPDATE),
            summary: "Update an existing page".into(),
            description: Some("Updates the content of an existing Confluence page".into()),
            input_schema: json!({
                "type": "object",
                "required": ["page_id", "title", "body", "version_number"],
                "additionalProperties": false,
                "properties": {
                    "page_id": {
                        "type": "string",
                        "minLength": 1,
                        "pattern": "^[^/\\\\]+$",
                        "not": { "enum": [".", ".."] },
                        "description": "Page ID to update"
                    },
                    "title": { "type": "string", "minLength": 1, "description": "New page title" },
                    "body": {
                        "type": "string",
                        "minLength": 1,
                        "description": "New page body in storage format"
                    },
                    "version_number": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Current page version number; the connector increments it by 1 for the provider request"
                    },
                    "version_message": { "type": "string", "description": "Optional version comment" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["id", "title"],
                "additionalProperties": false,
                "properties": {
                    "id": { "type": "string" },
                    "title": { "type": "string" },
                    "type": { "type": "string" },
                    "status": { "type": "string" },
                    "space": { "type": "object", "additionalProperties": true },
                    "version": { "type": "object", "additionalProperties": true },
                    "body": { "type": "object", "additionalProperties": true },
                    "_links": { "type": "object", "additionalProperties": true }
                }
            }),
            capability: CapabilityId::from_static(CAP_PAGES_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "When you need to update the content of an existing page".into(),
                common_mistakes: vec![
                    "Pass the current page version number; the connector increments it by 1".into(),
                    "Fetch the page first to get the current version number".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_PAGES_CREATE)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_PAGES_DELETE),
            summary: "Delete a page".into(),
            description: Some("Deletes a Confluence page; provider behavior may move content to trash unless purge semantics are implemented explicitly".into()),
            input_schema: json!({
                "type": "object",
                "required": ["page_id"],
                "additionalProperties": false,
                "properties": {
                    "page_id": {
                        "type": "string",
                        "minLength": 1,
                        "pattern": "^[^/\\\\]+$",
                        "not": { "enum": [".", ".."] },
                        "description": "Page ID to delete"
                    }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["deleted"],
                "additionalProperties": false,
                "properties": {
                    "deleted": { "type": "boolean" }
                }
            }),
            capability: CapabilityId::from_static(CAP_PAGES_WRITE),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "When you need to delete a wiki page".into(),
                common_mistakes: vec![
                    "Confluence delete may move content to trash unless purge behavior is implemented explicitly".into(),
                    "Deleting a parent page can affect descendants and linked content".into(),
                ],
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        OperationInfo {
            id: OperationId::from_static(OP_SEARCH),
            summary: "Search Confluence content".into(),
            description: Some("Search for pages and content using CQL (Confluence Query Language)".into()),
            input_schema: json!({
                "type": "object",
                "required": ["cql"],
                "additionalProperties": false,
                "properties": {
                    "cql": { "type": "string", "minLength": 1, "description": "CQL query string" },
                    "start": { "type": "integer", "minimum": 0, "default": 0 },
                    "limit": { "type": "integer", "minimum": 1, "default": 25 }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["results", "size"],
                "additionalProperties": false,
                "properties": {
                    "results": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["title"],
                            "additionalProperties": true
                        }
                    },
                    "start": { "type": "integer", "minimum": 0 },
                    "limit": { "type": "integer", "minimum": 0 },
                    "size": { "type": "integer", "minimum": 0 },
                    "_links": { "type": "object", "additionalProperties": true }
                }
            }),
            capability: CapabilityId::from_static(CAP_PAGES_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to search for content across Confluence".into(),
                common_mistakes: vec![
                    "CQL syntax uses field operators, e.g. 'text ~ \"search term\"'".into(),
                    "Use space = KEY to limit search to a specific space".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_PAGES_LIST)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_HEALTH),
            summary: "Check Confluence API health".into(),
            description: Some("Validates Confluence API reachability and auth".into()),
            input_schema: json!({ "type": "object", "additionalProperties": false }),
            output_schema: json!({
                "type": "object",
                "required": ["status"],
                "additionalProperties": false,
                "properties": {
                    "status": { "type": "string", "enum": ["ok"] }
                }
            }),
            capability: CapabilityId::from_static(CAP_SPACES_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to verify Confluence connectivity".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
    ]
}

fcp_core::impl_fcp_sealed!(ConfluenceConnector);

#[async_trait]
impl FcpConnector for ConfluenceConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config: ConfluenceConfig =
            serde_json::from_value(config).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid Confluence config: {e}"),
            })?;

        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(config.request_timeout_ms)),
        ));

        let client = ConfluenceClient::new(
            &config.base_url,
            &config.email,
            &config.api_token,
            config.retry.clone(),
        )
        .map_err(|e| FcpError::Internal {
            message: format!("Failed to create Confluence client: {e}"),
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
        let mut snapshot = if self.config.is_some() {
            HealthSnapshot::ready()
        } else {
            HealthSnapshot::degraded("not configured")
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

        if client.is_secretless() {
            return Ok(SelfCheckReport::degraded(
                "credential_injection_required",
                "Configured with empty token; egress proxy injection required",
            ));
        }

        match client.health_check().await {
            Ok(()) => Ok(SelfCheckReport::ok()),
            Err(err) => {
                if err.is_retryable() {
                    Ok(SelfCheckReport::degraded(
                        "self_check_retryable",
                        err.to_string(),
                    ))
                } else {
                    Ok(SelfCheckReport::failed(
                        "self_check_failed",
                        err.to_string(),
                    ))
                }
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
                "Connector has not completed handshake",
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

impl ConfluenceConnector {
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
            message: "Confluence client missing after configure".into(),
        })?;

        let output = match operation {
            OP_SPACES_LIST => {
                let start = req.input.get("start").and_then(|v| v.as_u64()).unwrap_or(0);
                let limit = req
                    .input
                    .get("limit")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(25);
                let resp = client
                    .list_spaces(runtime, start, limit)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("JSON serialization error: {e}"),
                })?
            }
            OP_SPACES_GET => {
                let space_key = req.input.get("space_key").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'space_key' field".into(),
                    },
                )?;
                let resp = client
                    .get_space(runtime, space_key)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("JSON serialization error: {e}"),
                })?
            }
            OP_PAGES_LIST => {
                let space_key = req.input.get("space_key").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'space_key' field".into(),
                    },
                )?;
                let start = req.input.get("start").and_then(|v| v.as_u64()).unwrap_or(0);
                let limit = req
                    .input
                    .get("limit")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(25);
                let resp = client
                    .list_pages(runtime, space_key, start, limit)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("JSON serialization error: {e}"),
                })?
            }
            OP_PAGES_GET => {
                let page_id = req.input.get("page_id").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'page_id' field".into(),
                    },
                )?;
                let resp = client
                    .get_page(runtime, page_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("JSON serialization error: {e}"),
                })?
            }
            OP_PAGES_CREATE => {
                let space_key = req.input.get("space_key").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'space_key' field".into(),
                    },
                )?;
                let title = req.input.get("title").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'title' field".into(),
                    },
                )?;
                let body_content = req.input.get("body").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'body' field".into(),
                    },
                )?;

                let mut create_body = json!({
                    "type": "page",
                    "title": title,
                    "space": { "key": space_key },
                    "body": {
                        "storage": {
                            "value": body_content,
                            "representation": "storage"
                        }
                    }
                });

                if let Some(parent_id) = req.input.get("parent_id").and_then(|v| v.as_str()) {
                    create_body["ancestors"] = json!([{ "id": parent_id }]);
                }

                let resp = client
                    .create_page(runtime, &create_body)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("JSON serialization error: {e}"),
                })?
            }
            OP_PAGES_UPDATE => {
                let page_id = req.input.get("page_id").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'page_id' field".into(),
                    },
                )?;
                let title = req.input.get("title").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'title' field".into(),
                    },
                )?;
                let body_content = req.input.get("body").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'body' field".into(),
                    },
                )?;
                let version_number = req
                    .input
                    .get("version_number")
                    .and_then(|v| v.as_u64())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing or invalid 'version_number' field".into(),
                    })?;
                let version_message = req
                    .input
                    .get("version_message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                let update_body = json!({
                    "id": page_id,
                    "type": "page",
                    "title": title,
                    "body": {
                        "storage": {
                            "value": body_content,
                            "representation": "storage"
                        }
                    },
                    "version": {
                        "number": version_number + 1,
                        "message": version_message
                    }
                });

                let resp = client
                    .update_page(runtime, page_id, &update_body)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("JSON serialization error: {e}"),
                })?
            }
            OP_PAGES_DELETE => {
                let page_id = req.input.get("page_id").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'page_id' field".into(),
                    },
                )?;
                client
                    .delete_page(runtime, page_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({ "deleted": true })
            }
            OP_SEARCH => {
                let cql = req.input.get("cql").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'cql' field".into(),
                    },
                )?;
                let start = req.input.get("start").and_then(|v| v.as_u64()).unwrap_or(0);
                let limit = req
                    .input
                    .get("limit")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(25);
                let resp = client
                    .search(runtime, cql, start, limit)
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

    fn all_caps() -> Vec<CapabilityId> {
        vec![
            CapabilityId::from_static(CAP_SPACES_READ),
            CapabilityId::from_static(CAP_PAGES_READ),
            CapabilityId::from_static(CAP_PAGES_WRITE),
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
            "base_url": "https://test.atlassian.net/wiki",
            "email": "user@test.com",
            "api_token": "test-auth-material"
        })
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = ConfluenceConnector::new();
        let result = connector.handshake(base_handshake()).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_valid() {
        let mut connector = ConfluenceConnector::new();
        let result = connector.configure(test_config()).await;
        assert!(result.is_ok());
        assert!(connector.config.is_some());
        assert!(connector.client.is_some());
        assert!(connector.runtime.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_missing_fields() {
        let mut connector = ConfluenceConnector::new();
        let result = connector.configure(json!({})).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_before_configure() {
        let connector = ConfluenceConnector::new();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Degraded { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_after_configure() {
        let mut connector = ConfluenceConnector::new();
        connector.configure(test_config()).await.unwrap();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Ready));
    }

    #[test]
    fn test_doctor_before_configure() {
        let connector = ConfluenceConnector::new();
        let report = connector.doctor();
        assert!(!report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_after_configure() {
        let mut connector = ConfluenceConnector::new();
        connector.configure(test_config()).await.unwrap();
        let report = connector.doctor();
        assert!(report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_before_configure() {
        let connector = ConfluenceConnector::new();
        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate() {
        let connector = ConfluenceConnector::new();
        let req = SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(OP_SPACES_LIST),
            ZoneId::work(),
            json!({}),
            CapabilityToken::test_token(),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(!resp.would_succeed);
        assert_eq!(resp.denial_code.as_deref(), Some("FCP-5002"));
    }

    #[test]
    fn test_introspection_operations() {
        let connector = ConfluenceConnector::new();
        let intro = connector.introspect();
        assert_eq!(intro.operations.len(), 9);
        let ops: Vec<&str> = intro.operations.iter().map(|o| o.id.as_str()).collect();
        assert!(ops.contains(&OP_SPACES_LIST));
        assert!(ops.contains(&OP_SPACES_GET));
        assert!(ops.contains(&OP_PAGES_LIST));
        assert!(ops.contains(&OP_PAGES_GET));
        assert!(ops.contains(&OP_PAGES_CREATE));
        assert!(ops.contains(&OP_PAGES_UPDATE));
        assert!(ops.contains(&OP_PAGES_DELETE));
        assert!(ops.contains(&OP_SEARCH));
        assert!(ops.contains(&OP_HEALTH));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_unknown_operation() {
        let mut connector = ConfluenceConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), "confluence.nonexistent");
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_configure() {
        let connector = ConfluenceConnector::new();
        let req = base_invoke(connector.id(), OP_SPACES_LIST);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_space_key() {
        let mut connector = ConfluenceConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_SPACES_GET);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_page_id() {
        let mut connector = ConfluenceConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_PAGES_GET);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_cql() {
        let mut connector = ConfluenceConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_SEARCH);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_create_page_missing_fields() {
        let mut connector = ConfluenceConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let mut req = base_invoke(connector.id(), OP_PAGES_CREATE);
        req.input = json!({ "space_key": "DEV" }); // missing title and body
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_update_page_missing_version() {
        let mut connector = ConfluenceConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let mut req = base_invoke(connector.id(), OP_PAGES_UPDATE);
        req.input = json!({
            "page_id": "123",
            "title": "Test",
            "body": "<p>content</p>"
            // missing version_number
        });
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
    fn test_pages_create_is_risky() {
        let ops = operations_info();
        let create = ops
            .iter()
            .find(|op| op.id.as_str() == OP_PAGES_CREATE)
            .unwrap();
        assert_eq!(create.safety_tier, SafetyTier::Risky);
        assert_eq!(create.risk_level, RiskLevel::Medium);
        assert_eq!(create.idempotency, IdempotencyClass::BestEffort);
    }

    #[test]
    fn test_pages_update_is_best_effort() {
        let ops = operations_info();
        let update = ops
            .iter()
            .find(|op| op.id.as_str() == OP_PAGES_UPDATE)
            .unwrap();
        assert_eq!(update.safety_tier, SafetyTier::Risky);
        assert_eq!(update.risk_level, RiskLevel::Medium);
        assert_eq!(update.idempotency, IdempotencyClass::BestEffort);
    }

    #[test]
    fn test_pages_delete_is_dangerous() {
        let ops = operations_info();
        let delete = ops
            .iter()
            .find(|op| op.id.as_str() == OP_PAGES_DELETE)
            .unwrap();
        assert_eq!(delete.safety_tier, SafetyTier::Dangerous);
        assert_eq!(delete.risk_level, RiskLevel::High);
        assert_eq!(delete.idempotency, IdempotencyClass::BestEffort);
        assert_eq!(delete.requires_approval, Some(ApprovalMode::Interactive));
    }

    #[test]
    fn test_spaces_list_is_safe() {
        let ops = operations_info();
        let list = ops
            .iter()
            .find(|op| op.id.as_str() == OP_SPACES_LIST)
            .unwrap();
        assert_eq!(list.safety_tier, SafetyTier::Safe);
        assert_eq!(list.risk_level, RiskLevel::Low);
    }

    #[test]
    fn test_manifest_hash_deterministic() {
        let hash1 = ConfluenceConnector::manifest_hash();
        let hash2 = ConfluenceConnector::manifest_hash();
        assert_eq!(hash1, hash2);
        assert!(hash1.starts_with("sha256:"));
    }

    #[test]
    fn test_streaming_not_supported() {
        let connector = ConfluenceConnector::new();
        let intro = connector.introspect();
        assert!(!intro.event_caps.as_ref().unwrap().streaming);
    }

    #[test]
    fn test_connector_id() {
        let connector = ConfluenceConnector::new();
        assert_eq!(connector.id().as_str(), "fcp.confluence");
    }

    #[test]
    fn test_default_impl() {
        let connector = ConfluenceConnector::default();
        assert_eq!(connector.id().as_str(), "fcp.confluence");
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake_grants_all_caps() {
        let mut connector = ConfluenceConnector::new();
        let resp = connector.handshake(base_handshake()).await.unwrap();
        assert_eq!(resp.capabilities_granted.len(), 3);
    }

    #[fcp_async_core::runtime::test]
    async fn test_shutdown() {
        let mut connector = ConfluenceConnector::new();
        connector.configure(test_config()).await.unwrap();
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

    #[fcp_async_core::runtime::test]
    async fn test_invoke_delete_page_missing_id() {
        let mut connector = ConfluenceConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_PAGES_DELETE);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_pages_list_missing_space() {
        let mut connector = ConfluenceConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_PAGES_LIST);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }
}
