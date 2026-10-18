//! Obsidian connector implementation.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcp_prelude::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    HealthSnapshot, IdempotencyClass, Introspection, InvokeRequest, InvokeResponse, OperationId,
    OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId, ShutdownRequest,
    SimulateRequest, SimulateResponse,
};
use fcp_sdk::prelude::*;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::client::ObsidianClient;

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

// Operation IDs
const OP_NOTES_LIST: &str = "obsidian.notes.list";
const OP_NOTES_GET: &str = "obsidian.notes.get";
const OP_NOTES_CREATE: &str = "obsidian.notes.create";
const OP_NOTES_UPDATE: &str = "obsidian.notes.update";
const OP_NOTES_DELETE: &str = "obsidian.notes.delete";
const OP_SEARCH: &str = "obsidian.search";
const OP_TAGS_LIST: &str = "obsidian.tags.list";
const OP_BACKLINKS_GET: &str = "obsidian.backlinks.get";
const OP_HEALTH: &str = "obsidian.health";

// Capability IDs
const CAP_READ: &str = "obsidian.read";
const CAP_WRITE: &str = "obsidian.write";
const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/obsidian_connector_verification.sh";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/obsidian_connector/<timestamp>";
const VERIFY_COMMANDS: [&str; 6] = [
    "scripts/e2e/obsidian_connector_verification.sh",
    "rch exec -- cargo run -q -p fwc -- manifest fix connectors/obsidian/manifest.toml --check --json",
    "rch exec -- cargo check -p fcp-obsidian --all-targets",
    "cargo fmt -p fcp-obsidian -- --check",
    "rch exec -- cargo test -p fcp-obsidian --test integration -- --nocapture",
    "rch exec -- cargo clippy -p fcp-obsidian --all-targets -- -D warnings",
];

/// Obsidian connector configuration.
#[derive(Debug, Clone, Deserialize)]
struct ObsidianConfig {
    vault_path: String,
    #[serde(default = "default_request_timeout_ms")]
    request_timeout_ms: u64,
}

const fn default_request_timeout_ms() -> u64 {
    10_000
}

#[derive(Debug, Clone, serde::Serialize)]
struct ProvisioningReadiness {
    vault_path: String,
    request_timeout_ms: u64,
    local_only: bool,
    markdown_only: bool,
    hidden_directories_skipped: bool,
    write_probe_path: &'static str,
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

fn operator_guidance() -> OperatorGuidance {
    OperatorGuidance {
        prerequisites: vec![
            "Prepare a disposable Obsidian vault directory or sanitized fixture vault before running verification.",
            "Ensure the configured vault_path already exists and the connector process has read access; add write access if you need create, update, delete, or writable-health coverage.",
            "Keep verification fixtures markdown-only for the first slice because non-.md artifacts are intentionally excluded from note discovery and search evidence.",
        ],
        dedicated_environment: "Use a disposable or copied vault, never a live personal/work vault. create, update, and delete mutate real files, and health performs a temporary .fcp_write_test probe in the vault root.",
        redaction_rules: vec![
            "Redact absolute vault paths before sharing logs or stored evidence bundles outside the local machine.",
            "Treat note titles, note bodies, search excerpts, tags, backlink contexts, and folder names as potentially sensitive knowledge-base data.",
            "If artifacts are archived, replace personal or work notes with sanitized fixtures first so no live vault content is preserved in logs.",
        ],
        limitations: vec![
            "This connector is local-only and does not talk to Obsidian Sync, the Local REST API plugin, or any remote service.",
            "Only markdown files participate in note listing, search, tags, backlinks, and health counts; hidden directories such as .obsidian are skipped.",
            "Tag extraction and backlink discovery are best-effort text scans rather than full YAML parsing or graph-aware Obsidian semantics.",
        ],
        common_remediation: vec![
            RemediationHint {
                code: "invalid_vault_path",
                symptom: "configure fails because vault_path does not exist or is not a directory",
                action: "Point vault_path at an existing directory, then rerun configure and self_check.",
            },
            RemediationHint {
                code: "vault_read_only",
                symptom: "health or doctor reports writable=false and write operations fail",
                action: "Adjust filesystem permissions or rerun verification in a writable fixture vault before exercising create, update, or delete.",
            },
            RemediationHint {
                code: "path_validation_failed",
                symptom: "invoke rejects a note path with absolute, .., or null-byte content",
                action: "Use vault-relative markdown note paths such as daily/2026-03-21.md and keep all writes inside the configured vault root.",
            },
            RemediationHint {
                code: "note_not_found",
                symptom: "get, update, delete, or backlinks operations fail for a missing note path",
                action: "List notes first or seed the fixture vault with the expected markdown file before rerunning the operation.",
            },
        ],
        rerun_commands: VERIFY_COMMANDS.to_vec(),
        artifact_root_hint: ARTIFACT_ROOT_HINT,
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

/// Obsidian connector state.
#[derive(Debug)]
pub struct ObsidianConnector {
    base: BaseConnector,
    config: Option<ObsidianConfig>,
    client: Option<ObsidianClient>,
    runtime: Option<ConnectorRuntime>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl ObsidianConnector {
    /// Create a new connector instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.obsidian")),
            config: None,
            client: None,
            runtime: None,
            started_at: Instant::now(),
            verifier: None,
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

    fn provisioning_readiness(&self) -> Option<ProvisioningReadiness> {
        self.config.as_ref().map(|config| ProvisioningReadiness {
            vault_path: self.client.as_ref().map_or_else(
                || config.vault_path.clone(),
                |client| client.vault_path().to_string_lossy().to_string(),
            ),
            request_timeout_ms: config.request_timeout_ms,
            local_only: true,
            markdown_only: true,
            hidden_directories_skipped: true,
            write_probe_path: ".fcp_write_test",
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

    /// Run connector diagnostics.
    #[must_use]
    pub fn doctor(&self) -> DoctorResult {
        let provisioning = self.provisioning_readiness();
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
            name: "vault_accessible".into(),
            passed: client_ok,
            message: Some(if client_ok {
                format!(
                    "Vault accessible at: {}",
                    self.client
                        .as_ref()
                        .map(|c| c.vault_path().to_string_lossy().to_string())
                        .unwrap_or_default()
                )
            } else {
                "Vault client not initialized".into()
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

        if let Some(client) = &self.client {
            let health = client.vault_health();
            match health {
                Ok(h) => {
                    checks.push(DoctorCheck {
                        name: "vault_readable".into(),
                        passed: h.readable,
                        message: Some(format!(
                            "Vault readable, {} notes, {} bytes",
                            h.note_count, h.total_size_bytes
                        )),
                        critical: true,
                    });
                    checks.push(DoctorCheck {
                        name: "vault_writable".into(),
                        passed: h.writable,
                        message: Some(if h.writable {
                            "Vault is writable".into()
                        } else {
                            "Vault is read-only (write operations will fail)".into()
                        }),
                        critical: false,
                    });
                }
                Err(e) => {
                    checks.push(DoctorCheck {
                        name: "vault_health".into(),
                        passed: false,
                        message: Some(format!("Vault health check failed: {e}")),
                        critical: true,
                    });
                }
            }
        }

        DoctorResult::from_checks(checks, provisioning)
    }
}

impl Default for ObsidianConnector {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the typed operations catalog.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn operations_info() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static(OP_NOTES_LIST),
            summary: "List notes in the Obsidian vault".into(),
            description: Some("Lists all markdown notes, optionally filtered by folder".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "folder": { "type": "string", "description": "Optional folder path to filter by" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "notes": { "type": "array", "items": { "type": "object" } },
                    "count": { "type": "integer" }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to browse or list notes in the vault".into(),
                common_mistakes: vec![
                    "Folder paths are relative to the vault root".into(),
                ],
                examples: vec![r#"{"folder":"daily"}"#.into()],
                related: vec![CapabilityId::from_static(CAP_READ)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_NOTES_GET),
            summary: "Get a note by path".into(),
            description: Some("Retrieves the full content and metadata of a note".into()),
            input_schema: json!({
                "type": "object",
                "required": ["path"],
                "properties": {
                    "path": { "type": "string", "description": "Relative path to the note (e.g., 'folder/note.md')" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "title": { "type": "string" },
                    "content": { "type": "string" },
                    "size": { "type": "integer" },
                    "modified": { "type": "string" },
                    "created": { "type": "string" },
                    "tags": { "type": "array", "items": { "type": "string" } }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to read a specific note's content".into(),
                common_mistakes: vec![
                    "Path must be relative to vault root, e.g. 'daily/2026-03-21.md'".into(),
                ],
                examples: vec![r#"{"path":"daily/2026-03-21.md"}"#.into()],
                related: vec![CapabilityId::from_static(CAP_READ)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_NOTES_CREATE),
            summary: "Create a new note".into(),
            description: Some("Creates a new markdown note in the vault".into()),
            input_schema: json!({
                "type": "object",
                "required": ["path", "content"],
                "properties": {
                    "path": { "type": "string", "description": "Relative path for the new note" },
                    "content": { "type": "string", "description": "Markdown content" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "title": { "type": "string" },
                    "size": { "type": "integer" }
                }
            }),
            capability: CapabilityId::from_static(CAP_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to create a new note in the vault".into(),
                common_mistakes: vec![
                    "Will fail if a note already exists at the given path".into(),
                    "Parent directories are created automatically".into(),
                ],
                examples: vec![
                    r##"{"path":"inbox/idea.md","content":"# Idea\n\nBuild the Obsidian connector."}"##
                        .into(),
                ],
                related: vec![CapabilityId::from_static(CAP_WRITE)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_NOTES_UPDATE),
            summary: "Update an existing note".into(),
            description: Some("Replaces the content of an existing note".into()),
            input_schema: json!({
                "type": "object",
                "required": ["path", "content"],
                "properties": {
                    "path": { "type": "string", "description": "Path to the existing note" },
                    "content": { "type": "string", "description": "New markdown content" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "title": { "type": "string" },
                    "size": { "type": "integer" }
                }
            }),
            capability: CapabilityId::from_static(CAP_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to modify an existing note".into(),
                common_mistakes: vec![
                    "Will fail if the note does not exist; use create for new notes".into(),
                ],
                examples: vec![
                    r##"{"path":"daily/2026-03-21.md","content":"# Daily Log\n\nReviewed connector metadata."}"##
                        .into(),
                ],
                related: vec![CapabilityId::from_static(CAP_WRITE)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_NOTES_DELETE),
            summary: "Delete a note".into(),
            description: Some("Permanently deletes a note from the vault".into()),
            input_schema: json!({
                "type": "object",
                "required": ["path"],
                "properties": {
                    "path": { "type": "string", "description": "Path to the note to delete" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "deleted": { "type": "boolean" },
                    "path": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_WRITE),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to permanently delete a note".into(),
                common_mistakes: vec![
                    "This is irreversible - the note is permanently removed from the filesystem"
                        .into(),
                ],
                examples: vec![r#"{"path":"archive/old-note.md"}"#.into()],
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        OperationInfo {
            id: OperationId::from_static(OP_SEARCH),
            summary: "Search notes by text".into(),
            description: Some("Case-insensitive full-text search across all vault notes".into()),
            input_schema: json!({
                "type": "object",
                "required": ["query"],
                "properties": {
                    "query": { "type": "string", "description": "Text to search for" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "results": { "type": "array" },
                    "count": { "type": "integer" }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to find notes containing specific text".into(),
                common_mistakes: vec!["Search is case-insensitive".into()],
                examples: vec![r#"{"query":"meeting notes"}"#.into()],
                related: vec![CapabilityId::from_static(CAP_READ)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_TAGS_LIST),
            summary: "List all tags in the vault".into(),
            description: Some(
                "Returns all tags used across vault notes with usage counts".into(),
            ),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "tags": { "type": "array" },
                    "count": { "type": "integer" }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to see what tags are used in the vault".into(),
                common_mistakes: Vec::new(),
                examples: vec![r"{}".into()],
                related: vec![CapabilityId::from_static(CAP_READ)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_BACKLINKS_GET),
            summary: "Get backlinks for a note".into(),
            description: Some(
                "Finds all notes that contain a [[wikilink]] to the specified note".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["path"],
                "properties": {
                    "path": { "type": "string", "description": "Path to the note to find backlinks for" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "backlinks": { "type": "array" },
                    "count": { "type": "integer" }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to find which notes reference a given note".into(),
                common_mistakes: vec![
                    "Uses Obsidian [[wikilink]] syntax for detection".into(),
                ],
                examples: vec![r#"{"path":"projects/flywheel.md"}"#.into()],
                related: vec![CapabilityId::from_static(CAP_READ)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_HEALTH),
            summary: "Get vault health status".into(),
            description: Some(
                "Returns vault health including note count, size, and read/write status".into(),
            ),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "vault_path": { "type": "string" },
                    "note_count": { "type": "integer" },
                    "total_size_bytes": { "type": "integer" },
                    "readable": { "type": "boolean" },
                    "writable": { "type": "boolean" }
                }
            }),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to check if the vault is accessible and healthy".into(),
                common_mistakes: Vec::new(),
                examples: vec![r"{}".into()],
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
    ]
}

fcp_core::impl_fcp_sealed!(ObsidianConnector);

#[async_trait]
impl FcpConnector for ObsidianConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config: ObsidianConfig =
            serde_json::from_value(config).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid Obsidian config: {e}"),
            })?;

        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(config.request_timeout_ms)),
        ));

        let client =
            ObsidianClient::new(&config.vault_path).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Failed to open vault: {e}"),
            })?;

        self.client = Some(client);
        self.config = Some(config);
        self.base.set_configured(true);
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        if let Some(requested_instance_id) = req.requested_instance_id {
            self.base.instance_id = requested_instance_id;
        }

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
            None => HealthSnapshot::error("vault client not initialized"),
            Some(_) if self.runtime.is_none() => HealthSnapshot::error("runtime not initialized"),
            Some(client) => match client.vault_health() {
                Ok(health) if !health.readable => HealthSnapshot::degraded("vault not readable"),
                Ok(health) if !health.writable => {
                    HealthSnapshot::degraded("vault is readable but not writable")
                }
                Ok(_) => HealthSnapshot::ready(),
                Err(error) => HealthSnapshot::error(format!("vault health check failed: {error}")),
            },
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

        match client.vault_health() {
            Ok(health) if !health.readable => Ok(self.attach_self_check_details(
                SelfCheckReport::failed("vault_not_readable", "Vault directory is not readable"),
                Some(&json!(health)),
            )),
            Ok(health) => {
                let live_probe = json!(health);
                if health.writable {
                    Ok(self.attach_self_check_details(SelfCheckReport::ok(), Some(&live_probe)))
                } else {
                    Ok(self.attach_self_check_details(
                        SelfCheckReport::degraded(
                            "vault_read_only",
                            "Vault is readable but not writable; create, update, delete, and writable health probes will fail",
                        ),
                        Some(&live_probe),
                    ))
                }
            }
            Err(e) => Ok(self.attach_self_check_details(
                SelfCheckReport::failed("vault_check_failed", e.to_string()),
                None,
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

impl ObsidianConnector {
    #[allow(clippy::too_many_lines)]
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();

        let verifier = self.verifier.as_ref().ok_or(FcpError::Internal {
            message: "Capability verifier missing after successful handshake".into(),
        })?;
        let required_cap = match operation {
            OP_NOTES_LIST | OP_NOTES_GET | OP_SEARCH | OP_TAGS_LIST | OP_BACKLINKS_GET
            | OP_HEALTH => CapabilityId::from_static(CAP_READ),
            OP_NOTES_CREATE | OP_NOTES_UPDATE | OP_NOTES_DELETE => {
                CapabilityId::from_static(CAP_WRITE)
            }
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };
        // dja9u.1.c: typestate handoff via verify_bound.
        let _bound =
            verifier.verify_bound(req.capability_token, &required_cap, &req.operation, &[])?;

        let client = self.client.as_ref().ok_or(FcpError::Internal {
            message: "Obsidian client missing after configure".into(),
        })?;

        let output = match operation {
            OP_NOTES_LIST => {
                let folder = req.input.get("folder").and_then(serde_json::Value::as_str);
                let notes = client.list_notes(folder).map_err(|e| e.to_fcp_error())?;
                let count = notes.len();
                json!({ "notes": notes, "count": count })
            }
            OP_NOTES_GET => {
                let path = req
                    .input
                    .get("path")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'path' field".into(),
                    })?;
                let note = client.get_note(path).map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(note).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize note: {e}"),
                })?
            }
            OP_NOTES_CREATE => {
                let path = req
                    .input
                    .get("path")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'path' field".into(),
                    })?;
                let content = req
                    .input
                    .get("content")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'content' field".into(),
                    })?;
                let note = client
                    .create_note(path, content)
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(note).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize note: {e}"),
                })?
            }
            OP_NOTES_UPDATE => {
                let path = req
                    .input
                    .get("path")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'path' field".into(),
                    })?;
                let content = req
                    .input
                    .get("content")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'content' field".into(),
                    })?;
                let note = client
                    .update_note(path, content)
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(note).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize note: {e}"),
                })?
            }
            OP_NOTES_DELETE => {
                let path = req
                    .input
                    .get("path")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'path' field".into(),
                    })?;
                client.delete_note(path).map_err(|e| e.to_fcp_error())?;
                json!({ "deleted": true, "path": path })
            }
            OP_SEARCH => {
                let query = req
                    .input
                    .get("query")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'query' field".into(),
                    })?;
                let results = client.search(query).map_err(|e| e.to_fcp_error())?;
                let count = results.len();
                json!({ "results": results, "count": count })
            }
            OP_TAGS_LIST => {
                let tags = client.list_tags().map_err(|e| e.to_fcp_error())?;
                let count = tags.len();
                json!({ "tags": tags, "count": count })
            }
            OP_BACKLINKS_GET => {
                let path = req
                    .input
                    .get("path")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'path' field".into(),
                    })?;
                let backlinks = client.get_backlinks(path).map_err(|e| e.to_fcp_error())?;
                let count = backlinks.len();
                json!({ "backlinks": backlinks, "count": count })
            }
            OP_HEALTH => {
                let health = client.vault_health().map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(health).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize health: {e}"),
                })?
            }
            _ => unreachable!(),
        };

        Ok(InvokeResponse::ok(req.id, output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connector_id() {
        let connector = ObsidianConnector::new();
        assert_eq!(connector.id().as_str(), "fcp.obsidian");
    }

    #[test]
    fn default_connector() {
        let connector = ObsidianConnector::default();
        assert!(connector.config.is_none());
    }

    #[test]
    fn manifest_hash_deterministic() {
        let h1 = ObsidianConnector::manifest_hash();
        let h2 = ObsidianConnector::manifest_hash();
        assert_eq!(h1, h2);
        assert!(h1.starts_with("sha256:"));
    }

    #[test]
    fn operations_catalog() {
        let ops = operations_info();
        assert_eq!(ops.len(), 9);
        let ids: Vec<&str> = ops.iter().map(|o| o.id.as_str()).collect();
        assert!(ids.contains(&"obsidian.notes.list"));
        assert!(ids.contains(&"obsidian.notes.get"));
        assert!(ids.contains(&"obsidian.notes.create"));
        assert!(ids.contains(&"obsidian.notes.update"));
        assert!(ids.contains(&"obsidian.notes.delete"));
        assert!(ids.contains(&"obsidian.search"));
        assert!(ids.contains(&"obsidian.tags.list"));
        assert!(ids.contains(&"obsidian.backlinks.get"));
        assert!(ids.contains(&"obsidian.health"));
    }

    #[test]
    fn delete_is_dangerous() {
        let ops = operations_info();
        let delete = ops
            .iter()
            .find(|o| o.id.as_str() == "obsidian.notes.delete")
            .unwrap();
        assert_eq!(delete.safety_tier, SafetyTier::Dangerous);
        assert_eq!(delete.risk_level, RiskLevel::High);
        assert_eq!(delete.requires_approval, Some(ApprovalMode::Interactive));
    }

    #[test]
    fn create_is_risky() {
        let ops = operations_info();
        let create = ops
            .iter()
            .find(|o| o.id.as_str() == "obsidian.notes.create")
            .unwrap();
        assert_eq!(create.safety_tier, SafetyTier::Risky);
        assert_eq!(create.risk_level, RiskLevel::Medium);
    }

    #[test]
    fn list_is_safe() {
        let ops = operations_info();
        let list = ops
            .iter()
            .find(|o| o.id.as_str() == "obsidian.notes.list")
            .unwrap();
        assert_eq!(list.safety_tier, SafetyTier::Safe);
        assert_eq!(list.risk_level, RiskLevel::Low);
        assert_eq!(list.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn search_has_no_idempotency() {
        let ops = operations_info();
        let search = ops
            .iter()
            .find(|o| o.id.as_str() == "obsidian.search")
            .unwrap();
        assert_eq!(search.idempotency, IdempotencyClass::None);
    }

    #[test]
    fn introspect_has_all_operations() {
        let connector = ObsidianConnector::new();
        let intro = connector.introspect();
        assert_eq!(intro.operations.len(), 9);
    }

    #[test]
    fn doctor_unconfigured() {
        let connector = ObsidianConnector::new();
        let result = connector.doctor();
        assert!(!result.passed);
        assert!(
            result
                .checks
                .iter()
                .any(|c| c.name == "configuration" && !c.passed)
        );
    }

    #[fcp_async_core::runtime::test]
    async fn health_unconfigured() {
        let connector = ObsidianConnector::new();
        let health = connector.health().await;
        assert!(matches!(
            health.status,
            fcp_core::HealthState::Degraded { .. } | fcp_core::HealthState::Error { .. }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_unconfigured() {
        let connector = ObsidianConnector::new();
        let report = connector.self_check().await.unwrap();
        // Should be degraded since not configured
        assert!(report.reason_code.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_allowed() {
        use fcp_prelude::{CapabilityToken, ZoneId};
        let connector = ObsidianConnector::new();
        let req = SimulateRequest::new(
            ConnectorId::from_static("fcp.obsidian"),
            OperationId::from_static("obsidian.notes.list"),
            ZoneId::work(),
            json!({}),
            CapabilityToken::test_token(),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(matches!(resp, SimulateResponse { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn configure_valid_vault() {
        let dir = tempfile::tempdir().unwrap();
        let mut connector = ObsidianConnector::new();
        let config = json!({
            "vault_path": dir.path().to_str().unwrap()
        });
        let result = connector.configure(config).await;
        assert!(result.is_ok());
        assert!(connector.config.is_some());
        assert!(connector.client.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn configure_invalid_vault() {
        let mut connector = ObsidianConnector::new();
        let config = json!({
            "vault_path": "/nonexistent/vault"
        });
        let result = connector.configure(config).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn subscribe_not_supported() {
        use fcp_prelude::RequestId;
        let connector = ObsidianConnector::new();
        let req = SubscribeRequest {
            r#type: "subscribe".into(),
            id: RequestId::new("test-sub"),
            topics: vec![],
            since: None,
            max_events_per_sec: None,
            batch_ms: None,
            window_size: None,
            capability_token: None,
        };
        let result = connector.subscribe(req).await;
        assert!(matches!(result, Err(FcpError::StreamingNotSupported)));
    }

    #[test]
    fn read_ops_use_read_capability() {
        let ops = operations_info();
        let read_ops = [
            "obsidian.notes.list",
            "obsidian.notes.get",
            "obsidian.search",
            "obsidian.tags.list",
            "obsidian.backlinks.get",
            "obsidian.health",
        ];
        for op_id in read_ops {
            let op = ops.iter().find(|o| o.id.as_str() == op_id).unwrap();
            assert_eq!(
                op.capability.as_str(),
                "obsidian.read",
                "op {op_id} should use read cap"
            );
        }
    }

    #[test]
    fn write_ops_use_write_capability() {
        let ops = operations_info();
        let write_ops = [
            "obsidian.notes.create",
            "obsidian.notes.update",
            "obsidian.notes.delete",
        ];
        for op_id in write_ops {
            let op = ops.iter().find(|o| o.id.as_str() == op_id).unwrap();
            assert_eq!(
                op.capability.as_str(),
                "obsidian.write",
                "op {op_id} should use write cap"
            );
        }
    }

    #[test]
    fn every_operation_has_valid_examples() {
        let ops = operations_info();
        for op in ops {
            assert!(
                !op.ai_hints.examples.is_empty(),
                "operation {} should have at least one example",
                op.id.as_str()
            );
            for example in &op.ai_hints.examples {
                let parsed: serde_json::Value =
                    serde_json::from_str(example).unwrap_or_else(|err| {
                        panic!(
                            "operation {} has invalid JSON example {example:?}: {err}",
                            op.id.as_str()
                        )
                    });
                assert!(
                    parsed.is_object(),
                    "operation {} example should be a JSON object: {example}",
                    op.id.as_str()
                );
            }
        }
    }
}
