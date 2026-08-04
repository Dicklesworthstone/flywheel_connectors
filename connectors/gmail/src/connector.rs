//! FCP Gmail Connector implementation.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use fcp_google_discovery::{
    auth::{GoogleAuthError, GoogleAuthSelection, GoogleAuthSourceKind, GoogleMaterializedAuth},
    provisioning::load_default_google_provisioning_bundle,
};
use fcp_prelude::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken,
    CapabilityVerifier, ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, IdempotencyClass, InstanceId, Introspection, OperationId, OperationInfo,
    RiskLevel, SafetyTier, SelfCheckReport, SessionId, SimulateRequest, SimulateResponse,
    reject_secret_config_material,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, GmailClient},
    error::GmailError,
};

const DEFAULT_HISTORY_CURSOR_FILE: &str = "fcp-gmail-history-cursor.json";
const MANIFEST_TOML: &str = include_str!("../manifest.toml");

#[derive(Debug, Clone)]
struct GmailConfig {
    auth: GoogleMaterializedAuth,
    base_url: String,
    required_scopes: Vec<String>,
    granted_scopes: Vec<String>,
    history_cursor_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GmailHistoryCursorState {
    next_history_id: String,
    lease_seq: u64,
    #[serde(default)]
    lease_object_id: Option<String>,
    updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    message: String,
    critical: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorResult {
    status: DoctorStatus,
    checks: Vec<DoctorCheck>,
}

impl DoctorResult {
    fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let status = if checks.iter().any(|check| check.critical && !check.passed) {
            DoctorStatus::Unhealthy
        } else if checks.iter().any(|check| !check.passed) {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };
        Self { status, checks }
    }
}

/// FCP Gmail Connector.
pub struct GmailConnector {
    base: Arc<BaseConnector>,
    config: Option<GmailConfig>,
    client: Option<GmailClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
}

impl GmailConnector {
    /// Create a new Gmail connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("gmail"))),
            config: None,
            client: None,
            verifier: None,
            session_id: None,
        }
    }

    /// Return the connector instance identifier used for bound capability tokens.
    #[must_use]
    pub fn instance_id(&self) -> &InstanceId {
        &self.base.instance_id
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    /// Handle configure method.
    ///
    /// Uses the shared `GoogleAuthSelection` from `fcp-google-discovery`, but
    /// the connector configure boundary only accepts secretless credential
    /// references. Direct bearer material stays limited to low-level client
    /// tests and internal auth substrate coverage.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the configuration is invalid or client creation fails.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        reject_secret_config_material(&params)?;
        let base_url = parse_base_url(&params)?;
        let required_scopes = resolve_gmail_required_scopes(&params)?;
        let history_cursor_path = parse_history_cursor_path(&params)?;
        let mut auth_params = params.clone();
        let auth_object = auth_params
            .as_object_mut()
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "configure params must be a JSON object".into(),
            })?;
        auth_object.insert(
            "required_scopes".to_string(),
            json!(required_scopes.clone()),
        );

        // Use shared Google auth substrate for credential resolution.
        let selection =
            GoogleAuthSelection::from_connector_config(&auth_params).map_err(map_auth_error)?;

        let materialized =
            selection
                .materialize()
                .await
                .map_err(|error| FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Failed to materialize Google auth: {error}"),
                })?;

        let granted_scopes = materialized.granted_scopes().to_vec();

        let status = match &materialized {
            GoogleMaterializedAuth::CredentialReference { .. } => {
                "configured_pending_token_materialization"
            }
            GoogleMaterializedAuth::BearerToken { .. } => "configured",
        };

        let mut details = json!({
            "base_url": base_url,
            "required_scopes": required_scopes,
            "history_cursor_path": history_cursor_path.to_string_lossy().to_string(),
        });

        if !granted_scopes.is_empty() {
            details["granted_scopes"] = json!(granted_scopes);
        }

        if let GoogleMaterializedAuth::CredentialReference { credential_id, .. } = &materialized {
            details["credential_id"] = json!(credential_id.to_string());
            details["note"] = json!(
                "credential_id configured; live calls require egress proxy token materialization"
            );
        }

        let client = GmailClient::new_with_auth(materialized.clone())
            .map_err(|e| FcpError::Internal {
                message: format!("Failed to create HTTP client: {e}"),
            })?
            .with_base_url(base_url.clone());

        self.config = Some(GmailConfig {
            auth: materialized,
            base_url: base_url.clone(),
            required_scopes,
            granted_scopes,
            history_cursor_path,
        });
        self.client = Some(client);
        self.base.set_configured(true);

        let auth_label = self.config.as_ref().map_or_else(
            || "unknown".to_string(),
            |config| auth_label_for_materialized(&config.auth),
        );
        info!(auth = %auth_label, status, "Gmail connector configured");

        Ok(json!({ "status": status, "details": details }))
    }

    /// Handle handshake method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the request is invalid or serialization fails.
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
                min_buffer_events: 100,
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
    ///
    /// # Errors
    /// Returns [`FcpError`] if the health status cannot be determined.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let metrics = self.base.metrics();
        let scope_limited_operations = self
            .config
            .as_ref()
            .filter(|config| granted_scopes_are_authoritative(config))
            .map_or_else(Vec::new, missing_scope_limited_operations);
        let status = match self.config.as_ref() {
            Some(GmailConfig {
                auth: GoogleMaterializedAuth::CredentialReference { .. },
                ..
            }) => "degraded_pending_credential_materialization",
            Some(_) if !scope_limited_operations.is_empty() => "degraded_scope_limited",
            Some(_) => "healthy",
            None => "not_configured",
        };
        let auth_label = self.config.as_ref().map_or_else(
            || "unconfigured".to_string(),
            |config| auth_label_for_materialized(&config.auth),
        );
        Ok(json!({
            "status": status,
            "auth_mode": auth_label,
            "base_url": self.config.as_ref().map(|config| config.base_url.clone()),
            "history_cursor_path": self.config.as_ref().map(|config| config.history_cursor_path.to_string_lossy().to_string()),
            "required_scopes": self.config.as_ref().map(|config| config.required_scopes.clone()).unwrap_or_default(),
            "granted_scopes": self.config.as_ref().map(|config| config.granted_scopes.clone()).unwrap_or_default(),
            "scope_limited_operations": scope_limited_operations,
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        }))
    }

    /// Handle doctor checks.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let result = self.build_doctor_result().await;
        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize doctor result: {e}"),
        })
    }

    async fn build_doctor_result(&self) -> DoctorResult {
        let mut checks = Vec::new();

        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: if self.config.is_some() {
                "Configuration loaded".into()
            } else {
                "Not configured - call configure first".into()
            },
            critical: true,
        });

        let Some(config) = &self.config else {
            return DoctorResult::from_checks(checks);
        };

        checks.push(DoctorCheck {
            name: "auth_mode".into(),
            passed: true,
            message: format!("Auth mode: {}", auth_label_for_materialized(&config.auth)),
            critical: false,
        });

        checks.push(DoctorCheck {
            name: "network_constraints".into(),
            passed: endpoint_allowed_by_policy(&config.base_url),
            message: if endpoint_allowed_by_policy(&config.base_url) {
                format!("Endpoint accepted by policy checks: {}", config.base_url)
            } else {
                format!(
                    "Endpoint must use https or localhost/127.0.0.1 for tests: {}",
                    config.base_url
                )
            },
            critical: true,
        });

        match (&config.auth, &self.client) {
            (GoogleMaterializedAuth::CredentialReference { credential_id, .. }, _) => {
                checks.push(DoctorCheck {
                    name: "credential_materialization".into(),
                    passed: false,
                    message: format!(
                        "credential_id {credential_id} configured; token materialization required by egress proxy"
                    ),
                    critical: false,
                });
                checks.push(DoctorCheck {
                    name: "read_only_connectivity".into(),
                    passed: false,
                    message: "Skipping live connectivity check in credential_id mode".into(),
                    critical: false,
                });
            }
            (GoogleMaterializedAuth::BearerToken { .. }, Some(client)) => {
                checks.push(DoctorCheck {
                    name: "credential_materialization".into(),
                    passed: true,
                    message: "Access token materialized in-memory".into(),
                    critical: false,
                });

                match client.health_check().await {
                    Ok(()) => checks.push(DoctorCheck {
                        name: "read_only_connectivity".into(),
                        passed: true,
                        message: "Read-only list_labels check succeeded".into(),
                        critical: true,
                    }),
                    Err(error) => checks.push(DoctorCheck {
                        name: "read_only_connectivity".into(),
                        passed: false,
                        message: format!("Read-only list_labels check failed: {error}"),
                        critical: true,
                    }),
                }
            }
            (_, None) => {
                checks.push(DoctorCheck {
                    name: "credential_materialization".into(),
                    passed: false,
                    message: "Auth mode configured but HTTP client not initialized".into(),
                    critical: true,
                });
            }
        }

        if !config.required_scopes.is_empty() {
            let (passed, message, critical) = match &config.auth {
                GoogleMaterializedAuth::BearerToken {
                    source: GoogleAuthSourceKind::OAuthRefresh,
                    ..
                } => {
                    let granted: BTreeSet<&str> =
                        config.granted_scopes.iter().map(String::as_str).collect();
                    let missing: Vec<String> = config
                        .required_scopes
                        .iter()
                        .filter(|scope| !granted.contains(scope.as_str()))
                        .cloned()
                        .collect();
                    if missing.is_empty() {
                        (true, "All required scopes are present".into(), true)
                    } else {
                        (
                            false,
                            format!("Missing required scopes: {}", missing.join(", ")),
                            true,
                        )
                    }
                }
                GoogleMaterializedAuth::CredentialReference { .. } => (
                    true,
                    "Scope validation deferred to credential_id materialization".into(),
                    false,
                ),
                GoogleMaterializedAuth::BearerToken { .. } => (
                    true,
                    "Direct access token mode; required scopes cannot be introspected post-configure"
                        .into(),
                    false,
                ),
            };
            checks.push(DoctorCheck {
                name: "scope_validation".into(),
                passed,
                message,
                critical,
            });
        }

        if granted_scopes_are_authoritative(config) {
            let missing_operations = missing_scope_limited_operations(config);
            checks.push(DoctorCheck {
                name: "operation_scope_coverage".into(),
                passed: missing_operations.is_empty(),
                message: if missing_operations.is_empty() {
                    "Known granted scopes cover all exposed Gmail operations".into()
                } else {
                    format!(
                        "Known granted scopes do not cover exposed operations: {}",
                        missing_operations.join(", ")
                    )
                },
                critical: false,
            });
        }

        DoctorResult::from_checks(checks)
    }

    /// Handle connector self-check for host doctor/readiness.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(config) = &self.config else {
            let report = SelfCheckReport::degraded("not_configured", "Connector is not configured");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        if matches!(
            config.auth,
            GoogleMaterializedAuth::CredentialReference { .. }
        ) {
            let mut report = SelfCheckReport::degraded(
                "credential_injection_required",
                "Configured with credential_id; readiness depends on egress proxy token injection",
            );
            report.details = Some(json!({
                "auth_mode": auth_label_for_materialized(&config.auth),
                "base_url": config.base_url,
            }));
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        }

        let Some(client) = &self.client else {
            let report = SelfCheckReport::failed(
                "client_not_initialized",
                "Connector is configured but HTTP client is unavailable",
            );
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        let mut report = match client.health_check().await {
            Ok(()) => SelfCheckReport::ok(),
            Err(err) => {
                if err.is_retryable() {
                    SelfCheckReport::degraded("self_check_retryable", err.to_string())
                } else {
                    SelfCheckReport::failed("self_check_failed", err.to_string())
                }
            }
        };
        let scope_limited_operations = if granted_scopes_are_authoritative(config) {
            missing_scope_limited_operations(config)
        } else {
            Vec::new()
        };
        if matches!(report.status, fcp_core::SelfCheckStatus::Ok)
            && !scope_limited_operations.is_empty()
        {
            report = SelfCheckReport::degraded(
                "scope_limited",
                format!(
                    "Known granted scopes do not cover exposed operations: {}",
                    scope_limited_operations.join(", ")
                ),
            );
        }
        report.details = Some(json!({
            "auth_mode": auth_label_for_materialized(&config.auth),
            "base_url": config.base_url,
            "history_cursor_path": config.history_cursor_path.to_string_lossy().to_string(),
            "required_scopes": config.required_scopes,
            "granted_scopes": config.granted_scopes,
            "scope_limited_operations": scope_limited_operations,
        }));

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }

    fn operations_info() -> Vec<OperationInfo> {
        vec![
                op_info(
                    "gmail.send_message",
                    "Send an email message",
                    json!({
                        "type": "object",
                        "properties": {
                            "raw": { "type": "string", "description": "Optional base64url-encoded RFC 2822 message" },
                            "to": { "type": "string", "description": "Recipient email address when raw is omitted" },
                            "subject": { "type": "string", "description": "Subject line when raw is omitted" },
                            "body": { "type": "string", "description": "Plaintext body when raw is omitted" }
                        },
                        "anyOf": [
                            { "required": ["raw"] },
                            { "required": ["to", "subject", "body"] }
                        ]
                    }),
                    json!({ "type": "object", "properties": { "message": { "type": "object" } } }),
                    "gmail.send",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::None,
                    Some(ApprovalMode::Interactive),
                    AgentHint {
                        when_to_use: "Send a new email. Provide either a prebuilt base64url MIME payload in raw or structured to/subject/body fields.".into(),
                        common_mistakes: vec!["Using standard base64 instead of base64url encoding for raw payloads".into()],
                        examples: vec![
                            r#"{"raw": "RnJvbTogc2VuZGVyQGV4YW1wbGUuY29tClRvOiByZWNpcGllbnRAZXhhbXBsZS5jb20KU3ViamVjdDogVGVzdAoKSGVsbG8h"}"#.into(),
                            r#"{"to": "recipient@example.com", "subject": "Test", "body": "Hello!"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("gmail.read")],
                    },
                ),
                op_info(
                    "gmail.get_message",
                    "Get a single email message by ID",
                    json!({
                        "type": "object",
                        "required": ["message_id"],
                        "properties": {
                            "message_id": { "type": "string", "description": "Gmail message ID" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "message": { "type": "object" } } }),
                    "gmail.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    None,
                    AgentHint {
                        when_to_use: "Retrieve full details of a specific email message.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"message_id": "18d1234abc567890"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("gmail.read")],
                    },
                ),
                op_info(
                    "gmail.list_messages",
                    "List email messages with optional search query",
                    json!({
                        "type": "object",
                        "properties": {
                            "query": { "type": "string", "description": "Gmail search query (same syntax as web UI)" },
                            "max_results": { "type": "integer", "description": "Max messages to return" },
                            "page_token": { "type": "string", "description": "Pagination token" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "messages": { "type": "array" },
                            "next_page_token": { "type": "string" },
                            "result_size_estimate": { "type": "integer" }
                        }
                    }),
                    "gmail.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    None,
                    AgentHint {
                        when_to_use: "List or search email messages. Uses Gmail search syntax.".into(),
                        common_mistakes: vec!["Expecting full message bodies; list returns only IDs and thread IDs".into()],
                        examples: vec![
                            r#"{"query": "from:notifications@github.com is:unread", "max_results": 10}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("gmail.read")],
                    },
                ),
                op_info(
                    "gmail.sync_history",
                    "Incrementally fetch mailbox history changes using historyId cursor state",
                    json!({
                        "type": "object",
                        "required": ["lease_seq"],
                        "properties": {
                            "start_history_id": { "type": "string", "description": "Optional historyId override for first sync or explicit reset" },
                            "max_results": { "type": "integer", "description": "Optional page size passed to Gmail History API" },
                            "history_types": { "type": "array", "items": { "type": "string" }, "description": "Optional history type filters (messageAdded, messageDeleted, labelAdded, labelRemoved)" },
                            "lease_seq": { "type": "integer", "description": "Singleton-writer fencing token; must not regress" },
                            "lease_object_id": { "type": "string", "description": "Optional lease object reference for diagnostics/audit" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["history", "latest_history_id", "effective_start_history_id", "lease_seq"],
                        "properties": {
                            "history": { "type": "array", "items": { "type": "object" } },
                            "history_count": { "type": "integer" },
                            "latest_history_id": { "type": "string" },
                            "effective_start_history_id": { "type": "string" },
                            "dedup_applied": { "type": "boolean" },
                            "used_persisted_cursor": { "type": "boolean" },
                            "lease_seq": { "type": "integer" },
                            "cursor_state_path": { "type": "string" }
                        }
                    }),
                    "gmail.history.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    None,
                    AgentHint {
                        when_to_use: "Perform incremental mailbox sync with persisted historyId cursor and restart-safe dedup semantics.".into(),
                        common_mistakes: vec![
                            "Not persisting or reusing historyId between runs, causing duplicate processing".into(),
                            "Sending stale lease_seq from an old writer after failover".into(),
                        ],
                        examples: vec![
                            r#"{"start_history_id":"1000","lease_seq":1,"lease_object_id":"lease-a"}"#.into(),
                            r#"{"history_types":["messageAdded","labelRemoved"],"lease_seq":2}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("gmail.read")],
                    },
                ),
                op_info(
                    "gmail.modify_message",
                    "Modify message labels (add or remove)",
                    json!({
                        "type": "object",
                        "required": ["message_id"],
                        "properties": {
                            "message_id": { "type": "string", "description": "Gmail message ID" },
                            "add_label_ids": { "type": "array", "items": { "type": "string" }, "description": "Label IDs to add" },
                            "remove_label_ids": { "type": "array", "items": { "type": "string" }, "description": "Label IDs to remove" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "message": { "type": "object" } } }),
                    "gmail.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::BestEffort,
                    Some(ApprovalMode::Policy),
                    AgentHint {
                        when_to_use: "Add or remove labels from a message (e.g., mark as read, archive).".into(),
                        common_mistakes: vec!["Using label names instead of label IDs".into()],
                        examples: vec![
                            r#"{"message_id": "18d1234abc", "remove_label_ids": ["UNREAD"]}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("gmail.read"),
                            CapabilityId::from_static("gmail.write"),
                        ],
                    },
                ),
                op_info(
                    "gmail.trash_message",
                    "Move a message to trash",
                    json!({
                        "type": "object",
                        "required": ["message_id"],
                        "properties": {
                            "message_id": { "type": "string", "description": "Gmail message ID" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "message": { "type": "object" } } }),
                    "gmail.delete",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::BestEffort,
                    Some(ApprovalMode::Policy),
                    AgentHint {
                        when_to_use: "Move an email message to the trash.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"message_id": "18d1234abc567890"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("gmail.read")],
                    },
                ),
                op_info(
                    "gmail.get_thread",
                    "Get an email thread with all messages",
                    json!({
                        "type": "object",
                        "required": ["thread_id"],
                        "properties": {
                            "thread_id": { "type": "string", "description": "Gmail thread ID" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "thread": { "type": "object" } } }),
                    "gmail.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    None,
                    AgentHint {
                        when_to_use: "Retrieve all messages in an email thread/conversation.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"thread_id": "18d1234abc567890"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("gmail.read")],
                    },
                ),
                op_info(
                    "gmail.list_labels",
                    "List all Gmail labels",
                    json!({ "type": "object", "properties": {} }),
                    json!({
                        "type": "object",
                        "properties": { "labels": { "type": "array", "items": { "type": "object" } } }
                    }),
                    "gmail.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    None,
                    AgentHint {
                        when_to_use: "List all labels in the Gmail account (system and user-created).".into(),
                        common_mistakes: vec![],
                        examples: vec!["{}".into()],
                        related: vec![CapabilityId::from_static("gmail.write")],
                    },
                ),
                op_info(
                    "gmail.get_draft",
                    "Get a draft by ID",
                    json!({
                        "type": "object",
                        "required": ["draft_id"],
                        "properties": {
                            "draft_id": { "type": "string", "description": "Gmail draft ID" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "draft": { "type": "object" } } }),
                    "gmail.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    Some(ApprovalMode::Policy),
                    AgentHint {
                        when_to_use: "Retrieve a saved email draft.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"draft_id": "r1234567890"}"#.into()],
                        related: vec![CapabilityId::from_static("gmail.send")],
                    },
                ),
                op_info(
                    "gmail.create_draft",
                    "Create a saved Gmail draft",
                    json!({
                        "type": "object",
                        "properties": {
                            "raw": { "type": "string", "description": "Optional base64url-encoded RFC 2822 message" },
                            "to": { "type": "string", "description": "Recipient email address when raw is omitted" },
                            "subject": { "type": "string", "description": "Subject line when raw is omitted" },
                            "body": { "type": "string", "description": "Plaintext body when raw is omitted" }
                        },
                        "anyOf": [
                            { "required": ["raw"] },
                            { "required": ["to", "subject", "body"] }
                        ]
                    }),
                    json!({ "type": "object", "properties": { "draft": { "type": "object" } } }),
                    "gmail.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    Some(ApprovalMode::Policy),
                    AgentHint {
                        when_to_use: "Create a saved draft without sending it. Provide either a prebuilt base64url MIME payload in raw or structured to/subject/body fields.".into(),
                        common_mistakes: vec![
                            "Assuming this sends mail; drafts remain unsent until gmail.send_draft is invoked".into(),
                            "Using standard base64 instead of base64url encoding for raw payloads".into(),
                        ],
                        examples: vec![
                            r#"{"to": "recipient@example.com", "subject": "Draft", "body": "Draft body"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("gmail.write"),
                            CapabilityId::from_static("gmail.send"),
                        ],
                    },
                ),
                op_info(
                    "gmail.send_draft",
                    "Send a previously saved draft",
                    json!({
                        "type": "object",
                        "required": ["draft_id"],
                        "properties": {
                            "draft_id": { "type": "string", "description": "Gmail draft ID" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "message": { "type": "object" } } }),
                    "gmail.send",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::None,
                    Some(ApprovalMode::Interactive),
                    AgentHint {
                        when_to_use: "Send a draft that was previously created and saved.".into(),
                        common_mistakes: vec!["The draft is deleted after sending".into()],
                        examples: vec![r#"{"draft_id": "r1234567890"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("gmail.write"),
                            CapabilityId::from_static("gmail.send"),
                        ],
                    },
                ),
        ]
    }

    /// Handle introspect method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if serialization of the introspection data fails.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: Self::operations_info(),
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
    ///
    /// # Errors
    /// Returns [`FcpError`] if the request is invalid or serialization fails.
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let req: SimulateRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid simulate request: {e}"),
            })?;

        let capability = match gmail_capability_for_operation(req.operation.as_str()) {
            Ok(capability) => capability,
            Err(error) => {
                let response =
                    SimulateResponse::denied(req.id, error.to_string(), error.error_code());
                return serde_json::to_value(response).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                });
            }
        };

        if let Err(error) = validate_gmail_input(req.operation.as_str(), &req.input) {
            let response = SimulateResponse::denied(req.id, error.to_string(), error.error_code());
            return serde_json::to_value(response).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize response: {e}"),
            });
        }

        if self.config.is_none() || self.client.is_none() {
            let response = SimulateResponse::denied(
                req.id,
                "Connector is not configured",
                FcpError::NotConfigured.error_code(),
            );
            return serde_json::to_value(response).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize response: {e}"),
            });
        }

        let Some(verifier) = &self.verifier else {
            let response = SimulateResponse::denied(
                req.id,
                "Connector handshake not completed",
                FcpError::NotHandshaken.error_code(),
            );
            return serde_json::to_value(response).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize response: {e}"),
            });
        };

        let resource_uris = gmail_resource_uris(req.operation.as_str(), &req.input);
        let response = match verifier.verify_bound(
            req.capability_token,
            &capability,
            &req.operation,
            &resource_uris,
        ) {
            Ok(_) => SimulateResponse::allowed(req.id),
            Err(error) => {
                let is_grant_mismatch = matches!(
                    error,
                    FcpError::CapabilityDenied { .. } | FcpError::OperationNotGranted { .. }
                );
                let mut response =
                    SimulateResponse::denied(req.id, error.to_string(), error.error_code());
                if is_grant_mismatch {
                    response = response.with_missing_capabilities(vec![capability.as_str().into()]);
                }
                response
            }
        };
        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    /// Handle invoke method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the operation fails or capability verification fails.
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
        let cap_id = gmail_capability_for_operation(operation)?;
        validate_gmail_input(operation, &input)?;
        self.base.check_ready()?;

        let verifier = self.verifier.as_ref().ok_or(FcpError::NotHandshaken)?;
        let resource_uris = gmail_resource_uris(operation, &input);
        verifier.verify_bound(token, &cap_id, &op_id, &resource_uris)?;

        match operation {
            "gmail.send_message" => self.invoke_send_message(input).await,
            "gmail.get_message" => self.invoke_get_message(input).await,
            "gmail.list_messages" => self.invoke_list_messages(input).await,
            "gmail.sync_history" => self.invoke_sync_history(input).await,
            "gmail.modify_message" => self.invoke_modify_message(input).await,
            "gmail.trash_message" => self.invoke_trash_message(input).await,
            "gmail.get_thread" => self.invoke_get_thread(input).await,
            "gmail.list_labels" => self.invoke_list_labels().await,
            "gmail.get_draft" => self.invoke_get_draft(input).await,
            "gmail.create_draft" => self.invoke_create_draft(input).await,
            "gmail.send_draft" => self.invoke_send_draft(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    // ── Operation implementations ─────────────────────────────────

    async fn invoke_send_message(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let raw = match input.get("raw").and_then(|value| value.as_str()) {
            Some(raw) => raw.to_owned(),
            None => build_raw_message_from_fields(&input)?,
        };

        let message = client
            .send_message(&raw)
            .await
            .map_err(|e: GmailError| e.to_fcp_error())?;

        Ok(json!({ "message": message }))
    }

    async fn invoke_get_message(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let message_id = require_str(&input, "message_id")?;

        let message = client
            .get_message(message_id)
            .await
            .map_err(|e: GmailError| e.to_fcp_error())?;

        Ok(json!({ "message": message }))
    }

    async fn invoke_list_messages(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let query = input.get("query").and_then(|v| v.as_str());
        let max_results = input
            .get("max_results")
            .and_then(|value| value.as_u64())
            .and_then(|value| u32::try_from(value).ok());
        let page_token = input.get("page_token").and_then(|v| v.as_str());

        let result = client
            .list_messages(query, max_results, page_token)
            .await
            .map_err(|e: GmailError| e.to_fcp_error())?;

        Ok(json!({
            "messages": result.messages,
            "next_page_token": result.next_page_token,
            "result_size_estimate": result.result_size_estimate
        }))
    }

    async fn invoke_sync_history(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;

        let requested_start = parse_optional_string_field(&input, "start_history_id")?;
        let max_results = input
            .get("max_results")
            .and_then(|value| value.as_u64())
            .map(|value| u32::try_from(value).unwrap_or(u32::MAX));
        let history_types = parse_history_types(&input)?;
        let provided_lease_seq = parse_optional_u64_field(&input, "lease_seq")?;
        let provided_lease_object_id = parse_optional_string_field(&input, "lease_object_id")?;
        let lease_seq = provided_lease_seq.ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "lease_seq is required for singleton_writer cursor advancement".into(),
        })?;

        let previous = load_history_cursor_state(&config.history_cursor_path)?;
        let (effective_start_history_id, dedup_applied, used_persisted_cursor) =
            determine_effective_start_history_id(requested_start, previous.as_ref())?;

        if let Some(previous_state) = previous.as_ref()
            && lease_seq < previous_state.lease_seq
        {
            return Err(FcpError::Conflict {
                message: format!(
                    "stale lease_seq for gmail history cursor: current={}, incoming={lease_seq}",
                    previous_state.lease_seq,
                ),
            });
        }

        let mut page_token: Option<String> = None;
        let mut history: Vec<serde_json::Value> = Vec::new();
        let mut latest_history_id = effective_start_history_id.clone();

        loop {
            let page = client
                .list_history(
                    &effective_start_history_id,
                    max_results,
                    page_token.as_deref(),
                    history_types.as_deref(),
                )
                .await
                .map_err(|error: GmailError| error.to_fcp_error())?;

            if let Some(history_id) = page.history_id {
                if compare_history_ids(&history_id, &latest_history_id) == Ordering::Greater {
                    latest_history_id = history_id;
                }
            }

            history.extend(page.history);

            if let Some(next) = page.next_page_token {
                page_token = Some(next);
            } else {
                break;
            }
        }

        if let Some(previous_state) = previous.as_ref()
            && compare_history_ids(&latest_history_id, &previous_state.next_history_id)
                == Ordering::Less
        {
            return Err(FcpError::Conflict {
                message: format!(
                    "history cursor regression detected: current={}, incoming={latest_history_id}",
                    previous_state.next_history_id
                ),
            });
        }

        let cursor_state = GmailHistoryCursorState {
            next_history_id: latest_history_id.clone(),
            lease_seq,
            lease_object_id: provided_lease_object_id.or_else(|| {
                previous
                    .as_ref()
                    .and_then(|state| state.lease_object_id.clone())
            }),
            updated_at: current_unix_timestamp_secs(),
        };
        persist_history_cursor_state(&config.history_cursor_path, &cursor_state)?;
        let history_count = history.len();

        Ok(json!({
            "history": history,
            "history_count": history_count,
            "latest_history_id": latest_history_id,
            "effective_start_history_id": effective_start_history_id,
            "dedup_applied": dedup_applied,
            "used_persisted_cursor": used_persisted_cursor,
            "lease_seq": lease_seq,
            "cursor_state_path": config.history_cursor_path.to_string_lossy().to_string(),
        }))
    }

    async fn invoke_modify_message(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let message_id = require_str(&input, "message_id")?;

        let add_labels = parse_optional_string_array_field(&input, "add_label_ids")?;
        let remove_labels = parse_optional_string_array_field(&input, "remove_label_ids")?;

        let message = client
            .modify_message(message_id, &add_labels, &remove_labels)
            .await
            .map_err(|e: GmailError| e.to_fcp_error())?;

        Ok(json!({ "message": message }))
    }

    async fn invoke_trash_message(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let message_id = require_str(&input, "message_id")?;

        let message = client
            .trash_message(message_id)
            .await
            .map_err(|e: GmailError| e.to_fcp_error())?;

        Ok(json!({ "message": message }))
    }

    async fn invoke_get_thread(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let thread_id = require_str(&input, "thread_id")?;

        let thread = client
            .get_thread(thread_id)
            .await
            .map_err(|e: GmailError| e.to_fcp_error())?;

        Ok(json!({ "thread": thread }))
    }

    async fn invoke_list_labels(&self) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let labels = client
            .list_labels()
            .await
            .map_err(|e: GmailError| e.to_fcp_error())?;

        Ok(json!({ "labels": labels }))
    }

    async fn invoke_get_draft(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let draft_id = require_str(&input, "draft_id")?;

        let draft = client
            .get_draft(draft_id)
            .await
            .map_err(|e: GmailError| e.to_fcp_error())?;

        Ok(json!({ "draft": draft }))
    }

    async fn invoke_create_draft(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let raw = match input.get("raw").and_then(|value| value.as_str()) {
            Some(raw) => raw.to_owned(),
            None => build_raw_message_from_fields(&input)?,
        };

        let draft = client
            .create_draft(&raw)
            .await
            .map_err(|e: GmailError| e.to_fcp_error())?;

        Ok(json!({ "draft": draft }))
    }

    async fn invoke_send_draft(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let draft_id = require_str(&input, "draft_id")?;

        let message = client
            .send_draft(draft_id)
            .await
            .map_err(|e: GmailError| e.to_fcp_error())?;

        Ok(json!({ "message": message }))
    }

    /// Handle shutdown.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the shutdown process fails.
    pub async fn handle_shutdown(
        &self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Gmail connector shutting down");
        if let Some(client) = &self.client {
            client.shutdown();
        }
        self.base.set_handshaken(false);
        self.base.set_configured(false);
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for GmailConnector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helper functions ──────────────────────────────────────────────

fn parse_base_url(params: &serde_json::Value) -> FcpResult<String> {
    let raw = params
        .get("base_url")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_BASE_URL);

    let parsed = Url::parse(raw).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("Invalid base_url: {error}"),
    })?;
    if !matches!(parsed.scheme(), "https" | "http") {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must use http or https".into(),
        });
    }
    let host = parsed.host_str().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "base_url must include a host".into(),
    })?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include userinfo".into(),
        });
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        // Query/fragment components survive into `format!("{base_url}/...",
        // ...)` URL construction downstream, letting an attacker-controlled
        // base_url leak arbitrary query values into every Gmail API request.
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include a query string or fragment".into(),
        });
    }
    let local = is_local_test_host(host);
    if parsed.scheme() == "http" && !local {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must use https unless targeting localhost/127.0.0.1 for tests"
                .into(),
        });
    }
    // Pin direct-token base_url to the Google API domain. Substring
    // smuggles like https://evil.com/gmail.googleapis.com are rejected
    // because we parse the URL and check the host component directly.
    // Vault-proxy / credential_id mode resolves the destination through
    // fcp-google-discovery's allowlist at fetch time; we still require
    // the configured base_url to be a googleapis.com host here so the
    // connector cannot be redirected at config time even before the
    // discovery fetcher runs.
    if !local && !host_is_googleapis(host) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "base_url must target googleapis.com (localhost/127.0.0.1/::1 allowed for tests): {raw}"
            ),
        });
    }

    Ok(raw.trim_end_matches('/').to_string())
}

fn host_is_googleapis(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    lower == "googleapis.com" || lower.ends_with(".googleapis.com")
}

fn parse_required_scopes(params: &serde_json::Value) -> FcpResult<Vec<String>> {
    let Some(value) = params.get("required_scopes") else {
        return Ok(Vec::new());
    };

    let scopes: Vec<String> =
        serde_json::from_value(value.clone()).map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "required_scopes must be an array of non-empty strings".into(),
        })?;

    let mut normalized = Vec::new();
    for scope in scopes {
        let scope = scope.trim();
        if scope.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "required_scopes entries must not be empty".into(),
            });
        }
        normalized.push(scope.to_string());
    }

    Ok(normalized)
}

fn parse_string_array_field(
    params: &serde_json::Value,
    field: &str,
) -> FcpResult<Option<Vec<String>>> {
    let Some(value) = params.get(field) else {
        return Ok(None);
    };

    let values = value.as_array().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: format!("`{field}` must be an array of non-empty strings"),
    })?;
    if values.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("`{field}` must not be empty"),
        });
    }

    let mut normalized = Vec::new();
    for value in values {
        let item = value.as_str().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("`{field}` must contain only strings"),
        })?;
        let trimmed = item.trim();
        if trimmed.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("`{field}` entries must not be empty"),
            });
        }
        normalized.push(trimmed.to_string());
    }

    Ok(Some(normalized))
}

fn resolve_gmail_required_scopes(params: &serde_json::Value) -> FcpResult<Vec<String>> {
    let explicit_scopes = parse_required_scopes(params)?;
    let scope_triggers = parse_string_array_field(params, "scope_triggers")?.unwrap_or_default();
    if !explicit_scopes.is_empty() && !scope_triggers.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "Provide either `required_scopes` or `scope_triggers`, not both".into(),
        });
    }
    if !explicit_scopes.is_empty() {
        return validate_declared_gmail_scopes(explicit_scopes);
    }

    let bundle =
        load_default_google_provisioning_bundle("gmail").map_err(|error| FcpError::Internal {
            message: format!("Failed to load embedded Gmail provisioning bundle: {error}"),
        })?;
    bundle
        .scopes_for_triggers(scope_triggers)
        .map_err(|error| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid Gmail scope trigger selection: {error}"),
        })
}

fn validate_declared_gmail_scopes(scopes: Vec<String>) -> FcpResult<Vec<String>> {
    let bundle =
        load_default_google_provisioning_bundle("gmail").map_err(|error| FcpError::Internal {
            message: format!("Failed to load embedded Gmail provisioning bundle: {error}"),
        })?;
    let mut allowed = BTreeSet::new();
    allowed.extend(bundle.surface.default_scopes);
    for escalation in bundle.surface.escalation_paths {
        allowed.extend(escalation.add_scopes);
    }

    let normalized: Vec<String> = scopes
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let undeclared: Vec<String> = normalized
        .iter()
        .filter(|scope| !allowed.contains(scope.as_str()))
        .cloned()
        .collect();
    if !undeclared.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "required_scopes contains scopes outside the Gmail provisioning policy: {}",
                undeclared.join(", ")
            ),
        });
    }

    Ok(normalized)
}

#[allow(clippy::needless_pass_by_value)] // required by map_err(fn) signature
fn map_auth_error(error: GoogleAuthError) -> FcpError {
    match &error {
        GoogleAuthError::ExactlyOneSourceRequired { count: 0 } => FcpError::InvalidRequest {
            code: 1003,
            message: "Provide exactly one auth source: none supplied".into(),
        },
        GoogleAuthError::ExactlyOneSourceRequired { .. } => FcpError::InvalidRequest {
            code: 1003,
            message: format!("Provide exactly one auth source: {error}"),
        },
        _ => FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid Google auth configuration: {error}"),
        },
    }
}

fn parse_history_cursor_path(params: &serde_json::Value) -> FcpResult<PathBuf> {
    if let Some(path) = params.get("history_cursor_path") {
        let raw = path.as_str().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "history_cursor_path must be a string".into(),
        })?;
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "history_cursor_path must not be empty".into(),
            });
        }
        return Ok(PathBuf::from(trimmed));
    }

    if let Some(state_dir) = params.get("state_dir") {
        let raw = state_dir.as_str().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "state_dir must be a string".into(),
        })?;
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "state_dir must not be empty".into(),
            });
        }
        return Ok(PathBuf::from(trimmed).join(DEFAULT_HISTORY_CURSOR_FILE));
    }

    Ok(PathBuf::from(DEFAULT_HISTORY_CURSOR_FILE))
}

fn parse_optional_string_field(
    input: &serde_json::Value,
    field: &str,
) -> FcpResult<Option<String>> {
    match input.get(field) {
        None => Ok(None),
        Some(value) => {
            let value = value.as_str().ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: format!("{field} must be a string"),
            })?;
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("{field} must not be empty"),
                });
            }
            Ok(Some(trimmed.to_string()))
        }
    }
}

fn parse_optional_u64_field(input: &serde_json::Value, field: &str) -> FcpResult<Option<u64>> {
    match input.get(field) {
        None => Ok(None),
        Some(value) => value.as_u64().map(Some).ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must be an unsigned integer"),
        }),
    }
}

fn parse_history_types(input: &serde_json::Value) -> FcpResult<Option<Vec<String>>> {
    let Some(value) = input.get("history_types") else {
        return Ok(None);
    };
    let values: Vec<String> =
        serde_json::from_value(value.clone()).map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "history_types must be an array of non-empty strings".into(),
        })?;

    let mut normalized = Vec::with_capacity(values.len());
    for history_type in values {
        let trimmed = history_type.trim();
        if trimmed.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "history_types entries must not be empty".into(),
            });
        }
        normalized.push(trimmed.to_string());
    }
    if normalized.is_empty() {
        return Ok(None);
    }
    Ok(Some(normalized))
}

fn required_capability_for_operation(operation: &str) -> Option<&'static str> {
    match operation {
        "gmail.send_message" | "gmail.send_draft" => Some("gmail.send"),
        "gmail.get_message" | "gmail.list_messages" | "gmail.get_thread" | "gmail.list_labels" => {
            Some("gmail.read")
        }
        "gmail.sync_history" => Some("gmail.history.read"),
        "gmail.modify_message" | "gmail.get_draft" | "gmail.create_draft" => Some("gmail.write"),
        "gmail.trash_message" => Some("gmail.delete"),
        _ => None,
    }
}

fn gmail_capability_for_operation(operation: &str) -> FcpResult<CapabilityId> {
    required_capability_for_operation(operation)
        .map(CapabilityId::from_static)
        .ok_or_else(|| FcpError::OperationNotGranted {
            operation: operation.into(),
        })
}

fn validate_gmail_input(operation: &str, input: &serde_json::Value) -> FcpResult<()> {
    match operation {
        "gmail.send_message" | "gmail.create_draft" => {
            if input.get("raw").and_then(|value| value.as_str()).is_some() {
                Ok(())
            } else {
                build_raw_message_from_fields(input).map(|_| ())
            }
        }
        "gmail.get_message" | "gmail.trash_message" => require_str(input, "message_id").map(|_| ()),
        "gmail.list_messages" => {
            validate_optional_string_field(input, "query")?;
            validate_optional_u32_field(input, "max_results")?;
            validate_optional_string_field(input, "page_token")
        }
        "gmail.sync_history" => {
            parse_optional_string_field(input, "start_history_id")?;
            validate_optional_u32_field(input, "max_results")?;
            parse_history_types(input)?;
            parse_optional_u64_field(input, "lease_seq")?.ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "lease_seq is required for singleton_writer cursor advancement".into(),
            })?;
            parse_optional_string_field(input, "lease_object_id").map(|_| ())
        }
        "gmail.modify_message" => {
            require_str(input, "message_id")?;
            parse_optional_string_array_field(input, "add_label_ids")?;
            parse_optional_string_array_field(input, "remove_label_ids").map(|_| ())
        }
        "gmail.get_thread" => require_str(input, "thread_id").map(|_| ()),
        "gmail.list_labels" => Ok(()),
        "gmail.get_draft" | "gmail.send_draft" => require_str(input, "draft_id").map(|_| ()),
        _ => Err(FcpError::OperationNotGranted {
            operation: operation.into(),
        }),
    }
}

fn gmail_resource_uris(operation: &str, input: &serde_json::Value) -> Vec<String> {
    match operation {
        "gmail.send_message" => vec!["gmail:messages:send".into()],
        "gmail.get_message" | "gmail.modify_message" | "gmail.trash_message" => input
            .get("message_id")
            .and_then(|value| value.as_str())
            .map(|message_id| vec![format!("gmail:message:{message_id}")])
            .unwrap_or_default(),
        "gmail.list_messages" => vec!["gmail:messages".into()],
        "gmail.sync_history" => vec!["gmail:history".into()],
        "gmail.get_thread" => input
            .get("thread_id")
            .and_then(|value| value.as_str())
            .map(|thread_id| vec![format!("gmail:thread:{thread_id}")])
            .unwrap_or_default(),
        "gmail.list_labels" => vec!["gmail:labels".into()],
        "gmail.get_draft" | "gmail.send_draft" => input
            .get("draft_id")
            .and_then(|value| value.as_str())
            .map(|draft_id| vec![format!("gmail:draft:{draft_id}")])
            .unwrap_or_default(),
        "gmail.create_draft" => vec!["gmail:drafts:create".into()],
        _ => Vec::new(),
    }
}

fn validate_optional_string_field(input: &serde_json::Value, field: &str) -> FcpResult<()> {
    if let Some(value) = input.get(field)
        && value.as_str().is_none()
    {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must be a string"),
        });
    }
    Ok(())
}

fn validate_optional_u32_field(input: &serde_json::Value, field: &str) -> FcpResult<()> {
    if let Some(value) = input.get(field) {
        let number = value.as_u64().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must be an unsigned integer"),
        })?;
        u32::try_from(number).map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must fit in an unsigned 32-bit integer"),
        })?;
    }
    Ok(())
}

fn parse_optional_string_array_field(
    input: &serde_json::Value,
    field: &str,
) -> FcpResult<Vec<String>> {
    let Some(value) = input.get(field) else {
        return Ok(Vec::new());
    };
    let values: Vec<String> =
        serde_json::from_value(value.clone()).map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must be an array of strings"),
        })?;
    let mut normalized = Vec::with_capacity(values.len());
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("{field} entries must not be empty"),
            });
        }
        normalized.push(trimmed.to_string());
    }
    Ok(normalized)
}

fn granted_scopes_are_authoritative(config: &GmailConfig) -> bool {
    matches!(
        config.auth,
        GoogleMaterializedAuth::BearerToken {
            source: GoogleAuthSourceKind::OAuthRefresh,
            ..
        }
    ) && !config.granted_scopes.is_empty()
}

fn missing_scope_limited_operations(config: &GmailConfig) -> Vec<&'static str> {
    let granted: BTreeSet<&str> = config.granted_scopes.iter().map(String::as_str).collect();
    [
        (
            "gmail.send_message",
            &[
                "https://mail.google.com/",
                "https://www.googleapis.com/auth/gmail.send",
            ][..],
        ),
        (
            "gmail.send_draft",
            &[
                "https://mail.google.com/",
                "https://www.googleapis.com/auth/gmail.send",
            ][..],
        ),
        (
            "gmail.modify_message",
            &[
                "https://mail.google.com/",
                "https://www.googleapis.com/auth/gmail.modify",
            ][..],
        ),
        (
            "gmail.trash_message",
            &[
                "https://mail.google.com/",
                "https://www.googleapis.com/auth/gmail.modify",
            ][..],
        ),
        (
            "gmail.get_draft",
            &[
                "https://mail.google.com/",
                "https://www.googleapis.com/auth/gmail.compose",
            ][..],
        ),
        (
            "gmail.create_draft",
            &[
                "https://mail.google.com/",
                "https://www.googleapis.com/auth/gmail.compose",
                "https://www.googleapis.com/auth/gmail.modify",
            ][..],
        ),
    ]
    .into_iter()
    .filter_map(|(operation, accepted_scopes)| {
        accepted_scopes
            .iter()
            .all(|scope| !granted.contains(*scope))
            .then_some(operation)
    })
    .collect()
}

/// Produce a redacted auth label from materialized auth for diagnostics.
fn auth_label_for_materialized(auth: &GoogleMaterializedAuth) -> String {
    match auth {
        GoogleMaterializedAuth::BearerToken { source, .. } => source.to_string(),
        GoogleMaterializedAuth::CredentialReference { credential_id, .. } => {
            format!("credential_id:{credential_id}")
        }
    }
}

fn endpoint_allowed_by_policy(endpoint: &str) -> bool {
    let Ok(parsed) = reqwest::Url::parse(endpoint) else {
        return false;
    };
    if parsed.scheme() == "https" {
        return true;
    }
    parsed.host_str().is_some_and(is_local_test_host)
}

fn is_local_test_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1"
}

fn determine_effective_start_history_id(
    requested_start: Option<String>,
    previous_state: Option<&GmailHistoryCursorState>,
) -> FcpResult<(String, bool, bool)> {
    match (requested_start, previous_state) {
        (Some(requested), Some(previous)) => {
            if compare_history_ids(&requested, &previous.next_history_id) == Ordering::Less {
                Ok((previous.next_history_id.clone(), true, true))
            } else {
                Ok((requested, false, false))
            }
        }
        (Some(requested), None) => Ok((requested, false, false)),
        (None, Some(previous)) => Ok((previous.next_history_id.clone(), false, true)),
        (None, None) => Err(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing start_history_id and no persisted history cursor is available".into(),
        }),
    }
}

fn load_history_cursor_state(path: &Path) -> FcpResult<Option<GmailHistoryCursorState>> {
    if !path.exists() {
        return Ok(None);
    }

    let bytes = fs::read(path).map_err(|error| FcpError::Internal {
        message: format!(
            "Failed to read history cursor state {}: {error}",
            path.display()
        ),
    })?;

    let state = serde_json::from_slice(&bytes).map_err(|error| FcpError::Internal {
        message: format!(
            "Failed to parse history cursor state {}: {error}",
            path.display()
        ),
    })?;
    Ok(Some(state))
}

fn persist_history_cursor_state(path: &Path, state: &GmailHistoryCursorState) -> FcpResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| FcpError::Internal {
            message: format!(
                "Failed to create history cursor directory {}: {error}",
                parent.display()
            ),
        })?;
    }

    let data = serde_json::to_vec_pretty(state).map_err(|error| FcpError::Internal {
        message: format!("Failed to serialize history cursor state: {error}"),
    })?;

    let tmp_name = format!(
        ".{}-{}.tmp",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("gmail-history-cursor"),
        uuid::Uuid::new_v4()
    );
    let tmp_path = path.with_file_name(tmp_name);
    fs::write(&tmp_path, data).map_err(|error| FcpError::Internal {
        message: format!(
            "Failed to write temporary history cursor state {}: {error}",
            tmp_path.display()
        ),
    })?;
    fs::rename(&tmp_path, path).map_err(|error| FcpError::Internal {
        message: format!(
            "Failed to persist history cursor state {}: {error}",
            path.display()
        ),
    })?;

    Ok(())
}

fn compare_history_ids(lhs: &str, rhs: &str) -> Ordering {
    if lhs.bytes().all(|byte| byte.is_ascii_digit())
        && rhs.bytes().all(|byte| byte.is_ascii_digit())
    {
        let lhs = lhs.trim_start_matches('0');
        let rhs = rhs.trim_start_matches('0');
        let lhs = if lhs.is_empty() { "0" } else { lhs };
        let rhs = if rhs.is_empty() { "0" } else { rhs };

        match lhs.len().cmp(&rhs.len()) {
            Ordering::Equal => lhs.cmp(rhs),
            other => other,
        }
    } else {
        lhs.cmp(rhs)
    }
}

fn current_unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
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

#[allow(clippy::fn_params_excessive_bools)]
fn op_info(
    id: &'static str,
    summary: &str,
    input_schema: serde_json::Value,
    output_schema: serde_json::Value,
    capability: &'static str,
    risk_level: RiskLevel,
    safety_tier: SafetyTier,
    idempotency: IdempotencyClass,
    requires_approval: Option<ApprovalMode>,
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
        requires_approval,
        safety_tier,
        idempotency,
        ai_hints,
    }
}

/// Reject a header field value that would break out of its RFC 2822 header
/// line. A `\r`, `\n`, or NUL in `to`/`subject` lets a caller inject extra
/// headers (e.g. a hidden `Bcc:`) or a forged message body, so such values
/// are refused before the message is assembled.
fn validate_header_field(field: &str, value: &str) -> FcpResult<()> {
    if value.contains(['\r', '\n', '\0']) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Field `{field}` must not contain CR, LF, or NUL characters"),
        });
    }
    Ok(())
}

fn build_raw_message_from_fields(input: &serde_json::Value) -> FcpResult<String> {
    let to = require_str(input, "to")?;
    let subject = require_str(input, "subject")?;
    let body = require_str(input, "body")?;
    validate_header_field("to", to)?;
    validate_header_field("subject", subject)?;
    let normalized_body = body
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .replace('\n', "\r\n");
    let rfc_2822 = format!(
        "To: {to}\r\nSubject: {subject}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n{normalized_body}"
    );
    Ok(URL_SAFE_NO_PAD.encode(rfc_2822.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_prelude::CapabilityConstraints;
    use fcp_prelude::CredentialId;
    use std::{
        io::{BufRead, BufReader, Read, Write},
        net::{TcpListener, TcpStream},
        thread::{self, JoinHandle},
        time::Duration as StdDuration,
    };

    struct TestHttpResponse {
        method: &'static str,
        path: &'static str,
        query: Vec<(&'static str, &'static str)>,
        status: u16,
        body: Vec<u8>,
    }

    impl TestHttpResponse {
        fn json(
            method: &'static str,
            path: &'static str,
            query: Vec<(&'static str, &'static str)>,
            body: &serde_json::Value,
        ) -> Self {
            Self {
                method,
                path,
                query,
                status: 200,
                body: serde_json::to_vec(body).expect("serialize response json"),
            }
        }
    }

    struct TestHttpServer {
        base_url: String,
        _handle: JoinHandle<()>,
    }

    impl TestHttpServer {
        fn respond(response: TestHttpResponse) -> Self {
            Self::respond_sequence(vec![response])
        }

        fn respond_sequence(responses: Vec<TestHttpResponse>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind test HTTP server");
            let base_url = format!("http://{}", listener.local_addr().expect("local address"));
            let handle = thread::spawn(move || {
                for response in responses {
                    let (stream, _) = listener.accept().expect("accept test HTTP request");
                    handle_test_http_request(stream, &response);
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

    fn handle_test_http_request(mut stream: TcpStream, response: &TestHttpResponse) {
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
        let target = parts.next().expect("request target");
        let (path, query) = target.split_once('?').unwrap_or((target, ""));

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
                content_length = value.trim().parse().unwrap_or(0);
            }
        }
        if content_length > 0 {
            let mut body = vec![0; content_length];
            reader.read_exact(&mut body).expect("read request body");
        }

        assert_eq!(method, response.method);
        assert_eq!(path, response.path);
        for (name, value) in &response.query {
            let expected = format!("{name}={value}");
            assert!(query.split('&').any(|part| part == expected), "{expected}");
        }

        let status_text = match response.status {
            200 => "OK",
            404 => "Not Found",
            _ => "OK",
        };
        write!(
            stream,
            "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            response.status,
            status_text,
            response.body.len(),
        )
        .expect("write response header");
        if stream.write_all(&response.body).is_ok() {
            let _ = stream.flush();
        }
    }

    fn generate_token_with_cap(
        signing_key: &Ed25519SigningKey,
        connector: &GmailConnector,
        cap: &str,
        operations: &[&str],
    ) -> CapabilityToken {
        let now = Utc::now();
        // C3.4: tokens MUST include constraints (default-deny)
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
        let cose = CapabilityTokenBuilder::new()
            .capability_id(cap)
            .zone_id("z:work")
            .principal("user:test")
            .operations(operations)
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .target_instance(connector.base.instance_id.as_str())
            .try_constraints_cbor(&cbor)
            .unwrap()
            .sign(signing_key)
            .unwrap();
        CapabilityToken::from_raw(cose)
    }

    fn generate_valid_token(
        signing_key: &Ed25519SigningKey,
        connector: &GmailConnector,
        op: &str,
    ) -> CapabilityToken {
        let cap = gmail_capability_for_operation(op).unwrap();
        generate_token_with_cap(signing_key, connector, cap.as_str(), &[op])
    }

    fn simulate_request(
        operation: &'static str,
        input: serde_json::Value,
        capability: CapabilityToken,
    ) -> serde_json::Value {
        serde_json::to_value(SimulateRequest::new(
            ConnectorId::from_static("gmail"),
            OperationId::from_static(operation),
            fcp_core::ZoneId::work(),
            input,
            capability,
        ))
        .unwrap()
    }

    fn parse_simulate_response(value: serde_json::Value) -> SimulateResponse {
        serde_json::from_value(value).unwrap()
    }

    async fn configured_connector() -> GmailConnector {
        let mut connector = GmailConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": CredentialId::new().to_string(),
                "base_url": "http://localhost:9999"
            }))
            .await
            .unwrap();
        connector
    }

    async fn handshaken_connector() -> (GmailConnector, Ed25519SigningKey) {
        let mut connector = configured_connector().await;
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": [
                    "gmail.read",
                    "gmail.history.read",
                    "gmail.write",
                    "gmail.send",
                    "gmail.delete"
                ]
            }))
            .await
            .unwrap();
        (connector, signing_key)
    }

    // ── GoogleMaterializedAuth label ─────────────────────────────────

    #[test]
    fn auth_label_bearer_token() {
        use fcp_google_discovery::auth::GoogleAuthSourceKind;
        let auth = GoogleMaterializedAuth::BearerToken {
            access_token: "ya29.test".into(),
            source: GoogleAuthSourceKind::AccessToken,
            granted_scopes: vec![],
            quota_project_id: None,
        };
        let label = auth_label_for_materialized(&auth);
        assert_eq!(label, "access_token");
    }

    #[test]
    fn auth_label_credential_ref() {
        let id = fcp_core::CredentialId::new();
        let auth = GoogleMaterializedAuth::CredentialReference {
            credential_id: id,
            quota_project_id: None,
        };
        let label = auth_label_for_materialized(&auth);
        assert!(label.starts_with("credential_id:"));
        assert!(label.contains(&id.to_string()));
    }

    // ── DoctorResult ───────────────────────────────────────────────

    #[test]
    fn doctor_result_healthy_when_all_pass() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: true,
                message: "ok".into(),
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: true,
                message: "ok".into(),
                critical: false,
            },
        ];
        let result = DoctorResult::from_checks(checks);
        assert!(matches!(result.status, DoctorStatus::Healthy));
    }

    #[test]
    fn doctor_result_degraded_when_noncritical_fails() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: true,
                message: "ok".into(),
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: "warn".into(),
                critical: false,
            },
        ];
        let result = DoctorResult::from_checks(checks);
        assert!(matches!(result.status, DoctorStatus::Degraded));
    }

    #[test]
    fn doctor_result_unhealthy_when_critical_fails() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: false,
                message: "bad".into(),
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: true,
                message: "ok".into(),
                critical: false,
            },
        ];
        let result = DoctorResult::from_checks(checks);
        assert!(matches!(result.status, DoctorStatus::Unhealthy));
    }

    // ── parse_base_url ─────────────────────────────────────────────

    #[test]
    fn parse_base_url_defaults_to_gmail() {
        let result = parse_base_url(&json!({})).unwrap();
        assert!(result.contains("gmail.googleapis.com"));
    }

    #[test]
    fn parse_base_url_accepts_https_googleapis() {
        let result =
            parse_base_url(&json!({"base_url": "https://gmail.googleapis.com/gmail/v1"})).unwrap();
        assert_eq!(result, "https://gmail.googleapis.com/gmail/v1");
    }

    #[test]
    fn parse_base_url_strips_trailing_slash() {
        let result =
            parse_base_url(&json!({"base_url": "https://gmail.googleapis.com/gmail/v1/"})).unwrap();
        assert_eq!(result, "https://gmail.googleapis.com/gmail/v1");
    }

    #[test]
    fn parse_base_url_rejects_non_googleapis_host() {
        let err =
            parse_base_url(&json!({"base_url": "https://custom.example.com/api"})).unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("googleapis.com"), "got: {message}");
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn parse_base_url_rejects_substring_smuggle() {
        // Path-based smuggle: host component is evil.com, not googleapis.com,
        // even though the full string contains "googleapis.com".
        let err = parse_base_url(&json!({"base_url": "https://evil.com/gmail.googleapis.com/v1"}))
            .unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn parse_base_url_accepts_googleapis_subdomain() {
        let result =
            parse_base_url(&json!({"base_url": "https://content-gmail.googleapis.com/gmail/v1"}))
                .unwrap();
        assert_eq!(result, "https://content-gmail.googleapis.com/gmail/v1");
    }

    #[test]
    fn parse_base_url_rejects_query_string() {
        let err =
            parse_base_url(&json!({"base_url": "https://gmail.googleapis.com/?leak=attacker.com"}))
                .unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("query"), "got: {message}");
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn parse_base_url_rejects_fragment() {
        let err =
            parse_base_url(&json!({"base_url": "https://gmail.googleapis.com/gmail/v1#frag"}))
                .unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn parse_base_url_rejects_userinfo() {
        let err = parse_base_url(
            &json!({"base_url": "https://attacker:pw@gmail.googleapis.com/gmail/v1"}),
        )
        .unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("userinfo"), "got: {message}");
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn host_is_googleapis_recognizes_apex_and_subdomains() {
        assert!(host_is_googleapis("googleapis.com"));
        assert!(host_is_googleapis("gmail.googleapis.com"));
        assert!(host_is_googleapis("content-sheets.googleapis.com"));
        assert!(!host_is_googleapis("googleapis.com.evil.com"));
        assert!(!host_is_googleapis("evil-googleapis.com"));
        assert!(!host_is_googleapis("googleapis.example"));
    }

    #[test]
    fn parse_base_url_accepts_http_localhost() {
        let result = parse_base_url(&json!({"base_url": "http://localhost:8080/api"})).unwrap();
        assert_eq!(result, "http://localhost:8080/api");
    }

    #[test]
    fn parse_base_url_accepts_http_127001() {
        let result = parse_base_url(&json!({"base_url": "http://127.0.0.1:8080/api"})).unwrap();
        assert_eq!(result, "http://127.0.0.1:8080/api");
    }

    #[test]
    fn parse_base_url_rejects_http_non_local() {
        let result = parse_base_url(&json!({"base_url": "http://remote.example.com/api"}));
        assert!(result.is_err());
    }

    #[test]
    fn parse_base_url_rejects_invalid_url() {
        let result = parse_base_url(&json!({"base_url": "not a url"}));
        assert!(result.is_err());
    }

    #[test]
    fn parse_base_url_ignores_empty_string() {
        let result = parse_base_url(&json!({"base_url": "  "})).unwrap();
        assert!(result.contains("gmail.googleapis.com"));
    }

    // ── parse_required_scopes ──────────────────────────────────────

    #[test]
    fn parse_required_scopes_absent() {
        let result = parse_required_scopes(&json!({})).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn parse_required_scopes_valid() {
        let result = parse_required_scopes(&json!({
            "required_scopes": ["https://www.googleapis.com/auth/gmail.readonly", "https://www.googleapis.com/auth/gmail.labels"]
        })).unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn parse_required_scopes_rejects_empty_entry() {
        let result = parse_required_scopes(&json!({"required_scopes": ["valid", ""]}));
        assert!(result.is_err());
    }

    #[test]
    fn parse_required_scopes_trims_whitespace() {
        let result = parse_required_scopes(&json!({"required_scopes": ["  scope1  "]})).unwrap();
        assert_eq!(result[0], "scope1");
    }

    #[test]
    fn resolve_gmail_required_scopes_defaults_to_readonly_bundle() {
        let result = resolve_gmail_required_scopes(&json!({})).unwrap();
        assert_eq!(
            result,
            vec!["https://www.googleapis.com/auth/gmail.readonly".to_string()]
        );
    }

    #[test]
    fn resolve_gmail_required_scopes_applies_scope_triggers() {
        let result = resolve_gmail_required_scopes(&json!({
            "scope_triggers": ["User enables outbound send or draft-send workflows."]
        }))
        .unwrap();
        assert!(result.contains(&"https://www.googleapis.com/auth/gmail.readonly".to_string()));
        assert!(result.contains(&"https://www.googleapis.com/auth/gmail.send".to_string()));
    }

    #[test]
    fn resolve_gmail_required_scopes_rejects_mixed_inputs() {
        let result = resolve_gmail_required_scopes(&json!({
            "required_scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
            "scope_triggers": ["User enables outbound send or draft-send workflows."]
        }));
        assert!(result.is_err());
    }

    #[test]
    fn resolve_gmail_required_scopes_rejects_undeclared_google_scopes() {
        let result = resolve_gmail_required_scopes(&json!({
            "required_scopes": [
                "https://www.googleapis.com/auth/gmail.readonly",
                "https://www.googleapis.com/auth/drive.readonly"
            ]
        }));
        let err = result.expect_err("undeclared scope must fail");
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("outside the Gmail provisioning policy"));
                assert!(message.contains("drive.readonly"));
            }
            other => panic!("expected invalid request, got {other:?}"),
        }
    }

    #[test]
    fn resolve_gmail_required_scopes_accepts_declared_escalations_and_dedups() {
        let result = resolve_gmail_required_scopes(&json!({
            "required_scopes": [
                "https://mail.google.com/",
                "https://www.googleapis.com/auth/gmail.readonly",
                "https://mail.google.com/"
            ]
        }))
        .unwrap();
        assert_eq!(
            result,
            vec![
                "https://mail.google.com/".to_string(),
                "https://www.googleapis.com/auth/gmail.readonly".to_string(),
            ]
        );
    }

    // ── parse_history_cursor_path ──────────────────────────────────

    #[test]
    fn parse_history_cursor_path_default() {
        let result = parse_history_cursor_path(&json!({})).unwrap();
        assert_eq!(result, PathBuf::from(DEFAULT_HISTORY_CURSOR_FILE));
    }

    #[test]
    fn parse_history_cursor_path_custom() {
        let result =
            parse_history_cursor_path(&json!({"history_cursor_path": "/tmp/custom-cursor.json"}))
                .unwrap();
        assert_eq!(result.to_str().unwrap(), "/tmp/custom-cursor.json");
    }

    #[test]
    fn parse_history_cursor_path_uses_configured_state_dir() {
        let result = parse_history_cursor_path(&json!({"state_dir": "/tmp/gmail-state"})).unwrap();
        assert_eq!(
            result,
            PathBuf::from("/tmp/gmail-state").join(DEFAULT_HISTORY_CURSOR_FILE)
        );
    }

    #[test]
    fn parse_history_cursor_path_rejects_empty() {
        let result = parse_history_cursor_path(&json!({"history_cursor_path": ""}));
        assert!(result.is_err());
    }

    #[test]
    fn parse_history_cursor_path_rejects_non_string() {
        let result = parse_history_cursor_path(&json!({"history_cursor_path": 42}));
        assert!(result.is_err());
    }

    #[test]
    fn parse_history_cursor_path_rejects_bad_state_dir() {
        assert!(parse_history_cursor_path(&json!({"state_dir": ""})).is_err());
        assert!(parse_history_cursor_path(&json!({"state_dir": 42})).is_err());
    }

    // ── parse_optional_string_field ────────────────────────────────

    #[test]
    fn parse_optional_string_field_present() {
        let result = parse_optional_string_field(&json!({"field": "value"}), "field").unwrap();
        assert_eq!(result.as_deref(), Some("value"));
    }

    #[test]
    fn parse_optional_string_field_missing() {
        let result = parse_optional_string_field(&json!({}), "field").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_optional_string_field_empty_rejects() {
        let result = parse_optional_string_field(&json!({"field": "  "}), "field");
        assert!(result.is_err());
    }

    #[test]
    fn parse_optional_string_field_non_string() {
        let result = parse_optional_string_field(&json!({"field": 42}), "field");
        assert!(result.is_err());
    }

    #[test]
    fn parse_optional_string_field_trims() {
        let result = parse_optional_string_field(&json!({"field": "  hello  "}), "field").unwrap();
        assert_eq!(result.as_deref(), Some("hello"));
    }

    // ── parse_optional_string_array_field ──────────────────────────

    #[test]
    fn parse_optional_string_array_field_present() {
        let result = parse_optional_string_array_field(
            &json!({"labels": [" STARRED ", "UNREAD"]}),
            "labels",
        )
        .unwrap();
        assert_eq!(result, vec!["STARRED".to_string(), "UNREAD".to_string()]);
    }

    #[test]
    fn parse_optional_string_array_field_missing() {
        let result = parse_optional_string_array_field(&json!({}), "labels").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn parse_optional_string_array_field_rejects_non_array() {
        let result = parse_optional_string_array_field(&json!({"labels": "STARRED"}), "labels");
        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
    }

    #[test]
    fn parse_optional_string_array_field_rejects_empty_entry() {
        let result =
            parse_optional_string_array_field(&json!({"labels": ["STARRED", " "]}), "labels");
        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
    }

    // ── parse_optional_u64_field ───────────────────────────────────

    #[test]
    fn parse_optional_u64_field_present() {
        let result = parse_optional_u64_field(&json!({"n": 42}), "n").unwrap();
        assert_eq!(result, Some(42));
    }

    #[test]
    fn parse_optional_u64_field_missing() {
        let result = parse_optional_u64_field(&json!({}), "n").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_optional_u64_field_non_integer() {
        let result = parse_optional_u64_field(&json!({"n": "text"}), "n");
        assert!(result.is_err());
    }

    #[test]
    fn parse_optional_u64_field_negative() {
        let result = parse_optional_u64_field(&json!({"n": -1}), "n");
        assert!(result.is_err());
    }

    // ── parse_history_types ────────────────────────────────────────

    #[test]
    fn parse_history_types_absent() {
        let result = parse_history_types(&json!({})).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_history_types_valid() {
        let result =
            parse_history_types(&json!({"history_types": ["messageAdded", "labelRemoved"]}))
                .unwrap();
        let types = result.unwrap();
        assert_eq!(types.len(), 2);
        assert!(types.contains(&"messageAdded".to_string()));
    }

    #[test]
    fn parse_history_types_empty_array_returns_none() {
        let result = parse_history_types(&json!({"history_types": []})).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_history_types_rejects_empty_entry() {
        let result = parse_history_types(&json!({"history_types": ["valid", ""]}));
        assert!(result.is_err());
    }

    #[test]
    fn parse_history_types_trims() {
        let result = parse_history_types(&json!({"history_types": ["  messageAdded  "]})).unwrap();
        assert_eq!(result.unwrap()[0], "messageAdded");
    }

    // ── endpoint_allowed_by_policy ─────────────────────────────────

    #[test]
    fn endpoint_allowed_https() {
        assert!(endpoint_allowed_by_policy(
            "https://graph.googleapis.com/v1"
        ));
    }

    #[test]
    fn endpoint_allowed_http_localhost() {
        assert!(endpoint_allowed_by_policy("http://localhost:8080/api"));
    }

    #[test]
    fn endpoint_allowed_http_127001() {
        assert!(endpoint_allowed_by_policy("http://127.0.0.1:9090"));
    }

    #[test]
    fn endpoint_rejected_http_remote() {
        assert!(!endpoint_allowed_by_policy("http://remote.example.com"));
    }

    #[test]
    fn endpoint_rejected_invalid_url() {
        assert!(!endpoint_allowed_by_policy("not a url"));
    }

    // ── is_local_test_host ─────────────────────────────────────────

    #[test]
    fn is_local_test_host_localhost() {
        assert!(is_local_test_host("localhost"));
        assert!(is_local_test_host("LOCALHOST"));
        assert!(is_local_test_host("Localhost"));
    }

    #[test]
    fn is_local_test_host_ipv4_loopback() {
        assert!(is_local_test_host("127.0.0.1"));
    }

    #[test]
    fn is_local_test_host_ipv6_loopback() {
        assert!(is_local_test_host("::1"));
    }

    #[test]
    fn is_local_test_host_remote() {
        assert!(!is_local_test_host("example.com"));
        assert!(!is_local_test_host("192.168.1.1"));
    }

    // ── require_str ────────────────────────────────────────────────

    #[test]
    fn require_str_present() {
        let input = json!({"field": "value"});
        let result = require_str(&input, "field").unwrap();
        assert_eq!(result, "value");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        let result = require_str(&input, "field");
        assert!(result.is_err());
    }

    #[test]
    fn require_str_non_string() {
        let input = json!({"field": 42});
        let result = require_str(&input, "field");
        assert!(result.is_err());
    }

    // ── compare_history_ids ────────────────────────────────────────

    #[test]
    fn compare_history_ids_numeric_equal() {
        assert_eq!(compare_history_ids("100", "100"), std::cmp::Ordering::Equal);
    }

    #[test]
    fn compare_history_ids_numeric_less() {
        assert_eq!(compare_history_ids("99", "100"), std::cmp::Ordering::Less);
    }

    #[test]
    fn compare_history_ids_numeric_greater() {
        assert_eq!(
            compare_history_ids("101", "100"),
            std::cmp::Ordering::Greater
        );
    }

    #[test]
    fn compare_history_ids_numeric_different_lengths() {
        assert_eq!(compare_history_ids("9", "10"), std::cmp::Ordering::Less);
        assert_eq!(
            compare_history_ids("1000", "999"),
            std::cmp::Ordering::Greater
        );
    }

    #[test]
    fn compare_history_ids_leading_zeros() {
        assert_eq!(
            compare_history_ids("0100", "100"),
            std::cmp::Ordering::Equal
        );
        assert_eq!(compare_history_ids("000", "0"), std::cmp::Ordering::Equal);
    }

    #[test]
    fn compare_history_ids_non_numeric_falls_back_to_string() {
        assert_eq!(compare_history_ids("abc", "abd"), std::cmp::Ordering::Less);
    }

    #[test]
    fn build_raw_message_from_fields_accepts_manifest_style_input() {
        let raw = build_raw_message_from_fields(&json!({
            "to": "recipient@example.com",
            "subject": "Test Subject",
            "body": "Hello,\nworld!"
        }))
        .unwrap();
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(raw)
            .unwrap();
        let message = String::from_utf8(decoded).unwrap();
        assert!(message.contains("To: recipient@example.com"));
        assert!(message.contains("Subject: Test Subject"));
        assert!(message.ends_with("\r\n\r\nHello,\r\nworld!"));
    }

    #[test]
    fn build_raw_message_rejects_header_injection_via_to() {
        let err = build_raw_message_from_fields(&json!({
            "to": "victim@example.com\r\nBcc: attacker@evil.com",
            "subject": "Hi",
            "body": "ok"
        }))
        .unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { code: 1003, .. }));
    }

    #[test]
    fn build_raw_message_rejects_header_injection_via_subject() {
        let err = build_raw_message_from_fields(&json!({
            "to": "victim@example.com",
            "subject": "Hi\nInjected: header",
            "body": "ok"
        }))
        .unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { code: 1003, .. }));
    }

    #[test]
    fn build_raw_message_allows_multiline_body() {
        // CRLF in the body is legitimate and must still be accepted.
        let raw = build_raw_message_from_fields(&json!({
            "to": "recipient@example.com",
            "subject": "Test Subject",
            "body": "line1\r\nline2\nline3"
        }))
        .unwrap();
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(raw)
            .unwrap();
        let message = String::from_utf8(decoded).unwrap();
        assert!(message.ends_with("\r\n\r\nline1\r\nline2\r\nline3"));
    }

    // ── determine_effective_start_history_id ────────────────────────

    #[test]
    fn determine_effective_both_present_requested_newer() {
        let previous = GmailHistoryCursorState {
            next_history_id: "100".into(),
            lease_seq: 1,
            lease_object_id: None,
            updated_at: 0,
        };
        let (id, dedup, used_cursor) =
            determine_effective_start_history_id(Some("200".into()), Some(&previous)).unwrap();
        assert_eq!(id, "200");
        assert!(!dedup);
        assert!(!used_cursor);
    }

    #[test]
    fn determine_effective_both_present_requested_older() {
        let previous = GmailHistoryCursorState {
            next_history_id: "200".into(),
            lease_seq: 1,
            lease_object_id: None,
            updated_at: 0,
        };
        let (id, dedup, used_cursor) =
            determine_effective_start_history_id(Some("100".into()), Some(&previous)).unwrap();
        assert_eq!(id, "200");
        assert!(dedup);
        assert!(used_cursor);
    }

    #[test]
    fn determine_effective_only_requested() {
        let (id, dedup, used_cursor) =
            determine_effective_start_history_id(Some("50".into()), None).unwrap();
        assert_eq!(id, "50");
        assert!(!dedup);
        assert!(!used_cursor);
    }

    #[test]
    fn determine_effective_only_persisted() {
        let previous = GmailHistoryCursorState {
            next_history_id: "300".into(),
            lease_seq: 2,
            lease_object_id: None,
            updated_at: 0,
        };
        let (id, dedup, used_cursor) =
            determine_effective_start_history_id(None, Some(&previous)).unwrap();
        assert_eq!(id, "300");
        assert!(!dedup);
        assert!(used_cursor);
    }

    #[test]
    fn determine_effective_neither_errors() {
        let result = determine_effective_start_history_id(None, None);
        assert!(result.is_err());
    }

    // ── Schema completeness ────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn all_operations_have_input_and_output_schemas() {
        let connector = GmailConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for op in ops {
            let id = op["id"].as_str().unwrap();
            assert!(op["input_schema"].is_object(), "{id} missing input_schema");
            assert!(
                op["output_schema"].is_object(),
                "{id} missing output_schema"
            );
            assert!(op["summary"].is_string(), "{id} missing summary");
            assert!(
                !op["summary"].as_str().unwrap().is_empty(),
                "{id} has empty summary"
            );
            assert_eq!(
                op["input_schema"]["type"], "object",
                "{id} input_schema type must be object"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn introspect_has_correct_operation_count() {
        let connector = GmailConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        assert_eq!(ops.len(), 11);
    }

    // ── Risk levels ────────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn send_operations_are_high_risk() {
        let connector = GmailConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for op in ops {
            let id = op["id"].as_str().unwrap();
            if id == "gmail.send_message" || id == "gmail.send_draft" {
                assert_eq!(
                    op["risk_level"].as_str().unwrap().to_lowercase(),
                    "high",
                    "{id} should be High risk"
                );
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn read_operations_are_low_risk() {
        let connector = GmailConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        let read_ops = [
            "gmail.get_message",
            "gmail.list_messages",
            "gmail.get_thread",
            "gmail.list_labels",
            "gmail.sync_history",
        ];
        for op in ops {
            let id = op["id"].as_str().unwrap();
            if read_ops.contains(&id) {
                assert_eq!(
                    op["risk_level"].as_str().unwrap().to_lowercase(),
                    "low",
                    "{id} should be Low risk"
                );
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn modify_operations_are_medium_risk() {
        let connector = GmailConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        let modify_ops = [
            "gmail.modify_message",
            "gmail.trash_message",
            "gmail.get_draft",
            "gmail.create_draft",
        ];
        for op in ops {
            let id = op["id"].as_str().unwrap();
            if modify_ops.contains(&id) {
                assert_eq!(
                    op["risk_level"].as_str().unwrap().to_lowercase(),
                    "medium",
                    "{id} should be Medium risk"
                );
            }
        }
    }

    // ── Connector lifecycle ────────────────────────────────────────

    #[test]
    fn connector_default() {
        let connector = GmailConnector::default();
        assert!(connector.config.is_none());
        assert!(connector.client.is_none());
        assert!(connector.session_id.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn shutdown_returns_status() {
        let connector = GmailConnector::new();
        let result = connector.handle_shutdown(json!({})).await.unwrap();
        assert_eq!(result["status"], "shutdown");
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_not_configured() {
        let connector = GmailConnector::new();
        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "degraded");
        assert_eq!(result["reason_code"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_returns_allowed() {
        let (connector, signing_key) = handshaken_connector().await;
        let token = generate_valid_token(&signing_key, &connector, "gmail.get_message");
        let result = connector
            .handle_simulate(simulate_request(
                "gmail.get_message",
                json!({"message_id": "msg-1"}),
                token,
            ))
            .await
            .unwrap();
        let response = parse_simulate_response(result);
        assert!(response.would_succeed);
        assert!(response.missing_capabilities.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_before_configure_is_denied() {
        let connector = GmailConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let token = generate_valid_token(&signing_key, &connector, "gmail.get_message");
        let result = connector
            .handle_simulate(simulate_request(
                "gmail.get_message",
                json!({"message_id": "msg-1"}),
                token,
            ))
            .await
            .unwrap();
        let response = parse_simulate_response(result);
        assert!(!response.would_succeed);
        assert_eq!(
            response.denial_code,
            Some(FcpError::NotConfigured.error_code())
        );
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_before_handshake_is_denied() {
        let connector = configured_connector().await;
        let signing_key = Ed25519SigningKey::generate();
        let token = generate_valid_token(&signing_key, &connector, "gmail.get_message");
        let result = connector
            .handle_simulate(simulate_request(
                "gmail.get_message",
                json!({"message_id": "msg-1"}),
                token,
            ))
            .await
            .unwrap();
        let response = parse_simulate_response(result);
        assert!(!response.would_succeed);
        assert_eq!(
            response.denial_code,
            Some(FcpError::NotHandshaken.error_code())
        );
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_wrong_capability_is_denied() {
        let (connector, signing_key) = handshaken_connector().await;
        let token = generate_token_with_cap(
            &signing_key,
            &connector,
            "gmail.read",
            &["gmail.send_message"],
        );
        let result = connector
            .handle_simulate(simulate_request(
                "gmail.send_message",
                json!({"to": "recipient@example.com", "subject": "Test", "body": "Body"}),
                token,
            ))
            .await
            .unwrap();
        let response = parse_simulate_response(result);
        assert!(!response.would_succeed);
        assert_eq!(response.missing_capabilities, vec!["gmail.send"]);
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_missing_required_input_is_denied() {
        let (connector, signing_key) = handshaken_connector().await;
        let token = generate_valid_token(&signing_key, &connector, "gmail.get_message");
        let result = connector
            .handle_simulate(simulate_request("gmail.get_message", json!({}), token))
            .await
            .unwrap();
        let response = parse_simulate_response(result);
        assert!(!response.would_succeed);
        assert!(response.failure_reason.unwrap().contains("message_id"));
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_sync_history_requires_lease_seq() {
        let (connector, signing_key) = handshaken_connector().await;
        let token = generate_valid_token(&signing_key, &connector, "gmail.sync_history");
        let result = connector
            .handle_simulate(simulate_request(
                "gmail.sync_history",
                json!({"start_history_id": "1000"}),
                token,
            ))
            .await
            .unwrap();
        let response = parse_simulate_response(result);
        assert!(!response.would_succeed);
        assert!(response.failure_reason.unwrap().contains("lease_seq"));
    }

    // ── Invoke edge cases ──────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn invoke_unknown_op_returns_not_granted() {
        let mut connector = GmailConnector::new();
        connector.client = Some(
            GmailClient::new_with_auth(GoogleMaterializedAuth::BearerToken {
                access_token: "fake_key".into(),
                source: fcp_google_discovery::auth::GoogleAuthSourceKind::AccessToken,
                granted_scopes: vec![],
                quota_project_id: None,
            })
            .unwrap()
            .with_base_url("http://localhost:9999"),
        );

        let signing_key = Ed25519SigningKey::generate();
        let token = generate_token_with_cap(
            &signing_key,
            &connector,
            "gmail.read",
            &["gmail.nonexistent"],
        );

        let result = connector
            .handle_invoke(json!({
                "operation": "gmail.nonexistent",
                "input": {},
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FcpError::OperationNotGranted { .. }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_missing_operation_field() {
        let connector = GmailConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let token = generate_valid_token(&signing_key, &connector, "gmail.get_message");
        let result = connector
            .handle_invoke(json!({
                "input": {},
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("Missing operation"));
            }
            other => panic!("Expected InvalidRequest, got {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_missing_capability_token() {
        let connector = GmailConnector::new();
        let result = connector
            .handle_invoke(json!({
                "operation": "gmail.get_message",
                "input": {}
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("capability_token"));
            }
            other => panic!("Expected InvalidRequest, got {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_without_handshake_returns_not_handshaken() {
        let connector = configured_connector().await;
        let signing_key = Ed25519SigningKey::generate();
        let token = generate_valid_token(&signing_key, &connector, "gmail.get_message");

        let result = connector
            .handle_invoke(json!({
                "operation": "gmail.get_message",
                "input": {"message_id": "m1"},
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotHandshaken));
    }

    // ── Configure edge cases ───────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn configure_no_auth_source() {
        let mut connector = GmailConnector::new();
        let result = connector.handle_configure(json!({})).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("exactly one auth source"));
            }
            other => panic!("Expected InvalidRequest, got {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn configure_with_token_rejects_raw_secret() {
        let mut connector = GmailConnector::new();
        let result = connector
            .handle_configure(json!({
                "token": "ya29.test-token",
                "base_url": "http://localhost:9999"
            }))
            .await;

        assert!(matches!(
            result,
            Err(FcpError::ConfigurationLeakedSecret { .. })
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_secret_shaped_values() {
        let cases = [
            ("Bearer abcdefgh123", "raw_secret_config_value_bearer"),
            (
                "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjMifQ.abcdefgh",
                "raw_secret_config_value_jwt",
            ),
            ("sk-live-test", "raw_secret_config_value_openai"),
            ("xoxb-1234567890abcdef", "raw_secret_config_value_slack"),
            ("ghp_ABCdef123456", "raw_secret_config_value_github"),
            ("AKIAIOSFODNN7EXAMPLE", "raw_secret_config_value_aws"),
        ];

        for (sample, expected_detector) in cases {
            let mut connector = GmailConnector::new();
            let result = connector
                .handle_configure(json!({
                    "credential_id": CredentialId::new().to_string(),
                    "metadata": sample
                }))
                .await;

            match result {
                Err(FcpError::ConfigurationLeakedSecret { detector, .. }) => {
                    assert_eq!(detector, expected_detector);
                }
                other => panic!("Expected ConfigurationLeakedSecret, got {other:?}"),
            }
        }
    }

    // ── Handshake details ──────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn handshake_sets_session_id() {
        let mut connector = GmailConnector::new();
        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["gmail.read"]
            }))
            .await
            .unwrap();

        assert!(connector.session_id.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn handshake_grants_requested_capabilities() {
        let mut connector = GmailConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["gmail.read", "gmail.send"]
            }))
            .await
            .unwrap();

        let caps = result["capabilities_granted"].as_array().unwrap();
        assert_eq!(caps.len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn handshake_event_caps() {
        let mut connector = GmailConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": []
            }))
            .await
            .unwrap();

        let event_caps = &result["event_caps"];
        assert_eq!(event_caps["streaming"], false);
        assert_eq!(event_caps["replay"], false);
        assert_eq!(event_caps["min_buffer_events"], 100);
    }

    // ── Health details ─────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn health_shows_scopes_after_configure() {
        let mut connector = GmailConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": CredentialId::new().to_string(),
                "base_url": "http://localhost:9999",
                "required_scopes": ["https://www.googleapis.com/auth/gmail.readonly"]
            }))
            .await
            .unwrap();

        let health = connector.handle_health().await.unwrap();
        let scopes = health["required_scopes"].as_array().unwrap();
        assert_eq!(scopes.len(), 1);
    }

    // ── GmailHistoryCursorState serde ──────────────────────────────

    #[test]
    fn history_cursor_state_serde_roundtrip() {
        let state = GmailHistoryCursorState {
            next_history_id: "500".into(),
            lease_seq: 3,
            lease_object_id: Some("lease-x".into()),
            updated_at: 1709294400,
        };
        let json = serde_json::to_value(&state).unwrap();
        assert_eq!(json["next_history_id"], "500");
        assert_eq!(json["lease_seq"], 3);

        let back: GmailHistoryCursorState = serde_json::from_value(json).unwrap();
        assert_eq!(back.next_history_id, "500");
        assert_eq!(back.lease_object_id.as_deref(), Some("lease-x"));
    }

    #[test]
    fn history_cursor_state_without_lease_object() {
        let json = serde_json::json!({
            "next_history_id": "100",
            "lease_seq": 1,
            "updated_at": 0
        });
        let state: GmailHistoryCursorState = serde_json::from_value(json).unwrap();
        assert!(state.lease_object_id.is_none());
    }

    // ── DoctorStatus serde ─────────────────────────────────────────

    #[test]
    fn doctor_status_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&DoctorStatus::Healthy).unwrap(),
            "\"healthy\""
        );
        assert_eq!(
            serde_json::to_string(&DoctorStatus::Degraded).unwrap(),
            "\"degraded\""
        );
        assert_eq!(
            serde_json::to_string(&DoctorStatus::Unhealthy).unwrap(),
            "\"unhealthy\""
        );
    }

    // ── Existing tests preserved below ─────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = GmailConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["gmail.read"]
            }))
            .await
            .unwrap();

        assert_eq!(result["status"], "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = GmailConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_credential_id_sets_pending_status() {
        let mut connector = GmailConnector::new();
        let credential_id = CredentialId::new();

        let result = connector
            .handle_configure(json!({
                "credential_id": credential_id.to_string(),
            }))
            .await
            .unwrap();

        assert_eq!(result["status"], "configured_pending_token_materialization");
        let health = connector.handle_health().await.unwrap();
        assert_eq!(
            health["status"],
            "degraded_pending_credential_materialization"
        );
        assert!(
            health["auth_mode"]
                .as_str()
                .unwrap()
                .starts_with("credential_id:"),
            "expected auth_mode starting with 'credential_id:', got {:?}",
            health["auth_mode"]
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_multiple_auth_sources() {
        let mut connector = GmailConnector::new();
        let credential_id = CredentialId::new();

        let result = connector
            .handle_configure(json!({
                "token": "ya29.token",
                "credential_id": credential_id.to_string(),
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::ConfigurationLeakedSecret { detector, .. } => {
                assert_eq!(detector, "raw_secret_config_field");
            }
            other => panic!("Expected ConfigurationLeakedSecret, got: {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_oauth_refresh_rejects_raw_secret_material() {
        let mut connector = GmailConnector::new();
        let result = connector
            .handle_configure(json!({
                "base_url": "http://localhost:9999",
                "required_scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
                "oauth_refresh": {
                    "client_id": "client-id",
                    "client_secret": "client-secret",
                    "refresh_token": "refresh-token",
                    "token_url": "http://localhost:9999/token"
                }
            }))
            .await;

        assert!(matches!(
            result,
            Err(FcpError::ConfigurationLeakedSecret { .. })
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_degraded_for_credential_mode() {
        let mut connector = GmailConnector::new();
        let credential_id = CredentialId::new();

        connector
            .handle_configure(json!({
                "credential_id": credential_id.to_string(),
            }))
            .await
            .unwrap();

        let report = connector.handle_self_check().await.unwrap();
        assert_eq!(report["status"], "degraded");
        assert_eq!(report["reason_code"], "credential_injection_required");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = GmailConnector::new();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["gmail.read"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, &connector, "gmail.list_labels");

        let result = connector
            .handle_invoke(json!({
                "operation": "gmail.list_labels",
                "input": {},
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_field() {
        let mut connector = GmailConnector::new();
        connector.client = Some(
            GmailClient::new_with_auth(GoogleMaterializedAuth::BearerToken {
                access_token: "fake_key".into(),
                source: fcp_google_discovery::auth::GoogleAuthSourceKind::AccessToken,
                granted_scopes: vec![],
                quota_project_id: None,
            })
            .unwrap()
            .with_base_url("http://localhost:9999"),
        );

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["gmail.read"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, &connector, "gmail.get_message");

        let result = connector
            .handle_invoke(json!({
                "operation": "gmail.get_message",
                "input": {},
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("message_id"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_sync_history_resumes_from_persisted_cursor() {
        let state_path =
            std::env::temp_dir().join(format!("fcp-gmail-history-{}.json", uuid::Uuid::new_v4()));

        let server = TestHttpServer::respond_sequence(vec![
            TestHttpResponse::json(
                "GET",
                "/users/me/history",
                vec![("startHistoryId", "100")],
                &json!({
                    "history": [
                        { "id": "101", "messagesAdded": [{ "message": { "id": "m1" } }] }
                    ],
                    "historyId": "101"
                }),
            ),
            TestHttpResponse::json(
                "GET",
                "/users/me/history",
                vec![("startHistoryId", "101")],
                &json!({
                    "history": [],
                    "historyId": "101"
                }),
            ),
        ]);

        let mut connector = GmailConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": CredentialId::new().to_string(),
                "base_url": server.uri(),
                "history_cursor_path": state_path.to_string_lossy().to_string()
            }))
            .await
            .unwrap();

        let first = connector
            .invoke_sync_history(json!({
                "start_history_id": "100",
                "lease_seq": 1,
                "lease_object_id": "lease-a"
            }))
            .await
            .unwrap();

        assert_eq!(first["effective_start_history_id"], "100");
        assert_eq!(first["latest_history_id"], "101");
        assert_eq!(first["history_count"], 1);
        assert_eq!(first["used_persisted_cursor"], false);

        let mut restarted = GmailConnector::new();
        restarted
            .handle_configure(json!({
                "credential_id": CredentialId::new().to_string(),
                "base_url": server.uri(),
                "history_cursor_path": state_path.to_string_lossy().to_string()
            }))
            .await
            .unwrap();

        let resumed = restarted
            .invoke_sync_history(json!({
                "lease_seq": 2,
                "lease_object_id": "lease-b"
            }))
            .await
            .unwrap();

        assert_eq!(resumed["effective_start_history_id"], "101");
        assert_eq!(resumed["latest_history_id"], "101");
        assert_eq!(resumed["history_count"], 0);
        assert_eq!(resumed["used_persisted_cursor"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn test_sync_history_rejects_stale_lease_seq() {
        let state_path =
            std::env::temp_dir().join(format!("fcp-gmail-history-{}.json", uuid::Uuid::new_v4()));

        let server = TestHttpServer::respond(TestHttpResponse::json(
            "GET",
            "/users/me/history",
            vec![("startHistoryId", "200")],
            &json!({
                "history": [],
                "historyId": "200"
            }),
        ));

        let mut connector = GmailConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": CredentialId::new().to_string(),
                "base_url": server.uri(),
                "history_cursor_path": state_path.to_string_lossy().to_string()
            }))
            .await
            .unwrap();

        connector
            .invoke_sync_history(json!({
                "start_history_id": "200",
                "lease_seq": 5,
                "lease_object_id": "lease-current"
            }))
            .await
            .unwrap();

        let err = connector
            .invoke_sync_history(json!({
                "start_history_id": "200",
                "lease_seq": 4,
                "lease_object_id": "lease-stale"
            }))
            .await
            .unwrap_err();

        match err {
            FcpError::Conflict { message } => {
                assert!(message.contains("stale lease_seq"));
            }
            other => panic!("Expected conflict for stale lease, got: {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_all_operations() {
        let connector = GmailConnector::new();
        let result = connector.handle_introspect().await.unwrap();

        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert!(op_ids.contains(&"gmail.send_message"));
        assert!(op_ids.contains(&"gmail.get_message"));
        assert!(op_ids.contains(&"gmail.list_messages"));
        assert!(op_ids.contains(&"gmail.modify_message"));
        assert!(op_ids.contains(&"gmail.trash_message"));
        assert!(op_ids.contains(&"gmail.get_thread"));
        assert!(op_ids.contains(&"gmail.list_labels"));
        assert!(op_ids.contains(&"gmail.sync_history"));
        assert!(op_ids.contains(&"gmail.get_draft"));
        assert!(op_ids.contains(&"gmail.create_draft"));
        assert!(op_ids.contains(&"gmail.send_draft"));
        assert_eq!(ops.len(), 11);
    }

    #[test]
    fn handshake_manifest_hash_tracks_bundled_manifest() {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        let expected = format!("sha256:{}", hex::encode(hasher.finalize()));

        let actual = GmailConnector::manifest_hash();

        assert_eq!(actual, expected);
        assert_ne!(actual, "sha256:gmail-connector-v1");
    }
}
