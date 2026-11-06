//! FCP Linear Connector implementation.

use std::collections::{BTreeSet, VecDeque};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration as StdDuration, Instant};

use chrono::Utc;
use fcp_prelude::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, CredentialId, EventCaps, EventInfo, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, IdempotencyClass, InstanceId, Introspection, OperationId, OperationInfo,
    RiskLevel, SafetyTier, SelfCheckReport, SessionId, SimulateRequest, SimulateResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::{info, instrument};
use uuid::Uuid;

use crate::{
    client::{DEFAULT_API_URL, LinearAuth, LinearClient},
    error::LinearError,
    types::{BeadSyncSnapshot, LinearSyncSnapshot, SyncConflictPolicy, SyncOperationIntent},
};

const MAX_LINEAR_WEBHOOK_SKEW_MS: u64 = 60_000;
const MAX_LINEAR_WEBHOOK_REPLAY_RECEIPTS: usize = 10_000;
// A timestamp accepted at the future edge remains valid for two skew windows.
// The extra millisecond covers the inclusive timestamp acceptance boundary.
const LINEAR_WEBHOOK_REPLAY_RETENTION: StdDuration =
    StdDuration::from_millis(2 * MAX_LINEAR_WEBHOOK_SKEW_MS + 1);
const MANIFEST_TOML: &str = include_str!("../manifest.toml");

/// Parsed and validated Linear connector configuration.
#[derive(Debug, Clone)]
struct LinearConfig {
    auth: LinearAuth,
    api_url: String,
}

impl LinearConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let api_key = params
            .get("api_key")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string);

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
            (Some(key), None) => LinearAuth::ApiKey(key),
            (None, Some(cred_id)) => LinearAuth::CredentialId(cred_id),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide exactly one of api_key or credential_id".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing api_key or credential_id in configuration".into(),
                });
            }
        };

        let api_url = params
            .get("api_url")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_API_URL)
            .to_string();
        let api_url = validate_api_url_for_auth(&api_url, &auth)?;

        Ok(Self { auth, api_url })
    }
}

fn validate_api_url_for_auth(raw_url: &str, auth: &LinearAuth) -> FcpResult<String> {
    let parsed = reqwest::Url::parse(raw_url).map_err(|_| FcpError::InvalidRequest {
        code: 1003,
        message: "api_url must be an absolute URL".into(),
    })?;
    // Strip query/fragment/userinfo before host/scheme enforcement. The
    // validator returns parsed.to_string() which preserves those
    // components; LinearClient then concatenates the result into its
    // downstream request URLs. A payload like
    //   {"api_key": "lin_x", "api_url": "https://api.linear.app?leak=x"}
    // would otherwise pass validation and leak `?leak=x` on every
    // request with the POST body's GraphQL endpoint appended after
    // the `?` boundary. Userinfo would bake into every URL and
    // silently override the bearer the connector sets in the header.
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "api_url must not include userinfo".into(),
        });
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "api_url must not include a query string or fragment".into(),
        });
    }
    let host = parsed.host_str().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "api_url must include a host".into(),
    })?;
    let host_lower = host.to_ascii_lowercase();
    let is_local = matches!(host_lower.as_str(), "localhost" | "127.0.0.1" | "::1");
    let scheme = parsed.scheme();
    let token_origin_allowed = match auth {
        LinearAuth::ApiKey(_) => {
            (scheme == "https" && host_lower == "api.linear.app")
                || (is_local && matches!(scheme, "http" | "https"))
        }
        LinearAuth::CredentialId(_) => true,
    };

    if !token_origin_allowed {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "api_url must target https://api.linear.app for direct api_key mode".into(),
        });
    }

    Ok(parsed.to_string().trim_end_matches('/').to_string())
}

/// Doctor check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorResult {
    /// Overall status.
    status: DoctorStatus,
    /// Individual check results.
    checks: Vec<DoctorCheck>,
}

/// Doctor status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum DoctorStatus {
    /// All checks passed.
    Healthy,
    /// Some non-critical checks failed.
    Degraded,
    /// Critical checks failed.
    Unhealthy,
}

/// Individual doctor check.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorCheck {
    /// Check name.
    name: String,
    /// Check passed.
    passed: bool,
    /// Check message.
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    /// Whether this check is critical.
    critical: bool,
}

impl DoctorResult {
    /// Create a new doctor result from checks.
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

#[derive(Debug)]
struct AcceptedWebhookDelivery {
    delivery_id: Uuid,
    payload_fingerprint: [u8; 32],
    webhook_timestamp: i64,
    accepted_at: Instant,
}

/// Bounded replay protection for host-verified Linear deliveries.
///
/// Both indexes are updated together under the connector's replay mutex. The
/// payload index prevents an unsigned `Linear-Delivery` header from being
/// changed to admit the same authenticated payload again. Only fixed-size
/// identities are retained; neither payloads nor attacker-sized strings are
/// kept in the replay cache.
#[derive(Debug, Default)]
struct WebhookReplayReceipts {
    delivery_ids: BTreeSet<Uuid>,
    payload_fingerprints: BTreeSet<[u8; 32]>,
    accepted: VecDeque<AcceptedWebhookDelivery>,
    verification_time_ms: Option<i64>,
}

impl WebhookReplayReceipts {
    fn record(
        &mut self,
        delivery_id: Uuid,
        payload_fingerprint: [u8; 32],
        webhook_timestamp: i64,
        now_ms: i64,
        accepted_at: Instant,
    ) -> FcpResult<()> {
        // Once a signed timestamp has expired, a wall-clock rollback must not
        // make it admissible again after its receipt has been reclaimed. Only
        // trusted local time advances this watermark, never provider data.
        let verification_time_ms = self
            .verification_time_ms
            .map_or(now_ms, |previous| previous.max(now_ms));
        self.verification_time_ms = Some(verification_time_ms);
        if verification_time_ms.abs_diff(webhook_timestamp) > MAX_LINEAR_WEBHOOK_SKEW_MS {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "payload.webhookTimestamp is outside the accepted {MAX_LINEAR_WEBHOOK_SKEW_MS}ms replay window"
                ),
            });
        }

        // Provider timestamps must never control eviction: a newer (possibly
        // future-dated) delivery can otherwise erase still-valid older ones.
        // The production caller samples Instant while holding the mutex, so
        // this queue is ordered by local monotonic acceptance time. A stalled
        // or regressed wall clock also cannot discard a still-valid payload:
        // reclaim only after BOTH its local retention and signed validity end.
        while self.accepted.front().is_some_and(|receipt| {
            accepted_at.saturating_duration_since(receipt.accepted_at)
                >= LINEAR_WEBHOOK_REPLAY_RETENTION
                && verification_time_ms > receipt.webhook_timestamp
                && verification_time_ms.abs_diff(receipt.webhook_timestamp)
                    > MAX_LINEAR_WEBHOOK_SKEW_MS
        }) {
            if let Some(expired) = self.accepted.pop_front() {
                self.delivery_ids.remove(&expired.delivery_id);
                self.payload_fingerprints
                    .remove(&expired.payload_fingerprint);
            }
        }

        if self.delivery_ids.contains(&delivery_id) {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "delivery_id has already been processed within the replay window".into(),
            });
        }
        if self.payload_fingerprints.contains(&payload_fingerprint) {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "webhook payload has already been processed within the replay window"
                    .into(),
            });
        }
        if self.accepted.len() >= MAX_LINEAR_WEBHOOK_REPLAY_RECEIPTS {
            return Err(FcpError::ResourceExhausted {
                resource: "Linear webhook replay receipts; retry after active receipts expire"
                    .into(),
            });
        }

        self.delivery_ids.insert(delivery_id);
        self.payload_fingerprints.insert(payload_fingerprint);
        self.accepted.push_back(AcceptedWebhookDelivery {
            delivery_id,
            payload_fingerprint,
            webhook_timestamp,
            accepted_at,
        });
        Ok(())
    }
}

fn webhook_payload_fingerprint(payload: &serde_json::Value) -> FcpResult<[u8; 32]> {
    // Hash the complete host-verified payload, including provider fields not
    // represented by WebhookPayload. Canonical object ordering also prevents a
    // forwarding layer's JSON key ordering from creating a fresh replay key.
    let mut canonical_payload = payload.clone();
    canonical_payload.sort_all_objects();
    let encoded = serde_json::to_vec(&canonical_payload).map_err(|_| FcpError::Internal {
        message: "Failed to fingerprint Linear webhook payload".into(),
    })?;
    let mut hasher = Sha256::new();
    hasher.update(b"fcp.linear.webhook.payload.v1\0");
    hasher.update(encoded);
    Ok(hasher.finalize().into())
}

/// FCP Linear Connector.
pub struct LinearConnector {
    base: Arc<BaseConnector>,
    config: Option<LinearConfig>,
    client: Option<LinearClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
    webhook_replay_receipts: Mutex<WebhookReplayReceipts>,
}

impl LinearConnector {
    /// Create a new Linear connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("linear"))),
            config: None,
            client: None,
            verifier: None,
            session_id: None,
            webhook_replay_receipts: Mutex::new(WebhookReplayReceipts::default()),
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

    fn record_webhook_delivery(
        &self,
        delivery_id: Uuid,
        payload_fingerprint: [u8; 32],
        webhook_timestamp: i64,
    ) -> FcpResult<()> {
        let mut receipts = self
            .webhook_replay_receipts
            .lock()
            .map_err(|_| FcpError::Internal {
                message: "webhook replay cache poisoned".into(),
            })?;
        let result = receipts.record(
            delivery_id,
            payload_fingerprint,
            webhook_timestamp,
            Utc::now().timestamp_millis(),
            Instant::now(),
        );
        drop(receipts);
        result
    }

    /// Handle configure method.
    ///
    /// Accepts either `api_key` (direct) or `credential_id` (secretless via
    /// egress proxy injection). Exactly one must be provided.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = LinearConfig::from_params(&params)?;

        let client =
            LinearClient::new_with_auth(config.auth.clone()).map_err(|e| FcpError::Internal {
                message: format!("Failed to create HTTP client: {e}"),
            })?;
        let client = client.with_api_url(&config.api_url);

        self.config = Some(config);
        self.client = Some(client);
        self.base.set_configured(true);
        info!("Linear connector configured");

        Ok(json!({ "status": "configured" }))
    }

    /// Handle doctor diagnostics.
    ///
    /// Validates configuration, HTTP client, API URL, auth mode, network
    /// constraints, and credential injection status without making API calls.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let result = self.build_doctor_result();
        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize doctor result: {e}"),
        })
    }

    fn build_doctor_result(&self) -> DoctorResult {
        let mut checks = Vec::new();

        // Check 1: Configuration loaded
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

        let Some(config) = &self.config else {
            return DoctorResult::from_checks(checks);
        };

        // Check 2: HTTP client initialized
        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            passed: self.client.is_some(),
            message: Some(if self.client.is_some() {
                "HTTP client initialized".into()
            } else {
                "HTTP client missing; re-run configure".into()
            }),
            critical: true,
        });

        // Check 3: API URL scheme
        let scheme = if config.api_url.starts_with("https://") {
            "https"
        } else if config.api_url.starts_with("http://") {
            "http"
        } else {
            "unknown"
        };

        checks.push(DoctorCheck {
            name: "api_url".into(),
            passed: true,
            message: Some(format!("API URL ({scheme}): {}", config.api_url)),
            critical: false,
        });

        // Check 4: Auth mode
        checks.push(DoctorCheck {
            name: "auth_mode".into(),
            passed: true,
            message: Some(format!("Auth: {}", config.auth.redacted_label())),
            critical: false,
        });

        // Check 5: Network constraints - host must be api.linear.app (or test override)
        let allowed_hosts = ["api.linear.app"];
        let host_ok = config.api_url.starts_with("http://localhost")
            || config.api_url.starts_with("http://127.0.0.1")
            || allowed_hosts.iter().any(|h| config.api_url.contains(h));
        checks.push(DoctorCheck {
            name: "network_constraints".into(),
            passed: host_ok,
            message: Some(if host_ok {
                "API URL matches allowed host (api.linear.app)".into()
            } else {
                format!(
                    "API URL {} does not match allowed hosts: {:?}",
                    config.api_url, allowed_hosts
                )
            }),
            critical: true,
        });

        // Check 6: Credential injection status
        let secretless = config.auth.is_secretless();
        checks.push(DoctorCheck {
            name: "credential_injection".into(),
            passed: !secretless,
            message: Some(if secretless {
                "Credential injection required via egress proxy".into()
            } else {
                "Direct API key configured".into()
            }),
            critical: false,
        });

        DoctorResult::from_checks(checks)
    }

    /// Handle connector self-check.
    ///
    /// Performs a safe, read-only GraphQL query (viewer) to validate the API key
    /// is valid and the Linear API is reachable. Does not leak secrets in the report.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(client) = &self.client else {
            let report = SelfCheckReport::degraded("not_configured", "Connector is not configured");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        // If using credential_id, we can't validate directly
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
                streaming: true,
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
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.client.is_some();
        let metrics = self.base.metrics();
        Ok(json!({
            "status": if configured { "healthy" } else { "not_configured" },
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        }))
    }

    /// Handle introspect method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                op_info(
                    "linear.create_issue",
                    "Create an issue in Linear",
                    json!({
                        "type": "object",
                        "required": ["title", "team_id"],
                        "properties": {
                            "title": { "type": "string" },
                            "team_id": { "type": "string" },
                            "description": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "issue": { "type": "object" } } }),
                    "linear.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Create a new issue in Linear.".into(),
                        common_mistakes: vec!["Not specifying the team ID".into()],
                        examples: vec![
                            r#"{"title": "Fix login bug", "team_id": "TEAM-123"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("linear.get_issue"),
                            CapabilityId::from_static("linear.search_issues"),
                        ],
                    },
                ),
                op_info(
                    "linear.get_issue",
                    "Get a Linear issue by ID",
                    json!({
                        "type": "object",
                        "required": ["issue_id"],
                        "properties": {
                            "issue_id": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "issue": { "type": "object" } } }),
                    "linear.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Look up a specific issue by ID.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"issue_id": "LIN-123"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("linear.create_issue"),
                            CapabilityId::from_static("linear.update_issue"),
                        ],
                    },
                ),
                op_info(
                    "linear.update_issue",
                    "Update an issue's properties",
                    json!({
                        "type": "object",
                        "required": ["issue_id"],
                        "properties": {
                            "issue_id": { "type": "string" },
                            "title": { "type": "string" },
                            "state_id": { "type": "string" },
                            "description": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "issue": { "type": "object" } } }),
                    "linear.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Update issue title, status, assignee, or other fields."
                            .into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"issue_id": "LIN-123", "state_id": "done-state-id"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("linear.get_issue")],
                    },
                ),
                op_info(
                    "linear.search_issues",
                    "Search issues with text query",
                    json!({
                        "type": "object",
                        "required": ["query"],
                        "properties": {
                            "query": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "issues": { "type": "array" }
                        }
                    }),
                    "linear.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Search for issues matching a text query.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"query": "login bug"}"#.into()],
                        related: vec![CapabilityId::from_static("linear.get_issue")],
                    },
                ),
                op_info(
                    "linear.list_teams",
                    "List all teams in the workspace",
                    json!({
                        "type": "object",
                        "properties": {}
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "teams": { "type": "array" }
                        }
                    }),
                    "linear.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List available teams in the workspace.".into(),
                        common_mistakes: vec![],
                        examples: vec![r"{}".into()],
                        related: vec![CapabilityId::from_static("linear.create_issue")],
                    },
                ),
                op_info(
                    "linear.list_cycles",
                    "List cycles for a team",
                    json!({
                        "type": "object",
                        "required": ["team_id"],
                        "properties": {
                            "team_id": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "cycles": { "type": "array" }
                        }
                    }),
                    "linear.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List sprints/cycles for a team.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"team_id": "TEAM-123"}"#.into()],
                        related: vec![CapabilityId::from_static("linear.list_teams")],
                    },
                ),
                op_info(
                    "linear.add_comment",
                    "Add a comment to an issue",
                    json!({
                        "type": "object",
                        "required": ["issue_id", "body"],
                        "properties": {
                            "issue_id": { "type": "string" },
                            "body": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "comment": { "type": "object" } } }),
                    "linear.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Comment on an issue.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"issue_id": "LIN-123", "body": "Working on this now."}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("linear.get_issue")],
                    },
                ),
                op_info(
                    "linear.list_projects",
                    "List projects in the workspace",
                    json!({
                        "type": "object",
                        "properties": {}
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "projects": { "type": "array" }
                        }
                    }),
                    "linear.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List projects.".into(),
                        common_mistakes: vec![],
                        examples: vec![r"{}".into()],
                        related: vec![CapabilityId::from_static("linear.list_teams")],
                    },
                ),
                op_info(
                    "linear.plan_sync",
                    "Plan a deterministic Beads ↔ Linear sync action without side effects",
                    json!({
                        "type": "object",
                        "required": ["planned_at"],
                        "properties": {
                            "bead": {
                                "type": "object",
                                "description": "Optional Beads-side snapshot to compare"
                            },
                            "linear": {
                                "type": "object",
                                "description": "Optional Linear-side snapshot to compare"
                            },
                            "policy": {
                                "type": "string",
                                "enum": ["prefer_freshest", "prefer_bead", "prefer_linear", "manual"]
                            },
                            "planned_at": {
                                "type": "string",
                                "description": "RFC3339 timestamp recorded in the sync intent"
                            }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "intent": { "type": "object" }
                        }
                    }),
                    "linear.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Preview the exact Beads ↔ Linear sync action before any write."
                            .into(),
                        common_mistakes: vec![
                            "planned_at is required so the audit artifact stays explicit".into(),
                            "Provide at least one of bead or linear; both missing is not a meaningful sync plan"
                                .into(),
                        ],
                        examples: vec![
                            r#"{"planned_at":"2026-03-15T00:00:00Z","policy":"prefer_freshest","bead":{"bead_id":"br-123","title":"New title","description":"Body","status":"open","priority":1,"updated_at":"2026-03-15T00:00:00Z"},"linear":{"issue_id":"lin-1","identifier":"LIN-123","title":"Old title","description":"Body","status":"open","priority":1,"updated_at":"2026-03-14T23:00:00Z"}}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("linear.get_issue"),
                            CapabilityId::from_static("linear.process_webhook"),
                        ],
                    },
                ),
                op_info(
                    "linear.process_webhook",
                    "Process an inbound Linear webhook payload forwarded by fcp-host",
                    json!({
                        "type": "object",
                        "required": ["payload", "delivery_id", "signature_validated"],
                        "properties": {
                            "delivery_id": {
                                "type": "string",
                                "description": "Linear-Delivery header UUID forwarded by fcp-host"
                            },
                            "signature_validated": {
                                "type": "boolean",
                                "description": "True only when fcp-host has already verified Linear-Signature against the raw body"
                            },
                            "payload": {
                                "type": "object",
                                "description": "Raw Linear webhook payload"
                            }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "event": {
                                "type": "object",
                                "properties": {
                                    "topic": { "type": "string" },
                                    "resource_type": { "type": "string" },
                                    "action": { "type": "string" },
                                    "resource_uri": { "type": "string" },
                                    "data": { "type": "object" },
                                    "delivery_id": { "type": "string" },
                                    "idempotency_key": { "type": "string" },
                                    "webhook_timestamp": { "type": "integer" }
                                }
                            }
                        }
                    }),
                    "linear.process_webhook",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Process a webhook event forwarded by fcp-host.".into(),
                        common_mistakes: vec![
                            "Sending the payload without the wrapper object".into(),
                            "Forwarding parsed webhook JSON before fcp-host verifies the Linear-Signature header".into(),
                            "Dropping the Linear-Delivery header; without it downstream idempotency receipts cannot be stable".into(),
                        ],
                        examples: vec![
                            r#"{"delivery_id":"234d1a4e-b617-4388-90fe-adc3633d6b72","signature_validated":true,"payload":{"action":"create","type":"Issue","createdAt":"2026-03-07T00:00:00Z","webhookTimestamp":1762459200000,"data":{"id":"i1"}}}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("linear.get_issue"),
                        ],
                    },
                ),
            ],
            events: vec![
                EventInfo {
                    topic: "linear.issue.create".into(),
                    schema: json!({
                        "type": "object",
                        "properties": {
                            "topic": { "type": "string" },
                            "resource_type": { "type": "string", "enum": ["Issue"] },
                            "action": { "type": "string", "enum": ["create"] },
                            "resource_uri": { "type": "string" },
                            "data": { "type": "object" }
                        }
                    }),
                    requires_ack: false,
                },
                EventInfo {
                    topic: "linear.issue.update".into(),
                    schema: json!({
                        "type": "object",
                        "properties": {
                            "topic": { "type": "string" },
                            "resource_type": { "type": "string", "enum": ["Issue"] },
                            "action": { "type": "string", "enum": ["update"] },
                            "resource_uri": { "type": "string" },
                            "data": { "type": "object" }
                        }
                    }),
                    requires_ack: false,
                },
                EventInfo {
                    topic: "linear.issue.remove".into(),
                    schema: json!({
                        "type": "object",
                        "properties": {
                            "topic": { "type": "string" },
                            "resource_type": { "type": "string", "enum": ["Issue"] },
                            "action": { "type": "string", "enum": ["remove"] },
                            "resource_uri": { "type": "string" },
                            "data": { "type": "object" }
                        }
                    }),
                    requires_ack: false,
                },
                EventInfo {
                    topic: "linear.comment.create".into(),
                    schema: json!({
                        "type": "object",
                        "properties": {
                            "topic": { "type": "string" },
                            "resource_type": { "type": "string", "enum": ["Comment"] },
                            "action": { "type": "string", "enum": ["create"] },
                            "resource_uri": { "type": "string" },
                            "data": { "type": "object" }
                        }
                    }),
                    requires_ack: false,
                },
                EventInfo {
                    topic: "linear.comment.update".into(),
                    schema: json!({
                        "type": "object",
                        "properties": {
                            "topic": { "type": "string" },
                            "resource_type": { "type": "string", "enum": ["Comment"] },
                            "action": { "type": "string", "enum": ["update"] },
                            "resource_uri": { "type": "string" },
                            "data": { "type": "object" }
                        }
                    }),
                    requires_ack: false,
                },
                EventInfo {
                    topic: "linear.comment.remove".into(),
                    schema: json!({
                        "type": "object",
                        "properties": {
                            "topic": { "type": "string" },
                            "resource_type": { "type": "string", "enum": ["Comment"] },
                            "action": { "type": "string", "enum": ["remove"] },
                            "resource_uri": { "type": "string" },
                            "data": { "type": "object" }
                        }
                    }),
                    requires_ack: false,
                },
                EventInfo {
                    topic: "linear.project.create".into(),
                    schema: json!({
                        "type": "object",
                        "properties": {
                            "topic": { "type": "string" },
                            "resource_type": { "type": "string", "enum": ["Project"] },
                            "action": { "type": "string", "enum": ["create"] },
                            "resource_uri": { "type": "string" },
                            "data": { "type": "object" }
                        }
                    }),
                    requires_ack: false,
                },
                EventInfo {
                    topic: "linear.project.update".into(),
                    schema: json!({
                        "type": "object",
                        "properties": {
                            "topic": { "type": "string" },
                            "resource_type": { "type": "string", "enum": ["Project"] },
                            "action": { "type": "string", "enum": ["update"] },
                            "resource_uri": { "type": "string" },
                            "data": { "type": "object" }
                        }
                    }),
                    requires_ack: false,
                },
                EventInfo {
                    topic: "linear.project.remove".into(),
                    schema: json!({
                        "type": "object",
                        "properties": {
                            "topic": { "type": "string" },
                            "resource_type": { "type": "string", "enum": ["Project"] },
                            "action": { "type": "string", "enum": ["remove"] },
                            "resource_uri": { "type": "string" },
                            "data": { "type": "object" }
                        }
                    }),
                    requires_ack: false,
                },
                EventInfo {
                    topic: "linear.cycle.create".into(),
                    schema: json!({
                        "type": "object",
                        "properties": {
                            "topic": { "type": "string" },
                            "resource_type": { "type": "string", "enum": ["Cycle"] },
                            "action": { "type": "string", "enum": ["create"] },
                            "resource_uri": { "type": "string" },
                            "data": { "type": "object" }
                        }
                    }),
                    requires_ack: false,
                },
                EventInfo {
                    topic: "linear.cycle.update".into(),
                    schema: json!({
                        "type": "object",
                        "properties": {
                            "topic": { "type": "string" },
                            "resource_type": { "type": "string", "enum": ["Cycle"] },
                            "action": { "type": "string", "enum": ["update"] },
                            "resource_uri": { "type": "string" },
                            "data": { "type": "object" }
                        }
                    }),
                    requires_ack: false,
                },
                EventInfo {
                    topic: "linear.cycle.remove".into(),
                    schema: json!({
                        "type": "object",
                        "properties": {
                            "topic": { "type": "string" },
                            "resource_type": { "type": "string", "enum": ["Cycle"] },
                            "action": { "type": "string", "enum": ["remove"] },
                            "resource_uri": { "type": "string" },
                            "data": { "type": "object" }
                        }
                    }),
                    requires_ack: false,
                },
            ],
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

        let resource_uris = resource_uris_for_operation(operation, &input)?;

        if let Some(verifier) = &self.verifier {
            // dja9u.1.b: typestate handoff via verify_bound.
            let _bound = verifier.verify_bound(token, &cap_id, &op_id, &resource_uris)?;
        } else {
            return Err(FcpError::NotConfigured);
        }

        match operation {
            "linear.create_issue" => self.invoke_create_issue(input).await,
            "linear.get_issue" => self.invoke_get_issue(input).await,
            "linear.update_issue" => self.invoke_update_issue(input).await,
            "linear.search_issues" => self.invoke_search_issues(input).await,
            "linear.list_teams" => self.invoke_list_teams().await,
            "linear.list_cycles" => self.invoke_list_cycles(input).await,
            "linear.add_comment" => self.invoke_add_comment(input).await,
            "linear.list_projects" => self.invoke_list_projects().await,
            "linear.plan_sync" => self.invoke_plan_sync(input).await,
            "linear.process_webhook" => self.invoke_process_webhook(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    // ── Operation implementations ─────────────────────────────────

    async fn invoke_create_issue(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let title = require_str(&input, "title")?;
        let team_id = require_str(&input, "team_id")?;
        let description = input.get("description").and_then(|v| v.as_str());

        let issue = client
            .create_issue(title, team_id, description)
            .await
            .map_err(|e: LinearError| e.to_fcp_error())?;

        Ok(json!({ "issue": issue }))
    }

    async fn invoke_get_issue(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let issue_id = require_str(&input, "issue_id")?;

        let issue = client
            .get_issue(issue_id)
            .await
            .map_err(|e: LinearError| e.to_fcp_error())?;

        Ok(json!({ "issue": issue }))
    }

    async fn invoke_update_issue(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let issue_id = require_str(&input, "issue_id")?;
        let title = input.get("title").and_then(|v| v.as_str());
        let state_id = input.get("state_id").and_then(|v| v.as_str());
        let description = input.get("description").and_then(|v| v.as_str());

        let issue = client
            .update_issue(issue_id, title, state_id, description)
            .await
            .map_err(|e: LinearError| e.to_fcp_error())?;

        Ok(json!({ "issue": issue }))
    }

    async fn invoke_search_issues(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let query = require_str(&input, "query")?;

        let issues = client
            .search_issues(query)
            .await
            .map_err(|e: LinearError| e.to_fcp_error())?;

        Ok(json!({ "issues": issues }))
    }

    async fn invoke_list_teams(&self) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let teams = client
            .list_teams()
            .await
            .map_err(|e: LinearError| e.to_fcp_error())?;

        Ok(json!({ "teams": teams }))
    }

    async fn invoke_list_cycles(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let team_id = require_str(&input, "team_id")?;

        let cycles = client
            .list_cycles(team_id)
            .await
            .map_err(|e: LinearError| e.to_fcp_error())?;

        Ok(json!({ "cycles": cycles }))
    }

    async fn invoke_add_comment(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let issue_id = require_str(&input, "issue_id")?;
        let body = require_str(&input, "body")?;

        let comment = client
            .add_comment(issue_id, body)
            .await
            .map_err(|e: LinearError| e.to_fcp_error())?;

        Ok(json!({ "comment": comment }))
    }

    async fn invoke_list_projects(&self) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let projects = client
            .list_projects()
            .await
            .map_err(|e: LinearError| e.to_fcp_error())?;

        Ok(json!({ "projects": projects }))
    }

    async fn invoke_plan_sync(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let bead = input
            .get("bead")
            .cloned()
            .map(serde_json::from_value::<BeadSyncSnapshot>)
            .transpose()
            .map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid bead snapshot: {e}"),
            })?;
        let linear = input
            .get("linear")
            .cloned()
            .map(serde_json::from_value::<LinearSyncSnapshot>)
            .transpose()
            .map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid linear snapshot: {e}"),
            })?;

        if bead.is_none() && linear.is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "At least one of bead or linear must be provided".into(),
            });
        }

        let policy = input
            .get("policy")
            .cloned()
            .map(serde_json::from_value::<SyncConflictPolicy>)
            .transpose()
            .map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid sync policy: {e}"),
            })?
            .unwrap_or(SyncConflictPolicy::PreferFreshest);
        let planned_at = require_str(&input, "planned_at")?;
        let intent =
            SyncOperationIntent::from_snapshots(bead.as_ref(), linear.as_ref(), policy, planned_at);

        Ok(json!({ "intent": intent }))
    }

    async fn invoke_process_webhook(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        use crate::types::{WebhookPayload, WebhookResourceType};

        let delivery_id_raw = require_str(&input, "delivery_id")?;
        let delivery_id =
            Uuid::parse_str(delivery_id_raw).map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "delivery_id must be a UUID from the Linear-Delivery header".into(),
            })?;
        let signature_validated = input
            .get("signature_validated")
            .and_then(|value| value.as_bool())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "signature_validated must be a boolean".into(),
            })?;
        if !signature_validated {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "signature_validated must be true before processing webhook payloads"
                    .into(),
            });
        }

        let payload_value = input.get("payload").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing required field: payload".into(),
        })?;

        let payload: WebhookPayload =
            serde_json::from_value(payload_value.clone()).map_err(|e| {
                FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid webhook payload: {e}"),
                }
            })?;
        let webhook_timestamp = payload.webhook_timestamp.ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "payload.webhookTimestamp is required for replay protection".into(),
        })?;
        self.record_webhook_delivery(
            delivery_id,
            webhook_payload_fingerprint(payload_value)?,
            webhook_timestamp,
        )?;

        let topic = payload.resource_type.to_topic(payload.action);
        let idempotency_key = format!("linear.webhook.{}", delivery_id.as_hyphenated());

        info!(
            event = "linear.webhook.processed",
            topic = %topic,
            resource_type = %payload.resource_type,
            action = %payload.action,
            delivery_id = %delivery_id,
            webhook_id = ?payload.webhook_id,
            "Linear webhook event processed"
        );

        // Extract resource ID from data if available
        let resource_id = payload
            .data
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let resource_uri = match payload.resource_type {
            WebhookResourceType::Issue => format!("linear://issue/{resource_id}"),
            WebhookResourceType::Comment => format!("linear://comment/{resource_id}"),
            WebhookResourceType::Project => format!("linear://project/{resource_id}"),
            WebhookResourceType::Cycle => format!("linear://cycle/{resource_id}"),
            WebhookResourceType::IssueLabel => format!("linear://label/{resource_id}"),
            WebhookResourceType::Reaction => format!("linear://reaction/{resource_id}"),
        };

        Ok(json!({
            "event": {
                "topic": topic,
                "resource_type": payload.resource_type.to_string(),
                "action": payload.action.to_string(),
                "resource_uri": resource_uri,
                "resource_id": resource_id,
                "actor": payload.actor,
                "timestamp": payload.created_at,
                "webhook_timestamp": webhook_timestamp,
                "data": payload.data,
                "delivery_id": delivery_id.to_string(),
                "idempotency_key": idempotency_key,
                "webhook_id": payload.webhook_id,
            }
        }))
    }

    /// Handle shutdown.
    pub async fn handle_shutdown(
        &self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        if let Some(client) = &self.client {
            client.shutdown();
        }
        info!("Linear connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for LinearConnector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helper functions ──────────────────────────────────────────────

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required field: {field}"),
        })
}

fn resource_uris_for_operation(
    operation: &str,
    input: &serde_json::Value,
) -> FcpResult<Vec<String>> {
    let uris = match operation {
        "linear.create_issue" => {
            let team_id = require_str(input, "team_id")?;
            vec![format!("linear://team/{team_id}/issues")]
        }
        "linear.get_issue" | "linear.update_issue" => {
            let issue_id = require_str(input, "issue_id")?;
            vec![format!("linear://issue/{issue_id}")]
        }
        "linear.list_cycles" => {
            let team_id = require_str(input, "team_id")?;
            vec![format!("linear://team/{team_id}/cycles")]
        }
        "linear.add_comment" => {
            let issue_id = require_str(input, "issue_id")?;
            vec![format!("linear://issue/{issue_id}/comments")]
        }
        "linear.process_webhook" => {
            let payload_value = input.get("payload").ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required field: payload".into(),
            })?;
            let payload: crate::types::WebhookPayload =
                serde_json::from_value(payload_value.clone()).map_err(|e| {
                    FcpError::InvalidRequest {
                        code: 1003,
                        message: format!("Invalid webhook payload: {e}"),
                    }
                })?;
            vec![resource_uri_for_webhook_payload(&payload)]
        }
        _ => Vec::new(),
    };

    Ok(uris)
}

fn resource_uri_for_webhook_payload(payload: &crate::types::WebhookPayload) -> String {
    let resource_id = payload
        .data
        .get("id")
        .and_then(|value| value.as_str())
        .unwrap_or("unknown");

    match payload.resource_type {
        crate::types::WebhookResourceType::Issue => format!("linear://issue/{resource_id}"),
        crate::types::WebhookResourceType::Comment => format!("linear://comment/{resource_id}"),
        crate::types::WebhookResourceType::Project => format!("linear://project/{resource_id}"),
        crate::types::WebhookResourceType::Cycle => format!("linear://cycle/{resource_id}"),
        crate::types::WebhookResourceType::IssueLabel => format!("linear://label/{resource_id}"),
        crate::types::WebhookResourceType::Reaction => {
            format!("linear://reaction/{resource_id}")
        }
    }
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
        requires_approval: None,
        safety_tier,
        idempotency,
        ai_hints,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_manifest::{ConnectorManifest, OperationSection};
    use fcp_prelude::CapabilityConstraints;
    use std::path::PathBuf;

    #[test]
    fn validate_api_url_for_auth_accepts_api_linear_app_with_api_key() {
        let auth = LinearAuth::ApiKey("lin_api_test".into());
        let out = validate_api_url_for_auth("https://api.linear.app/graphql", &auth).unwrap();
        assert_eq!(out, "https://api.linear.app/graphql");
    }

    #[test]
    fn validate_api_url_for_auth_rejects_query_string_with_api_key() {
        let auth = LinearAuth::ApiKey("lin_api_test".into());
        let err =
            validate_api_url_for_auth("https://api.linear.app/graphql?leak=x", &auth).unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("query"), "got: {message}");
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn validate_api_url_for_auth_rejects_fragment_with_api_key() {
        let auth = LinearAuth::ApiKey("lin_api_test".into());
        let err =
            validate_api_url_for_auth("https://api.linear.app/graphql#frag", &auth).unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn validate_api_url_for_auth_rejects_userinfo_with_api_key() {
        let auth = LinearAuth::ApiKey("lin_api_test".into());
        let err = validate_api_url_for_auth("https://attacker:pw@api.linear.app/graphql", &auth)
            .unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("userinfo"), "got: {message}");
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn validate_api_url_for_auth_rejects_query_string_with_credential_id() {
        let cid = fcp_core::CredentialId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let auth = LinearAuth::CredentialId(cid);
        let err = validate_api_url_for_auth("https://vault-proxy.example/graphql?leak=x", &auth)
            .unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn validate_api_url_for_auth_rejects_substring_smuggle_with_api_key() {
        // Parsed host is evil.com, not api.linear.app — rejected.
        let auth = LinearAuth::ApiKey("lin_api_test".into());
        let err = validate_api_url_for_auth("https://evil.com/api.linear.app/graphql", &auth)
            .unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    fn generate_token_with_constraints(
        signing_key: &Ed25519SigningKey,
        op: &str,
        instance_id: &InstanceId,
        constraints: &CapabilityConstraints,
    ) -> CapabilityToken {
        let cap = match op {
            "linear.create_issue" | "linear.update_issue" | "linear.add_comment" => "linear.write",
            "linear.process_webhook" => "linear.process_webhook",
            _ => "linear.read",
        };
        let mut constraints_cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut constraints_cbor).unwrap();

        let now = Utc::now();
        let cose = CapabilityTokenBuilder::new()
            .capability_id(cap)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[op])
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&constraints_cbor)
            .expect("constraints CBOR should be valid")
            .target_instance(instance_id.as_str())
            .sign(signing_key)
            .unwrap();
        CapabilityToken::from_raw(cose)
    }

    fn generate_valid_token(
        signing_key: &Ed25519SigningKey,
        op: &str,
        instance_id: &InstanceId,
    ) -> CapabilityToken {
        generate_token_with_constraints(
            signing_key,
            op,
            instance_id,
            &CapabilityConstraints {
                resource_allow: vec!["*".into()],
                ..Default::default()
            },
        )
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = LinearConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["linear.read"]
            }))
            .await
            .unwrap();

        assert_eq!(result["status"], "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = LinearConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = LinearConnector::new();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["linear.get_issue"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "linear.get_issue", connector.instance_id());

        let result = connector
            .handle_invoke(json!({
                "operation": "linear.get_issue",
                "input": { "issue_id": "LIN-123" },
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_field() {
        let mut connector = LinearConnector::new();
        connector.client = Some(
            LinearClient::new("fake_key")
                .unwrap()
                .with_api_url("http://localhost:9999/graphql"),
        );

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["linear.create_issue"]
            }))
            .await
            .unwrap();

        let token =
            generate_valid_token(&signing_key, "linear.create_issue", connector.instance_id());

        let result = connector
            .handle_invoke(json!({
                "operation": "linear.create_issue",
                "input": { "title": "Bug" },
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("team_id"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_resource_uris_for_issue_operations() {
        let get_issue =
            resource_uris_for_operation("linear.get_issue", &json!({ "issue_id": "issue-42" }))
                .unwrap();
        assert_eq!(get_issue, vec!["linear://issue/issue-42"]);

        let create_issue =
            resource_uris_for_operation("linear.create_issue", &json!({ "team_id": "team-7" }))
                .unwrap();
        assert_eq!(create_issue, vec!["linear://team/team-7/issues"]);

        let add_comment =
            resource_uris_for_operation("linear.add_comment", &json!({ "issue_id": "issue-42" }))
                .unwrap();
        assert_eq!(add_comment, vec!["linear://issue/issue-42/comments"]);
    }

    #[test]
    fn test_resource_uris_for_webhook_operation() {
        let uris = resource_uris_for_operation(
            "linear.process_webhook",
            &json!({
                "payload": {
                    "action": "create",
                    "type": "Issue",
                    "createdAt": "2026-03-07T00:00:00Z",
                    "webhookTimestamp": 1762459200000_i64,
                    "data": { "id": "issue-1" }
                }
            }),
        )
        .unwrap();
        assert_eq!(uris, vec!["linear://issue/issue-1"]);
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_issue_rejects_disallowed_resource_scope() {
        let mut connector = LinearConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["linear.get_issue"]
            }))
            .await
            .unwrap();

        let token = generate_token_with_constraints(
            &signing_key,
            "linear.get_issue",
            connector.instance_id(),
            &CapabilityConstraints {
                resource_allow: vec!["linear://issue/issue-allowed".into()],
                ..Default::default()
            },
        );

        let result = connector
            .handle_invoke(json!({
                "operation": "linear.get_issue",
                "input": { "issue_id": "issue-42" },
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::ResourceNotAllowed { resource } => {
                assert_eq!(resource, "linear://issue/issue-42");
            }
            other => panic!("Expected ResourceNotAllowed, got: {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_plan_sync_requires_at_least_one_snapshot() {
        let mut connector = LinearConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["linear.plan_sync"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "linear.plan_sync", connector.instance_id());
        let result = connector
            .handle_invoke(json!({
                "operation": "linear.plan_sync",
                "input": { "planned_at": "2026-03-15T00:00:00Z" },
                "capability_token": token
            }))
            .await;

        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("At least one of bead or linear"));
            }
            other => panic!("Expected InvalidRequest, got: {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_all_operations() {
        let connector = LinearConnector::new();
        let result = connector.handle_introspect().await.unwrap();

        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert!(op_ids.contains(&"linear.create_issue"));
        assert!(op_ids.contains(&"linear.get_issue"));
        assert!(op_ids.contains(&"linear.update_issue"));
        assert!(op_ids.contains(&"linear.search_issues"));
        assert!(op_ids.contains(&"linear.list_teams"));
        assert!(op_ids.contains(&"linear.list_cycles"));
        assert!(op_ids.contains(&"linear.add_comment"));
        assert!(op_ids.contains(&"linear.list_projects"));
        assert!(op_ids.contains(&"linear.plan_sync"));
        assert!(op_ids.contains(&"linear.process_webhook"));
        assert_eq!(ops.len(), 10);

        // Verify event descriptors are present
        let events = result["events"].as_array().unwrap();
        assert_eq!(events.len(), 12);
        let topics: Vec<&str> = events
            .iter()
            .map(|e| e["topic"].as_str().unwrap())
            .collect();
        assert!(topics.contains(&"linear.issue.create"));
        assert!(topics.contains(&"linear.issue.update"));
        assert!(topics.contains(&"linear.issue.remove"));
        assert!(topics.contains(&"linear.comment.create"));
        assert!(topics.contains(&"linear.project.update"));
        assert!(topics.contains(&"linear.cycle.remove"));
    }

    // ── Doctor tests ──────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_doctor_not_configured() {
        let connector = LinearConnector::new();
        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "unhealthy");
        let checks = result["checks"].as_array().unwrap();
        let config_check = &checks[0];
        assert_eq!(config_check["name"], "configuration");
        assert!(!config_check["passed"].as_bool().unwrap());
        assert!(config_check["critical"].as_bool().unwrap());
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured_api_key() {
        let mut connector = LinearConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "lin_api_test123"
            }))
            .await
            .unwrap();

        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "healthy");
        let checks = result["checks"].as_array().unwrap();

        // All critical checks should pass
        for check in checks {
            if check["critical"].as_bool().unwrap() {
                assert!(
                    check["passed"].as_bool().unwrap(),
                    "Critical check '{}' should pass",
                    check["name"]
                );
            }
        }

        // Auth mode should show redacted
        let auth_check = checks.iter().find(|c| c["name"] == "auth_mode").unwrap();
        assert!(
            auth_check["message"]
                .as_str()
                .unwrap()
                .contains("api_key:redacted")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured_credential_id() {
        let mut connector = LinearConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "550e8400-e29b-41d4-a716-446655440000"
            }))
            .await
            .unwrap();

        let result = connector.handle_doctor().await.unwrap();
        // Should be degraded because credential_injection check fails (not passed)
        // but it's not critical, so status depends on other checks
        let checks = result["checks"].as_array().unwrap();
        let cred_check = checks
            .iter()
            .find(|c| c["name"] == "credential_injection")
            .unwrap();
        assert!(!cred_check["passed"].as_bool().unwrap());
        assert!(!cred_check["critical"].as_bool().unwrap());

        let auth_check = checks.iter().find(|c| c["name"] == "auth_mode").unwrap();
        assert!(
            auth_check["message"]
                .as_str()
                .unwrap()
                .contains("credential_id:")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_bad_network_host() {
        let mut connector = LinearConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "550e8400-e29b-41d4-a716-446655440000",
                "api_url": "https://evil.example.com/graphql"
            }))
            .await
            .unwrap();

        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "unhealthy");
        let checks = result["checks"].as_array().unwrap();
        let net_check = checks
            .iter()
            .find(|c| c["name"] == "network_constraints")
            .unwrap();
        assert!(!net_check["passed"].as_bool().unwrap());
        assert!(net_check["critical"].as_bool().unwrap());
    }

    // ── Self-check tests ────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_self_check_not_configured() {
        use fcp_prelude::SelfCheckStatus;
        let connector = LinearConnector::new();
        let result = connector.handle_self_check().await.unwrap();
        let report: SelfCheckReport = serde_json::from_value(result).unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_credential_id_mode() {
        use fcp_prelude::SelfCheckStatus;
        let mut connector = LinearConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "550e8400-e29b-41d4-a716-446655440000"
            }))
            .await
            .unwrap();

        let result = connector.handle_self_check().await.unwrap();
        let report: SelfCheckReport = serde_json::from_value(result).unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
        assert_eq!(
            report.reason_code.as_deref(),
            Some("credential_injection_required")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_unreachable_api() {
        use fcp_prelude::SelfCheckStatus;
        let mut connector = LinearConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "bad-key",
                "api_url": "http://127.0.0.1:1/graphql"
            }))
            .await
            .unwrap();

        let result = connector.handle_self_check().await.unwrap();
        let report: SelfCheckReport = serde_json::from_value(result).unwrap();
        // Should be degraded (retryable) since connection refused is an HTTP error
        assert!(
            report.status == SelfCheckStatus::Degraded || report.status == SelfCheckStatus::Failed
        );
    }

    // ── Configure multi-auth tests ──────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_configure_api_key() {
        let mut connector = LinearConnector::new();
        let result = connector
            .handle_configure(json!({ "api_key": "lin_api_test" }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_credential_id() {
        let mut connector = LinearConnector::new();
        let result = connector
            .handle_configure(json!({
                "credential_id": "550e8400-e29b-41d4-a716-446655440000"
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_both_rejected() {
        let mut connector = LinearConnector::new();
        let result = connector
            .handle_configure(json!({
                "api_key": "test",
                "credential_id": "550e8400-e29b-41d4-a716-446655440000"
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("exactly one"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_none_rejected() {
        let mut connector = LinearConnector::new();
        let result = connector.handle_configure(json!({})).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("Missing"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_webhook_payload_fingerprint_is_canonical_and_preserves_unknown_fields() {
        let first: serde_json::Value = serde_json::from_str(
            r#"{"data":{"id":"issue-1","labels":[{"name":"bug","id":"label-1"}]},"updatedFrom":{"title":"old"},"webhookId":"hook-1"}"#,
        )
        .unwrap();
        let reordered: serde_json::Value = serde_json::from_str(
            r#"{"webhookId":"hook-1","updatedFrom":{"title":"old"},"data":{"labels":[{"id":"label-1","name":"bug"}],"id":"issue-1"}}"#,
        )
        .unwrap();
        assert_eq!(
            webhook_payload_fingerprint(&first).unwrap(),
            webhook_payload_fingerprint(&reordered).unwrap()
        );

        // updatedFrom is provider evidence that the typed WebhookPayload does
        // not retain. It still distinguishes authenticated payloads.
        let mut changed = first.clone();
        changed["updatedFrom"]["title"] = json!("different old title");
        assert_ne!(
            webhook_payload_fingerprint(&first).unwrap(),
            webhook_payload_fingerprint(&changed).unwrap()
        );
    }

    #[test]
    fn test_webhook_replay_timestamp_boundaries_and_extremes() {
        let mut receipts = WebhookReplayReceipts::default();
        let now: i64 = 1_000_000;
        let accepted_at = Instant::now();
        for (id, timestamp) in [(1, now - 60_000), (2, now + 60_000)] {
            receipts
                .record(
                    Uuid::from_u128(id),
                    Sha256::digest(timestamp.to_le_bytes()).into(),
                    timestamp,
                    now,
                    accepted_at,
                )
                .unwrap();
        }
        for timestamp in [now - 60_001, now + 60_001, i64::MIN, i64::MAX] {
            let error = receipts
                .record(Uuid::new_v4(), [9; 32], timestamp, now, accepted_at)
                .unwrap_err();
            assert!(matches!(
                error,
                FcpError::InvalidRequest { ref message, .. }
                    if message.contains("replay window")
            ));
        }
        assert_eq!(receipts.accepted.len(), 2);
        assert_eq!(receipts.delivery_ids.len(), 2);
        assert_eq!(receipts.payload_fingerprints.len(), 2);
    }

    #[test]
    fn test_webhook_replay_provider_timestamps_cannot_evict_live_receipts() {
        let mut receipts = WebhookReplayReceipts::default();
        let now = 1_000_000;
        let accepted_at = Instant::now();
        let old_delivery = Uuid::from_u128(1);
        receipts
            .record(old_delivery, [1; 32], now - 59_000, now, accepted_at)
            .unwrap();
        receipts
            .record(
                Uuid::from_u128(2),
                [2; 32],
                now + 59_000,
                now + 1,
                accepted_at + StdDuration::from_millis(1),
            )
            .unwrap();

        for delivery_id in [old_delivery, Uuid::from_u128(3)] {
            let error = receipts
                .record(
                    delivery_id,
                    [1; 32],
                    now - 59_000,
                    now + 2,
                    accepted_at + StdDuration::from_millis(2),
                )
                .unwrap_err();
            assert!(matches!(
                error,
                FcpError::InvalidRequest { ref message, .. }
                    if message.contains("already been processed")
            ));
        }
        assert_eq!(receipts.accepted.len(), 2);
        assert!(!receipts.delivery_ids.contains(&Uuid::from_u128(3)));
        assert_eq!(receipts.accepted[0].accepted_at, accepted_at);
    }

    #[test]
    fn test_webhook_replay_survives_clock_stall_and_rollback_after_expiration() {
        let mut receipts = WebhookReplayReceipts::default();
        let now = 1_000_000;
        let accepted_at = Instant::now();
        let delivery_id = Uuid::from_u128(1);
        let timestamp = now + 60_000;
        receipts
            .record(delivery_id, [1; 32], timestamp, now, accepted_at)
            .unwrap();

        // Wall time has stalled while monotonic retention has fully elapsed.
        // The signed payload remains valid, so its receipt must remain too.
        let later = accepted_at + StdDuration::from_secs(180);
        let duplicate = receipts
            .record(Uuid::from_u128(2), [1; 32], timestamp, now, later)
            .unwrap_err();
        assert!(matches!(
            duplicate,
            FcpError::InvalidRequest { ref message, .. }
                if message.contains("already been processed")
        ));
        assert_eq!(receipts.accepted.len(), 1);
        assert_eq!(receipts.accepted[0].accepted_at, accepted_at);

        // Advancing beyond signed validity permits safe reclamation.
        let after_expiry = now + 120_001;
        receipts
            .record(
                Uuid::from_u128(2),
                [2; 32],
                after_expiry,
                after_expiry,
                later + StdDuration::from_millis(1),
            )
            .unwrap();
        assert_eq!(receipts.accepted.len(), 1);
        assert!(!receipts.delivery_ids.contains(&delivery_id));
        assert!(!receipts.payload_fingerprints.contains(&[1; 32]));

        // Rolling UTC back cannot authorize the now-forgotten signed payload.
        let expired = receipts
            .record(
                delivery_id,
                [1; 32],
                timestamp,
                now,
                later + StdDuration::from_millis(2),
            )
            .unwrap_err();
        assert!(matches!(
            expired,
            FcpError::InvalidRequest { ref message, .. }
                if message.contains("replay window")
        ));
        assert_eq!(receipts.verification_time_ms, Some(after_expiry));
        assert_eq!(receipts.accepted.len(), 1);
    }

    #[test]
    fn test_webhook_replay_capacity_fails_closed_and_duplicates_do_not_refresh() {
        let mut receipts = WebhookReplayReceipts::default();
        let now = 1_000_000;
        let accepted_at = Instant::now();
        let timestamp = now + 60_000;
        for index in 0..MAX_LINEAR_WEBHOOK_REPLAY_RECEIPTS {
            receipts
                .record(
                    Uuid::from_u128(u128::try_from(index).unwrap()),
                    Sha256::digest(index.to_le_bytes()).into(),
                    timestamp,
                    now,
                    accepted_at,
                )
                .unwrap();
        }

        let rejected_id = Uuid::new_v4();
        let rejected_fingerprint = [255; 32];
        let capacity_error = receipts
            .record(
                rejected_id,
                rejected_fingerprint,
                timestamp,
                now + 60_000,
                accepted_at + StdDuration::from_secs(60),
            )
            .unwrap_err();
        assert!(matches!(capacity_error, FcpError::ResourceExhausted { .. }));
        assert!(!receipts.delivery_ids.contains(&rejected_id));
        assert!(
            !receipts
                .payload_fingerprints
                .contains(&rejected_fingerprint)
        );

        let first_fingerprint = Sha256::digest(0_usize.to_le_bytes()).into();
        // Both duplicate indexes must take precedence over capacity, and
        // neither failed alias may consume the other index or refresh expiry.
        for (delivery_id, fingerprint) in [
            (Uuid::nil(), rejected_fingerprint),
            (rejected_id, first_fingerprint),
        ] {
            let error = receipts
                .record(
                    delivery_id,
                    fingerprint,
                    timestamp,
                    now + 120_000,
                    accepted_at + StdDuration::from_secs(120),
                )
                .unwrap_err();
            assert!(matches!(
                error,
                FcpError::InvalidRequest { ref message, .. }
                    if message.contains("already been processed")
            ));
        }
        assert_eq!(receipts.accepted[0].accepted_at, accepted_at);
        assert_eq!(receipts.accepted.len(), MAX_LINEAR_WEBHOOK_REPLAY_RECEIPTS);
        assert_eq!(
            receipts.delivery_ids.len(),
            MAX_LINEAR_WEBHOOK_REPLAY_RECEIPTS
        );
        assert_eq!(
            receipts.payload_fingerprints.len(),
            MAX_LINEAR_WEBHOOK_REPLAY_RECEIPTS
        );

        // The failed candidate was not partially recorded, and duplicate
        // attempts did not extend the original receipts' acceptance times.
        receipts
            .record(
                rejected_id,
                rejected_fingerprint,
                now + 120_001,
                now + 120_001,
                accepted_at + LINEAR_WEBHOOK_REPLAY_RETENTION,
            )
            .unwrap();
        assert_eq!(receipts.accepted.len(), 1);
        assert_eq!(receipts.delivery_ids.len(), 1);
        assert_eq!(receipts.payload_fingerprints.len(), 1);
        assert_eq!(receipts.accepted[0].delivery_id, rejected_id);
    }

    #[test]
    fn test_webhook_replay_concurrent_payload_aliases_are_admitted_once() {
        let connector = Arc::new(LinearConnector::new());
        let barrier = Arc::new(std::sync::Barrier::new(12));
        let timestamp = Utc::now().timestamp_millis();
        let fingerprint = webhook_payload_fingerprint(&json!({
            "webhookTimestamp": timestamp,
            "data": { "id": "issue-1" }
        }))
        .unwrap();
        let workers: Vec<_> = (0..12)
            .map(|_| {
                let connector = Arc::clone(&connector);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    connector.record_webhook_delivery(Uuid::new_v4(), fingerprint, timestamp)
                })
            })
            .collect();
        let mut accepted = 0;
        for worker in workers {
            match worker.join().unwrap() {
                Ok(()) => accepted += 1,
                Err(FcpError::InvalidRequest { message, .. }) => {
                    assert!(message.contains("already been processed"));
                }
                Err(error) => panic!("unexpected admission error: {error:?}"),
            }
        }
        assert_eq!(accepted, 1);
        let receipts = connector.webhook_replay_receipts.lock().unwrap();
        assert_eq!(receipts.accepted.len(), 1);
        assert_eq!(receipts.delivery_ids.len(), 1);
        assert_eq!(receipts.payload_fingerprints.len(), 1);
    }

    #[test]
    fn test_webhook_replay_concurrent_admission_cannot_exceed_capacity() {
        let connector = Arc::new(LinearConnector::new());
        let timestamp = Utc::now().timestamp_millis();
        for index in 0..MAX_LINEAR_WEBHOOK_REPLAY_RECEIPTS - 1 {
            connector
                .record_webhook_delivery(
                    Uuid::from_u128(u128::try_from(index).unwrap()),
                    Sha256::digest(index.to_le_bytes()).into(),
                    timestamp,
                )
                .unwrap();
        }
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let workers: Vec<_> = (0..8)
            .map(|index| {
                let connector = Arc::clone(&connector);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    connector.record_webhook_delivery(Uuid::new_v4(), [index; 32], timestamp)
                })
            })
            .collect();
        let mut accepted = 0;
        for worker in workers {
            match worker.join().unwrap() {
                Ok(()) => accepted += 1,
                Err(FcpError::ResourceExhausted { .. }) => {}
                Err(error) => panic!("unexpected admission error: {error:?}"),
            }
        }
        assert_eq!(accepted, 1);
        let receipts = connector.webhook_replay_receipts.lock().unwrap();
        assert_eq!(receipts.accepted.len(), MAX_LINEAR_WEBHOOK_REPLAY_RECEIPTS);
        assert_eq!(
            receipts.delivery_ids.len(),
            MAX_LINEAR_WEBHOOK_REPLAY_RECEIPTS
        );
        assert_eq!(
            receipts.payload_fingerprints.len(),
            MAX_LINEAR_WEBHOOK_REPLAY_RECEIPTS
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_process_webhook_requires_verified_signature() {
        let mut connector = LinearConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["linear.process_webhook"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(
            &signing_key,
            "linear.process_webhook",
            connector.instance_id(),
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "linear.process_webhook",
                "input": {
                    "delivery_id": Uuid::new_v4().to_string(),
                    "signature_validated": false,
                    "payload": {
                        "action": "create",
                        "type": "Issue",
                        "createdAt": "2026-03-07T00:00:00Z",
                        "webhookTimestamp": Utc::now().timestamp_millis(),
                        "data": { "id": "issue-1" }
                    }
                },
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("signature_validated"));
            }
            other => panic!("Expected InvalidRequest, got: {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_process_webhook_rejects_stale_timestamp() {
        let mut connector = LinearConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["linear.process_webhook"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(
            &signing_key,
            "linear.process_webhook",
            connector.instance_id(),
        );
        let result = connector
            .handle_invoke(json!({
                "operation": "linear.process_webhook",
                "input": {
                    "delivery_id": Uuid::new_v4().to_string(),
                    "signature_validated": true,
                    "payload": {
                        "action": "create",
                        "type": "Issue",
                        "createdAt": "2026-03-07T00:00:00Z",
                        "webhookTimestamp": Utc::now().timestamp_millis() - 120_000,
                        "data": { "id": "issue-1" }
                    }
                },
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("replay window"));
            }
            other => panic!("Expected InvalidRequest, got: {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_process_webhook_rejects_duplicate_delivery_id() {
        let mut connector = LinearConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["linear.process_webhook"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(
            &signing_key,
            "linear.process_webhook",
            connector.instance_id(),
        );
        let delivery_id = Uuid::new_v4().to_string();
        let input = json!({
            "delivery_id": delivery_id,
            "signature_validated": true,
            "payload": {
                "action": "create",
                "type": "Issue",
                "createdAt": "2026-03-07T00:00:00Z",
                "webhookTimestamp": Utc::now().timestamp_millis(),
                "data": { "id": "issue-1" }
            }
        });

        let first = connector
            .handle_invoke(json!({
                "operation": "linear.process_webhook",
                "input": input.clone(),
                "capability_token": token.clone()
            }))
            .await
            .expect("first delivery should succeed");
        assert_eq!(first["event"]["resource_id"], "issue-1");

        let second = connector
            .handle_invoke(json!({
                "operation": "linear.process_webhook",
                "input": input,
                "capability_token": token
            }))
            .await;

        assert!(second.is_err());
        match second.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("already been processed"));
            }
            other => panic!("Expected InvalidRequest, got: {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_process_webhook_rejects_payload_alias_and_timestamp_reordering() {
        let mut connector = LinearConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": signing_key.verifying_key().to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["linear.process_webhook"]
            }))
            .await
            .unwrap();
        let token = generate_valid_token(
            &signing_key,
            "linear.process_webhook",
            connector.instance_id(),
        );
        let now = Utc::now().timestamp_millis();
        let original = json!({
            "delivery_id": Uuid::new_v4().to_string(),
            "signature_validated": true,
            "payload": {
                "action": "update",
                "type": "Issue",
                "createdAt": "2026-03-07T00:00:00Z",
                "webhookTimestamp": now - 45_000,
                "webhookId": "hook-shared-across-updates",
                "data": { "id": "issue-1", "title": "first update" }
            }
        });
        connector
            .handle_invoke(json!({
                "operation": "linear.process_webhook",
                "input": original.clone(),
                "capability_token": token.clone()
            }))
            .await
            .unwrap();

        let mut future_delivery = original.clone();
        future_delivery["delivery_id"] = json!(Uuid::new_v4().to_string());
        future_delivery["payload"]["webhookTimestamp"] = json!(now + 45_000);
        future_delivery["payload"]["data"]["title"] = json!("second update");
        let second = connector
            .handle_invoke(json!({
                "operation": "linear.process_webhook",
                "input": future_delivery,
                "capability_token": token.clone()
            }))
            .await
            .unwrap();
        assert_eq!(second["event"]["data"]["title"], "second update");
        assert_eq!(second["event"]["webhook_id"], "hook-shared-across-updates");

        let mut alias = original.clone();
        alias["delivery_id"] = json!(Uuid::new_v4().to_string());
        for replay in [original, alias.clone()] {
            let error = connector
                .handle_invoke(json!({
                    "operation": "linear.process_webhook",
                    "input": replay,
                    "capability_token": token.clone()
                }))
                .await
                .unwrap_err();
            assert!(matches!(
                error,
                FcpError::InvalidRequest { ref message, .. }
                    if message.contains("already been processed")
            ));
        }

        // A refused alias does not reserve its public delivery ID. A distinct
        // authenticated payload with the same webhookId remains admissible.
        alias["payload"]["data"]["title"] = json!("third update");
        let third = connector
            .handle_invoke(json!({
                "operation": "linear.process_webhook",
                "input": alias,
                "capability_token": token
            }))
            .await
            .unwrap();
        assert_eq!(third["event"]["data"]["title"], "third update");
        assert_eq!(third["event"]["webhook_id"], "hook-shared-across-updates");
        assert_eq!(
            connector
                .webhook_replay_receipts
                .lock()
                .unwrap()
                .accepted
                .len(),
            3
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_process_webhook_rejects_disallowed_resource_scope() {
        let mut connector = LinearConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["linear.process_webhook"]
            }))
            .await
            .unwrap();

        let token = generate_token_with_constraints(
            &signing_key,
            "linear.process_webhook",
            connector.instance_id(),
            &CapabilityConstraints {
                resource_allow: vec!["linear://issue/issue-allowed".into()],
                ..Default::default()
            },
        );

        let result = connector
            .handle_invoke(json!({
                "operation": "linear.process_webhook",
                "input": {
                    "delivery_id": Uuid::new_v4().to_string(),
                    "signature_validated": true,
                    "payload": {
                        "action": "create",
                        "type": "Issue",
                        "createdAt": "2026-03-07T00:00:00Z",
                        "webhookTimestamp": Utc::now().timestamp_millis(),
                        "data": { "id": "issue-1" }
                    }
                },
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::ResourceNotAllowed { resource } => {
                assert_eq!(resource, "linear://issue/issue-1");
            }
            other => panic!("Expected ResourceNotAllowed, got: {other:?}"),
        }
    }

    fn manifest_from_file() -> ConnectorManifest {
        let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("manifest.toml");
        let raw = std::fs::read_to_string(&manifest_path).expect("read manifest");
        ConnectorManifest::parse_str(&raw).expect("manifest should validate")
    }

    fn assert_linear_api_network_constraints(id: &str, operation: &OperationSection) {
        let constraints = operation
            .network_constraints
            .as_ref()
            .unwrap_or_else(|| panic!("{id} should declare network_constraints"));
        assert_eq!(
            constraints.host_allow,
            ["api.linear.app"],
            "{id} should only allow the Linear GraphQL API host"
        );
        assert_eq!(constraints.port_allow, [443], "{id}");
        assert!(constraints.require_sni, "{id} should require SNI");
        assert!(constraints.deny_localhost, "{id} should deny localhost");
        assert!(
            constraints.deny_private_ranges,
            "{id} should deny private ranges"
        );
        assert!(
            constraints.deny_tailnet_ranges,
            "{id} should deny tailnet ranges"
        );
        assert!(constraints.deny_ip_literals, "{id} should deny IP literals");
        assert!(
            constraints.require_host_canonicalization,
            "{id} should require canonical host matching"
        );
        assert_eq!(constraints.dns_max_ips, 16, "{id}");
        assert_eq!(constraints.max_redirects, 0, "{id}");
    }

    fn assert_no_connector_egress_network_constraints(id: &str, operation: &OperationSection) {
        let constraints = operation
            .network_constraints
            .as_ref()
            .unwrap_or_else(|| panic!("{id} should declare network_constraints"));
        assert_eq!(
            constraints.host_allow,
            ["none.invalid"],
            "{id} should advertise no connector-owned egress"
        );
        assert_eq!(constraints.port_allow, [0], "{id}");
        assert!(
            !constraints.require_sni,
            "{id} should not require SNI for a no-egress sentinel"
        );
        assert!(constraints.deny_localhost, "{id} should deny localhost");
        assert!(
            constraints.deny_private_ranges,
            "{id} should deny private ranges"
        );
        assert!(
            constraints.deny_tailnet_ranges,
            "{id} should deny tailnet ranges"
        );
        assert!(constraints.deny_ip_literals, "{id} should deny IP literals");
        assert_eq!(constraints.dns_max_ips, 0, "{id}");
        assert_eq!(constraints.max_redirects, 0, "{id}");
        assert_eq!(constraints.max_response_bytes, 65_536, "{id}");
    }

    #[test]
    fn manifest_declares_per_operation_network_constraints() {
        let manifest = manifest_from_file();

        for operation_id in [
            "linear.create_issue",
            "linear.get_issue",
            "linear.update_issue",
            "linear.search_issues",
            "linear.list_teams",
            "linear.list_cycles",
            "linear.add_comment",
            "linear.list_projects",
        ] {
            let operation = manifest
                .provides
                .operations
                .get(operation_id)
                .expect("operation should exist");
            assert_linear_api_network_constraints(operation_id, operation);
        }

        for operation_id in ["linear.plan_sync", "linear.process_webhook"] {
            let operation = manifest
                .provides
                .operations
                .get(operation_id)
                .expect("operation should exist");
            assert_no_connector_egress_network_constraints(operation_id, operation);
        }
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
            .expect("compute interface hash");
        assert_eq!(manifest.manifest.interface_hash, computed);

        let manifest2 = ConnectorManifest::parse_str_unchecked(&raw).expect("parse unchecked");
        let computed2 = manifest2
            .compute_interface_hash()
            .expect("compute interface hash");
        assert_eq!(computed, computed2);
    }

    #[test]
    fn handshake_manifest_hash_tracks_bundled_manifest() {
        let mut expected = Sha256::new();
        expected.update(MANIFEST_TOML.as_bytes());
        let expected = format!("sha256:{}", hex::encode(expected.finalize()));

        assert_eq!(LinearConnector::manifest_hash(), expected);
        assert_ne!(
            LinearConnector::manifest_hash(),
            "sha256:linear-connector-v1"
        );
    }

    // ── Sync unit tests: config, helpers ──────────────────────────

    #[test]
    fn config_from_api_key() {
        let cfg = LinearConfig::from_params(&json!({ "api_key": "lin_api_test" })).unwrap();
        assert!(!cfg.auth.is_secretless());
        assert_eq!(cfg.api_url, DEFAULT_API_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let cfg = LinearConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000"
        }))
        .unwrap();
        assert!(cfg.auth.is_secretless());
    }

    #[test]
    fn config_custom_api_url() {
        let result = LinearConfig::from_params(&json!({
            "api_key": "test",
            "api_url": "https://linear.example.com/graphql"
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_credential_id_allows_custom_api_url() {
        let cfg = LinearConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "api_url": "https://linear-proxy.internal/graphql"
        }))
        .unwrap();
        assert_eq!(cfg.api_url, "https://linear-proxy.internal/graphql");
    }

    #[test]
    fn config_trims_api_key() {
        let cfg = LinearConfig::from_params(&json!({ "api_key": "  lin_api_test  " })).unwrap();
        match &cfg.auth {
            LinearAuth::ApiKey(k) => assert_eq!(k, "lin_api_test"),
            LinearAuth::CredentialId(_) => panic!("expected ApiKey"),
        }
    }

    #[test]
    fn config_rejects_empty_api_key() {
        assert!(LinearConfig::from_params(&json!({ "api_key": "" })).is_err());
    }

    #[test]
    fn config_rejects_whitespace_api_key() {
        assert!(LinearConfig::from_params(&json!({ "api_key": "   " })).is_err());
    }

    #[test]
    fn config_rejects_both_auth() {
        let result = LinearConfig::from_params(&json!({
            "api_key": "test",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000"
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        assert!(LinearConfig::from_params(&json!({})).is_err());
    }

    #[test]
    fn config_rejects_invalid_credential_id() {
        assert!(LinearConfig::from_params(&json!({ "credential_id": "bad" })).is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        assert!(LinearConfig::from_params(&json!({ "credential_id": 12345 })).is_err());
    }

    #[test]
    fn require_str_extracts_value() {
        let input = json!({"issue_id": "LIN-1"});
        assert_eq!(require_str(&input, "issue_id").unwrap(), "LIN-1");
    }

    #[test]
    fn require_str_missing() {
        assert!(require_str(&json!({}), "x").is_err());
    }

    #[test]
    fn require_str_non_string() {
        assert!(require_str(&json!({"x": 42}), "x").is_err());
    }

    #[test]
    fn require_str_null() {
        assert!(require_str(&json!({"x": null}), "x").is_err());
    }

    #[test]
    fn connector_default() {
        let c = LinearConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }
}
