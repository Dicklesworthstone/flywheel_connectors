//! FCP Cron Connector implementation.
//!
//! A local meta-connector that manages cron schedules and execution history
//! in memory. No external API calls are needed.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use fcp_prelude::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier, ConnectorId,
    ConnectorMetrics, EventCaps, FcpConnector, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, HealthSnapshot, IdempotencyClass, Introspection, InvokeRequest,
    InvokeResponse, OperationId, OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId,
    ShutdownRequest, SimulateRequest, SimulateResponse, SubscribeRequest, SubscribeResponse,
    UnsubscribeRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::{info, instrument};
use uuid::Uuid;

use crate::error::CronError;
use crate::types::{Execution, Schedule, validate_cron_expression};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

/// Default maximum number of executions returned.
const DEFAULT_EXECUTION_LIMIT: u64 = 50;
/// Maximum number of executions returned.
const MAX_EXECUTION_LIMIT: u64 = 100;
/// Upper bound for configured schedule capacity.
const MAX_CONFIGURED_SCHEDULES: usize = 100_000;
/// Upper bound for configured execution history capacity.
const MAX_CONFIGURED_EXECUTIONS: usize = 1_000_000;
/// Maximum accepted clock skew tolerance (seconds).
const MAX_CLOCK_SKEW_SECONDS: u32 = 300;

/// Doctor check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorResult {
    status: DoctorStatus,
    checks: Vec<DoctorCheck>,
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

/// Cron state store backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StateStoreBackend {
    Memory,
}

impl StateStoreBackend {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Memory => "memory",
        }
    }
}

/// State storage policy configured at provisioning time.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct StateStorePolicy {
    backend: StateStoreBackend,
    max_schedules: usize,
    max_executions: usize,
    persist_to_disk: bool,
}

impl Default for StateStorePolicy {
    fn default() -> Self {
        Self {
            backend: StateStoreBackend::Memory,
            max_schedules: 10_000,
            max_executions: 100_000,
            persist_to_disk: false,
        }
    }
}

/// Clock source for cron scheduling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ClockSource {
    SystemUtc,
}

impl ClockSource {
    const fn as_str(self) -> &'static str {
        match self {
            Self::SystemUtc => "system_utc",
        }
    }
}

/// Clock policy configured at provisioning time.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ClockPolicy {
    source: ClockSource,
    timezone: String,
    max_clock_skew_seconds: u32,
}

impl Default for ClockPolicy {
    fn default() -> Self {
        Self {
            source: ClockSource::SystemUtc,
            timezone: "UTC".to_string(),
            max_clock_skew_seconds: 30,
        }
    }
}

/// Typed provisioning policy for deterministic cron setup.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct ProvisioningPolicy {
    state_store: StateStorePolicy,
    clock: ClockPolicy,
}

impl ProvisioningPolicy {
    fn normalize(mut self) -> Self {
        self.clock.timezone = self.clock.timezone.trim().to_ascii_uppercase();
        self
    }

    fn validate(&self) -> FcpResult<()> {
        if self.state_store.persist_to_disk {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "persist_to_disk must be false for fcp.cron (in-memory only)".into(),
            });
        }

        if self.state_store.max_schedules == 0
            || self.state_store.max_schedules > MAX_CONFIGURED_SCHEDULES
        {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "state_store.max_schedules must be in 1..={MAX_CONFIGURED_SCHEDULES}"
                ),
            });
        }

        if self.state_store.max_executions == 0
            || self.state_store.max_executions > MAX_CONFIGURED_EXECUTIONS
        {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "state_store.max_executions must be in 1..={MAX_CONFIGURED_EXECUTIONS}"
                ),
            });
        }

        if self.clock.source != ClockSource::SystemUtc {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "clock.source must be system_utc".into(),
            });
        }

        if self.clock.timezone != "UTC" {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "clock.timezone must be UTC".into(),
            });
        }

        if self.clock.max_clock_skew_seconds > MAX_CLOCK_SKEW_SECONDS {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "clock.max_clock_skew_seconds must be <= {MAX_CLOCK_SKEW_SECONDS}"
                ),
            });
        }

        Ok(())
    }
}

/// FCP Cron Connector.
///
/// Manages cron schedules and execution history entirely in memory.
pub struct CronConnector {
    base: Arc<BaseConnector>,
    configured: bool,
    session_id: Option<String>,
    verifier: Option<CapabilityVerifier>,
    started_at: Instant,
    provisioning: ProvisioningPolicy,
    schedules: Vec<Schedule>,
    executions: VecDeque<Execution>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl CronConnector {
    /// Create a new Cron connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("cron"))),
            configured: false,
            session_id: None,
            verifier: None,
            started_at: Instant::now(),
            provisioning: ProvisioningPolicy::default(),
            schedules: Vec::new(),
            executions: VecDeque::new(),
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for CronConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl CronConnector {
    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        let digest = hasher.finalize();
        format!("sha256:{digest:x}")
    }

    /// Handle the `configure` method.
    ///
    /// The cron connector requires no external credentials. Configuration
    /// validates local state-store and clock policy, then marks the connector as ready.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let provisioning: ProvisioningPolicy =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid configure params: {e}"),
            })?;
        let provisioning = provisioning.normalize();
        provisioning.validate()?;
        if self.schedules.len() > provisioning.state_store.max_schedules {
            return Err(FcpError::Conflict {
                message: format!(
                    "Cannot lower max_schedules below the {} existing schedules",
                    self.schedules.len()
                ),
            });
        }

        info!("Configuring Cron connector (local meta-connector, no external auth)");
        let expired = self
            .executions
            .len()
            .saturating_sub(provisioning.state_store.max_executions);
        self.executions.drain(..expired);
        self.provisioning = provisioning;
        self.configured = true;
        self.base.set_configured(true);
        Ok(json!({
            "status": "configured",
            "state_store": {
                "backend": self.provisioning.state_store.backend.as_str(),
                "max_schedules": self.provisioning.state_store.max_schedules,
                "max_executions": self.provisioning.state_store.max_executions,
                "persist_to_disk": self.provisioning.state_store.persist_to_disk,
            },
            "clock": {
                "source": self.provisioning.clock.source.as_str(),
                "timezone": self.provisioning.clock.timezone.as_str(),
                "max_clock_skew_seconds": self.provisioning.clock.max_clock_skew_seconds,
            }
        }))
    }

    /// Handle the `handshake` method.
    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        if !self.configured {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: "Connector not configured".into(),
            });
        }

        let request: HandshakeRequest =
            serde_json::from_value(params).map_err(|error| FcpError::InvalidRequest {
                code: 1004,
                message: format!("Invalid handshake params: {error}"),
            })?;

        let response = HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted: request
                .capabilities_requested
                .into_iter()
                .map(|capability| CapabilityGrant {
                    capability,
                    operation: None,
                })
                .collect(),
            session_id: SessionId::new(),
            manifest_hash: Self::manifest_hash(),
            nonce: request.nonce,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        };

        self.session_id = Some(response.session_id.to_string());
        self.base.set_handshaken(true);

        serde_json::to_value(response).map_err(|error| FcpError::Internal {
            message: format!("failed to serialize handshake response: {error}"),
        })
    }

    /// Handle the `health` method.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let handshaken = self.session_id.is_some();

        let mut snapshot = if !self.configured {
            HealthSnapshot::degraded("not configured")
        } else if !handshaken {
            HealthSnapshot::degraded("handshake not completed")
        } else {
            HealthSnapshot::ready()
        };
        snapshot.uptime_ms =
            u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        snapshot.details = Some(json!({
            "configured": self.configured,
            "handshaken": handshaken,
            "session_id": self.session_id.as_deref(),
            "schedules": self.schedules.len(),
            "executions": self.executions.len(),
            "requests": self.request_count.load(Ordering::Relaxed),
            "errors": self.error_count.load(Ordering::Relaxed),
            "manifest_hash": Self::manifest_hash(),
            "state_store": {
                "backend": self.provisioning.state_store.backend.as_str(),
                "max_schedules": self.provisioning.state_store.max_schedules,
                "max_executions": self.provisioning.state_store.max_executions,
                "persist_to_disk": self.provisioning.state_store.persist_to_disk,
            },
            "clock": {
                "source": self.provisioning.clock.source.as_str(),
                "timezone": self.provisioning.clock.timezone.as_str(),
                "max_clock_skew_seconds": self.provisioning.clock.max_clock_skew_seconds,
            }
        }));

        serde_json::to_value(snapshot).map_err(|error| FcpError::Internal {
            message: format!("failed to serialize health snapshot: {error}"),
        })
    }

    /// Handle the `doctor` method.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();

        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.configured,
            message: if self.configured {
                None
            } else {
                Some("Not configured - call configure first".into())
            },
            critical: true,
        });

        let handshaken = self.session_id.is_some();
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

        let state_store_ok = self.configured
            && self.provisioning.state_store.backend == StateStoreBackend::Memory
            && !self.provisioning.state_store.persist_to_disk;
        checks.push(DoctorCheck {
            name: "state_store".into(),
            passed: state_store_ok,
            message: if self.configured {
                Some(format!(
                    "backend={}, max_schedules={}, max_executions={}, persist_to_disk={}, current=({} schedules, {} executions)",
                    self.provisioning.state_store.backend.as_str(),
                    self.provisioning.state_store.max_schedules,
                    self.provisioning.state_store.max_executions,
                    self.provisioning.state_store.persist_to_disk,
                    self.schedules.len(),
                    self.executions.len()
                ))
            } else {
                Some("State store policy unavailable until configured".into())
            },
            critical: true,
        });

        let clock_policy_ok = self.configured
            && self.provisioning.clock.source == ClockSource::SystemUtc
            && self.provisioning.clock.timezone == "UTC"
            && self.provisioning.clock.max_clock_skew_seconds <= MAX_CLOCK_SKEW_SECONDS;
        checks.push(DoctorCheck {
            name: "clock_policy".into(),
            passed: clock_policy_ok,
            message: if self.configured {
                Some(format!(
                    "source={}, timezone={}, max_clock_skew_seconds={}",
                    self.provisioning.clock.source.as_str(),
                    self.provisioning.clock.timezone,
                    self.provisioning.clock.max_clock_skew_seconds
                ))
            } else {
                Some("Clock policy unavailable until configured".into())
            },
            critical: true,
        });

        let result = DoctorResult::from_checks(checks);
        Ok(serde_json::to_value(result).unwrap_or(json!({"status": "error"})))
    }

    /// Handle the `self_check` method.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.cron",
            "version": "0.1.0",
            "status": if self.configured { "ok" } else { "degraded" },
        }))
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let ops = serde_json::to_value(operations_info()).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize operations: {e}"),
        })?;
        Ok(json!({
            "connector_id": "fcp.cron",
            "version": "0.1.0",
            "operations": ops,
        }))
    }

    /// Handle the `invoke` method.
    #[instrument(skip(self, params))]
    pub async fn handle_invoke(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        self.base.check_ready()?;

        let operation = params
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation_id".into(),
            })?;

        let input = params.get("input").cloned().unwrap_or(json!({}));

        self.request_count.fetch_add(1, Ordering::Relaxed);

        let result = match operation {
            "cron.schedules.list" => self.invoke_schedules_list(),
            "cron.schedules.create" => self.invoke_schedules_create(&input),
            "cron.schedules.delete" => self.invoke_schedules_delete(&input),
            "cron.trigger" => self.invoke_trigger(&input),
            "cron.executions.list" => self.invoke_executions_list(&input),
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

        let allowed = operations_info().iter().any(|o| o.id.as_ref() == operation);

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
        info!("Cron connector shutting down");
        self.configured = false;
        self.session_id = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    #[allow(clippy::unnecessary_wraps)]
    fn invoke_schedules_list(&self) -> Result<serde_json::Value, CronError> {
        let schedules: Vec<serde_json::Value> = self
            .schedules
            .iter()
            .map(|s| serde_json::to_value(s).unwrap_or(serde_json::Value::Null))
            .collect();
        Ok(json!({ "schedules": schedules }))
    }

    fn invoke_schedules_create(
        &mut self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, CronError> {
        let name = input
            .get("name")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| CronError::Internal {
                message: "Missing required field: name".into(),
            })?;

        let expression = input
            .get("expression")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| CronError::Internal {
                message: "Missing required field: expression".into(),
            })?;

        let target_operation = input
            .get("target_operation")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| CronError::Internal {
                message: "Missing required field: target_operation".into(),
            })?;

        // Validate cron expression
        if !validate_cron_expression(expression) {
            return Err(CronError::InvalidExpression {
                expression: expression.into(),
            });
        }

        // Check for duplicate names
        if self.schedules.iter().any(|s| s.name == name) {
            return Err(CronError::DuplicateName { name: name.into() });
        }
        if self.schedules.len() >= self.provisioning.state_store.max_schedules {
            return Err(CronError::ScheduleCapacity {
                limit: self.provisioning.state_store.max_schedules,
            });
        }

        let enabled = input
            .get("enabled")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true);

        let payload = input.get("payload").cloned();

        let schedule_id = format!("sched_{}", Uuid::new_v4());
        let now = Utc::now().to_rfc3339();

        let schedule = Schedule {
            id: schedule_id.clone(),
            name: name.into(),
            expression: expression.into(),
            target_operation: target_operation.into(),
            payload,
            enabled,
            created_at: now,
        };

        self.schedules.push(schedule);

        Ok(json!({ "schedule_id": schedule_id }))
    }

    fn invoke_schedules_delete(
        &mut self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, CronError> {
        let schedule_id = input
            .get("schedule_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| CronError::Internal {
                message: "Missing required field: schedule_id".into(),
            })?;

        let idx = self
            .schedules
            .iter()
            .position(|s| s.id == schedule_id)
            .ok_or_else(|| CronError::ScheduleNotFound {
                schedule_id: schedule_id.into(),
            })?;

        self.schedules.remove(idx);

        Ok(json!({}))
    }

    fn invoke_trigger(
        &mut self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, CronError> {
        let schedule_id = input
            .get("schedule_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| CronError::Internal {
                message: "Missing required field: schedule_id".into(),
            })?;

        // Verify schedule exists
        if !self.schedules.iter().any(|s| s.id == schedule_id) {
            return Err(CronError::ScheduleNotFound {
                schedule_id: schedule_id.into(),
            });
        }

        let execution_id = format!("exec_{}", Uuid::new_v4());
        let now = Utc::now().to_rfc3339();

        let execution = Execution {
            id: execution_id.clone(),
            schedule_id: schedule_id.into(),
            triggered_at: now,
            status: "triggered".into(),
        };

        if self.executions.len() == self.provisioning.state_store.max_executions {
            self.executions.pop_front();
        }
        self.executions.push_back(execution);

        Ok(json!({ "execution_id": execution_id }))
    }

    #[allow(clippy::unnecessary_wraps)]
    fn invoke_executions_list(
        &self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, CronError> {
        let schedule_id_filter = input.get("schedule_id").and_then(serde_json::Value::as_str);

        let limit = input
            .get("limit")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(DEFAULT_EXECUTION_LIMIT)
            .min(MAX_EXECUTION_LIMIT);

        let executions: Vec<serde_json::Value> = self
            .executions
            .iter()
            .filter(|e| schedule_id_filter.is_none_or(|filter| e.schedule_id == filter))
            .rev() // most recent first
            .take(limit as usize)
            .map(|e| serde_json::to_value(e).unwrap_or(serde_json::Value::Null))
            .collect();

        Ok(json!({ "executions": executions }))
    }

    // -- Accessors for testing --

    /// Get the number of schedules.
    #[must_use]
    pub fn schedule_count(&self) -> usize {
        self.schedules.len()
    }

    /// Get the number of executions.
    #[must_use]
    pub fn execution_count(&self) -> usize {
        self.executions.len()
    }
}

/// Build a single [`OperationInfo`].
#[allow(clippy::fn_params_excessive_bools, clippy::too_many_arguments)]
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

/// Build the operations info for introspection.
fn operations_info() -> Vec<OperationInfo> {
    vec![
        op_info(
            "cron.schedules.list",
            "List configured cron schedules",
            json!({"type": "object", "required": [], "properties": {}}),
            json!({"type": "object", "required": ["schedules"], "properties": {"schedules": {"type": "array"}}}),
            "cron.schedules.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List all configured cron schedules.".into(),
                common_mistakes: vec![
                    "Assuming the list includes disabled schedules by default — all schedules are returned regardless of enabled state.".into(),
                ],
                examples: vec!["{}".into()],
                related: vec![
                    CapabilityId::from_static("cron.schedules.create"),
                    CapabilityId::from_static("cron.schedules.delete"),
                ],
            },
        ),
        op_info(
            "cron.schedules.create",
            "Create a new cron schedule",
            json!({
                "type": "object",
                "required": ["name", "expression", "target_operation"],
                "properties": {
                    "name": {"type": "string", "description": "Human-readable name for the schedule"},
                    "expression": {"type": "string", "description": "Cron expression (e.g. '*/5 * * * *' for every 5 minutes)"},
                    "target_operation": {"type": "string", "description": "FCP operation ID to invoke on trigger"},
                    "payload": {"type": "object", "description": "Static payload to pass to the target operation"},
                    "enabled": {"type": "boolean"}
                }
            }),
            json!({"type": "object", "required": ["schedule_id"], "properties": {"schedule_id": {"type": "string"}}}),
            "cron.schedules.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Create a new timed schedule to invoke an operation periodically."
                    .into(),
                common_mistakes: vec![
                    "Using invalid cron expressions.".into(),
                    "Forgetting to specify target_operation.".into(),
                ],
                examples: vec![
                    r#"{"name": "hourly-sync", "expression": "0 * * * *", "target_operation": "slack.channels.list"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("cron.schedules.list"),
                    CapabilityId::from_static("cron.schedules.delete"),
                ],
            },
        ),
        op_info(
            "cron.schedules.delete",
            "Delete a cron schedule",
            json!({"type": "object", "required": ["schedule_id"], "properties": {"schedule_id": {"type": "string"}}}),
            json!({"type": "object", "properties": {}}),
            "cron.schedules.write",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Remove a cron schedule. The operation will no longer be triggered."
                    .into(),
                common_mistakes: vec![
                    "Deleting a schedule without first checking its recent execution history for in-flight jobs.".into(),
                    "Using schedule name instead of schedule_id.".into(),
                ],
                examples: vec![
                    r#"{"schedule_id": "sched_abc123"}"#.into(),
                ],
                related: vec![CapabilityId::from_static("cron.schedules.list")],
            },
        ),
        op_info(
            "cron.trigger",
            "Manually trigger a schedule immediately",
            json!({"type": "object", "required": ["schedule_id"], "properties": {"schedule_id": {"type": "string"}}}),
            json!({"type": "object", "required": ["execution_id"], "properties": {"execution_id": {"type": "string"}}}),
            "cron.schedules.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Manually trigger a schedule outside its normal cron timing.".into(),
                common_mistakes: vec![
                    "Triggering a disabled schedule without re-enabling it first.".into(),
                    "Calling trigger repeatedly without waiting for the previous execution to complete.".into(),
                ],
                examples: vec![
                    r#"{"schedule_id": "sched_abc123"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("cron.schedules.list"),
                    CapabilityId::from_static("cron.executions.list"),
                ],
            },
        ),
        op_info(
            "cron.executions.list",
            "List recent execution history for a schedule",
            json!({
                "type": "object",
                "required": [],
                "properties": {
                    "schedule_id": {"type": "string"},
                    "limit": {"type": "integer", "maximum": 100}
                }
            }),
            json!({"type": "object", "required": ["executions"], "properties": {"executions": {"type": "array"}}}),
            "cron.executions.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "View execution history for a cron schedule.".into(),
                common_mistakes: vec![
                    "Omitting schedule_id and expecting executions across all schedules.".into(),
                    "Not accounting for timezone differences when interpreting execution timestamps.".into(),
                ],
                examples: vec![
                    r#"{"schedule_id": "sched_abc123", "limit": 20}"#.into(),
                ],
                related: vec![CapabilityId::from_static("cron.schedules.list")],
            },
        ),
    ]
}

// ── FcpConnector trait implementation (FCP3 execution model) ─────────────

fcp_core::impl_fcp_sealed!(CronConnector);

#[async_trait]
impl FcpConnector for CronConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        self.handle_configure(config).await?;
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        if !self.configured {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: "Connector not configured".into(),
            });
        }

        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let response = HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted: req
                .capabilities_requested
                .into_iter()
                .map(|capability| CapabilityGrant {
                    capability,
                    operation: None,
                })
                .collect(),
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
        };

        self.session_id = Some(response.session_id.to_string());
        self.base.set_handshaken(true);
        Ok(response)
    }

    async fn health(&self) -> HealthSnapshot {
        let handshaken = self.session_id.is_some();

        if !self.configured {
            HealthSnapshot::degraded("not configured")
        } else if !handshaken {
            HealthSnapshot::degraded("not handshaken")
        } else {
            HealthSnapshot::ready()
        }
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        if self.configured {
            Ok(SelfCheckReport::ok())
        } else {
            Ok(SelfCheckReport::degraded(
                "not_configured",
                "Connector not configured",
            ))
        }
    }

    fn metrics(&self) -> ConnectorMetrics {
        ConnectorMetrics {
            requests_total: self.request_count.load(Ordering::Relaxed),
            requests_error: self.error_count.load(Ordering::Relaxed),
            ..ConnectorMetrics::default()
        }
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        info!("Cron connector shutting down (FcpConnector trait)");
        self.configured = false;
        self.session_id = None;
        self.verifier = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: operations_info(),
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;

        let operation = req.operation.as_ref();
        let input = req.input.clone();

        self.request_count.fetch_add(1, Ordering::Relaxed);

        // SAFETY: invoke takes &self but we need &mut for schedule/execution
        // mutation. The cron connector is single-threaded (stdio loop), so
        // interior mutability would be the proper fix. For now, delegate to
        // the handle_invoke path which has &mut self.
        let result_value = match operation {
            "cron.schedules.list" => self.invoke_schedules_list_readonly(),
            "cron.executions.list" => self.invoke_executions_list_readonly(&input),
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1002,
                    message: format!(
                        "Operation {operation} requires mutable access; use handle_invoke"
                    ),
                });
            }
        };

        match result_value {
            Ok(data) => Ok(InvokeResponse::ok(req.id, data)),
            Err(e) => {
                self.error_count.fetch_add(1, Ordering::Relaxed);
                Err(e.to_fcp_error())
            }
        }
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        let operation = req.operation.as_ref();
        let allowed = operations_info().iter().any(|o| o.id.as_ref() == operation);
        if allowed {
            Ok(SimulateResponse::allowed(req.id))
        } else {
            Ok(SimulateResponse::denied(
                req.id,
                format!("Unknown operation: {operation}"),
                "unknown_operation",
            ))
        }
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Err(FcpError::InvalidRequest {
            code: 1002,
            message: "Cron connector does not support event subscriptions".into(),
        })
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Err(FcpError::InvalidRequest {
            code: 1002,
            message: "Cron connector does not support event subscriptions".into(),
        })
    }
}

impl CronConnector {
    /// Read-only schedule list for trait-based invoke (&self).
    #[allow(clippy::unnecessary_wraps)]
    fn invoke_schedules_list_readonly(&self) -> Result<serde_json::Value, CronError> {
        let schedules: Vec<serde_json::Value> = self
            .schedules
            .iter()
            .map(|s| serde_json::to_value(s).unwrap_or(serde_json::Value::Null))
            .collect();
        Ok(json!({ "schedules": schedules }))
    }

    /// Read-only execution list for trait-based invoke (&self).
    #[allow(clippy::unnecessary_wraps)]
    fn invoke_executions_list_readonly(
        &self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, CronError> {
        let schedule_id = input.get("schedule_id").and_then(serde_json::Value::as_str);
        let limit = input
            .get("limit")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(DEFAULT_EXECUTION_LIMIT)
            .min(MAX_EXECUTION_LIMIT);

        let executions: Vec<&Execution> = self
            .executions
            .iter()
            .filter(|ex| schedule_id.is_none() || schedule_id == Some(ex.schedule_id.as_str()))
            .rev()
            .take(limit as usize)
            .collect();

        let values: Vec<serde_json::Value> = executions
            .iter()
            .map(|e| serde_json::to_value(e).unwrap_or(serde_json::Value::Null))
            .collect();
        Ok(json!({ "executions": values }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Constructor / Default --

    #[test]
    fn connector_new() {
        let c = CronConnector::new();
        assert!(!c.configured);
        assert!(c.session_id.is_none());
        assert!(c.schedules.is_empty());
        assert!(c.executions.is_empty());
    }

    #[test]
    fn connector_default() {
        let c = CronConnector::default();
        assert!(!c.configured);
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_default_provisioning_policy() {
        let c = CronConnector::new();
        assert_eq!(
            c.provisioning.state_store.backend,
            StateStoreBackend::Memory
        );
        assert_eq!(c.provisioning.clock.source, ClockSource::SystemUtc);
        assert_eq!(c.provisioning.clock.timezone, "UTC");
        assert!(!c.provisioning.state_store.persist_to_disk);
    }

    #[test]
    fn provisioning_policy_normalizes_timezone() {
        let policy = ProvisioningPolicy {
            state_store: StateStorePolicy::default(),
            clock: ClockPolicy {
                source: ClockSource::SystemUtc,
                timezone: " utc ".into(),
                max_clock_skew_seconds: 10,
            },
        }
        .normalize();
        assert_eq!(policy.clock.timezone, "UTC");
    }

    #[test]
    fn provisioning_policy_rejects_disk_persistence() {
        let policy = ProvisioningPolicy {
            state_store: StateStorePolicy {
                persist_to_disk: true,
                ..StateStorePolicy::default()
            },
            clock: ClockPolicy::default(),
        };
        assert!(policy.validate().is_err());
    }

    #[test]
    fn provisioning_policy_rejects_non_utc_timezone() {
        let policy = ProvisioningPolicy {
            state_store: StateStorePolicy::default(),
            clock: ClockPolicy {
                timezone: "America/New_York".into(),
                ..ClockPolicy::default()
            },
        };
        assert!(policy.validate().is_err());
    }

    // -- Operations info --

    #[test]
    fn operations_info_has_5_operations() {
        let ops = operations_info();
        assert_eq!(ops.len(), 5);
    }

    #[test]
    fn operations_all_have_required_fields() {
        let ops = operations_info();
        for op in &ops {
            assert!(!op.id.as_ref().is_empty(), "missing id");
            assert!(!op.summary.is_empty(), "missing summary");
            assert!(!op.capability.as_ref().is_empty(), "missing capability");
        }
    }

    #[test]
    fn operations_ids_are_unique() {
        let ops = operations_info();
        let ids: Vec<&str> = ops.iter().map(|o| o.id.as_ref()).collect();
        let mut unique = ids.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(ids.len(), unique.len(), "duplicate operation IDs found");
    }

    #[test]
    fn operations_risk_levels_valid() {
        let ops = operations_info();
        for op in &ops {
            let v = serde_json::to_value(op.risk_level).unwrap();
            let rl = v.as_str().unwrap();
            assert!(
                ["low", "medium", "high", "critical"].contains(&rl),
                "invalid risk_level: {rl}"
            );
        }
    }

    #[test]
    fn operations_safety_tiers_valid() {
        let ops = operations_info();
        for op in &ops {
            let v = serde_json::to_value(op.safety_tier).unwrap();
            let st = v.as_str().unwrap();
            assert!(
                ["safe", "risky", "dangerous"].contains(&st),
                "invalid safety_tier: {st}"
            );
        }
    }

    #[test]
    fn read_operations_are_safe() {
        let ops = operations_info();
        for op in &ops {
            let cap = op.capability.as_ref();
            #[allow(clippy::case_sensitive_file_extension_comparisons)]
            if cap.ends_with(".read") {
                assert_eq!(
                    op.safety_tier,
                    SafetyTier::Safe,
                    "read op {} should be safe",
                    op.id.as_ref()
                );
                assert_eq!(
                    op.risk_level,
                    RiskLevel::Low,
                    "read op {} should be low risk",
                    op.id.as_ref()
                );
            }
        }
    }

    #[test]
    fn operations_contain_expected_ids() {
        let ops = operations_info();
        let ids: Vec<&str> = ops.iter().map(|o| o.id.as_ref()).collect();
        assert!(ids.contains(&"cron.schedules.list"));
        assert!(ids.contains(&"cron.schedules.create"));
        assert!(ids.contains(&"cron.schedules.delete"));
        assert!(ids.contains(&"cron.trigger"));
        assert!(ids.contains(&"cron.executions.list"));
    }

    #[test]
    fn operations_all_have_idempotency() {
        let ops = operations_info();
        for op in &ops {
            let v = serde_json::to_value(op.idempotency).unwrap();
            assert!(
                v.is_string(),
                "op {} idempotency should serialize",
                op.id.as_ref()
            );
        }
    }

    #[test]
    fn delete_is_dangerous() {
        let ops = operations_info();
        let delete_op = ops
            .iter()
            .find(|o| o.id.as_ref() == "cron.schedules.delete")
            .unwrap();
        assert_eq!(delete_op.safety_tier, SafetyTier::Dangerous);
        assert_eq!(delete_op.risk_level, RiskLevel::High);
    }

    #[test]
    fn trigger_is_risky() {
        let ops = operations_info();
        let trigger_op = ops
            .iter()
            .find(|o| o.id.as_ref() == "cron.trigger")
            .unwrap();
        assert_eq!(trigger_op.safety_tier, SafetyTier::Risky);
        assert_eq!(trigger_op.risk_level, RiskLevel::Medium);
    }

    // -- Doctor --

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
    fn doctor_result_empty_checks() {
        let r = DoctorResult::from_checks(vec![]);
        assert_eq!(r.status, DoctorStatus::Healthy);
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

    // -- In-memory schedule operations (sync) --

    #[test]
    fn create_schedule_basic() {
        let mut c = CronConnector::new();
        c.configured = true;
        let result = c
            .invoke_schedules_create(&json!({
                "name": "hourly-sync",
                "expression": "0 * * * *",
                "target_operation": "slack.channels.list"
            }))
            .unwrap();
        assert!(
            result["schedule_id"]
                .as_str()
                .unwrap()
                .starts_with("sched_")
        );
        assert_eq!(c.schedules.len(), 1);
        assert_eq!(c.schedules[0].name, "hourly-sync");
        assert_eq!(c.schedules[0].expression, "0 * * * *");
        assert!(c.schedules[0].enabled);
    }

    #[test]
    fn create_schedule_with_payload() {
        let mut c = CronConnector::new();
        c.configured = true;
        let result = c
            .invoke_schedules_create(&json!({
                "name": "test",
                "expression": "*/5 * * * *",
                "target_operation": "op.test",
                "payload": {"channel": "general"}
            }))
            .unwrap();
        assert!(result["schedule_id"].as_str().is_some());
        assert_eq!(c.schedules[0].payload, Some(json!({"channel": "general"})));
    }

    #[test]
    fn create_schedule_disabled() {
        let mut c = CronConnector::new();
        c.configured = true;
        c.invoke_schedules_create(&json!({
            "name": "disabled-job",
            "expression": "0 0 * * *",
            "target_operation": "op.test",
            "enabled": false
        }))
        .unwrap();
        assert!(!c.schedules[0].enabled);
    }

    #[test]
    fn create_schedule_invalid_expression() {
        let mut c = CronConnector::new();
        c.configured = true;
        let err = c
            .invoke_schedules_create(&json!({
                "name": "bad",
                "expression": "not a cron expr",
                "target_operation": "op.test"
            }))
            .unwrap_err();
        assert!(matches!(err, CronError::InvalidExpression { .. }));
    }

    #[test]
    fn create_schedule_too_few_fields() {
        let mut c = CronConnector::new();
        c.configured = true;
        let err = c
            .invoke_schedules_create(&json!({
                "name": "bad",
                "expression": "* *",
                "target_operation": "op.test"
            }))
            .unwrap_err();
        assert!(matches!(err, CronError::InvalidExpression { .. }));
    }

    #[test]
    fn create_schedule_duplicate_name() {
        let mut c = CronConnector::new();
        c.configured = true;
        c.invoke_schedules_create(&json!({
            "name": "my-job",
            "expression": "0 * * * *",
            "target_operation": "op.a"
        }))
        .unwrap();
        let err = c
            .invoke_schedules_create(&json!({
                "name": "my-job",
                "expression": "0 0 * * *",
                "target_operation": "op.b"
            }))
            .unwrap_err();
        assert!(matches!(err, CronError::DuplicateName { .. }));
    }

    #[test]
    fn create_schedule_missing_name() {
        let mut c = CronConnector::new();
        c.configured = true;
        let err = c
            .invoke_schedules_create(&json!({
                "expression": "0 * * * *",
                "target_operation": "op.test"
            }))
            .unwrap_err();
        assert!(matches!(err, CronError::Internal { .. }));
    }

    #[test]
    fn create_schedule_missing_expression() {
        let mut c = CronConnector::new();
        c.configured = true;
        let err = c
            .invoke_schedules_create(&json!({
                "name": "test",
                "target_operation": "op.test"
            }))
            .unwrap_err();
        assert!(matches!(err, CronError::Internal { .. }));
    }

    #[test]
    fn create_schedule_missing_target_operation() {
        let mut c = CronConnector::new();
        c.configured = true;
        let err = c
            .invoke_schedules_create(&json!({
                "name": "test",
                "expression": "0 * * * *"
            }))
            .unwrap_err();
        assert!(matches!(err, CronError::Internal { .. }));
    }

    #[test]
    fn list_schedules_empty() {
        let c = CronConnector::new();
        let result = c.invoke_schedules_list().unwrap();
        assert_eq!(result["schedules"].as_array().unwrap().len(), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn catalog_limits_preserve_schedules_and_retain_newest_history() {
        let mut c = CronConnector::new();
        c.handle_configure(json!({"state_store": {"max_schedules": 2, "max_executions": 2}}))
            .await
            .unwrap();
        let create = |name: &str| {
            json!({
                "name": name, "expression": "* * * * *", "target_operation": "test.run",
            })
        };
        let first = c.invoke_schedules_create(&create("first")).unwrap();
        let second = c.invoke_schedules_create(&create("second")).unwrap();
        assert!(matches!(
            c.invoke_schedules_create(&create("third"))
                .unwrap_err()
                .to_fcp_error(),
            FcpError::ResourceExhausted { .. }
        ));
        c.invoke_trigger(&first).unwrap();
        let older = c.invoke_trigger(&second).unwrap();
        let latest = c.invoke_trigger(&first).unwrap();
        assert_eq!(c.executions.len(), 2);
        assert_eq!(json!(c.executions[0].id), older["execution_id"]);
        assert!(
            c.handle_configure(json!({"state_store": {"max_schedules": 1, "max_executions": 1}}))
                .await
                .is_err()
        );
        assert_eq!(c.executions.len(), 2);
        assert_eq!(c.provisioning.state_store.max_executions, 2);
        c.invoke_schedules_delete(&first).unwrap();
        c.invoke_schedules_create(&create("third")).unwrap();
        c.handle_configure(json!({"state_store": {"max_schedules": 2, "max_executions": 1}}))
            .await
            .unwrap();
        let history = c.invoke_executions_list(&json!({})).unwrap();
        assert_eq!(history["executions"].as_array().unwrap().len(), 1);
        assert_eq!(history["executions"][0]["id"], latest["execution_id"]);
    }

    #[test]
    fn list_schedules_after_create() {
        let mut c = CronConnector::new();
        c.configured = true;
        c.invoke_schedules_create(&json!({
            "name": "a",
            "expression": "0 * * * *",
            "target_operation": "op.a"
        }))
        .unwrap();
        c.invoke_schedules_create(&json!({
            "name": "b",
            "expression": "0 0 * * *",
            "target_operation": "op.b"
        }))
        .unwrap();
        let result = c.invoke_schedules_list().unwrap();
        assert_eq!(result["schedules"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn delete_schedule() {
        let mut c = CronConnector::new();
        c.configured = true;
        let created = c
            .invoke_schedules_create(&json!({
                "name": "to-delete",
                "expression": "0 * * * *",
                "target_operation": "op.test"
            }))
            .unwrap();
        let sched_id = created["schedule_id"].as_str().unwrap();
        assert_eq!(c.schedules.len(), 1);

        c.invoke_schedules_delete(&json!({ "schedule_id": sched_id }))
            .unwrap();
        assert!(c.schedules.is_empty());
    }

    #[test]
    fn delete_schedule_not_found() {
        let mut c = CronConnector::new();
        let err = c
            .invoke_schedules_delete(&json!({ "schedule_id": "nonexistent" }))
            .unwrap_err();
        assert!(matches!(err, CronError::ScheduleNotFound { .. }));
    }

    #[test]
    fn delete_schedule_missing_id() {
        let mut c = CronConnector::new();
        let err = c.invoke_schedules_delete(&json!({})).unwrap_err();
        assert!(matches!(err, CronError::Internal { .. }));
    }

    #[test]
    fn trigger_schedule() {
        let mut c = CronConnector::new();
        c.configured = true;
        let created = c
            .invoke_schedules_create(&json!({
                "name": "trigger-me",
                "expression": "0 * * * *",
                "target_operation": "op.test"
            }))
            .unwrap();
        let sched_id = created["schedule_id"].as_str().unwrap();

        let result = c
            .invoke_trigger(&json!({ "schedule_id": sched_id }))
            .unwrap();
        assert!(
            result["execution_id"]
                .as_str()
                .unwrap()
                .starts_with("exec_")
        );
        assert_eq!(c.executions.len(), 1);
        assert_eq!(c.executions[0].schedule_id, sched_id);
        assert_eq!(c.executions[0].status, "triggered");
    }

    #[test]
    fn trigger_nonexistent_schedule() {
        let mut c = CronConnector::new();
        let err = c
            .invoke_trigger(&json!({ "schedule_id": "sched_nonexistent" }))
            .unwrap_err();
        assert!(matches!(err, CronError::ScheduleNotFound { .. }));
    }

    #[test]
    fn trigger_missing_schedule_id() {
        let mut c = CronConnector::new();
        let err = c.invoke_trigger(&json!({})).unwrap_err();
        assert!(matches!(err, CronError::Internal { .. }));
    }

    #[test]
    fn executions_list_empty() {
        let c = CronConnector::new();
        let result = c.invoke_executions_list(&json!({})).unwrap();
        assert_eq!(result["executions"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn executions_list_after_trigger() {
        let mut c = CronConnector::new();
        c.configured = true;
        let created = c
            .invoke_schedules_create(&json!({
                "name": "test",
                "expression": "0 * * * *",
                "target_operation": "op.test"
            }))
            .unwrap();
        let sched_id = created["schedule_id"].as_str().unwrap();

        c.invoke_trigger(&json!({ "schedule_id": sched_id }))
            .unwrap();
        c.invoke_trigger(&json!({ "schedule_id": sched_id }))
            .unwrap();

        let result = c.invoke_executions_list(&json!({})).unwrap();
        assert_eq!(result["executions"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn executions_list_filter_by_schedule() {
        let mut c = CronConnector::new();
        c.configured = true;

        let s1 = c
            .invoke_schedules_create(&json!({
                "name": "a",
                "expression": "0 * * * *",
                "target_operation": "op.a"
            }))
            .unwrap();
        let s2 = c
            .invoke_schedules_create(&json!({
                "name": "b",
                "expression": "0 0 * * *",
                "target_operation": "op.b"
            }))
            .unwrap();

        let sid1 = s1["schedule_id"].as_str().unwrap();
        let sid2 = s2["schedule_id"].as_str().unwrap();

        c.invoke_trigger(&json!({ "schedule_id": sid1 })).unwrap();
        c.invoke_trigger(&json!({ "schedule_id": sid1 })).unwrap();
        c.invoke_trigger(&json!({ "schedule_id": sid2 })).unwrap();

        let filtered = c
            .invoke_executions_list(&json!({ "schedule_id": sid1 }))
            .unwrap();
        assert_eq!(filtered["executions"].as_array().unwrap().len(), 2);

        let filtered2 = c
            .invoke_executions_list(&json!({ "schedule_id": sid2 }))
            .unwrap();
        assert_eq!(filtered2["executions"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn executions_list_with_limit() {
        let mut c = CronConnector::new();
        c.configured = true;
        let created = c
            .invoke_schedules_create(&json!({
                "name": "test",
                "expression": "0 * * * *",
                "target_operation": "op.test"
            }))
            .unwrap();
        let sched_id = created["schedule_id"].as_str().unwrap();

        for _ in 0..10 {
            c.invoke_trigger(&json!({ "schedule_id": sched_id }))
                .unwrap();
        }

        let result = c.invoke_executions_list(&json!({ "limit": 3 })).unwrap();
        assert_eq!(result["executions"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn executions_list_limit_capped_at_max() {
        let mut c = CronConnector::new();
        c.configured = true;
        let created = c
            .invoke_schedules_create(&json!({
                "name": "test",
                "expression": "0 * * * *",
                "target_operation": "op.test"
            }))
            .unwrap();
        let sched_id = created["schedule_id"].as_str().unwrap();

        // Create 5 executions and request limit 200 (should be capped to 100)
        for _ in 0..5 {
            c.invoke_trigger(&json!({ "schedule_id": sched_id }))
                .unwrap();
        }

        let result = c.invoke_executions_list(&json!({ "limit": 200 })).unwrap();
        // Only 5 exist, so 5 returned (limit capped at 100 but only 5 available)
        assert_eq!(result["executions"].as_array().unwrap().len(), 5);
    }

    #[test]
    fn executions_list_default_limit() {
        let mut c = CronConnector::new();
        c.configured = true;
        let created = c
            .invoke_schedules_create(&json!({
                "name": "test",
                "expression": "0 * * * *",
                "target_operation": "op.test"
            }))
            .unwrap();
        let sched_id = created["schedule_id"].as_str().unwrap();

        // Create 3 executions, no limit specified (defaults to 50)
        for _ in 0..3 {
            c.invoke_trigger(&json!({ "schedule_id": sched_id }))
                .unwrap();
        }

        let result = c.invoke_executions_list(&json!({})).unwrap();
        assert_eq!(result["executions"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn executions_list_reversed_order() {
        let mut c = CronConnector::new();
        c.configured = true;
        let created = c
            .invoke_schedules_create(&json!({
                "name": "test",
                "expression": "0 * * * *",
                "target_operation": "op.test"
            }))
            .unwrap();
        let sched_id = created["schedule_id"].as_str().unwrap();

        c.invoke_trigger(&json!({ "schedule_id": sched_id }))
            .unwrap();
        c.invoke_trigger(&json!({ "schedule_id": sched_id }))
            .unwrap();

        let result = c.invoke_executions_list(&json!({})).unwrap();
        let execs = result["executions"].as_array().unwrap();
        // Most recent first (second trigger should be first in the list)
        let id0 = execs[0]["id"].as_str().unwrap();
        let id1 = execs[1]["id"].as_str().unwrap();
        assert_ne!(id0, id1);
    }

    // -- Accessors --

    #[test]
    fn schedule_count() {
        let mut c = CronConnector::new();
        c.configured = true;
        assert_eq!(c.schedule_count(), 0);
        c.invoke_schedules_create(&json!({
            "name": "a",
            "expression": "0 * * * *",
            "target_operation": "op.a"
        }))
        .unwrap();
        assert_eq!(c.schedule_count(), 1);
    }

    #[test]
    fn execution_count() {
        let mut c = CronConnector::new();
        c.configured = true;
        let created = c
            .invoke_schedules_create(&json!({
                "name": "a",
                "expression": "0 * * * *",
                "target_operation": "op.a"
            }))
            .unwrap();
        assert_eq!(c.execution_count(), 0);
        let sched_id = created["schedule_id"].as_str().unwrap();
        c.invoke_trigger(&json!({ "schedule_id": sched_id }))
            .unwrap();
        assert_eq!(c.execution_count(), 1);
    }

    // -- Multiple creates and deletes --

    #[test]
    fn create_multiple_then_delete_one() {
        let mut c = CronConnector::new();
        c.configured = true;
        let s1 = c
            .invoke_schedules_create(&json!({
                "name": "a",
                "expression": "0 * * * *",
                "target_operation": "op.a"
            }))
            .unwrap();
        c.invoke_schedules_create(&json!({
            "name": "b",
            "expression": "0 0 * * *",
            "target_operation": "op.b"
        }))
        .unwrap();
        assert_eq!(c.schedules.len(), 2);

        let sid1 = s1["schedule_id"].as_str().unwrap();
        c.invoke_schedules_delete(&json!({ "schedule_id": sid1 }))
            .unwrap();
        assert_eq!(c.schedules.len(), 1);
        assert_eq!(c.schedules[0].name, "b");
    }

    #[test]
    fn delete_then_create_with_same_name() {
        let mut c = CronConnector::new();
        c.configured = true;
        let s1 = c
            .invoke_schedules_create(&json!({
                "name": "recycled",
                "expression": "0 * * * *",
                "target_operation": "op.a"
            }))
            .unwrap();
        let sid1 = s1["schedule_id"].as_str().unwrap();
        c.invoke_schedules_delete(&json!({ "schedule_id": sid1 }))
            .unwrap();

        // Should succeed since the name is no longer taken
        let s2 = c
            .invoke_schedules_create(&json!({
                "name": "recycled",
                "expression": "0 0 * * *",
                "target_operation": "op.b"
            }))
            .unwrap();
        assert!(s2["schedule_id"].as_str().is_some());
        assert_eq!(c.schedules.len(), 1);
    }

    #[test]
    fn create_schedule_with_null_payload() {
        let mut c = CronConnector::new();
        c.configured = true;
        c.invoke_schedules_create(&json!({
            "name": "null-payload",
            "expression": "0 * * * *",
            "target_operation": "op.test",
            "payload": null
        }))
        .unwrap();
        // null payload is stored as Some(Value::Null)
        assert!(c.schedules[0].payload.is_some());
    }

    #[test]
    fn create_schedule_has_created_at() {
        let mut c = CronConnector::new();
        c.configured = true;
        c.invoke_schedules_create(&json!({
            "name": "timestamped",
            "expression": "0 * * * *",
            "target_operation": "op.test"
        }))
        .unwrap();
        assert!(!c.schedules[0].created_at.is_empty());
        // Should be a valid ISO 8601 timestamp
        assert!(c.schedules[0].created_at.contains('T'));
    }

    #[test]
    fn trigger_records_execution_with_timestamp() {
        let mut c = CronConnector::new();
        c.configured = true;
        let created = c
            .invoke_schedules_create(&json!({
                "name": "test",
                "expression": "0 * * * *",
                "target_operation": "op.test"
            }))
            .unwrap();
        let sched_id = created["schedule_id"].as_str().unwrap();

        c.invoke_trigger(&json!({ "schedule_id": sched_id }))
            .unwrap();

        assert!(!c.executions[0].triggered_at.is_empty());
        assert!(c.executions[0].triggered_at.contains('T'));
    }

    // -- DoctorStatus serde --

    #[test]
    fn doctor_status_serializes_to_lowercase() {
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
    fn doctor_status_deserializes_from_lowercase() {
        let h: DoctorStatus = serde_json::from_value(json!("healthy")).unwrap();
        assert_eq!(h, DoctorStatus::Healthy);
        let d: DoctorStatus = serde_json::from_value(json!("degraded")).unwrap();
        assert_eq!(d, DoctorStatus::Degraded);
        let u: DoctorStatus = serde_json::from_value(json!("unhealthy")).unwrap();
        assert_eq!(u, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_status_copy_and_eq() {
        let s = DoctorStatus::Healthy;
        let s2 = s;
        assert_eq!(s, s2);
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
            message: Some("failure reason".into()),
            critical: true,
        };
        let v = serde_json::to_string(&check).unwrap();
        assert!(v.contains("failure reason"));
    }

    #[test]
    fn doctor_result_preserves_checks() {
        let checks = vec![
            DoctorCheck {
                name: "check_a".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "check_b".into(),
                passed: false,
                message: Some("warn".into()),
                critical: false,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.checks.len(), 2);
        assert_eq!(r.checks[0].name, "check_a");
        assert_eq!(r.checks[1].name, "check_b");
    }

    // -- Operations info edge cases --

    #[test]
    fn operations_all_have_summary() {
        let ops = operations_info();
        for op in &ops {
            assert!(
                !op.summary.is_empty(),
                "op {} has empty summary",
                op.id.as_ref()
            );
        }
    }

    #[test]
    fn operations_schedules_create_is_risky() {
        let ops = operations_info();
        let create_op = ops
            .iter()
            .find(|o| o.id.as_ref() == "cron.schedules.create")
            .unwrap();
        assert_eq!(create_op.safety_tier, SafetyTier::Risky);
        assert_eq!(create_op.risk_level, RiskLevel::Medium);
    }

    #[test]
    fn operations_schedules_list_is_strict_idempotent() {
        let ops = operations_info();
        let list_op = ops
            .iter()
            .find(|o| o.id.as_ref() == "cron.schedules.list")
            .unwrap();
        assert_eq!(list_op.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn operations_trigger_idempotency_none() {
        let ops = operations_info();
        let trigger_op = ops
            .iter()
            .find(|o| o.id.as_ref() == "cron.trigger")
            .unwrap();
        assert_eq!(trigger_op.idempotency, IdempotencyClass::None);
    }

    // -- Connector accessors / state --

    #[test]
    fn connector_new_zero_request_count() {
        let c = CronConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn connector_new_zero_error_count() {
        let c = CronConnector::new();
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn create_schedule_empty_target_operation() {
        let mut c = CronConnector::new();
        c.configured = true;
        // An empty target_operation is accepted (validation not enforced on content)
        let result = c.invoke_schedules_create(&json!({
            "name": "empty-target",
            "expression": "0 * * * *",
            "target_operation": ""
        }));
        assert!(result.is_ok());
    }

    #[test]
    fn delete_then_list_is_empty() {
        let mut c = CronConnector::new();
        c.configured = true;
        let s = c
            .invoke_schedules_create(&json!({
                "name": "temp",
                "expression": "0 * * * *",
                "target_operation": "op.test"
            }))
            .unwrap();
        let sid = s["schedule_id"].as_str().unwrap();
        c.invoke_schedules_delete(&json!({ "schedule_id": sid }))
            .unwrap();
        let list = c.invoke_schedules_list().unwrap();
        assert_eq!(list["schedules"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn executions_list_filter_nonexistent_schedule() {
        let c = CronConnector::new();
        let result = c
            .invoke_executions_list(&json!({ "schedule_id": "sched_ghost" }))
            .unwrap();
        assert_eq!(result["executions"].as_array().unwrap().len(), 0);
    }
}
