//! Doctor report service for mesh health and connector self-checks.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use fcp_async_core::{AsyncError, ExecutionContext};
use fcp_kernel::{ConnectorId, SelfCheckReport, SelfCheckStatus};
use fcp_policy::ZoneId;
use futures_util::stream::StreamExt;
use serde::{Deserialize, Serialize};

use crate::{ConnectorRegistry, HostError, HostResult};

/// Doctor report request payload.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DoctorRequest {
    /// Zone to diagnose.
    pub zone_id: String,

    /// Connector IDs to self-check.
    #[serde(default)]
    pub connectors: Vec<String>,

    /// Whether to run connector self-checks.
    #[serde(default)]
    pub self_check: bool,
}

/// Connector self-check entry in the report.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConnectorSelfCheck {
    /// Connector identifier.
    pub connector_id: ConnectorId,

    /// Self-check report from connector.
    pub report: SelfCheckReport,
}

/// Identity-bound connector report returned by a host self-check query.
///
/// Remote reports contribute connector evidence only; they cannot replace the
/// requesting host's local zone-health baseline.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HostConnectorSelfCheckResponse {
    /// Connector whose implementation produced the report.
    pub connector_id: ConnectorId,
    /// Zone whose admission policy was checked before invoking the connector.
    pub zone_id: ZoneId,
    /// Result of the connector's bounded self-check.
    pub report: SelfCheckReport,
}

/// Overall status of the zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum OverallStatus {
    /// Zone is healthy and all checks pass.
    Ok,
    /// Zone has warnings but operations can proceed.
    Warn,
    /// Zone has critical failures; Risky/Dangerous operations should fail.
    Fail,
}

/// Freshness level for heads/checkpoints.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessLevel {
    /// Data is fresh and up-to-date.
    #[default]
    Fresh,
    /// Data is stale but operations allowed in degraded mode.
    Stale,
    /// Data is too stale; operations must fail.
    TooStale,
    /// Data is missing/unavailable.
    Missing,
}

/// Checkpoint freshness status.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct CheckpointStatus {
    /// Freshness level.
    pub freshness: FreshnessLevel,
}

/// Revocation head freshness status.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct RevocationStatus {
    /// Freshness level.
    pub freshness: FreshnessLevel,
}

/// Audit head freshness status.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AuditStatus {
    /// Freshness level.
    pub freshness: FreshnessLevel,
}

/// Transport policy status.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct TransportPolicyStatus {
    /// Whether LAN transport is allowed.
    pub allow_lan: bool,
    /// Whether DERP relay transport is allowed.
    pub allow_derp: bool,
    /// Whether Funnel ingress is allowed.
    pub allow_funnel: bool,
}

/// Store coverage status for key roots.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct StoreCoverageStatus {
    /// Overall store health.
    pub store_healthy: bool,
}

/// Degraded mode status.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct DegradedModeStatus {
    /// Whether the system is in degraded mode.
    pub is_degraded: bool,
}

/// Individual check result.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CheckResult {
    /// Check name.
    pub name: String,
    /// Connector this check applies to, when the result is connector-specific.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connector_id: Option<ConnectorId>,
    /// Stable reason code for machine-readable triage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// Check status.
    pub status: CheckStatus,
    /// Check severity.
    pub severity: CheckSeverity,
    /// Human-readable message.
    pub message: String,
    /// Ordered remediation hints for the smallest useful next steps.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repair_hints: Vec<String>,
}

/// Check status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum CheckStatus {
    Ok,
    Warn,
    Fail,
}

/// Check severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckSeverity {
    Info,
    Warning,
    Critical,
}

/// Complete doctor report including zone health and freshness status.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DoctorReport {
    /// Schema version for forward/backward compatibility.
    pub schema_version: String,

    /// Timestamp when the report was generated.
    pub generated_at: DateTime<Utc>,

    /// Zone being diagnosed.
    pub zone_id: ZoneId,

    /// Overall status summary.
    pub overall_status: OverallStatus,

    /// Checkpoint freshness status.
    pub checkpoint: CheckpointStatus,

    /// Revocation head freshness status.
    pub revocation: RevocationStatus,

    /// Audit head freshness status.
    pub audit: AuditStatus,

    /// Transport policy settings.
    pub transport_policy: TransportPolicyStatus,

    /// Store coverage summary for key roots.
    pub store_coverage: StoreCoverageStatus,

    /// Degraded mode status and reasons.
    pub degraded_mode: DegradedModeStatus,

    /// Individual check results.
    pub checks: Vec<CheckResult>,

    /// Deduplicated next steps pulled from the failing or degraded checks.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recommended_actions: Vec<String>,

    /// Connector self-check results (when requested).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub connector_self_checks: Vec<ConnectorSelfCheck>,
}

impl DoctorReport {
    /// Schema version constant (aligned with fcp-cli).
    pub const SCHEMA_VERSION: &'static str = "1.1.0";

    /// # Panics
    /// Panics if `zone_id` is not a valid canonical zone ID.
    #[must_use]
    pub fn baseline(zone_id: &str) -> Self {
        let zone_id: ZoneId = zone_id
            .parse()
            .expect("doctor report baseline zone ids must be canonical");
        Self::baseline_for_zone(zone_id)
    }

    #[must_use]
    fn baseline_for_zone(zone_id: ZoneId) -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            generated_at: Utc::now(),
            zone_id,
            overall_status: OverallStatus::Ok,
            checkpoint: CheckpointStatus::default(),
            revocation: RevocationStatus::default(),
            audit: AuditStatus::default(),
            transport_policy: TransportPolicyStatus {
                allow_lan: true,
                allow_derp: false,
                allow_funnel: false,
            },
            store_coverage: StoreCoverageStatus {
                store_healthy: true,
            },
            degraded_mode: DegradedModeStatus::default(),
            checks: Vec::new(),
            recommended_actions: Vec::new(),
            connector_self_checks: Vec::new(),
        }
    }

    fn with_self_checks(mut self, checks: Vec<ConnectorSelfCheck>) -> Self {
        let derived_checks: Vec<CheckResult> = checks
            .iter()
            .filter_map(check_result_from_self_check)
            .collect();
        self.recommended_actions = recommended_actions_from_checks(&derived_checks);
        self.checks.extend(derived_checks);
        self.overall_status = overall_status_from_self_checks(&checks);
        self.connector_self_checks = checks;
        self
    }
}

const DEFAULT_SELF_CHECK_TIMEOUT: Duration = Duration::from_secs(5);

/// Doctor report service built on top of a connector registry.
#[derive(Clone)]
pub struct DoctorService<R> {
    registry: Arc<R>,
    self_check_timeout: Duration,
}

impl<R> DoctorService<R>
where
    R: ConnectorRegistry + 'static,
{
    /// Create a new doctor service.
    #[allow(clippy::missing_const_for_fn)]
    pub fn new(registry: Arc<R>) -> Self {
        Self {
            registry,
            self_check_timeout: DEFAULT_SELF_CHECK_TIMEOUT,
        }
    }

    /// Create a doctor service with a custom self-check timeout.
    #[allow(clippy::missing_const_for_fn)]
    pub fn with_timeout(registry: Arc<R>, self_check_timeout: Duration) -> Self {
        Self {
            registry,
            self_check_timeout,
        }
    }

    /// Maximum time allowed for each connector self-check, including routing.
    #[must_use]
    pub const fn self_check_timeout(&self) -> Duration {
        self.self_check_timeout
    }

    /// Build a doctor report using the local connector registry.
    ///
    /// # Errors
    /// Returns a `HostError` when the zone or a connector identifier is invalid.
    pub async fn handle(&self, request: DoctorRequest) -> HostResult<DoctorReport> {
        self.handle_with_self_check(request, |connector_id, _zone_id| async move {
            Ok(self.registry.self_check(&connector_id).await)
        })
        .await
    }

    /// Build a doctor report using a resolver for connector self-check evidence.
    ///
    /// Each resolver receives the requested connector and zone, and its entire
    /// operation is bounded by the configured self-check timeout. Individual
    /// routing failures become failed connector reports so other results remain
    /// available. The zone-health baseline always belongs to the requesting host.
    ///
    /// # Errors
    /// Returns a `HostError` when the zone or a connector identifier is invalid.
    pub async fn handle_with_self_check<F, Fut>(
        &self,
        request: DoctorRequest,
        resolve: F,
    ) -> HostResult<DoctorReport>
    where
        F: Fn(ConnectorId, ZoneId) -> Fut,
        Fut: Future<Output = HostResult<Option<SelfCheckReport>>>,
    {
        let zone: ZoneId = request.zone_id.parse().map_err(|err| {
            HostError::InvalidFilter(format!("invalid zone_id '{}': {err}", request.zone_id))
        })?;

        let mut self_checks = Vec::new();
        if request.self_check {
            let mut futures = Vec::new();

            for connector in request.connectors {
                let connector_id: ConnectorId = connector.parse().map_err(|err| {
                    HostError::InvalidFilter(format!("invalid connector id '{connector}': {err}"))
                })?;

                let resolve = &resolve;
                let connector_zone = zone.clone();
                let timeout = self.self_check_timeout;

                futures.push(async move {
                    let context = ExecutionContext::request_scoped(timeout);
                    let report = match context
                        .run(resolve(connector_id.clone(), connector_zone))
                        .await
                    {
                        Ok(Ok(Some(report))) => report,
                        Ok(Ok(None)) => SelfCheckReport::failed(
                            "not_found",
                            "connector not found in registry".to_string(),
                        ),
                        Ok(Err(error)) => SelfCheckReport::failed(
                            "self_check_runtime",
                            format!("connector self_check failed: {error}"),
                        ),
                        Err(AsyncError::Timeout { .. }) => SelfCheckReport::failed(
                            "self_check_timeout",
                            format!("self_check exceeded {}ms", timeout.as_millis()),
                        ),
                        Err(AsyncError::Cancelled) => SelfCheckReport::failed(
                            "self_check_cancelled",
                            "self_check cancelled by execution context".to_string(),
                        ),
                        Err(error) => SelfCheckReport::failed(
                            "self_check_runtime",
                            format!("self_check runtime failure: {error}"),
                        ),
                    };
                    ConnectorSelfCheck {
                        connector_id,
                        report,
                    }
                });
            }

            let mut stream = futures_util::stream::iter(futures).buffer_unordered(16);
            while let Some(check) = stream.next().await {
                self_checks.push(check);
            }
        }

        Ok(DoctorReport::baseline_for_zone(zone).with_self_checks(self_checks))
    }
}

fn overall_status_from_self_checks(checks: &[ConnectorSelfCheck]) -> OverallStatus {
    if checks
        .iter()
        .any(|check| check.report.status == SelfCheckStatus::Failed)
    {
        return OverallStatus::Fail;
    }

    if checks.iter().any(|check| {
        matches!(
            check.report.status,
            SelfCheckStatus::Degraded | SelfCheckStatus::Unsupported
        )
    }) {
        return OverallStatus::Warn;
    }

    OverallStatus::Ok
}

fn check_result_from_self_check(check: &ConnectorSelfCheck) -> Option<CheckResult> {
    let status = match check.report.status {
        SelfCheckStatus::Ok => return None,
        SelfCheckStatus::Degraded | SelfCheckStatus::Unsupported => CheckStatus::Warn,
        SelfCheckStatus::Failed => CheckStatus::Fail,
    };
    let severity = match check.report.status {
        SelfCheckStatus::Ok | SelfCheckStatus::Unsupported => CheckSeverity::Info,
        SelfCheckStatus::Degraded => CheckSeverity::Warning,
        SelfCheckStatus::Failed => CheckSeverity::Critical,
    };
    let name = classify_self_check(&check.report).to_owned();
    let message = check
        .report
        .message
        .clone()
        .unwrap_or_else(|| default_self_check_message(check.report.status));

    Some(CheckResult {
        name,
        connector_id: Some(check.connector_id.clone()),
        code: check.report.reason_code.clone(),
        status,
        severity,
        message,
        repair_hints: repair_hints_for_self_check(check),
    })
}

fn default_self_check_message(status: SelfCheckStatus) -> String {
    match status {
        SelfCheckStatus::Ok => "connector self-check succeeded".to_string(),
        SelfCheckStatus::Degraded => "connector self-check reported a degraded state".to_string(),
        SelfCheckStatus::Failed => "connector self-check failed".to_string(),
        SelfCheckStatus::Unsupported => {
            "connector does not expose a self-check implementation".to_string()
        }
    }
}

fn classify_self_check(report: &SelfCheckReport) -> &'static str {
    if report.status == SelfCheckStatus::Unsupported {
        return "unsupported";
    }

    let mut haystack = String::new();
    if let Some(code) = &report.reason_code {
        haystack.push_str(code);
        haystack.push(' ');
    }
    if let Some(message) = &report.message {
        haystack.push_str(message);
    }
    let haystack = haystack.to_ascii_lowercase();

    if contains_any(
        &haystack,
        &["schema", "config", "validation", "invalid", "parse"],
    ) {
        "schema"
    } else if contains_any(
        &haystack,
        &["secret", "credential", "token", "oauth", "auth"],
    ) {
        "secrets"
    } else if contains_any(
        &haystack,
        &["policy", "approval", "scope", "denied", "forbidden"],
    ) {
        "policy"
    } else if contains_any(
        &haystack,
        &[
            "timeout",
            "not_found",
            "not found",
            "missing",
            "offline",
            "unavailable",
            "network",
            "connection",
        ],
    ) {
        "availability"
    } else {
        "runtime"
    }
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn repair_hints_for_self_check(check: &ConnectorSelfCheck) -> Vec<String> {
    let classification = classify_self_check(&check.report);
    let mut hints = match classification {
        "schema" => vec![
            "Validate the connector config against the host schema before retrying.".to_string(),
            "Inspect the active revision diff to see which field changed.".to_string(),
        ],
        "secrets" => vec![
            "Verify secret references, credential availability, and token freshness for this connector."
                .to_string(),
            "Refresh or re-bind the missing credential material, then rerun doctor.".to_string(),
        ],
        "policy" => vec![
            "Inspect capability, approval, or policy constraints before retrying.".to_string(),
            "Request the missing approval or broader scope if the denial is expected.".to_string(),
        ],
        "availability" => {
            let mut availability_hints = vec![
                "Check connector reachability and upstream dependency availability before retrying."
                    .to_string(),
                "Inspect live logs/events to see whether startup or health checks are failing."
                    .to_string(),
            ];
            let reason = check
                .report
                .reason_code
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase();
            if reason.contains("timeout") {
                availability_hints = vec![
                    "Inspect connector logs and rerun doctor with a longer self-check timeout."
                        .to_string(),
                    "Check whether the connector or one of its upstream dependencies is hung or overloaded."
                        .to_string(),
                ];
            } else if reason.contains("not_found") || reason.contains("missing") {
                availability_hints = vec![
                    "Confirm the connector is installed and that the connector ID is correct."
                        .to_string(),
                    "Refresh host discovery/status to verify the connector is registered before retrying."
                        .to_string(),
                ];
            }
            availability_hints
        }
        "unsupported" => vec![
            "Use connector status/health surfaces instead of self-check for this connector."
                .to_string(),
            "Treat unsupported self-check as missing runtime evidence, not as confirmed health."
                .to_string(),
        ],
        _ => vec![
            "Inspect connector logs/details and retry after repairing the reported runtime failure."
                .to_string(),
            "If the failure followed a config change, diff or roll back the latest revision before retrying."
                .to_string(),
        ],
    };

    if check.report.status == SelfCheckStatus::Degraded
        && !hints.iter().any(|hint| hint.contains("degraded"))
    {
        hints.insert(
            0,
            "Inspect the degraded reason and confirm whether the connector stabilizes without a restart."
                .to_string(),
        );
    }

    hints
}

fn recommended_actions_from_checks(checks: &[CheckResult]) -> Vec<String> {
    let mut actions = Vec::new();
    for check in checks {
        for hint in &check.repair_hints {
            if !actions.iter().any(|existing| existing == hint) {
                actions.push(hint.clone());
            }
        }
    }
    actions
}

#[cfg(test)]
mod tests {
    use super::*;

    use fcp_kernel::{
        ConnectorHealth, ConnectorId, Introspection, RateLimitDeclarations, SelfCheckReport,
        SelfCheckStatus,
    };

    use crate::{ConnectorArchetype, ConnectorRegistry, ConnectorSummary};

    fn test_connector_id(raw: &str) -> ConnectorId {
        raw.parse()
            .expect("doctor tests must use canonical connector identifiers")
    }

    fn fixture_connector_id(name: impl AsRef<str>) -> ConnectorId {
        test_connector_id(&format!("fixture.{}:utility:1.0.0", name.as_ref()))
    }

    // ── Mock Registry ──
    type SelfCheckFn = dyn Fn(&ConnectorId) -> Option<SelfCheckReport> + Send + Sync;

    struct TestRegistry {
        self_check_fn: Box<SelfCheckFn>,
    }

    impl TestRegistry {
        fn always_ok() -> Self {
            Self {
                self_check_fn: Box::new(|_| Some(SelfCheckReport::ok())),
            }
        }

        fn always_fail() -> Self {
            Self {
                self_check_fn: Box::new(|_| {
                    Some(SelfCheckReport::failed("test_fail", "test failure reason"))
                }),
            }
        }

        fn not_found() -> Self {
            Self {
                self_check_fn: Box::new(|_| None),
            }
        }

        fn degraded() -> Self {
            Self {
                self_check_fn: Box::new(|_| {
                    Some(SelfCheckReport::degraded(
                        "test_degraded",
                        "degraded reason",
                    ))
                }),
            }
        }
    }

    #[async_trait::async_trait]
    impl ConnectorRegistry for TestRegistry {
        async fn list(&self) -> Vec<ConnectorSummary> {
            vec![]
        }

        async fn get(&self, _id: &ConnectorId) -> Option<ConnectorSummary> {
            Some(ConnectorSummary {
                id: ConnectorId::from_static("test.doctor:utility:1.0.0"),
                name: "Test".to_string(),
                description: None,
                version: semver::Version::new(1, 0, 0),
                categories: vec![],
                tool_count: 0,
                max_safety_tier: fcp_core::SafetyTier::Safe,
                enabled: true,
                health: ConnectorHealth::healthy(),
                last_health_check: None,
            })
        }

        async fn get_introspection(&self, _id: &ConnectorId) -> Option<Introspection> {
            None
        }

        async fn get_archetype(&self, _id: &ConnectorId) -> Option<ConnectorArchetype> {
            Some(ConnectorArchetype::RequestResponse)
        }

        async fn get_rate_limits(&self, _id: &ConnectorId) -> Option<RateLimitDeclarations> {
            None
        }

        async fn self_check(&self, id: &ConnectorId) -> Option<SelfCheckReport> {
            (self.self_check_fn)(id)
        }

        fn version(&self) -> u64 {
            1
        }
    }

    // ── overall_status_from_self_checks tests ──

    #[test]
    fn overall_ok_when_all_ok() {
        let checks = vec![
            ConnectorSelfCheck {
                connector_id: test_connector_id("test.a:utility:1.0.0"),
                report: SelfCheckReport::ok(),
            },
            ConnectorSelfCheck {
                connector_id: test_connector_id("test.b:utility:1.0.0"),
                report: SelfCheckReport::ok(),
            },
        ];
        assert_eq!(overall_status_from_self_checks(&checks), OverallStatus::Ok);
    }

    #[test]
    fn overall_fail_when_any_failed() {
        let checks = vec![
            ConnectorSelfCheck {
                connector_id: test_connector_id("test.a:utility:1.0.0"),
                report: SelfCheckReport::ok(),
            },
            ConnectorSelfCheck {
                connector_id: test_connector_id("test.b:utility:1.0.0"),
                report: SelfCheckReport::failed("test", "failed"),
            },
        ];
        assert_eq!(
            overall_status_from_self_checks(&checks),
            OverallStatus::Fail
        );
    }

    #[test]
    fn overall_warn_when_degraded() {
        let checks = vec![ConnectorSelfCheck {
            connector_id: test_connector_id("test.a:utility:1.0.0"),
            report: SelfCheckReport::degraded("test", "degraded"),
        }];
        assert_eq!(
            overall_status_from_self_checks(&checks),
            OverallStatus::Warn
        );
    }

    #[test]
    fn overall_fail_beats_warn() {
        let checks = vec![
            ConnectorSelfCheck {
                connector_id: test_connector_id("test.a:utility:1.0.0"),
                report: SelfCheckReport::degraded("test", "degraded"),
            },
            ConnectorSelfCheck {
                connector_id: test_connector_id("test.b:utility:1.0.0"),
                report: SelfCheckReport::failed("test", "failed"),
            },
        ];
        assert_eq!(
            overall_status_from_self_checks(&checks),
            OverallStatus::Fail
        );
    }

    #[test]
    fn overall_ok_when_empty() {
        assert_eq!(overall_status_from_self_checks(&[]), OverallStatus::Ok);
    }

    // ── DoctorReport tests ──

    #[test]
    fn baseline_report_has_correct_defaults() {
        let report = DoctorReport::baseline("z:test-zone");
        assert_eq!(report.zone_id.as_str(), "z:test-zone");
        assert_eq!(report.overall_status, OverallStatus::Ok);
        assert_eq!(report.checkpoint.freshness, FreshnessLevel::Fresh);
        assert_eq!(report.revocation.freshness, FreshnessLevel::Fresh);
        assert_eq!(report.audit.freshness, FreshnessLevel::Fresh);
        assert!(report.transport_policy.allow_lan);
        assert!(!report.transport_policy.allow_derp);
        assert!(!report.transport_policy.allow_funnel);
        assert!(report.store_coverage.store_healthy);
        assert!(!report.degraded_mode.is_degraded);
        assert!(report.checks.is_empty());
        assert!(report.connector_self_checks.is_empty());
        assert_eq!(report.schema_version, DoctorReport::SCHEMA_VERSION);
    }

    #[test]
    fn report_json_serializable() {
        let report = DoctorReport::baseline("z:test-zone");
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("z:test-zone"));
        assert!(json.contains("OK"));
    }

    // ── DoctorService tests ──

    #[fcp_async_core::runtime::test]
    async fn doctor_no_self_check() {
        let registry = Arc::new(TestRegistry::always_ok());
        let service = DoctorService::new(registry);

        let request = DoctorRequest {
            zone_id: "z:test".to_string(),
            connectors: vec![],
            self_check: false,
        };

        let report = service.handle(request).await.unwrap();
        assert_eq!(report.overall_status, OverallStatus::Ok);
        assert!(report.connector_self_checks.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_self_check_ok() {
        let registry = Arc::new(TestRegistry::always_ok());
        let service = DoctorService::new(registry);

        let request = DoctorRequest {
            zone_id: "z:test".to_string(),
            connectors: vec!["test.doctor:utility:1.0.0".to_string()],
            self_check: true,
        };

        let report = service.handle(request).await.unwrap();
        assert_eq!(report.overall_status, OverallStatus::Ok);
        assert_eq!(report.connector_self_checks.len(), 1);
        assert_eq!(
            report.connector_self_checks[0].report.status,
            SelfCheckStatus::Ok
        );
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_self_check_failed() {
        let registry = Arc::new(TestRegistry::always_fail());
        let service = DoctorService::new(registry);

        let request = DoctorRequest {
            zone_id: "z:test".to_string(),
            connectors: vec!["test.doctor:utility:1.0.0".to_string()],
            self_check: true,
        };

        let report = service.handle(request).await.unwrap();
        assert_eq!(report.overall_status, OverallStatus::Fail);
        assert_eq!(report.connector_self_checks.len(), 1);
        assert_eq!(
            report.connector_self_checks[0].report.status,
            SelfCheckStatus::Failed
        );
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_self_check_degraded() {
        let registry = Arc::new(TestRegistry::degraded());
        let service = DoctorService::new(registry);

        let request = DoctorRequest {
            zone_id: "z:test".to_string(),
            connectors: vec!["test.doctor:utility:1.0.0".to_string()],
            self_check: true,
        };

        let report = service.handle(request).await.unwrap();
        assert_eq!(report.overall_status, OverallStatus::Warn);
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_connector_not_found() {
        let registry = Arc::new(TestRegistry::not_found());
        let service = DoctorService::new(registry);

        let request = DoctorRequest {
            zone_id: "z:test".to_string(),
            connectors: vec!["test.doctor:utility:1.0.0".to_string()],
            self_check: true,
        };

        let result = service.handle(request).await.unwrap();
        assert_eq!(result.overall_status, OverallStatus::Fail);
        assert_eq!(result.connector_self_checks.len(), 1);
        assert_eq!(
            result.connector_self_checks[0].report.status,
            SelfCheckStatus::Failed
        );
        assert_eq!(
            result.connector_self_checks[0].report.reason_code,
            Some("not_found".to_string())
        );
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_invalid_zone_id() {
        let registry = Arc::new(TestRegistry::always_ok());
        let service = DoctorService::new(registry);

        let request = DoctorRequest {
            zone_id: String::new(),
            connectors: vec![],
            self_check: false,
        };

        let result = service.handle(request).await;
        assert!(matches!(result, Err(HostError::InvalidFilter(_))));
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_multiple_connectors() {
        let registry = Arc::new(TestRegistry::always_ok());
        let service = DoctorService::new(registry);

        let request = DoctorRequest {
            zone_id: "z:test".to_string(),
            connectors: vec![
                "test.a:utility:1.0.0".to_string(),
                "test.b:utility:1.0.0".to_string(),
            ],
            self_check: true,
        };

        let report = service.handle(request).await.unwrap();
        assert_eq!(report.connector_self_checks.len(), 2);
        assert_eq!(report.overall_status, OverallStatus::Ok);
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_custom_timeout() {
        let registry = Arc::new(TestRegistry::always_ok());
        let service = DoctorService::with_timeout(registry, Duration::from_secs(1));

        let request = DoctorRequest {
            zone_id: "z:test".to_string(),
            connectors: vec!["test.doctor:utility:1.0.0".to_string()],
            self_check: true,
        };

        let report = service.handle(request).await.unwrap();
        assert_eq!(report.overall_status, OverallStatus::Ok);
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_routed_self_checks_keep_zone_baseline_and_aggregate_missing_evidence() {
        let service = DoctorService::new(Arc::new(TestRegistry::always_fail()));
        let request = DoctorRequest {
            zone_id: "z:work".to_string(),
            connectors: vec![
                fixture_connector_id("ready").to_string(),
                fixture_connector_id("unsupported").to_string(),
            ],
            self_check: true,
        };

        let report = service
            .handle_with_self_check(request, |connector_id, zone_id| async move {
                assert_eq!(zone_id.as_str(), "z:work");
                if connector_id == fixture_connector_id("ready") {
                    Ok(Some(SelfCheckReport::ok()))
                } else {
                    assert_eq!(connector_id, fixture_connector_id("unsupported"));
                    Ok(Some(SelfCheckReport::unsupported()))
                }
            })
            .await
            .unwrap();

        assert_eq!(report.connector_self_checks.len(), 2);
        assert_eq!(report.overall_status, OverallStatus::Warn);
        assert!(report.connector_self_checks.iter().any(|check| {
            check.connector_id == fixture_connector_id("ready")
                && check.report.status == SelfCheckStatus::Ok
        }));
        assert!(report.checks.iter().any(|check| {
            check.connector_id.as_ref() == Some(&fixture_connector_id("unsupported"))
                && check.status == CheckStatus::Warn
                && check
                    .repair_hints
                    .iter()
                    .any(|hint| hint.contains("missing runtime evidence"))
        }));
        assert!(
            report
                .recommended_actions
                .iter()
                .any(|hint| hint.contains("missing runtime evidence"))
        );

        let baseline = DoctorReport::baseline("z:work");
        assert_eq!(report.zone_id, baseline.zone_id);
        assert_eq!(report.checkpoint.freshness, baseline.checkpoint.freshness);
        assert_eq!(report.revocation.freshness, baseline.revocation.freshness);
        assert_eq!(report.audit.freshness, baseline.audit.freshness);
        assert_eq!(
            report.store_coverage.store_healthy,
            baseline.store_coverage.store_healthy
        );
        assert_eq!(
            report.transport_policy.allow_lan,
            baseline.transport_policy.allow_lan
        );
        assert_eq!(
            report.transport_policy.allow_derp,
            baseline.transport_policy.allow_derp
        );
        assert_eq!(
            report.transport_policy.allow_funnel,
            baseline.transport_policy.allow_funnel
        );
        assert_eq!(
            report.degraded_mode.is_degraded,
            baseline.degraded_mode.is_degraded
        );
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_routing_errors_preserve_every_requested_connector() {
        let service = DoctorService::new(Arc::new(TestRegistry::always_fail()));
        let request = DoctorRequest {
            zone_id: "z:work".to_string(),
            connectors: vec![
                fixture_connector_id("ready").to_string(),
                fixture_connector_id("unreachable").to_string(),
            ],
            self_check: true,
        };

        let report = service
            .handle_with_self_check(request, |connector_id, _zone_id| async move {
                if connector_id == fixture_connector_id("ready") {
                    Ok(Some(SelfCheckReport::ok()))
                } else {
                    Err(HostError::Unavailable("peer unavailable".to_string()))
                }
            })
            .await
            .unwrap();

        assert_eq!(report.connector_self_checks.len(), 2);
        assert_eq!(report.overall_status, OverallStatus::Fail);
        assert!(report.connector_self_checks.iter().any(|check| {
            check.connector_id == fixture_connector_id("ready")
                && check.report.status == SelfCheckStatus::Ok
        }));
        let failed = report
            .connector_self_checks
            .iter()
            .find(|check| check.connector_id == fixture_connector_id("unreachable"))
            .expect("routing failures must retain the requested connector");
        assert_eq!(failed.report.status, SelfCheckStatus::Failed);
        assert_eq!(
            failed.report.reason_code.as_deref(),
            Some("self_check_runtime")
        );
        assert!(
            failed
                .report
                .message
                .as_deref()
                .is_some_and(|message| message.contains("peer unavailable"))
        );
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_routing_deadline_covers_an_unresponsive_resolver() {
        let service = DoctorService::with_timeout(
            Arc::new(TestRegistry::always_ok()),
            Duration::from_millis(20),
        );
        let request = DoctorRequest {
            zone_id: "z:work".to_string(),
            connectors: vec![fixture_connector_id("unresponsive").to_string()],
            self_check: true,
        };

        let report = service
            .handle_with_self_check(request, |_, _| {
                std::future::pending::<HostResult<Option<SelfCheckReport>>>()
            })
            .await
            .unwrap();

        assert_eq!(report.connector_self_checks.len(), 1);
        assert_eq!(report.overall_status, OverallStatus::Fail);
        assert_eq!(
            report.connector_self_checks[0]
                .report
                .reason_code
                .as_deref(),
            Some("self_check_timeout")
        );
    }

    // ── FreshnessLevel tests ──

    #[test]
    fn freshness_level_default_is_fresh() {
        assert_eq!(FreshnessLevel::default(), FreshnessLevel::Fresh);
    }

    // ── CheckResult/CheckStatus/CheckSeverity tests ──

    #[test]
    fn check_result_serialization() {
        let result = CheckResult {
            name: "test_check".to_string(),
            connector_id: None,
            code: None,
            status: CheckStatus::Warn,
            severity: CheckSeverity::Warning,
            message: "something is off".to_string(),
            repair_hints: Vec::new(),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["name"], "test_check");
        assert_eq!(json["status"], "WARN");
        assert_eq!(json["severity"], "warning");
    }

    #[test]
    fn check_result_serialization_includes_optional_triage_fields() {
        let result = CheckResult {
            name: "auth".to_string(),
            connector_id: Some(test_connector_id("test.auth:utility:1.0.0")),
            code: Some("token_expired".to_string()),
            status: CheckStatus::Fail,
            severity: CheckSeverity::Critical,
            message: "token expired".to_string(),
            repair_hints: vec![
                "Refresh the connector token and rerun doctor.".to_string(),
                "Verify the secret reference resolves in the target zone.".to_string(),
            ],
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["connector_id"], "test.auth:utility:1.0.0");
        assert_eq!(json["code"], "token_expired");
        assert_eq!(
            json["repair_hints"][0],
            "Refresh the connector token and rerun doctor."
        );
        assert_eq!(json["repair_hints"].as_array().unwrap().len(), 2);
    }

    // ── OverallStatus serde tests ──

    #[test]
    fn overall_status_serialization() {
        for (status, expected) in [
            (OverallStatus::Ok, "\"OK\""),
            (OverallStatus::Warn, "\"WARN\""),
            (OverallStatus::Fail, "\"FAIL\""),
        ] {
            let json = serde_json::to_string(&status).unwrap();
            assert_eq!(json, expected);
        }
    }

    #[test]
    fn overall_status_eq_and_copy() {
        let a = OverallStatus::Ok;
        let b = a;
        assert_eq!(a, b);
        assert_ne!(OverallStatus::Ok, OverallStatus::Fail);
    }

    // ── FreshnessLevel serde tests ──

    #[test]
    fn freshness_level_all_variants_serialize() {
        for (level, expected) in [
            (FreshnessLevel::Fresh, "\"fresh\""),
            (FreshnessLevel::Stale, "\"stale\""),
            (FreshnessLevel::TooStale, "\"too_stale\""),
            (FreshnessLevel::Missing, "\"missing\""),
        ] {
            let json = serde_json::to_string(&level).unwrap();
            assert_eq!(json, expected);
        }
    }

    #[test]
    fn freshness_level_eq_and_copy() {
        let a = FreshnessLevel::Stale;
        let b = a;
        assert_eq!(a, b);
        assert_ne!(FreshnessLevel::Fresh, FreshnessLevel::TooStale);
    }

    // ── CheckStatus serde tests ──

    #[test]
    fn check_status_serialization() {
        for (status, expected) in [
            (CheckStatus::Ok, "\"OK\""),
            (CheckStatus::Warn, "\"WARN\""),
            (CheckStatus::Fail, "\"FAIL\""),
        ] {
            let json = serde_json::to_string(&status).unwrap();
            assert_eq!(json, expected);
        }
    }

    #[test]
    fn check_status_eq_and_copy() {
        let a = CheckStatus::Fail;
        let b = a;
        assert_eq!(a, b);
    }

    // ── CheckSeverity serde tests ──

    #[test]
    fn check_severity_serialization() {
        for (sev, expected) in [
            (CheckSeverity::Info, "\"info\""),
            (CheckSeverity::Warning, "\"warning\""),
            (CheckSeverity::Critical, "\"critical\""),
        ] {
            let json = serde_json::to_string(&sev).unwrap();
            assert_eq!(json, expected);
        }
    }

    #[test]
    fn check_severity_eq_and_copy() {
        let a = CheckSeverity::Critical;
        let b = a;
        assert_eq!(a, b);
    }

    // ── Default status struct tests ──

    #[test]
    fn checkpoint_status_default_is_fresh() {
        let s = CheckpointStatus::default();
        assert_eq!(s.freshness, FreshnessLevel::Fresh);
    }

    #[test]
    fn revocation_status_default_is_fresh() {
        let s = RevocationStatus::default();
        assert_eq!(s.freshness, FreshnessLevel::Fresh);
    }

    #[test]
    fn audit_status_default_is_fresh() {
        let s = AuditStatus::default();
        assert_eq!(s.freshness, FreshnessLevel::Fresh);
    }

    #[test]
    fn transport_policy_default_all_false() {
        let t = TransportPolicyStatus::default();
        assert!(!t.allow_lan);
        assert!(!t.allow_derp);
        assert!(!t.allow_funnel);
    }

    #[test]
    fn store_coverage_default_not_healthy() {
        let s = StoreCoverageStatus::default();
        assert!(!s.store_healthy);
    }

    #[test]
    fn degraded_mode_default_not_degraded() {
        let d = DegradedModeStatus::default();
        assert!(!d.is_degraded);
    }

    // ── DoctorReport tests ──

    #[test]
    fn schema_version_constant_is_semver() {
        let v: semver::Version = DoctorReport::SCHEMA_VERSION.parse().unwrap();
        assert_eq!(v.major, 1);
    }

    #[test]
    fn baseline_transport_policy_allows_lan_only() {
        let report = DoctorReport::baseline("z:test");
        assert!(report.transport_policy.allow_lan);
        assert!(!report.transport_policy.allow_derp);
        assert!(!report.transport_policy.allow_funnel);
    }

    #[test]
    fn with_self_checks_sets_overall_status() {
        let checks = vec![ConnectorSelfCheck {
            connector_id: test_connector_id("test.connector:utility:1.0.0"),
            report: SelfCheckReport::failed("test", "fail"),
        }];
        let report = DoctorReport::baseline("z:test").with_self_checks(checks);
        assert_eq!(report.overall_status, OverallStatus::Fail);
        assert_eq!(report.connector_self_checks.len(), 1);
    }

    #[test]
    fn with_self_checks_empty_stays_ok() {
        let report = DoctorReport::baseline("z:test").with_self_checks(vec![]);
        assert_eq!(report.overall_status, OverallStatus::Ok);
        assert!(report.connector_self_checks.is_empty());
    }

    // ── DoctorRequest deserialization tests ──

    #[test]
    fn doctor_request_defaults() {
        let json = r#"{"zone_id": "z:test"}"#;
        let req: DoctorRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.zone_id, "z:test");
        assert!(req.connectors.is_empty());
        assert!(!req.self_check);
    }

    #[test]
    fn doctor_request_full() {
        let json = r#"{"zone_id": "z:prod", "connectors": ["a.b:c:1.0.0"], "self_check": true}"#;
        let req: DoctorRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.zone_id, "z:prod");
        assert_eq!(req.connectors.len(), 1);
        assert!(req.self_check);
    }

    // ── ConnectorSelfCheck serialization ──

    #[test]
    fn connector_self_check_serialization() {
        let check = ConnectorSelfCheck {
            connector_id: test_connector_id("test.check:utility:1.0.0"),
            report: SelfCheckReport::ok(),
        };
        let json = serde_json::to_value(&check).unwrap();
        assert_eq!(json["connector_id"], "test.check:utility:1.0.0");
    }

    // ── DoctorReport full serialization ──

    #[test]
    fn doctor_report_skips_empty_self_checks() {
        let report = DoctorReport::baseline("z:test");
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("connector_self_checks"));
    }

    #[test]
    fn doctor_report_includes_nonempty_self_checks() {
        let checks = vec![ConnectorSelfCheck {
            connector_id: test_connector_id("test.a:utility:1.0.0"),
            report: SelfCheckReport::ok(),
        }];
        let report = DoctorReport::baseline("z:test").with_self_checks(checks);
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("connector_self_checks"));
    }

    // ── CheckResult construction ──

    #[test]
    fn check_result_fields_accessible() {
        let result = CheckResult {
            name: "connectivity".to_string(),
            connector_id: None,
            code: None,
            status: CheckStatus::Ok,
            severity: CheckSeverity::Info,
            message: "all good".to_string(),
            repair_hints: Vec::new(),
        };
        assert_eq!(result.name, "connectivity");
        assert_eq!(result.status, CheckStatus::Ok);
        assert_eq!(result.severity, CheckSeverity::Info);
        assert_eq!(result.message, "all good");
    }

    #[test]
    fn check_result_fail_critical_serialization() {
        let result = CheckResult {
            name: "disk_space".to_string(),
            connector_id: None,
            code: None,
            status: CheckStatus::Fail,
            severity: CheckSeverity::Critical,
            message: "disk full".to_string(),
            repair_hints: Vec::new(),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["status"], "FAIL");
        assert_eq!(json["severity"], "critical");
    }

    // ── OverallStatus serde names ──

    #[test]
    fn overall_status_serde_uppercase() {
        assert_eq!(serde_json::to_string(&OverallStatus::Ok).unwrap(), "\"OK\"");
        assert_eq!(
            serde_json::to_string(&OverallStatus::Warn).unwrap(),
            "\"WARN\""
        );
        assert_eq!(
            serde_json::to_string(&OverallStatus::Fail).unwrap(),
            "\"FAIL\""
        );
    }

    // ── CheckStatus serde ──

    #[test]
    fn check_status_serde_names() {
        assert_eq!(serde_json::to_string(&CheckStatus::Ok).unwrap(), "\"OK\"");
        assert_eq!(
            serde_json::to_string(&CheckStatus::Warn).unwrap(),
            "\"WARN\""
        );
        assert_eq!(
            serde_json::to_string(&CheckStatus::Fail).unwrap(),
            "\"FAIL\""
        );
    }

    // ── CheckSeverity serde ──

    #[test]
    fn check_severity_serde_names() {
        assert_eq!(
            serde_json::to_string(&CheckSeverity::Info).unwrap(),
            "\"info\""
        );
        assert_eq!(
            serde_json::to_string(&CheckSeverity::Warning).unwrap(),
            "\"warning\""
        );
        assert_eq!(
            serde_json::to_string(&CheckSeverity::Critical).unwrap(),
            "\"critical\""
        );
    }

    // ── FreshnessLevel serde names ──

    #[test]
    fn freshness_level_serde_names() {
        assert_eq!(
            serde_json::to_string(&FreshnessLevel::Fresh).unwrap(),
            "\"fresh\""
        );
        assert_eq!(
            serde_json::to_string(&FreshnessLevel::Stale).unwrap(),
            "\"stale\""
        );
        assert_eq!(
            serde_json::to_string(&FreshnessLevel::TooStale).unwrap(),
            "\"too_stale\""
        );
        assert_eq!(
            serde_json::to_string(&FreshnessLevel::Missing).unwrap(),
            "\"missing\""
        );
    }

    // ── Status struct serialization with non-default values ──

    #[test]
    fn checkpoint_status_stale_serialization() {
        let s = CheckpointStatus {
            freshness: FreshnessLevel::Stale,
        };
        let json = serde_json::to_value(&s).unwrap();
        assert_eq!(json["freshness"], "stale");
    }

    #[test]
    fn transport_policy_custom_serialization() {
        let s = TransportPolicyStatus {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: false,
        };
        let json = serde_json::to_value(&s).unwrap();
        assert_eq!(json["allow_lan"], true);
        assert_eq!(json["allow_derp"], true);
        assert_eq!(json["allow_funnel"], false);
    }

    #[test]
    fn store_coverage_healthy_serialization() {
        let s = StoreCoverageStatus {
            store_healthy: true,
        };
        let json = serde_json::to_value(&s).unwrap();
        assert_eq!(json["store_healthy"], true);
    }

    #[test]
    fn degraded_mode_active_serialization() {
        let s = DegradedModeStatus { is_degraded: true };
        let json = serde_json::to_value(&s).unwrap();
        assert_eq!(json["is_degraded"], true);
    }

    // ── with_self_checks precedence ──

    #[test]
    fn with_self_checks_mixed_ok_warn_fail_returns_fail() {
        let checks = vec![
            ConnectorSelfCheck {
                connector_id: test_connector_id("test.a:utility:1.0.0"),
                report: SelfCheckReport::ok(),
            },
            ConnectorSelfCheck {
                connector_id: test_connector_id("test.b:utility:1.0.0"),
                report: SelfCheckReport::degraded("slow", "slow response"),
            },
            ConnectorSelfCheck {
                connector_id: test_connector_id("test.c:utility:1.0.0"),
                report: SelfCheckReport::failed("test", "down"),
            },
        ];
        let report = DoctorReport::baseline("z:test").with_self_checks(checks);
        assert_eq!(report.overall_status, OverallStatus::Fail);
    }

    #[test]
    fn with_self_checks_warn_only_returns_warn() {
        let checks = vec![
            ConnectorSelfCheck {
                connector_id: test_connector_id("test.a:utility:1.0.0"),
                report: SelfCheckReport::ok(),
            },
            ConnectorSelfCheck {
                connector_id: test_connector_id("test.b:utility:1.0.0"),
                report: SelfCheckReport::degraded("slow", "slow response"),
            },
        ];
        let report = DoctorReport::baseline("z:test").with_self_checks(checks);
        assert_eq!(report.overall_status, OverallStatus::Warn);
    }

    // ── DoctorReport baseline values ──

    #[test]
    fn baseline_report_schema_version() {
        let report = DoctorReport::baseline("z:test");
        assert_eq!(report.schema_version, "1.1.0");
    }

    #[test]
    fn baseline_report_zone_id_preserved() {
        let report = DoctorReport::baseline("z:custom");
        assert_eq!(report.zone_id.as_str(), "z:custom");
    }

    #[test]
    fn baseline_report_transport_policy_defaults() {
        let report = DoctorReport::baseline("z:test");
        assert!(report.transport_policy.allow_lan);
        assert!(!report.transport_policy.allow_derp);
        assert!(!report.transport_policy.allow_funnel);
    }

    #[test]
    fn baseline_report_store_coverage_healthy() {
        let report = DoctorReport::baseline("z:test");
        assert!(report.store_coverage.store_healthy);
    }

    #[test]
    fn baseline_report_no_degraded_mode() {
        let report = DoctorReport::baseline("z:test");
        assert!(!report.degraded_mode.is_degraded);
    }

    // ── ConnectorSelfCheck serde roundtrip ──

    #[test]
    fn connector_self_check_roundtrip() {
        let check = ConnectorSelfCheck {
            connector_id: test_connector_id("test:conn:1.0.0"),
            report: SelfCheckReport::ok(),
        };
        let json = serde_json::to_string(&check).unwrap();
        assert!(json.contains("test:conn:1.0.0"));
        assert!(json.contains("ok"));
    }

    #[test]
    fn connector_self_check_failed_report() {
        let check = ConnectorSelfCheck {
            connector_id: test_connector_id("test:fail:1.0.0"),
            report: SelfCheckReport::failed("auth", "token expired"),
        };
        let json = serde_json::to_string(&check).unwrap();
        assert!(json.contains("failed"));
        assert!(json.contains("token expired"));
    }

    // ── DoctorReport full serialization ──

    #[test]
    fn doctor_report_full_serialization_roundtrip() {
        let report = DoctorReport::baseline("z:roundtrip");
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("z:roundtrip"));
        assert!(json.contains("1.1.0"));
        assert!(json.contains("\"OK\""));
        assert!(json.contains("\"fresh\""));
    }

    // ── CheckResult all status-severity combinations ──

    #[test]
    fn check_result_all_status_severity_combinations() {
        let statuses = [CheckStatus::Ok, CheckStatus::Warn, CheckStatus::Fail];
        let severities = [
            CheckSeverity::Info,
            CheckSeverity::Warning,
            CheckSeverity::Critical,
        ];
        for status in &statuses {
            for severity in &severities {
                let result = CheckResult {
                    name: format!("{status:?}_{severity:?}"),
                    connector_id: None,
                    code: None,
                    status: *status,
                    severity: *severity,
                    message: "test".to_string(),
                    repair_hints: Vec::new(),
                };
                let json = serde_json::to_value(&result).unwrap();
                assert!(!json["status"].as_str().unwrap().is_empty());
                assert!(!json["severity"].as_str().unwrap().is_empty());
            }
        }
    }

    // ── DoctorRequest deserialization edge cases ──

    #[test]
    fn doctor_request_empty_zone_id() {
        let json = r#"{"zone_id": ""}"#;
        let req: DoctorRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.zone_id, "");
    }

    #[test]
    fn doctor_request_serde_roundtrip() {
        let json = r#"{"zone_id": "z:test", "connectors": ["a", "b"], "self_check": true}"#;
        let req: DoctorRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.zone_id, "z:test");
        assert_eq!(req.connectors, vec!["a", "b"]);
        assert!(req.self_check);
    }

    // ── DoctorReport clone ──

    #[test]
    fn doctor_report_clone_preserves_all_fields() {
        let report = DoctorReport::baseline("z:clone-test");
        let cloned = report.clone();
        assert_eq!(report.zone_id, cloned.zone_id);
        assert_eq!(report.overall_status, cloned.overall_status);
        assert_eq!(report.schema_version, cloned.schema_version);
        assert_eq!(report.checkpoint.freshness, cloned.checkpoint.freshness);
        assert_eq!(
            report.transport_policy.allow_lan,
            cloned.transport_policy.allow_lan
        );
    }

    // ── DoctorReport debug ──

    #[test]
    fn doctor_report_debug_output() {
        let report = DoctorReport::baseline("z:debug");
        let dbg = format!("{report:?}");
        assert!(dbg.contains("DoctorReport"));
        assert!(dbg.contains("z:debug"));
    }

    // ── OverallStatus debug ──

    #[test]
    fn overall_status_debug() {
        let dbg = format!("{:?}", OverallStatus::Ok);
        assert!(dbg.contains("Ok"));
        let dbg = format!("{:?}", OverallStatus::Warn);
        assert!(dbg.contains("Warn"));
        let dbg = format!("{:?}", OverallStatus::Fail);
        assert!(dbg.contains("Fail"));
    }

    // ── FreshnessLevel debug ──

    #[test]
    fn freshness_level_debug_all_variants() {
        for level in [
            FreshnessLevel::Fresh,
            FreshnessLevel::Stale,
            FreshnessLevel::TooStale,
            FreshnessLevel::Missing,
        ] {
            let dbg = format!("{level:?}");
            assert!(!dbg.is_empty());
        }
    }

    // ── CheckStatus debug ──

    #[test]
    fn check_status_debug_all_variants() {
        for status in [CheckStatus::Ok, CheckStatus::Warn, CheckStatus::Fail] {
            let dbg = format!("{status:?}");
            assert!(!dbg.is_empty());
        }
    }

    // ── CheckSeverity debug ──

    #[test]
    fn check_severity_debug_all_variants() {
        for sev in [
            CheckSeverity::Info,
            CheckSeverity::Warning,
            CheckSeverity::Critical,
        ] {
            let dbg = format!("{sev:?}");
            assert!(!dbg.is_empty());
        }
    }

    // ── ConnectorSelfCheck clone ──

    #[test]
    fn connector_self_check_clone() {
        let check = ConnectorSelfCheck {
            connector_id: test_connector_id("test:conn:1.0.0"),
            report: SelfCheckReport::ok(),
        };
        let cloned = check.clone();
        assert_eq!(check.connector_id, cloned.connector_id);
        assert_eq!(check.report.status, cloned.report.status);
    }

    // ── ConnectorSelfCheck debug ──

    #[test]
    fn connector_self_check_debug() {
        let check = ConnectorSelfCheck {
            connector_id: test_connector_id("debug:conn:1.0.0"),
            report: SelfCheckReport::ok(),
        };
        let dbg = format!("{check:?}");
        assert!(dbg.contains("ConnectorSelfCheck"));
        assert!(dbg.contains("debug:conn:1.0.0"));
    }

    // ── CheckpointStatus clone and debug ──

    #[test]
    fn checkpoint_status_clone() {
        let s = CheckpointStatus {
            freshness: FreshnessLevel::TooStale,
        };
        let cloned = s.clone();
        assert_eq!(s.freshness, cloned.freshness);
    }

    #[test]
    fn checkpoint_status_debug() {
        let s = CheckpointStatus::default();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("CheckpointStatus"));
    }

    // ── RevocationStatus clone and debug ──

    #[test]
    fn revocation_status_clone() {
        let s = RevocationStatus {
            freshness: FreshnessLevel::Missing,
        };
        let cloned = s.clone();
        assert_eq!(s.freshness, cloned.freshness);
    }

    #[test]
    fn revocation_status_debug() {
        let s = RevocationStatus::default();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("RevocationStatus"));
    }

    // ── AuditStatus clone and debug ──

    #[test]
    fn audit_status_clone() {
        let s = AuditStatus {
            freshness: FreshnessLevel::Stale,
        };
        let cloned = s.clone();
        assert_eq!(s.freshness, cloned.freshness);
    }

    #[test]
    fn audit_status_debug() {
        let s = AuditStatus::default();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("AuditStatus"));
    }

    // ── TransportPolicyStatus clone and debug ──

    #[test]
    fn transport_policy_status_clone() {
        let s = TransportPolicyStatus {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: false,
        };
        let cloned = s.clone();
        assert_eq!(s.allow_lan, cloned.allow_lan);
        assert_eq!(s.allow_derp, cloned.allow_derp);
        assert_eq!(s.allow_funnel, cloned.allow_funnel);
    }

    #[test]
    fn transport_policy_status_debug() {
        let s = TransportPolicyStatus::default();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("TransportPolicyStatus"));
    }

    // ── StoreCoverageStatus clone and debug ──

    #[test]
    fn store_coverage_status_clone() {
        let s = StoreCoverageStatus {
            store_healthy: true,
        };
        let cloned = s.clone();
        assert_eq!(s.store_healthy, cloned.store_healthy);
    }

    #[test]
    fn store_coverage_status_debug() {
        let s = StoreCoverageStatus::default();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("StoreCoverageStatus"));
    }

    // ── DegradedModeStatus clone and debug ──

    #[test]
    fn degraded_mode_status_clone() {
        let s = DegradedModeStatus { is_degraded: true };
        let cloned = s.clone();
        assert_eq!(s.is_degraded, cloned.is_degraded);
    }

    #[test]
    fn degraded_mode_status_debug() {
        let s = DegradedModeStatus::default();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("DegradedModeStatus"));
    }

    // ── CheckResult clone and debug ──

    #[test]
    fn check_result_clone() {
        let result = CheckResult {
            name: "clone_test".to_string(),
            connector_id: None,
            code: None,
            status: CheckStatus::Warn,
            severity: CheckSeverity::Warning,
            message: "cloned".to_string(),
            repair_hints: Vec::new(),
        };
        let cloned = result.clone();
        assert_eq!(result.name, cloned.name);
        assert_eq!(result.status, cloned.status);
        assert_eq!(result.severity, cloned.severity);
        assert_eq!(result.message, cloned.message);
    }

    #[test]
    fn check_result_debug() {
        let result = CheckResult {
            name: "debug_test".to_string(),
            connector_id: None,
            code: None,
            status: CheckStatus::Fail,
            severity: CheckSeverity::Critical,
            message: "debug msg".to_string(),
            repair_hints: Vec::new(),
        };
        let dbg = format!("{result:?}");
        assert!(dbg.contains("CheckResult"));
        assert!(dbg.contains("debug_test"));
    }

    // ── DoctorReport with multiple checks ──

    #[test]
    fn doctor_report_with_checks_serialization() {
        let mut report = DoctorReport::baseline("z:checks");
        report.checks.push(CheckResult {
            name: "disk".to_string(),
            connector_id: None,
            code: None,
            status: CheckStatus::Warn,
            severity: CheckSeverity::Warning,
            message: "low space".to_string(),
            repair_hints: Vec::new(),
        });
        report.checks.push(CheckResult {
            name: "cpu".to_string(),
            connector_id: None,
            code: None,
            status: CheckStatus::Ok,
            severity: CheckSeverity::Info,
            message: "normal".to_string(),
            repair_hints: Vec::new(),
        });
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("disk"));
        assert!(json.contains("cpu"));
        assert!(json.contains("WARN"));
    }

    // ── DoctorReport unicode zone_id ──

    #[test]
    fn baseline_report_unicode_zone_id() {
        let report = DoctorReport::baseline("z:eleve");
        assert_eq!(report.zone_id.as_str(), "z:eleve");
    }

    // ── DoctorRequest unicode ──

    #[test]
    fn doctor_request_unicode_zone_id() {
        let json = r#"{"zone_id": "z:\u00e9l\u00e8ve"}"#;
        let req: DoctorRequest = serde_json::from_str(json).unwrap();
        assert!(req.zone_id.contains('\u{00e9}'));
    }

    // ── DoctorRequest many connectors ──

    #[test]
    fn doctor_request_many_connectors() {
        let connectors: Vec<String> = (0..100).map(|i| format!("conn{i}")).collect();
        let req = DoctorRequest {
            zone_id: "z:bulk".to_string(),
            connectors,
            self_check: true,
        };
        assert_eq!(req.connectors.len(), 100);
    }

    // ── overall_status_from_self_checks with many entries ──

    #[test]
    fn overall_status_many_ok_entries() {
        let checks: Vec<ConnectorSelfCheck> = (0..50)
            .map(|i| ConnectorSelfCheck {
                connector_id: fixture_connector_id(format!("conn{i}")),
                report: SelfCheckReport::ok(),
            })
            .collect();
        assert_eq!(overall_status_from_self_checks(&checks), OverallStatus::Ok);
    }

    #[test]
    fn overall_status_last_entry_failed() {
        let mut checks: Vec<ConnectorSelfCheck> = (0..10)
            .map(|i| ConnectorSelfCheck {
                connector_id: fixture_connector_id(format!("conn{i}")),
                report: SelfCheckReport::ok(),
            })
            .collect();
        checks.push(ConnectorSelfCheck {
            connector_id: fixture_connector_id("last"),
            report: SelfCheckReport::failed("err", "final failure"),
        });
        assert_eq!(
            overall_status_from_self_checks(&checks),
            OverallStatus::Fail
        );
    }

    // ── DoctorReport transport_policy all true ──

    #[test]
    fn transport_policy_all_true() {
        let t = TransportPolicyStatus {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: true,
        };
        let json = serde_json::to_value(&t).unwrap();
        assert_eq!(json["allow_lan"], true);
        assert_eq!(json["allow_derp"], true);
        assert_eq!(json["allow_funnel"], true);
    }

    // ── FreshnessLevel copy semantics ──

    #[test]
    fn freshness_level_copy_semantics() {
        let a = FreshnessLevel::TooStale;
        let b = a;
        let c = a;
        assert_eq!(b, c);
        assert_eq!(a, FreshnessLevel::TooStale);
    }

    // ── OverallStatus copy semantics ──

    #[test]
    fn overall_status_copy_semantics() {
        let a = OverallStatus::Warn;
        let b = a;
        let c = a;
        assert_eq!(b, c);
        assert_eq!(a, OverallStatus::Warn);
    }

    // ── NEW: OverallStatus serialize-to-Value roundtrip ──

    #[test]
    fn overall_status_ok_to_value_roundtrip() {
        let val = serde_json::to_value(OverallStatus::Ok).unwrap();
        assert_eq!(val.as_str(), Some("OK"));
    }

    #[test]
    fn overall_status_warn_to_value_roundtrip() {
        let val = serde_json::to_value(OverallStatus::Warn).unwrap();
        assert_eq!(val.as_str(), Some("WARN"));
    }

    #[test]
    fn overall_status_fail_to_value_roundtrip() {
        let val = serde_json::to_value(OverallStatus::Fail).unwrap();
        assert_eq!(val.as_str(), Some("FAIL"));
    }

    // ── NEW: FreshnessLevel serialize-to-Value roundtrip ──

    #[test]
    fn freshness_level_fresh_to_value() {
        let val = serde_json::to_value(FreshnessLevel::Fresh).unwrap();
        assert_eq!(val.as_str(), Some("fresh"));
    }

    #[test]
    fn freshness_level_stale_to_value() {
        let val = serde_json::to_value(FreshnessLevel::Stale).unwrap();
        assert_eq!(val.as_str(), Some("stale"));
    }

    #[test]
    fn freshness_level_too_stale_to_value() {
        let val = serde_json::to_value(FreshnessLevel::TooStale).unwrap();
        assert_eq!(val.as_str(), Some("too_stale"));
    }

    #[test]
    fn freshness_level_missing_to_value() {
        let val = serde_json::to_value(FreshnessLevel::Missing).unwrap();
        assert_eq!(val.as_str(), Some("missing"));
    }

    // ── NEW: CheckStatus serialize-to-Value roundtrip ──

    #[test]
    fn check_status_ok_to_value() {
        let val = serde_json::to_value(CheckStatus::Ok).unwrap();
        assert_eq!(val.as_str(), Some("OK"));
    }

    #[test]
    fn check_status_warn_to_value() {
        let val = serde_json::to_value(CheckStatus::Warn).unwrap();
        assert_eq!(val.as_str(), Some("WARN"));
    }

    #[test]
    fn check_status_fail_to_value() {
        let val = serde_json::to_value(CheckStatus::Fail).unwrap();
        assert_eq!(val.as_str(), Some("FAIL"));
    }

    // ── NEW: CheckSeverity serialize-to-Value roundtrip ──

    #[test]
    fn check_severity_info_to_value() {
        let val = serde_json::to_value(CheckSeverity::Info).unwrap();
        assert_eq!(val.as_str(), Some("info"));
    }

    #[test]
    fn check_severity_warning_to_value() {
        let val = serde_json::to_value(CheckSeverity::Warning).unwrap();
        assert_eq!(val.as_str(), Some("warning"));
    }

    #[test]
    fn check_severity_critical_to_value() {
        let val = serde_json::to_value(CheckSeverity::Critical).unwrap();
        assert_eq!(val.as_str(), Some("critical"));
    }

    // ── NEW: OverallStatus inequality combinations ──

    #[test]
    fn overall_status_all_pairs_inequality() {
        let variants = [OverallStatus::Ok, OverallStatus::Warn, OverallStatus::Fail];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    // ── NEW: CheckStatus inequality combinations ──

    #[test]
    fn check_status_all_pairs_inequality() {
        let variants = [CheckStatus::Ok, CheckStatus::Warn, CheckStatus::Fail];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    // ── NEW: CheckSeverity inequality combinations ──

    #[test]
    fn check_severity_all_pairs_inequality() {
        let variants = [
            CheckSeverity::Info,
            CheckSeverity::Warning,
            CheckSeverity::Critical,
        ];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    // ── NEW: FreshnessLevel inequality combinations ──

    #[test]
    fn freshness_level_all_pairs_inequality() {
        let variants = [
            FreshnessLevel::Fresh,
            FreshnessLevel::Stale,
            FreshnessLevel::TooStale,
            FreshnessLevel::Missing,
        ];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    // ── NEW: DoctorRequest edge cases ──

    #[test]
    fn doctor_request_missing_zone_id_fails() {
        let result = serde_json::from_str::<DoctorRequest>(r"{}");
        assert!(result.is_err());
    }

    #[test]
    fn doctor_request_extra_fields_ignored() {
        let json = r#"{"zone_id": "z:test", "unknown_field": 42}"#;
        let req: DoctorRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.zone_id, "z:test");
    }

    #[test]
    fn doctor_request_self_check_defaults_false() {
        let json = r#"{"zone_id": "z:test", "connectors": ["a"]}"#;
        let req: DoctorRequest = serde_json::from_str(json).unwrap();
        assert!(!req.self_check);
    }

    #[test]
    fn doctor_request_connectors_defaults_empty() {
        let json = r#"{"zone_id": "z:test", "self_check": true}"#;
        let req: DoctorRequest = serde_json::from_str(json).unwrap();
        assert!(req.connectors.is_empty());
        assert!(req.self_check);
    }

    #[test]
    fn doctor_request_clone_preserves_fields() {
        let req = DoctorRequest {
            zone_id: "z:cloned".to_string(),
            connectors: vec!["conn1".to_string(), "conn2".to_string()],
            self_check: true,
        };
        let cloned = req.clone();
        assert_eq!(req.zone_id, cloned.zone_id);
        assert_eq!(req.connectors, cloned.connectors);
        assert_eq!(req.self_check, cloned.self_check);
    }

    #[test]
    fn doctor_request_debug_output() {
        let req = DoctorRequest {
            zone_id: "z:dbg".to_string(),
            connectors: vec![],
            self_check: false,
        };
        let dbg = format!("{req:?}");
        assert!(dbg.contains("DoctorRequest"));
        assert!(dbg.contains("z:dbg"));
    }

    // ── NEW: DoctorReport with non-default freshness values ──

    #[test]
    fn doctor_report_stale_checkpoint_serialization() {
        let mut report = DoctorReport::baseline("z:stale");
        report.checkpoint.freshness = FreshnessLevel::Stale;
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["checkpoint"]["freshness"], "stale");
    }

    #[test]
    fn doctor_report_too_stale_revocation_serialization() {
        let mut report = DoctorReport::baseline("z:too-stale");
        report.revocation.freshness = FreshnessLevel::TooStale;
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["revocation"]["freshness"], "too_stale");
    }

    #[test]
    fn doctor_report_missing_audit_serialization() {
        let mut report = DoctorReport::baseline("z:missing");
        report.audit.freshness = FreshnessLevel::Missing;
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["audit"]["freshness"], "missing");
    }

    // ── NEW: DoctorReport degraded mode and store coverage ──

    #[test]
    fn doctor_report_degraded_mode_active_serialization() {
        let mut report = DoctorReport::baseline("z:degraded");
        report.degraded_mode.is_degraded = true;
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["degraded_mode"]["is_degraded"], true);
    }

    #[test]
    fn doctor_report_store_unhealthy_serialization() {
        let mut report = DoctorReport::baseline("z:unhealthy-store");
        report.store_coverage.store_healthy = false;
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["store_coverage"]["store_healthy"], false);
    }

    // ── NEW: DoctorReport with checks vec serialization ──

    #[test]
    fn doctor_report_empty_checks_serialized_as_array() {
        let report = DoctorReport::baseline("z:empty-checks");
        let json = serde_json::to_value(&report).unwrap();
        assert!(json["checks"].as_array().unwrap().is_empty());
    }

    #[test]
    fn doctor_report_multiple_checks_count_preserved() {
        let mut report = DoctorReport::baseline("z:multi");
        for i in 0u64..5 {
            report.checks.push(CheckResult {
                name: format!("check_{i}"),
                connector_id: None,
                code: None,
                status: CheckStatus::Ok,
                severity: CheckSeverity::Info,
                message: format!("msg_{i}"),
                repair_hints: Vec::new(),
            });
        }
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["checks"].as_array().unwrap().len(), 5);
    }

    // ── NEW: overall_status_from_self_checks edge cases ──

    #[test]
    fn overall_status_single_ok() {
        let checks = [ConnectorSelfCheck {
            connector_id: fixture_connector_id("sole"),
            report: SelfCheckReport::ok(),
        }];
        assert_eq!(overall_status_from_self_checks(&checks), OverallStatus::Ok);
    }

    #[test]
    fn overall_status_single_degraded() {
        let checks = [ConnectorSelfCheck {
            connector_id: fixture_connector_id("sole"),
            report: SelfCheckReport::degraded("deg", "degraded"),
        }];
        assert_eq!(
            overall_status_from_self_checks(&checks),
            OverallStatus::Warn
        );
    }

    #[test]
    fn overall_status_single_failed() {
        let checks = [ConnectorSelfCheck {
            connector_id: fixture_connector_id("sole"),
            report: SelfCheckReport::failed("err", "failed"),
        }];
        assert_eq!(
            overall_status_from_self_checks(&checks),
            OverallStatus::Fail
        );
    }

    #[test]
    fn overall_status_fail_first_entry() {
        let checks = [
            ConnectorSelfCheck {
                connector_id: fixture_connector_id("first"),
                report: SelfCheckReport::failed("err", "failed"),
            },
            ConnectorSelfCheck {
                connector_id: fixture_connector_id("second"),
                report: SelfCheckReport::ok(),
            },
        ];
        assert_eq!(
            overall_status_from_self_checks(&checks),
            OverallStatus::Fail
        );
    }

    #[test]
    fn overall_status_degraded_middle_entry() {
        let checks = [
            ConnectorSelfCheck {
                connector_id: fixture_connector_id("first"),
                report: SelfCheckReport::ok(),
            },
            ConnectorSelfCheck {
                connector_id: fixture_connector_id("middle"),
                report: SelfCheckReport::degraded("slow", "slow"),
            },
            ConnectorSelfCheck {
                connector_id: fixture_connector_id("last"),
                report: SelfCheckReport::ok(),
            },
        ];
        assert_eq!(
            overall_status_from_self_checks(&checks),
            OverallStatus::Warn
        );
    }

    #[test]
    fn overall_status_all_degraded() {
        let checks: Vec<ConnectorSelfCheck> = (0u64..3)
            .map(|i| ConnectorSelfCheck {
                connector_id: fixture_connector_id(format!("d{i}")),
                report: SelfCheckReport::degraded("slow", "slow"),
            })
            .collect();
        assert_eq!(
            overall_status_from_self_checks(&checks),
            OverallStatus::Warn
        );
    }

    #[test]
    fn overall_status_all_failed() {
        let checks: Vec<ConnectorSelfCheck> = (0u64..3)
            .map(|i| ConnectorSelfCheck {
                connector_id: fixture_connector_id(format!("f{i}")),
                report: SelfCheckReport::failed("err", "fail"),
            })
            .collect();
        assert_eq!(
            overall_status_from_self_checks(&checks),
            OverallStatus::Fail
        );
    }

    // ── NEW: with_self_checks overrides baseline status ──

    #[test]
    fn with_self_checks_overrides_baseline_ok_to_fail() {
        let baseline = DoctorReport::baseline("z:override");
        assert_eq!(baseline.overall_status, OverallStatus::Ok);
        let checks = vec![ConnectorSelfCheck {
            connector_id: fixture_connector_id("bad"),
            report: SelfCheckReport::failed("err", "fail"),
        }];
        let report = baseline.with_self_checks(checks);
        assert_eq!(report.overall_status, OverallStatus::Fail);
    }

    #[test]
    fn with_self_checks_overrides_baseline_ok_to_warn() {
        let baseline = DoctorReport::baseline("z:override-warn");
        let checks = vec![ConnectorSelfCheck {
            connector_id: fixture_connector_id("slow"),
            report: SelfCheckReport::degraded("lag", "high latency"),
        }];
        let report = baseline.with_self_checks(checks);
        assert_eq!(report.overall_status, OverallStatus::Warn);
    }

    #[test]
    fn with_self_checks_preserves_other_report_fields() {
        let mut baseline = DoctorReport::baseline("z:preserve");
        baseline.checkpoint.freshness = FreshnessLevel::Stale;
        baseline.degraded_mode.is_degraded = true;
        let checks = vec![ConnectorSelfCheck {
            connector_id: fixture_connector_id("c"),
            report: SelfCheckReport::ok(),
        }];
        let report = baseline.with_self_checks(checks);
        assert_eq!(report.checkpoint.freshness, FreshnessLevel::Stale);
        assert!(report.degraded_mode.is_degraded);
        assert_eq!(report.zone_id.as_str(), "z:preserve");
    }

    // ── NEW: DoctorReport clone with checks ──

    #[test]
    fn doctor_report_clone_with_checks_and_self_checks() {
        let mut report = DoctorReport::baseline("z:full-clone");
        report.checks.push(CheckResult {
            name: "mem".to_string(),
            connector_id: None,
            code: None,
            status: CheckStatus::Warn,
            severity: CheckSeverity::Warning,
            message: "low mem".to_string(),
            repair_hints: Vec::new(),
        });
        let checks = vec![ConnectorSelfCheck {
            connector_id: fixture_connector_id("sc"),
            report: SelfCheckReport::degraded("slow", "slow"),
        }];
        let report = report.with_self_checks(checks);
        let cloned = report.clone();
        assert_eq!(report.checks.len(), cloned.checks.len());
        assert_eq!(
            report.connector_self_checks.len(),
            cloned.connector_self_checks.len()
        );
        assert_eq!(report.checks[0].name, cloned.checks[0].name);
        assert_eq!(
            report.connector_self_checks[0].connector_id,
            cloned.connector_self_checks[0].connector_id
        );
    }

    // ── NEW: ConnectorSelfCheck with unsupported status ──

    #[test]
    fn connector_self_check_unsupported_report() {
        let check = ConnectorSelfCheck {
            connector_id: test_connector_id("unsup:conn:1.0.0"),
            report: SelfCheckReport::unsupported(),
        };
        assert_eq!(check.report.status, SelfCheckStatus::Unsupported);
        let json = serde_json::to_string(&check).unwrap();
        assert!(json.contains("unsupported"));
    }

    #[test]
    fn overall_status_unsupported_is_missing_health_evidence() {
        let checks = [ConnectorSelfCheck {
            connector_id: fixture_connector_id("unsup"),
            report: SelfCheckReport::unsupported(),
        }];
        assert_eq!(
            overall_status_from_self_checks(&checks),
            OverallStatus::Warn
        );
    }

    #[test]
    fn with_self_checks_derives_actionable_checks_and_recommended_actions() {
        let checks = vec![
            ConnectorSelfCheck {
                connector_id: fixture_connector_id("cfg"),
                report: SelfCheckReport::failed("schema_invalid", "config field is invalid"),
            },
            ConnectorSelfCheck {
                connector_id: fixture_connector_id("slow"),
                report: SelfCheckReport::degraded("self_check_timeout", "timed out"),
            },
        ];

        let report = DoctorReport::baseline("z:doctor").with_self_checks(checks);

        assert_eq!(report.overall_status, OverallStatus::Fail);
        assert_eq!(report.checks.len(), 2);
        assert!(report.checks.iter().any(|check| check.name == "schema"
            && check.code.as_deref() == Some("schema_invalid")
            && check.connector_id.as_ref().map(ConnectorId::as_str)
                == Some("fixture.cfg:utility:1.0.0")
            && !check.repair_hints.is_empty()));
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.name == "availability"
                    && check.code.as_deref() == Some("self_check_timeout"))
        );
        assert!(!report.recommended_actions.is_empty());
    }

    #[test]
    fn with_self_checks_deduplicates_recommended_actions() {
        let checks = vec![
            ConnectorSelfCheck {
                connector_id: fixture_connector_id("missing-a"),
                report: SelfCheckReport::failed("not_found", "missing"),
            },
            ConnectorSelfCheck {
                connector_id: fixture_connector_id("missing-b"),
                report: SelfCheckReport::failed("not_found", "missing"),
            },
        ];

        let report = DoctorReport::baseline("z:doctor").with_self_checks(checks);

        assert_eq!(report.recommended_actions.len(), 2);
        assert!(
            report
                .recommended_actions
                .iter()
                .any(|hint| hint.contains("connector is installed"))
        );
    }

    // ── NEW: SelfCheckReport reason_code and message fields ──

    #[test]
    fn self_check_ok_has_no_reason_code() {
        let report = SelfCheckReport::ok();
        assert!(report.reason_code.is_none());
        assert!(report.message.is_none());
    }

    #[test]
    fn self_check_failed_has_reason_and_message() {
        let report = SelfCheckReport::failed("auth_error", "token expired");
        assert_eq!(report.reason_code.as_deref(), Some("auth_error"));
        assert_eq!(report.message.as_deref(), Some("token expired"));
    }

    #[test]
    fn self_check_degraded_has_reason_and_message() {
        let report = SelfCheckReport::degraded("high_latency", "response time > 2s");
        assert_eq!(report.reason_code.as_deref(), Some("high_latency"));
        assert_eq!(report.message.as_deref(), Some("response time > 2s"));
    }

    // ── NEW: DoctorReport JSON structure validation ──

    #[test]
    fn doctor_report_json_has_all_top_level_keys() {
        let report = DoctorReport::baseline("z:keys");
        let json = serde_json::to_value(&report).unwrap();
        let obj = json.as_object().unwrap();
        let expected_keys = [
            "schema_version",
            "generated_at",
            "zone_id",
            "overall_status",
            "checkpoint",
            "revocation",
            "audit",
            "transport_policy",
            "store_coverage",
            "degraded_mode",
            "checks",
        ];
        for key in &expected_keys {
            assert!(obj.contains_key(*key), "missing key: {key}");
        }
    }

    #[test]
    fn doctor_report_json_no_self_checks_key_when_empty() {
        let report = DoctorReport::baseline("z:no-sc");
        let json = serde_json::to_value(&report).unwrap();
        let obj = json.as_object().unwrap();
        assert!(!obj.contains_key("connector_self_checks"));
    }

    #[test]
    fn doctor_report_json_has_self_checks_key_when_present() {
        let checks = vec![ConnectorSelfCheck {
            connector_id: fixture_connector_id("sc"),
            report: SelfCheckReport::ok(),
        }];
        let report = DoctorReport::baseline("z:with-sc").with_self_checks(checks);
        let json = serde_json::to_value(&report).unwrap();
        let obj = json.as_object().unwrap();
        assert!(obj.contains_key("connector_self_checks"));
    }

    #[test]
    fn doctor_report_json_has_recommended_actions_when_present() {
        let checks = vec![ConnectorSelfCheck {
            connector_id: fixture_connector_id("cfg"),
            report: SelfCheckReport::failed("schema_invalid", "config field is invalid"),
        }];
        let report = DoctorReport::baseline("z:with-actions").with_self_checks(checks);
        let json = serde_json::to_value(&report).unwrap();
        let obj = json.as_object().unwrap();
        assert!(obj.contains_key("recommended_actions"));
        assert!(!json["recommended_actions"].as_array().unwrap().is_empty());
    }

    // ── NEW: TransportPolicyStatus all combinations ──

    #[test]
    fn transport_policy_all_false_serialization() {
        let t = TransportPolicyStatus {
            allow_lan: false,
            allow_derp: false,
            allow_funnel: false,
        };
        let json = serde_json::to_value(&t).unwrap();
        assert_eq!(json["allow_lan"], false);
        assert_eq!(json["allow_derp"], false);
        assert_eq!(json["allow_funnel"], false);
    }

    #[test]
    fn transport_policy_only_derp_serialization() {
        let t = TransportPolicyStatus {
            allow_lan: false,
            allow_derp: true,
            allow_funnel: false,
        };
        let json = serde_json::to_value(&t).unwrap();
        assert_eq!(json["allow_lan"], false);
        assert_eq!(json["allow_derp"], true);
        assert_eq!(json["allow_funnel"], false);
    }

    #[test]
    fn transport_policy_only_funnel_serialization() {
        let t = TransportPolicyStatus {
            allow_lan: false,
            allow_derp: false,
            allow_funnel: true,
        };
        let json = serde_json::to_value(&t).unwrap();
        assert_eq!(json["allow_funnel"], true);
    }

    // ── NEW: CheckResult with empty and long strings ──

    #[test]
    fn check_result_empty_name_and_message() {
        let result = CheckResult {
            name: String::new(),
            connector_id: None,
            code: None,
            status: CheckStatus::Ok,
            severity: CheckSeverity::Info,
            message: String::new(),
            repair_hints: Vec::new(),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["name"], "");
        assert_eq!(json["message"], "");
    }

    #[test]
    fn check_result_long_message() {
        let long_msg = "x".repeat(10_000);
        let result = CheckResult {
            name: "long_check".to_string(),
            connector_id: None,
            code: None,
            status: CheckStatus::Warn,
            severity: CheckSeverity::Warning,
            message: long_msg,
            repair_hints: Vec::new(),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["message"].as_str().unwrap().len(), 10_000);
    }

    // ── NEW: DoctorReport baseline with special zone_id values ──

    #[test]
    fn baseline_report_long_zone_id() {
        let long_zone = format!("z:{}", "a".repeat(62));
        let report = DoctorReport::baseline(&long_zone);
        assert_eq!(report.zone_id.as_str(), long_zone);
    }

    #[test]
    fn baseline_report_zone_id_with_special_chars() {
        // Underscores were removed from the ZoneId charset (4728b8918) so
        // zone ids stay representable as Tailscale ACL tags; hyphens and
        // digits remain valid.
        let zone = "z:test-zone-123-prod";
        let report = DoctorReport::baseline(zone);
        assert_eq!(report.zone_id.as_str(), zone);
    }

    // ── NEW: DoctorReport generated_at is recent ──

    #[test]
    fn baseline_report_generated_at_is_recent() {
        let before = Utc::now();
        let report = DoctorReport::baseline("z:time");
        let after = Utc::now();
        assert!(report.generated_at >= before);
        assert!(report.generated_at <= after);
    }

    // ── NEW: DEFAULT_SELF_CHECK_TIMEOUT value ──

    #[test]
    fn default_self_check_timeout_is_five_seconds() {
        assert_eq!(DEFAULT_SELF_CHECK_TIMEOUT, Duration::from_secs(5));
    }

    // ── NEW: DoctorService clone ──

    #[test]
    fn doctor_service_default_timeout() {
        let registry = Arc::new(TestRegistry::always_ok());
        let service = DoctorService::new(Arc::clone(&registry));
        assert_eq!(service.self_check_timeout, Duration::from_secs(5));
    }

    // ── NEW: DoctorService custom timeout preserved ──

    #[test]
    fn doctor_service_custom_timeout_preserved() {
        let registry = Arc::new(TestRegistry::always_ok());
        let service =
            DoctorService::with_timeout(Arc::clone(&registry), Duration::from_millis(500));
        assert_eq!(service.self_check_timeout, Duration::from_millis(500));
    }

    #[test]
    fn doctor_service_zero_timeout() {
        let registry = Arc::new(TestRegistry::always_ok());
        let service = DoctorService::with_timeout(Arc::clone(&registry), Duration::ZERO);
        assert_eq!(service.self_check_timeout, Duration::ZERO);
    }

    #[test]
    fn doctor_service_large_timeout() {
        let registry = Arc::new(TestRegistry::always_ok());
        let timeout = Duration::from_secs(30);
        let service = DoctorService::with_timeout(Arc::clone(&registry), timeout);
        assert_eq!(service.self_check_timeout, timeout);
    }

    // ── NEW: Schema version format ──

    #[test]
    fn schema_version_matches_expected_format() {
        let parts: Vec<&str> = DoctorReport::SCHEMA_VERSION.split('.').collect();
        assert_eq!(parts.len(), 3);
        for part in &parts {
            assert!(part.parse::<u32>().is_ok());
        }
    }

    // ── NEW: classify_self_check keyword coverage ──

    #[test]
    fn classify_schema_via_reason_code() {
        let report = SelfCheckReport::failed("schema_error", "something went wrong");
        assert_eq!(classify_self_check(&report), "schema");
    }

    #[test]
    fn classify_schema_via_config_in_message() {
        let report = SelfCheckReport::failed("generic", "bad config entry");
        assert_eq!(classify_self_check(&report), "schema");
    }

    #[test]
    fn classify_schema_via_validation_keyword() {
        let report = SelfCheckReport::failed("check", "validation failed for field X");
        assert_eq!(classify_self_check(&report), "schema");
    }

    #[test]
    fn classify_schema_via_invalid_keyword() {
        let report = SelfCheckReport::failed("check", "invalid parameter supplied");
        assert_eq!(classify_self_check(&report), "schema");
    }

    #[test]
    fn classify_schema_via_parse_keyword() {
        let report = SelfCheckReport::failed("check", "could not parse input");
        assert_eq!(classify_self_check(&report), "schema");
    }

    #[test]
    fn classify_secrets_via_credential_keyword() {
        let report = SelfCheckReport::failed("check", "credential not found");
        assert_eq!(classify_self_check(&report), "secrets");
    }

    #[test]
    fn classify_secrets_via_token_keyword() {
        let report = SelfCheckReport::failed("check", "token expired");
        assert_eq!(classify_self_check(&report), "secrets");
    }

    #[test]
    fn classify_secrets_via_oauth_keyword() {
        let report = SelfCheckReport::failed("oauth_err", "refresh failed");
        assert_eq!(classify_self_check(&report), "secrets");
    }

    #[test]
    fn classify_secrets_via_secret_keyword() {
        let report = SelfCheckReport::failed("check", "missing secret reference");
        assert_eq!(classify_self_check(&report), "secrets");
    }

    #[test]
    fn classify_secrets_via_auth_keyword() {
        let report = SelfCheckReport::failed("auth_check", "not authorized");
        assert_eq!(classify_self_check(&report), "secrets");
    }

    #[test]
    fn classify_policy_via_policy_keyword() {
        let report = SelfCheckReport::failed("check", "policy violation detected");
        assert_eq!(classify_self_check(&report), "policy");
    }

    #[test]
    fn classify_policy_via_approval_keyword() {
        let report = SelfCheckReport::failed("check", "approval required for this action");
        assert_eq!(classify_self_check(&report), "policy");
    }

    #[test]
    fn classify_policy_via_scope_keyword() {
        let report = SelfCheckReport::failed("check", "scope insufficient");
        assert_eq!(classify_self_check(&report), "policy");
    }

    #[test]
    fn classify_policy_via_denied_keyword() {
        let report = SelfCheckReport::failed("check", "access denied");
        assert_eq!(classify_self_check(&report), "policy");
    }

    #[test]
    fn classify_policy_via_forbidden_keyword() {
        let report = SelfCheckReport::failed("check", "forbidden resource");
        assert_eq!(classify_self_check(&report), "policy");
    }

    #[test]
    fn classify_availability_via_timeout_keyword() {
        let report = SelfCheckReport::failed("check", "request timeout");
        assert_eq!(classify_self_check(&report), "availability");
    }

    #[test]
    fn classify_availability_via_not_found_keyword() {
        let report = SelfCheckReport::failed("not_found", "resource missing");
        assert_eq!(classify_self_check(&report), "availability");
    }

    #[test]
    fn classify_availability_via_offline_keyword() {
        let report = SelfCheckReport::failed("check", "service is offline");
        assert_eq!(classify_self_check(&report), "availability");
    }

    #[test]
    fn classify_availability_via_unavailable_keyword() {
        let report = SelfCheckReport::failed("check", "connector unavailable");
        assert_eq!(classify_self_check(&report), "availability");
    }

    #[test]
    fn classify_availability_via_network_keyword() {
        let report = SelfCheckReport::failed("check", "network error occurred");
        assert_eq!(classify_self_check(&report), "availability");
    }

    #[test]
    fn classify_availability_via_connection_keyword() {
        let report = SelfCheckReport::failed("check", "connection refused");
        assert_eq!(classify_self_check(&report), "availability");
    }

    #[test]
    fn classify_availability_via_missing_keyword_in_message() {
        let report = SelfCheckReport::failed("check", "dependency is missing");
        assert_eq!(classify_self_check(&report), "availability");
    }

    #[test]
    fn classify_runtime_fallback() {
        let report = SelfCheckReport::failed("unknown_err", "something unexpected broke");
        assert_eq!(classify_self_check(&report), "runtime");
    }

    #[test]
    fn classify_unsupported_status() {
        let report = SelfCheckReport::unsupported();
        assert_eq!(classify_self_check(&report), "unsupported");
    }

    #[test]
    fn classify_case_insensitive_matching() {
        let report = SelfCheckReport::failed("CHECK", "TOKEN EXPIRED");
        assert_eq!(classify_self_check(&report), "secrets");
    }

    #[test]
    fn classify_mixed_case_schema() {
        let report = SelfCheckReport::failed("Schema_Error", "Validation issue");
        assert_eq!(classify_self_check(&report), "schema");
    }

    // ── NEW: check_result_from_self_check coverage ──

    #[test]
    fn check_result_from_self_check_ok_returns_none() {
        let connector_id = fixture_connector_id("ok-conn");
        let check = ConnectorSelfCheck {
            connector_id,
            report: SelfCheckReport::ok(),
        };
        assert!(check_result_from_self_check(&check).is_none());
    }

    #[test]
    fn check_result_from_self_check_degraded_returns_warn() {
        let connector_id = fixture_connector_id("deg-conn");
        let check = ConnectorSelfCheck {
            connector_id: connector_id.clone(),
            report: SelfCheckReport::degraded("slow", "slow response"),
        };
        let result = check_result_from_self_check(&check).unwrap();
        assert_eq!(result.status, CheckStatus::Warn);
        assert_eq!(result.severity, CheckSeverity::Warning);
        assert_eq!(result.connector_id.as_ref(), Some(&connector_id));
    }

    #[test]
    fn check_result_from_self_check_failed_returns_fail_critical() {
        let connector_id = fixture_connector_id("fail-conn");
        let check = ConnectorSelfCheck {
            connector_id,
            report: SelfCheckReport::failed("err", "error happened"),
        };
        let result = check_result_from_self_check(&check).unwrap();
        assert_eq!(result.status, CheckStatus::Fail);
        assert_eq!(result.severity, CheckSeverity::Critical);
    }

    #[test]
    fn check_result_from_self_check_unsupported_returns_warn_info() {
        let connector_id = fixture_connector_id("unsup-conn");
        let check = ConnectorSelfCheck {
            connector_id,
            report: SelfCheckReport::unsupported(),
        };
        let result = check_result_from_self_check(&check).unwrap();
        assert_eq!(result.status, CheckStatus::Warn);
        assert_eq!(result.severity, CheckSeverity::Info);
        assert_eq!(result.name, "unsupported");
    }

    #[test]
    fn check_result_from_self_check_preserves_reason_code() {
        let connector_id = fixture_connector_id("code-conn");
        let check = ConnectorSelfCheck {
            connector_id,
            report: SelfCheckReport::failed("auth_expired", "token is old"),
        };
        let result = check_result_from_self_check(&check).unwrap();
        assert_eq!(result.code.as_deref(), Some("auth_expired"));
    }

    #[test]
    fn check_result_from_self_check_uses_default_message_when_none() {
        let connector_id = fixture_connector_id("no-msg");
        let check = ConnectorSelfCheck {
            connector_id,
            report: SelfCheckReport {
                status: SelfCheckStatus::Failed,
                reason_code: Some("runtime_err".to_string()),
                message: None,
                details: None,
            },
        };
        let result = check_result_from_self_check(&check).unwrap();
        assert_eq!(result.message, "connector self-check failed");
    }

    // ── NEW: default_self_check_message all variants ──

    #[test]
    fn default_message_ok() {
        assert_eq!(
            default_self_check_message(SelfCheckStatus::Ok),
            "connector self-check succeeded"
        );
    }

    #[test]
    fn default_message_degraded() {
        assert_eq!(
            default_self_check_message(SelfCheckStatus::Degraded),
            "connector self-check reported a degraded state"
        );
    }

    #[test]
    fn default_message_failed() {
        assert_eq!(
            default_self_check_message(SelfCheckStatus::Failed),
            "connector self-check failed"
        );
    }

    #[test]
    fn default_message_unsupported() {
        assert_eq!(
            default_self_check_message(SelfCheckStatus::Unsupported),
            "connector does not expose a self-check implementation"
        );
    }

    // ── NEW: repair_hints_for_self_check classification-specific hints ──

    #[test]
    fn repair_hints_schema_classification() {
        let check = ConnectorSelfCheck {
            connector_id: fixture_connector_id("cfg"),
            report: SelfCheckReport::failed("schema_err", "invalid config"),
        };
        let hints = repair_hints_for_self_check(&check);
        assert!(hints.iter().any(|h| h.contains("schema")));
        assert!(hints.iter().any(|h| h.contains("revision diff")));
    }

    #[test]
    fn repair_hints_secrets_classification() {
        let check = ConnectorSelfCheck {
            connector_id: fixture_connector_id("sec"),
            report: SelfCheckReport::failed("token_err", "token expired"),
        };
        let hints = repair_hints_for_self_check(&check);
        assert!(
            hints
                .iter()
                .any(|h| h.contains("secret") || h.contains("credential"))
        );
    }

    #[test]
    fn repair_hints_policy_classification() {
        let check = ConnectorSelfCheck {
            connector_id: fixture_connector_id("pol"),
            report: SelfCheckReport::failed("policy_err", "policy violation"),
        };
        let hints = repair_hints_for_self_check(&check);
        assert!(
            hints
                .iter()
                .any(|h| h.contains("policy") || h.contains("approval"))
        );
    }

    #[test]
    fn repair_hints_availability_generic() {
        let check = ConnectorSelfCheck {
            connector_id: fixture_connector_id("avail"),
            report: SelfCheckReport::failed("offline_err", "service is offline"),
        };
        let hints = repair_hints_for_self_check(&check);
        assert!(
            hints
                .iter()
                .any(|h| h.contains("reachability") || h.contains("availability"))
        );
    }

    #[test]
    fn repair_hints_availability_timeout_reason_code() {
        let check = ConnectorSelfCheck {
            connector_id: fixture_connector_id("timeout"),
            report: SelfCheckReport::failed("self_check_timeout", "timed out"),
        };
        let hints = repair_hints_for_self_check(&check);
        assert!(hints.iter().any(|h| h.contains("timeout")));
        assert!(
            hints
                .iter()
                .any(|h| h.contains("hung") || h.contains("overloaded"))
        );
    }

    #[test]
    fn repair_hints_availability_not_found_reason_code() {
        let check = ConnectorSelfCheck {
            connector_id: fixture_connector_id("nf"),
            report: SelfCheckReport::failed("not_found", "connector missing"),
        };
        let hints = repair_hints_for_self_check(&check);
        assert!(hints.iter().any(|h| h.contains("installed")));
        assert!(
            hints
                .iter()
                .any(|h| h.contains("discovery") || h.contains("registered"))
        );
    }

    #[test]
    fn repair_hints_availability_missing_reason_code() {
        let check = ConnectorSelfCheck {
            connector_id: fixture_connector_id("miss"),
            report: SelfCheckReport::failed("missing", "resource is missing"),
        };
        let hints = repair_hints_for_self_check(&check);
        assert!(hints.iter().any(|h| h.contains("installed")));
    }

    #[test]
    fn repair_hints_unsupported_classification() {
        let check = ConnectorSelfCheck {
            connector_id: fixture_connector_id("unsup"),
            report: SelfCheckReport::unsupported(),
        };
        let hints = repair_hints_for_self_check(&check);
        assert!(hints.iter().any(|h| h.contains("status/health")));
        assert!(hints.iter().any(|h| h.contains("unsupported")));
    }

    #[test]
    fn repair_hints_runtime_fallback() {
        let check = ConnectorSelfCheck {
            connector_id: fixture_connector_id("rt"),
            report: SelfCheckReport::failed("unknown", "something broke"),
        };
        let hints = repair_hints_for_self_check(&check);
        assert!(hints.iter().any(|h| h.contains("runtime failure")));
    }

    #[test]
    fn repair_hints_degraded_inserts_prefix_hint() {
        let check = ConnectorSelfCheck {
            connector_id: fixture_connector_id("deg"),
            report: SelfCheckReport::degraded("unknown_slow", "something slow"),
        };
        let hints = repair_hints_for_self_check(&check);
        assert!(hints[0].contains("degraded"));
    }

    #[test]
    fn repair_hints_degraded_no_duplicate_degraded_hint() {
        // When classification already contains "degraded" in a hint, no prefix inserted
        let check = ConnectorSelfCheck {
            connector_id: fixture_connector_id("deg2"),
            report: SelfCheckReport::degraded("timeout", "degraded due to slow network"),
        };
        let hints = repair_hints_for_self_check(&check);
        // The availability-timeout branch doesn't mention "degraded", so prefix IS added
        assert!(hints[0].contains("degraded"));
    }

    // ── NEW: recommended_actions_from_checks edge cases ──

    #[test]
    fn recommended_actions_empty_checks() {
        let actions = recommended_actions_from_checks(&[]);
        assert!(actions.is_empty());
    }

    #[test]
    fn recommended_actions_single_check_no_hints() {
        let check = CheckResult {
            name: "test".to_string(),
            connector_id: None,
            code: None,
            status: CheckStatus::Warn,
            severity: CheckSeverity::Warning,
            message: "warn".to_string(),
            repair_hints: Vec::new(),
        };
        let actions = recommended_actions_from_checks(&[check]);
        assert!(actions.is_empty());
    }

    #[test]
    fn recommended_actions_preserves_order() {
        let check = CheckResult {
            name: "test".to_string(),
            connector_id: None,
            code: None,
            status: CheckStatus::Fail,
            severity: CheckSeverity::Critical,
            message: "fail".to_string(),
            repair_hints: vec!["first hint".to_string(), "second hint".to_string()],
        };
        let actions = recommended_actions_from_checks(&[check]);
        assert_eq!(actions.len(), 2);
        assert_eq!(actions[0], "first hint");
        assert_eq!(actions[1], "second hint");
    }

    #[test]
    fn recommended_actions_deduplicates_across_checks() {
        let checks = vec![
            CheckResult {
                name: "a".to_string(),
                connector_id: None,
                code: None,
                status: CheckStatus::Fail,
                severity: CheckSeverity::Critical,
                message: "fail a".to_string(),
                repair_hints: vec!["shared hint".to_string(), "unique a".to_string()],
            },
            CheckResult {
                name: "b".to_string(),
                connector_id: None,
                code: None,
                status: CheckStatus::Fail,
                severity: CheckSeverity::Critical,
                message: "fail b".to_string(),
                repair_hints: vec!["shared hint".to_string(), "unique b".to_string()],
            },
        ];
        let actions = recommended_actions_from_checks(&checks);
        assert_eq!(actions.len(), 3);
        assert_eq!(actions.iter().filter(|a| *a == "shared hint").count(), 1);
    }

    // ── NEW: contains_any edge cases ──

    #[test]
    fn contains_any_empty_haystack() {
        assert!(!contains_any("", &["foo", "bar"]));
    }

    #[test]
    fn contains_any_empty_needles() {
        assert!(!contains_any("hello world", &[]));
    }

    #[test]
    fn contains_any_empty_both() {
        assert!(!contains_any("", &[]));
    }

    #[test]
    fn contains_any_substring_match() {
        assert!(contains_any("hello world", &["world"]));
    }

    #[test]
    fn contains_any_no_match() {
        assert!(!contains_any("hello world", &["xyz", "abc"]));
    }

    #[test]
    fn contains_any_first_needle_matches() {
        assert!(contains_any("hello", &["hello", "nope"]));
    }

    #[test]
    fn contains_any_last_needle_matches() {
        assert!(contains_any("hello", &["nope", "hello"]));
    }

    // ── NEW: Deserialization roundtrips ──

    #[test]
    fn overall_status_deserialize_ok() {
        let v: OverallStatus = serde_json::from_str("\"OK\"").unwrap();
        assert_eq!(v, OverallStatus::Ok);
    }

    #[test]
    fn overall_status_deserialize_warn() {
        let v: OverallStatus = serde_json::from_str("\"WARN\"").unwrap();
        assert_eq!(v, OverallStatus::Warn);
    }

    #[test]
    fn overall_status_deserialize_fail() {
        let v: OverallStatus = serde_json::from_str("\"FAIL\"").unwrap();
        assert_eq!(v, OverallStatus::Fail);
    }

    #[test]
    fn overall_status_deserialize_invalid_rejected() {
        let result = serde_json::from_str::<OverallStatus>("\"UNKNOWN\"");
        assert!(result.is_err());
    }

    #[test]
    fn check_status_deserialize_ok() {
        let v: CheckStatus = serde_json::from_str("\"OK\"").unwrap();
        assert_eq!(v, CheckStatus::Ok);
    }

    #[test]
    fn check_status_deserialize_warn() {
        let v: CheckStatus = serde_json::from_str("\"WARN\"").unwrap();
        assert_eq!(v, CheckStatus::Warn);
    }

    #[test]
    fn check_status_deserialize_fail() {
        let v: CheckStatus = serde_json::from_str("\"FAIL\"").unwrap();
        assert_eq!(v, CheckStatus::Fail);
    }

    #[test]
    fn check_status_deserialize_invalid_rejected() {
        let result = serde_json::from_str::<CheckStatus>("\"INVALID\"");
        assert!(result.is_err());
    }

    #[test]
    fn check_severity_deserialize_info() {
        let v: CheckSeverity = serde_json::from_str("\"info\"").unwrap();
        assert_eq!(v, CheckSeverity::Info);
    }

    #[test]
    fn check_severity_deserialize_warning() {
        let v: CheckSeverity = serde_json::from_str("\"warning\"").unwrap();
        assert_eq!(v, CheckSeverity::Warning);
    }

    #[test]
    fn check_severity_deserialize_critical() {
        let v: CheckSeverity = serde_json::from_str("\"critical\"").unwrap();
        assert_eq!(v, CheckSeverity::Critical);
    }

    #[test]
    fn check_severity_deserialize_invalid_rejected() {
        let result = serde_json::from_str::<CheckSeverity>("\"fatal\"");
        assert!(result.is_err());
    }

    #[test]
    fn freshness_level_deserialize_all_variants() {
        for (json_str, expected) in [
            ("\"fresh\"", FreshnessLevel::Fresh),
            ("\"stale\"", FreshnessLevel::Stale),
            ("\"too_stale\"", FreshnessLevel::TooStale),
            ("\"missing\"", FreshnessLevel::Missing),
        ] {
            let v: FreshnessLevel = serde_json::from_str(json_str).unwrap();
            assert_eq!(v, expected);
        }
    }

    #[test]
    fn freshness_level_deserialize_invalid_rejected() {
        let result = serde_json::from_str::<FreshnessLevel>("\"expired\"");
        assert!(result.is_err());
    }

    // ── NEW: CheckResult deserialization roundtrip ──

    #[test]
    fn check_result_serde_roundtrip() {
        let original = CheckResult {
            name: "roundtrip".to_string(),
            connector_id: Some(test_connector_id("rt:conn:1.0.0")),
            code: Some("rt_code".to_string()),
            status: CheckStatus::Warn,
            severity: CheckSeverity::Warning,
            message: "roundtrip msg".to_string(),
            repair_hints: vec!["hint1".to_string(), "hint2".to_string()],
        };
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: CheckResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "roundtrip");
        assert_eq!(
            deserialized.connector_id.as_ref().map(ConnectorId::as_str),
            Some("rt:conn:1.0.0")
        );
        assert_eq!(deserialized.code.as_deref(), Some("rt_code"));
        assert_eq!(deserialized.status, CheckStatus::Warn);
        assert_eq!(deserialized.severity, CheckSeverity::Warning);
        assert_eq!(deserialized.message, "roundtrip msg");
        assert_eq!(deserialized.repair_hints.len(), 2);
    }

    #[test]
    fn check_result_deserialize_without_optional_fields() {
        let json = r#"{"name":"test","status":"OK","severity":"info","message":"ok"}"#;
        let result: CheckResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.name, "test");
        assert!(result.connector_id.is_none());
        assert!(result.code.is_none());
        assert!(result.repair_hints.is_empty());
    }

    // ── NEW: DoctorReport deserialization roundtrip ──

    #[test]
    fn doctor_report_serde_full_roundtrip() {
        let checks = vec![ConnectorSelfCheck {
            connector_id: fixture_connector_id("sc-rt"),
            report: SelfCheckReport::failed("rt_err", "broken"),
        }];
        let original = DoctorReport::baseline("z:roundtrip").with_self_checks(checks);
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: DoctorReport = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.zone_id.as_str(), "z:roundtrip");
        assert_eq!(deserialized.overall_status, OverallStatus::Fail);
        assert_eq!(deserialized.connector_self_checks.len(), 1);
        assert!(!deserialized.recommended_actions.is_empty());
    }

    // ── NEW: DoctorService handle error paths ──

    #[fcp_async_core::runtime::test]
    async fn doctor_handle_invalid_connector_id_rejected() {
        let registry = Arc::new(TestRegistry::always_ok());
        let service = DoctorService::new(registry);
        let request = DoctorRequest {
            zone_id: "z:test".to_string(),
            connectors: vec![String::new()],
            self_check: true,
        };
        let result = service.handle(request).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_handle_self_check_false_ignores_connectors_list() {
        let registry = Arc::new(TestRegistry::always_fail());
        let service = DoctorService::new(registry);
        let request = DoctorRequest {
            zone_id: "z:test".to_string(),
            connectors: vec!["test.doctor:utility:1.0.0".to_string()],
            self_check: false,
        };
        let report = service.handle(request).await.unwrap();
        assert_eq!(report.overall_status, OverallStatus::Ok);
        assert!(report.connector_self_checks.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_handle_empty_connectors_with_self_check_true() {
        let registry = Arc::new(TestRegistry::always_ok());
        let service = DoctorService::new(registry);
        let request = DoctorRequest {
            zone_id: "z:test".to_string(),
            connectors: vec![],
            self_check: true,
        };
        let report = service.handle(request).await.unwrap();
        assert_eq!(report.overall_status, OverallStatus::Ok);
        assert!(report.connector_self_checks.is_empty());
    }

    // ── NEW: with_self_checks extends existing checks ──

    #[test]
    fn with_self_checks_extends_existing_checks_vec() {
        let mut report = DoctorReport::baseline("z:extend");
        report.checks.push(CheckResult {
            name: "preexisting".to_string(),
            connector_id: None,
            code: None,
            status: CheckStatus::Ok,
            severity: CheckSeverity::Info,
            message: "existed before".to_string(),
            repair_hints: Vec::new(),
        });
        let checks = vec![ConnectorSelfCheck {
            connector_id: fixture_connector_id("new"),
            report: SelfCheckReport::failed("err", "broken"),
        }];
        let report = report.with_self_checks(checks);
        // The preexisting check should still be there plus the derived one
        assert!(report.checks.len() >= 2);
        assert!(report.checks.iter().any(|c| c.name == "preexisting"));
    }

    // ── NEW: classify_self_check with no reason_code and no message ──

    #[test]
    fn classify_with_no_reason_code_and_no_message_is_runtime() {
        let report = SelfCheckReport {
            status: SelfCheckStatus::Failed,
            reason_code: None,
            message: None,
            details: None,
        };
        assert_eq!(classify_self_check(&report), "runtime");
    }

    #[test]
    fn classify_with_only_reason_code_matching() {
        let report = SelfCheckReport {
            status: SelfCheckStatus::Failed,
            reason_code: Some("secret_missing".to_string()),
            message: None,
            details: None,
        };
        assert_eq!(classify_self_check(&report), "secrets");
    }

    #[test]
    fn classify_with_only_message_matching() {
        let report = SelfCheckReport {
            status: SelfCheckStatus::Failed,
            reason_code: None,
            message: Some("policy constraint violated".to_string()),
            details: None,
        };
        assert_eq!(classify_self_check(&report), "policy");
    }

    // ── NEW: classify priority (schema > secrets > policy > availability > runtime) ──

    #[test]
    fn classify_schema_takes_priority_over_secrets() {
        // "schema" keyword matched before "token" keyword
        let report = SelfCheckReport::failed("schema", "token also mentioned");
        assert_eq!(classify_self_check(&report), "schema");
    }

    #[test]
    fn classify_secrets_takes_priority_over_policy() {
        let report = SelfCheckReport::failed("credential", "policy also mentioned");
        assert_eq!(classify_self_check(&report), "secrets");
    }

    #[test]
    fn classify_policy_takes_priority_over_availability() {
        let report = SelfCheckReport::failed("denied", "timeout also mentioned");
        // "denied" is policy, "timeout" is availability; policy wins
        assert_eq!(classify_self_check(&report), "policy");
    }

    // ── NEW: DoctorRequest serialization roundtrip ──

    #[test]
    fn doctor_request_serialize_then_deserialize() {
        let req = DoctorRequest {
            zone_id: "z:ser-deser".to_string(),
            connectors: vec!["a.b:c:1.0.0".to_string()],
            self_check: true,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: DoctorRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.zone_id, "z:ser-deser");
        assert_eq!(back.connectors.len(), 1);
        assert!(back.self_check);
    }
}
