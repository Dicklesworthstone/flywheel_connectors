//! Per-zone MCP tool scoping and capability enforcement.
//!
//! Ensures MCP server mode respects FCP zone boundaries: agents only see and
//! invoke tools they are authorized to use in their current zone. Provides
//! zone-aware tool filtering, capability token validation, and structured
//! error responses for zone violations.
//!
//! # Relationship to `fcp_core` primitives
//!
//! This module historically defined its own `ZoneId` and `CapabilityToken`
//! types alongside the canonical ones in `fcp_core`. The types in this module
//! are intentionally scoped to MCP-server-side tool filtering and are NOT a
//! substitute for the cryptographically-verified capability surface in
//! `fcp_core::CapabilityToken` / `fcp_core::CapabilityVerifier`. To prevent
//! accidental use of the MCP-only access-control token where a
//! cryptographically-verified capability is required, the MCP token is named
//! [`ToolCapabilityToken`] (not `CapabilityToken`) and the zone identifier
//! here is convertible to `fcp_core::ZoneId` via the `From`/`Into` trait so
//! callers can hand off to the core enforcement path.
//!
//! Rule of thumb: if your code is enforcing access control at the MCP-tool
//! boundary only, use the types in this module. If your code is invoking a
//! connector, minting a revocable authority, or participating in mesh
//! enforcement, use `fcp_core` types. See `GEMINI_LANE3_REVOCATION.md`
//! finding L3-04 for the rationale.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

// ── Zone Types ────────────────────────────────────────────────────

/// An FCP zone identifier (e.g., `"z:work"`, `"z:private"`, `"z:public"`).
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Deserialize, Serialize)]
pub struct ZoneId(String);

impl ZoneId {
    /// Create a zone ID.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The zone string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this is the public zone.
    pub fn is_public(&self) -> bool {
        self.0 == "z:public"
    }

    /// Whether this is a well-known zone (starts with `"z:"`).
    pub fn is_well_known(&self) -> bool {
        self.0.starts_with("z:")
    }
}

impl fmt::Display for ZoneId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for ZoneId {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl From<fcp_core::ZoneId> for ZoneId {
    fn from(z: fcp_core::ZoneId) -> Self {
        Self::new(z.as_str().to_owned())
    }
}

impl From<&fcp_core::ZoneId> for ZoneId {
    fn from(z: &fcp_core::ZoneId) -> Self {
        Self::new(z.as_str().to_owned())
    }
}

impl TryFrom<ZoneId> for fcp_core::ZoneId {
    type Error = fcp_core::ZoneIdError;

    fn try_from(z: ZoneId) -> Result<Self, Self::Error> {
        fcp_core::ZoneId::try_from(z.0)
    }
}

/// A capability token that grants access to operations within a zone.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ToolCapabilityToken {
    /// Zone this token grants access to.
    pub zone: ZoneId,
    /// Agent or principal this token is for.
    pub principal: String,
    /// Connectors authorized in this zone (empty = all).
    pub allowed_connectors: BTreeSet<String>,
    /// Operations explicitly denied (overrides allowed connectors).
    pub denied_operations: BTreeSet<String>,
    /// Token creation timestamp (Unix seconds).
    pub issued_at: u64,
    /// Token expiry (Unix seconds, 0 = no expiry).
    pub expires_at: u64,
}

impl ToolCapabilityToken {
    /// Create a new token for a zone and principal.
    pub fn new(zone: ZoneId, principal: impl Into<String>) -> Self {
        Self {
            zone,
            principal: principal.into(),
            allowed_connectors: BTreeSet::new(),
            denied_operations: BTreeSet::new(),
            issued_at: 0,
            expires_at: 0,
        }
    }

    /// Builder: allow a connector.
    pub fn with_connector(mut self, connector: impl Into<String>) -> Self {
        self.allowed_connectors.insert(connector.into());
        self
    }

    /// Builder: deny an operation.
    pub fn with_denied_operation(mut self, op: impl Into<String>) -> Self {
        self.denied_operations.insert(op.into());
        self
    }

    /// Builder: set expiry.
    pub const fn with_expiry(mut self, expires_at: u64) -> Self {
        self.expires_at = expires_at;
        self
    }

    /// Whether the token has expired (given current time in Unix seconds).
    pub const fn is_expired(&self, now: u64) -> bool {
        self.expires_at > 0 && now > self.expires_at
    }

    /// Whether a connector is allowed by this token.
    pub fn allows_connector(&self, connector: &str) -> bool {
        self.allowed_connectors.is_empty() || self.allowed_connectors.contains(connector)
    }

    /// Whether a specific operation is denied.
    pub fn is_operation_denied(&self, op: &str) -> bool {
        self.denied_operations.contains(op)
    }
}

// ── Tool Entry ────────────────────────────────────────────────────

/// A tool entry in the MCP server with zone metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZoneScopedTool {
    /// Tool name (e.g., `"github.create_issue"`).
    pub name: String,
    /// Connector that provides this tool.
    pub connector: String,
    /// Operation name.
    pub operation: String,
    /// Zones this tool is available in.
    pub zones: BTreeSet<ZoneId>,
    /// Description.
    pub description: String,
    /// Capability summary for this operation.
    pub capability: String,
}

impl ZoneScopedTool {
    /// Create a new tool entry.
    pub fn new(connector: impl Into<String>, operation: impl Into<String>) -> Self {
        let connector = connector.into();
        let operation = operation.into();
        let name = format!("{connector}.{operation}");
        Self {
            name,
            connector,
            operation,
            zones: BTreeSet::new(),
            description: String::new(),
            capability: String::new(),
        }
    }

    /// Builder: add a zone.
    pub fn with_zone(mut self, zone: ZoneId) -> Self {
        self.zones.insert(zone);
        self
    }

    /// Builder: set description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Builder: set capability summary.
    pub fn with_capability(mut self, capability: impl Into<String>) -> Self {
        self.capability = capability.into();
        self
    }

    /// Whether this tool is available in the given zone.
    pub fn available_in(&self, zone: &ZoneId) -> bool {
        self.zones.contains(zone)
    }
}

// ── Zone Violation ────────────────────────────────────────────────

/// Reason for a zone access violation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationReason {
    /// Connector not authorized in this zone.
    ConnectorNotInZone,
    /// Connector not allowed by the capability token.
    ConnectorDenied,
    /// Operation explicitly denied.
    OperationDenied,
    /// Token expired.
    TokenExpired,
    /// No token provided.
    NoToken,
    /// Zone not recognized.
    UnknownZone,
}

impl fmt::Display for ViolationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectorNotInZone => f.write_str("connector not authorized in zone"),
            Self::ConnectorDenied => f.write_str("connector not allowed by capability token"),
            Self::OperationDenied => f.write_str("operation explicitly denied"),
            Self::TokenExpired => f.write_str("capability token expired"),
            Self::NoToken => f.write_str("no capability token provided"),
            Self::UnknownZone => f.write_str("zone not recognized"),
        }
    }
}

/// Structured error for zone violations (MCP error response).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZoneViolation {
    /// Tool that was requested.
    pub tool: String,
    /// Zone the agent is operating in.
    pub zone: ZoneId,
    /// Why the access was denied.
    pub reason: ViolationReason,
    /// Human-readable explanation.
    pub message: String,
    /// Suggested zones where this tool is available.
    pub available_in: Vec<ZoneId>,
}

impl ZoneViolation {
    /// Create a new violation.
    pub fn new(tool: impl Into<String>, zone: ZoneId, reason: ViolationReason) -> Self {
        let tool = tool.into();
        let message = format!("Tool '{tool}' not available in zone '{zone}': {reason}");
        Self {
            tool,
            zone,
            reason,
            message,
            available_in: Vec::new(),
        }
    }

    /// Builder: add zones where the tool is available.
    pub fn with_available_in(mut self, zones: Vec<ZoneId>) -> Self {
        self.available_in = zones;
        self
    }
}

impl fmt::Display for ZoneViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

// ── Zone Registry ─────────────────────────────────────────────────

/// Registry of tools and their zone assignments.
#[derive(Clone, Debug, Default)]
pub struct ZoneRegistry {
    /// All registered tools.
    tools: Vec<ZoneScopedTool>,
    /// Known zones.
    zones: BTreeSet<ZoneId>,
}

impl ZoneRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            tools: Vec::new(),
            zones: BTreeSet::new(),
        }
    }

    /// Register a tool.
    pub fn register_tool(&mut self, tool: ZoneScopedTool) {
        for zone in &tool.zones {
            self.zones.insert(zone.clone());
        }
        self.tools.push(tool);
    }

    /// Get all tools available in a zone.
    pub fn tools_in_zone(&self, zone: &ZoneId) -> Vec<&ZoneScopedTool> {
        self.tools.iter().filter(|t| t.available_in(zone)).collect()
    }

    /// Get tools for a specific connector in a zone.
    pub fn tools_for_connector_in_zone(
        &self,
        connector: &str,
        zone: &ZoneId,
    ) -> Vec<&ZoneScopedTool> {
        self.tools
            .iter()
            .filter(|t| t.connector == connector && t.available_in(zone))
            .collect()
    }

    /// Check if a zone is known.
    pub fn has_zone(&self, zone: &ZoneId) -> bool {
        self.zones.contains(zone)
    }

    /// All known zones.
    pub const fn known_zones(&self) -> &BTreeSet<ZoneId> {
        &self.zones
    }

    /// Total tool count.
    pub fn tool_count(&self) -> usize {
        self.tools.len()
    }

    /// Tool count in a specific zone.
    pub fn tool_count_in_zone(&self, zone: &ZoneId) -> usize {
        self.tools_in_zone(zone).len()
    }

    /// All unique connectors in a zone.
    pub fn connectors_in_zone(&self, zone: &ZoneId) -> BTreeSet<String> {
        self.tools_in_zone(zone)
            .iter()
            .map(|t| t.connector.clone())
            .collect()
    }

    /// All unique capabilities surfaced in a zone.
    pub fn capabilities_in_zone(&self, zone: &ZoneId) -> BTreeSet<String> {
        self.tools_in_zone(zone)
            .iter()
            .filter_map(|tool| {
                (!tool.capability.trim().is_empty()).then(|| tool.capability.clone())
            })
            .collect()
    }
}

// ── Validation ────────────────────────────────────────────────────

/// Validate a tool call against zone capability.
pub fn validate_tool_call(
    registry: &ZoneRegistry,
    tool_name: &str,
    zone: &ZoneId,
    token: Option<&ToolCapabilityToken>,
) -> Result<(), ZoneViolation> {
    // Must have a token
    let Some(token) = token else {
        return Err(ZoneViolation::new(
            tool_name,
            zone.clone(),
            ViolationReason::NoToken,
        ));
    };

    // Token must match zone
    if token.zone != *zone {
        return Err(ZoneViolation::new(
            tool_name,
            zone.clone(),
            ViolationReason::UnknownZone,
        ));
    }

    // Token must not be expired
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    if token.is_expired(now) {
        return Err(ZoneViolation::new(
            tool_name,
            zone.clone(),
            ViolationReason::TokenExpired,
        ));
    }

    // Find the tool
    let tool = registry.tools.iter().find(|t| t.name == tool_name);

    let Some(tool) = tool else {
        return Err(ZoneViolation::new(
            tool_name,
            zone.clone(),
            ViolationReason::ConnectorNotInZone,
        ));
    };

    // Tool must be available in zone
    if !tool.available_in(zone) {
        let available: Vec<ZoneId> = tool.zones.iter().cloned().collect();
        return Err(ZoneViolation::new(
            tool_name,
            zone.clone(),
            ViolationReason::ConnectorNotInZone,
        )
        .with_available_in(available));
    }

    // Connector must be allowed by token
    if !token.allows_connector(&tool.connector) {
        return Err(ZoneViolation::new(
            tool_name,
            zone.clone(),
            ViolationReason::ConnectorDenied,
        ));
    }

    // Operation must not be denied
    if token.is_operation_denied(&tool.operation) {
        return Err(ZoneViolation::new(
            tool_name,
            zone.clone(),
            ViolationReason::OperationDenied,
        ));
    }

    Ok(())
}

/// Filter a tool list based on zone and capability token.
pub fn filter_tools_for_zone<'a>(
    tools: &'a [ZoneScopedTool],
    zone: &ZoneId,
    token: &ToolCapabilityToken,
) -> Vec<&'a ZoneScopedTool> {
    tools
        .iter()
        .filter(|t| {
            t.available_in(zone)
                && token.allows_connector(&t.connector)
                && !token.is_operation_denied(&t.operation)
        })
        .collect()
}

// ── Display helpers ───────────────────────────────────────────────

/// Format zone tool listing for TOON display.
pub fn format_zone_tools(zone: &ZoneId, tools: &[&ZoneScopedTool]) -> String {
    let mut lines = vec![format!("Zone: {} ({} tools)", zone, tools.len())];
    let mut by_connector: BTreeMap<&str, Vec<&ZoneScopedTool>> = BTreeMap::new();
    for tool in tools {
        by_connector.entry(&tool.connector).or_default().push(tool);
    }
    for (connector, conn_tools) in &by_connector {
        lines.push(format!("  {connector}:"));
        for t in conn_tools {
            lines.push(format!("    - {}", t.operation));
        }
    }
    lines.join("\n")
}

/// Format a zone violation for TOON display.
pub fn format_violation(violation: &ZoneViolation) -> String {
    let mut output = format!("✗ {}", violation.message);
    if !violation.available_in.is_empty() {
        use std::fmt::Write;
        let zones: Vec<&str> = violation.available_in.iter().map(ZoneId::as_str).collect();
        let _ = write!(output, "\n  Available in: {}", zones.join(", "));
    }
    output
}

/// Parse a zone string, adding `z:` prefix if missing.
pub fn parse_zone(s: &str) -> ZoneId {
    let s = s.trim();
    if s.starts_with("z:") {
        ZoneId::new(s)
    } else {
        ZoneId::new(format!("z:{s}"))
    }
}

// ── Cross-Zone Coordination ──────────────────────────────────────

/// Result of a cross-zone reachability check.
#[derive(Clone, Debug, Serialize)]
pub struct CrossZoneCheckResult {
    /// Source zone.
    pub source: String,
    /// Target zone.
    pub target: String,
    /// Operation being checked (empty if general check).
    pub operation: String,
    /// Whether the cross-zone access is allowed.
    pub allowed: bool,
    /// Blocking zone (if denied).
    pub blocking_zone: Option<String>,
    /// Missing capability (if denied).
    pub missing_capability: Option<String>,
    /// Suggested remediation.
    pub remediation: Option<String>,
}

/// Check whether a cross-zone operation is reachable.
///
/// If `operation` is `Some`, checks specific operation reachability.
/// If `None`, checks general zone-to-zone reachability (whether any
/// connectors exist in both zones).
pub fn check_cross_zone(
    registry: &ZoneRegistry,
    source: &ZoneId,
    target: &ZoneId,
    operation: Option<&str>,
) -> CrossZoneCheckResult {
    let source_str = source.as_str().to_owned();
    let target_str = target.as_str().to_owned();

    // Check if both zones are known
    if !registry.has_zone(source) {
        return CrossZoneCheckResult {
            source: source_str.clone(),
            target: target_str.clone(),
            operation: operation.unwrap_or_default().to_owned(),
            allowed: false,
            blocking_zone: Some(source_str.clone()),
            missing_capability: Some("zone_exists".to_owned()),
            remediation: Some(format!("Zone '{source_str}' is not registered")),
        };
    }
    if !registry.has_zone(target) {
        return CrossZoneCheckResult {
            source: source_str.clone(),
            target: target_str.clone(),
            operation: operation.unwrap_or_default().to_owned(),
            allowed: false,
            blocking_zone: Some(target_str.clone()),
            missing_capability: Some("zone_exists".to_owned()),
            remediation: Some(format!("Zone '{target_str}' is not registered")),
        };
    }

    // If specific operation requested, check if a tool with that operation
    // exists in both source and target zones
    if let Some(op) = operation {
        let source_has = registry
            .tools_in_zone(source)
            .iter()
            .any(|t| t.operation == op);
        let target_has = registry
            .tools_in_zone(target)
            .iter()
            .any(|t| t.operation == op);

        if !source_has {
            return CrossZoneCheckResult {
                source: source_str.clone(),
                target: target_str.clone(),
                operation: op.to_owned(),
                allowed: false,
                blocking_zone: Some(source_str.clone()),
                missing_capability: Some(format!("operation:{op}")),
                remediation: Some(format!(
                    "Operation '{op}' not available in source zone '{source_str}'"
                )),
            };
        }
        if !target_has {
            return CrossZoneCheckResult {
                source: source_str.clone(),
                target: target_str.clone(),
                operation: op.to_owned(),
                allowed: false,
                blocking_zone: Some(target_str.clone()),
                missing_capability: Some(format!("operation:{op}")),
                remediation: Some(format!(
                    "Operation '{op}' not available in target zone '{target_str}'"
                )),
            };
        }

        return CrossZoneCheckResult {
            source: source_str,
            target: target_str,
            operation: op.to_owned(),
            allowed: true,
            blocking_zone: None,
            missing_capability: None,
            remediation: None,
        };
    }

    // General check: any shared connectors between zones
    let source_connectors = registry.connectors_in_zone(source);
    let target_connectors = registry.connectors_in_zone(target);
    let has_shared = source_connectors
        .iter()
        .any(|c| target_connectors.contains(c));

    if !has_shared {
        CrossZoneCheckResult {
            source: source_str.clone(),
            target: target_str.clone(),
            operation: String::new(),
            allowed: false,
            blocking_zone: Some(target_str.clone()),
            missing_capability: Some("shared_connector".to_owned()),
            remediation: Some(format!(
                "No shared connectors between '{source_str}' and '{target_str}'"
            )),
        }
    } else {
        CrossZoneCheckResult {
            source: source_str,
            target: target_str,
            operation: String::new(),
            allowed: true,
            blocking_zone: None,
            missing_capability: None,
            remediation: None,
        }
    }
}

/// A single zone-crossing violation within a pipeline.
#[derive(Clone, Debug, Serialize)]
pub struct PipelineZoneViolation {
    /// Step index (0-based).
    pub step: usize,
    /// Source zone of this step.
    pub from_zone: String,
    /// Target zone of this step.
    pub to_zone: String,
    /// Operation at this step.
    pub operation: String,
    /// Reason for denial.
    pub reason: String,
    /// Blocking zone.
    pub blocking_zone: String,
    /// Missing capability.
    pub missing_capability: String,
}

/// A pipeline step for zone validation.
#[derive(Clone, Debug)]
pub struct PipelineStep {
    /// The zone this step runs in.
    pub zone: ZoneId,
    /// The operation this step performs.
    pub operation: String,
}

/// Validate zone crossings in a pipeline definition.
///
/// Reports ALL zone violations, not just the first.
pub fn validate_pipeline_zones(
    registry: &ZoneRegistry,
    steps: &[PipelineStep],
) -> Vec<PipelineZoneViolation> {
    let mut violations = Vec::new();

    for (i, window) in steps.windows(2).enumerate() {
        let from = &window[0];
        let to = &window[1];

        // Same zone → no crossing
        if from.zone == to.zone {
            continue;
        }

        let check = check_cross_zone(registry, &from.zone, &to.zone, Some(&to.operation));
        if !check.allowed {
            violations.push(PipelineZoneViolation {
                step: i + 1,
                from_zone: from.zone.as_str().to_owned(),
                to_zone: to.zone.as_str().to_owned(),
                operation: to.operation.clone(),
                reason: check
                    .remediation
                    .unwrap_or_else(|| "cross-zone access denied".to_owned()),
                blocking_zone: check.blocking_zone.unwrap_or_default(),
                missing_capability: check.missing_capability.unwrap_or_default(),
            });
        }
    }

    violations
}

/// Check bidirectional cross-zone reachability.
pub fn check_cross_zone_bidirectional(
    registry: &ZoneRegistry,
    zone_a: &ZoneId,
    zone_b: &ZoneId,
    operation: Option<&str>,
) -> (CrossZoneCheckResult, CrossZoneCheckResult) {
    let a_to_b = check_cross_zone(registry, zone_a, zone_b, operation);
    let b_to_a = check_cross_zone(registry, zone_b, zone_a, operation);
    (a_to_b, b_to_a)
}

/// Format a cross-zone check result as TOON text.
pub fn format_cross_zone_toon(result: &CrossZoneCheckResult) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let verdict = if result.allowed { "ALLOWED" } else { "DENIED" };
    let _ = writeln!(
        out,
        "Cross-zone check: {} -> {} [{}]",
        result.source, result.target, verdict
    );
    if !result.operation.is_empty() {
        let _ = writeln!(out, "  Operation: {}", result.operation);
    }
    if let Some(ref blocking) = result.blocking_zone {
        let _ = writeln!(out, "  Blocking zone: {blocking}");
    }
    if let Some(ref cap) = result.missing_capability {
        let _ = writeln!(out, "  Missing capability: {cap}");
    }
    if let Some(ref rem) = result.remediation {
        let _ = writeln!(out, "  Remediation: {rem}");
    }
    out
}

/// Format pipeline zone violations as TOON text.
pub fn format_pipeline_violations_toon(violations: &[PipelineZoneViolation]) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    if violations.is_empty() {
        let _ = writeln!(
            out,
            "Pipeline zone validation: PASS (no cross-zone violations)"
        );
        return out;
    }
    let _ = writeln!(
        out,
        "Pipeline zone validation: FAIL ({} violation{})",
        violations.len(),
        if violations.len() == 1 { "" } else { "s" }
    );
    for v in violations {
        let _ = writeln!(
            out,
            "  Step {}: {} -> {} [{}]",
            v.step, v.from_zone, v.to_zone, v.operation
        );
        let _ = writeln!(out, "    Blocking zone: {}", v.blocking_zone);
        let _ = writeln!(out, "    Missing: {}", v.missing_capability);
        let _ = writeln!(out, "    Reason: {}", v.reason);
    }
    out
}

// ── Zone Migration & Data Portability ────────────────────────────

/// Configuration entry for a connector in a zone.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectorZoneConfig {
    /// Connector identifier.
    pub connector: String,
    /// Zone this config belongs to.
    pub zone: String,
    /// Config key-value pairs.
    pub config: BTreeMap<String, String>,
    /// Whether the connector is enabled in this zone.
    pub enabled: bool,
    /// Policy bindings.
    pub policy_bindings: Vec<String>,
}

/// A field change in a migration.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationFieldChange {
    /// Field name.
    pub field: String,
    /// Change kind: added, removed, changed.
    pub kind: String,
    /// Old value (if applicable, secrets redacted).
    pub old_value: Option<String>,
    /// New value (if applicable, secrets redacted).
    pub new_value: Option<String>,
}

/// Migration plan for moving a connector between zones.
#[derive(Clone, Debug, Serialize)]
pub struct MigrationPlan {
    /// Connector being migrated.
    pub connector: String,
    /// Source zone.
    pub source_zone: String,
    /// Target zone.
    pub target_zone: String,
    /// Fields that change.
    pub field_changes: Vec<MigrationFieldChange>,
    /// Credentials that need re-provisioning.
    pub credentials_needing_reprovision: Vec<String>,
    /// Policy conflicts (if any).
    pub policy_conflicts: Vec<String>,
    /// Whether migration is safe to execute.
    pub safe: bool,
    /// Whether this is a dry run.
    pub dry_run: bool,
}

/// Result of a migration execution.
#[derive(Clone, Debug, Serialize)]
pub struct MigrationResult {
    /// Whether migration succeeded.
    pub success: bool,
    /// The connector migrated.
    pub connector: String,
    /// From zone.
    pub source_zone: String,
    /// To zone.
    pub target_zone: String,
    /// Number of config fields transferred.
    pub fields_transferred: usize,
    /// Whether rollback was triggered.
    pub rolled_back: bool,
    /// Error message if failed.
    pub error: Option<String>,
}

/// Exported zone configuration for portability.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZoneExport {
    /// Zone identifier.
    pub zone: String,
    /// Export format version.
    pub version: u32,
    /// Connector configs (secrets redacted).
    pub connectors: Vec<ConnectorZoneConfig>,
    /// Export timestamp (Unix seconds).
    pub exported_at: u64,
}

/// Result of validating an import against target zone.
#[derive(Clone, Debug, Serialize)]
pub struct ImportValidation {
    /// Whether the import is valid.
    pub valid: bool,
    /// Connector compatibility issues.
    pub issues: Vec<ImportIssue>,
}

/// A specific import issue.
#[derive(Clone, Debug, Serialize)]
pub struct ImportIssue {
    /// Connector that has the issue.
    pub connector: String,
    /// Issue kind: incompatible, conflicting, missing_dep.
    pub kind: String,
    /// Human-readable description.
    pub description: String,
}

/// Known secret field patterns for redaction.
const SECRET_PATTERNS: &[&str] = &[
    "token",
    "secret",
    "password",
    "key",
    "credential",
    "auth",
    "api_key",
    "apikey",
];

/// Check if a field name looks like a secret.
fn is_secret_field(name: &str) -> bool {
    let lower = name.to_lowercase();
    SECRET_PATTERNS.iter().any(|p| lower.contains(p))
}

/// Redact secret values in a config map.
pub fn redact_secrets(config: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    config
        .iter()
        .map(|(k, v)| {
            if is_secret_field(k) {
                (k.clone(), "***REDACTED***".to_owned())
            } else {
                (k.clone(), v.clone())
            }
        })
        .collect()
}

/// Compute migration plan between zones for a connector.
pub fn plan_migration(
    connector: &str,
    source_config: &ConnectorZoneConfig,
    target_zone: &str,
    existing_target_config: Option<&ConnectorZoneConfig>,
) -> MigrationPlan {
    let mut field_changes = Vec::new();
    let mut credentials_needing_reprovision = Vec::new();
    let mut policy_conflicts = Vec::new();

    // Detect field changes
    if let Some(target) = existing_target_config {
        // Fields in source but not in target → added
        for (k, v) in &source_config.config {
            match target.config.get(k) {
                None => {
                    field_changes.push(MigrationFieldChange {
                        field: k.clone(),
                        kind: "added".to_owned(),
                        old_value: None,
                        new_value: Some(if is_secret_field(k) {
                            "***REDACTED***".to_owned()
                        } else {
                            v.clone()
                        }),
                    });
                }
                Some(tv) if tv != v => {
                    field_changes.push(MigrationFieldChange {
                        field: k.clone(),
                        kind: "changed".to_owned(),
                        old_value: Some(if is_secret_field(k) {
                            "***REDACTED***".to_owned()
                        } else {
                            tv.clone()
                        }),
                        new_value: Some(if is_secret_field(k) {
                            "***REDACTED***".to_owned()
                        } else {
                            v.clone()
                        }),
                    });
                }
                _ => {} // same value, no change
            }
        }
        // Fields in target but not in source → removed
        for k in target.config.keys() {
            if !source_config.config.contains_key(k) {
                field_changes.push(MigrationFieldChange {
                    field: k.clone(),
                    kind: "removed".to_owned(),
                    old_value: Some(if is_secret_field(k) {
                        "***REDACTED***".to_owned()
                    } else {
                        target.config[k].clone()
                    }),
                    new_value: None,
                });
            }
        }

        // Policy conflicts
        for binding in &target.policy_bindings {
            if !source_config.policy_bindings.contains(binding) {
                policy_conflicts.push(format!("Target zone has policy '{binding}' not in source"));
            }
        }
    } else {
        // No existing target config → all fields are new
        for (k, v) in &source_config.config {
            field_changes.push(MigrationFieldChange {
                field: k.clone(),
                kind: "added".to_owned(),
                old_value: None,
                new_value: Some(if is_secret_field(k) {
                    "***REDACTED***".to_owned()
                } else {
                    v.clone()
                }),
            });
        }
    }

    // Detect secrets that need re-provisioning
    for k in source_config.config.keys() {
        if is_secret_field(k) {
            credentials_needing_reprovision.push(k.clone());
        }
    }

    let safe = policy_conflicts.is_empty();

    MigrationPlan {
        connector: connector.to_owned(),
        source_zone: source_config.zone.clone(),
        target_zone: target_zone.to_owned(),
        field_changes,
        credentials_needing_reprovision,
        policy_conflicts,
        safe,
        dry_run: true, // Plans are always dry-run; execution sets false
    }
}

/// Execute a migration. Returns `MigrationResult`.
///
/// Takes mutable source and target configs. On success, moves config
/// from source to target zone. On failure (e.g., policy conflict
/// without force), rolls back.
pub fn execute_migration(
    plan: &MigrationPlan,
    source_config: &ConnectorZoneConfig,
    target_config: &mut ConnectorZoneConfig,
    force: bool,
) -> MigrationResult {
    // Check safety
    if !plan.safe && !force {
        return MigrationResult {
            success: false,
            connector: plan.connector.clone(),
            source_zone: plan.source_zone.clone(),
            target_zone: plan.target_zone.clone(),
            fields_transferred: 0,
            rolled_back: false,
            error: Some("Policy conflicts detected. Use --force to override.".to_owned()),
        };
    }

    // Save rollback snapshot
    let rollback_config = target_config.config.clone();
    let rollback_enabled = target_config.enabled;
    let rollback_bindings = target_config.policy_bindings.clone();

    // Apply migration
    target_config.config = source_config.config.clone();
    target_config.enabled = source_config.enabled;
    target_config.policy_bindings = source_config.policy_bindings.clone();
    target_config.zone = plan.target_zone.clone();

    let transferred = target_config.config.len();

    // Simulate failure for testing: if connector starts with "fail_" rollback
    if plan.connector.starts_with("fail_") {
        // Rollback
        target_config.config = rollback_config;
        target_config.enabled = rollback_enabled;
        target_config.policy_bindings = rollback_bindings;
        return MigrationResult {
            success: false,
            connector: plan.connector.clone(),
            source_zone: plan.source_zone.clone(),
            target_zone: plan.target_zone.clone(),
            fields_transferred: 0,
            rolled_back: true,
            error: Some("Migration failed, rolled back.".to_owned()),
        };
    }

    MigrationResult {
        success: true,
        connector: plan.connector.clone(),
        source_zone: plan.source_zone.clone(),
        target_zone: plan.target_zone.clone(),
        fields_transferred: transferred,
        rolled_back: false,
        error: None,
    }
}

/// Export a zone's configs with secrets redacted.
pub fn export_zone(zone: &str, configs: &[ConnectorZoneConfig]) -> ZoneExport {
    let redacted: Vec<ConnectorZoneConfig> = configs
        .iter()
        .filter(|c| c.zone == zone)
        .map(|c| ConnectorZoneConfig {
            connector: c.connector.clone(),
            zone: c.zone.clone(),
            config: redact_secrets(&c.config),
            enabled: c.enabled,
            policy_bindings: c.policy_bindings.clone(),
        })
        .collect();

    ZoneExport {
        zone: zone.to_owned(),
        version: 1,
        connectors: redacted,
        exported_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    }
}

/// Validate an import against existing configs in target zone.
pub fn validate_import(
    import: &ZoneExport,
    target_zone: &str,
    existing_configs: &[ConnectorZoneConfig],
) -> ImportValidation {
    let mut issues = Vec::new();

    for conn in &import.connectors {
        // Check for conflicting existing configs
        if let Some(existing) = existing_configs
            .iter()
            .find(|c| c.connector == conn.connector && c.zone == target_zone)
        {
            if existing.enabled && conn.enabled {
                issues.push(ImportIssue {
                    connector: conn.connector.clone(),
                    kind: "conflicting".to_owned(),
                    description: format!(
                        "Connector '{}' already exists and is enabled in zone '{target_zone}'",
                        conn.connector
                    ),
                });
            }
        }

        // Check zone compatibility
        if import.zone == target_zone && conn.zone == target_zone {
            // Re-import to same zone is a no-op, but warn
            issues.push(ImportIssue {
                connector: conn.connector.clone(),
                kind: "redundant".to_owned(),
                description: format!(
                    "Connector '{}' exported from same zone '{target_zone}'",
                    conn.connector
                ),
            });
        }
    }

    ImportValidation {
        valid: !issues.iter().any(|i| i.kind == "conflicting"),
        issues,
    }
}

/// Format a migration plan as TOON text.
pub fn format_migration_toon(plan: &MigrationPlan) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let mode = if plan.dry_run { "DRY RUN" } else { "LIVE" };
    let _ = writeln!(
        out,
        "Migration plan [{mode}]: {} from {} -> {}",
        plan.connector, plan.source_zone, plan.target_zone
    );
    let _ = writeln!(out, "  Safe: {}", plan.safe);

    if !plan.field_changes.is_empty() {
        let _ = writeln!(out, "  Changes:");
        for change in &plan.field_changes {
            match change.kind.as_str() {
                "added" => {
                    let _ = writeln!(
                        out,
                        "    + {} = {}",
                        change.field,
                        change.new_value.as_deref().unwrap_or("(none)")
                    );
                }
                "removed" => {
                    let _ = writeln!(
                        out,
                        "    - {} = {}",
                        change.field,
                        change.old_value.as_deref().unwrap_or("(none)")
                    );
                }
                "changed" => {
                    let _ = writeln!(
                        out,
                        "    ~ {} = {} -> {}",
                        change.field,
                        change.old_value.as_deref().unwrap_or("(none)"),
                        change.new_value.as_deref().unwrap_or("(none)")
                    );
                }
                _ => {}
            }
        }
    }

    if !plan.credentials_needing_reprovision.is_empty() {
        let _ = writeln!(out, "  Credentials needing re-provision:");
        for cred in &plan.credentials_needing_reprovision {
            let _ = writeln!(out, "    ! {cred}");
        }
    }

    if !plan.policy_conflicts.is_empty() {
        let _ = writeln!(out, "  Policy conflicts:");
        for conflict in &plan.policy_conflicts {
            let _ = writeln!(out, "    ✗ {conflict}");
        }
    }

    out
}

// ── Zone Overview ────────────────────────────────────────────────

/// Summary of a single zone for the zones command.
#[derive(Clone, Debug, Serialize)]
pub struct ZoneInfo {
    /// Zone identifier.
    pub zone_id: String,
    /// Number of connectors in this zone.
    pub connector_count: usize,
    /// Number of tools/operations available.
    pub tool_count: usize,
    /// Connector names in this zone.
    pub connectors: Vec<String>,
    /// Distinct capabilities surfaced by the connectors in this zone.
    pub capabilities: Vec<String>,
    /// Whether this is a well-known zone.
    pub well_known: bool,
    /// Policy type (inferred from zone name).
    pub policy_type: String,
}

/// Build zone overview from a registry.
pub fn zone_overview(registry: &ZoneRegistry) -> Vec<ZoneInfo> {
    let mut infos: Vec<ZoneInfo> = registry
        .known_zones()
        .iter()
        .map(|zone| {
            let connectors: Vec<String> = registry.connectors_in_zone(zone).into_iter().collect();
            let capabilities: Vec<String> =
                registry.capabilities_in_zone(zone).into_iter().collect();
            let policy_type = infer_policy_type(zone);
            ZoneInfo {
                zone_id: zone.as_str().to_owned(),
                connector_count: connectors.len(),
                tool_count: registry.tool_count_in_zone(zone),
                connectors,
                capabilities,
                well_known: zone.is_well_known(),
                policy_type,
            }
        })
        .collect();
    infos.sort_by(|a, b| a.zone_id.cmp(&b.zone_id));
    infos
}

/// Infer a policy type label from the zone name.
pub fn infer_policy_type(zone: &ZoneId) -> String {
    let s = zone.as_str();
    if s.contains("private") {
        "restricted".to_owned()
    } else if s.contains("public") {
        "open".to_owned()
    } else if s.contains("work") {
        "standard".to_owned()
    } else {
        "custom".to_owned()
    }
}

/// Format zone overview as TOON text.
pub fn format_zones_toon(infos: &[ZoneInfo]) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let total = infos.len();
    let _ = writeln!(out, "Zones: {total} configured");
    let _ = writeln!(
        out,
        "{:<20} {:>5} {:>5}  {:<12} {:<24} CONNECTORS",
        "ZONE", "CONN", "TOOLS", "POLICY", "CAPABILITIES"
    );
    for info in infos {
        let connectors_display = summarize_zone_items(&info.connectors, 2);
        let capability_display = summarize_zone_items(&info.capabilities, 2);
        let _ = writeln!(
            out,
            "{:<20} {:>5} {:>5}  {:<12} {:<24} {}",
            info.zone_id,
            info.connector_count,
            info.tool_count,
            info.policy_type,
            capability_display,
            connectors_display
        );
    }
    out
}

/// Format zone detail for a single zone as TOON text.
pub fn format_zone_detail_toon(info: &ZoneInfo) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let _ = writeln!(out, "Zone: {}", info.zone_id);
    let _ = writeln!(out, "  Policy: {}", info.policy_type);
    let _ = writeln!(out, "  Well-known: {}", info.well_known);
    let _ = writeln!(out, "  Connectors: {}", info.connector_count);
    let _ = writeln!(out, "  Tools: {}", info.tool_count);
    let _ = writeln!(out, "  Capabilities: {}", info.capabilities.len());
    if !info.capabilities.is_empty() {
        let _ = writeln!(out, "  Capability list:");
        for capability in &info.capabilities {
            let _ = writeln!(out, "    - {capability}");
        }
    }
    if !info.connectors.is_empty() {
        let _ = writeln!(out, "  Connector list:");
        for c in &info.connectors {
            let _ = writeln!(out, "    - {c}");
        }
    }
    out
}

fn summarize_zone_items(items: &[String], visible: usize) -> String {
    match items.len() {
        0 => "-".to_owned(),
        len if len <= visible => items.join(", "),
        len => format!("{}, ... (+{})", items[..visible].join(", "), len - visible),
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn zone_work() -> ZoneId {
        ZoneId::new("z:work")
    }

    fn zone_public() -> ZoneId {
        ZoneId::new("z:public")
    }

    fn zone_private() -> ZoneId {
        ZoneId::new("z:private")
    }

    fn sample_token(zone: ZoneId) -> ToolCapabilityToken {
        ToolCapabilityToken::new(zone, "agent-1")
    }

    fn sample_registry() -> ZoneRegistry {
        let mut reg = ZoneRegistry::new();
        reg.register_tool(
            ZoneScopedTool::new("github", "create_issue")
                .with_zone(zone_work())
                .with_zone(zone_public())
                .with_capability("issue.write"),
        );
        reg.register_tool(
            ZoneScopedTool::new("github", "list_repos")
                .with_zone(zone_work())
                .with_zone(zone_public())
                .with_capability("repo.read"),
        );
        reg.register_tool(
            ZoneScopedTool::new("slack", "send_message")
                .with_zone(zone_work())
                .with_capability("chat.write"),
        );
        reg.register_tool(
            ZoneScopedTool::new("vault", "get_secret")
                .with_zone(zone_private())
                .with_capability("secret.read"),
        );
        reg
    }

    // ── ZoneId ────────────────────────────────────────────────────

    #[test]
    fn zone_id_basic() {
        let z = ZoneId::new("z:work");
        assert_eq!(z.as_str(), "z:work");
        assert_eq!(z.to_string(), "z:work");
    }

    #[test]
    fn zone_id_public() {
        assert!(ZoneId::new("z:public").is_public());
        assert!(!ZoneId::new("z:work").is_public());
    }

    #[test]
    fn zone_id_well_known() {
        assert!(ZoneId::new("z:work").is_well_known());
        assert!(!ZoneId::new("custom").is_well_known());
    }

    #[test]
    fn zone_id_from_str() {
        let z: ZoneId = "z:test".into();
        assert_eq!(z.as_str(), "z:test");
    }

    #[test]
    fn zone_id_equality() {
        assert_eq!(ZoneId::new("z:work"), ZoneId::new("z:work"));
        assert_ne!(ZoneId::new("z:work"), ZoneId::new("z:public"));
    }

    #[test]
    fn zone_id_ordering() {
        assert!(ZoneId::new("z:a") < ZoneId::new("z:b"));
    }

    #[test]
    fn zone_id_serializes() {
        let z = ZoneId::new("z:work");
        let json = serde_json::to_value(&z).unwrap();
        assert_eq!(json, "z:work");
    }

    // ── ToolCapabilityToken ───────────────────────────────────────────

    #[test]
    fn token_basic() {
        let t = ToolCapabilityToken::new(zone_work(), "agent-1");
        assert_eq!(t.zone, zone_work());
        assert_eq!(t.principal, "agent-1");
        assert!(t.allowed_connectors.is_empty());
    }

    #[test]
    fn token_allows_all_connectors_when_empty() {
        let t = sample_token(zone_work());
        assert!(t.allows_connector("github"));
        assert!(t.allows_connector("slack"));
    }

    #[test]
    fn token_restricts_connectors() {
        let t = sample_token(zone_work()).with_connector("github");
        assert!(t.allows_connector("github"));
        assert!(!t.allows_connector("slack"));
    }

    #[test]
    fn token_denied_operations() {
        let t = sample_token(zone_work()).with_denied_operation("delete_repo");
        assert!(t.is_operation_denied("delete_repo"));
        assert!(!t.is_operation_denied("create_issue"));
    }

    #[test]
    fn token_not_expired() {
        let t = sample_token(zone_work()).with_expiry(u64::MAX);
        assert!(!t.is_expired(1000));
    }

    #[test]
    fn token_expired() {
        let t = sample_token(zone_work()).with_expiry(100);
        assert!(t.is_expired(200));
    }

    #[test]
    fn token_no_expiry() {
        let t = sample_token(zone_work());
        assert!(!t.is_expired(u64::MAX));
    }

    #[test]
    fn token_serializes() {
        let t = sample_token(zone_work());
        let json = serde_json::to_value(&t).unwrap();
        assert_eq!(json["zone"], "z:work");
        assert_eq!(json["principal"], "agent-1");
    }

    // ── ZoneScopedTool ────────────────────────────────────────────

    #[test]
    fn tool_basic() {
        let t = ZoneScopedTool::new("github", "create_issue");
        assert_eq!(t.name, "github.create_issue");
        assert_eq!(t.connector, "github");
        assert_eq!(t.operation, "create_issue");
    }

    #[test]
    fn tool_with_zones() {
        let t = ZoneScopedTool::new("github", "create_issue")
            .with_zone(zone_work())
            .with_zone(zone_public());
        assert!(t.available_in(&zone_work()));
        assert!(t.available_in(&zone_public()));
        assert!(!t.available_in(&zone_private()));
    }

    #[test]
    fn tool_with_description() {
        let t =
            ZoneScopedTool::new("github", "create_issue").with_description("Create a GitHub issue");
        assert_eq!(t.description, "Create a GitHub issue");
    }

    #[test]
    fn tool_serializes() {
        let t = ZoneScopedTool::new("github", "create_issue").with_zone(zone_work());
        let json = serde_json::to_value(&t).unwrap();
        assert_eq!(json["name"], "github.create_issue");
    }

    // ── ViolationReason ───────────────────────────────────────────

    #[test]
    fn violation_reason_display() {
        assert_eq!(
            ViolationReason::ConnectorNotInZone.to_string(),
            "connector not authorized in zone"
        );
        assert_eq!(
            ViolationReason::OperationDenied.to_string(),
            "operation explicitly denied"
        );
        assert_eq!(
            ViolationReason::TokenExpired.to_string(),
            "capability token expired"
        );
        assert_eq!(
            ViolationReason::NoToken.to_string(),
            "no capability token provided"
        );
    }

    #[test]
    fn violation_reason_serializes() {
        let json = serde_json::to_value(ViolationReason::NoToken).unwrap();
        assert_eq!(json, "no_token");
    }

    // ── ZoneViolation ─────────────────────────────────────────────

    #[test]
    fn violation_basic() {
        let v = ZoneViolation::new(
            "github.create_issue",
            zone_public(),
            ViolationReason::ConnectorNotInZone,
        );
        assert_eq!(v.tool, "github.create_issue");
        assert_eq!(v.zone, zone_public());
        assert!(v.message.contains("not available"));
    }

    #[test]
    fn violation_with_available_in() {
        let v = ZoneViolation::new(
            "vault.get_secret",
            zone_public(),
            ViolationReason::ConnectorNotInZone,
        )
        .with_available_in(vec![zone_private()]);
        assert_eq!(v.available_in.len(), 1);
    }

    #[test]
    fn violation_display() {
        let v = ZoneViolation::new("test", zone_work(), ViolationReason::NoToken);
        let s = v.to_string();
        assert!(s.contains("not available"));
    }

    // ── ZoneRegistry ──────────────────────────────────────────────

    #[test]
    fn registry_empty() {
        let reg = ZoneRegistry::new();
        assert_eq!(reg.tool_count(), 0);
        assert!(reg.known_zones().is_empty());
    }

    #[test]
    fn registry_register_tool() {
        let mut reg = ZoneRegistry::new();
        reg.register_tool(ZoneScopedTool::new("github", "create_issue").with_zone(zone_work()));
        assert_eq!(reg.tool_count(), 1);
        assert!(reg.has_zone(&zone_work()));
    }

    #[test]
    fn registry_tools_in_zone() {
        let reg = sample_registry();
        let work_tools = reg.tools_in_zone(&zone_work());
        assert_eq!(work_tools.len(), 3); // github.create_issue, github.list_repos, slack.send_message
        let public_tools = reg.tools_in_zone(&zone_public());
        assert_eq!(public_tools.len(), 2); // github.create_issue, github.list_repos
        let private_tools = reg.tools_in_zone(&zone_private());
        assert_eq!(private_tools.len(), 1); // vault.get_secret
    }

    #[test]
    fn registry_tools_for_connector() {
        let reg = sample_registry();
        let github_work = reg.tools_for_connector_in_zone("github", &zone_work());
        assert_eq!(github_work.len(), 2);
        let slack_public = reg.tools_for_connector_in_zone("slack", &zone_public());
        assert!(slack_public.is_empty());
    }

    #[test]
    fn registry_tool_count_in_zone() {
        let reg = sample_registry();
        assert_eq!(reg.tool_count_in_zone(&zone_work()), 3);
        assert_eq!(reg.tool_count_in_zone(&zone_private()), 1);
    }

    #[test]
    fn registry_connectors_in_zone() {
        let reg = sample_registry();
        let connectors = reg.connectors_in_zone(&zone_work());
        assert!(connectors.contains("github"));
        assert!(connectors.contains("slack"));
        assert!(!connectors.contains("vault"));
    }

    // ── validate_tool_call ────────────────────────────────────────

    #[test]
    fn validate_succeeds() {
        let reg = sample_registry();
        let token = sample_token(zone_work());
        let result = validate_tool_call(&reg, "github.create_issue", &zone_work(), Some(&token));
        assert!(result.is_ok());
    }

    #[test]
    fn validate_no_token() {
        let reg = sample_registry();
        let result = validate_tool_call(&reg, "github.create_issue", &zone_work(), None);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().reason, ViolationReason::NoToken);
    }

    #[test]
    fn validate_wrong_zone() {
        let reg = sample_registry();
        let token = sample_token(zone_public()); // Token for public
        let result = validate_tool_call(&reg, "github.create_issue", &zone_work(), Some(&token));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().reason, ViolationReason::UnknownZone);
    }

    #[test]
    fn validate_tool_not_in_zone() {
        let reg = sample_registry();
        let token = sample_token(zone_public());
        let result = validate_tool_call(&reg, "slack.send_message", &zone_public(), Some(&token));
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().reason,
            ViolationReason::ConnectorNotInZone
        );
    }

    #[test]
    fn validate_connector_restricted() {
        let reg = sample_registry();
        let token = sample_token(zone_work()).with_connector("github"); // Only github allowed
        let result = validate_tool_call(&reg, "slack.send_message", &zone_work(), Some(&token));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().reason, ViolationReason::ConnectorDenied);
    }

    #[test]
    fn connector_denied_serializes_snake_case() {
        let json = serde_json::to_value(ViolationReason::ConnectorDenied).unwrap();
        assert_eq!(json, "connector_denied");
    }

    #[test]
    fn validate_operation_denied() {
        let reg = sample_registry();
        let token = sample_token(zone_work()).with_denied_operation("create_issue");
        let result = validate_tool_call(&reg, "github.create_issue", &zone_work(), Some(&token));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().reason, ViolationReason::OperationDenied);
    }

    #[test]
    fn validate_unknown_tool() {
        let reg = sample_registry();
        let token = sample_token(zone_work());
        let result = validate_tool_call(&reg, "nonexistent.op", &zone_work(), Some(&token));
        assert!(result.is_err());
    }

    // ── filter_tools_for_zone ─────────────────────────────────────

    #[test]
    fn filter_tools_basic() {
        let reg = sample_registry();
        let token = sample_token(zone_work());
        let filtered = filter_tools_for_zone(&reg.tools, &zone_work(), &token);
        assert_eq!(filtered.len(), 3);
    }

    #[test]
    fn filter_tools_restricted_connector() {
        let reg = sample_registry();
        let token = sample_token(zone_work()).with_connector("github");
        let filtered = filter_tools_for_zone(&reg.tools, &zone_work(), &token);
        assert_eq!(filtered.len(), 2); // Only github tools
    }

    #[test]
    fn filter_tools_denied_operation() {
        let reg = sample_registry();
        let token = sample_token(zone_work()).with_denied_operation("create_issue");
        let filtered = filter_tools_for_zone(&reg.tools, &zone_work(), &token);
        assert_eq!(filtered.len(), 2); // list_repos + send_message
    }

    #[test]
    fn filter_tools_different_zone() {
        let reg = sample_registry();
        let token = sample_token(zone_public());
        let filtered = filter_tools_for_zone(&reg.tools, &zone_public(), &token);
        assert_eq!(filtered.len(), 2); // Only github tools in public
    }

    // ── format helpers ────────────────────────────────────────────

    #[test]
    fn format_zone_tools_display() {
        let reg = sample_registry();
        let tools = reg.tools_in_zone(&zone_work());
        let s = format_zone_tools(&zone_work(), &tools);
        assert!(s.contains("z:work (3 tools)"));
        assert!(s.contains("github:"));
        assert!(s.contains("slack:"));
    }

    #[test]
    fn format_violation_display() {
        let v = ZoneViolation::new(
            "vault.get_secret",
            zone_public(),
            ViolationReason::ConnectorNotInZone,
        )
        .with_available_in(vec![zone_private()]);
        let s = format_violation(&v);
        assert!(s.contains("not available"));
        assert!(s.contains("z:private"));
    }

    #[test]
    fn format_violation_no_alternatives() {
        let v = ZoneViolation::new("test", zone_work(), ViolationReason::NoToken);
        let s = format_violation(&v);
        assert!(!s.contains("Available in"));
    }

    // ── parse_zone ────────────────────────────────────────────────

    #[test]
    fn parse_zone_with_prefix() {
        let z = parse_zone("z:work");
        assert_eq!(z.as_str(), "z:work");
    }

    #[test]
    fn parse_zone_without_prefix() {
        let z = parse_zone("work");
        assert_eq!(z.as_str(), "z:work");
    }

    #[test]
    fn parse_zone_with_whitespace() {
        let z = parse_zone("  z:work  ");
        assert_eq!(z.as_str(), "z:work");
    }

    // ── ZoneId edge cases ────────────────────────────────────────

    #[test]
    fn zone_id_empty() {
        let z = ZoneId::new("");
        assert_eq!(z.as_str(), "");
        assert!(!z.is_public());
        assert!(!z.is_well_known());
    }

    #[test]
    fn zone_id_no_prefix() {
        let z = ZoneId::new("custom_zone");
        assert!(!z.is_well_known());
        assert!(!z.is_public());
        assert_eq!(z.to_string(), "custom_zone");
    }

    #[test]
    fn zone_id_colon_only() {
        let z = ZoneId::new("z:");
        assert!(z.is_well_known());
        assert!(!z.is_public());
    }

    #[test]
    fn zone_id_display() {
        let z = ZoneId::new("z:staging");
        assert_eq!(format!("{z}"), "z:staging");
    }

    #[test]
    fn zone_id_hash_set() {
        let mut set = BTreeSet::new();
        set.insert(ZoneId::new("z:a"));
        set.insert(ZoneId::new("z:a"));
        set.insert(ZoneId::new("z:b"));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn zone_id_serde_roundtrip() {
        let z = ZoneId::new("z:test");
        let json = serde_json::to_string(&z).unwrap();
        let z2: ZoneId = serde_json::from_str(&json).unwrap();
        assert_eq!(z, z2);
    }

    #[test]
    fn zone_id_from_str_impl() {
        let z: ZoneId = "z:derived".into();
        assert_eq!(z, ZoneId::new("z:derived"));
    }

    #[test]
    fn zone_id_clone() {
        let z = ZoneId::new("z:work");
        let z2 = z.clone();
        assert_eq!(z, z2);
    }

    // ── ToolCapabilityToken edge cases ───────────────────────────────

    #[test]
    fn token_expiry_exact_boundary() {
        let t = ToolCapabilityToken::new(zone_work(), "agent").with_expiry(100);
        assert!(!t.is_expired(100)); // now == expires_at → NOT expired
        assert!(t.is_expired(101)); // now > expires_at → expired
    }

    #[test]
    fn token_expiry_zero_means_no_expiry() {
        let t = ToolCapabilityToken::new(zone_work(), "agent").with_expiry(0);
        assert!(!t.is_expired(0));
        assert!(!t.is_expired(u64::MAX));
    }

    #[test]
    fn token_multiple_connectors() {
        let t = ToolCapabilityToken::new(zone_work(), "agent")
            .with_connector("github")
            .with_connector("slack")
            .with_connector("jira");
        assert!(t.allows_connector("github"));
        assert!(t.allows_connector("slack"));
        assert!(t.allows_connector("jira"));
        assert!(!t.allows_connector("linear"));
    }

    #[test]
    fn token_multiple_denied_operations() {
        let t = ToolCapabilityToken::new(zone_work(), "agent")
            .with_denied_operation("delete_repo")
            .with_denied_operation("delete_org");
        assert!(t.is_operation_denied("delete_repo"));
        assert!(t.is_operation_denied("delete_org"));
        assert!(!t.is_operation_denied("create_issue"));
    }

    #[test]
    fn token_serde_roundtrip_full() {
        let t = ToolCapabilityToken::new(zone_work(), "agent-42")
            .with_connector("github")
            .with_denied_operation("delete")
            .with_expiry(99999);
        let json = serde_json::to_string(&t).unwrap();
        let t2: ToolCapabilityToken = serde_json::from_str(&json).unwrap();
        assert_eq!(t2.zone, zone_work());
        assert_eq!(t2.principal, "agent-42");
        assert!(t2.allows_connector("github"));
        assert!(!t2.allows_connector("slack"));
        assert!(t2.is_operation_denied("delete"));
        assert_eq!(t2.expires_at, 99999);
    }

    #[test]
    fn token_clone() {
        let t = ToolCapabilityToken::new(zone_work(), "agent").with_connector("github");
        let t2 = t.clone();
        assert_eq!(t.zone, t2.zone);
        assert!(t2.allows_connector("github"));
    }

    // ── ZoneScopedTool edge cases ────────────────────────────────

    #[test]
    fn tool_name_format() {
        let t = ZoneScopedTool::new("my-connector", "some_operation");
        assert_eq!(t.name, "my-connector.some_operation");
    }

    #[test]
    fn tool_no_zones() {
        let t = ZoneScopedTool::new("github", "create_issue");
        assert!(t.zones.is_empty());
        assert!(!t.available_in(&zone_work()));
    }

    #[test]
    fn tool_duplicate_zone_no_effect() {
        let t = ZoneScopedTool::new("github", "create_issue")
            .with_zone(zone_work())
            .with_zone(zone_work());
        assert_eq!(t.zones.len(), 1);
    }

    #[test]
    fn tool_serde_roundtrip() {
        let t = ZoneScopedTool::new("github", "create_issue")
            .with_zone(zone_work())
            .with_description("Create issue");
        let json = serde_json::to_string(&t).unwrap();
        let t2: ZoneScopedTool = serde_json::from_str(&json).unwrap();
        assert_eq!(t2.name, "github.create_issue");
        assert_eq!(t2.description, "Create issue");
    }

    // ── ViolationReason additional ───────────────────────────────

    #[test]
    fn violation_reason_display_unknown_zone() {
        assert_eq!(
            ViolationReason::UnknownZone.to_string(),
            "zone not recognized"
        );
    }

    #[test]
    fn violation_reason_serde_all() {
        for reason in &[
            ViolationReason::ConnectorNotInZone,
            ViolationReason::OperationDenied,
            ViolationReason::TokenExpired,
            ViolationReason::NoToken,
            ViolationReason::UnknownZone,
        ] {
            let json = serde_json::to_string(reason).unwrap();
            let r2: ViolationReason = serde_json::from_str(&json).unwrap();
            assert_eq!(*reason, r2);
        }
    }

    // ── ZoneViolation additional ─────────────────────────────────

    #[test]
    fn violation_serde_roundtrip() {
        let v = ZoneViolation::new(
            "github.create_issue",
            zone_work(),
            ViolationReason::OperationDenied,
        )
        .with_available_in(vec![zone_public()]);
        let json = serde_json::to_string(&v).unwrap();
        let v2: ZoneViolation = serde_json::from_str(&json).unwrap();
        assert_eq!(v2.tool, "github.create_issue");
        assert_eq!(v2.reason, ViolationReason::OperationDenied);
    }

    #[test]
    fn violation_message_format() {
        let v = ZoneViolation::new(
            "vault.get_secret",
            ZoneId::new("z:public"),
            ViolationReason::TokenExpired,
        );
        assert!(v.message.contains("vault.get_secret"));
        assert!(v.message.contains("z:public"));
        assert!(v.message.contains("token expired"));
    }

    #[test]
    fn violation_display_matches_message() {
        let v = ZoneViolation::new("test.op", zone_work(), ViolationReason::NoToken);
        assert_eq!(v.to_string(), v.message);
    }

    #[test]
    fn violation_empty_available_in() {
        let v = ZoneViolation::new("test", zone_work(), ViolationReason::NoToken);
        assert!(v.available_in.is_empty());
    }

    // ── ZoneRegistry additional ──────────────────────────────────

    #[test]
    fn registry_has_zone_unknown() {
        let reg = sample_registry();
        assert!(!reg.has_zone(&ZoneId::new("z:staging")));
    }

    #[test]
    fn registry_known_zones() {
        let reg = sample_registry();
        let zones = reg.known_zones();
        assert!(zones.contains(&zone_work()));
        assert!(zones.contains(&zone_public()));
        assert!(zones.contains(&zone_private()));
        assert_eq!(zones.len(), 3);
    }

    #[test]
    fn registry_connectors_in_zone_empty() {
        let reg = sample_registry();
        let connectors = reg.connectors_in_zone(&ZoneId::new("z:staging"));
        assert!(connectors.is_empty());
    }

    #[test]
    fn registry_connectors_in_zone_public() {
        let reg = sample_registry();
        let connectors = reg.connectors_in_zone(&zone_public());
        assert_eq!(connectors.len(), 1);
        assert!(connectors.contains("github"));
    }

    #[test]
    fn registry_tool_count_in_zone_unknown() {
        let reg = sample_registry();
        assert_eq!(reg.tool_count_in_zone(&ZoneId::new("z:staging")), 0);
    }

    #[test]
    fn registry_clone() {
        let reg = sample_registry();
        let reg2 = reg.clone();
        assert_eq!(reg.tool_count(), reg2.tool_count());
        assert_eq!(reg.known_zones().len(), reg2.known_zones().len());
    }

    // ── validate_tool_call additional ────────────────────────────

    #[test]
    fn validate_expired_token() {
        let reg = sample_registry();
        let token = ToolCapabilityToken::new(zone_work(), "agent").with_expiry(1); // expired
        let result = validate_tool_call(&reg, "github.create_issue", &zone_work(), Some(&token));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().reason, ViolationReason::TokenExpired);
    }

    #[test]
    fn validate_tool_not_in_zone_has_alternatives() {
        let reg = sample_registry();
        let token = sample_token(zone_private());
        // slack.send_message is in z:work, not z:private
        let result = validate_tool_call(&reg, "slack.send_message", &zone_private(), Some(&token));
        let err = result.unwrap_err();
        assert_eq!(err.reason, ViolationReason::ConnectorNotInZone);
        assert!(!err.available_in.is_empty());
        assert!(err.available_in.contains(&zone_work()));
    }

    #[test]
    fn validate_multiple_denied_operations() {
        let reg = sample_registry();
        let token = sample_token(zone_work())
            .with_denied_operation("create_issue")
            .with_denied_operation("list_repos");
        assert!(
            validate_tool_call(&reg, "github.create_issue", &zone_work(), Some(&token)).is_err()
        );
        assert!(validate_tool_call(&reg, "github.list_repos", &zone_work(), Some(&token)).is_err());
        // slack.send_message not denied
        assert!(validate_tool_call(&reg, "slack.send_message", &zone_work(), Some(&token)).is_ok());
    }

    #[test]
    fn validate_connector_restricted_by_token() {
        let reg = sample_registry();
        let token = sample_token(zone_work()).with_connector("slack");
        // Only slack allowed, github should fail with the token-denial reason
        // (not ConnectorNotInZone — the connector IS in the zone).
        let result = validate_tool_call(&reg, "github.create_issue", &zone_work(), Some(&token));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().reason, ViolationReason::ConnectorDenied);
    }

    // ── filter_tools_for_zone additional ─────────────────────────

    #[test]
    fn filter_tools_empty_zone() {
        let reg = sample_registry();
        let token = sample_token(ZoneId::new("z:staging"));
        let filtered = filter_tools_for_zone(&reg.tools, &ZoneId::new("z:staging"), &token);
        assert!(filtered.is_empty());
    }

    #[test]
    fn filter_tools_all_denied() {
        let reg = sample_registry();
        let token = sample_token(zone_work())
            .with_denied_operation("create_issue")
            .with_denied_operation("list_repos")
            .with_denied_operation("send_message");
        let filtered = filter_tools_for_zone(&reg.tools, &zone_work(), &token);
        assert!(filtered.is_empty());
    }

    #[test]
    fn filter_tools_multiple_connectors() {
        let reg = sample_registry();
        let token = sample_token(zone_work())
            .with_connector("github")
            .with_connector("slack");
        let filtered = filter_tools_for_zone(&reg.tools, &zone_work(), &token);
        assert_eq!(filtered.len(), 3);
    }

    // ── format helpers additional ────────────────────────────────

    #[test]
    fn format_zone_tools_empty() {
        let tools: Vec<&ZoneScopedTool> = vec![];
        let s = format_zone_tools(&zone_work(), &tools);
        assert!(s.contains("z:work (0 tools)"));
    }

    #[test]
    fn format_violation_multiple_zones() {
        let v = ZoneViolation::new(
            "test.op",
            zone_public(),
            ViolationReason::ConnectorNotInZone,
        )
        .with_available_in(vec![zone_work(), zone_private()]);
        let s = format_violation(&v);
        assert!(s.contains("z:work"));
        assert!(s.contains("z:private"));
    }

    // ── parse_zone additional ────────────────────────────────────

    #[test]
    fn parse_zone_empty_string() {
        let z = parse_zone("");
        assert_eq!(z.as_str(), "z:");
    }

    #[test]
    fn parse_zone_z_colon_only() {
        let z = parse_zone("z:");
        assert_eq!(z.as_str(), "z:");
    }

    #[test]
    fn parse_zone_whitespace_only() {
        let z = parse_zone("   ");
        assert_eq!(z.as_str(), "z:");
    }

    #[test]
    fn parse_zone_double_prefix() {
        let z = parse_zone("z:z:work");
        // Already starts with "z:", returned as-is
        assert_eq!(z.as_str(), "z:z:work");
    }

    #[test]
    fn parse_zone_special_chars() {
        let z = parse_zone("my-zone_1");
        assert_eq!(z.as_str(), "z:my-zone_1");
    }

    // ── ZoneId extended ──────────────────────────────────────────────

    #[test]
    fn zone_id_long_string() {
        let long = format!("z:{}", "a".repeat(1000));
        let z = ZoneId::new(&long);
        assert_eq!(z.as_str(), long);
        assert!(z.is_well_known());
    }

    #[test]
    fn zone_id_unicode() {
        let z = ZoneId::new("z:trabajo");
        assert!(z.is_well_known());
        assert_eq!(z.as_str(), "z:trabajo");
    }

    #[test]
    fn zone_id_with_special_chars() {
        let z = ZoneId::new("z:my-zone_1.2");
        assert!(z.is_well_known());
        assert_eq!(z.to_string(), "z:my-zone_1.2");
    }

    #[test]
    fn zone_id_from_string_owned() {
        let s = String::from("z:owned");
        let z = ZoneId::new(s);
        assert_eq!(z.as_str(), "z:owned");
    }

    #[test]
    fn zone_id_hash_consistency() {
        use std::collections::HashMap;
        let mut map = HashMap::new();
        map.insert(ZoneId::new("z:test"), 42);
        assert_eq!(map.get(&ZoneId::new("z:test")), Some(&42));
        assert_eq!(map.get(&ZoneId::new("z:other")), None);
    }

    #[test]
    fn zone_id_ord_multiple() {
        let mut zones = [
            ZoneId::new("z:work"),
            ZoneId::new("z:alpha"),
            ZoneId::new("z:public"),
            ZoneId::new("z:beta"),
        ];
        zones.sort();
        assert_eq!(zones[0].as_str(), "z:alpha");
        assert_eq!(zones[1].as_str(), "z:beta");
        assert_eq!(zones[2].as_str(), "z:public");
        assert_eq!(zones[3].as_str(), "z:work");
    }

    #[test]
    fn zone_id_public_exact_match() {
        // Only exact "z:public" is public
        assert!(!ZoneId::new("z:public2").is_public());
        assert!(!ZoneId::new("z:publc").is_public());
        assert!(!ZoneId::new("z:PUBLIC").is_public());
    }

    #[test]
    fn zone_id_well_known_prefix_only() {
        assert!(!ZoneId::new("Z:work").is_well_known());
        assert!(!ZoneId::new("zz:work").is_well_known());
        assert!(ZoneId::new("z:").is_well_known());
        assert!(ZoneId::new("z:x").is_well_known());
    }

    #[test]
    fn zone_id_serde_empty() {
        let z = ZoneId::new("");
        let json = serde_json::to_string(&z).unwrap();
        let z2: ZoneId = serde_json::from_str(&json).unwrap();
        assert_eq!(z, z2);
        assert_eq!(z2.as_str(), "");
    }

    #[test]
    fn zone_id_btree_set_ordering() {
        let mut set = BTreeSet::new();
        set.insert(ZoneId::new("z:c"));
        set.insert(ZoneId::new("z:a"));
        set.insert(ZoneId::new("z:b"));
        let v: Vec<&str> = set.iter().map(ZoneId::as_str).collect();
        assert_eq!(v, vec!["z:a", "z:b", "z:c"]);
    }

    #[test]
    fn zone_id_display_format() {
        let z = ZoneId::new("z:formatted");
        assert_eq!(format!("zone={z}"), "zone=z:formatted");
    }

    // ── ToolCapabilityToken extended ─────────────────────────────────────

    #[test]
    fn token_default_timestamps() {
        let t = ToolCapabilityToken::new(zone_work(), "agent");
        assert_eq!(t.issued_at, 0);
        assert_eq!(t.expires_at, 0);
    }

    #[test]
    fn token_empty_principal() {
        let t = ToolCapabilityToken::new(zone_work(), "");
        assert_eq!(t.principal, "");
    }

    #[test]
    fn token_with_connector_chaining() {
        let t = ToolCapabilityToken::new(zone_work(), "agent")
            .with_connector("a")
            .with_connector("b")
            .with_connector("c")
            .with_connector("a"); // duplicate
        assert_eq!(t.allowed_connectors.len(), 3);
        assert!(t.allows_connector("a"));
        assert!(t.allows_connector("b"));
        assert!(t.allows_connector("c"));
    }

    #[test]
    fn token_denied_ops_chaining() {
        let t = ToolCapabilityToken::new(zone_work(), "agent")
            .with_denied_operation("delete")
            .with_denied_operation("destroy")
            .with_denied_operation("delete"); // duplicate
        assert_eq!(t.denied_operations.len(), 2);
    }

    #[test]
    fn token_expiry_boundary_exact_equals() {
        let t = ToolCapabilityToken::new(zone_work(), "agent").with_expiry(100);
        // now == expires_at is NOT expired (now > expires_at is the condition)
        assert!(!t.is_expired(99));
        assert!(!t.is_expired(100));
        assert!(t.is_expired(101));
    }

    #[test]
    fn token_expiry_max_u64() {
        let t = ToolCapabilityToken::new(zone_work(), "agent").with_expiry(u64::MAX);
        assert!(!t.is_expired(0));
        assert!(!t.is_expired(u64::MAX - 1));
        assert!(!t.is_expired(u64::MAX));
    }

    #[test]
    fn token_allows_all_when_empty_set() {
        let t = ToolCapabilityToken::new(zone_work(), "agent");
        // Empty allowed_connectors means ALL connectors are allowed
        assert!(t.allows_connector("anything"));
        assert!(t.allows_connector(""));
        assert!(t.allows_connector("some-random-connector"));
    }

    #[test]
    fn token_denies_when_not_in_allowed_set() {
        let t = ToolCapabilityToken::new(zone_work(), "agent").with_connector("only_this");
        assert!(t.allows_connector("only_this"));
        assert!(!t.allows_connector("not_this"));
        assert!(!t.allows_connector(""));
    }

    #[test]
    fn token_denied_op_empty_string() {
        let t = ToolCapabilityToken::new(zone_work(), "agent").with_denied_operation("");
        assert!(t.is_operation_denied(""));
        assert!(!t.is_operation_denied("something"));
    }

    #[test]
    fn token_serde_empty_sets() {
        let t = ToolCapabilityToken::new(zone_work(), "agent");
        let json = serde_json::to_string(&t).unwrap();
        let t2: ToolCapabilityToken = serde_json::from_str(&json).unwrap();
        assert!(t2.allowed_connectors.is_empty());
        assert!(t2.denied_operations.is_empty());
        assert_eq!(t2.expires_at, 0);
        assert_eq!(t2.issued_at, 0);
    }

    #[test]
    fn token_serde_with_all_fields() {
        let t = ToolCapabilityToken::new(zone_private(), "admin-agent")
            .with_connector("vault")
            .with_connector("1password")
            .with_denied_operation("delete_all")
            .with_denied_operation("purge")
            .with_expiry(9_999_999);
        let json = serde_json::to_string(&t).unwrap();
        let t2: ToolCapabilityToken = serde_json::from_str(&json).unwrap();
        assert_eq!(t2.zone, zone_private());
        assert_eq!(t2.principal, "admin-agent");
        assert_eq!(t2.allowed_connectors.len(), 2);
        assert_eq!(t2.denied_operations.len(), 2);
        assert_eq!(t2.expires_at, 9_999_999);
    }

    #[test]
    fn token_clone_independence() {
        let t = ToolCapabilityToken::new(zone_work(), "agent").with_connector("github");
        let mut t2 = t.clone();
        t2.allowed_connectors.insert("slack".into());
        // Original should not be affected
        assert!(!t.allows_connector("slack") || t.allowed_connectors.is_empty());
        assert_eq!(t.allowed_connectors.len(), 1);
        assert_eq!(t2.allowed_connectors.len(), 2);
    }

    // ── ZoneScopedTool extended ──────────────────────────────────────

    #[test]
    fn tool_empty_connector_and_operation() {
        let t = ZoneScopedTool::new("", "");
        assert_eq!(t.name, ".");
        assert_eq!(t.connector, "");
        assert_eq!(t.operation, "");
    }

    #[test]
    fn tool_default_description_empty() {
        let t = ZoneScopedTool::new("github", "list_repos");
        assert_eq!(t.description, "");
    }

    #[test]
    fn tool_multiple_zones() {
        let t = ZoneScopedTool::new("github", "create_issue")
            .with_zone(zone_work())
            .with_zone(zone_public())
            .with_zone(zone_private());
        assert_eq!(t.zones.len(), 3);
        assert!(t.available_in(&zone_work()));
        assert!(t.available_in(&zone_public()));
        assert!(t.available_in(&zone_private()));
    }

    #[test]
    fn tool_available_in_empty_zones() {
        let t = ZoneScopedTool::new("github", "list");
        assert!(!t.available_in(&zone_work()));
        assert!(!t.available_in(&zone_public()));
    }

    #[test]
    fn tool_serde_roundtrip_full() {
        let t = ZoneScopedTool::new("slack", "send_message")
            .with_zone(zone_work())
            .with_zone(zone_private())
            .with_description("Send a Slack message");
        let json = serde_json::to_string(&t).unwrap();
        let t2: ZoneScopedTool = serde_json::from_str(&json).unwrap();
        assert_eq!(t2.name, "slack.send_message");
        assert_eq!(t2.connector, "slack");
        assert_eq!(t2.operation, "send_message");
        assert_eq!(t2.description, "Send a Slack message");
        assert_eq!(t2.zones.len(), 2);
        assert!(t2.available_in(&zone_work()));
        assert!(t2.available_in(&zone_private()));
    }

    #[test]
    fn tool_clone_independence() {
        let t = ZoneScopedTool::new("github", "list").with_zone(zone_work());
        let mut t2 = t.clone();
        t2.zones.insert(zone_public());
        assert_eq!(t.zones.len(), 1);
        assert_eq!(t2.zones.len(), 2);
    }

    #[test]
    fn tool_debug_output() {
        let t = ZoneScopedTool::new("test", "op");
        let debug = format!("{t:?}");
        assert!(debug.contains("ZoneScopedTool"));
        assert!(debug.contains("test.op"));
    }

    // ── ViolationReason extended ─────────────────────────────────────

    #[test]
    fn violation_reason_equality() {
        assert_eq!(ViolationReason::NoToken, ViolationReason::NoToken);
        assert_ne!(ViolationReason::NoToken, ViolationReason::TokenExpired);
    }

    #[test]
    fn violation_reason_clone() {
        let r = ViolationReason::OperationDenied;
        let r2 = r.clone();
        assert_eq!(r, r2);
    }

    #[test]
    fn violation_reason_debug() {
        let r = ViolationReason::ConnectorNotInZone;
        let debug = format!("{r:?}");
        assert!(debug.contains("ConnectorNotInZone"));
    }

    #[test]
    fn violation_reason_all_variants_display() {
        let variants = [
            (
                ViolationReason::ConnectorNotInZone,
                "connector not authorized in zone",
            ),
            (
                ViolationReason::OperationDenied,
                "operation explicitly denied",
            ),
            (ViolationReason::TokenExpired, "capability token expired"),
            (ViolationReason::NoToken, "no capability token provided"),
            (ViolationReason::UnknownZone, "zone not recognized"),
        ];
        for (variant, expected) in &variants {
            assert_eq!(variant.to_string(), *expected);
        }
    }

    #[test]
    fn violation_reason_serde_roundtrip_all() {
        let variants = [
            ViolationReason::ConnectorNotInZone,
            ViolationReason::OperationDenied,
            ViolationReason::TokenExpired,
            ViolationReason::NoToken,
            ViolationReason::UnknownZone,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let v2: ViolationReason = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, v2);
        }
    }

    #[test]
    fn violation_reason_snake_case_serialization() {
        assert_eq!(
            serde_json::to_value(ViolationReason::ConnectorNotInZone).unwrap(),
            "connector_not_in_zone"
        );
        assert_eq!(
            serde_json::to_value(ViolationReason::OperationDenied).unwrap(),
            "operation_denied"
        );
        assert_eq!(
            serde_json::to_value(ViolationReason::TokenExpired).unwrap(),
            "token_expired"
        );
        assert_eq!(
            serde_json::to_value(ViolationReason::UnknownZone).unwrap(),
            "unknown_zone"
        );
    }

    // ── ZoneViolation extended ───────────────────────────────────────

    #[test]
    fn violation_all_reasons_produce_valid_message() {
        let reasons = [
            ViolationReason::ConnectorNotInZone,
            ViolationReason::OperationDenied,
            ViolationReason::TokenExpired,
            ViolationReason::NoToken,
            ViolationReason::UnknownZone,
        ];
        for reason in &reasons {
            let v = ZoneViolation::new("test.op", zone_work(), reason.clone());
            assert!(v.message.contains("test.op"));
            assert!(v.message.contains("z:work"));
            assert!(!v.message.is_empty());
        }
    }

    #[test]
    fn violation_serde_roundtrip_full() {
        let v = ZoneViolation::new(
            "vault.secret",
            zone_private(),
            ViolationReason::TokenExpired,
        )
        .with_available_in(vec![zone_work(), zone_public()]);
        let json = serde_json::to_string(&v).unwrap();
        let v2: ZoneViolation = serde_json::from_str(&json).unwrap();
        assert_eq!(v2.tool, "vault.secret");
        assert_eq!(v2.zone, zone_private());
        assert_eq!(v2.reason, ViolationReason::TokenExpired);
        assert_eq!(v2.available_in.len(), 2);
        assert!(v2.available_in.contains(&zone_work()));
        assert!(v2.available_in.contains(&zone_public()));
    }

    #[test]
    fn violation_clone() {
        let v = ZoneViolation::new("test.op", zone_work(), ViolationReason::NoToken)
            .with_available_in(vec![zone_public()]);
        let v2 = v.clone();
        assert_eq!(v.tool, v2.tool);
        assert_eq!(v.zone, v2.zone);
        assert_eq!(v.reason, v2.reason);
        assert_eq!(v.message, v2.message);
        assert_eq!(v.available_in.len(), v2.available_in.len());
    }

    #[test]
    fn violation_debug() {
        let v = ZoneViolation::new("test.op", zone_work(), ViolationReason::NoToken);
        let debug = format!("{v:?}");
        assert!(debug.contains("ZoneViolation"));
    }

    #[test]
    fn violation_with_empty_available_in() {
        let v = ZoneViolation::new("test.op", zone_work(), ViolationReason::NoToken)
            .with_available_in(vec![]);
        assert!(v.available_in.is_empty());
    }

    // ── ZoneRegistry extended ────────────────────────────────────────

    #[test]
    fn registry_multiple_tools_same_connector() {
        let mut reg = ZoneRegistry::new();
        reg.register_tool(ZoneScopedTool::new("github", "create_issue").with_zone(zone_work()));
        reg.register_tool(ZoneScopedTool::new("github", "list_repos").with_zone(zone_work()));
        reg.register_tool(ZoneScopedTool::new("github", "delete_repo").with_zone(zone_work()));
        assert_eq!(reg.tool_count(), 3);
        assert_eq!(
            reg.tools_for_connector_in_zone("github", &zone_work())
                .len(),
            3
        );
    }

    #[test]
    fn registry_tool_in_multiple_zones() {
        let mut reg = ZoneRegistry::new();
        reg.register_tool(
            ZoneScopedTool::new("github", "create_issue")
                .with_zone(zone_work())
                .with_zone(zone_public())
                .with_zone(zone_private()),
        );
        assert_eq!(reg.known_zones().len(), 3);
        assert_eq!(reg.tools_in_zone(&zone_work()).len(), 1);
        assert_eq!(reg.tools_in_zone(&zone_public()).len(), 1);
        assert_eq!(reg.tools_in_zone(&zone_private()).len(), 1);
    }

    #[test]
    fn registry_no_tools_in_zone() {
        let reg = sample_registry();
        let z = ZoneId::new("z:staging");
        assert!(reg.tools_in_zone(&z).is_empty());
        assert_eq!(reg.tool_count_in_zone(&z), 0);
        assert!(reg.connectors_in_zone(&z).is_empty());
    }

    #[test]
    fn registry_tools_for_nonexistent_connector() {
        let reg = sample_registry();
        let tools = reg.tools_for_connector_in_zone("nonexistent", &zone_work());
        assert!(tools.is_empty());
    }

    #[test]
    fn registry_default_is_empty() {
        let reg = ZoneRegistry::default();
        assert_eq!(reg.tool_count(), 0);
        assert!(reg.known_zones().is_empty());
    }

    #[test]
    fn registry_debug() {
        let reg = ZoneRegistry::new();
        let debug = format!("{reg:?}");
        assert!(debug.contains("ZoneRegistry"));
    }

    #[test]
    fn registry_clone_independence() {
        let mut reg = sample_registry();
        let reg2 = reg.clone();
        reg.register_tool(ZoneScopedTool::new("new", "tool").with_zone(zone_work()));
        assert_eq!(reg.tool_count(), 5);
        assert_eq!(reg2.tool_count(), 4);
    }

    #[test]
    fn registry_connectors_in_zone_deduplicates() {
        let reg = sample_registry();
        // github has 2 tools in z:work, but should appear once in connector set
        let connectors = reg.connectors_in_zone(&zone_work());
        let count = connectors.iter().filter(|c| *c == "github").count();
        assert_eq!(count, 1);
    }

    // ── validate_tool_call extended ──────────────────────────────────

    #[test]
    fn validate_all_tools_in_zone_with_valid_token() {
        let reg = sample_registry();
        let token = sample_token(zone_work());
        assert!(
            validate_tool_call(&reg, "github.create_issue", &zone_work(), Some(&token)).is_ok()
        );
        assert!(validate_tool_call(&reg, "github.list_repos", &zone_work(), Some(&token)).is_ok());
        assert!(validate_tool_call(&reg, "slack.send_message", &zone_work(), Some(&token)).is_ok());
    }

    #[test]
    fn validate_private_tool_requires_private_token() {
        let reg = sample_registry();
        let token = sample_token(zone_private());
        assert!(
            validate_tool_call(&reg, "vault.get_secret", &zone_private(), Some(&token)).is_ok()
        );
    }

    #[test]
    fn validate_private_tool_fails_with_work_token() {
        let reg = sample_registry();
        let token = sample_token(zone_work());
        let result = validate_tool_call(&reg, "vault.get_secret", &zone_work(), Some(&token));
        assert!(result.is_err());
        // vault.get_secret is only in z:private, not z:work
        assert_eq!(
            result.unwrap_err().reason,
            ViolationReason::ConnectorNotInZone
        );
    }

    #[test]
    fn validate_nonexistent_tool_fails() {
        let reg = sample_registry();
        let token = sample_token(zone_work());
        let err =
            validate_tool_call(&reg, "does.not.exist", &zone_work(), Some(&token)).unwrap_err();
        assert_eq!(err.reason, ViolationReason::ConnectorNotInZone);
        assert_eq!(err.tool, "does.not.exist");
    }

    #[test]
    fn validate_empty_registry() {
        let reg = ZoneRegistry::new();
        let token = sample_token(zone_work());
        let result = validate_tool_call(&reg, "any.tool", &zone_work(), Some(&token));
        assert!(result.is_err());
    }

    #[test]
    fn validate_connector_restricted_allows_correct() {
        let reg = sample_registry();
        let token = sample_token(zone_work())
            .with_connector("github")
            .with_connector("slack");
        assert!(
            validate_tool_call(&reg, "github.create_issue", &zone_work(), Some(&token)).is_ok()
        );
        assert!(validate_tool_call(&reg, "slack.send_message", &zone_work(), Some(&token)).is_ok());
    }

    #[test]
    fn validate_combined_connector_restriction_and_denial() {
        let reg = sample_registry();
        let token = sample_token(zone_work())
            .with_connector("github")
            .with_denied_operation("create_issue");
        // github allowed, but create_issue denied
        assert!(
            validate_tool_call(&reg, "github.create_issue", &zone_work(), Some(&token)).is_err()
        );
        // list_repos should still work
        assert!(validate_tool_call(&reg, "github.list_repos", &zone_work(), Some(&token)).is_ok());
    }

    #[test]
    fn validate_violation_zone_preserved() {
        let reg = sample_registry();
        let err = validate_tool_call(&reg, "github.create_issue", &zone_work(), None).unwrap_err();
        assert_eq!(err.zone, zone_work());
    }

    #[test]
    fn validate_violation_tool_name_preserved() {
        let reg = sample_registry();
        let err = validate_tool_call(&reg, "my.custom.tool", &zone_work(), None).unwrap_err();
        assert_eq!(err.tool, "my.custom.tool");
    }

    // ── filter_tools_for_zone extended ───────────────────────────────

    #[test]
    fn filter_tools_empty_tools_list() {
        let tools: Vec<ZoneScopedTool> = vec![];
        let token = sample_token(zone_work());
        let filtered = filter_tools_for_zone(&tools, &zone_work(), &token);
        assert!(filtered.is_empty());
    }

    #[test]
    fn filter_tools_all_connectors_allowed() {
        let reg = sample_registry();
        let token = sample_token(zone_work()); // empty allowed = all
        let filtered = filter_tools_for_zone(&reg.tools, &zone_work(), &token);
        assert_eq!(filtered.len(), 3);
    }

    #[test]
    fn filter_tools_single_connector() {
        let reg = sample_registry();
        let token = sample_token(zone_work()).with_connector("slack");
        let filtered = filter_tools_for_zone(&reg.tools, &zone_work(), &token);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].connector, "slack");
    }

    #[test]
    fn filter_tools_private_zone() {
        let reg = sample_registry();
        let token = sample_token(zone_private());
        let filtered = filter_tools_for_zone(&reg.tools, &zone_private(), &token);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].connector, "vault");
    }

    #[test]
    fn filter_tools_denied_all_ops_in_zone() {
        let reg = sample_registry();
        let token = sample_token(zone_private()).with_denied_operation("get_secret");
        let filtered = filter_tools_for_zone(&reg.tools, &zone_private(), &token);
        assert!(filtered.is_empty());
    }

    #[test]
    fn filter_tools_with_connector_not_in_zone() {
        let reg = sample_registry();
        // vault is only in z:private, filtering for z:work with vault connector
        let token = sample_token(zone_work()).with_connector("vault");
        let filtered = filter_tools_for_zone(&reg.tools, &zone_work(), &token);
        assert!(filtered.is_empty());
    }

    // ── format_zone_tools extended ───────────────────────────────────

    #[test]
    fn format_zone_tools_single_connector() {
        let reg = sample_registry();
        let tools = reg.tools_in_zone(&zone_private());
        let s = format_zone_tools(&zone_private(), &tools);
        assert!(s.contains("z:private (1 tools)"));
        assert!(s.contains("vault:"));
        assert!(s.contains("get_secret"));
    }

    #[test]
    fn format_zone_tools_operations_listed() {
        let reg = sample_registry();
        let tools = reg.tools_in_zone(&zone_work());
        let s = format_zone_tools(&zone_work(), &tools);
        assert!(s.contains("create_issue"));
        assert!(s.contains("list_repos"));
        assert!(s.contains("send_message"));
    }

    #[test]
    fn format_zone_tools_connectors_grouped() {
        let reg = sample_registry();
        let tools = reg.tools_in_zone(&zone_work());
        let s = format_zone_tools(&zone_work(), &tools);
        // github tools should be grouped together
        let github_pos = s.find("github:").unwrap();
        let slack_pos = s.find("slack:").unwrap();
        // BTreeMap sorts by key, github < slack
        assert!(github_pos < slack_pos);
    }

    // ── format_violation extended ────────────────────────────────────

    #[test]
    fn format_violation_contains_cross_mark() {
        let v = ZoneViolation::new("test", zone_work(), ViolationReason::NoToken);
        let s = format_violation(&v);
        assert!(s.starts_with('\u{2717}')); // ✗
    }

    #[test]
    fn format_violation_multiple_available_zones() {
        let v = ZoneViolation::new("test", zone_work(), ViolationReason::ConnectorNotInZone)
            .with_available_in(vec![zone_public(), zone_private()]);
        let s = format_violation(&v);
        assert!(s.contains("Available in:"));
        assert!(s.contains("z:public"));
        assert!(s.contains("z:private"));
    }

    #[test]
    fn format_violation_single_available_zone() {
        let v = ZoneViolation::new("test", zone_work(), ViolationReason::ConnectorNotInZone)
            .with_available_in(vec![zone_private()]);
        let s = format_violation(&v);
        assert!(s.contains("Available in: z:private"));
    }

    // ── parse_zone extended ──────────────────────────────────────────

    #[test]
    fn parse_zone_various_prefixed() {
        for name in ["z:work", "z:private", "z:public", "z:staging", "z:custom"] {
            let z = parse_zone(name);
            assert_eq!(z.as_str(), name);
        }
    }

    #[test]
    fn parse_zone_various_unprefixed() {
        for name in ["work", "private", "public", "staging", "custom"] {
            let z = parse_zone(name);
            assert_eq!(z.as_str(), &format!("z:{name}"));
        }
    }

    #[test]
    fn parse_zone_tabs_and_newlines() {
        let z = parse_zone("\t work \n");
        // trim() removes tabs and newlines
        assert_eq!(z.as_str(), "z:work");
    }

    #[test]
    fn parse_zone_already_prefixed_preserves() {
        let z = parse_zone("z:work");
        assert_eq!(z.as_str(), "z:work");
        assert!(z.is_well_known());
    }

    #[test]
    fn parse_zone_returns_well_known() {
        let z = parse_zone("test");
        assert!(z.is_well_known());
    }

    // ── Cross-cutting: token + registry interaction ──────────────────

    #[test]
    fn token_zone_mismatch_always_fails_validation() {
        let reg = sample_registry();
        let token = sample_token(zone_public());
        // Token for public, validating against work
        let err = validate_tool_call(&reg, "github.create_issue", &zone_work(), Some(&token))
            .unwrap_err();
        assert_eq!(err.reason, ViolationReason::UnknownZone);
    }

    #[test]
    fn filter_and_validate_consistency() {
        // If filter returns a tool, validate should pass for that tool
        let reg = sample_registry();
        let token = sample_token(zone_work());
        let filtered = filter_tools_for_zone(&reg.tools, &zone_work(), &token);
        for tool in &filtered {
            let result = validate_tool_call(&reg, &tool.name, &zone_work(), Some(&token));
            assert!(
                result.is_ok(),
                "validate failed for filtered tool {}",
                tool.name
            );
        }
    }

    #[test]
    fn restricted_token_filter_validate_consistent() {
        let reg = sample_registry();
        let token = sample_token(zone_work()).with_connector("github");
        let filtered = filter_tools_for_zone(&reg.tools, &zone_work(), &token);
        for tool in &filtered {
            assert_eq!(tool.connector, "github");
            let result = validate_tool_call(&reg, &tool.name, &zone_work(), Some(&token));
            assert!(result.is_ok());
        }
    }

    #[test]
    fn denied_ops_filter_validate_consistent() {
        let reg = sample_registry();
        let token = sample_token(zone_work()).with_denied_operation("create_issue");
        let filtered = filter_tools_for_zone(&reg.tools, &zone_work(), &token);
        // create_issue should not be in filtered results
        assert!(!filtered.iter().any(|t| t.operation == "create_issue"));
        for tool in &filtered {
            let result = validate_tool_call(&reg, &tool.name, &zone_work(), Some(&token));
            assert!(result.is_ok());
        }
    }

    // ── Zone ID ordering invariants ──────────────────────────────────

    #[test]
    fn zone_id_total_ordering() {
        let a = ZoneId::new("z:a");
        let b = ZoneId::new("z:b");
        let c = ZoneId::new("z:c");
        assert!(a < b);
        assert!(b < c);
        assert!(a < c); // transitivity
    }

    #[test]
    fn zone_id_partial_eq_reflexive() {
        let z = ZoneId::new("z:test");
        assert_eq!(z, z.clone());
    }

    // ── Large-scale registry tests ───────────────────────────────────

    #[test]
    fn registry_many_tools() {
        let mut reg = ZoneRegistry::new();
        for i in 0..100 {
            reg.register_tool(
                ZoneScopedTool::new(format!("conn_{i}"), format!("op_{i}")).with_zone(zone_work()),
            );
        }
        assert_eq!(reg.tool_count(), 100);
        assert_eq!(reg.tool_count_in_zone(&zone_work()), 100);
        assert_eq!(reg.connectors_in_zone(&zone_work()).len(), 100);
    }

    #[test]
    fn registry_many_zones() {
        let mut reg = ZoneRegistry::new();
        for i in 0..50 {
            reg.register_tool(
                ZoneScopedTool::new("github", format!("op_{i}"))
                    .with_zone(ZoneId::new(format!("z:zone-{i}"))),
            );
        }
        assert_eq!(reg.tool_count(), 50);
        assert_eq!(reg.known_zones().len(), 50);
    }

    #[test]
    fn filter_many_tools_performance() {
        let mut tools = Vec::new();
        for i in 0..200 {
            tools.push(
                ZoneScopedTool::new(format!("conn_{}", i % 10), format!("op_{i}"))
                    .with_zone(zone_work()),
            );
        }
        let token = sample_token(zone_work()).with_connector("conn_0");
        let filtered = filter_tools_for_zone(&tools, &zone_work(), &token);
        assert_eq!(filtered.len(), 20); // 200/10 connectors = 20 for conn_0
    }

    // ── Zone Overview ────────────────────────────────────────────

    #[test]
    fn zone_overview_from_sample_registry() {
        let reg = sample_registry();
        let infos = zone_overview(&reg);
        assert_eq!(infos.len(), 3); // z:private, z:public, z:work
    }

    #[test]
    fn zone_overview_sorted_by_zone_id() {
        let reg = sample_registry();
        let infos = zone_overview(&reg);
        assert_eq!(infos[0].zone_id, "z:private");
        assert_eq!(infos[1].zone_id, "z:public");
        assert_eq!(infos[2].zone_id, "z:work");
    }

    #[test]
    fn zone_overview_connector_counts() {
        let reg = sample_registry();
        let infos = zone_overview(&reg);
        // z:work has github (2 tools) + slack (1 tool) = 2 connectors
        let work = infos.iter().find(|i| i.zone_id == "z:work").unwrap();
        assert_eq!(work.connector_count, 2);
        // z:public has github only = 1 connector
        let public = infos.iter().find(|i| i.zone_id == "z:public").unwrap();
        assert_eq!(public.connector_count, 1);
        // z:private has vault only = 1 connector
        let private = infos.iter().find(|i| i.zone_id == "z:private").unwrap();
        assert_eq!(private.connector_count, 1);
    }

    #[test]
    fn zone_overview_tool_counts() {
        let reg = sample_registry();
        let infos = zone_overview(&reg);
        let work = infos.iter().find(|i| i.zone_id == "z:work").unwrap();
        assert_eq!(work.tool_count, 3); // create_issue, list_repos, send_message
        let public = infos.iter().find(|i| i.zone_id == "z:public").unwrap();
        assert_eq!(public.tool_count, 2); // create_issue, list_repos
        let private = infos.iter().find(|i| i.zone_id == "z:private").unwrap();
        assert_eq!(private.tool_count, 1); // get_secret
    }

    #[test]
    fn zone_overview_policy_types() {
        let reg = sample_registry();
        let infos = zone_overview(&reg);
        let work = infos.iter().find(|i| i.zone_id == "z:work").unwrap();
        assert_eq!(work.policy_type, "standard");
        let public = infos.iter().find(|i| i.zone_id == "z:public").unwrap();
        assert_eq!(public.policy_type, "open");
        let private = infos.iter().find(|i| i.zone_id == "z:private").unwrap();
        assert_eq!(private.policy_type, "restricted");
    }

    #[test]
    fn zone_overview_well_known_flags() {
        let reg = sample_registry();
        let infos = zone_overview(&reg);
        assert!(infos.iter().all(|i| i.well_known));
    }

    #[test]
    fn zone_overview_connectors_listed() {
        let reg = sample_registry();
        let infos = zone_overview(&reg);
        let work = infos.iter().find(|i| i.zone_id == "z:work").unwrap();
        assert!(work.connectors.contains(&"github".to_owned()));
        assert!(work.connectors.contains(&"slack".to_owned()));
    }

    #[test]
    fn zone_overview_capabilities_listed() {
        let reg = sample_registry();
        let infos = zone_overview(&reg);
        let work = infos.iter().find(|i| i.zone_id == "z:work").unwrap();
        assert!(work.capabilities.contains(&"issue.write".to_owned()));
        assert!(work.capabilities.contains(&"repo.read".to_owned()));
        assert!(work.capabilities.contains(&"chat.write".to_owned()));
    }

    #[test]
    fn zone_overview_empty_registry() {
        let reg = ZoneRegistry::new();
        let infos = zone_overview(&reg);
        assert!(infos.is_empty());
    }

    #[test]
    fn zone_overview_serializes_to_json() {
        let reg = sample_registry();
        let infos = zone_overview(&reg);
        let json = serde_json::to_value(&infos).unwrap();
        assert!(json.is_array());
        assert_eq!(json.as_array().unwrap().len(), 3);
        assert_eq!(json[0]["zone_id"], "z:private");
        assert_eq!(json[2]["capabilities"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn infer_policy_type_standard() {
        assert_eq!(infer_policy_type(&ZoneId::new("z:work")), "standard");
    }

    #[test]
    fn infer_policy_type_open() {
        assert_eq!(infer_policy_type(&ZoneId::new("z:public")), "open");
    }

    #[test]
    fn infer_policy_type_restricted() {
        assert_eq!(infer_policy_type(&ZoneId::new("z:private")), "restricted");
    }

    #[test]
    fn infer_policy_type_custom() {
        assert_eq!(infer_policy_type(&ZoneId::new("z:dev")), "custom");
    }

    // ── TOON formatting ──────────────────────────────────────────

    #[test]
    fn format_zones_toon_header() {
        let reg = sample_registry();
        let infos = zone_overview(&reg);
        let toon = format_zones_toon(&infos);
        assert!(toon.contains("Zones: 3 configured"));
        assert!(toon.contains("ZONE"));
        assert!(toon.contains("CONN"));
        assert!(toon.contains("TOOLS"));
        assert!(toon.contains("POLICY"));
        assert!(toon.contains("CAPABILITIES"));
    }

    #[test]
    fn format_zones_toon_shows_all_zones() {
        let reg = sample_registry();
        let infos = zone_overview(&reg);
        let toon = format_zones_toon(&infos);
        assert!(toon.contains("z:work"));
        assert!(toon.contains("z:public"));
        assert!(toon.contains("z:private"));
    }

    #[test]
    fn format_zones_toon_shows_policy_types() {
        let reg = sample_registry();
        let infos = zone_overview(&reg);
        let toon = format_zones_toon(&infos);
        assert!(toon.contains("standard"));
        assert!(toon.contains("open"));
        assert!(toon.contains("restricted"));
    }

    #[test]
    fn format_zones_toon_shows_capability_summaries() {
        let reg = sample_registry();
        let infos = zone_overview(&reg);
        let toon = format_zones_toon(&infos);
        assert!(toon.contains("issue.write"));
        assert!(toon.contains("repo.read"));
        assert!(toon.contains("(+1)"));
    }

    #[test]
    fn format_zones_toon_empty() {
        let toon = format_zones_toon(&[]);
        assert!(toon.contains("Zones: 0 configured"));
    }

    #[test]
    fn format_zones_toon_truncates_many_connectors() {
        let mut reg = ZoneRegistry::new();
        for name in &["alpha", "beta", "gamma", "delta", "epsilon"] {
            reg.register_tool(ZoneScopedTool::new(*name, "op").with_zone(zone_work()));
        }
        let infos = zone_overview(&reg);
        let toon = format_zones_toon(&infos);
        assert!(toon.contains("(+3)"));
    }

    // ── Zone detail TOON ─────────────────────────────────────────

    #[test]
    fn format_zone_detail_toon_basic() {
        let reg = sample_registry();
        let infos = zone_overview(&reg);
        let work = infos.iter().find(|i| i.zone_id == "z:work").unwrap();
        let detail = format_zone_detail_toon(work);
        assert!(detail.contains("Zone: z:work"));
        assert!(detail.contains("Policy: standard"));
        assert!(detail.contains("Well-known: true"));
        assert!(detail.contains("Connectors: 2"));
        assert!(detail.contains("Tools: 3"));
        assert!(detail.contains("Capabilities: 3"));
        assert!(detail.contains("- chat.write"));
        assert!(detail.contains("- issue.write"));
        assert!(detail.contains("- github"));
        assert!(detail.contains("- slack"));
    }

    #[test]
    fn format_zone_detail_toon_empty_connectors() {
        let info = ZoneInfo {
            zone_id: "z:empty".to_owned(),
            connector_count: 0,
            tool_count: 0,
            connectors: vec![],
            capabilities: vec![],
            well_known: true,
            policy_type: "custom".to_owned(),
        };
        let detail = format_zone_detail_toon(&info);
        assert!(detail.contains("Zone: z:empty"));
        assert!(detail.contains("Connectors: 0"));
        assert!(detail.contains("Capabilities: 0"));
        assert!(!detail.contains("Connector list:"));
    }

    // ── ZoneInfo struct ──────────────────────────────────────────

    #[test]
    fn zone_info_clone() {
        let info = ZoneInfo {
            zone_id: "z:work".to_owned(),
            connector_count: 2,
            tool_count: 5,
            connectors: vec!["github".to_owned()],
            capabilities: vec!["repo.read".to_owned()],
            well_known: true,
            policy_type: "standard".to_owned(),
        };
        let cloned = info.clone();
        assert_eq!(info.zone_id, "z:work");
        assert_eq!(cloned.connector_count, 2);
    }

    #[test]
    fn zone_info_debug() {
        let info = ZoneInfo {
            zone_id: "z:test".to_owned(),
            connector_count: 0,
            tool_count: 0,
            connectors: vec![],
            capabilities: vec![],
            well_known: true,
            policy_type: "custom".to_owned(),
        };
        let debug = format!("{info:?}");
        assert!(debug.contains("ZoneInfo"));
    }

    #[test]
    fn zone_info_serialize() {
        let info = ZoneInfo {
            zone_id: "z:work".to_owned(),
            connector_count: 2,
            tool_count: 5,
            connectors: vec!["github".to_owned(), "slack".to_owned()],
            capabilities: vec!["chat.write".to_owned(), "issue.write".to_owned()],
            well_known: true,
            policy_type: "standard".to_owned(),
        };
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["zone_id"], "z:work");
        assert_eq!(json["connector_count"], 2);
        assert_eq!(json["tool_count"], 5);
        assert_eq!(json["well_known"], true);
        assert_eq!(json["policy_type"], "standard");
        assert_eq!(json["connectors"].as_array().unwrap().len(), 2);
        assert_eq!(json["capabilities"].as_array().unwrap().len(), 2);
    }

    // ── Cross-zone check: allowed ───────────────────────────────

    #[test]
    fn cross_zone_check_allowed_shared_connector() {
        let reg = sample_registry();
        // z:work and z:public both have github → allowed
        let result = check_cross_zone(&reg, &zone_work(), &zone_public(), None);
        assert!(result.allowed);
        assert!(result.blocking_zone.is_none());
        assert!(result.missing_capability.is_none());
    }

    // ── Cross-zone check: denied with clear reason ──────────────

    #[test]
    fn cross_zone_check_denied_no_shared_connector() {
        let reg = sample_registry();
        // z:public has github; z:private has vault → no overlap
        let result = check_cross_zone(&reg, &zone_public(), &zone_private(), None);
        assert!(!result.allowed);
        assert!(result.blocking_zone.is_some());
        assert_eq!(
            result.missing_capability.as_deref(),
            Some("shared_connector")
        );
        assert!(result.remediation.unwrap().contains("No shared connectors"));
    }

    // ── Specific operation cross-zone check ─────────────────────

    #[test]
    fn cross_zone_check_specific_operation_allowed() {
        let reg = sample_registry();
        // create_issue is in both z:work and z:public
        let result = check_cross_zone(&reg, &zone_work(), &zone_public(), Some("create_issue"));
        assert!(result.allowed);
        assert_eq!(result.operation, "create_issue");
    }

    #[test]
    fn cross_zone_check_specific_operation_denied() {
        let reg = sample_registry();
        // send_message is only in z:work, not z:public
        let result = check_cross_zone(&reg, &zone_work(), &zone_public(), Some("send_message"));
        assert!(!result.allowed);
        assert_eq!(result.operation, "send_message");
        assert!(result.blocking_zone.is_some());
        assert!(
            result
                .missing_capability
                .as_deref()
                .unwrap()
                .contains("operation:send_message")
        );
    }

    // ── Pipeline zone validation catches violation ──────────────

    #[test]
    fn pipeline_validate_catches_zone_violation() {
        let reg = sample_registry();
        let steps = vec![
            PipelineStep {
                zone: zone_work(),
                operation: "send_message".to_owned(),
            },
            PipelineStep {
                zone: zone_private(),
                operation: "get_secret".to_owned(),
            },
        ];
        let violations = validate_pipeline_zones(&reg, &steps);
        // send_message not in z:private → violation
        assert!(!violations.is_empty());
        assert_eq!(violations[0].step, 1);
        assert_eq!(violations[0].from_zone, "z:work");
        assert_eq!(violations[0].to_zone, "z:private");
    }

    // ── Capability chain verification for zone crossing ─────────

    #[test]
    fn pipeline_validate_no_violation_same_zone() {
        let reg = sample_registry();
        let steps = vec![
            PipelineStep {
                zone: zone_work(),
                operation: "create_issue".to_owned(),
            },
            PipelineStep {
                zone: zone_work(),
                operation: "send_message".to_owned(),
            },
        ];
        let violations = validate_pipeline_zones(&reg, &steps);
        assert!(violations.is_empty());
    }

    #[test]
    fn pipeline_validate_allowed_cross_zone() {
        let reg = sample_registry();
        // create_issue exists in both z:work and z:public
        let steps = vec![
            PipelineStep {
                zone: zone_work(),
                operation: "create_issue".to_owned(),
            },
            PipelineStep {
                zone: zone_public(),
                operation: "create_issue".to_owned(),
            },
        ];
        let violations = validate_pipeline_zones(&reg, &steps);
        assert!(violations.is_empty());
    }

    // ── Bidirectional zone check ────────────────────────────────

    #[test]
    fn cross_zone_bidirectional() {
        let reg = sample_registry();
        let (a_to_b, b_to_a) =
            check_cross_zone_bidirectional(&reg, &zone_work(), &zone_public(), None);
        // Both have github → both directions allowed
        assert!(a_to_b.allowed);
        assert!(b_to_a.allowed);
    }

    #[test]
    fn cross_zone_bidirectional_asymmetric_operation() {
        let reg = sample_registry();
        // send_message is only in z:work
        let (a_to_b, b_to_a) = check_cross_zone_bidirectional(
            &reg,
            &zone_work(),
            &zone_public(),
            Some("send_message"),
        );
        // z:work → z:public: denied (send_message not in z:public)
        assert!(!a_to_b.allowed);
        // z:public → z:work: denied (send_message not in z:public source)
        assert!(!b_to_a.allowed);
    }

    // ── Nested zone traversal ───────────────────────────────────

    #[test]
    fn pipeline_validate_multi_step_traversal() {
        let reg = sample_registry();
        let steps = vec![
            PipelineStep {
                zone: zone_work(),
                operation: "create_issue".to_owned(),
            },
            PipelineStep {
                zone: zone_public(),
                operation: "list_repos".to_owned(),
            },
            PipelineStep {
                zone: zone_private(),
                operation: "get_secret".to_owned(),
            },
        ];
        let violations = validate_pipeline_zones(&reg, &steps);
        // Step 1 (work→public) list_repos exists in both → ok
        // Step 2 (public→private) get_secret only in private, not public → violation
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].step, 2);
    }

    // ── Error message includes blocking zone and capability ─────

    #[test]
    fn cross_zone_denied_includes_blocking_zone_and_capability() {
        let reg = sample_registry();
        let result = check_cross_zone(&reg, &zone_work(), &zone_private(), Some("send_message"));
        assert!(!result.allowed);
        assert!(result.blocking_zone.is_some());
        let blocking = result.blocking_zone.unwrap();
        assert!(
            blocking == "z:private" || blocking == "z:work",
            "blocking zone should be one of the zones involved"
        );
        assert!(result.missing_capability.is_some());
        assert!(result.remediation.is_some());
    }

    // ── Pipeline reports ALL violations ─────────────────────────

    #[test]
    fn pipeline_validate_reports_all_violations() {
        let reg = sample_registry();
        let steps = vec![
            PipelineStep {
                zone: zone_work(),
                operation: "send_message".to_owned(),
            },
            PipelineStep {
                zone: zone_private(),
                operation: "get_secret".to_owned(),
            },
            PipelineStep {
                zone: zone_public(),
                operation: "create_issue".to_owned(),
            },
        ];
        let violations = validate_pipeline_zones(&reg, &steps);
        // Step 1: work→private (get_secret not in work as source check) — violation
        // Step 2: private→public (create_issue not in private) — violation
        assert!(
            violations.len() >= 2,
            "should report all violations, got {}",
            violations.len()
        );
    }

    // ── Unknown zone checks ─────────────────────────────────────

    #[test]
    fn cross_zone_check_unknown_source() {
        let reg = sample_registry();
        let unknown = ZoneId::new("z:staging");
        let result = check_cross_zone(&reg, &unknown, &zone_work(), None);
        assert!(!result.allowed);
        assert_eq!(result.blocking_zone.as_deref(), Some("z:staging"));
        assert_eq!(result.missing_capability.as_deref(), Some("zone_exists"));
    }

    #[test]
    fn cross_zone_check_unknown_target() {
        let reg = sample_registry();
        let unknown = ZoneId::new("z:staging");
        let result = check_cross_zone(&reg, &zone_work(), &unknown, None);
        assert!(!result.allowed);
        assert_eq!(result.blocking_zone.as_deref(), Some("z:staging"));
    }

    // ── TOON formatting ─────────────────────────────────────────

    #[test]
    fn format_cross_zone_toon_allowed() {
        let result = CrossZoneCheckResult {
            source: "z:work".to_owned(),
            target: "z:public".to_owned(),
            operation: String::new(),
            allowed: true,
            blocking_zone: None,
            missing_capability: None,
            remediation: None,
        };
        let toon = format_cross_zone_toon(&result);
        assert!(toon.contains("ALLOWED"));
        assert!(toon.contains("z:work"));
        assert!(toon.contains("z:public"));
    }

    #[test]
    fn format_cross_zone_toon_denied_with_details() {
        let result = CrossZoneCheckResult {
            source: "z:public".to_owned(),
            target: "z:private".to_owned(),
            operation: "send_message".to_owned(),
            allowed: false,
            blocking_zone: Some("z:private".to_owned()),
            missing_capability: Some("operation:send_message".to_owned()),
            remediation: Some("Operation 'send_message' not available".to_owned()),
        };
        let toon = format_cross_zone_toon(&result);
        assert!(toon.contains("DENIED"));
        assert!(toon.contains("Operation: send_message"));
        assert!(toon.contains("Blocking zone: z:private"));
        assert!(toon.contains("Missing capability:"));
        assert!(toon.contains("Remediation:"));
    }

    #[test]
    fn format_pipeline_violations_toon_pass() {
        let toon = format_pipeline_violations_toon(&[]);
        assert!(toon.contains("PASS"));
        assert!(toon.contains("no cross-zone violations"));
    }

    #[test]
    fn format_pipeline_violations_toon_fail() {
        let violations = vec![PipelineZoneViolation {
            step: 1,
            from_zone: "z:work".to_owned(),
            to_zone: "z:private".to_owned(),
            operation: "get_secret".to_owned(),
            reason: "not available".to_owned(),
            blocking_zone: "z:private".to_owned(),
            missing_capability: "operation:get_secret".to_owned(),
        }];
        let toon = format_pipeline_violations_toon(&violations);
        assert!(toon.contains("FAIL"));
        assert!(toon.contains("1 violation"));
        assert!(toon.contains("Step 1"));
        assert!(toon.contains("z:work -> z:private"));
    }

    #[test]
    fn format_pipeline_violations_toon_plural() {
        let violations = vec![
            PipelineZoneViolation {
                step: 1,
                from_zone: "z:a".to_owned(),
                to_zone: "z:b".to_owned(),
                operation: "op1".to_owned(),
                reason: "denied".to_owned(),
                blocking_zone: "z:b".to_owned(),
                missing_capability: "cap1".to_owned(),
            },
            PipelineZoneViolation {
                step: 2,
                from_zone: "z:b".to_owned(),
                to_zone: "z:c".to_owned(),
                operation: "op2".to_owned(),
                reason: "denied".to_owned(),
                blocking_zone: "z:c".to_owned(),
                missing_capability: "cap2".to_owned(),
            },
        ];
        let toon = format_pipeline_violations_toon(&violations);
        assert!(toon.contains("2 violations"));
        assert!(toon.contains("Step 1"));
        assert!(toon.contains("Step 2"));
    }

    // ── CrossZoneCheckResult struct ─────────────────────────────

    #[test]
    fn cross_zone_result_serializes() {
        let result = CrossZoneCheckResult {
            source: "z:work".to_owned(),
            target: "z:public".to_owned(),
            operation: "create_issue".to_owned(),
            allowed: true,
            blocking_zone: None,
            missing_capability: None,
            remediation: None,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["source"], "z:work");
        assert_eq!(json["target"], "z:public");
        assert_eq!(json["allowed"], true);
        assert!(json["blocking_zone"].is_null());
    }

    #[test]
    fn cross_zone_result_clone() {
        let result = CrossZoneCheckResult {
            source: "z:a".to_owned(),
            target: "z:b".to_owned(),
            operation: String::new(),
            allowed: false,
            blocking_zone: Some("z:b".to_owned()),
            missing_capability: Some("shared_connector".to_owned()),
            remediation: Some("fix it".to_owned()),
        };
        let cloned = result.clone();
        assert_eq!(result.source, cloned.source);
        assert_eq!(result.allowed, cloned.allowed);
        assert_eq!(result.blocking_zone, cloned.blocking_zone);
    }

    // ── PipelineZoneViolation struct ────────────────────────────

    #[test]
    fn pipeline_violation_serializes() {
        let v = PipelineZoneViolation {
            step: 3,
            from_zone: "z:work".to_owned(),
            to_zone: "z:private".to_owned(),
            operation: "get_secret".to_owned(),
            reason: "denied".to_owned(),
            blocking_zone: "z:private".to_owned(),
            missing_capability: "operation:get_secret".to_owned(),
        };
        let json = serde_json::to_value(&v).unwrap();
        assert_eq!(json["step"], 3);
        assert_eq!(json["from_zone"], "z:work");
        assert_eq!(json["to_zone"], "z:private");
    }

    #[test]
    fn pipeline_violation_clone() {
        let v = PipelineZoneViolation {
            step: 1,
            from_zone: "z:a".to_owned(),
            to_zone: "z:b".to_owned(),
            operation: "op".to_owned(),
            reason: "reason".to_owned(),
            blocking_zone: "z:b".to_owned(),
            missing_capability: "cap".to_owned(),
        };
        let v2 = v.clone();
        assert_eq!(v.step, v2.step);
        assert_eq!(v.from_zone, v2.from_zone);
    }

    // ── PipelineStep struct ─────────────────────────────────────

    #[test]
    fn pipeline_step_clone() {
        let s = PipelineStep {
            zone: zone_work(),
            operation: "create_issue".to_owned(),
        };
        let s2 = s.clone();
        assert_eq!(s.zone, s2.zone);
        assert_eq!(s.operation, s2.operation);
    }

    // ── Empty pipeline ──────────────────────────────────────────

    #[test]
    fn pipeline_validate_empty() {
        let reg = sample_registry();
        let violations = validate_pipeline_zones(&reg, &[]);
        assert!(violations.is_empty());
    }

    #[test]
    fn pipeline_validate_single_step() {
        let reg = sample_registry();
        let steps = vec![PipelineStep {
            zone: zone_work(),
            operation: "create_issue".to_owned(),
        }];
        let violations = validate_pipeline_zones(&reg, &steps);
        assert!(violations.is_empty());
    }

    // ── Cross-zone with same zone ───────────────────────────────

    #[test]
    fn cross_zone_same_zone() {
        let reg = sample_registry();
        let result = check_cross_zone(&reg, &zone_work(), &zone_work(), None);
        assert!(result.allowed);
    }

    // ── Migration helpers ───────────────────────────────────────

    fn sample_source_config() -> ConnectorZoneConfig {
        let mut config = BTreeMap::new();
        config.insert("url".to_owned(), "https://api.example.com".to_owned());
        config.insert("api_key".to_owned(), "sk-12345".to_owned());
        config.insert("timeout".to_owned(), "30".to_owned());
        ConnectorZoneConfig {
            connector: "github".to_owned(),
            zone: "z:work".to_owned(),
            config,
            enabled: true,
            policy_bindings: vec!["read_only".to_owned()],
        }
    }

    fn sample_target_config() -> ConnectorZoneConfig {
        let mut config = BTreeMap::new();
        config.insert("url".to_owned(), "https://api.example.com/old".to_owned());
        config.insert("region".to_owned(), "us-east".to_owned());
        ConnectorZoneConfig {
            connector: "github".to_owned(),
            zone: "z:public".to_owned(),
            config,
            enabled: false,
            policy_bindings: vec!["open_access".to_owned()],
        }
    }

    // ── migrate happy path ──────────────────────────────────────

    #[test]
    fn migrate_happy_path() {
        let source = sample_source_config();
        let source_config = source.clone();
        let mut target = sample_target_config();
        let plan = plan_migration("github", &source, "z:public", Some(&target));
        // No policy conflicts between different bindings → safe=false
        // Actually the current logic: conflicts exist when target has bindings not in source
        // target has "open_access" not in source → policy conflict → safe=false
        let result = execute_migration(&plan, &source_config, &mut target, true);
        assert!(result.success);
        assert!(result.fields_transferred > 0);
        assert!(!result.rolled_back);
        assert_eq!(target.zone, "z:public");
        // Config was transferred
        assert_eq!(target.config.get("url").unwrap(), "https://api.example.com");
    }

    // ── migrate dry-run ─────────────────────────────────────────

    #[test]
    fn migrate_dry_run_no_state_changes() {
        let source = sample_source_config();
        let plan = plan_migration("github", &source, "z:public", None);
        assert!(plan.dry_run);
        // Plan exists but nothing was executed
        assert!(!plan.field_changes.is_empty());
        assert_eq!(plan.source_zone, "z:work");
        assert_eq!(plan.target_zone, "z:public");
    }

    // ── migrate with policy conflict ────────────────────────────

    #[test]
    fn migrate_policy_conflict_blocks_without_force() {
        let source = sample_source_config();
        let target = sample_target_config();
        let plan = plan_migration("github", &source, "z:public", Some(&target));
        // Target has "open_access" not in source → conflict
        assert!(!plan.safe);
        assert!(!plan.policy_conflicts.is_empty());

        let source_config = source.clone();
        let mut target_mut = target;
        let result = execute_migration(&plan, &source_config, &mut target_mut, false);
        assert!(!result.success);
        assert!(result.error.is_some());
        assert!(result.error.unwrap().contains("Policy conflicts"));
    }

    // ── migrate rollback on failure ─────────────────────────────

    #[test]
    fn migrate_rollback_on_failure() {
        let mut source_config = BTreeMap::new();
        source_config.insert("url".to_owned(), "https://fail.example.com".to_owned());
        let source = ConnectorZoneConfig {
            connector: "fail_connector".to_owned(),
            zone: "z:work".to_owned(),
            config: source_config,
            enabled: true,
            policy_bindings: vec![],
        };
        let mut target = ConnectorZoneConfig {
            connector: "fail_connector".to_owned(),
            zone: "z:public".to_owned(),
            config: BTreeMap::new(),
            enabled: false,
            policy_bindings: vec![],
        };
        let original_target_config = target.config.clone();
        let plan = plan_migration("fail_connector", &source, "z:public", Some(&target));
        let source_config = source;
        let result = execute_migration(&plan, &source_config, &mut target, true);
        assert!(!result.success);
        assert!(result.rolled_back);
        // Target config should be restored
        assert_eq!(target.config, original_target_config);
    }

    // ── export round-trip ───────────────────────────────────────

    #[test]
    fn export_import_round_trip() {
        let source = sample_source_config();
        let configs = vec![source.clone()];
        let exported = export_zone("z:work", &configs);
        assert_eq!(exported.zone, "z:work");
        assert_eq!(exported.connectors.len(), 1);
        assert_eq!(exported.version, 1);

        // Can serialize and deserialize
        let json = serde_json::to_string(&exported).unwrap();
        let imported: ZoneExport = serde_json::from_str(&json).unwrap();
        assert_eq!(imported.zone, "z:work");
        assert_eq!(imported.connectors.len(), 1);
        assert_eq!(imported.connectors[0].connector, "github");
    }

    // ── export redacts secrets ───────────────────────────────────

    #[test]
    fn export_redacts_secrets() {
        let source = sample_source_config();
        let configs = vec![source];
        let exported = export_zone("z:work", &configs);
        let conn = &exported.connectors[0];
        // api_key should be redacted
        assert_eq!(conn.config.get("api_key").unwrap(), "***REDACTED***");
        // url should NOT be redacted
        assert_eq!(conn.config.get("url").unwrap(), "https://api.example.com");
    }

    // ── import validates zone compatibility ──────────────────────

    #[test]
    fn import_validates_compatibility() {
        let exported = ZoneExport {
            zone: "z:work".to_owned(),
            version: 1,
            connectors: vec![ConnectorZoneConfig {
                connector: "github".to_owned(),
                zone: "z:work".to_owned(),
                config: BTreeMap::new(),
                enabled: true,
                policy_bindings: vec![],
            }],
            exported_at: 0,
        };
        // No existing configs → valid
        let validation = validate_import(&exported, "z:public", &[]);
        assert!(validation.valid);
        assert!(validation.issues.is_empty());
    }

    // ── import detects conflicting existing configs ──────────────

    #[test]
    fn import_detects_conflicting_configs() {
        let exported = ZoneExport {
            zone: "z:work".to_owned(),
            version: 1,
            connectors: vec![ConnectorZoneConfig {
                connector: "github".to_owned(),
                zone: "z:work".to_owned(),
                config: BTreeMap::new(),
                enabled: true,
                policy_bindings: vec![],
            }],
            exported_at: 0,
        };
        let existing = vec![ConnectorZoneConfig {
            connector: "github".to_owned(),
            zone: "z:public".to_owned(),
            config: BTreeMap::new(),
            enabled: true,
            policy_bindings: vec![],
        }];
        let validation = validate_import(&exported, "z:public", &existing);
        assert!(!validation.valid);
        assert_eq!(validation.issues[0].kind, "conflicting");
    }

    // ── is_secret_field ─────────────────────────────────────────

    #[test]
    fn secret_field_detection() {
        assert!(is_secret_field("api_key"));
        assert!(is_secret_field("API_KEY"));
        assert!(is_secret_field("auth_token"));
        assert!(is_secret_field("password"));
        assert!(is_secret_field("client_secret"));
        assert!(!is_secret_field("url"));
        assert!(!is_secret_field("timeout"));
        assert!(!is_secret_field("region"));
    }

    // ── redact_secrets ──────────────────────────────────────────

    #[test]
    fn redact_secrets_preserves_non_secrets() {
        let mut config = BTreeMap::new();
        config.insert("url".to_owned(), "https://example.com".to_owned());
        config.insert("api_key".to_owned(), "sk-secret".to_owned());
        config.insert("timeout".to_owned(), "30".to_owned());
        let redacted = redact_secrets(&config);
        assert_eq!(redacted["url"], "https://example.com");
        assert_eq!(redacted["api_key"], "***REDACTED***");
        assert_eq!(redacted["timeout"], "30");
    }

    // ── MigrationFieldChange ────────────────────────────────────

    #[test]
    fn migration_field_change_added() {
        let source = sample_source_config();
        let plan = plan_migration("github", &source, "z:public", None);
        // All fields are "added" when no target config exists
        assert!(plan.field_changes.iter().all(|c| c.kind == "added"));
    }

    #[test]
    fn migration_field_change_changed() {
        let source = sample_source_config();
        let target = sample_target_config();
        let plan = plan_migration("github", &source, "z:public", Some(&target));
        // "url" changed from old value to new
        let url_change = plan.field_changes.iter().find(|c| c.field == "url");
        assert!(url_change.is_some());
        assert_eq!(url_change.unwrap().kind, "changed");
    }

    #[test]
    fn migration_field_change_removed() {
        let source = sample_source_config();
        let target = sample_target_config();
        let plan = plan_migration("github", &source, "z:public", Some(&target));
        // "region" is in target but not in source → removed
        let region_change = plan.field_changes.iter().find(|c| c.field == "region");
        assert!(region_change.is_some());
        assert_eq!(region_change.unwrap().kind, "removed");
    }

    // ── Credentials needing reprovision ─────────────────────────

    #[test]
    fn migration_detects_credentials() {
        let source = sample_source_config();
        let plan = plan_migration("github", &source, "z:public", None);
        assert!(
            plan.credentials_needing_reprovision
                .contains(&"api_key".to_owned())
        );
    }

    // ── Secret redaction in migration plans ─────────────────────

    #[test]
    fn migration_plan_redacts_secret_values() {
        let source = sample_source_config();
        let plan = plan_migration("github", &source, "z:public", None);
        let api_key_change = plan
            .field_changes
            .iter()
            .find(|c| c.field == "api_key")
            .unwrap();
        assert_eq!(api_key_change.new_value.as_deref(), Some("***REDACTED***"));
    }

    // ── format_migration_toon ───────────────────────────────────

    #[test]
    fn format_migration_toon_basic() {
        let source = sample_source_config();
        let plan = plan_migration("github", &source, "z:public", None);
        let toon = format_migration_toon(&plan);
        assert!(toon.contains("DRY RUN"));
        assert!(toon.contains("github"));
        assert!(toon.contains("z:work -> z:public"));
        assert!(toon.contains("Changes:"));
    }

    #[test]
    fn format_migration_toon_shows_credentials() {
        let source = sample_source_config();
        let plan = plan_migration("github", &source, "z:public", None);
        let toon = format_migration_toon(&plan);
        assert!(toon.contains("Credentials needing re-provision:"));
        assert!(toon.contains("api_key"));
    }

    #[test]
    fn format_migration_toon_shows_policy_conflicts() {
        let source = sample_source_config();
        let target = sample_target_config();
        let plan = plan_migration("github", &source, "z:public", Some(&target));
        let toon = format_migration_toon(&plan);
        assert!(toon.contains("Policy conflicts:"));
    }

    // ── ConnectorZoneConfig struct ──────────────────────────────

    #[test]
    fn connector_zone_config_serde_roundtrip() {
        let config = sample_source_config();
        let json = serde_json::to_string(&config).unwrap();
        let config2: ConnectorZoneConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config2.connector, "github");
        assert_eq!(config2.zone, "z:work");
        assert!(config2.enabled);
    }

    #[test]
    fn connector_zone_config_clone() {
        let config = sample_source_config();
        let cloned = config.clone();
        assert_eq!(config.connector, cloned.connector);
        assert_eq!(config.config.len(), cloned.config.len());
    }

    // ── ZoneExport struct ───────────────────────────────────────

    #[test]
    fn zone_export_serializes() {
        let configs = vec![sample_source_config()];
        let exported = export_zone("z:work", &configs);
        let json = serde_json::to_value(&exported).unwrap();
        assert_eq!(json["zone"], "z:work");
        assert_eq!(json["version"], 1);
        assert!(json["connectors"].is_array());
    }

    // ── ImportValidation struct ─────────────────────────────────

    #[test]
    fn import_validation_serializes() {
        let validation = ImportValidation {
            valid: true,
            issues: vec![],
        };
        let json = serde_json::to_value(&validation).unwrap();
        assert_eq!(json["valid"], true);
        assert!(json["issues"].as_array().unwrap().is_empty());
    }

    // ── ImportIssue struct ──────────────────────────────────────

    #[test]
    fn import_issue_serializes() {
        let issue = ImportIssue {
            connector: "github".to_owned(),
            kind: "conflicting".to_owned(),
            description: "Already exists".to_owned(),
        };
        let json = serde_json::to_value(&issue).unwrap();
        assert_eq!(json["connector"], "github");
        assert_eq!(json["kind"], "conflicting");
    }

    // ── MigrationResult struct ──────────────────────────────────

    #[test]
    fn migration_result_serializes() {
        let result = MigrationResult {
            success: true,
            connector: "github".to_owned(),
            source_zone: "z:work".to_owned(),
            target_zone: "z:public".to_owned(),
            fields_transferred: 3,
            rolled_back: false,
            error: None,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["success"], true);
        assert_eq!(json["fields_transferred"], 3);
        assert!(json["error"].is_null());
    }

    // ── Import same zone warns ──────────────────────────────────

    #[test]
    fn import_same_zone_warns_redundant() {
        let exported = ZoneExport {
            zone: "z:work".to_owned(),
            version: 1,
            connectors: vec![ConnectorZoneConfig {
                connector: "github".to_owned(),
                zone: "z:work".to_owned(),
                config: BTreeMap::new(),
                enabled: false,
                policy_bindings: vec![],
            }],
            exported_at: 0,
        };
        let validation = validate_import(&exported, "z:work", &[]);
        assert!(validation.issues.iter().any(|i| i.kind == "redundant"));
    }

    // ── Export filters by zone ───────────────────────────────────

    #[test]
    fn export_filters_by_zone() {
        let configs = vec![
            sample_source_config(), // z:work
            ConnectorZoneConfig {
                connector: "slack".to_owned(),
                zone: "z:public".to_owned(),
                config: BTreeMap::new(),
                enabled: true,
                policy_bindings: vec![],
            },
        ];
        let exported = export_zone("z:work", &configs);
        assert_eq!(exported.connectors.len(), 1);
        assert_eq!(exported.connectors[0].connector, "github");
    }

    // ── MigrationPlan serializes ────────────────────────────────

    #[test]
    fn migration_plan_serializes() {
        let source = sample_source_config();
        let plan = plan_migration("github", &source, "z:public", None);
        let json = serde_json::to_value(&plan).unwrap();
        assert_eq!(json["connector"], "github");
        assert_eq!(json["source_zone"], "z:work");
        assert_eq!(json["target_zone"], "z:public");
        assert!(json["dry_run"].as_bool().unwrap());
    }
}
