//! Linear GraphQL API types.

use std::cmp::Ordering;

use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── GraphQL request/response ────────────────────────────────────

/// GraphQL request body.
#[derive(Debug, Serialize)]
pub struct GraphQLRequest {
    pub query: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variables: Option<serde_json::Value>,
}

/// GraphQL response wrapper.
#[derive(Debug, Deserialize)]
pub struct GraphQLResponse {
    pub data: Option<serde_json::Value>,
    pub errors: Option<Vec<GraphQLError>>,
}

/// GraphQL error detail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLError {
    pub message: String,
    pub path: Option<Vec<serde_json::Value>>,
    pub extensions: Option<serde_json::Value>,
}

// ── Issue ───────────────────────────────────────────────────────

/// Linear issue.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Issue {
    pub id: String,
    pub identifier: String,
    pub title: String,
    pub description: Option<String>,
    pub priority: Option<f64>,
    pub priority_label: Option<String>,
    pub state: Option<IssueState>,
    pub assignee: Option<User>,
    pub team: Option<TeamRef>,
    pub labels: Option<LabelConnection>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub url: Option<String>,
}

/// Issue state (workflow state).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueState {
    pub id: String,
    pub name: String,
    pub color: Option<String>,
    #[serde(rename = "type")]
    pub state_type: Option<String>,
}

/// Label connection (paginated).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelConnection {
    pub nodes: Vec<Label>,
}

/// Issue label.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Label {
    pub id: String,
    pub name: String,
    pub color: Option<String>,
}

// ── Team ────────────────────────────────────────────────────────

/// Linear team.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Team {
    pub id: String,
    pub name: String,
    pub key: String,
    pub description: Option<String>,
}

/// Lightweight team reference in issue responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamRef {
    pub id: String,
    pub name: Option<String>,
    pub key: Option<String>,
}

// ── User ────────────────────────────────────────────────────────

/// Linear user.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub id: String,
    pub name: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
}

// ── Cycle ───────────────────────────────────────────────────────

/// Linear cycle (sprint).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cycle {
    pub id: String,
    pub number: u32,
    pub name: Option<String>,
    pub starts_at: Option<String>,
    pub ends_at: Option<String>,
    pub completed_at: Option<String>,
}

// ── Project ─────────────────────────────────────────────────────

/// Linear project.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Project {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub state: Option<String>,
    pub progress: Option<f64>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub url: Option<String>,
}

// ── Comment ─────────────────────────────────────────────────────

/// Linear comment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueComment {
    pub id: String,
    pub body: String,
    pub user: Option<User>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

// ── Mutation results ────────────────────────────────────────────

/// Result from creating an issue.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueCreatePayload {
    pub success: bool,
    pub issue: Option<Issue>,
}

/// Result from updating an issue.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueUpdatePayload {
    pub success: bool,
    pub issue: Option<Issue>,
}

/// Result from creating a comment.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommentCreatePayload {
    pub success: bool,
    pub comment: Option<IssueComment>,
}

// ── Webhook Events ─────────────────────────────────────────────

/// Linear webhook payload envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebhookPayload {
    /// Webhook action type.
    pub action: WebhookAction,
    /// Actor who triggered the event (may be absent for system events).
    #[serde(default)]
    pub actor: Option<User>,
    /// ISO-8601 timestamp of the event.
    pub created_at: String,
    /// Webhook delivery URL (redacted in logs).
    #[serde(default)]
    pub url: Option<String>,
    /// Resource type that triggered the event.
    #[serde(rename = "type")]
    pub resource_type: WebhookResourceType,
    /// Event payload data — varies by resource type.
    #[serde(default)]
    pub data: serde_json::Value,
    /// Organization ID (present on org-level webhooks).
    #[serde(default)]
    pub organization_id: Option<String>,
    /// Provider webhook identifier; the delivery ID is forwarded separately.
    #[serde(default)]
    pub webhook_id: Option<String>,
    /// Millisecond timestamp used for replay-window validation.
    #[serde(default)]
    pub webhook_timestamp: Option<i64>,
}

/// Webhook action discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum WebhookAction {
    Create,
    Update,
    Remove,
}

impl std::fmt::Display for WebhookAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Create => write!(f, "create"),
            Self::Update => write!(f, "update"),
            Self::Remove => write!(f, "remove"),
        }
    }
}

/// Webhook resource type discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WebhookResourceType {
    Issue,
    Comment,
    Project,
    Cycle,
    IssueLabel,
    Reaction,
}

impl std::fmt::Display for WebhookResourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Issue => write!(f, "Issue"),
            Self::Comment => write!(f, "Comment"),
            Self::Project => write!(f, "Project"),
            Self::Cycle => write!(f, "Cycle"),
            Self::IssueLabel => write!(f, "IssueLabel"),
            Self::Reaction => write!(f, "Reaction"),
        }
    }
}

impl WebhookResourceType {
    /// Convert to FCP event topic string.
    #[must_use]
    pub fn to_topic(&self, action: WebhookAction) -> String {
        format!("linear.{}.{action}", self.to_string().to_lowercase())
    }
}

// ── Beads ↔ Linear sync planning ───────────────────────────────

/// Conflict resolution policy for Beads ↔ Linear sync planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncConflictPolicy {
    /// Update the older side using the newer side's differing fields.
    PreferFreshest,
    /// Beads wins for any differing field.
    PreferBead,
    /// Linear wins for any differing field.
    PreferLinear,
    /// Never auto-resolve; surface every differing field as a conflict.
    Manual,
}

impl SyncConflictPolicy {
    /// Stable machine-friendly name used in sync audit artifacts.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::PreferFreshest => "prefer_freshest",
            Self::PreferBead => "prefer_bead",
            Self::PreferLinear => "prefer_linear",
            Self::Manual => "manual",
        }
    }
}

/// Field-level sync surface between a Bead and a Linear issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncField {
    Linkage,
    Title,
    Description,
    Status,
    Priority,
}

impl SyncField {
    /// Stable machine-friendly name used in audit artifacts.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Linkage => "linkage",
            Self::Title => "title",
            Self::Description => "description",
            Self::Status => "status",
            Self::Priority => "priority",
        }
    }
}

/// High-level action implied by a deterministic sync plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncOperationKind {
    Noop,
    CreateLinear,
    UpdateLinear,
    CreateBead,
    UpdateBead,
    Conflict,
}

impl SyncOperationKind {
    /// Stable machine-friendly name used in idempotency keys and receipts.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Noop => "noop",
            Self::CreateLinear => "create_linear",
            Self::UpdateLinear => "update_linear",
            Self::CreateBead => "create_bead",
            Self::UpdateBead => "update_bead",
            Self::Conflict => "conflict",
        }
    }
}

/// Execution state for a sync receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncExecutionStatus {
    Noop,
    Planned,
    Applied,
    Conflicted,
}

/// Minimal Beads-side snapshot used for deterministic sync planning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeadSyncSnapshot {
    pub bead_id: String,
    pub linear_issue_id: Option<String>,
    pub title: String,
    pub description: Option<String>,
    pub status: Option<String>,
    pub priority: Option<u8>,
    pub updated_at: String,
}

/// Minimal Linear-side snapshot used for deterministic sync planning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinearSyncSnapshot {
    pub issue_id: String,
    pub identifier: String,
    pub bead_id: Option<String>,
    pub title: String,
    pub description: Option<String>,
    pub status: Option<String>,
    pub priority: Option<u8>,
    pub updated_at: String,
}

/// Explicit field-level conflict emitted by the sync planner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncConflict {
    pub field: SyncField,
    pub bead_updated_at: String,
    pub linear_updated_at: String,
}

/// Side-effect-free sync plan to be wrapped by intent/receipt machinery later.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SyncPlan {
    pub create_linear: bool,
    pub create_bead: bool,
    pub update_linear_fields: Vec<SyncField>,
    pub update_bead_fields: Vec<SyncField>,
    pub conflicts: Vec<SyncConflict>,
}

impl SyncPlan {
    /// True when no create/update/conflict work is needed.
    #[must_use]
    pub fn is_noop(&self) -> bool {
        !self.create_linear
            && !self.create_bead
            && self.update_linear_fields.is_empty()
            && self.update_bead_fields.is_empty()
            && self.conflicts.is_empty()
    }

    /// Collapse the plan into a single high-level sync operation kind.
    #[must_use]
    pub fn operation(&self) -> SyncOperationKind {
        if !self.conflicts.is_empty() {
            SyncOperationKind::Conflict
        } else if self.create_linear {
            SyncOperationKind::CreateLinear
        } else if self.create_bead {
            SyncOperationKind::CreateBead
        } else if !self.update_linear_fields.is_empty() {
            SyncOperationKind::UpdateLinear
        } else if !self.update_bead_fields.is_empty() {
            SyncOperationKind::UpdateBead
        } else {
            SyncOperationKind::Noop
        }
    }

    /// Return the fields the plan would touch or flag.
    #[must_use]
    pub fn affected_fields(&self) -> Vec<SyncField> {
        if !self.update_linear_fields.is_empty() {
            self.update_linear_fields.clone()
        } else if !self.update_bead_fields.is_empty() {
            self.update_bead_fields.clone()
        } else if !self.conflicts.is_empty() {
            self.conflicts
                .iter()
                .map(|conflict| conflict.field)
                .collect()
        } else {
            Vec::new()
        }
    }
}

/// Side-effect-free operation intent for Beads ↔ Linear sync orchestration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncOperationIntent {
    pub operation: SyncOperationKind,
    pub policy: SyncConflictPolicy,
    pub bead_id: Option<String>,
    pub linear_issue_id: Option<String>,
    pub linear_identifier: Option<String>,
    pub idempotency_key: String,
    pub planned_at: String,
    pub plan: SyncPlan,
}

impl SyncOperationIntent {
    /// Construct a deterministic intent envelope from the current snapshots.
    #[must_use]
    pub fn from_snapshots(
        bead: Option<&BeadSyncSnapshot>,
        linear: Option<&LinearSyncSnapshot>,
        policy: SyncConflictPolicy,
        planned_at: impl Into<String>,
    ) -> Self {
        let plan = plan_bead_linear_sync(bead, linear, policy);
        let operation = plan.operation();
        let bead_id = bead
            .map(|snapshot| snapshot.bead_id.clone())
            .or_else(|| linear.and_then(|snapshot| snapshot.bead_id.clone()));
        let linear_issue_id = linear
            .map(|snapshot| snapshot.issue_id.clone())
            .or_else(|| bead.and_then(|snapshot| snapshot.linear_issue_id.clone()));
        let linear_identifier = linear.map(|snapshot| snapshot.identifier.clone());
        let idempotency_key = derive_sync_idempotency_key(bead, linear, policy, &plan);

        Self {
            operation,
            policy,
            bead_id,
            linear_issue_id,
            linear_identifier,
            idempotency_key,
            planned_at: planned_at.into(),
            plan,
        }
    }
}

/// Auditable receipt derived from a sync intent once a controller decides what happened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncOperationReceipt {
    pub operation: SyncOperationKind,
    pub status: SyncExecutionStatus,
    pub bead_id: Option<String>,
    pub linear_issue_id: Option<String>,
    pub linear_identifier: Option<String>,
    pub idempotency_key: String,
    pub updated_fields: Vec<SyncField>,
    pub conflicts: Vec<SyncConflict>,
    pub executed_at: String,
}

impl SyncOperationReceipt {
    /// Derive an auditable receipt from an intent and the controller's execution outcome.
    #[must_use]
    pub fn from_intent(
        intent: &SyncOperationIntent,
        executed_at: impl Into<String>,
        applied: bool,
    ) -> Self {
        let status = if intent.plan.is_noop() {
            SyncExecutionStatus::Noop
        } else if !intent.plan.conflicts.is_empty() {
            SyncExecutionStatus::Conflicted
        } else if applied {
            SyncExecutionStatus::Applied
        } else {
            SyncExecutionStatus::Planned
        };

        Self {
            operation: intent.operation,
            status,
            bead_id: intent.bead_id.clone(),
            linear_issue_id: intent.linear_issue_id.clone(),
            linear_identifier: intent.linear_identifier.clone(),
            idempotency_key: intent.idempotency_key.clone(),
            updated_fields: intent.plan.affected_fields(),
            conflicts: intent.plan.conflicts.clone(),
            executed_at: executed_at.into(),
        }
    }
}

fn normalize_optional_text(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn join_sync_fields(fields: &[SyncField]) -> String {
    if fields.is_empty() {
        "none".to_string()
    } else {
        fields
            .iter()
            .map(SyncField::as_str)
            .collect::<Vec<_>>()
            .join(",")
    }
}

fn join_conflict_fields(conflicts: &[SyncConflict]) -> String {
    if conflicts.is_empty() {
        "none".to_string()
    } else {
        conflicts
            .iter()
            .map(|conflict| conflict.field.as_str())
            .collect::<Vec<_>>()
            .join(",")
    }
}

fn compare_sync_timestamps(left: &str, right: &str) -> Ordering {
    match (
        DateTime::<FixedOffset>::parse_from_rfc3339(left),
        DateTime::<FixedOffset>::parse_from_rfc3339(right),
    ) {
        (Ok(left), Ok(right)) => left.cmp(&right),
        _ => left.cmp(right),
    }
}

const UNKNOWN_SYNC_TIMESTAMP: &str = "unknown";

fn claims_remote_link(value: Option<&str>) -> bool {
    value.is_some_and(|value| !value.trim().is_empty())
}

fn incomplete_linkage_conflict(
    bead_updated_at: impl Into<String>,
    linear_updated_at: impl Into<String>,
) -> SyncConflict {
    SyncConflict {
        field: SyncField::Linkage,
        bead_updated_at: bead_updated_at.into(),
        linear_updated_at: linear_updated_at.into(),
    }
}

fn linkage_conflict(bead: &BeadSyncSnapshot, linear: &LinearSyncSnapshot) -> Option<SyncConflict> {
    let bead_mismatch = bead
        .linear_issue_id
        .as_deref()
        .is_some_and(|issue_id| issue_id != linear.issue_id.as_str());
    let linear_mismatch = linear
        .bead_id
        .as_deref()
        .is_some_and(|bead_id| bead_id != bead.bead_id.as_str());

    (bead_mismatch || linear_mismatch).then(|| SyncConflict {
        field: SyncField::Linkage,
        bead_updated_at: bead.updated_at.clone(),
        linear_updated_at: linear.updated_at.clone(),
    })
}

fn derive_sync_idempotency_key(
    bead: Option<&BeadSyncSnapshot>,
    linear: Option<&LinearSyncSnapshot>,
    policy: SyncConflictPolicy,
    plan: &SyncPlan,
) -> String {
    let bead_id = bead
        .map(|snapshot| snapshot.bead_id.as_str())
        .or_else(|| linear.and_then(|snapshot| snapshot.bead_id.as_deref()))
        .unwrap_or("none");
    let linear_issue_id = linear
        .map(|snapshot| snapshot.issue_id.as_str())
        .or_else(|| bead.and_then(|snapshot| snapshot.linear_issue_id.as_deref()))
        .unwrap_or("none");
    let bead_claimed_linear_issue_id = bead
        .and_then(|snapshot| snapshot.linear_issue_id.as_deref())
        .unwrap_or("none");
    let linear_claimed_bead_id = linear
        .and_then(|snapshot| snapshot.bead_id.as_deref())
        .unwrap_or("none");
    let linear_identifier = linear.map_or("none", |snapshot| snapshot.identifier.as_str());
    let bead_updated_at = bead.map_or("none", |snapshot| snapshot.updated_at.as_str());
    let linear_updated_at = linear.map_or("none", |snapshot| snapshot.updated_at.as_str());

    let fingerprint = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        plan.operation().as_str(),
        policy.as_str(),
        bead_id,
        linear_issue_id,
        bead_claimed_linear_issue_id,
        linear_claimed_bead_id,
        linear_identifier,
        bead_updated_at,
        linear_updated_at,
        join_sync_fields(&plan.update_linear_fields),
        join_sync_fields(&plan.update_bead_fields),
        join_conflict_fields(&plan.conflicts)
    );
    let intent_uuid = Uuid::new_v5(&Uuid::NAMESPACE_OID, fingerprint.as_bytes());
    format!(
        "fcp2:linear-sync:{}:{intent_uuid}",
        plan.operation().as_str()
    )
}

/// Build a deterministic sync plan between a Bead and a Linear issue snapshot.
#[must_use]
pub fn plan_bead_linear_sync(
    bead: Option<&BeadSyncSnapshot>,
    linear: Option<&LinearSyncSnapshot>,
    policy: SyncConflictPolicy,
) -> SyncPlan {
    match (bead, linear) {
        (Some(bead), None) => {
            if claims_remote_link(bead.linear_issue_id.as_deref()) {
                SyncPlan {
                    conflicts: vec![incomplete_linkage_conflict(
                        bead.updated_at.clone(),
                        UNKNOWN_SYNC_TIMESTAMP,
                    )],
                    ..SyncPlan::default()
                }
            } else {
                SyncPlan {
                    create_linear: true,
                    ..SyncPlan::default()
                }
            }
        }
        (None, Some(linear)) => {
            if claims_remote_link(linear.bead_id.as_deref()) {
                SyncPlan {
                    conflicts: vec![incomplete_linkage_conflict(
                        UNKNOWN_SYNC_TIMESTAMP,
                        linear.updated_at.clone(),
                    )],
                    ..SyncPlan::default()
                }
            } else {
                SyncPlan {
                    create_bead: true,
                    ..SyncPlan::default()
                }
            }
        }
        (None, None) => SyncPlan::default(),
        (Some(bead), Some(linear)) => {
            if let Some(conflict) = linkage_conflict(bead, linear) {
                return SyncPlan {
                    conflicts: vec![conflict],
                    ..SyncPlan::default()
                };
            }

            let mut differing_fields = Vec::new();

            if bead.title.trim() != linear.title.trim() {
                differing_fields.push(SyncField::Title);
            }
            if normalize_optional_text(bead.description.as_deref())
                != normalize_optional_text(linear.description.as_deref())
            {
                differing_fields.push(SyncField::Description);
            }
            if normalize_optional_text(bead.status.as_deref())
                != normalize_optional_text(linear.status.as_deref())
            {
                differing_fields.push(SyncField::Status);
            }
            if bead.priority != linear.priority {
                differing_fields.push(SyncField::Priority);
            }

            if differing_fields.is_empty() {
                return SyncPlan::default();
            }

            match policy {
                SyncConflictPolicy::PreferBead => SyncPlan {
                    update_linear_fields: differing_fields,
                    ..SyncPlan::default()
                },
                SyncConflictPolicy::PreferLinear => SyncPlan {
                    update_bead_fields: differing_fields,
                    ..SyncPlan::default()
                },
                SyncConflictPolicy::Manual => SyncPlan {
                    conflicts: differing_fields
                        .into_iter()
                        .map(|field| SyncConflict {
                            field,
                            bead_updated_at: bead.updated_at.clone(),
                            linear_updated_at: linear.updated_at.clone(),
                        })
                        .collect(),
                    ..SyncPlan::default()
                },
                SyncConflictPolicy::PreferFreshest => {
                    match compare_sync_timestamps(&bead.updated_at, &linear.updated_at) {
                        Ordering::Greater => SyncPlan {
                            update_linear_fields: differing_fields,
                            ..SyncPlan::default()
                        },
                        Ordering::Less => SyncPlan {
                            update_bead_fields: differing_fields,
                            ..SyncPlan::default()
                        },
                        Ordering::Equal => SyncPlan {
                            conflicts: differing_fields
                                .into_iter()
                                .map(|field| SyncConflict {
                                    field,
                                    bead_updated_at: bead.updated_at.clone(),
                                    linear_updated_at: linear.updated_at.clone(),
                                })
                                .collect(),
                            ..SyncPlan::default()
                        },
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_bead_snapshot() -> BeadSyncSnapshot {
        BeadSyncSnapshot {
            bead_id: "br-123".to_string(),
            linear_issue_id: Some("lin-1".to_string()),
            title: "Sync title".to_string(),
            description: Some("Sync description".to_string()),
            status: Some("open".to_string()),
            priority: Some(1),
            updated_at: "2026-03-07T07:00:00+00:00".to_string(),
        }
    }

    fn sample_unlinked_bead_snapshot() -> BeadSyncSnapshot {
        BeadSyncSnapshot {
            linear_issue_id: None,
            ..sample_bead_snapshot()
        }
    }

    fn sample_linear_snapshot() -> LinearSyncSnapshot {
        LinearSyncSnapshot {
            issue_id: "lin-1".to_string(),
            identifier: "LIN-123".to_string(),
            bead_id: Some("br-123".to_string()),
            title: "Sync title".to_string(),
            description: Some("Sync description".to_string()),
            status: Some("open".to_string()),
            priority: Some(1),
            updated_at: "2026-03-07T06:00:00+00:00".to_string(),
        }
    }

    fn sample_unlinked_linear_snapshot() -> LinearSyncSnapshot {
        LinearSyncSnapshot {
            bead_id: None,
            ..sample_linear_snapshot()
        }
    }

    // ════════════════════════════════════════════════════════════════
    // GraphQL types
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn graphql_request_serialize() {
        let req = GraphQLRequest {
            query: "{ viewer { id } }".to_string(),
            variables: Some(json!({"first": 10})),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("viewer"));
        assert!(json.contains("\"first\":10"));
    }

    #[test]
    fn sync_plan_creates_linear_when_missing() {
        let bead = sample_unlinked_bead_snapshot();
        let plan = plan_bead_linear_sync(Some(&bead), None, SyncConflictPolicy::PreferFreshest);

        assert!(plan.create_linear);
        assert!(!plan.create_bead);
        assert!(plan.update_linear_fields.is_empty());
        assert!(plan.conflicts.is_empty());
    }

    #[test]
    fn sync_plan_conflicts_when_bead_claims_missing_linear_issue() {
        let bead = sample_bead_snapshot();
        let plan = plan_bead_linear_sync(Some(&bead), None, SyncConflictPolicy::PreferFreshest);

        assert!(!plan.create_linear);
        assert!(!plan.create_bead);
        assert!(plan.update_linear_fields.is_empty());
        assert!(plan.update_bead_fields.is_empty());
        assert_eq!(plan.conflicts.len(), 1);
        assert_eq!(plan.conflicts[0].field, SyncField::Linkage);
        assert_eq!(plan.conflicts[0].bead_updated_at, bead.updated_at);
        assert_eq!(plan.conflicts[0].linear_updated_at, UNKNOWN_SYNC_TIMESTAMP);
    }

    #[test]
    fn sync_plan_conflicts_when_linear_claims_missing_bead() {
        let linear = sample_linear_snapshot();
        let plan = plan_bead_linear_sync(None, Some(&linear), SyncConflictPolicy::PreferFreshest);

        assert!(!plan.create_linear);
        assert!(!plan.create_bead);
        assert!(plan.update_linear_fields.is_empty());
        assert!(plan.update_bead_fields.is_empty());
        assert_eq!(plan.conflicts.len(), 1);
        assert_eq!(plan.conflicts[0].field, SyncField::Linkage);
        assert_eq!(plan.conflicts[0].bead_updated_at, UNKNOWN_SYNC_TIMESTAMP);
        assert_eq!(plan.conflicts[0].linear_updated_at, linear.updated_at);
    }

    #[test]
    fn sync_plan_updates_linear_when_bead_is_fresher() {
        let bead = BeadSyncSnapshot {
            title: "New bead title".to_string(),
            ..sample_bead_snapshot()
        };
        let linear = sample_linear_snapshot();

        let plan = plan_bead_linear_sync(
            Some(&bead),
            Some(&linear),
            SyncConflictPolicy::PreferFreshest,
        );

        assert_eq!(plan.update_linear_fields, vec![SyncField::Title]);
        assert!(plan.update_bead_fields.is_empty());
        assert!(plan.conflicts.is_empty());
    }

    #[test]
    fn sync_plan_updates_bead_when_linear_is_fresher() {
        let bead = sample_bead_snapshot();
        let linear = LinearSyncSnapshot {
            status: Some("done".to_string()),
            updated_at: "2026-03-07T08:00:00+00:00".to_string(),
            ..sample_linear_snapshot()
        };

        let plan = plan_bead_linear_sync(
            Some(&bead),
            Some(&linear),
            SyncConflictPolicy::PreferFreshest,
        );

        assert_eq!(plan.update_bead_fields, vec![SyncField::Status]);
        assert!(plan.update_linear_fields.is_empty());
        assert!(plan.conflicts.is_empty());
    }

    #[test]
    fn sync_plan_conflicts_when_timestamps_tie() {
        let bead = BeadSyncSnapshot {
            title: "Bead title".to_string(),
            updated_at: "2026-03-07T07:00:00+00:00".to_string(),
            ..sample_bead_snapshot()
        };
        let linear = LinearSyncSnapshot {
            title: "Linear title".to_string(),
            updated_at: "2026-03-07T07:00:00+00:00".to_string(),
            ..sample_linear_snapshot()
        };

        let plan = plan_bead_linear_sync(
            Some(&bead),
            Some(&linear),
            SyncConflictPolicy::PreferFreshest,
        );

        assert!(plan.update_linear_fields.is_empty());
        assert!(plan.update_bead_fields.is_empty());
        assert_eq!(plan.conflicts.len(), 1);
        assert_eq!(plan.conflicts[0].field, SyncField::Title);
    }

    #[test]
    fn sync_plan_manual_policy_never_auto_resolves() {
        let bead = BeadSyncSnapshot {
            priority: Some(0),
            ..sample_bead_snapshot()
        };
        let linear = LinearSyncSnapshot {
            priority: Some(2),
            updated_at: "2026-03-07T09:00:00+00:00".to_string(),
            ..sample_linear_snapshot()
        };

        let plan = plan_bead_linear_sync(Some(&bead), Some(&linear), SyncConflictPolicy::Manual);

        assert!(plan.update_linear_fields.is_empty());
        assert!(plan.update_bead_fields.is_empty());
        assert_eq!(plan.conflicts.len(), 1);
        assert_eq!(plan.conflicts[0].field, SyncField::Priority);
    }

    #[test]
    fn sync_plan_conflicts_when_linked_issue_ids_disagree() {
        let bead = BeadSyncSnapshot {
            linear_issue_id: Some("lin-other".to_string()),
            ..sample_bead_snapshot()
        };
        let linear = sample_linear_snapshot();

        let plan =
            plan_bead_linear_sync(Some(&bead), Some(&linear), SyncConflictPolicy::PreferBead);

        assert!(plan.update_linear_fields.is_empty());
        assert!(plan.update_bead_fields.is_empty());
        assert_eq!(plan.conflicts.len(), 1);
        assert_eq!(plan.conflicts[0].field, SyncField::Linkage);
    }

    #[test]
    fn sync_plan_conflicts_when_linked_bead_ids_disagree() {
        let bead = sample_bead_snapshot();
        let linear = LinearSyncSnapshot {
            bead_id: Some("br-other".to_string()),
            ..sample_linear_snapshot()
        };

        let plan =
            plan_bead_linear_sync(Some(&bead), Some(&linear), SyncConflictPolicy::PreferLinear);

        assert!(plan.update_linear_fields.is_empty());
        assert!(plan.update_bead_fields.is_empty());
        assert_eq!(plan.conflicts.len(), 1);
        assert_eq!(plan.conflicts[0].field, SyncField::Linkage);
    }

    #[test]
    fn sync_plan_operation_classification_is_stable() {
        let bead = sample_unlinked_bead_snapshot();
        let linear = sample_unlinked_linear_snapshot();

        assert_eq!(
            plan_bead_linear_sync(Some(&bead), None, SyncConflictPolicy::PreferFreshest)
                .operation(),
            SyncOperationKind::CreateLinear
        );
        assert_eq!(
            plan_bead_linear_sync(None, Some(&linear), SyncConflictPolicy::PreferFreshest)
                .operation(),
            SyncOperationKind::CreateBead
        );
        assert_eq!(SyncPlan::default().operation(), SyncOperationKind::Noop);
    }

    #[test]
    fn sync_operation_intent_derives_stable_idempotency_key() {
        let bead = BeadSyncSnapshot {
            title: "Retitle bead".to_string(),
            ..sample_bead_snapshot()
        };
        let linear = sample_linear_snapshot();

        let first = SyncOperationIntent::from_snapshots(
            Some(&bead),
            Some(&linear),
            SyncConflictPolicy::PreferFreshest,
            "2026-03-07T10:00:00+00:00",
        );
        let second = SyncOperationIntent::from_snapshots(
            Some(&bead),
            Some(&linear),
            SyncConflictPolicy::PreferFreshest,
            "2026-03-07T11:00:00+00:00",
        );

        assert_eq!(first.operation, SyncOperationKind::UpdateLinear);
        assert_eq!(first.idempotency_key, second.idempotency_key);
        assert!(
            first
                .idempotency_key
                .starts_with("fcp2:linear-sync:update_linear:")
        );
    }

    #[test]
    fn sync_operation_intent_uses_conflict_operation_for_linkage_mismatch() {
        let bead = BeadSyncSnapshot {
            linear_issue_id: Some("lin-other".to_string()),
            ..sample_bead_snapshot()
        };
        let linear = sample_linear_snapshot();

        let intent = SyncOperationIntent::from_snapshots(
            Some(&bead),
            Some(&linear),
            SyncConflictPolicy::PreferFreshest,
            "2026-03-07T10:00:00+00:00",
        );

        assert_eq!(intent.operation, SyncOperationKind::Conflict);
        assert_eq!(intent.plan.conflicts.len(), 1);
        assert_eq!(intent.plan.conflicts[0].field, SyncField::Linkage);
        assert!(
            intent
                .idempotency_key
                .starts_with("fcp2:linear-sync:conflict:")
        );
    }

    #[test]
    fn sync_operation_intent_distinguishes_conflicting_linkage_claims() {
        let linear = sample_linear_snapshot();
        let first_bead = BeadSyncSnapshot {
            linear_issue_id: Some("lin-other-a".to_string()),
            ..sample_bead_snapshot()
        };
        let second_bead = BeadSyncSnapshot {
            linear_issue_id: Some("lin-other-b".to_string()),
            ..sample_bead_snapshot()
        };

        let first = SyncOperationIntent::from_snapshots(
            Some(&first_bead),
            Some(&linear),
            SyncConflictPolicy::PreferFreshest,
            "2026-03-07T10:00:00+00:00",
        );
        let second = SyncOperationIntent::from_snapshots(
            Some(&second_bead),
            Some(&linear),
            SyncConflictPolicy::PreferFreshest,
            "2026-03-07T10:00:00+00:00",
        );

        assert_eq!(first.operation, SyncOperationKind::Conflict);
        assert_eq!(second.operation, SyncOperationKind::Conflict);
        assert_ne!(first.idempotency_key, second.idempotency_key);
    }

    #[test]
    fn sync_operation_intent_uses_bead_metadata_when_linear_missing() {
        let bead = sample_unlinked_bead_snapshot();

        let intent = SyncOperationIntent::from_snapshots(
            Some(&bead),
            None,
            SyncConflictPolicy::PreferBead,
            "2026-03-07T10:00:00+00:00",
        );

        assert_eq!(intent.operation, SyncOperationKind::CreateLinear);
        assert_eq!(intent.bead_id.as_deref(), Some("br-123"));
        assert!(intent.linear_issue_id.is_none());
        assert!(intent.linear_identifier.is_none());
    }

    #[test]
    fn sync_operation_intent_surfaces_claimed_link_when_linear_snapshot_missing() {
        let bead = sample_bead_snapshot();

        let intent = SyncOperationIntent::from_snapshots(
            Some(&bead),
            None,
            SyncConflictPolicy::PreferFreshest,
            "2026-03-07T10:00:00+00:00",
        );

        assert_eq!(intent.operation, SyncOperationKind::Conflict);
        assert_eq!(intent.bead_id.as_deref(), Some("br-123"));
        assert_eq!(intent.linear_issue_id.as_deref(), Some("lin-1"));
        assert_eq!(intent.plan.conflicts.len(), 1);
        assert_eq!(intent.plan.conflicts[0].field, SyncField::Linkage);
    }

    #[test]
    fn sync_operation_receipt_marks_conflicts_as_conflicted() {
        let bead = BeadSyncSnapshot {
            title: "Bead title".to_string(),
            updated_at: "2026-03-07T07:00:00+00:00".to_string(),
            ..sample_bead_snapshot()
        };
        let linear = LinearSyncSnapshot {
            title: "Linear title".to_string(),
            updated_at: "2026-03-07T07:00:00+00:00".to_string(),
            ..sample_linear_snapshot()
        };
        let intent = SyncOperationIntent::from_snapshots(
            Some(&bead),
            Some(&linear),
            SyncConflictPolicy::PreferFreshest,
            "2026-03-07T10:00:00+00:00",
        );

        let receipt =
            SyncOperationReceipt::from_intent(&intent, "2026-03-07T10:05:00+00:00", false);

        assert_eq!(receipt.status, SyncExecutionStatus::Conflicted);
        assert_eq!(receipt.updated_fields, vec![SyncField::Title]);
        assert_eq!(receipt.conflicts.len(), 1);
    }

    #[test]
    fn sync_operation_receipt_marks_updates_as_applied() {
        let bead = BeadSyncSnapshot {
            status: Some("blocked".to_string()),
            ..sample_bead_snapshot()
        };
        let linear = sample_linear_snapshot();
        let intent = SyncOperationIntent::from_snapshots(
            Some(&bead),
            Some(&linear),
            SyncConflictPolicy::PreferBead,
            "2026-03-07T10:00:00+00:00",
        );

        let receipt = SyncOperationReceipt::from_intent(&intent, "2026-03-07T10:05:00+00:00", true);

        assert_eq!(receipt.operation, SyncOperationKind::UpdateLinear);
        assert_eq!(receipt.status, SyncExecutionStatus::Applied);
        assert_eq!(receipt.updated_fields, vec![SyncField::Status]);
        assert!(receipt.conflicts.is_empty());
    }

    #[test]
    fn graphql_request_no_variables() {
        let req = GraphQLRequest {
            query: "{ viewer { id } }".to_string(),
            variables: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("variables"));
    }

    #[test]
    fn graphql_request_skip_serializing_if_variables_none() {
        let req = GraphQLRequest {
            query: "q".into(),
            variables: None,
        };
        let val: serde_json::Value = serde_json::to_value(&req).unwrap();
        assert!(
            val.get("variables").is_none(),
            "variables should be omitted when None"
        );
    }

    #[test]
    fn graphql_request_includes_variables_when_some() {
        let req = GraphQLRequest {
            query: "q".into(),
            variables: Some(json!({})),
        };
        let val: serde_json::Value = serde_json::to_value(&req).unwrap();
        assert!(val.get("variables").is_some());
    }

    #[test]
    fn graphql_request_debug() {
        let req = GraphQLRequest {
            query: "{ me }".into(),
            variables: None,
        };
        let debug = format!("{req:?}");
        assert!(debug.contains("GraphQLRequest"));
        assert!(debug.contains("me"));
    }

    #[test]
    fn graphql_request_complex_variables() {
        let req = GraphQLRequest {
            query: "mutation($input: IssueCreateInput!) { issueCreate(input: $input) { success } }"
                .into(),
            variables: Some(json!({
                "input": {
                    "title": "Bug report",
                    "teamId": "team-1",
                    "labels": ["bug", "urgent"],
                    "priority": 1
                }
            })),
        };
        let serialized = serde_json::to_string(&req).unwrap();
        assert!(serialized.contains("Bug report"));
        assert!(serialized.contains("urgent"));
    }

    #[test]
    fn graphql_response_with_data() {
        let json = r#"{"data":{"viewer":{"id":"u1"}}}"#;
        let resp: GraphQLResponse = serde_json::from_str(json).unwrap();
        assert!(resp.data.is_some());
        assert!(resp.errors.is_none());
    }

    #[test]
    fn graphql_response_with_errors() {
        let json = json!({
            "data": null,
            "errors": [{"message": "Not found", "path": ["issue"]}]
        });
        let resp: GraphQLResponse = serde_json::from_value(json).unwrap();
        assert!(resp.data.is_none());
        let errors = resp.errors.unwrap();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].message, "Not found");
    }

    #[test]
    fn graphql_response_both_data_and_errors() {
        // GraphQL spec allows partial data alongside errors
        let json = json!({
            "data": {"viewer": {"id": "u1"}},
            "errors": [{"message": "partial failure"}]
        });
        let resp: GraphQLResponse = serde_json::from_value(json).unwrap();
        assert!(resp.data.is_some());
        assert!(resp.errors.is_some());
        assert_eq!(resp.errors.unwrap().len(), 1);
    }

    #[test]
    fn graphql_response_empty_errors_array() {
        let json = json!({
            "data": {"ok": true},
            "errors": []
        });
        let resp: GraphQLResponse = serde_json::from_value(json).unwrap();
        assert!(resp.data.is_some());
        let errors = resp.errors.unwrap();
        assert!(errors.is_empty());
    }

    #[test]
    fn graphql_response_null_data_null_errors() {
        let json = json!({"data": null, "errors": null});
        let resp: GraphQLResponse = serde_json::from_value(json).unwrap();
        assert!(resp.data.is_none());
        assert!(resp.errors.is_none());
    }

    #[test]
    fn graphql_response_debug() {
        let resp = GraphQLResponse {
            data: Some(json!({"viewer": {"id": "u1"}})),
            errors: None,
        };
        let debug = format!("{resp:?}");
        assert!(debug.contains("GraphQLResponse"));
    }

    #[test]
    fn graphql_error_serde() {
        let err = GraphQLError {
            message: "Unauthorized".to_string(),
            path: Some(vec![json!("viewer")]),
            extensions: Some(json!({"code": "UNAUTHENTICATED"})),
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: GraphQLError = serde_json::from_str(&json).unwrap();
        assert_eq!(back.message, "Unauthorized");
    }

    #[test]
    fn graphql_error_minimal() {
        let json = json!({"message": "Something broke"});
        let err: GraphQLError = serde_json::from_value(json).unwrap();
        assert_eq!(err.message, "Something broke");
        assert!(err.path.is_none());
        assert!(err.extensions.is_none());
    }

    #[test]
    fn graphql_error_clone() {
        let err = GraphQLError {
            message: "Forbidden".into(),
            path: Some(vec![json!("mutation"), json!("issueCreate")]),
            extensions: None,
        };
        let cloned = err.clone();
        assert_eq!(cloned.message, err.message);
        assert_eq!(cloned.path, err.path);
    }

    #[test]
    fn graphql_error_debug() {
        let err = GraphQLError {
            message: "test".into(),
            path: None,
            extensions: None,
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("GraphQLError"));
        assert!(debug.contains("test"));
    }

    #[test]
    fn graphql_error_numeric_path() {
        let json = json!({
            "message": "err",
            "path": ["issues", "nodes", 0, "title"]
        });
        let err: GraphQLError = serde_json::from_value(json).unwrap();
        let path = err.path.unwrap();
        assert_eq!(path.len(), 4);
        assert_eq!(path[2], json!(0));
    }

    #[test]
    fn graphql_error_roundtrip_with_extensions() {
        let original = GraphQLError {
            message: "Rate limited".into(),
            path: None,
            extensions: Some(json!({
                "code": "RATE_LIMITED",
                "retryAfter": 30
            })),
        };
        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: GraphQLError = serde_json::from_str(&serialized).unwrap();
        assert_eq!(
            deserialized.extensions.as_ref().unwrap()["retryAfter"],
            json!(30)
        );
    }

    // ════════════════════════════════════════════════════════════════
    // Issue
    // ════════════════════════════════════════════════════════════════

    fn full_issue_json() -> serde_json::Value {
        json!({
            "id": "i1",
            "identifier": "PROJ-1",
            "title": "Fix bug",
            "description": "A bug",
            "priority": 2.0,
            "priorityLabel": "High",
            "state": {"id": "s1", "name": "In Progress", "color": "#ff0", "type": "started"},
            "assignee": {"id": "u1", "name": "Alice", "displayName": "alice", "email": "alice@example.com"},
            "team": {"id": "t1", "name": "Eng", "key": "ENG"},
            "labels": {"nodes": [{"id": "l1", "name": "bug", "color": "#f00"}]},
            "createdAt": "2026-01-01T00:00:00Z",
            "updatedAt": "2026-03-01T00:00:00Z",
            "url": "https://linear.app/project/PROJ-1"
        })
    }

    #[test]
    fn issue_camel_case_serde() {
        let issue: Issue = serde_json::from_value(full_issue_json()).unwrap();
        assert_eq!(issue.identifier, "PROJ-1");
        assert_eq!(issue.priority_label.as_deref(), Some("High"));
        assert!(issue.state.is_some());
        assert!(issue.assignee.is_some());
        assert_eq!(issue.labels.as_ref().unwrap().nodes.len(), 1);
        assert_eq!(issue.created_at.as_deref(), Some("2026-01-01T00:00:00Z"));
        assert_eq!(
            issue.url.as_deref(),
            Some("https://linear.app/project/PROJ-1")
        );
    }

    #[test]
    fn issue_minimal() {
        let json = json!({
            "id": "i2",
            "identifier": "PROJ-2",
            "title": "Task"
        });
        let issue: Issue = serde_json::from_value(json).unwrap();
        assert_eq!(issue.title, "Task");
        assert!(issue.state.is_none());
        assert!(issue.description.is_none());
        assert!(issue.priority.is_none());
        assert!(issue.priority_label.is_none());
        assert!(issue.assignee.is_none());
        assert!(issue.team.is_none());
        assert!(issue.labels.is_none());
        assert!(issue.created_at.is_none());
        assert!(issue.updated_at.is_none());
        assert!(issue.url.is_none());
    }

    #[test]
    fn issue_with_explicit_nulls() {
        let json = json!({
            "id": "i3",
            "identifier": "PROJ-3",
            "title": "Task",
            "description": null,
            "priority": null,
            "priorityLabel": null,
            "state": null,
            "assignee": null,
            "team": null,
            "labels": null,
            "createdAt": null,
            "updatedAt": null,
            "url": null
        });
        let issue: Issue = serde_json::from_value(json).unwrap();
        assert_eq!(issue.id, "i3");
        assert!(issue.description.is_none());
    }

    #[test]
    fn issue_roundtrip() {
        let original: Issue = serde_json::from_value(full_issue_json()).unwrap();
        let serialized = serde_json::to_string(&original).unwrap();
        let roundtripped: Issue = serde_json::from_str(&serialized).unwrap();
        assert_eq!(roundtripped.id, original.id);
        assert_eq!(roundtripped.identifier, original.identifier);
        assert_eq!(roundtripped.title, original.title);
        assert_eq!(roundtripped.description, original.description);
        assert_eq!(roundtripped.priority, original.priority);
        assert_eq!(roundtripped.priority_label, original.priority_label);
        assert_eq!(roundtripped.url, original.url);
    }

    #[test]
    fn issue_clone() {
        let issue: Issue = serde_json::from_value(full_issue_json()).unwrap();
        let cloned = issue.clone();
        assert_eq!(cloned.id, issue.id);
        assert_eq!(cloned.identifier, issue.identifier);
        assert_eq!(cloned.title, issue.title);
    }

    #[test]
    fn issue_debug() {
        let issue: Issue = serde_json::from_value(full_issue_json()).unwrap();
        let debug = format!("{issue:?}");
        assert!(debug.contains("Issue"));
        assert!(debug.contains("PROJ-1"));
    }

    #[test]
    fn issue_priority_as_float() {
        let json = json!({
            "id": "i4",
            "identifier": "P-4",
            "title": "Float priority",
            "priority": 1.5
        });
        let issue: Issue = serde_json::from_value(json).unwrap();
        assert_eq!(issue.priority, Some(1.5));
    }

    #[test]
    fn issue_priority_zero() {
        let json = json!({
            "id": "i5",
            "identifier": "P-5",
            "title": "No priority",
            "priority": 0.0
        });
        let issue: Issue = serde_json::from_value(json).unwrap();
        assert_eq!(issue.priority, Some(0.0));
    }

    #[test]
    fn issue_empty_labels() {
        let json = json!({
            "id": "i6",
            "identifier": "P-6",
            "title": "No labels",
            "labels": {"nodes": []}
        });
        let issue: Issue = serde_json::from_value(json).unwrap();
        assert!(issue.labels.as_ref().unwrap().nodes.is_empty());
    }

    #[test]
    fn issue_multiple_labels() {
        let json = json!({
            "id": "i7",
            "identifier": "P-7",
            "title": "Multi labels",
            "labels": {"nodes": [
                {"id": "l1", "name": "bug", "color": "#f00"},
                {"id": "l2", "name": "feature"},
                {"id": "l3", "name": "urgent", "color": "#ff0"}
            ]}
        });
        let issue: Issue = serde_json::from_value(json).unwrap();
        let labels = &issue.labels.unwrap().nodes;
        assert_eq!(labels.len(), 3);
        assert_eq!(labels[1].name, "feature");
        assert!(labels[1].color.is_none());
    }

    #[test]
    fn issue_serializes_camel_case() {
        let issue: Issue = serde_json::from_value(full_issue_json()).unwrap();
        let val: serde_json::Value = serde_json::to_value(&issue).unwrap();
        // Check that fields are camelCase, not snake_case
        assert!(val.get("priorityLabel").is_some());
        assert!(val.get("priority_label").is_none());
        assert!(val.get("createdAt").is_some());
        assert!(val.get("created_at").is_none());
    }

    // ════════════════════════════════════════════════════════════════
    // IssueState
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn issue_state_full() {
        let json = json!({
            "id": "s1",
            "name": "Done",
            "color": "#00ff00",
            "type": "completed"
        });
        let state: IssueState = serde_json::from_value(json).unwrap();
        assert_eq!(state.id, "s1");
        assert_eq!(state.name, "Done");
        assert_eq!(state.color.as_deref(), Some("#00ff00"));
        assert_eq!(state.state_type.as_deref(), Some("completed"));
    }

    #[test]
    fn issue_state_minimal() {
        let json = json!({"id": "s2", "name": "Triage"});
        let state: IssueState = serde_json::from_value(json).unwrap();
        assert_eq!(state.name, "Triage");
        assert!(state.color.is_none());
        assert!(state.state_type.is_none());
    }

    #[test]
    fn issue_state_type_renamed_from_type() {
        // Ensure the "type" JSON field maps to state_type Rust field
        let json = json!({"id": "s3", "name": "Backlog", "type": "backlog"});
        let state: IssueState = serde_json::from_value(json).unwrap();
        assert_eq!(state.state_type, Some("backlog".into()));

        // Roundtrip: serialized form uses "type" not "state_type"
        let val: serde_json::Value = serde_json::to_value(&state).unwrap();
        assert!(val.get("type").is_some());
        assert!(val.get("state_type").is_none());
        assert!(val.get("stateType").is_none());
    }

    #[test]
    fn issue_state_clone_debug() {
        let state = IssueState {
            id: "s1".into(),
            name: "In Progress".into(),
            color: Some("#0000ff".into()),
            state_type: Some("started".into()),
        };
        let cloned = state.clone();
        assert_eq!(cloned.name, state.name);
        let debug = format!("{state:?}");
        assert!(debug.contains("IssueState"));
    }

    #[test]
    fn issue_state_roundtrip() {
        let original = IssueState {
            id: "st1".into(),
            name: "Review".into(),
            color: Some("#abc".into()),
            state_type: Some("started".into()),
        };
        let json = serde_json::to_string(&original).unwrap();
        let back: IssueState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, original.id);
        assert_eq!(back.name, original.name);
        assert_eq!(back.color, original.color);
        assert_eq!(back.state_type, original.state_type);
    }

    // ════════════════════════════════════════════════════════════════
    // LabelConnection / Label
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn label_connection_empty_nodes() {
        let json = json!({"nodes": []});
        let conn: LabelConnection = serde_json::from_value(json).unwrap();
        assert!(conn.nodes.is_empty());
    }

    #[test]
    fn label_full() {
        let json = json!({"id": "l1", "name": "bug", "color": "#f00"});
        let label: Label = serde_json::from_value(json).unwrap();
        assert_eq!(label.name, "bug");
        assert_eq!(label.color.as_deref(), Some("#f00"));
    }

    #[test]
    fn label_no_color() {
        let json = json!({"id": "l2", "name": "feature"});
        let label: Label = serde_json::from_value(json).unwrap();
        assert!(label.color.is_none());
    }

    #[test]
    fn label_roundtrip() {
        let label = Label {
            id: "l1".into(),
            name: "enhancement".into(),
            color: Some("#00f".into()),
        };
        let json = serde_json::to_string(&label).unwrap();
        let back: Label = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, label.id);
        assert_eq!(back.name, label.name);
        assert_eq!(back.color, label.color);
    }

    #[test]
    fn label_clone_debug() {
        let label = Label {
            id: "l1".into(),
            name: "test".into(),
            color: None,
        };
        let cloned = label.clone();
        assert_eq!(cloned.name, "test");
        let debug = format!("{label:?}");
        assert!(debug.contains("Label"));
    }

    // ════════════════════════════════════════════════════════════════
    // Team
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn team_serde() {
        let team = Team {
            id: "t1".to_string(),
            name: "Engineering".to_string(),
            key: "ENG".to_string(),
            description: Some("Core team".to_string()),
        };
        let json = serde_json::to_string(&team).unwrap();
        let back: Team = serde_json::from_str(&json).unwrap();
        assert_eq!(back.key, "ENG");
    }

    #[test]
    fn team_no_description() {
        let json = json!({"id": "t2", "name": "Design", "key": "DES"});
        let team: Team = serde_json::from_value(json).unwrap();
        assert_eq!(team.key, "DES");
        assert!(team.description.is_none());
    }

    #[test]
    fn team_with_null_description() {
        let json = json!({"id": "t3", "name": "QA", "key": "QA", "description": null});
        let team: Team = serde_json::from_value(json).unwrap();
        assert!(team.description.is_none());
    }

    #[test]
    fn team_roundtrip() {
        let team = Team {
            id: "t1".into(),
            name: "Platform".into(),
            key: "PLAT".into(),
            description: Some("Platform engineering".into()),
        };
        let json = serde_json::to_string(&team).unwrap();
        let back: Team = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, team.id);
        assert_eq!(back.name, team.name);
        assert_eq!(back.key, team.key);
        assert_eq!(back.description, team.description);
    }

    #[test]
    fn team_clone_debug() {
        let team = Team {
            id: "t1".into(),
            name: "Eng".into(),
            key: "ENG".into(),
            description: None,
        };
        let cloned = team.clone();
        assert_eq!(cloned.key, "ENG");
        let debug = format!("{team:?}");
        assert!(debug.contains("Team"));
    }

    // ════════════════════════════════════════════════════════════════
    // TeamRef
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn team_ref_full() {
        let json = json!({"id": "t1", "name": "Eng", "key": "ENG"});
        let tr: TeamRef = serde_json::from_value(json).unwrap();
        assert_eq!(tr.id, "t1");
        assert_eq!(tr.name.as_deref(), Some("Eng"));
        assert_eq!(tr.key.as_deref(), Some("ENG"));
    }

    #[test]
    fn team_ref_id_only() {
        let json = json!({"id": "t2"});
        let tr: TeamRef = serde_json::from_value(json).unwrap();
        assert_eq!(tr.id, "t2");
        assert!(tr.name.is_none());
        assert!(tr.key.is_none());
    }

    #[test]
    fn team_ref_roundtrip() {
        let tr = TeamRef {
            id: "t1".into(),
            name: Some("Platform".into()),
            key: Some("PLAT".into()),
        };
        let json = serde_json::to_string(&tr).unwrap();
        let back: TeamRef = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, tr.id);
        assert_eq!(back.name, tr.name);
    }

    #[test]
    fn team_ref_clone_debug() {
        let tr = TeamRef {
            id: "t1".into(),
            name: None,
            key: None,
        };
        let cloned = tr.clone();
        assert_eq!(cloned.id, "t1");
        let debug = format!("{tr:?}");
        assert!(debug.contains("TeamRef"));
    }

    // ════════════════════════════════════════════════════════════════
    // User
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn user_full() {
        let json = json!({
            "id": "u1",
            "name": "Alice",
            "displayName": "alice_dev",
            "email": "alice@example.com"
        });
        let user: User = serde_json::from_value(json).unwrap();
        assert_eq!(user.name, "Alice");
        assert_eq!(user.display_name.as_deref(), Some("alice_dev"));
        assert_eq!(user.email.as_deref(), Some("alice@example.com"));
    }

    #[test]
    fn user_minimal() {
        let json = json!({"id": "u2", "name": "Bob"});
        let user: User = serde_json::from_value(json).unwrap();
        assert_eq!(user.name, "Bob");
        assert!(user.display_name.is_none());
        assert!(user.email.is_none());
    }

    #[test]
    fn user_camel_case_display_name() {
        // Verify camelCase field naming
        let user = User {
            id: "u1".into(),
            name: "Test".into(),
            display_name: Some("test_user".into()),
            email: None,
        };
        let val: serde_json::Value = serde_json::to_value(&user).unwrap();
        assert!(val.get("displayName").is_some());
        assert!(val.get("display_name").is_none());
    }

    #[test]
    fn user_roundtrip() {
        let user = User {
            id: "u1".into(),
            name: "Charlie".into(),
            display_name: Some("charlie".into()),
            email: Some("charlie@dev.com".into()),
        };
        let json = serde_json::to_string(&user).unwrap();
        let back: User = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, user.id);
        assert_eq!(back.name, user.name);
        assert_eq!(back.display_name, user.display_name);
        assert_eq!(back.email, user.email);
    }

    #[test]
    fn user_clone_debug() {
        let user = User {
            id: "u1".into(),
            name: "Test".into(),
            display_name: None,
            email: None,
        };
        let cloned = user.clone();
        assert_eq!(cloned.name, "Test");
        let debug = format!("{user:?}");
        assert!(debug.contains("User"));
    }

    // ════════════════════════════════════════════════════════════════
    // Cycle
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn cycle_camel_case_serde() {
        let json = json!({
            "id": "c1",
            "number": 5,
            "name": "Sprint 5",
            "startsAt": "2026-03-01",
            "endsAt": "2026-03-14",
            "completedAt": null
        });
        let cycle: Cycle = serde_json::from_value(json).unwrap();
        assert_eq!(cycle.number, 5);
        assert!(cycle.completed_at.is_none());
        assert_eq!(cycle.starts_at.as_deref(), Some("2026-03-01"));
        assert_eq!(cycle.ends_at.as_deref(), Some("2026-03-14"));
    }

    #[test]
    fn cycle_minimal() {
        let json = json!({"id": "c2", "number": 1});
        let cycle: Cycle = serde_json::from_value(json).unwrap();
        assert_eq!(cycle.number, 1);
        assert!(cycle.name.is_none());
        assert!(cycle.starts_at.is_none());
        assert!(cycle.ends_at.is_none());
        assert!(cycle.completed_at.is_none());
    }

    #[test]
    fn cycle_completed() {
        let json = json!({
            "id": "c3",
            "number": 10,
            "name": "Sprint 10",
            "startsAt": "2026-02-01",
            "endsAt": "2026-02-14",
            "completedAt": "2026-02-13T18:00:00Z"
        });
        let cycle: Cycle = serde_json::from_value(json).unwrap();
        assert!(cycle.completed_at.is_some());
    }

    #[test]
    fn cycle_roundtrip() {
        let cycle = Cycle {
            id: "c1".into(),
            number: 3,
            name: Some("Sprint 3".into()),
            starts_at: Some("2026-03-01".into()),
            ends_at: Some("2026-03-14".into()),
            completed_at: None,
        };
        let json = serde_json::to_string(&cycle).unwrap();
        let back: Cycle = serde_json::from_str(&json).unwrap();
        assert_eq!(back.number, cycle.number);
        assert_eq!(back.name, cycle.name);
    }

    #[test]
    fn cycle_serializes_camel_case() {
        let cycle = Cycle {
            id: "c1".into(),
            number: 1,
            name: None,
            starts_at: Some("2026-01-01".into()),
            ends_at: None,
            completed_at: None,
        };
        let val: serde_json::Value = serde_json::to_value(&cycle).unwrap();
        assert!(val.get("startsAt").is_some());
        assert!(val.get("starts_at").is_none());
        assert!(val.get("endsAt").is_some());
        assert!(val.get("completedAt").is_some());
    }

    #[test]
    fn cycle_clone_debug() {
        let cycle = Cycle {
            id: "c1".into(),
            number: 1,
            name: None,
            starts_at: None,
            ends_at: None,
            completed_at: None,
        };
        let cloned = cycle.clone();
        assert_eq!(cloned.number, 1);
        let debug = format!("{cycle:?}");
        assert!(debug.contains("Cycle"));
    }

    // ════════════════════════════════════════════════════════════════
    // Project
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn project_serde() {
        let json = json!({
            "id": "p1",
            "name": "Q1 Goals",
            "description": "quarterly",
            "state": "started",
            "progress": 0.75,
            "createdAt": "2026-01-01",
            "updatedAt": "2026-03-01",
            "url": "https://linear.app/project/p1"
        });
        let project: Project = serde_json::from_value(json).unwrap();
        assert_eq!(project.name, "Q1 Goals");
        assert_eq!(project.progress, Some(0.75));
        assert_eq!(project.state.as_deref(), Some("started"));
    }

    #[test]
    fn project_minimal() {
        let json = json!({"id": "p2", "name": "Quick Fix"});
        let project: Project = serde_json::from_value(json).unwrap();
        assert_eq!(project.name, "Quick Fix");
        assert!(project.description.is_none());
        assert!(project.state.is_none());
        assert!(project.progress.is_none());
        assert!(project.created_at.is_none());
        assert!(project.updated_at.is_none());
        assert!(project.url.is_none());
    }

    #[test]
    fn project_progress_zero() {
        let json = json!({"id": "p3", "name": "New", "progress": 0.0});
        let project: Project = serde_json::from_value(json).unwrap();
        assert_eq!(project.progress, Some(0.0));
    }

    #[test]
    fn project_progress_one() {
        let json = json!({"id": "p4", "name": "Done", "progress": 1.0});
        let project: Project = serde_json::from_value(json).unwrap();
        assert_eq!(project.progress, Some(1.0));
    }

    #[test]
    fn project_roundtrip() {
        let project = Project {
            id: "p1".into(),
            name: "Test".into(),
            description: Some("desc".into()),
            state: Some("planned".into()),
            progress: Some(0.5),
            created_at: Some("2026-01-01".into()),
            updated_at: Some("2026-02-01".into()),
            url: Some("https://linear.app/p1".into()),
        };
        let json = serde_json::to_string(&project).unwrap();
        let back: Project = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, project.id);
        assert_eq!(back.name, project.name);
        assert_eq!(back.progress, project.progress);
    }

    #[test]
    fn project_serializes_camel_case() {
        let project = Project {
            id: "p1".into(),
            name: "Test".into(),
            description: None,
            state: None,
            progress: None,
            created_at: Some("2026-01-01".into()),
            updated_at: None,
            url: None,
        };
        let val: serde_json::Value = serde_json::to_value(&project).unwrap();
        assert!(val.get("createdAt").is_some());
        assert!(val.get("created_at").is_none());
        assert!(val.get("updatedAt").is_some());
        assert!(val.get("updated_at").is_none());
    }

    #[test]
    fn project_clone_debug() {
        let project = Project {
            id: "p1".into(),
            name: "Test".into(),
            description: None,
            state: None,
            progress: None,
            created_at: None,
            updated_at: None,
            url: None,
        };
        let cloned = project.clone();
        assert_eq!(cloned.name, "Test");
        let debug = format!("{project:?}");
        assert!(debug.contains("Project"));
    }

    // ════════════════════════════════════════════════════════════════
    // IssueComment
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn issue_comment_serde() {
        let json = json!({
            "id": "cmt1",
            "body": "Looks good!",
            "user": {"id": "u1", "name": "Alice", "displayName": null, "email": null},
            "createdAt": "2026-03-03",
            "updatedAt": null
        });
        let comment: IssueComment = serde_json::from_value(json).unwrap();
        assert_eq!(comment.body, "Looks good!");
        assert!(comment.user.is_some());
    }

    #[test]
    fn issue_comment_minimal() {
        let json = json!({"id": "cmt2", "body": "LGTM"});
        let comment: IssueComment = serde_json::from_value(json).unwrap();
        assert_eq!(comment.body, "LGTM");
        assert!(comment.user.is_none());
        assert!(comment.created_at.is_none());
        assert!(comment.updated_at.is_none());
    }

    #[test]
    fn issue_comment_no_user() {
        let json = json!({
            "id": "cmt3",
            "body": "Automated comment",
            "user": null,
            "createdAt": "2026-03-04",
            "updatedAt": null
        });
        let comment: IssueComment = serde_json::from_value(json).unwrap();
        assert!(comment.user.is_none());
        assert_eq!(comment.body, "Automated comment");
    }

    #[test]
    fn issue_comment_roundtrip() {
        let comment = IssueComment {
            id: "cmt1".into(),
            body: "Test comment with **markdown**".into(),
            user: Some(User {
                id: "u1".into(),
                name: "Bot".into(),
                display_name: None,
                email: None,
            }),
            created_at: Some("2026-03-01T12:00:00Z".into()),
            updated_at: None,
        };
        let json = serde_json::to_string(&comment).unwrap();
        let back: IssueComment = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, comment.id);
        assert_eq!(back.body, comment.body);
        assert!(back.user.is_some());
    }

    #[test]
    fn issue_comment_camel_case() {
        let comment = IssueComment {
            id: "cmt1".into(),
            body: "text".into(),
            user: None,
            created_at: Some("2026-03-01".into()),
            updated_at: Some("2026-03-02".into()),
        };
        let val: serde_json::Value = serde_json::to_value(&comment).unwrap();
        assert!(val.get("createdAt").is_some());
        assert!(val.get("created_at").is_none());
        assert!(val.get("updatedAt").is_some());
        assert!(val.get("updated_at").is_none());
    }

    #[test]
    fn issue_comment_clone_debug() {
        let comment = IssueComment {
            id: "cmt1".into(),
            body: "hi".into(),
            user: None,
            created_at: None,
            updated_at: None,
        };
        let cloned = comment.clone();
        assert_eq!(cloned.body, "hi");
        let debug = format!("{comment:?}");
        assert!(debug.contains("IssueComment"));
    }

    #[test]
    fn issue_comment_empty_body() {
        let json = json!({"id": "cmt4", "body": ""});
        let comment: IssueComment = serde_json::from_value(json).unwrap();
        assert_eq!(comment.body, "");
    }

    #[test]
    fn issue_comment_unicode_body() {
        let json = json!({"id": "cmt5", "body": "Fix the bug \u{1F41B} immediately"});
        let comment: IssueComment = serde_json::from_value(json).unwrap();
        assert!(comment.body.contains('\u{1F41B}'));
    }

    // ════════════════════════════════════════════════════════════════
    // Mutation payloads
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn issue_create_payload_success() {
        let json = json!({
            "success": true,
            "issue": {
                "id": "i1", "identifier": "P-1", "title": "New"
            }
        });
        let payload: IssueCreatePayload = serde_json::from_value(json).unwrap();
        assert!(payload.success);
        assert!(payload.issue.is_some());
        assert_eq!(payload.issue.unwrap().identifier, "P-1");
    }

    #[test]
    fn issue_create_payload_failure_no_issue() {
        let json = json!({"success": false, "issue": null});
        let payload: IssueCreatePayload = serde_json::from_value(json).unwrap();
        assert!(!payload.success);
        assert!(payload.issue.is_none());
    }

    #[test]
    fn issue_create_payload_debug() {
        let json = json!({"success": true, "issue": null});
        let payload: IssueCreatePayload = serde_json::from_value(json).unwrap();
        let debug = format!("{payload:?}");
        assert!(debug.contains("IssueCreatePayload"));
    }

    #[test]
    fn issue_update_payload_success() {
        let json = json!({
            "success": true,
            "issue": {
                "id": "i1", "identifier": "P-1", "title": "Updated"
            }
        });
        let payload: IssueUpdatePayload = serde_json::from_value(json).unwrap();
        assert!(payload.success);
        assert_eq!(payload.issue.unwrap().title, "Updated");
    }

    #[test]
    fn issue_update_payload_failed() {
        let json = json!({"success": false, "issue": null});
        let payload: IssueUpdatePayload = serde_json::from_value(json).unwrap();
        assert!(!payload.success);
        assert!(payload.issue.is_none());
    }

    #[test]
    fn issue_update_payload_debug() {
        let json = json!({"success": false, "issue": null});
        let payload: IssueUpdatePayload = serde_json::from_value(json).unwrap();
        let debug = format!("{payload:?}");
        assert!(debug.contains("IssueUpdatePayload"));
    }

    #[test]
    fn comment_create_payload_success() {
        let json = json!({
            "success": true,
            "comment": {"id": "c1", "body": "hi", "user": null, "createdAt": null, "updatedAt": null}
        });
        let payload: CommentCreatePayload = serde_json::from_value(json).unwrap();
        assert!(payload.success);
        assert_eq!(payload.comment.unwrap().body, "hi");
    }

    #[test]
    fn comment_create_payload_failure() {
        let json = json!({"success": false, "comment": null});
        let payload: CommentCreatePayload = serde_json::from_value(json).unwrap();
        assert!(!payload.success);
        assert!(payload.comment.is_none());
    }

    #[test]
    fn comment_create_payload_debug() {
        let json = json!({"success": true, "comment": null});
        let payload: CommentCreatePayload = serde_json::from_value(json).unwrap();
        let debug = format!("{payload:?}");
        assert!(debug.contains("CommentCreatePayload"));
    }

    // ════════════════════════════════════════════════════════════════
    // Edge cases: missing optional fields deserialized from partial JSON
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn issue_missing_all_optional_fields_from_api() {
        // Linear GraphQL might return only required fields
        let json = json!({"id": "i99", "identifier": "X-99", "title": "Bare issue"});
        let issue: Issue = serde_json::from_value(json).unwrap();
        assert_eq!(issue.id, "i99");
        assert!(issue.description.is_none());
        assert!(issue.priority.is_none());
        assert!(issue.state.is_none());
        assert!(issue.assignee.is_none());
        assert!(issue.team.is_none());
        assert!(issue.labels.is_none());
    }

    #[test]
    fn issue_fails_without_required_id() {
        let json = json!({"identifier": "X-1", "title": "No id"});
        let result = serde_json::from_value::<Issue>(json);
        assert!(result.is_err());
    }

    #[test]
    fn issue_fails_without_required_identifier() {
        let json = json!({"id": "i1", "title": "No ident"});
        let result = serde_json::from_value::<Issue>(json);
        assert!(result.is_err());
    }

    #[test]
    fn issue_fails_without_required_title() {
        let json = json!({"id": "i1", "identifier": "X-1"});
        let result = serde_json::from_value::<Issue>(json);
        assert!(result.is_err());
    }

    #[test]
    fn team_fails_without_required_id() {
        let json = json!({"name": "Eng", "key": "ENG"});
        let result = serde_json::from_value::<Team>(json);
        assert!(result.is_err());
    }

    #[test]
    fn team_fails_without_required_key() {
        let json = json!({"id": "t1", "name": "Eng"});
        let result = serde_json::from_value::<Team>(json);
        assert!(result.is_err());
    }

    #[test]
    fn user_fails_without_required_name() {
        let json = json!({"id": "u1"});
        let result = serde_json::from_value::<User>(json);
        assert!(result.is_err());
    }

    #[test]
    fn cycle_fails_without_required_number() {
        let json = json!({"id": "c1"});
        let result = serde_json::from_value::<Cycle>(json);
        assert!(result.is_err());
    }

    #[test]
    fn project_fails_without_required_name() {
        let json = json!({"id": "p1"});
        let result = serde_json::from_value::<Project>(json);
        assert!(result.is_err());
    }

    #[test]
    fn issue_comment_fails_without_required_body() {
        let json = json!({"id": "cmt1"});
        let result = serde_json::from_value::<IssueComment>(json);
        assert!(result.is_err());
    }

    // ════════════════════════════════════════════════════════════════
    // Deserialization from extra/unknown fields (serde default behavior)
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn issue_ignores_unknown_fields() {
        let json = json!({
            "id": "i1",
            "identifier": "X-1",
            "title": "T",
            "unknownField": "should be ignored",
            "anotherExtra": 42
        });
        let issue: Issue = serde_json::from_value(json).unwrap();
        assert_eq!(issue.title, "T");
    }

    #[test]
    fn team_ignores_unknown_fields() {
        let json = json!({
            "id": "t1",
            "name": "Eng",
            "key": "ENG",
            "extra_field": true
        });
        let team: Team = serde_json::from_value(json).unwrap();
        assert_eq!(team.name, "Eng");
    }

    #[test]
    fn graphql_error_ignores_unknown_fields() {
        let json = json!({
            "message": "err",
            "locations": [{"line": 1, "column": 5}],
            "extra": "ignored"
        });
        let err: GraphQLError = serde_json::from_value(json).unwrap();
        assert_eq!(err.message, "err");
    }

    // ════════════════════════════════════════════════════════════════
    // Special string / encoding edge cases
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn issue_title_with_special_chars() {
        let json = json!({
            "id": "i1",
            "identifier": "X-1",
            "title": "Fix \"quoted\" & <html> chars"
        });
        let issue: Issue = serde_json::from_value(json).unwrap();
        assert!(issue.title.contains('"'));
        assert!(issue.title.contains('&'));
        assert!(issue.title.contains('<'));
    }

    #[test]
    fn issue_description_multiline() {
        let json = json!({
            "id": "i1",
            "identifier": "X-1",
            "title": "T",
            "description": "Line 1\nLine 2\n\nLine 4"
        });
        let issue: Issue = serde_json::from_value(json).unwrap();
        assert!(issue.description.unwrap().contains('\n'));
    }

    // ════════════════════════════════════════════════════════════════
    // Webhook types
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn webhook_action_serde_roundtrip() {
        for (action, expected) in [
            (WebhookAction::Create, "\"create\""),
            (WebhookAction::Update, "\"update\""),
            (WebhookAction::Remove, "\"remove\""),
        ] {
            let json = serde_json::to_string(&action).unwrap();
            assert_eq!(json, expected);
            let back: WebhookAction = serde_json::from_str(&json).unwrap();
            assert_eq!(action, back);
        }
    }

    #[test]
    fn webhook_action_display() {
        assert_eq!(WebhookAction::Create.to_string(), "create");
        assert_eq!(WebhookAction::Update.to_string(), "update");
        assert_eq!(WebhookAction::Remove.to_string(), "remove");
    }

    #[test]
    fn webhook_resource_type_serde_roundtrip() {
        for (rt, expected) in [
            (WebhookResourceType::Issue, "\"Issue\""),
            (WebhookResourceType::Comment, "\"Comment\""),
            (WebhookResourceType::Project, "\"Project\""),
            (WebhookResourceType::Cycle, "\"Cycle\""),
            (WebhookResourceType::IssueLabel, "\"IssueLabel\""),
            (WebhookResourceType::Reaction, "\"Reaction\""),
        ] {
            let json = serde_json::to_string(&rt).unwrap();
            assert_eq!(json, expected);
            let back: WebhookResourceType = serde_json::from_str(&json).unwrap();
            assert_eq!(rt, back);
        }
    }

    #[test]
    fn webhook_resource_type_to_topic() {
        assert_eq!(
            WebhookResourceType::Issue.to_topic(WebhookAction::Create),
            "linear.issue.create"
        );
        assert_eq!(
            WebhookResourceType::Comment.to_topic(WebhookAction::Update),
            "linear.comment.update"
        );
        assert_eq!(
            WebhookResourceType::Cycle.to_topic(WebhookAction::Remove),
            "linear.cycle.remove"
        );
    }

    #[test]
    fn webhook_payload_minimal_deserialization() {
        let json = json!({
            "action": "create",
            "createdAt": "2026-03-07T00:00:00.000Z",
            "type": "Issue",
            "data": {"id": "issue-1", "identifier": "LIN-1", "title": "Test"}
        });
        let payload: WebhookPayload = serde_json::from_value(json).unwrap();
        assert_eq!(payload.action, WebhookAction::Create);
        assert_eq!(payload.resource_type, WebhookResourceType::Issue);
        assert!(payload.actor.is_none());
        assert!(payload.url.is_none());
    }

    #[test]
    fn webhook_payload_full_deserialization() {
        let json = json!({
            "action": "update",
            "actor": {"id": "u1", "name": "Alice"},
            "createdAt": "2026-03-07T12:00:00.000Z",
            "url": "https://linear.app/hooks/xxx",
            "type": "Comment",
            "data": {"id": "c1", "body": "Hello"},
            "organizationId": "org-1",
            "webhookId": "wh-1"
        });
        let payload: WebhookPayload = serde_json::from_value(json).unwrap();
        assert_eq!(payload.action, WebhookAction::Update);
        assert_eq!(payload.resource_type, WebhookResourceType::Comment);
        assert_eq!(payload.actor.as_ref().unwrap().name, "Alice");
        assert_eq!(payload.organization_id.as_deref(), Some("org-1"));
        assert_eq!(payload.webhook_id.as_deref(), Some("wh-1"));
        assert!(payload.webhook_timestamp.is_none());
    }

    #[test]
    fn webhook_payload_serialization_roundtrip() {
        let payload = WebhookPayload {
            action: WebhookAction::Create,
            actor: Some(User {
                id: "u1".into(),
                name: "Bob".into(),
                display_name: None,
                email: None,
            }),
            created_at: "2026-03-07T00:00:00.000Z".into(),
            url: None,
            resource_type: WebhookResourceType::Issue,
            data: json!({"id": "i1"}),
            organization_id: None,
            webhook_id: Some("wh-123".into()),
            webhook_timestamp: None,
        };

        let json_str = serde_json::to_string(&payload).unwrap();
        let back: WebhookPayload = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.action, WebhookAction::Create);
        assert_eq!(back.resource_type, WebhookResourceType::Issue);
        assert_eq!(back.actor.unwrap().name, "Bob");
    }

    #[test]
    fn webhook_payload_unknown_fields_ignored() {
        let json = json!({
            "action": "create",
            "createdAt": "2026-03-07T00:00:00.000Z",
            "type": "Issue",
            "data": {},
            "unknownField": "should be ignored"
        });
        let payload: WebhookPayload = serde_json::from_value(json).unwrap();
        assert_eq!(payload.action, WebhookAction::Create);
    }
}
