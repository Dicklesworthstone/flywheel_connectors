//! Lease coordinator for multi-node execution authority.
//!
//! Implements the lease acquisition, renewal, conflict detection, and
//! coordinator election protocol from `FCP_Specification_V3.md` §11.3
//! (Leases), §11.3.1 (Distributed Lease Issuance), and §11.3.2
//! (Lease Conflict Handling).
//!
//! # Design
//!
//! The coordinator manages the lifecycle of execution leases across
//! mesh nodes. It ensures:
//!
//! 1. **Exclusive ownership**: Only one node holds authority for a
//!    given subject/purpose at any time.
//! 2. **Fencing**: Higher `lease_seq` always wins, preventing stale
//!    holders from executing after authority transfer.
//! 3. **Deterministic election**: HRW (rendezvous hashing) selects
//!    the coordinator without central coordination.
//! 4. **Conflict detection**: Overlapping leases are detected and
//!    escalated based on risk tier.
//! 5. **Audit trail**: Every authority change produces a durable
//!    timeline event for post-incident analysis.

use std::cmp::Ordering;

use fcp_core::{
    Lease as CoreLease, LeaseParams as CoreLeaseParams, LeasePurpose as CoreLeasePurpose,
    LeaseValidationError as CoreLeaseValidationError, ObjectHeader,
    validate_lease as validate_core_lease,
};
use fcp_prelude::{ObjectId, TailscaleNodeId, ZoneId, select_coordinator};
use fcp_telemetry::metrics;
use serde::{Deserialize, Serialize};

use crate::authority::{AuthorityReasonCode, AuthorityTimelineEvent, ObservedLeaseAuthority};
use crate::planner::{HeldLease, LeasePurpose};

// ── Configuration ───────────────────────────────────────────────────────

/// Lease coordinator configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseCoordinatorConfig {
    /// Default TTL for new leases (seconds).
    pub default_ttl_secs: u32,
    /// Minimum TTL (prevents excessively short leases).
    pub min_ttl_secs: u32,
    /// Maximum TTL (prevents excessively long leases).
    pub max_ttl_secs: u32,
    /// Renew when this fraction of TTL remains (basis points, 0-10000).
    pub renew_threshold_bps: u16,
    /// Maximum concurrent leases per node.
    pub max_leases_per_node: usize,
    /// Whether to escalate conflicts for dangerous operations.
    pub escalate_dangerous_conflicts: bool,
}

/// Maximum allowed drift for fencing tokens during rebase (prevents poisoning).
const MAX_FENCING_TOKEN_DRIFT: u64 = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FencingRebaseStatus {
    Ready,
    Exhausted,
    DriftTooLarge,
}

impl FencingRebaseStatus {
    const fn rejection_reason(self) -> Option<&'static str> {
        match self {
            Self::Ready => None,
            Self::Exhausted => Some("fencing token space exhausted"),
            Self::DriftTooLarge => Some("observed fencing token drift exceeds safety limit"),
        }
    }
}

impl Default for LeaseCoordinatorConfig {
    fn default() -> Self {
        Self {
            default_ttl_secs: 300,     // 5 minutes
            min_ttl_secs: 10,          // 10 seconds minimum
            max_ttl_secs: 3600,        // 1 hour maximum
            renew_threshold_bps: 2000, // renew at 20% remaining
            max_leases_per_node: 64,
            escalate_dangerous_conflicts: true,
        }
    }
}

// ── Lease Coordinator ───────────────────────────────────────────────────

/// Outcome of a lease acquisition attempt.
#[must_use]
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum AcquireOutcome {
    /// Lease granted to the requester.
    Granted { fencing_token: u64, expires_at: u64 },
    /// Lease rejected before holder comparison (capacity or local admission).
    Rejected { reason: String },
    /// Lease denied because another node holds it.
    Denied {
        current_holder: TailscaleNodeId,
        current_fencing_token: u64,
        expires_at: u64,
        reason: String,
    },
    /// Lease conflict detected (overlapping active leases).
    Conflict {
        holders: Vec<TailscaleNodeId>,
        fencing_tokens: Vec<u64>,
        reason: String,
    },
}

/// Outcome of a lease renewal attempt.
#[must_use]
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum RenewOutcome {
    /// Lease renewed with same fencing token, new expiry.
    Renewed { expires_at: u64 },
    /// Renewal denied (lease expired or superseded).
    Denied { reason: String },
}

/// Outcome of a lease release.
#[must_use]
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ReleaseOutcome {
    /// Lease released successfully.
    Released,
    /// Release failed (not the holder or already expired).
    NotHeld { reason: String },
}

/// Request to issue a durable, quorum-signed core lease through the mesh coordinator.
#[derive(Debug, Clone)]
pub struct SignedLeaseIssueRequest {
    /// Core lease parameters supplied by the caller. The coordinator replaces
    /// `lease_seq` with the next admitted fencing token and clamps `ttl_secs`
    /// according to [`LeaseCoordinatorConfig`].
    pub params: CoreLeaseParams,
    /// Lease observations currently visible to the issuing node.
    pub existing_leases: Vec<ObservedLeaseAuthority>,
    /// Nodes eligible to coordinate this subject.
    pub eligible_nodes: Vec<TailscaleNodeId>,
    /// Minimum quorum signatures required before the lease can be materialized.
    pub required_signatures: usize,
    /// Logical clock time for the admission decision.
    pub now_secs: u64,
}

/// Outcome of issuing a durable core lease object.
#[must_use]
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum SignedLeaseIssueOutcome {
    /// Lease granted and materialized as a core lease object.
    Granted { lease: Box<CoreLease> },
    /// Lease rejected before holder comparison.
    Rejected { reason: String },
    /// Lease denied because another node currently holds authority.
    Denied {
        current_holder: TailscaleNodeId,
        current_fencing_token: u64,
        expires_at: u64,
        reason: String,
    },
    /// Multiple active holders were observed for the same subject/purpose.
    Conflict {
        holders: Vec<TailscaleNodeId>,
        fencing_tokens: Vec<u64>,
        reason: String,
    },
}

/// Conflict severity for escalation decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictSeverity {
    /// Informational — lower-fencing-token holder should yield.
    Info,
    /// Warning — overlapping leases detected but resolvable.
    Warning,
    /// Critical — dangerous operation with split-brain risk.
    Critical,
}

/// A detected lease conflict with evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseConflict {
    /// Zone where conflict occurred.
    pub zone_id: ZoneId,
    /// Subject with conflicting leases.
    pub subject_id: ObjectId,
    /// Purpose of the conflicting leases.
    pub purpose: LeasePurpose,
    /// Severity of the conflict.
    pub severity: ConflictSeverity,
    /// Competing lease holders.
    pub holders: Vec<ConflictingHolder>,
    /// When the conflict was detected (Unix ms).
    pub detected_at_ms: u64,
    /// Resolution recommendation.
    pub resolution: String,
}

/// A holder involved in a lease conflict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictingHolder {
    /// Node holding the lease.
    pub node_id: TailscaleNodeId,
    /// Fencing token for the lease.
    pub fencing_token: u64,
    /// Expiration of the lease.
    pub expires_at: u64,
}

/// Lease coordinator for managing execution authority across mesh nodes.
///
/// The coordinator computes outcomes from observed lease state and returns
/// decisions. It keeps a local next-token cursor, but rebases that cursor
/// against observed fencing tokens before issuing a new lease. Actual lease
/// storage is managed by the caller (mesh node or host).
#[derive(Debug, Clone)]
pub struct LeaseCoordinator {
    config: LeaseCoordinatorConfig,
    /// Monotonic sequence counter for fencing tokens.
    next_seq: u64,
}

impl LeaseCoordinator {
    /// Create a new lease coordinator with the given configuration.
    #[must_use]
    pub fn new(config: LeaseCoordinatorConfig) -> Self {
        Self {
            config,
            next_seq: 1,
        }
    }

    /// Create a coordinator with the default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(LeaseCoordinatorConfig::default())
    }

    /// Attempt to acquire a lease for a subject.
    ///
    /// The coordinator checks existing leases for the subject/purpose
    /// and grants or denies based on fencing token ordering.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub fn acquire(
        &mut self,
        requester: &TailscaleNodeId,
        zone_id: &ZoneId,
        subject_id: &ObjectId,
        purpose: &LeasePurpose,
        existing_leases: &[ObservedLeaseAuthority],
        eligible_nodes: &[TailscaleNodeId],
        now_secs: u64,
        requested_ttl: Option<u32>,
    ) -> (AcquireOutcome, Vec<AuthorityTimelineEvent>) {
        let mut timeline = Vec::new();
        let ttl = self.clamp_ttl(requested_ttl.unwrap_or(self.config.default_ttl_secs));
        let rebase_status = self.rebase_next_seq(existing_leases);

        // Filter to active leases for this subject/purpose
        let active =
            canonical_active_leases_for_subject(existing_leases, subject_id, *purpose, now_secs);

        // No active leases — grant immediately
        if active.is_empty() {
            let observed_prior_holder = existing_leases
                .iter()
                .any(|obs| obs.lease.subject_id == *subject_id && obs.lease.purpose == *purpose);
            if let Some(reason) = rebase_status.rejection_reason() {
                timeline.push(AuthorityTimelineEvent {
                    observed_at_ms: now_secs * 1000,
                    operation: "lease.acquire_refused".into(),
                    subject_id: *subject_id,
                    purpose: purpose.clone(),
                    holder: None,
                    coordinator: select_coordinator(zone_id, subject_id, eligible_nodes),
                    reason_code: AuthorityReasonCode::LeaseAcquisitionRejected,
                    fencing_token: None,
                    expires_at: None,
                    explanation: reason.to_string(),
                });
                return (
                    AcquireOutcome::Rejected {
                        reason: reason.to_string(),
                    },
                    timeline,
                );
            }

            let active_leases_for_requester =
                canonical_active_lease_count_for_holder(existing_leases, requester, now_secs);
            if active_leases_for_requester >= self.config.max_leases_per_node {
                let reason = format!(
                    "Lease rejected: {} already holds {} active leases (limit={})",
                    requester.as_str(),
                    active_leases_for_requester,
                    self.config.max_leases_per_node
                );
                timeline.push(AuthorityTimelineEvent {
                    observed_at_ms: now_secs * 1000,
                    operation: "lease.acquire_rejected".into(),
                    subject_id: *subject_id,
                    purpose: purpose.clone(),
                    holder: Some(requester.clone()),
                    coordinator: select_coordinator(zone_id, subject_id, eligible_nodes),
                    reason_code: AuthorityReasonCode::LeaseAcquisitionRejected,
                    fencing_token: None,
                    expires_at: None,
                    explanation: reason.clone(),
                });
                return (AcquireOutcome::Rejected { reason }, timeline);
            }

            let Some(token) = self.next_fencing_token() else {
                // Fencing token space exhausted. Unreachable via legitimate
                // operation (u64 holds ~18e18 values) but reachable when an
                // adversarial peer reports fencing_token = u64::MAX in
                // existing_leases, which rebase_next_seq clamps into
                // next_seq via saturating_add. Refuse gracefully instead of
                // panicking the coordinator.
                timeline.push(AuthorityTimelineEvent {
                    observed_at_ms: now_secs * 1000,
                    operation: "lease.acquire_refused".into(),
                    subject_id: *subject_id,
                    purpose: purpose.clone(),
                    holder: None,
                    coordinator: select_coordinator(zone_id, subject_id, eligible_nodes),
                    reason_code: AuthorityReasonCode::LeaseAcquisitionRejected,
                    fencing_token: None,
                    expires_at: None,
                    explanation: "Fencing token space exhausted — refusing to grant lease".into(),
                });

                return (
                    AcquireOutcome::Rejected {
                        reason: "fencing token space exhausted".into(),
                    },
                    timeline,
                );
            };
            let expires_at = now_secs + u64::from(ttl);

            timeline.push(AuthorityTimelineEvent {
                observed_at_ms: now_secs * 1000,
                operation: "lease.acquired".into(),
                subject_id: *subject_id,
                purpose: purpose.clone(),
                holder: Some(requester.clone()),
                coordinator: select_coordinator(zone_id, subject_id, eligible_nodes),
                reason_code: AuthorityReasonCode::ActiveAuthority,
                fencing_token: Some(token),
                expires_at: Some(expires_at),
                explanation: format!(
                    "Lease granted to {} (no competing holders)",
                    requester.as_str()
                ),
            });
            let purpose_label = purpose.to_string();
            metrics::record_lease_issued(&purpose_label, "granted");
            if observed_prior_holder {
                metrics::record_lease_handed_off("previous_expired", None);
            }

            return (
                AcquireOutcome::Granted {
                    fencing_token: token,
                    expires_at,
                },
                timeline,
            );
        }

        // Check for conflicts
        if active.len() > 1 {
            let severity = if self.config.escalate_dangerous_conflicts {
                ConflictSeverity::Critical
            } else {
                ConflictSeverity::Warning
            };

            let holders: Vec<TailscaleNodeId> = active.iter().map(|o| o.holder.clone()).collect();
            let tokens: Vec<u64> = active.iter().map(|o| o.lease.fencing_token).collect();

            timeline.push(AuthorityTimelineEvent {
                observed_at_ms: now_secs * 1000,
                operation: "lease.conflict_detected".into(),
                subject_id: *subject_id,
                purpose: purpose.clone(),
                holder: None,
                coordinator: select_coordinator(zone_id, subject_id, eligible_nodes),
                reason_code: AuthorityReasonCode::LeaseConflictDetected,
                fencing_token: None,
                expires_at: None,
                explanation: format!(
                    "Conflict: {} active leases for subject (severity: {severity:?})",
                    active.len()
                ),
            });
            let purpose_label = purpose.to_string();
            metrics::record_lease_fenced(&purpose_label, "conflict_detected");

            return (
                AcquireOutcome::Conflict {
                    holders,
                    fencing_tokens: tokens,
                    reason: "Multiple active leases detected for subject/purpose".into(),
                },
                timeline,
            );
        }

        // Single active lease — check if requester is the holder
        let current = &active[0];
        if current.holder == *requester {
            // Already holds it — treat as renewal
            let (renew_outcome, renew_events) = self.renew(
                requester,
                subject_id,
                purpose,
                current.lease.fencing_token,
                existing_leases,
                now_secs,
                Some(ttl),
            );
            timeline.extend(renew_events);
            match renew_outcome {
                RenewOutcome::Renewed { expires_at } => {
                    return (
                        AcquireOutcome::Granted {
                            fencing_token: current.lease.fencing_token,
                            expires_at,
                        },
                        timeline,
                    );
                }
                RenewOutcome::Denied { reason } => {
                    return (
                        AcquireOutcome::Denied {
                            current_holder: current.holder.clone(),
                            current_fencing_token: current.lease.fencing_token,
                            expires_at: current.lease.expires_at,
                            reason,
                        },
                        timeline,
                    );
                }
            }
        }

        let selected_coordinator = select_coordinator(zone_id, subject_id, eligible_nodes);
        let current_holder_online = eligible_nodes.iter().any(|node| node == &current.holder);
        if !current_holder_online
            && selected_coordinator
                .as_ref()
                .is_some_and(|holder| holder == requester)
        {
            if let Some(reason) = rebase_status.rejection_reason() {
                timeline.push(AuthorityTimelineEvent {
                    observed_at_ms: now_secs * 1000,
                    operation: "lease.handoff_refused".into(),
                    subject_id: *subject_id,
                    purpose: purpose.clone(),
                    holder: Some(requester.clone()),
                    coordinator: selected_coordinator,
                    reason_code: AuthorityReasonCode::LeaseAcquisitionRejected,
                    fencing_token: None,
                    expires_at: None,
                    explanation: reason.to_string(),
                });
                return (
                    AcquireOutcome::Rejected {
                        reason: reason.to_string(),
                    },
                    timeline,
                );
            }

            let active_leases_for_requester =
                canonical_active_lease_count_for_holder(existing_leases, requester, now_secs);
            if active_leases_for_requester >= self.config.max_leases_per_node {
                let reason = format!(
                    "Lease handoff rejected: {} already holds {} active leases (limit={})",
                    requester.as_str(),
                    active_leases_for_requester,
                    self.config.max_leases_per_node
                );
                timeline.push(AuthorityTimelineEvent {
                    observed_at_ms: now_secs * 1000,
                    operation: "lease.handoff_rejected".into(),
                    subject_id: *subject_id,
                    purpose: purpose.clone(),
                    holder: Some(requester.clone()),
                    coordinator: selected_coordinator,
                    reason_code: AuthorityReasonCode::LeaseAcquisitionRejected,
                    fencing_token: None,
                    expires_at: None,
                    explanation: reason.clone(),
                });
                return (AcquireOutcome::Rejected { reason }, timeline);
            }

            let Some(token) = self.next_fencing_token() else {
                timeline.push(AuthorityTimelineEvent {
                    observed_at_ms: now_secs * 1000,
                    operation: "lease.handoff_refused".into(),
                    subject_id: *subject_id,
                    purpose: purpose.clone(),
                    holder: Some(requester.clone()),
                    coordinator: selected_coordinator,
                    reason_code: AuthorityReasonCode::LeaseAcquisitionRejected,
                    fencing_token: None,
                    expires_at: None,
                    explanation: "Fencing token space exhausted — refusing handoff".into(),
                });

                return (
                    AcquireOutcome::Rejected {
                        reason: "fencing token space exhausted".into(),
                    },
                    timeline,
                );
            };
            let expires_at = now_secs + u64::from(ttl);
            timeline.push(AuthorityTimelineEvent {
                observed_at_ms: now_secs * 1000,
                operation: "lease.handed_off".into(),
                subject_id: *subject_id,
                purpose: purpose.clone(),
                holder: Some(requester.clone()),
                coordinator: selected_coordinator,
                reason_code: AuthorityReasonCode::ActiveAuthority,
                fencing_token: Some(token),
                expires_at: Some(expires_at),
                explanation: format!(
                    "Lease handed off from offline holder {} to {} (old_fencing_token={}, new_fencing_token={token})",
                    current.holder.as_str(),
                    requester.as_str(),
                    current.lease.fencing_token
                ),
            });
            let purpose_label = purpose.to_string();
            metrics::record_lease_issued(&purpose_label, "handoff");
            metrics::record_lease_handed_off("leader_offline", None);
            return (
                AcquireOutcome::Granted {
                    fencing_token: token,
                    expires_at,
                },
                timeline,
            );
        }

        // Different holder — deny
        timeline.push(AuthorityTimelineEvent {
            observed_at_ms: now_secs * 1000,
            operation: "lease.denied".into(),
            subject_id: *subject_id,
            purpose: purpose.clone(),
            holder: Some(current.holder.clone()),
            coordinator: select_coordinator(zone_id, subject_id, eligible_nodes),
            reason_code: AuthorityReasonCode::SupersededByPreferredLease,
            fencing_token: Some(current.lease.fencing_token),
            expires_at: Some(current.lease.expires_at),
            explanation: format!(
                "Denied: {} holds active lease (fencing_token={}, expires={})",
                current.holder.as_str(),
                current.lease.fencing_token,
                current.lease.expires_at
            ),
        });
        let purpose_label = purpose.to_string();
        metrics::record_lease_fenced(&purpose_label, "active_holder");

        (
            AcquireOutcome::Denied {
                current_holder: current.holder.clone(),
                current_fencing_token: current.lease.fencing_token,
                expires_at: current.lease.expires_at,
                reason: format!("Active lease held by {}", current.holder.as_str()),
            },
            timeline,
        )
    }

    /// Select the HRW coordinator for a subject using the normative core hash.
    #[must_use]
    pub fn select_coordinator(
        &self,
        zone_id: &ZoneId,
        subject_id: &ObjectId,
        eligible_nodes: &[TailscaleNodeId],
    ) -> Option<TailscaleNodeId> {
        fcp_prelude::select_coordinator(zone_id, subject_id, eligible_nodes)
    }

    /// Issue a durable [`CoreLease`] after the local admission check grants authority.
    ///
    /// The returned lease carries the caller-supplied quorum signatures and uses the
    /// admitted fencing token. Persistence and gossip distribution remain caller-owned.
    pub fn issue_signed_lease(
        &mut self,
        request: SignedLeaseIssueRequest,
    ) -> (SignedLeaseIssueOutcome, Vec<AuthorityTimelineEvent>) {
        let SignedLeaseIssueRequest {
            mut params,
            existing_leases,
            eligible_nodes,
            required_signatures,
            now_secs,
        } = request;
        let planner_purpose = planner_purpose_for_core(params.purpose);
        if let Some(rejection) =
            signed_lease_issue_hrw_rejection(&params, &eligible_nodes, planner_purpose, now_secs)
        {
            return rejection;
        }
        if let Some(rejection) = signed_lease_issue_quorum_rejection(
            &params,
            &eligible_nodes,
            planner_purpose,
            now_secs,
            required_signatures,
        ) {
            return rejection;
        }
        let (outcome, timeline) = self.acquire(
            &params.holder,
            &params.zone_id,
            &params.subject_object_id,
            &planner_purpose,
            &existing_leases,
            &eligible_nodes,
            now_secs,
            Some(params.ttl_secs),
        );

        let issue_outcome = match outcome {
            AcquireOutcome::Granted {
                fencing_token,
                expires_at,
            } => {
                params.lease_seq = fencing_token;
                params.ttl_secs =
                    u32::try_from(expires_at.saturating_sub(now_secs)).unwrap_or(u32::MAX);
                SignedLeaseIssueOutcome::Granted {
                    lease: Box::new(core_lease_from_params(params, now_secs, expires_at)),
                }
            }
            AcquireOutcome::Rejected { reason } => SignedLeaseIssueOutcome::Rejected { reason },
            AcquireOutcome::Denied {
                current_holder,
                current_fencing_token,
                expires_at,
                reason,
            } => SignedLeaseIssueOutcome::Denied {
                current_holder,
                current_fencing_token,
                expires_at,
                reason,
            },
            AcquireOutcome::Conflict {
                holders,
                fencing_tokens,
                reason,
            } => SignedLeaseIssueOutcome::Conflict {
                holders,
                fencing_tokens,
                reason,
            },
        };
        (issue_outcome, timeline)
    }

    /// Validate a durable core lease against expected authority context.
    ///
    /// # Errors
    /// Returns [`CoreLeaseValidationError`] when the lease is expired, mismatched,
    /// superseded, or lacks the required quorum signature count.
    #[allow(clippy::too_many_arguments)] // Mirrors the core lease validation contract.
    pub fn validate_signed_lease(
        &self,
        lease: &CoreLease,
        expected_subject: &ObjectId,
        expected_zone: &ZoneId,
        expected_purpose: CoreLeasePurpose,
        current_known_seq: u64,
        now_secs: u64,
        required_signatures: usize,
    ) -> Result<(), CoreLeaseValidationError> {
        validate_core_lease(
            lease,
            expected_subject,
            expected_zone,
            expected_purpose,
            current_known_seq,
            now_secs,
            required_signatures,
        )
    }

    /// Renew an existing lease.
    ///
    /// Authoritative validation is performed against `existing_leases`:
    ///
    /// 1. `requester` must currently hold an active lease with
    ///    `held_fencing_token` for the given subject/purpose.
    /// 2. No observed active lease for the same subject/purpose may hold a
    ///    higher fencing token (the requester must not have been superseded).
    /// 3. Renewal is monotonic: the new expiry never regresses below the
    ///    previously observed expiry, even if `now_secs` regresses (clock
    ///    skew, NTP step-back, or a malicious caller reporting a stale time).
    #[allow(clippy::too_many_arguments)] // Lease renewal must bind caller, subject, fencing, observations, and time.
    pub fn renew(
        &self,
        requester: &TailscaleNodeId,
        subject_id: &ObjectId,
        purpose: &LeasePurpose,
        held_fencing_token: u64,
        existing_leases: &[ObservedLeaseAuthority],
        now_secs: u64,
        requested_ttl: Option<u32>,
    ) -> (RenewOutcome, Vec<AuthorityTimelineEvent>) {
        let mut timeline = Vec::new();
        let ttl = self.clamp_ttl(requested_ttl.unwrap_or(self.config.default_ttl_secs));

        // (1) Requester must still hold the claimed token as an active lease.
        let held = existing_leases.iter().find(|obs| {
            obs.holder == *requester
                && obs.lease.subject_id == *subject_id
                && obs.lease.purpose == *purpose
                && obs.lease.fencing_token == held_fencing_token
                && obs.lease.is_active(now_secs)
        });
        let Some(held) = held else {
            let reason = format!(
                "Renew denied: no active lease matches holder={} token={held_fencing_token}",
                requester.as_str()
            );
            timeline.push(AuthorityTimelineEvent {
                observed_at_ms: now_secs * 1000,
                operation: "lease.renew_denied".into(),
                subject_id: *subject_id,
                purpose: *purpose,
                holder: Some(requester.clone()),
                coordinator: None,
                reason_code: AuthorityReasonCode::LeaseNotHeld,
                fencing_token: Some(held_fencing_token),
                expires_at: None,
                explanation: reason.clone(),
            });
            let purpose_label = purpose.to_string();
            metrics::record_lease_fenced(&purpose_label, "not_held");
            return (RenewOutcome::Denied { reason }, timeline);
        };

        // (2) Held lease must not have been superseded by a higher token.
        let max_active_token = existing_leases
            .iter()
            .filter(|obs| {
                obs.lease.subject_id == *subject_id
                    && obs.lease.purpose == *purpose
                    && obs.lease.is_active(now_secs)
            })
            .map(|obs| obs.lease.fencing_token)
            .max()
            .unwrap_or(held_fencing_token);
        if max_active_token > held_fencing_token {
            let reason = format!(
                "Renew denied: lease superseded (held_token={held_fencing_token}, max_active={max_active_token})"
            );
            timeline.push(AuthorityTimelineEvent {
                observed_at_ms: now_secs * 1000,
                operation: "lease.renew_denied".into(),
                subject_id: *subject_id,
                purpose: *purpose,
                holder: Some(requester.clone()),
                coordinator: None,
                reason_code: AuthorityReasonCode::SupersededByPreferredLease,
                fencing_token: Some(held_fencing_token),
                expires_at: Some(held.lease.expires_at),
                explanation: reason.clone(),
            });
            let purpose_label = purpose.to_string();
            metrics::record_lease_fenced(&purpose_label, "superseded");
            return (RenewOutcome::Denied { reason }, timeline);
        }

        // (3) Monotonic expiry — guard against clock regression or a stale
        //     `now_secs` that would otherwise shorten an active lease.
        let computed = now_secs.saturating_add(u64::from(ttl));
        let new_expires = computed.max(held.lease.expires_at);

        timeline.push(AuthorityTimelineEvent {
            observed_at_ms: now_secs * 1000,
            operation: "lease.renewed".into(),
            subject_id: *subject_id,
            purpose: purpose.clone(),
            holder: Some(requester.clone()),
            coordinator: None,
            reason_code: AuthorityReasonCode::ActiveAuthority,
            fencing_token: Some(held_fencing_token),
            expires_at: Some(new_expires),
            explanation: format!(
                "Lease renewed for {} (fencing_token={held_fencing_token}, new_expires={new_expires})",
                requester.as_str()
            ),
        });
        let purpose_label = purpose.to_string();
        metrics::record_lease_renewed(&purpose_label, "renewed");

        (
            RenewOutcome::Renewed {
                expires_at: new_expires,
            },
            timeline,
        )
    }

    /// Release a lease voluntarily.
    pub fn release(
        &self,
        requester: &TailscaleNodeId,
        subject_id: &ObjectId,
        purpose: &LeasePurpose,
        held_fencing_token: u64,
        existing_leases: &[ObservedLeaseAuthority],
        now_secs: u64,
    ) -> (ReleaseOutcome, Vec<AuthorityTimelineEvent>) {
        let mut timeline = Vec::new();

        let held = existing_leases.iter().find(|obs| {
            obs.holder == *requester
                && obs.lease.subject_id == *subject_id
                && obs.lease.purpose == *purpose
                && obs.lease.fencing_token == held_fencing_token
                && obs.lease.is_active(now_secs)
        });

        let holder = requester.as_str();
        if held.is_some() {
            timeline.push(AuthorityTimelineEvent {
                observed_at_ms: now_secs * 1000,
                operation: "lease.released".into(),
                subject_id: *subject_id,
                purpose: purpose.clone(),
                holder: Some(requester.clone()),
                coordinator: None,
                reason_code: AuthorityReasonCode::LeaseReleased,
                fencing_token: Some(held_fencing_token),
                expires_at: None,
                explanation: format!(
                    "Lease released by {holder} (fencing_token={held_fencing_token})"
                ),
            });
            let purpose_label = purpose.to_string();
            metrics::record_lease_revoked(&purpose_label, "voluntary_release");
            (ReleaseOutcome::Released, timeline)
        } else {
            timeline.push(AuthorityTimelineEvent {
                observed_at_ms: now_secs * 1000,
                operation: "lease.release_failed".into(),
                subject_id: *subject_id,
                purpose: purpose.clone(),
                holder: Some(requester.clone()),
                coordinator: None,
                reason_code: AuthorityReasonCode::LeaseNotHeld,
                fencing_token: Some(held_fencing_token),
                expires_at: None,
                explanation: format!("Release failed: {holder} does not hold matching lease"),
            });
            (
                ReleaseOutcome::NotHeld {
                    reason: "No matching active lease found".into(),
                },
                timeline,
            )
        }
    }

    /// Detect conflicts among observed leases for a subject.
    ///
    /// # Panics
    ///
    /// Panics if the active lease set is non-empty but has no maximum fencing
    /// token, which should be impossible for a non-empty iterator.
    #[must_use]
    pub fn detect_conflicts(
        &self,
        zone_id: &ZoneId,
        subject_id: &ObjectId,
        purpose: &LeasePurpose,
        observed: &[ObservedLeaseAuthority],
        now_secs: u64,
    ) -> Option<LeaseConflict> {
        let active = canonical_active_leases_for_subject(observed, subject_id, *purpose, now_secs);

        if active.len() <= 1 {
            return None;
        }

        let severity = if self.config.escalate_dangerous_conflicts {
            ConflictSeverity::Critical
        } else {
            ConflictSeverity::Warning
        };

        let holders: Vec<ConflictingHolder> = active
            .iter()
            .map(|obs| ConflictingHolder {
                node_id: obs.holder.clone(),
                fencing_token: obs.lease.fencing_token,
                expires_at: obs.lease.expires_at,
            })
            .collect();

        // Resolution: highest fencing token wins
        let winner = active
            .iter()
            .max_by(|left, right| compare_conflicting_leases(left, right))
            .unwrap();

        Some(LeaseConflict {
            zone_id: zone_id.clone(),
            subject_id: *subject_id,
            purpose: purpose.clone(),
            severity,
            holders,
            detected_at_ms: now_secs * 1000,
            resolution: format!(
                "Highest fencing token wins: {} (token={})",
                winner.holder.as_str(),
                winner.lease.fencing_token
            ),
        })
    }

    /// Check whether a lease should be renewed based on remaining TTL.
    #[must_use]
    pub fn should_renew(&self, lease: &HeldLease, now_secs: u64) -> bool {
        if !lease.is_active(now_secs) {
            return false;
        }
        let remaining = lease.expires_at.saturating_sub(now_secs);
        // Compare remaining time against the configured TTL to decide
        // whether renewal is needed. Use the default TTL as the reference
        // since we don't track the original grant TTL.
        let reference_ttl = u64::from(self.config.default_ttl_secs);
        if reference_ttl == 0 {
            return true;
        }
        // Use u128 intermediate to avoid overflow when remaining is near
        // u64::MAX (can happen if an adversarial peer or buggy state machine
        // reports expires_at == u64::MAX). `remaining * 10_000` overflows
        // u64 for remaining > 1_844_674_407_370_955 seconds (~58B years),
        // which is pathological but should not panic.
        let remaining_bps = (u128::from(remaining) * 10_000) / u128::from(reference_ttl);
        remaining_bps <= u128::from(self.config.renew_threshold_bps)
    }

    /// Get the current configuration.
    #[must_use]
    pub const fn config(&self) -> &LeaseCoordinatorConfig {
        &self.config
    }

    // ── Internal ────────────────────────────────────────────────────

    /// Hand out the next fencing token and advance the counter.
    ///
    /// Returns `None` when the counter has reached `u64::MAX` and cannot
    /// produce another token without wrapping. Callers must treat this as
    /// an unavailable-resource condition, not a panic. Normal operation
    /// never reaches this (u64 fencing token space is ~18e18 values); the
    /// `None` path guards against an adversarial peer pinning `next_seq`
    /// at `u64::MAX` via a poisoned `existing_leases` observation (see
    /// `rebase_next_seq`).
    fn next_fencing_token(&mut self) -> Option<u64> {
        let next = self.next_seq.checked_add(1)?;
        let token = self.next_seq;
        self.next_seq = next;
        Some(token)
    }

    fn rebase_next_seq(
        &mut self,
        existing_leases: &[ObservedLeaseAuthority],
    ) -> FencingRebaseStatus {
        // Rebase against observed history, not only active leases. Fencing
        // tokens are monotonic authority guards; reusing a token lower than a
        // previously observed expired lease can let stale holders look newer
        // to downstream systems that compare only fencing tokens.
        if let Some(max_observed) = existing_leases
            .iter()
            .map(|observed| observed.lease.fencing_token)
            .max()
        {
            let Some(next_candidate) = max_observed.checked_add(1) else {
                return FencingRebaseStatus::Exhausted;
            };
            if next_candidate > self.next_seq {
                if next_candidate.saturating_sub(self.next_seq) > MAX_FENCING_TOKEN_DRIFT {
                    return FencingRebaseStatus::DriftTooLarge;
                }
                self.next_seq = next_candidate;
            }
        }
        FencingRebaseStatus::Ready
    }

    fn clamp_ttl(&self, ttl: u32) -> u32 {
        ttl.clamp(self.config.min_ttl_secs, self.config.max_ttl_secs)
    }
}

fn planner_purpose_for_core(purpose: CoreLeasePurpose) -> LeasePurpose {
    match purpose {
        CoreLeasePurpose::ConnectorStateWrite => LeasePurpose::SingletonWriter,
        CoreLeasePurpose::OperationExecution => LeasePurpose::OperationExecution,
        CoreLeasePurpose::CoordinatorElection => LeasePurpose::CoordinatorElection,
        CoreLeasePurpose::ComputationMigration
        | CoreLeasePurpose::Migration
        | CoreLeasePurpose::ResourceAccess => LeasePurpose::Other,
    }
}

fn signed_lease_issue_hrw_rejection(
    params: &CoreLeaseParams,
    eligible_nodes: &[TailscaleNodeId],
    planner_purpose: LeasePurpose,
    now_secs: u64,
) -> Option<(SignedLeaseIssueOutcome, Vec<AuthorityTimelineEvent>)> {
    let selected_holder =
        select_coordinator(&params.zone_id, &params.subject_object_id, eligible_nodes);
    match selected_holder.as_ref() {
        Some(holder) if holder == &params.holder => None,
        Some(holder) => {
            let reason = format!(
                "Lease issue rejected: {} is not HRW-selected holder for subject {}; expected {}",
                params.holder.as_str(),
                params.subject_object_id,
                holder.as_str()
            );
            let purpose_label = planner_purpose.to_string();
            metrics::record_lease_fenced(&purpose_label, "wrong_hrw_holder");
            Some((
                SignedLeaseIssueOutcome::Rejected {
                    reason: reason.clone(),
                },
                vec![AuthorityTimelineEvent {
                    observed_at_ms: now_secs * 1000,
                    operation: "lease.issue_rejected".into(),
                    subject_id: params.subject_object_id,
                    purpose: planner_purpose,
                    holder: Some(params.holder.clone()),
                    coordinator: Some(holder.clone()),
                    reason_code: AuthorityReasonCode::LeaseAcquisitionRejected,
                    fencing_token: None,
                    expires_at: None,
                    explanation: reason,
                }],
            ))
        }
        None => {
            let reason = "Lease issue rejected: no HRW-eligible holder for subject".to_owned();
            let purpose_label = planner_purpose.to_string();
            metrics::record_lease_fenced(&purpose_label, "no_eligible_holder");
            Some((
                SignedLeaseIssueOutcome::Rejected {
                    reason: reason.clone(),
                },
                vec![AuthorityTimelineEvent {
                    observed_at_ms: now_secs * 1000,
                    operation: "lease.issue_rejected".into(),
                    subject_id: params.subject_object_id,
                    purpose: planner_purpose,
                    holder: Some(params.holder.clone()),
                    coordinator: None,
                    reason_code: AuthorityReasonCode::LeaseAcquisitionRejected,
                    fencing_token: None,
                    expires_at: None,
                    explanation: reason,
                }],
            ))
        }
    }
}

fn signed_lease_issue_quorum_rejection(
    params: &CoreLeaseParams,
    eligible_nodes: &[TailscaleNodeId],
    planner_purpose: LeasePurpose,
    now_secs: u64,
    required_signatures: usize,
) -> Option<(SignedLeaseIssueOutcome, Vec<AuthorityTimelineEvent>)> {
    if let Some(node_id) = params.quorum_signatures.duplicate_node_id() {
        let reason =
            format!("Lease issue rejected: duplicate quorum signer {node_id} is not allowed");
        let purpose_label = planner_purpose.to_string();
        metrics::record_lease_fenced(&purpose_label, "duplicate_quorum_signer");
        return Some((
            SignedLeaseIssueOutcome::Rejected {
                reason: reason.clone(),
            },
            vec![AuthorityTimelineEvent {
                observed_at_ms: now_secs * 1000,
                operation: "lease.issue_rejected".into(),
                subject_id: params.subject_object_id,
                purpose: planner_purpose,
                holder: Some(params.holder.clone()),
                coordinator: select_coordinator(
                    &params.zone_id,
                    &params.subject_object_id,
                    eligible_nodes,
                ),
                reason_code: AuthorityReasonCode::LeaseAcquisitionRejected,
                fencing_token: None,
                expires_at: None,
                explanation: reason,
            }],
        ));
    }

    let got = params.quorum_signatures.len();
    if got < required_signatures {
        let reason = format!(
            "Lease issue rejected: insufficient quorum signatures (required={required_signatures}, got={got})"
        );
        let purpose_label = planner_purpose.to_string();
        metrics::record_lease_fenced(&purpose_label, "insufficient_quorum");
        return Some((
            SignedLeaseIssueOutcome::Rejected {
                reason: reason.clone(),
            },
            vec![AuthorityTimelineEvent {
                observed_at_ms: now_secs * 1000,
                operation: "lease.issue_rejected".into(),
                subject_id: params.subject_object_id,
                purpose: planner_purpose,
                holder: Some(params.holder.clone()),
                coordinator: select_coordinator(
                    &params.zone_id,
                    &params.subject_object_id,
                    eligible_nodes,
                ),
                reason_code: AuthorityReasonCode::LeaseAcquisitionRejected,
                fencing_token: None,
                expires_at: None,
                explanation: reason,
            }],
        ));
    }

    if let Some(signature) = params.quorum_signatures.iter().find(|signature| {
        !eligible_nodes
            .iter()
            .any(|node| node.as_str() == signature.node_id.as_str())
    }) {
        let reason = format!(
            "Lease issue rejected: quorum signer {} is not in the eligible signer set",
            signature.node_id
        );
        let purpose_label = planner_purpose.to_string();
        metrics::record_lease_fenced(&purpose_label, "unknown_quorum_signer");
        return Some((
            SignedLeaseIssueOutcome::Rejected {
                reason: reason.clone(),
            },
            vec![AuthorityTimelineEvent {
                observed_at_ms: now_secs * 1000,
                operation: "lease.issue_rejected".into(),
                subject_id: params.subject_object_id,
                purpose: planner_purpose,
                holder: Some(params.holder.clone()),
                coordinator: select_coordinator(
                    &params.zone_id,
                    &params.subject_object_id,
                    eligible_nodes,
                ),
                reason_code: AuthorityReasonCode::LeaseAcquisitionRejected,
                fencing_token: None,
                expires_at: None,
                explanation: reason,
            }],
        ));
    }

    None
}

/// Convert a durable core lease into the compact planner observation format.
#[must_use]
pub fn held_lease_from_signed(lease: &CoreLease) -> HeldLease {
    HeldLease {
        subject_id: lease.subject_object_id,
        purpose: planner_purpose_for_core(lease.purpose),
        expires_at: lease.exp,
        fencing_token: lease.lease_seq,
    }
}

fn core_lease_from_params(params: CoreLeaseParams, created_at: u64, expires_at: u64) -> CoreLease {
    CoreLease {
        header: ObjectHeader {
            encryption_kind: Default::default(),
            schema: params.schema,
            zone_id: params.zone_id,
            created_at,
            provenance: params.provenance,
            refs: vec![params.subject_object_id],
            foreign_refs: Vec::new(),
            ttl_secs: Some(expires_at.saturating_sub(created_at)),
            placement: None,
        },
        holder: params.holder,
        lease_seq: params.lease_seq,
        exp: expires_at,
        subject_object_id: params.subject_object_id,
        purpose: params.purpose,
        quorum_signatures: params.quorum_signatures,
    }
}

fn compare_conflicting_leases(
    left: &ObservedLeaseAuthority,
    right: &ObservedLeaseAuthority,
) -> Ordering {
    left.lease
        .fencing_token
        .cmp(&right.lease.fencing_token)
        .then_with(|| left.lease.expires_at.cmp(&right.lease.expires_at))
        .then_with(|| right.holder.as_str().cmp(left.holder.as_str()))
}

fn same_lease_scope(left: &ObservedLeaseAuthority, right: &ObservedLeaseAuthority) -> bool {
    left.holder == right.holder
        && left.lease.subject_id == right.lease.subject_id
        && left.lease.purpose == right.lease.purpose
}

fn push_canonical_active<'a>(
    canonical: &mut Vec<&'a ObservedLeaseAuthority>,
    candidate: &'a ObservedLeaseAuthority,
) {
    if let Some(existing) = canonical
        .iter_mut()
        .find(|existing| same_lease_scope(existing, candidate))
    {
        if compare_conflicting_leases(candidate, existing).is_gt() {
            *existing = candidate;
        }
    } else {
        canonical.push(candidate);
    }
}

fn canonical_active_leases(
    observed: &[ObservedLeaseAuthority],
    now_secs: u64,
) -> Vec<&ObservedLeaseAuthority> {
    let mut canonical = Vec::new();
    for entry in observed
        .iter()
        .filter(|entry| entry.lease.is_active(now_secs))
    {
        push_canonical_active(&mut canonical, entry);
    }
    canonical
}

fn canonical_active_leases_for_subject<'a>(
    observed: &'a [ObservedLeaseAuthority],
    subject_id: &ObjectId,
    purpose: LeasePurpose,
    now_secs: u64,
) -> Vec<&'a ObservedLeaseAuthority> {
    canonical_active_leases(observed, now_secs)
        .into_iter()
        .filter(|entry| entry.lease.subject_id == *subject_id && entry.lease.purpose == purpose)
        .collect()
}

fn canonical_active_lease_count_for_holder(
    observed: &[ObservedLeaseAuthority],
    holder: &TailscaleNodeId,
    now_secs: u64,
) -> usize {
    canonical_active_leases(observed, now_secs)
        .into_iter()
        .filter(|entry| entry.holder == *holder)
        .count()
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn node(name: &str) -> TailscaleNodeId {
        TailscaleNodeId::new(name)
    }

    fn zone() -> ZoneId {
        "z:coordinator-test".parse().unwrap()
    }

    fn subject() -> ObjectId {
        ObjectId::from_bytes([0xCC; 32])
    }

    fn purpose() -> LeasePurpose {
        LeasePurpose::SingletonWriter
    }

    fn held_lease(holder: &str, token: u64, expires: u64) -> ObservedLeaseAuthority {
        ObservedLeaseAuthority::new(
            node(holder),
            HeldLease {
                subject_id: subject(),
                purpose: purpose(),
                expires_at: expires,
                fencing_token: token,
            },
        )
    }

    fn selected_holder_for(eligible: &[TailscaleNodeId]) -> TailscaleNodeId {
        fcp_prelude::select_coordinator(&zone(), &subject(), eligible)
            .expect("test eligible holder set should not be empty")
    }

    fn first_non_selected_holder(eligible: &[TailscaleNodeId]) -> TailscaleNodeId {
        let selected = selected_holder_for(eligible);
        eligible
            .iter()
            .find(|node| **node != selected)
            .expect("test holder set should include at least two nodes")
            .clone()
    }

    fn signatures(signers: &[&str]) -> fcp_core::SignatureSet {
        let mut set = fcp_core::SignatureSet::new();
        for (idx, signer) in signers.iter().enumerate() {
            let signature_byte = u8::try_from(idx).unwrap_or(u8::MAX);
            set.add(fcp_core::NodeSignature::new(
                fcp_core::NodeId::new(*signer),
                [signature_byte; 64],
                1_000 + u64::try_from(idx).unwrap_or(u64::MAX),
            ));
        }
        set
    }

    fn duplicate_signature_set(node_id: &str) -> fcp_core::SignatureSet {
        serde_json::from_value(serde_json::json!({
            "signatures": [
                {
                    "node_id": node_id,
                    "signature": "aa".repeat(64),
                    "signed_at": 1_000
                },
                {
                    "node_id": node_id,
                    "signature": "bb".repeat(64),
                    "signed_at": 1_001
                }
            ]
        }))
        .expect("duplicate signature JSON should deserialize")
    }

    fn core_lease_params(
        holder: &str,
        ttl_secs: u32,
        purpose: CoreLeasePurpose,
        quorum_signatures: fcp_core::SignatureSet,
    ) -> CoreLeaseParams {
        CoreLeaseParams {
            schema: fcp_cbor::SchemaId::new("fcp.lease", "lease", semver::Version::new(1, 0, 0)),
            zone_id: zone(),
            holder: node(holder),
            lease_seq: 0,
            ttl_secs,
            subject_object_id: subject(),
            provenance: fcp_core::Provenance::new(zone()),
            purpose,
            quorum_signatures,
        }
    }

    fn issued_connector_state_lease(ttl_secs: u32, now_secs: u64) -> (LeaseCoordinator, CoreLease) {
        let mut coord = LeaseCoordinator::with_defaults();
        let eligible_nodes = vec![node("node-a"), node("node-b"), node("node-c")];
        let holder = selected_holder_for(&eligible_nodes);
        let request = SignedLeaseIssueRequest {
            params: core_lease_params(
                holder.as_str(),
                ttl_secs,
                CoreLeasePurpose::ConnectorStateWrite,
                signatures(&["node-a", "node-b"]),
            ),
            existing_leases: Vec::new(),
            eligible_nodes,
            required_signatures: 2,
            now_secs,
        };
        let (outcome, _timeline) = coord.issue_signed_lease(request);
        let SignedLeaseIssueOutcome::Granted { lease } = outcome else {
            panic!("expected signed lease grant");
        };
        (coord, *lease)
    }

    // ── Acquire ──────────────────────────────────────────────────

    #[test]
    fn acquire_grants_when_no_existing_leases() {
        let mut coord = LeaseCoordinator::with_defaults();
        let eligible = vec![node("a"), node("b"), node("c")];

        let (outcome, timeline) = coord.acquire(
            &node("a"),
            &zone(),
            &subject(),
            &purpose(),
            &[],
            &eligible,
            1000,
            None,
        );

        assert!(matches!(outcome, AcquireOutcome::Granted { .. }));
        if let AcquireOutcome::Granted {
            fencing_token,
            expires_at,
        } = outcome
        {
            assert!(fencing_token > 0);
            assert!(expires_at > 1000);
        }
        assert_eq!(timeline.len(), 1);
        assert_eq!(timeline[0].operation, "lease.acquired");
    }

    #[test]
    fn select_coordinator_matches_normative_hrw_selection() {
        let coord = LeaseCoordinator::with_defaults();
        let eligible = vec![node("node-a"), node("node-b"), node("node-c")];

        assert_eq!(
            coord.select_coordinator(&zone(), &subject(), &eligible),
            fcp_prelude::select_coordinator(&zone(), &subject(), &eligible)
        );
    }

    #[test]
    fn issue_signed_lease_materializes_core_lease_with_quorum_signatures() {
        let mut coord = LeaseCoordinator::with_defaults();
        let eligible = vec![node("node-a"), node("node-b"), node("node-c")];
        let holder = selected_holder_for(&eligible);
        let request = SignedLeaseIssueRequest {
            params: core_lease_params(
                holder.as_str(),
                300,
                CoreLeasePurpose::ConnectorStateWrite,
                signatures(&["node-a", "node-b"]),
            ),
            existing_leases: Vec::new(),
            eligible_nodes: eligible,
            required_signatures: 2,
            now_secs: 1_000,
        };

        let (outcome, timeline) = coord.issue_signed_lease(request);
        let SignedLeaseIssueOutcome::Granted { lease } = outcome else {
            panic!("expected signed lease grant");
        };

        assert_eq!(lease.holder, holder);
        assert_eq!(lease.subject_object_id, subject());
        assert_eq!(lease.purpose, CoreLeasePurpose::ConnectorStateWrite);
        assert_eq!(lease.lease_seq, 1);
        assert_eq!(lease.exp, 1_300);
        assert_eq!(lease.header.created_at, 1_000);
        assert_eq!(lease.header.ttl_secs, Some(300));
        assert_eq!(lease.header.refs, vec![subject()]);
        assert_eq!(lease.quorum_signatures.len(), 2);
        assert_eq!(
            held_lease_from_signed(&lease),
            HeldLease {
                subject_id: subject(),
                purpose: LeasePurpose::SingletonWriter,
                expires_at: 1_300,
                fencing_token: 1,
            }
        );
        assert!(
            timeline
                .iter()
                .any(|event| event.operation == "lease.acquired")
        );
    }

    #[test]
    fn issue_signed_lease_rejects_insufficient_quorum_before_materialization() {
        let mut coord = LeaseCoordinator::with_defaults();
        let eligible = vec![node("node-a"), node("node-b"), node("node-c")];
        let holder = selected_holder_for(&eligible);
        let request = SignedLeaseIssueRequest {
            params: core_lease_params(
                holder.as_str(),
                300,
                CoreLeasePurpose::ConnectorStateWrite,
                signatures(&["node-a"]),
            ),
            existing_leases: Vec::new(),
            eligible_nodes: eligible.clone(),
            required_signatures: 2,
            now_secs: 1_000,
        };

        let (outcome, timeline) = coord.issue_signed_lease(request);

        match outcome {
            SignedLeaseIssueOutcome::Rejected { reason } => {
                assert!(
                    reason.contains("insufficient quorum signatures"),
                    "expected quorum rejection, got: {reason}"
                );
                assert!(reason.contains("required=2"));
                assert!(reason.contains("got=1"));
            }
            other => panic!("expected Rejected for insufficient quorum, got {other:?}"),
        }
        assert!(timeline.iter().any(|event| {
            event.operation == "lease.issue_rejected"
                && event.fencing_token.is_none()
                && event.reason_code == AuthorityReasonCode::LeaseAcquisitionRejected
                && event.explanation.contains("insufficient quorum signatures")
        }));

        let grant_request = SignedLeaseIssueRequest {
            params: core_lease_params(
                holder.as_str(),
                300,
                CoreLeasePurpose::ConnectorStateWrite,
                signatures(&["node-a", "node-b"]),
            ),
            existing_leases: Vec::new(),
            eligible_nodes: eligible,
            required_signatures: 2,
            now_secs: 1_000,
        };
        let (grant, _timeline) = coord.issue_signed_lease(grant_request);
        let SignedLeaseIssueOutcome::Granted { lease } = grant else {
            panic!("expected valid quorum lease grant");
        };
        assert_eq!(lease.lease_seq, 1);
    }

    #[test]
    fn issue_signed_lease_rejects_duplicate_quorum_signer_before_materialization() {
        let mut coord = LeaseCoordinator::with_defaults();
        let eligible = vec![node("node-a"), node("node-b"), node("node-c")];
        let holder = selected_holder_for(&eligible);
        let request = SignedLeaseIssueRequest {
            params: core_lease_params(
                holder.as_str(),
                300,
                CoreLeasePurpose::ConnectorStateWrite,
                duplicate_signature_set("node-a"),
            ),
            existing_leases: Vec::new(),
            eligible_nodes: eligible.clone(),
            required_signatures: 2,
            now_secs: 1_000,
        };

        let (outcome, timeline) = coord.issue_signed_lease(request);

        match outcome {
            SignedLeaseIssueOutcome::Rejected { reason } => {
                assert!(
                    reason.contains("duplicate quorum signer"),
                    "expected duplicate-signer rejection, got: {reason}"
                );
                assert!(reason.contains("node-a"));
            }
            other => panic!("expected Rejected for duplicate quorum signer, got {other:?}"),
        }
        assert!(timeline.iter().any(|event| {
            event.operation == "lease.issue_rejected"
                && event.fencing_token.is_none()
                && event.reason_code == AuthorityReasonCode::LeaseAcquisitionRejected
                && event.explanation.contains("duplicate quorum signer")
        }));

        let grant_request = SignedLeaseIssueRequest {
            params: core_lease_params(
                holder.as_str(),
                300,
                CoreLeasePurpose::ConnectorStateWrite,
                signatures(&["node-a", "node-b"]),
            ),
            existing_leases: Vec::new(),
            eligible_nodes: eligible,
            required_signatures: 2,
            now_secs: 1_000,
        };
        let (grant, _timeline) = coord.issue_signed_lease(grant_request);
        let SignedLeaseIssueOutcome::Granted { lease } = grant else {
            panic!("expected valid duplicate-free lease grant");
        };
        assert_eq!(lease.lease_seq, 1);
    }

    #[test]
    fn issue_signed_lease_rejects_unknown_quorum_signer_before_materialization() {
        let mut coord = LeaseCoordinator::with_defaults();
        let eligible = vec![node("node-a"), node("node-b"), node("node-c")];
        let holder = selected_holder_for(&eligible);
        let request = SignedLeaseIssueRequest {
            params: core_lease_params(
                holder.as_str(),
                300,
                CoreLeasePurpose::ConnectorStateWrite,
                signatures(&["node-a", "node-z"]),
            ),
            existing_leases: Vec::new(),
            eligible_nodes: eligible.clone(),
            required_signatures: 2,
            now_secs: 1_000,
        };

        let (outcome, timeline) = coord.issue_signed_lease(request);

        match outcome {
            SignedLeaseIssueOutcome::Rejected { reason } => {
                assert!(
                    reason.contains("not in the eligible signer set"),
                    "expected signer-set rejection, got: {reason}"
                );
                assert!(reason.contains("node-z"));
            }
            other => panic!("expected Rejected for unknown quorum signer, got {other:?}"),
        }
        assert!(timeline.iter().any(|event| {
            event.operation == "lease.issue_rejected"
                && event.fencing_token.is_none()
                && event.reason_code == AuthorityReasonCode::LeaseAcquisitionRejected
                && event.explanation.contains("node-z")
        }));

        let grant_request = SignedLeaseIssueRequest {
            params: core_lease_params(
                holder.as_str(),
                300,
                CoreLeasePurpose::ConnectorStateWrite,
                signatures(&["node-a", "node-b"]),
            ),
            existing_leases: Vec::new(),
            eligible_nodes: eligible,
            required_signatures: 2,
            now_secs: 1_000,
        };
        let (grant, _timeline) = coord.issue_signed_lease(grant_request);
        let SignedLeaseIssueOutcome::Granted { lease } = grant else {
            panic!("expected valid signer-set lease grant");
        };
        assert_eq!(lease.lease_seq, 1);
    }

    #[test]
    fn issue_signed_lease_rebases_fencing_token_from_expired_observation() {
        let mut coord = LeaseCoordinator::with_defaults();
        let eligible_nodes = vec![node("node-a"), node("node-b"), node("node-c")];
        let holder = selected_holder_for(&eligible_nodes);
        let request = SignedLeaseIssueRequest {
            params: core_lease_params(
                holder.as_str(),
                300,
                CoreLeasePurpose::ConnectorStateWrite,
                signatures(&["node-b", "node-c"]),
            ),
            existing_leases: vec![held_lease("node-a", 7, 100)],
            eligible_nodes,
            required_signatures: 2,
            now_secs: 1_000,
        };

        let (outcome, _timeline) = coord.issue_signed_lease(request);
        let SignedLeaseIssueOutcome::Granted { lease } = outcome else {
            panic!("expired observation should not block grant");
        };

        assert_eq!(lease.lease_seq, 8);
        assert_eq!(lease.exp, 1_300);
    }

    #[test]
    fn issue_signed_lease_denies_when_active_holder_differs() {
        let mut coord = LeaseCoordinator::with_defaults();
        let eligible_nodes = vec![node("node-a"), node("node-b"), node("node-c")];
        let holder = selected_holder_for(&eligible_nodes);
        let active_holder = first_non_selected_holder(&eligible_nodes);
        let request = SignedLeaseIssueRequest {
            params: core_lease_params(
                holder.as_str(),
                300,
                CoreLeasePurpose::ConnectorStateWrite,
                signatures(&["node-b", "node-c"]),
            ),
            existing_leases: vec![held_lease(active_holder.as_str(), 5, 2_000)],
            eligible_nodes,
            required_signatures: 2,
            now_secs: 1_000,
        };

        let (outcome, _timeline) = coord.issue_signed_lease(request);

        assert!(matches!(
            outcome,
            SignedLeaseIssueOutcome::Denied {
                current_holder,
                current_fencing_token: 5,
                ..
            } if current_holder == active_holder
        ));
    }

    #[test]
    fn issue_signed_lease_rejects_non_hrw_holder_without_existing_leases() {
        let mut coord = LeaseCoordinator::with_defaults();
        let eligible_nodes = vec![node("node-a"), node("node-b"), node("node-c")];
        let wrong_holder = first_non_selected_holder(&eligible_nodes);
        let request = SignedLeaseIssueRequest {
            params: core_lease_params(
                wrong_holder.as_str(),
                300,
                CoreLeasePurpose::ConnectorStateWrite,
                signatures(&["node-a", "node-b"]),
            ),
            existing_leases: Vec::new(),
            eligible_nodes,
            required_signatures: 2,
            now_secs: 1_000,
        };

        let (outcome, timeline) = coord.issue_signed_lease(request);

        match outcome {
            SignedLeaseIssueOutcome::Rejected { reason } => {
                assert!(
                    reason.contains("not HRW-selected"),
                    "expected wrong-holder rejection, got: {reason}"
                );
            }
            other => panic!("expected Rejected for non-HRW holder, got {other:?}"),
        }
        assert!(timeline.iter().any(|event| {
            event.operation == "lease.issue_rejected"
                && event.reason_code == AuthorityReasonCode::LeaseAcquisitionRejected
        }));
    }

    #[test]
    fn issue_signed_lease_handoff_supersedes_active_offline_holder() {
        let mut coord = LeaseCoordinator::with_defaults();
        let eligible_nodes = vec![node("node-b"), node("node-c")];
        let holder = selected_holder_for(&eligible_nodes);
        let request = SignedLeaseIssueRequest {
            params: core_lease_params(
                holder.as_str(),
                300,
                CoreLeasePurpose::ConnectorStateWrite,
                signatures(&["node-b", "node-c"]),
            ),
            existing_leases: vec![held_lease("node-a", 5, 2_000)],
            eligible_nodes,
            required_signatures: 2,
            now_secs: 1_000,
        };

        let (outcome, timeline) = coord.issue_signed_lease(request);
        let SignedLeaseIssueOutcome::Granted { lease } = outcome else {
            panic!("expected HRW-selected handoff holder to receive new lease");
        };

        assert_eq!(lease.holder, holder);
        assert_eq!(lease.lease_seq, 6);
        assert_eq!(lease.exp, 1_300);
        assert!(timeline.iter().any(|event| {
            event.operation == "lease.handed_off"
                && event.fencing_token == Some(6)
                && event.reason_code == AuthorityReasonCode::ActiveAuthority
        }));
    }

    #[test]
    fn validate_signed_lease_enforces_quorum_signature_count() {
        let mut coord = LeaseCoordinator::with_defaults();
        let eligible_nodes = vec![node("node-a"), node("node-b"), node("node-c")];
        let holder = selected_holder_for(&eligible_nodes);
        let request = SignedLeaseIssueRequest {
            params: core_lease_params(
                holder.as_str(),
                300,
                CoreLeasePurpose::ConnectorStateWrite,
                signatures(&["node-a"]),
            ),
            existing_leases: Vec::new(),
            eligible_nodes,
            required_signatures: 1,
            now_secs: 1_000,
        };
        let (outcome, _timeline) = coord.issue_signed_lease(request);
        let SignedLeaseIssueOutcome::Granted { lease } = outcome else {
            panic!("expected grant");
        };

        let err = coord
            .validate_signed_lease(
                &lease,
                &subject(),
                &zone(),
                CoreLeasePurpose::ConnectorStateWrite,
                lease.lease_seq,
                1_001,
                2,
            )
            .expect_err("one signature must not satisfy a two-signature quorum");
        assert!(matches!(
            err,
            CoreLeaseValidationError::InsufficientQuorum {
                required: 2,
                got: 1,
            }
        ));

        coord
            .validate_signed_lease(
                &lease,
                &subject(),
                &zone(),
                CoreLeasePurpose::ConnectorStateWrite,
                lease.lease_seq,
                1_001,
                1,
            )
            .expect("one signature satisfies a one-signature quorum");
    }

    #[test]
    fn validate_signed_lease_rejects_expired_lease() {
        let (coord, lease) = issued_connector_state_lease(10, 1_000);

        let err = coord
            .validate_signed_lease(
                &lease,
                &subject(),
                &zone(),
                CoreLeasePurpose::ConnectorStateWrite,
                lease.lease_seq,
                1_010,
                1,
            )
            .expect_err("lease at its expiry boundary must be rejected");

        assert_eq!(
            err,
            CoreLeaseValidationError::Expired {
                expired_at: 1_010,
                now: 1_010,
            }
        );
    }

    #[test]
    fn validate_signed_lease_rejects_mismatched_subject_zone_and_purpose() {
        let (coord, lease) = issued_connector_state_lease(300, 1_000);
        let wrong_subject = ObjectId::from_bytes([0xAB; 32]);
        let wrong_zone: ZoneId = "z:wrong-lease-zone".parse().unwrap();

        let subject_err = coord
            .validate_signed_lease(
                &lease,
                &wrong_subject,
                &zone(),
                CoreLeasePurpose::ConnectorStateWrite,
                lease.lease_seq,
                1_001,
                1,
            )
            .expect_err("wrong lease subject must be rejected");
        assert_eq!(
            subject_err,
            CoreLeaseValidationError::SubjectMismatch {
                expected: wrong_subject,
                got: subject(),
            }
        );

        let zone_err = coord
            .validate_signed_lease(
                &lease,
                &subject(),
                &wrong_zone,
                CoreLeasePurpose::ConnectorStateWrite,
                lease.lease_seq,
                1_001,
                1,
            )
            .expect_err("wrong lease zone must be rejected");
        assert_eq!(
            zone_err,
            CoreLeaseValidationError::ZoneMismatch {
                expected: wrong_zone,
                got: zone(),
            }
        );

        let purpose_err = coord
            .validate_signed_lease(
                &lease,
                &subject(),
                &zone(),
                CoreLeasePurpose::OperationExecution,
                lease.lease_seq,
                1_001,
                1,
            )
            .expect_err("wrong lease purpose must be rejected");
        assert_eq!(
            purpose_err,
            CoreLeaseValidationError::PurposeMismatch {
                expected: CoreLeasePurpose::OperationExecution,
                got: CoreLeasePurpose::ConnectorStateWrite,
            }
        );
    }

    #[test]
    fn validate_signed_lease_rejects_superseded_fencing_token() {
        let (coord, lease) = issued_connector_state_lease(300, 1_000);

        let err = coord
            .validate_signed_lease(
                &lease,
                &subject(),
                &zone(),
                CoreLeasePurpose::ConnectorStateWrite,
                lease.lease_seq + 1,
                1_001,
                1,
            )
            .expect_err("lease with a lower seq than current known seq must be fenced");

        assert_eq!(
            err,
            CoreLeaseValidationError::Superseded {
                held_seq: lease.lease_seq,
                current_seq: lease.lease_seq + 1,
            }
        );
    }

    #[test]
    fn acquire_denies_when_different_holder() {
        let mut coord = LeaseCoordinator::with_defaults();
        let eligible = vec![node("a"), node("b")];
        let existing = vec![held_lease("a", 1, 2000)];

        let (outcome, timeline) = coord.acquire(
            &node("b"),
            &zone(),
            &subject(),
            &purpose(),
            &existing,
            &eligible,
            1000,
            None,
        );

        assert!(matches!(outcome, AcquireOutcome::Denied { .. }));
        if let AcquireOutcome::Denied { current_holder, .. } = &outcome {
            assert_eq!(current_holder, &node("a"));
        }
        assert!(!timeline.is_empty());
    }

    #[test]
    fn acquire_grants_when_existing_lease_expired() {
        let mut coord = LeaseCoordinator::with_defaults();
        let eligible = vec![node("a"), node("b")];
        let existing = vec![held_lease("a", 1, 500)]; // expired at 500

        let (outcome, _timeline) = coord.acquire(
            &node("b"),
            &zone(),
            &subject(),
            &purpose(),
            &existing,
            &eligible,
            1000, // now > 500
            None,
        );

        assert!(matches!(outcome, AcquireOutcome::Granted { .. }));
    }

    #[test]
    fn acquire_detects_conflict_with_multiple_holders() {
        let mut coord = LeaseCoordinator::with_defaults();
        let eligible = vec![node("a"), node("b"), node("c")];
        let existing = vec![held_lease("a", 1, 2000), held_lease("b", 2, 2000)];

        let (outcome, timeline) = coord.acquire(
            &node("c"),
            &zone(),
            &subject(),
            &purpose(),
            &existing,
            &eligible,
            1000,
            None,
        );

        assert!(matches!(outcome, AcquireOutcome::Conflict { .. }));
        assert!(
            timeline
                .iter()
                .any(|e| e.operation == "lease.conflict_detected")
        );
        assert!(
            timeline
                .iter()
                .any(|e| e.reason_code == AuthorityReasonCode::LeaseConflictDetected)
        );
    }

    // ── Admission hardening (regression, HIGH) ───────────────────

    #[test]
    fn acquire_rejects_when_requester_exceeds_active_lease_cap() {
        let mut coord = LeaseCoordinator::new(LeaseCoordinatorConfig {
            max_leases_per_node: 1,
            ..LeaseCoordinatorConfig::default()
        });
        let eligible = vec![node("a"), node("b")];
        let existing = vec![ObservedLeaseAuthority::new(
            node("a"),
            HeldLease {
                subject_id: ObjectId::from_bytes([0xDD; 32]),
                purpose: purpose(),
                expires_at: 2_000,
                fencing_token: 1,
            },
        )];

        let (outcome, timeline) = coord.acquire(
            &node("a"),
            &zone(),
            &subject(),
            &purpose(),
            &existing,
            &eligible,
            1_000,
            None,
        );

        assert!(matches!(outcome, AcquireOutcome::Rejected { .. }));
        assert!(timeline.iter().any(|event| {
            event.reason_code == AuthorityReasonCode::LeaseAcquisitionRejected
                && event.operation == "lease.acquire_rejected"
        }));
    }

    #[test]
    fn acquire_collapses_duplicate_same_holder_observations_before_conflict_check() {
        let mut coord = LeaseCoordinator::with_defaults();
        let eligible = vec![node("a"), node("b")];
        let existing = vec![held_lease("a", 7, 2_000), held_lease("a", 7, 1_900)];

        let (outcome, _timeline) = coord.acquire(
            &node("b"),
            &zone(),
            &subject(),
            &purpose(),
            &existing,
            &eligible,
            1_000,
            None,
        );

        assert!(
            matches!(outcome, AcquireOutcome::Denied { .. }),
            "duplicate observations from one holder must not escalate into a split-brain conflict"
        );
    }

    #[test]
    fn acquire_rebases_fencing_token_above_observed_history() {
        let mut coord = LeaseCoordinator::with_defaults();
        let eligible = vec![node("a"), node("b")];
        let existing = vec![held_lease("a", 99, 500)]; // expired but still observed

        let (outcome, _) = coord.acquire(
            &node("b"),
            &zone(),
            &subject(),
            &purpose(),
            &existing,
            &eligible,
            1000,
            None,
        );

        assert!(matches!(
            outcome,
            AcquireOutcome::Granted {
                fencing_token: 100,
                ..
            }
        ));
    }

    #[test]
    fn acquire_renews_when_requester_already_holds() {
        let mut coord = LeaseCoordinator::with_defaults();
        let eligible = vec![node("a")];
        let existing = vec![held_lease("a", 5, 2000)];

        let (outcome, timeline) = coord.acquire(
            &node("a"),
            &zone(),
            &subject(),
            &purpose(),
            &existing,
            &eligible,
            1000,
            None,
        );

        assert!(matches!(
            outcome,
            AcquireOutcome::Granted {
                fencing_token: 5,
                ..
            }
        ));
        assert!(timeline.iter().any(|e| e.operation == "lease.renewed"));
    }

    // ── Fencing Token Monotonicity ───────────────────────────────

    #[test]
    fn fencing_tokens_are_strictly_monotonic() {
        let mut coord = LeaseCoordinator::with_defaults();
        let eligible = vec![node("a")];

        let mut prev_token = 0;
        for _ in 0..10 {
            let (outcome, _) = coord.acquire(
                &node("a"),
                &zone(),
                &subject(),
                &purpose(),
                &[],
                &eligible,
                1000,
                None,
            );
            if let AcquireOutcome::Granted { fencing_token, .. } = outcome {
                assert!(
                    fencing_token > prev_token,
                    "fencing tokens must be monotonic"
                );
                prev_token = fencing_token;
            }
        }
    }

    // ── Renewal ─────────────────────────────────────────────────

    #[test]
    fn renew_extends_expiry() {
        let coord = LeaseCoordinator::with_defaults();
        let existing = vec![held_lease("a", 42, 1100)];
        let (outcome, timeline) = coord.renew(
            &node("a"),
            &subject(),
            &purpose(),
            42,
            &existing,
            1000,
            Some(300),
        );

        if let RenewOutcome::Renewed { expires_at } = outcome {
            assert_eq!(expires_at, 1300);
        } else {
            panic!("expected Renewed, got {outcome:?}");
        }
        assert_eq!(timeline.len(), 1);
        assert_eq!(timeline[0].operation, "lease.renewed");
    }

    // ── Renewal validation (regression, HIGH) ────────────────────

    #[test]
    fn renew_rejects_when_no_matching_lease() {
        // Non-holder should not be able to renew a lease they don't hold.
        let coord = LeaseCoordinator::with_defaults();
        let existing = vec![held_lease("a", 42, 2000)];

        let (outcome, timeline) = coord.renew(
            &node("b"),
            &subject(),
            &purpose(),
            42,
            &existing,
            1000,
            Some(300),
        );

        assert!(matches!(outcome, RenewOutcome::Denied { .. }));
        assert!(
            timeline
                .iter()
                .any(|e| e.reason_code == AuthorityReasonCode::LeaseNotHeld)
        );
    }

    #[test]
    fn renew_rejects_when_lease_superseded() {
        // A stale holder with a lower fencing token must not be able to
        // renew past a higher-token authority transfer.
        let coord = LeaseCoordinator::with_defaults();
        let existing = vec![
            held_lease("a", 5, 2000), // old holder
            held_lease("b", 9, 2000), // new authority
        ];

        let (outcome, timeline) = coord.renew(
            &node("a"),
            &subject(),
            &purpose(),
            5,
            &existing,
            1000,
            Some(300),
        );

        assert!(
            matches!(outcome, RenewOutcome::Denied { .. }),
            "superseded renew must be denied, got {outcome:?}"
        );
        assert!(
            timeline
                .iter()
                .any(|e| e.reason_code == AuthorityReasonCode::SupersededByPreferredLease)
        );
    }

    #[test]
    fn renew_rejects_when_held_lease_expired() {
        let coord = LeaseCoordinator::with_defaults();
        // lease expired at 900, now=1000
        let existing = vec![held_lease("a", 42, 900)];

        let (outcome, _) = coord.renew(
            &node("a"),
            &subject(),
            &purpose(),
            42,
            &existing,
            1000,
            Some(300),
        );

        assert!(matches!(outcome, RenewOutcome::Denied { .. }));
    }

    #[test]
    fn renew_is_monotonic_under_clock_regression() {
        // If now_secs regresses (clock skew / stale caller), the new
        // expiry must not fall below the currently observed expiry.
        let coord = LeaseCoordinator::with_defaults();
        let existing = vec![held_lease("a", 42, 5000)];

        // Caller reports now=100 with ttl=300 → naive computed expiry=400,
        // but held expiry is 5000. We must keep 5000.
        let (outcome, _) = coord.renew(
            &node("a"),
            &subject(),
            &purpose(),
            42,
            &existing,
            100,
            Some(300),
        );

        match outcome {
            RenewOutcome::Renewed { expires_at } => {
                assert!(
                    expires_at >= 5000,
                    "renew must not shorten expiry on clock regression; got {expires_at}"
                );
            }
            RenewOutcome::Denied { reason } => panic!("expected Renewed, got Denied: {reason}"),
        }
    }

    // ── Release ─────────────────────────────────────────────────

    #[test]
    fn release_succeeds_for_matching_holder() {
        let coord = LeaseCoordinator::with_defaults();
        let existing = vec![held_lease("a", 1, 2000)];

        let (outcome, timeline) =
            coord.release(&node("a"), &subject(), &purpose(), 1, &existing, 1000);

        assert!(matches!(outcome, ReleaseOutcome::Released));
        assert!(timeline.iter().any(|e| e.operation == "lease.released"));
        assert!(
            timeline
                .iter()
                .any(|e| e.reason_code == AuthorityReasonCode::LeaseReleased)
        );
    }

    #[test]
    fn release_fails_for_non_holder() {
        let coord = LeaseCoordinator::with_defaults();
        let existing = vec![held_lease("a", 1, 2000)];

        let (outcome, timeline) =
            coord.release(&node("b"), &subject(), &purpose(), 1, &existing, 1000);

        assert!(matches!(outcome, ReleaseOutcome::NotHeld { .. }));
        assert!(
            timeline
                .iter()
                .any(|e| e.reason_code == AuthorityReasonCode::LeaseNotHeld)
        );
    }

    #[test]
    fn release_fails_for_expired_lease() {
        let coord = LeaseCoordinator::with_defaults();
        let existing = vec![held_lease("a", 1, 500)];

        let (outcome, timeline) =
            coord.release(&node("a"), &subject(), &purpose(), 1, &existing, 1000);

        assert!(matches!(outcome, ReleaseOutcome::NotHeld { .. }));
        assert!(
            timeline
                .iter()
                .any(|e| e.reason_code == AuthorityReasonCode::LeaseNotHeld)
        );
    }

    // ── Conflict Detection ──────────────────────────────────────

    #[test]
    fn detect_conflicts_returns_none_for_single_holder() {
        let coord = LeaseCoordinator::with_defaults();
        let existing = vec![held_lease("a", 1, 2000)];

        let conflict = coord.detect_conflicts(&zone(), &subject(), &purpose(), &existing, 1000);

        assert!(conflict.is_none());
    }

    #[test]
    fn detect_conflicts_finds_overlapping_leases() {
        let coord = LeaseCoordinator::with_defaults();
        let existing = vec![held_lease("a", 1, 2000), held_lease("b", 2, 2000)];

        let conflict = coord.detect_conflicts(&zone(), &subject(), &purpose(), &existing, 1000);

        assert!(conflict.is_some());
        let conflict = conflict.unwrap();
        assert_eq!(conflict.holders.len(), 2);
        assert_eq!(conflict.severity, ConflictSeverity::Critical);
        assert!(conflict.resolution.contains('b')); // higher token wins
    }

    #[test]
    fn detect_conflicts_ignores_duplicate_same_holder_observations() {
        let coord = LeaseCoordinator::with_defaults();
        let existing = vec![held_lease("a", 7, 2_000), held_lease("a", 7, 1_900)];

        let conflict = coord.detect_conflicts(&zone(), &subject(), &purpose(), &existing, 1_000);

        assert!(conflict.is_none());
    }

    #[test]
    fn detect_conflicts_breaks_ties_deterministically() {
        let coord = LeaseCoordinator::with_defaults();
        let existing = vec![held_lease("b", 7, 2000), held_lease("a", 7, 2000)];

        let conflict = coord
            .detect_conflicts(&zone(), &subject(), &purpose(), &existing, 1000)
            .expect("conflict should be detected");

        assert!(conflict.resolution.contains('a'));
    }

    #[test]
    fn detect_conflicts_ignores_expired_leases() {
        let coord = LeaseCoordinator::with_defaults();
        let existing = vec![
            held_lease("a", 1, 500),  // expired
            held_lease("b", 2, 2000), // active
        ];

        let conflict = coord.detect_conflicts(&zone(), &subject(), &purpose(), &existing, 1000);

        assert!(conflict.is_none());
    }

    // ── Should Renew ────────────────────────────────────────────

    #[test]
    fn should_renew_true_when_near_expiry() {
        let coord = LeaseCoordinator::with_defaults(); // 20% threshold
        let lease = HeldLease {
            subject_id: subject(),
            purpose: purpose(),
            expires_at: 1050, // 50 seconds remaining at now=1000
            fencing_token: 1,
        };
        // 50/1050 remaining ≈ 4.7% < 20% threshold
        assert!(coord.should_renew(&lease, 1000));
    }

    #[test]
    fn should_renew_false_when_plenty_remaining() {
        let coord = LeaseCoordinator::with_defaults();
        let lease = HeldLease {
            subject_id: subject(),
            purpose: purpose(),
            expires_at: 5000, // plenty remaining
            fencing_token: 1,
        };
        assert!(!coord.should_renew(&lease, 1000));
    }

    #[test]
    fn should_renew_false_when_expired() {
        let coord = LeaseCoordinator::with_defaults();
        let lease = HeldLease {
            subject_id: subject(),
            purpose: purpose(),
            expires_at: 500, // already expired
            fencing_token: 1,
        };
        assert!(!coord.should_renew(&lease, 1000));
    }

    // ── Config ──────────────────────────────────────────────────

    #[test]
    fn config_default_values() {
        let config = LeaseCoordinatorConfig::default();
        assert_eq!(config.default_ttl_secs, 300);
        assert_eq!(config.min_ttl_secs, 10);
        assert_eq!(config.max_ttl_secs, 3600);
        assert_eq!(config.renew_threshold_bps, 2000);
        assert!(config.escalate_dangerous_conflicts);
    }

    #[test]
    fn config_serialization_roundtrip() {
        let config = LeaseCoordinatorConfig::default();
        let json = serde_json::to_value(&config).unwrap();
        let rt: LeaseCoordinatorConfig = serde_json::from_value(json).unwrap();
        assert_eq!(config, rt);
    }

    #[test]
    fn ttl_clamped_to_bounds() {
        let coord = LeaseCoordinator::with_defaults();
        assert_eq!(coord.clamp_ttl(5), 10); // below min
        assert_eq!(coord.clamp_ttl(300), 300); // within range
        assert_eq!(coord.clamp_ttl(9999), 3600); // above max
    }

    // ── Conflict Serialization ──────────────────────────────────

    #[test]
    fn lease_conflict_serialization_roundtrip() {
        let conflict = LeaseConflict {
            zone_id: zone(),
            subject_id: subject(),
            purpose: purpose(),
            severity: ConflictSeverity::Critical,
            holders: vec![
                ConflictingHolder {
                    node_id: node("a"),
                    fencing_token: 1,
                    expires_at: 2000,
                },
                ConflictingHolder {
                    node_id: node("b"),
                    fencing_token: 2,
                    expires_at: 2000,
                },
            ],
            detected_at_ms: 1_000_000,
            resolution: "highest fencing token wins".into(),
        };

        let json = serde_json::to_value(&conflict).unwrap();
        let rt: LeaseConflict = serde_json::from_value(json).unwrap();
        assert_eq!(rt.holders.len(), 2);
        assert_eq!(rt.severity, ConflictSeverity::Critical);
    }

    #[test]
    fn rebase_next_seq_does_not_panic_on_u64_max_fencing_token() {
        // Defensive guard: a malicious or buggy peer reporting fencing_token
        // == u64::MAX must not cause the coordinator to panic via the rebase
        // path. The acquire flow calls rebase_next_seq(existing_leases)
        // before handing out a new token; an external peer influencing that
        // input should never be able to crash us.
        let mut coordinator = LeaseCoordinator::with_defaults();
        let poisoned = vec![ObservedLeaseAuthority::new(
            node("malicious-peer"),
            HeldLease {
                subject_id: subject(),
                purpose: purpose(),
                expires_at: u64::MAX,
                fencing_token: u64::MAX,
            },
        )];

        // Would previously panic via checked_add(1).expect("... exhausted").
        let (outcome, _timeline) = coordinator.acquire(
            &node("requester"),
            &zone(),
            &subject(),
            &purpose(),
            &poisoned,
            &[node("requester"), node("malicious-peer")],
            1_000,
            Some(60),
        );

        // Since the poisoned lease is active (expires_at = u64::MAX > 1_000),
        // the requester (who isn't the holder) is denied — but crucially we
        // did not panic during the rebase path, and we didn't update next_seq
        // because u64::MAX is beyond the drift limit.
        match outcome {
            AcquireOutcome::Denied { current_holder, .. } => {
                assert_eq!(current_holder, node("malicious-peer"));
            }
            other => panic!("expected Denied, got {other:?}"),
        }
        assert_eq!(coordinator.next_seq, 1);
    }

    #[test]
    fn acquire_does_not_panic_on_u64_max_fencing_token_with_expired_lease() {
        // Defensive guard against a subtler variant of the u64::MAX-poisoning
        // attack: an adversarial peer reports a lease with
        // fencing_token = u64::MAX but expires_at in the past (so the lease
        // is INACTIVE). rebase_next_seq clamps next_seq at u64::MAX via
        // saturating_add(1), the active-filter drops the poisoned lease, and
        // the grant branch reaches next_fencing_token(). Previously this path
        // panicked via checked_add(1).expect("... exhausted"). The fix makes
        // next_fencing_token() return Option<u64> and refuses to grant when
        // the space is exhausted, mapping to AcquireOutcome::Rejected with a
        // clear reason string.
        let mut coordinator = LeaseCoordinator::with_defaults();
        let poisoned_expired = vec![ObservedLeaseAuthority::new(
            node("adversary"),
            HeldLease {
                subject_id: subject(),
                purpose: purpose(),
                expires_at: 500, // already expired at now_secs=1_000
                fencing_token: u64::MAX,
            },
        )];

        let (outcome, _timeline) = coordinator.acquire(
            &node("requester"),
            &zone(),
            &subject(),
            &purpose(),
            &poisoned_expired,
            &[node("requester"), node("adversary")],
            1_000,
            Some(60),
        );

        match outcome {
            AcquireOutcome::Rejected { reason } => {
                assert!(
                    reason.contains("exhausted"),
                    "expected exhausted reason, got {reason}"
                );
            }
            other => panic!("expected Rejected(exhausted), got {other:?}"),
        }
    }

    #[test]
    fn should_renew_does_not_panic_on_u64_max_remaining() {
        // Defensive guard: remaining * 10_000 as a u64 would overflow when
        // expires_at is near u64::MAX. Using u128 intermediate, the function
        // should return Some reasonable result instead of panicking.
        let coordinator = LeaseCoordinator::with_defaults();
        let lease = HeldLease {
            subject_id: subject(),
            purpose: purpose(),
            expires_at: u64::MAX,
            fencing_token: 1,
        };

        // This would previously panic in debug on arithmetic overflow.
        // With a very-large remaining and a small reference TTL, the
        // lease is nowhere near its renewal threshold, so should_renew
        // is false.
        let answer = coordinator.should_renew(&lease, 0);
        assert!(
            !answer,
            "lease with u64::MAX remaining should not need renewal"
        );
    }
}
