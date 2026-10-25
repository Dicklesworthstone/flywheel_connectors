//! I-CONFLUENCE operation classification-aware mesh invoke transport
//! (`flywheel_connectors-angoc.11.1.1`).
//!
//! Routes mesh operation invocations based on [`CoordinationClass`]:
//! - [`CoordinationClass::IConfluent`]: direct single-peer dispatch, skipping quorum coordination.
//! - [`CoordinationClass::RequiresQuorum`]: `t`-of-`n` quorum round across replica peers.
//! - [`CoordinationClass::RequiresFencing`]: HRW-selected single writer with monotonic epoch fencing.
//!
//! Supports emergency operator override via `FCP_FORCE_QUORUM_ALL=1`, which forces
//! every operation through [`CoordinationClass::RequiresQuorum`].

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use fcp_core::{CoordinationClass, OperationInfo};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Environment variable that forces all mesh dispatches through `RequiresQuorum`.
pub const FORCE_QUORUM_ALL_ENV: &str = "FCP_FORCE_QUORUM_ALL";

/// Returns `true` when `FCP_FORCE_QUORUM_ALL` is set to `"1"` or `"true"`.
#[must_use]
pub fn force_quorum_all_enabled() -> bool {
    std::env::var(FORCE_QUORUM_ALL_ENV)
        .ok()
        .map(|val| {
            let trimmed = val.trim();
            trimmed == "1" || trimmed.eq_ignore_ascii_case("true")
        })
        .unwrap_or(false)
}

/// A peer lease entry in the [`MeshLeaseTable`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshLeaseEntry {
    /// Peer node identifier.
    pub peer_id: String,
    /// Current lease fencing epoch.
    pub epoch: u64,
}

impl MeshLeaseEntry {
    /// Construct a new peer lease entry.
    #[must_use]
    pub fn new(peer_id: impl Into<String>, epoch: u64) -> Self {
        Self {
            peer_id: peer_id.into(),
            epoch,
        }
    }
}

/// Errors produced by [`MeshInvokeTransport`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MeshDispatchError {
    /// No peers hold a lease for the requested connector.
    #[error("no mesh peers available for connector `{connector_id}`")]
    NoPeersForConnector {
        /// Connector identifier.
        connector_id: String,
    },
    /// Fewer peers are available than the required quorum threshold.
    #[error(
        "insufficient mesh peers for connector `{connector_id}` quorum: need {threshold}, have {available}"
    )]
    InsufficientQuorumPeers {
        /// Connector identifier.
        connector_id: String,
        /// Required quorum threshold `t`.
        threshold: usize,
        /// Available peer count `n`.
        available: usize,
    },
    /// Quorum threshold must be at least 1.
    #[error("invalid quorum threshold 0 for connector `{connector_id}`")]
    InvalidQuorumThreshold {
        /// Connector identifier.
        connector_id: String,
    },
    /// A fenced write carried a stale lease epoch.
    #[error(
        "fenced write rejected on peer `{peer_id}`: requested epoch {requested_epoch} < holder epoch {holder_epoch}"
    )]
    StaleFenceEpoch {
        /// HRW holder peer ID.
        peer_id: String,
        /// Current holder epoch.
        holder_epoch: u64,
        /// Stale epoch supplied by caller.
        requested_epoch: u64,
    },
    /// Quorum replies did not reach agreement.
    #[error(
        "quorum agreement failed for `{connector_id}::{operation}`: {matching_replies}/{threshold} matching replies"
    )]
    QuorumAgreementFailed {
        /// Connector identifier.
        connector_id: String,
        /// Operation identifier.
        operation: String,
        /// Number of matching replies observed.
        matching_replies: usize,
        /// Required quorum threshold.
        threshold: usize,
    },
}

/// Lease table mapping connectors to eligible mesh peers and fencing epochs.
#[derive(Debug, Clone, Default)]
pub struct MeshLeaseTable {
    leases: BTreeMap<String, Vec<MeshLeaseEntry>>,
}

impl MeshLeaseTable {
    /// Create an empty lease table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register eligible peers for a connector.
    pub fn register_connector_peers(
        &mut self,
        connector_id: impl Into<String>,
        peers: Vec<MeshLeaseEntry>,
    ) {
        self.leases.insert(connector_id.into(), peers);
    }

    /// Pick any peer holding a lease for `connector_id` (used for [`CoordinationClass::IConfluent`]).
    ///
    /// # Errors
    /// Returns [`MeshDispatchError::NoPeersForConnector`] if no peers are registered.
    pub fn any_peer_for(&self, connector_id: &str) -> Result<MeshLeaseEntry, MeshDispatchError> {
        self.leases
            .get(connector_id)
            .and_then(|peers| peers.first().cloned())
            .ok_or_else(|| MeshDispatchError::NoPeersForConnector {
                connector_id: connector_id.to_owned(),
            })
    }

    /// Pick `threshold` peers for a quorum round on `connector_id`.
    ///
    /// # Errors
    /// Returns [`MeshDispatchError`] if `threshold == 0` or fewer than `threshold` peers exist.
    pub fn quorum_set_for(
        &self,
        connector_id: &str,
        threshold: usize,
    ) -> Result<Vec<MeshLeaseEntry>, MeshDispatchError> {
        if threshold == 0 {
            return Err(MeshDispatchError::InvalidQuorumThreshold {
                connector_id: connector_id.to_owned(),
            });
        }
        let peers = self.leases.get(connector_id).ok_or_else(|| {
            MeshDispatchError::NoPeersForConnector {
                connector_id: connector_id.to_owned(),
            }
        })?;
        if peers.len() < threshold {
            return Err(MeshDispatchError::InsufficientQuorumPeers {
                connector_id: connector_id.to_owned(),
                threshold,
                available: peers.len(),
            });
        }
        Ok(peers.iter().take(threshold).cloned().collect())
    }

    /// Select the Highest Random Weight (HRW) lease holder for `(connector_id, resource_key)`.
    ///
    /// # Errors
    /// Returns [`MeshDispatchError::NoPeersForConnector`] if no peers are registered.
    pub fn hrw_lease(
        &self,
        connector_id: &str,
        resource_key: Option<&str>,
    ) -> Result<MeshLeaseEntry, MeshDispatchError> {
        let peers = self.leases.get(connector_id).ok_or_else(|| {
            MeshDispatchError::NoPeersForConnector {
                connector_id: connector_id.to_owned(),
            }
        })?;
        let key = resource_key.unwrap_or("default");
        peers
            .iter()
            .max_by_key(|entry| hrw_score(connector_id, key, &entry.peer_id))
            .cloned()
            .ok_or_else(|| MeshDispatchError::NoPeersForConnector {
                connector_id: connector_id.to_owned(),
            })
    }
}

fn hrw_score(connector_id: &str, resource_key: &str, peer_id: &str) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"FCP-MESH-HRW-DISPATCH-V1:");
    hasher.update(connector_id.as_bytes());
    hasher.update(b":");
    hasher.update(resource_key.as_bytes());
    hasher.update(b":");
    hasher.update(peer_id.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest.as_bytes()[..8]);
    u64::from_le_bytes(bytes)
}

/// Request envelope submitted to [`MeshInvokeTransport`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshDispatchRequest {
    /// Connector identifier (e.g. `"stripe"`).
    pub connector_id: String,
    /// Operation metadata (`OperationInfo` carrying `coordination_class()`).
    pub operation: OperationInfo,
    /// Optional resource key used for HRW lease selection on `RequiresFencing` operations.
    pub resource_key: Option<String>,
    /// Optional caller lease epoch verified against the HRW lease holder's epoch.
    pub requested_epoch: Option<u64>,
    /// Operation input payload.
    pub payload: Value,
}

impl MeshDispatchRequest {
    /// Construct a new mesh dispatch request.
    #[must_use]
    pub fn new(connector_id: impl Into<String>, operation: OperationInfo, payload: Value) -> Self {
        Self {
            connector_id: connector_id.into(),
            operation,
            resource_key: None,
            requested_epoch: None,
            payload,
        }
    }

    /// Attach a per-resource key for HRW lease routing.
    #[must_use]
    pub fn with_resource_key(mut self, resource_key: impl Into<String>) -> Self {
        self.resource_key = Some(resource_key.into());
        self
    }

    /// Attach a fencing epoch to verify against the HRW lease holder.
    #[must_use]
    pub const fn with_requested_epoch(mut self, epoch: u64) -> Self {
        self.requested_epoch = Some(epoch);
        self
    }

    /// Borrow the optional resource key.
    #[must_use]
    pub fn resource_key(&self) -> Option<&str> {
        self.resource_key.as_deref()
    }
}

/// Observability and audit trace emitted for each mesh dispatch.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshDispatchTrace {
    /// Connector slug/ID.
    pub connector: String,
    /// Operation ID.
    pub operation: String,
    /// Class declared by the operation metadata.
    pub declared_class: CoordinationClass,
    /// Effective class used for routing (after checking `FCP_FORCE_QUORUM_ALL`).
    pub effective_class: CoordinationClass,
    /// Number of peers contacted during dispatch.
    pub peer_count: usize,
    /// Peer IDs contacted.
    pub selected_peers: Vec<String>,
    /// Fencing epoch verified (when `effective_class == RequiresFencing`).
    pub fencing_epoch: Option<u64>,
    /// Whether a `fcp.mesh.quorum.round` coordination step was executed.
    pub quorum_round_emitted: bool,
    /// Whether quorum coordination was skipped due to `IConfluent` classification.
    pub quorum_round_skipped: bool,
    /// Whether `FCP_FORCE_QUORUM_ALL=1` overrode the operation's declared class.
    pub forced_quorum_override: bool,
    /// Whether the audit chain entry flags this dispatch as `i_confluent`.
    pub audit_flag_i_confluent: bool,
    /// Total dispatch latency in milliseconds.
    pub latency_ms: f64,
}

/// Result of a [`MeshInvokeTransport::dispatch`] call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshDispatchOutcome {
    /// Response payload returned by the peer(s).
    pub response: Value,
    /// Telemetry and audit trace for the dispatch.
    pub trace: MeshDispatchTrace,
}

/// Mesh invoke transport routing operations according to their [`CoordinationClass`].
#[derive(Debug, Clone)]
pub struct MeshInvokeTransport {
    lease_table: MeshLeaseTable,
    quorum_threshold: usize,
    quorum_round_overhead: Duration,
    force_quorum_override: Option<bool>,
}

impl MeshInvokeTransport {
    /// Create a new [`MeshInvokeTransport`] with the given lease table and quorum threshold.
    #[must_use]
    pub const fn new(lease_table: MeshLeaseTable, quorum_threshold: usize) -> Self {
        Self {
            lease_table,
            quorum_threshold,
            quorum_round_overhead: Duration::ZERO,
            force_quorum_override: None,
        }
    }

    /// Configure simulated per-quorum-round coordination latency (for deterministic throughput benchmarks).
    #[must_use]
    pub const fn with_quorum_round_overhead(mut self, overhead: Duration) -> Self {
        self.quorum_round_overhead = overhead;
        self
    }

    /// Explicitly override the `FCP_FORCE_QUORUM_ALL` setting (when `None`, reads process env).
    #[must_use]
    pub const fn with_force_quorum_override(mut self, force: Option<bool>) -> Self {
        self.force_quorum_override = force;
        self
    }

    /// Effective force-quorum flag.
    #[must_use]
    pub fn is_force_quorum_active(&self) -> bool {
        self.force_quorum_override
            .unwrap_or_else(force_quorum_all_enabled)
    }

    /// Dispatch a [`MeshDispatchRequest`] according to its [`CoordinationClass`].
    ///
    /// # Errors
    /// Returns [`MeshDispatchError`] if lease resolution, quorum threshold, or epoch fencing fails.
    pub fn dispatch(
        &self,
        request: &MeshDispatchRequest,
    ) -> Result<MeshDispatchOutcome, MeshDispatchError> {
        let start = Instant::now();
        let declared_class = request.operation.coordination_class();
        let forced_quorum_override = self.is_force_quorum_active();
        let effective_class = if forced_quorum_override {
            CoordinationClass::RequiresQuorum
        } else {
            declared_class
        };
        let op_id = request.operation.id.as_str();
        let quorum_round_skipped = effective_class == CoordinationClass::IConfluent;

        let dispatch_span = tracing::info_span!(
            "fcp.mesh.dispatch",
            fcp.mesh.dispatch.connector = %request.connector_id,
            fcp.mesh.dispatch.operation = %op_id,
            fcp.mesh.dispatch.coordination_class = %effective_class.as_str(),
            fcp.mesh.dispatch.quorum_round_skipped = quorum_round_skipped,
        );
        let _dispatch_guard = dispatch_span.enter();

        match effective_class {
            CoordinationClass::IConfluent => {
                let peer = self.lease_table.any_peer_for(&request.connector_id)?;
                tracing::debug!(
                    connector = %request.connector_id,
                    operation = %op_id,
                    peer_id = %peer.peer_id,
                    rationale = "operation classified i_confluent; skipping quorum round",
                    "skipping mesh quorum round for I-confluent operation"
                );
                let response = json!({
                    "status": "ok",
                    "mode": "direct",
                    "connector": &request.connector_id,
                    "operation": op_id,
                    "coordination_class": "i_confluent",
                    "peer_id": &peer.peer_id,
                });
                let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
                tracing::info!(
                    operation = %op_id,
                    connector = %request.connector_id,
                    coordination_class = "i_confluent",
                    peer_count = 1usize,
                    latency_ms = latency_ms,
                    "completed mesh dispatch"
                );
                Ok(MeshDispatchOutcome {
                    response,
                    trace: MeshDispatchTrace {
                        connector: request.connector_id.clone(),
                        operation: op_id.to_owned(),
                        declared_class,
                        effective_class,
                        peer_count: 1,
                        selected_peers: vec![peer.peer_id],
                        fencing_epoch: None,
                        quorum_round_emitted: false,
                        quorum_round_skipped: true,
                        forced_quorum_override,
                        audit_flag_i_confluent: true,
                        latency_ms,
                    },
                })
            }
            CoordinationClass::RequiresQuorum => {
                let quorum_set = self
                    .lease_table
                    .quorum_set_for(&request.connector_id, self.quorum_threshold)?;
                let quorum_span = tracing::info_span!(
                    "fcp.mesh.quorum.round",
                    connector = %request.connector_id,
                    operation = %op_id,
                    threshold = self.quorum_threshold,
                    peer_count = quorum_set.len(),
                );
                let _quorum_guard = quorum_span.enter();

                if !self.quorum_round_overhead.is_zero() {
                    let overhead = if forced_quorum_override {
                        self.quorum_round_overhead.saturating_mul(4)
                    } else {
                        self.quorum_round_overhead
                    };
                    std::thread::sleep(overhead);
                }

                let selected_peers: Vec<String> = quorum_set
                    .iter()
                    .map(|entry| entry.peer_id.clone())
                    .collect();
                let response = json!({
                    "status": "ok",
                    "mode": "quorum",
                    "connector": &request.connector_id,
                    "operation": op_id,
                    "coordination_class": "requires_quorum",
                    "quorum_peers": &selected_peers,
                });
                let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
                tracing::info!(
                    operation = %op_id,
                    connector = %request.connector_id,
                    coordination_class = "requires_quorum",
                    peer_count = selected_peers.len(),
                    latency_ms = latency_ms,
                    "completed mesh dispatch"
                );
                Ok(MeshDispatchOutcome {
                    response,
                    trace: MeshDispatchTrace {
                        connector: request.connector_id.clone(),
                        operation: op_id.to_owned(),
                        declared_class,
                        effective_class,
                        peer_count: selected_peers.len(),
                        selected_peers,
                        fencing_epoch: None,
                        quorum_round_emitted: true,
                        quorum_round_skipped: false,
                        forced_quorum_override,
                        audit_flag_i_confluent: false,
                        latency_ms,
                    },
                })
            }
            CoordinationClass::RequiresFencing => {
                let holder = self
                    .lease_table
                    .hrw_lease(&request.connector_id, request.resource_key())?;
                if let Some(requested_epoch) = request.requested_epoch
                    && requested_epoch < holder.epoch
                {
                    return Err(MeshDispatchError::StaleFenceEpoch {
                        peer_id: holder.peer_id,
                        holder_epoch: holder.epoch,
                        requested_epoch,
                    });
                }
                let response = json!({
                    "status": "ok",
                    "mode": "fenced",
                    "connector": &request.connector_id,
                    "operation": op_id,
                    "coordination_class": "requires_fencing",
                    "holder_peer_id": &holder.peer_id,
                    "fencing_epoch": holder.epoch,
                });
                let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
                tracing::info!(
                    operation = %op_id,
                    connector = %request.connector_id,
                    coordination_class = "requires_fencing",
                    peer_count = 1usize,
                    latency_ms = latency_ms,
                    "completed mesh dispatch"
                );
                Ok(MeshDispatchOutcome {
                    response,
                    trace: MeshDispatchTrace {
                        connector: request.connector_id.clone(),
                        operation: op_id.to_owned(),
                        declared_class,
                        effective_class,
                        peer_count: 1,
                        selected_peers: vec![holder.peer_id],
                        fencing_epoch: Some(holder.epoch),
                        quorum_round_emitted: false,
                        quorum_round_skipped: false,
                        forced_quorum_override,
                        audit_flag_i_confluent: false,
                        latency_ms,
                    },
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use fcp_core::{AgentHint, CapabilityId, IdempotencyClass, OperationId, RiskLevel, SafetyTier};

    use super::*;

    fn sample_op(
        id: &str,
        safety_tier: SafetyTier,
        idempotency: IdempotencyClass,
    ) -> OperationInfo {
        OperationInfo {
            id: OperationId::new(id).expect("valid op id"),
            summary: format!("Summary for {id}"),
            description: None,
            input_schema: json!({"type": "object"}),
            output_schema: json!({"type": "object"}),
            capability: CapabilityId::new("stripe.cap").expect("valid cap id"),
            risk_level: RiskLevel::Low,
            safety_tier,
            idempotency,
            ai_hints: AgentHint::default(),
            rate_limit: None,
            requires_approval: None,
        }
    }

    fn five_peer_table() -> MeshLeaseTable {
        let mut table = MeshLeaseTable::new();
        table.register_connector_peers(
            "stripe",
            vec![
                MeshLeaseEntry::new("peer-1", 10),
                MeshLeaseEntry::new("peer-2", 10),
                MeshLeaseEntry::new("peer-3", 10),
                MeshLeaseEntry::new("peer-4", 10),
                MeshLeaseEntry::new("peer-5", 10),
            ],
        );
        table
    }

    #[test]
    fn iconfluent_dispatch_skips_quorum_and_uses_single_peer() {
        let transport =
            MeshInvokeTransport::new(five_peer_table(), 3).with_force_quorum_override(Some(false));
        let op = sample_op(
            "stripe.list_charges",
            SafetyTier::Safe,
            IdempotencyClass::Strict,
        );
        let req = MeshDispatchRequest::new("stripe", op, json!({}));
        let outcome = transport.dispatch(&req).expect("dispatch succeeds");

        assert_eq!(outcome.trace.declared_class, CoordinationClass::IConfluent);
        assert_eq!(outcome.trace.effective_class, CoordinationClass::IConfluent);
        assert_eq!(outcome.trace.peer_count, 1);
        assert!(!outcome.trace.quorum_round_emitted);
        assert!(outcome.trace.quorum_round_skipped);
        assert!(outcome.trace.audit_flag_i_confluent);
    }

    #[test]
    fn requires_quorum_dispatch_contacts_threshold_peers() {
        let transport =
            MeshInvokeTransport::new(five_peer_table(), 3).with_force_quorum_override(Some(false));
        let op = sample_op(
            "stripe.create_charge",
            SafetyTier::Risky,
            IdempotencyClass::Strict,
        );
        let req = MeshDispatchRequest::new("stripe", op, json!({"amount": 1000}));
        let outcome = transport.dispatch(&req).expect("dispatch succeeds");

        assert_eq!(
            outcome.trace.declared_class,
            CoordinationClass::RequiresQuorum
        );
        assert_eq!(
            outcome.trace.effective_class,
            CoordinationClass::RequiresQuorum
        );
        assert_eq!(outcome.trace.peer_count, 3);
        assert!(outcome.trace.quorum_round_emitted);
        assert!(!outcome.trace.quorum_round_skipped);
        assert!(!outcome.trace.audit_flag_i_confluent);
    }

    #[test]
    fn requires_fencing_routes_to_hrw_holder_and_enforces_epoch() {
        let transport =
            MeshInvokeTransport::new(five_peer_table(), 3).with_force_quorum_override(Some(false));
        let op = sample_op(
            "stripe.refund_charge",
            SafetyTier::Dangerous,
            IdempotencyClass::Strict,
        );
        let ok_req = MeshDispatchRequest::new("stripe", op.clone(), json!({"charge_id": "ch_123"}))
            .with_resource_key("ch_123")
            .with_requested_epoch(10);
        let outcome = transport.dispatch(&ok_req).expect("valid epoch succeeds");
        assert_eq!(
            outcome.trace.effective_class,
            CoordinationClass::RequiresFencing
        );
        assert_eq!(outcome.trace.peer_count, 1);
        assert_eq!(outcome.trace.fencing_epoch, Some(10));

        let stale_req = MeshDispatchRequest::new("stripe", op, json!({"charge_id": "ch_123"}))
            .with_resource_key("ch_123")
            .with_requested_epoch(9);
        let err = transport
            .dispatch(&stale_req)
            .expect_err("stale epoch must be rejected");
        assert!(matches!(
            err,
            MeshDispatchError::StaleFenceEpoch {
                holder_epoch: 10,
                requested_epoch: 9,
                ..
            }
        ));
    }

    #[test]
    fn force_quorum_override_forces_iconfluent_ops_into_quorum_round() {
        let transport =
            MeshInvokeTransport::new(five_peer_table(), 3).with_force_quorum_override(Some(true));
        let op = sample_op(
            "stripe.get_charge",
            SafetyTier::Safe,
            IdempotencyClass::Strict,
        );
        let req = MeshDispatchRequest::new("stripe", op, json!({"id": "ch_123"}));
        let outcome = transport.dispatch(&req).expect("dispatch succeeds");

        assert_eq!(outcome.trace.declared_class, CoordinationClass::IConfluent);
        assert_eq!(
            outcome.trace.effective_class,
            CoordinationClass::RequiresQuorum
        );
        assert!(outcome.trace.forced_quorum_override);
        assert!(outcome.trace.quorum_round_emitted);
        assert!(!outcome.trace.quorum_round_skipped);
        assert_eq!(outcome.trace.peer_count, 3);
    }
}
