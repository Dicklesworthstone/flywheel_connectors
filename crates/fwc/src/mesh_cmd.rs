// Mesh targeting and availability command family.
//
// Provides mesh status, node listing, topology visualization, and
// availability checking for the FCP mesh network. All formatting
// functions produce TOON-style human-readable output as `Vec<String>`.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

// ── Node state ──────────────────────────────────────────────────────

/// Operational state of a mesh node.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MeshNodeState {
    /// Node is fully operational and accepting work.
    Active,
    /// Node is draining — finishing existing work but not accepting new tasks.
    Draining,
    /// Node is offline and unreachable.
    Offline,
    /// Node is in the process of joining the mesh.
    Joining,
    /// Node state could not be determined.
    Unknown,
}

impl MeshNodeState {
    /// Machine-readable tag for this state.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Draining => "draining",
            Self::Offline => "offline",
            Self::Joining => "joining",
            Self::Unknown => "unknown",
        }
    }

    /// Whether the node is considered available for new work.
    #[must_use]
    pub const fn is_available(self) -> bool {
        matches!(self, Self::Active)
    }

    /// Whether the node is reachable (Active or Draining).
    #[must_use]
    pub const fn is_reachable(self) -> bool {
        matches!(self, Self::Active | Self::Draining)
    }

    /// Whether the node is in a terminal/inactive state.
    #[must_use]
    pub const fn is_inactive(self) -> bool {
        matches!(self, Self::Offline)
    }

    /// Whether the node is in a transitional state.
    #[must_use]
    pub const fn is_transitional(self) -> bool {
        matches!(self, Self::Draining | Self::Joining)
    }

    /// All known variants for iteration.
    pub const ALL: &'static [Self] = &[
        Self::Active,
        Self::Draining,
        Self::Offline,
        Self::Joining,
        Self::Unknown,
    ];
}

impl fmt::Display for MeshNodeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.tag())
    }
}

impl std::str::FromStr for MeshNodeState {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "active" => Ok(Self::Active),
            "draining" => Ok(Self::Draining),
            "offline" => Ok(Self::Offline),
            "joining" => Ok(Self::Joining),
            "unknown" => Ok(Self::Unknown),
            other => Err(format!("unknown mesh node state: {other}")),
        }
    }
}

// ── Node info ───────────────────────────────────────────────────────

/// Information about a single mesh node.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MeshNodeInfo {
    /// Unique identifier for this node.
    pub node_id: String,
    /// Zone this node belongs to.
    pub zone: String,
    /// Current operational state.
    pub state: MeshNodeState,
    /// Network address of the node.
    pub address: String,
    /// Unix timestamp of last heartbeat.
    pub last_seen: u64,
    /// Capabilities this node advertises.
    pub capabilities: Vec<String>,
}

impl MeshNodeInfo {
    /// Create a new node info with required fields.
    #[must_use]
    pub fn new(
        node_id: impl Into<String>,
        zone: impl Into<String>,
        state: MeshNodeState,
        address: impl Into<String>,
    ) -> Self {
        Self {
            node_id: node_id.into(),
            zone: zone.into(),
            state,
            address: address.into(),
            last_seen: 0,
            capabilities: Vec::new(),
        }
    }

    /// Set the last-seen timestamp (builder pattern).
    #[must_use]
    pub const fn with_last_seen(mut self, ts: u64) -> Self {
        self.last_seen = ts;
        self
    }

    /// Add capabilities (builder pattern).
    #[must_use]
    pub fn with_capabilities(mut self, caps: Vec<String>) -> Self {
        self.capabilities = caps;
        self
    }

    /// Whether this node can accept new work.
    #[must_use]
    pub const fn can_accept_work(&self) -> bool {
        self.state.is_available()
    }

    /// Whether this node is reachable for any purpose.
    #[must_use]
    pub const fn is_reachable(&self) -> bool {
        self.state.is_reachable()
    }

    /// Human-readable summary line.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} ({}) [{}] @ {}",
            self.node_id, self.zone, self.state, self.address
        )
    }
}

// ── Zone status ─────────────────────────────────────────────────────

/// Status of a single mesh zone.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MeshZoneStatus {
    /// Zone identifier.
    pub zone_id: String,
    /// Total number of nodes in this zone.
    pub node_count: usize,
    /// Number of healthy (active) nodes.
    pub healthy_count: usize,
    /// Number of degraded (draining/joining) nodes.
    pub degraded_count: usize,
    /// Policy enforcement status (e.g. "enforcing", "permissive").
    pub policy_status: String,
}

impl MeshZoneStatus {
    /// Create a new zone status.
    #[must_use]
    pub fn new(zone_id: impl Into<String>) -> Self {
        Self {
            zone_id: zone_id.into(),
            node_count: 0,
            healthy_count: 0,
            degraded_count: 0,
            policy_status: "unknown".to_owned(),
        }
    }

    /// Build zone status from a list of nodes belonging to this zone.
    #[must_use]
    pub fn from_nodes(zone_id: impl Into<String>, nodes: &[MeshNodeInfo]) -> Self {
        let mut status = Self::new(zone_id);
        status.node_count = nodes.len();
        for node in nodes {
            match node.state {
                MeshNodeState::Active => status.healthy_count += 1,
                MeshNodeState::Draining | MeshNodeState::Joining => {
                    status.degraded_count += 1;
                }
                MeshNodeState::Offline | MeshNodeState::Unknown => {}
            }
        }
        status.policy_status = if status.node_count == 0 {
            "offline".to_owned()
        } else if status.healthy_count == status.node_count {
            "enforcing".to_owned()
        } else if status.healthy_count > 0 {
            "degraded".to_owned()
        } else {
            "offline".to_owned()
        };
        status
    }

    /// Number of offline/unknown nodes.
    #[must_use]
    pub const fn offline_count(&self) -> usize {
        self.node_count
            .saturating_sub(self.healthy_count)
            .saturating_sub(self.degraded_count)
    }

    /// Whether the zone has any available nodes.
    #[must_use]
    pub const fn is_available(&self) -> bool {
        self.healthy_count > 0
    }

    /// Fraction of healthy nodes (0.0..=1.0).
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn health_ratio(&self) -> f64 {
        if self.node_count == 0 {
            return 0.0;
        }
        self.healthy_count as f64 / self.node_count as f64
    }
}

// ── Topology edge ───────────────────────────────────────────────────

/// A directional edge in the mesh topology graph.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MeshTopologyEdge {
    /// Source node ID.
    pub from_node: String,
    /// Destination node ID.
    pub to_node: String,
    /// Measured latency in milliseconds.
    pub latency_ms: Option<u64>,
    /// Bandwidth classification (e.g. "high", "medium", "low").
    pub bandwidth_class: String,
    /// Whether this edge is considered healthy.
    pub healthy: bool,
}

impl MeshTopologyEdge {
    /// Create a new topology edge.
    #[must_use]
    pub fn new(from_node: impl Into<String>, to_node: impl Into<String>, healthy: bool) -> Self {
        Self {
            from_node: from_node.into(),
            to_node: to_node.into(),
            latency_ms: None,
            bandwidth_class: "unknown".to_owned(),
            healthy,
        }
    }

    /// Set latency (builder pattern).
    #[must_use]
    pub const fn with_latency(mut self, ms: u64) -> Self {
        self.latency_ms = Some(ms);
        self
    }

    /// Set bandwidth class (builder pattern).
    #[must_use]
    pub fn with_bandwidth(mut self, class: impl Into<String>) -> Self {
        self.bandwidth_class = class.into();
        self
    }

    /// Human-readable edge description.
    #[must_use]
    pub fn description(&self) -> String {
        let latency = self
            .latency_ms
            .map_or_else(|| "?ms".to_owned(), |ms| format!("{ms}ms"));
        let health = if self.healthy { "OK" } else { "FAIL" };
        format!(
            "{} -> {} [{latency}, {bw}, {health}]",
            self.from_node,
            self.to_node,
            latency = latency,
            bw = self.bandwidth_class,
            health = health,
        )
    }
}

// ── Topology ────────────────────────────────────────────────────────

/// Full mesh topology snapshot.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MeshTopology {
    /// All known nodes in the mesh.
    pub nodes: Vec<MeshNodeInfo>,
    /// Edges between nodes.
    pub edges: Vec<MeshTopologyEdge>,
    /// Per-zone aggregate status.
    pub zones: Vec<MeshZoneStatus>,
}

impl MeshTopology {
    /// Create an empty topology.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            zones: Vec::new(),
        }
    }

    /// Build a topology from a set of nodes and edges.
    /// Zone statuses are computed from the node list.
    #[must_use]
    pub fn from_nodes_and_edges(nodes: Vec<MeshNodeInfo>, edges: Vec<MeshTopologyEdge>) -> Self {
        let zones = compute_zone_statuses(&nodes);
        Self {
            nodes,
            edges,
            zones,
        }
    }

    /// Total node count.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Total edge count.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Number of healthy edges.
    #[must_use]
    pub fn healthy_edge_count(&self) -> usize {
        self.edges.iter().filter(|e| e.healthy).count()
    }

    /// Number of unhealthy edges.
    #[must_use]
    pub fn unhealthy_edge_count(&self) -> usize {
        self.edges.iter().filter(|e| !e.healthy).count()
    }

    /// Get nodes in a specific zone.
    #[must_use]
    pub fn nodes_in_zone(&self, zone: &str) -> Vec<&MeshNodeInfo> {
        self.nodes.iter().filter(|n| n.zone == zone).collect()
    }

    /// Get edges involving a specific node.
    #[must_use]
    pub fn edges_for_node(&self, node_id: &str) -> Vec<&MeshTopologyEdge> {
        self.edges
            .iter()
            .filter(|e| e.from_node == node_id || e.to_node == node_id)
            .collect()
    }

    /// Distinct zone IDs from the node list.
    #[must_use]
    pub fn zone_ids(&self) -> Vec<String> {
        let mut seen = std::collections::BTreeSet::new();
        for node in &self.nodes {
            seen.insert(node.zone.clone());
        }
        seen.into_iter().collect()
    }

    /// Detect potential split-brain: zones that have no healthy edges between them.
    #[must_use]
    pub fn detect_split_brain(&self) -> Vec<(String, String)> {
        let zone_ids = self.zone_ids();
        let mut splits = Vec::new();

        for (i, z1) in zone_ids.iter().enumerate() {
            for z2 in zone_ids.iter().skip(i + 1) {
                let has_healthy_cross_edge = self.edges.iter().any(|e| {
                    let from_zone = self
                        .nodes
                        .iter()
                        .find(|n| n.node_id == e.from_node)
                        .map(|n| n.zone.as_str());
                    let to_zone = self
                        .nodes
                        .iter()
                        .find(|n| n.node_id == e.to_node)
                        .map(|n| n.zone.as_str());

                    e.healthy
                        && ((from_zone == Some(z1.as_str()) && to_zone == Some(z2.as_str()))
                            || (from_zone == Some(z2.as_str()) && to_zone == Some(z1.as_str())))
                });

                if !has_healthy_cross_edge {
                    splits.push((z1.clone(), z2.clone()));
                }
            }
        }

        splits
    }
}

/// Compute per-zone statuses from a flat list of nodes.
fn compute_zone_statuses(nodes: &[MeshNodeInfo]) -> Vec<MeshZoneStatus> {
    let mut zone_nodes: BTreeMap<&str, Vec<&MeshNodeInfo>> = BTreeMap::new();
    for node in nodes {
        zone_nodes.entry(node.zone.as_str()).or_default().push(node);
    }

    zone_nodes
        .into_iter()
        .map(|(zone_id, znodes)| {
            let mut status = MeshZoneStatus::new(zone_id);
            status.node_count = znodes.len();
            for n in &znodes {
                match n.state {
                    MeshNodeState::Active => status.healthy_count += 1,
                    MeshNodeState::Draining | MeshNodeState::Joining => {
                        status.degraded_count += 1;
                    }
                    MeshNodeState::Offline | MeshNodeState::Unknown => {}
                }
            }
            status.policy_status = if status.node_count == 0 {
                "offline".to_owned()
            } else if status.healthy_count == status.node_count {
                "enforcing".to_owned()
            } else if status.healthy_count > 0 {
                "degraded".to_owned()
            } else {
                "offline".to_owned()
            };
            status
        })
        .collect()
}

// ── Placement recommendation ────────────────────────────────────────

/// Recommendation for where to place a connector/operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlacementRecommendation {
    /// Preferred zone for placement.
    pub preferred_zone: String,
    /// Reason for this recommendation.
    pub reason: String,
    /// Alternative zones that could also work.
    pub alternatives: Vec<String>,
}

impl PlacementRecommendation {
    /// Create a new placement recommendation.
    #[must_use]
    pub fn new(
        preferred_zone: impl Into<String>,
        reason: impl Into<String>,
        alternatives: Vec<String>,
    ) -> Self {
        Self {
            preferred_zone: preferred_zone.into(),
            reason: reason.into(),
            alternatives,
        }
    }

    /// Whether there are alternative placements.
    #[must_use]
    pub fn has_alternatives(&self) -> bool {
        !self.alternatives.is_empty()
    }

    /// Total number of viable zones (preferred + alternatives).
    #[must_use]
    pub fn viable_zone_count(&self) -> usize {
        1 + self.alternatives.len()
    }
}

// ── Availability result ─────────────────────────────────────────────

/// Result of checking where a connector/operation can run.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MeshAvailabilityResult {
    /// Connector being checked.
    pub connector: String,
    /// Operation being checked (if specified).
    pub operation: Option<String>,
    /// Zones where this connector/operation is available.
    pub zones_available: Vec<String>,
    /// Zones where this connector/operation is NOT available.
    pub zones_unavailable: Vec<String>,
    /// Placement recommendation based on current mesh state.
    pub placement_recommendation: Option<PlacementRecommendation>,
}

impl MeshAvailabilityResult {
    /// Create a new availability result.
    #[must_use]
    pub fn new(connector: impl Into<String>) -> Self {
        Self {
            connector: connector.into(),
            operation: None,
            zones_available: Vec::new(),
            zones_unavailable: Vec::new(),
            placement_recommendation: None,
        }
    }

    /// Set the operation (builder pattern).
    #[must_use]
    pub fn with_operation(mut self, op: impl Into<String>) -> Self {
        self.operation = Some(op.into());
        self
    }

    /// Add an available zone (builder pattern).
    #[must_use]
    pub fn with_available_zone(mut self, zone: impl Into<String>) -> Self {
        self.zones_available.push(zone.into());
        self
    }

    /// Add an unavailable zone (builder pattern).
    #[must_use]
    pub fn with_unavailable_zone(mut self, zone: impl Into<String>) -> Self {
        self.zones_unavailable.push(zone.into());
        self
    }

    /// Set the placement recommendation (builder pattern).
    #[must_use]
    pub fn with_recommendation(mut self, rec: PlacementRecommendation) -> Self {
        self.placement_recommendation = Some(rec);
        self
    }

    /// Whether the connector is available anywhere.
    #[must_use]
    pub fn is_available(&self) -> bool {
        !self.zones_available.is_empty()
    }

    /// Total number of zones considered.
    #[must_use]
    pub fn total_zones(&self) -> usize {
        self.zones_available.len() + self.zones_unavailable.len()
    }
}

// ── Cutover gates ──────────────────────────────────────────────────

/// Default number of connectors that must satisfy inventory/state gates.
pub const DEFAULT_CUTOVER_GATE_CONNECTOR_COUNT: usize = 3;

/// Default minimum mesh replicas required for connector/state gates.
pub const DEFAULT_CUTOVER_GATE_REPLICA_COUNT: usize = 2;

/// Default staleness budget for state/audit/policy cutover telemetry.
pub const DEFAULT_CUTOVER_GATE_STALENESS_SECONDS: u64 = 60;

/// Default minimum policy peers that must hold verified policy bundles.
pub const DEFAULT_CUTOVER_GATE_POLICY_PEER_COUNT: usize = 2;

/// Stable schema version for `fwc mesh cutover-gates --json`.
pub const MESH_CUTOVER_GATES_SCHEMA_VERSION: &str = "1.2.0";

/// Stable machine status for a mesh-native cutover gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CutoverGateStatus {
    /// Predicate is satisfied by direct current evidence.
    Green,
    /// Predicate was evaluated and is not satisfied.
    Red,
    /// Predicate cannot be evaluated because required live infrastructure is unavailable.
    Skip,
}

impl CutoverGateStatus {
    /// Machine-readable tag for this status.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Green => "green",
            Self::Red => "red",
            Self::Skip => "skip",
        }
    }

    /// Prometheus-shaped status value for `fcp_cutover_gate_status`.
    #[must_use]
    pub const fn metric_value(self) -> u8 {
        match self {
            Self::Red => 0,
            Self::Skip => 1,
            Self::Green => 2,
        }
    }
}

/// Arguments controlling cutover gate targets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeshCutoverGateArgs {
    /// Minimum connectors that must satisfy connector-level gates.
    pub min_connectors: usize,
    /// Minimum mesh replica count per connector/state object.
    pub replica_count: usize,
    /// Maximum staleness in seconds for state replication.
    pub state_staleness_seconds: u64,
    /// Maximum staleness in seconds for audit quorum checkpoints.
    pub audit_staleness_seconds: u64,
    /// Minimum peers that must hold verified policy bundles.
    pub policy_peer_count: usize,
}

impl Default for MeshCutoverGateArgs {
    fn default() -> Self {
        Self {
            min_connectors: DEFAULT_CUTOVER_GATE_CONNECTOR_COUNT,
            replica_count: DEFAULT_CUTOVER_GATE_REPLICA_COUNT,
            state_staleness_seconds: DEFAULT_CUTOVER_GATE_STALENESS_SECONDS,
            audit_staleness_seconds: DEFAULT_CUTOVER_GATE_STALENESS_SECONDS,
            policy_peer_count: DEFAULT_CUTOVER_GATE_POLICY_PEER_COUNT,
        }
    }
}

/// A single measurable mesh-native cutover gate.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MeshCutoverGate {
    /// Stable gate identifier.
    pub gate_id: String,
    /// Human-readable gate name.
    pub name: String,
    /// Exact predicate the gate evaluates.
    pub predicate_text: String,
    /// Current evaluated status.
    pub status: CutoverGateStatus,
    /// Current measurement, or explicit missing-telemetry detail.
    pub measured_value: Value,
    /// Required target value.
    pub target: Value,
    /// Commands or artifacts used to measure the predicate.
    pub how_measured: Vec<String>,
    /// Operator guidance for moving a red gate forward.
    pub remediation: String,
}

impl MeshCutoverGate {
    fn skip(
        gate_id: &str,
        name: &str,
        predicate_text: String,
        measured_value: Value,
        target: Value,
        how_measured: Vec<String>,
        remediation: &str,
    ) -> Self {
        Self {
            gate_id: gate_id.to_owned(),
            name: name.to_owned(),
            predicate_text,
            status: CutoverGateStatus::Skip,
            measured_value,
            target,
            how_measured,
            remediation: remediation.to_owned(),
        }
    }
}

/// Overall status for a group of cutover gates.
#[must_use]
pub fn cutover_gate_overall_status(gates: &[MeshCutoverGate]) -> CutoverGateStatus {
    if gates
        .iter()
        .any(|gate| matches!(gate.status, CutoverGateStatus::Red))
    {
        CutoverGateStatus::Red
    } else if gates
        .iter()
        .all(|gate| matches!(gate.status, CutoverGateStatus::Green))
    {
        CutoverGateStatus::Green
    } else {
        CutoverGateStatus::Skip
    }
}

/// Build the mesh-native cutover gate contract.
///
/// The current implementation is fail-closed: it exposes the stable schema and
/// reports SKIP until `fwc` and the host expose direct live telemetry for every
/// predicate. SKIP gates never count as green, which prevents a green-by-default
/// cutover when no mesh evidence is available.
#[must_use]
pub fn mesh_cutover_gates(args: &MeshCutoverGateArgs) -> Vec<MeshCutoverGate> {
    vec![
        MeshCutoverGate::skip(
            "mesh-inventory-placement",
            "Mesh-backed connector inventory with placement evidence",
            format!(
                "At least {} connectors have placement.has_mesh_replica=true and placement.replica_count >= {}.",
                args.min_connectors, args.replica_count
            ),
            json!({
                "telemetry_state": "unavailable",
                "connectors_meeting_predicate": 0,
                "available_route": "fwc mesh explain-availability",
                "missing_fields": ["placement.has_mesh_replica", "placement.replica_count"],
            }),
            json!({
                "connectors_meeting_predicate": args.min_connectors,
                "placement.has_mesh_replica": true,
                "placement.replica_count": args.replica_count,
            }),
            vec![
                "fwc mesh explain-availability <connector> --host <endpoint> --json".to_owned(),
                "bv --robot-triage".to_owned(),
            ],
            "Expose live placement replica telemetry on the host/mesh availability route; until that route is available this gate remains skipped and cannot count as green.",
        ),
        MeshCutoverGate::skip(
            "mesh-lifecycle-state-replication",
            "Mesh-backed lifecycle state replication",
            format!(
                "ConnectorStateRoot for at least {} connectors is mesh-replicated with replica_count >= {} and last_replicated_seq advancing within {}s.",
                args.min_connectors, args.replica_count, args.state_staleness_seconds
            ),
            json!({
                "telemetry_state": "unavailable",
                "connectors_meeting_predicate": 0,
                "missing_fields": [
                    "connector_state_root.replica_count",
                    "connector_state_root.last_replicated_seq",
                    "connector_state_root.last_replicated_age_seconds"
                ],
            }),
            json!({
                "connectors_meeting_predicate": args.min_connectors,
                "replica_count": args.replica_count,
                "last_replicated_age_seconds_lte": args.state_staleness_seconds,
            }),
            vec![
                "fwc mesh cutover-gates --json".to_owned(),
                "future: fwc mesh state status --json".to_owned(),
            ],
            "Publish ConnectorStateRoot replication telemetry; until that route is available this gate remains skipped and cannot count as green.",
        ),
        MeshCutoverGate::skip(
            "mesh-audit-chain-quorum",
            "Mesh-backed audit chain quorum across at least two nodes",
            format!(
                "Audit chain status reports quorum_signed_checkpoints >= 1 and quorum_signers >= 2 within {}s.",
                args.audit_staleness_seconds
            ),
            json!({
                "telemetry_state": "route_available_artifact_required",
                "quorum_signed_checkpoints": 0,
                "quorum_signers": 0,
                "available_route": "fwc audit chain status --json",
                "missing_fields": ["live_quorum_checkpoint_snapshot"],
            }),
            json!({
                "quorum_signed_checkpoints": 1,
                "quorum_signers": 2,
                "checkpoint_age_seconds_lte": args.audit_staleness_seconds,
            }),
            vec!["fwc audit chain status --json".to_owned()],
            "Wire live quorum checkpoint telemetry into the audit status route; until that telemetry is available this gate remains skipped and cannot count as green.",
        ),
        MeshCutoverGate::skip(
            "mesh-policy-object-distribution",
            "Mesh-backed policy-object distribution",
            format!(
                "Policy bundles for the active zone are present on at least {} mesh peers with verified owner signatures.",
                args.policy_peer_count
            ),
            json!({
                "telemetry_state": "unavailable",
                "peer_count": 0,
                "verified_owner_signatures": false,
                "missing_route": "fwc policy distribution --json",
            }),
            json!({
                "peer_count": args.policy_peer_count,
                "verified_owner_signatures": true,
            }),
            vec!["fwc policy distribution --json".to_owned()],
            "Expose policy bundle distribution and signature verification telemetry; until that route is available this gate remains skipped and cannot count as green.",
        ),
    ]
}

// ── Command argument types ──────────────────────────────────────────

/// Arguments for `fwc mesh status`.
#[derive(Clone, Debug, Default)]
pub struct MeshStatusArgs {
    /// Filter to a specific zone.
    pub zone: Option<String>,
    /// Include additional detail in output.
    pub verbose: bool,
    /// Include inter-node connectivity info.
    pub include_connectivity: bool,
}

/// Arguments for `fwc mesh nodes`.
#[derive(Clone, Debug, Default)]
pub struct MeshNodesArgs {
    /// Filter to a specific zone.
    pub zone: Option<String>,
    /// Filter by node state.
    pub state_filter: Option<MeshNodeState>,
    /// Output format ("table" or "json").
    pub format: Option<String>,
}

/// Arguments for `fwc mesh topology`.
#[derive(Clone, Debug, Default)]
pub struct MeshTopologyArgs {
    /// Filter to a specific zone.
    pub zone: Option<String>,
    /// Include edge details.
    pub include_edges: bool,
}

/// Arguments for `fwc mesh availability`.
#[derive(Clone, Debug)]
pub struct MeshAvailabilityArgs {
    /// Connector to check availability for.
    pub connector: String,
    /// Specific operation to check (optional).
    pub operation: Option<String>,
    /// Restrict check to a specific zone.
    pub zone: Option<String>,
}

// ── Core functions ──────────────────────────────────────────────────

/// Compute mesh status from a topology snapshot.
///
/// Returns per-zone status aggregations filtered by the optional zone argument.
#[must_use]
pub fn mesh_status(topology: &MeshTopology, args: &MeshStatusArgs) -> Vec<MeshZoneStatus> {
    let mut zones = topology.zones.clone();

    if let Some(ref zone_filter) = args.zone {
        zones.retain(|z| z.zone_id == *zone_filter);
    }

    zones
}

/// List mesh nodes with optional filtering.
///
/// Filters by zone and/or node state as specified in args.
#[must_use]
pub fn mesh_nodes(topology: &MeshTopology, args: &MeshNodesArgs) -> Vec<MeshNodeInfo> {
    let mut nodes = topology.nodes.clone();

    if let Some(ref zone_filter) = args.zone {
        nodes.retain(|n| n.zone == *zone_filter);
    }

    if let Some(state_filter) = args.state_filter {
        nodes.retain(|n| n.state == state_filter);
    }

    nodes
}

/// Get mesh topology, optionally filtered to a zone.
///
/// When a zone filter is provided, only nodes in that zone and edges
/// connecting those nodes are included.
#[must_use]
pub fn mesh_topology(topology: &MeshTopology, args: &MeshTopologyArgs) -> MeshTopology {
    args.zone.as_ref().map_or_else(
        || {
            let edges = if args.include_edges {
                topology.edges.clone()
            } else {
                Vec::new()
            };
            MeshTopology {
                nodes: topology.nodes.clone(),
                edges,
                zones: topology.zones.clone(),
            }
        },
        |zone_filter| {
            let filtered_nodes: Vec<MeshNodeInfo> = topology
                .nodes
                .iter()
                .filter(|n| n.zone == *zone_filter)
                .cloned()
                .collect();

            let node_ids: std::collections::HashSet<&str> =
                filtered_nodes.iter().map(|n| n.node_id.as_str()).collect();

            let filtered_edges: Vec<MeshTopologyEdge> = if args.include_edges {
                topology
                    .edges
                    .iter()
                    .filter(|e| {
                        node_ids.contains(e.from_node.as_str())
                            || node_ids.contains(e.to_node.as_str())
                    })
                    .cloned()
                    .collect()
            } else {
                Vec::new()
            };

            let zones = compute_zone_statuses(&filtered_nodes);
            MeshTopology {
                nodes: filtered_nodes,
                edges: filtered_edges,
                zones,
            }
        },
    )
}

/// Check availability of a connector/operation across mesh zones.
///
/// Examines each zone in the topology and determines whether the given
/// connector (and optionally a specific operation) could be placed there.
/// Zones with at least one active node that has the required capability
/// are considered available.
#[must_use]
pub fn mesh_availability(
    topology: &MeshTopology,
    args: &MeshAvailabilityArgs,
) -> MeshAvailabilityResult {
    let mut result = MeshAvailabilityResult::new(&args.connector);
    result.operation.clone_from(&args.operation);

    let zone_ids = args.zone.as_ref().map_or_else(
        || topology.zone_ids(),
        |zone_filter| vec![zone_filter.clone()],
    );

    let required_cap = args.connector.clone();

    for zone_id in &zone_ids {
        let zone_nodes = topology.nodes_in_zone(zone_id);
        let has_capable_active_node = zone_nodes.iter().any(|n| {
            n.state.is_available()
                && (n.capabilities.is_empty() || n.capabilities.iter().any(|c| c == &required_cap))
        });

        if has_capable_active_node {
            result.zones_available.push(zone_id.clone());
        } else {
            result.zones_unavailable.push(zone_id.clone());
        }
    }

    // Generate placement recommendation.
    if !result.zones_available.is_empty() {
        let preferred = select_preferred_zone(topology, &result.zones_available);
        let alternatives: Vec<String> = result
            .zones_available
            .iter()
            .filter(|z| *z != &preferred)
            .cloned()
            .collect();

        let reason = if result.zones_available.len() == 1 {
            "only available zone".to_owned()
        } else {
            topology
                .zones
                .iter()
                .find(|z| z.zone_id == preferred)
                .map_or_else(
                    || "best available zone".to_owned(),
                    |zs| {
                        format!(
                            "highest health ratio ({:.0}%, {} active nodes)",
                            zs.health_ratio() * 100.0,
                            zs.healthy_count,
                        )
                    },
                )
        };

        result.placement_recommendation = Some(PlacementRecommendation::new(
            preferred,
            reason,
            alternatives,
        ));
    }

    result
}

/// Select the preferred zone from a list of available zones based on health.
fn select_preferred_zone(topology: &MeshTopology, available_zones: &[String]) -> String {
    let mut best_zone = available_zones[0].clone();
    let mut best_ratio = -1.0_f64;

    for zone_id in available_zones {
        let ratio = topology
            .zones
            .iter()
            .find(|z| z.zone_id == *zone_id)
            .map_or(0.0, MeshZoneStatus::health_ratio);

        if ratio > best_ratio {
            best_ratio = ratio;
            best_zone.clone_from(zone_id);
        }
    }

    best_zone
}

// ── TOON formatting ─────────────────────────────────────────────────

/// Format mesh status as TOON-style human-readable lines.
#[must_use]
pub fn format_status_toon(zones: &[MeshZoneStatus], verbose: bool) -> Vec<String> {
    let mut lines = Vec::new();

    if zones.is_empty() {
        lines.push("No mesh zones found.".to_owned());
        return lines;
    }

    let total_nodes: usize = zones.iter().map(|z| z.node_count).sum();
    let total_healthy: usize = zones.iter().map(|z| z.healthy_count).sum();
    let total_degraded: usize = zones.iter().map(|z| z.degraded_count).sum();
    let total_offline: usize = zones.iter().map(MeshZoneStatus::offline_count).sum();

    lines.push(format!(
        "Mesh: {} zone(s), {} node(s) ({} active, {} degraded, {} offline)",
        zones.len(),
        total_nodes,
        total_healthy,
        total_degraded,
        total_offline,
    ));
    lines.push(String::new());

    // Table header.
    lines.push(format!(
        "{:<20}{:<10}{:<10}{:<12}{:<12}",
        "Zone", "Nodes", "Active", "Degraded", "Policy"
    ));
    lines.push("-".repeat(64));

    for zone in zones {
        lines.push(format!(
            "{:<20}{:<10}{:<10}{:<12}{:<12}",
            zone.zone_id,
            zone.node_count,
            zone.healthy_count,
            zone.degraded_count,
            zone.policy_status,
        ));

        if verbose {
            let offline = zone.offline_count();
            if offline > 0 {
                lines.push(format!("  {offline} offline node(s)"));
            }
            lines.push(format!(
                "  health ratio: {:.1}%",
                zone.health_ratio() * 100.0
            ));
        }
    }

    lines
}

/// Format mesh nodes as TOON-style human-readable lines.
#[must_use]
pub fn format_nodes_toon(nodes: &[MeshNodeInfo]) -> Vec<String> {
    let mut lines = Vec::new();

    if nodes.is_empty() {
        lines.push("No mesh nodes found.".to_owned());
        return lines;
    }

    lines.push(format!("{} node(s):", nodes.len()));
    lines.push(String::new());

    // Table header.
    lines.push(format!(
        "{:<20}{:<14}{:<12}{:<24}{:<14}Capabilities",
        "Node ID", "Zone", "State", "Address", "Last Seen"
    ));
    lines.push("-".repeat(96));

    for node in nodes {
        let caps = if node.capabilities.is_empty() {
            "-".to_owned()
        } else {
            node.capabilities.join(", ")
        };
        let last_seen_str = if node.last_seen == 0 {
            "never".to_owned()
        } else {
            format!("t={}", node.last_seen)
        };

        lines.push(format!(
            "{:<20}{:<14}{:<12}{:<24}{:<14}{}",
            node.node_id, node.zone, node.state, node.address, last_seen_str, caps,
        ));
    }

    lines
}

/// Format mesh topology as TOON-style human-readable lines.
#[must_use]
pub fn format_topology_toon(topology: &MeshTopology) -> Vec<String> {
    let mut lines = Vec::new();

    if topology.nodes.is_empty() {
        lines.push("Empty mesh topology.".to_owned());
        return lines;
    }

    lines.push(format!(
        "Topology: {} node(s), {} edge(s) ({} healthy, {} unhealthy)",
        topology.node_count(),
        topology.edge_count(),
        topology.healthy_edge_count(),
        topology.unhealthy_edge_count(),
    ));
    lines.push(String::new());

    // Zones summary.
    lines.push("Zones:".to_owned());
    for zone in &topology.zones {
        lines.push(format!(
            "  {} - {} node(s), {} active, policy={}",
            zone.zone_id, zone.node_count, zone.healthy_count, zone.policy_status,
        ));
    }

    // Nodes.
    lines.push(String::new());
    lines.push("Nodes:".to_owned());
    for node in &topology.nodes {
        lines.push(format!("  {}", node.summary()));
    }

    // Edges.
    if !topology.edges.is_empty() {
        lines.push(String::new());
        lines.push("Edges:".to_owned());
        for edge in &topology.edges {
            let health_marker = if edge.healthy { "+" } else { "!" };
            let latency = edge
                .latency_ms
                .map_or_else(|| "?ms".to_owned(), |ms| format!("{ms}ms"));
            lines.push(format!(
                "  [{health_marker}] {} -> {} ({latency}, {})",
                edge.from_node, edge.to_node, edge.bandwidth_class,
            ));
        }
    }

    // Split-brain detection.
    let splits = topology.detect_split_brain();
    if !splits.is_empty() {
        lines.push(String::new());
        lines.push("WARNING: Potential split-brain detected:".to_owned());
        for (z1, z2) in &splits {
            lines.push(format!(
                "  No healthy cross-zone edges between {z1} and {z2}"
            ));
        }
    }

    lines
}

/// Format availability result as TOON-style human-readable lines.
#[must_use]
pub fn format_availability_toon(result: &MeshAvailabilityResult) -> Vec<String> {
    let mut lines = Vec::new();

    let target = result.operation.as_ref().map_or_else(
        || result.connector.clone(),
        |op| format!("{}:{op}", result.connector),
    );

    if result.is_available() {
        lines.push(format!(
            "Availability for `{target}`: available in {} zone(s)",
            result.zones_available.len(),
        ));
    } else {
        lines.push(format!(
            "Availability for `{target}`: NOT available in any zone",
        ));
    }
    lines.push(String::new());

    if !result.zones_available.is_empty() {
        lines.push("Available zones:".to_owned());
        for zone in &result.zones_available {
            lines.push(format!("  [+] {zone}"));
        }
    }

    if !result.zones_unavailable.is_empty() {
        lines.push("Unavailable zones:".to_owned());
        for zone in &result.zones_unavailable {
            lines.push(format!("  [-] {zone}"));
        }
    }

    if let Some(ref rec) = result.placement_recommendation {
        lines.push(String::new());
        lines.push(format!("Recommendation: place in `{}`", rec.preferred_zone));
        lines.push(format!("  Reason: {}", rec.reason));
        if !rec.alternatives.is_empty() {
            lines.push(format!("  Alternatives: {}", rec.alternatives.join(", ")));
        }
    }

    lines
}

// ── JSON output ─────────────────────────────────────────────────────

/// Serialize mesh status zones to JSON.
///
/// # Errors
///
/// Returns an error if serialization fails.
pub fn format_status_json(
    zones: &[MeshZoneStatus],
) -> Result<serde_json::Value, serde_json::Error> {
    serde_json::to_value(zones)
}

/// Serialize mesh nodes to JSON.
///
/// # Errors
///
/// Returns an error if serialization fails.
pub fn format_nodes_json(nodes: &[MeshNodeInfo]) -> Result<serde_json::Value, serde_json::Error> {
    serde_json::to_value(nodes)
}

/// Serialize mesh topology to JSON.
///
/// # Errors
///
/// Returns an error if serialization fails.
pub fn format_topology_json(
    topology: &MeshTopology,
) -> Result<serde_json::Value, serde_json::Error> {
    serde_json::to_value(topology)
}

/// Serialize availability result to JSON.
///
/// # Errors
///
/// Returns an error if serialization fails.
pub fn format_availability_json(
    result: &MeshAvailabilityResult,
) -> Result<serde_json::Value, serde_json::Error> {
    serde_json::to_value(result)
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ─────────────────────────────────────────────────────

    fn node(id: &str, zone: &str, state: MeshNodeState) -> MeshNodeInfo {
        MeshNodeInfo::new(id, zone, state, format!("10.0.0.{}", id.len()))
    }

    fn node_with_caps(id: &str, zone: &str, state: MeshNodeState, caps: &[&str]) -> MeshNodeInfo {
        MeshNodeInfo::new(id, zone, state, format!("10.0.0.{}", id.len()))
            .with_capabilities(caps.iter().map(|c| (*c).to_owned()).collect())
    }

    fn edge(from: &str, to: &str, healthy: bool) -> MeshTopologyEdge {
        MeshTopologyEdge::new(from, to, healthy)
    }

    fn sample_topology() -> MeshTopology {
        let nodes = vec![
            node("n1", "us-east", MeshNodeState::Active),
            node("n2", "us-east", MeshNodeState::Active),
            node("n3", "us-west", MeshNodeState::Active),
            node("n4", "us-west", MeshNodeState::Draining),
            node("n5", "eu-west", MeshNodeState::Offline),
        ];
        let edges = vec![
            edge("n1", "n2", true)
                .with_latency(5)
                .with_bandwidth("high"),
            edge("n1", "n3", true)
                .with_latency(45)
                .with_bandwidth("medium"),
            edge("n2", "n4", true)
                .with_latency(40)
                .with_bandwidth("medium"),
            edge("n3", "n5", false)
                .with_latency(200)
                .with_bandwidth("low"),
        ];
        MeshTopology::from_nodes_and_edges(nodes, edges)
    }

    // ── MeshNodeState tests ─────────────────────────────────────────

    #[test]
    fn node_state_tag_active() {
        assert_eq!(MeshNodeState::Active.tag(), "active");
    }

    #[test]
    fn node_state_tag_draining() {
        assert_eq!(MeshNodeState::Draining.tag(), "draining");
    }

    #[test]
    fn node_state_tag_offline() {
        assert_eq!(MeshNodeState::Offline.tag(), "offline");
    }

    #[test]
    fn node_state_tag_joining() {
        assert_eq!(MeshNodeState::Joining.tag(), "joining");
    }

    #[test]
    fn node_state_tag_unknown() {
        assert_eq!(MeshNodeState::Unknown.tag(), "unknown");
    }

    #[test]
    fn node_state_display_all() {
        for state in MeshNodeState::ALL {
            assert_eq!(state.to_string(), state.tag());
        }
    }

    #[test]
    fn node_state_from_str_valid() {
        assert_eq!(
            "active".parse::<MeshNodeState>().unwrap(),
            MeshNodeState::Active
        );
        assert_eq!(
            "draining".parse::<MeshNodeState>().unwrap(),
            MeshNodeState::Draining
        );
        assert_eq!(
            "offline".parse::<MeshNodeState>().unwrap(),
            MeshNodeState::Offline
        );
        assert_eq!(
            "joining".parse::<MeshNodeState>().unwrap(),
            MeshNodeState::Joining
        );
        assert_eq!(
            "unknown".parse::<MeshNodeState>().unwrap(),
            MeshNodeState::Unknown
        );
    }

    #[test]
    fn node_state_from_str_case_insensitive() {
        assert_eq!(
            "ACTIVE".parse::<MeshNodeState>().unwrap(),
            MeshNodeState::Active
        );
        assert_eq!(
            "Draining".parse::<MeshNodeState>().unwrap(),
            MeshNodeState::Draining
        );
        assert_eq!(
            "OFFLINE".parse::<MeshNodeState>().unwrap(),
            MeshNodeState::Offline
        );
    }

    #[test]
    fn node_state_from_str_invalid() {
        assert!("bogus".parse::<MeshNodeState>().is_err());
    }

    #[test]
    fn node_state_is_available() {
        assert!(MeshNodeState::Active.is_available());
        assert!(!MeshNodeState::Draining.is_available());
        assert!(!MeshNodeState::Offline.is_available());
        assert!(!MeshNodeState::Joining.is_available());
        assert!(!MeshNodeState::Unknown.is_available());
    }

    #[test]
    fn node_state_is_reachable() {
        assert!(MeshNodeState::Active.is_reachable());
        assert!(MeshNodeState::Draining.is_reachable());
        assert!(!MeshNodeState::Offline.is_reachable());
        assert!(!MeshNodeState::Joining.is_reachable());
        assert!(!MeshNodeState::Unknown.is_reachable());
    }

    #[test]
    fn node_state_is_inactive() {
        assert!(MeshNodeState::Offline.is_inactive());
        assert!(!MeshNodeState::Active.is_inactive());
        assert!(!MeshNodeState::Draining.is_inactive());
    }

    #[test]
    fn node_state_is_transitional() {
        assert!(MeshNodeState::Draining.is_transitional());
        assert!(MeshNodeState::Joining.is_transitional());
        assert!(!MeshNodeState::Active.is_transitional());
        assert!(!MeshNodeState::Offline.is_transitional());
        assert!(!MeshNodeState::Unknown.is_transitional());
    }

    #[test]
    fn node_state_serialization_roundtrip() {
        for state in MeshNodeState::ALL {
            let json = serde_json::to_string(state).unwrap();
            let back: MeshNodeState = serde_json::from_str(&json).unwrap();
            assert_eq!(back, *state);
        }
    }

    #[test]
    fn node_state_ordering() {
        assert!(MeshNodeState::Active < MeshNodeState::Draining);
        assert!(MeshNodeState::Draining < MeshNodeState::Offline);
        assert!(MeshNodeState::Offline < MeshNodeState::Joining);
        assert!(MeshNodeState::Joining < MeshNodeState::Unknown);
    }

    // ── MeshNodeInfo tests ──────────────────────────────────────────

    #[test]
    fn node_info_new() {
        let n = MeshNodeInfo::new("n1", "us-east", MeshNodeState::Active, "10.0.0.1");
        assert_eq!(n.node_id, "n1");
        assert_eq!(n.zone, "us-east");
        assert_eq!(n.state, MeshNodeState::Active);
        assert_eq!(n.address, "10.0.0.1");
        assert_eq!(n.last_seen, 0);
        assert!(n.capabilities.is_empty());
    }

    #[test]
    fn node_info_with_last_seen() {
        let n = MeshNodeInfo::new("n1", "z", MeshNodeState::Active, "a").with_last_seen(12345);
        assert_eq!(n.last_seen, 12345);
    }

    #[test]
    fn node_info_with_capabilities() {
        let n = MeshNodeInfo::new("n1", "z", MeshNodeState::Active, "a")
            .with_capabilities(vec!["github".to_owned(), "slack".to_owned()]);
        assert_eq!(n.capabilities.len(), 2);
        assert_eq!(n.capabilities[0], "github");
    }

    #[test]
    fn node_info_can_accept_work_active() {
        let n = node("n1", "z", MeshNodeState::Active);
        assert!(n.can_accept_work());
    }

    #[test]
    fn node_info_cannot_accept_work_draining() {
        let n = node("n1", "z", MeshNodeState::Draining);
        assert!(!n.can_accept_work());
    }

    #[test]
    fn node_info_cannot_accept_work_offline() {
        let n = node("n1", "z", MeshNodeState::Offline);
        assert!(!n.can_accept_work());
    }

    #[test]
    fn node_info_is_reachable_active() {
        let n = node("n1", "z", MeshNodeState::Active);
        assert!(n.is_reachable());
    }

    #[test]
    fn node_info_is_reachable_draining() {
        let n = node("n1", "z", MeshNodeState::Draining);
        assert!(n.is_reachable());
    }

    #[test]
    fn node_info_not_reachable_offline() {
        let n = node("n1", "z", MeshNodeState::Offline);
        assert!(!n.is_reachable());
    }

    #[test]
    fn node_info_summary_contains_fields() {
        let n = MeshNodeInfo::new("node-1", "us-east", MeshNodeState::Active, "10.0.0.1");
        let s = n.summary();
        assert!(s.contains("node-1"));
        assert!(s.contains("us-east"));
        assert!(s.contains("active"));
        assert!(s.contains("10.0.0.1"));
    }

    #[test]
    fn node_info_serialization_roundtrip() {
        let n = MeshNodeInfo::new("n1", "us-east", MeshNodeState::Active, "10.0.0.1")
            .with_last_seen(999)
            .with_capabilities(vec!["github".to_owned()]);
        let json = serde_json::to_string(&n).unwrap();
        let back: MeshNodeInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.node_id, "n1");
        assert_eq!(back.zone, "us-east");
        assert_eq!(back.state, MeshNodeState::Active);
        assert_eq!(back.last_seen, 999);
        assert_eq!(back.capabilities, vec!["github"]);
    }

    // ── MeshZoneStatus tests ────────────────────────────────────────

    #[test]
    fn zone_status_new_defaults() {
        let z = MeshZoneStatus::new("us-east");
        assert_eq!(z.zone_id, "us-east");
        assert_eq!(z.node_count, 0);
        assert_eq!(z.healthy_count, 0);
        assert_eq!(z.degraded_count, 0);
        assert_eq!(z.policy_status, "unknown");
    }

    #[test]
    fn zone_status_from_nodes_all_active() {
        let nodes = vec![
            node("n1", "z", MeshNodeState::Active),
            node("n2", "z", MeshNodeState::Active),
        ];
        let z = MeshZoneStatus::from_nodes("z", &nodes);
        assert_eq!(z.node_count, 2);
        assert_eq!(z.healthy_count, 2);
        assert_eq!(z.degraded_count, 0);
        assert_eq!(z.policy_status, "enforcing");
    }

    #[test]
    fn zone_status_from_nodes_mixed() {
        let nodes = vec![
            node("n1", "z", MeshNodeState::Active),
            node("n2", "z", MeshNodeState::Draining),
            node("n3", "z", MeshNodeState::Offline),
        ];
        let z = MeshZoneStatus::from_nodes("z", &nodes);
        assert_eq!(z.node_count, 3);
        assert_eq!(z.healthy_count, 1);
        assert_eq!(z.degraded_count, 1);
        assert_eq!(z.policy_status, "degraded");
    }

    #[test]
    fn zone_status_from_nodes_all_offline() {
        let nodes = vec![
            node("n1", "z", MeshNodeState::Offline),
            node("n2", "z", MeshNodeState::Offline),
        ];
        let z = MeshZoneStatus::from_nodes("z", &nodes);
        assert_eq!(z.node_count, 2);
        assert_eq!(z.healthy_count, 0);
        assert_eq!(z.policy_status, "offline");
    }

    #[test]
    fn zone_status_from_nodes_empty() {
        let z = MeshZoneStatus::from_nodes("z", &[]);
        assert_eq!(z.node_count, 0);
        assert_eq!(z.healthy_count, 0);
        assert_eq!(z.policy_status, "offline");
    }

    #[test]
    fn zone_status_offline_count() {
        let mut z = MeshZoneStatus::new("z");
        z.node_count = 5;
        z.healthy_count = 2;
        z.degraded_count = 1;
        assert_eq!(z.offline_count(), 2);
    }

    #[test]
    fn zone_status_offline_count_saturates() {
        let mut z = MeshZoneStatus::new("z");
        z.node_count = 0;
        z.healthy_count = 0;
        z.degraded_count = 0;
        assert_eq!(z.offline_count(), 0);
    }

    #[test]
    fn zone_status_is_available() {
        let mut z = MeshZoneStatus::new("z");
        z.healthy_count = 1;
        assert!(z.is_available());
    }

    #[test]
    fn zone_status_not_available() {
        let z = MeshZoneStatus::new("z");
        assert!(!z.is_available());
    }

    #[test]
    fn zone_status_health_ratio_full() {
        let mut z = MeshZoneStatus::new("z");
        z.node_count = 4;
        z.healthy_count = 4;
        assert!((z.health_ratio() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn zone_status_health_ratio_half() {
        let mut z = MeshZoneStatus::new("z");
        z.node_count = 4;
        z.healthy_count = 2;
        assert!((z.health_ratio() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn zone_status_health_ratio_empty() {
        let z = MeshZoneStatus::new("z");
        assert!((z.health_ratio() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn zone_status_serialization_roundtrip() {
        let z = MeshZoneStatus::from_nodes(
            "prod",
            &[
                node("n1", "prod", MeshNodeState::Active),
                node("n2", "prod", MeshNodeState::Draining),
            ],
        );
        let json = serde_json::to_string(&z).unwrap();
        let back: MeshZoneStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back.zone_id, "prod");
        assert_eq!(back.node_count, 2);
        assert_eq!(back.healthy_count, 1);
    }

    // ── MeshTopologyEdge tests ──────────────────────────────────────

    #[test]
    fn edge_new_defaults() {
        let e = MeshTopologyEdge::new("a", "b", true);
        assert_eq!(e.from_node, "a");
        assert_eq!(e.to_node, "b");
        assert!(e.healthy);
        assert_eq!(e.latency_ms, None);
        assert_eq!(e.bandwidth_class, "unknown");
    }

    #[test]
    fn edge_with_latency() {
        let e = MeshTopologyEdge::new("a", "b", true).with_latency(42);
        assert_eq!(e.latency_ms, Some(42));
    }

    #[test]
    fn edge_with_bandwidth() {
        let e = MeshTopologyEdge::new("a", "b", true).with_bandwidth("high");
        assert_eq!(e.bandwidth_class, "high");
    }

    #[test]
    fn edge_description_healthy() {
        let e = edge("a", "b", true).with_latency(10).with_bandwidth("high");
        let desc = e.description();
        assert!(desc.contains("a -> b"));
        assert!(desc.contains("10ms"));
        assert!(desc.contains("high"));
        assert!(desc.contains("OK"));
    }

    #[test]
    fn edge_description_unhealthy() {
        let e = edge("a", "b", false)
            .with_latency(200)
            .with_bandwidth("low");
        let desc = e.description();
        assert!(desc.contains("FAIL"));
    }

    #[test]
    fn edge_description_no_latency() {
        let e = edge("a", "b", true);
        let desc = e.description();
        assert!(desc.contains("?ms"));
    }

    #[test]
    fn edge_serialization_roundtrip() {
        let e = edge("x", "y", true)
            .with_latency(100)
            .with_bandwidth("medium");
        let json = serde_json::to_string(&e).unwrap();
        let back: MeshTopologyEdge = serde_json::from_str(&json).unwrap();
        assert_eq!(back.from_node, "x");
        assert_eq!(back.to_node, "y");
        assert!(back.healthy);
        assert_eq!(back.latency_ms, Some(100));
        assert_eq!(back.bandwidth_class, "medium");
    }

    // ── MeshTopology tests ──────────────────────────────────────────

    #[test]
    fn topology_empty() {
        let t = MeshTopology::empty();
        assert_eq!(t.node_count(), 0);
        assert_eq!(t.edge_count(), 0);
        assert!(t.zones.is_empty());
    }

    #[test]
    fn topology_from_nodes_and_edges_computes_zones() {
        let t = sample_topology();
        assert_eq!(t.node_count(), 5);
        assert_eq!(t.edge_count(), 4);
        assert_eq!(t.zones.len(), 3); // us-east, us-west, eu-west
    }

    #[test]
    fn topology_healthy_edge_count() {
        let t = sample_topology();
        assert_eq!(t.healthy_edge_count(), 3);
    }

    #[test]
    fn topology_unhealthy_edge_count() {
        let t = sample_topology();
        assert_eq!(t.unhealthy_edge_count(), 1);
    }

    #[test]
    fn topology_nodes_in_zone() {
        let t = sample_topology();
        let us_east = t.nodes_in_zone("us-east");
        assert_eq!(us_east.len(), 2);
        let eu_west = t.nodes_in_zone("eu-west");
        assert_eq!(eu_west.len(), 1);
    }

    #[test]
    fn topology_nodes_in_nonexistent_zone() {
        let t = sample_topology();
        assert!(t.nodes_in_zone("ap-south").is_empty());
    }

    #[test]
    fn topology_edges_for_node() {
        let t = sample_topology();
        let n1_edges = t.edges_for_node("n1");
        assert_eq!(n1_edges.len(), 2); // n1->n2, n1->n3
    }

    #[test]
    fn topology_edges_for_node_no_edges() {
        let t = sample_topology();
        let n5_edges = t.edges_for_node("n99");
        assert!(n5_edges.is_empty());
    }

    #[test]
    fn topology_zone_ids() {
        let t = sample_topology();
        let ids = t.zone_ids();
        assert_eq!(ids, vec!["eu-west", "us-east", "us-west"]);
    }

    #[test]
    fn topology_zone_ids_empty() {
        let t = MeshTopology::empty();
        assert!(t.zone_ids().is_empty());
    }

    #[test]
    fn topology_detect_split_brain_none() {
        // All zones connected by healthy edges.
        let nodes = vec![
            node("n1", "z1", MeshNodeState::Active),
            node("n2", "z2", MeshNodeState::Active),
        ];
        let edges = vec![edge("n1", "n2", true)];
        let t = MeshTopology::from_nodes_and_edges(nodes, edges);
        assert!(t.detect_split_brain().is_empty());
    }

    #[test]
    fn topology_detect_split_brain_found() {
        // Two zones with no healthy cross-zone edges.
        let nodes = vec![
            node("n1", "z1", MeshNodeState::Active),
            node("n2", "z2", MeshNodeState::Active),
        ];
        let edges = vec![edge("n1", "n2", false)]; // unhealthy!
        let t = MeshTopology::from_nodes_and_edges(nodes, edges);
        let splits = t.detect_split_brain();
        assert_eq!(splits.len(), 1);
        assert_eq!(splits[0], ("z1".to_owned(), "z2".to_owned()));
    }

    #[test]
    fn topology_detect_split_brain_no_edges() {
        let nodes = vec![
            node("n1", "z1", MeshNodeState::Active),
            node("n2", "z2", MeshNodeState::Active),
            node("n3", "z3", MeshNodeState::Active),
        ];
        let t = MeshTopology::from_nodes_and_edges(nodes, vec![]);
        let splits = t.detect_split_brain();
        assert_eq!(splits.len(), 3); // z1-z2, z1-z3, z2-z3
    }

    #[test]
    fn topology_detect_split_brain_single_zone() {
        let nodes = vec![
            node("n1", "z1", MeshNodeState::Active),
            node("n2", "z1", MeshNodeState::Active),
        ];
        let t = MeshTopology::from_nodes_and_edges(nodes, vec![]);
        assert!(t.detect_split_brain().is_empty());
    }

    #[test]
    fn topology_serialization_roundtrip() {
        let t = sample_topology();
        let json = serde_json::to_string(&t).unwrap();
        let back: MeshTopology = serde_json::from_str(&json).unwrap();
        assert_eq!(back.node_count(), t.node_count());
        assert_eq!(back.edge_count(), t.edge_count());
        assert_eq!(back.zones.len(), t.zones.len());
    }

    // ── PlacementRecommendation tests ───────────────────────────────

    #[test]
    fn placement_new() {
        let p = PlacementRecommendation::new("us-east", "best zone", vec![]);
        assert_eq!(p.preferred_zone, "us-east");
        assert_eq!(p.reason, "best zone");
        assert!(p.alternatives.is_empty());
    }

    #[test]
    fn placement_has_alternatives_true() {
        let p = PlacementRecommendation::new("us-east", "best", vec!["us-west".to_owned()]);
        assert!(p.has_alternatives());
    }

    #[test]
    fn placement_has_alternatives_false() {
        let p = PlacementRecommendation::new("us-east", "only", vec![]);
        assert!(!p.has_alternatives());
    }

    #[test]
    fn placement_viable_zone_count_single() {
        let p = PlacementRecommendation::new("z1", "r", vec![]);
        assert_eq!(p.viable_zone_count(), 1);
    }

    #[test]
    fn placement_viable_zone_count_multiple() {
        let p = PlacementRecommendation::new("z1", "r", vec!["z2".to_owned(), "z3".to_owned()]);
        assert_eq!(p.viable_zone_count(), 3);
    }

    #[test]
    fn placement_serialization_roundtrip() {
        let p =
            PlacementRecommendation::new("us-east", "highest health", vec!["eu-west".to_owned()]);
        let json = serde_json::to_string(&p).unwrap();
        let back: PlacementRecommendation = serde_json::from_str(&json).unwrap();
        assert_eq!(back.preferred_zone, "us-east");
        assert_eq!(back.alternatives, vec!["eu-west"]);
    }

    // ── MeshAvailabilityResult tests ────────────────────────────────

    #[test]
    fn availability_result_new() {
        let r = MeshAvailabilityResult::new("github");
        assert_eq!(r.connector, "github");
        assert!(r.operation.is_none());
        assert!(r.zones_available.is_empty());
        assert!(r.zones_unavailable.is_empty());
        assert!(r.placement_recommendation.is_none());
    }

    #[test]
    fn availability_result_with_operation() {
        let r = MeshAvailabilityResult::new("github").with_operation("list_repos");
        assert_eq!(r.operation, Some("list_repos".to_owned()));
    }

    #[test]
    fn availability_result_builder() {
        let r = MeshAvailabilityResult::new("slack")
            .with_operation("send_message")
            .with_available_zone("us-east")
            .with_unavailable_zone("eu-west")
            .with_recommendation(PlacementRecommendation::new("us-east", "only zone", vec![]));
        assert!(r.is_available());
        assert_eq!(r.total_zones(), 2);
        assert!(r.placement_recommendation.is_some());
    }

    #[test]
    fn availability_result_not_available() {
        let r = MeshAvailabilityResult::new("github").with_unavailable_zone("z1");
        assert!(!r.is_available());
    }

    #[test]
    fn availability_result_total_zones() {
        let r = MeshAvailabilityResult::new("github")
            .with_available_zone("z1")
            .with_available_zone("z2")
            .with_unavailable_zone("z3");
        assert_eq!(r.total_zones(), 3);
    }

    #[test]
    fn availability_result_serialization_roundtrip() {
        let r = MeshAvailabilityResult::new("github")
            .with_operation("list_repos")
            .with_available_zone("us-east");
        let json = serde_json::to_string(&r).unwrap();
        let back: MeshAvailabilityResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.connector, "github");
        assert_eq!(back.operation, Some("list_repos".to_owned()));
        assert_eq!(back.zones_available, vec!["us-east"]);
    }

    // ── mesh_cutover_gates() tests ──────────────────────────────────

    #[test]
    fn cutover_gate_status_tags_are_stable() {
        assert_eq!(CutoverGateStatus::Green.tag(), "green");
        assert_eq!(CutoverGateStatus::Red.tag(), "red");
        assert_eq!(CutoverGateStatus::Skip.tag(), "skip");
    }

    #[test]
    fn cutover_gate_status_metric_values_are_stable() {
        assert_eq!(CutoverGateStatus::Red.metric_value(), 0);
        assert_eq!(CutoverGateStatus::Skip.metric_value(), 1);
        assert_eq!(CutoverGateStatus::Green.metric_value(), 2);
    }

    #[test]
    fn cutover_gates_skip_until_live_telemetry_exists() {
        let args = MeshCutoverGateArgs::default();
        let gates = mesh_cutover_gates(&args);
        assert_eq!(gates.len(), 4);
        assert_eq!(cutover_gate_overall_status(&gates), CutoverGateStatus::Skip);
        assert!(
            gates
                .iter()
                .all(|gate| gate.status == CutoverGateStatus::Skip)
        );
        assert_eq!(gates[0].gate_id, "mesh-inventory-placement");
        assert_eq!(
            gates[0].measured_value["telemetry_state"],
            serde_json::Value::String("unavailable".to_owned())
        );
    }

    #[test]
    fn cutover_gate_overall_status_red_dominates_and_green_requires_unanimity() {
        let args = MeshCutoverGateArgs::default();
        let gates = mesh_cutover_gates(&args);

        // One red gate forces the whole ladder red even if every other gate is green.
        let mut one_red = gates.clone();
        for (index, gate) in one_red.iter_mut().enumerate() {
            gate.status = if index == 0 {
                CutoverGateStatus::Red
            } else {
                CutoverGateStatus::Green
            };
        }
        assert_eq!(
            cutover_gate_overall_status(&one_red),
            CutoverGateStatus::Red
        );

        // Green requires unanimity: a single skip keeps the ladder at skip.
        let mut one_skip = gates.clone();
        for (index, gate) in one_skip.iter_mut().enumerate() {
            gate.status = if index == 1 {
                CutoverGateStatus::Skip
            } else {
                CutoverGateStatus::Green
            };
        }
        assert_eq!(
            cutover_gate_overall_status(&one_skip),
            CutoverGateStatus::Skip
        );

        let mut all_green = gates;
        for gate in &mut all_green {
            gate.status = CutoverGateStatus::Green;
        }
        assert_eq!(
            cutover_gate_overall_status(&all_green),
            CutoverGateStatus::Green
        );
    }

    #[test]
    fn cutover_gate_targets_follow_args() {
        let args = MeshCutoverGateArgs {
            min_connectors: 5,
            replica_count: 3,
            state_staleness_seconds: 45,
            audit_staleness_seconds: 90,
            policy_peer_count: 4,
        };
        let gates = mesh_cutover_gates(&args);
        assert_eq!(gates[0].target["connectors_meeting_predicate"], 5);
        assert_eq!(gates[0].target["placement.replica_count"], 3);
        assert_eq!(gates[1].target["last_replicated_age_seconds_lte"], 45);
        assert_eq!(gates[2].target["checkpoint_age_seconds_lte"], 90);
        assert_eq!(gates[3].target["peer_count"], 4);
    }

    // ── mesh_status() tests ─────────────────────────────────────────

    #[test]
    fn mesh_status_all_zones() {
        let t = sample_topology();
        let args = MeshStatusArgs::default();
        let zones = mesh_status(&t, &args);
        assert_eq!(zones.len(), 3);
    }

    #[test]
    fn mesh_status_filter_zone() {
        let t = sample_topology();
        let args = MeshStatusArgs {
            zone: Some("us-east".to_owned()),
            ..Default::default()
        };
        let zones = mesh_status(&t, &args);
        assert_eq!(zones.len(), 1);
        assert_eq!(zones[0].zone_id, "us-east");
    }

    #[test]
    fn mesh_status_filter_nonexistent_zone() {
        let t = sample_topology();
        let args = MeshStatusArgs {
            zone: Some("ap-south".to_owned()),
            ..Default::default()
        };
        let zones = mesh_status(&t, &args);
        assert!(zones.is_empty());
    }

    #[test]
    fn mesh_status_empty_topology() {
        let t = MeshTopology::empty();
        let args = MeshStatusArgs::default();
        let zones = mesh_status(&t, &args);
        assert!(zones.is_empty());
    }

    // ── mesh_nodes() tests ──────────────────────────────────────────

    #[test]
    fn mesh_nodes_all() {
        let t = sample_topology();
        let args = MeshNodesArgs::default();
        let nodes = mesh_nodes(&t, &args);
        assert_eq!(nodes.len(), 5);
    }

    #[test]
    fn mesh_nodes_filter_zone() {
        let t = sample_topology();
        let args = MeshNodesArgs {
            zone: Some("us-west".to_owned()),
            ..Default::default()
        };
        let nodes = mesh_nodes(&t, &args);
        assert_eq!(nodes.len(), 2);
    }

    #[test]
    fn mesh_nodes_filter_state() {
        let t = sample_topology();
        let args = MeshNodesArgs {
            state_filter: Some(MeshNodeState::Active),
            ..Default::default()
        };
        let nodes = mesh_nodes(&t, &args);
        assert_eq!(nodes.len(), 3); // n1, n2, n3
    }

    #[test]
    fn mesh_nodes_filter_draining() {
        let t = sample_topology();
        let args = MeshNodesArgs {
            state_filter: Some(MeshNodeState::Draining),
            ..Default::default()
        };
        let nodes = mesh_nodes(&t, &args);
        assert_eq!(nodes.len(), 1); // n4
    }

    #[test]
    fn mesh_nodes_filter_offline() {
        let t = sample_topology();
        let args = MeshNodesArgs {
            state_filter: Some(MeshNodeState::Offline),
            ..Default::default()
        };
        let nodes = mesh_nodes(&t, &args);
        assert_eq!(nodes.len(), 1); // n5
    }

    #[test]
    fn mesh_nodes_filter_zone_and_state() {
        let t = sample_topology();
        let args = MeshNodesArgs {
            zone: Some("us-west".to_owned()),
            state_filter: Some(MeshNodeState::Active),
            ..Default::default()
        };
        let nodes = mesh_nodes(&t, &args);
        assert_eq!(nodes.len(), 1); // n3
    }

    #[test]
    fn mesh_nodes_filter_no_match() {
        let t = sample_topology();
        let args = MeshNodesArgs {
            state_filter: Some(MeshNodeState::Joining),
            ..Default::default()
        };
        let nodes = mesh_nodes(&t, &args);
        assert!(nodes.is_empty());
    }

    #[test]
    fn mesh_nodes_empty_topology() {
        let t = MeshTopology::empty();
        let args = MeshNodesArgs::default();
        let nodes = mesh_nodes(&t, &args);
        assert!(nodes.is_empty());
    }

    // ── mesh_topology() tests ───────────────────────────────────────

    #[test]
    fn mesh_topology_full_without_edges() {
        let t = sample_topology();
        let args = MeshTopologyArgs {
            include_edges: false,
            ..Default::default()
        };
        let result = mesh_topology(&t, &args);
        assert_eq!(result.node_count(), 5);
        assert_eq!(result.edge_count(), 0);
    }

    #[test]
    fn mesh_topology_full_with_edges() {
        let t = sample_topology();
        let args = MeshTopologyArgs {
            include_edges: true,
            ..Default::default()
        };
        let result = mesh_topology(&t, &args);
        assert_eq!(result.node_count(), 5);
        assert_eq!(result.edge_count(), 4);
    }

    #[test]
    fn mesh_topology_zone_filter_without_edges() {
        let t = sample_topology();
        let args = MeshTopologyArgs {
            zone: Some("us-east".to_owned()),
            include_edges: false,
        };
        let result = mesh_topology(&t, &args);
        assert_eq!(result.node_count(), 2);
        assert_eq!(result.edge_count(), 0);
    }

    #[test]
    fn mesh_topology_zone_filter_with_edges() {
        let t = sample_topology();
        let args = MeshTopologyArgs {
            zone: Some("us-east".to_owned()),
            include_edges: true,
        };
        let result = mesh_topology(&t, &args);
        assert_eq!(result.node_count(), 2); // n1, n2
        // Edges involving us-east nodes: n1->n2, n1->n3, n2->n4
        assert_eq!(result.edge_count(), 3);
    }

    #[test]
    fn mesh_topology_nonexistent_zone() {
        let t = sample_topology();
        let args = MeshTopologyArgs {
            zone: Some("ap-south".to_owned()),
            include_edges: true,
        };
        let result = mesh_topology(&t, &args);
        assert_eq!(result.node_count(), 0);
        assert_eq!(result.edge_count(), 0);
    }

    // ── mesh_availability() tests ───────────────────────────────────

    #[test]
    fn availability_all_zones_no_caps() {
        // Nodes without capabilities match any connector.
        let t = sample_topology();
        let args = MeshAvailabilityArgs {
            connector: "github".to_owned(),
            operation: None,
            zone: None,
        };
        let result = mesh_availability(&t, &args);
        assert!(result.is_available());
        // us-east and us-west have active nodes; eu-west has only offline
        assert_eq!(result.zones_available.len(), 2);
        assert_eq!(result.zones_unavailable.len(), 1);
    }

    #[test]
    fn availability_with_operation() {
        let t = sample_topology();
        let args = MeshAvailabilityArgs {
            connector: "github".to_owned(),
            operation: Some("list_repos".to_owned()),
            zone: None,
        };
        let result = mesh_availability(&t, &args);
        assert_eq!(result.operation, Some("list_repos".to_owned()));
    }

    #[test]
    fn availability_zone_filter() {
        let t = sample_topology();
        let args = MeshAvailabilityArgs {
            connector: "github".to_owned(),
            operation: None,
            zone: Some("us-east".to_owned()),
        };
        let result = mesh_availability(&t, &args);
        assert_eq!(result.total_zones(), 1);
        assert!(result.is_available());
    }

    #[test]
    fn availability_zone_filter_offline() {
        let t = sample_topology();
        let args = MeshAvailabilityArgs {
            connector: "github".to_owned(),
            operation: None,
            zone: Some("eu-west".to_owned()),
        };
        let result = mesh_availability(&t, &args);
        assert!(!result.is_available());
    }

    #[test]
    fn availability_with_capabilities_match() {
        let nodes = vec![
            node_with_caps("n1", "z1", MeshNodeState::Active, &["github", "slack"]),
            node_with_caps("n2", "z2", MeshNodeState::Active, &["jira"]),
        ];
        let t = MeshTopology::from_nodes_and_edges(nodes, vec![]);
        let args = MeshAvailabilityArgs {
            connector: "github".to_owned(),
            operation: None,
            zone: None,
        };
        let result = mesh_availability(&t, &args);
        assert_eq!(result.zones_available, vec!["z1"]);
        assert_eq!(result.zones_unavailable, vec!["z2"]);
    }

    #[test]
    fn availability_with_capabilities_no_match() {
        let nodes = vec![
            node_with_caps("n1", "z1", MeshNodeState::Active, &["jira"]),
            node_with_caps("n2", "z2", MeshNodeState::Active, &["slack"]),
        ];
        let t = MeshTopology::from_nodes_and_edges(nodes, vec![]);
        let args = MeshAvailabilityArgs {
            connector: "github".to_owned(),
            operation: None,
            zone: None,
        };
        let result = mesh_availability(&t, &args);
        assert!(!result.is_available());
        assert!(result.placement_recommendation.is_none());
    }

    #[test]
    fn availability_recommendation_single_zone() {
        let nodes = vec![node("n1", "z1", MeshNodeState::Active)];
        let t = MeshTopology::from_nodes_and_edges(nodes, vec![]);
        let args = MeshAvailabilityArgs {
            connector: "github".to_owned(),
            operation: None,
            zone: None,
        };
        let result = mesh_availability(&t, &args);
        let rec = result.placement_recommendation.unwrap();
        assert_eq!(rec.preferred_zone, "z1");
        assert!(rec.reason.contains("only available zone"));
        assert!(rec.alternatives.is_empty());
    }

    #[test]
    fn availability_recommendation_multi_zone() {
        let nodes = vec![
            node("n1", "z1", MeshNodeState::Active),
            node("n2", "z1", MeshNodeState::Active),
            node("n3", "z2", MeshNodeState::Active),
        ];
        let t = MeshTopology::from_nodes_and_edges(nodes, vec![]);
        let args = MeshAvailabilityArgs {
            connector: "github".to_owned(),
            operation: None,
            zone: None,
        };
        let result = mesh_availability(&t, &args);
        let rec = result.placement_recommendation.unwrap();
        // z1 has 2 active nodes, z2 has 1, both at 100% ratio but z1 comes first alphabetically
        assert!(rec.has_alternatives());
        assert_eq!(rec.viable_zone_count(), 2);
    }

    #[test]
    fn availability_recommendation_prefers_healthier_zone() {
        let nodes = vec![
            node("n1", "z1", MeshNodeState::Active),
            node("n2", "z1", MeshNodeState::Offline),
            node("n3", "z2", MeshNodeState::Active),
        ];
        let t = MeshTopology::from_nodes_and_edges(nodes, vec![]);
        let args = MeshAvailabilityArgs {
            connector: "github".to_owned(),
            operation: None,
            zone: None,
        };
        let result = mesh_availability(&t, &args);
        let rec = result.placement_recommendation.unwrap();
        // z2 has 100% health ratio, z1 has 50%
        assert_eq!(rec.preferred_zone, "z2");
    }

    #[test]
    fn availability_empty_topology() {
        let t = MeshTopology::empty();
        let args = MeshAvailabilityArgs {
            connector: "github".to_owned(),
            operation: None,
            zone: None,
        };
        let result = mesh_availability(&t, &args);
        assert!(!result.is_available());
        assert!(result.placement_recommendation.is_none());
    }

    #[test]
    fn availability_draining_node_not_available() {
        let nodes = vec![node("n1", "z1", MeshNodeState::Draining)];
        let t = MeshTopology::from_nodes_and_edges(nodes, vec![]);
        let args = MeshAvailabilityArgs {
            connector: "github".to_owned(),
            operation: None,
            zone: None,
        };
        let result = mesh_availability(&t, &args);
        assert!(!result.is_available());
    }

    #[test]
    fn availability_joining_node_not_available() {
        let nodes = vec![node("n1", "z1", MeshNodeState::Joining)];
        let t = MeshTopology::from_nodes_and_edges(nodes, vec![]);
        let args = MeshAvailabilityArgs {
            connector: "github".to_owned(),
            operation: None,
            zone: None,
        };
        let result = mesh_availability(&t, &args);
        assert!(!result.is_available());
    }

    // ── format_status_toon() tests ──────────────────────────────────

    #[test]
    fn format_status_toon_empty() {
        let lines = format_status_toon(&[], false);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("No mesh zones found"));
    }

    #[test]
    fn format_status_toon_single_zone() {
        let zones = vec![MeshZoneStatus::from_nodes(
            "prod",
            &[
                node("n1", "prod", MeshNodeState::Active),
                node("n2", "prod", MeshNodeState::Active),
            ],
        )];
        let lines = format_status_toon(&zones, false);
        assert!(lines.len() >= 4); // summary, blank, header, separator, row
        assert!(lines[0].contains("1 zone(s)"));
        assert!(lines[0].contains("2 node(s)"));
    }

    #[test]
    fn format_status_toon_multi_zone() {
        let zones = vec![
            MeshZoneStatus::from_nodes("us-east", &[node("n1", "us-east", MeshNodeState::Active)]),
            MeshZoneStatus::from_nodes(
                "eu-west",
                &[node("n2", "eu-west", MeshNodeState::Draining)],
            ),
        ];
        let lines = format_status_toon(&zones, false);
        assert!(lines[0].contains("2 zone(s)"));
    }

    #[test]
    fn format_status_toon_verbose() {
        let zones = vec![MeshZoneStatus::from_nodes(
            "prod",
            &[
                node("n1", "prod", MeshNodeState::Active),
                node("n2", "prod", MeshNodeState::Offline),
            ],
        )];
        let lines = format_status_toon(&zones, true);
        let text = lines.join("\n");
        assert!(text.contains("health ratio"));
        assert!(text.contains("offline node"));
    }

    #[test]
    fn format_status_toon_contains_header() {
        let zones = vec![MeshZoneStatus::from_nodes(
            "z",
            &[node("n1", "z", MeshNodeState::Active)],
        )];
        let lines = format_status_toon(&zones, false);
        let text = lines.join("\n");
        assert!(text.contains("Zone"));
        assert!(text.contains("Nodes"));
        assert!(text.contains("Active"));
        assert!(text.contains("Policy"));
    }

    // ── format_nodes_toon() tests ───────────────────────────────────

    #[test]
    fn format_nodes_toon_empty() {
        let lines = format_nodes_toon(&[]);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("No mesh nodes found"));
    }

    #[test]
    fn format_nodes_toon_single_node() {
        let nodes = vec![node("n1", "z1", MeshNodeState::Active)];
        let lines = format_nodes_toon(&nodes);
        assert!(lines.len() >= 4);
        assert!(lines[0].contains("1 node(s)"));
    }

    #[test]
    fn format_nodes_toon_with_capabilities() {
        let nodes = vec![node_with_caps(
            "n1",
            "z1",
            MeshNodeState::Active,
            &["github", "slack"],
        )];
        let lines = format_nodes_toon(&nodes);
        let text = lines.join("\n");
        assert!(text.contains("github"));
        assert!(text.contains("slack"));
    }

    #[test]
    fn format_nodes_toon_no_capabilities() {
        let nodes = vec![node("n1", "z1", MeshNodeState::Active)];
        let lines = format_nodes_toon(&nodes);
        // The row line for caps should show "-"
        let last_data_line = &lines[lines.len() - 1];
        assert!(last_data_line.contains('-'));
    }

    #[test]
    fn format_nodes_toon_with_last_seen() {
        let nodes = vec![
            MeshNodeInfo::new("n1", "z1", MeshNodeState::Active, "10.0.0.1").with_last_seen(12345),
        ];
        let lines = format_nodes_toon(&nodes);
        let text = lines.join("\n");
        assert!(text.contains("t=12345"));
    }

    #[test]
    fn format_nodes_toon_never_seen() {
        let nodes = vec![node("n1", "z1", MeshNodeState::Active)];
        let lines = format_nodes_toon(&nodes);
        let text = lines.join("\n");
        assert!(text.contains("never"));
    }

    #[test]
    fn format_nodes_toon_contains_header() {
        let nodes = vec![node("n1", "z1", MeshNodeState::Active)];
        let lines = format_nodes_toon(&nodes);
        let text = lines.join("\n");
        assert!(text.contains("Node ID"));
        assert!(text.contains("Zone"));
        assert!(text.contains("State"));
        assert!(text.contains("Address"));
    }

    // ── format_topology_toon() tests ────────────────────────────────

    #[test]
    fn format_topology_toon_empty() {
        let t = MeshTopology::empty();
        let lines = format_topology_toon(&t);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("Empty mesh topology"));
    }

    #[test]
    fn format_topology_toon_basic() {
        let t = sample_topology();
        let lines = format_topology_toon(&t);
        let text = lines.join("\n");
        assert!(text.contains("5 node(s)"));
        assert!(text.contains("4 edge(s)"));
        assert!(text.contains("Zones:"));
        assert!(text.contains("Nodes:"));
        assert!(text.contains("Edges:"));
    }

    #[test]
    fn format_topology_toon_healthy_marker() {
        let nodes = vec![
            node("n1", "z", MeshNodeState::Active),
            node("n2", "z", MeshNodeState::Active),
        ];
        let edges = vec![edge("n1", "n2", true)];
        let t = MeshTopology::from_nodes_and_edges(nodes, edges);
        let lines = format_topology_toon(&t);
        let text = lines.join("\n");
        assert!(text.contains("[+]"));
    }

    #[test]
    fn format_topology_toon_unhealthy_marker() {
        let nodes = vec![
            node("n1", "z1", MeshNodeState::Active),
            node("n2", "z2", MeshNodeState::Active),
        ];
        let edges = vec![edge("n1", "n2", false)];
        let t = MeshTopology::from_nodes_and_edges(nodes, edges);
        let lines = format_topology_toon(&t);
        let text = lines.join("\n");
        assert!(text.contains("[!]"));
    }

    #[test]
    fn format_topology_toon_split_brain_warning() {
        let nodes = vec![
            node("n1", "z1", MeshNodeState::Active),
            node("n2", "z2", MeshNodeState::Active),
        ];
        let edges = vec![edge("n1", "n2", false)];
        let t = MeshTopology::from_nodes_and_edges(nodes, edges);
        let lines = format_topology_toon(&t);
        let text = lines.join("\n");
        assert!(text.contains("WARNING"));
        assert!(text.contains("split-brain"));
    }

    #[test]
    fn format_topology_toon_no_edges() {
        let nodes = vec![node("n1", "z", MeshNodeState::Active)];
        let t = MeshTopology::from_nodes_and_edges(nodes, vec![]);
        let lines = format_topology_toon(&t);
        let text = lines.join("\n");
        assert!(!text.contains("Edges:"));
    }

    // ── format_availability_toon() tests ────────────────────────────

    #[test]
    fn format_availability_toon_available() {
        let r = MeshAvailabilityResult::new("github")
            .with_available_zone("us-east")
            .with_recommendation(PlacementRecommendation::new("us-east", "only zone", vec![]));
        let lines = format_availability_toon(&r);
        let text = lines.join("\n");
        assert!(text.contains("available in 1 zone(s)"));
        assert!(text.contains("[+] us-east"));
        assert!(text.contains("Recommendation"));
    }

    #[test]
    fn format_availability_toon_not_available() {
        let r = MeshAvailabilityResult::new("github").with_unavailable_zone("eu-west");
        let lines = format_availability_toon(&r);
        let text = lines.join("\n");
        assert!(text.contains("NOT available"));
        assert!(text.contains("[-] eu-west"));
    }

    #[test]
    fn format_availability_toon_with_operation() {
        let r = MeshAvailabilityResult::new("github")
            .with_operation("list_repos")
            .with_available_zone("z1");
        let lines = format_availability_toon(&r);
        assert!(lines[0].contains("github:list_repos"));
    }

    #[test]
    fn format_availability_toon_recommendation_with_alternatives() {
        let r = MeshAvailabilityResult::new("github")
            .with_available_zone("z1")
            .with_available_zone("z2")
            .with_recommendation(PlacementRecommendation::new(
                "z1",
                "best",
                vec!["z2".to_owned()],
            ));
        let lines = format_availability_toon(&r);
        let text = lines.join("\n");
        assert!(text.contains("Alternatives: z2"));
    }

    #[test]
    fn format_availability_toon_no_recommendation() {
        let r = MeshAvailabilityResult::new("github").with_unavailable_zone("z1");
        let lines = format_availability_toon(&r);
        let text = lines.join("\n");
        assert!(!text.contains("Recommendation"));
    }

    // ── JSON output tests ───────────────────────────────────────────

    #[test]
    fn json_status_empty() {
        let json = format_status_json(&[]).unwrap();
        assert!(json.is_array());
        assert_eq!(json.as_array().unwrap().len(), 0);
    }

    #[test]
    fn json_status_single_zone() {
        let zones = vec![MeshZoneStatus::from_nodes(
            "prod",
            &[node("n1", "prod", MeshNodeState::Active)],
        )];
        let json = format_status_json(&zones).unwrap();
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["zone_id"], "prod");
    }

    #[test]
    fn json_nodes_roundtrip() {
        let nodes = vec![node("n1", "z1", MeshNodeState::Active)];
        let json = format_nodes_json(&nodes).unwrap();
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["node_id"], "n1");
    }

    #[test]
    fn json_topology_structure() {
        let t = sample_topology();
        let json = format_topology_json(&t).unwrap();
        assert!(json["nodes"].is_array());
        assert!(json["edges"].is_array());
        assert!(json["zones"].is_array());
    }

    #[test]
    fn json_availability_structure() {
        let r = MeshAvailabilityResult::new("github")
            .with_operation("list_repos")
            .with_available_zone("z1");
        let json = format_availability_json(&r).unwrap();
        assert_eq!(json["connector"], "github");
        assert_eq!(json["operation"], "list_repos");
        assert!(json["zones_available"].is_array());
    }

    // ── compute_zone_statuses tests ─────────────────────────────────

    #[test]
    fn compute_zones_empty() {
        let zones = compute_zone_statuses(&[]);
        assert!(zones.is_empty());
    }

    #[test]
    fn compute_zones_single_zone_all_active() {
        let nodes = vec![
            node("n1", "z1", MeshNodeState::Active),
            node("n2", "z1", MeshNodeState::Active),
        ];
        let zones = compute_zone_statuses(&nodes);
        assert_eq!(zones.len(), 1);
        assert_eq!(zones[0].zone_id, "z1");
        assert_eq!(zones[0].node_count, 2);
        assert_eq!(zones[0].healthy_count, 2);
        assert_eq!(zones[0].policy_status, "enforcing");
    }

    #[test]
    fn compute_zones_multi_zone() {
        let nodes = vec![
            node("n1", "z1", MeshNodeState::Active),
            node("n2", "z2", MeshNodeState::Offline),
        ];
        let zones = compute_zone_statuses(&nodes);
        assert_eq!(zones.len(), 2);
    }

    #[test]
    fn compute_zones_joining_counted_as_degraded() {
        let nodes = vec![node("n1", "z1", MeshNodeState::Joining)];
        let zones = compute_zone_statuses(&nodes);
        assert_eq!(zones[0].degraded_count, 1);
        assert_eq!(zones[0].healthy_count, 0);
    }

    // ── select_preferred_zone tests ─────────────────────────────────

    #[test]
    fn select_preferred_zone_single() {
        let nodes = vec![node("n1", "z1", MeshNodeState::Active)];
        let t = MeshTopology::from_nodes_and_edges(nodes, vec![]);
        let preferred = select_preferred_zone(&t, &["z1".to_owned()]);
        assert_eq!(preferred, "z1");
    }

    #[test]
    fn select_preferred_zone_healthier_wins() {
        let nodes = vec![
            node("n1", "z1", MeshNodeState::Active),
            node("n2", "z1", MeshNodeState::Offline),
            node("n3", "z2", MeshNodeState::Active),
        ];
        let t = MeshTopology::from_nodes_and_edges(nodes, vec![]);
        let preferred = select_preferred_zone(&t, &["z1".to_owned(), "z2".to_owned()]);
        assert_eq!(preferred, "z2"); // 100% vs 50%
    }

    // ── Edge case tests ─────────────────────────────────────────────

    #[test]
    fn all_nodes_offline_mesh() {
        let nodes = vec![
            node("n1", "z1", MeshNodeState::Offline),
            node("n2", "z2", MeshNodeState::Offline),
        ];
        let t = MeshTopology::from_nodes_and_edges(nodes, vec![]);
        let args = MeshAvailabilityArgs {
            connector: "github".to_owned(),
            operation: None,
            zone: None,
        };
        let result = mesh_availability(&t, &args);
        assert!(!result.is_available());
        assert_eq!(result.zones_unavailable.len(), 2);
    }

    #[test]
    fn all_nodes_unknown_state() {
        let nodes = vec![
            node("n1", "z1", MeshNodeState::Unknown),
            node("n2", "z2", MeshNodeState::Unknown),
        ];
        let t = MeshTopology::from_nodes_and_edges(nodes, vec![]);
        let args = MeshAvailabilityArgs {
            connector: "github".to_owned(),
            operation: None,
            zone: None,
        };
        let result = mesh_availability(&t, &args);
        assert!(!result.is_available());
    }

    #[test]
    fn mixed_capability_nodes_in_same_zone() {
        let nodes = vec![
            node_with_caps("n1", "z1", MeshNodeState::Active, &["jira"]),
            node_with_caps("n2", "z1", MeshNodeState::Active, &["github"]),
        ];
        let t = MeshTopology::from_nodes_and_edges(nodes, vec![]);

        let github_args = MeshAvailabilityArgs {
            connector: "github".to_owned(),
            operation: None,
            zone: None,
        };
        let result = mesh_availability(&t, &github_args);
        assert!(result.is_available());
        assert_eq!(result.zones_available, vec!["z1"]);

        let jira_args = MeshAvailabilityArgs {
            connector: "jira".to_owned(),
            operation: None,
            zone: None,
        };
        let result = mesh_availability(&t, &jira_args);
        assert!(result.is_available());
    }

    #[test]
    fn large_mesh_performance() {
        // Verify that basic operations work with many nodes.
        let mut nodes = Vec::new();
        for i in 0..100 {
            let zone = format!("z{}", i % 10);
            let state = if i % 5 == 0 {
                MeshNodeState::Offline
            } else {
                MeshNodeState::Active
            };
            nodes.push(node(&format!("n{i}"), &zone, state));
        }
        let t = MeshTopology::from_nodes_and_edges(nodes, vec![]);
        assert_eq!(t.node_count(), 100);
        assert_eq!(t.zones.len(), 10);

        let args = MeshStatusArgs::default();
        let zones = mesh_status(&t, &args);
        assert_eq!(zones.len(), 10);
    }

    #[test]
    fn topology_with_self_loop_edge() {
        let nodes = vec![node("n1", "z1", MeshNodeState::Active)];
        let edges = vec![edge("n1", "n1", true)];
        let t = MeshTopology::from_nodes_and_edges(nodes, edges);
        assert_eq!(t.edges_for_node("n1").len(), 1);
    }

    #[test]
    fn topology_with_duplicate_edges() {
        let nodes = vec![
            node("n1", "z1", MeshNodeState::Active),
            node("n2", "z1", MeshNodeState::Active),
        ];
        let edges = vec![edge("n1", "n2", true), edge("n1", "n2", false)];
        let t = MeshTopology::from_nodes_and_edges(nodes, edges);
        assert_eq!(t.edge_count(), 2);
        assert_eq!(t.healthy_edge_count(), 1);
        assert_eq!(t.unhealthy_edge_count(), 1);
    }

    #[test]
    fn zone_status_from_nodes_with_joining() {
        let nodes = vec![
            node("n1", "z", MeshNodeState::Active),
            node("n2", "z", MeshNodeState::Joining),
        ];
        let z = MeshZoneStatus::from_nodes("z", &nodes);
        assert_eq!(z.degraded_count, 1);
        assert_eq!(z.healthy_count, 1);
        assert_eq!(z.policy_status, "degraded");
    }

    #[test]
    fn format_status_toon_verbose_no_offline() {
        let zones = vec![MeshZoneStatus::from_nodes(
            "z",
            &[node("n1", "z", MeshNodeState::Active)],
        )];
        let lines = format_status_toon(&zones, true);
        let text = lines.join("\n");
        assert!(text.contains("health ratio: 100.0%"));
        // Should not mention offline when there are none.
        assert!(!text.contains("offline node"));
    }

    #[test]
    fn format_topology_toon_with_latency() {
        let nodes = vec![
            node("n1", "z", MeshNodeState::Active),
            node("n2", "z", MeshNodeState::Active),
        ];
        let edges = vec![edge("n1", "n2", true).with_latency(42)];
        let t = MeshTopology::from_nodes_and_edges(nodes, edges);
        let lines = format_topology_toon(&t);
        let text = lines.join("\n");
        assert!(text.contains("42ms"));
    }

    #[test]
    fn mesh_nodes_args_default() {
        let args = MeshNodesArgs::default();
        assert!(args.zone.is_none());
        assert!(args.state_filter.is_none());
        assert!(args.format.is_none());
    }

    #[test]
    fn mesh_topology_args_default() {
        let args = MeshTopologyArgs::default();
        assert!(args.zone.is_none());
        assert!(!args.include_edges);
    }

    #[test]
    fn mesh_status_args_default() {
        let args = MeshStatusArgs::default();
        assert!(args.zone.is_none());
        assert!(!args.verbose);
        assert!(!args.include_connectivity);
    }
}
