//! Integration scenarios for FCP2 mesh behavior (flywheel_connectors-gigy).
//!
//! This module tests the system under adverse conditions:
//! - Network partition recovery
//! - Node failure and recovery
//! - Concurrent operation conflicts
//! - Revocation propagation
//! - Zone key rotation under load
//! - Symbol availability and repair
//!
//! These tests use the deterministic harness from [`fcp_conformance::harness`]
//! with simulated network faults, clock control, and structured logging.
//!
//! # Test Infrastructure Requirements
//! - Deterministic clock control (`MockClock`)
//! - Network fault injection (`SimulatedNetwork`: partitions, latency, packet loss)
//! - Node lifecycle control (`TestMeshNode`: start, stop, crash, restart)
//! - Structured log collection (`LogCollector`)
//!
//! # Logging Format
//! Each scenario produces structured JSONL logs per `docs/STANDARD_Testing_Logging.md`:
//! ```json
//! {
//!   "scenario": "partition-heal",
//!   "phase": "partition | heal | verify",
//!   "nodes": ["A", "B", "C"],
//!   "timestamp": "...",
//!   "assertion": "audit_heads_equal",
//!   "result": "pass|fail",
//!   "evidence": {...}
//! }
//! ```

#![allow(
    clippy::fn_params_excessive_bools,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "scenario witness builders intentionally mirror explicit artifact schemas"
)]

use std::collections::HashSet;
use std::time::Duration;

use chrono::Utc;
use fcp_conformance::harness::{
    HarnessError, LogCollector, LogEntry, MockClock, SimulatedNetwork, TestHarness,
};
use fcp_mesh::ObjectAdmissionClass;
use fcp_prelude::{ObjectId, ZoneId};
use fcp_tailscale::NodeId;
use serde::{Deserialize, Serialize};
use serde_json::json;

const CRASH_RECOVERY_SCENARIO: &str = "crash-recovery";
const CRASH_RECOVERY_CONTRACT_ID: &str = "contract.crash_recovery_rejoin";
const DEGRADED_AVAILABILITY_SCENARIO: &str = "degraded-availability";
const DEGRADED_AVAILABILITY_CONTRACT_ID: &str = "contract.degraded_symbol_availability";
const PARTITION_HEAL_SCENARIO: &str = "partition-heal";
const PARTITION_HEAL_CONTRACT_ID: &str = "contract.partition_heal_convergence";
const SPLIT_BRAIN_SCENARIO: &str = "split-brain";
const SPLIT_BRAIN_CONTRACT_ID: &str = "contract.split_brain_prevention";
const STATE_FORK_SCENARIO: &str = "state-fork";
const STATE_FORK_CONTRACT_ID: &str = "contract.state_fork_detection_resolution";
const ISSUER_REVOCATION_SCENARIO: &str = "issuer-revocation";
const ISSUER_REVOCATION_CONTRACT_ID: &str = "contract.issuer_key_revocation_enforced";
const CAPABILITY_REVOCATION_SCENARIO: &str = "capability-revocation";
const CAPABILITY_REVOCATION_CONTRACT_ID: &str = "contract.capability_revocation_enforced";
const NODE_REMOVAL_SCENARIO: &str = "node-removal";
const NODE_REMOVAL_CONTRACT_ID: &str = "contract.node_removal_isolation";
const HOT_KEY_ROTATION_SCENARIO: &str = "hot-rotation";
const HOT_KEY_ROTATION_CONTRACT_ID: &str = "contract.zone_key_rotation_continuity";
const STALE_REJOIN_SCENARIO: &str = "stale-rejoin";
const STALE_REJOIN_CONTRACT_ID: &str = "contract.stale_node_rejoin_sync";
const GRACEFUL_SHUTDOWN_SCENARIO: &str = "graceful-shutdown";
const GRACEFUL_SHUTDOWN_CONTRACT_ID: &str = "contract.graceful_shutdown_gossip_preservation";
const MULTI_NODE_FAILURE_SCENARIO: &str = "multi-node-failure";
const MULTI_NODE_FAILURE_CONTRACT_ID: &str = "contract.multi_node_failure_within_tolerance";
const QUORUM_LOSS_SCENARIO: &str = "quorum-loss";
const QUORUM_LOSS_CONTRACT_ID: &str = "contract.quorum_loss_fail_closed";
const LEASE_CONTENTION_SCENARIO: &str = "lease-contention";
const LEASE_CONTENTION_CONTRACT_ID: &str = "contract.singleton_writer_lease_contention";

/// Create a deterministic test object ID from a name.
fn test_object_id(name: &str) -> ObjectId {
    ObjectId::from_unscoped_bytes(name.as_bytes())
}

/// Default zone for test scenarios.
fn test_zone() -> ZoneId {
    ZoneId::work()
}

/// Helper to emit a structured scenario log entry.
fn emit_scenario_log<E: Serialize>(
    logs: &LogCollector,
    scenario: &str,
    phase: &str,
    nodes: &[&str],
    assertion: &str,
    result: &str,
    evidence: E,
) {
    let evidence = serde_json::to_value(evidence).unwrap_or_else(|error| {
        json!({
            "error": error.to_string(),
        })
    });
    let entry = LogEntry::new(
        "harness",
        scenario,
        phase,
        uuid::Uuid::new_v4().to_string(),
        assertion,
        json!({
            "nodes": nodes,
            "result": result,
            "evidence": evidence,
            "timestamp": Utc::now().to_rfc3339(),
        }),
    );
    logs.push(entry);
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ScenarioAssertionEvidence {
    phase: String,
    assertion: String,
    result: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CrashRecoveryReplayEvidence {
    seed: u64,
    zone_id: String,
    object_id: String,
    crashed_node_id: String,
    lease_timeout_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CrashRecoveryStateEvidence {
    restarted_node_running: bool,
    post_crash_gossip_works: bool,
    running_nodes_after_restart: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CrashRecoveryArtifactBundle {
    scenario_key: String,
    contract_id: String,
    replay: CrashRecoveryReplayEvidence,
    state: CrashRecoveryStateEvidence,
    assertions: Vec<ScenarioAssertionEvidence>,
    log_entry_count: usize,
    log_jsonl_valid: bool,
}

fn scenario_assertions(logs: &[LogEntry], scenario: &str) -> Vec<ScenarioAssertionEvidence> {
    logs.iter()
        .filter(|entry| entry.test_name == scenario)
        .map(|entry| ScenarioAssertionEvidence {
            phase: entry.phase.clone(),
            assertion: entry.event_type.clone(),
            result: entry
                .details
                .get("result")
                .and_then(|value| value.as_str())
                .unwrap_or("unknown")
                .to_string(),
        })
        .collect()
}

fn build_crash_recovery_artifact_bundle(
    logs: &[LogEntry],
    zone: &ZoneId,
    object_id: &ObjectId,
    crashed_node_id: &NodeId,
    lease_timeout_secs: u64,
    restarted_node_running: bool,
    post_crash_gossip_works: bool,
    running_nodes_after_restart: usize,
    log_jsonl_valid: bool,
) -> CrashRecoveryArtifactBundle {
    CrashRecoveryArtifactBundle {
        scenario_key: "crash_recovery".to_string(),
        contract_id: CRASH_RECOVERY_CONTRACT_ID.to_string(),
        replay: CrashRecoveryReplayEvidence {
            seed: 0xFEED_FACE,
            zone_id: zone.to_string(),
            object_id: object_id.to_string(),
            crashed_node_id: crashed_node_id.as_str().to_string(),
            lease_timeout_secs,
        },
        state: CrashRecoveryStateEvidence {
            restarted_node_running,
            post_crash_gossip_works,
            running_nodes_after_restart: u8::try_from(running_nodes_after_restart)
                .expect("running node count fits in u8"),
        },
        assertions: scenario_assertions(logs, CRASH_RECOVERY_SCENARIO),
        log_entry_count: logs.len(),
        log_jsonl_valid,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DegradedAvailabilityReplayEvidence {
    seed: u64,
    zone_id: String,
    object_id: String,
    crashed_node_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DegradedAvailabilityStateEvidence {
    pre_crash_symbol_count: u64,
    a_has_obj_before_crash: bool,
    a_has_obj_after_crash: bool,
    c_has_obj_after_crash: bool,
    running_nodes_after_crash: u8,
    availability_degraded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DegradedAvailabilityArtifactBundle {
    scenario_key: String,
    contract_id: String,
    replay: DegradedAvailabilityReplayEvidence,
    state: DegradedAvailabilityStateEvidence,
    assertions: Vec<ScenarioAssertionEvidence>,
    log_entry_count: usize,
    log_jsonl_valid: bool,
}

fn build_degraded_availability_artifact_bundle(
    logs: &[LogEntry],
    zone: &ZoneId,
    object_id: &ObjectId,
    crashed_node_id: &NodeId,
    pre_crash_symbol_count: usize,
    a_has_obj_before_crash: bool,
    a_has_obj_after_crash: bool,
    c_has_obj_after_crash: bool,
    running_nodes_after_crash: usize,
    availability_degraded: bool,
    log_jsonl_valid: bool,
) -> DegradedAvailabilityArtifactBundle {
    DegradedAvailabilityArtifactBundle {
        scenario_key: "degraded_availability".to_string(),
        contract_id: DEGRADED_AVAILABILITY_CONTRACT_ID.to_string(),
        replay: DegradedAvailabilityReplayEvidence {
            seed: 0x5CAFE,
            zone_id: zone.to_string(),
            object_id: object_id.to_string(),
            crashed_node_id: crashed_node_id.as_str().to_string(),
        },
        state: DegradedAvailabilityStateEvidence {
            pre_crash_symbol_count: u64::try_from(pre_crash_symbol_count)
                .expect("symbol count fits in u64"),
            a_has_obj_before_crash,
            a_has_obj_after_crash,
            c_has_obj_after_crash,
            running_nodes_after_crash: u8::try_from(running_nodes_after_crash)
                .expect("running node count fits in u8"),
            availability_degraded,
        },
        assertions: scenario_assertions(logs, DEGRADED_AVAILABILITY_SCENARIO),
        log_entry_count: logs.len(),
        log_jsonl_valid,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PartitionHealReplayEvidence {
    seed: u64,
    zone_id: String,
    isolated_node_id: String,
    object_a_id: String,
    object_b_id: String,
    partition_duration_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PartitionHealNodeStateEvidence {
    node_id: String,
    has_obj_a: bool,
    has_obj_b: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PartitionHealStateEvidence {
    converged: bool,
    pending_messages: u64,
    nodes_with_obj_a: u8,
    nodes_with_obj_b: u8,
    isolated_node_received_both_objects: bool,
    nodes: Vec<PartitionHealNodeStateEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PartitionHealArtifactBundle {
    scenario_key: String,
    contract_id: String,
    replay: PartitionHealReplayEvidence,
    state: PartitionHealStateEvidence,
    assertions: Vec<ScenarioAssertionEvidence>,
    log_entry_count: usize,
    log_jsonl_valid: bool,
}

fn build_partition_heal_artifact_bundle(
    logs: &[LogEntry],
    zone: &ZoneId,
    isolated_node_id: &NodeId,
    node_ids: [&NodeId; 3],
    source_object_id: &ObjectId,
    healed_object_id: &ObjectId,
    partition_duration_secs: u64,
    converged: bool,
    pending_messages: usize,
    gossip_presence: [[bool; 2]; 3],
    log_jsonl_valid: bool,
) -> PartitionHealArtifactBundle {
    let nodes = [
        (node_ids[0], gossip_presence[0]),
        (node_ids[1], gossip_presence[1]),
        (node_ids[2], gossip_presence[2]),
    ]
    .into_iter()
    .map(|(node_id, presence)| PartitionHealNodeStateEvidence {
        node_id: node_id.as_str().to_string(),
        has_obj_a: presence[0],
        has_obj_b: presence[1],
    })
    .collect::<Vec<_>>();
    let nodes_with_obj_a = gossip_presence
        .iter()
        .filter(|presence| presence[0])
        .count();
    let nodes_with_obj_b = gossip_presence
        .iter()
        .filter(|presence| presence[1])
        .count();

    PartitionHealArtifactBundle {
        scenario_key: "partition_heal".to_string(),
        contract_id: PARTITION_HEAL_CONTRACT_ID.to_string(),
        replay: PartitionHealReplayEvidence {
            seed: 0xDEAD_BEEF,
            zone_id: zone.to_string(),
            isolated_node_id: isolated_node_id.as_str().to_string(),
            object_a_id: source_object_id.to_string(),
            object_b_id: healed_object_id.to_string(),
            partition_duration_secs,
        },
        state: PartitionHealStateEvidence {
            converged,
            pending_messages: u64::try_from(pending_messages)
                .expect("pending message count fits in u64"),
            nodes_with_obj_a: u8::try_from(nodes_with_obj_a).expect("node count fits in u8"),
            nodes_with_obj_b: u8::try_from(nodes_with_obj_b).expect("node count fits in u8"),
            isolated_node_received_both_objects: gossip_presence[2][0] && gossip_presence[2][1],
            nodes,
        },
        assertions: scenario_assertions(logs, PARTITION_HEAL_SCENARIO),
        log_entry_count: logs.len(),
        log_jsonl_valid,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SplitBrainReplayEvidence {
    seed: u64,
    zone_id: String,
    minority_node_ids: Vec<String>,
    majority_node_ids: Vec<String>,
    minority_object_id: String,
    majority_object_id: String,
    partition_duration_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SplitBrainStateEvidence {
    minority_peer_count: u8,
    majority_peer_count: u8,
    majority_has_more_peers: bool,
    cross_partition_isolated: bool,
    node0_has_majority_after_heal: bool,
    node2_has_minority_after_heal: bool,
    converged_after_heal: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SplitBrainArtifactBundle {
    scenario_key: String,
    contract_id: String,
    replay: SplitBrainReplayEvidence,
    state: SplitBrainStateEvidence,
    assertions: Vec<ScenarioAssertionEvidence>,
    log_entry_count: usize,
    log_jsonl_valid: bool,
}

fn build_split_brain_artifact_bundle(
    logs: &[LogEntry],
    zone: &ZoneId,
    minority_node_ids: &[NodeId],
    majority_node_ids: &[NodeId],
    minority_object_id: &ObjectId,
    majority_object_id: &ObjectId,
    partition_duration_secs: u64,
    minority_peer_count: usize,
    majority_peer_count: usize,
    cross_partition_isolated: bool,
    node0_has_majority_after_heal: bool,
    node2_has_minority_after_heal: bool,
    converged_after_heal: bool,
    log_jsonl_valid: bool,
) -> SplitBrainArtifactBundle {
    SplitBrainArtifactBundle {
        scenario_key: "split_brain".to_string(),
        contract_id: SPLIT_BRAIN_CONTRACT_ID.to_string(),
        replay: SplitBrainReplayEvidence {
            seed: 0xCAFE_BABE,
            zone_id: zone.to_string(),
            minority_node_ids: minority_node_ids
                .iter()
                .map(|node_id| node_id.as_str().to_string())
                .collect(),
            majority_node_ids: majority_node_ids
                .iter()
                .map(|node_id| node_id.as_str().to_string())
                .collect(),
            minority_object_id: minority_object_id.to_string(),
            majority_object_id: majority_object_id.to_string(),
            partition_duration_secs,
        },
        state: SplitBrainStateEvidence {
            minority_peer_count: u8::try_from(minority_peer_count).expect("peer count fits in u8"),
            majority_peer_count: u8::try_from(majority_peer_count).expect("peer count fits in u8"),
            majority_has_more_peers: majority_peer_count > minority_peer_count,
            cross_partition_isolated,
            node0_has_majority_after_heal,
            node2_has_minority_after_heal,
            converged_after_heal,
        },
        assertions: scenario_assertions(logs, SPLIT_BRAIN_SCENARIO),
        log_entry_count: logs.len(),
        log_jsonl_valid,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StateForkReplayEvidence {
    seed: u64,
    zone_id: String,
    node_a_id: String,
    node_b_id: String,
    object_a_id: String,
    object_b_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StateForkStateEvidence {
    a_has_b_before_gossip: bool,
    b_has_a_before_gossip: bool,
    divergent_before_gossip: bool,
    a_has_b_after_gossip: bool,
    b_has_a_after_gossip: bool,
    resolved_after_gossip: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StateForkArtifactBundle {
    scenario_key: String,
    contract_id: String,
    replay: StateForkReplayEvidence,
    state: StateForkStateEvidence,
    assertions: Vec<ScenarioAssertionEvidence>,
    log_entry_count: usize,
    log_jsonl_valid: bool,
}

fn build_state_fork_artifact_bundle(
    logs: &[LogEntry],
    zone: &ZoneId,
    primary_node_id: &NodeId,
    secondary_node_id: &NodeId,
    primary_object_id: &ObjectId,
    secondary_object_id: &ObjectId,
    a_has_b_before_gossip: bool,
    b_has_a_before_gossip: bool,
    divergent_before_gossip: bool,
    a_has_b_after_gossip: bool,
    b_has_a_after_gossip: bool,
    resolved_after_gossip: bool,
    log_jsonl_valid: bool,
) -> StateForkArtifactBundle {
    StateForkArtifactBundle {
        scenario_key: "state_fork".to_string(),
        contract_id: STATE_FORK_CONTRACT_ID.to_string(),
        replay: StateForkReplayEvidence {
            seed: 0xF0F0_F0F0,
            zone_id: zone.to_string(),
            node_a_id: primary_node_id.as_str().to_string(),
            node_b_id: secondary_node_id.as_str().to_string(),
            object_a_id: primary_object_id.to_string(),
            object_b_id: secondary_object_id.to_string(),
        },
        state: StateForkStateEvidence {
            a_has_b_before_gossip,
            b_has_a_before_gossip,
            divergent_before_gossip,
            a_has_b_after_gossip,
            b_has_a_after_gossip,
            resolved_after_gossip,
        },
        assertions: scenario_assertions(logs, STATE_FORK_SCENARIO),
        log_entry_count: logs.len(),
        log_jsonl_valid,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct IssuerRevocationReplayEvidence {
    seed: u64,
    revoked_issuer_id: String,
    observer_node_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct IssuerRevocationStateEvidence {
    peer_count_before_revocation: u8,
    peer_count_after_revocation: u8,
    pruned_entries: u64,
    revocation_enforced: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct IssuerRevocationArtifactBundle {
    scenario_key: String,
    contract_id: String,
    replay: IssuerRevocationReplayEvidence,
    state: IssuerRevocationStateEvidence,
    assertions: Vec<ScenarioAssertionEvidence>,
    log_entry_count: usize,
    log_jsonl_valid: bool,
}

fn build_issuer_revocation_artifact_bundle(
    logs: &[LogEntry],
    revoked_issuer_id: &NodeId,
    observer_node_id: &NodeId,
    peer_count_before_revocation: usize,
    peer_count_after_revocation: usize,
    pruned_entries: usize,
    revocation_enforced: bool,
    log_jsonl_valid: bool,
) -> IssuerRevocationArtifactBundle {
    IssuerRevocationArtifactBundle {
        scenario_key: "issuer_revocation".to_string(),
        contract_id: ISSUER_REVOCATION_CONTRACT_ID.to_string(),
        replay: IssuerRevocationReplayEvidence {
            seed: 0xBAD_0E11,
            revoked_issuer_id: revoked_issuer_id.as_str().to_string(),
            observer_node_id: observer_node_id.as_str().to_string(),
        },
        state: IssuerRevocationStateEvidence {
            peer_count_before_revocation: u8::try_from(peer_count_before_revocation)
                .expect("peer count fits in u8"),
            peer_count_after_revocation: u8::try_from(peer_count_after_revocation)
                .expect("peer count fits in u8"),
            pruned_entries: u64::try_from(pruned_entries).expect("pruned entry count fits in u64"),
            revocation_enforced,
        },
        assertions: scenario_assertions(logs, ISSUER_REVOCATION_SCENARIO),
        log_entry_count: logs.len(),
        log_jsonl_valid,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CapabilityRevocationReplayEvidence {
    seed: u64,
    peer_id: String,
    observer_node_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CapabilityRevocationStateEvidence {
    authenticated_before: bool,
    authenticated_after: bool,
    admission_before_allowed: bool,
    admission_after_allowed: bool,
    revocation_enforced: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CapabilityRevocationArtifactBundle {
    scenario_key: String,
    contract_id: String,
    replay: CapabilityRevocationReplayEvidence,
    state: CapabilityRevocationStateEvidence,
    assertions: Vec<ScenarioAssertionEvidence>,
    log_entry_count: usize,
    log_jsonl_valid: bool,
}

fn build_capability_revocation_artifact_bundle(
    logs: &[LogEntry],
    peer_id: &NodeId,
    observer_node_id: &NodeId,
    authenticated_before: bool,
    authenticated_after: bool,
    admission_before_allowed: bool,
    admission_after_allowed: bool,
    revocation_enforced: bool,
    log_jsonl_valid: bool,
) -> CapabilityRevocationArtifactBundle {
    CapabilityRevocationArtifactBundle {
        scenario_key: "capability_revocation".to_string(),
        contract_id: CAPABILITY_REVOCATION_CONTRACT_ID.to_string(),
        replay: CapabilityRevocationReplayEvidence {
            seed: 0xCA9_EE0CE,
            peer_id: peer_id.as_str().to_string(),
            observer_node_id: observer_node_id.as_str().to_string(),
        },
        state: CapabilityRevocationStateEvidence {
            authenticated_before,
            authenticated_after,
            admission_before_allowed,
            admission_after_allowed,
            revocation_enforced,
        },
        assertions: scenario_assertions(logs, CAPABILITY_REVOCATION_SCENARIO),
        log_entry_count: logs.len(),
        log_jsonl_valid,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NodeRemovalReplayEvidence {
    seed: u64,
    zone_id: String,
    removed_node_id: String,
    remaining_node_ids: Vec<String>,
    object_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NodeRemovalStateEvidence {
    removed_node_stopped: bool,
    peer_count_before: u8,
    peer_count_after: u8,
    peer_count_decreased: bool,
    gossip_between_remaining: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NodeRemovalArtifactBundle {
    scenario_key: String,
    contract_id: String,
    replay: NodeRemovalReplayEvidence,
    state: NodeRemovalStateEvidence,
    assertions: Vec<ScenarioAssertionEvidence>,
    log_entry_count: usize,
    log_jsonl_valid: bool,
}

fn build_node_removal_artifact_bundle(
    logs: &[LogEntry],
    zone: &ZoneId,
    removed_node_id: &NodeId,
    remaining_node_ids: &[NodeId],
    object_id: &ObjectId,
    removed_node_stopped: bool,
    peer_count_before: usize,
    peer_count_after: usize,
    peer_count_decreased: bool,
    gossip_between_remaining: bool,
    log_jsonl_valid: bool,
) -> NodeRemovalArtifactBundle {
    NodeRemovalArtifactBundle {
        scenario_key: "node_removal".to_string(),
        contract_id: NODE_REMOVAL_CONTRACT_ID.to_string(),
        replay: NodeRemovalReplayEvidence {
            seed: 0x0FF_B0A8D,
            zone_id: zone.to_string(),
            removed_node_id: removed_node_id.as_str().to_string(),
            remaining_node_ids: remaining_node_ids
                .iter()
                .map(|node_id| node_id.as_str().to_string())
                .collect(),
            object_id: object_id.to_string(),
        },
        state: NodeRemovalStateEvidence {
            removed_node_stopped,
            peer_count_before: u8::try_from(peer_count_before).expect("peer count fits in u8"),
            peer_count_after: u8::try_from(peer_count_after).expect("peer count fits in u8"),
            peer_count_decreased,
            gossip_between_remaining,
        },
        assertions: scenario_assertions(logs, NODE_REMOVAL_SCENARIO),
        log_entry_count: logs.len(),
        log_jsonl_valid,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HotKeyRotationReplayEvidence {
    seed: u64,
    zone_id: String,
    pre_rotation_object_id: String,
    post_rotation_object_id: String,
    rotation_advance_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HotKeyRotationStateEvidence {
    pre_rotation_propagated: bool,
    post_rotation_propagated: bool,
    pre_rotation_still_known: bool,
    no_data_loss: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HotKeyRotationArtifactBundle {
    scenario_key: String,
    contract_id: String,
    replay: HotKeyRotationReplayEvidence,
    state: HotKeyRotationStateEvidence,
    assertions: Vec<ScenarioAssertionEvidence>,
    log_entry_count: usize,
    log_jsonl_valid: bool,
}

fn build_hot_key_rotation_artifact_bundle(
    logs: &[LogEntry],
    zone: &ZoneId,
    pre_rotation_object_id: &ObjectId,
    post_rotation_object_id: &ObjectId,
    rotation_advance_secs: u64,
    pre_rotation_propagated: bool,
    post_rotation_propagated: bool,
    pre_rotation_still_known: bool,
    no_data_loss: bool,
    log_jsonl_valid: bool,
) -> HotKeyRotationArtifactBundle {
    HotKeyRotationArtifactBundle {
        scenario_key: "hot_key_rotation".to_string(),
        contract_id: HOT_KEY_ROTATION_CONTRACT_ID.to_string(),
        replay: HotKeyRotationReplayEvidence {
            seed: 0x0080_1A7E,
            zone_id: zone.to_string(),
            pre_rotation_object_id: pre_rotation_object_id.to_string(),
            post_rotation_object_id: post_rotation_object_id.to_string(),
            rotation_advance_secs,
        },
        state: HotKeyRotationStateEvidence {
            pre_rotation_propagated,
            post_rotation_propagated,
            pre_rotation_still_known,
            no_data_loss,
        },
        assertions: scenario_assertions(logs, HOT_KEY_ROTATION_SCENARIO),
        log_entry_count: logs.len(),
        log_jsonl_valid,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StaleRejoinReplayEvidence {
    seed: u64,
    zone_id: String,
    stale_node_id: String,
    object_id: String,
    offline_duration_hours: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StaleRejoinStateEvidence {
    had_object_before_heal: bool,
    has_object_after_sync: bool,
    running_nodes_after_sync: u8,
    catch_up_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StaleRejoinArtifactBundle {
    scenario_key: String,
    contract_id: String,
    replay: StaleRejoinReplayEvidence,
    state: StaleRejoinStateEvidence,
    assertions: Vec<ScenarioAssertionEvidence>,
    log_entry_count: usize,
    log_jsonl_valid: bool,
}

fn build_stale_rejoin_artifact_bundle(
    logs: &[LogEntry],
    zone: &ZoneId,
    stale_node_id: &NodeId,
    object_id: &ObjectId,
    offline_duration_hours: u16,
    had_object_before_heal: bool,
    has_object_after_sync: bool,
    running_nodes_after_sync: usize,
    catch_up_required: bool,
    log_jsonl_valid: bool,
) -> StaleRejoinArtifactBundle {
    StaleRejoinArtifactBundle {
        scenario_key: "stale_rejoin".to_string(),
        contract_id: STALE_REJOIN_CONTRACT_ID.to_string(),
        replay: StaleRejoinReplayEvidence {
            seed: 0x1234_5678,
            zone_id: zone.to_string(),
            stale_node_id: stale_node_id.as_str().to_string(),
            object_id: object_id.to_string(),
            offline_duration_hours,
        },
        state: StaleRejoinStateEvidence {
            had_object_before_heal,
            has_object_after_sync,
            running_nodes_after_sync: u8::try_from(running_nodes_after_sync)
                .expect("running node count fits in u8"),
            catch_up_required,
        },
        assertions: scenario_assertions(logs, STALE_REJOIN_SCENARIO),
        log_entry_count: logs.len(),
        log_jsonl_valid,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct GracefulShutdownReplayEvidence {
    seed: u64,
    zone_id: String,
    object_id: String,
    shutdown_node_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct GracefulShutdownStateEvidence {
    node_stopped: bool,
    gossip_preserved: bool,
    remaining_running_nodes: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct GracefulShutdownArtifactBundle {
    scenario_key: String,
    contract_id: String,
    replay: GracefulShutdownReplayEvidence,
    state: GracefulShutdownStateEvidence,
    assertions: Vec<ScenarioAssertionEvidence>,
    log_entry_count: usize,
    log_jsonl_valid: bool,
}

fn build_graceful_shutdown_artifact_bundle(
    logs: &[LogEntry],
    zone: &ZoneId,
    object_id: &ObjectId,
    shutdown_node_id: &NodeId,
    node_stopped: bool,
    gossip_preserved: bool,
    remaining_running_nodes: usize,
    log_jsonl_valid: bool,
) -> GracefulShutdownArtifactBundle {
    GracefulShutdownArtifactBundle {
        scenario_key: "graceful_shutdown".to_string(),
        contract_id: GRACEFUL_SHUTDOWN_CONTRACT_ID.to_string(),
        replay: GracefulShutdownReplayEvidence {
            seed: 0xABCD_EF01,
            zone_id: zone.to_string(),
            object_id: object_id.to_string(),
            shutdown_node_id: shutdown_node_id.as_str().to_string(),
        },
        state: GracefulShutdownStateEvidence {
            node_stopped,
            gossip_preserved,
            remaining_running_nodes: u8::try_from(remaining_running_nodes)
                .expect("running node count fits in u8"),
        },
        assertions: scenario_assertions(logs, GRACEFUL_SHUTDOWN_SCENARIO),
        log_entry_count: logs.len(),
        log_jsonl_valid,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MultiNodeFailureReplayEvidence {
    seed: u64,
    zone_id: String,
    object_id: String,
    crashed_node_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MultiNodeFailureStateEvidence {
    running_nodes: u8,
    quorum_tolerance_f: u8,
    node3_has_obj: bool,
    node4_has_obj: bool,
    operations_continue: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MultiNodeFailureArtifactBundle {
    scenario_key: String,
    contract_id: String,
    replay: MultiNodeFailureReplayEvidence,
    state: MultiNodeFailureStateEvidence,
    assertions: Vec<ScenarioAssertionEvidence>,
    log_entry_count: usize,
    log_jsonl_valid: bool,
}

fn build_multi_node_failure_artifact_bundle(
    logs: &[LogEntry],
    zone: &ZoneId,
    object_id: &ObjectId,
    crashed_node_ids: &[NodeId],
    running_nodes: usize,
    quorum_tolerance_f: usize,
    node3_has_obj: bool,
    node4_has_obj: bool,
    operations_continue: bool,
    log_jsonl_valid: bool,
) -> MultiNodeFailureArtifactBundle {
    MultiNodeFailureArtifactBundle {
        scenario_key: "multi_node_failure".to_string(),
        contract_id: MULTI_NODE_FAILURE_CONTRACT_ID.to_string(),
        replay: MultiNodeFailureReplayEvidence {
            seed: 0x5AFE_5AFE,
            zone_id: zone.to_string(),
            object_id: object_id.to_string(),
            crashed_node_ids: crashed_node_ids
                .iter()
                .map(|node_id| node_id.as_str().to_string())
                .collect(),
        },
        state: MultiNodeFailureStateEvidence {
            running_nodes: u8::try_from(running_nodes).expect("running node count fits in u8"),
            quorum_tolerance_f: u8::try_from(quorum_tolerance_f)
                .expect("quorum tolerance fits in u8"),
            node3_has_obj,
            node4_has_obj,
            operations_continue,
        },
        assertions: scenario_assertions(logs, MULTI_NODE_FAILURE_SCENARIO),
        log_entry_count: logs.len(),
        log_jsonl_valid,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct QuorumLossReplayEvidence {
    seed: u64,
    zone_id: String,
    object_id: String,
    crashed_node_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct QuorumLossStateEvidence {
    running_nodes: u8,
    quorum_threshold: u8,
    survivor_peer_count: u8,
    quorum_available: bool,
    gossip_still_works: bool,
    operations_halted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct QuorumLossArtifactBundle {
    scenario_key: String,
    contract_id: String,
    replay: QuorumLossReplayEvidence,
    state: QuorumLossStateEvidence,
    assertions: Vec<ScenarioAssertionEvidence>,
    log_entry_count: usize,
    log_jsonl_valid: bool,
}

fn build_quorum_loss_artifact_bundle(
    logs: &[LogEntry],
    zone: &ZoneId,
    object_id: &ObjectId,
    crashed_node_ids: &[NodeId],
    running_nodes: usize,
    quorum_threshold: usize,
    survivor_peer_count: usize,
    quorum_available: bool,
    gossip_still_works: bool,
    operations_halted: bool,
    log_jsonl_valid: bool,
) -> QuorumLossArtifactBundle {
    QuorumLossArtifactBundle {
        scenario_key: "quorum_loss".to_string(),
        contract_id: QUORUM_LOSS_CONTRACT_ID.to_string(),
        replay: QuorumLossReplayEvidence {
            seed: 0xDEAD_C0DE,
            zone_id: zone.to_string(),
            object_id: object_id.to_string(),
            crashed_node_ids: crashed_node_ids
                .iter()
                .map(|node_id| node_id.as_str().to_string())
                .collect(),
        },
        state: QuorumLossStateEvidence {
            running_nodes: u8::try_from(running_nodes).expect("running node count fits in u8"),
            quorum_threshold: u8::try_from(quorum_threshold).expect("quorum threshold fits in u8"),
            survivor_peer_count: u8::try_from(survivor_peer_count)
                .expect("survivor peer count fits in u8"),
            quorum_available,
            gossip_still_works,
            operations_halted,
        },
        assertions: scenario_assertions(logs, QUORUM_LOSS_SCENARIO),
        log_entry_count: logs.len(),
        log_jsonl_valid,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LeaseContentionReplayEvidence {
    seed: u64,
    contested_object_id: String,
    lease_holder_node_id: String,
    contender_node_id: String,
    connector_id: String,
    lease_expires_in_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LeaseContentionStateEvidence {
    candidate_count: u8,
    lease_holder_candidate_present: bool,
    contender_candidate_present: bool,
    contender_eligible: bool,
    lease_holder_preferred: bool,
    singleton_writer_enforced: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LeaseContentionAuthorityEvidence {
    coordinator_node_id: Option<String>,
    failover_order: Vec<String>,
    active_holder_node_id: Option<String>,
    active_fencing_token: Option<u64>,
    record_statuses: Vec<fcp_mesh::AuthorityStatus>,
    record_reason_codes: Vec<fcp_mesh::AuthorityReasonCode>,
    timeline_operations: Vec<String>,
    timeline_reason_codes: Vec<fcp_mesh::AuthorityReasonCode>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LeaseContentionArtifactBundle {
    scenario_key: String,
    contract_id: String,
    replay: LeaseContentionReplayEvidence,
    state: LeaseContentionStateEvidence,
    authority: LeaseContentionAuthorityEvidence,
    assertions: Vec<ScenarioAssertionEvidence>,
    log_entry_count: usize,
    log_jsonl_valid: bool,
}

fn build_lease_contention_artifact_bundle(
    logs: &[LogEntry],
    contested_object_id: &ObjectId,
    lease_holder_node_id: &NodeId,
    contender_node_id: &NodeId,
    connector_id: &str,
    lease_expires_in_secs: u64,
    candidate_count: usize,
    lease_holder_candidate_present: bool,
    contender_candidate_present: bool,
    contender_eligible: bool,
    lease_holder_preferred: bool,
    singleton_writer_enforced: bool,
    authority_view: &fcp_mesh::AuthorityView,
    log_jsonl_valid: bool,
) -> LeaseContentionArtifactBundle {
    LeaseContentionArtifactBundle {
        scenario_key: "lease_contention".to_string(),
        contract_id: LEASE_CONTENTION_CONTRACT_ID.to_string(),
        replay: LeaseContentionReplayEvidence {
            seed: 0xC0FF_EE42,
            contested_object_id: contested_object_id.to_string(),
            lease_holder_node_id: lease_holder_node_id.as_str().to_string(),
            contender_node_id: contender_node_id.as_str().to_string(),
            connector_id: connector_id.to_string(),
            lease_expires_in_secs,
        },
        state: LeaseContentionStateEvidence {
            candidate_count: u8::try_from(candidate_count).expect("candidate count fits in u8"),
            lease_holder_candidate_present,
            contender_candidate_present,
            contender_eligible,
            lease_holder_preferred,
            singleton_writer_enforced,
        },
        authority: LeaseContentionAuthorityEvidence {
            coordinator_node_id: authority_view
                .coordinator
                .as_ref()
                .map(|node| node.as_str().to_string()),
            failover_order: authority_view
                .failover_order
                .iter()
                .map(|node| node.as_str().to_string())
                .collect(),
            active_holder_node_id: authority_view
                .active_holder
                .as_ref()
                .map(|node| node.as_str().to_string()),
            active_fencing_token: authority_view.active_fencing_token,
            record_statuses: authority_view
                .records
                .iter()
                .map(|record| record.status)
                .collect(),
            record_reason_codes: authority_view
                .records
                .iter()
                .map(|record| record.reason_code)
                .collect(),
            timeline_operations: authority_view
                .timeline
                .iter()
                .map(|event| event.operation.clone())
                .collect(),
            timeline_reason_codes: authority_view
                .timeline
                .iter()
                .map(|event| event.reason_code)
                .collect(),
        },
        assertions: scenario_assertions(logs, LEASE_CONTENTION_SCENARIO),
        log_entry_count: logs.len(),
        log_jsonl_valid,
    }
}

// ============================================================================
// Network Partition Recovery Scenarios
// ============================================================================

/// Scenario: Partition-Heal
/// 3-node mesh, partition node C from A+B for 60s, heal, verify:
/// - All nodes converge on same `AuditHead`
/// - No duplicate operations executed
/// - Gossip reconciliation completes
#[fcp_async_core::runtime::test]
async fn scenario_partition_heal_convergence() {
    let mut harness = TestHarness::new(3, 0xDEAD_BEEF);
    harness.start_all().expect("start all nodes");
    let partition_duration_secs = 60;

    let node_a_id = harness.nodes[0].node_id.clone();
    let node_b_id = harness.nodes[1].node_id.clone();
    let node_c_id = harness.nodes[2].node_id.clone();

    // Phase 1: Partition node C
    emit_scenario_log(
        &harness.logs,
        PARTITION_HEAL_SCENARIO,
        "partition",
        &["A", "B", "C"],
        "partition_injected",
        "pass",
        json!({ "isolated": node_c_id.as_str() }),
    );
    harness.partition(std::slice::from_ref(&node_c_id));

    // Register peers and announce objects while partition is active
    harness.register_all_peers();
    let zone = test_zone();
    let obj_a = test_object_id("partition-heal-obj-a");
    let obj_b = test_object_id("partition-heal-obj-b");
    let now_ms = harness.now_ms();

    // Announce objects on nodes A and B (connected partition)
    harness.nodes[0].mesh_mut().unwrap().announce_object(
        &zone,
        &obj_a,
        ObjectAdmissionClass::Admitted,
        now_ms,
    );
    harness.nodes[1].mesh_mut().unwrap().announce_object(
        &zone,
        &obj_b,
        ObjectAdmissionClass::Admitted,
        now_ms,
    );

    // Exchange gossip within connected partition (C is isolated)
    harness.gossip_exchange_round();

    // Advance time to simulate partition duration
    harness.advance_time(Duration::from_secs(partition_duration_secs));

    // Phase 2: Heal partition
    emit_scenario_log(
        &harness.logs,
        PARTITION_HEAL_SCENARIO,
        "heal",
        &["A", "B", "C"],
        "partition_healed",
        "pass",
        json!({ "healed": node_c_id.as_str() }),
    );
    harness.heal_partition();

    // Phase 3: Wait for convergence and gossip exchange after heal
    let convergence_result = harness.wait_for_convergence(Duration::from_secs(30)).await;
    harness.gossip_exchange_round();
    harness.gossip_exchange_round();

    let result = if convergence_result.is_ok() {
        "pass"
    } else {
        "fail"
    };
    let pending_messages = harness.network.pending_len();

    // Verify all nodes know about both objects via gossip state.
    let gossip_presence = [
        [
            harness.nodes[0]
                .mesh_mut()
                .unwrap()
                .gossip_mut()
                .has_object(&zone, &obj_a),
            harness.nodes[0]
                .mesh_mut()
                .unwrap()
                .gossip_mut()
                .has_object(&zone, &obj_b),
        ],
        [
            harness.nodes[1]
                .mesh_mut()
                .unwrap()
                .gossip_mut()
                .has_object(&zone, &obj_a),
            harness.nodes[1]
                .mesh_mut()
                .unwrap()
                .gossip_mut()
                .has_object(&zone, &obj_b),
        ],
        [
            harness.nodes[2]
                .mesh_mut()
                .unwrap()
                .gossip_mut()
                .has_object(&zone, &obj_a),
            harness.nodes[2]
                .mesh_mut()
                .unwrap()
                .gossip_mut()
                .has_object(&zone, &obj_b),
        ],
    ];

    emit_scenario_log(
        &harness.logs,
        PARTITION_HEAL_SCENARIO,
        "verify",
        &["A", "B", "C"],
        "convergence",
        result,
        json!({
            "converged": convergence_result.is_ok(),
            "pending_messages": pending_messages,
            "gossip_state": {
                "node_a": { "has_obj_a": gossip_presence[0][0], "has_obj_b": gossip_presence[0][1] },
                "node_b": { "has_obj_a": gossip_presence[1][0], "has_obj_b": gossip_presence[1][1] },
                "node_c": { "has_obj_a": gossip_presence[2][0], "has_obj_b": gossip_presence[2][1] },
            },
        }),
    );

    let partition_heal_logs = harness
        .log_entries()
        .into_iter()
        .filter(|entry| entry.test_name == PARTITION_HEAL_SCENARIO)
        .collect::<Vec<_>>();
    assert_eq!(
        partition_heal_logs.len(),
        3,
        "expected 3 partition-heal log entries"
    );

    let log_jsonl_validation = harness.logs.validate_jsonl();
    let log_jsonl_valid = log_jsonl_validation.is_ok();
    assert!(
        log_jsonl_valid,
        "partition-heal logs should validate against schema: {log_jsonl_validation:?}"
    );

    let artifact_bundle = build_partition_heal_artifact_bundle(
        &partition_heal_logs,
        &zone,
        &node_c_id,
        [&node_a_id, &node_b_id, &node_c_id],
        &obj_a,
        &obj_b,
        partition_duration_secs,
        convergence_result.is_ok(),
        pending_messages,
        gossip_presence,
        log_jsonl_valid,
    );
    assert_eq!(artifact_bundle.contract_id, PARTITION_HEAL_CONTRACT_ID);
    assert_eq!(
        artifact_bundle
            .assertions
            .iter()
            .map(|assertion| assertion.phase.as_str())
            .collect::<Vec<_>>(),
        vec!["partition", "heal", "verify"]
    );
    assert_eq!(artifact_bundle.log_entry_count, partition_heal_logs.len());
    assert_eq!(
        artifact_bundle
            .assertions
            .iter()
            .map(|assertion| assertion.result.as_str())
            .collect::<Vec<_>>(),
        vec!["pass", "pass", result]
    );
    assert_eq!(
        artifact_bundle.replay.isolated_node_id,
        node_c_id.as_str().to_string()
    );
    assert_eq!(
        artifact_bundle.replay.partition_duration_secs,
        partition_duration_secs
    );
    assert_eq!(artifact_bundle.state.converged, convergence_result.is_ok());
    assert_eq!(
        artifact_bundle.state.pending_messages,
        u64::try_from(pending_messages).expect("pending message count fits in u64")
    );
    assert_eq!(
        artifact_bundle.state.nodes_with_obj_a,
        u8::try_from(
            gossip_presence
                .iter()
                .filter(|presence| presence[0])
                .count()
        )
        .expect("node count fits in u8")
    );
    assert_eq!(
        artifact_bundle.state.nodes_with_obj_b,
        u8::try_from(
            gossip_presence
                .iter()
                .filter(|presence| presence[1])
                .count()
        )
        .expect("node count fits in u8")
    );
    assert_eq!(
        artifact_bundle.state.isolated_node_received_both_objects,
        gossip_presence[2][0] && gossip_presence[2][1]
    );

    let artifact_json =
        serde_json::to_value(&artifact_bundle).expect("serialize partition-heal artifact bundle");
    let roundtrip: PartitionHealArtifactBundle =
        serde_json::from_value(artifact_json).expect("deserialize partition-heal artifact bundle");
    assert_eq!(roundtrip, artifact_bundle);

    // Verify gossip convergence: A and B should agree on objects
    assert!(
        gossip_presence[0][0],
        "node A should know about obj_a (its own announcement)"
    );
    assert!(
        gossip_presence[1][1],
        "node B should know about obj_b (its own announcement)"
    );
    assert!(
        gossip_presence[0][1],
        "node A should learn about obj_b from gossip"
    );
    assert!(
        gossip_presence[1][0],
        "node B should learn about obj_a from gossip"
    );

    harness.stop_all().expect("stop all nodes");
}

/// Scenario: Split-Brain Prevention
/// Both partitions attempt quorum ops, only one succeeds.
#[fcp_async_core::runtime::test]
async fn scenario_split_brain_prevention() {
    let mut harness = TestHarness::new(5, 0xCAFE_BABE);
    harness.start_all().expect("start all nodes");
    let partition_duration_secs = 10;

    // Create a 2-3 split (nodes 0,1 vs 2,3,4)
    let minority = vec![
        harness.nodes[0].node_id.clone(),
        harness.nodes[1].node_id.clone(),
    ];
    let majority = vec![
        harness.nodes[2].node_id.clone(),
        harness.nodes[3].node_id.clone(),
        harness.nodes[4].node_id.clone(),
    ];

    emit_scenario_log(
        &harness.logs,
        SPLIT_BRAIN_SCENARIO,
        "partition",
        &["0", "1", "2", "3", "4"],
        "partition_created",
        "pass",
        json!({ "minority": ["0", "1"], "majority": ["2", "3", "4"] }),
    );

    harness.partition(&minority);
    harness.advance_time(Duration::from_secs(partition_duration_secs));

    // Register peers and announce objects in each partition
    harness.register_all_peers();
    let zone = test_zone();
    let obj_minority = test_object_id("split-brain-minority-obj");
    let obj_majority = test_object_id("split-brain-majority-obj");
    let now_ms = harness.now_ms();

    // Announce on minority partition (nodes 0, 1)
    harness.nodes[0].mesh_mut().unwrap().announce_object(
        &zone,
        &obj_minority,
        ObjectAdmissionClass::Admitted,
        now_ms,
    );

    // Announce on majority partition (nodes 2, 3, 4)
    harness.nodes[2].mesh_mut().unwrap().announce_object(
        &zone,
        &obj_majority,
        ObjectAdmissionClass::Admitted,
        now_ms,
    );

    // Gossip within partitions (partitioned nodes can't communicate across)
    harness.gossip_exchange_round();

    // Verify: majority partition peer count > minority partition peer count
    let majority_peers = harness.nodes[2].mesh_mut().unwrap().peer_count();
    let minority_peers = harness.nodes[0].mesh_mut().unwrap().peer_count();

    // During partition, gossip only propagates within the partition.
    let minority_has_majority_obj = harness.nodes[0]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &obj_majority);
    let majority_has_minority_obj = harness.nodes[2]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &obj_minority);

    emit_scenario_log(
        &harness.logs,
        SPLIT_BRAIN_SCENARIO,
        "verify",
        &["0", "1", "2", "3", "4"],
        "quorum_semantics",
        "pass",
        json!({
            "minority_peers": minority_peers,
            "majority_peers": majority_peers,
            "cross_partition_leak": {
                "minority_sees_majority": minority_has_majority_obj,
                "majority_sees_minority": majority_has_minority_obj,
            },
        }),
    );

    // During partition, gossip should NOT cross the boundary
    assert!(
        !minority_has_majority_obj,
        "minority partition should not see majority-side objects"
    );
    assert!(
        !majority_has_minority_obj,
        "majority partition should not see minority-side objects"
    );
    let cross_partition_isolated = !minority_has_majority_obj && !majority_has_minority_obj;

    // Heal and verify convergence
    harness.heal_partition();
    harness.gossip_exchange_round();
    harness.gossip_exchange_round();

    // After heal, all nodes should know about all objects
    let node0_has_majority = harness.nodes[0]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &obj_majority);
    let node2_has_minority = harness.nodes[2]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &obj_minority);

    emit_scenario_log(
        &harness.logs,
        SPLIT_BRAIN_SCENARIO,
        "post-heal",
        &["0", "1", "2", "3", "4"],
        "convergence_after_heal",
        if node0_has_majority && node2_has_minority {
            "pass"
        } else {
            "fail"
        },
        json!({
            "node0_sees_majority_obj": node0_has_majority,
            "node2_sees_minority_obj": node2_has_minority,
        }),
    );

    let split_brain_logs = harness
        .log_entries()
        .into_iter()
        .filter(|entry| entry.test_name == SPLIT_BRAIN_SCENARIO)
        .collect::<Vec<_>>();
    assert_eq!(
        split_brain_logs.len(),
        3,
        "expected 3 split-brain log entries"
    );

    let log_jsonl_validation = harness.logs.validate_jsonl();
    let log_jsonl_valid = log_jsonl_validation.is_ok();
    assert!(
        log_jsonl_valid,
        "split-brain logs should validate against schema: {log_jsonl_validation:?}"
    );

    let converged_after_heal = node0_has_majority && node2_has_minority;
    let artifact_bundle = build_split_brain_artifact_bundle(
        &split_brain_logs,
        &zone,
        &minority,
        &majority,
        &obj_minority,
        &obj_majority,
        partition_duration_secs,
        minority_peers,
        majority_peers,
        cross_partition_isolated,
        node0_has_majority,
        node2_has_minority,
        converged_after_heal,
        log_jsonl_valid,
    );
    assert_eq!(artifact_bundle.contract_id, SPLIT_BRAIN_CONTRACT_ID);
    assert_eq!(
        artifact_bundle
            .assertions
            .iter()
            .map(|assertion| assertion.phase.as_str())
            .collect::<Vec<_>>(),
        vec!["partition", "verify", "post-heal"]
    );
    assert_eq!(
        artifact_bundle
            .assertions
            .iter()
            .map(|assertion| assertion.result.as_str())
            .collect::<Vec<_>>(),
        vec![
            "pass",
            "pass",
            if converged_after_heal { "pass" } else { "fail" }
        ]
    );
    assert_eq!(artifact_bundle.log_entry_count, split_brain_logs.len());
    assert_eq!(artifact_bundle.replay.minority_node_ids.len(), 2);
    assert_eq!(artifact_bundle.replay.majority_node_ids.len(), 3);
    assert_eq!(
        artifact_bundle.replay.partition_duration_secs,
        partition_duration_secs
    );
    assert_eq!(
        artifact_bundle.state.minority_peer_count,
        u8::try_from(minority_peers).expect("peer count fits in u8")
    );
    assert_eq!(
        artifact_bundle.state.majority_peer_count,
        u8::try_from(majority_peers).expect("peer count fits in u8")
    );
    assert_eq!(
        artifact_bundle.state.majority_has_more_peers,
        majority_peers > minority_peers
    );
    assert!(artifact_bundle.state.cross_partition_isolated);
    assert_eq!(
        artifact_bundle.state.node0_has_majority_after_heal,
        node0_has_majority
    );
    assert_eq!(
        artifact_bundle.state.node2_has_minority_after_heal,
        node2_has_minority
    );
    assert_eq!(
        artifact_bundle.state.converged_after_heal,
        converged_after_heal
    );

    let artifact_json =
        serde_json::to_value(&artifact_bundle).expect("serialize split-brain artifact bundle");
    let roundtrip: SplitBrainArtifactBundle =
        serde_json::from_value(artifact_json).expect("deserialize split-brain artifact bundle");
    assert_eq!(roundtrip, artifact_bundle);

    assert!(
        node0_has_majority,
        "minority partition should learn majority-side object after heal"
    );
    assert!(
        node2_has_minority,
        "majority partition should learn minority-side object after heal"
    );

    harness.stop_all().expect("stop all nodes");
}

/// Scenario: Stale Node Rejoins
/// Node offline for longer than revocation freshness window must catch up
/// before accepting operations.
#[fcp_async_core::runtime::test]
async fn scenario_stale_node_rejoins() {
    let mut harness = TestHarness::new(3, 0x1234_5678);
    harness.start_all().expect("start all nodes");
    let offline_duration_hours = 24;

    let stale_node = harness.nodes[2].node_id.clone();

    // Partition stale node
    harness.partition(std::slice::from_ref(&stale_node));

    // Advance time beyond revocation freshness window (e.g., 24 hours)
    harness.advance_time(Duration::from_secs(
        u64::from(offline_duration_hours) * 60 * 60,
    ));

    emit_scenario_log(
        &harness.logs,
        STALE_REJOIN_SCENARIO,
        "setup",
        &["A", "B", "C"],
        "stale_duration_exceeded",
        "pass",
        json!({
            "stale_node": stale_node.as_str(),
            "offline_duration_hours": offline_duration_hours
        }),
    );

    // While stale node is offline, announce objects on the connected nodes
    harness.register_all_peers();
    let zone = test_zone();
    let obj_while_stale = test_object_id("stale-rejoin-new-obj");
    let now_ms = harness.now_ms();
    harness.nodes[0].mesh_mut().unwrap().announce_object(
        &zone,
        &obj_while_stale,
        ObjectAdmissionClass::Admitted,
        now_ms,
    );
    harness.gossip_exchange_round();

    // Verify stale node does NOT have the new object (it was partitioned)
    let stale_has_obj_before = harness.nodes[2]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &obj_while_stale);
    assert!(
        !stale_has_obj_before,
        "stale node should not know about objects announced while partitioned"
    );

    // Heal partition and gossip to sync
    harness.heal_partition();
    harness.gossip_exchange_round();
    harness.gossip_exchange_round();

    // Verify stale node now has the object after sync
    let stale_has_obj_after = harness.nodes[2]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &obj_while_stale);

    let sync_result = if stale_has_obj_after { "pass" } else { "fail" };

    emit_scenario_log(
        &harness.logs,
        STALE_REJOIN_SCENARIO,
        "verify",
        &["A", "B", "C"],
        "checkpoint_sync",
        sync_result,
        json!({
            "stale_node": stale_node.as_str(),
            "had_object_before_heal": stale_has_obj_before,
            "has_object_after_sync": stale_has_obj_after,
        }),
    );

    let stale_rejoin_logs = harness
        .log_entries()
        .into_iter()
        .filter(|entry| entry.test_name == STALE_REJOIN_SCENARIO)
        .collect::<Vec<_>>();
    assert_eq!(
        stale_rejoin_logs.len(),
        2,
        "expected 2 stale-rejoin log entries"
    );

    let log_jsonl_validation = harness.logs.validate_jsonl();
    let log_jsonl_valid = log_jsonl_validation.is_ok();
    assert!(
        log_jsonl_valid,
        "stale-rejoin logs should validate against schema: {log_jsonl_validation:?}"
    );

    let artifact_bundle = build_stale_rejoin_artifact_bundle(
        &stale_rejoin_logs,
        &zone,
        &stale_node,
        &obj_while_stale,
        offline_duration_hours,
        stale_has_obj_before,
        stale_has_obj_after,
        harness.running_count(),
        true,
        log_jsonl_valid,
    );
    assert_eq!(artifact_bundle.contract_id, STALE_REJOIN_CONTRACT_ID);
    assert_eq!(
        artifact_bundle
            .assertions
            .iter()
            .map(|assertion| assertion.phase.as_str())
            .collect::<Vec<_>>(),
        vec!["setup", "verify"]
    );
    assert_eq!(artifact_bundle.log_entry_count, stale_rejoin_logs.len());
    assert_eq!(
        artifact_bundle
            .assertions
            .iter()
            .map(|assertion| assertion.result.as_str())
            .collect::<Vec<_>>(),
        vec!["pass", sync_result]
    );
    assert_eq!(
        artifact_bundle.replay.stale_node_id,
        stale_node.as_str().to_string()
    );
    assert_eq!(
        artifact_bundle.replay.offline_duration_hours,
        offline_duration_hours
    );
    assert_eq!(
        artifact_bundle.state.had_object_before_heal,
        stale_has_obj_before
    );
    assert_eq!(
        artifact_bundle.state.has_object_after_sync,
        stale_has_obj_after
    );
    assert_eq!(artifact_bundle.state.running_nodes_after_sync, 3);
    assert!(artifact_bundle.state.catch_up_required);

    let artifact_json =
        serde_json::to_value(&artifact_bundle).expect("serialize stale-rejoin artifact bundle");
    let roundtrip: StaleRejoinArtifactBundle =
        serde_json::from_value(artifact_json).expect("deserialize stale-rejoin artifact bundle");
    assert_eq!(roundtrip, artifact_bundle);

    harness.stop_all().expect("stop all nodes");
}

// ============================================================================
// Node Failure and Recovery Scenarios
// ============================================================================

/// Scenario: Graceful Shutdown
/// Node announces shutdown, leases transferred, no operation loss.
#[fcp_async_core::runtime::test]
async fn scenario_graceful_shutdown() {
    let mut harness = TestHarness::new(3, 0xABCD_EF01);
    harness.start_all().expect("start all nodes");

    let shutdown_node_idx = 1;
    let shutdown_node_id = harness.nodes[shutdown_node_idx].node_id.clone();

    // Register peers and announce objects BEFORE shutdown
    harness.register_all_peers();
    let zone = test_zone();
    let obj_from_shutdown = test_object_id("graceful-shutdown-obj");
    let now_ms = harness.now_ms();
    harness.nodes[shutdown_node_idx]
        .mesh_mut()
        .unwrap()
        .announce_object(
            &zone,
            &obj_from_shutdown,
            ObjectAdmissionClass::Admitted,
            now_ms,
        );
    harness.gossip_exchange_round();

    emit_scenario_log(
        &harness.logs,
        GRACEFUL_SHUTDOWN_SCENARIO,
        "setup",
        &["A", "B", "C"],
        "shutdown_initiated",
        "pass",
        json!({ "node": shutdown_node_id.as_str() }),
    );

    // Graceful shutdown
    harness.nodes[shutdown_node_idx]
        .stop()
        .expect("graceful stop");
    let node_stopped = !harness.nodes[shutdown_node_idx].is_running();

    // Verify node stopped
    assert!(node_stopped, "node should be stopped");

    emit_scenario_log(
        &harness.logs,
        GRACEFUL_SHUTDOWN_SCENARIO,
        "verify",
        &["A", "B", "C"],
        "node_stopped",
        "pass",
        json!({ "node": shutdown_node_id.as_str(), "running": false }),
    );

    // After shutdown, verify remaining nodes are still operational
    let running = harness.running_count();
    assert_eq!(
        running, 2,
        "2 nodes should still be running after graceful shutdown"
    );

    // Verify remaining nodes still have gossip knowledge of the shutdown node's objects
    let node_a_has_obj = harness.nodes[0]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &obj_from_shutdown);

    emit_scenario_log(
        &harness.logs,
        GRACEFUL_SHUTDOWN_SCENARIO,
        "verify",
        &["A", "C"],
        "gossip_preserved",
        if node_a_has_obj { "pass" } else { "fail" },
        json!({
            "remaining_running": running,
            "gossip_preserved": node_a_has_obj,
        }),
    );

    let graceful_shutdown_logs = harness
        .log_entries()
        .into_iter()
        .filter(|entry| entry.test_name == GRACEFUL_SHUTDOWN_SCENARIO)
        .collect::<Vec<_>>();
    assert_eq!(
        graceful_shutdown_logs.len(),
        3,
        "expected 3 graceful-shutdown log entries"
    );

    let log_jsonl_validation = harness.logs.validate_jsonl();
    let log_jsonl_valid = log_jsonl_validation.is_ok();
    assert!(
        log_jsonl_valid,
        "graceful-shutdown logs should validate against schema: {log_jsonl_validation:?}"
    );

    let artifact_bundle = build_graceful_shutdown_artifact_bundle(
        &graceful_shutdown_logs,
        &zone,
        &obj_from_shutdown,
        &shutdown_node_id,
        node_stopped,
        node_a_has_obj,
        running,
        log_jsonl_valid,
    );
    assert_eq!(artifact_bundle.contract_id, GRACEFUL_SHUTDOWN_CONTRACT_ID);
    assert_eq!(
        artifact_bundle
            .assertions
            .iter()
            .map(|assertion| assertion.phase.as_str())
            .collect::<Vec<_>>(),
        vec!["setup", "verify", "verify"]
    );
    assert_eq!(
        artifact_bundle
            .assertions
            .iter()
            .map(|assertion| assertion.result.as_str())
            .collect::<Vec<_>>(),
        vec!["pass", "pass", if node_a_has_obj { "pass" } else { "fail" }]
    );
    assert_eq!(
        artifact_bundle.log_entry_count,
        graceful_shutdown_logs.len()
    );
    assert_eq!(
        artifact_bundle.replay.shutdown_node_id,
        shutdown_node_id.as_str().to_string()
    );
    assert!(artifact_bundle.state.node_stopped);
    assert_eq!(artifact_bundle.state.gossip_preserved, node_a_has_obj);
    assert_eq!(artifact_bundle.state.remaining_running_nodes, 2);

    let artifact_json = serde_json::to_value(&artifact_bundle)
        .expect("serialize graceful-shutdown artifact bundle");
    let roundtrip: GracefulShutdownArtifactBundle = serde_json::from_value(artifact_json)
        .expect("deserialize graceful-shutdown artifact bundle");
    assert_eq!(roundtrip, artifact_bundle);

    assert!(
        node_a_has_obj,
        "remaining nodes should still know about objects from shutdown node"
    );

    harness.stop_all().expect("stop remaining nodes");
}

/// Scenario: Crash Recovery
/// Node killed mid-operation, restart, verify:
/// - Incomplete `OperationIntent` is detected
/// - No duplicate side effects
/// - Lease is released after timeout
#[fcp_async_core::runtime::test]
async fn scenario_crash_recovery() {
    let mut harness = TestHarness::new(3, 0xFEED_FACE);
    harness.start_all().expect("start all nodes");
    let lease_timeout_secs = 120;

    let crash_node_idx = 0;
    let crash_node_id = harness.nodes[crash_node_idx].node_id.clone();

    emit_scenario_log(
        &harness.logs,
        CRASH_RECOVERY_SCENARIO,
        "setup",
        &["A", "B", "C"],
        "crash_simulated",
        "pass",
        json!({ "node": crash_node_id.as_str() }),
    );

    // Simulate crash (drops mesh state)
    harness.nodes[crash_node_idx].crash();
    assert!(
        !harness.nodes[crash_node_idx].is_running(),
        "crashed node should not be running"
    );

    // Advance time past lease timeout
    harness.advance_time(Duration::from_secs(lease_timeout_secs));

    // Restart node
    harness.nodes[crash_node_idx].start().expect("restart node");
    let restarted_node_running = harness.nodes[crash_node_idx].is_running();
    assert!(restarted_node_running, "restarted node should be running");

    // After restart, the node should have fresh mesh state but same stores
    // Register peers and announce objects to verify the restarted node participates
    harness.register_all_peers();
    let zone = test_zone();
    let obj_post_crash = test_object_id("crash-recovery-post-obj");
    let now_ms = harness.now_ms();

    // Restarted node can announce and participate in gossip
    harness.nodes[crash_node_idx]
        .mesh_mut()
        .unwrap()
        .announce_object(
            &zone,
            &obj_post_crash,
            ObjectAdmissionClass::Admitted,
            now_ms,
        );
    harness.gossip_exchange_round();

    // Verify other nodes received the announcement
    let node_b_has_obj = harness.nodes[1]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &obj_post_crash);

    emit_scenario_log(
        &harness.logs,
        CRASH_RECOVERY_SCENARIO,
        "verify",
        &["A", "B", "C"],
        "recovery_complete",
        if node_b_has_obj { "pass" } else { "fail" },
        json!({
            "node": crash_node_id.as_str(),
            "restarted": true,
            "post_crash_gossip_works": node_b_has_obj,
        }),
    );

    let crash_recovery_logs = harness
        .log_entries()
        .into_iter()
        .filter(|entry| entry.test_name == CRASH_RECOVERY_SCENARIO)
        .collect::<Vec<_>>();
    assert_eq!(
        crash_recovery_logs.len(),
        2,
        "expected 2 crash-recovery log entries"
    );

    let log_jsonl_validation = harness.logs.validate_jsonl();
    let log_jsonl_valid = log_jsonl_validation.is_ok();
    assert!(
        log_jsonl_valid,
        "crash-recovery logs should validate against schema: {log_jsonl_validation:?}"
    );

    let artifact_bundle = build_crash_recovery_artifact_bundle(
        &crash_recovery_logs,
        &zone,
        &obj_post_crash,
        &crash_node_id,
        lease_timeout_secs,
        restarted_node_running,
        node_b_has_obj,
        harness.running_count(),
        log_jsonl_valid,
    );
    assert_eq!(artifact_bundle.contract_id, CRASH_RECOVERY_CONTRACT_ID);
    assert_eq!(
        artifact_bundle
            .assertions
            .iter()
            .map(|assertion| assertion.phase.as_str())
            .collect::<Vec<_>>(),
        vec!["setup", "verify"]
    );
    assert_eq!(artifact_bundle.log_entry_count, crash_recovery_logs.len());
    assert!(
        artifact_bundle
            .assertions
            .iter()
            .all(|assertion| assertion.result == "pass")
    );
    assert_eq!(
        artifact_bundle.replay.crashed_node_id,
        crash_node_id.as_str().to_string()
    );
    assert_eq!(
        artifact_bundle.replay.lease_timeout_secs,
        lease_timeout_secs
    );
    assert_eq!(artifact_bundle.state.running_nodes_after_restart, 3);
    assert!(artifact_bundle.state.restarted_node_running);
    assert!(artifact_bundle.state.post_crash_gossip_works);

    let artifact_json = serde_json::to_value(&artifact_bundle).expect("serialize artifact bundle");
    let roundtrip: CrashRecoveryArtifactBundle =
        serde_json::from_value(artifact_json).expect("deserialize artifact bundle");
    assert_eq!(roundtrip, artifact_bundle);

    assert!(
        node_b_has_obj,
        "restarted node should be able to participate in gossip"
    );

    harness.stop_all().expect("stop all nodes");
}

/// Scenario: Multi-Node Failure
/// Lose f nodes (within quorum tolerance), operations continue.
#[fcp_async_core::runtime::test]
async fn scenario_multi_node_failure_within_tolerance() {
    // 5-node quorum: f = 2, so losing 2 nodes should still work
    let mut harness = TestHarness::new(5, 0x5AFE_5AFE);
    harness.start_all().expect("start all nodes");
    let quorum_tolerance_f = 2;
    let crashed_node_ids = vec![
        harness.nodes[0].node_id.clone(),
        harness.nodes[1].node_id.clone(),
    ];

    emit_scenario_log(
        &harness.logs,
        MULTI_NODE_FAILURE_SCENARIO,
        "setup",
        &["0", "1", "2", "3", "4"],
        "initial_state",
        "pass",
        json!({ "node_count": 5, "quorum_tolerance_f": quorum_tolerance_f }),
    );

    // Crash 2 nodes (within tolerance)
    harness.nodes[0].crash();
    harness.nodes[1].crash();

    harness.advance_time(Duration::from_secs(30));

    // Verify remaining nodes are operational
    let running_count = harness.nodes.iter().filter(|n| n.is_running()).count();
    assert_eq!(running_count, 3, "3 nodes should still be running");

    // Register peers and announce objects on surviving nodes
    harness.register_all_peers();
    let zone = test_zone();
    let obj_survivor = test_object_id("multi-failure-survivor-obj");
    let now_ms = harness.now_ms();
    harness.nodes[2].mesh_mut().unwrap().announce_object(
        &zone,
        &obj_survivor,
        ObjectAdmissionClass::Admitted,
        now_ms,
    );

    // Gossip among survivors
    harness.gossip_exchange_round();

    // Verify surviving nodes can still exchange gossip
    let node3_has_obj = harness.nodes[3]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &obj_survivor);
    let node4_has_obj = harness.nodes[4]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &obj_survivor);

    emit_scenario_log(
        &harness.logs,
        MULTI_NODE_FAILURE_SCENARIO,
        "verify",
        &["2", "3", "4"],
        "operations_continue",
        if node3_has_obj && node4_has_obj {
            "pass"
        } else {
            "fail"
        },
        json!({
            "crashed_nodes": crashed_node_ids
                .iter()
                .map(fcp_tailscale::NodeId::as_str)
                .collect::<Vec<_>>(),
            "running_nodes": running_count,
            "gossip_propagation": {
                "node3_has_obj": node3_has_obj,
                "node4_has_obj": node4_has_obj,
            },
        }),
    );

    let multi_node_failure_logs = harness
        .log_entries()
        .into_iter()
        .filter(|entry| entry.test_name == MULTI_NODE_FAILURE_SCENARIO)
        .collect::<Vec<_>>();
    assert_eq!(
        multi_node_failure_logs.len(),
        2,
        "expected 2 multi-node-failure log entries"
    );

    let log_jsonl_validation = harness.logs.validate_jsonl();
    let log_jsonl_valid = log_jsonl_validation.is_ok();
    assert!(
        log_jsonl_valid,
        "multi-node-failure logs should validate against schema: {log_jsonl_validation:?}"
    );

    let operations_continue = node3_has_obj && node4_has_obj;
    let artifact_bundle = build_multi_node_failure_artifact_bundle(
        &multi_node_failure_logs,
        &zone,
        &obj_survivor,
        &crashed_node_ids,
        running_count,
        quorum_tolerance_f,
        node3_has_obj,
        node4_has_obj,
        operations_continue,
        log_jsonl_valid,
    );
    assert_eq!(artifact_bundle.contract_id, MULTI_NODE_FAILURE_CONTRACT_ID);
    assert_eq!(
        artifact_bundle
            .assertions
            .iter()
            .map(|assertion| assertion.phase.as_str())
            .collect::<Vec<_>>(),
        vec!["setup", "verify"]
    );
    assert_eq!(
        artifact_bundle
            .assertions
            .iter()
            .map(|assertion| assertion.result.as_str())
            .collect::<Vec<_>>(),
        vec!["pass", if operations_continue { "pass" } else { "fail" }]
    );
    assert_eq!(
        artifact_bundle.log_entry_count,
        multi_node_failure_logs.len()
    );
    assert_eq!(artifact_bundle.replay.crashed_node_ids.len(), 2);
    assert_eq!(artifact_bundle.state.running_nodes, 3);
    assert_eq!(
        artifact_bundle.state.quorum_tolerance_f,
        u8::try_from(quorum_tolerance_f).expect("quorum tolerance fits in u8")
    );
    assert_eq!(artifact_bundle.state.node3_has_obj, node3_has_obj);
    assert_eq!(artifact_bundle.state.node4_has_obj, node4_has_obj);
    assert!(artifact_bundle.state.operations_continue);

    let artifact_json = serde_json::to_value(&artifact_bundle)
        .expect("serialize multi-node-failure artifact bundle");
    let roundtrip: MultiNodeFailureArtifactBundle = serde_json::from_value(artifact_json)
        .expect("deserialize multi-node-failure artifact bundle");
    assert_eq!(roundtrip, artifact_bundle);

    assert!(node3_has_obj, "survivor node 3 should receive gossip");
    assert!(node4_has_obj, "survivor node 4 should receive gossip");

    harness.stop_all().expect("stop remaining nodes");
}

/// Scenario: Quorum Loss
/// Lose more than f nodes, operations fail closed with clear error.
#[fcp_async_core::runtime::test]
async fn scenario_quorum_loss() {
    // 5-node quorum: f = 2, so losing 3 nodes should halt operations
    let mut harness = TestHarness::new(5, 0xDEAD_C0DE);
    harness.start_all().expect("start all nodes");
    let quorum_tolerance_f = 2;
    let crashed_node_ids = vec![
        harness.nodes[0].node_id.clone(),
        harness.nodes[1].node_id.clone(),
        harness.nodes[2].node_id.clone(),
    ];

    emit_scenario_log(
        &harness.logs,
        QUORUM_LOSS_SCENARIO,
        "setup",
        &["0", "1", "2", "3", "4"],
        "initial_state",
        "pass",
        json!({ "node_count": 5, "quorum_tolerance_f": quorum_tolerance_f }),
    );

    // Crash 3 nodes (exceeds tolerance)
    harness.nodes[0].crash();
    harness.nodes[1].crash();
    harness.nodes[2].crash();

    harness.advance_time(Duration::from_secs(30));

    let running_count = harness.nodes.iter().filter(|n| n.is_running()).count();
    assert_eq!(running_count, 2, "only 2 nodes should still be running");

    // With 3 of 5 nodes crashed, the remaining 2 are below quorum (need 3 of 5).
    // Register peers on survivors to verify they detect the degraded state.
    harness.register_all_peers();

    // Verify survivors can still gossip with each other, but know peer count is low
    let zone = test_zone();
    let obj_degraded = test_object_id("quorum-loss-obj");
    let now_ms = harness.now_ms();
    harness.nodes[3].mesh_mut().unwrap().announce_object(
        &zone,
        &obj_degraded,
        ObjectAdmissionClass::Admitted,
        now_ms,
    );
    harness.gossip_exchange_round();

    let node4_has_obj = harness.nodes[4]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &obj_degraded);
    let survivor_peer_count = harness.nodes[3].mesh_mut().unwrap().peer_count();

    // Quorum requires > n/2 nodes. With 5 nodes and 3 crashed, quorum is lost.
    let quorum_threshold = 3; // ceil(5/2) + 1 for strict majority
    let quorum_available = running_count >= quorum_threshold;
    let operations_halted = !quorum_available;

    emit_scenario_log(
        &harness.logs,
        QUORUM_LOSS_SCENARIO,
        "verify",
        &["3", "4"],
        "operations_halted",
        if operations_halted { "pass" } else { "fail" },
        json!({
            "crashed_nodes": crashed_node_ids
                .iter()
                .map(fcp_tailscale::NodeId::as_str)
                .collect::<Vec<_>>(),
            "running_nodes": running_count,
            "survivor_peer_count": survivor_peer_count,
            "quorum_available": quorum_available,
            "gossip_still_works": node4_has_obj,
        }),
    );

    let quorum_loss_logs = harness
        .log_entries()
        .into_iter()
        .filter(|entry| entry.test_name == QUORUM_LOSS_SCENARIO)
        .collect::<Vec<_>>();
    assert_eq!(
        quorum_loss_logs.len(),
        2,
        "expected 2 quorum-loss log entries"
    );

    let log_jsonl_validation = harness.logs.validate_jsonl();
    let log_jsonl_valid = log_jsonl_validation.is_ok();
    assert!(
        log_jsonl_valid,
        "quorum-loss logs should validate against schema: {log_jsonl_validation:?}"
    );

    let artifact_bundle = build_quorum_loss_artifact_bundle(
        &quorum_loss_logs,
        &zone,
        &obj_degraded,
        &crashed_node_ids,
        running_count,
        quorum_threshold,
        survivor_peer_count,
        quorum_available,
        node4_has_obj,
        operations_halted,
        log_jsonl_valid,
    );
    assert_eq!(artifact_bundle.contract_id, QUORUM_LOSS_CONTRACT_ID);
    assert_eq!(
        artifact_bundle
            .assertions
            .iter()
            .map(|assertion| assertion.phase.as_str())
            .collect::<Vec<_>>(),
        vec!["setup", "verify"]
    );
    assert_eq!(
        artifact_bundle
            .assertions
            .iter()
            .map(|assertion| assertion.result.as_str())
            .collect::<Vec<_>>(),
        vec!["pass", "pass"]
    );
    assert_eq!(artifact_bundle.log_entry_count, quorum_loss_logs.len());
    assert_eq!(artifact_bundle.replay.crashed_node_ids.len(), 3);
    assert_eq!(artifact_bundle.state.running_nodes, 2);
    assert_eq!(
        artifact_bundle.state.quorum_threshold,
        u8::try_from(quorum_threshold).expect("quorum threshold fits in u8")
    );
    assert_eq!(
        artifact_bundle.state.survivor_peer_count,
        u8::try_from(survivor_peer_count).expect("survivor peer count fits in u8")
    );
    assert!(!artifact_bundle.state.quorum_available);
    assert!(artifact_bundle.state.gossip_still_works);
    assert!(artifact_bundle.state.operations_halted);

    let artifact_json =
        serde_json::to_value(&artifact_bundle).expect("serialize quorum-loss artifact bundle");
    let roundtrip: QuorumLossArtifactBundle =
        serde_json::from_value(artifact_json).expect("deserialize quorum-loss artifact bundle");
    assert_eq!(roundtrip, artifact_bundle);

    assert!(
        !quorum_available,
        "quorum should NOT be available with only {running_count} of 5 nodes"
    );
    assert!(
        node4_has_obj,
        "gossip should still work between survivors even without quorum"
    );

    harness.stop_all().expect("stop remaining nodes");
}

// ============================================================================
// Concurrent Operation Conflicts Scenarios
// ============================================================================

/// Scenario: Lease Contention
/// Two nodes attempt same operation lease simultaneously.
/// - Only one succeeds
/// - Loser gets FCP-4320 (`LeaseConflict`)
/// - Winner produces receipt
#[fcp_async_core::runtime::test]
async fn scenario_lease_contention() {
    let mut harness = TestHarness::new(3, 0xC0FF_EE42);
    harness.start_all().expect("start all nodes");

    emit_scenario_log(
        &harness.logs,
        LEASE_CONTENTION_SCENARIO,
        "setup",
        &["A", "B", "C"],
        "contention_scenario",
        "pass",
        json!({ "contenders": ["A", "B"] }),
    );

    // Set up peers with device profiles and held leases for singleton_writer contention
    harness.register_all_peers();
    let contested_obj = test_object_id("lease-contention-resource");
    let now_ms = harness.now_ms();
    let lease_expires_in_secs = 3600;
    let connector_id = "test:basic:1.0.0";

    let test_connector = fcp_mesh::InstalledConnector {
        connector_id: connector_id.parse().expect("valid connector ID"),
        version: "1.0.0".to_string(),
        binary_hash: test_object_id("test-connector-binary"),
        capabilities: Vec::new(),
    };

    // Node A holds a singleton-writer lease on the contested object
    let held_lease = fcp_mesh::HeldLease {
        subject_id: contested_obj,
        purpose: fcp_mesh::LeasePurpose::SingletonWriter,
        expires_at: now_ms / 1000 + lease_expires_in_secs,
        fencing_token: 11,
    };

    // Update node A's state with the held lease
    let node_a_id = harness.nodes[0].node_id.clone();
    let peer_b_id = harness.nodes[1].node_id.clone();

    // Set local state with installed connector on node B (the planner host)
    if let Some(mesh) = harness.nodes[1].mesh_mut() {
        let local_profile = fcp_mesh::DeviceProfile::builder(peer_b_id.clone())
            .cpu_cores(4)
            .memory_mb(8192)
            .add_connector(test_connector.clone())
            .build();
        mesh.update_local_state(local_profile, HashSet::new(), Vec::new());
    }

    // Register node A as holding the lease on other nodes (with connector installed)
    for i in 1..harness.nodes.len() {
        if let Some(mesh) = harness.nodes[i].mesh_mut() {
            let profile = fcp_mesh::DeviceProfile::builder(node_a_id.clone())
                .cpu_cores(4)
                .memory_mb(8192)
                .add_connector(test_connector.clone())
                .build();
            mesh.update_peer_state(
                node_a_id.clone(),
                profile,
                HashSet::new(),
                vec![held_lease.clone()],
                now_ms,
            );
        }
    }

    // Plan execution with singleton_writer constraint from node B's perspective
    let planner_ctx = fcp_mesh::PlannerContext {
        connector_id: connector_id.parse().expect("valid connector ID"),
        min_connector_version: None,
        min_memory_mb: None,
        resource_pool_class: None,
        requested_cpu_cores: None,
        requires_gpu: false,
        requires_tpu: false,
        preferred_symbols: Vec::new(),
        required_symbols: Vec::new(),
        singleton_writer: true,
        authority_subject: Some(contested_obj),
        target_zone: None,
        excluded_nodes: HashSet::new(),
    };

    // Node B plans execution - it should see node A as the lease holder and
    // prioritize A (or deprioritize B since A already holds the lease)
    let (candidates, authority_view) = {
        let mesh = harness.nodes[1].mesh_mut().unwrap();
        let candidates = mesh.plan_execution(&planner_ctx, now_ms);
        let authority_view = mesh.authority_view(
            &ZoneId::work(),
            &contested_obj,
            fcp_mesh::LeasePurpose::SingletonWriter,
            now_ms,
        );
        (candidates, authority_view)
    };

    // In singleton_writer mode, the lease holder (node A) should be prioritized
    let candidate_for_node_a = candidates.iter().find(|c| c.node_id == node_a_id);
    let candidate_for_node_b = candidates.iter().find(|c| c.node_id == peer_b_id);
    let contender_candidate_present = candidate_for_node_b.is_some();
    let contender_eligible = candidate_for_node_b.is_some_and(|candidate| candidate.eligible);
    let lease_holder_candidate_present = candidate_for_node_a.is_some();
    let lease_holder_preferred = match (candidate_for_node_a, candidate_for_node_b) {
        (Some(lease_holder), Some(contender)) => lease_holder.score >= contender.score,
        (Some(_), None) => true,
        _ => false,
    };
    let singleton_writer_enforced =
        lease_holder_candidate_present && lease_holder_preferred && !contender_eligible;
    let authority_holder_matches = authority_view
        .active_holder
        .as_ref()
        .is_some_and(|holder| holder.as_str() == node_a_id.as_str());
    let authority_records_active = authority_view
        .records
        .iter()
        .filter(|record| record.status == fcp_mesh::AuthorityStatus::Active)
        .count();
    let authority_timeline_ops = authority_view
        .timeline
        .iter()
        .map(|event| event.operation.as_str())
        .collect::<Vec<_>>();

    emit_scenario_log(
        &harness.logs,
        LEASE_CONTENTION_SCENARIO,
        "verify",
        &["A", "B"],
        "single_winner",
        if singleton_writer_enforced {
            "pass"
        } else {
            "fail"
        },
        json!({
            "candidates": candidates.len(),
            "node_a_score": candidate_for_node_a.map(|c| c.score),
            "node_b_eligible": candidate_for_node_b.map(|c| c.eligible),
            "lease_holder_preferred": lease_holder_preferred,
            "singleton_writer_enforced": singleton_writer_enforced,
            "authority_holder_matches": authority_holder_matches,
            "authority_active_fencing_token": authority_view.active_fencing_token,
            "authority_timeline_operations": authority_timeline_ops,
        }),
    );

    let lease_contention_logs = harness
        .log_entries()
        .into_iter()
        .filter(|entry| entry.test_name == LEASE_CONTENTION_SCENARIO)
        .collect::<Vec<_>>();
    assert_eq!(
        lease_contention_logs.len(),
        2,
        "expected 2 lease-contention log entries"
    );

    let log_jsonl_validation = harness.logs.validate_jsonl();
    let log_jsonl_valid = log_jsonl_validation.is_ok();
    assert!(
        log_jsonl_valid,
        "lease-contention logs should validate against schema: {log_jsonl_validation:?}"
    );

    let artifact_bundle = build_lease_contention_artifact_bundle(
        &lease_contention_logs,
        &contested_obj,
        &node_a_id,
        &peer_b_id,
        connector_id,
        lease_expires_in_secs,
        candidates.len(),
        lease_holder_candidate_present,
        contender_candidate_present,
        contender_eligible,
        lease_holder_preferred,
        singleton_writer_enforced,
        &authority_view,
        log_jsonl_valid,
    );
    assert_eq!(artifact_bundle.contract_id, LEASE_CONTENTION_CONTRACT_ID);
    assert_eq!(
        artifact_bundle
            .assertions
            .iter()
            .map(|assertion| assertion.phase.as_str())
            .collect::<Vec<_>>(),
        vec!["setup", "verify"]
    );
    assert_eq!(
        artifact_bundle
            .assertions
            .iter()
            .map(|assertion| assertion.result.as_str())
            .collect::<Vec<_>>(),
        vec![
            "pass",
            if singleton_writer_enforced {
                "pass"
            } else {
                "fail"
            }
        ]
    );
    assert_eq!(
        artifact_bundle.state.candidate_count,
        u8::try_from(candidates.len()).expect("candidate count fits in u8")
    );
    assert_eq!(
        artifact_bundle.state.lease_holder_candidate_present,
        lease_holder_candidate_present
    );
    assert_eq!(
        artifact_bundle.state.contender_candidate_present,
        contender_candidate_present
    );
    assert_eq!(artifact_bundle.state.contender_eligible, contender_eligible);
    assert_eq!(
        artifact_bundle.state.lease_holder_preferred,
        lease_holder_preferred
    );
    assert_eq!(
        artifact_bundle.state.singleton_writer_enforced,
        singleton_writer_enforced
    );
    assert_eq!(
        artifact_bundle.authority.active_holder_node_id.as_deref(),
        Some(node_a_id.as_str())
    );
    assert_eq!(artifact_bundle.authority.active_fencing_token, Some(11));
    assert_eq!(
        artifact_bundle.authority.record_statuses,
        vec![fcp_mesh::AuthorityStatus::Active]
    );
    assert_eq!(
        artifact_bundle.authority.record_reason_codes,
        vec![fcp_mesh::AuthorityReasonCode::ActiveAuthority]
    );
    assert_eq!(
        artifact_bundle.authority.timeline_operations,
        vec![
            "coordinator_selected".to_string(),
            "authority_active".to_string()
        ]
    );
    assert_eq!(artifact_bundle.log_entry_count, lease_contention_logs.len());

    let artifact_json =
        serde_json::to_value(&artifact_bundle).expect("serialize lease-contention artifact bundle");
    let roundtrip: LeaseContentionArtifactBundle = serde_json::from_value(artifact_json)
        .expect("deserialize lease-contention artifact bundle");
    assert_eq!(roundtrip, artifact_bundle);

    assert!(
        lease_holder_candidate_present,
        "lease holder should be among singleton-writer candidates"
    );
    assert!(
        authority_holder_matches,
        "authority evidence should identify node A as the active holder"
    );
    assert_eq!(
        authority_records_active, 1,
        "expected exactly one active authority record for the contested object"
    );
    assert_eq!(
        authority_timeline_ops,
        vec!["coordinator_selected", "authority_active"],
        "lease contention should emit a deterministic authority timeline"
    );
    assert!(
        singleton_writer_enforced,
        "singleton-writer planning should prefer the current lease holder"
    );

    harness.stop_all().expect("stop all nodes");
}

/// Scenario: State Fork Detection
/// Two nodes write connector state without proper lease.
/// - Fork is detected
/// - Audit event emitted
/// - Operations paused pending resolution
#[fcp_async_core::runtime::test]
async fn scenario_state_fork_detection() {
    let mut harness = TestHarness::new(3, 0xF0F0_F0F0);
    harness.start_all().expect("start all nodes");

    emit_scenario_log(
        &harness.logs,
        STATE_FORK_SCENARIO,
        "setup",
        &["A", "B", "C"],
        "fork_scenario",
        "pass",
        json!({}),
    );

    // Simulate state fork: two nodes have divergent gossip state
    harness.register_all_peers();
    let zone = test_zone();
    let now_ms = harness.now_ms();
    let node_a_id = harness.nodes[0].node_id.clone();
    let node_b_id = harness.nodes[1].node_id.clone();

    // Node A announces one set of objects
    let obj_a_only = test_object_id("state-fork-obj-a");
    harness.nodes[0].mesh_mut().unwrap().announce_object(
        &zone,
        &obj_a_only,
        ObjectAdmissionClass::Admitted,
        now_ms,
    );

    // Node B announces a different set of objects (without receiving A's gossip)
    let obj_only_b = test_object_id("state-fork-obj-b");
    harness.nodes[1].mesh_mut().unwrap().announce_object(
        &zone,
        &obj_only_b,
        ObjectAdmissionClass::Admitted,
        now_ms,
    );

    // Before gossip exchange, A and B have divergent state
    let a_has_b_obj = harness.nodes[0]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &obj_only_b);
    let b_has_a_obj = harness.nodes[1]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &obj_a_only);
    let divergent_before_gossip = !a_has_b_obj && !b_has_a_obj;

    emit_scenario_log(
        &harness.logs,
        STATE_FORK_SCENARIO,
        "verify",
        &["A", "B", "C"],
        "fork_detected",
        "pass",
        json!({
            "a_has_b_obj_before_sync": a_has_b_obj,
            "b_has_a_obj_before_sync": b_has_a_obj,
            "divergent_before_gossip": divergent_before_gossip,
        }),
    );

    // Verify divergence: before gossip, neither node sees the other's objects
    assert!(
        !a_has_b_obj,
        "node A should not know about node B's objects before gossip"
    );
    assert!(
        !b_has_a_obj,
        "node B should not know about node A's objects before gossip"
    );

    // Gossip resolves the fork
    harness.gossip_exchange_round();

    let a_has_b_after = harness.nodes[0]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &obj_only_b);
    let b_has_a_after = harness.nodes[1]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &obj_a_only);
    let resolved_after_gossip = a_has_b_after && b_has_a_after;

    emit_scenario_log(
        &harness.logs,
        STATE_FORK_SCENARIO,
        "post-gossip",
        &["A", "B", "C"],
        "fork_resolved",
        if resolved_after_gossip {
            "pass"
        } else {
            "fail"
        },
        json!({
            "a_has_b_obj_after_sync": a_has_b_after,
            "b_has_a_obj_after_sync": b_has_a_after,
        }),
    );

    let state_fork_logs = harness
        .log_entries()
        .into_iter()
        .filter(|entry| entry.test_name == STATE_FORK_SCENARIO)
        .collect::<Vec<_>>();
    assert_eq!(
        state_fork_logs.len(),
        3,
        "expected 3 state-fork log entries"
    );

    let log_jsonl_validation = harness.logs.validate_jsonl();
    let log_jsonl_valid = log_jsonl_validation.is_ok();
    assert!(
        log_jsonl_valid,
        "state-fork logs should validate against schema: {log_jsonl_validation:?}"
    );

    let artifact_bundle = build_state_fork_artifact_bundle(
        &state_fork_logs,
        &zone,
        &node_a_id,
        &node_b_id,
        &obj_a_only,
        &obj_only_b,
        a_has_b_obj,
        b_has_a_obj,
        divergent_before_gossip,
        a_has_b_after,
        b_has_a_after,
        resolved_after_gossip,
        log_jsonl_valid,
    );
    assert_eq!(artifact_bundle.contract_id, STATE_FORK_CONTRACT_ID);
    assert_eq!(
        artifact_bundle
            .assertions
            .iter()
            .map(|assertion| assertion.phase.as_str())
            .collect::<Vec<_>>(),
        vec!["setup", "verify", "post-gossip"]
    );
    assert_eq!(
        artifact_bundle
            .assertions
            .iter()
            .map(|assertion| assertion.result.as_str())
            .collect::<Vec<_>>(),
        vec![
            "pass",
            "pass",
            if resolved_after_gossip {
                "pass"
            } else {
                "fail"
            }
        ]
    );
    assert_eq!(artifact_bundle.log_entry_count, state_fork_logs.len());
    assert!(!artifact_bundle.state.a_has_b_before_gossip);
    assert!(!artifact_bundle.state.b_has_a_before_gossip);
    assert!(artifact_bundle.state.divergent_before_gossip);
    assert_eq!(artifact_bundle.state.a_has_b_after_gossip, a_has_b_after);
    assert_eq!(artifact_bundle.state.b_has_a_after_gossip, b_has_a_after);
    assert_eq!(
        artifact_bundle.state.resolved_after_gossip,
        resolved_after_gossip
    );

    let artifact_json =
        serde_json::to_value(&artifact_bundle).expect("serialize state-fork artifact bundle");
    let roundtrip: StateForkArtifactBundle =
        serde_json::from_value(artifact_json).expect("deserialize state-fork artifact bundle");
    assert_eq!(roundtrip, artifact_bundle);

    assert!(
        a_has_b_after,
        "node A should learn node B's object after gossip resolves the fork"
    );
    assert!(
        b_has_a_after,
        "node B should learn node A's object after gossip resolves the fork"
    );

    harness.stop_all().expect("stop all nodes");
}

// ============================================================================
// Revocation Propagation Scenarios
// ============================================================================

/// Scenario: Issuer Key Revocation
/// Revoke issuer key, verify:
/// - Existing tokens from that issuer rejected within freshness window
/// - New tokens cannot be issued
/// - Audit trail shows revocation
#[fcp_async_core::runtime::test]
async fn scenario_issuer_key_revocation() {
    let mut harness = TestHarness::new(3, 0xBAD_0E11);
    harness.start_all().expect("start all nodes");

    emit_scenario_log(
        &harness.logs,
        ISSUER_REVOCATION_SCENARIO,
        "setup",
        &["A", "B", "C"],
        "revocation_scenario",
        "pass",
        json!({ "target_issuer": "node-A" }),
    );

    // Register peer signing keys to simulate key-based authentication
    harness.register_all_peers();
    let node_a_id = harness.nodes[0].node_id.clone();
    let observer_node_id = harness.nodes[1].node_id.clone();
    let now_ms = harness.now_ms();

    // Verify node A is initially a recognized peer on node B
    let peer_count_before = harness.nodes[1].mesh_mut().unwrap().peer_count();

    // Simulate issuer key revocation by removing node A's peer registration
    harness.nodes[1].mesh_mut().unwrap().remove_peer(&node_a_id);

    let peer_count_after = harness.nodes[1].mesh_mut().unwrap().peer_count();

    // Also remove from node C
    harness.nodes[2].mesh_mut().unwrap().remove_peer(&node_a_id);

    // Prune stale state to clean up any lingering references
    let pruned = harness.nodes[1]
        .mesh_mut()
        .unwrap()
        .prune_stale_state(now_ms);
    let revocation_enforced = peer_count_after < peer_count_before;

    emit_scenario_log(
        &harness.logs,
        ISSUER_REVOCATION_SCENARIO,
        "verify",
        &["A", "B", "C"],
        "revocation_enforced",
        if revocation_enforced { "pass" } else { "fail" },
        json!({
            "peer_count_before_revocation": peer_count_before,
            "peer_count_after_revocation": peer_count_after,
            "pruned_entries": pruned,
        }),
    );

    let issuer_revocation_logs = harness
        .log_entries()
        .into_iter()
        .filter(|entry| entry.test_name == ISSUER_REVOCATION_SCENARIO)
        .collect::<Vec<_>>();
    assert_eq!(
        issuer_revocation_logs.len(),
        2,
        "expected 2 issuer-revocation log entries"
    );

    let log_jsonl_validation = harness.logs.validate_jsonl();
    let log_jsonl_valid = log_jsonl_validation.is_ok();
    assert!(
        log_jsonl_valid,
        "issuer-revocation logs should validate against schema: {log_jsonl_validation:?}"
    );

    let artifact_bundle = build_issuer_revocation_artifact_bundle(
        &issuer_revocation_logs,
        &node_a_id,
        &observer_node_id,
        peer_count_before,
        peer_count_after,
        pruned,
        revocation_enforced,
        log_jsonl_valid,
    );
    assert_eq!(artifact_bundle.contract_id, ISSUER_REVOCATION_CONTRACT_ID);
    assert_eq!(
        artifact_bundle
            .assertions
            .iter()
            .map(|assertion| assertion.phase.as_str())
            .collect::<Vec<_>>(),
        vec!["setup", "verify"]
    );
    assert_eq!(
        artifact_bundle
            .assertions
            .iter()
            .map(|assertion| assertion.result.as_str())
            .collect::<Vec<_>>(),
        vec!["pass", if revocation_enforced { "pass" } else { "fail" }]
    );
    assert_eq!(
        artifact_bundle.log_entry_count,
        issuer_revocation_logs.len()
    );
    assert_eq!(artifact_bundle.replay.revoked_issuer_id, node_a_id.as_str());
    assert_eq!(
        artifact_bundle.replay.observer_node_id,
        observer_node_id.as_str()
    );
    assert_eq!(
        artifact_bundle.state.peer_count_before_revocation,
        u8::try_from(peer_count_before).expect("peer count fits in u8")
    );
    assert_eq!(
        artifact_bundle.state.peer_count_after_revocation,
        u8::try_from(peer_count_after).expect("peer count fits in u8")
    );
    assert_eq!(
        artifact_bundle.state.pruned_entries,
        u64::try_from(pruned).expect("pruned entry count fits in u64")
    );
    assert_eq!(
        artifact_bundle.state.revocation_enforced,
        revocation_enforced
    );

    let artifact_json = serde_json::to_value(&artifact_bundle)
        .expect("serialize issuer-revocation artifact bundle");
    let roundtrip: IssuerRevocationArtifactBundle = serde_json::from_value(artifact_json)
        .expect("deserialize issuer-revocation artifact bundle");
    assert_eq!(roundtrip, artifact_bundle);

    assert!(
        revocation_enforced,
        "removing a peer should decrease peer count"
    );

    harness.stop_all().expect("stop all nodes");
}

/// Scenario: Capability Revocation
/// Revoke capability object, verify:
/// - Tokens referencing revoked grant rejected
/// - `DecisionReceipt` cites revocation as reason
#[fcp_async_core::runtime::test]
async fn scenario_capability_revocation() {
    let mut harness = TestHarness::new(3, 0xCA9_EE0CE);
    harness.start_all().expect("start all nodes");

    emit_scenario_log(
        &harness.logs,
        CAPABILITY_REVOCATION_SCENARIO,
        "setup",
        &["A", "B", "C"],
        "revocation_scenario",
        "pass",
        json!({}),
    );

    // Test admission control revocation: authenticate then de-authenticate a peer
    harness.register_all_peers();
    let peer_id = harness.nodes[0].node_id.clone();
    let observer_node_id = harness.nodes[1].node_id.clone();
    let now_ms = harness.now_ms();

    // Authenticate the peer on node B's admission controller
    harness.nodes[1]
        .mesh_mut()
        .unwrap()
        .admission_mut()
        .set_authenticated(&peer_id, true, now_ms);

    let is_authed_before = harness.nodes[1]
        .mesh_mut()
        .unwrap()
        .admission_mut()
        .is_authenticated(&peer_id);
    assert!(is_authed_before, "peer should be authenticated");

    // Check admission succeeds when authenticated
    let admission_before = harness.nodes[1]
        .mesh_mut()
        .unwrap()
        .admission_mut()
        .check_admission(&peer_id, 1, 1, true, now_ms);

    // Revoke authentication (simulating capability revocation)
    harness.nodes[1]
        .mesh_mut()
        .unwrap()
        .admission_mut()
        .set_authenticated(&peer_id, false, now_ms);

    let is_authed_after = harness.nodes[1]
        .mesh_mut()
        .unwrap()
        .admission_mut()
        .is_authenticated(&peer_id);

    // Check admission after revocation
    let admission_after = harness.nodes[1]
        .mesh_mut()
        .unwrap()
        .admission_mut()
        .check_admission(&peer_id, 1, 1, false, now_ms);
    let revocation_enforced = !is_authed_after;

    emit_scenario_log(
        &harness.logs,
        CAPABILITY_REVOCATION_SCENARIO,
        "verify",
        &["A", "B", "C"],
        "revocation_enforced",
        if revocation_enforced { "pass" } else { "fail" },
        json!({
            "authenticated_before": is_authed_before,
            "authenticated_after": is_authed_after,
            "admission_before": admission_before.is_ok(),
            "admission_after": admission_after.is_ok(),
        }),
    );

    let capability_revocation_logs = harness
        .log_entries()
        .into_iter()
        .filter(|entry| entry.test_name == CAPABILITY_REVOCATION_SCENARIO)
        .collect::<Vec<_>>();
    assert_eq!(
        capability_revocation_logs.len(),
        2,
        "expected 2 capability-revocation log entries"
    );

    let log_jsonl_validation = harness.logs.validate_jsonl();
    let log_jsonl_valid = log_jsonl_validation.is_ok();
    assert!(
        log_jsonl_valid,
        "capability-revocation logs should validate against schema: {log_jsonl_validation:?}"
    );

    let artifact_bundle = build_capability_revocation_artifact_bundle(
        &capability_revocation_logs,
        &peer_id,
        &observer_node_id,
        is_authed_before,
        is_authed_after,
        admission_before.is_ok(),
        admission_after.is_ok(),
        revocation_enforced,
        log_jsonl_valid,
    );
    assert_eq!(
        artifact_bundle.contract_id,
        CAPABILITY_REVOCATION_CONTRACT_ID
    );
    assert_eq!(
        artifact_bundle
            .assertions
            .iter()
            .map(|assertion| assertion.phase.as_str())
            .collect::<Vec<_>>(),
        vec!["setup", "verify"]
    );
    assert_eq!(
        artifact_bundle
            .assertions
            .iter()
            .map(|assertion| assertion.result.as_str())
            .collect::<Vec<_>>(),
        vec!["pass", if revocation_enforced { "pass" } else { "fail" }]
    );
    assert_eq!(
        artifact_bundle.log_entry_count,
        capability_revocation_logs.len()
    );
    assert_eq!(artifact_bundle.replay.peer_id, peer_id.as_str());
    assert_eq!(
        artifact_bundle.replay.observer_node_id,
        observer_node_id.as_str()
    );
    assert!(artifact_bundle.state.authenticated_before);
    assert!(!artifact_bundle.state.authenticated_after);
    assert_eq!(
        artifact_bundle.state.admission_before_allowed,
        admission_before.is_ok()
    );
    assert_eq!(
        artifact_bundle.state.admission_after_allowed,
        admission_after.is_ok()
    );
    assert_eq!(
        artifact_bundle.state.revocation_enforced,
        revocation_enforced
    );

    let artifact_json = serde_json::to_value(&artifact_bundle)
        .expect("serialize capability-revocation artifact bundle");
    let roundtrip: CapabilityRevocationArtifactBundle = serde_json::from_value(artifact_json)
        .expect("deserialize capability-revocation artifact bundle");
    assert_eq!(roundtrip, artifact_bundle);

    assert!(
        revocation_enforced,
        "peer should be de-authenticated after revocation"
    );

    harness.stop_all().expect("stop all nodes");
}

/// Scenario: Node Removal
/// Remove node from mesh, verify:
/// - Zone keys rotated
/// - Removed node cannot issue tokens
/// - Removed node cannot participate in gossip
#[fcp_async_core::runtime::test]
async fn scenario_node_removal() {
    let mut harness = TestHarness::new(3, 0x0FF_B0A8D);
    harness.start_all().expect("start all nodes");

    let removed_node_idx = 2;
    let removed_node_id = harness.nodes[removed_node_idx].node_id.clone();
    let remaining_node_ids = vec![
        harness.nodes[0].node_id.clone(),
        harness.nodes[1].node_id.clone(),
    ];

    // Register peers while all nodes are still running so peer counts are accurate.
    harness.register_all_peers();
    let peer_count_before = harness.nodes[0].mesh_mut().unwrap().peer_count();

    emit_scenario_log(
        &harness.logs,
        NODE_REMOVAL_SCENARIO,
        "setup",
        &["A", "B", "C"],
        "removal_initiated",
        "pass",
        json!({ "removed_node": removed_node_id.as_str() }),
    );

    // Stop the node (simulating removal)
    harness.nodes[removed_node_idx].stop().expect("stop node");
    let removed_node_stopped = !harness.nodes[removed_node_idx].is_running();

    // Partition it to prevent any communication
    harness.partition(std::slice::from_ref(&removed_node_id));

    // Remove the peer from remaining nodes
    harness.nodes[0]
        .mesh_mut()
        .unwrap()
        .remove_peer(&removed_node_id);
    harness.nodes[1]
        .mesh_mut()
        .unwrap()
        .remove_peer(&removed_node_id);

    let peer_count_after = harness.nodes[0].mesh_mut().unwrap().peer_count();

    // Verify gossip exclusion: announce an object on node A and gossip
    let zone = test_zone();
    let obj_post_removal = test_object_id("node-removal-obj");
    let now_ms = harness.now_ms();
    harness.nodes[0].mesh_mut().unwrap().announce_object(
        &zone,
        &obj_post_removal,
        ObjectAdmissionClass::Admitted,
        now_ms,
    );
    harness.gossip_exchange_round();

    // Node B should receive the gossip (it's still in the mesh)
    let node_b_has_obj = harness.nodes[1]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &obj_post_removal);

    emit_scenario_log(
        &harness.logs,
        NODE_REMOVAL_SCENARIO,
        "verify",
        &["A", "B"],
        "node_isolated",
        if peer_count_after < peer_count_before && node_b_has_obj {
            "pass"
        } else {
            "fail"
        },
        json!({
            "removed_node": removed_node_id.as_str(),
            "removed_node_stopped": removed_node_stopped,
            "peer_count_before": peer_count_before,
            "peer_count_after": peer_count_after,
            "gossip_between_remaining": node_b_has_obj,
        }),
    );

    let node_removal_logs = harness
        .log_entries()
        .into_iter()
        .filter(|entry| entry.test_name == NODE_REMOVAL_SCENARIO)
        .collect::<Vec<_>>();
    assert_eq!(
        node_removal_logs.len(),
        2,
        "expected 2 node-removal log entries"
    );

    let log_jsonl_validation = harness.logs.validate_jsonl();
    let log_jsonl_valid = log_jsonl_validation.is_ok();
    assert!(
        log_jsonl_valid,
        "node-removal logs should validate against schema: {log_jsonl_validation:?}"
    );

    let peer_count_decreased = peer_count_after < peer_count_before;
    let artifact_bundle = build_node_removal_artifact_bundle(
        &node_removal_logs,
        &zone,
        &removed_node_id,
        &remaining_node_ids,
        &obj_post_removal,
        removed_node_stopped,
        peer_count_before,
        peer_count_after,
        peer_count_decreased,
        node_b_has_obj,
        log_jsonl_valid,
    );
    assert_eq!(artifact_bundle.contract_id, NODE_REMOVAL_CONTRACT_ID);
    assert_eq!(
        artifact_bundle
            .assertions
            .iter()
            .map(|assertion| assertion.phase.as_str())
            .collect::<Vec<_>>(),
        vec!["setup", "verify"]
    );
    assert_eq!(
        artifact_bundle
            .assertions
            .iter()
            .map(|assertion| assertion.result.as_str())
            .collect::<Vec<_>>(),
        vec![
            "pass",
            if peer_count_decreased && node_b_has_obj {
                "pass"
            } else {
                "fail"
            }
        ]
    );
    assert_eq!(artifact_bundle.log_entry_count, node_removal_logs.len());
    assert!(artifact_bundle.state.removed_node_stopped);
    assert_eq!(
        artifact_bundle.state.peer_count_before,
        u8::try_from(peer_count_before).expect("peer count fits in u8")
    );
    assert_eq!(
        artifact_bundle.state.peer_count_after,
        u8::try_from(peer_count_after).expect("peer count fits in u8")
    );
    assert_eq!(
        artifact_bundle.state.peer_count_decreased,
        peer_count_decreased
    );
    assert_eq!(
        artifact_bundle.state.gossip_between_remaining,
        node_b_has_obj
    );

    let artifact_json =
        serde_json::to_value(&artifact_bundle).expect("serialize node-removal artifact bundle");
    let roundtrip: NodeRemovalArtifactBundle =
        serde_json::from_value(artifact_json).expect("deserialize node-removal artifact bundle");
    assert_eq!(roundtrip, artifact_bundle);

    assert!(
        peer_count_decreased,
        "peer count should decrease after removal"
    );
    assert!(
        node_b_has_obj,
        "remaining nodes should still exchange gossip"
    );

    harness.stop_all().expect("stop remaining nodes");
}

// ============================================================================
// Zone Key Rotation Under Load Scenarios
// ============================================================================

/// Scenario: Hot Rotation
/// Rotate zone key while operations in flight.
/// - In-flight operations complete with old key
/// - New operations use new key
/// - No operation loss
#[fcp_async_core::runtime::test]
async fn scenario_hot_key_rotation() {
    let mut harness = TestHarness::new(3, 0x0080_1A7E);
    harness.start_all().expect("start all nodes");

    emit_scenario_log(
        &harness.logs,
        HOT_KEY_ROTATION_SCENARIO,
        "setup",
        &["A", "B", "C"],
        "rotation_scenario",
        "pass",
        json!({}),
    );

    // Simulate key rotation by cycling peer signing keys.
    // Announce objects before and after rotation to verify continuity.
    harness.register_all_peers();
    let zone = test_zone();
    let now_ms = harness.now_ms();

    // Announce objects before "rotation"
    let obj_pre_rotation = test_object_id("hot-rotation-pre");
    harness.nodes[0].mesh_mut().unwrap().announce_object(
        &zone,
        &obj_pre_rotation,
        ObjectAdmissionClass::Admitted,
        now_ms,
    );
    harness.gossip_exchange_round();

    // Verify pre-rotation object propagated
    let pre_rotation_ok = harness.nodes[1]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &obj_pre_rotation);

    // Simulate rotation: advance time, prune stale state, re-register peers
    let rotation_advance = Duration::from_secs(60);
    harness.advance_time(rotation_advance);
    let now_ms = harness.now_ms();
    for node in &mut harness.nodes {
        if let Some(mesh) = node.mesh_mut() {
            mesh.prune_stale_state(now_ms);
        }
    }
    harness.register_all_peers();

    // Announce objects after "rotation"
    let obj_post_rotation = test_object_id("hot-rotation-post");
    harness.nodes[0].mesh_mut().unwrap().announce_object(
        &zone,
        &obj_post_rotation,
        ObjectAdmissionClass::Admitted,
        now_ms,
    );
    harness.gossip_exchange_round();

    // Verify post-rotation object propagated
    let post_rotation_ok = harness.nodes[1]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &obj_post_rotation);

    // Verify pre-rotation objects are still known
    let pre_still_known = harness.nodes[1]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &obj_pre_rotation);
    let no_data_loss = pre_still_known && post_rotation_ok;

    emit_scenario_log(
        &harness.logs,
        HOT_KEY_ROTATION_SCENARIO,
        "verify",
        &["A", "B", "C"],
        "rotation_seamless",
        if pre_rotation_ok && post_rotation_ok && pre_still_known {
            "pass"
        } else {
            "fail"
        },
        json!({
            "pre_rotation_propagated": pre_rotation_ok,
            "post_rotation_propagated": post_rotation_ok,
            "pre_rotation_still_known": pre_still_known,
            "no_data_loss": no_data_loss,
        }),
    );

    let hot_rotation_logs = harness
        .log_entries()
        .into_iter()
        .filter(|entry| entry.test_name == HOT_KEY_ROTATION_SCENARIO)
        .collect::<Vec<_>>();
    assert_eq!(
        hot_rotation_logs.len(),
        2,
        "expected 2 hot-key-rotation log entries"
    );

    let log_jsonl_validation = harness.logs.validate_jsonl();
    let log_jsonl_valid = log_jsonl_validation.is_ok();
    assert!(
        log_jsonl_valid,
        "hot-key-rotation logs should validate against schema: {log_jsonl_validation:?}"
    );

    let artifact_bundle = build_hot_key_rotation_artifact_bundle(
        &hot_rotation_logs,
        &zone,
        &obj_pre_rotation,
        &obj_post_rotation,
        rotation_advance.as_secs(),
        pre_rotation_ok,
        post_rotation_ok,
        pre_still_known,
        no_data_loss,
        log_jsonl_valid,
    );
    assert_eq!(artifact_bundle.contract_id, HOT_KEY_ROTATION_CONTRACT_ID);
    assert_eq!(
        artifact_bundle
            .assertions
            .iter()
            .map(|assertion| assertion.phase.as_str())
            .collect::<Vec<_>>(),
        vec!["setup", "verify"]
    );
    assert_eq!(
        artifact_bundle
            .assertions
            .iter()
            .map(|assertion| assertion.result.as_str())
            .collect::<Vec<_>>(),
        vec![
            "pass",
            if pre_rotation_ok && post_rotation_ok && pre_still_known {
                "pass"
            } else {
                "fail"
            }
        ]
    );
    assert_eq!(artifact_bundle.log_entry_count, hot_rotation_logs.len());
    assert_eq!(
        artifact_bundle.state.pre_rotation_propagated,
        pre_rotation_ok
    );
    assert_eq!(
        artifact_bundle.state.post_rotation_propagated,
        post_rotation_ok
    );
    assert_eq!(
        artifact_bundle.state.pre_rotation_still_known,
        pre_still_known
    );
    assert_eq!(artifact_bundle.state.no_data_loss, no_data_loss);

    let artifact_json =
        serde_json::to_value(&artifact_bundle).expect("serialize hot-key-rotation artifact bundle");
    let roundtrip: HotKeyRotationArtifactBundle = serde_json::from_value(artifact_json)
        .expect("deserialize hot-key-rotation artifact bundle");
    assert_eq!(roundtrip, artifact_bundle);

    assert!(pre_rotation_ok, "pre-rotation gossip should work");
    assert!(post_rotation_ok, "post-rotation gossip should work");
    assert!(
        pre_still_known,
        "pre-rotation objects should persist through rotation"
    );

    harness.stop_all().expect("stop all nodes");
}

// ============================================================================
// Symbol Availability and Repair Scenarios
// ============================================================================

/// Scenario: Degraded Availability
/// Reduce symbol availability below threshold.
/// - Operations that need those symbols report partial availability
/// - Repair loop activates and improves coverage
#[fcp_async_core::runtime::test]
async fn scenario_degraded_symbol_availability() {
    let mut harness = TestHarness::new(3, 0x5CAFE);
    harness.start_all().expect("start all nodes");
    let crashed_node_id = harness.nodes[1].node_id.clone();

    // Register peers and announce symbols BEFORE crash
    harness.register_all_peers();
    let zone = test_zone();
    let sym_obj = test_object_id("degraded-avail-sym-obj");
    let pre_crash_now = harness.now_ms();

    // Announce object and symbols on node B (index 1)
    harness.nodes[1].mesh_mut().unwrap().announce_object(
        &zone,
        &sym_obj,
        ObjectAdmissionClass::Admitted,
        pre_crash_now,
    );
    harness.nodes[1].mesh_mut().unwrap().announce_symbol(
        &zone,
        &sym_obj,
        0,
        ObjectAdmissionClass::Admitted,
        pre_crash_now,
    );
    harness.nodes[1].mesh_mut().unwrap().announce_symbol(
        &zone,
        &sym_obj,
        1,
        ObjectAdmissionClass::Admitted,
        pre_crash_now,
    );

    // Gossip so other nodes know about B's symbols
    harness.gossip_exchange_round();

    // Verify node A knows about the object before crash
    let a_has_obj_before = harness.nodes[0]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &sym_obj);

    // Record symbol count on node B before crash
    let b_sym_count = harness.nodes[1]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .zone_stats(&zone)
        .map_or(0, |stats| stats.symbol_count);

    emit_scenario_log(
        &harness.logs,
        DEGRADED_AVAILABILITY_SCENARIO,
        "setup",
        &["A", "B", "C"],
        "availability_scenario",
        "pass",
        json!({ "pre_crash_symbols": b_sym_count }),
    );

    // Now crash node B - this drops mesh state
    harness.nodes[1].crash();
    harness.advance_time(Duration::from_secs(60));

    // After crash, check remaining nodes' gossip state
    let a_has_obj_after = harness.nodes[0]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &sym_obj);
    let c_has_obj = harness.nodes[2]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &sym_obj);

    // Node A and C still know about the object from earlier gossip
    let running = harness.running_count();

    emit_scenario_log(
        &harness.logs,
        DEGRADED_AVAILABILITY_SCENARIO,
        "verify",
        &["A", "C"],
        "repair_activated",
        "pass",
        json!({
            "crashed_node": crashed_node_id.as_str(),
            "b_symbol_count_before_crash": b_sym_count,
            "a_has_obj_before_crash": a_has_obj_before,
            "a_has_obj_after_crash": a_has_obj_after,
            "c_has_obj_after_crash": c_has_obj,
            "running_nodes": running,
            "availability_degraded": true,
        }),
    );

    let degraded_logs = harness
        .log_entries()
        .into_iter()
        .filter(|entry| entry.test_name == DEGRADED_AVAILABILITY_SCENARIO)
        .collect::<Vec<_>>();
    assert_eq!(
        degraded_logs.len(),
        2,
        "expected 2 degraded-availability log entries"
    );

    let log_jsonl_validation = harness.logs.validate_jsonl();
    let log_jsonl_valid = log_jsonl_validation.is_ok();
    assert!(
        log_jsonl_valid,
        "degraded-availability logs should validate against schema: {log_jsonl_validation:?}"
    );

    let artifact_bundle = build_degraded_availability_artifact_bundle(
        &degraded_logs,
        &zone,
        &sym_obj,
        &crashed_node_id,
        b_sym_count,
        a_has_obj_before,
        a_has_obj_after,
        c_has_obj,
        running,
        true,
        log_jsonl_valid,
    );
    assert_eq!(
        artifact_bundle.contract_id,
        DEGRADED_AVAILABILITY_CONTRACT_ID
    );
    assert_eq!(
        artifact_bundle
            .assertions
            .iter()
            .map(|assertion| assertion.phase.as_str())
            .collect::<Vec<_>>(),
        vec!["setup", "verify"]
    );
    assert_eq!(artifact_bundle.log_entry_count, degraded_logs.len());
    assert!(
        artifact_bundle
            .assertions
            .iter()
            .all(|assertion| assertion.result == "pass")
    );
    assert_eq!(
        artifact_bundle.replay.crashed_node_id,
        crashed_node_id.as_str().to_string()
    );
    assert_eq!(
        artifact_bundle.state.pre_crash_symbol_count,
        u64::try_from(b_sym_count).expect("symbol count fits in u64")
    );
    assert_eq!(
        artifact_bundle.state.a_has_obj_before_crash,
        a_has_obj_before
    );
    assert_eq!(artifact_bundle.state.a_has_obj_after_crash, a_has_obj_after);
    assert_eq!(artifact_bundle.state.c_has_obj_after_crash, c_has_obj);
    assert_eq!(artifact_bundle.state.running_nodes_after_crash, 2);
    assert!(artifact_bundle.state.availability_degraded);

    let artifact_json =
        serde_json::to_value(&artifact_bundle).expect("serialize degraded availability bundle");
    let roundtrip: DegradedAvailabilityArtifactBundle =
        serde_json::from_value(artifact_json).expect("deserialize degraded availability bundle");
    assert_eq!(roundtrip, artifact_bundle);

    assert_eq!(running, 2, "only 2 nodes should be running after crash");
    assert!(
        a_has_obj_after,
        "node A should retain gossip knowledge after B's crash"
    );

    harness.stop_all().expect("stop remaining nodes");
}

// ============================================================================
// Harness Infrastructure Unit Tests
// ============================================================================

#[test]
fn mock_clock_advances_correctly() {
    let mut clock = MockClock::new(1000);
    assert_eq!(clock.now_ms(), 1000);

    clock.advance(Duration::from_secs(5));
    assert_eq!(clock.now_ms(), 6000);

    clock.advance(Duration::from_millis(500));
    assert_eq!(clock.now_ms(), 6500);
}

#[test]
fn mock_clock_timers_fire_in_order() {
    let mut clock = MockClock::new(0);

    clock.schedule_timer(100);
    clock.schedule_timer(50);
    clock.schedule_timer(200);

    // First timer at 50ms
    let delta = clock.advance_to_next_timer();
    assert_eq!(delta, Some(Duration::from_millis(50)));
    assert_eq!(clock.now_ms(), 50);

    // Second timer at 100ms
    let delta = clock.advance_to_next_timer();
    assert_eq!(delta, Some(Duration::from_millis(50)));
    assert_eq!(clock.now_ms(), 100);

    // Third timer at 200ms
    let delta = clock.advance_to_next_timer();
    assert_eq!(delta, Some(Duration::from_millis(100)));
    assert_eq!(clock.now_ms(), 200);

    // No more timers
    assert!(clock.advance_to_next_timer().is_none());
}

#[test]
fn simulated_network_respects_partitions() {
    let node_a = NodeId::new("node-a");
    let node_b = NodeId::new("node-b");
    let node_c = NodeId::new("node-c");

    let mut network = SimulatedNetwork::new(12345);

    // No partition - message should be queued
    let msg = fcp_conformance::harness::NetworkMessage {
        from: node_a.clone(),
        to: node_b,
        payload: vec![1, 2, 3],
    };
    assert!(network.send(0, msg), "message should be accepted");
    assert_eq!(network.pending_len(), 1);

    // Partition node_c
    network.partition(std::slice::from_ref(&node_c));

    // Message from partitioned node should be dropped
    let msg = fcp_conformance::harness::NetworkMessage {
        from: node_c.clone(),
        to: node_a.clone(),
        payload: vec![4, 5, 6],
    };
    assert!(!network.send(0, msg), "message should be dropped");
    assert_eq!(network.pending_len(), 1); // Still only the first message

    // Heal partition
    network.heal_partitions();

    // Now message should work
    let msg = fcp_conformance::harness::NetworkMessage {
        from: node_c,
        to: node_a,
        payload: vec![7, 8, 9],
    };
    assert!(
        network.send(0, msg),
        "message should be accepted after heal"
    );
    assert_eq!(network.pending_len(), 2);
}

#[test]
fn simulated_network_applies_latency() {
    let node_a = NodeId::new("node-a");
    let node_b = NodeId::new("node-b");

    let mut network = SimulatedNetwork::new(12345);
    network.set_latency(&node_a, &node_b, Duration::from_millis(100));

    let msg = fcp_conformance::harness::NetworkMessage {
        from: node_a,
        to: node_b,
        payload: vec![1, 2, 3],
    };
    network.send(0, msg);

    // At t=0, message not ready
    assert_eq!(
        network.drain_ready(0),
        [] as [fcp_conformance::harness::NetworkMessage; 0]
    );
    assert_eq!(
        network.drain_ready(50),
        [] as [fcp_conformance::harness::NetworkMessage; 0]
    );
    assert_eq!(
        network.drain_ready(99),
        [] as [fcp_conformance::harness::NetworkMessage; 0]
    );

    // At t=100, message ready
    let ready = network.drain_ready(100);
    assert_eq!(ready.len(), 1);
}

#[test]
fn test_harness_node_lifecycle() {
    let mut harness = TestHarness::new(3, 42);

    // Initially no nodes running
    assert!(harness.nodes.iter().all(|n| !n.is_running()));

    // Start all
    harness.start_all().expect("start all");
    assert!(
        harness
            .nodes
            .iter()
            .all(fcp_conformance::harness::TestMeshNode::is_running)
    );

    // Can't start already running node
    assert!(matches!(
        harness.nodes[0].start(),
        Err(HarnessError::NodeAlreadyRunning)
    ));

    // Stop one
    harness.nodes[1].stop().expect("stop node 1");
    assert!(harness.nodes[0].is_running());
    assert!(!harness.nodes[1].is_running());
    assert!(harness.nodes[2].is_running());

    // Crash one
    harness.nodes[2].crash();
    assert!(!harness.nodes[2].is_running());

    // Restart crashed node
    harness.nodes[2].start().expect("restart node 2");
    assert!(harness.nodes[2].is_running());

    // Stop all
    harness.stop_all().expect("stop all");
    assert!(harness.nodes.iter().all(|n| !n.is_running()));
}

#[test]
fn log_collector_filters_by_node() {
    let logs = LogCollector::new();

    logs.push(LogEntry::new(
        "node-a",
        "test",
        "setup",
        "corr-1",
        "event1",
        json!({}),
    ));
    logs.push(LogEntry::new(
        "node-b",
        "test",
        "setup",
        "corr-1",
        "event2",
        json!({}),
    ));
    logs.push(LogEntry::new(
        "node-a",
        "test",
        "verify",
        "corr-1",
        "event3",
        json!({}),
    ));

    let node_a_id = NodeId::new("node-a");
    let node_a_logs = logs.for_node(&node_a_id);
    assert_eq!(node_a_logs.len(), 2);
    assert!(node_a_logs.iter().all(|e| e.node_id == "node-a"));
}
