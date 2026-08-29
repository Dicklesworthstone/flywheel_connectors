//! E2E tests for the FCP2 Offline/Repair flow.
//!
//! Exercises the offline availability tracking, coverage evaluation,
//! repair controller, and access pattern prediction subsystems end-to-end.

use std::collections::HashMap;
use std::time::Duration;

use fcp_prelude::{
    ObjectHeader, ObjectId, ObjectPlacementPolicy, Provenance, RetentionClass, StorageMeta,
    StoredObject, ZoneId,
};
use fcp_store::{
    AccessPatternTracker, CoverageEvaluation, CoverageHealth, GarbageCollector, GcConfig,
    GcDecisionAction, GcReasonCode, GcRoots, GcRunReport, MemoryObjectStore,
    MemoryObjectStoreConfig, MemorySymbolStore, MemorySymbolStoreConfig, ObjectStore,
    ObjectSymbolMeta, ObjectTransmissionInfo, OfflineAccess, OfflineCapability, OfflineStatus,
    RepairController, RepairControllerConfig, RepairEvaluationReasonCode, RepairEvaluationReport,
    RepairPlan, RepairPlanningOptions, RepairQueueAction, RepairReasonCode, RepairRequest,
    RepairResult, RepairStats, StoredSymbol, SymbolDistribution, SymbolMeta, SymbolStore,
    ZoneLifecycleSnapshot, snapshot_zone_lifecycle,
};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn obj(label: &[u8]) -> ObjectId {
    ObjectId::from_unscoped_bytes(label)
}

fn default_policy() -> ObjectPlacementPolicy {
    ObjectPlacementPolicy {
        min_nodes: 1,
        max_node_fraction_bps: 10_000,
        preferred_devices: Vec::new(),
        excluded_devices: Vec::new(),
        target_coverage_bps: 10_000,
        min_source_diversity: 0,
    }
}

fn strict_policy() -> ObjectPlacementPolicy {
    ObjectPlacementPolicy {
        min_nodes: 3,
        max_node_fraction_bps: 5000,
        preferred_devices: Vec::new(),
        excluded_devices: Vec::new(),
        target_coverage_bps: 15_000,
        min_source_diversity: 3,
    }
}

fn default_repair_config() -> RepairControllerConfig {
    RepairControllerConfig {
        max_concurrent_repairs: 10,
        max_repairs_per_minute: 100,
        repair_interval: Duration::from_secs(60),
        min_deficit_bps: 500,
        max_symbols_per_repair: 100,
        battery_defer_threshold_percent: 20,
    }
}

const OFFLINE_REPAIR_E2E_SCENARIO: &str = "offline_repair_lifecycle_gc";
const OFFLINE_REPAIR_E2E_CONTRACT_ID: &str = "contract.offline_repair_e2e.lifecycle_gc";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct OfflineRepairPhaseAssertion {
    phase: String,
    passed: bool,
    detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)] // persisted evidence schema; regrouping toggles into enums would churn the artifact format with no defect behind it
struct OfflineRepairStateEvidence {
    root_id: ObjectId,
    payload_id: ObjectId,
    expired_id: ObjectId,
    repair_evaluation_before_queue_depth_before: usize,
    repair_evaluation_before_queue_depth_after: usize,
    repair_evaluation_after_queue_depth_before: usize,
    repair_evaluation_after_queue_depth_after: usize,
    repair_evaluation_before_action: RepairQueueAction,
    repair_evaluation_after_action: RepairQueueAction,
    repair_evaluation_before_reason_code: RepairEvaluationReasonCode,
    repair_evaluation_after_reason_code: RepairEvaluationReasonCode,
    repair_plan_before_reason_code: RepairReasonCode,
    plan_action_count_before: usize,
    plan_action_count_after: usize,
    reconstructable_before: bool,
    reconstructable_after: bool,
    placement_before: bool,
    placement_after: bool,
    gc_root_count: usize,
    gc_evicted: usize,
    gc_expired_leases: usize,
    root_retained_after_gc: bool,
    payload_retained_after_gc: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OfflineRepairArtifactBundle {
    scenario_key: String,
    contract_id: String,
    phase_assertions: Vec<OfflineRepairPhaseAssertion>,
    state: OfflineRepairStateEvidence,
    before_repair: ZoneLifecycleSnapshot,
    repair_evaluation_before: RepairEvaluationReport,
    repair_plan_before: RepairPlan,
    after_repair: ZoneLifecycleSnapshot,
    repair_evaluation_after: RepairEvaluationReport,
    repair_plan_after: RepairPlan,
    gc_report: GcRunReport,
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)] // linear evidence-bundle builder; each stage writes one artifact class and splitting would scatter the emission order the test pins
fn build_offline_repair_artifact_bundle(
    root_id: ObjectId,
    payload_id: ObjectId,
    expired_id: ObjectId,
    before_repair: ZoneLifecycleSnapshot,
    repair_evaluation_before: RepairEvaluationReport,
    repair_plan_before: RepairPlan,
    after_repair: ZoneLifecycleSnapshot,
    repair_evaluation_after: RepairEvaluationReport,
    repair_plan_after: RepairPlan,
    gc_report: GcRunReport,
    root_retained_after_gc: bool,
    payload_retained_after_gc: bool,
) -> OfflineRepairArtifactBundle {
    let payload_before = before_repair
        .objects
        .iter()
        .find(|object| object.object_id == payload_id)
        .expect("payload before snapshot present");
    let payload_after = after_repair
        .objects
        .iter()
        .find(|object| object.object_id == payload_id)
        .expect("payload after snapshot present");
    let before_decision = repair_evaluation_before
        .decisions
        .iter()
        .find(|decision| decision.object_id == payload_id)
        .expect("payload queued before repair");
    let after_decision = repair_evaluation_after
        .decisions
        .iter()
        .find(|decision| decision.object_id == payload_id)
        .expect("payload refreshed after repair");
    let plan_action_before = repair_plan_before
        .actions
        .iter()
        .find(|action| action.object_id == payload_id)
        .expect("payload plan action before repair");
    let payload_before_reconstructable = payload_before
        .reconstructable
        .expect("payload before snapshot should expose reconstructable state");
    let payload_after_reconstructable = payload_after
        .reconstructable
        .expect("payload after snapshot should expose reconstructable state");
    let payload_before_meets_placement = payload_before
        .meets_placement_policy
        .expect("payload before snapshot should expose placement state");
    let payload_after_meets_placement = payload_after
        .meets_placement_policy
        .expect("payload after snapshot should expose placement state");

    let phase_assertions = vec![
        OfflineRepairPhaseAssertion {
            phase: "setup".to_string(),
            passed: before_repair.object_count == 3
                && before_repair.reachable_count == 2
                && before_repair.unreachable_count == 1,
            detail: format!(
                "objects={} reachable={} unreachable={}",
                before_repair.object_count,
                before_repair.reachable_count,
                before_repair.unreachable_count
            ),
        },
        OfflineRepairPhaseAssertion {
            phase: "evaluate_before_repair".to_string(),
            passed: repair_evaluation_before.queue_depth_before == 0
                && repair_evaluation_before.queue_depth_after == 1
                && before_decision.action == RepairQueueAction::Queue
                && before_decision.reason_code == RepairEvaluationReasonCode::PolicySloDeficit
                && plan_action_before.reason_code == RepairReasonCode::PolicySloDeficit,
            detail: format!(
                "queue_depth_before={} queue_depth_after={} action={:?} reason={:?}",
                repair_evaluation_before.queue_depth_before,
                repair_evaluation_before.queue_depth_after,
                before_decision.action,
                before_decision.reason_code
            ),
        },
        OfflineRepairPhaseAssertion {
            phase: "repair".to_string(),
            passed: !payload_before_reconstructable
                && !payload_before_meets_placement
                && payload_after_reconstructable
                && payload_after_meets_placement,
            detail: format!(
                "reconstructable_before={payload_before_reconstructable} reconstructable_after={payload_after_reconstructable} placement_before={payload_before_meets_placement} placement_after={payload_after_meets_placement}"
            ),
        },
        OfflineRepairPhaseAssertion {
            phase: "evaluate_after_repair".to_string(),
            passed: repair_evaluation_after.queue_depth_before == 1
                && repair_evaluation_after.queue_depth_after == 0
                && repair_plan_after.actions.is_empty()
                && after_decision.action == RepairQueueAction::Remove
                && after_decision.reason_code == RepairEvaluationReasonCode::Healthy,
            detail: format!(
                "queue_depth_before={} queue_depth_after={} action={:?} reason={:?} remaining_actions={}",
                repair_evaluation_after.queue_depth_before,
                repair_evaluation_after.queue_depth_after,
                after_decision.action,
                after_decision.reason_code,
                repair_plan_after.actions.len()
            ),
        },
        OfflineRepairPhaseAssertion {
            phase: "gc".to_string(),
            passed: gc_report.result.evicted == 1
                && gc_report.result.expired_leases == 1
                && root_retained_after_gc
                && payload_retained_after_gc
                && gc_report.transcript.decisions.iter().any(|decision| {
                    decision.object_id == root_id
                        && decision.reason_code == GcReasonCode::RootCheckpoint
                })
                && gc_report.transcript.decisions.iter().any(|decision| {
                    decision.object_id == payload_id
                        && decision.reason_code == GcReasonCode::ReachableRef
                })
                && gc_report.transcript.decisions.iter().any(|decision| {
                    decision.object_id == expired_id
                        && decision.reason_code == GcReasonCode::LeaseExpired
                        && decision.action == GcDecisionAction::Evict
                }),
            detail: format!(
                "evicted={} expired_leases={} root_retained={} payload_retained={}",
                gc_report.result.evicted,
                gc_report.result.expired_leases,
                root_retained_after_gc,
                payload_retained_after_gc
            ),
        },
    ];

    let state = OfflineRepairStateEvidence {
        root_id,
        payload_id,
        expired_id,
        repair_evaluation_before_queue_depth_before: repair_evaluation_before.queue_depth_before,
        repair_evaluation_before_queue_depth_after: repair_evaluation_before.queue_depth_after,
        repair_evaluation_after_queue_depth_before: repair_evaluation_after.queue_depth_before,
        repair_evaluation_after_queue_depth_after: repair_evaluation_after.queue_depth_after,
        repair_evaluation_before_action: before_decision.action,
        repair_evaluation_after_action: after_decision.action,
        repair_evaluation_before_reason_code: before_decision.reason_code,
        repair_evaluation_after_reason_code: after_decision.reason_code,
        repair_plan_before_reason_code: plan_action_before.reason_code,
        plan_action_count_before: repair_plan_before.actions.len(),
        plan_action_count_after: repair_plan_after.actions.len(),
        reconstructable_before: payload_before_reconstructable,
        reconstructable_after: payload_after_reconstructable,
        placement_before: payload_before_meets_placement,
        placement_after: payload_after_meets_placement,
        gc_root_count: gc_report.transcript.root_count,
        gc_evicted: gc_report.result.evicted,
        gc_expired_leases: gc_report.result.expired_leases,
        root_retained_after_gc,
        payload_retained_after_gc,
    };

    OfflineRepairArtifactBundle {
        scenario_key: OFFLINE_REPAIR_E2E_SCENARIO.to_string(),
        contract_id: OFFLINE_REPAIR_E2E_CONTRACT_ID.to_string(),
        phase_assertions,
        state,
        before_repair,
        repair_evaluation_before,
        repair_plan_before,
        after_repair,
        repair_evaluation_after,
        repair_plan_after,
        gc_report,
    }
}

// ---------------------------------------------------------------------------
// A. OfflineAccess Tests
// ---------------------------------------------------------------------------

#[test]
fn offline_available_when_symbols_meet_threshold() {
    let id = obj(b"available-object");
    let mut access = OfflineAccess::new(id, 10, 20, 256);
    access.set_local_symbols(10);
    assert!(access.can_access());
    assert_eq!(access.status(), OfflineStatus::Available);
}

#[test]
fn offline_available_when_symbols_exceed_threshold() {
    let id = obj(b"over-threshold");
    let mut access = OfflineAccess::new(id, 10, 20, 256);
    access.set_local_symbols(15);
    assert!(access.can_access());
    assert_eq!(access.status(), OfflineStatus::Available);
    assert!(access.coverage_bps() > 10_000);
}

#[test]
fn offline_partial_when_below_threshold() {
    let id = obj(b"partial-object");
    let mut access = OfflineAccess::new(id, 10, 20, 256);
    access.set_local_symbols(5);
    assert!(!access.can_access());
    assert_eq!(access.status(), OfflineStatus::Partial);
}

#[test]
fn offline_not_cached_when_zero() {
    let id = obj(b"not-cached");
    let access = OfflineAccess::new(id, 10, 20, 256);
    assert!(!access.can_access());
    assert_eq!(access.status(), OfflineStatus::NotCached);
    assert_eq!(access.local_symbols, 0);
}

#[test]
fn offline_coverage_bps_calculation() {
    let id = obj(b"coverage-calc");
    let mut access = OfflineAccess::new(id, 10, 20, 256);
    // 5 out of 10 = 50% = 5000 bps
    access.set_local_symbols(5);
    assert_eq!(access.coverage_bps(), 5000);
    // 10 out of 10 = 100% = 10000 bps
    access.set_local_symbols(10);
    assert_eq!(access.coverage_bps(), 10_000);
    // 15 out of 10 = 150% = 15000 bps (overcoverage)
    access.set_local_symbols(15);
    assert_eq!(access.coverage_bps(), 15_000);
}

#[test]
fn offline_coverage_bps_zero_k() {
    let id = obj(b"zero-k");
    let access = OfflineAccess::new(id, 0, 0, 256);
    // k==0 means a zero-symbol object that is trivially reconstructable
    // (no data to reconstruct), so coverage is full (10000 bps),
    // consistent with can_access() returning true for k==0.
    assert_eq!(access.coverage_bps(), 10_000);
}

#[test]
fn offline_coverage_float() {
    let id = obj(b"coverage-float");
    let mut access = OfflineAccess::new(id, 4, 8, 128);
    access.set_local_symbols(2);
    let cov = access.coverage();
    assert!((cov - 0.5).abs() < 0.001);
}

#[test]
fn offline_symbols_needed_correct() {
    let id = obj(b"symbols-needed");
    let mut access = OfflineAccess::new(id, 10, 20, 256);
    access.set_local_symbols(7);
    assert_eq!(access.symbols_needed(), 3);
    access.set_local_symbols(10);
    assert_eq!(access.symbols_needed(), 0);
    access.set_local_symbols(15);
    assert_eq!(access.symbols_needed(), 0);
}

#[test]
fn offline_bytes_needed_correct() {
    let id = obj(b"bytes-needed");
    let mut access = OfflineAccess::new(id, 10, 20, 256);
    access.set_local_symbols(7);
    // needs 3 symbols * 256 bytes = 768
    assert_eq!(access.bytes_needed(), 768);
    access.set_local_symbols(10);
    assert_eq!(access.bytes_needed(), 0);
}

#[test]
fn offline_add_and_remove_symbols() {
    let id = obj(b"add-remove");
    let mut access = OfflineAccess::new(id, 10, 20, 128);
    access.add_symbols(6);
    assert_eq!(access.local_symbols, 6);
    access.add_symbols(4);
    assert_eq!(access.local_symbols, 10);
    assert!(access.can_access());
    access.remove_symbols(3);
    assert_eq!(access.local_symbols, 7);
    assert!(!access.can_access());
}

#[test]
fn offline_add_symbols_saturates() {
    let id = obj(b"saturate");
    let mut access = OfflineAccess::new(id, 10, 20, 128);
    access.set_local_symbols(u32::MAX - 1);
    access.add_symbols(10);
    assert_eq!(access.local_symbols, u32::MAX);
}

#[test]
fn offline_remove_symbols_saturates_at_zero() {
    let id = obj(b"saturate-zero");
    let mut access = OfflineAccess::new(id, 10, 20, 128);
    access.set_local_symbols(3);
    access.remove_symbols(10);
    assert_eq!(access.local_symbols, 0);
    assert_eq!(access.status(), OfflineStatus::NotCached);
}

// ---------------------------------------------------------------------------
// B. OfflineCapability (Aggregate) Tests
// ---------------------------------------------------------------------------

#[test]
fn capability_tracks_multiple_objects() {
    let mut cap = OfflineCapability::new();
    for i in 0..5u8 {
        let mut a = OfflineAccess::new(obj(&[i]), 10, 20, 128);
        a.set_local_symbols(10);
        cap.track(a);
    }
    assert_eq!(cap.object_count(), 5);
}

#[test]
fn capability_readiness_all_available() {
    let mut cap = OfflineCapability::new();
    for i in 0..4u8 {
        let mut a = OfflineAccess::new(obj(&[i]), 10, 20, 128);
        a.set_local_symbols(10);
        cap.track(a);
    }
    assert_eq!(cap.available_count(), 4);
    assert_eq!(cap.readiness_bps(), 10_000);
}

#[test]
fn capability_readiness_partial() {
    let mut cap = OfflineCapability::new();
    // 2 available
    for i in 0..2u8 {
        let mut a = OfflineAccess::new(obj(&[i]), 10, 20, 128);
        a.set_local_symbols(10);
        cap.track(a);
    }
    // 2 partial
    for i in 2..4u8 {
        let mut a = OfflineAccess::new(obj(&[i]), 10, 20, 128);
        a.set_local_symbols(5);
        cap.track(a);
    }
    assert_eq!(cap.object_count(), 4);
    assert_eq!(cap.available_count(), 2);
    // 2/4 = 5000 bps
    assert_eq!(cap.readiness_bps(), 5000);
}

#[test]
fn capability_readiness_empty() {
    let cap = OfflineCapability::new();
    assert_eq!(cap.readiness_bps(), 0);
}

#[test]
fn capability_available_vs_incomplete() {
    let mut cap = OfflineCapability::new();
    // 3 available
    for i in 0..3u8 {
        let mut a = OfflineAccess::new(obj(&[i]), 10, 20, 128);
        a.set_local_symbols(10);
        cap.track(a);
    }
    // 2 incomplete
    for i in 3..5u8 {
        let mut a = OfflineAccess::new(obj(&[i]), 10, 20, 128);
        a.set_local_symbols(4);
        cap.track(a);
    }
    assert_eq!(cap.available_objects().count(), 3);
    assert_eq!(cap.incomplete_objects().count(), 2);
}

#[test]
fn capability_total_bytes_needed() {
    let mut cap = OfflineCapability::new();
    // Object 1: needs 3 symbols * 128 = 384
    let mut a1 = OfflineAccess::new(obj(b"a1"), 10, 20, 128);
    a1.set_local_symbols(7);
    cap.track(a1);
    // Object 2: needs 5 symbols * 256 = 1280
    let mut a2 = OfflineAccess::new(obj(b"a2"), 10, 20, 256);
    a2.set_local_symbols(5);
    cap.track(a2);
    // Object 3: fully available, needs 0
    let mut a3 = OfflineAccess::new(obj(b"a3"), 10, 20, 128);
    a3.set_local_symbols(10);
    cap.track(a3);
    assert_eq!(cap.total_bytes_needed(), 384 + 1280);
}

#[test]
fn capability_objects_by_coverage_sorted() {
    let mut cap = OfflineCapability::new();
    let mut a1 = OfflineAccess::new(obj(b"high"), 10, 20, 128);
    a1.set_local_symbols(9); // 9000 bps
    cap.track(a1);
    let mut a2 = OfflineAccess::new(obj(b"low"), 10, 20, 128);
    a2.set_local_symbols(2); // 2000 bps
    cap.track(a2);
    let mut a3 = OfflineAccess::new(obj(b"mid"), 10, 20, 128);
    a3.set_local_symbols(5); // 5000 bps
    cap.track(a3);

    let sorted = cap.objects_by_coverage();
    assert_eq!(sorted.len(), 3);
    assert_eq!(sorted[0].coverage_bps(), 2000);
    assert_eq!(sorted[1].coverage_bps(), 5000);
    assert_eq!(sorted[2].coverage_bps(), 9000);
}

#[test]
fn capability_get_and_get_mut() {
    let mut cap = OfflineCapability::new();
    let id = obj(b"mutable");
    let a = OfflineAccess::new(id, 10, 20, 128);
    cap.track(a);
    assert!(cap.get(&id).is_some());
    assert_eq!(cap.get(&id).unwrap().local_symbols, 0);
    cap.get_mut(&id).unwrap().set_local_symbols(10);
    assert!(cap.can_access(&id));
}

#[test]
fn capability_remove() {
    let mut cap = OfflineCapability::new();
    let id = obj(b"removable");
    let a = OfflineAccess::new(id, 10, 20, 128);
    cap.track(a);
    assert_eq!(cap.object_count(), 1);
    let removed = cap.remove(&id);
    assert!(removed.is_some());
    assert_eq!(cap.object_count(), 0);
}

#[test]
fn capability_summary() {
    let mut cap = OfflineCapability::new();
    // 2 available
    for i in 0..2u8 {
        let mut a = OfflineAccess::new(obj(&[10 + i]), 10, 20, 128);
        a.set_local_symbols(10);
        cap.track(a);
    }
    // 1 partial
    let mut partial = OfflineAccess::new(obj(&[20]), 10, 20, 128);
    partial.set_local_symbols(5);
    cap.track(partial);
    // 1 not cached
    let nc = OfflineAccess::new(obj(&[30]), 10, 20, 128);
    cap.track(nc);

    let summary = cap.summary();
    assert_eq!(summary.total_objects, 4);
    assert_eq!(summary.available_objects, 2);
    assert_eq!(summary.partial_objects, 1);
    assert_eq!(summary.not_cached_objects, 1);
    assert_eq!(summary.readiness_bps, 5000);
    // partial needs 5*128=640, not_cached needs 10*128=1280
    assert_eq!(summary.bytes_needed, 640 + 1280);
}

// ---------------------------------------------------------------------------
// C. CoverageEvaluation Tests
// ---------------------------------------------------------------------------

#[test]
fn coverage_from_distribution_basic() {
    let id = obj(b"coverage-basic");
    let mut dist = SymbolDistribution::new(10);
    for _ in 0..10 {
        dist.add_symbol(1, 100);
    }
    let eval = CoverageEvaluation::from_distribution(id, &dist);
    assert_eq!(eval.distinct_nodes, 1);
    assert_eq!(eval.coverage_bps, 10_000);
    assert!(eval.is_available);
    assert_eq!(eval.total_symbols, 10);
    assert_eq!(eval.source_symbols, 10);
}

#[test]
fn coverage_from_empty_distribution() {
    let id = obj(b"coverage-empty");
    let dist = SymbolDistribution::new(10);
    let eval = CoverageEvaluation::from_distribution(id, &dist);
    assert_eq!(eval.distinct_nodes, 0);
    assert_eq!(eval.coverage_bps, 0);
    assert!(!eval.is_available);
}

#[test]
fn coverage_healthy_meets_policy() {
    let id = obj(b"healthy");
    let mut dist = SymbolDistribution::new(10);
    // 10 symbols across 1 node
    for _ in 0..10 {
        dist.add_symbol(1, 100);
    }
    let eval = CoverageEvaluation::from_distribution(id, &dist);
    let policy = default_policy();
    assert_eq!(eval.health(&policy), CoverageHealth::Healthy);
    assert!(eval.meets_policy(&policy));
}

#[test]
fn coverage_degraded_but_available() {
    let id = obj(b"degraded");
    let mut dist = SymbolDistribution::new(10);
    // 10 symbols on 1 node but policy requires 3 nodes
    for _ in 0..10 {
        dist.add_symbol(1, 100);
    }
    let eval = CoverageEvaluation::from_distribution(id, &dist);
    let policy = strict_policy(); // min_nodes=3, target=15000
    assert!(eval.is_available);
    assert!(!eval.meets_policy(&policy));
    assert_eq!(eval.health(&policy), CoverageHealth::Degraded);
}

#[test]
fn coverage_unavailable() {
    let id = obj(b"unavailable");
    let mut dist = SymbolDistribution::new(10);
    // Only 5 symbols, need 10
    for _ in 0..5 {
        dist.add_symbol(1, 100);
    }
    let eval = CoverageEvaluation::from_distribution(id, &dist);
    let policy = default_policy();
    assert!(!eval.is_available);
    assert_eq!(eval.health(&policy), CoverageHealth::Unavailable);
}

#[test]
fn coverage_deficit_bps_correct() {
    let id = obj(b"deficit");
    let mut dist = SymbolDistribution::new(10);
    for _ in 0..7 {
        dist.add_symbol(1, 100);
    }
    let eval = CoverageEvaluation::from_distribution(id, &dist);
    // 7/10 = 7000 bps, target 10000 => deficit 3000
    assert_eq!(eval.coverage_bps, 7000);
    assert_eq!(eval.coverage_deficit_bps(10_000), 3000);
}

#[test]
fn coverage_deficit_bps_zero_when_above_target() {
    let id = obj(b"no-deficit");
    let mut dist = SymbolDistribution::new(10);
    for _ in 0..15 {
        dist.add_symbol(1, 100);
    }
    let eval = CoverageEvaluation::from_distribution(id, &dist);
    assert_eq!(eval.coverage_deficit_bps(10_000), 0);
}

#[test]
fn coverage_symbols_needed_for_target() {
    let id = obj(b"symbols-target");
    let mut dist = SymbolDistribution::new(10);
    for _ in 0..7 {
        dist.add_symbol(1, 100);
    }
    let eval = CoverageEvaluation::from_distribution(id, &dist);
    // target 10000 bps => need 10 symbols, have 7, need 3 more
    assert_eq!(eval.symbols_needed(10_000), 3);
    // target 15000 bps => need 15 symbols, have 7, need 8 more
    assert_eq!(eval.symbols_needed(15_000), 8);
    // Already above 7000 => need 0
    assert_eq!(eval.symbols_needed(7000), 0);
}

#[test]
fn coverage_max_node_fraction() {
    let id = obj(b"fraction");
    let mut dist = SymbolDistribution::new(10);
    // Node 1: 6 symbols, Node 2: 4 symbols = 10 total
    for _ in 0..6 {
        dist.add_symbol(1, 100);
    }
    for _ in 0..4 {
        dist.add_symbol(2, 100);
    }
    let eval = CoverageEvaluation::from_distribution(id, &dist);
    assert_eq!(eval.distinct_nodes, 2);
    // max_node_fraction = 6/10 = 6000 bps
    assert_eq!(eval.max_node_fraction_bps, 6000);
}

#[test]
fn coverage_distributed_three_nodes() {
    let id = obj(b"three-nodes");
    let mut dist = SymbolDistribution::new(10);
    for _ in 0..4 {
        dist.add_symbol(1, 100);
    }
    for _ in 0..3 {
        dist.add_symbol(2, 100);
    }
    for _ in 0..3 {
        dist.add_symbol(3, 100);
    }
    let eval = CoverageEvaluation::from_distribution(id, &dist);
    assert_eq!(eval.distinct_nodes, 3);
    assert_eq!(eval.coverage_bps, 10_000);
    // max fraction = 4/10 = 4000 bps
    assert_eq!(eval.max_node_fraction_bps, 4000);
    assert!(eval.is_available);
}

#[test]
fn coverage_overcoverage() {
    let id = obj(b"over");
    let mut dist = SymbolDistribution::new(10);
    for _ in 0..20 {
        dist.add_symbol(1, 100);
    }
    let eval = CoverageEvaluation::from_distribution(id, &dist);
    assert_eq!(eval.coverage_bps, 20_000);
    assert!(eval.is_available);
}

#[test]
fn coverage_diversity_bps() {
    let id = obj(b"div-bps");
    let mut dist = SymbolDistribution::new(10);
    for _ in 0..5 {
        dist.add_symbol(1, 100);
    }
    for _ in 0..5 {
        dist.add_symbol(2, 100);
    }
    let eval = CoverageEvaluation::from_distribution(id, &dist);
    // No diversity requirement => 10000
    assert_eq!(eval.diversity_bps(0), 10_000);
    // min_diversity=2, have 2 => 10000
    assert_eq!(eval.diversity_bps(2), 10_000);
    // min_diversity=4, have 2 => 2/4 * 10000 = 5000
    assert_eq!(eval.diversity_bps(4), 5000);
}

#[test]
fn coverage_diversity_deficit() {
    let id = obj(b"div-deficit");
    let mut dist = SymbolDistribution::new(10);
    for _ in 0..10 {
        dist.add_symbol(1, 100);
    }
    let eval = CoverageEvaluation::from_distribution(id, &dist);
    // 1 node, need 3 => deficit of 2
    assert_eq!(eval.diversity_deficit(3), 2);
    // 1 node, need 1 => deficit of 0
    assert_eq!(eval.diversity_deficit(1), 0);
    // 1 node, need 0 => deficit of 0
    assert_eq!(eval.diversity_deficit(0), 0);
}

#[test]
fn coverage_concentration_deficit_bps() {
    let id = obj(b"conc-deficit");
    let mut dist = SymbolDistribution::new(10);
    // All 10 symbols on node 1 => fraction = 10000 bps
    for _ in 0..10 {
        dist.add_symbol(1, 100);
    }
    let eval = CoverageEvaluation::from_distribution(id, &dist);
    assert_eq!(eval.max_node_fraction_bps, 10_000);
    // max allowed 5000 => deficit 5000
    assert_eq!(eval.concentration_deficit_bps(5000), 5000);
    // max allowed 10000 => no deficit
    assert_eq!(eval.concentration_deficit_bps(10_000), 0);
}

#[test]
fn coverage_meets_diversity_for_reconstruction() {
    let id = obj(b"div-recon");
    let mut dist = SymbolDistribution::new(10);
    for _ in 0..5 {
        dist.add_symbol(1, 100);
    }
    for _ in 0..5 {
        dist.add_symbol(2, 100);
    }
    let eval = CoverageEvaluation::from_distribution(id, &dist);
    let policy = ObjectPlacementPolicy {
        min_nodes: 2,
        max_node_fraction_bps: 6000,
        preferred_devices: Vec::new(),
        excluded_devices: Vec::new(),
        target_coverage_bps: 10_000,
        min_source_diversity: 2,
    };
    assert!(eval.meets_diversity_for_reconstruction(&policy));
}

// ---------------------------------------------------------------------------
// D. Repair Controller Tests
// ---------------------------------------------------------------------------

#[test]
fn repair_queue_and_dequeue() {
    let controller = RepairController::new(default_repair_config());
    let id = obj(b"repair-obj");
    let mut dist = SymbolDistribution::new(10);
    for _ in 0..5 {
        dist.add_symbol(1, 100);
    }
    let coverage = CoverageEvaluation::from_distribution(id, &dist);
    let policy = default_policy();
    controller.queue_repair(RepairRequest {
        object_id: id,
        zone_id: ZoneId::work(),
        coverage,
        policy,
        priority: 100,
    });
    assert_eq!(controller.queue_depth(), 1);
    let next = controller.next_repair();
    assert!(next.is_some());
    assert_eq!(next.unwrap().object_id, id);
    assert_eq!(controller.queue_depth(), 0);
}

#[test]
fn repair_priority_ordering() {
    let controller = RepairController::new(default_repair_config());
    let policy = default_policy();

    // Queue low-priority first
    let id_low = obj(b"low-pri");
    let mut dist_low = SymbolDistribution::new(10);
    for _ in 0..7 {
        dist_low.add_symbol(1, 100);
    }
    let cov_low = CoverageEvaluation::from_distribution(id_low, &dist_low);
    controller.queue_repair(RepairRequest {
        object_id: id_low,
        zone_id: ZoneId::work(),
        coverage: cov_low,
        policy: policy.clone(),
        priority: 50,
    });

    // Queue high-priority second
    let id_high = obj(b"high-pri");
    let mut dist_high = SymbolDistribution::new(10);
    for _ in 0..3 {
        dist_high.add_symbol(1, 100);
    }
    let cov_high = CoverageEvaluation::from_distribution(id_high, &dist_high);
    controller.queue_repair(RepairRequest {
        object_id: id_high,
        zone_id: ZoneId::work(),
        coverage: cov_high,
        policy,
        priority: 200,
    });

    assert_eq!(controller.queue_depth(), 2);
    // Higher priority should come first
    let first = controller.next_repair().unwrap();
    assert_eq!(first.priority, 200);
    assert_eq!(first.object_id, id_high);
    let second = controller.next_repair().unwrap();
    assert_eq!(second.priority, 50);
}

#[test]
fn repair_deduplicates_same_object() {
    let controller = RepairController::new(default_repair_config());
    let id = obj(b"dedup-obj");
    let policy = default_policy();
    let mut dist = SymbolDistribution::new(10);
    for _ in 0..5 {
        dist.add_symbol(1, 100);
    }
    let coverage = CoverageEvaluation::from_distribution(id, &dist);

    controller.queue_repair(RepairRequest {
        object_id: id,
        zone_id: ZoneId::work(),
        coverage: coverage.clone(),
        policy: policy.clone(),
        priority: 100,
    });
    // Same object, different priority — should be deduplicated
    controller.queue_repair(RepairRequest {
        object_id: id,
        zone_id: ZoneId::work(),
        coverage,
        policy,
        priority: 200,
    });
    assert_eq!(controller.queue_depth(), 1);
}

#[test]
fn repair_concurrent_limit() {
    let config = RepairControllerConfig {
        max_concurrent_repairs: 2,
        ..default_repair_config()
    };
    let controller = RepairController::new(config);

    let p1 = controller.try_acquire_permit();
    assert!(p1.is_some());
    let p2 = controller.try_acquire_permit();
    assert!(p2.is_some());
    // Third should fail
    let p3 = controller.try_acquire_permit();
    assert!(p3.is_none());

    // Drop one permit and try again
    drop(p1);
    let p4 = controller.try_acquire_permit();
    assert!(p4.is_some());
}

#[test]
fn repair_result_success_updates_stats() {
    let controller = RepairController::new(default_repair_config());
    let result = RepairResult {
        object_id: obj(b"success-obj"),
        success: true,
        new_coverage_bps: 10_000,
        symbols_added: 5,
        error: None,
    };
    controller.record_result(&result);
    let stats = controller.stats();
    assert_eq!(stats.repairs_attempted, 1);
    assert_eq!(stats.repairs_succeeded, 1);
    assert_eq!(stats.repairs_failed, 0);
    assert_eq!(stats.symbols_added, 5);
}

#[test]
fn repair_result_failure_updates_stats() {
    let controller = RepairController::new(default_repair_config());
    let result = RepairResult {
        object_id: obj(b"fail-obj"),
        success: false,
        new_coverage_bps: 5000,
        symbols_added: 0,
        error: Some("network error".to_string()),
    };
    controller.record_result(&result);
    let stats = controller.stats();
    assert_eq!(stats.repairs_attempted, 1);
    assert_eq!(stats.repairs_succeeded, 0);
    assert_eq!(stats.repairs_failed, 1);
    assert_eq!(stats.symbols_added, 0);
}

#[test]
fn repair_multiple_results_accumulate() {
    let controller = RepairController::new(default_repair_config());
    for i in 0..5 {
        controller.record_result(&RepairResult {
            object_id: obj(&[i]),
            success: true,
            new_coverage_bps: 10_000,
            symbols_added: 3,
            error: None,
        });
    }
    controller.record_result(&RepairResult {
        object_id: obj(b"fail"),
        success: false,
        new_coverage_bps: 0,
        symbols_added: 0,
        error: Some("timeout".to_string()),
    });
    let stats = controller.stats();
    assert_eq!(stats.repairs_attempted, 6);
    assert_eq!(stats.repairs_succeeded, 5);
    assert_eq!(stats.repairs_failed, 1);
    assert_eq!(stats.symbols_added, 15);
}

#[test]
fn repair_needs_repair_unavailable() {
    let controller = RepairController::new(default_repair_config());
    let id = obj(b"unavail");
    let mut dist = SymbolDistribution::new(10);
    for _ in 0..3 {
        dist.add_symbol(1, 100);
    }
    let coverage = CoverageEvaluation::from_distribution(id, &dist);
    let policy = default_policy();
    assert!(controller.needs_repair(&coverage, &policy));
}

#[test]
fn repair_needs_repair_healthy_no_repair() {
    let controller = RepairController::new(default_repair_config());
    let id = obj(b"healthy-obj");
    let mut dist = SymbolDistribution::new(10);
    for _ in 0..10 {
        dist.add_symbol(1, 100);
    }
    let coverage = CoverageEvaluation::from_distribution(id, &dist);
    let policy = default_policy();
    assert!(!controller.needs_repair(&coverage, &policy));
}

#[test]
fn repair_calculate_priority_unavailable_highest() {
    let controller = RepairController::new(default_repair_config());
    let policy = default_policy();

    // Unavailable object — should get priority >= 1000
    let id_unavail = obj(b"unavail-pri");
    let mut dist_u = SymbolDistribution::new(10);
    for _ in 0..3 {
        dist_u.add_symbol(1, 100);
    }
    let cov_u = CoverageEvaluation::from_distribution(id_unavail, &dist_u);
    let pri_u = controller.calculate_priority(&cov_u, &policy);
    assert!(pri_u >= 1000);

    // Healthy object — priority 0
    let id_healthy = obj(b"healthy-pri");
    let mut dist_h = SymbolDistribution::new(10);
    for _ in 0..10 {
        dist_h.add_symbol(1, 100);
    }
    let cov_h = CoverageEvaluation::from_distribution(id_healthy, &dist_h);
    let pri_h = controller.calculate_priority(&cov_h, &policy);
    assert_eq!(pri_h, 0);

    assert!(pri_u > pri_h);
}

#[test]
fn repair_clear_queue() {
    let controller = RepairController::new(default_repair_config());
    let policy = default_policy();
    for i in 0..5u8 {
        let id = obj(&[i]);
        let mut dist = SymbolDistribution::new(10);
        for _ in 0..5 {
            dist.add_symbol(u64::from(i), 100);
        }
        let coverage = CoverageEvaluation::from_distribution(id, &dist);
        controller.queue_repair(RepairRequest {
            object_id: id,
            zone_id: ZoneId::work(),
            coverage,
            policy: policy.clone(),
            priority: u32::from(i) * 10,
        });
    }
    assert_eq!(controller.queue_depth(), 5);
    controller.clear_queue();
    assert_eq!(controller.queue_depth(), 0);
    assert!(controller.next_repair().is_none());
}

#[test]
fn repair_empty_queue_returns_none() {
    let controller = RepairController::new(default_repair_config());
    assert!(controller.next_repair().is_none());
}

// ---------------------------------------------------------------------------
// E. AccessPatternTracker Tests
// ---------------------------------------------------------------------------

#[test]
fn access_pattern_records_and_scores() {
    let mut tracker = AccessPatternTracker::new();
    let id = obj(b"accessed");
    tracker.record_access(id);
    assert_eq!(tracker.access_count(&id), 1);
    // Score should be positive immediately after recording
    let score = tracker.priority_score(&id);
    assert!(score > 0.0);
}

#[test]
fn access_pattern_untracked_score_zero() {
    let tracker = AccessPatternTracker::new();
    let id = obj(b"unknown");
    assert_eq!(tracker.priority_score(&id), 0.0);
    assert_eq!(tracker.access_count(&id), 0);
}

#[test]
fn access_pattern_multiple_accesses_increase_count() {
    let mut tracker = AccessPatternTracker::new();
    let id = obj(b"multi-access");
    for _ in 0..5 {
        tracker.record_access(id);
    }
    assert_eq!(tracker.access_count(&id), 5);
}

#[test]
fn access_pattern_decay() {
    let mut tracker = AccessPatternTracker::new();
    let id = obj(b"decay-obj");
    tracker.record_access(id);
    let score_before = tracker.priority_score(&id);
    tracker.decay_all(0.5);
    let score_after = tracker.priority_score(&id);
    // After 50% decay, the EWMA frequency halves, so score decreases
    assert!(score_after < score_before);
}

#[test]
fn access_pattern_decay_zero_eliminates_scores() {
    let mut tracker = AccessPatternTracker::new();
    let id = obj(b"decay-zero");
    tracker.record_access(id);
    tracker.decay_all(0.0);
    let score = tracker.priority_score(&id);
    assert!((score - 0.0).abs() < f64::EPSILON);
}

#[test]
fn access_pattern_top_n() {
    let mut tracker = AccessPatternTracker::new();
    let id_a = obj(b"top-a");
    let id_b = obj(b"top-b");
    let id_c = obj(b"top-c");

    // All objects get recorded, all have ewma_frequency=1.0 since EWMA
    // converges to 1.0 when each access contributes value 1.0.
    tracker.record_access(id_a);
    tracker.record_access(id_b);
    tracker.record_access(id_c);

    // Now decay all, then re-access only id_b — its score will be boosted
    tracker.decay_all(0.1); // reduce all to 10% of original
    tracker.record_access(id_b); // re-record boosts id_b's EWMA

    let top = tracker.top_n(2);
    assert_eq!(top.len(), 2);
    // id_b should be first since it was accessed after decay
    assert_eq!(top[0].0, id_b);
    // The other two have equal (decayed) scores — just verify top_n truncates
    assert!(top[1].0 == id_a || top[1].0 == id_c);
}

#[test]
fn access_pattern_prioritized_order() {
    let mut tracker = AccessPatternTracker::new();
    let id1 = obj(b"p-one");
    let id2 = obj(b"p-two");
    let id3 = obj(b"p-three");

    // Initial access for all
    tracker.record_access(id1);
    tracker.record_access(id2);
    tracker.record_access(id3);

    // Decay, then selectively re-access to create differentiated scores
    tracker.decay_all(0.1);
    // id2 gets re-accessed (highest score)
    tracker.record_access(id2);
    // Decay again, then re-access id3
    tracker.decay_all(0.1);
    tracker.record_access(id3);

    let prioritized = tracker.prioritized_objects();
    assert_eq!(prioritized.len(), 3);
    // Scores should be in descending order
    assert!(prioritized[0].1 >= prioritized[1].1);
    assert!(prioritized[1].1 >= prioritized[2].1);
    // id3 was re-accessed most recently after last decay => highest EWMA
    assert_eq!(prioritized[0].0, id3);
}

#[test]
fn access_pattern_tracked_count() {
    let mut tracker = AccessPatternTracker::new();
    assert_eq!(tracker.tracked_count(), 0);
    tracker.record_access(obj(b"x"));
    tracker.record_access(obj(b"y"));
    assert_eq!(tracker.tracked_count(), 2);
}

#[test]
fn access_pattern_clear() {
    let mut tracker = AccessPatternTracker::new();
    tracker.record_access(obj(b"clear-me"));
    tracker.record_access(obj(b"clear-me-too"));
    assert_eq!(tracker.tracked_count(), 2);
    tracker.clear();
    assert_eq!(tracker.tracked_count(), 0);
}

#[test]
fn access_pattern_with_config() {
    let tracker = AccessPatternTracker::with_config(0.5, Duration::from_secs(300), 100);
    assert_eq!(tracker.tracked_count(), 0);
}

#[test]
fn access_pattern_eviction_at_capacity() {
    let mut tracker = AccessPatternTracker::with_config(0.3, Duration::from_secs(3600), 3);
    tracker.record_access(obj(b"ev-1"));
    tracker.record_access(obj(b"ev-2"));
    tracker.record_access(obj(b"ev-3"));
    assert_eq!(tracker.tracked_count(), 3);
    // Adding a 4th should evict the oldest
    tracker.record_access(obj(b"ev-4"));
    assert_eq!(tracker.tracked_count(), 3);
}

// ---------------------------------------------------------------------------
// F. E2E Flow Tests
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_lines)]
#[test]
fn offline_repair_full_flow() {
    // Phase 1: Setup — create objects with encoding parameters
    let mut cap = OfflineCapability::new();
    let ids: Vec<ObjectId> = (0..5u8).map(|i| obj(&[100 + i])).collect();
    for &id in &ids {
        let mut access = OfflineAccess::new(id, 10, 20, 256);
        access.set_local_symbols(10);
        cap.track(access);
    }

    // Phase 2: Verify initial coverage — all objects available
    assert_eq!(cap.available_count(), 5);
    assert_eq!(cap.readiness_bps(), 10_000);
    for &id in &ids {
        assert!(cap.can_access(&id));
    }

    // Phase 3: Simulate node failure — reduce symbols on 2 objects
    cap.get_mut(&ids[0]).unwrap().remove_symbols(5); // 10 -> 5 (partial)
    cap.get_mut(&ids[1]).unwrap().set_local_symbols(0); // not cached

    assert_eq!(cap.available_count(), 3);
    assert_eq!(cap.readiness_bps(), 6000); // 3/5 = 6000 bps
    assert_eq!(cap.get(&ids[0]).unwrap().status(), OfflineStatus::Partial);
    assert_eq!(cap.get(&ids[1]).unwrap().status(), OfflineStatus::NotCached);

    // Phase 4: Repair controller queues repairs
    let controller = RepairController::new(default_repair_config());
    let policy = default_policy();

    for &id in &[ids[0], ids[1]] {
        let access = cap.get(&id).unwrap();
        let mut dist = SymbolDistribution::new(access.k);
        for _ in 0..access.local_symbols {
            dist.add_symbol(1, u64::from(access.symbol_size));
        }
        let coverage = CoverageEvaluation::from_distribution(id, &dist);
        if controller.needs_repair(&coverage, &policy) {
            let priority = controller.calculate_priority(&coverage, &policy);
            controller.queue_repair(RepairRequest {
                object_id: id,
                zone_id: ZoneId::work(),
                coverage,
                policy: policy.clone(),
                priority,
            });
        }
    }

    assert_eq!(controller.queue_depth(), 2);

    // Phase 5: Process repairs and verify recovery
    while let Some(request) = controller.next_repair() {
        let symbols_to_add = request.coverage.symbols_needed(10_000);
        // Simulate repair success
        controller.record_result(&RepairResult {
            object_id: request.object_id,
            success: true,
            new_coverage_bps: 10_000,
            symbols_added: symbols_to_add,
            error: None,
        });
        // Update the offline capability
        if let Some(access) = cap.get_mut(&request.object_id) {
            access.add_symbols(symbols_to_add);
        }
    }

    // All objects should be available again
    assert_eq!(cap.available_count(), 5);
    assert_eq!(cap.readiness_bps(), 10_000);
    let stats = controller.stats();
    assert_eq!(stats.repairs_attempted, 2);
    assert_eq!(stats.repairs_succeeded, 2);
    assert_eq!(stats.repairs_failed, 0);
}

#[fcp_async_core::runtime::test]
async fn offline_repair_artifact_bundle_captures_lifecycle_and_gc_evidence() {
    let zone = ZoneId::work();
    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    let symbol_store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
    let controller = RepairController::new(default_repair_config());
    let gc = GarbageCollector::new(GcConfig {
        max_evictions_per_run: 4,
        ..GcConfig::default()
    });

    let root_id = obj(b"artifact-root");
    let payload_id = obj(b"artifact-payload");
    let expired_id = obj(b"artifact-expired");
    let placement = ObjectPlacementPolicy {
        min_nodes: 2,
        max_node_fraction_bps: 10_000,
        preferred_devices: Vec::new(),
        excluded_devices: Vec::new(),
        target_coverage_bps: 10_000,
        min_source_diversity: 2,
    };

    let object = |object_id: ObjectId,
                  refs: Vec<ObjectId>,
                  retention: RetentionClass,
                  ttl_secs: Option<u64>,
                  placement: Option<ObjectPlacementPolicy>,
                  fill: u8| {
        StoredObject {
            object_id,
            header: ObjectHeader {
                schema: fcp_core::ConnectorBinarySymbolSet::schema(),
                zone_id: zone.clone(),
                created_at: 1_700_000_000,
                provenance: Provenance::new(zone.clone()),
                refs,
                foreign_refs: vec![],
                ttl_secs,
                placement,
            },
            body: vec![fill; 64],
            storage: StorageMeta { retention },
        }
    };

    store
        .put(object(
            root_id,
            vec![payload_id],
            RetentionClass::Ephemeral,
            None,
            None,
            0x11,
        ))
        .await
        .expect("put root");
    store
        .put(object(
            payload_id,
            vec![],
            RetentionClass::Lease { expires_at: 5_000 },
            Some(600),
            Some(placement.clone()),
            0x22,
        ))
        .await
        .expect("put payload");
    store
        .put(object(
            expired_id,
            vec![],
            RetentionClass::Lease { expires_at: 500 },
            None,
            None,
            0x33,
        ))
        .await
        .expect("put expired lease");

    symbol_store
        .put_object_meta(ObjectSymbolMeta {
            object_id: payload_id,
            zone_id: zone.clone(),
            oti: ObjectTransmissionInfo {
                transfer_length: 1024,
                symbol_size: 256,
                source_blocks: 1,
                sub_blocks: 1,
                alignment: 1,
                payload_hash: None,
            },
            source_symbols: 3,
            first_symbol_at: 1_000,
        })
        .await
        .expect("put payload meta");
    for esi in 0..2 {
        symbol_store
            .put_symbol(StoredSymbol {
                meta: SymbolMeta {
                    object_id: payload_id,
                    esi,
                    zone_id: zone.clone(),
                    source_node: Some(1),
                    stored_at: 1_000 + u64::from(esi),
                },
                data: vec![u8::try_from(esi).expect("esi fits in u8"); 256].into(),
            })
            .await
            .expect("put degraded repair symbol");
    }

    let mut roots = GcRoots::new();
    roots.set_checkpoint(root_id);

    let policies = HashMap::from([(payload_id, placement.clone())]);
    let repair_evaluation_before = controller
        .evaluate_zone_with_report(&zone, &symbol_store, &policies)
        .await;
    assert_eq!(repair_evaluation_before.queue_depth_before, 0);
    assert_eq!(repair_evaluation_before.queue_depth_after, 1);
    assert_eq!(repair_evaluation_before.decisions.len(), 1);
    assert_eq!(
        repair_evaluation_before.decisions[0].action,
        RepairQueueAction::Queue
    );
    assert_eq!(
        repair_evaluation_before.decisions[0].reason_code,
        RepairEvaluationReasonCode::PolicySloDeficit
    );
    let plan_before = controller
        .plan_zone(
            &zone,
            &symbol_store,
            &policies,
            &RepairPlanningOptions::default(),
        )
        .await;
    assert_eq!(plan_before.actions.len(), 1);
    assert_eq!(plan_before.actions[0].object_id, payload_id);
    assert_eq!(
        plan_before.actions[0].reason_code,
        RepairReasonCode::PolicySloDeficit
    );

    let before_snapshot =
        snapshot_zone_lifecycle(&zone, &roots, &store, Some(&symbol_store), 1_500)
            .await
            .expect("snapshot before repair");
    assert_eq!(before_snapshot.object_count, 3);
    assert_eq!(before_snapshot.reachable_count, 2);
    assert_eq!(before_snapshot.unreachable_count, 1);
    assert_eq!(before_snapshot.reconstructable_count, Some(0));
    let payload_before = before_snapshot
        .objects
        .iter()
        .find(|object| object.object_id == payload_id)
        .expect("payload before snapshot");
    assert!(payload_before.reachable_from_roots);
    assert_eq!(payload_before.reconstructable, Some(false));
    assert_eq!(payload_before.meets_placement_policy, Some(false));

    symbol_store
        .put_symbol(StoredSymbol {
            meta: SymbolMeta {
                object_id: payload_id,
                esi: 2,
                zone_id: zone.clone(),
                source_node: Some(2),
                stored_at: 1_600,
            },
            data: vec![0x7F; 256].into(),
        })
        .await
        .expect("put repaired symbol");

    let plan_after = controller
        .plan_zone(
            &zone,
            &symbol_store,
            &policies,
            &RepairPlanningOptions::default(),
        )
        .await;
    assert!(
        plan_after.actions.is_empty(),
        "recovered coverage should clear the repair plan"
    );
    let repair_evaluation_after = controller
        .evaluate_zone_with_report(&zone, &symbol_store, &policies)
        .await;
    assert_eq!(repair_evaluation_after.queue_depth_before, 1);
    assert_eq!(repair_evaluation_after.queue_depth_after, 0);
    assert_eq!(repair_evaluation_after.decisions.len(), 1);
    assert_eq!(
        repair_evaluation_after.decisions[0].action,
        RepairQueueAction::Remove
    );
    assert_eq!(
        repair_evaluation_after.decisions[0].reason_code,
        RepairEvaluationReasonCode::Healthy
    );

    let after_snapshot = snapshot_zone_lifecycle(&zone, &roots, &store, Some(&symbol_store), 2_000)
        .await
        .expect("snapshot after repair");
    assert_eq!(after_snapshot.reconstructable_count, Some(1));
    let payload_after = after_snapshot
        .objects
        .iter()
        .find(|object| object.object_id == payload_id)
        .expect("payload after snapshot");
    assert_eq!(payload_after.reconstructable, Some(true));
    assert_eq!(payload_after.meets_placement_policy, Some(true));

    let gc_report = gc
        .collect_with_transcript(&zone, &roots, &store, 1_500)
        .await
        .expect("gc with transcript");
    assert_eq!(gc_report.result.evicted, 1);
    assert_eq!(gc_report.result.expired_leases, 1);
    assert!(
        gc_report
            .transcript
            .decisions
            .iter()
            .any(|decision| decision.object_id == root_id
                && decision.reason_code == GcReasonCode::RootCheckpoint)
    );
    assert!(
        gc_report
            .transcript
            .decisions
            .iter()
            .any(|decision| decision.object_id == payload_id
                && decision.reason_code == GcReasonCode::ReachableRef)
    );
    assert!(
        gc_report
            .transcript
            .decisions
            .iter()
            .any(|decision| decision.object_id == expired_id
                && decision.reason_code == GcReasonCode::LeaseExpired
                && decision.action == GcDecisionAction::Evict)
    );
    assert!(!store.exists(&expired_id).await);
    let root_retained_after_gc = store.exists(&root_id).await;
    let payload_retained_after_gc = store.exists(&payload_id).await;
    assert!(root_retained_after_gc);
    assert!(payload_retained_after_gc);

    let artifact_bundle = build_offline_repair_artifact_bundle(
        root_id,
        payload_id,
        expired_id,
        before_snapshot,
        repair_evaluation_before,
        plan_before,
        after_snapshot,
        repair_evaluation_after,
        plan_after,
        gc_report,
        root_retained_after_gc,
        payload_retained_after_gc,
    );
    let phase_order: Vec<_> = artifact_bundle
        .phase_assertions
        .iter()
        .map(|assertion| assertion.phase.as_str())
        .collect();
    assert_eq!(
        phase_order,
        vec![
            "setup",
            "evaluate_before_repair",
            "repair",
            "evaluate_after_repair",
            "gc",
        ]
    );
    assert!(
        artifact_bundle
            .phase_assertions
            .iter()
            .all(|assertion| assertion.passed),
        "offline repair phase assertions should all pass: {:?}",
        artifact_bundle.phase_assertions
    );
    assert_eq!(
        artifact_bundle.state.repair_evaluation_before_reason_code,
        RepairEvaluationReasonCode::PolicySloDeficit
    );
    assert_eq!(
        artifact_bundle.state.repair_evaluation_after_reason_code,
        RepairEvaluationReasonCode::Healthy
    );
    assert_eq!(
        artifact_bundle
            .state
            .repair_evaluation_before_queue_depth_before,
        0
    );
    assert_eq!(
        artifact_bundle
            .state
            .repair_evaluation_before_queue_depth_after,
        1
    );
    assert_eq!(
        artifact_bundle
            .state
            .repair_evaluation_after_queue_depth_before,
        1
    );
    assert_eq!(
        artifact_bundle
            .state
            .repair_evaluation_after_queue_depth_after,
        0
    );
    assert_eq!(
        artifact_bundle.state.repair_evaluation_before_action,
        RepairQueueAction::Queue
    );
    assert_eq!(
        artifact_bundle.state.repair_evaluation_after_action,
        RepairQueueAction::Remove
    );
    assert_eq!(artifact_bundle.state.plan_action_count_before, 1);
    assert_eq!(artifact_bundle.state.plan_action_count_after, 0);
    assert!(!artifact_bundle.state.reconstructable_before);
    assert!(artifact_bundle.state.reconstructable_after);
    assert!(!artifact_bundle.state.placement_before);
    assert!(artifact_bundle.state.placement_after);
    assert_eq!(artifact_bundle.state.gc_evicted, 1);
    assert_eq!(artifact_bundle.state.gc_expired_leases, 1);
    assert_eq!(artifact_bundle.state.gc_root_count, 1);

    let artifact_json =
        serde_json::to_value(&artifact_bundle).expect("serialize offline repair artifact bundle");
    assert_eq!(artifact_json["before_repair"]["object_count"], 3);
    assert_eq!(
        artifact_json["repair_evaluation_before"]["queue_depth_after"],
        1
    );
    assert_eq!(
        artifact_json["repair_evaluation_after"]["queue_depth_after"],
        0
    );
    assert_eq!(artifact_json["after_repair"]["reconstructable_count"], 1);
    assert_eq!(artifact_json["gc_report"]["result"]["expired_leases"], 1);
    assert_eq!(artifact_json["gc_report"]["transcript"]["root_count"], 1);
    let roundtrip: OfflineRepairArtifactBundle = serde_json::from_value(artifact_json.clone())
        .expect("deserialize offline repair artifact bundle");
    let roundtrip_json =
        serde_json::to_value(&roundtrip).expect("re-serialize offline repair artifact bundle");
    assert_eq!(roundtrip_json, artifact_json);
    assert_eq!(roundtrip.scenario_key, OFFLINE_REPAIR_E2E_SCENARIO);
    assert_eq!(roundtrip.contract_id, OFFLINE_REPAIR_E2E_CONTRACT_ID);
    assert_eq!(roundtrip.phase_assertions, artifact_bundle.phase_assertions);
    assert_eq!(roundtrip.state, artifact_bundle.state);
}

#[test]
fn coverage_recovery_deterministic() {
    // Create the same scenario twice and verify identical repair plans
    let run_scenario = || {
        let controller = RepairController::new(default_repair_config());
        let policy = default_policy();
        let mut repair_order = Vec::new();

        // Queue 3 objects with different deficits
        let configs: Vec<(ObjectId, u32)> = vec![
            (obj(b"det-alpha"), 3), // worst
            (obj(b"det-beta"), 7),  // moderate
            (obj(b"det-gamma"), 5), // medium
        ];

        for (id, local) in &configs {
            let mut dist = SymbolDistribution::new(10);
            for _ in 0..*local {
                dist.add_symbol(1, 100);
            }
            let coverage = CoverageEvaluation::from_distribution(*id, &dist);
            let priority = controller.calculate_priority(&coverage, &policy);
            controller.queue_repair(RepairRequest {
                object_id: *id,
                zone_id: ZoneId::work(),
                coverage,
                policy: policy.clone(),
                priority,
            });
        }

        while let Some(req) = controller.next_repair() {
            repair_order.push((req.object_id, req.priority));
        }
        repair_order
    };

    let run1 = run_scenario();
    let run2 = run_scenario();
    assert_eq!(run1.len(), 3);
    assert_eq!(run1, run2, "Repair plan must be deterministic");
    // Verify priority ordering: highest priority first
    assert!(run1[0].1 >= run1[1].1);
    assert!(run1[1].1 >= run1[2].1);
}

#[test]
fn predictive_prestage_flow() {
    // Phase 1: Record access patterns
    let mut tracker = AccessPatternTracker::new();
    let hot_obj = obj(b"hot-document");
    let cold_obj = obj(b"cold-archive");

    // Both get an initial access
    tracker.record_access(hot_obj);
    tracker.record_access(cold_obj);

    // Decay, then re-access only the hot object to differentiate scores
    tracker.decay_all(0.1);
    for _ in 0..5 {
        tracker.record_access(hot_obj);
    }

    // Phase 2: Get prioritized pre-staging list
    let top = tracker.top_n(5);
    assert!(!top.is_empty());
    // Hot object should have higher score than cold
    let hot_score = tracker.priority_score(&hot_obj);
    let cold_score = tracker.priority_score(&cold_obj);
    assert!(hot_score > cold_score);
    assert_eq!(top[0].0, hot_obj);
    assert!(top[0].1 > 0.0);

    // Phase 3: Pre-stage the hot object
    let mut cap = OfflineCapability::new();
    // Start with nothing cached
    let access = OfflineAccess::new(hot_obj, 10, 20, 512);
    cap.track(access);
    assert!(!cap.can_access(&hot_obj));

    // Pre-stage: add symbols based on priority
    cap.get_mut(&hot_obj).unwrap().set_local_symbols(10);
    assert!(cap.can_access(&hot_obj));
    assert_eq!(
        cap.get(&hot_obj).unwrap().status(),
        OfflineStatus::Available
    );
}

#[test]
fn symbol_distribution_add_and_remove() {
    let mut dist = SymbolDistribution::new(10);
    dist.add_symbol(1, 100);
    dist.add_symbol(1, 100);
    dist.add_symbol(2, 100);
    assert_eq!(dist.distinct_nodes(), 2);
    assert_eq!(dist.total_symbols, 3);
    assert_eq!(dist.max_node_symbols(), 2);

    dist.remove_symbol(1, 100);
    assert_eq!(dist.total_symbols, 2);
    // Node 1 still has 1 symbol
    assert_eq!(dist.distinct_nodes(), 2);

    dist.remove_symbol(1, 100);
    // Node 1 should be removed (0 symbols)
    assert_eq!(dist.distinct_nodes(), 1);
    assert_eq!(dist.total_symbols, 1);
}

#[test]
fn symbol_distribution_remove_nonexistent() {
    let mut dist = SymbolDistribution::new(10);
    dist.add_symbol(1, 100);
    // Remove from a node that doesn't exist — should be a no-op
    dist.remove_symbol(99, 100);
    assert_eq!(dist.total_symbols, 1);
    assert_eq!(dist.distinct_nodes(), 1);
}

#[test]
fn repair_config_default_values() {
    let config = RepairControllerConfig::default();
    assert_eq!(config.max_concurrent_repairs, 10);
    assert_eq!(config.max_repairs_per_minute, 100);
    assert_eq!(config.repair_interval, Duration::from_secs(60));
    assert_eq!(config.min_deficit_bps, 500);
    assert_eq!(config.max_symbols_per_repair, 100);
}

#[test]
fn repair_stats_default() {
    let stats = RepairStats::default();
    assert_eq!(stats.repairs_attempted, 0);
    assert_eq!(stats.repairs_succeeded, 0);
    assert_eq!(stats.repairs_failed, 0);
    assert_eq!(stats.symbols_added, 0);
    assert_eq!(stats.queue_depth, 0);
    assert_eq!(stats.rate_limited, 0);
}

#[test]
fn offline_access_serialization_roundtrip() {
    let id = obj(b"serde-test");
    let mut access = OfflineAccess::new(id, 10, 20, 256);
    access.set_local_symbols(7);
    let json = serde_json::to_string(&access).unwrap();
    let deserialized: OfflineAccess = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.object_id, id);
    assert_eq!(deserialized.local_symbols, 7);
    assert_eq!(deserialized.k, 10);
    assert_eq!(deserialized.n, 20);
    assert_eq!(deserialized.symbol_size, 256);
}

#[test]
fn coverage_evaluation_serialization_roundtrip() {
    let id = obj(b"serde-cov");
    let mut dist = SymbolDistribution::new(10);
    for _ in 0..8 {
        dist.add_symbol(1, 100);
    }
    let eval = CoverageEvaluation::from_distribution(id, &dist);
    let json = serde_json::to_string(&eval).unwrap();
    let deserialized: CoverageEvaluation = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.object_id, id);
    assert_eq!(deserialized.coverage_bps, 8000);
    assert_eq!(deserialized.total_symbols, 8);
    assert_eq!(deserialized.source_symbols, 10);
}

#[test]
fn repair_result_serialization_roundtrip() {
    let result = RepairResult {
        object_id: obj(b"serde-repair"),
        success: true,
        new_coverage_bps: 10_000,
        symbols_added: 5,
        error: None,
    };
    let json = serde_json::to_string(&result).unwrap();
    let deserialized: RepairResult = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.object_id, result.object_id);
    assert!(deserialized.success);
    assert_eq!(deserialized.new_coverage_bps, 10_000);
    assert_eq!(deserialized.symbols_added, 5);
    assert!(deserialized.error.is_none());
}

#[test]
fn repair_result_with_error_serialization() {
    let result = RepairResult {
        object_id: obj(b"serde-err"),
        success: false,
        new_coverage_bps: 3000,
        symbols_added: 0,
        error: Some("connection refused".to_string()),
    };
    let json = serde_json::to_string(&result).unwrap();
    let deserialized: RepairResult = serde_json::from_str(&json).unwrap();
    assert!(!deserialized.success);
    assert_eq!(deserialized.error.as_deref(), Some("connection refused"));
}

#[test]
fn offline_status_equality() {
    assert_eq!(OfflineStatus::Available, OfflineStatus::Available);
    assert_eq!(OfflineStatus::Partial, OfflineStatus::Partial);
    assert_eq!(OfflineStatus::NotCached, OfflineStatus::NotCached);
    assert_ne!(OfflineStatus::Available, OfflineStatus::Partial);
    assert_ne!(OfflineStatus::Partial, OfflineStatus::NotCached);
}

#[test]
fn coverage_health_equality() {
    assert_eq!(CoverageHealth::Healthy, CoverageHealth::Healthy);
    assert_eq!(CoverageHealth::Degraded, CoverageHealth::Degraded);
    assert_eq!(CoverageHealth::Unavailable, CoverageHealth::Unavailable);
    assert_ne!(CoverageHealth::Healthy, CoverageHealth::Degraded);
}

#[test]
fn degraded_repair_flow_with_strict_policy() {
    // Object is available but doesn't meet the strict policy — degraded
    let controller = RepairController::new(default_repair_config());
    let id = obj(b"degraded-flow");
    let policy = strict_policy(); // min_nodes=3, target=15000, min_diversity=3

    // 10 symbols on 1 node: available but degraded
    let mut dist = SymbolDistribution::new(10);
    for _ in 0..10 {
        dist.add_symbol(1, 100);
    }
    let coverage = CoverageEvaluation::from_distribution(id, &dist);
    assert!(coverage.is_available);
    assert_eq!(coverage.health(&policy), CoverageHealth::Degraded);
    assert!(controller.needs_repair(&coverage, &policy));

    let priority = controller.calculate_priority(&coverage, &policy);
    assert!(priority > 0);
    assert!(priority < 1000); // Degraded, not unavailable

    controller.queue_repair(RepairRequest {
        object_id: id,
        zone_id: ZoneId::work(),
        coverage,
        policy,
        priority,
    });
    assert_eq!(controller.queue_depth(), 1);
}

#[test]
fn multi_object_repair_prioritization() {
    let controller = RepairController::new(default_repair_config());
    let policy = default_policy();

    // Create 4 objects with varying coverage levels
    let scenarios: Vec<(&[u8], u32)> = vec![
        (b"obj-full", 10),  // fully covered — no repair
        (b"obj-slight", 9), // barely degraded — low priority
        (b"obj-half", 5),   // half covered — unavailable
        (b"obj-empty", 0),  // empty — unavailable, highest priority
    ];

    let mut queued = 0;
    for (label, local_sym) in &scenarios {
        let id = obj(label);
        let mut dist = SymbolDistribution::new(10);
        for _ in 0..*local_sym {
            dist.add_symbol(1, 100);
        }
        let coverage = CoverageEvaluation::from_distribution(id, &dist);
        if controller.needs_repair(&coverage, &policy) {
            let priority = controller.calculate_priority(&coverage, &policy);
            controller.queue_repair(RepairRequest {
                object_id: id,
                zone_id: ZoneId::work(),
                coverage,
                policy: policy.clone(),
                priority,
            });
            queued += 1;
        }
    }

    // obj-full should NOT need repair, the other 3 should
    assert_eq!(queued, 3);
    assert_eq!(controller.queue_depth(), 3);

    // Dequeue and verify priority ordering
    let first = controller.next_repair().unwrap();
    let second = controller.next_repair().unwrap();
    let third = controller.next_repair().unwrap();
    assert!(first.priority >= second.priority);
    assert!(second.priority >= third.priority);
    // The empty object should have highest priority
    assert_eq!(first.object_id, obj(b"obj-empty"));
}

#[test]
fn offline_capability_iter() {
    let mut cap = OfflineCapability::new();
    for i in 0..3u8 {
        let mut a = OfflineAccess::new(obj(&[50 + i]), 10, 20, 128);
        a.set_local_symbols(u32::from(i) * 5);
        cap.track(a);
    }
    assert_eq!(cap.iter().count(), 3);
}

#[test]
fn offline_capability_partial_count() {
    let mut cap = OfflineCapability::new();
    // 1 available
    let mut a1 = OfflineAccess::new(obj(b"pc-avail"), 10, 20, 128);
    a1.set_local_symbols(10);
    cap.track(a1);
    // 2 partial
    let mut a2 = OfflineAccess::new(obj(b"pc-part1"), 10, 20, 128);
    a2.set_local_symbols(5);
    cap.track(a2);
    let mut a3 = OfflineAccess::new(obj(b"pc-part2"), 10, 20, 128);
    a3.set_local_symbols(3);
    cap.track(a3);
    // 1 not cached
    let a4 = OfflineAccess::new(obj(b"pc-none"), 10, 20, 128);
    cap.track(a4);

    assert_eq!(cap.partial_count(), 2);
    assert_eq!(cap.available_count(), 1);
    assert_eq!(cap.object_count(), 4);
}
