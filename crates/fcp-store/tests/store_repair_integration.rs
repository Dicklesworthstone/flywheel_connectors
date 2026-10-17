//! Real-component integration tests for fcp-store + fcp-raptorq.
//!
//! These tests exercise the full pipeline: encode → store → partial loss →
//! coverage evaluation → repair → reconstruct, using real `RaptorQ` encoding
//! and real in-memory stores (no mocks).
//!
//! Covers: `MemorySymbolStore`, `MemoryObjectStore`, `CoverageEvaluation`,
//! `RepairController`, `RaptorQEncoder`, `RaptorQDecoder`.

#![allow(clippy::option_if_let_else)]
#![allow(clippy::cast_possible_truncation)]

use std::collections::{HashMap, HashSet};
use std::panic::{self, AssertUnwindSafe};
use std::time::{Duration, Instant};

use bytes::Bytes;
use chrono::Utc;
use fcp_async_core::ExecutionContext;
use fcp_prelude::{
    ObjectId, ObjectPlacementPolicy, Provenance, RetentionClass, StorageMeta, StoredObject, ZoneId,
};
use fcp_raptorq::{DecodeAdmissionController, RaptorQConfig, RaptorQDecoder, RaptorQEncoder};
use fcp_store::{
    CoverageEvaluation, CoverageHealth, MemoryObjectStore, MemoryObjectStoreConfig,
    MemorySymbolStore, MemorySymbolStoreConfig, ObjectStore, ObjectSymbolMeta,
    ObjectTransmissionInfo, RepairController, RepairControllerConfig, RepairCycleBudget,
    RepairEvaluationReasonCode, RepairPlanningOptions, RepairQueueAction, RepairReasonCode,
    RepairResult, StoredSymbol, SymbolMeta, SymbolStore, snapshot_zone_lifecycle,
};
use serde_json::json;
use uuid::Uuid;

// ─── Structured JSONL test harness (matches existing crate convention) ────

#[derive(Default)]
struct StoreLogData {
    object_id: Option<ObjectId>,
    object_size: Option<u64>,
    symbol_count: Option<u32>,
    coverage_bps: Option<u32>,
    nodes_holding: Option<Vec<String>>,
    details: Option<serde_json::Value>,
}

fn run_store_test<F, Fut>(test_name: &str, phase: &str, operation: &str, assertions: u32, f: F)
where
    F: FnOnce() -> Fut + panic::UnwindSafe,
    Fut: std::future::Future<Output = StoreLogData>,
{
    let start = Instant::now();
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        fcp_async_core::runtime::block_on_sync(f()).expect("runtime")
    }));
    let duration_us = start.elapsed().as_micros();

    let (passed, failed, outcome, data) = match &result {
        Ok(data) => (assertions, 0, "pass", Some(data)),
        Err(_) => (0, assertions, "fail", None),
    };

    let log = json!({
        "timestamp": Utc::now().to_rfc3339(),
        "level": "info",
        "test_name": test_name,
        "module": "fcp-store-integration",
        "phase": phase,
        "operation": operation,
        "correlation_id": Uuid::new_v4().to_string(),
        "result": outcome,
        "duration_us": duration_us,
        "object_id": data.and_then(|d| d.object_id).map(|id| id.to_string()),
        "object_size": data.and_then(|d| d.object_size),
        "symbol_count": data.and_then(|d| d.symbol_count),
        "coverage_bps": data.and_then(|d| d.coverage_bps),
        "nodes_holding": data.and_then(|d| d.nodes_holding.clone()),
        "details": data.and_then(|d| d.details.clone()),
        "assertions": {
            "passed": passed,
            "failed": failed
        }
    });
    println!("{log}");

    if let Err(payload) = result {
        panic::resume_unwind(payload);
    }
}

// ─── Shared helpers ──────────────────────────────────────────────────────────

const fn test_raptorq_config() -> RaptorQConfig {
    RaptorQConfig {
        symbol_size: 64,
        repair_ratio_bps: 2000, // 20% repair overhead for meaningful repair symbol count
        max_object_size: 1024 * 1024,
        decode_timeout: Duration::from_secs(30),
        max_chunk_threshold: 1024,
        chunk_size: 256,
    }
}

fn test_zone() -> ZoneId {
    "z:integration".parse().unwrap()
}

const fn test_object_id() -> ObjectId {
    ObjectId::from_bytes([0xAB; 32])
}

/// Create a deterministic payload of the given size.
fn make_payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i % 251).expect("modulo fits u8"))
        .collect()
}

/// Encode a payload and return (symbols, OTI, `source_symbol_count`).
fn encode_payload(
    payload: &[u8],
    config: &RaptorQConfig,
) -> (
    Vec<(u32, Vec<u8>)>,
    fcp_raptorq::ObjectTransmissionInformation,
    u32,
) {
    let encoder = RaptorQEncoder::new(payload, config).expect("encode");
    let oti = encoder.transmission_info();
    let source_k = encoder.source_symbols();
    let symbols = encoder.encode_all();
    (symbols, oti, source_k)
}

/// Helper: put object meta + all given symbols into the store.
async fn store_symbols(
    store: &MemorySymbolStore,
    object_id: ObjectId,
    oti: fcp_raptorq::ObjectTransmissionInformation,
    source_k: u32,
    symbols: &[(u32, Vec<u8>)],
    node_id: u64,
) {
    let oti_ser = ObjectTransmissionInfo::from_oti(oti);
    let meta = ObjectSymbolMeta {
        object_id,
        zone_id: test_zone(),
        oti: oti_ser,
        source_symbols: source_k,
        first_symbol_at: 1_000_000,
    };
    store.put_object_meta(meta).await.unwrap();

    for (esi, data) in symbols {
        let symbol = StoredSymbol {
            meta: SymbolMeta {
                object_id,
                esi: *esi,
                zone_id: test_zone(),
                source_node: Some(node_id),
                stored_at: 1_000_000 + u64::from(*esi),
            },
            data: Bytes::from(data.clone()),
        };
        store.put_symbol(symbol).await.unwrap();
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

/// Full encode → store → fetch → decode roundtrip using real `RaptorQ` and
/// real `MemorySymbolStore`.
#[test]
fn encode_store_reconstruct() {
    run_store_test(
        "encode_store_reconstruct",
        "integration",
        "roundtrip",
        2,
        || async {
            let config = test_raptorq_config();
            let payload = make_payload(512);
            let object_id = test_object_id();

            // Encode
            let (symbols, oti, source_k) = encode_payload(&payload, &config);
            let total_symbols = symbols.len() as u32;

            // Store all symbols
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig {
                max_bytes: 1024 * 1024,
                local_node_id: 1,
            });
            store_symbols(&store, object_id, oti, source_k, &symbols, 1).await;

            // Retrieve and decode
            let all = store.get_all_symbols(&object_id).await;
            let mut rq_decoder = RaptorQDecoder::new(oti, &config);
            let mut reconstructed = None;
            for sym in &all {
                if let Some(data) = rq_decoder
                    .add_symbol(sym.meta.esi, sym.data.to_vec())
                    .expect("no timeout")
                {
                    reconstructed = Some(data);
                    break;
                }
            }

            let result_data = reconstructed.expect("should reconstruct");
            assert_eq!(result_data, payload, "decoded payload must match original");
            assert!(
                store.can_reconstruct(&object_id).await,
                "store reports reconstructable"
            );

            StoreLogData {
                object_id: Some(object_id),
                object_size: Some(payload.len() as u64),
                symbol_count: Some(total_symbols),
                details: Some(json!({
                    "source_symbols": source_k,
                    "total_symbols": total_symbols,
                    "decoded_len": result_data.len(),
                })),
                ..StoreLogData::default()
            }
        },
    );
}

/// After deleting some symbols the store correctly reports degraded coverage.
#[test]
fn partial_loss_degrades_coverage() {
    run_store_test(
        "partial_loss_degrades_coverage",
        "integration",
        "coverage",
        4,
        || async {
            let config = test_raptorq_config();
            let payload = make_payload(512);
            let object_id = test_object_id();

            let (symbols, oti, source_k) = encode_payload(&payload, &config);

            let store = MemorySymbolStore::new(MemorySymbolStoreConfig {
                max_bytes: 1024 * 1024,
                local_node_id: 1,
            });
            store_symbols(&store, object_id, oti, source_k, &symbols, 1).await;

            // Full coverage check
            let dist_full = store.get_distribution(&object_id).await.unwrap();
            let eval_full = CoverageEvaluation::from_distribution(object_id, &dist_full);
            assert!(eval_full.is_available, "initially available");
            assert!(eval_full.coverage_bps >= 10000, "initial coverage >= 100%");

            // Delete half the symbols to simulate partial loss
            let esis_to_delete: Vec<u32> = symbols
                .iter()
                .take(symbols.len() / 2)
                .map(|(esi, _)| *esi)
                .collect();
            for esi in &esis_to_delete {
                store.delete_symbol(&object_id, *esi).await.unwrap();
            }

            // Degraded coverage check
            let dist_after = store.get_distribution(&object_id).await.unwrap();
            let eval_after = CoverageEvaluation::from_distribution(object_id, &dist_after);
            assert!(
                eval_after.coverage_bps < eval_full.coverage_bps,
                "coverage dropped after loss"
            );

            let policy = ObjectPlacementPolicy {
                min_nodes: 1,
                max_node_fraction_bps: 10000,
                preferred_devices: vec![],
                excluded_devices: vec![],
                target_coverage_bps: 10000,
                min_source_diversity: 0,
            };
            let health = eval_after.health(&policy);
            assert!(
                health != CoverageHealth::Healthy,
                "health should not be Healthy after loss"
            );

            StoreLogData {
                object_id: Some(object_id),
                symbol_count: Some(dist_after.total_symbols),
                coverage_bps: Some(eval_after.coverage_bps),
                details: Some(json!({
                    "coverage_before_bps": eval_full.coverage_bps,
                    "coverage_after_bps": eval_after.coverage_bps,
                    "symbols_deleted": esis_to_delete.len(),
                    "health": format!("{health:?}"),
                })),
                ..StoreLogData::default()
            }
        },
    );
}

/// Full pipeline: encode → store → lose symbols → repair adds new symbols →
/// verify reconstruction succeeds.
#[test]
#[allow(clippy::too_many_lines)]
fn partial_loss_repair_reconstruct() {
    run_store_test(
        "partial_loss_repair_reconstruct",
        "integration",
        "repair",
        3,
        || async {
            let config = test_raptorq_config();
            let payload = make_payload(640); // 10 source symbols × 64 bytes
            let object_id = test_object_id();

            let (symbols, oti, source_k) = encode_payload(&payload, &config);
            let total_encoded = symbols.len() as u32;

            // Store only source symbols (not repair) to leave room for repair later
            let source_only: Vec<_> = symbols
                .iter()
                .filter(|(esi, _)| *esi < source_k)
                .cloned()
                .collect();

            let store = MemorySymbolStore::new(MemorySymbolStoreConfig {
                max_bytes: 1024 * 1024,
                local_node_id: 1,
            });
            store_symbols(&store, object_id, oti, source_k, &source_only, 1).await;

            // Delete some source symbols to simulate loss
            let delete_count = (source_k / 3).max(1);
            for esi in 0..delete_count {
                store.delete_symbol(&object_id, esi).await.unwrap();
            }

            // Verify not reconstructable
            let remaining = store.symbol_count(&object_id).await;
            assert!(
                remaining < source_k,
                "fewer symbols than K after deletion: {remaining} < {source_k}"
            );

            // Re-encode to get repair symbols (simulates what a repair peer would do)
            let (repair_symbols, _, _) = encode_payload(&payload, &config);
            let repair_only: Vec<_> = repair_symbols
                .iter()
                .filter(|(esi, _)| *esi >= source_k)
                .cloned()
                .collect();

            // Add repair symbols to fill the gap
            for (esi, data) in &repair_only {
                let symbol = StoredSymbol {
                    meta: SymbolMeta {
                        object_id,
                        esi: *esi,
                        zone_id: test_zone(),
                        source_node: Some(2), // Different node
                        stored_at: 2_000_000 + u64::from(*esi),
                    },
                    data: Bytes::from(data.clone()),
                };
                store.put_symbol(symbol).await.unwrap();
            }

            // Also re-add some deleted source symbols from a "repair peer"
            // (we need at least K' ≈ K symbols total to reconstruct)
            let need_more = source_k.saturating_sub(store.symbol_count(&object_id).await);
            for esi in 0..need_more {
                let matching: Option<&(u32, Vec<u8>)> = symbols.iter().find(|(e, _)| *e == esi);
                if let Some((e, d)) = matching {
                    let symbol = StoredSymbol {
                        meta: SymbolMeta {
                            object_id,
                            esi: *e,
                            zone_id: test_zone(),
                            source_node: Some(3),
                            stored_at: 3_000_000 + u64::from(*e),
                        },
                        data: Bytes::from(d.clone()),
                    };
                    store.put_symbol(symbol).await.unwrap();
                }
            }

            // Reconstruct
            let all = store.get_all_symbols(&object_id).await;
            let mut rq_decoder = RaptorQDecoder::new(oti, &config);
            let mut reconstructed = None;
            for sym in &all {
                if let Some(data) = rq_decoder
                    .add_symbol(sym.meta.esi, sym.data.to_vec())
                    .expect("no timeout")
                {
                    reconstructed = Some(data);
                    break;
                }
            }

            let result_data = reconstructed.expect("should reconstruct after repair");
            assert_eq!(result_data, payload, "repaired payload matches original");

            let dist = store.get_distribution(&object_id).await.unwrap();
            let eval = CoverageEvaluation::from_distribution(object_id, &dist);

            StoreLogData {
                object_id: Some(object_id),
                object_size: Some(payload.len() as u64),
                symbol_count: Some(dist.total_symbols),
                coverage_bps: Some(eval.coverage_bps),
                details: Some(json!({
                    "source_k": source_k,
                    "total_encoded": total_encoded,
                    "deleted": delete_count,
                    "repair_added": repair_only.len(),
                    "final_count": dist.total_symbols,
                    "reconstructed": true,
                })),
                ..StoreLogData::default()
            }
        },
    );
}

/// `RepairController` detects degraded coverage and queues repair; after adding
/// symbols, coverage converges to the target and the queue empties.
#[test]
#[allow(clippy::too_many_lines)]
fn repair_controller_drives_convergence() {
    run_store_test(
        "repair_controller_drives_convergence",
        "integration",
        "repair",
        4,
        || async {
            let config = test_raptorq_config();
            let payload = make_payload(640);
            let object_id = test_object_id();

            let (symbols, oti, source_k) = encode_payload(&payload, &config);

            let store = MemorySymbolStore::new(MemorySymbolStoreConfig {
                max_bytes: 1024 * 1024,
                local_node_id: 1,
            });

            // Store only half the source symbols → under-covered
            let half = (source_k / 2) as usize;
            let partial: Vec<_> = symbols.iter().take(half).cloned().collect();
            store_symbols(&store, object_id, oti, source_k, &partial, 1).await;

            let policy = ObjectPlacementPolicy {
                min_nodes: 1,
                max_node_fraction_bps: 10000,
                preferred_devices: vec![],
                excluded_devices: vec![],
                target_coverage_bps: 10000,
                min_source_diversity: 0,
            };

            let controller = RepairController::new(RepairControllerConfig {
                min_deficit_bps: 100,
                max_symbols_per_repair: 20,
                ..Default::default()
            });

            let mut policies = HashMap::new();
            policies.insert(object_id, policy.clone());

            // Evaluate zone — should queue a repair
            let initial_report = controller
                .evaluate_zone_with_report(&test_zone(), &store, &policies)
                .await;
            let initial_depth = controller.queue_depth();
            assert!(initial_depth > 0, "repair should be queued");
            assert_eq!(initial_report.queue_depth_before, 0);
            assert_eq!(initial_report.queue_depth_after, 1);
            assert_eq!(initial_report.decisions.len(), 1);
            assert_eq!(initial_report.decisions[0].action, RepairQueueAction::Queue);
            assert_eq!(
                initial_report.decisions[0].reason_code,
                RepairEvaluationReasonCode::PolicySloDeficit
            );

            // Simulate repair: take from queue, add symbols
            if let Some(request) = controller.next_repair() {
                let needed = request
                    .coverage
                    .symbols_needed(request.policy.target_coverage_bps);
                let to_add = needed.min(controller.config().max_symbols_per_repair);

                // Re-encode to get fresh symbols
                let (fresh_symbols, _, _) = encode_payload(&payload, &config);

                // Use symbols the store doesn't already have
                let mut added = 0_u32;
                for (esi, data) in &fresh_symbols {
                    if added >= to_add {
                        break;
                    }
                    if store.get_symbol(&object_id, *esi).await.is_err() {
                        let symbol = StoredSymbol {
                            meta: SymbolMeta {
                                object_id,
                                esi: *esi,
                                zone_id: test_zone(),
                                source_node: Some(2),
                                stored_at: 2_000_000 + u64::from(*esi),
                            },
                            data: Bytes::from(data.clone()),
                        };
                        store.put_symbol(symbol).await.unwrap();
                        added += 1;
                    }
                }

                let dist = store.get_distribution(&object_id).await.unwrap();
                let eval = CoverageEvaluation::from_distribution(object_id, &dist);

                controller.record_result(&RepairResult {
                    object_id,
                    success: true,
                    new_coverage_bps: eval.coverage_bps,
                    symbols_added: added,
                    error: None,
                });
            }

            // Re-evaluate — queue should be empty now
            let final_report = controller
                .evaluate_zone_with_report(&test_zone(), &store, &policies)
                .await;

            let dist_final = store.get_distribution(&object_id).await.unwrap();
            let eval_final = CoverageEvaluation::from_distribution(object_id, &dist_final);

            assert!(
                eval_final.coverage_bps >= policy.target_coverage_bps,
                "coverage should meet target: {} >= {}",
                eval_final.coverage_bps,
                policy.target_coverage_bps,
            );
            assert_eq!(controller.queue_depth(), 0, "queue empty after convergence");

            let stats = controller.stats();
            assert!(
                stats.repairs_succeeded >= 1,
                "at least one repair succeeded"
            );
            assert_eq!(final_report.queue_depth_before, 0);
            assert_eq!(final_report.queue_depth_after, 0);
            assert_eq!(final_report.pruned_stale_requests, 0);
            assert_eq!(final_report.decisions.len(), 1);
            assert_eq!(final_report.decisions[0].action, RepairQueueAction::Skip);
            assert_eq!(
                final_report.decisions[0].reason_code,
                RepairEvaluationReasonCode::Healthy
            );

            StoreLogData {
                object_id: Some(object_id),
                symbol_count: Some(dist_final.total_symbols),
                coverage_bps: Some(eval_final.coverage_bps),
                details: Some(json!({
                    "initial_queue_depth": initial_depth,
                    "final_queue_depth": controller.queue_depth(),
                    "repairs_attempted": stats.repairs_attempted,
                    "repairs_succeeded": stats.repairs_succeeded,
                    "symbols_added": stats.symbols_added,
                    "initial_queue_action": initial_report.decisions[0].action,
                    "final_queue_action": final_report.decisions[0].action,
                })),
                ..StoreLogData::default()
            }
        },
    );
}

/// Deterministic planner cycle improves the number of objects that meet the zone SLO.
#[test]
#[allow(clippy::too_many_lines)]
fn repair_planner_cycle_improves_zone_slo() {
    run_store_test(
        "repair_planner_cycle_improves_zone_slo",
        "integration",
        "repair_plan",
        7,
        || async {
            let config = test_raptorq_config();
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig {
                max_bytes: 2 * 1024 * 1024,
                local_node_id: 1,
            });
            let controller = RepairController::new(RepairControllerConfig {
                min_deficit_bps: 100,
                max_symbols_per_repair: 8,
                ..Default::default()
            });

            let mut policies = HashMap::new();
            let mut repair_catalog: HashMap<ObjectId, Vec<(u32, Vec<u8>)>> = HashMap::new();

            for (index, (raw_id, payload_len)) in [
                ([0xC1; 32], 640usize),
                ([0xC2; 32], 704usize),
                ([0xC3; 32], 768usize),
            ]
            .into_iter()
            .enumerate()
            {
                let object_id = ObjectId::from_bytes(raw_id);
                let payload = make_payload(payload_len + index);
                let (symbols, oti, source_k) = encode_payload(&payload, &config);
                let partial: Vec<_> = symbols
                    .iter()
                    .take((source_k as usize / 2).max(1))
                    .cloned()
                    .collect();

                store_symbols(&store, object_id, oti, source_k, &partial, 1).await;
                repair_catalog.insert(object_id, symbols);
                policies.insert(
                    object_id,
                    ObjectPlacementPolicy {
                        min_nodes: 1,
                        max_node_fraction_bps: 10000,
                        preferred_devices: vec![],
                        excluded_devices: vec![],
                        target_coverage_bps: 10000,
                        min_source_diversity: 0,
                    },
                );
            }

            let options = RepairPlanningOptions {
                cycle_id: 41,
                budget: RepairCycleBudget {
                    max_repairs: 2,
                    max_bytes: u64::MAX,
                    max_decode_ms: u32::MAX,
                },
                ..Default::default()
            };

            let before_plan = controller
                .plan_zone(&test_zone(), &store, &policies, &options)
                .await;
            assert_eq!(before_plan.actions.len(), 2, "budget should cap repairs");
            assert_eq!(
                before_plan.deferred.len(),
                1,
                "over-budget work should stay visible as deferred"
            );
            assert!(
                before_plan
                    .actions
                    .iter()
                    .all(|action| action.reason_code == RepairReasonCode::PolicySloDeficit)
            );
            assert!(
                before_plan
                    .deferred
                    .iter()
                    .all(|action| action.reason_code == RepairReasonCode::DeferredCycleBudget)
            );
            assert_eq!(
                before_plan.object_count_below_target,
                before_plan.actions.len() + before_plan.deferred.len(),
                "planner should account for both selected and deferred below-target objects",
            );

            for action in &before_plan.actions {
                let symbols = repair_catalog
                    .get(&action.object_id)
                    .expect("catalog entry for planned object");
                let mut added = 0_u32;

                for (esi, data) in symbols {
                    if added >= action.estimated_symbols {
                        break;
                    }
                    if store.get_symbol(&action.object_id, *esi).await.is_err() {
                        let symbol = StoredSymbol {
                            meta: SymbolMeta {
                                object_id: action.object_id,
                                esi: *esi,
                                zone_id: test_zone(),
                                source_node: Some(2),
                                stored_at: 2_000_000 + u64::from(*esi),
                            },
                            data: Bytes::from(data.clone()),
                        };
                        store.put_symbol(symbol).await.unwrap();
                        added += 1;
                    }
                }
            }

            let after_plan = controller
                .plan_zone(
                    &test_zone(),
                    &store,
                    &policies,
                    &RepairPlanningOptions {
                        cycle_id: 42,
                        ..options
                    },
                )
                .await;

            assert!(
                after_plan.object_count_below_target < before_plan.object_count_below_target,
                "planner cycle should reduce below-target objects: {} -> {}",
                before_plan.object_count_below_target,
                after_plan.object_count_below_target,
            );
            assert!(
                after_plan.slo_metrics.coverage_p50_bps > before_plan.slo_metrics.coverage_p50_bps,
                "planner cycle should improve median coverage: {} -> {}",
                before_plan.slo_metrics.coverage_p50_bps,
                after_plan.slo_metrics.coverage_p50_bps,
            );
            assert!(
                after_plan.budget_used.repairs <= before_plan.budget.max_repairs,
                "budget accounting should stay within configured cycle cap",
            );

            StoreLogData {
                symbol_count: Some(before_plan.object_count_tracked as u32),
                details: Some(json!({
                    "zone_id": before_plan.zone_id.to_string(),
                    "cycle_ids": {
                        "before": before_plan.cycle_id,
                        "after": after_plan.cycle_id
                    },
                    "before_below_target": before_plan.object_count_below_target,
                    "after_below_target": after_plan.object_count_below_target,
                    "policy_targets": {
                        "target_coverage_bps": before_plan.policy_targets.target_coverage_bps,
                        "min_source_diversity": before_plan.policy_targets.min_source_diversity,
                        "max_node_fraction_bps": before_plan.policy_targets.max_node_fraction_bps
                    },
                    "budget": {
                        "max_repairs": before_plan.budget.max_repairs,
                        "max_bytes": before_plan.budget.max_bytes,
                        "max_decode_ms": before_plan.budget.max_decode_ms
                    },
                    "before_slo_metrics": {
                        "coverage_p50_bps": before_plan.slo_metrics.coverage_p50_bps,
                        "coverage_p90_bps": before_plan.slo_metrics.coverage_p90_bps,
                        "coverage_p99_bps": before_plan.slo_metrics.coverage_p99_bps,
                        "hot_object_access_bps": before_plan.slo_metrics.hot_object_access_bps
                    },
                    "after_slo_metrics": {
                        "coverage_p50_bps": after_plan.slo_metrics.coverage_p50_bps,
                        "coverage_p90_bps": after_plan.slo_metrics.coverage_p90_bps,
                        "coverage_p99_bps": after_plan.slo_metrics.coverage_p99_bps,
                        "hot_object_access_bps": after_plan.slo_metrics.hot_object_access_bps
                    },
                    "budget_used": {
                        "repairs": before_plan.budget_used.repairs,
                        "bytes": before_plan.budget_used.bytes,
                        "decode_ms": before_plan.budget_used.decode_ms
                    },
                    "planned_actions": before_plan.actions.iter().map(|action| {
                        json!({
                            "object_id": action.object_id.to_string(),
                            "reason_code": action.reason_code.as_str(),
                            "estimated_symbols": action.estimated_symbols,
                            "estimated_bytes": action.estimated_bytes
                        })
                    }).collect::<Vec<_>>(),
                    "deferred_actions": before_plan.deferred.iter().map(|action| {
                        json!({
                            "object_id": action.object_id.to_string(),
                            "reason_code": action.reason_code.as_str(),
                            "estimated_symbols": action.estimated_symbols,
                            "estimated_bytes": action.estimated_bytes
                        })
                    }).collect::<Vec<_>>()
                })),
                ..StoreLogData::default()
            }
        },
    );
}

/// Planner behavior adapts to mains power and metered-network constraints.
#[test]
#[allow(clippy::too_many_lines)]
fn repair_planner_adapts_to_power_and_network_conditions() {
    run_store_test(
        "repair_planner_adapts_to_power_and_network_conditions",
        "integration",
        "repair_plan",
        17,
        || async {
            let config = test_raptorq_config();
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig {
                max_bytes: 2 * 1024 * 1024,
                local_node_id: 1,
            });
            let controller = RepairController::new(RepairControllerConfig {
                min_deficit_bps: 100,
                max_symbols_per_repair: 8,
                ..Default::default()
            });

            let critical_object = ObjectId::from_bytes([0xD1; 32]);
            let degraded_object = ObjectId::from_bytes([0xD2; 32]);
            let hot_object = ObjectId::from_bytes([0xD3; 32]);

            for (object_id, payload_len, mode) in [
                (critical_object, 640usize, "partial"),
                (degraded_object, 704usize, "source_only"),
                (hot_object, 768usize, "source_only"),
            ] {
                let payload = make_payload(payload_len);
                let (symbols, oti, source_k) = encode_payload(&payload, &config);
                let source_only: Vec<_> = symbols
                    .iter()
                    .filter(|(esi, _)| *esi < source_k)
                    .cloned()
                    .collect();
                let symbols_to_store = if mode == "partial" {
                    source_only
                        .iter()
                        .take((source_k as usize / 2).max(1))
                        .cloned()
                        .collect::<Vec<_>>()
                } else {
                    source_only
                };
                store_symbols(&store, object_id, oti, source_k, &symbols_to_store, 1).await;
            }

            let base_policy = ObjectPlacementPolicy {
                min_nodes: 1,
                max_node_fraction_bps: 10_000,
                preferred_devices: vec![],
                excluded_devices: vec![],
                target_coverage_bps: 12_000,
                min_source_diversity: 0,
            };
            let degraded_policy = base_policy.clone();
            let hot_policy = ObjectPlacementPolicy {
                target_coverage_bps: 9_000,
                ..base_policy.clone()
            };

            let policies = HashMap::from([
                (
                    critical_object,
                    ObjectPlacementPolicy {
                        target_coverage_bps: 10_000,
                        ..degraded_policy.clone()
                    },
                ),
                (degraded_object, degraded_policy),
                (hot_object, hot_policy),
            ]);

            let baseline_options = RepairPlanningOptions {
                cycle_id: 51,
                budget: RepairCycleBudget {
                    max_repairs: 1,
                    max_bytes: 2_048,
                    max_decode_ms: 64,
                },
                hot_objects: vec![hot_object],
                hot_object_min_coverage_bps: 15_000,
                ..Default::default()
            };

            let baseline_plan = controller
                .plan_zone(&test_zone(), &store, &policies, &baseline_options)
                .await;
            assert_eq!(baseline_plan.budget.max_repairs, 1);
            assert_eq!(baseline_plan.actions.len(), 1);
            assert_eq!(baseline_plan.actions[0].object_id, critical_object);
            assert_eq!(
                baseline_plan.actions[0].reason_code,
                RepairReasonCode::PolicySloDeficit
            );

            let aggressive_plan = controller
                .plan_zone(
                    &test_zone(),
                    &store,
                    &policies,
                    &RepairPlanningOptions {
                        cycle_id: 52,
                        mains_power: true,
                        bandwidth_estimate_kbps: 100_000,
                        ..baseline_options.clone()
                    },
                )
                .await;
            assert_eq!(aggressive_plan.budget.max_repairs, 2);
            assert_eq!(aggressive_plan.budget.max_bytes, 4_096);
            assert_eq!(aggressive_plan.budget.max_decode_ms, 128);
            assert_eq!(aggressive_plan.actions.len(), 2);
            assert!(
                aggressive_plan.actions.len() > baseline_plan.actions.len(),
                "mains power + bandwidth should increase actionable repair budget",
            );
            assert!(
                aggressive_plan
                    .actions
                    .iter()
                    .any(|action| action.object_id == hot_object),
                "aggressive plan should include the hot-object pre-stage candidate",
            );

            let metered_plan = controller
                .plan_zone(
                    &test_zone(),
                    &store,
                    &policies,
                    &RepairPlanningOptions {
                        cycle_id: 53,
                        budget: RepairCycleBudget {
                            max_repairs: 3,
                            max_bytes: 8_192,
                            max_decode_ms: 256,
                        },
                        hot_objects: vec![hot_object],
                        hot_object_min_coverage_bps: 15_000,
                        metered_network: true,
                        ..Default::default()
                    },
                )
                .await;
            assert_eq!(metered_plan.actions.len(), 1);
            assert_eq!(metered_plan.actions[0].object_id, critical_object);
            assert_eq!(metered_plan.deferred.len(), 2);
            assert!(
                metered_plan
                    .deferred
                    .iter()
                    .all(|action| action.reason_code == RepairReasonCode::DeferredPowerBudget),
                "metered network should defer non-critical repairs with an explainable reason",
            );
            assert!(
                metered_plan
                    .deferred
                    .iter()
                    .any(|action| action.object_id == degraded_object),
                "metered network should defer the non-critical policy-deficit object",
            );
            assert!(
                metered_plan
                    .deferred
                    .iter()
                    .any(|action| action.object_id == hot_object),
                "metered network should defer the hot-object pre-stage candidate",
            );

            StoreLogData {
                symbol_count: Some(metered_plan.object_count_tracked as u32),
                details: Some(json!({
                    "baseline": {
                        "budget": {
                            "max_repairs": baseline_plan.budget.max_repairs,
                            "max_bytes": baseline_plan.budget.max_bytes,
                            "max_decode_ms": baseline_plan.budget.max_decode_ms
                        },
                        "actions": baseline_plan.actions.iter().map(|action| json!({
                            "object_id": action.object_id.to_string(),
                            "reason_code": action.reason_code.as_str()
                        })).collect::<Vec<_>>()
                    },
                    "aggressive": {
                        "budget": {
                            "max_repairs": aggressive_plan.budget.max_repairs,
                            "max_bytes": aggressive_plan.budget.max_bytes,
                            "max_decode_ms": aggressive_plan.budget.max_decode_ms
                        },
                        "actions": aggressive_plan.actions.iter().map(|action| json!({
                            "object_id": action.object_id.to_string(),
                            "reason_code": action.reason_code.as_str()
                        })).collect::<Vec<_>>()
                    },
                    "metered": {
                        "actions": metered_plan.actions.iter().map(|action| json!({
                            "object_id": action.object_id.to_string(),
                            "reason_code": action.reason_code.as_str()
                        })).collect::<Vec<_>>(),
                        "deferred": metered_plan.deferred.iter().map(|action| json!({
                            "object_id": action.object_id.to_string(),
                            "reason_code": action.reason_code.as_str()
                        })).collect::<Vec<_>>()
                    }
                })),
                ..StoreLogData::default()
            }
        },
    );
}

/// Object store and symbol store work together: store a complete object and
/// its symbols, verify both are accessible and coverage is healthy.
#[test]
#[allow(clippy::too_many_lines)]
fn object_and_symbol_stores_coherent() {
    run_store_test(
        "object_and_symbol_stores_coherent",
        "integration",
        "roundtrip",
        5,
        || async {
            let config = test_raptorq_config();
            let payload = make_payload(384);
            let object_id = test_object_id();

            let (symbols, oti, source_k) = encode_payload(&payload, &config);

            // Object store: store the complete object
            let obj_store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let stored_obj = StoredObject {
                object_id,
                header: fcp_core::ObjectHeader {
                    encryption_kind: fcp_core::ObjectEncryptionKind::default(),
                    schema: fcp_cbor::SchemaId::new(
                        "fcp.test",
                        "IntegrationTest",
                        semver::Version::new(1, 0, 0),
                    ),
                    zone_id: test_zone(),
                    created_at: 1_000_000,
                    provenance: Provenance::new(test_zone()),
                    refs: vec![],
                    foreign_refs: vec![],
                    ttl_secs: None,
                    placement: None,
                },
                body: payload.clone(),
                storage: StorageMeta {
                    retention: RetentionClass::Pinned,
                },
            };
            obj_store.put(stored_obj).await.unwrap();

            // Symbol store: store all encoded symbols
            let sym_store = MemorySymbolStore::new(MemorySymbolStoreConfig {
                max_bytes: 1024 * 1024,
                local_node_id: 1,
            });
            store_symbols(&sym_store, object_id, oti, source_k, &symbols, 1).await;

            // Verify object store has the object
            let retrieved = obj_store.get(&object_id).await.unwrap();
            assert_eq!(retrieved.body, payload, "object store body matches");

            // Verify symbol store has all symbols
            let sym_count = sym_store.symbol_count(&object_id).await;
            assert_eq!(
                sym_count,
                symbols.len() as u32,
                "symbol count matches encoded"
            );

            // Verify symbol store reports reconstructable
            assert!(
                sym_store.can_reconstruct(&object_id).await,
                "can reconstruct from symbols"
            );

            // Verify coverage is healthy
            let dist = sym_store.get_distribution(&object_id).await.unwrap();
            let eval = CoverageEvaluation::from_distribution(object_id, &dist);
            assert!(eval.is_available, "coverage reports available");

            let policy = ObjectPlacementPolicy {
                min_nodes: 1,
                max_node_fraction_bps: 10000,
                preferred_devices: vec![],
                excluded_devices: vec![],
                target_coverage_bps: 10000,
                min_source_diversity: 0,
            };
            assert!(eval.meets_policy(&policy), "meets placement policy");

            // Verify retention class persisted correctly
            let storage_meta = obj_store.get_storage_meta(&object_id).await.unwrap();
            assert!(
                matches!(storage_meta.retention, RetentionClass::Pinned),
                "retention is Pinned"
            );

            StoreLogData {
                object_id: Some(object_id),
                object_size: Some(payload.len() as u64),
                symbol_count: Some(sym_count),
                coverage_bps: Some(eval.coverage_bps),
                details: Some(json!({
                    "source_k": source_k,
                    "total_symbols": symbols.len(),
                    "retention": "Pinned",
                    "is_available": eval.is_available,
                    "meets_policy": eval.meets_policy(&policy),
                })),
                ..StoreLogData::default()
            }
        },
    );
}

/// Multi-node distribution: symbols spread across multiple nodes should
/// report correct `distinct_nodes` and `max_node_fraction` in coverage.
#[test]
fn multi_node_symbol_distribution() {
    run_store_test(
        "multi_node_symbol_distribution",
        "integration",
        "placement",
        4,
        || async {
            let config = test_raptorq_config();
            let payload = make_payload(640);
            let object_id = test_object_id();

            let (symbols, oti, source_k) = encode_payload(&payload, &config);

            let store = MemorySymbolStore::new(MemorySymbolStoreConfig {
                max_bytes: 1024 * 1024,
                local_node_id: 1,
            });

            let oti_ser = ObjectTransmissionInfo::from_oti(oti);
            let meta = ObjectSymbolMeta {
                object_id,
                zone_id: test_zone(),
                oti: oti_ser,
                source_symbols: source_k,
                first_symbol_at: 1_000_000,
            };
            store.put_object_meta(meta).await.unwrap();

            // Distribute symbols across 3 nodes in round-robin
            for (i, (esi, data)) in symbols.iter().enumerate() {
                let node_id = (i % 3) as u64 + 1; // nodes 1, 2, 3
                let symbol = StoredSymbol {
                    meta: SymbolMeta {
                        object_id,
                        esi: *esi,
                        zone_id: test_zone(),
                        source_node: Some(node_id),
                        stored_at: 1_000_000 + u64::from(*esi),
                    },
                    data: Bytes::from(data.clone()),
                };
                store.put_symbol(symbol).await.unwrap();
            }

            let dist = store.get_distribution(&object_id).await.unwrap();
            let eval = CoverageEvaluation::from_distribution(object_id, &dist);

            assert_eq!(eval.distinct_nodes, 3, "3 distinct nodes");
            assert!(eval.is_available, "available with all symbols");

            // Max fraction should be roughly 1/3 (3333 bps) since round-robin
            // but off-by-one in distribution is possible
            assert!(
                eval.max_node_fraction_bps <= 5000,
                "no single node has > 50% of symbols: {}",
                eval.max_node_fraction_bps
            );

            let policy = ObjectPlacementPolicy {
                min_nodes: 3,
                max_node_fraction_bps: 5000,
                preferred_devices: vec![],
                excluded_devices: vec![],
                target_coverage_bps: 10000,
                min_source_diversity: 0,
            };
            assert!(eval.meets_policy(&policy), "meets 3-node policy");

            StoreLogData {
                object_id: Some(object_id),
                symbol_count: Some(dist.total_symbols),
                coverage_bps: Some(eval.coverage_bps),
                nodes_holding: Some(vec!["node-1".into(), "node-2".into(), "node-3".into()]),
                details: Some(json!({
                    "distinct_nodes": eval.distinct_nodes,
                    "max_node_fraction_bps": eval.max_node_fraction_bps,
                    "total_symbols": dist.total_symbols,
                })),
                ..StoreLogData::default()
            }
        },
    );
}

/// Verify that encoding + decoding works with only repair symbols
/// (no source symbols present), demonstrating fountain code properties.
#[test]
fn reconstruct_from_repair_symbols_only() {
    run_store_test(
        "reconstruct_from_repair_symbols_only",
        "integration",
        "decode",
        1,
        || async {
            let config = RaptorQConfig {
                symbol_size: 64,
                repair_ratio_bps: 10000, // 100% repair overhead = K repair symbols
                max_object_size: 1024 * 1024,
                decode_timeout: Duration::from_secs(30),
                max_chunk_threshold: 1024,
                chunk_size: 256,
            };
            let payload = make_payload(384); // 6 source symbols
            let object_id = test_object_id();

            let (symbols, oti, source_k) = encode_payload(&payload, &config);

            // Keep only repair symbols (ESI >= source_k)
            let repair_only: Vec<_> = symbols
                .iter()
                .filter(|(esi, _)| *esi >= source_k)
                .cloned()
                .collect();

            assert!(
                !repair_only.is_empty(),
                "must have repair symbols for this test"
            );

            let store = MemorySymbolStore::new(MemorySymbolStoreConfig {
                max_bytes: 1024 * 1024,
                local_node_id: 1,
            });
            store_symbols(&store, object_id, oti, source_k, &repair_only, 1).await;

            // Attempt decode using only repair symbols
            let all = store.get_all_symbols(&object_id).await;
            let mut rq_decoder = RaptorQDecoder::new(oti, &config);
            let mut reconstructed = None;
            for sym in &all {
                if let Some(data) = rq_decoder
                    .add_symbol(sym.meta.esi, sym.data.to_vec())
                    .expect("no timeout")
                {
                    reconstructed = Some(data);
                    break;
                }
            }

            // Fountain code property: repair symbols alone should reconstruct
            // if we have enough (≈ K' symbols)
            let success = reconstructed.as_ref().is_some_and(|d| *d == payload);

            // Note: with K repair symbols, reconstruction should generally succeed
            // since RaptorQ needs K' ≈ K×1.002. With 100% overhead we have K repair
            // symbols which equals K, which is nearly always sufficient.
            assert!(success, "reconstructed from repair symbols only");

            StoreLogData {
                object_id: Some(object_id),
                object_size: Some(payload.len() as u64),
                symbol_count: Some(repair_only.len() as u32),
                details: Some(json!({
                    "source_k": source_k,
                    "repair_only_count": repair_only.len(),
                    "reconstructed": success,
                })),
                ..StoreLogData::default()
            }
        },
    );
}

/// Adversarial input: corrupted symbols must never yield a valid payload
/// reconstruction, and decode should remain bounded by timeout budget.
#[test]
fn adversarial_corrupted_symbols_reject_valid_reconstruction() {
    run_store_test(
        "adversarial_corrupted_symbols_reject_valid_reconstruction",
        "integration",
        "adversarial",
        3,
        || async {
            let config = RaptorQConfig {
                decode_timeout: Duration::from_millis(100),
                ..test_raptorq_config()
            };
            let payload = make_payload(640);
            let object_id = test_object_id();

            let (symbols, oti, source_k) = encode_payload(&payload, &config);
            let source_only: Vec<_> = symbols
                .iter()
                .filter(|(esi, _)| *esi < source_k)
                .cloned()
                .collect();
            assert!(!source_only.is_empty(), "source symbols should exist");

            let corrupted_source: Vec<_> = source_only
                .iter()
                .map(|(esi, data)| {
                    let mut corrupted = data.clone();
                    if let Some(first) = corrupted.first_mut() {
                        *first ^= 0xA5;
                    }
                    (*esi, corrupted)
                })
                .collect();

            let store = MemorySymbolStore::new(MemorySymbolStoreConfig {
                max_bytes: 1024 * 1024,
                local_node_id: 1,
            });
            store_symbols(&store, object_id, oti, source_k, &corrupted_source, 1).await;

            let all = store.get_all_symbols(&object_id).await;
            let mut decoder = RaptorQDecoder::new(oti, &config);
            let mut reconstructed = None;
            for sym in &all {
                if let Some(data) = decoder
                    .add_symbol(sym.meta.esi, sym.data.to_vec())
                    .expect("bounded adversarial decode should not timeout")
                {
                    reconstructed = Some(data);
                    break;
                }
            }

            let valid_reconstruction = reconstructed.as_ref().is_some_and(|d| *d == payload);
            assert!(
                !valid_reconstruction,
                "corrupted symbol stream must not reconstruct original payload"
            );
            assert!(
                !decoder.is_timed_out(),
                "adversarial decode should complete within timeout budget"
            );

            StoreLogData {
                object_id: Some(object_id),
                object_size: Some(payload.len() as u64),
                symbol_count: Some(
                    u32::try_from(corrupted_source.len()).expect("symbol count fits in u32"),
                ),
                details: Some(json!({
                    "source_k": source_k,
                    "corrupted_symbols": corrupted_source.len(),
                    "decode_budget_ms": config.decode_timeout.as_millis(),
                    "received_unique": decoder.received_count(),
                    "valid_reconstruction": valid_reconstruction,
                })),
                ..StoreLogData::default()
            }
        },
    );
}

/// Adversarial delivery: reordered symbols with duplicates should still
/// reconstruct, and duplicate ESIs must not inflate unique symbol accounting.
#[test]
fn adversarial_reordered_duplicate_symbols_reconstruct() {
    run_store_test(
        "adversarial_reordered_duplicate_symbols_reconstruct",
        "integration",
        "adversarial",
        3,
        || async {
            let config = test_raptorq_config();
            let payload = make_payload(640);

            let (symbols, oti, _) = encode_payload(&payload, &config);
            let unique_esis: HashSet<u32> = symbols.iter().map(|(esi, _)| *esi).collect();

            let mut adversarial_stream = symbols;
            adversarial_stream.reverse(); // reorder
            let duplicate_tail: Vec<_> = adversarial_stream.iter().take(3).cloned().collect();
            adversarial_stream.extend(duplicate_tail); // duplicate ESIs

            let mut decoder = RaptorQDecoder::new(oti, &config);
            let mut reconstructed = None;
            for (esi, data) in adversarial_stream {
                if let Some(payload) = decoder
                    .add_symbol(esi, data)
                    .expect("decode should stay within budget")
                {
                    reconstructed = Some(payload);
                    break;
                }
            }

            let reconstructed_payload =
                reconstructed.expect("reordered + duplicate stream should reconstruct");
            assert_eq!(
                reconstructed_payload, payload,
                "decoded payload must match original"
            );

            let unique_count =
                u32::try_from(unique_esis.len()).expect("unique symbol count fits in u32");
            assert!(
                decoder.received_count() <= unique_count,
                "duplicate ESIs should not increase unique count"
            );
            assert!(
                !decoder.is_timed_out(),
                "decode should finish within configured budget"
            );

            StoreLogData {
                object_size: Some(payload.len() as u64),
                symbol_count: Some(unique_count),
                details: Some(json!({
                    "decode_budget_ms": config.decode_timeout.as_millis(),
                    "unique_symbols": unique_count,
                    "received_unique": decoder.received_count(),
                    "reordered": true,
                    "duplicates_injected": 3,
                })),
                ..StoreLogData::default()
            }
        },
    );
}

/// Adversarial delivery: a store-backed decoder must reject the
/// `(max_symbols + 1)`th distinct symbol for a block that never completes,
/// without buffering the rejected symbol or growing past the configured cap.
#[test]
fn adversarial_symbol_flood_is_capped_without_stale_decoder_state() {
    run_store_test(
        "adversarial_symbol_flood_is_capped_without_stale_decoder_state",
        "integration",
        "adversarial",
        5,
        || async {
            let config = RaptorQConfig {
                symbol_size: 1,
                repair_ratio_bps: 0,
                max_object_size: 2001,
                decode_timeout: Duration::from_secs(120),
                max_chunk_threshold: 4096,
                chunk_size: 1024,
            };
            let object_id = test_object_id();
            let oti = fcp_raptorq::ObjectTransmissionInformation::new(1001, 1, 1, 1, 8)
                .with_payload_hash([0xCD; 32]);
            let source_k = 1001_u32;
            let max_symbols = config.total_symbols(1001).saturating_add(1000);
            let attack_stream: Vec<_> = (0..=max_symbols)
                .map(|offset| (10_000 + offset, vec![0xAA]))
                .collect();

            let store = MemorySymbolStore::new(MemorySymbolStoreConfig {
                // One-byte symbols are already the minimum payload. Give the
                // test enough quota for symbol metadata so it exercises the
                // decoder cap instead of failing earlier in the store layer.
                max_bytes: 128 * 1024,
                local_node_id: 9,
            });
            store_symbols(&store, object_id, oti, source_k, &attack_stream, 9).await;

            let stored = store.get_all_symbols(&object_id).await;
            assert_eq!(
                stored.len(),
                usize::try_from(max_symbols + 1).expect("symbol count fits in usize"),
                "symbol store should retain the full attacker stream"
            );

            let controller = DecodeAdmissionController::with_limits(
                1,
                usize::try_from(max_symbols).expect("buffer budget fits in usize"),
                Duration::from_secs(5),
                max_symbols,
            );
            let context = ExecutionContext::request_scoped(Duration::from_secs(5));
            let mut decoder = RaptorQDecoder::new(oti, &config);
            let symbols = stored
                .iter()
                .map(|sym| (sym.meta.esi, sym.data.to_vec()))
                .collect::<Vec<_>>();
            let err = controller
                .decode_with_context(&context, &mut decoder, symbols)
                .await
                .expect_err("decoder should reject the capped symbol");
            assert!(
                matches!(err, fcp_raptorq::DecodeError::SymbolBufferExceeded { .. }),
                "expected SymbolBufferExceeded, got {err:?}"
            );
            assert_eq!(
                decoder.received_count(),
                0,
                "rejected symbol must not remain buffered"
            );
            assert!(
                !decoder.is_timed_out(),
                "cap rejection must happen before timeout"
            );

            StoreLogData {
                object_id: Some(object_id),
                object_size: Some(oti.transfer_length()),
                symbol_count: Some(decoder.received_count()),
                details: Some(json!({
                    "stored_attack_symbols": stored.len(),
                    "decoder_buffered_symbols": decoder.received_count(),
                    "max_symbols": max_symbols,
                    "stale_state_after_rejection": decoder.received_count() != 0,
                    "last_error": format!("{err}"),
                })),
                ..StoreLogData::default()
            }
        },
    );
}

/// OTI round-trip: `ObjectTransmissionInfo` converts losslessly between
/// the fcp-store serializable form and raptorq's native form.
#[test]
fn oti_roundtrip_fidelity() {
    run_store_test(
        "oti_roundtrip_fidelity",
        "integration",
        "oti",
        5,
        || async {
            let config = test_raptorq_config();
            let payload = make_payload(512);

            let encoder = RaptorQEncoder::new(&payload, &config).expect("encode");
            let oti_native = encoder.transmission_info();

            // Convert to serializable form
            let oti_ser = ObjectTransmissionInfo::from_oti(oti_native);

            // Convert back
            let oti_back = oti_ser.to_oti();

            // Verify all fields match
            assert_eq!(
                oti_native.transfer_length(),
                oti_back.transfer_length(),
                "transfer_length"
            );
            assert_eq!(
                oti_native.symbol_size(),
                oti_back.symbol_size(),
                "symbol_size"
            );
            assert_eq!(
                oti_native.source_blocks(),
                oti_back.source_blocks(),
                "source_blocks"
            );
            assert_eq!(oti_native.sub_blocks(), oti_back.sub_blocks(), "sub_blocks");
            assert_eq!(
                oti_native.symbol_alignment(),
                oti_back.symbol_alignment(),
                "alignment"
            );

            StoreLogData {
                object_size: Some(payload.len() as u64),
                details: Some(json!({
                    "transfer_length": oti_ser.transfer_length,
                    "symbol_size": oti_ser.symbol_size,
                    "source_blocks": oti_ser.source_blocks,
                    "sub_blocks": oti_ser.sub_blocks,
                    "alignment": oti_ser.alignment,
                })),
                ..StoreLogData::default()
            }
        },
    );
}

/// Zone lifecycle snapshots expose deterministic durable-state structure and
/// current reconstruction posture without needing GC or repair internals.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "this end-to-end lifecycle snapshot test intentionally keeps the full store and symbol setup inline"
)]
fn lifecycle_snapshot_reflects_reachability_and_symbol_state() {
    run_store_test(
        "lifecycle_snapshot_reflects_reachability_and_symbol_state",
        "integration",
        "lifecycle",
        9,
        || async {
            let config = test_raptorq_config();
            let payload = make_payload(512);
            let object_id = test_object_id();

            let (symbols, oti, source_k) = encode_payload(&payload, &config);

            let store = MemoryObjectStore::new(MemoryObjectStoreConfig {
                max_bytes: 1024 * 1024,
            });
            let symbol_store = MemorySymbolStore::new(MemorySymbolStoreConfig {
                max_bytes: 1024 * 1024,
                local_node_id: 1,
            });

            let root_id = ObjectId::from_bytes([0xCD; 32]);
            let mut root = StoredObject {
                object_id: root_id,
                header: fcp_core::ObjectHeader {
                    encryption_kind: fcp_core::ObjectEncryptionKind::default(),
                    schema: fcp_cbor::SchemaId::new(
                        "fcp.test",
                        "LifecycleRoot",
                        semver::Version::new(1, 0, 0),
                    ),
                    zone_id: test_zone(),
                    created_at: 1_000,
                    provenance: Provenance::new(test_zone()),
                    refs: vec![object_id],
                    foreign_refs: vec![],
                    ttl_secs: None,
                    placement: None,
                },
                body: b"root".to_vec(),
                storage: StorageMeta {
                    retention: RetentionClass::Pinned,
                },
            };
            root.header.refs.sort_unstable();
            store.put(root).await.unwrap();

            let mut payload_object = StoredObject {
                object_id,
                header: fcp_core::ObjectHeader {
                    encryption_kind: fcp_core::ObjectEncryptionKind::default(),
                    schema: fcp_cbor::SchemaId::new(
                        "fcp.test",
                        "LifecyclePayload",
                        semver::Version::new(1, 0, 0),
                    ),
                    zone_id: test_zone(),
                    created_at: 1_100,
                    provenance: Provenance::new(test_zone()),
                    refs: vec![],
                    foreign_refs: vec![],
                    ttl_secs: Some(600),
                    placement: Some(ObjectPlacementPolicy {
                        min_nodes: 2,
                        max_node_fraction_bps: 10_000,
                        preferred_devices: Vec::new(),
                        excluded_devices: Vec::new(),
                        target_coverage_bps: 10_000,
                        min_source_diversity: 2,
                    }),
                },
                body: payload.clone(),
                storage: StorageMeta {
                    retention: RetentionClass::Lease { expires_at: 5_000 },
                },
            };
            payload_object.header.refs.sort_unstable();
            store.put(payload_object).await.unwrap();

            let last_index = symbols.len() - 1;
            store_symbols(
                &symbol_store,
                object_id,
                oti,
                source_k,
                &symbols[..last_index],
                1,
            )
            .await;
            let final_symbol = StoredSymbol {
                meta: SymbolMeta {
                    object_id,
                    esi: symbols[last_index].0,
                    zone_id: test_zone(),
                    source_node: Some(2),
                    stored_at: 2_000,
                },
                data: Bytes::from(symbols[last_index].1.clone()),
            };
            symbol_store.put_symbol(final_symbol).await.unwrap();

            let mut roots = fcp_store::GcRoots::new();
            roots.set_checkpoint(root_id);

            let snapshot =
                snapshot_zone_lifecycle(&test_zone(), &roots, &store, Some(&symbol_store), 1_500)
                    .await
                    .unwrap();

            assert_eq!(snapshot.object_count, 2);
            assert_eq!(snapshot.reachable_count, 2);
            assert_eq!(snapshot.reconstructable_count, Some(1));
            assert_eq!(snapshot.roots.len(), 1);
            assert!(matches!(
                snapshot.roots[0].status,
                fcp_store::LifecycleRootStatus::Valid
            ));

            let payload_entry = snapshot
                .objects
                .iter()
                .find(|entry| entry.object_id == object_id)
                .unwrap();
            assert!(payload_entry.reachable_from_roots);
            assert_eq!(payload_entry.reconstructable, Some(true));
            assert_eq!(payload_entry.meets_placement_policy, Some(true));
            assert_eq!(payload_entry.coverage.as_ref().unwrap().distinct_nodes, 2);
            assert_eq!(
                payload_entry.lease_state,
                fcp_store::ObjectLeaseState::Active
            );
            assert_eq!(payload_entry.ttl_secs, Some(600));

            StoreLogData {
                object_id: Some(object_id),
                object_size: Some(payload.len() as u64),
                coverage_bps: Some(payload_entry.coverage.as_ref().unwrap().coverage_bps),
                details: Some(json!({
                    "reachable_count": snapshot.reachable_count,
                    "reconstructable_count": snapshot.reconstructable_count,
                    "root_status": snapshot.roots[0].status,
                    "distinct_nodes": payload_entry.coverage.as_ref().unwrap().distinct_nodes,
                })),
                ..StoreLogData::default()
            }
        },
    );
}
