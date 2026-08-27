//! Integration tests for fcp-store: object store, symbol store, GC, repair,
//! quarantine, coverage, and offline capabilities.
//!
//! Uses `MemoryObjectStore` and `MemorySymbolStore` for real storage operations
//! without external dependencies.

use std::collections::HashMap;

use bytes::Bytes;
use fcp_prelude::{
    ConnectorBinaryObject, ConnectorBinarySymbolSet, ConnectorBinaryTransmissionInfo,
    ConnectorManifestObject, ConnectorTarget, ObjectHeader, ObjectId, ObjectIdKey,
    ObjectPlacementPolicy, Provenance, RetentionClass, StorageMeta, StoredObject, ZoneId,
};
use fcp_store::{
    AccessPatternTracker, CoverageEvaluation, CoverageHealth, GarbageCollector, GcConfig,
    GcDecisionAction, GcReasonCode, GcResult, GcRoots, GcRunReport, MemoryObjectStore,
    MemoryObjectStoreConfig, MemorySymbolStore, MemorySymbolStoreConfig, ObjectAdmissionPolicy,
    ObjectStore, ObjectStoreError, ObjectSymbolMeta, ObjectTransmissionInfo, OfflineAccess,
    OfflineCapability, OfflineStatus, PromotionReason, QuarantineError, QuarantineStore,
    QuarantinedObject, RepairController, RepairControllerConfig, RepairPlanningOptions,
    RepairReasonCode, RepairRequest, RepairResult, StoredSymbol, SymbolDistribution, SymbolMeta,
    SymbolStore,
};

// ── helpers ──

fn test_zone() -> ZoneId {
    ZoneId::work()
}

const fn test_object_id(n: u8) -> ObjectId {
    ObjectId::from_bytes([n; 32])
}

fn test_schema() -> fcp_cbor::SchemaId {
    fcp_cbor::SchemaId::new("fcp.test", "TestObject", semver::Version::new(1, 0, 0))
}

fn test_stored_object(n: u8) -> StoredObject {
    let zone = test_zone();
    let header = ObjectHeader {
        schema: test_schema(),
        zone_id: zone,
        created_at: 1000,
        provenance: Provenance::new(ZoneId::work()),
        refs: vec![],
        foreign_refs: vec![],
        ttl_secs: None,
        placement: None,
    };
    StoredObject {
        object_id: test_object_id(n),
        header,
        body: vec![n; 64],
        storage: StorageMeta {
            retention: RetentionClass::Pinned,
        },
    }
}

fn test_stored_object_with_retention(n: u8, retention: RetentionClass) -> StoredObject {
    let mut obj = test_stored_object(n);
    obj.storage.retention = retention;
    obj
}

fn test_stored_object_in_zone(n: u8, zone: ZoneId) -> StoredObject {
    let mut obj = test_stored_object(n);
    obj.header.zone_id = zone;
    obj
}

#[allow(clippy::missing_const_for_fn)]
fn test_coverage(
    object_id: ObjectId,
    distinct_nodes: usize,
    coverage_bps: u32,
    source_symbols: u32,
) -> CoverageEvaluation {
    CoverageEvaluation {
        object_id,
        distinct_nodes,
        max_node_fraction_bps: if distinct_nodes > 0 {
            10_000 / u16::try_from(distinct_nodes).expect("test node count fits in u16")
        } else {
            10_000
        },
        coverage_bps,
        is_available: coverage_bps >= 10_000,
        total_symbols: (coverage_bps * source_symbols) / 10_000,
        source_symbols,
    }
}

fn test_object_meta(n: u8) -> ObjectSymbolMeta {
    ObjectSymbolMeta {
        object_id: test_object_id(n),
        zone_id: test_zone(),
        oti: ObjectTransmissionInfo {
            transfer_length: 1024,
            symbol_size: 128,
            source_blocks: 1,
            sub_blocks: 1,
            alignment: 8,
            payload_hash: None,
        },
        source_symbols: 10,
        first_symbol_at: 1000,
    }
}

fn durable_header(schema: fcp_cbor::SchemaId, zone: ZoneId) -> ObjectHeader {
    ObjectHeader {
        schema,
        zone_id: zone.clone(),
        created_at: 1_700_000_000,
        provenance: Provenance::new(zone),
        refs: vec![],
        foreign_refs: vec![],
        ttl_secs: None,
        placement: None,
    }
}

fn test_symbol_with_source(n: u8, esi: u32, source_node: u64) -> StoredSymbol {
    StoredSymbol {
        meta: SymbolMeta {
            object_id: test_object_id(n),
            esi,
            zone_id: test_zone(),
            source_node: Some(source_node),
            stored_at: 1000 + u64::from(esi),
        },
        data: Bytes::from(vec![
            u8::try_from(esi % 251).expect("test esi fits in u8");
            128
        ]),
    }
}

struct SourceDiversityLogEntry<'a> {
    test_name: &'a str,
    zone_id: &'a ZoneId,
    object_id: ObjectId,
    distinct_sources_observed: usize,
    max_concentration_bps_observed: u16,
    min_distinct_sources_required: u8,
    max_concentration_bps_required: u16,
    repair_actions: &'a [RepairReasonCode],
    result: &'a str,
}

fn emit_source_diversity_log(entry: &SourceDiversityLogEntry<'_>) {
    let repair_actions = entry
        .repair_actions
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    println!(
        "{}",
        serde_json::json!({
            "test_name": entry.test_name,
            "module": "fcp-store-no-mock",
            "phase": "integration",
            "operation": "source_diversity",
            "zone_id": entry.zone_id.to_string(),
            "object_id": entry.object_id.to_string(),
            "distinct_sources_observed": entry.distinct_sources_observed,
            "max_concentration_bps_observed": entry.max_concentration_bps_observed,
            "min_distinct_sources_required": entry.min_distinct_sources_required,
            "max_concentration_bps_required": entry.max_concentration_bps_required,
            "repair_actions": repair_actions,
            "result": entry.result,
        })
    );
}

#[allow(clippy::missing_const_for_fn)]
fn test_placement_policy() -> ObjectPlacementPolicy {
    ObjectPlacementPolicy {
        min_nodes: 3,
        max_node_fraction_bps: 5_000,
        preferred_devices: vec![],
        excluded_devices: vec![],
        target_coverage_bps: 15_000,
        min_source_diversity: 0,
    }
}

// ── MemoryObjectStore ──

#[fcp_async_core::runtime::test]
async fn object_store_put_and_get() {
    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    let obj = test_stored_object(1);
    let id = obj.object_id;

    store.put(obj.clone()).await.expect("put");
    let retrieved = store.get(&id).await.expect("get");
    assert_eq!(retrieved.object_id, id);
    assert_eq!(retrieved.body, obj.body);
}

#[fcp_async_core::runtime::test]
async fn object_store_exists() {
    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    let id = test_object_id(1);
    assert!(!store.exists(&id).await);

    store.put(test_stored_object(1)).await.expect("put");
    assert!(store.exists(&id).await);
}

#[fcp_async_core::runtime::test]
async fn object_store_delete() {
    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    let obj = test_stored_object(1);
    let id = obj.object_id;

    store.put(obj).await.expect("put");
    store.delete(&id).await.expect("delete");
    assert!(!store.exists(&id).await);
}

#[fcp_async_core::runtime::test]
async fn object_store_delete_not_found() {
    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    let result = store.delete(&test_object_id(99)).await;
    assert!(matches!(result, Err(ObjectStoreError::NotFound(_))));
}

#[fcp_async_core::runtime::test]
async fn object_store_get_not_found() {
    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    let result = store.get(&test_object_id(99)).await;
    assert!(matches!(result, Err(ObjectStoreError::NotFound(_))));
}

#[fcp_async_core::runtime::test]
async fn object_store_duplicate_put_fails() {
    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    store.put(test_stored_object(1)).await.expect("first put");
    let result = store.put(test_stored_object(1)).await;
    assert!(matches!(result, Err(ObjectStoreError::AlreadyExists(_))));
}

#[fcp_async_core::runtime::test]
async fn object_store_get_header() {
    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    let obj = test_stored_object(1);
    let id = obj.object_id;

    store.put(obj).await.expect("put");
    let header = store.get_header(&id).await.expect("header");
    assert_eq!(header.zone_id, test_zone());
}

#[fcp_async_core::runtime::test]
async fn object_store_get_storage_meta() {
    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    let obj = test_stored_object(1);
    let id = obj.object_id;

    store.put(obj).await.expect("put");
    let meta = store.get_storage_meta(&id).await.expect("meta");
    assert!(matches!(meta.retention, RetentionClass::Pinned));
}

#[fcp_async_core::runtime::test]
async fn object_store_set_retention() {
    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    let obj = test_stored_object(1);
    let id = obj.object_id;

    store.put(obj).await.expect("put");
    store
        .set_retention(&id, RetentionClass::Ephemeral)
        .await
        .expect("set retention");
    let meta = store.get_storage_meta(&id).await.expect("meta");
    assert!(matches!(meta.retention, RetentionClass::Ephemeral));
}

#[fcp_async_core::runtime::test]
async fn object_store_list_zone() {
    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    store.put(test_stored_object(1)).await.expect("put 1");
    store.put(test_stored_object(2)).await.expect("put 2");
    store
        .put(test_stored_object_in_zone(3, ZoneId::private()))
        .await
        .expect("put 3");

    let work_objects = store.list_zone(&test_zone()).await;
    assert_eq!(work_objects.len(), 2);

    let private_objects = store.list_zone(&ZoneId::private()).await;
    assert_eq!(private_objects.len(), 1);
}

#[fcp_async_core::runtime::test]
async fn object_store_storage_used() {
    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    assert_eq!(store.storage_used().await, 0);

    store.put(test_stored_object(1)).await.expect("put");
    assert!(store.storage_used().await > 0);
}

#[fcp_async_core::runtime::test]
async fn object_store_storage_quota() {
    let config = MemoryObjectStoreConfig { max_bytes: 1024 };
    let store = MemoryObjectStore::new(config);
    assert_eq!(store.storage_quota().await, 1024);
}

// ── MemorySymbolStore ──

#[fcp_async_core::runtime::test]
async fn symbol_store_put_and_get() {
    let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
    let oid = test_object_id(1);
    store
        .put_object_meta(test_object_meta(1))
        .await
        .expect("put meta");
    let symbol = StoredSymbol {
        meta: SymbolMeta {
            object_id: oid,
            esi: 0,
            zone_id: test_zone(),
            source_node: Some(1),
            stored_at: 1000,
        },
        data: Bytes::from(vec![0xAB; 128]),
    };

    store.put_symbol(symbol.clone()).await.expect("put");
    let retrieved = store.get_symbol(&oid, 0).await.expect("get");
    assert_eq!(retrieved.data, symbol.data);
    assert_eq!(retrieved.meta.esi, 0);
}

#[fcp_async_core::runtime::test]
async fn symbol_store_get_all_symbols() {
    let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
    let oid = test_object_id(1);
    store
        .put_object_meta(test_object_meta(1))
        .await
        .expect("put meta");

    for esi in 0..5 {
        let symbol = StoredSymbol {
            meta: SymbolMeta {
                object_id: oid,
                esi,
                zone_id: test_zone(),
                source_node: Some(1),
                stored_at: 1000 + u64::from(esi),
            },
            data: Bytes::from(vec![u8::try_from(esi).expect("test esi fits in u8"); 128]),
        };
        store.put_symbol(symbol).await.expect("put");
    }

    let all = store.get_all_symbols(&oid).await;
    assert_eq!(all.len(), 5);
}

#[fcp_async_core::runtime::test]
async fn symbol_store_symbol_count() {
    let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
    let oid = test_object_id(1);
    assert_eq!(store.symbol_count(&oid).await, 0);
    store
        .put_object_meta(test_object_meta(1))
        .await
        .expect("put meta");

    for esi in 0..3 {
        let symbol = StoredSymbol {
            meta: SymbolMeta {
                object_id: oid,
                esi,
                zone_id: test_zone(),
                source_node: Some(1),
                stored_at: 1000,
            },
            data: Bytes::from(vec![0u8; 128]),
        };
        store.put_symbol(symbol).await.expect("put");
    }
    assert_eq!(store.symbol_count(&oid).await, 3);
}

#[fcp_async_core::runtime::test]
async fn symbol_store_delete_object() {
    let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
    let oid = test_object_id(1);
    store
        .put_object_meta(test_object_meta(1))
        .await
        .expect("put meta");

    let symbol = StoredSymbol {
        meta: SymbolMeta {
            object_id: oid,
            esi: 0,
            zone_id: test_zone(),
            source_node: Some(1),
            stored_at: 1000,
        },
        data: Bytes::from(vec![0u8; 128]),
    };
    store.put_symbol(symbol).await.expect("put");
    assert_eq!(store.symbol_count(&oid).await, 1);

    store.delete_object(&oid).await.expect("delete");
    assert_eq!(store.symbol_count(&oid).await, 0);
}

#[fcp_async_core::runtime::test]
async fn symbol_store_delete_single_symbol() {
    let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
    let oid = test_object_id(1);
    store
        .put_object_meta(test_object_meta(1))
        .await
        .expect("put meta");

    for esi in 0..3 {
        let symbol = StoredSymbol {
            meta: SymbolMeta {
                object_id: oid,
                esi,
                zone_id: test_zone(),
                source_node: Some(1),
                stored_at: 1000,
            },
            data: Bytes::from(vec![0u8; 128]),
        };
        store.put_symbol(symbol).await.expect("put");
    }

    store.delete_symbol(&oid, 1).await.expect("delete esi=1");
    assert_eq!(store.symbol_count(&oid).await, 2);
    assert!(store.get_symbol(&oid, 1).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn symbol_store_list_zone() {
    let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

    for n in 0..3u8 {
        store
            .put_object_meta(test_object_meta(n))
            .await
            .expect("put meta");
    }
    for n in 0..3 {
        let symbol = StoredSymbol {
            meta: SymbolMeta {
                object_id: test_object_id(n),
                esi: 0,
                zone_id: test_zone(),
                source_node: Some(1),
                stored_at: 1000,
            },
            data: Bytes::from(vec![0u8; 128]),
        };
        store.put_symbol(symbol).await.expect("put");
    }

    let objects = store.list_zone(&test_zone()).await;
    assert_eq!(objects.len(), 3);
}

#[fcp_async_core::runtime::test]
async fn symbol_store_storage_used_and_quota() {
    let config = MemorySymbolStoreConfig {
        max_bytes: 4096,
        ..Default::default()
    };
    let store = MemorySymbolStore::new(config);
    assert_eq!(store.storage_used().await, 0);
    assert_eq!(store.storage_quota().await, 4096);
    store
        .put_object_meta(test_object_meta(1))
        .await
        .expect("put meta");

    let symbol = StoredSymbol {
        meta: SymbolMeta {
            object_id: test_object_id(1),
            esi: 0,
            zone_id: test_zone(),
            source_node: Some(1),
            stored_at: 1000,
        },
        data: Bytes::from(vec![0u8; 128]),
    };
    store.put_symbol(symbol).await.expect("put");
    assert!(store.storage_used().await > 0);
}

#[fcp_async_core::runtime::test]
async fn source_diversity_plan_requires_new_source_when_single_node_dominates() {
    let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
    let object_n = 7;
    let object_id = test_object_id(object_n);

    let mut meta = test_object_meta(object_n);
    meta.source_symbols = 4;
    store.put_object_meta(meta).await.expect("put meta");

    for esi in 0..4 {
        store
            .put_symbol(test_symbol_with_source(object_n, esi, 10))
            .await
            .expect("put single-source symbol");
    }

    let policy = ObjectPlacementPolicy {
        min_nodes: 1,
        max_node_fraction_bps: 10_000,
        preferred_devices: vec![],
        excluded_devices: vec![],
        target_coverage_bps: 10_000,
        min_source_diversity: 2,
    };

    assert!(
        !store.can_reconstruct_with_policy(&object_id, &policy).await,
        "single-source coverage should fail diversity-gated reconstruction"
    );

    let distribution = store
        .get_distribution(&object_id)
        .await
        .expect("distribution");
    let evaluation = CoverageEvaluation::from_distribution(object_id, &distribution);
    assert!(evaluation.is_available, "coverage should already satisfy K");
    assert_eq!(evaluation.distinct_nodes, 1);
    assert_eq!(evaluation.diversity_deficit(policy.min_source_diversity), 1);

    let controller = RepairController::new(RepairControllerConfig::default());
    let policies = HashMap::from([(object_id, policy.clone())]);
    let plan = controller
        .plan_zone(
            &test_zone(),
            &store,
            &policies,
            &RepairPlanningOptions::default(),
        )
        .await;
    assert_eq!(plan.actions.len(), 1, "one repair action should be planned");
    assert_eq!(plan.actions[0].object_id, object_id);
    assert_eq!(
        plan.actions[0].reason_code,
        RepairReasonCode::DiversityDeficit
    );

    store
        .put_symbol(test_symbol_with_source(object_n, 4, 11))
        .await
        .expect("put second-source symbol");
    assert!(
        store.can_reconstruct_with_policy(&object_id, &policy).await,
        "fresh ESI from a second source should satisfy diversity"
    );

    let repaired_distribution = store
        .get_distribution(&object_id)
        .await
        .expect("repaired distribution");
    let repaired_evaluation =
        CoverageEvaluation::from_distribution(object_id, &repaired_distribution);
    emit_source_diversity_log(&SourceDiversityLogEntry {
        test_name: "source_diversity_plan_requires_new_source_when_single_node_dominates",
        zone_id: &test_zone(),
        object_id,
        distinct_sources_observed: repaired_evaluation.distinct_nodes,
        max_concentration_bps_observed: repaired_evaluation.max_node_fraction_bps,
        min_distinct_sources_required: policy.min_source_diversity,
        max_concentration_bps_required: policy.max_node_fraction_bps,
        repair_actions: &plan
            .actions
            .iter()
            .map(|action| action.reason_code)
            .collect::<Vec<_>>(),
        result: "repair_planned_then_satisfied",
    });
}

#[fcp_async_core::runtime::test]
async fn source_diversity_plan_recovers_after_source_churn() {
    let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
    let object_n = 8;
    let object_id = test_object_id(object_n);

    let mut meta = test_object_meta(object_n);
    meta.source_symbols = 4;
    store.put_object_meta(meta).await.expect("put meta");

    for (esi, source_node) in [(0, 20), (1, 20), (2, 21), (3, 22), (4, 20)] {
        store
            .put_symbol(test_symbol_with_source(object_n, esi, source_node))
            .await
            .expect("put churn seed symbol");
    }

    let policy = ObjectPlacementPolicy {
        min_nodes: 1,
        max_node_fraction_bps: 10_000,
        preferred_devices: vec![],
        excluded_devices: vec![],
        target_coverage_bps: 10_000,
        min_source_diversity: 3,
    };

    assert!(
        store.can_reconstruct_with_policy(&object_id, &policy).await,
        "initial three-source placement should satisfy diversity"
    );

    store
        .delete_symbol(&object_id, 3)
        .await
        .expect("remove churned source");

    let distribution = store
        .get_distribution(&object_id)
        .await
        .expect("distribution after churn");
    let evaluation = CoverageEvaluation::from_distribution(object_id, &distribution);
    assert!(
        evaluation.is_available,
        "coverage should remain reconstructable"
    );
    assert_eq!(evaluation.distinct_nodes, 2);
    assert_eq!(evaluation.diversity_deficit(policy.min_source_diversity), 1);

    let controller = RepairController::new(RepairControllerConfig::default());
    let policies = HashMap::from([(object_id, policy.clone())]);
    let plan = controller
        .plan_zone(
            &test_zone(),
            &store,
            &policies,
            &RepairPlanningOptions::default(),
        )
        .await;
    assert_eq!(
        plan.actions.len(),
        1,
        "churn should trigger one repair action"
    );
    assert_eq!(
        plan.actions[0].reason_code,
        RepairReasonCode::DiversityDeficit
    );

    emit_source_diversity_log(&SourceDiversityLogEntry {
        test_name: "source_diversity_plan_recovers_after_source_churn",
        zone_id: &test_zone(),
        object_id,
        distinct_sources_observed: evaluation.distinct_nodes,
        max_concentration_bps_observed: evaluation.max_node_fraction_bps,
        min_distinct_sources_required: policy.min_source_diversity,
        max_concentration_bps_required: policy.max_node_fraction_bps,
        repair_actions: &plan
            .actions
            .iter()
            .map(|action| action.reason_code)
            .collect::<Vec<_>>(),
        result: "diversity_deficit_detected_after_churn",
    });
}

#[fcp_async_core::runtime::test]
async fn source_diversity_duplicate_esi_cannot_spoof_new_source() {
    let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
    let object_n = 9;
    let object_id = test_object_id(object_n);

    let mut meta = test_object_meta(object_n);
    meta.source_symbols = 2;
    store.put_object_meta(meta).await.expect("put meta");

    store
        .put_symbol(test_symbol_with_source(object_n, 0, 30))
        .await
        .expect("put first source symbol");
    store
        .put_symbol(test_symbol_with_source(object_n, 1, 30))
        .await
        .expect("put second source symbol");

    store
        .put_symbol(test_symbol_with_source(object_n, 1, 31))
        .await
        .expect("duplicate esi should be ignored");

    let policy = ObjectPlacementPolicy {
        min_nodes: 1,
        max_node_fraction_bps: 10_000,
        preferred_devices: vec![],
        excluded_devices: vec![],
        target_coverage_bps: 10_000,
        min_source_diversity: 2,
    };

    let distribution = store
        .get_distribution(&object_id)
        .await
        .expect("distribution");
    let evaluation = CoverageEvaluation::from_distribution(object_id, &distribution);
    assert_eq!(
        distribution.total_symbols, 2,
        "duplicate ESI must not increase symbol count"
    );
    assert_eq!(
        evaluation.distinct_nodes, 1,
        "duplicate ESI must not create a fake source"
    );
    assert!(
        !store.can_reconstruct_with_policy(&object_id, &policy).await,
        "spoofed source metadata must not satisfy diversity"
    );

    emit_source_diversity_log(&SourceDiversityLogEntry {
        test_name: "source_diversity_duplicate_esi_cannot_spoof_new_source",
        zone_id: &test_zone(),
        object_id,
        distinct_sources_observed: evaluation.distinct_nodes,
        max_concentration_bps_observed: evaluation.max_node_fraction_bps,
        min_distinct_sources_required: policy.min_source_diversity,
        max_concentration_bps_required: policy.max_node_fraction_bps,
        repair_actions: &[],
        result: "duplicate_ignored",
    });
}

#[fcp_async_core::runtime::test]
async fn source_diversity_plan_requires_rebalancing_when_concentration_too_high() {
    let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
    let object_n = 10;
    let object_id = test_object_id(object_n);

    let mut meta = test_object_meta(object_n);
    meta.source_symbols = 4;
    store.put_object_meta(meta).await.expect("put meta");

    for (esi, source_node) in [(0, 40), (1, 40), (2, 40), (3, 41)] {
        store
            .put_symbol(test_symbol_with_source(object_n, esi, source_node))
            .await
            .expect("put concentrated symbol");
    }

    let policy = ObjectPlacementPolicy {
        min_nodes: 1,
        max_node_fraction_bps: 5_000,
        preferred_devices: vec![],
        excluded_devices: vec![],
        target_coverage_bps: 10_000,
        min_source_diversity: 2,
    };

    assert!(
        !store.can_reconstruct_with_policy(&object_id, &policy).await,
        "concentration violation should block policy-gated reconstruction"
    );

    let distribution = store
        .get_distribution(&object_id)
        .await
        .expect("distribution");
    let evaluation = CoverageEvaluation::from_distribution(object_id, &distribution);
    assert!(evaluation.is_available, "coverage should satisfy K");
    assert_eq!(evaluation.distinct_nodes, 2);
    assert_eq!(evaluation.max_node_fraction_bps, 7_500);
    assert_eq!(
        evaluation.concentration_deficit_bps(policy.max_node_fraction_bps),
        2_500
    );

    let controller = RepairController::new(RepairControllerConfig::default());
    let policies = HashMap::from([(object_id, policy.clone())]);
    let plan = controller
        .plan_zone(
            &test_zone(),
            &store,
            &policies,
            &RepairPlanningOptions::default(),
        )
        .await;
    assert_eq!(
        plan.actions.len(),
        1,
        "one rebalance action should be planned"
    );
    assert_eq!(plan.actions[0].object_id, object_id);
    assert_eq!(
        plan.actions[0].reason_code,
        RepairReasonCode::DiversityDeficit
    );
    assert_eq!(plan.actions[0].estimated_symbols, 2);

    for (esi, source_node) in [(4, 41), (5, 42)] {
        store
            .put_symbol(test_symbol_with_source(object_n, esi, source_node))
            .await
            .expect("put balancing symbol");
    }

    assert!(
        store.can_reconstruct_with_policy(&object_id, &policy).await,
        "extra symbols from other sources should dilute concentration enough to pass"
    );

    let repaired_distribution = store
        .get_distribution(&object_id)
        .await
        .expect("repaired distribution");
    let repaired_evaluation =
        CoverageEvaluation::from_distribution(object_id, &repaired_distribution);
    emit_source_diversity_log(&SourceDiversityLogEntry {
        test_name: "source_diversity_plan_requires_rebalancing_when_concentration_too_high",
        zone_id: &test_zone(),
        object_id,
        distinct_sources_observed: repaired_evaluation.distinct_nodes,
        max_concentration_bps_observed: repaired_evaluation.max_node_fraction_bps,
        min_distinct_sources_required: policy.min_source_diversity,
        max_concentration_bps_required: policy.max_node_fraction_bps,
        repair_actions: &plan
            .actions
            .iter()
            .map(|action| action.reason_code)
            .collect::<Vec<_>>(),
        result: "concentration_rebalanced",
    });
}

// ── CoverageEvaluation + SymbolDistribution ──

#[test]
fn symbol_distribution_new_and_add() {
    let mut dist = SymbolDistribution::new(10);
    assert_eq!(dist.distinct_nodes(), 0);
    assert_eq!(dist.total_symbols, 0);

    dist.add_symbol(1, 128);
    dist.add_symbol(2, 128);
    dist.add_symbol(1, 128);
    assert_eq!(dist.distinct_nodes(), 2);
    assert_eq!(dist.total_symbols, 3);
}

#[test]
fn symbol_distribution_remove() {
    let mut dist = SymbolDistribution::new(10);
    dist.add_symbol(1, 128);
    dist.add_symbol(1, 128);
    assert_eq!(dist.total_symbols, 2);

    dist.remove_symbol(1, 128);
    assert_eq!(dist.total_symbols, 1);
    assert_eq!(dist.distinct_nodes(), 1);
}

#[test]
fn symbol_distribution_max_node_symbols() {
    let mut dist = SymbolDistribution::new(10);
    dist.add_symbol(1, 128);
    dist.add_symbol(1, 128);
    dist.add_symbol(1, 128);
    dist.add_symbol(2, 128);
    assert_eq!(dist.max_node_symbols(), 3);
}

#[test]
fn coverage_from_distribution() {
    let mut dist = SymbolDistribution::new(10);
    dist.add_symbol(1, 128);
    dist.add_symbol(2, 128);
    dist.add_symbol(3, 128);

    let eval = CoverageEvaluation::from_distribution(test_object_id(1), &dist);
    assert_eq!(eval.distinct_nodes, 3);
    assert_eq!(eval.total_symbols, 3);
    assert_eq!(eval.source_symbols, 10);
}

#[test]
fn coverage_health_healthy() {
    let policy = test_placement_policy();
    let eval = test_coverage(test_object_id(1), 5, 15000, 10);
    assert_eq!(eval.health(&policy), CoverageHealth::Healthy);
    assert!(eval.meets_policy(&policy));
}

#[test]
fn coverage_health_degraded() {
    let policy = test_placement_policy();
    // Available (total >= source) but doesn't meet policy (not enough nodes/coverage)
    let eval = CoverageEvaluation {
        object_id: test_object_id(1),
        distinct_nodes: 2,
        max_node_fraction_bps: 5000,
        coverage_bps: 10000,
        is_available: true,
        total_symbols: 10,
        source_symbols: 10,
    };
    assert_eq!(eval.health(&policy), CoverageHealth::Degraded);
    assert!(!eval.meets_policy(&policy));
}

#[test]
fn coverage_health_unavailable() {
    let policy = test_placement_policy();
    let eval = test_coverage(test_object_id(1), 0, 0, 10);
    assert_eq!(eval.health(&policy), CoverageHealth::Unavailable);
}

#[test]
fn coverage_deficit_bps() {
    let eval = test_coverage(test_object_id(1), 2, 8000, 10);
    assert_eq!(eval.coverage_deficit_bps(15000), 7000);
    assert_eq!(eval.coverage_deficit_bps(5000), 0);
}

#[test]
fn coverage_symbols_needed() {
    let eval = test_coverage(test_object_id(1), 2, 5000, 10);
    let needed = eval.symbols_needed(15000);
    assert!(needed > 0);
}

#[test]
fn coverage_serde_roundtrip() {
    let eval = test_coverage(test_object_id(1), 3, 12000, 10);
    let json = serde_json::to_string(&eval).expect("serialize");
    let deserialized: CoverageEvaluation = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(deserialized.object_id, eval.object_id);
    assert_eq!(deserialized.coverage_bps, eval.coverage_bps);
}

// ── GarbageCollector ──

#[fcp_async_core::runtime::test]
async fn gc_empty_store() {
    let gc = GarbageCollector::new(GcConfig::default());
    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    let roots = GcRoots::new();

    let result = gc
        .collect(&test_zone(), &roots, &store, 1000)
        .await
        .expect("gc");
    assert_eq!(result.evicted, 0);
    assert_eq!(result.live, 0);
}

#[fcp_async_core::runtime::test]
async fn gc_pinned_objects_survive() {
    let gc = GarbageCollector::new(GcConfig::default());
    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    // Object with Pinned retention but NOT in GcRoots → unreachable but kept by retention
    let obj = test_stored_object(1);
    let id = obj.object_id;
    store.put(obj).await.expect("put");

    let roots = GcRoots::new(); // Empty roots — object is unreachable
    let result = gc
        .collect(&test_zone(), &roots, &store, 1000)
        .await
        .expect("gc");
    // Object is unreachable but has Pinned retention → counted as pinned, not evicted
    assert_eq!(result.pinned, 1);
    assert_eq!(result.evicted, 0);
    assert!(store.exists(&id).await);
}

#[fcp_async_core::runtime::test]
async fn gc_ephemeral_objects_evicted() {
    let gc = GarbageCollector::new(GcConfig::default());
    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    let obj = test_stored_object_with_retention(1, RetentionClass::Ephemeral);
    let id = obj.object_id;
    store.put(obj).await.expect("put");

    let roots = GcRoots::new();
    let result = gc
        .collect(&test_zone(), &roots, &store, 1000)
        .await
        .expect("gc");
    assert_eq!(result.evicted, 1);
    assert!(!store.exists(&id).await);
}

#[fcp_async_core::runtime::test]
async fn gc_expired_lease_evicted() {
    let config = GcConfig {
        enforce_lease_expiry: true,
        ..Default::default()
    };
    let gc = GarbageCollector::new(config);
    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    let obj = test_stored_object_with_retention(1, RetentionClass::Lease { expires_at: 500 });
    let id = obj.object_id;
    store.put(obj).await.expect("put");

    let roots = GcRoots::new();
    // current_time > expires_at → should be evicted
    let result = gc
        .collect(&test_zone(), &roots, &store, 1000)
        .await
        .expect("gc");
    assert_eq!(result.expired_leases, 1);
    assert!(!store.exists(&id).await);
}

#[fcp_async_core::runtime::test]
async fn gc_active_lease_survives() {
    let gc = GarbageCollector::new(GcConfig::default());
    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    let obj = test_stored_object_with_retention(1, RetentionClass::Lease { expires_at: 5000 });
    let id = obj.object_id;
    store.put(obj).await.expect("put");

    let roots = GcRoots::new();
    // current_time < expires_at → should survive
    let result = gc
        .collect(&test_zone(), &roots, &store, 1000)
        .await
        .expect("gc");
    assert_eq!(result.evicted, 0);
    assert!(store.exists(&id).await);
}

#[fcp_async_core::runtime::test]
async fn gc_checkpoint_root_survives() {
    let gc = GarbageCollector::new(GcConfig::default());
    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    let obj = test_stored_object_with_retention(1, RetentionClass::Ephemeral);
    let id = obj.object_id;
    store.put(obj).await.expect("put");

    let mut roots = GcRoots::new();
    roots.set_checkpoint(id);

    let result = gc
        .collect(&test_zone(), &roots, &store, 1000)
        .await
        .expect("gc");
    assert_eq!(result.evicted, 0, "checkpoint root should not be evicted");
    assert!(store.exists(&id).await);
}

#[fcp_async_core::runtime::test]
async fn gc_collect_with_transcript_exposes_reason_log() {
    let gc = GarbageCollector::new(GcConfig {
        max_evictions_per_run: 1,
        ..GcConfig::default()
    });
    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());

    let root = test_stored_object_with_retention(1, RetentionClass::Ephemeral);
    let root_id = root.object_id;
    let reachable_id = test_object_id(2);
    store.put(root).await.expect("put root");
    store
        .put(StoredObject {
            object_id: reachable_id,
            header: ObjectHeader {
                schema: test_schema(),
                zone_id: test_zone(),
                created_at: 1_000_000,
                provenance: Provenance::new(test_zone()),
                refs: vec![],
                foreign_refs: vec![],
                ttl_secs: None,
                placement: None,
            },
            body: vec![2_u8; 32],
            storage: StorageMeta {
                retention: RetentionClass::Ephemeral,
            },
        })
        .await
        .expect("put reachable");
    store
        .set_retention(&root_id, RetentionClass::Ephemeral)
        .await
        .expect("retention");

    let mut root_header = store.get(&root_id).await.expect("get root");
    root_header.header.refs = vec![reachable_id];
    store.delete(&root_id).await.expect("delete old root");
    store.put(root_header).await.expect("re-put root");

    let active_lease_id = test_object_id(3);
    store
        .put(test_stored_object_with_retention(
            3,
            RetentionClass::Lease { expires_at: 5_000 },
        ))
        .await
        .expect("put active lease");
    let expired_lease_id = test_object_id(4);
    store
        .put(test_stored_object_with_retention(
            4,
            RetentionClass::Lease { expires_at: 500 },
        ))
        .await
        .expect("put expired lease");
    let deferred_ephemeral_id = test_object_id(5);
    store
        .put(test_stored_object_with_retention(
            5,
            RetentionClass::Ephemeral,
        ))
        .await
        .expect("put deferred ephemeral");

    let mut roots = GcRoots::new();
    roots.set_checkpoint(root_id);

    let report = gc
        .collect_with_transcript(&test_zone(), &roots, &store, 1_000)
        .await
        .expect("gc with transcript");

    assert_eq!(
        report
            .transcript
            .decisions
            .iter()
            .map(|decision| decision.object_id)
            .collect::<Vec<_>>(),
        vec![
            root_id,
            reachable_id,
            active_lease_id,
            expired_lease_id,
            deferred_ephemeral_id,
        ]
    );
    assert_eq!(
        report
            .transcript
            .decisions
            .iter()
            .find(|decision| decision.object_id == root_id)
            .expect("root decision")
            .reason_code,
        GcReasonCode::RootCheckpoint
    );
    assert_eq!(
        report
            .transcript
            .decisions
            .iter()
            .find(|decision| decision.object_id == reachable_id)
            .expect("reachable decision")
            .reason_code,
        GcReasonCode::ReachableRef
    );
    assert_eq!(
        report
            .transcript
            .decisions
            .iter()
            .find(|decision| decision.object_id == active_lease_id)
            .expect("active lease decision")
            .reason_code,
        GcReasonCode::LeaseActive
    );
    assert_eq!(
        report
            .transcript
            .decisions
            .iter()
            .find(|decision| decision.object_id == expired_lease_id)
            .expect("expired lease decision")
            .action,
        GcDecisionAction::Evict
    );
    assert_eq!(
        report
            .transcript
            .decisions
            .iter()
            .find(|decision| decision.object_id == deferred_ephemeral_id)
            .expect("deferred decision")
            .action,
        GcDecisionAction::Defer
    );
    assert!(!store.exists(&expired_lease_id).await);
    assert!(store.exists(&deferred_ephemeral_id).await);
}

#[fcp_async_core::runtime::test]
async fn gc_would_collect() {
    let gc = GarbageCollector::new(GcConfig::default());
    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    let obj = test_stored_object_with_retention(1, RetentionClass::Ephemeral);
    let id = obj.object_id;
    store.put(obj).await.expect("put");

    let roots = GcRoots::new();
    assert!(
        gc.would_collect(&id, &test_zone(), &roots, &store, 1000)
            .await
    );

    let mut pinned_roots = GcRoots::new();
    pinned_roots.add_pin(id);
    assert!(
        !gc.would_collect(&id, &test_zone(), &pinned_roots, &store, 1000)
            .await
    );
}

// ── GcRoots ──

#[test]
fn gc_roots_operations() {
    let mut roots = GcRoots::new();
    let id1 = test_object_id(1);
    let id2 = test_object_id(2);

    assert!(!roots.is_root(&id1));

    roots.add_pin(id1);
    assert!(roots.is_root(&id1));
    assert!(!roots.is_root(&id2));

    roots.set_checkpoint(id2);
    assert!(roots.is_root(&id2));

    let all = roots.all_roots();
    assert_eq!(all.len(), 2);

    roots.remove_pin(&id1);
    assert!(!roots.is_root(&id1));
}

#[test]
fn gc_config_defaults() {
    let config = GcConfig::default();
    assert!(config.max_evictions_per_run > 0);
    assert!(config.enforce_lease_expiry);
}

#[test]
fn gc_result_serde() {
    let result = GcResult {
        live: 10,
        evicted: 3,
        expired_leases: 1,
        pinned: 5,
    };
    let json = serde_json::to_string(&result).expect("serialize");
    let deserialized: GcResult = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(deserialized.live, 10);
    assert_eq!(deserialized.evicted, 3);
}

#[test]
fn gc_run_report_serde() {
    let object_id = test_object_id(9);
    let report = GcRunReport {
        result: GcResult {
            live: 2,
            evicted: 1,
            expired_leases: 1,
            pinned: 0,
        },
        transcript: fcp_store::GcTranscript {
            zone_id: test_zone(),
            current_time: 1_000,
            checkpoint_root: Some(object_id),
            root_count: 1,
            decisions: vec![fcp_store::GcDecision {
                object_id,
                retention: RetentionClass::Ephemeral,
                action: GcDecisionAction::Keep,
                reason_code: GcReasonCode::RootCheckpoint,
                authoritative_checkpoint: Some(object_id),
            }],
        },
    };

    let json = serde_json::to_string(&report).expect("serialize");
    let deserialized: GcRunReport = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(deserialized, report);
}

// ── RepairController ──

#[test]
fn repair_controller_queue_and_dequeue() {
    let controller = RepairController::new(RepairControllerConfig::default());
    let request = RepairRequest {
        object_id: test_object_id(1),
        zone_id: test_zone(),
        coverage: test_coverage(test_object_id(1), 1, 5000, 10),
        policy: test_placement_policy(),
        priority: 100,
    };

    controller.queue_repair(request);
    let stats = controller.stats();
    assert_eq!(stats.queue_depth, 1);

    let next = controller.next_repair();
    assert!(next.is_some());
    assert_eq!(next.unwrap().priority, 100);
}

#[test]
fn repair_controller_needs_repair() {
    let controller = RepairController::new(RepairControllerConfig::default());
    let policy = test_placement_policy();

    let healthy = test_coverage(test_object_id(1), 5, 15000, 10);
    assert!(!controller.needs_repair(&healthy, &policy));

    let degraded = test_coverage(test_object_id(2), 1, 5000, 10);
    assert!(controller.needs_repair(&degraded, &policy));
}

#[test]
fn repair_controller_calculate_priority() {
    let controller = RepairController::new(RepairControllerConfig::default());
    let policy = test_placement_policy();

    let bad = test_coverage(test_object_id(1), 1, 2000, 10);
    let less_bad = test_coverage(test_object_id(2), 2, 8000, 10);

    let priority_bad = controller.calculate_priority(&bad, &policy);
    let priority_less_bad = controller.calculate_priority(&less_bad, &policy);
    assert!(
        priority_bad > priority_less_bad,
        "worse coverage should have higher priority"
    );
}

#[test]
fn repair_controller_record_result() {
    let controller = RepairController::new(RepairControllerConfig::default());

    let success = RepairResult {
        object_id: test_object_id(1),
        success: true,
        new_coverage_bps: 15000,
        symbols_added: 5,
        error: None,
    };
    controller.record_result(&success);

    let fail = RepairResult {
        object_id: test_object_id(2),
        success: false,
        new_coverage_bps: 0,
        symbols_added: 0,
        error: Some("test error".to_string()),
    };
    controller.record_result(&fail);

    let stats = controller.stats();
    assert_eq!(stats.repairs_attempted, 2);
    assert_eq!(stats.repairs_succeeded, 1);
    assert_eq!(stats.repairs_failed, 1);
    assert_eq!(stats.symbols_added, 5);
}

#[test]
fn repair_controller_try_acquire_permit() {
    let config = RepairControllerConfig {
        max_concurrent_repairs: 2,
        ..Default::default()
    };
    let controller = RepairController::new(config);

    let permit1 = controller.try_acquire_permit();
    assert!(permit1.is_some());
    let permit2 = controller.try_acquire_permit();
    assert!(permit2.is_some());
    // Third should fail since max_concurrent is 2
    let permit3 = controller.try_acquire_permit();
    assert!(permit3.is_none());

    drop(permit1);
    // After dropping, should be able to acquire again
    let permit4 = controller.try_acquire_permit();
    assert!(permit4.is_some());
}

#[test]
fn repair_result_serde() {
    let result = RepairResult {
        object_id: test_object_id(1),
        success: true,
        new_coverage_bps: 15000,
        symbols_added: 5,
        error: None,
    };
    let json = serde_json::to_string(&result).expect("serialize");
    let deserialized: RepairResult = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(deserialized.symbols_added, 5);
    assert!(deserialized.success);
}

#[test]
fn repair_config_defaults() {
    let config = RepairControllerConfig::default();
    assert!(config.max_concurrent_repairs > 0);
    assert!(config.max_repairs_per_minute > 0);
    assert!(config.min_deficit_bps > 0);
}

// ── QuarantineStore ──

#[test]
fn quarantine_store_add_and_get() {
    let store = QuarantineStore::new(ObjectAdmissionPolicy::default());
    let oid = test_object_id(1);
    let obj = QuarantinedObject {
        object_id: oid,
        zone_id: test_zone(),
        data: Bytes::from(vec![0xAB; 64]),
        source_peer: Some(42),
        received_at: 1000,
        peer_reputation: 5,
    };

    store.quarantine(obj).expect("quarantine");
    assert!(store.contains(&oid));

    let retrieved = store.get(&oid);
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().source_peer, Some(42));
}

#[test]
fn quarantine_store_remove() {
    let store = QuarantineStore::new(ObjectAdmissionPolicy::default());
    let oid = test_object_id(1);
    let obj = QuarantinedObject {
        object_id: oid,
        zone_id: test_zone(),
        data: Bytes::from(vec![0u8; 32]),
        source_peer: None,
        received_at: 1000,
        peer_reputation: 0,
    };

    store.quarantine(obj).expect("quarantine");
    let removed = store.remove(&oid).expect("remove");
    assert_eq!(removed.object_id, oid);
    assert!(!store.contains(&oid));
}

#[test]
fn quarantine_store_remove_not_found() {
    let store = QuarantineStore::new(ObjectAdmissionPolicy::default());
    let result = store.remove(&test_object_id(99));
    assert!(matches!(result, Err(QuarantineError::NotFound(_))));
}

#[test]
fn quarantine_store_promote_with_schema_validation() {
    let policy = ObjectAdmissionPolicy {
        require_schema_validation: true,
        ..Default::default()
    };
    let store = QuarantineStore::new(policy);
    let oid = test_object_id(1);
    let obj = QuarantinedObject {
        object_id: oid,
        zone_id: test_zone(),
        data: Bytes::from(vec![0u8; 32]),
        source_peer: None,
        received_at: 1000,
        peer_reputation: 0,
    };

    store.quarantine(obj).expect("quarantine");

    // Promote with schema_valid=true should succeed
    let reason = PromotionReason::LocalPin {
        reason: "test".to_string(),
    };
    let promoted = store.promote(&oid, &reason, true).expect("promote");
    assert_eq!(promoted.object_id, oid);
    assert!(!store.contains(&oid));
}

#[test]
fn quarantine_store_promote_without_schema_fails() {
    let policy = ObjectAdmissionPolicy {
        require_schema_validation: true,
        ..Default::default()
    };
    let store = QuarantineStore::new(policy);
    let oid = test_object_id(1);
    let obj = QuarantinedObject {
        object_id: oid,
        zone_id: test_zone(),
        data: Bytes::from(vec![0u8; 32]),
        source_peer: None,
        received_at: 1000,
        peer_reputation: 0,
    };

    store.quarantine(obj).expect("quarantine");

    let reason = PromotionReason::LocalPin {
        reason: "test".to_string(),
    };
    let result = store.promote(&oid, &reason, false);
    assert!(matches!(
        result,
        Err(QuarantineError::SchemaValidationFailed { .. })
    ));
}

#[test]
fn quarantine_store_evict_expired() {
    let store = QuarantineStore::new(ObjectAdmissionPolicy {
        quarantine_ttl_secs: 100,
        ..Default::default()
    });

    let obj = QuarantinedObject {
        object_id: test_object_id(1),
        zone_id: test_zone(),
        data: Bytes::from(vec![0u8; 32]),
        source_peer: None,
        received_at: 1000,
        peer_reputation: 0,
    };
    store.quarantine(obj).expect("quarantine");

    // Not expired yet
    let evicted = store.evict_expired(1050);
    assert_eq!(evicted, 0);

    // Now expired (received_at=1000, ttl=100, current=1200)
    let evicted = store.evict_expired(1200);
    assert_eq!(evicted, 1);
    assert!(!store.contains(&test_object_id(1)));
}

#[test]
fn quarantine_store_zone_stats() {
    let store = QuarantineStore::new(ObjectAdmissionPolicy::default());
    let obj = QuarantinedObject {
        object_id: test_object_id(1),
        zone_id: test_zone(),
        data: Bytes::from(vec![0u8; 64]),
        source_peer: None,
        received_at: 1000,
        peer_reputation: 0,
    };
    store.quarantine(obj).expect("quarantine");

    let stats = store.zone_stats(&test_zone());
    assert_eq!(stats.object_count, 1);
    assert!(stats.used_bytes > 0);
}

#[test]
fn quarantine_stats_near_capacity() {
    use fcp_store::QuarantineStats;
    let stats = QuarantineStats {
        object_count: 90,
        used_bytes: 900,
        max_bytes: 1000,
        max_objects: 100,
    };
    assert!(stats.is_near_capacity(80));
    assert!(!stats.is_near_capacity(95));
}

#[test]
fn quarantine_store_list_zone() {
    let store = QuarantineStore::new(ObjectAdmissionPolicy::default());
    for n in 0..3 {
        let obj = QuarantinedObject {
            object_id: test_object_id(n),
            zone_id: test_zone(),
            data: Bytes::from(vec![0u8; 128]),
            source_peer: None,
            received_at: 1000,
            peer_reputation: 0,
        };
        store.quarantine(obj).expect("quarantine");
    }

    let objects = store.list_zone(&test_zone());
    assert_eq!(objects.len(), 3);
}

#[test]
fn quarantine_promotion_reason_serde() {
    let reason = PromotionReason::ReachableFromCheckpoint {
        checkpoint_id: test_object_id(1),
    };
    let json = serde_json::to_string(&reason).expect("serialize");
    let deserialized: PromotionReason = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(reason, deserialized);
}

// ── OfflineAccess + OfflineCapability ──

#[test]
fn offline_access_can_access() {
    let access = OfflineAccess::new(test_object_id(1), 10, 20, 128);
    // 0 local symbols → cannot access
    assert!(!access.can_access());
    assert_eq!(access.status(), OfflineStatus::NotCached);
}

#[test]
fn offline_access_with_enough_symbols() {
    let mut access = OfflineAccess::new(test_object_id(1), 10, 20, 128);
    access.set_local_symbols(10);
    assert!(access.can_access());
    assert_eq!(access.status(), OfflineStatus::Available);
}

#[test]
fn offline_access_partial() {
    let mut access = OfflineAccess::new(test_object_id(1), 10, 20, 128);
    access.set_local_symbols(5);
    assert!(!access.can_access());
    assert_eq!(access.status(), OfflineStatus::Partial);
    assert_eq!(access.symbols_needed(), 5);
}

#[test]
fn offline_access_add_remove_symbols() {
    let mut access = OfflineAccess::new(test_object_id(1), 10, 20, 128);
    access.add_symbols(5);
    assert_eq!(access.symbols_needed(), 5);
    assert_eq!(access.status(), OfflineStatus::Partial);

    access.add_symbols(5);
    assert!(access.can_access());

    access.remove_symbols(3);
    assert_eq!(access.symbols_needed(), 3);
}

#[test]
fn offline_access_coverage_bps() {
    let mut access = OfflineAccess::new(test_object_id(1), 10, 20, 128);
    assert_eq!(access.coverage_bps(), 0);

    access.set_local_symbols(10);
    assert_eq!(access.coverage_bps(), 10000); // 10/10 = 100%
}

#[test]
fn offline_access_bytes_needed() {
    let access = OfflineAccess::new(test_object_id(1), 10, 20, 128);
    assert_eq!(access.bytes_needed(), 10 * 128); // 10 symbols * 128 bytes
}

#[test]
fn offline_access_serde() {
    let access = OfflineAccess::new(test_object_id(1), 10, 20, 128);
    let json = serde_json::to_string(&access).expect("serialize");
    let deserialized: OfflineAccess = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(deserialized.object_id, access.object_id);
}

#[test]
fn offline_capability_track_and_query() {
    let mut cap = OfflineCapability::new();
    assert_eq!(cap.object_count(), 0);

    let mut access = OfflineAccess::new(test_object_id(1), 10, 20, 128);
    access.set_local_symbols(10);
    cap.track(access);

    assert_eq!(cap.object_count(), 1);
    assert!(cap.can_access(&test_object_id(1)));
    assert!(!cap.can_access(&test_object_id(2)));
}

#[test]
fn offline_capability_counts() {
    let mut cap = OfflineCapability::new();

    // Available object
    let mut a1 = OfflineAccess::new(test_object_id(1), 10, 20, 128);
    a1.set_local_symbols(10);
    cap.track(a1);

    // Partial object
    let mut a2 = OfflineAccess::new(test_object_id(2), 10, 20, 128);
    a2.set_local_symbols(5);
    cap.track(a2);

    // Not cached object
    let a3 = OfflineAccess::new(test_object_id(3), 10, 20, 128);
    cap.track(a3);

    assert_eq!(cap.available_count(), 1);
    assert_eq!(cap.partial_count(), 1);
    assert_eq!(cap.object_count(), 3);
}

#[test]
fn offline_capability_readiness_bps() {
    let mut cap = OfflineCapability::new();

    let mut a1 = OfflineAccess::new(test_object_id(1), 10, 20, 128);
    a1.set_local_symbols(10);
    cap.track(a1);

    let a2 = OfflineAccess::new(test_object_id(2), 10, 20, 128);
    cap.track(a2);

    // 1 of 2 available → 50% = 5000 bps
    assert_eq!(cap.readiness_bps(), 5000);
}

#[test]
fn offline_capability_remove() {
    let mut cap = OfflineCapability::new();
    let access = OfflineAccess::new(test_object_id(1), 10, 20, 128);
    cap.track(access);

    let removed = cap.remove(&test_object_id(1));
    assert!(removed.is_some());
    assert_eq!(cap.object_count(), 0);
}

#[test]
fn offline_capability_get_mut() {
    let mut cap = OfflineCapability::new();
    let access = OfflineAccess::new(test_object_id(1), 10, 20, 128);
    cap.track(access);

    let entry = cap.get_mut(&test_object_id(1)).expect("get_mut");
    entry.set_local_symbols(10);
    assert!(cap.can_access(&test_object_id(1)));
}

#[test]
fn offline_capability_total_bytes_needed() {
    let mut cap = OfflineCapability::new();

    let a1 = OfflineAccess::new(test_object_id(1), 10, 20, 128);
    cap.track(a1);
    let a2 = OfflineAccess::new(test_object_id(2), 5, 10, 256);
    cap.track(a2);

    let total = cap.total_bytes_needed();
    assert_eq!(total, 10 * 128 + 5 * 256);
}

#[test]
fn offline_capability_objects_by_coverage() {
    let mut cap = OfflineCapability::new();

    let mut a1 = OfflineAccess::new(test_object_id(1), 10, 20, 128);
    a1.set_local_symbols(8);
    cap.track(a1);

    let mut a2 = OfflineAccess::new(test_object_id(2), 10, 20, 128);
    a2.set_local_symbols(3);
    cap.track(a2);

    let sorted = cap.objects_by_coverage();
    assert_eq!(sorted.len(), 2);
    // Lower coverage should come first
    assert!(sorted[0].coverage_bps() <= sorted[1].coverage_bps());
}

#[test]
fn offline_status_serde() {
    let status = OfflineStatus::Available;
    let json = serde_json::to_string(&status).expect("serialize");
    let deserialized: OfflineStatus = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(status, deserialized);
}

// ── AccessPatternTracker ──

#[test]
fn access_tracker_record_and_count() {
    let mut tracker = AccessPatternTracker::new();
    let oid = test_object_id(1);

    assert_eq!(tracker.access_count(&oid), 0);

    tracker.record_access(oid);
    tracker.record_access(oid);
    tracker.record_access(oid);
    assert_eq!(tracker.access_count(&oid), 3);
}

#[test]
fn access_tracker_priority_score() {
    let mut tracker = AccessPatternTracker::new();
    let oid1 = test_object_id(1);
    let oid2 = test_object_id(2);

    // More accesses → higher priority
    for _ in 0..10 {
        tracker.record_access(oid1);
    }
    tracker.record_access(oid2);

    let s1 = tracker.priority_score(&oid1);
    let s2 = tracker.priority_score(&oid2);
    assert!(s1 > s2, "more frequently accessed should have higher score");
}

#[test]
fn access_tracker_prioritized_objects() {
    let mut tracker = AccessPatternTracker::new();

    for _ in 0..5 {
        tracker.record_access(test_object_id(1));
    }
    for _ in 0..10 {
        tracker.record_access(test_object_id(2));
    }
    tracker.record_access(test_object_id(3));

    let prioritized = tracker.prioritized_objects();
    assert_eq!(prioritized.len(), 3);
    // Highest priority first
    assert!(prioritized[0].1 >= prioritized[1].1);
    assert!(prioritized[1].1 >= prioritized[2].1);
}

// ── Error types ──

#[test]
fn object_store_error_display() {
    let err = ObjectStoreError::NotFound(test_object_id(1));
    assert_ne!(err.to_string(), "");

    let err = ObjectStoreError::QuotaExceeded { used: 100, max: 50 };
    let msg = err.to_string();
    assert!(msg.contains("100") || msg.contains("50"));
}

#[test]
fn quarantine_error_display() {
    let err = QuarantineError::NotFound(test_object_id(1));
    assert_ne!(err.to_string(), "");

    let err = QuarantineError::PromotionDenied {
        reason: "test".to_string(),
    };
    assert!(err.to_string().contains("test"));
}

#[test]
fn repair_config_serde() {
    let config = RepairControllerConfig::default();
    let json = serde_json::to_string(&config).expect("serialize");
    let deserialized: RepairControllerConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        deserialized.max_concurrent_repairs,
        config.max_concurrent_repairs
    );
}

#[test]
fn object_admission_policy_defaults() {
    let policy = ObjectAdmissionPolicy::default();
    assert!(policy.max_quarantine_bytes_per_zone > 0);
    assert!(policy.max_quarantine_objects_per_zone > 0);
    assert!(policy.quarantine_ttl_secs > 0);
    assert!(policy.require_schema_validation);
}

// ── MemoryObjectStoreConfig ──

#[test]
fn memory_object_store_config_default() {
    let config = MemoryObjectStoreConfig::default();
    assert!(config.max_bytes > 0, "default quota should be positive");
}

// ── MemorySymbolStoreConfig ──

#[test]
fn memory_symbol_store_config_default() {
    let config = MemorySymbolStoreConfig::default();
    assert!(config.max_bytes > 0);
}

#[fcp_async_core::runtime::test]
async fn test_durable_object_roundtrip() {
    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    let zone = test_zone();
    let key = ObjectIdKey::from_bytes([0x33; 32]);

    let manifest = ConnectorManifestObject {
        manifest_toml: "[connector]\nid = \"fcp.example\"\n".into(),
        manifest_hash: "sha256:manifest".into(),
    };
    let manifest_header = durable_header(ConnectorManifestObject::schema(), zone.clone());
    let manifest_body =
        fcp_cbor::CanonicalSerializer::serialize(&manifest, &ConnectorManifestObject::schema())
            .expect("manifest body");
    let manifest_object_id =
        StoredObject::derive_id(&manifest_header, &manifest_body, &key).expect("manifest id");

    let binary = ConnectorBinaryObject {
        target: ConnectorTarget {
            os: "linux".into(),
            arch: "arm64".into(),
        },
        binary_hash: "sha256:binary".into(),
        binary: vec![0xAA; 128],
    };
    let mut binary_header = durable_header(ConnectorBinaryObject::schema(), zone.clone());
    binary_header.refs.push(manifest_object_id);
    let binary_body =
        fcp_cbor::CanonicalSerializer::serialize(&binary, &ConnectorBinaryObject::schema())
            .expect("binary body");
    let binary_object_id =
        StoredObject::derive_id(&binary_header, &binary_body, &key).expect("binary id");

    let descriptor = ConnectorBinarySymbolSet {
        manifest_object_id,
        binary_object_id,
        target: binary.target.clone(),
        binary_hash: binary.binary_hash.clone(),
        encoded_body_hash: "sha256:encoded".into(),
        oti: ConnectorBinaryTransmissionInfo::new(128, 32, 1, 1, 8),
        source_symbols: 4,
        total_symbols: 6,
        mirrored_at: 1_700_000_100,
    };
    let mut descriptor_header = durable_header(ConnectorBinarySymbolSet::schema(), zone);
    descriptor_header.refs.push(manifest_object_id);
    descriptor_header.refs.push(binary_object_id);
    let descriptor_body =
        fcp_cbor::CanonicalSerializer::serialize(&descriptor, &ConnectorBinarySymbolSet::schema())
            .expect("descriptor body");
    let descriptor_object_id =
        StoredObject::derive_id(&descriptor_header, &descriptor_body, &key).expect("descriptor id");

    store
        .put(StoredObject {
            object_id: manifest_object_id,
            header: manifest_header,
            body: manifest_body,
            storage: StorageMeta {
                retention: RetentionClass::Pinned,
            },
        })
        .await
        .expect("put manifest");
    store
        .put(StoredObject {
            object_id: binary_object_id,
            header: binary_header,
            body: binary_body,
            storage: StorageMeta {
                retention: RetentionClass::Pinned,
            },
        })
        .await
        .expect("put binary");
    store
        .put(StoredObject {
            object_id: descriptor_object_id,
            header: descriptor_header,
            body: descriptor_body,
            storage: StorageMeta {
                retention: RetentionClass::Pinned,
            },
        })
        .await
        .expect("put descriptor");

    let manifest_back = store.get(&manifest_object_id).await.expect("get manifest");
    let binary_back = store.get(&binary_object_id).await.expect("get binary");
    let descriptor_back = store
        .get(&descriptor_object_id)
        .await
        .expect("get descriptor");

    let manifest_roundtrip: ConnectorManifestObject = fcp_cbor::CanonicalSerializer::deserialize(
        &manifest_back.body,
        &ConnectorManifestObject::schema(),
    )
    .expect("manifest roundtrip");
    let binary_roundtrip: ConnectorBinaryObject = fcp_cbor::CanonicalSerializer::deserialize(
        &binary_back.body,
        &ConnectorBinaryObject::schema(),
    )
    .expect("binary roundtrip");
    let descriptor_roundtrip: ConnectorBinarySymbolSet =
        fcp_cbor::CanonicalSerializer::deserialize(
            &descriptor_back.body,
            &ConnectorBinarySymbolSet::schema(),
        )
        .expect("descriptor roundtrip");

    assert_eq!(manifest_roundtrip, manifest);
    assert_eq!(binary_roundtrip, binary);
    assert_eq!(descriptor_roundtrip, descriptor);
}

#[fcp_async_core::runtime::test]
async fn test_schema_evolution_backward_compat() {
    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    let zone = test_zone();
    let key = ObjectIdKey::from_bytes([0x44; 32]);

    let manifest = ConnectorManifestObject {
        manifest_toml: "[connector]\nid = \"fcp.example\"\n".into(),
        manifest_hash: "sha256:manifest".into(),
    };
    let future_schema = fcp_cbor::SchemaId::new(
        "fcp.core",
        "ConnectorManifestObject",
        semver::Version::new(2, 0, 0),
    );
    let header = durable_header(future_schema.clone(), zone);
    let body =
        fcp_cbor::CanonicalSerializer::serialize(&manifest, &ConnectorManifestObject::schema())
            .expect("body");
    let object_id = StoredObject::derive_id(&header, &body, &key).expect("id");

    store
        .put(StoredObject {
            object_id,
            header: header.clone(),
            body: body.clone(),
            storage: StorageMeta {
                retention: RetentionClass::Pinned,
            },
        })
        .await
        .expect("put");

    let fetched = store.get(&object_id).await.expect("get");
    let fetched_header = store.get_header(&object_id).await.expect("header");

    assert_eq!(fetched.header.schema, future_schema);
    assert_eq!(fetched_header.schema, future_schema);
    assert_eq!(fetched.body, body);
}
