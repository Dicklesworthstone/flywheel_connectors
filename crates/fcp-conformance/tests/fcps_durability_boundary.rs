//! Cross-crate FCPS durability boundary tests (NORMATIVE).
//!
//! Validates that objects flowing through the store → FCPS → registry pipeline
//! maintain consistent durability contracts as required by `FCP_Specification_V3.md`
//! §6 (Durable Object and Evidence Model), §9.8.2 (FCPS Frame Format), and
//! §12.4 (Mirroring and Sovereignty).
//!
//! # Coverage
//!
//! 1. Stored symbols can be packed into valid FCPS frame headers
//! 2. Zone ID hash consistency between store metadata and FCPS frames
//! 3. Frame sequence monotonicity across repair cycles
//! 4. Object ID preservation across store → FCPS → registry roundtrip
//! 5. Symbol size consistency between `RaptorQ` config and FCPS frame header
//! 6. Coverage evaluation maps correctly to FCPS frame semantics
//! 7. GC decisions preserve FCPS-compatible objects with active retention
//! 8. Lifecycle snapshot captures FCPS-durability-relevant state

use std::collections::HashMap;
use std::time::Duration;

use fcp_cbor::SchemaId;
use fcp_prelude::{
    ObjectId, ObjectPlacementPolicy, Provenance, RetentionClass, StorageMeta, StoredObject, ZoneId,
    ZoneKeyId,
};
use fcp_protocol::{
    FCPS_HEADER_LEN, FCPS_MAGIC, FCPS_VERSION, FcpsFrameHeader, FrameFlags, SYMBOL_RECORD_OVERHEAD,
};
use fcp_raptorq::{ObjectTransmissionInformation, RaptorQConfig, RaptorQEncoder};
use fcp_store::{
    GarbageCollector, GcConfig, GcDecisionAction, GcReasonCode, GcRoots, MemoryObjectStore,
    MemoryObjectStoreConfig, MemorySymbolStore, MemorySymbolStoreConfig, ObjectStore,
    ObjectSymbolMeta, ObjectTransmissionInfo, RepairController, RepairControllerConfig,
    RepairEvaluationReasonCode, RepairPlanningOptions, RepairQueueAction, RepairReasonCode,
    StoredSymbol, SymbolMeta, SymbolStore, snapshot_zone_lifecycle,
};
use semver::Version;
use serde_json::{Value, json};

// ─── Test helpers ───────────────────────────────────────────────────────────

fn test_zone() -> ZoneId {
    "z:durability".parse().unwrap()
}

const fn test_raptorq_config() -> RaptorQConfig {
    RaptorQConfig {
        symbol_size: 64,
        repair_ratio_bps: 2000,
        max_object_size: 1024 * 1024,
        decode_timeout: Duration::from_secs(30),
        max_chunk_threshold: 1024,
        chunk_size: 256,
    }
}

fn make_object(seed: u8, payload: &[u8]) -> StoredObject {
    StoredObject {
        object_id: ObjectId::from_bytes([seed; 32]),
        header: fcp_core::ObjectHeader {
            schema: SchemaId::new("fcp.test", "DurabilityPayload", Version::new(0, 1, 0)),
            zone_id: test_zone(),
            created_at: 1_000_000,
            provenance: Provenance::new(test_zone()),
            refs: Vec::new(),
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        },
        body: payload.to_vec(),
        storage: StorageMeta {
            retention: fcp_core::RetentionClass::Pinned,
        },
    }
}

fn make_fcps_header(
    object_id: ObjectId,
    zone: &ZoneId,
    symbol_count: u32,
    symbol_size: u16,
    frame_seq: u64,
) -> FcpsFrameHeader {
    let payload_len =
        symbol_count * (u32::from(symbol_size) + u32::try_from(SYMBOL_RECORD_OVERHEAD).unwrap());
    FcpsFrameHeader {
        version: FCPS_VERSION,
        flags: FrameFlags::default(),
        symbol_count,
        total_payload_len: payload_len,
        object_id,
        symbol_size,
        zone_key_id: ZoneKeyId::from_bytes([1u8; 8]),
        zone_id_hash: zone.hash(),
        epoch_id: 1,
        sender_instance_id: 0xDEAD_BEEF,
        frame_seq,
    }
}

const fn durability_policy() -> ObjectPlacementPolicy {
    ObjectPlacementPolicy {
        min_nodes: 2,
        max_node_fraction_bps: 10_000,
        preferred_devices: Vec::new(),
        excluded_devices: Vec::new(),
        target_coverage_bps: 10_000,
        min_source_diversity: 2,
    }
}

const fn default_repair_config() -> RepairControllerConfig {
    RepairControllerConfig {
        max_concurrent_repairs: 10,
        max_repairs_per_minute: 100,
        repair_interval: Duration::from_secs(60),
        min_deficit_bps: 500,
        max_symbols_per_repair: 100,
        battery_defer_threshold_percent: 20,
    }
}

fn build_durability_object(
    zone: &ZoneId,
    object_id: ObjectId,
    refs: Vec<ObjectId>,
    retention: RetentionClass,
    ttl_secs: Option<u64>,
    placement: Option<ObjectPlacementPolicy>,
    fill: u8,
) -> StoredObject {
    StoredObject {
        object_id,
        header: fcp_core::ObjectHeader {
            schema: SchemaId::new("fcp.test", "DurabilityPayload", Version::new(0, 1, 0)),
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
}

async fn seed_recovery_objects(
    store: &MemoryObjectStore,
    zone: &ZoneId,
    root_id: ObjectId,
    payload_id: ObjectId,
    expired_id: ObjectId,
    placement: &ObjectPlacementPolicy,
) {
    store
        .put(build_durability_object(
            zone,
            root_id,
            vec![payload_id],
            RetentionClass::Pinned,
            None,
            None,
            0x11,
        ))
        .await
        .unwrap();
    store
        .put(build_durability_object(
            zone,
            payload_id,
            vec![],
            RetentionClass::Lease { expires_at: 5_000 },
            Some(600),
            Some(placement.clone()),
            0x22,
        ))
        .await
        .unwrap();
    store
        .put(build_durability_object(
            zone,
            expired_id,
            vec![],
            RetentionClass::Lease { expires_at: 500 },
            None,
            None,
            0x33,
        ))
        .await
        .unwrap();
}

async fn seed_recovery_symbols(
    symbol_store: &MemorySymbolStore,
    zone: &ZoneId,
    payload_id: ObjectId,
) {
    symbol_store
        .put_object_meta(ObjectSymbolMeta {
            object_id: payload_id,
            zone_id: zone.clone(),
            oti: ObjectTransmissionInfo::from_oti(ObjectTransmissionInformation::new(
                1024, 256, 1, 1, 1,
            )),
            source_symbols: 3,
            first_symbol_at: 1_000,
        })
        .await
        .unwrap();

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
                data: vec![u8::try_from(esi).unwrap(); 256].into(),
            })
            .await
            .unwrap();
    }
}

async fn build_recovery_artifact_bundle() -> Value {
    let zone = test_zone();
    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    let symbol_store = MemorySymbolStore::new(MemorySymbolStoreConfig {
        max_bytes: 1024 * 1024,
        local_node_id: 1,
    });
    let controller = RepairController::new(default_repair_config());
    let gc = GarbageCollector::new(GcConfig {
        max_evictions_per_run: 4,
        ..GcConfig::default()
    });

    let root_id = ObjectId::from_unscoped_bytes(b"durability-artifact-root");
    let payload_id = ObjectId::from_unscoped_bytes(b"durability-artifact-payload");
    let expired_id = ObjectId::from_unscoped_bytes(b"durability-artifact-expired");
    let placement = durability_policy();
    seed_recovery_objects(&store, &zone, root_id, payload_id, expired_id, &placement).await;
    seed_recovery_symbols(&symbol_store, &zone, payload_id).await;

    let mut roots = GcRoots::new();
    roots.set_checkpoint(root_id);

    let policies = HashMap::from([(payload_id, placement)]);
    let repair_evaluation_before = controller
        .evaluate_zone_with_report(&zone, &symbol_store, &policies)
        .await;
    let plan_before = controller
        .plan_zone(
            &zone,
            &symbol_store,
            &policies,
            &RepairPlanningOptions::default(),
        )
        .await;
    let before_snapshot =
        snapshot_zone_lifecycle(&zone, &roots, &store, Some(&symbol_store), 1_500)
            .await
            .unwrap();

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
        .unwrap();

    let repair_evaluation_after = controller
        .evaluate_zone_with_report(&zone, &symbol_store, &policies)
        .await;
    let plan_after = controller
        .plan_zone(
            &zone,
            &symbol_store,
            &policies,
            &RepairPlanningOptions::default(),
        )
        .await;
    let after_snapshot = snapshot_zone_lifecycle(&zone, &roots, &store, Some(&symbol_store), 2_000)
        .await
        .unwrap();
    let gc_report = gc
        .collect_with_transcript(&zone, &roots, &store, 1_500)
        .await
        .unwrap();

    json!({
        "scenario": "fcps_durability_recovery",
        "zone_id": zone,
        "replay": {
            "checkpoint_root": root_id,
            "recovery_object": payload_id,
            "expired_object": expired_id,
        },
        "before_repair": before_snapshot,
        "repair_evaluation_before": repair_evaluation_before,
        "repair_plan_before": plan_before,
        "after_repair": after_snapshot,
        "repair_evaluation_after": repair_evaluation_after,
        "repair_plan_after": plan_after,
        "gc_report": gc_report,
    })
}

// ─── Tests ──────────────────────────────────────────────────────────────────

/// Stored symbols can produce valid FCPS frame headers with consistent metadata.
#[test]
fn stored_symbols_produce_valid_fcps_frame_headers() {
    let zone = test_zone();
    let object_id = ObjectId::from_bytes([0xAA; 32]);
    let config = test_raptorq_config();

    let payload = vec![42u8; 256];
    let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
    let source_k = encoder.source_symbols();
    let symbols = encoder.encode_all();

    let header = make_fcps_header(object_id, &zone, source_k, config.symbol_size, 1);

    // Header encodes to exactly 114 bytes
    let header_bytes = header.encode();
    assert_eq!(header_bytes.len(), FCPS_HEADER_LEN);

    // Magic bytes are correct
    assert_eq!(&header_bytes[0..4], &FCPS_MAGIC);

    // Object ID preserved in header
    let decoded = FcpsFrameHeader::decode(&header_bytes).unwrap();
    assert_eq!(decoded.object_id, object_id);

    // Zone hash matches
    assert_eq!(decoded.zone_id_hash, zone.hash());

    // Symbol count matches source symbols
    assert_eq!(decoded.symbol_count, source_k);

    // Symbol size matches config
    assert_eq!(decoded.symbol_size, config.symbol_size);

    // Symbols exist and are non-empty
    assert_ne!(symbols, [] as [(u32, std::vec::Vec<u8>); 0]);
    assert!(symbols.len() >= source_k as usize);
}

/// Zone ID hash is deterministic and consistent across store and FCPS layers.
#[test]
fn zone_id_hash_consistency_across_layers() {
    let zone = test_zone();
    let zone_hash = zone.hash();

    // Hash is deterministic
    assert_eq!(zone.hash(), zone_hash);

    // Different zones produce different hashes
    let work_zone: ZoneId = "z:work".parse().unwrap();
    assert_ne!(zone.hash(), work_zone.hash());

    // Zone hash roundtrips through FCPS header
    let header = make_fcps_header(ObjectId::from_bytes([1; 32]), &zone, 10, 64, 0);
    let encoded = header.encode();
    let decoded = FcpsFrameHeader::decode(&encoded).unwrap();
    assert_eq!(decoded.zone_id_hash, zone_hash);

    // Zone hash is exactly 32 bytes
    assert_eq!(zone_hash.as_bytes().len(), 32);
}

/// Frame sequence monotonicity across repair cycles.
#[test]
fn frame_seq_monotonicity_across_repair_cycles() {
    let zone = test_zone();
    let object_id = ObjectId::from_bytes([0xBB; 32]);

    let mut prev_seq = 0u64;
    for cycle in 1..=5 {
        let header = make_fcps_header(object_id, &zone, 10, 64, cycle);
        let encoded = header.encode();
        let decoded = FcpsFrameHeader::decode(&encoded).unwrap();

        assert!(
            decoded.frame_seq > prev_seq,
            "cycle {cycle}: frame_seq must be monotonic"
        );
        prev_seq = decoded.frame_seq;

        assert_eq!(decoded.object_id, object_id);
        assert_eq!(decoded.epoch_id, 1);
    }
}

/// Object ID preservation across store → FCPS header roundtrip.
#[test]
fn object_id_preserved_across_store_fcps_roundtrip() {
    fcp_async_core::runtime::block_on_sync(async {
        let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());

        let payload = b"durability-test-payload";
        let object = make_object(0xCC, payload);
        let object_id = object.object_id;

        store.put(object).await.unwrap();

        // get() returns Result<StoredObject, _> — NotFound on missing
        let retrieved = store.get(&object_id).await.unwrap();
        assert_eq!(retrieved.object_id, object_id);

        let header = make_fcps_header(retrieved.object_id, &retrieved.header.zone_id, 1, 64, 1);
        let decoded = FcpsFrameHeader::decode(&header.encode()).unwrap();

        assert_eq!(decoded.object_id, object_id);
        assert_eq!(decoded.zone_id_hash, test_zone().hash());
    })
    .unwrap();
}

/// Symbol size in `RaptorQ` config matches FCPS frame header `symbol_size` field.
#[test]
fn symbol_size_consistency_between_raptorq_and_fcps() {
    let config = test_raptorq_config();
    let payload = vec![0u8; 512];
    let encoder = RaptorQEncoder::new(&payload, &config).unwrap();

    let oti = encoder.transmission_info();
    assert_eq!(oti.symbol_size(), config.symbol_size);

    let header = make_fcps_header(
        ObjectId::from_bytes([1; 32]),
        &test_zone(),
        encoder.source_symbols(),
        config.symbol_size,
        1,
    );
    assert_eq!(header.symbol_size, config.symbol_size);

    let symbols = encoder.encode_all();
    for (esi, data) in &symbols {
        assert_eq!(
            data.len(),
            config.symbol_size as usize,
            "symbol ESI={esi} size mismatch"
        );
    }
}

/// Coverage evaluation produces valid basis-point values compatible with
/// FCPS durability guarantees.
#[test]
fn coverage_evaluation_maps_to_fcps_durability() {
    fcp_async_core::runtime::block_on_sync(async {
        let symbol_store = MemorySymbolStore::new(MemorySymbolStoreConfig {
            max_bytes: 1024 * 1024,
            local_node_id: 1,
        });

        let config = test_raptorq_config();
        let payload = vec![42u8; 256];
        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let oti = encoder.transmission_info();
        let source_k = encoder.source_symbols();
        let symbols = encoder.encode_all();

        let object_id = ObjectId::from_bytes([0xDD; 32]);
        let zone = test_zone();

        let store_oti: ObjectTransmissionInfo = oti;
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone.clone(),
            oti: store_oti,
            source_symbols: source_k,
            first_symbol_at: 1_000_000,
        };
        symbol_store.put_object_meta(meta).await.unwrap();

        for (esi, data) in symbols.iter().take(source_k as usize) {
            symbol_store
                .put_symbol(StoredSymbol {
                    data: data.clone().into(),
                    meta: SymbolMeta {
                        object_id,
                        esi: *esi,
                        zone_id: zone.clone(),
                        source_node: Some(1),
                        stored_at: 1_000_000,
                    },
                })
                .await
                .unwrap();
        }

        // can_reconstruct verifies we have enough symbols for FCPS delivery
        assert!(symbol_store.can_reconstruct(&object_id).await);

        // Get distribution for coverage analysis
        let dist = symbol_store.get_distribution(&object_id).await.unwrap();
        assert!(dist.total_symbols >= source_k);
    })
    .unwrap();
}

/// GC decisions preserve FCPS-compatible objects with active retention.
#[test]
fn gc_preserves_fcps_compatible_objects_with_active_retention() {
    fcp_async_core::runtime::block_on_sync(async {
        let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());

        let pinned = make_object(0xE1, b"pinned-durable");
        let pinned_id = pinned.object_id;
        store.put(pinned).await.unwrap();

        let mut ephemeral = make_object(0xE2, b"ephemeral");
        ephemeral.storage.retention = fcp_core::RetentionClass::Ephemeral;
        store.put(ephemeral).await.unwrap();

        let mut roots = GcRoots::new();
        roots.add_pin(pinned_id);

        let gc = GarbageCollector::new(GcConfig::default());
        let report = gc
            .collect_with_transcript(&test_zone(), &roots, &store, 2_000_000)
            .await
            .unwrap();

        // Pinned object survives
        assert!(store.get(&pinned_id).await.is_ok());

        // Transcript records decisions for both objects
        assert!(report.transcript.decisions.len() >= 2);

        // Verify each decision references a valid ObjectId
        for decision in &report.transcript.decisions {
            assert!(!decision.object_id.as_bytes().iter().all(|b| *b == 0));
        }
    })
    .unwrap();
}

/// Lifecycle snapshot captures FCPS-durability-relevant state consistently.
#[test]
fn lifecycle_snapshot_captures_fcps_durability_state() {
    fcp_async_core::runtime::block_on_sync(async {
        let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
        let symbol_store = MemorySymbolStore::new(MemorySymbolStoreConfig {
            max_bytes: 1024 * 1024,
            local_node_id: 1,
        });

        let config = test_raptorq_config();
        let payload = vec![99u8; 128];
        let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
        let oti = encoder.transmission_info();
        let source_k = encoder.source_symbols();
        let symbols = encoder.encode_all();
        let object_id = ObjectId::from_bytes([0xFF; 32]);
        let zone = test_zone();

        let mut object = make_object(0xFF, &payload);
        object.header.placement = Some(ObjectPlacementPolicy {
            min_nodes: 1,
            max_node_fraction_bps: 10_000,
            preferred_devices: Vec::new(),
            excluded_devices: Vec::new(),
            target_coverage_bps: 10_000,
            min_source_diversity: 0,
        });
        store.put(object).await.unwrap();

        let store_oti: ObjectTransmissionInfo = oti;
        symbol_store
            .put_object_meta(ObjectSymbolMeta {
                object_id,
                zone_id: zone.clone(),
                oti: store_oti,
                source_symbols: source_k,
                first_symbol_at: 1_000_000,
            })
            .await
            .unwrap();

        for (esi, data) in symbols.iter().take(source_k as usize) {
            symbol_store
                .put_symbol(StoredSymbol {
                    data: data.clone().into(),
                    meta: SymbolMeta {
                        object_id,
                        esi: *esi,
                        zone_id: zone.clone(),
                        source_node: Some(1),
                        stored_at: 1_000_000,
                    },
                })
                .await
                .unwrap();
        }

        let snapshot =
            snapshot_zone_lifecycle(&zone, &GcRoots::new(), &store, Some(&symbol_store), 10)
                .await
                .unwrap();

        assert_eq!(snapshot.objects.len(), 1);

        let entry = &snapshot.objects[0];
        assert_eq!(entry.object_id, object_id);
        assert_eq!(entry.reconstructable, Some(true));

        assert!(entry.coverage.is_some());
        let cov = entry.coverage.as_ref().unwrap();
        assert_eq!(cov.object_id, object_id);
        assert!(cov.is_available);
        assert!(cov.coverage_bps >= 10_000);

        assert_eq!(entry.meets_placement_policy, Some(true));
        assert_eq!(snapshot.zone_id, zone);

        // Verify FCPS header can be constructed from snapshot data
        let header = make_fcps_header(
            entry.object_id,
            &snapshot.zone_id,
            cov.source_symbols,
            config.symbol_size,
            1,
        );
        let decoded = FcpsFrameHeader::decode(&header.encode()).unwrap();
        assert_eq!(decoded.object_id, object_id);
        assert_eq!(decoded.zone_id_hash, zone.hash());
    })
    .unwrap();
}

/// Repair/recovery evidence bundles remain deterministic and retrieval-friendly.
#[test]
fn repair_recovery_artifact_bundle_is_deterministic_and_serializable() {
    fcp_async_core::runtime::block_on_sync(async {
        let first = build_recovery_artifact_bundle().await;
        let second = build_recovery_artifact_bundle().await;

        assert_eq!(
            first, second,
            "recovery artifact bundle should be deterministic"
        );

        assert_eq!(first["scenario"], json!("fcps_durability_recovery"));
        assert_eq!(first["before_repair"]["object_count"], json!(3));
        assert_eq!(first["before_repair"]["reconstructable_count"], json!(0));
        assert_eq!(
            first["repair_evaluation_before"]["queue_depth_after"],
            json!(1)
        );
        assert_eq!(
            first["repair_evaluation_before"]["decisions"][0]["action"],
            json!("queue")
        );
        assert_eq!(
            first["repair_evaluation_before"]["decisions"][0]["reason_code"],
            json!(RepairEvaluationReasonCode::PolicySloDeficit)
        );
        assert_eq!(
            first["repair_plan_before"]["actions"][0]["reason_code"],
            json!(RepairReasonCode::PolicySloDeficit)
        );
        assert_eq!(first["after_repair"]["reconstructable_count"], json!(1));
        assert_eq!(
            first["repair_evaluation_after"]["queue_depth_after"],
            json!(0)
        );
        assert_eq!(
            first["repair_evaluation_after"]["decisions"][0]["action"],
            json!(RepairQueueAction::Remove)
        );
        assert_eq!(
            first["repair_evaluation_after"]["decisions"][0]["reason_code"],
            json!(RepairEvaluationReasonCode::Healthy)
        );
        assert_eq!(
            first["repair_plan_after"]["actions"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        assert_eq!(first["gc_report"]["result"]["expired_leases"], json!(1));
        assert_eq!(first["gc_report"]["result"]["evicted"], json!(1));
        assert_eq!(first["gc_report"]["transcript"]["root_count"], json!(1));
        assert!(
            first["gc_report"]["transcript"]["decisions"]
                .as_array()
                .unwrap()
                .iter()
                .any(
                    |decision| decision["object_id"] == first["replay"]["expired_object"]
                        && decision["reason_code"] == json!(GcReasonCode::LeaseExpired)
                        && decision["action"] == json!(GcDecisionAction::Evict)
                )
        );

        let roundtrip: Value =
            serde_json::from_str(&serde_json::to_string(&first).unwrap()).unwrap();
        assert_eq!(
            roundtrip, first,
            "artifact bundle should survive retrieval roundtrip"
        );
    })
    .unwrap();
}

/// FCPS frame header encode/decode preserves all durability-relevant fields.
#[test]
fn fcps_header_roundtrip_preserves_durability_fields() {
    let zone = test_zone();
    let object_id = ObjectId::from_bytes([0x42; 32]);
    let zone_key_id = ZoneKeyId::from_bytes([0xAA; 8]);

    let header = FcpsFrameHeader {
        version: FCPS_VERSION,
        flags: FrameFlags::ENCRYPTED | FrameFlags::RAPTORQ,
        symbol_count: 100,
        total_payload_len: {
            let symbol_record_overhead =
                u32::try_from(SYMBOL_RECORD_OVERHEAD).expect("symbol overhead fits in u32");
            100 * (64 + symbol_record_overhead)
        },
        object_id,
        symbol_size: 64,
        zone_key_id,
        zone_id_hash: zone.hash(),
        epoch_id: 42,
        sender_instance_id: 0xCAFE_BABE,
        frame_seq: 999,
    };

    let bytes = header.encode();
    let decoded = FcpsFrameHeader::decode(&bytes).unwrap();

    assert_eq!(decoded.version, FCPS_VERSION);
    assert_eq!(decoded.flags, FrameFlags::ENCRYPTED | FrameFlags::RAPTORQ);
    assert_eq!(decoded.symbol_count, 100);
    assert_eq!(decoded.object_id, object_id);
    assert_eq!(decoded.symbol_size, 64);
    assert_eq!(decoded.zone_key_id, zone_key_id);
    assert_eq!(decoded.zone_id_hash, zone.hash());
    assert_eq!(decoded.epoch_id, 42);
    assert_eq!(decoded.sender_instance_id, 0xCAFE_BABE);
    assert_eq!(decoded.frame_seq, 999);
}

/// Default frame flags include ENCRYPTED and RAPTORQ per spec §9.8.3.
#[test]
fn default_frame_flags_match_spec() {
    let flags = FrameFlags::default();
    assert!(flags.contains(FrameFlags::ENCRYPTED));
    assert!(flags.contains(FrameFlags::RAPTORQ));
    assert!(!flags.contains(FrameFlags::COMPRESSED));
    assert!(!flags.contains(FrameFlags::CONTROL_PLANE));
}

/// Symbol record overhead constant matches the spec (ESI:4 + K:2 + `auth_tag:16` = 22).
#[test]
fn symbol_record_overhead_matches_spec() {
    assert_eq!(SYMBOL_RECORD_OVERHEAD, 22);
}
