#![no_main]

mod store_gc_object_headers;

use arbitrary::{Arbitrary, Unstructured};
use bytes::Bytes;
use fcp_core::{
    ObjectHeader, ObjectId, ObjectPlacementPolicy, Provenance, RetentionClass, StorageMeta,
    StoredObject, ZoneId,
};
use fcp_store::{
    GarbageCollector, GcConfig, GcRoots, MemoryObjectStore, MemoryObjectStoreConfig,
    MemorySymbolStore, MemorySymbolStoreConfig, ObjectStore, ObjectSymbolMeta,
    ObjectTransmissionInfo, RepairController, RepairControllerConfig, RepairCycleBudget,
    RepairPlanningOptions, RepairResult, StoredSymbol, SymbolMeta, SymbolStore,
    snapshot_zone_lifecycle,
};
use libfuzzer_sys::fuzz_target;
use semver::Version;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};

const MAX_OBJECTS: usize = 6;
const MAX_SYMBOLS_PER_OBJECT: usize = 8;
const MAX_BODY_BYTES: usize = 128;
const MAX_SYMBOL_BYTES: usize = 64;

#[derive(Debug, Clone, Deserialize)]
struct StoreSeed {
    zone_id: Option<String>,
    current_time: Option<u64>,
    checkpoint: Option<usize>,
    checkpoint_vector: Option<String>,
    body_vector: Option<String>,
    header_mutations: Option<Vec<HeaderMutationSeed>>,
    pinned: Option<Vec<usize>>,
    hot_objects: Option<Vec<usize>>,
    cycle_id: Option<u64>,
    power_saver: Option<bool>,
    mains_power: Option<bool>,
    metered_network: Option<bool>,
    bandwidth_estimate_kbps: Option<u32>,
    derp_penalty_bps: Option<u32>,
    objects: Option<Vec<ObjectSeed>>,
}

#[derive(Debug, Clone, Deserialize)]
struct ObjectSeed {
    id_hex: Option<String>,
    id_byte: Option<u8>,
    zone_id: Option<String>,
    body_hex: Option<String>,
    refs: Option<Vec<usize>>,
    foreign_refs: Option<Vec<usize>>,
    retention: Option<String>,
    lease_expires_at: Option<u64>,
    ttl_secs: Option<u64>,
    placement: Option<PlacementSeed>,
    include_policy: Option<bool>,
    source_symbols: Option<u32>,
    symbol_size: Option<u16>,
    symbols: Option<Vec<SymbolSeed>>,
}

#[derive(Debug, Clone, Deserialize)]
struct PlacementSeed {
    min_nodes: Option<u8>,
    max_node_fraction_bps: Option<u16>,
    target_coverage_bps: Option<u32>,
    min_source_diversity: Option<u8>,
}

#[derive(Debug, Clone, Deserialize)]
struct SymbolSeed {
    esi: Option<u32>,
    data_hex: Option<String>,
    source_node: Option<u64>,
    zone_id: Option<String>,
    stored_at: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
struct HeaderMutationSeed {
    index: Option<usize>,
    action: Option<String>,
    target: Option<usize>,
    zone_id: Option<String>,
    ttl_secs: Option<u64>,
}

fn bounded_len(u: &mut Unstructured<'_>, max_len: usize) -> usize {
    u.int_in_range(0..=max_len).unwrap_or(0)
}

fn bounded_bytes(u: &mut Unstructured<'_>, max_len: usize) -> Vec<u8> {
    let len = bounded_len(u, max_len);
    u.bytes(len).map(ToOwned::to_owned).unwrap_or_default()
}

fn bounded_string(u: &mut Unstructured<'_>, max_len: usize) -> String {
    String::from_utf8_lossy(&bounded_bytes(u, max_len)).into_owned()
}

fn optional_bool(u: &mut Unstructured<'_>) -> Option<bool> {
    if u.arbitrary::<bool>().unwrap_or(false) {
        Some(u.arbitrary::<bool>().unwrap_or(false))
    } else {
        None
    }
}

fn maybe_text(u: &mut Unstructured<'_>, max_len: usize) -> Option<String> {
    if u.arbitrary::<bool>().unwrap_or(false) {
        Some(bounded_string(u, max_len))
    } else {
        None
    }
}

fn store_seed_from_unstructured(data: &[u8]) -> StoreSeed {
    let mut u = Unstructured::new(data);
    let object_count = bounded_len(&mut u, MAX_OBJECTS);
    let mut objects = Vec::with_capacity(object_count);
    for index in 0..object_count {
        let symbol_count = bounded_len(&mut u, MAX_SYMBOLS_PER_OBJECT);
        let mut symbols = Vec::with_capacity(symbol_count);
        for symbol_index in 0..symbol_count {
            let source_node = if u.arbitrary::<bool>().unwrap_or(false) {
                Some(u64::from(
                    u16::arbitrary(&mut u).unwrap_or(symbol_index as u16),
                ))
            } else {
                None
            };
            symbols.push(SymbolSeed {
                esi: Some(u32::from(
                    u16::arbitrary(&mut u).unwrap_or(symbol_index as u16),
                )),
                data_hex: Some(hex::encode(bounded_bytes(&mut u, MAX_SYMBOL_BYTES))),
                source_node,
                zone_id: maybe_text(&mut u, 16),
                stored_at: Some(u64::from(
                    u16::arbitrary(&mut u).unwrap_or(symbol_index as u16),
                )),
            });
        }

        objects.push(ObjectSeed {
            id_hex: None,
            id_byte: Some(u8::arbitrary(&mut u).unwrap_or(index as u8)),
            zone_id: maybe_text(&mut u, 16),
            body_hex: Some(hex::encode(bounded_bytes(&mut u, MAX_BODY_BYTES))),
            refs: Some(
                (0..bounded_len(&mut u, 3))
                    .map(|_| bounded_len(&mut u, MAX_OBJECTS.saturating_sub(1)))
                    .collect(),
            ),
            foreign_refs: Some(
                (0..bounded_len(&mut u, 2))
                    .map(|_| bounded_len(&mut u, MAX_OBJECTS.saturating_sub(1)))
                    .collect(),
            ),
            retention: Some(match u.int_in_range(0..=2).unwrap_or(1) {
                0 => "pinned".to_string(),
                1 => "ephemeral".to_string(),
                _ => "lease".to_string(),
            }),
            lease_expires_at: Some(u64::from(u16::arbitrary(&mut u).unwrap_or(0))),
            ttl_secs: Some(u64::from(u16::arbitrary(&mut u).unwrap_or(0))),
            placement: Some(PlacementSeed {
                min_nodes: Some(u.int_in_range(1..=4).unwrap_or(1)),
                max_node_fraction_bps: Some(u.int_in_range(1_000..=10_000).unwrap_or(10_000)),
                target_coverage_bps: Some(u.int_in_range(0..=10_000).unwrap_or(10_000)),
                min_source_diversity: Some(u.int_in_range(0..=4).unwrap_or(0)),
            }),
            include_policy: optional_bool(&mut u),
            source_symbols: Some(u32::from(u.int_in_range::<u8>(1..=8).unwrap_or(1))),
            symbol_size: Some(u.int_in_range(1..=64).unwrap_or(8)),
            symbols: Some(symbols),
        });
    }

    StoreSeed {
        zone_id: maybe_text(&mut u, 16),
        current_time: Some(u64::from(u16::arbitrary(&mut u).unwrap_or(0))),
        checkpoint: Some(bounded_len(&mut u, MAX_OBJECTS.saturating_sub(1))),
        checkpoint_vector: None,
        body_vector: None,
        header_mutations: None,
        pinned: Some(
            (0..bounded_len(&mut u, 3))
                .map(|_| bounded_len(&mut u, MAX_OBJECTS.saturating_sub(1)))
                .collect(),
        ),
        hot_objects: Some(
            (0..bounded_len(&mut u, 3))
                .map(|_| bounded_len(&mut u, MAX_OBJECTS.saturating_sub(1)))
                .collect(),
        ),
        cycle_id: Some(u64::from(u16::arbitrary(&mut u).unwrap_or(0))),
        power_saver: optional_bool(&mut u),
        mains_power: optional_bool(&mut u),
        metered_network: optional_bool(&mut u),
        bandwidth_estimate_kbps: Some(u32::from(u16::arbitrary(&mut u).unwrap_or(0))),
        derp_penalty_bps: Some(u32::from(u16::arbitrary(&mut u).unwrap_or(0))),
        objects: Some(objects),
    }
}

fn store_input(data: &[u8]) -> StoreSeed {
    serde_json::from_slice::<StoreSeed>(data).unwrap_or_else(|_| store_seed_from_unstructured(data))
}

fn parse_zone(value: Option<&str>, fallback: &ZoneId) -> ZoneId {
    value
        .and_then(|candidate| candidate.parse::<ZoneId>().ok())
        .unwrap_or_else(|| fallback.clone())
}

fn decode_hex_or_empty(value: Option<&str>) -> Vec<u8> {
    value
        .and_then(|encoded| hex::decode(encoded).ok())
        .unwrap_or_default()
}

fn schema() -> fcp_cbor::SchemaId {
    fcp_cbor::SchemaId::new("fcp.store", "FuzzObject", Version::new(1, 0, 0))
}

fn object_id_for(seed: &ObjectSeed, index: usize) -> ObjectId {
    if let Some(id_hex) = seed.id_hex.as_deref()
        && let Some(object_id) = store_gc_object_headers::parse_object_id_hex(id_hex)
    {
        return object_id;
    }
    let mut raw = [seed.id_byte.unwrap_or(index as u8); 32];
    raw[31] = index as u8;
    ObjectId::from_bytes(raw)
}

fn retention_for(seed: &ObjectSeed, current_time: u64) -> RetentionClass {
    match seed.retention.as_deref() {
        Some("pinned") => RetentionClass::Pinned,
        Some("lease") => RetentionClass::Lease {
            expires_at: seed
                .lease_expires_at
                .unwrap_or(current_time.saturating_add(1)),
        },
        _ => RetentionClass::Ephemeral,
    }
}

fn placement_for(seed: &ObjectSeed) -> Option<ObjectPlacementPolicy> {
    let placement = seed.placement.as_ref()?;
    Some(ObjectPlacementPolicy {
        min_nodes: placement.min_nodes.unwrap_or(1).max(1),
        max_node_fraction_bps: placement
            .max_node_fraction_bps
            .unwrap_or(10_000)
            .clamp(1, 10_000),
        preferred_devices: Vec::new(),
        excluded_devices: Vec::new(),
        target_coverage_bps: placement
            .target_coverage_bps
            .unwrap_or(10_000)
            .clamp(0, 10_000),
        min_source_diversity: placement.min_source_diversity.unwrap_or(0),
    })
}

fn selected_ids(indices: Option<&[usize]>, ids: &[ObjectId]) -> Vec<ObjectId> {
    indices
        .unwrap_or(&[])
        .iter()
        .filter_map(|index| ids.get(*index).copied())
        .collect()
}

fn planning_options(seed: &StoreSeed, ids: &[ObjectId]) -> RepairPlanningOptions {
    RepairPlanningOptions {
        cycle_id: seed.cycle_id.unwrap_or(0),
        budget: RepairCycleBudget {
            max_repairs: ids.len().saturating_add(1),
            max_bytes: 64 * 1024,
            max_decode_ms: 10_000,
        },
        hot_objects: selected_ids(seed.hot_objects.as_deref(), ids),
        hot_object_min_coverage_bps: 9_500,
        power_saver: seed.power_saver.unwrap_or(false),
        mains_power: seed.mains_power.unwrap_or(false),
        metered_network: seed.metered_network.unwrap_or(false),
        bandwidth_estimate_kbps: seed.bandwidth_estimate_kbps.unwrap_or(0),
        derp_penalty_bps: seed.derp_penalty_bps.unwrap_or(0).min(20_000),
    }
}

fn controller_config(max_repairs: usize) -> RepairControllerConfig {
    RepairControllerConfig {
        max_concurrent_repairs: max_repairs.max(1),
        max_repairs_per_minute: 128,
        repair_interval: std::time::Duration::from_secs(1),
        min_deficit_bps: 100,
        max_symbols_per_repair: 32,
    }
}

fuzz_target!(|data: &[u8]| {
    let seed = store_input(data);
    let (primary_zone, mut objects, default_checkpoint) =
        store_gc_object_headers::hydrate_vector_objects(&seed).unwrap_or_else(|| {
            let primary_zone = seed
                .zone_id
                .as_deref()
                .and_then(|zone| zone.parse::<ZoneId>().ok())
                .unwrap_or_else(ZoneId::work);
            let objects = seed
                .objects
                .clone()
                .unwrap_or_default()
                .into_iter()
                .take(MAX_OBJECTS)
                .collect::<Vec<_>>();
            (primary_zone, objects, None)
        });
    store_gc_object_headers::apply_header_mutations(&mut objects, seed.header_mutations.as_deref());
    let object_store = MemoryObjectStore::new(MemoryObjectStoreConfig { max_bytes: 1 << 20 });
    let symbol_store = MemorySymbolStore::new(MemorySymbolStoreConfig {
        max_bytes: 1 << 20,
        local_node_id: 0,
    });
    let ids = objects
        .iter()
        .enumerate()
        .map(|(index, object)| object_id_for(object, index))
        .collect::<Vec<_>>();
    let options = planning_options(&seed, &ids);
    let controller = RepairController::new(controller_config(ids.len()));
    let current_time = seed.current_time.unwrap_or(0);

    let _ = fcp_async_core::runtime::block_on_sync(async {
        let mut policies = HashMap::new();
        for (index, object_seed) in objects.iter().enumerate() {
            let zone = parse_zone(object_seed.zone_id.as_deref(), &primary_zone);
            let placement = placement_for(object_seed);
            let stored = StoredObject {
                object_id: ids[index],
                header: ObjectHeader {
                    schema: schema(),
                    zone_id: zone.clone(),
                    created_at: current_time.saturating_add(index as u64),
                    provenance: Provenance::new(zone.clone()),
                    refs: selected_ids(object_seed.refs.as_deref(), &ids),
                    foreign_refs: selected_ids(object_seed.foreign_refs.as_deref(), &ids),
                    ttl_secs: object_seed.ttl_secs,
                    placement: placement.clone(),
                },
                body: decode_hex_or_empty(object_seed.body_hex.as_deref()),
                storage: StorageMeta {
                    retention: retention_for(object_seed, current_time),
                },
            };
            let _ = object_store.put(stored).await;

            let symbol_size = object_seed.symbol_size.unwrap_or(8).max(1);
            let source_symbols = object_seed.source_symbols.unwrap_or_else(|| {
                object_seed
                    .symbols
                    .as_ref()
                    .map_or(1, |symbols| symbols.len() as u32)
                    .max(1)
            });
            let meta = ObjectSymbolMeta {
                object_id: ids[index],
                zone_id: zone.clone(),
                oti: ObjectTransmissionInfo {
                    transfer_length: u64::from(source_symbols) * u64::from(symbol_size),
                    symbol_size,
                    source_blocks: 1,
                    sub_blocks: 1,
                    alignment: 8,
                    payload_hash: None,
                },
                source_symbols,
                first_symbol_at: current_time,
            };
            let _ = symbol_store.put_object_meta(meta).await;

            for symbol_seed in object_seed
                .symbols
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .take(MAX_SYMBOLS_PER_OBJECT)
            {
                let _ = symbol_store
                    .put_symbol(StoredSymbol {
                        meta: SymbolMeta {
                            object_id: ids[index],
                            esi: symbol_seed.esi.unwrap_or(0),
                            zone_id: parse_zone(symbol_seed.zone_id.as_deref(), &zone),
                            source_node: symbol_seed.source_node,
                            stored_at: symbol_seed.stored_at.unwrap_or(current_time),
                        },
                        data: Bytes::from(decode_hex_or_empty(symbol_seed.data_hex.as_deref())),
                    })
                    .await;
            }

            if object_seed.include_policy.unwrap_or(placement.is_some())
                && let Some(policy) = placement
            {
                policies.insert(ids[index], policy);
            }
        }

        let mut roots = GcRoots::new();
        if let Some(checkpoint) = seed
            .checkpoint
            .or(default_checkpoint)
            .and_then(|index| ids.get(index))
            .copied()
        {
            roots.set_checkpoint(checkpoint);
        }
        for pinned in selected_ids(seed.pinned.as_deref(), &ids) {
            roots.add_pin(pinned);
        }

        if let Ok(snapshot) = snapshot_zone_lifecycle(
            &primary_zone,
            &roots,
            &object_store,
            Some(&symbol_store),
            current_time,
        )
        .await
        {
            assert_eq!(snapshot.zone_id, primary_zone);
            let snapshot_ids = snapshot
                .objects
                .iter()
                .map(|object| object.object_id)
                .collect::<HashSet<_>>();
            assert_eq!(snapshot_ids.len(), snapshot.objects.len());
        }

        let report = controller
            .evaluate_zone_with_report(&primary_zone, &symbol_store, &policies)
            .await;
        assert_eq!(report.zone_id, primary_zone);
        assert_eq!(report.queue_depth_after, controller.queue_depth());

        let plan = controller
            .plan_zone(&primary_zone, &symbol_store, &policies, &options)
            .await;
        assert_eq!(plan.zone_id, primary_zone);
        assert_eq!(
            plan.actions.len().saturating_add(plan.deferred.len()),
            plan.object_count_below_target
        );
        assert!(plan.budget_used.repairs <= plan.budget.max_repairs);
        assert!(plan.budget_used.bytes <= plan.budget.max_bytes);
        assert!(plan.budget_used.decode_ms <= plan.budget.max_decode_ms);

        let mut drained = 0usize;
        while let Some(request) = controller.next_repair() {
            controller.record_result(&RepairResult {
                object_id: request.object_id,
                success: true,
                new_coverage_bps: request.coverage.coverage_bps,
                symbols_added: 0,
                error: None,
            });
            drained = drained.saturating_add(1);
            if drained > MAX_OBJECTS {
                break;
            }
        }

        let stats = controller.stats();
        assert!(stats.repairs_attempted as usize >= drained);
        assert!(stats.queue_depth <= report.queue_depth_after);

        let gc = GarbageCollector::new(GcConfig {
            max_evictions_per_run: ids.len().max(1),
            enforce_lease_expiry: true,
        });
        if let Ok(gc_report) = gc
            .collect_and_prune_symbols_with_transcript(
                &primary_zone,
                &roots,
                &object_store,
                &symbol_store,
                current_time,
            )
            .await
        {
            assert_eq!(gc_report.transcript.zone_id, primary_zone);
            assert_eq!(gc_report.transcript.root_count, roots.root_count());
            assert!(gc_report.transcript.decisions.len() <= ids.len());
            assert!(gc_report.result.live <= ids.len());
            assert!(gc_report.result.evicted <= ids.len());
        }
    });
});
