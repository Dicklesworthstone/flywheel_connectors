//! Pin `DeviceSelector` + `ObjectPlacementPolicy` serde shape — the
//! closest analogues to "`ConnectorTopology`"
//! (flywheel_connectors-xmri2).
//!
//! Bead asks for `ConnectorTopology serde JSON+CBOR roundtrip`. No
//! type literally named `ConnectorTopology` exists in fcp-core. The
//! topology-shaped surface that decides "which mesh nodes can host
//! which objects/connectors" splits across:
//!
//!  - `DeviceSelector` (object.rs:154) — 5-variant externally-
//!    tagged enum (Tag/Class/NodeId/Zone/HasCapability) selecting
//!    nodes by attribute. NOT yet pinned for serde shape.
//!  - `ObjectPlacementPolicy` (object.rs:180) — placement struct
//!    (`min_nodes` / `max_node_fraction_bps` / `preferred_devices` /
//!    `excluded_devices` / `target_coverage_bps` / `min_source_diversity`).
//!    NOT yet pinned for serde.
//!  - `MeshPlacementHint` (object.rs:165) — preference hint
//!    classifier, already pinned by
//!    `mesh_placement_hint_serde_ordering.rs`.
//!
//! Pinning targets:
//!
//!   1. **`DeviceSelector` per-variant JSON shape** — externally-
//!      tagged single-key form `{"VariantName": <payload>}` with
//!      `PascalCase` variant names (no `rename_all`).
//!   2. **JSON round-trip** preserves variant + payload for all 5
//!      variants.
//!   3. **CBOR round-trip** preserves variant + payload (externally-
//!      tagged, so no Content-shim quirk).
//!   4. **`PascalCase` canonical, `snake_case` rejected** — drift
//!      sentinel.
//!   5. **`ObjectPlacementPolicy` JSON shape** — 6-field struct
//!      with defaults on `preferred_devices`, `excluded_devices`,
//!      `min_source_diversity`.
//!   6. **`ObjectPlacementPolicy` JSON + CBOR round-trip**.
//!   7. **Default values** for unset fields when deserializing
//!      partial JSON — `min_source_diversity` default 0,
//!      preferred/excluded devices default to empty Vecs.
//!   8. **Nested `DeviceSelector` list preserved** through round-trip
//!      inside an `ObjectPlacementPolicy`.

use ciborium::value::Value as CborValue;
use fcp_core::{DeviceSelector, ObjectPlacementPolicy, ZoneId};

fn ts_node_zone() -> ZoneId {
    ZoneId::work()
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. DeviceSelector per-variant JSON shape
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn device_selector_tag_variant_json_shape_pinned() {
    let value =
        serde_json::to_value(DeviceSelector::Tag("trusted".to_string())).expect("serialize");
    assert_eq!(
        value,
        serde_json::json!({"Tag": "trusted"}),
        "Tag MUST encode externally-tagged single-key with payload"
    );
}

#[test]
fn device_selector_class_variant_json_shape_pinned() {
    let value = serde_json::to_value(DeviceSelector::Class("hub".to_string())).expect("serialize");
    assert_eq!(value, serde_json::json!({"Class": "hub"}));
}

#[test]
fn device_selector_node_id_variant_json_shape_pinned() {
    let value = serde_json::to_value(DeviceSelector::NodeId(123)).expect("serialize");
    assert_eq!(value, serde_json::json!({"NodeId": 123}));
}

#[test]
fn device_selector_zone_variant_json_shape_pinned() {
    let value = serde_json::to_value(DeviceSelector::Zone(ts_node_zone())).expect("serialize");
    assert_eq!(
        value,
        serde_json::json!({"Zone": "z:work"}),
        "Zone payload is the canonical zone id string"
    );
}

#[test]
fn device_selector_has_capability_variant_json_shape_pinned() {
    let value = serde_json::to_value(DeviceSelector::HasCapability("oauth".to_string()))
        .expect("serialize");
    assert_eq!(value, serde_json::json!({"HasCapability": "oauth"}));
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. DeviceSelector JSON round-trip per variant
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn device_selector_json_roundtrip_preserves_tag() {
    let original = DeviceSelector::Tag("alpha".to_string());
    let json = serde_json::to_string(&original).expect("serialize");
    let back: DeviceSelector = serde_json::from_str(&json).expect("deserialize");
    match back {
        DeviceSelector::Tag(s) => assert_eq!(s, "alpha"),
        other => panic!("expected Tag, got {other:?}"),
    }
}

#[test]
fn device_selector_json_roundtrip_preserves_class() {
    let original = DeviceSelector::Class("hub".to_string());
    let json = serde_json::to_string(&original).expect("serialize");
    let back: DeviceSelector = serde_json::from_str(&json).expect("deserialize");
    match back {
        DeviceSelector::Class(s) => assert_eq!(s, "hub"),
        other => panic!("expected Class, got {other:?}"),
    }
}

#[test]
fn device_selector_json_roundtrip_preserves_node_id() {
    let original = DeviceSelector::NodeId(u64::MAX);
    let json = serde_json::to_string(&original).expect("serialize");
    let back: DeviceSelector = serde_json::from_str(&json).expect("deserialize");
    match back {
        DeviceSelector::NodeId(n) => assert_eq!(n, u64::MAX),
        other => panic!("expected NodeId, got {other:?}"),
    }
}

#[test]
fn device_selector_json_roundtrip_preserves_zone() {
    let original = DeviceSelector::Zone(ZoneId::owner());
    let json = serde_json::to_string(&original).expect("serialize");
    let back: DeviceSelector = serde_json::from_str(&json).expect("deserialize");
    match back {
        DeviceSelector::Zone(z) => assert_eq!(z, ZoneId::owner()),
        other => panic!("expected Zone, got {other:?}"),
    }
}

#[test]
fn device_selector_json_roundtrip_preserves_has_capability() {
    let original = DeviceSelector::HasCapability("read".to_string());
    let json = serde_json::to_string(&original).expect("serialize");
    let back: DeviceSelector = serde_json::from_str(&json).expect("deserialize");
    match back {
        DeviceSelector::HasCapability(s) => assert_eq!(s, "read"),
        other => panic!("expected HasCapability, got {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. DeviceSelector CBOR round-trip per variant
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn device_selector_cbor_roundtrip_preserves_every_variant() {
    let cases = [
        DeviceSelector::Tag("t".to_string()),
        DeviceSelector::Class("c".to_string()),
        DeviceSelector::NodeId(42),
        DeviceSelector::Zone(ZoneId::work()),
        DeviceSelector::HasCapability("k".to_string()),
    ];
    for variant in cases {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&variant, &mut buf).expect("encode");
        let back: DeviceSelector = ciborium::de::from_reader(buf.as_slice()).expect("decode");
        // We compare via JSON since DeviceSelector doesn't derive PartialEq.
        let original_json = serde_json::to_value(&variant).unwrap();
        let back_json = serde_json::to_value(&back).unwrap();
        assert_eq!(original_json, back_json, "CBOR round-trip drift");
    }
}

#[test]
fn device_selector_cbor_carries_externally_tagged_variant_key() {
    // Externally-tagged: CBOR encoding is single-key map keyed on
    // PascalCase variant name.
    let variant = DeviceSelector::Tag("inspect".to_string());
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&variant, &mut buf).expect("encode");
    let value: CborValue = ciborium::de::from_reader(buf.as_slice()).expect("decode as Value");
    let map = match value {
        CborValue::Map(m) => m,
        other => panic!("DeviceSelector MUST encode as CBOR Map, got {other:?}"),
    };
    assert_eq!(map.len(), 1, "single-key form");
    let (key, payload) = &map[0];
    match key {
        CborValue::Text(s) => assert_eq!(s, "Tag"),
        other => panic!("outer key MUST be Text, got {other:?}"),
    }
    match payload {
        CborValue::Text(s) => assert_eq!(s, "inspect"),
        other => panic!("Tag payload MUST be Text, got {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. PascalCase canonical / snake_case rejected
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn device_selector_rejects_snake_case_outer_key() {
    let bad = serde_json::json!({"tag": "x"});
    let parsed = serde_json::from_value::<DeviceSelector>(bad);
    assert!(
        parsed.is_err(),
        "snake_case outer key MUST be rejected — wire form is PascalCase variant name"
    );
}

#[test]
fn device_selector_rejects_kebab_case_outer_key() {
    let bad = serde_json::json!({"has-capability": "x"});
    let parsed = serde_json::from_value::<DeviceSelector>(bad);
    assert!(parsed.is_err());
}

#[test]
fn device_selector_rejects_unknown_variant() {
    let bad = serde_json::json!({"Unknown": "x"});
    let parsed = serde_json::from_value::<DeviceSelector>(bad);
    assert!(parsed.is_err(), "unknown variant MUST be rejected");
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. ObjectPlacementPolicy JSON shape
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn object_placement_policy_full_json_shape_pinned() {
    let policy = ObjectPlacementPolicy {
        min_nodes: 3,
        max_node_fraction_bps: 5_000,
        preferred_devices: vec![DeviceSelector::Tag("trusted".to_string())],
        excluded_devices: vec![DeviceSelector::Class("untrusted".to_string())],
        target_coverage_bps: 9_000,
        min_source_diversity: 2,
    };
    let value = serde_json::to_value(&policy).expect("serialize");
    assert_eq!(
        value,
        serde_json::json!({
            "min_nodes": 3,
            "max_node_fraction_bps": 5_000,
            "preferred_devices": [{"Tag": "trusted"}],
            "excluded_devices": [{"Class": "untrusted"}],
            "target_coverage_bps": 9_000,
            "min_source_diversity": 2,
        }),
        "ObjectPlacementPolicy JSON shape drift"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. ObjectPlacementPolicy JSON + CBOR round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn object_placement_policy_json_roundtrip_preserves_all_fields() {
    let policy = ObjectPlacementPolicy {
        min_nodes: 5,
        max_node_fraction_bps: 3_333,
        preferred_devices: vec![
            DeviceSelector::Tag("a".to_string()),
            DeviceSelector::NodeId(99),
        ],
        excluded_devices: vec![DeviceSelector::Zone(ZoneId::public())],
        target_coverage_bps: 8_500,
        min_source_diversity: 3,
    };
    let json = serde_json::to_string(&policy).expect("serialize");
    let back: ObjectPlacementPolicy = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(back.min_nodes, policy.min_nodes);
    assert_eq!(back.max_node_fraction_bps, policy.max_node_fraction_bps);
    assert_eq!(back.target_coverage_bps, policy.target_coverage_bps);
    assert_eq!(back.min_source_diversity, policy.min_source_diversity);
    assert_eq!(back.preferred_devices.len(), policy.preferred_devices.len());
    assert_eq!(back.excluded_devices.len(), policy.excluded_devices.len());

    // Spot-check via JSON re-serialization since DeviceSelector
    // doesn't derive PartialEq.
    assert_eq!(
        serde_json::to_value(&back.preferred_devices).unwrap(),
        serde_json::to_value(&policy.preferred_devices).unwrap()
    );
}

#[test]
fn object_placement_policy_cbor_roundtrip_preserves_all_fields() {
    let policy = ObjectPlacementPolicy {
        min_nodes: 1,
        max_node_fraction_bps: 10_000,
        preferred_devices: vec![DeviceSelector::HasCapability("write".to_string())],
        excluded_devices: vec![],
        target_coverage_bps: 0,
        min_source_diversity: 0,
    };
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&policy, &mut buf).expect("encode");
    let back: ObjectPlacementPolicy = ciborium::de::from_reader(buf.as_slice()).expect("decode");
    assert_eq!(back.min_nodes, policy.min_nodes);
    assert_eq!(back.max_node_fraction_bps, policy.max_node_fraction_bps);
    assert_eq!(back.target_coverage_bps, policy.target_coverage_bps);
    assert_eq!(back.min_source_diversity, policy.min_source_diversity);
    assert_eq!(back.preferred_devices.len(), 1);
    assert_eq!(back.excluded_devices, [] as [fcp_core::DeviceSelector; 0]);
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Default values when deserializing partial JSON
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn object_placement_policy_min_source_diversity_defaults_to_zero() {
    // The field has `#[serde(default)]` — pin that omitting it
    // from the wire form gives 0.
    let json = r#"{
        "min_nodes": 1,
        "max_node_fraction_bps": 100,
        "preferred_devices": [],
        "excluded_devices": [],
        "target_coverage_bps": 100
    }"#;
    let policy: ObjectPlacementPolicy = serde_json::from_str(json).expect("deserialize");
    assert_eq!(
        policy.min_source_diversity, 0,
        "min_source_diversity MUST default to 0 when omitted"
    );
}

#[test]
fn object_placement_policy_preferred_excluded_default_to_empty_vec() {
    // Both Vec fields have `#[serde(default)]` — pin that omitting
    // them from the wire form gives empty Vec.
    let json = r#"{
        "min_nodes": 1,
        "max_node_fraction_bps": 100,
        "target_coverage_bps": 100
    }"#;
    let policy: ObjectPlacementPolicy = serde_json::from_str(json).expect("deserialize");
    assert_eq!(
        policy.preferred_devices,
        [] as [fcp_core::DeviceSelector; 0]
    );
    assert_eq!(policy.excluded_devices, [] as [fcp_core::DeviceSelector; 0]);
    assert_eq!(policy.min_source_diversity, 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Nested DeviceSelector list preserved through round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn nested_device_selector_list_preserved_through_policy_roundtrip() {
    let policy = ObjectPlacementPolicy {
        min_nodes: 2,
        max_node_fraction_bps: 5_000,
        preferred_devices: vec![
            DeviceSelector::Tag("a".to_string()),
            DeviceSelector::Class("b".to_string()),
            DeviceSelector::NodeId(7),
            DeviceSelector::Zone(ZoneId::work()),
            DeviceSelector::HasCapability("ping".to_string()),
        ],
        excluded_devices: vec![DeviceSelector::Tag("blocked".to_string())],
        target_coverage_bps: 5_000,
        min_source_diversity: 1,
    };

    let json = serde_json::to_string(&policy).expect("serialize");
    let back: ObjectPlacementPolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        back.preferred_devices.len(),
        5,
        "all 5 DeviceSelector variants survive round-trip"
    );
    // Order preservation pinned via JSON re-serialization equality.
    assert_eq!(
        serde_json::to_value(&back.preferred_devices).unwrap(),
        serde_json::to_value(&policy.preferred_devices).unwrap()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. Cross-format consistency
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn placement_policy_json_and_cbor_decode_to_same_policy() {
    let policy = ObjectPlacementPolicy {
        min_nodes: 2,
        max_node_fraction_bps: 5_000,
        preferred_devices: vec![DeviceSelector::Tag("x".to_string())],
        excluded_devices: vec![DeviceSelector::Class("y".to_string())],
        target_coverage_bps: 5_000,
        min_source_diversity: 1,
    };

    let json = serde_json::to_string(&policy).expect("JSON serialize");
    let from_json: ObjectPlacementPolicy = serde_json::from_str(&json).expect("JSON deserialize");

    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&policy, &mut cbor).expect("CBOR encode");
    let from_cbor: ObjectPlacementPolicy =
        ciborium::de::from_reader(cbor.as_slice()).expect("CBOR decode");

    assert_eq!(from_json.min_nodes, from_cbor.min_nodes);
    assert_eq!(
        from_json.max_node_fraction_bps,
        from_cbor.max_node_fraction_bps
    );
    assert_eq!(from_json.target_coverage_bps, from_cbor.target_coverage_bps);
    assert_eq!(
        from_json.min_source_diversity,
        from_cbor.min_source_diversity
    );
}
