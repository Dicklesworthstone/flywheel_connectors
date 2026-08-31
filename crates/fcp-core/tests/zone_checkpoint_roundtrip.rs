use fcp_cbor::SchemaId;
use fcp_core::{
    DeviceSelector, EpochId, NodeId, NodeSignature, ObjectHeader, ObjectId, ObjectPlacementPolicy,
    Provenance, ProvenanceStep, SignatureSet, ZoneCheckpoint, ZoneId,
};
use semver::Version;

const CHECKPOINT_FIELDS: &[&str] = &[
    "header",
    "zone_id",
    "rev_head",
    "rev_seq",
    "audit_head",
    "audit_seq",
    "zone_definition_head",
    "zone_policy_head",
    "active_zone_key_manifest",
    "checkpoint_seq",
    "as_of_epoch",
    "quorum_signatures",
    "revocation_freshness_sla_secs",
];

#[test]
fn zone_checkpoint_json_and_cbor_roundtrip_with_all_fields_populated() {
    let checkpoint = canonical_zone_checkpoint();

    let json_value = serde_json::to_value(&checkpoint).expect("ZoneCheckpoint serializes to JSON");
    assert_top_level_fields_present(&json_value);
    assert_header_fields_present(&json_value);

    let json_bytes = serde_json::to_vec(&checkpoint).expect("ZoneCheckpoint encodes as JSON");
    let json_decoded: ZoneCheckpoint =
        serde_json::from_slice(&json_bytes).expect("ZoneCheckpoint decodes from JSON");
    assert_eq!(serde_json::to_value(&json_decoded).unwrap(), json_value);

    let mut cbor_bytes = Vec::new();
    ciborium::into_writer(&checkpoint, &mut cbor_bytes).expect("ZoneCheckpoint encodes as CBOR");
    let cbor_decoded: ZoneCheckpoint =
        ciborium::from_reader(&cbor_bytes[..]).expect("ZoneCheckpoint decodes from CBOR");
    assert_eq!(serde_json::to_value(&cbor_decoded).unwrap(), json_value);

    assert_eq!(cbor_decoded.zone_id(), checkpoint.zone_id());
    assert_eq!(cbor_decoded.quorum_signatures.len(), 3);
    assert_eq!(
        cbor_decoded
            .quorum_signatures
            .as_slice()
            .iter()
            .map(|sig| sig.node_id.as_str())
            .collect::<Vec<_>>(),
        ["node-a", "node-b", "node-c"],
    );
}

fn canonical_zone_checkpoint() -> ZoneCheckpoint {
    let zone_id = "z:project:checkpoint"
        .parse::<ZoneId>()
        .expect("project zone parses");

    ZoneCheckpoint {
        header: ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.core", "ZoneCheckpoint", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 1_700_000_123,
            provenance: Provenance::tainted(ZoneId::public())
                .with_step(ProvenanceStep {
                    timestamp_ms: 1_700_000_123_456,
                    zone: ZoneId::public(),
                    actor: "principal:alice".to_owned(),
                    action: "checkpoint.propose".to_owned(),
                    resource: "fcp://checkpoint/zones/checkpoint".to_owned(),
                })
                .elevated_with("approval-token-1"),
            refs: vec![object_id(0x11), object_id(0x12)],
            foreign_refs: vec![object_id(0x21)],
            ttl_secs: Some(86_400),
            placement: Some(ObjectPlacementPolicy {
                min_nodes: 3,
                max_node_fraction_bps: 5_000,
                preferred_devices: vec![
                    DeviceSelector::Tag("tag:fcp-work".to_owned()),
                    DeviceSelector::Class("nvme".to_owned()),
                    DeviceSelector::NodeId(42),
                ],
                excluded_devices: vec![
                    DeviceSelector::Zone(ZoneId::public()),
                    DeviceSelector::HasCapability("cap.untrusted".to_owned()),
                ],
                target_coverage_bps: 9_500,
                min_source_diversity: 2,
            }),
        },
        zone_id,
        rev_head: object_id(0x31),
        rev_seq: 17,
        audit_head: object_id(0x41),
        audit_seq: 29,
        zone_definition_head: object_id(0x51),
        zone_policy_head: object_id(0x61),
        active_zone_key_manifest: object_id(0x71),
        checkpoint_seq: 7,
        as_of_epoch: EpochId::new("epoch-2026-04-28"),
        quorum_signatures: quorum_signatures(),
        revocation_freshness_sla_secs: 900,
    }
}

fn quorum_signatures() -> SignatureSet {
    let mut signatures = SignatureSet::new();
    assert!(signatures.add(NodeSignature::new(
        NodeId::new("node-c"),
        [0x03; 64],
        1_700_000_126,
    )));
    assert!(signatures.add(NodeSignature::new(
        NodeId::new("node-a"),
        [0x01; 64],
        1_700_000_124,
    )));
    assert!(signatures.add(NodeSignature::new(
        NodeId::new("node-b"),
        [0x02; 64],
        1_700_000_125,
    )));
    signatures
}

const fn object_id(byte: u8) -> ObjectId {
    ObjectId::from_bytes([byte; 32])
}

fn assert_top_level_fields_present(value: &serde_json::Value) {
    let object = value.as_object().expect("ZoneCheckpoint is a JSON object");
    for field in CHECKPOINT_FIELDS {
        assert!(
            object.contains_key(*field),
            "missing checkpoint field {field}"
        );
    }
}

fn assert_header_fields_present(value: &serde_json::Value) {
    let header = value
        .get("header")
        .and_then(serde_json::Value::as_object)
        .expect("header is a JSON object");
    for field in [
        "schema",
        "zone_id",
        "created_at",
        "provenance",
        "refs",
        "foreign_refs",
        "ttl_secs",
        "placement",
    ] {
        assert!(header.contains_key(field), "missing header field {field}");
    }

    let provenance = header
        .get("provenance")
        .and_then(serde_json::Value::as_object)
        .expect("provenance is a JSON object");
    assert_eq!(provenance.get("taint"), Some(&serde_json::json!("Tainted")));
    assert_eq!(provenance.get("elevated"), Some(&serde_json::json!(true)));
    assert!(provenance.contains_key("elevation_token"));
}
