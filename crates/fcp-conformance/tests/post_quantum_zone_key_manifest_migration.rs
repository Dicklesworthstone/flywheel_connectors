//! Post-quantum conformance: `ZoneKeyManifest` V3 to V4 migration determinism.

use fcp_core::{
    NodeId, NodeSignature, ObjectHeader, ObjectIdKeyId, Provenance, TailscaleNodeId,
    WrappedZoneKey, ZoneId, ZoneKemAlgorithm, ZoneKeyAlgorithm, ZoneKeyId, ZoneKeyManifest,
};
use fcp_crypto::HpkeSealedBox;
use semver::Version;

const EXPECTED_V4_MIGRATION_HASH: &str =
    "bfb6b6d4be3ab01baba6f544380ccb4bd640b4d9a66cf9162a56c2f37b8ded58";

fn fixture_manifest() -> ZoneKeyManifest {
    let zone_id = ZoneId::work();
    ZoneKeyManifest {
        header: ObjectHeader {
            encryption_kind: Default::default(),
            schema: fcp_cbor::SchemaId::new("fcp.zone", "ZoneKeyManifest", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 1_700_000_000,
            provenance: Provenance::new(zone_id.clone()),
            refs: Vec::new(),
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        },
        zone_id,
        zone_key_id: ZoneKeyId::from_bytes([0xA1; 8]),
        object_id_key_id: ObjectIdKeyId::from_bytes([0xB2; 8]),
        algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
        valid_from: 1_700_000_000,
        valid_until: Some(1_800_000_000),
        prev_zone_key_id: Some(ZoneKeyId::from_bytes([0xC3; 8])),
        wrapped_keys: vec![
            WrappedZoneKey {
                recipient: TailscaleNodeId::new("node-alpha"),
                issued_at: 1_700_000_010,
                sealed: HpkeSealedBox {
                    enc: vec![0x11; 32],
                    ciphertext: vec![0x12; 48],
                },
            },
            WrappedZoneKey {
                recipient: TailscaleNodeId::new("node-beta"),
                issued_at: 1_700_000_020,
                sealed: HpkeSealedBox {
                    enc: vec![0x21; 32],
                    ciphertext: vec![0x22; 48],
                },
            },
        ],
        wrapped_object_id_keys: Vec::new(),
        rekey_policy: None,
        signature: NodeSignature::new(NodeId::new("owner-node"), [0xD4; 64], 1_700_000_000),
        kem: ZoneKemAlgorithm::HpkeX25519,
        wrapped_keys_v4: Vec::new(),
    }
}

#[test]
fn zone_key_manifest_v3_to_v4_migration_is_byte_deterministic() {
    let source = fixture_manifest();
    // br-z8bsg: migrated_to_v4 returns UnsignedV4Manifest. The
    // determinism property is over the migrated PAYLOAD, accessed via
    // .as_payload(); the eventual owner signature is out of scope
    // here.
    let first = source.migrated_to_v4(ZoneKemAlgorithm::XWing);
    let second = source.migrated_to_v4(ZoneKemAlgorithm::XWing);
    let third = source.migrated_to_v4(ZoneKemAlgorithm::XWing);

    assert_eq!(first.as_payload().kem, ZoneKemAlgorithm::XWing);
    assert_eq!(second.as_payload().kem, ZoneKemAlgorithm::XWing);
    assert_eq!(third.as_payload().kem, ZoneKemAlgorithm::XWing);
    assert_eq!(
        first.as_payload().wrapped_keys.len(),
        2,
        "V3 wraps stay present"
    );
    assert_eq!(
        first.as_payload().wrapped_keys_v4.len(),
        2,
        "V3 wraps are promoted into the V4 list"
    );

    let first_bytes =
        fcp_cbor::to_canonical_cbor(first.as_payload()).expect("first V4 manifest encodes");
    let second_bytes =
        fcp_cbor::to_canonical_cbor(second.as_payload()).expect("second V4 manifest encodes");
    let third_bytes =
        fcp_cbor::to_canonical_cbor(third.as_payload()).expect("third V4 manifest encodes");
    assert_eq!(
        first_bytes, second_bytes,
        "canonical CBOR must be deterministic across migration runs"
    );
    assert_eq!(
        second_bytes, third_bytes,
        "cloned input must produce byte-identical V4 manifest"
    );
    assert_eq!(
        blake3::hash(&first_bytes).to_hex().as_str(),
        EXPECTED_V4_MIGRATION_HASH,
        "V3 to V4 migration golden hash drifted"
    );
}
