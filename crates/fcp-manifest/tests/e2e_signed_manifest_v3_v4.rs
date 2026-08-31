use base64::Engine;
use fcp_core::{
    NodeId, NodeSignature, ObjectHeader, ObjectIdKey, ObjectIdKeyId, Provenance, TailscaleNodeId,
    ZONE_KEY_LEN, ZoneId, ZoneKemAlgorithm, ZoneKey, ZoneKeyAlgorithm, ZoneKeyId, ZoneKeyManifest,
    ZoneKeyRing, wrap_object_id_key, wrap_zone_key,
};
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_crypto::x25519::X25519SecretKey;
use fcp_manifest::{Base64Bytes, ConnectorManifest};
use tracing::{Level, span};

const PLACEHOLDER_HASH: &str =
    "blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000";

fn connector_manifest_toml(interface_hash: &str, publisher_sig: &Base64Bytes) -> String {
    format!(
        r#"[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"
min_mesh_version = "2.0.0"
min_protocol = "fcp2-sym/2.0"
protocol_features = []
max_datagram_bytes = 1200
interface_hash = "{interface_hash}"

[connector]
id = "fcp.e2e-manifest"
name = "E2E Manifest Connector"
version = "1.0.0"
description = "E2E signed manifest fixture"
archetypes = ["operational"]
format = "native"

[zones]
home = "z:work"
allowed_sources = ["z:work"]
allowed_targets = ["z:work"]
forbidden = []

[capabilities]
required = ["network.dns", "manifest.e2e"]
optional = []
forbidden = ["system.exec"]

[provides.operations.manifest_e2e]
description = "Exercise signed manifest E2E"
capability = "manifest.e2e"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "none"
input_schema = {{ type = "object" }}
output_schema = {{ type = "object" }}

[sandbox]
profile = "strict"
memory_mb = 64
cpu_percent = 20
wall_clock_timeout_ms = 1000
fs_readonly_paths = ["/usr"]
fs_writable_paths = ["$CONNECTOR_STATE"]
deny_exec = true
deny_ptrace = true

[signatures]
publisher_threshold = "1-of-1"

[[signatures.publisher_signatures]]
kid = "manifest-e2e-publisher"
sig = "{publisher_sig}"
"#,
        publisher_sig = String::from(publisher_sig.clone()),
    )
}

fn signed_connector_manifest() -> ConnectorManifest {
    let signing_key = Ed25519SigningKey::generate();
    let signature = signing_key.sign(b"fcp-manifest-e2e-signed-construction");
    let publisher_sig = Base64Bytes::try_from(format!(
        "base64:{}",
        base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
    ))
    .expect("base64 signature");
    let unchecked = ConnectorManifest::parse_str_unchecked(&connector_manifest_toml(
        PLACEHOLDER_HASH,
        &publisher_sig,
    ))
    .expect("unchecked manifest");
    let interface_hash = unchecked.compute_interface_hash().expect("interface hash");
    ConnectorManifest::parse_str(&connector_manifest_toml(
        &interface_hash.to_string(),
        &publisher_sig,
    ))
    .expect("signed manifest validates")
}

fn test_header(zone_id: &ZoneId) -> ObjectHeader {
    ObjectHeader {
        encryption_kind: Default::default(),
        schema: fcp_cbor::SchemaId::new(
            "fcp.zone",
            "ZoneKeyManifest",
            semver::Version::new(1, 0, 0),
        ),
        zone_id: zone_id.clone(),
        created_at: 1_700_000_000,
        provenance: Provenance::new(zone_id.clone()),
        refs: Vec::new(),
        foreign_refs: Vec::new(),
        ttl_secs: None,
        placement: None,
    }
}

fn test_signature() -> NodeSignature {
    NodeSignature::new(NodeId::new("owner-node-e2e"), [0xA5; 64], 1_700_000_000)
}

fn apply_for_recipient(
    manifest: &ZoneKeyManifest,
    node_id: &TailscaleNodeId,
    secret_key: &X25519SecretKey,
) -> ZoneKey {
    let mut ring = ZoneKeyRing::new(manifest.zone_id.clone());
    ring.apply_manifest(manifest, node_id, secret_key)
        .expect("recipient applies manifest");
    *ring.active_zone_key().expect("active zone key")
}

struct ZoneKeyMigrationFixture {
    zone_id: ZoneId,
    issued_at: u64,
    zone_key: ZoneKey,
    object_id_key: ObjectIdKey,
    alice_id: TailscaleNodeId,
    bob_id: TailscaleNodeId,
    alice_sk: X25519SecretKey,
    bob_sk: X25519SecretKey,
}

impl ZoneKeyMigrationFixture {
    fn new() -> Self {
        Self {
            zone_id: ZoneId::work(),
            issued_at: 1_700_000_123,
            zone_key: ZoneKey::from_bytes([0x42; ZONE_KEY_LEN]),
            object_id_key: ObjectIdKey::from_bytes([0x24; ZONE_KEY_LEN]),
            alice_id: TailscaleNodeId::new("node-alice-e2e"),
            bob_id: TailscaleNodeId::new("node-bob-e2e"),
            alice_sk: X25519SecretKey::generate(),
            bob_sk: X25519SecretKey::generate(),
        }
    }
}

fn assert_signed_connector_manifest_phase(phases: &mut Vec<&'static str>) {
    let span = span!(
        Level::INFO,
        "e2e_manifest_phase",
        crate_name = "fcp-manifest",
        phase = "signed_connector_manifest"
    );
    let _entered = span.enter();
    phases.push("signed_connector_manifest");
    let manifest = signed_connector_manifest();
    let signatures = manifest.signatures.expect("signature section");
    assert_eq!(signatures.publisher_signatures.len(), 1);
    assert_eq!(
        signatures.publisher_threshold.unwrap().to_string(),
        "1-of-1"
    );
}

fn construct_v3_manifest_phase(
    phases: &mut Vec<&'static str>,
    fixture: &ZoneKeyMigrationFixture,
) -> ZoneKeyManifest {
    let span = span!(
        Level::INFO,
        "e2e_manifest_phase",
        crate_name = "fcp-manifest",
        phase = "construct_v3"
    );
    let _entered = span.enter();
    phases.push("construct_v3");
    ZoneKeyManifest {
        header: test_header(&fixture.zone_id),
        zone_id: fixture.zone_id.clone(),
        zone_key_id: ZoneKeyId::from_bytes([0x11; 8]),
        object_id_key_id: ObjectIdKeyId::from_bytes([0x22; 8]),
        algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
        valid_from: fixture.issued_at,
        valid_until: None,
        prev_zone_key_id: None,
        wrapped_keys: vec![
            wrap_zone_key(
                &fixture.alice_sk.public_key(),
                &fixture.zone_id,
                &fixture.alice_id,
                fixture.issued_at,
                &fixture.zone_key,
            )
            .expect("alice v3 zone wrap"),
            wrap_zone_key(
                &fixture.bob_sk.public_key(),
                &fixture.zone_id,
                &fixture.bob_id,
                fixture.issued_at,
                &fixture.zone_key,
            )
            .expect("bob v3 zone wrap"),
        ],
        wrapped_object_id_keys: vec![
            wrap_object_id_key(
                &fixture.alice_sk.public_key(),
                &fixture.zone_id,
                &fixture.alice_id,
                fixture.issued_at,
                &fixture.object_id_key,
            )
            .expect("alice object-id wrap"),
            wrap_object_id_key(
                &fixture.bob_sk.public_key(),
                &fixture.zone_id,
                &fixture.bob_id,
                fixture.issued_at,
                &fixture.object_id_key,
            )
            .expect("bob object-id wrap"),
        ],
        rekey_policy: None,
        signature: test_signature(),
        kem: ZoneKemAlgorithm::HpkeX25519,
        wrapped_keys_v4: Vec::new(),
    }
}

fn migrate_v4_phase(
    phases: &mut Vec<&'static str>,
    v3_manifest: &ZoneKeyManifest,
) -> ZoneKeyManifest {
    let span = span!(
        Level::INFO,
        "e2e_manifest_phase",
        crate_name = "fcp-manifest",
        phase = "migrate_v4"
    );
    let _entered = span.enter();
    phases.push("migrate_v4");
    let unsigned = v3_manifest.migrated_to_v4(ZoneKemAlgorithm::XWing);
    let payload = unsigned.as_payload();
    assert_eq!(payload.kem, ZoneKemAlgorithm::XWing);
    assert_eq!(payload.wrapped_keys_v4.len(), payload.wrapped_keys.len());
    for v3 in &payload.wrapped_keys {
        let v4 = payload
            .wrapped_key_v4_for(&v3.recipient)
            .expect("promoted v4 wrap");
        assert_eq!(v4.sealed.kem(), ZoneKemAlgorithm::HpkeX25519);
        let sealed = v4
            .sealed
            .hpke_sealed()
            .expect("safe migration promotes V3 HPKE bytes");
        assert_eq!(sealed.enc, v3.sealed.enc);
        assert_eq!(sealed.ciphertext, v3.sealed.ciphertext);
    }
    unsigned.sign(test_signature())
}

fn assert_cross_recipient_phase(
    phases: &mut Vec<&'static str>,
    migrated: &ZoneKeyManifest,
    fixture: &ZoneKeyMigrationFixture,
) {
    let span = span!(
        Level::INFO,
        "e2e_manifest_phase",
        crate_name = "fcp-manifest",
        phase = "cross_recipient_verify"
    );
    let _entered = span.enter();
    phases.push("cross_recipient_verify");
    migrated
        .validate_no_recipient_split_view()
        .expect("promoted V4 wraps are split-view safe");
    let alice_key = apply_for_recipient(migrated, &fixture.alice_id, &fixture.alice_sk);
    let bob_key = apply_for_recipient(migrated, &fixture.bob_id, &fixture.bob_sk);
    assert_eq!(alice_key.as_bytes(), fixture.zone_key.as_bytes());
    assert_eq!(bob_key.as_bytes(), fixture.zone_key.as_bytes());
    assert_eq!(alice_key, bob_key);
}

#[test]
fn e2e_signed_manifest_v3_v4_migration_preserves_recipient_zone_key() {
    let mut phases = Vec::new();
    let fixture = ZoneKeyMigrationFixture::new();

    assert_signed_connector_manifest_phase(&mut phases);
    let v3_manifest = construct_v3_manifest_phase(&mut phases, &fixture);
    let migrated = migrate_v4_phase(&mut phases, &v3_manifest);
    assert_cross_recipient_phase(&mut phases, &migrated, &fixture);

    assert_eq!(
        phases,
        [
            "signed_connector_manifest",
            "construct_v3",
            "migrate_v4",
            "cross_recipient_verify"
        ]
    );
}
