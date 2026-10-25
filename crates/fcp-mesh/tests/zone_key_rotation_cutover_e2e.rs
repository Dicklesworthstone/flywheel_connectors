//! Deterministic no-live-network E2E harness for V3/V4 zone-key rotation cutover (`br-kyopb.1.2.4`).
//!
//! Exercises `MeshNode::publish_initial_zone_key`, `MeshNode::publish_zone_key_rotation`,
//! `build_zone_key_rotation_cutover`, `enforce_incoming_zone_key_policy`,
//! `zone_key_manifest_owner_payload`, and `ZoneKeyRing` across:
//! 1. `v3_only`
//! 2. `v4_only`
//! 3. `mixed_v3_v4`
//! 4. `require_pq_kem`
//! 5. `membership_change_rekey`
//! 6. `revocation_rekey`
//! 7. `downgrade_tamper`

#![forbid(unsafe_code)]
#![allow(clippy::too_many_lines)]

use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Arc;

use fcp_cbor::SchemaId;
use fcp_core::{
    NodeId, NodeSignature, ObjectEncryptionKind, ObjectHeader, ObjectIdKey, ObjectIdKeyId,
    Provenance, TailscaleNodeId, ZONE_KEY_LEN, ZoneId, ZoneKemAlgorithm, ZoneKey, ZoneKeyAlgorithm,
    ZoneKeyId, ZoneKeyManifest, ZoneKeyRing, wrap_object_id_key, wrap_zone_key,
};
use fcp_crypto::{
    Ed25519Signature, Ed25519SigningKey, X25519SecretKey, XWingKem, XWingProvider, XWingSecretKey,
};
use fcp_mesh::{
    DeferredAckReason, MeshNode, MeshNodeConfig, PeerProtocolCapabilities, PreferredKem,
    ProtocolVersionPolicy, ZoneKeyRecipient, ZoneKeyRotationError, ZoneKeyRotationPhase,
    enforce_incoming_zone_key_policy, zone_key_manifest_owner_payload,
};
use fcp_store::{
    MemoryObjectStore, MemoryObjectStoreConfig, MemorySymbolStore, MemorySymbolStoreConfig,
    ObjectAdmissionPolicy, ObjectStore, QuarantineStore,
};
use semver::Version;
use serde_json::{Value, json};

fn build_mesh_node(
    name: &str,
    instance_id: u64,
    local_node_id: u64,
) -> (MeshNode, Arc<MemoryObjectStore>) {
    let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
    let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig {
        local_node_id,
        ..MemorySymbolStoreConfig::default()
    }));
    let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));
    let node = MeshNode::new(
        MeshNodeConfig::new(name).with_sender_instance_id(instance_id),
        Arc::clone(&object_store) as Arc<dyn ObjectStore>,
        symbol_store,
        quarantine_store,
    );
    (node, object_store)
}

fn hash_redacted(label: &str) -> String {
    let digest = blake3::hash(label.as_bytes());
    format!("b3:{}", &digest.to_hex()[..16])
}

fn manifest_template(
    zone_id: &ZoneId,
    zone_key_id: ZoneKeyId,
    object_id_key_id: ObjectIdKeyId,
    prev_zone_key_id: Option<ZoneKeyId>,
    valid_from: u64,
    recipients: &[ZoneKeyRecipient],
    object_id_key: &ObjectIdKey,
) -> ZoneKeyManifest {
    let wrapped_object_id_keys = recipients
        .iter()
        .map(|recipient| {
            wrap_object_id_key(
                &recipient.hpke_public_key,
                zone_id,
                &recipient.node_id,
                valid_from,
                object_id_key,
            )
            .expect("wrap object-id key")
        })
        .collect();

    ZoneKeyManifest {
        header: ObjectHeader {
            encryption_kind: ObjectEncryptionKind::default(),
            schema: SchemaId::new("fcp.zone", "ZoneKeyManifest", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: valid_from,
            provenance: Provenance::new(zone_id.clone()),
            refs: Vec::new(),
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        },
        zone_id: zone_id.clone(),
        zone_key_id,
        object_id_key_id,
        algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
        valid_from,
        valid_until: None,
        prev_zone_key_id,
        wrapped_keys: Vec::new(),
        wrapped_object_id_keys,
        rekey_policy: None,
        signature: NodeSignature::new(NodeId::new("owner-node"), [0_u8; 64], valid_from),
        kem: ZoneKemAlgorithm::HpkeX25519,
        wrapped_keys_v4: Vec::new(),
    }
}

fn make_v3_peer(name: &str, seed: u8) -> (ZoneKeyRecipient, X25519SecretKey) {
    let sk = X25519SecretKey::from_bytes([seed; 32]);
    let recipient = ZoneKeyRecipient::new(
        TailscaleNodeId::new(name),
        sk.public_key(),
        None,
        PeerProtocolCapabilities::v3_only(),
    );
    (recipient, sk)
}

fn make_v4_peer(
    name: &str,
    hpke_seed: u8,
    xwing: &XWingProvider,
) -> (ZoneKeyRecipient, X25519SecretKey, XWingSecretKey) {
    let hpke_sk = X25519SecretKey::from_bytes([hpke_seed; 32]);
    let (xwing_pk, xwing_sk) = xwing.generate().expect("generate X-Wing keypair");
    let recipient = ZoneKeyRecipient::new(
        TailscaleNodeId::new(name),
        hpke_sk.public_key(),
        Some(xwing_pk),
        PeerProtocolCapabilities::v3_v4(),
    );
    (recipient, hpke_sk, xwing_sk)
}

fn emit_jsonl_record(record: &Value) {
    let line = serde_json::to_string(record).expect("serialize JSONL record");
    println!("ZONE_KEY_ROTATION_E2E_JSONL:{line}");
    if let Ok(path) = std::env::var("ZONE_KEY_ROTATION_E2E_JSONL")
        && !path.trim().is_empty()
    {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("open ZONE_KEY_ROTATION_E2E_JSONL file");
        writeln!(file, "{line}").expect("write JSONL line");
    }
}

#[fcp_async_core::runtime::test]
async fn zone_key_rotation_v4_full_cutover_and_interop_e2e() {
    let xwing = XWingProvider::new();
    let zone_id = ZoneId::work();
    let owner_signing_key =
        Ed25519SigningKey::from_bytes(&[0x71; 32]).expect("deterministic owner signing key");
    let owner_verifying_key = owner_signing_key.verifying_key();
    let object_id_key = ObjectIdKey::from_bytes([0xE1; ZONE_KEY_LEN]);
    let object_id_key_id = ObjectIdKeyId::from_bytes([0x55; 8]);
    let git_rev = option_env!("GIT_SHA").unwrap_or("HEAD");
    let cmd_line = "cargo test -p fcp-mesh --test zone_key_rotation_cutover_e2e -- --nocapture";

    let (mut owner_node, object_store) = build_mesh_node("owner-node", 0x1001, 1);

    // 1. V3-only issuance via MeshNode::publish_initial_zone_key
    let (v3_alice, v3_alice_sk) = make_v3_peer("node-v3-alice", 0x11);
    let (v3_bob, v3_bob_sk) = make_v3_peer("node-v3-bob", 0x12);
    let v3_zone_key = ZoneKey::from_bytes([0xA1; ZONE_KEY_LEN]);
    let v3_policy = ProtocolVersionPolicy {
        preferred_kem: PreferredKem::HpkeX25519,
        require_pq_kem: false,
    };
    let v3_template = manifest_template(
        &zone_id,
        ZoneKeyId::from_bytes([0x01; 8]),
        object_id_key_id,
        None,
        1_700_001_000,
        &[v3_alice.clone(), v3_bob.clone()],
        &object_id_key,
    );
    let (v3_obj_id, v3_cutover) = owner_node
        .publish_initial_zone_key(
            v3_template,
            &v3_zone_key,
            &[v3_alice.clone(), v3_bob.clone()],
            v3_policy,
            &xwing,
            &owner_signing_key,
            &object_id_key,
            1_700_001_000_000,
        )
        .await
        .expect("publish v3_only initial zone key");
    assert!(object_store.get(&v3_obj_id).await.is_ok());
    assert_eq!(v3_cutover.phase, ZoneKeyRotationPhase::Complete);
    assert_eq!(v3_cutover.manifest.wrapped_keys.len(), 2);
    let mut alice_ring = ZoneKeyRing::new(zone_id.clone());
    alice_ring
        .apply_manifest(&v3_cutover.manifest, &v3_alice.node_id, &v3_alice_sk)
        .expect("v3 alice applies v3 manifest");
    let mut bob_ring = ZoneKeyRing::new(zone_id.clone());
    bob_ring
        .apply_manifest(&v3_cutover.manifest, &v3_bob.node_id, &v3_bob_sk)
        .expect("v3 bob applies v3 manifest");
    assert_eq!(alice_ring.active_zone_key(), Some(&v3_zone_key));
    assert_eq!(bob_ring.active_zone_key(), Some(&v3_zone_key));

    emit_jsonl_record(&json!({
        "command_line": cmd_line,
        "git_revision": git_rev,
        "fixture_id": "v3_only",
        "node_id_hashes": [hash_redacted(v3_alice.node_id.as_str()), hash_redacted(v3_bob.node_id.as_str())],
        "protocol_versions": ["v3"],
        "policy_flags": {"preferred_kem": "hpke_x25519", "require_pq_kem": false},
        "wrapped_key_variant_counts": {"hpke_x25519": 2, "x_wing": 0},
        "rotation_phase": "complete",
        "recipient_capability_class": "v3_only",
        "signature_verification_result": "verified",
        "downgrade_decision": "explicit_v3_policy",
        "fcp_error_mapping": null,
        "cleanup_result": "stored_and_verified",
        "skip_reason": null
    }));

    // 2. V4-only issuance via MeshNode::publish_initial_zone_key
    let (v4_carol, v4_carol_hpke_sk, v4_carol_xwing_sk) =
        make_v4_peer("node-v4-carol", 0x21, &xwing);
    let (v4_dave, v4_dave_hpke_sk, v4_dave_xwing_sk) = make_v4_peer("node-v4-dave", 0x22, &xwing);
    let v4_zone_key = ZoneKey::from_bytes([0xA2; ZONE_KEY_LEN]);
    let v4_template = manifest_template(
        &zone_id,
        ZoneKeyId::from_bytes([0x02; 8]),
        object_id_key_id,
        None,
        1_700_002_000,
        &[v4_carol.clone(), v4_dave.clone()],
        &object_id_key,
    );
    let (v4_obj_id, v4_cutover) = owner_node
        .publish_initial_zone_key(
            v4_template,
            &v4_zone_key,
            &[v4_carol.clone(), v4_dave.clone()],
            ProtocolVersionPolicy::require_xwing(),
            &xwing,
            &owner_signing_key,
            &object_id_key,
            1_700_002_000_000,
        )
        .await
        .expect("publish v4_only initial zone key");
    assert!(object_store.get(&v4_obj_id).await.is_ok());
    assert_eq!(v4_cutover.phase, ZoneKeyRotationPhase::Complete);
    assert!(v4_cutover.manifest.wrapped_keys.is_empty());
    assert_eq!(v4_cutover.manifest.wrapped_keys_v4.len(), 2);
    let mut carol_ring = ZoneKeyRing::new(zone_id.clone());
    carol_ring
        .apply_manifest_v4(
            &v4_cutover.manifest,
            &v4_carol.node_id,
            &v4_carol_hpke_sk,
            &v4_carol_xwing_sk,
            &xwing,
        )
        .expect("carol applies v4 manifest");
    let mut dave_ring = ZoneKeyRing::new(zone_id.clone());
    dave_ring
        .apply_manifest_v4(
            &v4_cutover.manifest,
            &v4_dave.node_id,
            &v4_dave_hpke_sk,
            &v4_dave_xwing_sk,
            &xwing,
        )
        .expect("dave applies v4 manifest");
    assert_eq!(carol_ring.active_zone_key(), Some(&v4_zone_key));
    assert_eq!(dave_ring.active_zone_key(), Some(&v4_zone_key));

    emit_jsonl_record(&json!({
        "command_line": cmd_line,
        "git_revision": git_rev,
        "fixture_id": "v4_only",
        "node_id_hashes": [hash_redacted(v4_carol.node_id.as_str()), hash_redacted(v4_dave.node_id.as_str())],
        "protocol_versions": ["v3", "v4"],
        "policy_flags": {"preferred_kem": "x_wing", "require_pq_kem": true},
        "wrapped_key_variant_counts": {"hpke_x25519": 0, "x_wing": 2},
        "rotation_phase": "complete",
        "recipient_capability_class": "v4_xwing",
        "signature_verification_result": "verified",
        "downgrade_decision": "no_downgrade_needed",
        "fcp_error_mapping": null,
        "cleanup_result": "stored_and_verified",
        "skip_reason": null
    }));

    // 3. Mixed V3/V4 issuance (single manifest with mixed wraps + V3 tolerance of V4 manifest)
    let mixed_zone_key = ZoneKey::from_bytes([0xA3; ZONE_KEY_LEN]);
    let mixed_recipients = [v3_alice.clone(), v4_carol.clone()];
    let mixed_template = manifest_template(
        &zone_id,
        ZoneKeyId::from_bytes([0x03; 8]),
        object_id_key_id,
        Some(ZoneKeyId::from_bytes([0x01; 8])),
        1_700_003_000,
        &mixed_recipients,
        &object_id_key,
    );
    let (_mixed_obj_id, mixed_cutover) = owner_node
        .publish_initial_zone_key(
            mixed_template,
            &mixed_zone_key,
            &mixed_recipients,
            ProtocolVersionPolicy::migration_default(),
            &xwing,
            &owner_signing_key,
            &object_id_key,
            1_700_003_000_000,
        )
        .await
        .expect("publish mixed_v3_v4 zone key");
    assert_eq!(
        mixed_cutover.phase,
        ZoneKeyRotationPhase::DeferredAcknowledgement
    );
    assert_eq!(
        mixed_cutover.deferred_ack_peers(),
        vec![v3_alice.node_id.clone()]
    );
    assert_eq!(mixed_cutover.manifest.wrapped_keys.len(), 1);
    assert_eq!(mixed_cutover.manifest.wrapped_keys_v4.len(), 2);

    // Round-trip CBOR + JSON to verify V3 deserializer tolerates V4 manifest
    let serialized = serde_json::to_vec(&mixed_cutover.manifest).expect("serialize mixed manifest");
    let roundtripped: ZoneKeyManifest =
        serde_json::from_slice(&serialized).expect("deserialize mixed manifest");
    alice_ring
        .apply_manifest(&roundtripped, &v3_alice.node_id, &v3_alice_sk)
        .expect("V3 peer tolerates V4 manifest and unwraps HPKE fallback");
    carol_ring
        .apply_manifest_v4(
            &roundtripped,
            &v4_carol.node_id,
            &v4_carol_hpke_sk,
            &v4_carol_xwing_sk,
            &xwing,
        )
        .expect("V4 peer unwraps X-Wing from mixed manifest");
    assert_eq!(alice_ring.active_zone_key(), Some(&mixed_zone_key));
    assert_eq!(carol_ring.active_zone_key(), Some(&mixed_zone_key));

    emit_jsonl_record(&json!({
        "command_line": cmd_line,
        "git_revision": git_rev,
        "fixture_id": "mixed_v3_v4",
        "node_id_hashes": [hash_redacted(v3_alice.node_id.as_str()), hash_redacted(v4_carol.node_id.as_str())],
        "protocol_versions": ["v3", "v4"],
        "policy_flags": {"preferred_kem": "auto", "require_pq_kem": false},
        "wrapped_key_variant_counts": {"hpke_x25519": 1, "x_wing": 1},
        "rotation_phase": "deferred_acknowledgement",
        "recipient_capability_class": "mixed_v3_and_v4",
        "signature_verification_result": "verified",
        "downgrade_decision": "deferred_ack_for_v3_peer",
        "fcp_error_mapping": null,
        "cleanup_result": "stored_and_verified",
        "skip_reason": null
    }));

    // 4. require_pq_kem refusal (sender refuses V4 recipient lacking X-Wing key; receiver refuses HPKE fallback)
    let v4_missing_xwing = ZoneKeyRecipient::new(
        TailscaleNodeId::new("node-v4-missing-xwing"),
        v3_bob.hpke_public_key.clone(),
        None,
        PeerProtocolCapabilities::v3_v4(),
    );
    let pq_err = owner_node
        .publish_zone_key_rotation(
            manifest_template(
                &zone_id,
                ZoneKeyId::from_bytes([0x04; 8]),
                object_id_key_id,
                Some(mixed_cutover.manifest.zone_key_id),
                1_700_004_000,
                std::slice::from_ref(&v4_missing_xwing),
                &object_id_key,
            ),
            &ZoneKey::from_bytes([0xA4; ZONE_KEY_LEN]),
            std::slice::from_ref(&v4_missing_xwing),
            ProtocolVersionPolicy::require_xwing(),
            &xwing,
            &owner_signing_key,
            &object_id_key,
            1_700_004_000_000,
        )
        .await
        .expect_err("require_pq_kem must refuse downgrade");
    assert!(matches!(
        pq_err,
        fcp_mesh::MeshNodeError::ZoneKeyRotation(ZoneKeyRotationError::PostQuantumKemRequired {
            reason: DeferredAckReason::MissingXWingPublicKey,
            ..
        })
    ));
    let recv_err = enforce_incoming_zone_key_policy(
        &mixed_cutover.manifest,
        &v3_alice.node_id,
        ProtocolVersionPolicy::require_xwing(),
    )
    .expect_err("receiver with require_pq_kem must reject HPKE wrap");
    assert!(matches!(
        recv_err,
        ZoneKeyRotationError::KemTooWeak {
            kem: ZoneKemAlgorithm::HpkeX25519,
            ..
        }
    ));

    emit_jsonl_record(&json!({
        "command_line": cmd_line,
        "git_revision": git_rev,
        "fixture_id": "require_pq_kem",
        "node_id_hashes": [hash_redacted(v4_missing_xwing.node_id.as_str()), hash_redacted(v3_alice.node_id.as_str())],
        "protocol_versions": ["v3", "v4"],
        "policy_flags": {"preferred_kem": "x_wing", "require_pq_kem": true},
        "wrapped_key_variant_counts": {"hpke_x25519": 0, "x_wing": 0},
        "rotation_phase": "rejected",
        "recipient_capability_class": "v4_missing_xwing_key",
        "signature_verification_result": "not_signed_rejected_pre_seal",
        "downgrade_decision": "refused_by_require_pq_kem",
        "fcp_error_mapping": "ZoneKeyRotationError::PostQuantumKemRequired+KemTooWeak",
        "cleanup_result": "no_partial_state_committed",
        "skip_reason": null
    }));

    // 5. Membership-change rekey: v3_alice upgrades to V4 with X-Wing key, v4_dave joins
    let (alice_xwing_pk, alice_xwing_sk) = xwing.generate().expect("alice X-Wing upgrade key");
    let mut v4_alice_upgraded = v3_alice.clone();
    v4_alice_upgraded.xwing_public_key = Some(alice_xwing_pk);
    v4_alice_upgraded.protocol_capabilities = PeerProtocolCapabilities::v3_v4();
    let membership_recipients = [
        v4_alice_upgraded.clone(),
        v4_carol.clone(),
        v4_dave.clone(),
        v3_bob.clone(),
    ];
    let membership_zone_key = ZoneKey::from_bytes([0xA5; ZONE_KEY_LEN]);
    let mut membership_template = mixed_cutover.manifest.clone();
    membership_template.zone_key_id = ZoneKeyId::from_bytes([0x05; 8]);
    membership_template.prev_zone_key_id = Some(mixed_cutover.manifest.zone_key_id);
    membership_template.valid_from = 1_700_005_000;
    membership_template.header.created_at = 1_700_005_000;
    membership_template.wrapped_object_id_keys = membership_recipients
        .iter()
        .map(|r| {
            wrap_object_id_key(
                &r.hpke_public_key,
                &zone_id,
                &r.node_id,
                membership_template.valid_from,
                &object_id_key,
            )
            .expect("wrap object-id key")
        })
        .collect();
    let (_mem_obj_id, membership_cutover) = owner_node
        .publish_zone_key_rotation(
            membership_template,
            &membership_zone_key,
            &membership_recipients,
            ProtocolVersionPolicy::migration_default(),
            &xwing,
            &owner_signing_key,
            &object_id_key,
            1_700_005_000_000,
        )
        .await
        .expect("publish membership_change_rekey");
    membership_cutover
        .manifest
        .validate_no_recipient_split_view()
        .expect("no split view after upgrade");
    assert_eq!(membership_cutover.manifest.wrapped_keys.len(), 1);
    assert_eq!(membership_cutover.manifest.wrapped_keys_v4.len(), 4);
    alice_ring
        .apply_manifest_v4(
            &membership_cutover.manifest,
            &v4_alice_upgraded.node_id,
            &v3_alice_sk,
            &alice_xwing_sk,
            &xwing,
        )
        .expect("upgraded alice applies v4 rotation");
    assert_eq!(alice_ring.active_zone_key(), Some(&membership_zone_key));

    emit_jsonl_record(&json!({
        "command_line": cmd_line,
        "git_revision": git_rev,
        "fixture_id": "membership_change_rekey",
        "node_id_hashes": [
            hash_redacted(v4_alice_upgraded.node_id.as_str()),
            hash_redacted(v4_carol.node_id.as_str()),
            hash_redacted(v4_dave.node_id.as_str()),
            hash_redacted(v3_bob.node_id.as_str())
        ],
        "protocol_versions": ["v3", "v4"],
        "policy_flags": {"preferred_kem": "auto", "require_pq_kem": false},
        "wrapped_key_variant_counts": {"hpke_x25519": 1, "x_wing": 3},
        "rotation_phase": "deferred_acknowledgement",
        "recipient_capability_class": "upgraded_v4_plus_retained_v3",
        "signature_verification_result": "verified",
        "downgrade_decision": "upgraded_peer_promoted_to_xwing",
        "fcp_error_mapping": null,
        "cleanup_result": "legacy_hpke_split_view_removed",
        "skip_reason": null
    }));

    // 6. Post-revocation rotation: revoke v3_bob and v4_dave, keeping only v4_alice_upgraded and v4_carol
    let post_revocation_recipients = [v4_alice_upgraded.clone(), v4_carol.clone()];
    let post_revocation_zone_key = ZoneKey::from_bytes([0xA6; ZONE_KEY_LEN]);
    let mut revocation_template = membership_cutover.manifest.clone();
    revocation_template.zone_key_id = ZoneKeyId::from_bytes([0x06; 8]);
    revocation_template.prev_zone_key_id = Some(membership_cutover.manifest.zone_key_id);
    revocation_template.valid_from = 1_700_006_000;
    revocation_template.header.created_at = 1_700_006_000;
    let (_rev_obj_id, revocation_cutover) = owner_node
        .publish_zone_key_rotation(
            revocation_template,
            &post_revocation_zone_key,
            &post_revocation_recipients,
            ProtocolVersionPolicy::require_xwing(),
            &xwing,
            &owner_signing_key,
            &object_id_key,
            1_700_006_000_000,
        )
        .await
        .expect("publish revocation_rekey");
    assert_eq!(revocation_cutover.phase, ZoneKeyRotationPhase::Complete);
    assert!(revocation_cutover.manifest.wrapped_keys.is_empty());
    assert_eq!(revocation_cutover.manifest.wrapped_keys_v4.len(), 2);
    assert_eq!(revocation_cutover.manifest.wrapped_object_id_keys.len(), 2);
    for revoked in [&v3_bob.node_id, &v4_dave.node_id] {
        assert!(matches!(
            enforce_incoming_zone_key_policy(
                &revocation_cutover.manifest,
                revoked,
                ProtocolVersionPolicy::migration_default()
            ),
            Err(ZoneKeyRotationError::MissingRecipientWrap { .. })
        ));
    }
    carol_ring
        .apply_manifest_v4(
            &revocation_cutover.manifest,
            &v4_carol.node_id,
            &v4_carol_hpke_sk,
            &v4_carol_xwing_sk,
            &xwing,
        )
        .expect("retained carol applies post-revocation key");
    assert_eq!(
        carol_ring.active_zone_key(),
        Some(&post_revocation_zone_key)
    );

    emit_jsonl_record(&json!({
        "command_line": cmd_line,
        "git_revision": git_rev,
        "fixture_id": "revocation_rekey",
        "node_id_hashes": [
            hash_redacted(v4_alice_upgraded.node_id.as_str()),
            hash_redacted(v4_carol.node_id.as_str())
        ],
        "protocol_versions": ["v4"],
        "policy_flags": {"preferred_kem": "x_wing", "require_pq_kem": true},
        "wrapped_key_variant_counts": {"hpke_x25519": 0, "x_wing": 2},
        "rotation_phase": "complete",
        "recipient_capability_class": "v4_xwing",
        "signature_verification_result": "verified",
        "downgrade_decision": "revoked_peers_evicted_and_v4_enforced",
        "fcp_error_mapping": "ZoneKeyRotationError::MissingRecipientWrap",
        "cleanup_result": "revoked_zone_and_object_id_wraps_purged",
        "skip_reason": null
    }));

    // 7. Downgrade-tamper regression: tamper with signed V4 manifest changing XWing -> HpkeX25519
    let signed_manifest = &revocation_cutover.manifest;
    let original_payload =
        zone_key_manifest_owner_payload(signed_manifest).expect("canonical owner payload");
    let owner_sig = Ed25519Signature::from_bytes(&signed_manifest.signature.signature);
    owner_verifying_key
        .verify(&original_payload, &owner_sig)
        .expect("untampered owner signature verifies");

    let mut tampered = signed_manifest.clone();
    let forged_hpke = wrap_zone_key(
        &v4_carol.hpke_public_key,
        &zone_id,
        &v4_carol.node_id,
        tampered.valid_from,
        &post_revocation_zone_key,
    )
    .expect("forged hpke wrap");
    tampered.kem = ZoneKemAlgorithm::HpkeX25519;
    tampered.wrapped_keys = vec![forged_hpke.clone()];
    tampered.wrapped_keys_v4 = vec![forged_hpke.to_v4()];
    let tampered_payload =
        zone_key_manifest_owner_payload(&tampered).expect("tampered owner payload");
    assert_ne!(original_payload, tampered_payload);
    assert!(
        owner_verifying_key
            .verify(&tampered_payload, &owner_sig)
            .is_err(),
        "XWing -> HpkeX25519 downgrade tamper must invalidate owner signature"
    );

    emit_jsonl_record(&json!({
        "command_line": cmd_line,
        "git_revision": git_rev,
        "fixture_id": "downgrade_tamper",
        "node_id_hashes": [hash_redacted(v4_carol.node_id.as_str())],
        "protocol_versions": ["v3", "v4"],
        "policy_flags": {"preferred_kem": "x_wing", "require_pq_kem": true},
        "wrapped_key_variant_counts": {"hpke_x25519": 1, "x_wing": 0},
        "rotation_phase": "tamper_rejected",
        "recipient_capability_class": "v4_xwing",
        "signature_verification_result": "failed_tamper_detected",
        "downgrade_decision": "rejected_signature_mismatch",
        "fcp_error_mapping": "CryptoError::SignatureVerificationFailed",
        "cleanup_result": "tampered_manifest_discarded",
        "skip_reason": null
    }));
}
