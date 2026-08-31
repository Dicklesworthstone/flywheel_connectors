use chrono::Utc;
use fcp_cbor::SchemaId;
use fcp_crypto::{Ed25519SigningKey, X25519SecretKey};
use fcp_prelude::{
    DeviceEnrollmentApproval, DeviceEnrollmentRequest, DeviceMetadata, NodeSignature, ObjectHeader,
    ObjectIdKey, ObjectIdKeyId, Provenance, RevocationObject, RevocationRegistry, RevocationScope,
    StoredObject, ZoneId, ZoneKemAlgorithm, ZoneKeyAlgorithm, ZoneKeyId, ZoneKeyManifest,
};
use fcp_tailscale::{MeshIdentity, NodeId, NodeKeyAttestation, NodeKeys};
use semver::Version;

fn now_ts_u64() -> u64 {
    Utc::now().timestamp().try_into().unwrap_or(0)
}

fn create_test_keys() -> (
    Ed25519SigningKey,
    fcp_crypto::Ed25519VerifyingKey,
    fcp_crypto::X25519PublicKey,
    fcp_crypto::Ed25519VerifyingKey,
    NodeKeys,
) {
    let signing_key = Ed25519SigningKey::generate();
    let encryption_key = X25519SecretKey::generate();
    let issuance_key = Ed25519SigningKey::generate();

    let node_keys = NodeKeys::new(
        signing_key.verifying_key(),
        encryption_key.public_key(),
        issuance_key.verifying_key(),
    );

    (
        signing_key.clone(),
        signing_key.verifying_key(),
        encryption_key.public_key(),
        issuance_key.verifying_key(),
        node_keys,
    )
}

fn create_header(zone_id: ZoneId, schema: SchemaId) -> ObjectHeader {
    ObjectHeader {
        encryption_kind: Default::default(),
        schema,
        zone_id: zone_id.clone(),
        created_at: now_ts_u64(),
        provenance: Provenance::new(zone_id),
        refs: vec![],
        foreign_refs: vec![],
        ttl_secs: None,
        placement: None,
    }
}

fn create_empty_manifest(
    zone_id: ZoneId,
    valid_from: u64,
    _owner_key: &Ed25519SigningKey,
) -> ZoneKeyManifest {
    let signature = NodeSignature::new(
        fcp_core::NodeId::new("owner"), // fcp-core NodeId, not Tailscale NodeId
        [0u8; 64],
        valid_from,
    );

    ZoneKeyManifest {
        header: create_header(
            zone_id.clone(),
            SchemaId::new("fcp.zone", "ZoneKeyManifest", Version::new(1, 0, 0)),
        ),
        zone_id,
        zone_key_id: ZoneKeyId::from_bytes([0u8; 8]),
        object_id_key_id: ObjectIdKeyId::from_bytes([0u8; 8]),
        algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
        valid_from,
        valid_until: None,
        prev_zone_key_id: None,
        wrapped_keys: vec![],
        wrapped_object_id_keys: vec![],
        rekey_policy: None,
        signature,
        kem: ZoneKemAlgorithm::HpkeX25519,
        wrapped_keys_v4: vec![],
    }
}

#[test]
fn test_enrollment_lifecycle_with_revocation() {
    // 1. Setup Keys and Zone
    let zone_id = ZoneId::work();
    let object_id_key = ObjectIdKey::from_bytes([0x42; 32]);
    let owner_key = Ed25519SigningKey::generate();

    let (device_signing_secret, device_signing_pub, device_enc_pub, device_issuance_pub, node_keys) =
        create_test_keys();
    let device_id = NodeId::new("node-test-123");

    // 2. Create DeviceEnrollmentRequest
    let request = DeviceEnrollmentRequest::new(
        device_id.to_string(),
        device_signing_pub,
        device_enc_pub,
        device_issuance_pub,
        DeviceMetadata::default(),
        &device_signing_secret,
    )
    .expect("Failed to create enrollment request");

    // 3. Owner Approves Request
    let initial_manifest = create_empty_manifest(zone_id.clone(), now_ts_u64(), &owner_key);
    let approval_header_zone_id = zone_id.clone();
    let attestation_header_zone_id = zone_id.clone();
    let revocation_header_zone_id = zone_id.clone();
    let approval = DeviceEnrollmentApproval::sign(
        &owner_key,
        &request,
        zone_id,
        vec!["tag:fcp-work".to_string()],
        initial_manifest,
        24,
    )
    .expect("Failed to sign approval");

    // 4. Store Approval as Mesh Object to get ObjectId
    let approval_schema = SchemaId::new(
        "fcp.core",
        "DeviceEnrollmentApproval",
        Version::new(1, 0, 0),
    );
    let approval_header = create_header(approval_header_zone_id, approval_schema);
    let approval_body =
        fcp_cbor::to_canonical_cbor(&approval).expect("Failed to serialize approval");

    let approval_id = StoredObject::derive_id(&approval_header, &approval_body, &object_id_key)
        .expect("Failed to derive approval ID");

    // 5. Create NodeKeyAttestation (The "Passport")
    let attestation = NodeKeyAttestation::sign(
        &owner_key,
        &device_id,
        &node_keys,
        &[], // no tags for now
        24,
    )
    .expect("Failed to sign attestation");

    // 6. Store Attestation as Mesh Object
    let attestation_schema =
        SchemaId::new("fcp.tailscale", "NodeKeyAttestation", Version::new(1, 0, 0));
    let attestation_header = create_header(attestation_header_zone_id, attestation_schema);
    let attestation_body =
        fcp_cbor::to_canonical_cbor(&attestation).expect("Failed to serialize attestation");

    let attestation_id =
        StoredObject::derive_id(&attestation_header, &attestation_body, &object_id_key)
            .expect("Failed to derive attestation ID");

    // 7. Initialize Revocation Registry
    let mut registry = RevocationRegistry::new();

    // Verify not revoked yet
    assert!(!registry.is_revoked(&approval_id));
    assert!(!registry.is_revoked(&attestation_id));

    // 8. Revoke the Attestation
    let revocation = RevocationObject {
        header: create_header(
            revocation_header_zone_id,
            SchemaId::new("fcp.core", "RevocationObject", Version::new(1, 0, 0)),
        ),
        revoked: vec![attestation_id],
        scope: RevocationScope::NodeAttestation,
        reason: "Device compromised".to_string(),
        effective_at: now_ts_u64(),
        expires_at: None,
        signature: [0u8; 64],
    };

    registry.add_revocation(&revocation);

    // 9. Verify Revocation
    assert!(
        registry.is_revoked(&attestation_id),
        "Attestation should be revoked"
    );
    assert!(
        !registry.is_revoked(&approval_id),
        "Approval should NOT be revoked (different ID)"
    );

    // 10. Verify Removal Workflow Implications
    // We verify the attestation signature first
    let identity = MeshIdentity::new(
        device_id,
        "test-host".to_string(),
        vec![],
        vec![],
        owner_key.verifying_key(),
        node_keys,
    )
    .with_attestation(attestation);

    assert!(identity.verify_attestation().is_ok());

    // Then we check revocation against the registry
    let attestation_ok = identity.verify_attestation().is_ok();
    let is_valid = attestation_ok && !registry.is_revoked(&attestation_id);

    assert!(
        !is_valid,
        "Identity should be invalid because attestation is revoked"
    );
}
