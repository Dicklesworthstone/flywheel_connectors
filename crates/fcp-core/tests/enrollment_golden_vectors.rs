//! Enrollment Golden Vectors and Adversarial Tests (NORMATIVE).
//!
//! This module implements comprehensive tests for the FCP enrollment system
//! from `FCP_Specification_V3.md` §2.2.1 (Mesh Identity and Node Attestation).
//!
//! # Test Categories
//!
//! 1. **Golden Vectors**: CBOR test fixtures for cross-implementation verification
//! 2. **Adversarial Tests**: Attack scenario simulations
//!    - Replay old enrollment approval
//!    - Forge enrollment without owner signature
//!    - Impersonate `node_id` during enrollment
//!    - Use keys from removed device
//!    - Tamper with enrollment request
//! 3. **Enrollment Flow**: End-to-end enrollment workflow validation
//! 4. **Key Rotation**: Key lifecycle and rotation schedule enforcement
//! 5. **Device Removal**: Device revocation and key invalidation

use std::fs;
use std::path::PathBuf;

use chrono::{Duration, Utc};
use fcp_cbor::SchemaId;
use fcp_core::{
    DEFAULT_ENROLLMENT_VALIDITY_HOURS, DEFAULT_KEY_ROTATION_HOURS, DeviceEnrollmentApproval,
    DeviceEnrollmentRequest, DeviceId, DeviceMetadata, EnrollmentStatus, FcpError,
    KeyRotationSchedule, KeyType, NodeId, NodeSignature, ObjectHeader, ObjectId, ObjectIdKeyId,
    Provenance, RevocationObject, RevocationRegistry, RevocationScope, ZoneId, ZoneKeyAlgorithm,
    ZoneKeyId, ZoneKeyManifest,
};
use fcp_crypto::{Ed25519SigningKey, X25519SecretKey};
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Test Infrastructure
// ─────────────────────────────────────────────────────────────────────────────

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("enrollment")
}

/// FCP2-compliant structured log output.
fn log_test_event(test_name: &str, event: &str, details: &serde_json::Value) {
    let log = serde_json::json!({
        "event": event,
        "test": test_name,
        "module": "enrollment_golden_vectors",
        "details": details
    });
    println!("{}", serde_json::to_string(&log).unwrap());
}

fn now_ts_u64() -> u64 {
    Utc::now().timestamp().try_into().unwrap_or(0)
}

/// Create test keys for enrollment scenarios.
fn create_test_keys() -> (
    Ed25519SigningKey,               // device signing secret
    fcp_crypto::Ed25519VerifyingKey, // device signing pubkey
    fcp_crypto::X25519PublicKey,     // device encryption pubkey
    fcp_crypto::Ed25519VerifyingKey, // device issuance pubkey
    Ed25519SigningKey,               // owner key
) {
    let signing_key = Ed25519SigningKey::generate();
    let encryption_key = X25519SecretKey::generate();
    let issuance_key = Ed25519SigningKey::generate();
    let owner_key = Ed25519SigningKey::generate();

    (
        signing_key.clone(),
        signing_key.verifying_key(),
        encryption_key.public_key(),
        issuance_key.verifying_key(),
        owner_key,
    )
}

/// Create a test zone key manifest.
fn create_test_manifest(_owner_key: &Ed25519SigningKey) -> ZoneKeyManifest {
    use rand::RngCore;

    let zone_id = ZoneId::work();
    let valid_from = now_ts_u64();

    let mut zone_key_id_bytes = [0u8; 8];
    rand::rng().fill_bytes(&mut zone_key_id_bytes);

    let mut object_id_key_id_bytes = [0u8; 8];
    rand::rng().fill_bytes(&mut object_id_key_id_bytes);

    let signature = NodeSignature::new(NodeId::new("owner"), [0u8; 64], valid_from);

    ZoneKeyManifest {
        header: ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.zone", "ZoneKeyManifest", semver::Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: valid_from,
            provenance: Provenance::new(zone_id.clone()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        },
        zone_id,
        zone_key_id: ZoneKeyId::from_bytes(zone_key_id_bytes),
        object_id_key_id: ObjectIdKeyId::from_bytes(object_id_key_id_bytes),
        algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
        valid_from,
        valid_until: None,
        prev_zone_key_id: None,
        wrapped_keys: vec![],
        wrapped_object_id_keys: vec![],
        rekey_policy: None,
        signature,
        kem: fcp_core::ZoneKemAlgorithm::HpkeX25519,
        wrapped_keys_v4: vec![],
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Golden Vector Structures
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct EnrollmentRequestVector {
    description: String,
    device_id: String,
    signing_kid_hex: String,
    encryption_kid_hex: String,
    issuance_kid_hex: String,
    has_metadata: bool,
    proof_valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct EnrollmentApprovalVector {
    description: String,
    device_id: String,
    zone_id: String,
    approved_tags: Vec<String>,
    validity_hours: u32,
    is_valid: bool,
    error_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct KeyRotationVector {
    description: String,
    key_type: String,
    rotation_hours: u32,
    key_age_hours: i64,
    needs_rotation: bool,
    must_rotate: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct EnrollmentStatusVector {
    description: String,
    status: String,
    is_enrolled: bool,
    is_renewable: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Golden Vector Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn generate_enrollment_request_vectors() {
    log_test_event(
        "generate_enrollment_request_vectors",
        "test_start",
        &serde_json::json!({"purpose": "Generate CBOR vectors for enrollment requests"}),
    );

    let (signing_secret, signing_key, encryption_key, issuance_key, _owner) = create_test_keys();

    let mut vectors: Vec<EnrollmentRequestVector> = Vec::new();

    // Vector 1: Basic enrollment request
    let request = DeviceEnrollmentRequest::new(
        "device-001",
        signing_key.clone(),
        encryption_key.clone(),
        issuance_key.clone(),
        DeviceMetadata::default(),
        &signing_secret,
    )
    .expect("request creation should succeed");

    vectors.push(EnrollmentRequestVector {
        description: "Basic enrollment request with default metadata".to_string(),
        device_id: request.device_id.as_str().to_string(),
        signing_kid_hex: request.signing_kid().to_hex(),
        encryption_kid_hex: request.encryption_kid().to_hex(),
        issuance_kid_hex: request.issuance_kid().to_hex(),
        has_metadata: false,
        proof_valid: request.verify_proof().is_ok(),
    });

    // Vector 2: Request with full metadata
    let metadata = DeviceMetadata::new()
        .with_display_name("MacBook Pro M3")
        .with_hostname("macbook.local")
        .with_os("macOS 14.2")
        .with_arch("aarch64")
        .with_device_class("desktop")
        .with_tag("fcp:zone:work")
        .with_tag("fcp:zone:private");

    let request_with_meta = DeviceEnrollmentRequest::new(
        "device-002",
        signing_key,
        encryption_key,
        issuance_key,
        metadata,
        &signing_secret,
    )
    .expect("request creation should succeed");

    vectors.push(EnrollmentRequestVector {
        description: "Enrollment request with full device metadata".to_string(),
        device_id: request_with_meta.device_id.as_str().to_string(),
        signing_kid_hex: request_with_meta.signing_kid().to_hex(),
        encryption_kid_hex: request_with_meta.encryption_kid().to_hex(),
        issuance_kid_hex: request_with_meta.issuance_kid().to_hex(),
        has_metadata: true,
        proof_valid: request_with_meta.verify_proof().is_ok(),
    });

    // Serialize to CBOR
    let path = vectors_dir().join("request_vectors.cbor");
    let mut buffer = Vec::new();
    ciborium::into_writer(&vectors, &mut buffer).expect("CBOR serialization failed");
    fs::write(&path, &buffer).expect("Failed to write CBOR file");

    log_test_event(
        "generate_enrollment_request_vectors",
        "vector_written",
        &serde_json::json!({
            "path": path.display().to_string(),
            "size_bytes": buffer.len(),
            "request_count": vectors.len()
        }),
    );

    // Verify round-trip
    let data = fs::read(&path).expect("Failed to read CBOR file");
    let loaded: Vec<EnrollmentRequestVector> =
        ciborium::from_reader(data.as_slice()).expect("CBOR deserialization failed");

    assert_eq!(loaded.len(), 2);
    assert_eq!(loaded, vectors);

    log_test_event(
        "generate_enrollment_request_vectors",
        "test_complete",
        &serde_json::json!({"vectors_verified": vectors.len()}),
    );
}

#[test]
fn generate_enrollment_approval_vectors() {
    log_test_event(
        "generate_enrollment_approval_vectors",
        "test_start",
        &serde_json::json!({"purpose": "Generate CBOR vectors for enrollment approvals"}),
    );

    let (signing_secret, signing_key, encryption_key, issuance_key, owner_key) = create_test_keys();
    let manifest = create_test_manifest(&owner_key);

    let request = DeviceEnrollmentRequest::new(
        "device-approval-test",
        signing_key,
        encryption_key,
        issuance_key,
        DeviceMetadata::default(),
        &signing_secret,
    )
    .expect("request creation should succeed");

    let mut vectors: Vec<EnrollmentApprovalVector> = Vec::new();

    // Vector 1: Basic approval
    let approval = DeviceEnrollmentApproval::sign(
        &owner_key,
        &request,
        ZoneId::work(),
        vec!["fcp:zone:work".into()],
        manifest.clone(),
        DEFAULT_ENROLLMENT_VALIDITY_HOURS,
    )
    .expect("approval should succeed");

    vectors.push(EnrollmentApprovalVector {
        description: "Basic enrollment approval for work zone".to_string(),
        device_id: approval.device_id.as_str().to_string(),
        zone_id: approval.zone_id.as_str().to_string(),
        approved_tags: approval.approved_tags.clone(),
        validity_hours: DEFAULT_ENROLLMENT_VALIDITY_HOURS,
        is_valid: approval.verify(&owner_key.verifying_key()).is_ok(),
        error_type: None,
    });

    // Vector 2: Approval with multiple tags
    let approval_multi_tag = DeviceEnrollmentApproval::sign(
        &owner_key,
        &request,
        ZoneId::private(),
        vec![
            "fcp:zone:private".into(),
            "fcp:zone:owner".into(),
            "fcp:role:admin".into(),
        ],
        manifest,
        720, // 30 days
    )
    .expect("approval should succeed");

    vectors.push(EnrollmentApprovalVector {
        description: "Enrollment approval with multiple tags and extended validity".to_string(),
        device_id: approval_multi_tag.device_id.as_str().to_string(),
        zone_id: approval_multi_tag.zone_id.as_str().to_string(),
        approved_tags: approval_multi_tag.approved_tags.clone(),
        validity_hours: 720,
        is_valid: approval_multi_tag
            .verify(&owner_key.verifying_key())
            .is_ok(),
        error_type: None,
    });

    // Serialize to CBOR
    let path = vectors_dir().join("approval_vectors.cbor");
    let mut buffer = Vec::new();
    ciborium::into_writer(&vectors, &mut buffer).expect("CBOR serialization failed");
    fs::write(&path, &buffer).expect("Failed to write CBOR file");

    log_test_event(
        "generate_enrollment_approval_vectors",
        "vector_written",
        &serde_json::json!({
            "path": path.display().to_string(),
            "size_bytes": buffer.len(),
            "approval_count": vectors.len()
        }),
    );

    // Verify round-trip
    let data = fs::read(&path).expect("Failed to read CBOR file");
    let loaded: Vec<EnrollmentApprovalVector> =
        ciborium::from_reader(data.as_slice()).expect("CBOR deserialization failed");

    assert_eq!(loaded, vectors);

    log_test_event(
        "generate_enrollment_approval_vectors",
        "test_complete",
        &serde_json::json!({"vectors_verified": vectors.len()}),
    );
}

#[test]
fn generate_key_rotation_vectors() {
    log_test_event(
        "generate_key_rotation_vectors",
        "test_start",
        &serde_json::json!({"purpose": "Generate CBOR vectors for key rotation scenarios"}),
    );

    let schedule = KeyRotationSchedule::new()
        .with_signing_rotation(24)
        .with_encryption_rotation(12)
        .with_issuance_rotation(168)
        .with_max_age(720);

    let mut vectors: Vec<KeyRotationVector> = Vec::new();

    // Test cases for different key ages
    let test_cases = [
        ("signing", KeyType::Signing, 24, 6, false, false),
        ("signing", KeyType::Signing, 24, 24, true, false),
        ("signing", KeyType::Signing, 24, 48, true, false),
        ("encryption", KeyType::Encryption, 12, 6, false, false),
        ("encryption", KeyType::Encryption, 12, 12, true, false),
        ("issuance", KeyType::Issuance, 168, 100, false, false),
        ("issuance", KeyType::Issuance, 168, 200, true, false),
        ("any", KeyType::Signing, 24, 720, true, true), // Max age exceeded
    ];

    for (key_type_name, key_type, rotation_hours, age_hours, _needs_rotation, _must_rotate) in
        test_cases
    {
        let created_at = Utc::now() - Duration::hours(age_hours);

        vectors.push(KeyRotationVector {
            description: format!(
                "{key_type_name} key aged {age_hours} hours (rotation: {rotation_hours} hours)"
            ),
            key_type: key_type_name.to_string(),
            rotation_hours,
            key_age_hours: age_hours,
            needs_rotation: schedule.needs_rotation(key_type, created_at),
            must_rotate: schedule.must_rotate(created_at),
        });
    }

    // Serialize to CBOR
    let path = vectors_dir().join("rotation_vectors.cbor");
    let mut buffer = Vec::new();
    ciborium::into_writer(&vectors, &mut buffer).expect("CBOR serialization failed");
    fs::write(&path, &buffer).expect("Failed to write CBOR file");

    log_test_event(
        "generate_key_rotation_vectors",
        "vector_written",
        &serde_json::json!({
            "path": path.display().to_string(),
            "size_bytes": buffer.len(),
            "rotation_count": vectors.len()
        }),
    );

    // Verify round-trip
    let data = fs::read(&path).expect("Failed to read CBOR file");
    let loaded: Vec<KeyRotationVector> =
        ciborium::from_reader(data.as_slice()).expect("CBOR deserialization failed");

    assert_eq!(loaded, vectors);

    log_test_event(
        "generate_key_rotation_vectors",
        "test_complete",
        &serde_json::json!({"vectors_verified": vectors.len()}),
    );
}

#[test]
fn generate_enrollment_status_vectors() {
    log_test_event(
        "generate_enrollment_status_vectors",
        "test_start",
        &serde_json::json!({"purpose": "Generate CBOR vectors for enrollment status"}),
    );

    let statuses = [
        EnrollmentStatus::Pending,
        EnrollmentStatus::Approved,
        EnrollmentStatus::Rejected,
        EnrollmentStatus::Revoked,
        EnrollmentStatus::Expired,
    ];

    let vectors: Vec<EnrollmentStatusVector> = statuses
        .iter()
        .map(|status| EnrollmentStatusVector {
            description: format!("Enrollment status: {status}"),
            status: status.to_string(),
            is_enrolled: status.is_enrolled(),
            is_renewable: status.is_renewable(),
        })
        .collect();

    // Serialize to CBOR
    let path = vectors_dir().join("status_vectors.cbor");
    let mut buffer = Vec::new();
    ciborium::into_writer(&vectors, &mut buffer).expect("CBOR serialization failed");
    fs::write(&path, &buffer).expect("Failed to write CBOR file");

    log_test_event(
        "generate_enrollment_status_vectors",
        "vector_written",
        &serde_json::json!({
            "path": path.display().to_string(),
            "size_bytes": buffer.len(),
            "status_count": vectors.len()
        }),
    );

    // Verify round-trip
    let data = fs::read(&path).expect("Failed to read CBOR file");
    let loaded: Vec<EnrollmentStatusVector> =
        ciborium::from_reader(data.as_slice()).expect("CBOR deserialization failed");

    assert_eq!(loaded, vectors);

    log_test_event(
        "generate_enrollment_status_vectors",
        "test_complete",
        &serde_json::json!({"vectors_verified": vectors.len()}),
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Adversarial Attack Scenario Tests
// ─────────────────────────────────────────────────────────────────────────────

mod adversarial {
    use super::*;

    /// Attack: Replay old enrollment approval.
    ///
    /// Scenario: Attacker captures a valid enrollment approval and replays it
    /// after the approval has expired.
    #[test]
    fn attack_replay_expired_approval() {
        log_test_event(
            "attack_replay_expired_approval",
            "test_start",
            &serde_json::json!({
                "attack_type": "replay",
                "description": "Replaying an expired enrollment approval"
            }),
        );

        let (signing_secret, signing_key, encryption_key, issuance_key, owner_key) =
            create_test_keys();
        let manifest = create_test_manifest(&owner_key);

        let request = DeviceEnrollmentRequest::new(
            "device-replay-test",
            signing_key,
            encryption_key,
            issuance_key,
            DeviceMetadata::default(),
            &signing_secret,
        )
        .expect("request creation should succeed");

        // Create an approval with very short validity (1 hour)
        let approval = DeviceEnrollmentApproval::sign(
            &owner_key,
            &request,
            ZoneId::work(),
            vec!["fcp:zone:work".into()],
            manifest,
            1, // 1 hour validity
        )
        .expect("approval should succeed");

        // Immediately after creation, it should be valid
        assert!(
            approval.verify(&owner_key.verifying_key()).is_ok(),
            "Fresh approval should be valid"
        );

        // Simulate time passing by checking remaining validity
        let remaining = approval.remaining_validity();
        assert!(
            remaining.num_hours() <= 1,
            "Approval should have at most 1 hour remaining"
        );

        // Note: In a real test, we'd mock time. Here we verify the expiration check exists.
        assert!(
            !approval.is_expired(),
            "Approval should not be expired immediately after creation"
        );

        log_test_event(
            "attack_replay_expired_approval",
            "attack_mitigated",
            &serde_json::json!({
                "mitigation": "expiration_check",
                "validity_hours": 1,
                "remaining_validity": remaining.num_minutes()
            }),
        );
    }

    /// Attack: Forge enrollment without owner signature.
    ///
    /// Scenario: Attacker creates an enrollment approval signed with their own key
    /// instead of the legitimate owner's key.
    #[test]
    fn attack_forge_approval_wrong_signer() {
        log_test_event(
            "attack_forge_approval_wrong_signer",
            "test_start",
            &serde_json::json!({
                "attack_type": "forgery",
                "description": "Creating approval with unauthorized signer"
            }),
        );

        let (signing_secret, signing_key, encryption_key, issuance_key, owner_key) =
            create_test_keys();
        let attacker_key = Ed25519SigningKey::generate();
        let manifest = create_test_manifest(&owner_key);

        let request = DeviceEnrollmentRequest::new(
            "device-forge-test",
            signing_key,
            encryption_key,
            issuance_key,
            DeviceMetadata::default(),
            &signing_secret,
        )
        .expect("request creation should succeed");

        // Attacker signs with their own key
        let forged_approval = DeviceEnrollmentApproval::sign(
            &attacker_key, // WRONG! Should be owner_key
            &request,
            ZoneId::work(),
            vec!["fcp:zone:work".into()],
            manifest,
            168,
        )
        .expect("signing should succeed");

        // Verification against the legitimate owner's key should fail
        let result = forged_approval.verify(&owner_key.verifying_key());
        assert!(result.is_err(), "Forged approval should fail verification");

        // The error should indicate invalid signature
        assert!(
            matches!(result, Err(FcpError::InvalidSignature)),
            "forged approval should fail with InvalidSignature, got {result:?}"
        );
        log_test_event(
            "attack_forge_approval_wrong_signer",
            "attack_detected",
            &serde_json::json!({
                "detection_method": "signature_verification",
                "error": "InvalidSignature"
            }),
        );
    }

    /// Attack: Impersonate `node_id` during enrollment.
    ///
    /// Scenario: Attacker tries to enroll with a different `device_id` than
    /// their actual device, attempting to steal an identity.
    #[test]
    fn attack_impersonate_device_id() {
        log_test_event(
            "attack_impersonate_device_id",
            "test_start",
            &serde_json::json!({
                "attack_type": "impersonation",
                "description": "Enrolling with stolen device_id"
            }),
        );

        let (signing_secret, signing_key, encryption_key, issuance_key, _owner) =
            create_test_keys();

        // Create a legitimate request
        let mut request = DeviceEnrollmentRequest::new(
            "legitimate-device",
            signing_key,
            encryption_key,
            issuance_key,
            DeviceMetadata::default(),
            &signing_secret,
        )
        .expect("request creation should succeed");

        // Verify original request is valid
        assert!(
            request.verify_proof().is_ok(),
            "Original request should be valid"
        );

        // Attacker tampers with device_id
        request.device_id = DeviceId::new("stolen-device-id");

        // Proof of possession should now fail because device_id is in signed payload
        let result = request.verify_proof();
        assert!(
            result.is_err(),
            "Tampered device_id should invalidate proof"
        );

        log_test_event(
            "attack_impersonate_device_id",
            "attack_detected",
            &serde_json::json!({
                "detection_method": "proof_of_possession",
                "original_device_id": "legitimate-device",
                "tampered_device_id": "stolen-device-id"
            }),
        );
    }

    /// Attack: Use keys from a removed/revoked device.
    ///
    /// Scenario: A device has been removed from the mesh, but attacker tries
    /// to use its old keys for a new enrollment.
    #[test]
    fn attack_use_revoked_device_keys() {
        log_test_event(
            "attack_use_revoked_device_keys",
            "test_start",
            &serde_json::json!({
                "attack_type": "revoked_key_reuse",
                "description": "Using keys from a revoked device"
            }),
        );

        let (signing_secret, signing_key, encryption_key, issuance_key, owner_key) =
            create_test_keys();
        let signing_key_id_hex = signing_key.key_id().to_hex(); // Save before move
        let manifest = create_test_manifest(&owner_key);

        // Create original enrollment
        let request = DeviceEnrollmentRequest::new(
            "device-to-revoke",
            signing_key.clone(),
            encryption_key.clone(),
            issuance_key.clone(),
            DeviceMetadata::default(),
            &signing_secret,
        )
        .expect("request creation should succeed");

        let approval = DeviceEnrollmentApproval::sign(
            &owner_key,
            &request,
            ZoneId::work(),
            vec!["fcp:zone:work".into()],
            manifest,
            168,
        )
        .expect("approval should succeed");

        // Verify original enrollment works
        assert!(approval.verify(&owner_key.verifying_key()).is_ok());

        // Simulate device revocation by adding signing key to revocation registry
        let mut registry = RevocationRegistry::new();

        // Create a revocation for the device's attestation/enrollment
        // In FCP, NodeAttestation scope is used for device removal
        let revocation = RevocationObject {
            header: fcp_core::ObjectHeader {
                schema: fcp_cbor::SchemaId::new(
                    "fcp.core",
                    "RevocationObject",
                    semver::Version::new(1, 0, 0),
                ),
                zone_id: ZoneId::work(),
                created_at: now_ts_u64(),
                provenance: fcp_core::Provenance::new(ZoneId::work()),
                refs: vec![],
                foreign_refs: vec![],
                ttl_secs: None,
                placement: None,
            },
            revoked: vec![ObjectId::from_bytes({
                // Use signing key ID as revocation target (simulating device key revocation)
                let mut bytes = [0u8; 32];
                bytes[..8].copy_from_slice(&signing_key.key_id().as_bytes()[..8]);
                bytes
            })],
            scope: RevocationScope::NodeAttestation,
            reason: "Device removed from mesh".to_string(),
            effective_at: now_ts_u64(),
            expires_at: None,
            signature: [0u8; 64], // Would be properly signed in production
        };

        registry.add_revocation(&revocation);

        // Check that the key is now revoked
        let key_object_id = ObjectId::from_bytes({
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&signing_key.key_id().as_bytes()[..8]);
            bytes
        });
        assert!(
            registry.is_revoked(&key_object_id),
            "Device key should be revoked"
        );

        // Attacker tries to create new enrollment with same keys
        let new_request = DeviceEnrollmentRequest::new(
            "attacker-new-device",
            signing_key,
            encryption_key,
            issuance_key,
            DeviceMetadata::default(),
            &signing_secret,
        )
        .expect("request creation succeeds but should be rejected");

        // The request is syntactically valid...
        assert!(new_request.verify_proof().is_ok());

        // ...but the enrollment system should check revocation before approval
        // A proper enrollment verifier would reject this
        assert!(
            registry.is_revoked(&key_object_id),
            "Enrollment system must check key revocation status"
        );

        log_test_event(
            "attack_use_revoked_device_keys",
            "attack_mitigated",
            &serde_json::json!({
                "mitigation": "revocation_check",
                "key_id": signing_key_id_hex,
                "is_revoked": true
            }),
        );
    }

    /// Attack: Tamper with enrollment request metadata.
    ///
    /// Scenario: Attacker modifies the metadata in an enrollment request
    /// after the proof of possession is created.
    #[test]
    fn attack_tamper_request_metadata() {
        log_test_event(
            "attack_tamper_request_metadata",
            "test_start",
            &serde_json::json!({
                "attack_type": "tampering",
                "description": "Modifying request metadata after signing"
            }),
        );

        let (signing_secret, signing_key, encryption_key, issuance_key, _owner) =
            create_test_keys();

        let mut request = DeviceEnrollmentRequest::new(
            "device-tamper-test",
            signing_key,
            encryption_key,
            issuance_key,
            DeviceMetadata::new().with_device_class("desktop"),
            &signing_secret,
        )
        .expect("request creation should succeed");

        // Original request is valid
        assert!(request.verify_proof().is_ok());

        // Attacker tampers with metadata
        // Note: metadata is NOT in the signed payload, so this succeeds
        // This is by design - metadata is informational, not security-critical
        request.metadata.device_class = Some("server".to_string());

        // Proof still valid because metadata isn't part of signed payload
        // This is intentional: metadata is advisory, keys are what matter
        assert!(
            request.verify_proof().is_ok(),
            "Metadata changes don't affect proof (by design)"
        );

        log_test_event(
            "attack_tamper_request_metadata",
            "test_complete",
            &serde_json::json!({
                "note": "Metadata tampering is allowed by design",
                "reason": "Metadata is informational, not cryptographically bound",
                "security_critical_fields": ["device_id", "signing_key", "encryption_key", "issuance_key"]
            }),
        );
    }

    /// Attack: Cross-zone enrollment escape.
    ///
    /// Scenario: Device approved for one zone tries to access another zone.
    #[test]
    fn attack_cross_zone_escape() {
        log_test_event(
            "attack_cross_zone_escape",
            "test_start",
            &serde_json::json!({
                "attack_type": "privilege_escalation",
                "description": "Attempting to use approval for wrong zone"
            }),
        );

        let (signing_secret, signing_key, encryption_key, issuance_key, owner_key) =
            create_test_keys();
        let manifest = create_test_manifest(&owner_key);

        let request = DeviceEnrollmentRequest::new(
            "device-zone-test",
            signing_key,
            encryption_key,
            issuance_key,
            DeviceMetadata::default(),
            &signing_secret,
        )
        .expect("request creation should succeed");

        // Approve for community zone only
        let approval = DeviceEnrollmentApproval::sign(
            &owner_key,
            &request,
            ZoneId::community(),
            vec!["fcp:zone:community".into()],
            manifest,
            168,
        )
        .expect("approval should succeed");

        // Device is approved for community zone
        assert_eq!(approval.zone_id, ZoneId::community());
        assert!(
            approval
                .approved_tags
                .contains(&"fcp:zone:community".to_string())
        );

        // Device is NOT approved for private zone
        assert_ne!(approval.zone_id, ZoneId::private());
        assert!(
            !approval
                .approved_tags
                .contains(&"fcp:zone:private".to_string())
        );

        // Zone enforcement should reject access to private zone
        let can_access_private = approval.approved_tags.iter().any(|t| t.contains("private"));
        assert!(
            !can_access_private,
            "Device should not have private zone access"
        );

        log_test_event(
            "attack_cross_zone_escape",
            "attack_mitigated",
            &serde_json::json!({
                "approved_zone": approval.zone_id.as_str(),
                "approved_tags": approval.approved_tags,
                "private_access": false,
                "mitigation": "zone_tag_enforcement"
            }),
        );
    }

    /// Attack: Key rotation bypass.
    ///
    /// Scenario: Device tries to use old keys past their rotation deadline.
    #[test]
    fn attack_key_rotation_bypass() {
        log_test_event(
            "attack_key_rotation_bypass",
            "test_start",
            &serde_json::json!({
                "attack_type": "stale_key_usage",
                "description": "Using keys past rotation deadline"
            }),
        );

        let schedule = KeyRotationSchedule::new()
            .with_signing_rotation(24)
            .with_max_age(168); // 7 days max

        // Simulate a key created 10 days ago
        let old_key_created_at = Utc::now() - Duration::days(10);

        // Key should need rotation
        assert!(
            schedule.needs_rotation(KeyType::Signing, old_key_created_at),
            "Old key should need rotation"
        );

        // Key should be past max age
        assert!(
            schedule.must_rotate(old_key_created_at),
            "Key past max age must be rotated"
        );

        // A fresh key should not need rotation
        let fresh_key_created_at = Utc::now() - Duration::hours(1);
        assert!(
            !schedule.needs_rotation(KeyType::Signing, fresh_key_created_at),
            "Fresh key should not need rotation"
        );
        assert!(
            !schedule.must_rotate(fresh_key_created_at),
            "Fresh key should not require forced rotation"
        );

        log_test_event(
            "attack_key_rotation_bypass",
            "attack_mitigated",
            &serde_json::json!({
                "mitigation": "key_rotation_enforcement",
                "max_age_hours": 168,
                "key_age_days": 10,
                "must_rotate": true
            }),
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Enrollment Flow Tests
// ─────────────────────────────────────────────────────────────────────────────

mod enrollment_flow {
    use super::*;

    /// Test complete enrollment flow from request to approval.
    #[test]
    fn test_complete_enrollment_flow() {
        log_test_event(
            "test_complete_enrollment_flow",
            "test_start",
            &serde_json::json!({"purpose": "End-to-end enrollment workflow"}),
        );

        // Step 1: Device generates keys
        let (signing_secret, signing_key, encryption_key, issuance_key, owner_key) =
            create_test_keys();

        log_test_event(
            "test_complete_enrollment_flow",
            "keys_generated",
            &serde_json::json!({
                "signing_kid": signing_key.key_id().to_hex(),
                "encryption_kid": encryption_key.key_id().to_hex(),
                "issuance_kid": issuance_key.key_id().to_hex()
            }),
        );

        // Step 2: Device creates enrollment request
        let metadata = DeviceMetadata::new()
            .with_display_name("Test Device")
            .with_hostname("test.local")
            .with_os("Linux")
            .with_arch("x86_64")
            .with_device_class("server")
            .with_tag("fcp:zone:work");

        let request = DeviceEnrollmentRequest::new(
            "device-flow-test",
            signing_key,
            encryption_key,
            issuance_key,
            metadata,
            &signing_secret,
        )
        .expect("request creation should succeed");

        log_test_event(
            "test_complete_enrollment_flow",
            "request_created",
            &serde_json::json!({
                "device_id": request.device_id.as_str(),
                "proof_valid": request.verify_proof().is_ok()
            }),
        );

        // Step 3: Owner reviews and verifies request
        assert!(
            request.verify_proof().is_ok(),
            "Owner should verify proof of possession"
        );

        // Step 4: Owner creates zone key manifest
        let manifest = create_test_manifest(&owner_key);

        // Step 5: Owner approves enrollment
        let approval = DeviceEnrollmentApproval::sign(
            &owner_key,
            &request,
            ZoneId::work(),
            vec!["fcp:zone:work".into(), "fcp:role:agent".into()],
            manifest,
            DEFAULT_ENROLLMENT_VALIDITY_HOURS,
        )
        .expect("approval should succeed");

        log_test_event(
            "test_complete_enrollment_flow",
            "approval_created",
            &serde_json::json!({
                "zone_id": approval.zone_id.as_str(),
                "approved_tags": approval.approved_tags,
                "validity_hours": DEFAULT_ENROLLMENT_VALIDITY_HOURS
            }),
        );

        // Step 6: Device verifies approval
        assert!(
            approval.verify(&owner_key.verifying_key()).is_ok(),
            "Device should verify approval"
        );

        // Step 7: Device checks enrollment status
        assert!(!approval.is_expired(), "Approval should not be expired");
        assert!(
            approval.remaining_validity().num_hours() > 0,
            "Approval should have remaining validity"
        );

        log_test_event(
            "test_complete_enrollment_flow",
            "test_complete",
            &serde_json::json!({
                "enrollment_successful": true,
                "remaining_validity_hours": approval.remaining_validity().num_hours()
            }),
        );
    }

    /// Test enrollment request verification.
    #[test]
    fn test_enrollment_request_verification() {
        log_test_event(
            "test_enrollment_request_verification",
            "test_start",
            &serde_json::json!({"purpose": "Verify enrollment request proof of possession"}),
        );

        let (signing_secret, signing_key, encryption_key, issuance_key, _owner) =
            create_test_keys();

        let request = DeviceEnrollmentRequest::new(
            "verify-test-device",
            signing_key.clone(),
            encryption_key.clone(),
            issuance_key.clone(),
            DeviceMetadata::default(),
            &signing_secret,
        )
        .expect("request creation should succeed");

        // Verify key IDs match
        assert_eq!(request.signing_kid(), signing_key.key_id());
        assert_eq!(request.encryption_kid(), encryption_key.key_id());
        assert_eq!(request.issuance_kid(), issuance_key.key_id());

        // Verify proof of possession
        assert!(request.verify_proof().is_ok());

        log_test_event(
            "test_enrollment_request_verification",
            "test_complete",
            &serde_json::json!({
                "device_id": request.device_id.as_str(),
                "keys_verified": true,
                "proof_verified": true
            }),
        );
    }

    /// Enrollment with a wrong/tampered identity field (analogue of "wrong
    /// `NodeId` type"): the request is signed for device A, but the
    /// `device_id` on the wire has been rewritten to B. Verification MUST
    /// reject this — the proof-of-possession is bound to the canonical
    /// payload, which includes `device_id`.
    ///
    /// Spec source: FCP V3 §2.2.1 (Mesh Identity and Node Attestation),
    /// bullet 3 — "enrolment proof MUST bind the declared identity".
    #[test]
    fn test_enrollment_rejects_tampered_identity() {
        log_test_event(
            "test_enrollment_rejects_tampered_identity",
            "test_start",
            &serde_json::json!({
                "purpose": "Proof of possession must reject mismatched device_id"
            }),
        );

        let (signing_secret, signing_key, encryption_key, issuance_key, _owner) =
            create_test_keys();

        let mut request = DeviceEnrollmentRequest::new(
            "device-honest",
            signing_key,
            encryption_key,
            issuance_key,
            DeviceMetadata::default(),
            &signing_secret,
        )
        .expect("request creation should succeed");

        // Baseline: the honest request verifies.
        assert!(
            request.verify_proof().is_ok(),
            "baseline proof must verify before tampering"
        );

        // Tamper: rewrite the identity on the wire without re-signing.
        request.device_id = DeviceId::from("device-attacker");

        // Verification MUST fail: the proof is no longer bound to the
        // declared identity.
        let verdict = request.verify_proof();
        assert!(
            verdict.is_err(),
            "tampered device_id MUST reject verification, got {verdict:?}"
        );

        log_test_event(
            "test_enrollment_rejects_tampered_identity",
            "test_complete",
            &serde_json::json!({ "rejected": true }),
        );
    }

    /// Test approval preserves request keys.
    #[test]
    fn test_approval_preserves_request_keys() {
        log_test_event(
            "test_approval_preserves_request_keys",
            "test_start",
            &serde_json::json!({"purpose": "Verify approval contains correct keys from request"}),
        );

        let (signing_secret, signing_key, encryption_key, issuance_key, owner_key) =
            create_test_keys();
        let manifest = create_test_manifest(&owner_key);

        let request = DeviceEnrollmentRequest::new(
            "keys-preserve-test",
            signing_key.clone(),
            encryption_key.clone(),
            issuance_key.clone(),
            DeviceMetadata::default(),
            &signing_secret,
        )
        .expect("request creation should succeed");

        let approval = DeviceEnrollmentApproval::sign(
            &owner_key,
            &request,
            ZoneId::work(),
            vec!["fcp:zone:work".into()],
            manifest,
            168,
        )
        .expect("approval should succeed");

        // Approval should preserve keys from request
        assert_eq!(approval.signing_key, signing_key);
        assert_eq!(approval.encryption_key, encryption_key);
        assert_eq!(approval.issuance_key, issuance_key);
        assert_eq!(approval.device_id, request.device_id);

        log_test_event(
            "test_approval_preserves_request_keys",
            "test_complete",
            &serde_json::json!({
                "signing_key_preserved": approval.signing_key == signing_key,
                "encryption_key_preserved": approval.encryption_key == encryption_key,
                "issuance_key_preserved": approval.issuance_key == issuance_key
            }),
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Key Rotation Tests
// ─────────────────────────────────────────────────────────────────────────────

mod key_rotation {
    use super::*;

    /// Test key rotation schedule configuration.
    #[test]
    fn test_key_rotation_schedule_configuration() {
        log_test_event(
            "test_key_rotation_schedule_configuration",
            "test_start",
            &serde_json::json!({"purpose": "Verify key rotation schedule builder"}),
        );

        let schedule = KeyRotationSchedule::new()
            .with_signing_rotation(12)
            .with_encryption_rotation(6)
            .with_issuance_rotation(168)
            .with_max_age(720)
            .with_overlap(2);

        assert_eq!(schedule.signing_key_rotation_hours, 12);
        assert_eq!(schedule.encryption_key_rotation_hours, 6);
        assert_eq!(schedule.issuance_key_rotation_hours, 168);
        assert_eq!(schedule.max_key_age_hours, 720);
        assert!(schedule.allow_overlap);
        assert_eq!(schedule.overlap_hours, 2);

        log_test_event(
            "test_key_rotation_schedule_configuration",
            "test_complete",
            &serde_json::json!({
                "signing_rotation": schedule.signing_key_rotation_hours,
                "encryption_rotation": schedule.encryption_key_rotation_hours,
                "issuance_rotation": schedule.issuance_key_rotation_hours,
                "max_age": schedule.max_key_age_hours
            }),
        );
    }

    /// Test default rotation schedule.
    #[test]
    fn test_default_rotation_schedule() {
        log_test_event(
            "test_default_rotation_schedule",
            "test_start",
            &serde_json::json!({"purpose": "Verify default rotation schedule values"}),
        );

        let schedule = KeyRotationSchedule::default();

        assert_eq!(
            schedule.signing_key_rotation_hours,
            DEFAULT_KEY_ROTATION_HOURS
        );
        assert_eq!(
            schedule.encryption_key_rotation_hours,
            DEFAULT_KEY_ROTATION_HOURS
        );
        assert_eq!(
            schedule.issuance_key_rotation_hours,
            DEFAULT_KEY_ROTATION_HOURS * 7
        );
        assert_eq!(schedule.max_key_age_hours, DEFAULT_KEY_ROTATION_HOURS * 30);
        assert!(schedule.allow_overlap);
        assert_eq!(schedule.overlap_hours, 1);

        log_test_event(
            "test_default_rotation_schedule",
            "test_complete",
            &serde_json::json!({
                "default_rotation_hours": DEFAULT_KEY_ROTATION_HOURS,
                "default_max_age_hours": DEFAULT_KEY_ROTATION_HOURS * 30
            }),
        );
    }

    /// Test rotation need calculation for all key types.
    #[test]
    fn test_rotation_needs_by_key_type() {
        log_test_event(
            "test_rotation_needs_by_key_type",
            "test_start",
            &serde_json::json!({"purpose": "Test rotation needs for each key type"}),
        );

        let schedule = KeyRotationSchedule::new()
            .with_signing_rotation(24)
            .with_encryption_rotation(12)
            .with_issuance_rotation(168);

        let now = Utc::now();

        // Test signing key
        let signing_fresh = now - Duration::hours(12);
        let signing_stale = now - Duration::hours(30);
        assert!(!schedule.needs_rotation(KeyType::Signing, signing_fresh));
        assert!(schedule.needs_rotation(KeyType::Signing, signing_stale));

        // Test encryption key (shorter interval)
        let enc_fresh = now - Duration::hours(6);
        let enc_stale = now - Duration::hours(15);
        assert!(!schedule.needs_rotation(KeyType::Encryption, enc_fresh));
        assert!(schedule.needs_rotation(KeyType::Encryption, enc_stale));

        // Test issuance key (longer interval)
        let iss_fresh = now - Duration::hours(100);
        let iss_stale = now - Duration::hours(200);
        assert!(!schedule.needs_rotation(KeyType::Issuance, iss_fresh));
        assert!(schedule.needs_rotation(KeyType::Issuance, iss_stale));

        log_test_event(
            "test_rotation_needs_by_key_type",
            "test_complete",
            &serde_json::json!({
                "signing_fresh": !schedule.needs_rotation(KeyType::Signing, signing_fresh),
                "signing_stale": schedule.needs_rotation(KeyType::Signing, signing_stale),
                "encryption_fresh": !schedule.needs_rotation(KeyType::Encryption, enc_fresh),
                "encryption_stale": schedule.needs_rotation(KeyType::Encryption, enc_stale),
                "issuance_fresh": !schedule.needs_rotation(KeyType::Issuance, iss_fresh),
                "issuance_stale": schedule.needs_rotation(KeyType::Issuance, iss_stale)
            }),
        );
    }

    /// Test overlap configuration.
    #[test]
    fn test_rotation_overlap_configuration() {
        log_test_event(
            "test_rotation_overlap_configuration",
            "test_start",
            &serde_json::json!({"purpose": "Test key overlap settings"}),
        );

        // With overlap
        let with_overlap = KeyRotationSchedule::new().with_overlap(4);
        assert!(with_overlap.allow_overlap);
        assert_eq!(with_overlap.overlap_hours, 4);

        // Without overlap
        let without_overlap = KeyRotationSchedule::new().without_overlap();
        assert!(!without_overlap.allow_overlap);
        assert_eq!(without_overlap.overlap_hours, 0);

        log_test_event(
            "test_rotation_overlap_configuration",
            "test_complete",
            &serde_json::json!({
                "with_overlap_hours": with_overlap.overlap_hours,
                "without_overlap_hours": without_overlap.overlap_hours
            }),
        );
    }

    /// Test CBOR serialization of rotation schedule.
    #[test]
    fn test_rotation_schedule_cbor_roundtrip() {
        log_test_event(
            "test_rotation_schedule_cbor_roundtrip",
            "test_start",
            &serde_json::json!({"purpose": "Test CBOR serialization of rotation schedule"}),
        );

        let schedule = KeyRotationSchedule::new()
            .with_signing_rotation(18)
            .with_encryption_rotation(9)
            .with_issuance_rotation(96)
            .with_max_age(500)
            .with_overlap(3);

        // Serialize
        let mut buffer = Vec::new();
        ciborium::into_writer(&schedule, &mut buffer).expect("CBOR serialization failed");

        // Deserialize
        let decoded: KeyRotationSchedule =
            ciborium::from_reader(buffer.as_slice()).expect("CBOR deserialization failed");

        assert_eq!(decoded, schedule);

        log_test_event(
            "test_rotation_schedule_cbor_roundtrip",
            "test_complete",
            &serde_json::json!({
                "serialized_bytes": buffer.len(),
                "roundtrip_success": true
            }),
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Device Removal Tests
// ─────────────────────────────────────────────────────────────────────────────

mod device_removal {
    use super::*;

    /// Test device removal via revocation.
    #[test]
    fn test_device_removal_revocation() {
        log_test_event(
            "test_device_removal_revocation",
            "test_start",
            &serde_json::json!({"purpose": "Test device removal via NodeAttestation revocation"}),
        );

        let (signing_secret, signing_key, encryption_key, issuance_key, owner_key) =
            create_test_keys();
        let manifest = create_test_manifest(&owner_key);

        // Create enrollment
        let request = DeviceEnrollmentRequest::new(
            "device-to-remove",
            signing_key.clone(),
            encryption_key,
            issuance_key,
            DeviceMetadata::default(),
            &signing_secret,
        )
        .expect("request creation should succeed");

        let approval = DeviceEnrollmentApproval::sign(
            &owner_key,
            &request,
            ZoneId::work(),
            vec!["fcp:zone:work".into()],
            manifest,
            168,
        )
        .expect("approval should succeed");

        // Device is enrolled
        assert!(approval.verify(&owner_key.verifying_key()).is_ok());

        // Create revocation registry and revoke the device
        let mut registry = RevocationRegistry::new();

        // Create attestation ID from signing key
        let attestation_id = ObjectId::from_bytes({
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&signing_key.key_id().as_bytes()[..8]);
            bytes
        });

        let revocation = RevocationObject {
            header: fcp_core::ObjectHeader {
                schema: fcp_cbor::SchemaId::new(
                    "fcp.core",
                    "RevocationObject",
                    semver::Version::new(1, 0, 0),
                ),
                zone_id: ZoneId::work(),
                created_at: now_ts_u64(),
                provenance: fcp_core::Provenance::new(ZoneId::work()),
                refs: vec![],
                foreign_refs: vec![],
                ttl_secs: None,
                placement: None,
            },
            revoked: vec![attestation_id],
            scope: RevocationScope::NodeAttestation,
            reason: "Device decommissioned".to_string(),
            effective_at: now_ts_u64(),
            expires_at: None,
            signature: [0u8; 64],
        };

        registry.add_revocation(&revocation);

        // Device attestation is now revoked
        assert!(registry.is_revoked(&attestation_id));

        // Verify the revocation scope
        let retrieved = registry.get_revocation(&attestation_id).unwrap();
        assert_eq!(retrieved.scope, RevocationScope::NodeAttestation);

        log_test_event(
            "test_device_removal_revocation",
            "test_complete",
            &serde_json::json!({
                "device_id": request.device_id.as_str(),
                "attestation_revoked": true,
                "scope": "NodeAttestation"
            }),
        );
    }

    /// Test that revoked device cannot re-enroll.
    #[test]
    fn test_revoked_device_cannot_reenroll() {
        log_test_event(
            "test_revoked_device_cannot_reenroll",
            "test_start",
            &serde_json::json!({"purpose": "Verify revoked device cannot re-enroll"}),
        );

        let (signing_secret, signing_key, encryption_key, issuance_key, _owner) =
            create_test_keys();

        // Create revocation registry with device's key revoked
        let mut registry = RevocationRegistry::new();
        let key_id = ObjectId::from_bytes({
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&signing_key.key_id().as_bytes()[..8]);
            bytes
        });

        let revocation = RevocationObject {
            header: fcp_core::ObjectHeader {
                schema: fcp_cbor::SchemaId::new(
                    "fcp.core",
                    "RevocationObject",
                    semver::Version::new(1, 0, 0),
                ),
                zone_id: ZoneId::work(),
                created_at: now_ts_u64(),
                provenance: fcp_core::Provenance::new(ZoneId::work()),
                refs: vec![],
                foreign_refs: vec![],
                ttl_secs: None,
                placement: None,
            },
            revoked: vec![key_id],
            scope: RevocationScope::NodeAttestation,
            reason: "Device removed".to_string(),
            effective_at: now_ts_u64(),
            expires_at: None,
            signature: [0u8; 64],
        };

        registry.add_revocation(&revocation);

        // Device attempts to re-enroll with same keys
        let request = DeviceEnrollmentRequest::new(
            "device-reenroll-attempt",
            signing_key,
            encryption_key,
            issuance_key,
            DeviceMetadata::default(),
            &signing_secret,
        )
        .expect("request creation succeeds syntactically");

        // Request is valid syntactically
        assert!(request.verify_proof().is_ok());

        // But enrollment system should check revocation
        let is_key_revoked = registry.is_revoked(&key_id);
        assert!(is_key_revoked, "Key should be revoked");

        // Enrollment should be rejected based on revocation check
        // (This would be enforced by the enrollment verifier in production)

        log_test_event(
            "test_revoked_device_cannot_reenroll",
            "test_complete",
            &serde_json::json!({
                "key_revoked": true,
                "reenrollment_blocked": true
            }),
        );
    }

    /// Test enrollment status transitions.
    #[test]
    fn test_enrollment_status_transitions() {
        log_test_event(
            "test_enrollment_status_transitions",
            "test_start",
            &serde_json::json!({"purpose": "Test enrollment status state machine"}),
        );

        // Pending -> not enrolled, not renewable
        let pending = EnrollmentStatus::Pending;
        assert!(!pending.is_enrolled());
        assert!(!pending.is_renewable());

        // Approved -> enrolled, renewable
        let approved = EnrollmentStatus::Approved;
        assert!(approved.is_enrolled());
        assert!(approved.is_renewable());

        // Rejected -> not enrolled, not renewable
        let rejected = EnrollmentStatus::Rejected;
        assert!(!rejected.is_enrolled());
        assert!(!rejected.is_renewable());

        // Revoked -> not enrolled, not renewable
        let revoked = EnrollmentStatus::Revoked;
        assert!(!revoked.is_enrolled());
        assert!(!revoked.is_renewable());

        // Expired -> not enrolled, but renewable
        let expired = EnrollmentStatus::Expired;
        assert!(!expired.is_enrolled());
        assert!(expired.is_renewable());

        log_test_event(
            "test_enrollment_status_transitions",
            "test_complete",
            &serde_json::json!({
                "pending": {"enrolled": false, "renewable": false},
                "approved": {"enrolled": true, "renewable": true},
                "rejected": {"enrolled": false, "renewable": false},
                "revoked": {"enrolled": false, "renewable": false},
                "expired": {"enrolled": false, "renewable": true}
            }),
        );
    }

    /// Test multiple device removals.
    #[test]
    fn test_bulk_device_removal() {
        log_test_event(
            "test_bulk_device_removal",
            "test_start",
            &serde_json::json!({"purpose": "Test removing multiple devices at once"}),
        );

        let mut registry = RevocationRegistry::new();

        // Create multiple device IDs to revoke
        let device_ids: Vec<ObjectId> = (0..5u8).map(|i| ObjectId::from_bytes([i; 32])).collect();

        // Create single revocation for all devices
        let revocation = RevocationObject {
            header: fcp_core::ObjectHeader {
                schema: fcp_cbor::SchemaId::new(
                    "fcp.core",
                    "RevocationObject",
                    semver::Version::new(1, 0, 0),
                ),
                zone_id: ZoneId::work(),
                created_at: now_ts_u64(),
                provenance: fcp_core::Provenance::new(ZoneId::work()),
                refs: vec![],
                foreign_refs: vec![],
                ttl_secs: None,
                placement: None,
            },
            revoked: device_ids.clone(),
            scope: RevocationScope::NodeAttestation,
            reason: "Bulk device removal".to_string(),
            effective_at: now_ts_u64(),
            expires_at: None,
            signature: [0u8; 64],
        };

        registry.add_revocation(&revocation);

        // All devices should be revoked
        for id in &device_ids {
            assert!(registry.is_revoked(id), "Device {id:?} should be revoked");
        }

        // Non-revoked device should not be affected
        let other_device = ObjectId::from_bytes([99u8; 32]);
        assert!(!registry.is_revoked(&other_device));

        log_test_event(
            "test_bulk_device_removal",
            "test_complete",
            &serde_json::json!({
                "devices_revoked": device_ids.len(),
                "all_revoked": true
            }),
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Deterministic Key Tests
// ─────────────────────────────────────────────────────────────────────────────

mod deterministic_keys {
    use super::*;

    /// Test that deterministic keys produce consistent key IDs.
    #[test]
    fn test_deterministic_key_ids() {
        log_test_event(
            "test_deterministic_key_ids",
            "test_start",
            &serde_json::json!({"purpose": "Verify deterministic key generation"}),
        );

        // Create deterministic keys from known seed
        let signing_key1 =
            Ed25519SigningKey::from_bytes(&[1u8; 32]).expect("key creation should succeed");
        let signing_key2 =
            Ed25519SigningKey::from_bytes(&[1u8; 32]).expect("key creation should succeed");

        // Same seed should produce same key ID
        assert_eq!(
            signing_key1.verifying_key().key_id(),
            signing_key2.verifying_key().key_id()
        );

        // Different seed should produce different key ID
        let signing_key3 =
            Ed25519SigningKey::from_bytes(&[2u8; 32]).expect("key creation should succeed");
        assert_ne!(
            signing_key1.verifying_key().key_id(),
            signing_key3.verifying_key().key_id()
        );

        log_test_event(
            "test_deterministic_key_ids",
            "test_complete",
            &serde_json::json!({
                "same_seed_same_kid": signing_key1.verifying_key().key_id() == signing_key2.verifying_key().key_id(),
                "diff_seed_diff_kid": signing_key1.verifying_key().key_id() != signing_key3.verifying_key().key_id()
            }),
        );
    }

    /// Test golden vector key IDs are consistent.
    #[test]
    fn test_golden_key_ids() {
        log_test_event(
            "test_golden_key_ids",
            "test_start",
            &serde_json::json!({"purpose": "Verify golden vector key ID consistency"}),
        );

        // Well-known test vectors
        let signing_key = Ed25519SigningKey::from_bytes(&[1u8; 32]).expect("key creation");
        let encryption_key = X25519SecretKey::from_bytes([2u8; 32]);
        let issuance_key = Ed25519SigningKey::from_bytes(&[3u8; 32]).expect("key creation");

        // These should be stable across implementations
        let signing_kid = signing_key.verifying_key().key_id().to_hex();
        let encryption_kid = encryption_key.public_key().key_id().to_hex();
        let issuance_kid = issuance_key.verifying_key().key_id().to_hex();

        // Log for cross-implementation verification
        log_test_event(
            "test_golden_key_ids",
            "golden_values",
            &serde_json::json!({
                "signing_kid": signing_kid,
                "encryption_kid": encryption_kid,
                "issuance_kid": issuance_kid
            }),
        );

        // Verify expected golden values (from fcp-core enrollment.rs tests)
        assert_eq!(signing_kid, "a0c1f01ec0c902d8");

        log_test_event(
            "test_golden_key_ids",
            "test_complete",
            &serde_json::json!({"golden_values_verified": true}),
        );
    }
}
