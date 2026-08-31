//! E2E enrollment tests with posture enforcement.
//!
//! These tests verify the enrollment flow when zones require device posture attestation.
//! Per `docs/STANDARD_Testing_Logging.md`, all tests emit structured JSONL logs
//! and validate against the E2E schema.

mod support;

use std::collections::HashMap;
use std::time::Instant;

use chrono::{Duration, Utc};
use fcp_cbor::SchemaId;
use fcp_core::{
    DecisionReasonCode, DeviceEnrollmentApproval, DeviceEnrollmentRequest, DeviceMetadata, NodeId,
    NodeSignature, ObjectHeader, ObjectIdKeyId, PostureAttestation, PostureAttributeKey,
    PostureAttributeValue, PostureCheckResult, PostureRequirements, Provenance, ZoneId,
    ZoneKemAlgorithm, ZoneKeyAlgorithm, ZoneKeyId, ZoneKeyManifest,
};
use fcp_crypto::{Ed25519SigningKey, X25519SecretKey};
use serde_json::json;
use support::LogCapture;
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// Test Infrastructure
// ─────────────────────────────────────────────────────────────────────────────

/// E2E test context with structured logging.
struct E2ETestContext {
    test_name: String,
    module: String,
    correlation_id: String,
    capture: LogCapture,
    start_time: Instant,
    assertions_passed: u32,
    assertions_failed: u32,
}

impl E2ETestContext {
    fn new(test_name: &str) -> Self {
        Self {
            test_name: test_name.to_string(),
            module: "fcp-core::enrollment::posture".to_string(),
            correlation_id: Uuid::new_v4().to_string(),
            capture: LogCapture::new(),
            start_time: Instant::now(),
            assertions_passed: 0,
            assertions_failed: 0,
        }
    }

    fn log_phase(&self, phase: &str, details: Option<serde_json::Value>) {
        #[allow(clippy::cast_possible_truncation)]
        let duration_ms = self.start_time.elapsed().as_millis() as u64;
        let mut entry = json!({
            "timestamp": Utc::now().to_rfc3339(),
            "test_name": self.test_name,
            "module": self.module,
            "phase": phase,
            "correlation_id": self.correlation_id,
            "result": "pass",
            "duration_ms": duration_ms,
            "assertions": {
                "passed": self.assertions_passed,
                "failed": self.assertions_failed
            }
        });

        if let Some(d) = details {
            entry["details"] = d;
        }

        self.capture.push_value(&entry).expect("log entry");
    }

    fn assert_true(&mut self, condition: bool, msg: &str) {
        if condition {
            self.assertions_passed += 1;
        } else {
            self.assertions_failed += 1;
            panic!("{msg}");
        }
    }

    fn assert_eq<T: std::fmt::Debug + PartialEq>(&mut self, actual: &T, expected: &T, msg: &str) {
        if actual == expected {
            self.assertions_passed += 1;
        } else {
            self.assertions_failed += 1;
            panic!("{msg}: expected {expected:?}, got {actual:?}");
        }
    }

    fn finalize(&self, result: &str) {
        #[allow(clippy::cast_possible_truncation)]
        let duration_ms = self.start_time.elapsed().as_millis() as u64;
        let entry = json!({
            "timestamp": Utc::now().to_rfc3339(),
            "test_name": self.test_name,
            "module": self.module,
            "phase": "verify",
            "correlation_id": self.correlation_id,
            "result": result,
            "duration_ms": duration_ms,
            "assertions": {
                "passed": self.assertions_passed,
                "failed": self.assertions_failed
            }
        });
        self.capture.push_value(&entry).expect("final log entry");

        // Validate all logs against E2E schema
        self.capture.assert_valid();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Enrollment Posture Validation
// ─────────────────────────────────────────────────────────────────────────────

/// Result of enrollment posture validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollmentPostureResult {
    /// Posture requirements satisfied (or no requirements).
    Allowed,
    /// Posture attestation required but missing.
    PostureAttestationMissing,
    /// Posture attestation expired.
    PostureAttestationExpired,
    /// Posture attestation invalid (wrong schema).
    PostureAttestationInvalid,
    /// Posture requirement not met.
    PostureRequirementNotMet { attribute: PostureAttributeKey },
    /// Verifier not in allowed list.
    PostureVerifierNotAllowed,
}

impl EnrollmentPostureResult {
    /// Convert to [`DecisionReasonCode`] for policy engine compatibility.
    #[must_use]
    pub const fn to_reason_code(&self) -> DecisionReasonCode {
        match self {
            Self::Allowed => DecisionReasonCode::Allow,
            Self::PostureAttestationMissing => DecisionReasonCode::PostureAttestationMissing,
            Self::PostureAttestationExpired => DecisionReasonCode::PostureAttestationExpired,
            Self::PostureAttestationInvalid => DecisionReasonCode::PostureAttestationInvalid,
            Self::PostureRequirementNotMet { .. } => DecisionReasonCode::PostureRequirementNotMet,
            Self::PostureVerifierNotAllowed => DecisionReasonCode::PostureVerifierNotAllowed,
        }
    }

    /// Check if enrollment is allowed.
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed)
    }
}

/// Validate enrollment request against zone posture requirements.
///
/// This function checks whether a device meets the posture requirements
/// for enrolling in a zone. It should be called during the enrollment
/// approval process.
///
/// # Arguments
///
/// * `requirements` - Zone posture requirements (None means no requirements)
/// * `attestation` - Device's posture attestation (None means no attestation provided)
///
/// # Returns
///
/// [`EnrollmentPostureResult`] indicating whether enrollment is allowed.
#[must_use]
pub fn validate_enrollment_posture(
    requirements: Option<&PostureRequirements>,
    attestation: Option<&PostureAttestation>,
) -> EnrollmentPostureResult {
    // No requirements means posture is not required
    let Some(reqs) = requirements else {
        return EnrollmentPostureResult::Allowed;
    };

    // Requirements exist but no attestation provided
    let Some(att) = attestation else {
        return EnrollmentPostureResult::PostureAttestationMissing;
    };

    // Check attestation schema before expiry (schema indicates fundamental validity)
    if att.schema != PostureAttestation::SCHEMA {
        return EnrollmentPostureResult::PostureAttestationInvalid;
    }

    // Check attestation expiry
    if att.is_expired() {
        return EnrollmentPostureResult::PostureAttestationExpired;
    }

    // Verify against requirements
    match reqs.is_satisfied_by(att) {
        PostureCheckResult::Satisfied => EnrollmentPostureResult::Allowed,
        PostureCheckResult::AttestationExpired | PostureCheckResult::AttestationTooOld => {
            EnrollmentPostureResult::PostureAttestationExpired
        }
        PostureCheckResult::VerifierNotAllowed => {
            EnrollmentPostureResult::PostureVerifierNotAllowed
        }
        PostureCheckResult::RequirementNotMet { attribute } => {
            EnrollmentPostureResult::PostureRequirementNotMet { attribute }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test Fixtures
// ─────────────────────────────────────────────────────────────────────────────

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

fn now_ts_u64() -> u64 {
    Utc::now().timestamp().try_into().unwrap_or(0)
}

fn create_test_manifest_for_zone(zone_id: ZoneId) -> ZoneKeyManifest {
    use rand::RngCore;

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
        kem: ZoneKemAlgorithm::HpkeX25519,
        wrapped_keys_v4: vec![],
    }
}

fn create_test_manifest(_owner_key: &Ed25519SigningKey) -> ZoneKeyManifest {
    create_test_manifest_for_zone(ZoneId::owner())
}

fn create_valid_attestation(node_id: &NodeId) -> PostureAttestation {
    let mut attributes = HashMap::new();
    attributes.insert(
        PostureAttributeKey::OsType,
        PostureAttributeValue::String("macos".to_string()),
    );
    attributes.insert(
        PostureAttributeKey::OsVersion,
        PostureAttributeValue::String("14.2.1".to_string()),
    );
    attributes.insert(
        PostureAttributeKey::DiskEncryption,
        PostureAttributeValue::Bool(true),
    );
    attributes.insert(
        PostureAttributeKey::FirewallEnabled,
        PostureAttributeValue::Bool(true),
    );
    attributes.insert(
        PostureAttributeKey::ScreenLockEnabled,
        PostureAttributeValue::Bool(true),
    );
    attributes.insert(
        PostureAttributeKey::TpmPresent,
        PostureAttributeValue::Bool(true),
    );

    PostureAttestation {
        schema: PostureAttestation::SCHEMA.to_string(),
        attestation_id: format!("att-{}", Uuid::new_v4()),
        node_id: node_id.clone(),
        attributes,
        issued_at: Utc::now(),
        expires_at: Utc::now() + Duration::hours(24),
        verifier_id: "trusted-verifier".to_string(),
        signature: "valid-signature-placeholder".to_string(),
        verifier_kid: "key-id-1".to_string(),
    }
}

fn create_zone_posture_requirements() -> PostureRequirements {
    PostureRequirements::builder()
        .require_disk_encryption(true)
        .require_firewall(true)
        .allow_verifier("trusted-verifier")
        .max_attestation_age_secs(86400)
        .build()
}

// ─────────────────────────────────────────────────────────────────────────────
// E2E Test: Enrollment with valid posture in z:owner succeeds
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn e2e_enrollment_with_posture_in_owner_zone_succeeds() {
    let mut ctx = E2ETestContext::new("e2e_enrollment_with_posture_in_owner_zone_succeeds");

    // Setup: Create keys, enrollment request, and posture attestation
    ctx.log_phase(
        "setup",
        Some(json!({
            "description": "Create enrollment request and posture attestation for z:owner",
            "zone_id": "z:owner",
            "requires_posture": true
        })),
    );

    let (signing_secret, signing_key, encryption_key, issuance_key, owner_key) = create_test_keys();
    let device_id = "device-with-posture";
    let node_id = NodeId::new(device_id);

    // Create enrollment request
    let request = DeviceEnrollmentRequest::new(
        device_id,
        signing_key,
        encryption_key,
        issuance_key,
        DeviceMetadata::new()
            .with_display_name("Test Device")
            .with_os("macOS 14.2.1"),
        &signing_secret,
    )
    .expect("create enrollment request");

    // Create posture attestation
    let attestation = create_valid_attestation(&node_id);
    let requirements = create_zone_posture_requirements();

    ctx.log_phase(
        "execute",
        Some(json!({
            "device_id": device_id,
            "attestation_id": attestation.attestation_id,
            "verifier_id": attestation.verifier_id,
            "disk_encryption": attestation.disk_encryption_enabled(),
            "requirements": {
                "disk_encryption": true,
                "firewall": true
            }
        })),
    );

    // Validate posture before enrollment approval
    let posture_result = validate_enrollment_posture(Some(&requirements), Some(&attestation));

    ctx.assert_true(
        posture_result.is_allowed(),
        "Posture validation should allow enrollment",
    );
    ctx.assert_eq(
        &posture_result.to_reason_code(),
        &DecisionReasonCode::Allow,
        "Reason code should be Allowed",
    );

    // Create enrollment approval (posture is satisfied)
    let manifest = create_test_manifest(&owner_key);
    let approval = DeviceEnrollmentApproval::sign(
        &owner_key,
        &request,
        ZoneId::owner(),
        vec!["fcp:zone:owner".into()],
        manifest,
        168,
    )
    .expect("create enrollment approval");

    // Verify approval is valid
    ctx.assert_true(
        approval.verify(&owner_key.verifying_key()).is_ok(),
        "Enrollment approval should be valid",
    );
    ctx.assert_true(
        !approval.is_expired(),
        "Enrollment approval should not be expired",
    );
    ctx.assert_eq(
        &approval.zone_id,
        &ZoneId::owner(),
        "Approval should be for z:owner",
    );

    ctx.finalize("pass");
}

// ─────────────────────────────────────────────────────────────────────────────
// E2E Test: Enrollment without posture in z:owner is denied
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn e2e_enrollment_without_posture_in_owner_zone_denied() {
    let mut ctx = E2ETestContext::new("e2e_enrollment_without_posture_in_owner_zone_denied");

    // Setup: Create enrollment request without posture attestation
    ctx.log_phase(
        "setup",
        Some(json!({
            "description": "Attempt enrollment without posture attestation for z:owner",
            "zone_id": "z:owner",
            "requires_posture": true,
            "has_attestation": false
        })),
    );

    let (signing_secret, signing_key, encryption_key, issuance_key, _owner_key) =
        create_test_keys();
    let device_id = "device-without-posture";

    // Create enrollment request
    let _request = DeviceEnrollmentRequest::new(
        device_id,
        signing_key,
        encryption_key,
        issuance_key,
        DeviceMetadata::new().with_display_name("Test Device No Posture"),
        &signing_secret,
    )
    .expect("create enrollment request");

    // Zone requires posture, but no attestation provided
    let requirements = create_zone_posture_requirements();

    ctx.log_phase(
        "execute",
        Some(json!({
            "device_id": device_id,
            "attestation": null,
            "requirements": {
                "disk_encryption": true,
                "firewall": true
            }
        })),
    );

    // Validate posture - should fail because no attestation
    let posture_result = validate_enrollment_posture(Some(&requirements), None);

    ctx.assert_true(
        !posture_result.is_allowed(),
        "Posture validation should deny enrollment",
    );
    ctx.assert_eq(
        &posture_result,
        &EnrollmentPostureResult::PostureAttestationMissing,
        "Result should be PostureAttestationMissing",
    );
    ctx.assert_eq(
        &posture_result.to_reason_code(),
        &DecisionReasonCode::PostureAttestationMissing,
        "Reason code should be PostureAttestationMissing",
    );

    ctx.log_phase(
        "verify",
        Some(json!({
            "enrollment_denied": true,
            "reason_code": "PostureAttestationMissing",
            "message": "Device enrollment denied - posture attestation required but not provided"
        })),
    );

    ctx.finalize("pass");
}

// ─────────────────────────────────────────────────────────────────────────────
// E2E Test: Enrollment with expired posture is denied
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn e2e_enrollment_with_expired_posture_denied() {
    let mut ctx = E2ETestContext::new("e2e_enrollment_with_expired_posture_denied");

    ctx.log_phase(
        "setup",
        Some(json!({
            "description": "Attempt enrollment with expired posture attestation",
            "zone_id": "z:owner"
        })),
    );

    let node_id = NodeId::new("device-expired-posture");
    let mut attestation = create_valid_attestation(&node_id);
    attestation.expires_at = Utc::now() - Duration::hours(1);

    let requirements = create_zone_posture_requirements();

    ctx.log_phase(
        "execute",
        Some(json!({
            "attestation_expired": true,
            "expires_at": attestation.expires_at.to_rfc3339()
        })),
    );

    let posture_result = validate_enrollment_posture(Some(&requirements), Some(&attestation));

    ctx.assert_true(
        !posture_result.is_allowed(),
        "Expired posture should deny enrollment",
    );
    ctx.assert_eq(
        &posture_result,
        &EnrollmentPostureResult::PostureAttestationExpired,
        "Result should be PostureAttestationExpired",
    );
    ctx.assert_eq(
        &posture_result.to_reason_code(),
        &DecisionReasonCode::PostureAttestationExpired,
        "Reason code should be PostureAttestationExpired",
    );

    ctx.finalize("pass");
}

// ─────────────────────────────────────────────────────────────────────────────
// E2E Test: Enrollment with invalid verifier is denied
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn e2e_enrollment_with_untrusted_verifier_denied() {
    let mut ctx = E2ETestContext::new("e2e_enrollment_with_untrusted_verifier_denied");

    ctx.log_phase(
        "setup",
        Some(json!({
            "description": "Attempt enrollment with attestation from untrusted verifier",
            "zone_id": "z:owner"
        })),
    );

    let node_id = NodeId::new("device-untrusted-verifier");
    let mut attestation = create_valid_attestation(&node_id);
    attestation.verifier_id = "untrusted-verifier".to_string();

    let requirements = create_zone_posture_requirements();

    ctx.log_phase(
        "execute",
        Some(json!({
            "attestation_verifier": attestation.verifier_id,
            "allowed_verifiers": ["trusted-verifier"]
        })),
    );

    let posture_result = validate_enrollment_posture(Some(&requirements), Some(&attestation));

    ctx.assert_true(
        !posture_result.is_allowed(),
        "Untrusted verifier should deny enrollment",
    );
    ctx.assert_eq(
        &posture_result,
        &EnrollmentPostureResult::PostureVerifierNotAllowed,
        "Result should be PostureVerifierNotAllowed",
    );
    ctx.assert_eq(
        &posture_result.to_reason_code(),
        &DecisionReasonCode::PostureVerifierNotAllowed,
        "Reason code should be PostureVerifierNotAllowed",
    );

    ctx.finalize("pass");
}

// ─────────────────────────────────────────────────────────────────────────────
// E2E Test: Enrollment with insufficient posture is denied
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn e2e_enrollment_with_insufficient_posture_denied() {
    let mut ctx = E2ETestContext::new("e2e_enrollment_with_insufficient_posture_denied");

    ctx.log_phase(
        "setup",
        Some(json!({
            "description": "Attempt enrollment with posture missing required attribute",
            "zone_id": "z:owner"
        })),
    );

    let node_id = NodeId::new("device-insufficient-posture");
    let mut attestation = create_valid_attestation(&node_id);
    // Remove disk encryption from attestation
    attestation
        .attributes
        .remove(&PostureAttributeKey::DiskEncryption);

    let requirements = create_zone_posture_requirements();

    ctx.log_phase(
        "execute",
        Some(json!({
            "has_disk_encryption": false,
            "requires_disk_encryption": true
        })),
    );

    let posture_result = validate_enrollment_posture(Some(&requirements), Some(&attestation));

    ctx.assert_true(
        !posture_result.is_allowed(),
        "Missing disk encryption should deny enrollment",
    );

    match &posture_result {
        EnrollmentPostureResult::PostureRequirementNotMet { attribute } => {
            ctx.assert_eq(
                attribute,
                &PostureAttributeKey::DiskEncryption,
                "Failed attribute should be DiskEncryption",
            );
        }
        other => panic!("Expected PostureRequirementNotMet, got {other:?}"),
    }

    ctx.assert_eq(
        &posture_result.to_reason_code(),
        &DecisionReasonCode::PostureRequirementNotMet,
        "Reason code should be PostureRequirementNotMet",
    );

    ctx.finalize("pass");
}

// ─────────────────────────────────────────────────────────────────────────────
// E2E Test: Enrollment in zone without posture requirements succeeds
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn e2e_enrollment_without_posture_requirements_succeeds() {
    let mut ctx = E2ETestContext::new("e2e_enrollment_without_posture_requirements_succeeds");

    ctx.log_phase(
        "setup",
        Some(json!({
            "description": "Enrollment in zone without posture requirements",
            "zone_id": "z:work",
            "requires_posture": false
        })),
    );

    let (signing_secret, signing_key, encryption_key, issuance_key, owner_key) = create_test_keys();
    let device_id = "device-no-posture-required";

    let request = DeviceEnrollmentRequest::new(
        device_id,
        signing_key,
        encryption_key,
        issuance_key,
        DeviceMetadata::new().with_display_name("Test Device"),
        &signing_secret,
    )
    .expect("create enrollment request");

    ctx.log_phase(
        "execute",
        Some(json!({
            "device_id": device_id,
            "posture_required": false,
            "attestation_provided": false
        })),
    );

    // No posture requirements for this zone
    let posture_result = validate_enrollment_posture(None, None);

    ctx.assert_true(
        posture_result.is_allowed(),
        "Enrollment should be allowed without posture requirements",
    );
    ctx.assert_eq(
        &posture_result.to_reason_code(),
        &DecisionReasonCode::Allow,
        "Reason code should be Allowed",
    );

    // Create enrollment approval
    let manifest = create_test_manifest_for_zone(ZoneId::work());
    let approval = DeviceEnrollmentApproval::sign(
        &owner_key,
        &request,
        ZoneId::work(),
        vec!["fcp:zone:work".into()],
        manifest,
        168,
    )
    .expect("create enrollment approval");

    ctx.assert_true(
        approval.verify(&owner_key.verifying_key()).is_ok(),
        "Enrollment approval should be valid",
    );
    ctx.assert_eq(
        &approval.zone_id,
        &ZoneId::work(),
        "Approval should be for z:work",
    );

    ctx.finalize("pass");
}

// ─────────────────────────────────────────────────────────────────────────────
// E2E Test: Full enrollment flow with posture validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn e2e_full_enrollment_flow_with_posture() {
    let mut ctx = E2ETestContext::new("e2e_full_enrollment_flow_with_posture");

    ctx.log_phase(
        "setup",
        Some(json!({
            "description": "Full enrollment flow: request -> posture validation -> approval",
            "scenario": "happy_path"
        })),
    );

    // Step 1: Device generates keys
    let (signing_secret, signing_key, encryption_key, issuance_key, owner_key) = create_test_keys();
    let device_id = "device-full-flow";
    let node_id = NodeId::new(device_id);

    // Step 2: Device creates enrollment request
    let request = DeviceEnrollmentRequest::new(
        device_id,
        signing_key.clone(),
        encryption_key.clone(),
        issuance_key,
        DeviceMetadata::new()
            .with_display_name("Full Flow Device")
            .with_os("macOS 14.2.1")
            .with_hostname("device.local"),
        &signing_secret,
    )
    .expect("create enrollment request");

    // Verify proof of possession
    ctx.assert_true(
        request.verify_proof().is_ok(),
        "Enrollment request proof should be valid",
    );

    // Step 3: Device obtains posture attestation
    let attestation = create_valid_attestation(&node_id);

    ctx.log_phase(
        "execute",
        Some(json!({
            "step": "posture_validation",
            "device_id": device_id,
            "attestation_id": attestation.attestation_id
        })),
    );

    // Step 4: Validate posture against zone requirements
    let requirements = create_zone_posture_requirements();
    let posture_result = validate_enrollment_posture(Some(&requirements), Some(&attestation));

    ctx.assert_true(
        posture_result.is_allowed(),
        "Posture should be satisfied for enrollment",
    );

    // Step 5: Owner approves enrollment
    let manifest = create_test_manifest(&owner_key);
    let approval = DeviceEnrollmentApproval::sign(
        &owner_key,
        &request,
        ZoneId::owner(),
        vec!["fcp:zone:owner".into()],
        manifest.clone(),
        168,
    )
    .expect("create enrollment approval");

    ctx.log_phase(
        "verify",
        Some(json!({
            "step": "approval_verification",
            "approval_zone": approval.zone_id.as_str(),
            "approval_valid": approval.verify(&owner_key.verifying_key()).is_ok()
        })),
    );

    // Verify approval
    ctx.assert_true(
        approval.verify(&owner_key.verifying_key()).is_ok(),
        "Enrollment approval should verify against owner key",
    );

    // Verify device received correct keys
    ctx.assert_eq(
        &approval.device_id.as_str(),
        &device_id,
        "Device ID should match",
    );
    ctx.assert_eq(
        &approval.signing_key.key_id(),
        &signing_key.key_id(),
        "Signing key should match",
    );
    ctx.assert_eq(
        &approval.encryption_key.key_id(),
        &encryption_key.key_id(),
        "Encryption key should match",
    );
    ctx.assert_eq(
        &approval.initial_manifest.zone_key_id,
        &manifest.zone_key_id,
        "Zone key manifest should match",
    );

    ctx.finalize("pass");
}
