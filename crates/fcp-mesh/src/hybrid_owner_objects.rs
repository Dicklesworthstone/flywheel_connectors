//! Mesh ingress helpers for V4 hybrid owner-governed objects.
//!
//! These helpers are the fail-closed boundary mesh callers use before
//! accepting owner-governed state during the V3 to V4 cutover.

use fcp_core::{AuditEvent, AuditHead, CapabilityToken, NodeId, NodeSignature, ZoneId};
use fcp_evidence::{
    FcpCryptoMlDsa65Verifier, HybridOwnerObjectKind, HybridOwnerObjectSignatures,
    HybridOwnerObjectTranscript, HybridOwnerObjectVerificationError,
    HybridOwnerObjectVerificationReceipt, MlDsa65VerifyingKeyBytes, OwnerKeyMigrationAttestation,
    OwnerMigrationVerificationContext, verify_hybrid_owner_object,
};
use serde::Serialize;
use thiserror::Error;

/// Verified V3 to V4 owner authority for one mesh owner-governed object flow.
#[derive(Debug, Clone)]
pub struct MeshHybridOwnerAuthority {
    /// Cross-signed V3 to V4 owner-key migration bridge.
    pub migration_attestation: OwnerKeyMigrationAttestation,
    /// Accepted V4 ML-DSA-65 owner key.
    pub v4_verifying_key: MlDsa65VerifyingKeyBytes,
    /// Migration verification context, including trusted V3 roots and time.
    pub migration_context: OwnerMigrationVerificationContext,
}

impl MeshHybridOwnerAuthority {
    /// Build a mesh hybrid-owner authority.
    #[must_use]
    pub fn new(
        migration_attestation: OwnerKeyMigrationAttestation,
        v4_verifying_key: MlDsa65VerifyingKeyBytes,
        migration_context: OwnerMigrationVerificationContext,
    ) -> Self {
        Self {
            migration_attestation,
            v4_verifying_key,
            migration_context,
        }
    }
}

/// Mesh-side verification error for hybrid owner-governed objects.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MeshHybridOwnerObjectError {
    /// Canonical object payload serialization failed.
    #[error("hybrid owner object payload serialization failed: {0}")]
    PayloadSerialization(String),

    /// Embedded legacy V3 signature field did not match the hybrid V3 signature.
    #[error("zone-key manifest embedded V3 signature does not match hybrid owner signature")]
    LegacyV3SignatureMismatch,

    /// The evidence-layer hybrid owner-object verifier rejected the object.
    #[error(transparent)]
    Verification(#[from] HybridOwnerObjectVerificationError),
}

/// Verify a zone-key manifest against the V3/V4 hybrid owner authority.
///
/// The legacy `signature` field is normalized out of the signed payload and is
/// required to match the V3 signature carried in `signatures`, so callers cannot
/// accept a shadow edge where the object claims one issuer while the hybrid
/// envelope proves another.
///
/// # Errors
///
/// Returns [`MeshHybridOwnerObjectError`] when serialization or hybrid
/// signature verification fails.
pub fn verify_zone_key_manifest_hybrid_owner(
    manifest: &fcp_core::ZoneKeyManifest,
    signatures: &HybridOwnerObjectSignatures,
    authority: &MeshHybridOwnerAuthority,
) -> Result<HybridOwnerObjectVerificationReceipt, MeshHybridOwnerObjectError> {
    if manifest.signature.signature != signatures.signed_with_v3.to_bytes() {
        return Err(MeshHybridOwnerObjectError::LegacyV3SignatureMismatch);
    }
    let payload = zone_key_manifest_owner_payload(manifest)?;
    verify_owner_governed_payload_hybrid_owner(
        HybridOwnerObjectKind::ZoneKeyManifest,
        &manifest.zone_id,
        &payload,
        signatures,
        authority,
    )
}

/// Verify a capability token as an owner-governed V4 object before token-state
/// validation consumes the token for authorization.
///
/// # Errors
///
/// Returns [`MeshHybridOwnerObjectError`] when token serialization or hybrid
/// signature verification fails.
pub fn verify_capability_token_hybrid_owner<S>(
    zone_id: &ZoneId,
    token: &CapabilityToken<S>,
    signatures: &HybridOwnerObjectSignatures,
    authority: &MeshHybridOwnerAuthority,
) -> Result<HybridOwnerObjectVerificationReceipt, MeshHybridOwnerObjectError> {
    let payload = token
        .raw()
        .to_cbor()
        .map_err(|err| MeshHybridOwnerObjectError::PayloadSerialization(err.to_string()))?;
    verify_owner_governed_payload_hybrid_owner(
        HybridOwnerObjectKind::CapabilityToken,
        zone_id,
        &payload,
        signatures,
        authority,
    )
}

/// Verify an audit-chain event against the V3/V4 hybrid owner authority.
///
/// The executing-node signature is normalized out before hashing; the hybrid
/// owner signature authorizes the audit record content, while the node
/// signature remains a separate execution proof.
///
/// # Errors
///
/// Returns [`MeshHybridOwnerObjectError`] when serialization or hybrid
/// signature verification fails.
pub fn verify_audit_event_hybrid_owner(
    event: &AuditEvent,
    signatures: &HybridOwnerObjectSignatures,
    authority: &MeshHybridOwnerAuthority,
) -> Result<HybridOwnerObjectVerificationReceipt, MeshHybridOwnerObjectError> {
    let payload = audit_event_owner_payload(event)?;
    verify_owner_governed_payload_hybrid_owner(
        HybridOwnerObjectKind::AuditEvent,
        &event.zone_id,
        &payload,
        signatures,
        authority,
    )
}

/// Verify an audit-chain head checkpoint against the V3/V4 hybrid owner
/// authority.
///
/// # Errors
///
/// Returns [`MeshHybridOwnerObjectError`] when serialization or hybrid
/// signature verification fails.
pub fn verify_audit_head_hybrid_owner(
    head: &AuditHead,
    signatures: &HybridOwnerObjectSignatures,
    authority: &MeshHybridOwnerAuthority,
) -> Result<HybridOwnerObjectVerificationReceipt, MeshHybridOwnerObjectError> {
    let payload = canonical_cbor(head)?;
    verify_owner_governed_payload_hybrid_owner(
        HybridOwnerObjectKind::AuditHead,
        &head.zone_id,
        &payload,
        signatures,
        authority,
    )
}

/// Verify canonical owner-governed payload bytes with the hybrid owner-object
/// verifier.
///
/// # Errors
///
/// Returns [`MeshHybridOwnerObjectError`] when the evidence-layer verifier
/// rejects the migration bridge or object signatures.
pub fn verify_owner_governed_payload_hybrid_owner(
    kind: HybridOwnerObjectKind,
    zone_id: &ZoneId,
    payload: &[u8],
    signatures: &HybridOwnerObjectSignatures,
    authority: &MeshHybridOwnerAuthority,
) -> Result<HybridOwnerObjectVerificationReceipt, MeshHybridOwnerObjectError> {
    let transcript = HybridOwnerObjectTranscript::new(kind, zone_id.clone(), payload);
    verify_hybrid_owner_object(
        &transcript,
        signatures,
        &authority.migration_attestation,
        &authority.v4_verifying_key,
        &authority.migration_context,
        &FcpCryptoMlDsa65Verifier,
    )
    .map_err(MeshHybridOwnerObjectError::from)
}

fn zone_key_manifest_owner_payload(
    manifest: &fcp_core::ZoneKeyManifest,
) -> Result<Vec<u8>, MeshHybridOwnerObjectError> {
    let mut unsigned = manifest.clone();
    unsigned.signature = normalized_signature(&manifest.signature);
    canonical_cbor(&unsigned)
}

fn audit_event_owner_payload(event: &AuditEvent) -> Result<Vec<u8>, MeshHybridOwnerObjectError> {
    let mut unsigned = event.clone();
    unsigned.signature = normalized_signature(&event.signature);
    canonical_cbor(&unsigned)
}

fn normalized_signature(signature: &NodeSignature) -> NodeSignature {
    NodeSignature::new(NodeId::new(signature.node_id.as_str()), [0_u8; 64], 0)
}

fn canonical_cbor<T>(value: &T) -> Result<Vec<u8>, MeshHybridOwnerObjectError>
where
    T: Serialize,
{
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)
        .map_err(|err| MeshHybridOwnerObjectError::PayloadSerialization(err.to_string()))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use fcp_core::{
        AuditEvent, AuditHead, CapabilityConstraints, CapabilityToken, CorrelationId, EpochId,
        NodeId, NodeSignature, ObjectHeader, ObjectId, ObjectIdKeyId, OperationId, PrincipalId,
        Provenance, SignatureSet, ZoneId, ZoneKemAlgorithm, ZoneKeyAlgorithm, ZoneKeyId,
        ZoneKeyManifest,
    };
    use fcp_crypto::{Ed25519SigningKey, MlDsa65SigningKey, cose::CapabilityTokenBuilder};
    use fcp_evidence::{
        HybridOwnerObjectKind, HybridOwnerObjectSignatures, MlDsa65SignatureBytes,
        MlDsa65VerifyingKeyBytes, OwnerKeyMigrationAttestation, OwnerKeyMigrationTranscript,
        OwnerMigrationVerificationContext, TrustedV3OwnerMap,
    };

    use super::*;

    struct HybridObjectFixture {
        v3_signing_key: Ed25519SigningKey,
        v4_signing_key: MlDsa65SigningKey,
        authority: MeshHybridOwnerAuthority,
    }

    impl HybridObjectFixture {
        fn new() -> Self {
            let v3_signing_key = Ed25519SigningKey::generate();
            let v4_signing_key = MlDsa65SigningKey::generate().expect("generate ML-DSA-65 key");
            let v4_verifying_key = evidence_v4_key(&v4_signing_key);
            let prior_v3_attestation = b"mesh-last-v3-owner-state".to_vec();
            let new_v4_attestation = b"mesh-first-v4-owner-state".to_vec();
            let migration_transcript = OwnerKeyMigrationTranscript::new(
                v3_signing_key.verifying_key().key_id(),
                v4_verifying_key.key_id(),
                blake3_hash(&prior_v3_attestation),
                blake3_hash(&new_v4_attestation),
                19,
                1_700_000_000,
                1_800_000_000,
            );
            let migration_bytes = migration_transcript.signing_bytes();
            let migration_attestation = OwnerKeyMigrationAttestation::new(
                migration_transcript,
                v3_signing_key.sign(&migration_bytes),
                evidence_v4_signature(
                    &v4_signing_key
                        .sign_deterministic(&migration_bytes, b"")
                        .expect("sign migration bridge"),
                ),
            );
            let migration_context = OwnerMigrationVerificationContext::new(
                TrustedV3OwnerMap::from_keys([v3_signing_key.verifying_key()]),
                prior_v3_attestation,
                new_v4_attestation,
                18,
                1_750_000_000,
            );
            let authority = MeshHybridOwnerAuthority::new(
                migration_attestation,
                v4_verifying_key,
                migration_context,
            );
            Self {
                v3_signing_key,
                v4_signing_key,
                authority,
            }
        }

        fn sign(
            &self,
            kind: HybridOwnerObjectKind,
            zone_id: &ZoneId,
            payload: &[u8],
        ) -> HybridOwnerObjectSignatures {
            let transcript = HybridOwnerObjectTranscript::new(kind, zone_id.clone(), payload);
            let signing_bytes = transcript.signing_bytes();
            HybridOwnerObjectSignatures::new(
                self.v3_signing_key.sign(&signing_bytes),
                evidence_v4_signature(
                    &self
                        .v4_signing_key
                        .sign_deterministic(&signing_bytes, b"")
                        .expect("sign hybrid owner object"),
                ),
            )
        }
    }

    fn evidence_v4_key(signing_key: &MlDsa65SigningKey) -> MlDsa65VerifyingKeyBytes {
        MlDsa65VerifyingKeyBytes::try_from_bytes(signing_key.verifying_key().as_bytes().to_vec())
            .expect("valid evidence ML-DSA-65 key")
    }

    fn evidence_v4_signature(
        signature: &fcp_crypto::owner_key::MlDsa65SignatureBytes,
    ) -> MlDsa65SignatureBytes {
        MlDsa65SignatureBytes::try_from_bytes(signature.as_bytes().to_vec())
            .expect("valid evidence ML-DSA-65 signature")
    }

    fn blake3_hash(bytes: &[u8]) -> [u8; 32] {
        *blake3::hash(bytes).as_bytes()
    }

    fn object_header(zone_id: ZoneId, name: &'static str) -> ObjectHeader {
        ObjectHeader {
            encryption_kind: Default::default(),
            schema: fcp_cbor::SchemaId::new("fcp.mesh", name, semver::Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 1_700_000_000,
            provenance: Provenance::new(zone_id),
            refs: Vec::new(),
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        }
    }

    fn test_zone_key_manifest(zone_id: ZoneId) -> ZoneKeyManifest {
        ZoneKeyManifest {
            header: object_header(zone_id.clone(), "ZoneKeyManifest"),
            zone_id,
            zone_key_id: ZoneKeyId([0x11; 8]),
            object_id_key_id: ObjectIdKeyId([0x22; 8]),
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: 1_700_000_000,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: Vec::new(),
            wrapped_object_id_keys: Vec::new(),
            rekey_policy: None,
            signature: NodeSignature::new(NodeId::new("zone-owner"), [0_u8; 64], 0),
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: Vec::new(),
        }
    }

    fn test_capability_object(zone_id: &ZoneId) -> CapabilityToken {
        let signing_key = Ed25519SigningKey::generate();
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".to_string()],
            ..Default::default()
        };
        let mut constraints_cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut constraints_cbor).expect("encode constraints");
        let now = Utc::now();
        let cose = CapabilityTokenBuilder::new()
            .capability_id("cap.hybrid-owner")
            .zone_id(zone_id.as_str())
            .principal("principalowner")
            .operations(&["op.hybrid-owner"])
            .issuer("node.owner")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&constraints_cbor)
            .expect("valid constraints cbor")
            .sign(&signing_key)
            .expect("sign real capability object");
        CapabilityToken::from_raw(cose)
    }

    fn test_audit_event(zone_id: ZoneId) -> AuditEvent {
        AuditEvent {
            header: object_header(zone_id.clone(), "AuditEvent"),
            correlation_id: CorrelationId::new(),
            trace_context: None,
            event_type: "capability.invoke".to_string(),
            actor: PrincipalId::new("principalowner").expect("principal id"),
            zone_id,
            connector_id: None,
            operation: Some(OperationId::from_static("ophybridowner")),
            capability_token_jti: None,
            request_object_id: Some(ObjectId::from_bytes([0x33; 32])),
            result_object_id: None,
            prev: None,
            seq: 0,
            occurred_at: 1_700_000_000,
            signature: NodeSignature::new(NodeId::new("executor"), [0x44; 64], 1_700_000_000),
        }
    }

    fn test_audit_head(zone_id: ZoneId) -> AuditHead {
        AuditHead {
            header: object_header(zone_id.clone(), "AuditHead"),
            zone_id,
            head_event: ObjectId::from_bytes([0x55; 32]),
            head_seq: 12,
            coverage: 1.0,
            epoch_id: EpochId::new("epoch-12"),
            quorum_signatures: SignatureSet::new(),
        }
    }

    #[test]
    fn hybrid_owner_objects_verify_zone_manifest_token_and_audit_chain() {
        let fixture = HybridObjectFixture::new();
        let zone_id = ZoneId::work();

        let mut manifest = test_zone_key_manifest(zone_id.clone());
        let manifest_payload = zone_key_manifest_owner_payload(&manifest).expect("payload");
        let manifest_signatures = fixture.sign(
            HybridOwnerObjectKind::ZoneKeyManifest,
            &zone_id,
            &manifest_payload,
        );
        manifest.signature = NodeSignature::new(
            NodeId::new("zone-owner"),
            manifest_signatures.signed_with_v3.to_bytes(),
            1_700_000_000,
        );
        let manifest_receipt = verify_zone_key_manifest_hybrid_owner(
            &manifest,
            &manifest_signatures,
            &fixture.authority,
        )
        .expect("manifest hybrid owner verification");
        assert_eq!(
            manifest_receipt.kind,
            HybridOwnerObjectKind::ZoneKeyManifest
        );

        let capability = test_capability_object(&zone_id);
        let capability_payload = capability.raw().to_cbor().expect("capability cbor");
        let capability_signatures = fixture.sign(
            HybridOwnerObjectKind::CapabilityToken,
            &zone_id,
            &capability_payload,
        );
        let capability_receipt = verify_capability_token_hybrid_owner(
            &zone_id,
            &capability,
            &capability_signatures,
            &fixture.authority,
        )
        .expect("capability hybrid owner verification");
        assert_eq!(
            capability_receipt.kind,
            HybridOwnerObjectKind::CapabilityToken
        );

        let audit_event = test_audit_event(zone_id.clone());
        let audit_event_payload = audit_event_owner_payload(&audit_event).expect("payload");
        let audit_event_signatures = fixture.sign(
            HybridOwnerObjectKind::AuditEvent,
            &zone_id,
            &audit_event_payload,
        );
        let audit_event_receipt = verify_audit_event_hybrid_owner(
            &audit_event,
            &audit_event_signatures,
            &fixture.authority,
        )
        .expect("audit event hybrid owner verification");
        assert_eq!(audit_event_receipt.kind, HybridOwnerObjectKind::AuditEvent);

        let audit_head = test_audit_head(zone_id.clone());
        let audit_head_payload = canonical_cbor(&audit_head).expect("payload");
        let audit_head_signatures = fixture.sign(
            HybridOwnerObjectKind::AuditHead,
            &zone_id,
            &audit_head_payload,
        );
        let audit_head_receipt =
            verify_audit_head_hybrid_owner(&audit_head, &audit_head_signatures, &fixture.authority)
                .expect("audit head hybrid owner verification");
        assert_eq!(audit_head_receipt.kind, HybridOwnerObjectKind::AuditHead);
    }

    #[test]
    fn hybrid_owner_objects_reject_manifest_shadow_signature_claim() {
        let fixture = HybridObjectFixture::new();
        let zone_id = ZoneId::work();
        let manifest = test_zone_key_manifest(zone_id.clone());
        let payload = zone_key_manifest_owner_payload(&manifest).expect("payload");
        let signatures = fixture.sign(HybridOwnerObjectKind::ZoneKeyManifest, &zone_id, &payload);

        let error =
            verify_zone_key_manifest_hybrid_owner(&manifest, &signatures, &fixture.authority)
                .expect_err("embedded shadow signature must be rejected");

        assert_eq!(error, MeshHybridOwnerObjectError::LegacyV3SignatureMismatch);
    }
}
