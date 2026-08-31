//! Post-quantum conformance: hybrid owner signatures bind V3 and V4 manifests.

use fcp_core::{
    NodeId, NodeSignature, ObjectHeader, ObjectIdKeyId, Provenance, TailscaleNodeId,
    WrappedZoneKey, ZoneId, ZoneKemAlgorithm, ZoneKeyAlgorithm, ZoneKeyId, ZoneKeyManifest,
};
use fcp_crypto::{Ed25519SigningKey, HpkeSealedBox, MlDsa65SigningKey};
use fcp_evidence::{
    FcpCryptoMlDsa65Verifier, HybridOwnerObjectKind, HybridOwnerObjectSignatures,
    HybridOwnerObjectTranscript, HybridOwnerObjectVerificationError, MlDsa65SignatureBytes,
    MlDsa65VerifyingKeyBytes, OwnerKeyMigrationAttestation, OwnerKeyMigrationTranscript,
    OwnerMigrationVerificationContext, TrustedV3OwnerMap, verify_hybrid_owner_object,
};
use semver::Version;

const ISSUED_AT: u64 = 1_700_000_000;

struct HybridOwnerFixture {
    v3_owner: Ed25519SigningKey,
    v4_owner: MlDsa65SigningKey,
    v4_verifying_key: MlDsa65VerifyingKeyBytes,
    migration_attestation: OwnerKeyMigrationAttestation,
    context: OwnerMigrationVerificationContext,
}

fn header(zone_id: &ZoneId) -> ObjectHeader {
    ObjectHeader {
        encryption_kind: Default::default(),
        schema: fcp_cbor::SchemaId::new("fcp.zone", "ZoneKeyManifest", Version::new(1, 0, 0)),
        zone_id: zone_id.clone(),
        created_at: ISSUED_AT,
        provenance: Provenance::new(zone_id.clone()),
        refs: Vec::new(),
        foreign_refs: Vec::new(),
        ttl_secs: None,
        placement: None,
    }
}

fn signature() -> NodeSignature {
    NodeSignature::new(NodeId::new("owner-node"), [0x11; 64], ISSUED_AT)
}

fn v3_manifest() -> ZoneKeyManifest {
    let zone_id = ZoneId::work();
    let recipient = TailscaleNodeId::new("pq-owner-recipient");
    ZoneKeyManifest {
        header: header(&zone_id),
        zone_id,
        zone_key_id: ZoneKeyId::from_bytes([0x21; 8]),
        object_id_key_id: ObjectIdKeyId::from_bytes([0x22; 8]),
        algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
        valid_from: ISSUED_AT,
        valid_until: None,
        prev_zone_key_id: None,
        wrapped_keys: vec![WrappedZoneKey {
            recipient,
            issued_at: ISSUED_AT,
            sealed: HpkeSealedBox {
                enc: vec![0x31; 32],
                ciphertext: vec![0x32; 48],
            },
        }],
        wrapped_object_id_keys: Vec::new(),
        rekey_policy: None,
        signature: signature(),
        kem: ZoneKemAlgorithm::HpkeX25519,
        wrapped_keys_v4: Vec::new(),
    }
}

fn evidence_v4_key(signing_key: &MlDsa65SigningKey) -> MlDsa65VerifyingKeyBytes {
    MlDsa65VerifyingKeyBytes::try_from_bytes(signing_key.verifying_key().as_bytes().to_vec())
        .expect("valid ML-DSA-65 evidence verifying key")
}

fn evidence_v4_signature(signature: &fcp_crypto::MlDsa65SignatureBytes) -> MlDsa65SignatureBytes {
    MlDsa65SignatureBytes::try_from_bytes(signature.as_bytes().to_vec())
        .expect("valid ML-DSA-65 evidence signature")
}

impl HybridOwnerFixture {
    fn new(v3_payload: &[u8], v4_payload: &[u8]) -> Self {
        let v3_owner =
            Ed25519SigningKey::from_bytes(&[0x41; 32]).expect("deterministic Ed25519 key");
        let v4_owner =
            MlDsa65SigningKey::from_seed(&[0x42; 32]).expect("deterministic ML-DSA-65 key");
        let v4_verifying_key = evidence_v4_key(&v4_owner);
        let transcript = OwnerKeyMigrationTranscript::new(
            v3_owner.verifying_key().key_id(),
            v4_verifying_key.key_id(),
            *blake3::hash(v3_payload).as_bytes(),
            *blake3::hash(v4_payload).as_bytes(),
            9,
            1_700_000_000,
            1_800_000_000,
        );
        let signing_bytes = transcript.signing_bytes();
        let migration_attestation = OwnerKeyMigrationAttestation::new(
            transcript,
            v3_owner.sign(&signing_bytes),
            evidence_v4_signature(
                &v4_owner
                    .sign_deterministic(&signing_bytes, b"")
                    .expect("ML-DSA migration signature"),
            ),
        );
        let context = OwnerMigrationVerificationContext::new(
            TrustedV3OwnerMap::from_keys([v3_owner.verifying_key()]),
            v3_payload.to_vec(),
            v4_payload.to_vec(),
            8,
            1_750_000_000,
        );
        Self {
            v3_owner,
            v4_owner,
            v4_verifying_key,
            migration_attestation,
            context,
        }
    }

    fn sign(&self, transcript: &HybridOwnerObjectTranscript) -> HybridOwnerObjectSignatures {
        let signing_bytes = transcript.signing_bytes();
        HybridOwnerObjectSignatures::new(
            self.v3_owner.sign(&signing_bytes),
            evidence_v4_signature(
                &self
                    .v4_owner
                    .sign_deterministic(&signing_bytes, b"")
                    .expect("ML-DSA object signature"),
            ),
        )
    }

    fn verify(
        &self,
        transcript: &HybridOwnerObjectTranscript,
        signatures: &HybridOwnerObjectSignatures,
    ) -> Result<(), HybridOwnerObjectVerificationError> {
        verify_hybrid_owner_object(
            transcript,
            signatures,
            &self.migration_attestation,
            &self.v4_verifying_key,
            &self.context,
            &FcpCryptoMlDsa65Verifier,
        )
        .map(|_| ())
    }
}

#[test]
fn ml_dsa_65_and_ed25519_hybrid_signatures_verify_for_v3_and_v4_manifest_payloads() {
    let v3 = v3_manifest();
    // br-z8bsg: migrated_to_v4 returns UnsignedV4Manifest; serialise
    // its inner payload via .as_payload(). The hybrid signatures
    // computed below are exactly what an owner would sign over the
    // pre-publication payload.
    let v4 = v3.migrated_to_v4(ZoneKemAlgorithm::XWing);
    let v3_payload = fcp_cbor::to_canonical_cbor(&v3).expect("V3 manifest canonical CBOR");
    let v4_payload =
        fcp_cbor::to_canonical_cbor(v4.as_payload()).expect("V4 manifest canonical CBOR");
    let fixture = HybridOwnerFixture::new(&v3_payload, &v4_payload);

    for (name, payload) in [("v3-manifest", &v3_payload), ("v4-manifest", &v4_payload)] {
        let transcript = HybridOwnerObjectTranscript::new(
            HybridOwnerObjectKind::ZoneKeyManifest,
            ZoneId::work(),
            payload,
        );
        let signatures = fixture.sign(&transcript);
        fixture
            .verify(&transcript, &signatures)
            .unwrap_or_else(|err| panic!("{name} hybrid owner signatures rejected: {err:?}"));
    }
}

#[test]
fn hybrid_owner_manifest_signatures_reject_cross_payload_swaps() {
    let v3 = v3_manifest();
    // br-z8bsg: migrated_to_v4 returns UnsignedV4Manifest; serialise
    // its inner payload via .as_payload(). The hybrid signatures
    // computed below are exactly what an owner would sign over the
    // pre-publication payload.
    let v4 = v3.migrated_to_v4(ZoneKemAlgorithm::XWing);
    let v3_payload = fcp_cbor::to_canonical_cbor(&v3).expect("V3 manifest canonical CBOR");
    let v4_payload =
        fcp_cbor::to_canonical_cbor(v4.as_payload()).expect("V4 manifest canonical CBOR");
    let fixture = HybridOwnerFixture::new(&v3_payload, &v4_payload);

    let v3_transcript = HybridOwnerObjectTranscript::new(
        HybridOwnerObjectKind::ZoneKeyManifest,
        ZoneId::work(),
        &v3_payload,
    );
    let v4_transcript = HybridOwnerObjectTranscript::new(
        HybridOwnerObjectKind::ZoneKeyManifest,
        ZoneId::work(),
        &v4_payload,
    );
    let v3_signatures = fixture.sign(&v3_transcript);
    let v4_signatures = fixture.sign(&v4_transcript);

    let v3_signature_on_v4_manifest = HybridOwnerObjectSignatures::new(
        v3_signatures.signed_with_v3,
        v4_signatures.signed_with_v4.clone(),
    );
    let err = fixture
        .verify(&v4_transcript, &v3_signature_on_v4_manifest)
        .expect_err("V3 signature over V3 payload must not authorize V4 manifest");
    assert_eq!(
        err,
        HybridOwnerObjectVerificationError::V3ObjectSignatureRejected
    );

    let v4_signature_on_v3_manifest = HybridOwnerObjectSignatures::new(
        v4_signatures.signed_with_v3,
        v3_signatures.signed_with_v4,
    );
    let err = fixture
        .verify(&v4_transcript, &v4_signature_on_v3_manifest)
        .expect_err("V4 signature over V3 payload must not authorize V4 manifest");
    assert_eq!(
        err,
        HybridOwnerObjectVerificationError::V4ObjectSignatureRejected
    );
}
