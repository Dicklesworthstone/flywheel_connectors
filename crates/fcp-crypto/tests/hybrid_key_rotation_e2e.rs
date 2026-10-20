//! End-to-end hybrid key rotation and Wesolowski VDF rate-limit ceremonies (`flywheel_connectors-angoc.8`).

use fcp_crypto::{
    CryptoResult, Ed25519SigningKey, HybridOwnerKeyIds, HybridOwnerSignature, HybridOwnerSigner,
    HybridSignedObjectKind, KeyId, MlDsa65SigningKey, OwnerKeyMigrationAttestation,
    OwnerKeyMigrationTranscript, PqSigningPolicy, SignedEnvelope, signing_bytes_for_payload,
    vdf::{VdfError, VdfParams, WesolowskiVdf},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EpochObjectPayload {
    epoch: u64,
    zone_id: String,
    statement: String,
}

struct SynchronizedHybridOwner {
    epoch: u64,
    ed25519: Ed25519SigningKey,
    ml_dsa_65: MlDsa65SigningKey,
}

impl SynchronizedHybridOwner {
    fn from_seeds(epoch: u64, ed25519_seed: [u8; 32], ml_dsa_seed: [u8; 32]) -> Self {
        Self {
            epoch,
            ed25519: Ed25519SigningKey::from_bytes(&ed25519_seed)
                .expect("Ed25519 seed must decode"),
            ml_dsa_65: MlDsa65SigningKey::from_seed(&ml_dsa_seed)
                .expect("ML-DSA-65 seed must decode"),
        }
    }

    fn sign_envelope(
        &self,
        kind: HybridSignedObjectKind,
        statement: &str,
    ) -> (SignedEnvelope<EpochObjectPayload>, Vec<u8>) {
        let payload = EpochObjectPayload {
            epoch: self.epoch,
            zone_id: "z:owner".to_string(),
            statement: statement.to_string(),
        };
        let signing_bytes =
            signing_bytes_for_payload(kind, &payload).expect("payload signing bytes must encode");
        let envelope = SignedEnvelope::sign(
            kind.as_str(),
            payload,
            &signing_bytes,
            &self.ed25519,
            &self.ml_dsa_65,
        )
        .expect("hybrid envelope signing must succeed");
        (envelope, signing_bytes)
    }
}

impl HybridOwnerSigner for SynchronizedHybridOwner {
    fn hybrid_owner_key_ids(&self) -> HybridOwnerKeyIds {
        let ed_pub = self.ed25519.verifying_key();
        let pq_pub = self.ml_dsa_65.verifying_key();
        HybridOwnerKeyIds {
            ed25519: KeyId::derive_from_public_key(&ed_pub.to_bytes()),
            ml_dsa_65: pq_pub.key_id(),
        }
    }

    fn sign_hybrid_owner(&self, transcript: &[u8]) -> CryptoResult<HybridOwnerSignature> {
        let ed25519 = self.ed25519.sign(transcript);
        let ml_dsa_65 = self
            .ml_dsa_65
            .sign(transcript, fcp_crypto::OWNER_KEY_MIGRATION_DOMAIN)?;
        Ok(HybridOwnerSignature { ed25519, ml_dsa_65 })
    }
}

#[test]
fn hybrid_key_rotation_synchronized_epoch_boundary_e2e() {
    let epoch1 = SynchronizedHybridOwner::from_seeds(1, [0x11; 32], [0x21; 32]);
    let epoch2 = SynchronizedHybridOwner::from_seeds(2, [0x33; 32], [0x44; 32]);

    // 1. Epoch 1 signs a ZoneCheckpoint envelope under steady-state BothRequired policy.
    let (epoch1_checkpoint, epoch1_bytes) =
        epoch1.sign_envelope(HybridSignedObjectKind::ZoneCheckpoint, "checkpoint-epoch-1");
    let epoch1_report = epoch1_checkpoint
        .verify(
            &epoch1_bytes,
            &epoch1.ed25519.verifying_key(),
            epoch1.ml_dsa_65.verifying_key(),
        )
        .expect("epoch 1 envelope must verify under epoch 1 keys");
    assert!(epoch1_report.signatures_verified.classical);
    assert!(epoch1_report.signatures_verified.pq);
    assert!(epoch1_report.warning.is_none());

    // 2. Synchronized rotation ceremony from Epoch 1 -> Epoch 2 cross-signs the migration transcript.
    let epoch1_ids = epoch1.hybrid_owner_key_ids();
    let epoch2_ids = epoch2.hybrid_owner_key_ids();
    assert_ne!(epoch1_ids.ed25519, epoch2_ids.ed25519);
    assert_ne!(epoch1_ids.ml_dsa_65, epoch2_ids.ml_dsa_65);

    let prior_hash = *blake3::hash(&epoch1_bytes).as_bytes();
    let new_hash = *blake3::hash(b"epoch-2-bootstrap-attestation").as_bytes();
    let transcript = OwnerKeyMigrationTranscript::new(
        epoch1_ids.ed25519,
        epoch2_ids.ml_dsa_65,
        prior_hash,
        new_hash,
        2,
        1_700_000_000,
        1_700_086_400,
    );
    let transcript_bytes = transcript.signing_bytes();

    // Prior V3/classical root signs the handoff; new V4/ML-DSA-65 root counter-signs.
    let prior_sig = epoch1
        .sign_hybrid_owner(&transcript_bytes)
        .expect("epoch 1 owner signing must succeed");
    let next_sig = epoch2
        .sign_hybrid_owner(&transcript_bytes)
        .expect("epoch 2 owner signing must succeed");
    let attestation =
        OwnerKeyMigrationAttestation::new(transcript, prior_sig.ed25519, next_sig.ml_dsa_65);

    epoch1
        .ed25519
        .verifying_key()
        .verify(
            &attestation.transcript.signing_bytes(),
            &attestation.signed_with_v3,
        )
        .expect("prior Ed25519 root must verify migration transcript");
    epoch2
        .ml_dsa_65
        .verifying_key()
        .verify(
            &attestation.transcript.signing_bytes(),
            fcp_crypto::OWNER_KEY_MIGRATION_DOMAIN,
            &attestation.signed_with_v4,
        )
        .expect("new ML-DSA-65 root must verify migration transcript");

    // 3. Epoch 2 signs new CapabilityToken and Revocation envelopes; Epoch 1 verifiers are rejected.
    let (epoch2_token, epoch2_bytes) =
        epoch2.sign_envelope(HybridSignedObjectKind::CapabilityToken, "cap-token-epoch-2");
    epoch2_token
        .verify(
            &epoch2_bytes,
            &epoch2.ed25519.verifying_key(),
            epoch2.ml_dsa_65.verifying_key(),
        )
        .expect("epoch 2 envelope must verify under epoch 2 keys");

    assert!(
        epoch2_token
            .verify(
                &epoch2_bytes,
                &epoch1.ed25519.verifying_key(),
                epoch1.ml_dsa_65.verifying_key(),
            )
            .is_err(),
        "stale epoch 1 verifiers must reject epoch 2 envelopes"
    );
}

#[test]
fn hybrid_key_rotation_rejects_unsynchronized_cross_epoch_key_pair() {
    let epoch1 = SynchronizedHybridOwner::from_seeds(1, [0x51; 32], [0x61; 32]);
    let epoch2 = SynchronizedHybridOwner::from_seeds(2, [0x71; 32], [0x81; 32]);

    let payload = EpochObjectPayload {
        epoch: 2,
        zone_id: "z:owner".to_string(),
        statement: "mismatched-rotation-attempt".to_string(),
    };
    let signing_bytes =
        signing_bytes_for_payload(HybridSignedObjectKind::Revocation, &payload).unwrap();

    // Sign with Epoch 2 Ed25519 but stale Epoch 1 ML-DSA-65 (simulating partial rotation or single-key compromise).
    let mismatched_pq = SignedEnvelope::sign(
        HybridSignedObjectKind::Revocation.as_str(),
        payload.clone(),
        &signing_bytes,
        &epoch2.ed25519,
        &epoch1.ml_dsa_65,
    )
    .unwrap();
    assert!(
        mismatched_pq
            .verify_with_policy(
                &signing_bytes,
                PqSigningPolicy::BothRequired,
                Some(&epoch2.ed25519.verifying_key()),
                Some(epoch2.ml_dsa_65.verifying_key()),
            )
            .is_err(),
        "steady-state BothRequired policy must reject envelope signed with stale ML-DSA-65 key"
    );

    // Symmetric: sign with stale Epoch 1 Ed25519 and Epoch 2 ML-DSA-65.
    let mismatched_classical = SignedEnvelope::sign(
        HybridSignedObjectKind::Revocation.as_str(),
        payload,
        &signing_bytes,
        &epoch1.ed25519,
        &epoch2.ml_dsa_65,
    )
    .unwrap();
    assert!(
        mismatched_classical
            .verify_with_policy(
                &signing_bytes,
                PqSigningPolicy::BothRequired,
                Some(&epoch2.ed25519.verifying_key()),
                Some(epoch2.ml_dsa_65.verifying_key()),
            )
            .is_err(),
        "steady-state BothRequired policy must reject envelope signed with stale Ed25519 key"
    );
}

#[test]
fn hybrid_key_rotation_with_wesolowski_vdf_rate_limit_proof() {
    let epoch1 = SynchronizedHybridOwner::from_seeds(1, [0x91; 32], [0xA1; 32]);
    let epoch2 = SynchronizedHybridOwner::from_seeds(2, [0xB1; 32], [0xC1; 32]);

    let transcript = OwnerKeyMigrationTranscript::new(
        epoch1.hybrid_owner_key_ids().ed25519,
        epoch2.hybrid_owner_key_ids().ml_dsa_65,
        [0xAA; 32],
        [0xBB; 32],
        2,
        1_700_000_000,
        1_700_086_400,
    );
    let challenge = transcript.signing_bytes();

    // Evaluate Wesolowski VDF over the canonical migration transcript bytes.
    let params = VdfParams::new(256).with_calibrated_floor_ms(0);
    let proof = WesolowskiVdf::eval(&challenge, params).expect("VDF evaluation must succeed");
    let verify_duration =
        WesolowskiVdf::verify(&challenge, 256, &proof).expect("VDF proof must verify");
    assert!(verify_duration.as_millis() < 50);

    // Replaying the VDF proof against a different epoch transcript must fail verification.
    let replayed_transcript = OwnerKeyMigrationTranscript::new(
        epoch1.hybrid_owner_key_ids().ed25519,
        epoch2.hybrid_owner_key_ids().ml_dsa_65,
        [0xAA; 32],
        [0xBB; 32],
        3,
        1_700_000_000,
        1_700_086_400,
    );
    let err = WesolowskiVdf::verify(&replayed_transcript.signing_bytes(), 256, &proof)
        .expect_err("VDF proof must not verify for a mutated migration epoch");
    assert_eq!(err, VdfError::VerificationFailed);
}
