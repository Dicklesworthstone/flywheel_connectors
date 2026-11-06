//! Fresh, process-bound evidence for the host's existing deployment classifier.
//!
//! An operator pins an independent health observer's public key for one host
//! subject and execution zone. The observer obtains the process challenge over
//! an authenticated admin channel and signs short-lived observations of real
//! peer health, lease-coordinator reachability and that zone's revocation
//! freshness. A signature authenticates the observer's statement; it does not
//! discover peers, prove the observations independently, or approve operations.
//!
//! The verifier preserves the existing signed-quorum classifier and all of its
//! thresholds. It adds host, zone, process, time and generation bindings. Callers
//! must treat every missing, unreadable, malformed or rejected evidence file as
//! Evaluation and must never fall back to a previously accepted classification.
//! Normal capability, policy, approval, placement and lease checks still apply.

use std::time::Instant;

use fcp_crypto::{
    aead::XChaCha20Nonce,
    ed25519::{Ed25519Signature, Ed25519SigningKey, Ed25519VerifyingKey},
    kid::KeyId,
};
use fcp_prelude::ZoneId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    DeploymentClassification, MeshQuorumSignals, SignedMeshQuorumSignals,
    classify_deployment_mode_verified,
};

/// Signed-envelope schema version. Changing the transcript requires a new domain.
pub const DEPLOYMENT_EVIDENCE_SCHEMA_VERSION: u16 = 1;
/// Domain separation for the complete deployment-health evidence envelope.
pub const DEPLOYMENT_EVIDENCE_DOMAIN: &[u8] = b"FCP3-HOST-DEPLOYMENT-EVIDENCE-V1";
/// Maximum signed observation lifetime, measured from issuance to expiration.
pub const MAX_DEPLOYMENT_EVIDENCE_LIFETIME_MS: u64 = 30_000;
/// Maximum observer clock lead accepted at the host.
pub const MAX_DEPLOYMENT_EVIDENCE_FUTURE_SKEW_MS: u64 = 5_000;
/// Maximum fixed host-subject label size.
pub const MAX_DEPLOYMENT_EVIDENCE_SUBJECT_BYTES: usize = 256;

/// Public descriptor for one host process and its independently pinned observer.
///
/// Obtain this descriptor through the host's authenticated admin surface. The
/// challenge is public, but must belong to the intended host and execution zone.
/// An observer must not sign arbitrary caller-supplied health claims or borrow
/// observations from another host, zone or historical snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentEvidenceChallenge {
    /// Version of the descriptor and signed evidence transcript.
    pub schema_version: u16,
    /// Immutable operator-selected host label.
    pub subject: String,
    /// Only this execution zone may use the resulting classification.
    pub zone_id: ZoneId,
    /// Unpredictable nonce generated afresh for this host process.
    pub challenge: [u8; 32],
    /// Key ID derived from the independently pinned observer public key.
    pub attesting_kid: KeyId,
    /// Maximum permitted signed lifetime; an observer may choose a shorter one.
    pub max_lifetime_ms: u64,
    /// Maximum permitted observer clock lead.
    pub max_future_skew_ms: u64,
}

/// A fresh health observation bound to a host process and execution zone.
///
/// Both signatures must use the independently pinned observer key. The outer
/// signature commits to all fields, including the existing signed quorum
/// snapshot and its signature. New signal semantics require new inner and outer
/// transcript domains; JSON field additions must not silently change authority.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedDeploymentEvidence {
    /// Signed-envelope schema version.
    pub schema_version: u16,
    /// Intended host label, exactly as advertised in the challenge.
    pub subject: String,
    /// Execution zone whose revocation freshness was observed.
    pub zone_id: ZoneId,
    /// Intended host process's unpredictable challenge.
    pub challenge: [u8; 32],
    /// Observation issuance time in Unix epoch milliseconds.
    pub issued_at_ms: u64,
    /// Exclusive expiration time in Unix epoch milliseconds.
    pub expires_at_ms: u64,
    /// Strictly increasing snapshot generation, beginning at one per challenge.
    pub generation: u64,
    /// Existing authenticated mesh-health snapshot.
    pub quorum: SignedMeshQuorumSignals,
    /// Ed25519 signature over the complete domain-separated transcript.
    pub signature: Ed25519Signature,
}

#[derive(Serialize)]
struct DeploymentEvidenceTranscript<'a> {
    schema_version: u16,
    subject: &'a str,
    zone_id: &'a ZoneId,
    challenge: &'a [u8; 32],
    issued_at_ms: u64,
    expires_at_ms: u64,
    generation: u64,
    quorum: &'a SignedMeshQuorumSignals,
}

impl SignedDeploymentEvidence {
    /// Sign genuine observations for the advertised host process and zone.
    ///
    /// The health observer is responsible for observing actual healthy peers
    /// excluding this host, lease-coordinator reachability and this zone's
    /// revocation freshness. Signing a supplied count is not health discovery.
    /// Increment generation for every new observation or renewed expiration.
    ///
    /// # Errors
    /// Rejects invalid descriptors, another signing key, zero generations,
    /// invalid time intervals and encoding failures.
    pub fn sign(
        descriptor: &DeploymentEvidenceChallenge,
        signals: MeshQuorumSignals,
        generation: u64,
        issued_at_ms: u64,
        expires_at_ms: u64,
        signing_key: &Ed25519SigningKey,
    ) -> Result<Self, DeploymentEvidenceError> {
        validate_subject(&descriptor.subject)?;
        if descriptor.schema_version != DEPLOYMENT_EVIDENCE_SCHEMA_VERSION
            || descriptor.max_lifetime_ms != MAX_DEPLOYMENT_EVIDENCE_LIFETIME_MS
            || descriptor.max_future_skew_ms != MAX_DEPLOYMENT_EVIDENCE_FUTURE_SKEW_MS
        {
            return Err(DeploymentEvidenceError::InvalidChallengeDescriptor);
        }
        if signing_key.key_id() != descriptor.attesting_kid {
            return Err(DeploymentEvidenceError::UnknownAttester);
        }
        let mut evidence = Self {
            schema_version: DEPLOYMENT_EVIDENCE_SCHEMA_VERSION,
            subject: descriptor.subject.clone(),
            zone_id: descriptor.zone_id.clone(),
            challenge: descriptor.challenge,
            issued_at_ms,
            expires_at_ms,
            generation,
            quorum: signals.sign(signing_key),
            signature: Ed25519Signature::from_bytes(&[0; 64]),
        };
        evidence.signature = signing_key.sign(&evidence.signing_bytes()?);
        Ok(evidence)
    }

    /// Canonical bytes authenticated by the outer signature.
    ///
    /// This is the domain constant followed by deterministic CBOR for every
    /// envelope field except the outer signature. The nested quorum signature
    /// is included. No JSON serialization choices influence the transcript.
    ///
    /// # Errors
    /// Rejects unsupported versions, invalid labels, zero generations, invalid
    /// lifetimes and deterministic-encoding failures.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, DeploymentEvidenceError> {
        self.validate_shape()?;
        let transcript = DeploymentEvidenceTranscript {
            schema_version: self.schema_version,
            subject: &self.subject,
            zone_id: &self.zone_id,
            challenge: &self.challenge,
            issued_at_ms: self.issued_at_ms,
            expires_at_ms: self.expires_at_ms,
            generation: self.generation,
            quorum: &self.quorum,
        };
        let encoded = fcp_cbor::to_canonical_cbor(&transcript)
            .map_err(|_| DeploymentEvidenceError::EncodingFailed)?;
        let mut bytes = Vec::with_capacity(DEPLOYMENT_EVIDENCE_DOMAIN.len() + encoded.len());
        bytes.extend_from_slice(DEPLOYMENT_EVIDENCE_DOMAIN);
        bytes.extend_from_slice(&encoded);
        Ok(bytes)
    }

    fn validate_shape(&self) -> Result<(), DeploymentEvidenceError> {
        if self.schema_version != DEPLOYMENT_EVIDENCE_SCHEMA_VERSION {
            return Err(DeploymentEvidenceError::UnsupportedVersion);
        }
        validate_subject(&self.subject)?;
        if self.generation == 0 {
            return Err(DeploymentEvidenceError::InvalidGeneration);
        }
        if !self
            .expires_at_ms
            .checked_sub(self.issued_at_ms)
            .is_some_and(|lifetime| (1..=MAX_DEPLOYMENT_EVIDENCE_LIFETIME_MS).contains(&lifetime))
        {
            return Err(DeploymentEvidenceError::InvalidLifetime);
        }
        Ok(())
    }
}

#[derive(Debug)]
struct EvidenceGeneration {
    generation: u64,
    transcript_digest: [u8; 32],
    conflicted: bool,
}

#[derive(Debug)]
struct EvidenceClock {
    epoch_ms: u64,
    observed_at: Instant,
}

/// Verifies fresh evidence for exactly one process, host subject and zone.
///
/// Keep one instance for the whole host process. Reconstructing this verifier
/// intentionally creates a new challenge and invalidates earlier evidence.
/// The verifier stores only replay and clock floors, never an accepted mode.
/// Callers must independently retain Evaluation on file or verification errors.
#[derive(Debug)]
pub struct DeploymentEvidenceVerifier {
    descriptor: DeploymentEvidenceChallenge,
    pinned_attester: Ed25519VerifyingKey,
    generation_floor: Option<EvidenceGeneration>,
    clock_floor: Option<EvidenceClock>,
}

impl DeploymentEvidenceVerifier {
    /// Pin an independently authorized health observer for one host and zone.
    ///
    /// The key must come from operator-owned configuration, never the evidence
    /// file or the host's own capability-signing key. A fresh OS-random nonce
    /// prevents evidence reuse across host restarts, even with the same label.
    ///
    /// # Errors
    /// Rejects empty, oversized or noncanonical host-subject labels.
    pub fn new(
        subject: String,
        zone_id: ZoneId,
        pinned_attester: Ed25519VerifyingKey,
    ) -> Result<Self, DeploymentEvidenceError> {
        validate_subject(&subject)?;
        let nonce = XChaCha20Nonce::generate();
        let challenge = blake3::derive_key(
            "FCP3 host deployment evidence process challenge v1",
            nonce.as_bytes(),
        );
        Ok(Self {
            descriptor: DeploymentEvidenceChallenge {
                schema_version: DEPLOYMENT_EVIDENCE_SCHEMA_VERSION,
                subject,
                zone_id,
                challenge,
                attesting_kid: pinned_attester.key_id(),
                max_lifetime_ms: MAX_DEPLOYMENT_EVIDENCE_LIFETIME_MS,
                max_future_skew_ms: MAX_DEPLOYMENT_EVIDENCE_FUTURE_SKEW_MS,
            },
            pinned_attester,
            generation_floor: None,
            clock_floor: None,
        })
    }

    /// Descriptor to expose only through the host's authenticated admin API.
    #[must_use]
    pub const fn challenge(&self) -> &DeploymentEvidenceChallenge {
        &self.descriptor
    }

    /// Authenticate and classify one newly read evidence snapshot.
    ///
    /// Supply the host's current Unix epoch milliseconds, never a caller clock.
    /// A process-monotonic clock floor prevents backward or stalled wall time
    /// from extending an observation. The highest authenticated generation is
    /// retained even if its lease is stale; failures never reset that floor.
    /// Identical generations are reusable only with exactly the same signed
    /// transcript. Conflicting authenticated snapshots poison their generation
    /// until a later one arrives. Forged or misbound input cannot advance it.
    ///
    /// # Errors
    /// Rejects malformed, unauthenticated, misbound, stale, future-dated,
    /// rolled-back or conflicting evidence. Never returns a cached mode.
    pub fn evaluate(
        &mut self,
        evidence: &SignedDeploymentEvidence,
        now_ms: u64,
    ) -> Result<DeploymentClassification, DeploymentEvidenceError> {
        self.evaluate_at(evidence, now_ms, Instant::now())
    }

    fn evaluate_at(
        &mut self,
        evidence: &SignedDeploymentEvidence,
        wall_now_ms: u64,
        monotonic_now: Instant,
    ) -> Result<DeploymentClassification, DeploymentEvidenceError> {
        let now_ms = self.effective_now_ms(wall_now_ms, monotonic_now);
        let transcript = evidence.signing_bytes()?;
        if evidence.subject != self.descriptor.subject {
            return Err(DeploymentEvidenceError::WrongSubject);
        }
        if evidence.zone_id != self.descriptor.zone_id {
            return Err(DeploymentEvidenceError::WrongZone);
        }
        if evidence.challenge != self.descriptor.challenge {
            return Err(DeploymentEvidenceError::WrongChallenge);
        }
        if evidence.quorum.attesting_kid != self.descriptor.attesting_kid {
            return Err(DeploymentEvidenceError::UnknownAttester);
        }
        self.pinned_attester
            .verify(&transcript, &evidence.signature)
            .map_err(|_| DeploymentEvidenceError::InvalidSignature)?;
        let classification = classify_deployment_mode_verified(&evidence.quorum, |kid| {
            (kid == &self.descriptor.attesting_kid).then(|| self.pinned_attester.clone())
        })
        .map_err(|_| DeploymentEvidenceError::InvalidQuorumSignature)?;

        self.observe_generation(evidence.generation, *blake3::hash(&transcript).as_bytes())?;
        if evidence.issued_at_ms > now_ms.saturating_add(MAX_DEPLOYMENT_EVIDENCE_FUTURE_SKEW_MS) {
            return Err(DeploymentEvidenceError::NotYetValid);
        }
        if now_ms >= evidence.expires_at_ms {
            return Err(DeploymentEvidenceError::Expired);
        }
        Ok(classification)
    }

    fn observe_generation(
        &mut self,
        generation: u64,
        transcript_digest: [u8; 32],
    ) -> Result<(), DeploymentEvidenceError> {
        if let Some(floor) = &mut self.generation_floor {
            if generation < floor.generation {
                return Err(DeploymentEvidenceError::GenerationRollback);
            }
            if generation == floor.generation {
                if floor.conflicted || transcript_digest != floor.transcript_digest {
                    floor.conflicted = true;
                    return Err(DeploymentEvidenceError::ConflictingGeneration);
                }
                return Ok(());
            }
        }
        self.generation_floor = Some(EvidenceGeneration {
            generation,
            transcript_digest,
            conflicted: false,
        });
        Ok(())
    }

    fn effective_now_ms(&mut self, wall_now_ms: u64, monotonic_now: Instant) -> u64 {
        if let Some(floor) = &self.clock_floor {
            let elapsed_ms = u64::try_from(
                monotonic_now
                    .saturating_duration_since(floor.observed_at)
                    .as_millis(),
            )
            .unwrap_or(u64::MAX);
            let projected = floor.epoch_ms.saturating_add(elapsed_ms);
            if projected >= wall_now_ms {
                return projected;
            }
        }
        self.clock_floor = Some(EvidenceClock {
            epoch_ms: wall_now_ms,
            observed_at: monotonic_now,
        });
        wall_now_ms
    }
}

/// Static, redaction-safe reasons for rejecting deployment health evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DeploymentEvidenceError {
    /// The configured or signed subject is not a bounded ASCII host label.
    #[error("invalid deployment evidence host subject")]
    InvalidSubject,
    /// The signing helper was given another descriptor format or limits.
    #[error("invalid deployment evidence challenge descriptor")]
    InvalidChallengeDescriptor,
    /// The envelope uses another transcript version.
    #[error("unsupported deployment evidence version")]
    UnsupportedVersion,
    /// Generation zero cannot establish a replay floor.
    #[error("deployment evidence generation must be positive")]
    InvalidGeneration,
    /// Observation lifetime is empty, backwards or above the hard ceiling.
    #[error("invalid deployment evidence lifetime")]
    InvalidLifetime,
    /// Canonical transcript encoding failed.
    #[error("deployment evidence transcript encoding failed")]
    EncodingFailed,
    /// The signed observation belongs to another host label.
    #[error("deployment evidence host subject mismatch")]
    WrongSubject,
    /// The signed observation belongs to another execution zone.
    #[error("deployment evidence execution zone mismatch")]
    WrongZone,
    /// The signed observation belongs to another host process.
    #[error("deployment evidence process challenge mismatch")]
    WrongChallenge,
    /// The evidence key is not the independently pinned observer.
    #[error("deployment evidence attester is not trusted")]
    UnknownAttester,
    /// Outer signature verification failed.
    #[error("deployment evidence signature verification failed")]
    InvalidSignature,
    /// Existing signed quorum snapshot verification failed.
    #[error("deployment evidence quorum signature verification failed")]
    InvalidQuorumSignature,
    /// Observer issuance time is beyond the bounded future skew.
    #[error("deployment evidence issuance is in the future")]
    NotYetValid,
    /// Observation expiration has been reached.
    #[error("deployment evidence expired")]
    Expired,
    /// An older authenticated snapshot was presented after a newer one.
    #[error("deployment evidence generation rollback")]
    GenerationRollback,
    /// The observer signed different snapshots under one generation.
    #[error("deployment evidence generation conflict")]
    ConflictingGeneration,
}

fn validate_subject(subject: &str) -> Result<(), DeploymentEvidenceError> {
    if subject.is_empty()
        || subject.len() > MAX_DEPLOYMENT_EVIDENCE_SUBJECT_BYTES
        || !subject
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
    {
        return Err(DeploymentEvidenceError::InvalidSubject);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::{DeploymentClassificationReason, DeploymentMode};

    use super::*;

    const NOW: u64 = 1_000_000;

    fn key() -> Ed25519SigningKey {
        Ed25519SigningKey::from_bytes(&[73; 32]).unwrap()
    }

    fn verifier() -> DeploymentEvidenceVerifier {
        DeploymentEvidenceVerifier::new(
            "host:production-a".into(),
            ZoneId::work(),
            key().verifying_key(),
        )
        .unwrap()
    }

    fn signed(
        verifier: &DeploymentEvidenceVerifier,
        signals: MeshQuorumSignals,
        generation: u64,
        issued_at_ms: u64,
        expires_at_ms: u64,
    ) -> SignedDeploymentEvidence {
        SignedDeploymentEvidence::sign(
            verifier.challenge(),
            signals,
            generation,
            issued_at_ms,
            expires_at_ms,
            &key(),
        )
        .unwrap()
    }

    fn active(verifier: &DeploymentEvidenceVerifier, generation: u64) -> SignedDeploymentEvidence {
        signed(
            verifier,
            MeshQuorumSignals::fully_active(2),
            generation,
            NOW,
            NOW + MAX_DEPLOYMENT_EVIDENCE_LIFETIME_MS,
        )
    }

    #[test]
    fn challenges_are_process_unique_and_explicitly_scoped() {
        let first = verifier();
        let second = verifier();
        assert_ne!(first.challenge().challenge, second.challenge().challenge);
        assert_ne!(first.challenge().challenge, [0; 32]);
        assert_eq!(first.challenge().subject, "host:production-a");
        assert_eq!(first.challenge().zone_id, ZoneId::work());
        assert_eq!(first.challenge().attesting_kid, key().key_id());
        let encoded = serde_json::to_vec(first.challenge()).unwrap();
        let decoded: DeploymentEvidenceChallenge = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(&decoded, first.challenge());
    }

    #[test]
    fn subject_labels_reject_ambiguous_or_unbounded_identifiers() {
        for subject in [
            "", " host-a", "host-a ", "host\na", "host\0a", "höst", "host?a",
        ] {
            assert!(matches!(
                DeploymentEvidenceVerifier::new(
                    subject.into(),
                    ZoneId::work(),
                    key().verifying_key(),
                ),
                Err(DeploymentEvidenceError::InvalidSubject)
            ));
        }
        assert!(
            DeploymentEvidenceVerifier::new(
                "a".repeat(MAX_DEPLOYMENT_EVIDENCE_SUBJECT_BYTES),
                ZoneId::work(),
                key().verifying_key(),
            )
            .is_ok()
        );
        assert!(
            DeploymentEvidenceVerifier::new(
                "a".repeat(MAX_DEPLOYMENT_EVIDENCE_SUBJECT_BYTES + 1),
                ZoneId::work(),
                key().verifying_key(),
            )
            .is_err()
        );
    }

    #[test]
    fn fresh_authenticated_evidence_uses_existing_quorum_classifier() {
        let mut verifier = verifier();
        let evidence = active(&verifier, 1);
        let encoded = serde_json::to_vec(&evidence).unwrap();
        assert!(encoded.len() < 4096);
        let decoded: SignedDeploymentEvidence = serde_json::from_slice(&encoded).unwrap();
        let decision = verifier.evaluate(&decoded, NOW).unwrap();
        assert_eq!(decision.mode, DeploymentMode::MeshActive);
        assert_eq!(decision.signals, evidence.quorum.signals);
        assert_eq!(
            decision.reason,
            DeploymentClassificationReason::MeshQuorumActive
        );
        assert_eq!(verifier.evaluate(&decoded, NOW + 1).unwrap(), decision);
    }

    #[test]
    fn authenticated_unhealthy_observations_never_promote() {
        for signals in [
            MeshQuorumSignals::single_host_evaluation(),
            MeshQuorumSignals {
                healthy_peer_count: 20,
                lease_coordinator_reachable: Some(false),
                revocation_snapshot_fresh: true,
            },
            MeshQuorumSignals {
                healthy_peer_count: 20,
                lease_coordinator_reachable: Some(true),
                revocation_snapshot_fresh: false,
            },
        ] {
            let mut verifier = verifier();
            let evidence = signed(&verifier, signals, 1, NOW, NOW + 10_000);
            assert_eq!(
                verifier.evaluate(&evidence, NOW).unwrap().mode,
                DeploymentMode::Evaluation
            );
        }
    }

    #[test]
    fn signatures_bind_every_authority_time_and_snapshot_field() {
        let verifier = verifier();
        let evidence = active(&verifier, 1);
        let mut mutations = Vec::new();
        let mut changed = evidence.clone();
        changed.subject = "host:another".into();
        mutations.push(changed);
        let mut changed = evidence.clone();
        changed.zone_id = ZoneId::private();
        mutations.push(changed);
        let mut changed = evidence.clone();
        changed.challenge[0] ^= 1;
        mutations.push(changed);
        let mut changed = evidence.clone();
        changed.issued_at_ms += 1;
        mutations.push(changed);
        let mut changed = evidence.clone();
        changed.expires_at_ms -= 1;
        mutations.push(changed);
        let mut changed = evidence.clone();
        changed.generation += 1;
        mutations.push(changed);
        let mut changed = evidence.clone();
        changed.quorum.signals.healthy_peer_count += 1;
        mutations.push(changed);
        let mut changed = evidence.clone();
        changed.quorum.signals.lease_coordinator_reachable = None;
        mutations.push(changed);
        let mut changed = evidence.clone();
        changed.quorum.signals.revocation_snapshot_fresh = false;
        mutations.push(changed);
        for changed in mutations {
            assert!(
                key()
                    .verifying_key()
                    .verify(&changed.signing_bytes().unwrap(), &changed.signature)
                    .is_err()
            );
        }
    }

    #[test]
    fn wrong_subject_zone_or_process_cannot_reuse_valid_evidence() {
        let mut verifier = verifier();
        for (subject, zone, error) in [
            (
                "host:another",
                ZoneId::work(),
                DeploymentEvidenceError::WrongSubject,
            ),
            (
                "host:production-a",
                ZoneId::private(),
                DeploymentEvidenceError::WrongZone,
            ),
        ] {
            let mut descriptor = verifier.challenge().clone();
            descriptor.subject = subject.into();
            descriptor.zone_id = zone;
            let evidence = SignedDeploymentEvidence::sign(
                &descriptor,
                MeshQuorumSignals::fully_active(2),
                1,
                NOW,
                NOW + 1000,
                &key(),
            )
            .unwrap();
            assert_eq!(verifier.evaluate(&evidence, NOW), Err(error));
        }
        let restarted = self::verifier();
        assert_eq!(
            verifier.evaluate(&active(&restarted, 1), NOW),
            Err(DeploymentEvidenceError::WrongChallenge)
        );
        assert!(verifier.generation_floor.is_none());
    }

    #[test]
    fn independently_pinned_key_and_both_signatures_are_required() {
        let mut verifier = verifier();
        let good = active(&verifier, 1);
        let stranger = Ed25519SigningKey::from_bytes(&[74; 32]).unwrap();
        assert!(matches!(
            SignedDeploymentEvidence::sign(
                verifier.challenge(),
                good.quorum.signals,
                1,
                NOW,
                NOW + 1000,
                &stranger,
            ),
            Err(DeploymentEvidenceError::UnknownAttester)
        ));
        let mut forged = good.clone();
        forged.signature = stranger.sign(&forged.signing_bytes().unwrap());
        assert_eq!(
            verifier.evaluate(&forged, NOW),
            Err(DeploymentEvidenceError::InvalidSignature)
        );
        let mut wrong_inner_key = good.clone();
        wrong_inner_key.quorum = wrong_inner_key.quorum.signals.sign(&stranger);
        wrong_inner_key.signature = key().sign(&wrong_inner_key.signing_bytes().unwrap());
        assert_eq!(
            verifier.evaluate(&wrong_inner_key, NOW),
            Err(DeploymentEvidenceError::UnknownAttester)
        );
        let mut bad_inner = good.clone();
        bad_inner.quorum.signature = Ed25519Signature::from_bytes(&[0; 64]);
        bad_inner.signature = key().sign(&bad_inner.signing_bytes().unwrap());
        assert_eq!(
            verifier.evaluate(&bad_inner, NOW),
            Err(DeploymentEvidenceError::InvalidQuorumSignature)
        );
        assert!(verifier.generation_floor.is_none());
        assert!(verifier.evaluate(&good, NOW).is_ok());
    }

    #[test]
    fn signature_domains_are_not_interchangeable() {
        let mut verifier = verifier();
        let mut evidence = active(&verifier, 1);
        evidence.signature = evidence.quorum.signature;
        assert_eq!(
            verifier.evaluate(&evidence, NOW),
            Err(DeploymentEvidenceError::InvalidSignature)
        );
        let transcript = evidence.signing_bytes().unwrap();
        let payload = &transcript[DEPLOYMENT_EVIDENCE_DOMAIN.len()..];
        evidence.signature = key().sign(payload);
        assert_eq!(
            verifier.evaluate(&evidence, NOW),
            Err(DeploymentEvidenceError::InvalidSignature)
        );
    }

    #[test]
    fn lifetime_generation_version_and_descriptor_limits_fail_closed() {
        let verifier = verifier();
        for (generation, issued, expires, error) in [
            (0, NOW, NOW + 1, DeploymentEvidenceError::InvalidGeneration),
            (1, NOW, NOW, DeploymentEvidenceError::InvalidLifetime),
            (1, NOW, NOW - 1, DeploymentEvidenceError::InvalidLifetime),
            (
                1,
                NOW,
                NOW + MAX_DEPLOYMENT_EVIDENCE_LIFETIME_MS + 1,
                DeploymentEvidenceError::InvalidLifetime,
            ),
            (1, u64::MAX, 0, DeploymentEvidenceError::InvalidLifetime),
        ] {
            assert!(matches!(
                SignedDeploymentEvidence::sign(
                    verifier.challenge(),
                    MeshQuorumSignals::fully_active(2),
                    generation,
                    issued,
                    expires,
                    &key(),
                ),
                Err(actual) if actual == error
            ));
        }
        let mut descriptor = verifier.challenge().clone();
        descriptor.max_lifetime_ms += 1;
        assert!(matches!(
            SignedDeploymentEvidence::sign(
                &descriptor,
                MeshQuorumSignals::fully_active(2),
                1,
                NOW,
                NOW + 1,
                &key()
            ),
            Err(DeploymentEvidenceError::InvalidChallengeDescriptor)
        ));
        let mut evidence = active(&verifier, 1);
        evidence.schema_version += 1;
        assert_eq!(
            evidence.signing_bytes(),
            Err(DeploymentEvidenceError::UnsupportedVersion)
        );
    }

    #[test]
    fn expiration_is_exclusive_and_future_skew_is_bounded() {
        let mut verifier = verifier();
        let instant = Instant::now();
        let evidence = active(&verifier, 1);
        assert!(
            verifier
                .evaluate_at(&evidence, evidence.expires_at_ms - 1, instant)
                .is_ok()
        );
        assert_eq!(
            verifier.evaluate_at(&evidence, evidence.expires_at_ms, instant),
            Err(DeploymentEvidenceError::Expired)
        );

        let mut verifier = self::verifier();
        let issued = NOW + MAX_DEPLOYMENT_EVIDENCE_FUTURE_SKEW_MS;
        let boundary = signed(
            &verifier,
            MeshQuorumSignals::fully_active(2),
            1,
            issued,
            issued + 1000,
        );
        assert!(verifier.evaluate_at(&boundary, NOW, instant).is_ok());
        let future = signed(
            &verifier,
            MeshQuorumSignals::fully_active(2),
            2,
            issued + 1,
            issued + 1001,
        );
        assert_eq!(
            verifier.evaluate_at(&future, NOW, instant),
            Err(DeploymentEvidenceError::NotYetValid)
        );
    }

    #[test]
    fn renewed_generation_and_degraded_health_replace_old_snapshots() {
        let mut verifier = verifier();
        let first = active(&verifier, 1);
        assert_eq!(
            verifier.evaluate(&first, NOW).unwrap().mode,
            DeploymentMode::MeshActive
        );
        let degraded = signed(
            &verifier,
            MeshQuorumSignals::single_host_evaluation(),
            2,
            NOW,
            NOW + 1000,
        );
        assert_eq!(
            verifier.evaluate(&degraded, NOW).unwrap().mode,
            DeploymentMode::Evaluation
        );
        assert_eq!(
            verifier.evaluate(&first, NOW),
            Err(DeploymentEvidenceError::GenerationRollback)
        );
        let renewed = signed(
            &verifier,
            MeshQuorumSignals::fully_active(2),
            3,
            NOW + 1000,
            NOW + 31_000,
        );
        assert_eq!(
            verifier.evaluate(&renewed, NOW + 1000).unwrap().mode,
            DeploymentMode::MeshActive
        );
    }

    #[test]
    fn stale_authenticated_generation_keeps_the_rollback_floor() {
        let mut verifier = verifier();
        let first = active(&verifier, 1);
        verifier.evaluate(&first, NOW).unwrap();
        let expired_newer = signed(
            &verifier,
            MeshQuorumSignals::single_host_evaluation(),
            2,
            NOW - 1000,
            NOW,
        );
        assert_eq!(
            verifier.evaluate(&expired_newer, NOW),
            Err(DeploymentEvidenceError::Expired)
        );
        assert_eq!(
            verifier.evaluate(&first, NOW),
            Err(DeploymentEvidenceError::GenerationRollback)
        );
        let mut forged = active(&verifier, 1000);
        forged.signature = Ed25519Signature::from_bytes(&[0; 64]);
        assert_eq!(
            verifier.evaluate(&forged, NOW),
            Err(DeploymentEvidenceError::InvalidSignature)
        );
        assert!(
            verifier
                .evaluate(&active(&self::verifier(), 3), NOW)
                .is_err()
        );
        let recovery = active(&verifier, 3);
        assert!(verifier.evaluate(&recovery, NOW).is_ok());
    }

    #[test]
    fn conflicting_generation_requires_a_newer_authenticated_snapshot() {
        let mut verifier = verifier();
        let first = active(&verifier, 1);
        verifier.evaluate(&first, NOW).unwrap();
        let conflict = signed(
            &verifier,
            MeshQuorumSignals::single_host_evaluation(),
            1,
            NOW,
            NOW + 1000,
        );
        assert_eq!(
            verifier.evaluate(&conflict, NOW),
            Err(DeploymentEvidenceError::ConflictingGeneration)
        );
        assert_eq!(
            verifier.evaluate(&first, NOW),
            Err(DeploymentEvidenceError::ConflictingGeneration)
        );
        let renewed = active(&verifier, 2);
        assert!(verifier.evaluate(&renewed, NOW).is_ok());
    }

    #[test]
    fn changing_only_expiration_also_conflicts_with_same_generation() {
        let mut verifier = verifier();
        let first = active(&verifier, 1);
        verifier.evaluate(&first, NOW).unwrap();
        let changed = signed(&verifier, first.quorum.signals, 1, NOW, NOW + 20_000);
        assert_eq!(
            verifier.evaluate(&changed, NOW),
            Err(DeploymentEvidenceError::ConflictingGeneration)
        );
    }

    #[test]
    fn monotonic_time_prevents_wall_clock_rollback_or_stall_extending_a_lease() {
        let mut verifier = verifier();
        let evidence = active(&verifier, 1);
        let instant = Instant::now();
        verifier.evaluate_at(&evidence, NOW, instant).unwrap();
        let expired_instant = instant + Duration::from_millis(MAX_DEPLOYMENT_EVIDENCE_LIFETIME_MS);
        assert_eq!(
            verifier.evaluate_at(&evidence, NOW, expired_instant),
            Err(DeploymentEvidenceError::Expired)
        );
        assert_eq!(
            verifier.evaluate_at(&evidence, 0, expired_instant),
            Err(DeploymentEvidenceError::Expired)
        );
        let renewed = signed(
            &verifier,
            evidence.quorum.signals,
            2,
            NOW + 30_000,
            NOW + 60_000,
        );
        assert!(verifier.evaluate_at(&renewed, NOW, expired_instant).is_ok());
    }

    #[test]
    fn advanced_wall_clock_cannot_be_rolled_back_after_rejection() {
        let mut verifier = verifier();
        let evidence = active(&verifier, 1);
        let instant = Instant::now();
        assert_eq!(
            verifier.evaluate_at(&evidence, NOW + 40_000, instant),
            Err(DeploymentEvidenceError::Expired)
        );
        assert_eq!(
            verifier.evaluate_at(&evidence, NOW, instant),
            Err(DeploymentEvidenceError::Expired)
        );
    }

    #[test]
    fn unknown_envelope_fields_and_unsigned_signals_are_not_evidence() {
        let verifier = verifier();
        let evidence = active(&verifier, 1);
        let mut value = serde_json::to_value(&evidence).unwrap();
        value["force_mesh_active"] = serde_json::json!(true);
        assert!(serde_json::from_value::<SignedDeploymentEvidence>(value).is_err());
        assert!(
            serde_json::from_value::<SignedDeploymentEvidence>(
                serde_json::to_value(MeshQuorumSignals::fully_active(2)).unwrap()
            )
            .is_err()
        );
    }
}
