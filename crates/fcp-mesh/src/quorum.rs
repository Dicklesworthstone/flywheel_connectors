//! Compact BLS quorum certificates for mesh quorum decisions
//! (br-angoc.17.4).
//!
//! Quorum decisions that gossip across the mesh (zone admission, capability
//! revocation) previously carried one Ed25519 signature per signer via
//! [`fcp_core::SignatureSet`]. This module adds a compact
//! alternative: any k-of-n subset of PoP-registered signers produces a
//! [`BlsQuorumCertificate`] whose signature is a **single 96-byte BLS12-381
//! aggregate**, verified with two pairings regardless of signer count.
//!
//! The Ed25519 per-signer path remains authoritative fallback: a decision
//! whose BLS certificate fails verification MUST be re-validated (or
//! re-collected) through the existing [`SignatureSet`] path rather than
//! accepted — see the conformance failure-injection test.
//!
//! # Threshold semantics
//!
//! Signer-count thresholds reuse [`fcp_core::QuorumPolicy`] and
//! [`RiskTier`] unchanged: the certificate carries the distinct signer set,
//! the verifier checks `signers ⊆ eligible`, counts them against
//! `policy.is_quorum_met(count, tier)`, and only then runs the pairing
//! check. Rogue-key defense is inherited from
//! [`fcp_crypto::bls::PopRegistry`]: only PoP-verified keys can appear.
//!
//! [`SignatureSet`]: fcp_core::SignatureSet

use std::collections::BTreeSet;
use std::time::Instant;

use fcp_core::{QuorumPolicy, RiskTier};
use fcp_crypto::bls::{
    AggregateSignature, BlsError, BlsSecretKey, BlsSignature, PopRegistry, verify_aggregate,
};
use fcp_prelude::ZoneId;
use serde::{Deserialize, Serialize};

/// Domain prefix for quorum-decision signing bytes (versioned).
const QUORUM_DECISION_DOMAIN: &[u8] = b"fcp.mesh.quorum.v1";

/// The kind of mesh decision a quorum is being asked to authorize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QuorumDecisionKind {
    /// Admit a node (subject) into a zone.
    ZoneAdmission,
    /// Revoke a capability (subject = capability token / object ID).
    CapabilityRevocation,
}

impl QuorumDecisionKind {
    /// Stable one-byte discriminant for canonical signing bytes.
    const fn discriminant(self) -> u8 {
        match self {
            Self::ZoneAdmission => 1,
            Self::CapabilityRevocation => 2,
        }
    }

    /// The default risk tier a decision kind must satisfy.
    ///
    /// Zone admission expands the trust boundary (`Dangerous`, `n - f`);
    /// capability revocation rewrites authority state that every node
    /// enforces (`CriticalWrite`, `n - f`).
    #[must_use]
    pub const fn default_risk_tier(self) -> RiskTier {
        match self {
            Self::ZoneAdmission => RiskTier::Dangerous,
            Self::CapabilityRevocation => RiskTier::CriticalWrite,
        }
    }
}

/// A quorum decision to be signed: what is being authorized, for which
/// zone, about which subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumDecision {
    /// What kind of decision this is.
    pub kind: QuorumDecisionKind,
    /// Zone the decision applies to.
    pub zone_id: ZoneId,
    /// Decision subject (node ID for admission, capability/object ID for
    /// revocation).
    pub subject: String,
    /// Caller-supplied uniqueness nonce (e.g. epoch or decision UUID) so
    /// the same logical decision issued twice signs different bytes.
    pub nonce: u64,
}

impl QuorumDecision {
    /// Canonical byte encoding signed by every quorum member.
    ///
    /// Layout: `domain ‖ kind ‖ len(zone) ‖ zone ‖ len(subject) ‖ subject ‖
    /// nonce_le` — every variable-length field is length-prefixed so
    /// distinct decisions can never produce the same bytes.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let zone = self.zone_id.as_str().as_bytes();
        let subject = self.subject.as_bytes();
        let mut out = Vec::with_capacity(
            QUORUM_DECISION_DOMAIN.len() + 1 + 8 + zone.len() + subject.len() + 16,
        );
        out.extend_from_slice(QUORUM_DECISION_DOMAIN);
        out.push(self.kind.discriminant());
        out.extend_from_slice(&u32::try_from(zone.len()).unwrap_or(u32::MAX).to_le_bytes());
        out.extend_from_slice(zone);
        out.extend_from_slice(
            &u32::try_from(subject.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        out.extend_from_slice(subject);
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out
    }

    /// Sign this decision with a quorum member's BLS secret key.
    #[must_use]
    pub fn sign(&self, secret_key: &BlsSecretKey) -> BlsSignature {
        secret_key.sign(&self.signing_bytes())
    }
}

/// A quorum decision plus the compact aggregate signature authorizing it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlsQuorumCertificate {
    /// The decision that was signed.
    pub decision: QuorumDecision,
    /// Aggregate signature (single 96-byte G2 point + distinct signer set).
    pub aggregate: AggregateSignature,
}

/// Why a BLS quorum certificate was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QuorumVerifyError {
    /// A signer in the certificate is not in the eligible set for the zone.
    #[error("signer '{signer}' is not eligible for quorum decisions in this zone")]
    SignerNotEligible {
        /// The ineligible signer ID.
        signer: String,
    },

    /// Not enough distinct signers for the required risk tier.
    #[error("quorum not met: have {have} signers, need {need} for {tier:?}")]
    QuorumNotMet {
        /// Distinct signers present in the certificate.
        have: u32,
        /// Signatures required by the policy for this tier.
        need: u32,
        /// The risk tier that was evaluated.
        tier: RiskTier,
    },

    /// The underlying BLS aggregate failed (missing PoP, bad point,
    /// pairing failure, ...). Callers should fall back to the per-signer
    /// Ed25519 [`SignatureSet`](fcp_core::SignatureSet) path.
    #[error("BLS aggregate verification failed: {0}")]
    Bls(#[from] BlsError),
}

/// Verify a BLS quorum certificate against a PoP registry, an eligibility
/// set, and a zone quorum policy.
///
/// Check order is cheapest-first and fail-closed:
/// 1. every signer must be in `eligible` (membership before any crypto);
/// 2. the distinct-signer count must satisfy `policy` at `tier`
///    (the aggregate's signer set is a `BTreeSet`, so signers are
///    structurally distinct — one key signing N times cannot inflate the
///    count);
/// 3. the aggregate signature must verify over the decision's canonical
///    signing bytes with two pairings.
///
/// # Errors
///
/// Returns [`QuorumVerifyError`] describing the first failed check.
pub fn verify_certificate(
    certificate: &BlsQuorumCertificate,
    registry: &PopRegistry,
    eligible: &BTreeSet<String>,
    policy: &QuorumPolicy,
    tier: RiskTier,
) -> Result<(), QuorumVerifyError> {
    let started = Instant::now();

    for signer in certificate.aggregate.signers() {
        if !eligible.contains(signer) {
            return Err(QuorumVerifyError::SignerNotEligible {
                signer: signer.clone(),
            });
        }
    }

    let have = u32::try_from(certificate.aggregate.signer_count()).unwrap_or(u32::MAX);
    if !policy.is_quorum_met(have, tier) {
        return Err(QuorumVerifyError::QuorumNotMet {
            have,
            need: policy.required_signatures(tier),
            tier,
        });
    }

    verify_aggregate(
        &certificate.aggregate,
        &certificate.decision.signing_bytes(),
        registry,
    )?;

    let verify_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    tracing::debug!(
        target: "fcp.mesh.quorum",
        operation = "verify_certificate",
        kind = ?certificate.decision.kind,
        zone_id = %certificate.decision.zone_id,
        n_signers = certificate.aggregate.signer_count(),
        verify_us,
        "BLS quorum certificate verified"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use fcp_crypto::bls::aggregate;

    use super::*;

    struct Fixture {
        signers: Vec<(String, BlsSecretKey)>,
        registry: PopRegistry,
        eligible: BTreeSet<String>,
        policy: QuorumPolicy,
    }

    /// n=5 eligible signers, f=1 → Risky needs 2, Dangerous/CriticalWrite
    /// need 4.
    fn fixture() -> Fixture {
        let signers: Vec<(String, BlsSecretKey)> = (0..5)
            .map(|i| (format!("node-{i}"), BlsSecretKey::generate()))
            .collect();
        let mut registry = PopRegistry::new();
        for (id, sk) in &signers {
            registry
                .register(id.clone(), sk.public_key(), &sk.prove_possession())
                .unwrap();
        }
        let eligible: BTreeSet<String> = signers.iter().map(|(id, _)| id.clone()).collect();
        let policy = QuorumPolicy::new(ZoneId::work(), 5, 1);
        Fixture {
            signers,
            registry,
            eligible,
            policy,
        }
    }

    fn admission_decision() -> QuorumDecision {
        QuorumDecision {
            kind: QuorumDecisionKind::ZoneAdmission,
            zone_id: ZoneId::work(),
            subject: "node-candidate-9".to_string(),
            nonce: 7,
        }
    }

    fn certificate_from(
        fx: &Fixture,
        decision: &QuorumDecision,
        signer_range: std::ops::Range<usize>,
    ) -> BlsQuorumCertificate {
        let shares: Vec<(String, BlsSignature)> = fx.signers[signer_range]
            .iter()
            .map(|(id, sk)| (id.clone(), decision.sign(sk)))
            .collect();
        BlsQuorumCertificate {
            decision: decision.clone(),
            aggregate: aggregate(&shares, &fx.registry).unwrap(),
        }
    }

    #[test]
    fn certificate_with_quorum_verifies() {
        let fx = fixture();
        let decision = admission_decision();
        let cert = certificate_from(&fx, &decision, 0..4);

        verify_certificate(
            &cert,
            &fx.registry,
            &fx.eligible,
            &fx.policy,
            QuorumDecisionKind::ZoneAdmission.default_risk_tier(),
        )
        .expect("4-of-5 dangerous quorum verifies");
        assert_eq!(cert.aggregate.signature().to_bytes().len(), 96);
    }

    #[test]
    fn below_threshold_is_rejected_before_crypto() {
        let fx = fixture();
        let decision = admission_decision();
        let cert = certificate_from(&fx, &decision, 0..3);

        let err = verify_certificate(
            &cert,
            &fx.registry,
            &fx.eligible,
            &fx.policy,
            RiskTier::Dangerous,
        )
        .expect_err("3-of-5 must not satisfy a dangerous quorum");
        assert_eq!(
            err,
            QuorumVerifyError::QuorumNotMet {
                have: 3,
                need: 4,
                tier: RiskTier::Dangerous
            }
        );
    }

    #[test]
    fn ineligible_signer_is_rejected() {
        let fx = fixture();
        let decision = admission_decision();
        let cert = certificate_from(&fx, &decision, 0..4);

        let mut eligible = fx.eligible.clone();
        eligible.remove("node-0");
        let err = verify_certificate(
            &cert,
            &fx.registry,
            &eligible,
            &fx.policy,
            RiskTier::Dangerous,
        )
        .expect_err("signer outside the eligible set must be rejected");
        assert_eq!(
            err,
            QuorumVerifyError::SignerNotEligible {
                signer: "node-0".to_string()
            }
        );
    }

    #[test]
    fn tampered_decision_fails_pairing_check() {
        let fx = fixture();
        let decision = admission_decision();
        let mut cert = certificate_from(&fx, &decision, 0..4);
        cert.decision.subject = "node-attacker".to_string();

        let err = verify_certificate(
            &cert,
            &fx.registry,
            &fx.eligible,
            &fx.policy,
            RiskTier::Dangerous,
        )
        .expect_err("tampered decision must fail");
        assert_eq!(err, QuorumVerifyError::Bls(BlsError::VerificationFailed));
    }

    #[test]
    fn distinct_nonces_sign_distinct_bytes() {
        let decision_a = admission_decision();
        let mut decision_b = admission_decision();
        decision_b.nonce = 8;
        assert_ne!(decision_a.signing_bytes(), decision_b.signing_bytes());
    }

    #[test]
    fn decision_kinds_map_to_documented_tiers() {
        assert_eq!(
            QuorumDecisionKind::ZoneAdmission.default_risk_tier(),
            RiskTier::Dangerous
        );
        assert_eq!(
            QuorumDecisionKind::CapabilityRevocation.default_risk_tier(),
            RiskTier::CriticalWrite
        );
    }
}
