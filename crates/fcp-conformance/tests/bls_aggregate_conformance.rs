//! Conformance: BLS12-381 threshold-aggregate quorum signatures
//! (br-angoc.17.4).
//!
//! Pins the cross-crate contract between `fcp_crypto::bls` and
//! `fcp_mesh::quorum`:
//!
//! 1. `zone_admission_quorum` — five zone admins sign an admission
//!    decision; the aggregate is a **single 96-byte signature** that a
//!    remote zone verifier (fresh registry rebuilt from serialized public
//!    keys + PoPs, certificate round-tripped through canonical CBOR)
//!    accepts under the zone's quorum policy.
//! 2. `pop_enforcement_e2e` — a rogue admin whose key never proved
//!    possession is rejected at aggregation AND a certificate naming an
//!    unregistered signer is rejected at verification, both with
//!    `BlsError::PopMissing`.
//! 3. `failure_injection_falls_back_to_ed25519_path` — one corrupted
//!    signature share makes the BLS aggregate fail closed; the decision
//!    still authorizes through the existing per-signer Ed25519
//!    `SignatureSet` path, proving the fallback lane stays intact.

// `PoP`/`PoPs` (proof of possession) and `BTreeSet` appear in this file's
// prose; their mixed case trips `doc_markdown`. Matches the module-scoped
// allow in `fcp_crypto::bls`.
#![allow(clippy::doc_markdown)]

use std::collections::BTreeSet;

use fcp_core::{NodeId, NodeSignature, QuorumPolicy, RiskTier, SignatureSet};
use fcp_crypto::bls::{
    BlsPublicKey, BlsSecretKey, BlsSignature, PopRegistry, ProofOfPossession, aggregate,
};
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_mesh::quorum::{
    BlsQuorumCertificate, QuorumDecision, QuorumDecisionKind, QuorumVerifyError, verify_certificate,
};
use fcp_prelude::ZoneId;

const N_ADMINS: usize = 5;
const MAX_FAULTS: u32 = 1;

struct Admin {
    id: String,
    bls: BlsSecretKey,
    ed25519: Ed25519SigningKey,
}

fn admins() -> Vec<Admin> {
    (0..N_ADMINS)
        .map(|i| Admin {
            id: format!("admin-{i}"),
            bls: BlsSecretKey::generate(),
            ed25519: Ed25519SigningKey::generate(),
        })
        .collect()
}

/// Simulate key distribution to a remote zone: only serialized public keys
/// and PoPs cross the wire; the verifier rebuilds its own registry and
/// re-verifies every PoP on ingest.
fn remote_registry(admins: &[Admin]) -> PopRegistry {
    let mut registry = PopRegistry::new();
    for admin in admins {
        let pk_bytes = admin.bls.public_key().to_bytes();
        let pop_bytes = admin.bls.prove_possession().to_bytes();

        let pk = BlsPublicKey::from_bytes(&pk_bytes).expect("public key survives the wire");
        let pop = ProofOfPossession::from_bytes(&pop_bytes).expect("PoP survives the wire");
        registry
            .register(admin.id.clone(), pk, &pop)
            .expect("PoP verifies on the remote side");
    }
    registry
}

fn admission_decision() -> QuorumDecision {
    QuorumDecision {
        kind: QuorumDecisionKind::ZoneAdmission,
        zone_id: ZoneId::work(),
        subject: "node-candidate-77".to_string(),
        nonce: 42,
    }
}

fn eligible_set(admins: &[Admin]) -> BTreeSet<String> {
    admins.iter().map(|a| a.id.clone()).collect()
}

fn zone_policy() -> QuorumPolicy {
    QuorumPolicy::new(
        ZoneId::work(),
        u32::try_from(N_ADMINS).expect("small n"),
        MAX_FAULTS,
    )
}

#[test]
fn zone_admission_quorum() {
    let admins = admins();
    let decision = admission_decision();

    // All five admins sign; the local aggregator compresses to one point.
    let shares: Vec<(String, BlsSignature)> = admins
        .iter()
        .map(|a| (a.id.clone(), decision.sign(&a.bls)))
        .collect();
    let local_registry = remote_registry(&admins);
    let agg = aggregate(&shares, &local_registry).expect("aggregation succeeds");

    // The compact certificate is a SINGLE 96-byte signature regardless of
    // signer count.
    assert_eq!(agg.signature().to_bytes().len(), 96);
    assert_eq!(agg.signer_count(), N_ADMINS);

    // Ship the certificate to a remote zone through canonical CBOR.
    let certificate = BlsQuorumCertificate {
        decision,
        aggregate: agg,
    };
    let mut wire = Vec::new();
    ciborium::into_writer(&certificate, &mut wire).expect("certificate serializes");
    let received: BlsQuorumCertificate =
        ciborium::from_reader(&wire[..]).expect("certificate deserializes");
    assert_eq!(received, certificate);

    // The remote verifier has its own registry (rebuilt from distributed
    // keys + PoPs), the zone's eligibility set, and the zone policy.
    let registry = remote_registry(&admins);
    verify_certificate(
        &received,
        &registry,
        &eligible_set(&admins),
        &zone_policy(),
        QuorumDecisionKind::ZoneAdmission.default_risk_tier(),
    )
    .expect("remote zone accepts the admission quorum");
}

#[test]
fn pop_enforcement_e2e() {
    let admins = admins();
    let decision = admission_decision();
    let registry = remote_registry(&admins);

    // A rogue admin generates a key but never proves possession.
    let rogue = BlsSecretKey::generate();

    // 1. Aggregation-time enforcement: the rogue share is refused.
    let mut shares: Vec<(String, BlsSignature)> = admins
        .iter()
        .take(3)
        .map(|a| (a.id.clone(), decision.sign(&a.bls)))
        .collect();
    shares.push(("rogue-admin".to_string(), decision.sign(&rogue)));
    let err = aggregate(&shares, &registry).expect_err("rogue signer must be rejected");
    assert_eq!(
        err,
        fcp_crypto::bls::BlsError::PopMissing {
            signer: "rogue-admin".to_string()
        }
    );

    // 2. Verification-time enforcement: a certificate that lists an
    //    unregistered signer (aggregated against a permissive registry the
    //    attacker controls) is rejected by the honest verifier.
    let mut attacker_registry = remote_registry(&admins);
    attacker_registry
        .register("rogue-admin", rogue.public_key(), &rogue.prove_possession())
        .expect("attacker registers the rogue key on their own side");
    let forged = aggregate(&shares, &attacker_registry).expect("attacker-side aggregation");
    let certificate = BlsQuorumCertificate {
        decision,
        aggregate: forged,
    };

    let mut eligible = eligible_set(&admins);
    eligible.insert("rogue-admin".to_string());
    let err = verify_certificate(
        &certificate,
        &registry, // honest registry: no PoP for rogue-admin
        &eligible,
        &zone_policy(),
        RiskTier::Dangerous,
    )
    .expect_err("honest verifier must refuse the unproven key");
    assert_eq!(
        err,
        QuorumVerifyError::Bls(fcp_crypto::bls::BlsError::PopMissing {
            signer: "rogue-admin".to_string()
        })
    );
}

#[test]
fn failure_injection_falls_back_to_ed25519_path() {
    let admins = admins();
    let decision = admission_decision();
    let registry = remote_registry(&admins);

    // Failure injection: one admin's BLS share is replaced by a share over
    // different bytes (a syntactically valid but wrong signature).
    let mut shares: Vec<(String, BlsSignature)> = admins
        .iter()
        .take(4)
        .map(|a| (a.id.clone(), decision.sign(&a.bls)))
        .collect();
    shares[1].1 = admins[1].bls.sign(b"corrupted share bytes");

    let agg = aggregate(&shares, &registry).expect("corruption is not visible at aggregation");
    let certificate = BlsQuorumCertificate {
        decision: decision.clone(),
        aggregate: agg,
    };

    // The compact path fails closed...
    let err = verify_certificate(
        &certificate,
        &registry,
        &eligible_set(&admins),
        &zone_policy(),
        RiskTier::Dangerous,
    )
    .expect_err("corrupted aggregate must fail");
    assert_eq!(
        err,
        QuorumVerifyError::Bls(fcp_crypto::bls::BlsError::VerificationFailed)
    );

    // ...and the decision still authorizes through the existing per-signer
    // Ed25519 SignatureSet path (each admin signs the same canonical
    // decision bytes with their node key).
    let message = decision.signing_bytes();
    let mut set = SignatureSet::new();
    for admin in admins.iter().take(4) {
        let signature = admin.ed25519.sign(&message);
        let node_sig = NodeSignature::new(NodeId::new(admin.id.clone()), signature.to_bytes(), 0);
        assert!(set.add(node_sig));
    }
    assert!(set.satisfies_quorum(&zone_policy(), RiskTier::Dangerous));

    // The fallback signatures individually verify against each admin's
    // Ed25519 verifying key, so the fallback is a real authorization path,
    // not just a satisfied counter.
    for (admin, node_sig) in admins.iter().take(4).zip(set.iter()) {
        let sig = fcp_crypto::ed25519::Ed25519Signature::from_bytes(&node_sig.signature);
        admin
            .ed25519
            .verifying_key()
            .verify(&message, &sig)
            .expect("fallback ed25519 signature verifies");
    }
}

/// The aggregate signer set is structurally distinct (BTreeSet), so one
/// signer repeating cannot inflate the quorum count — the same property
/// br-31ed83fbd enforced for the Ed25519 `SignatureSet` path.
#[test]
fn duplicate_signer_cannot_inflate_quorum() {
    let admins = admins();
    let decision = admission_decision();
    let registry = remote_registry(&admins);

    let share = decision.sign(&admins[0].bls);
    let shares = vec![(admins[0].id.clone(), share), (admins[0].id.clone(), share)];
    let err = aggregate(&shares, &registry).expect_err("duplicate signer refused");
    assert_eq!(
        err,
        fcp_crypto::bls::BlsError::DuplicateSigner {
            signer: admins[0].id.clone()
        }
    );

    // Even if an attacker hand-crafts an AggregateSignature, `signers` is a
    // set: serializing a duplicate-bearing certificate is impossible via
    // the public API, and the count seen by the policy is the set size.
    let single = aggregate(&shares[..1], &registry).unwrap();
    let certificate = BlsQuorumCertificate {
        decision,
        aggregate: single,
    };
    let err = verify_certificate(
        &certificate,
        &registry,
        &eligible_set(&admins),
        &zone_policy(),
        RiskTier::Dangerous,
    )
    .expect_err("one signer is not a dangerous quorum");
    assert!(matches!(
        err,
        QuorumVerifyError::QuorumNotMet { have: 1, .. }
    ));
}

/// Serialized sizes stay pinned: 48-byte public keys, 96-byte signatures
/// and PoPs. A future curve/encoding change must update this test and the
/// design doc together.
#[test]
fn wire_sizes_are_pinned() {
    let sk = BlsSecretKey::generate();
    assert_eq!(sk.public_key().to_bytes().len(), 48);
    assert_eq!(sk.sign(b"m").to_bytes().len(), 96);
    assert_eq!(sk.prove_possession().to_bytes().len(), 96);
}
