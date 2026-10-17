//! Aggregate conformance test for Phase A.bis mesh-state alien-graveyard accretions
//! (`flywheel_connectors-angoc.17`).
//!
//! Exercises the smoke path for all five Phase A.bis accretions:
//! - A.bis.1: KZG & IPA vector commitments (`fcp_crypto::vector_commit`)
//! - A.bis.2: Masked IBLT anti-entropy (`fcp_mesh::iblt`)
//! - A.bis.3: Hybrid Logical Clocks (HLC) & Hierarchical Version Vectors (`fcp_core`)
//! - A.bis.4: BLS12-381 threshold aggregate quorum signatures with PoP (`fcp_crypto::bls`)
//! - A.bis.5: Wesolowski VDF owner-key rate limiter (`fcp_crypto::vdf` + `fcp_host::owner_key`)

use std::collections::BTreeSet;
use std::sync::Arc;

use fcp_audit::{HybridLogicalClock, HybridLogicalTimestamp};
use fcp_core::{ObjectId, ZoneId};
use fcp_crypto::bls::{BlsSecretKey, PopRegistry, aggregate, verify_aggregate};
use fcp_crypto::vdf::{VdfParams, WesolowskiVdf};
use fcp_crypto::vector_commit::kzg::KzgSrs;
use fcp_crypto::vector_commit::{
    IpaVectorCommitment, KzgVectorCommitment, VectorCommitmentScheme,
};
use fcp_host::owner_key::{OwnerKeyVdfRateGate, OwnerKeyVdfSubmission};
use fcp_mesh::iblt::{IbltMask, MaskedIblt};

#[test]
fn phase_a_bis_1_vector_commitments_kzg_and_ipa_smoke() {
    let slots = vec![[0x11u8; 32], [0x22u8; 32], [0x33u8; 32], [0x44u8; 32]];

    let srs = Arc::new(KzgSrs::insecure_deterministic(4, b"phase-a-bis-smoke"));
    let kzg = KzgVectorCommitment::new(srs, 4).expect("KZG setup");
    let kzg_commit = kzg.commit(&slots).expect("KZG commit");
    let kzg_proof = kzg.open(&slots, 2).expect("KZG open");
    kzg.verify(&kzg_commit, 2, &slots[2], &kzg_proof)
        .expect("KZG verify");

    let ipa = IpaVectorCommitment::new(4).expect("IPA setup");
    let ipa_commit = ipa.commit(&slots).expect("IPA commit");
    let ipa_proof = ipa.open(&slots, 2).expect("IPA open");
    ipa.verify(&ipa_commit, 2, &slots[2], &ipa_proof)
        .expect("IPA verify");
}

#[test]
fn phase_a_bis_2_masked_iblt_set_reconciliation_smoke() {
    let mask = IbltMask::for_zone(&ZoneId::work());
    let mut alice = MaskedIblt::with_cell_count(mask, 64).expect("alice IBLT");
    let mut bob = MaskedIblt::with_cell_count(mask, 64).expect("bob IBLT");

    let shared = ObjectId::from_bytes([0xAAu8; 32]);
    let alice_only = ObjectId::from_bytes([0xBBu8; 32]);
    let bob_only = ObjectId::from_bytes([0xCCu8; 32]);

    alice.insert(shared);
    alice.insert(alice_only);

    bob.insert(shared);
    bob.insert(bob_only);

    let diff = alice.subtract(&bob).expect("IBLT subtract");
    let decoded = diff.decode();
    assert!(decoded.complete, "IBLT peel should complete cleanly");
    assert_eq!(decoded.only_left, BTreeSet::from([alice_only]));
    assert_eq!(decoded.only_right, BTreeSet::from([bob_only]));
}

#[test]
fn phase_a_bis_3_hlc_causality_monotonicity_smoke() {
    let mut clock_a = HybridLogicalClock::new("node-a");
    let mut clock_b = HybridLogicalClock::new("node-b");

    let t1: HybridLogicalTimestamp = clock_a.tick(1_700_000_000_000);
    let t2: HybridLogicalTimestamp = clock_b.merge(&t1, 1_700_000_000_000);
    assert!(
        t2 > t1,
        "HLC merge must advance causally past sender timestamp"
    );
}

#[test]
fn phase_a_bis_4_bls_aggregate_quorum_with_pop_smoke() {
    let mut registry = PopRegistry::new();
    let signers: Vec<(String, BlsSecretKey)> = (0..3)
        .map(|idx| (format!("node-{idx}"), BlsSecretKey::generate()))
        .collect();
    for (id, sk) in &signers {
        registry
            .register(id.clone(), sk.public_key(), &sk.prove_possession())
            .expect("PoP registration succeeds");
    }

    let msg = b"phase-a-bis-quorum-checkpoint";
    let shares: Vec<(String, _)> = signers
        .iter()
        .map(|(id, sk)| (id.clone(), sk.sign(msg)))
        .collect();
    let agg = aggregate(&shares, &registry).expect("BLS aggregation succeeds");
    assert_eq!(agg.signature().to_bytes().len(), 96);
    verify_aggregate(&agg, msg, &registry).expect("BLS aggregate verification succeeds");
}

#[test]
fn phase_a_bis_5_wesolowski_vdf_owner_key_rate_gate_smoke() {
    let iterations = 64;
    let mut gate = OwnerKeyVdfRateGate::new(100, iterations, 1);
    let challenge = b"owner-key:phase-a-bis-smoke".to_vec();
    let proof = WesolowskiVdf::eval(
        &challenge,
        VdfParams::new(iterations).with_calibrated_floor_ms(0),
    )
    .expect("Wesolowski VDF eval");

    let submission = OwnerKeyVdfSubmission {
        owner_id: "owner:root".to_owned(),
        operation: "owner.rotate_key".to_owned(),
        timestamp_secs: 1_700_000_000,
        challenge,
        proof,
    };
    assert!(gate.submit(&submission).is_accepted());
}
