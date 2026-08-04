//! Conformance: vector-commitment state roots (br-angoc.17.1).
//!
//! Pins the cross-crate contract between `fcp_crypto::vector_commit` and
//! `fcp_mesh::state_root`:
//!
//! 1. `state_root_inclusion_proof` — build a 4096-slot state, commit under
//!    KZG, prove slot 1337, serialize the commitment + proof (a zone hop),
//!    and verify on the far side against a committer rebuilt from the same
//!    SRS. Constant-size proof; two-pairing verify.
//! 2. `cross_tier_kzg_rejected_ipa_reproof_accepted` — a KZG-trusted zone's
//!    commitment/proof is rejected outright by an IPA-only zone
//!    (`SchemeMismatch`), and the holder re-proves over the same slot bytes
//!    under IPA — the transparent, no-trusted-setup path — which the
//!    IPA-only zone accepts.

use std::sync::Arc;

use fcp_crypto::vector_commit::kzg::KzgSrs;
use fcp_crypto::vector_commit::{VcError, VcScheme};
use fcp_mesh::state_root::{
    MerkleTree, StateRootCommitter, StateRootInclusionProof, StateRootScheme,
};

/// Deterministic slot values (BLAKE3 of the index).
fn slots(n: usize) -> Vec<[u8; 32]> {
    (0..n)
        .map(|i| *blake3::hash(&(i as u64).to_le_bytes()).as_bytes())
        .collect()
}

fn roundtrip_commitment(commitment: &fcp_mesh::state_root::StateRootCommitment) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(commitment, &mut buf).expect("commitment serializes");
    buf
}

fn roundtrip_proof(proof: &StateRootInclusionProof) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(proof, &mut buf).expect("proof serializes");
    buf
}

#[test]
fn state_root_inclusion_proof() {
    const N: usize = 4096;
    const SLOT: usize = 1337;

    // Trusted-setup zone: a deterministic SRS stands in for a real
    // powers-of-tau ceremony (documented insecure; test-only).
    let srs = Arc::new(KzgSrs::insecure_deterministic(N, b"state-root-conformance"));
    let prover = StateRootCommitter::kzg(Arc::clone(&srs), N).unwrap();

    let values = slots(N);
    let commitment = prover.commit(&values).unwrap();
    assert_eq!(commitment.scheme, StateRootScheme::Kzg);
    assert_eq!(commitment.n_slots, N as u64);

    let proof = prover.open(&values, SLOT).unwrap();
    // KZG proof is constant-size regardless of N.
    assert_eq!(proof.proof.len(), 48, "KZG opening is one G1 element");

    // Zone hop: serialize both, deserialize on the far side.
    let commitment_bytes = roundtrip_commitment(&commitment);
    let proof_bytes = roundtrip_proof(&proof);
    let far_commitment: fcp_mesh::state_root::StateRootCommitment =
        ciborium::from_reader(&commitment_bytes[..]).unwrap();
    let far_proof: StateRootInclusionProof = ciborium::from_reader(&proof_bytes[..]).unwrap();

    // Far-side verifier rebuilds its committer from the shared SRS.
    let verifier = StateRootCommitter::kzg(srs, N).unwrap();
    verifier
        .verify(&far_commitment, SLOT, &values[SLOT], &far_proof)
        .expect("slot 1337 inclusion verifies across the zone hop");

    // A different slot's value must not verify at index 1337.
    assert_eq!(
        verifier.verify(&far_commitment, SLOT, &values[SLOT + 1], &far_proof),
        Err(VcError::VerificationFailed)
    );

    // The always-present Merkle fallback root matches, and its proof
    // verifies (the integrity anchor beneath the vector commitment).
    let tree = MerkleTree::new(&values);
    assert_eq!(tree.root(), far_commitment.merkle_root);
    let mproof = tree.prove(SLOT).unwrap();
    assert!(MerkleTree::verify(
        &far_commitment.merkle_root,
        N,
        SLOT,
        &values[SLOT],
        &mproof
    ));
    // The Merkle fallback authenticates the index: the same proof must not
    // verify at a different claimed slot.
    assert!(!MerkleTree::verify(
        &far_commitment.merkle_root,
        N,
        SLOT + 1,
        &values[SLOT],
        &mproof
    ));
}

#[test]
fn cross_tier_kzg_rejected_ipa_reproof_accepted() {
    // Small domain keeps the transparent IPA path fast in debug builds;
    // the cross-tier semantics are size-independent.
    const N: usize = 128;
    const SLOT: usize = 77;

    let values = slots(N);

    // KZG-trusted zone commits and proves.
    let srs = Arc::new(KzgSrs::insecure_deterministic(N, b"cross-tier"));
    let kzg_zone = StateRootCommitter::kzg(srs, N).unwrap();
    let kzg_commitment = kzg_zone.commit(&values).unwrap();
    let kzg_proof = kzg_zone.open(&values, SLOT).unwrap();

    // IPA-only zone (trusted-setup ban) refuses the KZG artifacts outright.
    let ipa_zone = StateRootCommitter::ipa(N).unwrap();
    let err = ipa_zone
        .verify(&kzg_commitment, SLOT, &values[SLOT], &kzg_proof)
        .expect_err("IPA-only zone must reject a KZG proof");
    assert_eq!(
        err,
        VcError::SchemeMismatch {
            proof_scheme: VcScheme::Kzg,
            verifier_scheme: VcScheme::Ipa,
        }
    );

    // The holder re-proves the SAME slot bytes under the transparent IPA
    // scheme (no trusted setup anywhere), which the IPA-only zone accepts.
    let ipa_commitment = ipa_zone.commit(&values).unwrap();
    assert_eq!(ipa_commitment.scheme, StateRootScheme::Ipa);
    let ipa_proof = ipa_zone.open(&values, SLOT).unwrap();
    ipa_zone
        .verify(&ipa_commitment, SLOT, &values[SLOT], &ipa_proof)
        .expect("IPA re-proof verifies with no trusted setup");

    // Symmetry: a KZG-trusted zone likewise rejects an IPA proof.
    let err = kzg_zone
        .verify(&ipa_commitment, SLOT, &values[SLOT], &ipa_proof)
        .expect_err("KZG zone must reject an IPA proof");
    assert_eq!(
        err,
        VcError::SchemeMismatch {
            proof_scheme: VcScheme::Ipa,
            verifier_scheme: VcScheme::Kzg,
        }
    );
}
