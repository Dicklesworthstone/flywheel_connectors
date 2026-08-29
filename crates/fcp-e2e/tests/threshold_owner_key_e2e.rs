//! Threshold owner-key E2E (br-rl5q7, [E.6] Threshold Owner Key
//! proof gap).
//!
//! `GoldenFinch`'s smdf5 audit found no `crates/fcp-e2e/tests/`
//! real-service scenario for a k-of-n FROST owner-key ceremony,
//! signing a `RevocationObject`-shaped message, losing one
//! participant, and completing the ceremony from the survivors.
//!
//! No mocks. Real `fcp_crypto::frost` DKG (parts 1/2/3 across all
//! participants), real per-participant signing nonces / commitments /
//! shares, real Ed25519 signature aggregation, real `OwnerSigner`
//! integration via `FrostLocalCoordinator`, real
//! `Ed25519VerifyingKey::verify` against the aggregated signature.
//!
//! Coverage matrix:
//! - Full DKG ceremony for k=2 / n=3 produces consistent key packages
//! - Threshold sign with 2-of-3 produces a valid Ed25519 signature
//!   that verifies under the group public key
//! - The bead's marquee scenario: lose one node, remaining two can
//!   still sign (the survivor-quorum property)
//! - Aggregated signature is byte-equivalent to a normal Ed25519
//!   signature — round-trips through standard verifying-key paths,
//!   no FROST-specific verifier needed downstream
//! - Single share alone (k-1 = 1) cannot proceed: `signing_package()`
//!   rejects with structured error
//! - Wrong-key forgery resistance: aggregated signature does NOT
//!   verify under a different verifying key
//! - Production payload shape: sign over a `RevocationObject`-shaped
//!   transcript and verify the signature
//! - Lean-witness status documented: smdf5 found NO Lean theorem for
//!   FROST owner-key semantics; this scenario asserts the absence
//!   matches the registered theorem list so the gap stays visible.

use std::collections::BTreeMap;

use chrono::Utc;
use serde_json::json;

use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_crypto::frost::{
    FrostDkgRound2Package, FrostKeyPackage, FrostLocalCoordinator, FrostPublicKeyPackage,
    aggregate, commit, dkg_part1, dkg_part2, dkg_part3, sign, signing_package,
};
use fcp_e2e::evidence::FORMAL_INVARIANT_THEOREMS;

/// JSONL log entry per phase per scenario, per the testing-perfect-e2e
/// triage contract. Visible under `cargo test -- --nocapture`.
fn log_event(scenario_id: &str, phase: &str, outcome: &str, detail: Option<&str>) {
    let entry = json!({
        "ts": Utc::now().to_rfc3339(),
        "scenario_id": scenario_id,
        "bead": "rl5q7",
        "phase": phase,
        "outcome": outcome,
        "detail": detail,
    });
    println!("{entry}");
}

/// Run the full FROST DKG (parts 1/2/3) end-to-end across `max_signers`
/// participants using OS randomness (per-participant fresh entropy —
/// matches production deployment shape, where each node has its own
/// hardware RNG). Returns each participant's `FrostKeyPackage` plus
/// the consensus `FrostPublicKeyPackage` (every participant produces
/// the same one — asserted in the happy-path scenario below).
fn execute_dkg(
    min_signers: u16,
    max_signers: u16,
) -> (BTreeMap<u16, FrostKeyPackage>, FrostPublicKeyPackage) {
    let mut round1_secrets = BTreeMap::new();
    let mut round1_public = BTreeMap::new();

    for participant in 1..=max_signers {
        let (secret, package) =
            dkg_part1(participant, max_signers, min_signers).expect("dkg_part1");
        round1_secrets.insert(participant, secret);
        round1_public.insert(participant, package);
    }

    let mut round2_secrets = BTreeMap::new();
    let mut inbound_round2: BTreeMap<u16, BTreeMap<u16, FrostDkgRound2Package>> =
        (1..=max_signers).map(|p| (p, BTreeMap::new())).collect();

    for participant in 1..=max_signers {
        let received = round1_public
            .iter()
            .filter(|(s, _)| **s != participant)
            .map(|(s, p)| (*s, p.clone()))
            .collect::<BTreeMap<_, _>>();
        let (secret, outbound) =
            dkg_part2(round1_secrets.get(&participant).unwrap(), &received).expect("dkg_part2");
        round2_secrets.insert(participant, secret);
        for (recipient, package) in outbound {
            inbound_round2
                .get_mut(&recipient)
                .unwrap()
                .insert(participant, package);
        }
    }

    let mut key_packages = BTreeMap::new();
    let mut public_packages = BTreeMap::new();
    for participant in 1..=max_signers {
        let received_round1 = round1_public
            .iter()
            .filter(|(s, _)| **s != participant)
            .map(|(s, p)| (*s, p.clone()))
            .collect::<BTreeMap<_, _>>();
        let received_round2 = inbound_round2.remove(&participant).unwrap();
        let (key_package, public_key_package) = dkg_part3(
            round2_secrets.get(&participant).unwrap(),
            &received_round1,
            &received_round2,
        )
        .expect("dkg_part3");
        key_packages.insert(participant, key_package);
        public_packages.insert(participant, public_key_package);
    }

    let consensus = public_packages
        .values()
        .next()
        .expect("at least one participant")
        .clone();
    for pk in public_packages.values() {
        assert_eq!(
            pk, &consensus,
            "DKG outputs MUST be consensus across all participants"
        );
    }

    (key_packages, consensus)
}

/// Run a threshold signing ceremony with the supplied participants.
/// Returns the aggregated Ed25519 signature.
fn threshold_sign_with_participants(
    selected: &[u16],
    key_packages: &BTreeMap<u16, FrostKeyPackage>,
    public_key_package: &FrostPublicKeyPackage,
    message: &[u8],
) -> Result<fcp_crypto::ed25519::Ed25519Signature, fcp_crypto::CryptoError> {
    let mut commitment_map = BTreeMap::new();
    let mut nonces_map = BTreeMap::new();
    for &participant in selected {
        let key_pkg = key_packages
            .get(&participant)
            .expect("selected participant must hold a key package");
        let (nonces, commitments) = commit(key_pkg)?;
        nonces_map.insert(participant, nonces);
        commitment_map.insert(participant, commitments);
    }

    let pkg = signing_package(public_key_package, &commitment_map, message)?;
    let mut shares = BTreeMap::new();
    for &participant in selected {
        let share = sign(
            &pkg,
            nonces_map
                .remove(&participant)
                .expect("nonces present for selected participant"),
            key_packages.get(&participant).expect("key package present"),
        )?;
        shares.insert(participant, share);
    }
    aggregate(&pkg, &shares, public_key_package)
}

// ─────────────────────────────────────────────────────────────────────
// Scenario 1: full DKG ceremony for k=2 / n=3 produces consistent key
// packages. Locks the baseline so subsequent threshold-signing
// scenarios run against a real DKG output (not a synthesized fixture).
// ─────────────────────────────────────────────────────────────────────

#[test]
fn threshold_owner_key_e2e_dkg_ceremony_produces_consensus_key_packages() {
    let scenario = "rl5q7.dkg_ceremony";
    log_event(scenario, "setup", "started", None);

    log_event(scenario, "dkg", "running", Some("k=2 n=3"));
    let (key_packages, public_key_package) = execute_dkg(2, 3);
    assert_eq!(public_key_package.min_signers(), 2);
    assert_eq!(public_key_package.max_signers(), 3);
    assert_eq!(public_key_package.verifying_shares().len(), 3);
    log_event(
        scenario,
        "dkg",
        "passed",
        Some(&format!(
            "group_key_id={}",
            public_key_package.group_public_key().key_id().to_hex()
        )),
    );

    // Every participant's key package agrees on the group public key.
    for (participant, key_package) in &key_packages {
        assert_eq!(key_package.participant(), *participant);
        assert_eq!(key_package.min_signers(), 2);
        assert_eq!(key_package.max_signers(), 3);
        assert_eq!(
            key_package.group_public_key(),
            public_key_package.group_public_key(),
            "participant {participant} group key MUST match consensus"
        );
        key_package
            .validate()
            .expect("each key package MUST be internally consistent");
    }
    public_key_package
        .validate()
        .expect("public key package MUST validate");
}

// ─────────────────────────────────────────────────────────────────────
// Scenario 2: threshold sign with 2-of-3 produces a valid Ed25519
// signature that verifies under the group public key. The aggregated
// signature is byte-equivalent to a standard Ed25519 signature — no
// FROST-specific verifier needed downstream.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn threshold_owner_key_e2e_two_of_three_produces_valid_ed25519_signature() {
    let scenario = "rl5q7.two_of_three_sign";
    log_event(scenario, "setup", "started", None);

    let (key_packages, pkpkg) = execute_dkg(2, 3);
    let message = b"FCP3-OWNER-CEREMONY: zone-key-rotation v1";

    log_event(scenario, "sign", "running", Some("participants=1,2"));
    let signature = threshold_sign_with_participants(&[1, 2], &key_packages, &pkpkg, message)
        .expect("2-of-3 sign MUST succeed");
    log_event(scenario, "sign", "passed", None);

    // Verify under the group public key — same path any downstream
    // consumer would use to authenticate an owner-signed object.
    log_event(scenario, "verify", "running", None);
    pkpkg
        .group_public_key()
        .verify(message, &signature)
        .expect("aggregated signature MUST verify under group public key");
    log_event(scenario, "verify", "passed", None);
}

// ─────────────────────────────────────────────────────────────────────
// Scenario 3: marquee — lose one node, remaining two can still sign.
// The bead's headline acceptance: simulate node 2 dropping (offline,
// network-partitioned, decommissioned), and verify nodes 1 + 3 alone
// can complete the ceremony.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn threshold_owner_key_e2e_lose_one_node_remaining_two_can_sign() {
    let scenario = "rl5q7.lose_one_node";
    log_event(scenario, "setup", "started", None);

    let (key_packages, pkpkg) = execute_dkg(2, 3);
    let message = b"FCP3-OWNER-CEREMONY: emergency-revocation v1";

    log_event(scenario, "node_2_offline", "simulated", None);
    // Nodes 1 and 3 alone — node 2 simulated as offline.
    log_event(
        scenario,
        "sign_with_survivors",
        "running",
        Some("participants=1,3"),
    );
    let signature = threshold_sign_with_participants(&[1, 3], &key_packages, &pkpkg, message)
        .expect("survivor quorum (1+3) MUST sign without node 2");
    log_event(scenario, "sign_with_survivors", "passed", None);

    pkpkg
        .group_public_key()
        .verify(message, &signature)
        .expect("survivor-quorum signature MUST verify under group key");
    log_event(scenario, "verify", "passed", None);
}

// ─────────────────────────────────────────────────────────────────────
// Scenario 4: K-1 alone CANNOT proceed. The bead's "assert K-1 cannot
// proceed" requirement: with min_signers=2, a single-participant
// signing_package() call MUST be rejected with a structured error.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn threshold_owner_key_e2e_k_minus_one_alone_cannot_proceed() {
    let scenario = "rl5q7.k_minus_one_blocked";
    log_event(scenario, "setup", "started", None);

    let (key_packages, pkpkg) = execute_dkg(2, 3);
    let message = b"FCP3-OWNER-CEREMONY: attempted unilateral signing";

    // Try to build a signing package with only ONE participant's
    // commitments — must be rejected.
    let (_nonces, commitments) = commit(key_packages.get(&1).unwrap()).expect("commit ok");
    let mut single_commitment_map = BTreeMap::new();
    single_commitment_map.insert(1_u16, commitments);

    log_event(scenario, "build_single_signer_package", "running", None);
    let err = signing_package(&pkpkg, &single_commitment_map, message)
        .expect_err("single-signer signing_package MUST be rejected");
    log_event(
        scenario,
        "build_single_signer_package",
        "rejected",
        Some(&format!("{err:?}")),
    );

    // Belt-and-braces: the FrostLocalCoordinator constructor enforces
    // the same threshold floor — passing < min_signers key packages
    // MUST be rejected before signing can even be attempted.
    let mut single_kp = BTreeMap::new();
    single_kp.insert(1_u16, key_packages.get(&1).unwrap().clone());
    log_event(scenario, "coordinator_with_single_kp", "running", None);
    let coord_err = FrostLocalCoordinator::new(single_kp, pkpkg.clone())
        .err()
        .expect("coordinator MUST refuse < min_signers key packages");
    log_event(
        scenario,
        "coordinator_with_single_kp",
        "rejected",
        Some(&format!("{coord_err:?}")),
    );
}

// ─────────────────────────────────────────────────────────────────────
// Scenario 5: forgery resistance — the aggregated signature MUST NOT
// verify under any other Ed25519 verifying key. Defends against the
// "stolen key swap" failure mode where an attacker tries to claim a
// legitimate signature was made by a different group.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn threshold_owner_key_e2e_signature_does_not_verify_under_unrelated_key() {
    let scenario = "rl5q7.forgery_resistance_wrong_key";
    log_event(scenario, "setup", "started", None);

    let (key_packages, pkpkg) = execute_dkg(2, 3);
    let message = b"FCP3-OWNER-CEREMONY: wrong-key check";
    let signature = threshold_sign_with_participants(&[1, 2], &key_packages, &pkpkg, message)
        .expect("2-of-3 sign ok");

    // An attacker's freshly-generated key MUST NOT verify the
    // aggregated signature.
    let attacker_key = Ed25519SigningKey::generate();
    log_event(scenario, "verify_under_attacker_key", "running", None);
    let err = attacker_key
        .verifying_key()
        .verify(message, &signature)
        .expect_err("verification under attacker key MUST fail");
    log_event(
        scenario,
        "verify_under_attacker_key",
        "rejected",
        Some(&format!("{err:?}")),
    );
}

// ─────────────────────────────────────────────────────────────────────
// Scenario 6: forgery resistance — tampering the message MUST
// invalidate the signature even under the correct group key. Catches
// the "signature replay against modified payload" failure mode.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn threshold_owner_key_e2e_tampered_message_does_not_verify() {
    let scenario = "rl5q7.forgery_resistance_tampered_msg";
    log_event(scenario, "setup", "started", None);

    let (key_packages, pkpkg) = execute_dkg(2, 3);
    let message = b"FCP3-OWNER-CEREMONY: original payload";
    let signature = threshold_sign_with_participants(&[1, 2], &key_packages, &pkpkg, message)
        .expect("2-of-3 sign ok");

    let mut tampered = message.to_vec();
    tampered[message.len() - 1] ^= 0x01;
    log_event(scenario, "verify_tampered_message", "running", None);
    let err = pkpkg
        .group_public_key()
        .verify(&tampered, &signature)
        .expect_err("tampered message MUST NOT verify under group key");
    log_event(
        scenario,
        "verify_tampered_message",
        "rejected",
        Some(&format!("{err:?}")),
    );
}

// ─────────────────────────────────────────────────────────────────────
// Scenario 7: production payload shape — sign over a transcript that
// mirrors a real `RevocationObject` body (zone_id || object_ids ||
// rev_seq) and verify the signature. This is the actual path the
// host would use to produce a quorum-signed revocation.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn threshold_owner_key_e2e_revocation_object_signing_byte_equivalent() {
    let scenario = "rl5q7.revocation_object_signing";
    log_event(scenario, "setup", "started", None);

    let (key_packages, pkpkg) = execute_dkg(2, 3);

    // Construct a RevocationObject-shaped transcript: domain prefix +
    // zone bytes + sorted object id bytes + rev_seq. Same shape the
    // production owner signer commits to.
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"FCP3-OWNER-REVOCATION-V1");
    transcript.extend_from_slice(b"z:work");
    let mut object_ids: Vec<[u8; 32]> = (0..5).map(|i| [i; 32]).collect();
    object_ids.sort_unstable();
    for id in &object_ids {
        transcript.extend_from_slice(id);
    }
    transcript.extend_from_slice(&42_u64.to_le_bytes());

    log_event(
        scenario,
        "sign_revocation_transcript",
        "running",
        Some(&format!("transcript_bytes={}", transcript.len())),
    );
    let signature = threshold_sign_with_participants(&[2, 3], &key_packages, &pkpkg, &transcript)
        .expect("2-of-3 sign ok over revocation transcript");
    log_event(scenario, "sign_revocation_transcript", "passed", None);

    pkpkg
        .group_public_key()
        .verify(&transcript, &signature)
        .expect("revocation transcript signature MUST verify under group key");
    log_event(scenario, "verify_revocation_transcript", "passed", None);
}

// ─────────────────────────────────────────────────────────────────────
// Scenario 8: FrostLocalCoordinator integration — verify the
// production OwnerSigner path produces a valid signature using the
// same DKG output. Locks the OwnerSigner trait contract (the same
// trait fcp-host uses to sign owner-issued objects).
// ─────────────────────────────────────────────────────────────────────

#[test]
fn threshold_owner_key_e2e_owner_signer_trait_signs_via_coordinator() {
    use fcp_crypto::ed25519::OwnerSigner;

    let scenario = "rl5q7.owner_signer_trait";
    log_event(scenario, "setup", "started", None);

    let (key_packages, pkpkg) = execute_dkg(2, 3);
    let coordinator = FrostLocalCoordinator::new(key_packages, pkpkg.clone())
        .expect("coordinator must accept all 3 key packages (≥ min_signers=2)");

    // owner_key_id MUST be the group key's KeyId — fcp-audit and
    // fcp-evidence consumers key off this.
    assert_eq!(
        coordinator.owner_key_id(),
        pkpkg.group_public_key().key_id()
    );

    let message = b"FCP3-OWNER-CEREMONY: owner_signer trait integration";
    log_event(scenario, "owner_sign", "running", None);
    let signature = coordinator
        .owner_sign(message)
        .expect("OwnerSigner::owner_sign via FROST coordinator MUST succeed");
    log_event(scenario, "owner_sign", "passed", None);

    pkpkg
        .group_public_key()
        .verify(message, &signature)
        .expect("OwnerSigner-produced signature MUST verify under group key");
    log_event(scenario, "verify", "passed", None);
}

// ─────────────────────────────────────────────────────────────────────
// Scenario 9: lean-witness gap is documented. smdf5 audit found NO
// Lean theorem for FROST owner-key ceremony semantics. This scenario
// asserts the absence: there is currently no theorem matching the
// FROST/threshold-owner-key topic registered in
// FORMAL_INVARIANT_THEOREMS, so the formal-gate loader cannot
// automatically attach one. Future work landing such a theorem
// should both extend FORMAL_INVARIANT_THEOREMS and update this
// assertion in the same commit so the gap-tracking stays honest.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn threshold_owner_key_e2e_lean_witness_absence_documented() {
    let scenario = "rl5q7.lean_witness_gap";
    log_event(scenario, "setup", "started", None);

    let frost_themed = FORMAL_INVARIANT_THEOREMS.iter().any(|t| {
        let lower = t.to_ascii_lowercase();
        lower.contains("frost") || lower.contains("threshold") || lower.contains("ceremony")
    });
    assert!(
        !frost_themed,
        "smdf5 audit recorded NO FROST/threshold/ceremony Lean theorem; if a witness \
         was just added, update this scenario to assert the new theorem name AND \
         update FORMAL_INVARIANT_THEOREMS to include it. (Currently registered: {FORMAL_INVARIANT_THEOREMS:?})"
    );
    log_event(
        scenario,
        "verify_witness_absence",
        "passed",
        Some("no_frost_lean_witness_yet"),
    );
}
