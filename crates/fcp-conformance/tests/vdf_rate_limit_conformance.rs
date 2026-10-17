//! Conformance suite for Wesolowski VDF owner-key rate limiting (`flywheel_connectors-angoc.17.5`).

use std::time::Duration;

use fcp_crypto::vdf::{
    DEFAULT_OWNER_KEY_VDF_ITERATIONS, VDF_PROOF_MAX_BYTES, VdfParams, WesolowskiVdf,
};
use fcp_host::owner_key::{
    DEFAULT_OWNER_KEY_HOURLY_CAP, OwnerKeyGateDecision, OwnerKeyVdfRateGate, OwnerKeyVdfSubmission,
};

#[test]
fn owner_key_burst_attack() {
    let iterations = 64;
    let mut gate = OwnerKeyVdfRateGate::new(DEFAULT_OWNER_KEY_HOURLY_CAP, iterations, 1);

    let mut accepted = 0usize;
    let mut cap_rejected = 0usize;

    // Submit 500 owner-key operations in a 1-hour window.
    for idx in 0..500u64 {
        let challenge = format!("owner-key:burst-op:{idx}").into_bytes();
        let proof = WesolowskiVdf::eval(
            &challenge,
            VdfParams::new(iterations).with_calibrated_floor_ms(0),
        )
        .expect("VDF eval succeeds");
        let submission = OwnerKeyVdfSubmission {
            owner_id: "owner:root".to_owned(),
            operation: "owner.rotate_zone_key".to_owned(),
            timestamp_secs: 1_700_000_000 + (idx % 1800),
            challenge,
            proof,
        };

        match gate.submit(&submission) {
            OwnerKeyGateDecision::Accepted { .. } => accepted += 1,
            OwnerKeyGateDecision::RejectedRateCapExceeded { alert, .. } => {
                assert_eq!(alert.kind, "rate_cap_exceeded");
                cap_rejected += 1;
            }
            other => panic!("unexpected gate decision on op {idx}: {other:?}"),
        }
    }

    assert_eq!(accepted, 100, "rate gate must accept at most 100 ops/hour");
    assert_eq!(
        cap_rejected, 400,
        "remaining 400 burst ops must be rejected by rate gate"
    );
    assert_eq!(gate.gate_triggered_count(), 400);
    assert_eq!(gate.audit_alerts().len(), 400);

    let doctor = gate.doctor_report();
    assert_eq!(doctor.ops_last_hour, 100);
    assert_eq!(doctor.gate_triggered_count, 400);
    assert!(doctor.warning);
}

#[test]
fn mutated_vdf_proof_triggers_audit_alert_and_manual_approve_fallback() {
    let iterations = DEFAULT_OWNER_KEY_VDF_ITERATIONS;
    let mut gate = OwnerKeyVdfRateGate::new(DEFAULT_OWNER_KEY_HOURLY_CAP, iterations, 100);

    let challenge = b"owner-key:emergency-override:z:owner".to_vec();
    let proof = WesolowskiVdf::eval(&challenge, VdfParams::new(iterations))
        .expect("calibrated T=10000 eval succeeds");
    assert!(proof.proof_bytes().len() <= VDF_PROOF_MAX_BYTES);
    assert!(proof.eval_ms >= 100);

    let verify_dur = WesolowskiVdf::verify(&challenge, iterations, &proof)
        .expect("unmodified proof verifies");
    assert!(verify_dur < Duration::from_millis(5));

    // Mutate one byte of the proof witness and submit to the host gate.
    let mut mutated_proof = proof;
    mutated_proof.pi[7] ^= 0x5A;

    let submission = OwnerKeyVdfSubmission {
        owner_id: "owner:root".to_owned(),
        operation: "owner.emergency_override".to_owned(),
        timestamp_secs: 1_700_010_000,
        challenge,
        proof: mutated_proof,
    };

    match gate.submit(&submission) {
        OwnerKeyGateDecision::RejectedInvalidVdf {
            fallback_manual_approve,
            alert,
            ..
        } => {
            assert!(
                fallback_manual_approve,
                "mutated VDF proof must fall back to manual-approve path"
            );
            assert_eq!(alert.kind, "invalid_vdf_proof");
        }
        other => panic!("expected RejectedInvalidVdf, got {other:?}"),
    }
}
