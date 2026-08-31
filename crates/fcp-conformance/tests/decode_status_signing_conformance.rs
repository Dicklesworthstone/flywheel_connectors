//! `DecodeStatus` transcript-binding + anti-amplification conformance.
//!
//! `DecodeStatus` (in `fcp-protocol/src/fcps.rs`) is the per-progress
//! status the receiver sends during a symbol transfer. Its transcript
//! binds to:
//!
//! ```text
//! "FCP2-DECODE-STATUS-V2" || object_id || zone_id || zone_key_id ||
//! epoch_id || recipient_node_id || request_nonce || received_unique ||
//! needed || complete || missing_hint
//! ```
//!
//! Two normative properties are pinned here:
//!
//! 1. **Transcript binding** — every signed field must round-trip and
//!    every tampered field must invalidate the signature, so a captured
//!    `DecodeStatus` cannot be repurposed onto a different exchange or
//!    progress claim.
//!
//! 2. **Anti-amplification guard** — `DecodeStatus::verify` rejects
//!    `missing_hint` payloads above `MAX_MISSING_HINT_ENTRIES` (= 100)
//!    BEFORE materializing the transcript. This stops an attacker
//!    from forcing a multi-MB allocation on every verify call. The
//!    test below pins the pre-transcript rejection, complementing the
//!    fuzz target that already protects against panics.

use fcp_cbor::SchemaId;
use fcp_crypto::{Ed25519Signature, Ed25519SigningKey};
use fcp_prelude::{ObjectHeader, ObjectId, Provenance, TailscaleNodeId, ZoneId, ZoneKeyId};
use fcp_protocol::{DecodeStatus, MAX_MISSING_HINT_ENTRIES};
use semver::Version;

fn test_header(zone: &ZoneId) -> ObjectHeader {
    ObjectHeader {
        encryption_kind: Default::default(),
        schema: SchemaId::new("fcp.test", "TestObject", Version::new(1, 0, 0)),
        zone_id: zone.clone(),
        created_at: 1_704_067_200,
        provenance: Provenance::new(zone.clone()),
        refs: vec![],
        foreign_refs: vec![],
        ttl_secs: None,
        placement: None,
    }
}

fn baseline_status() -> (DecodeStatus, Ed25519SigningKey) {
    let signing_key = Ed25519SigningKey::generate();
    let zone = ZoneId::work();
    let mut status = DecodeStatus {
        header: test_header(&zone),
        object_id: ObjectId::from_bytes([0x11; 32]),
        zone_id: zone,
        zone_key_id: ZoneKeyId::from_bytes([0x22; 8]),
        epoch_id: 1_000,
        recipient_node_id: TailscaleNodeId::new("node-recipient"),
        request_nonce: 0xCAFE_BABE_u64,
        received_unique: 500,
        needed: 1003,
        complete: false,
        missing_hint: Some(vec![10, 20, 30]),
        signature: Ed25519Signature::from_bytes(&[0u8; 64]),
    };
    status.sign(&signing_key);
    (status, signing_key)
}

#[test]
fn round_trip_sign_then_verify_passes() {
    let (status, signing_key) = baseline_status();
    status
        .verify(&signing_key.verifying_key())
        .expect("a freshly-signed DecodeStatus must verify under the same key");
}

#[test]
fn status_signed_under_one_key_does_not_verify_under_another() {
    let (status, _) = baseline_status();
    let attacker = Ed25519SigningKey::generate();
    status
        .verify(&attacker.verifying_key())
        .expect_err("DecodeStatus must not verify under a key that did not sign it");
}

#[test]
fn transcript_binds_to_object_id() {
    let (mut status, signing_key) = baseline_status();
    status.object_id = ObjectId::from_bytes([0x99; 32]);
    status
        .verify(&signing_key.verifying_key())
        .expect_err("signature must reject object_id tamper");
}

#[test]
fn transcript_binds_to_zone_id() {
    let (mut status, signing_key) = baseline_status();
    status.zone_id = ZoneId::private();
    status
        .verify(&signing_key.verifying_key())
        .expect_err("signature must reject zone_id tamper");
}

#[test]
fn transcript_binds_to_zone_key_id() {
    let (mut status, signing_key) = baseline_status();
    status.zone_key_id = ZoneKeyId::from_bytes([0xFF; 8]);
    status
        .verify(&signing_key.verifying_key())
        .expect_err("signature must reject zone_key_id tamper (key-rotation defense)");
}

#[test]
fn transcript_binds_to_epoch_id() {
    let (mut status, signing_key) = baseline_status();
    status.epoch_id = status.epoch_id.wrapping_add(1);
    status
        .verify(&signing_key.verifying_key())
        .expect_err("signature must reject epoch_id tamper (cross-epoch replay defense)");
}

#[test]
fn transcript_binds_to_recipient_node_id() {
    let (mut status, signing_key) = baseline_status();
    status.recipient_node_id = TailscaleNodeId::new("node-other");
    status
        .verify(&signing_key.verifying_key())
        .expect_err("signature must reject recipient_node_id tamper");
}

#[test]
fn transcript_binds_to_request_nonce() {
    // request_nonce uniquely identifies the symbol-request exchange
    // this status belongs to. The per-exchange replay defense.
    let (mut status, signing_key) = baseline_status();
    status.request_nonce = status.request_nonce.wrapping_add(1);
    status
        .verify(&signing_key.verifying_key())
        .expect_err("signature must reject request_nonce tamper (per-exchange replay defense)");
}

#[test]
fn transcript_binds_to_received_unique() {
    // The receiver-progress field. An attacker who flipped this
    // could lie about how much of the transfer has completed,
    // potentially tricking the sender into stopping early.
    let (mut status, signing_key) = baseline_status();
    status.received_unique = status.received_unique.wrapping_add(1);
    status
        .verify(&signing_key.verifying_key())
        .expect_err("signature must reject received_unique tamper");
}

#[test]
fn transcript_binds_to_needed() {
    let (mut status, signing_key) = baseline_status();
    status.needed = status.needed.wrapping_add(1);
    status
        .verify(&signing_key.verifying_key())
        .expect_err("signature must reject `needed` tamper");
}

#[test]
fn transcript_binds_to_complete_flag() {
    // The complete bool is the success signal. Letting an attacker
    // flip a not-complete status into a complete one would convince
    // the sender to stop sending symbols mid-transfer.
    let (mut status, signing_key) = baseline_status();
    assert!(!status.complete, "fixture sanity: starts incomplete");
    status.complete = true;
    status
        .verify(&signing_key.verifying_key())
        .expect_err("signature must reject `complete` flag tamper");
}

#[test]
fn transcript_binds_to_missing_hint_contents() {
    let (mut status, signing_key) = baseline_status();
    status.missing_hint = Some(vec![99, 100, 101]);
    status
        .verify(&signing_key.verifying_key())
        .expect_err("signature must reject missing_hint contents tamper");
}

#[test]
fn transcript_binds_to_missing_hint_presence() {
    // None vs Some([]) vs Some([entries]) are three distinct states.
    // Removing the hint entirely after signing must invalidate the
    // signature.
    let (mut status, signing_key) = baseline_status();
    assert!(status.missing_hint.is_some(), "fixture sanity");
    status.missing_hint = None;
    status
        .verify(&signing_key.verifying_key())
        .expect_err("signature must reject missing_hint presence tamper (Some -> None)");
}

#[test]
fn oversized_missing_hint_is_rejected_pre_transcript() {
    // NORMATIVE anti-amplification: verify() runs validate_hint_bounds
    // BEFORE building the transcript, so an attacker cannot force a
    // multi-MB transcript allocation on every verify call. We pin
    // that pre-allocation rejection here. The fixture builds a hint
    // of MAX_MISSING_HINT_ENTRIES + 1 entries; verify must reject
    // even though every other field is well-formed and the signature
    // would otherwise be valid.
    let signing_key = Ed25519SigningKey::generate();
    let zone = ZoneId::work();
    let oversized: Vec<u32> = (0..u32::try_from(MAX_MISSING_HINT_ENTRIES + 1).unwrap()).collect();
    let mut status = DecodeStatus {
        header: test_header(&zone),
        object_id: ObjectId::from_bytes([0x11; 32]),
        zone_id: zone,
        zone_key_id: ZoneKeyId::from_bytes([0x22; 8]),
        epoch_id: 1_000,
        recipient_node_id: TailscaleNodeId::new("node-recipient"),
        request_nonce: 0xCAFE_BABE_u64,
        received_unique: 500,
        needed: 1003,
        complete: false,
        missing_hint: Some(oversized),
        signature: Ed25519Signature::from_bytes(&[0u8; 64]),
    };
    // Sign anyway — validate_hint_bounds is supposed to reject BEFORE
    // verify reaches the signature check, so we need a syntactically
    // well-formed signature to prove the rejection isn't just from a
    // bad signature.
    status.sign(&signing_key);

    status.verify(&signing_key.verifying_key()).expect_err(
        "oversized missing_hint must be rejected by validate_hint_bounds before \
                     verify reaches the signature check (anti-amplification guard)",
    );
}

#[test]
fn header_field_is_not_part_of_signed_transcript() {
    // The ObjectHeader is intentionally outside the signed transcript
    // (see the `transcript_bytes` implementation in fcp-protocol). A
    // schema/header drift between sender and receiver MUST NOT break
    // an otherwise-valid status.
    let (mut status, signing_key) = baseline_status();
    let alt_zone = ZoneId::private();
    status.header = test_header(&alt_zone);
    status
        .verify(&signing_key.verifying_key())
        .expect("header is intentionally outside the signed transcript");
}
