//! `SymbolRequest` transcript-binding + pre-verify guard conformance.
//!
//! `SymbolRequest` (in `fcp-protocol/src/fcps.rs`) is the
//! requester-side message that drives a symbol-transfer exchange.
//! Its transcript binds to:
//!
//! ```text
//! "FCP2-SYMBOL-REQ-V1" || object_id || u32_le(|zone_id|) || zone_id ||
//! zone_key_id || epoch_id || max_symbols || current_symbols ||
//! u32_le(|missing_hint|) || missing_hint[0..]
//! ```
//!
//! `header` (an `ObjectHeader`) is intentionally outside the signed
//! transcript — it carries context only.
//!
//! `verify()` additionally enforces two pre-Ed25519 guards (br-7p8rd):
//!
//! 1. `validate_hint_bounds` rejects `missing_hint` payloads above
//!    `MAX_MISSING_HINT_ENTRIES` BEFORE materializing the transcript.
//! 2. `max_symbols > MAX_SYMBOLS_HARD_CAP` (= 2001) is refused at the
//!    same point, so an attacker holding a valid peer-signing key
//!    cannot force a receiver to burn a multi-megabyte transcript or
//!    an Ed25519-verify cycle on a request that admission control
//!    would reject anyway.
//!
//! The br-4p4ti fuzz target proves panic-freedom on adversarial CBOR
//! input. This file pins the ABOVE invariants with explicit oracles.

use fcp_cbor::SchemaId;
use fcp_crypto::Ed25519SigningKey;
use fcp_prelude::{ObjectHeader, ObjectId, Provenance, ZoneId, ZoneKeyId};
use fcp_protocol::{MAX_MISSING_HINT_ENTRIES, MAX_SYMBOLS_HARD_CAP, SymbolRequest};
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

fn baseline_request() -> (SymbolRequest, Ed25519SigningKey) {
    let signing_key = Ed25519SigningKey::generate();
    let zone = ZoneId::work();
    let mut req = SymbolRequest::new(
        test_header(&zone),
        ObjectId::from_bytes([0x11; 32]),
        zone,
        ZoneKeyId::from_bytes([0x22; 8]),
        1_000, // epoch_id
        100,   // max_symbols (well below MAX_SYMBOLS_HARD_CAP=2001)
        25,    // current_symbols
    )
    .with_missing_hint(vec![1, 5, 9]);
    req.sign(&signing_key);
    (req, signing_key)
}

#[test]
fn round_trip_sign_then_verify_passes() {
    let (req, signing_key) = baseline_request();
    req.verify(&signing_key.verifying_key())
        .expect("a freshly-signed SymbolRequest must verify under the same key");
}

#[test]
fn request_signed_under_one_key_does_not_verify_under_another() {
    let (req, _) = baseline_request();
    let attacker = Ed25519SigningKey::generate();
    req.verify(&attacker.verifying_key())
        .expect_err("SymbolRequest must not verify under a key that did not sign it");
}

#[test]
fn transcript_binds_to_object_id() {
    let (mut req, signing_key) = baseline_request();
    req.object_id = ObjectId::from_bytes([0x99; 32]);
    req.verify(&signing_key.verifying_key())
        .expect_err("signature must reject object_id tamper");
}

#[test]
fn transcript_binds_to_zone_id() {
    let (mut req, signing_key) = baseline_request();
    req.zone_id = ZoneId::private();
    req.verify(&signing_key.verifying_key())
        .expect_err("signature must reject zone_id tamper");
}

#[test]
fn transcript_binds_to_zone_key_id() {
    // zone_key_id rotates the zone key. A captured request signed
    // under zone_key_id A MUST NOT be re-presentable as if for
    // zone_key_id B — otherwise rotation is a no-op for requesters.
    let (mut req, signing_key) = baseline_request();
    req.zone_key_id = ZoneKeyId::from_bytes([0xFF; 8]);
    req.verify(&signing_key.verifying_key())
        .expect_err("signature must reject zone_key_id tamper");
}

#[test]
fn transcript_binds_to_epoch_id() {
    // epoch_id is the cross-epoch replay defense.
    let (mut req, signing_key) = baseline_request();
    req.epoch_id = req.epoch_id.wrapping_add(1);
    req.verify(&signing_key.verifying_key())
        .expect_err("signature must reject epoch_id tamper (cross-epoch replay defense)");
}

#[test]
fn transcript_binds_to_max_symbols() {
    // Rewriting max_symbols would let an attacker amplify a captured
    // request — turning a request for 10 symbols into a request for
    // 1000.
    let (mut req, signing_key) = baseline_request();
    req.max_symbols = req.max_symbols.wrapping_add(1);
    req.verify(&signing_key.verifying_key())
        .expect_err("signature must reject max_symbols tamper");
}

#[test]
fn transcript_binds_to_current_symbols() {
    // current_symbols feeds into receiver-side sizing decisions; an
    // attacker who lied about it could trick a sender into
    // over-sending or under-sending.
    let (mut req, signing_key) = baseline_request();
    req.current_symbols = req.current_symbols.wrapping_add(1);
    req.verify(&signing_key.verifying_key())
        .expect_err("signature must reject current_symbols tamper");
}

#[test]
fn transcript_binds_to_missing_hint_contents() {
    let (mut req, signing_key) = baseline_request();
    req.missing_hint = Some(vec![100, 200, 300]);
    req.verify(&signing_key.verifying_key())
        .expect_err("signature must reject missing_hint contents tamper");
}

#[test]
fn transcript_binds_to_missing_hint_presence() {
    // None vs Some(…) is encoded distinctly (4-byte 0 length header
    // vs the actual count). Removing the hint after signing must
    // invalidate the signature.
    let (mut req, signing_key) = baseline_request();
    assert!(req.missing_hint.is_some(), "fixture sanity: hint is Some");
    req.missing_hint = None;
    req.verify(&signing_key.verifying_key())
        .expect_err("signature must reject missing_hint presence tamper (Some -> None)");
}

#[test]
fn transcript_binds_to_missing_hint_count() {
    // Adding an entry to the hint changes both the length prefix and
    // the body, so the signature must reject.
    let (mut req, signing_key) = baseline_request();
    if let Some(ref mut hint) = req.missing_hint {
        hint.push(42);
    } else {
        panic!("fixture sanity: hint must be Some");
    }
    req.verify(&signing_key.verifying_key())
        .expect_err("signature must reject missing_hint count change");
}

#[test]
fn header_field_is_not_part_of_signed_transcript() {
    // header is intentionally outside the transcript (see
    // transcript_bytes in fcp-protocol). A schema/header drift
    // between sender and receiver MUST NOT break an otherwise-valid
    // request.
    let (mut req, signing_key) = baseline_request();
    req.header = test_header(&ZoneId::private());
    req.verify(&signing_key.verifying_key())
        .expect("header is intentionally outside the signed transcript");
}

#[test]
fn oversized_missing_hint_is_rejected_pre_verify() {
    // br-7p8rd guard: validate_hint_bounds runs BEFORE the transcript
    // is materialized, so an attacker cannot force a multi-MB
    // transcript allocation on every verify call. Build a hint of
    // MAX_MISSING_HINT_ENTRIES + 1 entries; verify must reject even
    // though every other field is well-formed.
    let signing_key = Ed25519SigningKey::generate();
    let zone = ZoneId::work();
    let oversized: Vec<u32> = (0..u32::try_from(MAX_MISSING_HINT_ENTRIES + 1).unwrap()).collect();
    let mut req = SymbolRequest::new(
        test_header(&zone),
        ObjectId::from_bytes([0x11; 32]),
        zone,
        ZoneKeyId::from_bytes([0x22; 8]),
        1_000,
        100,
        25,
    )
    .with_missing_hint(oversized);
    // Sign anyway — the rejection comes from validate_hint_bounds
    // BEFORE the signature check, so we want a syntactically
    // valid signature to prove the rejection isn't just a bad sig.
    req.sign(&signing_key);

    req.verify(&signing_key.verifying_key()).expect_err(
        "oversized missing_hint must be rejected by validate_hint_bounds before \
             reaching the signature check (br-7p8rd anti-amplification guard)",
    );
}

#[test]
fn max_symbols_above_hard_cap_is_rejected_pre_verify() {
    // br-7p8rd guard #2: max_symbols > MAX_SYMBOLS_HARD_CAP (= 2001)
    // is refused before the Ed25519 cycle. Build a request at the
    // hard cap + 1, sign it, and prove verify rejects.
    let signing_key = Ed25519SigningKey::generate();
    let zone = ZoneId::work();
    let mut req = SymbolRequest::new(
        test_header(&zone),
        ObjectId::from_bytes([0x11; 32]),
        zone,
        ZoneKeyId::from_bytes([0x22; 8]),
        1_000,
        MAX_SYMBOLS_HARD_CAP + 1,
        25,
    );
    req.sign(&signing_key);

    req.verify(&signing_key.verifying_key()).expect_err(
        "max_symbols above MAX_SYMBOLS_HARD_CAP must be rejected pre-verify \
             (br-7p8rd anti-amplification guard)",
    );
}

#[test]
fn max_symbols_at_hard_cap_is_accepted_when_signature_is_valid() {
    // The hard cap is exclusive only at the boundary above. A request
    // exactly at MAX_SYMBOLS_HARD_CAP must still verify.
    let signing_key = Ed25519SigningKey::generate();
    let zone = ZoneId::work();
    let mut req = SymbolRequest::new(
        test_header(&zone),
        ObjectId::from_bytes([0x11; 32]),
        zone,
        ZoneKeyId::from_bytes([0x22; 8]),
        1_000,
        MAX_SYMBOLS_HARD_CAP,
        25,
    );
    req.sign(&signing_key);

    req.verify(&signing_key.verifying_key())
        .expect("max_symbols == MAX_SYMBOLS_HARD_CAP must remain accepted");
}
