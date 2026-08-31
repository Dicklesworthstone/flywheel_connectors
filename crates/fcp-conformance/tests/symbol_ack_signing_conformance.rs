//! `SymbolAck` transcript-binding conformance.
//!
//! `SymbolAck` (in `fcp-protocol/src/fcps.rs`) is the receiver-side
//! acknowledgment that closes a symbol-transfer exchange. Its
//! transcript binds to:
//!
//! ```text
//! "FCP2-SYMBOL-ACK-V2" || object_id || zone_id || zone_key_id ||
//! epoch_id || recipient_node_id || request_nonce || reason ||
//! final_symbol_count
//! ```
//!
//! The fuzz target `mesh_post_verify_symbol_ack` covers post-verify
//! mesh handling, but no conformance test had previously pinned the
//! transcript binding itself. A regression that dropped any of these
//! fields would silently allow attackers to repurpose a captured
//! ack — most dangerously by changing `request_nonce` (per-exchange
//! replay) or `reason` (turning a `BudgetExceeded` reject into a
//! forged `Complete`).

use fcp_cbor::SchemaId;
use fcp_crypto::Ed25519SigningKey;
use fcp_prelude::{ObjectHeader, ObjectId, Provenance, TailscaleNodeId, ZoneId, ZoneKeyId};
use fcp_protocol::{SymbolAck, SymbolAckReason};
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

fn baseline_ack() -> (SymbolAck, Ed25519SigningKey) {
    let signing_key = Ed25519SigningKey::generate();
    let zone = ZoneId::work();
    let mut ack = SymbolAck::new(
        test_header(&zone),
        ObjectId::from_bytes([0x11; 32]),
        zone,
        ZoneKeyId::from_bytes([0x22; 8]),
        1_000,
        TailscaleNodeId::new("node-recipient"),
        0xDEAD_BEEF_u64,
        SymbolAckReason::Complete,
        100,
    );
    ack.sign(&signing_key);
    (ack, signing_key)
}

#[test]
fn round_trip_sign_then_verify_passes() {
    let (ack, signing_key) = baseline_ack();
    ack.verify(&signing_key.verifying_key())
        .expect("a freshly-signed ack must verify under the same key");
}

#[test]
fn ack_signed_under_one_key_does_not_verify_under_another() {
    let (ack, _) = baseline_ack();
    let attacker = Ed25519SigningKey::generate();
    ack.verify(&attacker.verifying_key())
        .expect_err("ack must not verify under a key that did not sign it");
}

#[test]
fn transcript_binds_to_object_id() {
    let (mut ack, signing_key) = baseline_ack();
    ack.object_id = ObjectId::from_bytes([0x99; 32]);
    ack.verify(&signing_key.verifying_key())
        .expect_err("ack signature must reject object_id tamper");
}

#[test]
fn transcript_binds_to_zone_id() {
    let (mut ack, signing_key) = baseline_ack();
    ack.zone_id = ZoneId::private();
    ack.verify(&signing_key.verifying_key())
        .expect_err("ack signature must reject zone_id tamper");
}

#[test]
fn transcript_binds_to_zone_key_id() {
    // zone_key_id rotates the zone key. An ack issued against
    // zone_key_id A MUST NOT be re-presentable as if it acknowledged
    // zone_key_id B's traffic — otherwise key rotation has no effect
    // on the ack stream.
    let (mut ack, signing_key) = baseline_ack();
    ack.zone_key_id = ZoneKeyId::from_bytes([0xFF; 8]);
    ack.verify(&signing_key.verifying_key())
        .expect_err("ack signature must reject zone_key_id tamper");
}

#[test]
fn transcript_binds_to_epoch_id() {
    let (mut ack, signing_key) = baseline_ack();
    ack.epoch_id = ack.epoch_id.wrapping_add(1);
    ack.verify(&signing_key.verifying_key())
        .expect_err("ack signature must reject epoch_id tamper (cross-epoch replay defense)");
}

#[test]
fn transcript_binds_to_recipient_node_id() {
    // The ack names its intended recipient explicitly. An attacker
    // who captures an ack destined for node-A MUST NOT be able to
    // re-present it to node-B's request stream.
    let (mut ack, signing_key) = baseline_ack();
    ack.recipient_node_id = TailscaleNodeId::new("node-other");
    ack.verify(&signing_key.verifying_key())
        .expect_err("ack signature must reject recipient_node_id tamper");
}

#[test]
fn transcript_binds_to_request_nonce() {
    // request_nonce uniquely identifies the symbol-request exchange.
    // This is the per-exchange replay defense — the same ack content
    // for a different exchange MUST be rejected.
    let (mut ack, signing_key) = baseline_ack();
    ack.request_nonce = ack.request_nonce.wrapping_add(1);
    ack.verify(&signing_key.verifying_key())
        .expect_err("ack signature must reject request_nonce tamper");
}

#[test]
fn transcript_binds_to_reason_complete_vs_cancelled() {
    // The four SymbolAckReason variants encode a critical semantic
    // distinction: Complete (transfer succeeded) vs Cancelled (peer
    // gave up) vs Duplicate (peer saw redundancy) vs BudgetExceeded
    // (peer hit a cap). Letting an attacker silently rewrite a
    // BudgetExceeded into a Complete would let them claim transfer
    // success that did not happen.
    let (mut ack, signing_key) = baseline_ack();
    assert_eq!(ack.reason, SymbolAckReason::Complete, "fixture sanity");
    ack.reason = SymbolAckReason::Cancelled;
    ack.verify(&signing_key.verifying_key())
        .expect_err("ack signature must reject reason tamper (Complete -> Cancelled)");
}

#[test]
fn transcript_binds_to_reason_complete_vs_budget_exceeded() {
    let (mut ack, signing_key) = baseline_ack();
    ack.reason = SymbolAckReason::BudgetExceeded;
    ack.verify(&signing_key.verifying_key())
        .expect_err("ack signature must reject reason tamper (Complete -> BudgetExceeded)");
}

#[test]
fn transcript_binds_to_final_symbol_count() {
    // final_symbol_count is the metric that drives transfer
    // accounting. Letting an attacker rewrite this would corrupt
    // peer reputation/usage tracking.
    let (mut ack, signing_key) = baseline_ack();
    ack.final_symbol_count = ack.final_symbol_count.wrapping_add(1);
    ack.verify(&signing_key.verifying_key())
        .expect_err("ack signature must reject final_symbol_count tamper");
}

#[test]
fn header_field_is_not_part_of_signed_transcript() {
    // The ObjectHeader is carried as context but NOT bound by the
    // signature (the transcript at fcp-protocol/src/fcps.rs only
    // hashes object_id, zone_id, zone_key_id, epoch_id,
    // recipient_node_id, request_nonce, reason, final_symbol_count).
    // This test pins that documented separation: mutating header
    // metadata MUST NOT invalidate the ack signature, otherwise a
    // schema/header drift between sender and receiver would break
    // every otherwise-valid ack.
    let (mut ack, signing_key) = baseline_ack();
    let alt_zone = ZoneId::private();
    ack.header = test_header(&alt_zone);
    ack.verify(&signing_key.verifying_key())
        .expect("header is intentionally outside the signed transcript");
}
