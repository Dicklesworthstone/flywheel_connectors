//! Regression for br-shbvv (security audit B2).
//!
//! Pins the V4 split-view defence: a `ZoneKeyManifest` with both V3
//! (`wrapped_keys`) and V4 (`wrapped_keys_v4`) wraps for the same
//! recipient is only safe when the V4 wrap is the
//! [`WrappedKey::HpkeX25519`] variant with byte-equal sealed bytes
//! (i.e. it was promoted by the `migrated_to_v4` helper). Any other
//! shape — V4 wrap of the X-Wing variant, or V4-HpkeX25519 with
//! divergent sealed bytes — would let V3 readers and V4 readers
//! resolve to different zone keys, silently partitioning the zone.

use fcp_core::{
    NodeId, NodeSignature, ObjectHeader, ObjectIdKeyId, Provenance, TailscaleNodeId, WrappedKey,
    WrappedZoneKeyV4, ZoneId, ZoneKemAlgorithm, ZoneKey, ZoneKeyAlgorithm, ZoneKeyError, ZoneKeyId,
    ZoneKeyManifest, wrap_zone_key,
};
use fcp_crypto::{Fcp4Aad, X25519SecretKey, XWingKem, XWingProvider};

fn zone() -> ZoneId {
    ZoneId::work()
}

fn node(label: &str) -> TailscaleNodeId {
    TailscaleNodeId::new(format!("100.64.0.{}", label.len()))
}

fn header() -> ObjectHeader {
    let z = zone();
    ObjectHeader {
        schema: fcp_cbor::SchemaId::new(
            "fcp.zone",
            "ZoneKeyManifest",
            semver::Version::new(1, 0, 0),
        ),
        zone_id: z.clone(),
        created_at: 1_700_000_000,
        provenance: Provenance::new(z),
        refs: vec![],
        foreign_refs: vec![],
        ttl_secs: None,
        placement: None,
    }
}

fn sig() -> NodeSignature {
    NodeSignature::new(NodeId::new("owner"), [0u8; 64], 1_700_000_000)
}

fn empty_v4_manifest() -> ZoneKeyManifest {
    ZoneKeyManifest {
        header: header(),
        zone_id: zone(),
        zone_key_id: ZoneKeyId::from_bytes([1u8; 8]),
        object_id_key_id: ObjectIdKeyId::from_bytes([2u8; 8]),
        algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
        valid_from: 1_700_000_000,
        valid_until: None,
        prev_zone_key_id: None,
        wrapped_keys: vec![],
        wrapped_object_id_keys: vec![],
        rekey_policy: None,
        signature: sig(),
        kem: ZoneKemAlgorithm::XWing,
        wrapped_keys_v4: vec![],
    }
}

#[test]
fn split_view_validate_passes_on_empty_manifest() {
    let m = empty_v4_manifest();
    assert_eq!(
        m.split_view_recipients(),
        [] as [fcp_core::TailscaleNodeId; 0]
    );
    m.validate_no_recipient_split_view()
        .expect("empty manifest is safe");
}

#[test]
fn split_view_validate_passes_on_v4_only_recipient() {
    // br-shbvv: a V4-only recipient (no entry in wrapped_keys) is the
    // common pure-V4 case and MUST pass validation.
    let z = zone();
    let zone_key = ZoneKey::from_bytes([0x42; 32]);
    let provider = XWingProvider::new();
    let (pk, _sk) = provider.generate().unwrap();
    let alice = node("alice");
    let aad = Fcp4Aad::for_zone_key(z.as_bytes(), alice.as_str().as_bytes(), 1_700_000_000)
        .encode()
        .unwrap();
    let sealed = provider.seal(&pk, zone_key.as_bytes(), &aad).unwrap();

    let mut m = empty_v4_manifest();
    m.add_xwing_wrap(alice, 1_700_000_000, sealed);

    assert_eq!(
        m.split_view_recipients(),
        [] as [fcp_core::TailscaleNodeId; 0]
    );
    m.validate_no_recipient_split_view()
        .expect("V4-only recipient is safe");
}

#[test]
fn split_view_validate_passes_on_promoted_v3_via_migrated_to_v4() {
    // br-shbvv: the migrated_to_v4 helper produces byte-equal V4
    // wraps from V3 wraps. Validation MUST treat these as safe.
    let z = zone();
    let zone_key = ZoneKey::from_bytes([0x33; 32]);
    let alice_sk = X25519SecretKey::generate();
    let alice = node("alice");
    let v3_wrap =
        wrap_zone_key(&alice_sk.public_key(), &z, &alice, 1_700_000_000, &zone_key).unwrap();

    let mut m = empty_v4_manifest();
    m.wrapped_keys = vec![v3_wrap];
    // br-z8bsg: migrated_to_v4 returns UnsignedV4Manifest; the
    // structural split-view validators live on the inner payload.
    let migrated = m.migrated_to_v4(ZoneKemAlgorithm::XWing);

    assert!(
        migrated.as_payload().split_view_recipients().is_empty(),
        "promoted V3→V4 wraps must be treated as safe (byte-equal HpkeX25519)"
    );
    migrated
        .as_payload()
        .validate_no_recipient_split_view()
        .expect("promoted wraps safe");
}

#[test]
fn split_view_validate_detects_v3_plus_xwing_v4_for_same_recipient() {
    // br-shbvv THE BUG: a recipient with a V3 HPKE wrap AND a V4
    // X-Wing wrap is the canonical split-view case. Different KEMs →
    // ciphertexts inherently differ → V3 and V4 readers cannot be
    // proven to resolve to the same zone key without decap.
    let z = zone();
    let zone_key_v3 = ZoneKey::from_bytes([0xAA; 32]);
    let zone_key_v4 = ZoneKey::from_bytes([0xBB; 32]);
    let alice_x25519 = X25519SecretKey::generate();
    let alice = node("alice");

    let v3_wrap = wrap_zone_key(
        &alice_x25519.public_key(),
        &z,
        &alice,
        1_700_000_000,
        &zone_key_v3,
    )
    .unwrap();

    let provider = XWingProvider::new();
    let (alice_xwing_pk, _alice_xwing_sk) = provider.generate().unwrap();
    let aad = Fcp4Aad::for_zone_key(z.as_bytes(), alice.as_str().as_bytes(), 1_700_000_000)
        .encode()
        .unwrap();
    let v4_xwing_sealed = provider
        .seal(&alice_xwing_pk, zone_key_v4.as_bytes(), &aad)
        .unwrap();

    let mut m = empty_v4_manifest();
    m.wrapped_keys = vec![v3_wrap];
    m.add_xwing_wrap(alice.clone(), 1_700_000_000, v4_xwing_sealed);

    let split = m.split_view_recipients();
    assert_eq!(
        split.len(),
        1,
        "split-view recipient must be detected: {split:?}"
    );
    assert_eq!(split[0], alice);

    let err = m
        .validate_no_recipient_split_view()
        .expect_err("split-view manifest must be rejected by strict validation");
    assert!(matches!(
        err,
        ZoneKeyError::InconsistentRecipientWraps { .. }
    ));
}

#[test]
fn split_view_validate_detects_byte_diverging_hpke_v4_for_same_recipient() {
    // br-shbvv: even an HpkeX25519 V4 wrap can be a split-view case
    // if its sealed bytes differ from the V3 entry — the issuer
    // re-sealed the same recipient under a different zone key. The
    // bytes-must-match check catches this.
    let z = zone();
    let alice_sk_a = X25519SecretKey::generate();
    let alice_sk_b = X25519SecretKey::generate();
    let alice = node("alice");
    let zone_key = ZoneKey::from_bytes([0x77; 32]);

    let v3_wrap = wrap_zone_key(
        &alice_sk_a.public_key(),
        &z,
        &alice,
        1_700_000_000,
        &zone_key,
    )
    .unwrap();
    // Same recipient, V4 list, but a DIFFERENT ciphertext — sealing
    // to a different X25519 key produces different sealed bytes.
    let v4_wrap_diverging = WrappedZoneKeyV4 {
        recipient: alice.clone(),
        issued_at: 1_700_000_001,
        sealed: WrappedKey::from_hpke(
            wrap_zone_key(
                &alice_sk_b.public_key(),
                &z,
                &alice,
                1_700_000_001,
                &zone_key,
            )
            .unwrap()
            .sealed,
        ),
    };

    let mut m = empty_v4_manifest();
    m.wrapped_keys = vec![v3_wrap];
    m.wrapped_keys_v4 = vec![v4_wrap_diverging];

    let split = m.split_view_recipients();
    assert_eq!(
        split.len(),
        1,
        "byte-diverging HpkeX25519 V4 wrap must be flagged"
    );
    assert!(m.validate_no_recipient_split_view().is_err());
}

#[test]
fn split_view_validate_passes_on_two_independent_recipients() {
    // br-shbvv: alice (V3 only) + bob (V4 only) — no recipient
    // overlap, no split-view risk, validation passes.
    let z = zone();
    let zone_key = ZoneKey::from_bytes([0x42; 32]);

    let alice_sk = X25519SecretKey::generate();
    let alice = node("alice");
    let alice_v3 =
        wrap_zone_key(&alice_sk.public_key(), &z, &alice, 1_700_000_000, &zone_key).unwrap();

    let provider = XWingProvider::new();
    let (bob_pk, _bob_sk) = provider.generate().unwrap();
    let bob = node("bob");
    let bob_aad = Fcp4Aad::for_zone_key(z.as_bytes(), bob.as_str().as_bytes(), 1_700_000_001)
        .encode()
        .unwrap();
    let bob_v4 = provider
        .seal(&bob_pk, zone_key.as_bytes(), &bob_aad)
        .unwrap();

    let mut m = empty_v4_manifest();
    m.wrapped_keys = vec![alice_v3];
    m.add_xwing_wrap(bob, 1_700_000_001, bob_v4);

    assert_eq!(
        m.split_view_recipients(),
        [] as [fcp_core::TailscaleNodeId; 0]
    );
    m.validate_no_recipient_split_view()
        .expect("disjoint recipients are safe");
}
