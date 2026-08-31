//! Regression for br-d2oa0 (profiling audit A3).
//!
//! Pins that `IndexedZoneKeyManifest` provides O(1) recipient
//! lookups equivalent to the linear-scan methods on the base
//! `ZoneKeyManifest`, with byte-equivalent results.

use fcp_core::{
    IndexedZoneKeyManifest, NodeId, NodeSignature, ObjectHeader, ObjectIdKeyId, Provenance,
    TailscaleNodeId, WrappedKey, WrappedZoneKeyV4, ZoneId, ZoneKemAlgorithm, ZoneKey,
    ZoneKeyAlgorithm, ZoneKeyId, ZoneKeyManifest, wrap_zone_key,
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
        encryption_kind: Default::default(),
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

fn make_manifest_with_n_recipients(n: usize) -> ZoneKeyManifest {
    let zone = zone();
    let zone_key = ZoneKey::from_bytes([0x42; 32]);
    let mut wrapped = Vec::with_capacity(n);
    for i in 0..n {
        let sk = X25519SecretKey::generate();
        let recipient = TailscaleNodeId::new(format!("100.64.{}.{}", (i / 256) % 256, i % 256));
        let wrap = wrap_zone_key(
            &sk.public_key(),
            &zone,
            &recipient,
            1_700_000_000,
            &zone_key,
        )
        .expect("HPKE wrap");
        wrapped.push(wrap);
    }
    ZoneKeyManifest {
        header: header(),
        zone_id: zone,
        zone_key_id: ZoneKeyId::from_bytes([1u8; 8]),
        object_id_key_id: ObjectIdKeyId::from_bytes([2u8; 8]),
        algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
        valid_from: 1_700_000_000,
        valid_until: None,
        prev_zone_key_id: None,
        wrapped_keys: wrapped,
        wrapped_object_id_keys: vec![],
        rekey_policy: None,
        signature: NodeSignature::new(NodeId::new("owner"), [0u8; 64], 1_700_000_000),
        kem: ZoneKemAlgorithm::HpkeX25519,
        wrapped_keys_v4: vec![],
    }
}

#[test]
fn indexed_lookup_v3_hit_matches_linear_scan_for_every_recipient() {
    // br-d2oa0: O(1) lookup MUST return identical results to the
    // O(n) linear scan for every recipient that is present in the
    // manifest.
    let manifest = make_manifest_with_n_recipients(32);
    let recipients: Vec<TailscaleNodeId> = manifest
        .wrapped_keys
        .iter()
        .map(|w| w.recipient.clone())
        .collect();
    let indexed = IndexedZoneKeyManifest::new(manifest.clone()).expect("unique recipients");

    for r in &recipients {
        let from_linear = manifest.wrapped_key_for(r);
        let from_indexed = indexed.wrapped_key_for(r);
        assert!(from_linear.is_some(), "linear scan must find {r:?}");
        assert!(from_indexed.is_some(), "indexed lookup must find {r:?}");
        assert_eq!(
            from_linear.map(|w| w.recipient.as_str().to_owned()),
            from_indexed.map(|w| w.recipient.as_str().to_owned()),
            "indexed and linear must agree for {r:?}"
        );
    }
}

#[test]
fn indexed_lookup_miss_returns_none_like_linear_scan() {
    let manifest = make_manifest_with_n_recipients(8);
    let indexed = IndexedZoneKeyManifest::new(manifest.clone()).expect("unique recipients");
    let missing = node("nonexistent");
    assert!(manifest.wrapped_key_for(&missing).is_none());
    assert!(indexed.wrapped_key_for(&missing).is_none());
}

#[test]
fn indexed_lookup_v4_hit_matches_linear_scan() {
    let zone = zone();
    let provider = XWingProvider::new();
    let mut manifest = make_manifest_with_n_recipients(0);
    manifest.kem = ZoneKemAlgorithm::XWing;

    let mut v4_recipients = Vec::new();
    for i in 0..8 {
        let recipient = TailscaleNodeId::new(format!("100.65.0.{i}"));
        let (pk, _sk) = provider.generate().unwrap();
        let aad = Fcp4Aad::for_zone_key(
            zone.as_bytes(),
            recipient.as_str().as_bytes(),
            1_700_000_000,
        )
        .encode()
        .unwrap();
        let sealed = provider.seal(&pk, b"zone-key-bytes", &aad).unwrap();
        manifest.wrapped_keys_v4.push(WrappedZoneKeyV4 {
            recipient: recipient.clone(),
            issued_at: 1_700_000_000,
            sealed: WrappedKey::from_xwing(sealed),
        });
        v4_recipients.push(recipient);
    }

    let indexed = IndexedZoneKeyManifest::new(manifest.clone()).expect("unique recipients");
    for r in &v4_recipients {
        let linear = manifest.wrapped_key_v4_for(r);
        let from_idx = indexed.wrapped_key_v4_for(r);
        assert!(linear.is_some());
        assert!(from_idx.is_some());
        assert_eq!(
            linear.map(|w| w.recipient.as_str().to_owned()),
            from_idx.map(|w| w.recipient.as_str().to_owned())
        );
    }
}

#[test]
fn indexed_resolved_wrapped_key_for_prefers_v4_then_v3() {
    // br-d2oa0: the V4-first / V3-fallback precedence MUST match
    // the linear-scan method byte-for-byte.
    let zone = zone();
    let zone_key = ZoneKey::from_bytes([0x33; 32]);

    // Alice: V3-only recipient.
    let alice_sk = X25519SecretKey::generate();
    let alice = TailscaleNodeId::new("100.66.0.1");
    let alice_v3 = wrap_zone_key(
        &alice_sk.public_key(),
        &zone,
        &alice,
        1_700_000_000,
        &zone_key,
    )
    .unwrap();

    // Bob: V4-only recipient.
    let provider = XWingProvider::new();
    let (bob_pk, _bob_sk) = provider.generate().unwrap();
    let bob = TailscaleNodeId::new("100.66.0.2");
    let bob_aad = Fcp4Aad::for_zone_key(zone.as_bytes(), bob.as_str().as_bytes(), 1_700_000_001)
        .encode()
        .unwrap();
    let bob_sealed = provider
        .seal(&bob_pk, zone_key.as_bytes(), &bob_aad)
        .unwrap();

    let mut manifest = make_manifest_with_n_recipients(0);
    manifest.kem = ZoneKemAlgorithm::XWing;
    manifest.wrapped_keys = vec![alice_v3];
    manifest.wrapped_keys_v4.push(WrappedZoneKeyV4 {
        recipient: bob.clone(),
        issued_at: 1_700_000_001,
        sealed: WrappedKey::from_xwing(bob_sealed),
    });

    let indexed = IndexedZoneKeyManifest::new(manifest.clone()).expect("unique recipients");

    // Alice resolves via V3 fallback in BOTH paths.
    let alice_lin = manifest
        .resolved_wrapped_key_for(&alice)
        .expect("alice via linear");
    let alice_idx = indexed
        .resolved_wrapped_key_for(&alice)
        .expect("alice via indexed");
    assert_eq!(alice_lin.kem(), alice_idx.kem());
    assert_eq!(alice_lin.kem(), ZoneKemAlgorithm::HpkeX25519);

    // Bob resolves via V4 in BOTH paths.
    let bob_lin = manifest
        .resolved_wrapped_key_for(&bob)
        .expect("bob via linear");
    let bob_idx = indexed
        .resolved_wrapped_key_for(&bob)
        .expect("bob via indexed");
    assert_eq!(bob_lin.kem(), bob_idx.kem());
    assert_eq!(bob_lin.kem(), ZoneKemAlgorithm::XWing);
}

#[test]
fn indexed_into_inner_returns_byte_equal_manifest() {
    // br-d2oa0: the index must NOT mutate the wire form. Round-trip
    // through into_inner + canonical CBOR must produce the same
    // bytes as the original manifest.
    let manifest = make_manifest_with_n_recipients(16);
    let original_cbor = fcp_cbor::to_canonical_cbor(&manifest).expect("original encodes");

    let indexed = IndexedZoneKeyManifest::new(manifest).expect("unique recipients");
    let recovered = indexed.into_inner();
    let recovered_cbor = fcp_cbor::to_canonical_cbor(&recovered).expect("recovered encodes");

    assert_eq!(
        original_cbor, recovered_cbor,
        "IndexedZoneKeyManifest round-trip must preserve canonical CBOR bytes"
    );
}

#[test]
fn indexed_manifest_borrow_exposes_non_lookup_fields() {
    let manifest = make_manifest_with_n_recipients(4);
    let indexed = IndexedZoneKeyManifest::new(manifest.clone()).expect("unique recipients");
    let m = indexed.manifest();
    assert_eq!(m.kem, manifest.kem);
    assert_eq!(m.zone_key_id, manifest.zone_key_id);
    assert_eq!(m.valid_from, manifest.valid_from);
}

#[test]
fn indexed_lookup_with_zero_recipients_works() {
    let manifest = make_manifest_with_n_recipients(0);
    let indexed = IndexedZoneKeyManifest::new(manifest).expect("unique recipients");
    assert!(indexed.wrapped_key_for(&node("alice")).is_none());
    assert!(indexed.wrapped_key_v4_for(&node("alice")).is_none());
    assert!(indexed.resolved_wrapped_key_for(&node("alice")).is_none());
}
