//! `ZoneKeyManifest` V4 schema migration tests (br-kyopb.1.2.3).
//!
//! Lives in `fcp-mesh/tests/` because the user-facing acceptance command
//! is `cargo test -p fcp-mesh zone_key_manifest_v4`. The actual schema
//! lives in `fcp-core::zone_keys`; these tests exercise it through
//! `fcp-mesh`'s normal type re-exports to make sure the V4 fields
//! propagate cleanly through the dependency chain that production
//! callers use.
//!
//! What we pin
//! -----------
//!
//! 1. **Backward compatibility (V3 → reader):** a V3 manifest that omits
//!    the `kem` and `wrapped_keys_v4` fields deserialises with
//!    `kem == HpkeX25519` and an empty V4 list (the serde `default`
//!    contract). Existing wraps are still readable.
//! 2. **V3 → V4 schema migration:** `ZoneKeyManifest::migrated_to_v4`
//!    promotes every `WrappedZoneKey` into a `WrappedZoneKeyV4` tagged
//!    `HpkeX25519`, and a single lookup against `wrapped_keys_v4`
//!    suffices for any recipient.
//! 3. **Mixed V3 + V4 wraps in one manifest:** a V4 sender adds
//!    `XWing` wraps for V4 recipients alongside the inherited
//!    `HpkeX25519` wraps for V3 recipients. `resolved_wrapped_key_for`
//!    returns the V4 form when present and falls back to V3 when not.
//! 4. **`WrappedKey` enum tag = "kem" discrimination** round-trips
//!    through serde JSON (the canonical FCP wire form is CBOR but JSON
//!    exercises the same serde Serialize/Deserialize path).
//! 5. **V4 X-Wing wrap end-to-end:** generate an X-Wing keypair, seal a
//!    real `ZoneKey` to it via the V4 path, embed in a V4 manifest, and
//!    confirm the receiver opens it cleanly with the V4 secret.

#![allow(clippy::similar_names, clippy::default_trait_access)]

use fcp_core::{
    NodeId, NodeSignature, ObjectHeader, ObjectIdKeyId, Provenance, TailscaleNodeId, WrappedKey,
    WrappedZoneKey, WrappedZoneKeyV4, ZoneId, ZoneKemAlgorithm, ZoneKey, ZoneKeyAlgorithm,
    ZoneKeyId, ZoneKeyManifest, wrap_zone_key,
};
use fcp_crypto::{Fcp4Aad, X25519SecretKey, XWingKem, XWingProvider, XWingSealedBox};

// ── Test helpers ────────────────────────────────────────────────────────

fn test_zone() -> ZoneId {
    ZoneId::work()
}

fn test_node(label: &str) -> TailscaleNodeId {
    TailscaleNodeId::new(format!("100.64.0.{}", label.len()))
}

const fn test_zone_key() -> ZoneKey {
    ZoneKey::from_bytes([0x42u8; 32])
}

fn test_signature(valid_from: u64) -> NodeSignature {
    NodeSignature::new(NodeId::new("owner"), [0u8; 64], valid_from)
}

fn test_header(zone: &ZoneId) -> ObjectHeader {
    ObjectHeader {
        encryption_kind: Default::default(),
        schema: fcp_cbor::SchemaId::new(
            "fcp.zone",
            "ZoneKeyManifest",
            semver::Version::new(1, 0, 0),
        ),
        zone_id: zone.clone(),
        created_at: 1_700_000_000,
        provenance: Provenance::new(zone.clone()),
        refs: vec![],
        foreign_refs: vec![],
        ttl_secs: None,
        placement: None,
    }
}

fn make_v3_manifest(zone: &ZoneId, valid_from: u64, wraps: Vec<WrappedZoneKey>) -> ZoneKeyManifest {
    ZoneKeyManifest {
        header: test_header(zone),
        zone_id: zone.clone(),
        zone_key_id: ZoneKeyId::from_bytes([1u8; 8]),
        object_id_key_id: ObjectIdKeyId::from_bytes([2u8; 8]),
        algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
        valid_from,
        valid_until: None,
        prev_zone_key_id: None,
        wrapped_keys: wraps,
        wrapped_object_id_keys: vec![],
        rekey_policy: None,
        signature: test_signature(valid_from),
        kem: ZoneKemAlgorithm::HpkeX25519,
        wrapped_keys_v4: vec![],
    }
}

// ── 1. Backward compatibility: V3 wire form deserialises ───────────────

#[test]
fn zone_key_manifest_v4_v3_wire_form_deserialises_with_default_kem() {
    // br-kyopb.1.2.3: a V3 manifest written by an old codebase has no
    // `kem` field and no `wrapped_keys_v4` field. The serde `default`
    // attributes MUST give us `HpkeX25519` and an empty V4 list — any
    // other behaviour breaks every existing manifest in the wild.
    //
    // Strategy: build a real manifest, serialise it, strip the V4
    // fields, deserialise. This proves the on-disk V3 wire form
    // (which the codebase produced before this commit) still parses.
    let zone = test_zone();
    let manifest = make_v3_manifest(&zone, 1_700_000_000, vec![]);
    let mut v = serde_json::to_value(&manifest).unwrap();
    let map = v.as_object_mut().unwrap();
    let removed_kem = map.remove("kem");
    let _ = map.remove("wrapped_keys_v4");
    assert!(
        removed_kem.is_some(),
        "fixture should have had a kem field to remove"
    );

    let parsed: ZoneKeyManifest =
        serde_json::from_value(v).expect("V3 wire form (no kem field) must deserialise");
    assert_eq!(
        parsed.kem,
        ZoneKemAlgorithm::HpkeX25519,
        "missing kem must default to HpkeX25519"
    );
    assert!(
        parsed.wrapped_keys_v4.is_empty(),
        "missing wrapped_keys_v4 must default to empty"
    );
}

#[test]
fn zone_key_manifest_v4_field_is_omitted_in_serialisation_when_empty() {
    // br-kyopb.1.2.3: V3 senders SHOULD continue to produce manifests
    // that look exactly like V3 on the wire (no extra empty arrays).
    // The serde skip_serializing_if = "Vec::is_empty" attribute on
    // wrapped_keys_v4 covers this.
    let zone = test_zone();
    let manifest = make_v3_manifest(&zone, 1_700_000_000, vec![]);
    let v = serde_json::to_value(&manifest).unwrap();
    assert!(
        v.get("wrapped_keys_v4").is_none(),
        "empty wrapped_keys_v4 must NOT appear on the wire — V3 readers should see exactly the V3 shape: {v:?}"
    );
}

// ── 2. V3 → V4 schema migration helper ──────────────────────────────────

#[test]
fn zone_key_manifest_v4_migrated_to_v4_promotes_v3_wraps() {
    // br-kyopb.1.2.3: ZoneKeyManifest::migrated_to_v4 produces a V4
    // manifest whose wrapped_keys_v4 covers every recipient that was in
    // wrapped_keys, tagged HpkeX25519. The V3 list is preserved so V3
    // readers keep working.
    let zone = test_zone();
    let zone_key = test_zone_key();
    let alice_sk = X25519SecretKey::generate();
    let alice_node = test_node("alice");
    let alice_v3 = wrap_zone_key(
        &alice_sk.public_key(),
        &zone,
        &alice_node,
        1_700_000_000,
        &zone_key,
    )
    .expect("HPKE wrap must succeed");

    let bob_sk = X25519SecretKey::generate();
    let bob_node = test_node("bob");
    let bob_v3 = wrap_zone_key(
        &bob_sk.public_key(),
        &zone,
        &bob_node,
        1_700_000_001,
        &zone_key,
    )
    .expect("HPKE wrap must succeed");

    let v3_manifest = make_v3_manifest(&zone, 1_700_000_000, vec![alice_v3, bob_v3]);

    // br-z8bsg: migrated_to_v4 returns UnsignedV4Manifest (typestate
    // enforcement). Inspection is via .as_payload(); a real publisher
    // would call .sign(owner_signature) to get a publishable
    // ZoneKeyManifest.
    let unsigned = v3_manifest.migrated_to_v4(ZoneKemAlgorithm::XWing);
    let v4_manifest = unsigned.as_payload();

    assert_eq!(v4_manifest.kem, ZoneKemAlgorithm::XWing);
    assert_eq!(
        v4_manifest.wrapped_keys.len(),
        2,
        "V3 list MUST be preserved for V3-only readers"
    );
    assert_eq!(
        v4_manifest.wrapped_keys_v4.len(),
        2,
        "every V3 wrap should have been promoted into the V4 list"
    );

    // Both promoted entries should be HpkeX25519-tagged (since they
    // came from V3 wraps).
    for entry in &v4_manifest.wrapped_keys_v4 {
        assert_eq!(
            entry.sealed.kem(),
            ZoneKemAlgorithm::HpkeX25519,
            "promoted V3 wrap MUST be tagged HpkeX25519, got {:?}",
            entry.sealed.kem()
        );
    }

    // Lookup via the V4 helper finds both promoted entries.
    assert!(v4_manifest.wrapped_key_v4_for(&alice_node).is_some());
    assert!(v4_manifest.wrapped_key_v4_for(&bob_node).is_some());

    // resolved_wrapped_key_for prefers V4 (where alice + bob now live).
    let resolved_alice = v4_manifest
        .resolved_wrapped_key_for(&alice_node)
        .expect("alice resolves");
    assert!(matches!(resolved_alice, WrappedKey::HpkeX25519 { .. }));
}

#[test]
fn zone_key_manifest_v4_migrated_to_v4_is_idempotent_for_already_migrated_recipients() {
    // br-kyopb.1.2.3: re-running migration on an already-migrated
    // manifest must not duplicate entries.
    let zone = test_zone();
    let zone_key = test_zone_key();
    let alice_sk = X25519SecretKey::generate();
    let alice = test_node("alice");
    let alice_v3 = wrap_zone_key(
        &alice_sk.public_key(),
        &zone,
        &alice,
        1_700_000_000,
        &zone_key,
    )
    .unwrap();

    let v3 = make_v3_manifest(&zone, 1_700_000_000, vec![alice_v3]);
    // br-z8bsg: typestate. once.migrated_to_v4 delegates re-migration
    // through the unsigned wrapper.
    let once = v3.migrated_to_v4(ZoneKemAlgorithm::XWing);
    let twice = once.migrated_to_v4(ZoneKemAlgorithm::XWing);

    assert_eq!(once.as_payload().wrapped_keys_v4.len(), 1);
    assert_eq!(
        twice.as_payload().wrapped_keys_v4.len(),
        1,
        "second migration must NOT duplicate wraps"
    );
}

// ── 3. Mixed V3 + V4 wraps in one manifest ──────────────────────────────

#[test]
fn zone_key_manifest_v4_supports_mixed_v3_and_v4_wraps() {
    // br-kyopb.1.2.3: per design doc §6 a single V4 manifest can carry
    // V3 (HpkeX25519) wraps for V3-only recipients alongside V4 (XWing)
    // wraps for V4-capable recipients.
    let zone = test_zone();
    let zone_key = test_zone_key();

    // V3-only recipient: alice
    let alice_sk = X25519SecretKey::generate();
    let alice = test_node("alice");
    let alice_v3 = wrap_zone_key(
        &alice_sk.public_key(),
        &zone,
        &alice,
        1_700_000_000,
        &zone_key,
    )
    .unwrap();

    // V4 recipient: bob
    let provider = XWingProvider::new();
    let (bob_xwing_pk, bob_xwing_sk) = provider.generate().unwrap();
    let bob = test_node("bob");
    let bob_aad = Fcp4Aad::for_zone_key(zone.as_bytes(), bob.as_str().as_bytes(), 1_700_000_001)
        .encode()
        .unwrap();
    let bob_xwing_sealed: XWingSealedBox = provider
        .seal(&bob_xwing_pk, zone_key.as_bytes(), &bob_aad)
        .unwrap();

    // Build the mixed manifest.
    let mut manifest = make_v3_manifest(&zone, 1_700_000_000, vec![alice_v3]);
    manifest.kem = ZoneKemAlgorithm::XWing;
    manifest.add_xwing_wrap(bob.clone(), 1_700_000_001, bob_xwing_sealed);

    // V3 reader path: sees alice's wrap, ignores bob's V4 entry.
    assert!(manifest.wrapped_key_for(&alice).is_some());
    assert!(manifest.wrapped_key_for(&bob).is_none());

    // V4 reader path: sees both via resolved_wrapped_key_for.
    let alice_resolved = manifest.resolved_wrapped_key_for(&alice).unwrap();
    assert_eq!(alice_resolved.kem(), ZoneKemAlgorithm::HpkeX25519);

    let bob_resolved = manifest.resolved_wrapped_key_for(&bob).unwrap();
    assert_eq!(bob_resolved.kem(), ZoneKemAlgorithm::XWing);

    // End-to-end: bob can actually open his V4 wrap and recover the
    // ORIGINAL zone key bytes.
    let bob_xwing_box = bob_resolved
        .xwing_sealed()
        .expect("bob's wrap is the X-Wing variant")
        .clone();
    let opened = provider
        .open(&bob_xwing_sk, &bob_xwing_box, &bob_aad)
        .expect("bob can decap his own wrap");
    assert_eq!(opened.as_slice(), zone_key.as_bytes());
}

// ── 4. WrappedKey serde round-trip ──────────────────────────────────────

#[test]
fn zone_key_manifest_v4_wrapped_key_kem_tag_round_trips_through_serde() {
    // br-kyopb.1.2.3: WrappedKey is tagged enum with `tag = "kem"`.
    // Serialising and deserialising round-trips both variants without
    // collapsing them.
    let zone = test_zone();
    let zone_key = test_zone_key();

    // HPKE variant
    let alice_sk = X25519SecretKey::generate();
    let alice = test_node("alice");
    let alice_v3 = wrap_zone_key(
        &alice_sk.public_key(),
        &zone,
        &alice,
        1_700_000_000,
        &zone_key,
    )
    .unwrap();
    let alice_wk = WrappedKey::from_hpke(alice_v3.sealed);
    let alice_json = serde_json::to_value(&alice_wk).unwrap();
    assert_eq!(
        alice_json.get("kem").and_then(|v| v.as_str()),
        Some("hpke_x25519"),
        "HPKE variant must serialise with kem=hpke_x25519: {alice_json:?}"
    );

    // X-Wing variant
    let provider = XWingProvider::new();
    let (bob_pk, _bob_sk) = provider.generate().unwrap();
    let aad = b"test aad";
    let bob_sealed = provider.seal(&bob_pk, zone_key.as_bytes(), aad).unwrap();
    let bob_wk = WrappedKey::from_xwing(bob_sealed);
    let bob_json = serde_json::to_value(&bob_wk).unwrap();
    assert_eq!(
        bob_json.get("kem").and_then(|v| v.as_str()),
        Some("x_wing"),
        "X-Wing variant must serialise with kem=x_wing: {bob_json:?}"
    );

    // Round-trip both variants and confirm tag preserved.
    let alice_back: WrappedKey = serde_json::from_value(alice_json).unwrap();
    assert_eq!(alice_back.kem(), ZoneKemAlgorithm::HpkeX25519);
    let bob_back: WrappedKey = serde_json::from_value(bob_json).unwrap();
    assert_eq!(bob_back.kem(), ZoneKemAlgorithm::XWing);
}

// ── 5. V4 X-Wing wrap end-to-end through manifest ──────────────────────

#[test]
fn zone_key_manifest_v4_xwing_wrap_round_trips_via_manifest() {
    // br-kyopb.1.2.3: the canonical flow — generate X-Wing keypair,
    // seal a zone key, embed in manifest, recipient walks the manifest,
    // pulls the X-Wing variant, opens.
    let zone = test_zone();
    let zone_key = test_zone_key();
    let provider = XWingProvider::new();
    let (recipient_pk, recipient_sk) = provider.generate().unwrap();
    let recipient = test_node("recipient");

    let aad = Fcp4Aad::for_zone_key(
        zone.as_bytes(),
        recipient.as_str().as_bytes(),
        1_700_000_000,
    )
    .encode()
    .unwrap();
    let sealed = provider
        .seal(&recipient_pk, zone_key.as_bytes(), &aad)
        .unwrap();

    let mut manifest = make_v3_manifest(&zone, 1_700_000_000, vec![]);
    manifest.kem = ZoneKemAlgorithm::XWing;
    manifest.add_xwing_wrap(recipient.clone(), 1_700_000_000, sealed);

    // Manifest is on the wire in CBOR, but we round-trip through serde
    // to confirm the wrapped enum survives serialisation cleanly.
    let on_wire = serde_json::to_vec(&manifest).unwrap();
    let recovered: ZoneKeyManifest = serde_json::from_slice(&on_wire).unwrap();
    assert_eq!(recovered.wrapped_keys_v4.len(), 1);

    // Recipient walks the recovered manifest and opens.
    let entry: &WrappedZoneKeyV4 = recovered
        .wrapped_key_v4_for(&recipient)
        .expect("recipient is in V4 list");
    let xwing_box = entry
        .sealed
        .xwing_sealed()
        .expect("variant is X-Wing")
        .clone();
    let opened = provider
        .open(&recipient_sk, &xwing_box, &aad)
        .expect("decap must succeed for valid manifest");
    assert_eq!(opened.as_slice(), zone_key.as_bytes());
}

#[test]
fn zone_key_manifest_v4_add_xwing_wrap_replaces_existing_entry() {
    // br-kyopb.1.2.3: re-publishing an X-Wing wrap for the same
    // recipient (e.g. on rekey) must REPLACE rather than append, to
    // avoid an unbounded V4 list.
    let zone = test_zone();
    let provider = XWingProvider::new();
    let (pk, _sk) = provider.generate().unwrap();
    let recipient = test_node("rec");
    let sealed_a = provider.seal(&pk, b"key-a", b"aad-a").unwrap();
    let sealed_b = provider.seal(&pk, b"key-b", b"aad-b").unwrap();

    let mut manifest = make_v3_manifest(&zone, 1_700_000_000, vec![]);
    manifest.add_xwing_wrap(recipient.clone(), 100, sealed_a);
    manifest.add_xwing_wrap(recipient, 200, sealed_b.clone());
    assert_eq!(manifest.wrapped_keys_v4.len(), 1, "must replace not append");
    assert_eq!(manifest.wrapped_keys_v4[0].issued_at, 200);
    let final_box = manifest.wrapped_keys_v4[0]
        .sealed
        .xwing_sealed()
        .unwrap()
        .clone();
    assert_eq!(final_box.enc, sealed_b.enc);
}

#[test]
fn zone_key_manifest_v4_zone_kem_algorithm_serde_uses_snake_case() {
    // br-kyopb.1.2.3: pin the wire labels for the ZoneKemAlgorithm
    // enum. A future rename without explicit serde aliases would break
    // every V4 manifest already in the field.
    let hpke = serde_json::to_string(&ZoneKemAlgorithm::HpkeX25519).unwrap();
    assert_eq!(hpke, "\"hpke_x25519\"");
    let xwing = serde_json::to_string(&ZoneKemAlgorithm::XWing).unwrap();
    assert_eq!(xwing, "\"x_wing\"");
}

#[test]
fn zone_key_manifest_v4_zone_kem_algorithm_default_is_hpke_x25519() {
    // br-kyopb.1.2.3: backward-compat anchor — default MUST stay
    // HpkeX25519 so V3 manifests with no kem field deserialise as V3.
    let default_kem: ZoneKemAlgorithm = Default::default();
    assert_eq!(default_kem, ZoneKemAlgorithm::HpkeX25519);
}
