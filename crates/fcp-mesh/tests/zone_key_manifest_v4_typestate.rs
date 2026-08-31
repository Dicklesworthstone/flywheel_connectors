//! Regression for br-z8bsg (modes-of-reasoning audit A3).
//!
//! Pins the V4 migration typestate: `ZoneKeyManifest::migrated_to_v4`
//! returns `UnsignedV4Manifest`, NOT `ZoneKeyManifest`. The only way
//! to extract a publishable manifest is via `UnsignedV4Manifest::sign`
//! with a caller-supplied owner signature.
//!
//! The compile-time enforcement is the load-bearing safety property
//! and cannot itself be tested at runtime (a successful test compile
//! IS the proof that `let m: ZoneKeyManifest = source.migrated_to_v4(...)`
//! is a type error). What this file pins is the runtime BEHAVIOUR of
//! the typestate:
//!
//! 1. Inspection via `as_payload()` returns a borrow of the migrated
//!    payload with all V4 fields populated.
//! 2. `sign(signature)` consumes the wrapper and produces a
//!    publishable `ZoneKeyManifest` with the caller-supplied
//!    signature.
//! 3. Idempotency of migration is preserved through the wrapper.
//! 4. `add_xwing_wrap` mutates the unsigned payload BEFORE signing
//!    (the eventual signature commits to the post-mutation form).
//! 5. Adversarial path: a downstream consumer that bypasses the
//!    typestate via `as_payload().clone()` and tries to publish the
//!    inner value DOES get a `ZoneKeyManifest`, but its signature
//!    field still commits to the pre-migration V3 payload — any
//!    verifier re-deriving canonical signing bytes will reject.

use fcp_core::{
    NodeId, NodeSignature, ObjectHeader, ObjectIdKeyId, Provenance, TailscaleNodeId, ZoneId,
    ZoneKemAlgorithm, ZoneKey, ZoneKeyAlgorithm, ZoneKeyId, ZoneKeyManifest, wrap_zone_key,
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

fn v3_signature() -> NodeSignature {
    // Distinctive byte pattern so we can detect "this signature came
    // from the inherited V3 payload, not from a fresh sign() call."
    NodeSignature::new(NodeId::new("v3-owner"), [0xD3; 64], 1_700_000_000)
}

fn fresh_owner_signature() -> NodeSignature {
    // Distinctive byte pattern so we can detect "this signature was
    // installed via UnsignedV4Manifest::sign()."
    NodeSignature::new(NodeId::new("v4-owner"), [0xF4; 64], 1_700_000_500)
}

fn make_v3_manifest_with_alice() -> ZoneKeyManifest {
    let z = zone();
    let alice_sk = X25519SecretKey::generate();
    let alice = node("alice");
    let alice_v3 = wrap_zone_key(
        &alice_sk.public_key(),
        &z,
        &alice,
        1_700_000_000,
        &ZoneKey::from_bytes([0x42; 32]),
    )
    .unwrap();

    ZoneKeyManifest {
        header: header(),
        zone_id: z,
        zone_key_id: ZoneKeyId::from_bytes([1u8; 8]),
        object_id_key_id: ObjectIdKeyId::from_bytes([2u8; 8]),
        algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
        valid_from: 1_700_000_000,
        valid_until: None,
        prev_zone_key_id: None,
        wrapped_keys: vec![alice_v3],
        wrapped_object_id_keys: vec![],
        rekey_policy: None,
        signature: v3_signature(),
        kem: ZoneKemAlgorithm::HpkeX25519,
        wrapped_keys_v4: vec![],
    }
}

// ── Inspection invariants ───────────────────────────────────────────

#[test]
fn typestate_as_payload_exposes_migrated_v4_fields() {
    // br-z8bsg: as_payload() borrows the migrated form with kem and
    // wrapped_keys_v4 populated.
    let v3 = make_v3_manifest_with_alice();
    let unsigned = v3.migrated_to_v4(ZoneKemAlgorithm::XWing);
    let payload = unsigned.as_payload();
    assert_eq!(payload.kem, ZoneKemAlgorithm::XWing);
    assert_eq!(payload.wrapped_keys.len(), 1, "V3 wraps preserved");
    assert_eq!(payload.wrapped_keys_v4.len(), 1, "V3 promoted to V4");
}

#[test]
fn typestate_as_payload_inherited_signature_is_v3_payload_signature() {
    // br-z8bsg secondary defence: the inner signature is the OLD
    // V3 payload's signature. If a downstream consumer bypasses the
    // typestate via .as_payload().clone() and publishes, the
    // signature will not verify under the V4-canonical signing bytes
    // — defence in depth.
    let v3 = make_v3_manifest_with_alice();
    let unsigned = v3.migrated_to_v4(ZoneKemAlgorithm::XWing);
    let payload_sig_bytes = unsigned.as_payload().signature.signature;
    assert_eq!(
        payload_sig_bytes, [0xD3; 64],
        "inner signature must still be the V3 fixture's [0xD3; 64], not a fresh sign()"
    );
}

// ── Type transition ─────────────────────────────────────────────────

#[test]
fn typestate_sign_installs_caller_supplied_signature() {
    // br-z8bsg: the only way to get a publishable ZoneKeyManifest is
    // via UnsignedV4Manifest::sign(signature).
    let v3 = make_v3_manifest_with_alice();
    let unsigned = v3.migrated_to_v4(ZoneKemAlgorithm::XWing);
    let signed: ZoneKeyManifest = unsigned.sign(fresh_owner_signature());
    assert_eq!(
        signed.signature.signature, [0xF4; 64],
        "sign() must install the caller-supplied signature, replacing the inherited V3 one"
    );
    assert_eq!(signed.signature.node_id.as_str(), "v4-owner");
    // V4 fields preserved post-sign.
    assert_eq!(signed.kem, ZoneKemAlgorithm::XWing);
    assert_eq!(signed.wrapped_keys_v4.len(), 1);
}

// ── Idempotency through the wrapper ─────────────────────────────────

#[test]
fn typestate_migrated_to_v4_is_idempotent_through_unsigned_wrapper() {
    let v3 = make_v3_manifest_with_alice();
    let once = v3.migrated_to_v4(ZoneKemAlgorithm::XWing);
    let twice = once.migrated_to_v4(ZoneKemAlgorithm::XWing);
    assert_eq!(once.as_payload().wrapped_keys_v4.len(), 1);
    assert_eq!(
        twice.as_payload().wrapped_keys_v4.len(),
        1,
        "idempotency preserved through the typestate"
    );
}

// ── Mutation pre-sign ───────────────────────────────────────────────

#[test]
fn typestate_add_xwing_wrap_mutates_pre_sign() {
    // br-z8bsg: adding wraps before signing is safe — the eventual
    // signature commits to the post-mutation payload.
    let v3 = make_v3_manifest_with_alice();
    let mut unsigned = v3.migrated_to_v4(ZoneKemAlgorithm::XWing);

    let provider = XWingProvider::new();
    let (bob_pk, _bob_sk) = provider.generate().unwrap();
    let bob = node("bob");
    let aad = Fcp4Aad::for_zone_key(zone().as_bytes(), bob.as_str().as_bytes(), 1_700_000_001)
        .encode()
        .unwrap();
    let bob_sealed = provider.seal(&bob_pk, b"zone-key", &aad).unwrap();
    unsigned.add_xwing_wrap(bob.clone(), 1_700_000_001, bob_sealed);

    // Bob's wrap is in the unsigned payload.
    assert!(unsigned.as_payload().wrapped_key_v4_for(&bob).is_some());

    let signed = unsigned.sign(fresh_owner_signature());
    // ...and survives the type transition.
    assert!(signed.wrapped_key_v4_for(&bob).is_some());
}

// ── Adversarial: bypass via clone is detectable downstream ─────────

#[test]
fn typestate_bypass_via_payload_clone_yields_manifest_with_invalid_v3_signature() {
    // br-z8bsg secondary defence: a "naughty" caller that bypasses
    // the typestate by cloning the inner value can construct a
    // ZoneKeyManifest, but its signature commits to the pre-migration
    // payload. Any verifier that re-derives canonical signing bytes
    // from the V4 form will see the OLD V3-payload signature and
    // reject.
    let v3 = make_v3_manifest_with_alice();
    let unsigned = v3.migrated_to_v4(ZoneKemAlgorithm::XWing);
    let bypassed: ZoneKeyManifest = unsigned.as_payload().clone();
    // Type-system view: bypassed IS a ZoneKeyManifest — the typestate
    // alone is bypassed. But the inner signature remains the V3
    // [0xD3; 64], not a fresh signature. Any verifier will reject.
    assert_eq!(
        bypassed.signature.signature, [0xD3; 64],
        "bypass leaves the inherited V3 signature in place — caught by signature verification"
    );
    assert_eq!(
        bypassed.signature.node_id.as_str(),
        "v3-owner",
        "bypass caller cannot rewrite who signed without going through sign()"
    );
}

// ── End-to-end happy path ───────────────────────────────────────────

#[test]
fn typestate_full_migrate_mutate_sign_lifecycle_produces_publishable_manifest() {
    // br-z8bsg: the canonical migration flow — migrate → mutate →
    // sign — produces a publishable ZoneKeyManifest with the V4
    // schema fully populated and the fresh signature installed.
    let v3 = make_v3_manifest_with_alice();
    let mut unsigned = v3.migrated_to_v4(ZoneKemAlgorithm::XWing);

    let provider = XWingProvider::new();
    let (carol_pk, _carol_sk) = provider.generate().unwrap();
    let carol = node("carol");
    let aad = Fcp4Aad::for_zone_key(zone().as_bytes(), carol.as_str().as_bytes(), 1_700_000_002)
        .encode()
        .unwrap();
    let carol_sealed = provider.seal(&carol_pk, b"zone-key", &aad).unwrap();
    unsigned.add_xwing_wrap(carol.clone(), 1_700_000_002, carol_sealed);

    let published = unsigned.sign(fresh_owner_signature());
    assert_eq!(published.kem, ZoneKemAlgorithm::XWing);
    assert!(published.wrapped_key_for(&node("alice")).is_some());
    assert!(published.wrapped_key_v4_for(&node("alice")).is_some());
    assert!(published.wrapped_key_v4_for(&carol).is_some());
    assert_eq!(
        published.signature.signature, [0xF4; 64],
        "fresh signature installed"
    );
    // Note: split-view safety on this composed manifest depends on
    // alice's V3+V4 wraps being byte-equal — handled by the shbvv
    // suite (zone_key_manifest_v4_split_view.rs). Out of scope for
    // the z8bsg typestate property.
}
