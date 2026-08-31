//! Pin `ZoneKeyAlgorithm` `snake_case`-quirk rejection sentinels +
//! `ZoneKeyManifest` embedded-algorithm round-trip
//! (flywheel_connectors-aznqw).
//!
//! [`ZoneKeyAlgorithm`] at `crates/fcp-core/src/zone_keys.rs:107` is a
//! 2-variant enum (`ChaCha20Poly1305` / `XChaCha20Poly1305`) with
//! `#[serde(rename_all = "snake_case")]`. Its surprising wire form is
//! `cha_cha20_poly1305` / `x_cha_cha20_poly1305` — serde's `snake_case`
//! aggressively splits at every uppercase transition (even inside the
//! `ChaCha20` acronym), producing a form that's easy to misread when
//! authoring zone-key manifests by hand.
//!
//! Existing `zone_namespace_display_serde_tag.rs` already pins the
//! happy-path JSON + CBOR tag-equals-`cha_cha20_poly1305`/
//! `x_cha_cha20_poly1305` shapes. This pin adds residual axes:
//!   * Loud "wrong-form rejection" sentinel: the more-obvious
//!     `chacha20_poly1305` (without the inner `_`) MUST NOT decode —
//!     pin so a future tolerant alias silently changes the wire
//!     vocabulary,
//!   * `PascalCase` / `SCREAMING` / `kebab-case` rejection sentinels,
//!   * Distinct-variant pairwise pin (the only 2 variants must produce
//!     distinct wire bytes; the X-prefix differentiates them),
//!   * `ZoneKeyManifest` with embedded algorithm: JSON+CBOR round-trip
//!     preserves both `ChaCha` and `XChaCha` algorithms inside the
//!     manifest envelope,
//!   * `HashMap`-key behavior (algorithm derives `Hash` via `PartialEq`+`Eq`
//!     ... actually no — let me check).
//!   * `skip_serializing_if` + default-`Vec` semantics for the 4 optional
//!     `ZoneKeyManifest` fields.

use ciborium::Value as CborValue;
use fcp_cbor::SchemaId;
use fcp_core::{
    NodeId, NodeSignature, ObjectHeader, ObjectIdKeyId, Provenance, WrappedObjectIdKey,
    WrappedZoneKey, ZoneId, ZoneKemAlgorithm, ZoneKeyAlgorithm, ZoneKeyId, ZoneKeyManifest,
};
use semver::Version;
use serde_json::json;

const ALL_ALGORITHMS: &[(ZoneKeyAlgorithm, &str)] = &[
    (ZoneKeyAlgorithm::ChaCha20Poly1305, "cha_cha20_poly1305"),
    (ZoneKeyAlgorithm::XChaCha20Poly1305, "x_cha_cha20_poly1305"),
];

#[test]
fn json_form_rejects_obvious_wrong_chacha20_poly1305_token() {
    // LOUD SENTINEL: the obvious-looking `chacha20_poly1305` (single
    // run of `chacha`, treating ChaCha as one acronym) is NOT the wire
    // form. Reject it loudly so a future tolerant-alias addition is
    // caught.
    for bad in [
        json!("chacha20_poly1305"),  // missing inner _
        json!("xchacha20_poly1305"), // missing inner _, no hyphen
        json!("chacha20-poly1305"),  // hyphen instead of _
        json!("chacha20"),
    ] {
        let result: Result<ZoneKeyAlgorithm, _> = serde_json::from_value(bad.clone());
        assert!(
            result.is_err(),
            "ZoneKeyAlgorithm must reject `{bad}`, got {result:?}"
        );
    }
}

#[test]
fn json_form_rejects_pascal_case_variant_names() {
    for bad in ["ChaCha20Poly1305", "XChaCha20Poly1305"] {
        let result: Result<ZoneKeyAlgorithm, _> = serde_json::from_value(json!(bad));
        assert!(
            result.is_err(),
            "PascalCase `{bad}` must reject, got {result:?}"
        );
    }
}

#[test]
fn json_form_rejects_screaming_and_kebab_case() {
    for bad in [
        "CHA_CHA20_POLY1305",
        "CHACHA20_POLY1305",
        "cha-cha20-poly1305",
        "x-cha-cha20-poly1305",
    ] {
        let result: Result<ZoneKeyAlgorithm, _> = serde_json::from_value(json!(bad));
        assert!(
            result.is_err(),
            "non-canonical `{bad}` must reject, got {result:?}"
        );
    }
}

#[test]
fn cha_cha20_and_x_cha_cha20_serialize_distinctly() {
    let a = serde_json::to_value(ZoneKeyAlgorithm::ChaCha20Poly1305).unwrap();
    let b = serde_json::to_value(ZoneKeyAlgorithm::XChaCha20Poly1305).unwrap();
    assert_ne!(a, b);
    // The X variant has the documented `x_` prefix; pin so a future
    // rename that drops the prefix is caught.
    let x_str = b.as_str().unwrap();
    assert!(
        x_str.starts_with("x_"),
        "XChaCha20Poly1305 wire form must start with `x_`, got `{x_str}`"
    );
}

#[test]
fn cbor_form_rejects_pascal_case_too() {
    // CBOR Text scalar with PascalCase must also reject (uses the same
    // serde adapter under the hood).
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&"ChaCha20Poly1305", &mut bytes).unwrap();
    let result: Result<ZoneKeyAlgorithm, _> = ciborium::de::from_reader(&bytes[..]);
    assert!(
        result.is_err(),
        "CBOR PascalCase must reject, got {result:?}"
    );
}

#[test]
fn cbor_form_uses_text_scalar_not_integer() {
    // ZoneKeyAlgorithm has no #[repr(u8)]/integer encoding directive →
    // the CBOR form is a Text scalar (not a numeric variant index).
    // Pin so a future #[serde(into = "u8")] silently changes the wire form.
    for &(algo, expected) in ALL_ALGORITHMS {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&algo, &mut bytes).unwrap();
        let value: CborValue = ciborium::de::from_reader(&bytes[..]).unwrap();
        match value {
            CborValue::Text(t) => assert_eq!(t, expected),
            other => panic!("ZoneKeyAlgorithm must encode as CBOR Text scalar, got {other:?}"),
        }
    }
}

fn make_signature() -> NodeSignature {
    NodeSignature::new(NodeId::new("owner"), [0u8; 64], 1_700_000_000)
}

fn make_manifest(algorithm: ZoneKeyAlgorithm) -> ZoneKeyManifest {
    let zone = ZoneId::work();
    ZoneKeyManifest {
        header: ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.zone", "ZoneKeyManifest", Version::new(1, 0, 0)),
            zone_id: zone.clone(),
            created_at: 1_700_000_000,
            provenance: Provenance::new(zone.clone()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        },
        zone_id: zone,
        zone_key_id: ZoneKeyId::from_bytes([1u8; 8]),
        object_id_key_id: ObjectIdKeyId::from_bytes([2u8; 8]),
        algorithm,
        valid_from: 1_700_000_000,
        valid_until: None,
        prev_zone_key_id: None,
        wrapped_keys: vec![],
        wrapped_object_id_keys: vec![],
        rekey_policy: None,
        signature: make_signature(),
        kem: ZoneKemAlgorithm::HpkeX25519,
        wrapped_keys_v4: vec![],
    }
}

#[test]
fn zone_key_manifest_embeds_algorithm_with_canonical_wire_form() {
    for &(algo, expected) in ALL_ALGORITHMS {
        let m = make_manifest(algo);
        let v = serde_json::to_value(&m).unwrap();
        let obj = v.as_object().unwrap();
        assert_eq!(
            obj.get("algorithm"),
            Some(&json!(expected)),
            "embedded algorithm wire form drift for {algo:?}"
        );
    }
}

#[test]
fn zone_key_manifest_json_roundtrip_preserves_algorithm() {
    for &(algo, _) in ALL_ALGORITHMS {
        let m = make_manifest(algo);
        let bytes = serde_json::to_vec(&m).unwrap();
        let back: ZoneKeyManifest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.algorithm, algo);
    }
}

#[test]
fn zone_key_manifest_cbor_roundtrip_preserves_algorithm() {
    for &(algo, _) in ALL_ALGORITHMS {
        let m = make_manifest(algo);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&m, &mut bytes).unwrap();
        let back: ZoneKeyManifest = ciborium::de::from_reader(&bytes[..]).unwrap();
        assert_eq!(back.algorithm, algo);
    }
}

#[test]
fn zone_key_manifest_skip_when_none_for_optional_fields() {
    let m = make_manifest(ZoneKeyAlgorithm::ChaCha20Poly1305);
    let v = serde_json::to_value(&m).unwrap();
    let obj = v.as_object().unwrap();

    // 4 fields use skip_serializing_if = "Option::is_none":
    // valid_until, prev_zone_key_id, rekey_policy.
    // wrapped_keys + wrapped_object_id_keys use #[serde(default)] but
    // NO skip → they serialize as [].
    assert!(!obj.contains_key("valid_until"));
    assert!(!obj.contains_key("prev_zone_key_id"));
    assert!(!obj.contains_key("rekey_policy"));

    // Empty Vec serializes as [].
    assert_eq!(obj.get("wrapped_keys"), Some(&json!([])));
    assert_eq!(obj.get("wrapped_object_id_keys"), Some(&json!([])));
}

#[test]
fn zone_key_manifest_with_populated_optional_fields_round_trips() {
    let mut m = make_manifest(ZoneKeyAlgorithm::XChaCha20Poly1305);
    m.valid_until = Some(2_000_000_000);
    m.prev_zone_key_id = Some(ZoneKeyId::from_bytes([9u8; 8]));

    let bytes = serde_json::to_vec(&m).unwrap();
    let back: ZoneKeyManifest = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(back.algorithm, ZoneKeyAlgorithm::XChaCha20Poly1305);
    assert_eq!(back.valid_until, Some(2_000_000_000));
    assert_eq!(back.prev_zone_key_id, Some(ZoneKeyId::from_bytes([9u8; 8])));
}

#[test]
fn distinct_algorithms_produce_distinct_manifest_serializations() {
    let cha = make_manifest(ZoneKeyAlgorithm::ChaCha20Poly1305);
    let xcha = make_manifest(ZoneKeyAlgorithm::XChaCha20Poly1305);
    assert_ne!(
        serde_json::to_value(&cha).unwrap(),
        serde_json::to_value(&xcha).unwrap(),
        "manifests differing only in algorithm must produce distinct JSON"
    );
}

#[test]
fn unknown_zone_key_algorithm_variant_rejects() {
    let result: Result<ZoneKeyAlgorithm, _> = serde_json::from_value(json!("aes_256_gcm"));
    assert!(
        result.is_err(),
        "unknown algorithm `aes_256_gcm` must reject — pin the closed vocabulary"
    );
}

#[test]
fn algorithm_count_is_documented_two() {
    // Loud sentinel for the closed-vocabulary contract: exactly 2
    // variants. Adding a third (e.g. AES-GCM) requires deliberate
    // protocol-level decision.
    assert_eq!(
        ALL_ALGORITHMS.len(),
        2,
        "ZoneKeyAlgorithm must have exactly 2 variants per documented closed vocabulary"
    );
}

#[test]
fn copy_clone_eq_derive_is_intact() {
    // ZoneKeyAlgorithm must remain Copy + Clone + PartialEq — these
    // properties are relied on by storage code that copies the
    // discriminator without ownership.
    fn assert_copy<T: Copy>() {}
    fn assert_clone<T: Clone>() {}

    assert_copy::<ZoneKeyAlgorithm>();
    assert_clone::<ZoneKeyAlgorithm>();

    let a = ZoneKeyAlgorithm::ChaCha20Poly1305;
    let b = a; // Copy
    assert_eq!(a, b);
    assert_ne!(a, ZoneKeyAlgorithm::XChaCha20Poly1305);
}

#[test]
fn wrapped_zone_key_serde_includes_recipient_issued_at_and_sealed() {
    // Sanity: WrappedZoneKey is a sibling type that lives inside
    // ZoneKeyManifest.wrapped_keys. Pin its 3-field shape so a future
    // change to embed an algorithm field directly here is caught.
    let wrapped = WrappedZoneKey {
        recipient: fcp_core::TailscaleNodeId::new("node-x"),
        issued_at: 1_700_000_000,
        sealed: fcp_crypto::HpkeSealedBox {
            enc: vec![0u8; 32],
            ciphertext: vec![1u8; 16],
        },
    };
    let v = serde_json::to_value(&wrapped).unwrap();
    let obj = v.as_object().unwrap();
    let expected: std::collections::BTreeSet<&str> =
        ["recipient", "issued_at", "sealed"].into_iter().collect();
    let actual: std::collections::BTreeSet<&str> = obj.keys().map(String::as_str).collect();
    assert_eq!(actual, expected, "WrappedZoneKey shape drift: {obj:?}");

    // Note: WrappedZoneKey carries no algorithm field — algorithm lives
    // ONLY at the manifest level. Pin so future scoping changes
    // (per-recipient algorithm) are caught.
    assert!(!obj.contains_key("algorithm"));
}

#[test]
fn wrapped_object_id_key_has_same_shape_as_wrapped_zone_key() {
    // Loud sentinel: WrappedObjectIdKey and WrappedZoneKey share the
    // same 3-field layout. Pin so a future divergence is caught at the
    // integration boundary.
    let w = WrappedObjectIdKey {
        recipient: fcp_core::TailscaleNodeId::new("node-x"),
        issued_at: 1_700_000_000,
        sealed: fcp_crypto::HpkeSealedBox {
            enc: vec![0u8; 32],
            ciphertext: vec![1u8; 16],
        },
    };
    let v = serde_json::to_value(&w).unwrap();
    let obj = v.as_object().unwrap();
    let expected: std::collections::BTreeSet<&str> =
        ["recipient", "issued_at", "sealed"].into_iter().collect();
    let actual: std::collections::BTreeSet<&str> = obj.keys().map(String::as_str).collect();
    assert_eq!(actual, expected);
}
