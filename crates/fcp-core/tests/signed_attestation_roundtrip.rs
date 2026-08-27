//! Pin `SupplyChainAttestation` serde + signing-bytes roundtrip — the closest
//! analogue to "`SignedAttestation`" (flywheel_connectors-o0grt).
//!
//! Bead asks for `SignedAttestation` serde + verify roundtrip pinning. No type
//! literally named `SignedAttestation` exists in fcp-core. The closest analogue
//! is [`SupplyChainAttestation`] at `crates/fcp-core/src/supply_chain.rs:282`,
//! which carries an [`SupplyChainSignature`] envelope, a deterministic
//! `signing_bytes()` method, and a `canonical_bytes(...)` method that produces
//! signable canonical CBOR/JSON. This test pins the wire-shape and the
//! deterministic-signing-bytes invariants together so future drift in any of:
//!   * `AttestationPredicateType` URI-rename serde tags,
//!   * `SupplyChainSignature` 4-field shape,
//!   * `SUPPLY_CHAIN_ATTESTATION_SIGNED_FIELDS` 12-element ordering,
//!   * `signing_bytes()` determinism (same struct → same bytes, mutation → different bytes),
//!   * `builder_allowlist` skip-when-empty serialization,
//!   * `metadata.invocation_id` skip-when-None serialization,
//!
//! This is caught loudly at the integration boundary.

use chrono::{TimeZone, Utc};
use ciborium::Value as CborValue;
use fcp_core::{
    AttestationMaterial, AttestationMetadata, AttestationPredicateType, CanonicalEncoding,
    SUPPLY_CHAIN_ATTESTATION_FORMAT, SUPPLY_CHAIN_ATTESTATION_SCHEMA_VERSION,
    SUPPLY_CHAIN_ATTESTATION_SIGNED_FIELDS, SupplyChainAttestation, SupplyChainSignature,
    TrustRootBinding,
};
use serde_json::json;

fn signature_repr() -> String {
    hex::encode([0x5a; 64])
}

fn sample_signature() -> SupplyChainSignature {
    SupplyChainSignature::new(
        "owner-key-1",
        signature_repr(),
        SUPPLY_CHAIN_ATTESTATION_SIGNED_FIELDS
            .iter()
            .map(|field| (*field).to_string())
            .collect(),
    )
}

fn sample_trust_root() -> TrustRootBinding {
    TrustRootBinding {
        root_type: "sigstore".to_string(),
        root_id: "sigstore-public-good".to_string(),
    }
}

fn sample_attestation() -> SupplyChainAttestation {
    SupplyChainAttestation {
        format: SUPPLY_CHAIN_ATTESTATION_FORMAT.to_string(),
        schema_version: SUPPLY_CHAIN_ATTESTATION_SCHEMA_VERSION.to_string(),
        subject_digest: format!("blake3-256:{}", "a".repeat(64)),
        predicate_type: AttestationPredicateType::SlsaProvenanceV1,
        builder_id: "builder://github/actions".to_string(),
        build_type: "https://slsa.dev/container-based-build/v1".to_string(),
        materials: vec![
            AttestationMaterial {
                uri: "git+https://github.com/flywheel/connectors@refs/heads/main".to_string(),
                digest: format!("blake3-256:{}", "b".repeat(64)),
            },
            AttestationMaterial {
                uri: "https://github.com/flywheel/connectors/archive/v1.2.3.tar.gz".to_string(),
                digest: format!("blake3-256:{}", "c".repeat(64)),
            },
        ],
        metadata: AttestationMetadata {
            build_started_at: Utc.with_ymd_and_hms(2026, 2, 1, 12, 0, 0).single().unwrap(),
            build_finished_at: Utc.with_ymd_and_hms(2026, 2, 1, 12, 5, 0).single().unwrap(),
            invocation_id: Some("gh-run-42".to_string()),
        },
        slsa_level: 3,
        provenance_hash: format!("blake3-256:{}", "d".repeat(64)),
        trust_root: sample_trust_root(),
        builder_allowlist: vec!["builder://github/actions".to_string()],
        signature: sample_signature(),
    }
}

#[test]
fn signed_fields_order_is_strictly_pinned() {
    // The 12-field signed-fields order is what signing_bytes() canonicalizes
    // over. Reordering this constant is a wire break for every signed
    // attestation already on disk.
    assert_eq!(SUPPLY_CHAIN_ATTESTATION_SIGNED_FIELDS.len(), 12);
    assert_eq!(
        SUPPLY_CHAIN_ATTESTATION_SIGNED_FIELDS,
        &[
            "format",
            "schema_version",
            "subject_digest",
            "predicate_type",
            "builder_id",
            "build_type",
            "materials",
            "metadata",
            "slsa_level",
            "provenance_hash",
            "trust_root",
            "builder_allowlist",
        ]
    );
}

#[test]
fn predicate_type_serde_uses_uri_renames() {
    // SLSA provenance v1 serializes to a literal URI string, NOT to PascalCase
    // or snake_case. This is the entire point of `#[serde(rename = "...")]` on
    // the AttestationPredicateType variants — the URI is the wire identifier.
    let slsa = serde_json::to_value(AttestationPredicateType::SlsaProvenanceV1).unwrap();
    assert_eq!(slsa, json!("https://slsa.dev/provenance/v1"));

    let intoto = serde_json::to_value(AttestationPredicateType::InTotoStatementV1).unwrap();
    assert_eq!(intoto, json!("https://in-toto.io/Statement/v1"));

    // Distinct discriminants → distinct strings.
    assert_ne!(slsa, intoto);

    // Round-trip both directions.
    let slsa_back: AttestationPredicateType = serde_json::from_value(slsa).unwrap();
    assert_eq!(slsa_back, AttestationPredicateType::SlsaProvenanceV1);
    let intoto_back: AttestationPredicateType = serde_json::from_value(intoto).unwrap();
    assert_eq!(intoto_back, AttestationPredicateType::InTotoStatementV1);
}

#[test]
fn predicate_type_rejects_pascalcase_input() {
    // Loud sentinel: anyone tempted to drop the URI rename would let
    // PascalCase through. Make sure the URI is the only accepted form.
    let pascal = json!("SlsaProvenanceV1");
    let result: Result<AttestationPredicateType, _> = serde_json::from_value(pascal);
    assert!(
        result.is_err(),
        "predicate_type must reject PascalCase input — got {result:?}"
    );

    let snake = json!("slsa_provenance_v1");
    let result: Result<AttestationPredicateType, _> = serde_json::from_value(snake);
    assert!(
        result.is_err(),
        "predicate_type must reject snake_case input — got {result:?}"
    );
}

#[test]
fn supply_chain_signature_4_field_json_shape() {
    let sig = sample_signature();
    let value = serde_json::to_value(&sig).unwrap();
    let obj = value.as_object().expect("signature must be object");

    // Exactly 4 fields, no more, no less.
    assert_eq!(obj.len(), 4, "signature shape drift: {obj:?}");
    assert_eq!(obj.get("algorithm"), Some(&json!("ed25519")));
    assert_eq!(obj.get("key_id"), Some(&json!("owner-key-1")));
    assert_eq!(obj.get("signature"), Some(&json!(signature_repr())));
    let signed_fields = obj
        .get("signed_fields")
        .and_then(|v| v.as_array())
        .expect("signed_fields must be array");
    assert_eq!(signed_fields.len(), 12);
    assert_eq!(signed_fields[0], json!("format"));
    assert_eq!(signed_fields[11], json!("builder_allowlist"));

    // Round-trip.
    let back: SupplyChainSignature = serde_json::from_value(value).unwrap();
    assert_eq!(back, sig);
}

#[test]
fn attestation_full_json_shape_pinned() {
    let att = sample_attestation();
    let value = serde_json::to_value(&att).unwrap();
    let obj = value.as_object().expect("attestation must be object");

    // 12 signed fields + signature → 13 keys when builder_allowlist is non-empty.
    let expected_keys: std::collections::BTreeSet<&str> = [
        "format",
        "schema_version",
        "subject_digest",
        "predicate_type",
        "builder_id",
        "build_type",
        "materials",
        "metadata",
        "slsa_level",
        "provenance_hash",
        "trust_root",
        "builder_allowlist",
        "signature",
    ]
    .into_iter()
    .collect();
    let actual_keys: std::collections::BTreeSet<&str> = obj.keys().map(String::as_str).collect();
    assert_eq!(actual_keys, expected_keys, "attestation shape drift");

    // Anchor a few critical scalars.
    assert_eq!(
        obj.get("format"),
        Some(&json!(SUPPLY_CHAIN_ATTESTATION_FORMAT))
    );
    assert_eq!(
        obj.get("schema_version"),
        Some(&json!(SUPPLY_CHAIN_ATTESTATION_SCHEMA_VERSION))
    );
    assert_eq!(obj.get("slsa_level"), Some(&json!(3)));
    assert_eq!(
        obj.get("predicate_type"),
        Some(&json!("https://slsa.dev/provenance/v1"))
    );
}

#[test]
fn attestation_json_roundtrip_preserves_all_fields() {
    let att = sample_attestation();
    let bytes = serde_json::to_vec(&att).unwrap();
    let back: SupplyChainAttestation = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(back, att);
}

#[test]
fn attestation_cbor_roundtrip_preserves_all_fields() {
    let att = sample_attestation();
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&att, &mut bytes).unwrap();
    let back: SupplyChainAttestation = ciborium::de::from_reader(&bytes[..]).unwrap();
    assert_eq!(back, att);
}

#[test]
fn attestation_canonical_cbor_decodes_to_same_struct_as_serde() {
    let att = sample_attestation();
    let canonical = att.canonical_bytes(CanonicalEncoding::Cbor).unwrap();
    let back: SupplyChainAttestation = ciborium::de::from_reader(&canonical[..]).unwrap();
    assert_eq!(back, att);
}

#[test]
fn attestation_canonical_json_decodes_to_same_struct_as_serde() {
    let att = sample_attestation();
    let canonical = att.canonical_bytes(CanonicalEncoding::Json).unwrap();
    let back: SupplyChainAttestation = serde_json::from_slice(&canonical).unwrap();
    assert_eq!(back, att);
}

#[test]
fn signing_bytes_are_deterministic_for_same_struct() {
    let a = sample_attestation();
    let b = sample_attestation();
    assert_eq!(a.signing_bytes().unwrap(), b.signing_bytes().unwrap());
}

#[test]
fn signing_bytes_omit_signature_field_so_signing_is_idempotent() {
    // signing_bytes() canonicalizes ONLY the signed view (12 fields, no
    // signature). Mutating only `signature` must not change signing_bytes —
    // otherwise verification of newly re-signed attestations would diverge.
    let mut a = sample_attestation();
    let bytes_before = a.signing_bytes().unwrap();
    a.signature = SupplyChainSignature::new(
        "different-key-id",
        hex::encode([0xee; 64]),
        SUPPLY_CHAIN_ATTESTATION_SIGNED_FIELDS
            .iter()
            .map(|field| (*field).to_string())
            .collect(),
    );
    let bytes_after = a.signing_bytes().unwrap();
    assert_eq!(
        bytes_before, bytes_after,
        "signing_bytes() must not depend on signature envelope"
    );
}

#[test]
fn signing_bytes_change_when_signed_field_mutates() {
    // Mutating any of the 12 signed fields MUST flip signing_bytes(), or we
    // have a silent canonicalization gap that breaks signature security.
    let base = sample_attestation();
    let base_bytes = base.signing_bytes().unwrap();

    // Mutate slsa_level.
    let mut a = base.clone();
    a.slsa_level = 4;
    assert_ne!(
        a.signing_bytes().unwrap(),
        base_bytes,
        "slsa_level change must alter signing_bytes"
    );

    // Mutate builder_id.
    let mut b = base.clone();
    b.builder_id = "builder://gitlab/runners".to_string();
    assert_ne!(
        b.signing_bytes().unwrap(),
        base_bytes,
        "builder_id change must alter signing_bytes"
    );

    // Mutate predicate_type.
    let mut c = base.clone();
    c.predicate_type = AttestationPredicateType::InTotoStatementV1;
    assert_ne!(
        c.signing_bytes().unwrap(),
        base_bytes,
        "predicate_type change must alter signing_bytes"
    );

    // Mutate builder_allowlist.
    let mut d = base;
    d.builder_allowlist = vec![
        "builder://github/actions".to_string(),
        "builder://gitlab/runners".to_string(),
    ];
    assert_ne!(
        d.signing_bytes().unwrap(),
        base_bytes,
        "builder_allowlist change must alter signing_bytes"
    );
}

#[test]
fn signing_bytes_have_nontrivial_length_with_schema_prefix_overhead() {
    // canonical_signing_bytes is `SIGNING_DOMAIN || schema_hash || cbor(unsigned_view)`.
    // The schema_hash is a 32-byte digest of the schema id, plus the CBOR
    // payload — together comfortably above 64 bytes for a populated
    // attestation. Pin the lower bound so a future change to "just CBOR" is
    // caught at the integration boundary.
    let att = sample_attestation();
    let bytes = att.signing_bytes().unwrap();
    assert!(
        bytes.len() > 64,
        "signing_bytes too short ({} bytes) — schema prefix likely dropped",
        bytes.len()
    );
}

#[test]
fn empty_builder_allowlist_omitted_from_wire_form() {
    let mut att = sample_attestation();
    att.builder_allowlist = vec![];

    let value = serde_json::to_value(&att).unwrap();
    let obj = value.as_object().unwrap();
    assert!(
        !obj.contains_key("builder_allowlist"),
        "empty builder_allowlist must be skipped"
    );

    // Round-trip recovers an empty Vec via serde(default).
    let back: SupplyChainAttestation = serde_json::from_value(value).unwrap();
    assert_eq!(back.builder_allowlist, [] as [std::string::String; 0]);
}

#[test]
fn missing_invocation_id_omitted_from_wire_form() {
    let mut att = sample_attestation();
    att.metadata.invocation_id = None;

    let value = serde_json::to_value(&att).unwrap();
    let metadata = value
        .get("metadata")
        .and_then(|v| v.as_object())
        .expect("metadata object");
    assert!(
        !metadata.contains_key("invocation_id"),
        "None invocation_id must be skipped"
    );

    // Round-trip preserves None.
    let back: SupplyChainAttestation = serde_json::from_value(value).unwrap();
    assert!(back.metadata.invocation_id.is_none());
}

#[test]
fn cbor_value_inspection_pins_predicate_type_uri_on_the_wire() {
    // CBOR encodes `predicate_type` as a TEXT key whose value is the URI text
    // — confirm the URI form survives the binary encoding too, not just JSON.
    let att = sample_attestation();
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&att, &mut bytes).unwrap();
    let value: CborValue = ciborium::de::from_reader(&bytes[..]).unwrap();
    let map = match &value {
        CborValue::Map(m) => m,
        other => panic!("expected CBOR map, got {other:?}"),
    };
    let mut found_uri = None;
    for (k, v) in map {
        if let CborValue::Text(name) = k {
            if name == "predicate_type" {
                if let CborValue::Text(uri) = v {
                    found_uri = Some(uri.clone());
                }
            }
        }
    }
    assert_eq!(
        found_uri.as_deref(),
        Some("https://slsa.dev/provenance/v1"),
        "predicate_type URI must survive CBOR encoding"
    );
}

#[test]
fn canonical_json_and_cbor_decode_to_same_struct() {
    let att = sample_attestation();
    let json_canonical = att.canonical_bytes(CanonicalEncoding::Json).unwrap();
    let cbor_canonical = att.canonical_bytes(CanonicalEncoding::Cbor).unwrap();

    let from_json: SupplyChainAttestation = serde_json::from_slice(&json_canonical).unwrap();
    let from_cbor: SupplyChainAttestation = ciborium::de::from_reader(&cbor_canonical[..]).unwrap();
    assert_eq!(
        from_json, from_cbor,
        "JSON and CBOR canonical encodings must round-trip to the same struct"
    );
}
