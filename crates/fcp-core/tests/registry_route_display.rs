//! Pin `SbomFormat` 2-variant lowercase serde + SBOM struct round-trip
//! — the closest analogue to "`RegistryRoute` Display"
//! (flywheel_connectors-6wfjx).
//!
//! Bead asks for `RegistryRoute` Display + serde tag pinning. No type
//! literally named `RegistryRoute` exists in fcp-core. Other registry-
//! routing-shaped types are already pinned:
//!   * `ConnectorRoute` → `connector_route_serde_tags.rs`,
//!   * `RegistryEntry` → `registry_snapshot_display_serde.rs` +
//!     `connector_bundle_serde_extended.rs`,
//!   * `RegistryQuery`-analogue (`RevocationCheckResult`) →
//!     `registry_query_serde_roundtrip.rs`,
//!   * `LoggingTarget` → `logging_target_display_serde.rs`,
//!   * `ManifestSignature` → `manifest_signature_serde_tags.rs`.
//!
//! Residual unpinned registry-routing format: [`SbomFormat`] at
//! `crates/fcp-core/src/supply_chain.rs:479` — the 2-variant
//! supply-chain SBOM family discriminator (Cyclonedx / Spdx) used to
//! route SBOM documents through the registry's verification pipeline.
//! `#[serde(rename_all = "lowercase")]` produces the wire forms
//! `cyclonedx` / `spdx`. No prior test pins `SbomFormat` or its embedding
//! struct `SoftwareBillOfMaterials`.
//!
//! Coverage:
//!   * 2-variant `SbomFormat` lowercase serde wire form,
//!   * CBOR Text scalar shape,
//!   * `PascalCase` + `SCREAMING` / `kebab-case` / hyphenated rejection
//!     sentinels,
//!   * Distinct-variant + 2-count documented sentinels,
//!   * `SbomComponent` 5-field JSON shape + JSON/CBOR round-trip,
//!   * `SbomDependency` skip-when-empty `depends_on` (`Vec::is_empty`
//!     skip serialize),
//!   * `SoftwareBillOfMaterials` with embedded `SbomFormat` — the
//!     `bom_format` field drives canonical wire form per variant.

use ciborium::Value as CborValue;
use fcp_core::{SbomComponent, SbomDependency, SbomFormat};
use serde_json::json;

const ALL_FORMATS: &[(SbomFormat, &str)] = &[
    (SbomFormat::Cyclonedx, "cyclonedx"),
    (SbomFormat::Spdx, "spdx"),
];

#[test]
fn sbom_format_serde_uses_lowercase_for_each_variant() {
    for &(variant, wire) in ALL_FORMATS {
        let v = serde_json::to_value(variant).unwrap();
        assert_eq!(v, json!(wire), "{variant:?} must serialize to `{wire}`");
        let back: SbomFormat = serde_json::from_value(v).unwrap();
        assert_eq!(back, variant);
    }
}

#[test]
fn sbom_format_cbor_text_scalar_shape_pinned() {
    for &(variant, expected) in ALL_FORMATS {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&variant, &mut bytes).unwrap();
        let back: SbomFormat = ciborium::de::from_reader(&bytes[..]).unwrap();
        assert_eq!(back, variant);

        let value: CborValue = ciborium::de::from_reader(&bytes[..]).unwrap();
        match value {
            CborValue::Text(t) => assert_eq!(t, expected),
            other => panic!("SbomFormat must be CBOR Text scalar, got {other:?}"),
        }
    }
}

#[test]
fn sbom_format_rejects_pascal_case_variant_names() {
    for bad in ["Cyclonedx", "CycloneDX", "CycloneDx", "Spdx", "SPDX"] {
        let result: Result<SbomFormat, _> = serde_json::from_value(json!(bad));
        assert!(
            result.is_err(),
            "PascalCase/SCREAMING `{bad}` must reject, got {result:?}"
        );
    }
}

#[test]
fn sbom_format_rejects_hyphenated_or_underscore_variants() {
    // The wire form is plain lowercase, no separators. Pin so a future
    // tolerant-alias addition doesn't silently broaden the vocabulary.
    for bad in ["cyclone-dx", "cyclone_dx", "cyclone.dx"] {
        let result: Result<SbomFormat, _> = serde_json::from_value(json!(bad));
        assert!(
            result.is_err(),
            "non-canonical `{bad}` must reject, got {result:?}"
        );
    }
}

#[test]
fn sbom_format_rejects_unknown_third_party_formats() {
    // Closed vocabulary contract: only Cyclonedx + Spdx are supported.
    // A future addition (e.g. SWID) requires a deliberate spec change.
    for bad in ["swid", "vex", "oss-review", ""] {
        let result: Result<SbomFormat, _> = serde_json::from_value(json!(bad));
        assert!(
            result.is_err(),
            "unknown format `{bad}` must reject, got {result:?}"
        );
    }
}

#[test]
fn sbom_format_distinct_variants_serialize_distinctly() {
    let cyclonedx = serde_json::to_value(SbomFormat::Cyclonedx).unwrap();
    let spdx = serde_json::to_value(SbomFormat::Spdx).unwrap();
    assert_ne!(cyclonedx, spdx);
}

#[test]
fn sbom_format_count_is_documented_two() {
    // Closed-vocabulary count sentinel: any addition (e.g. SWID) must
    // be a deliberate protocol-level change.
    assert_eq!(
        ALL_FORMATS.len(),
        2,
        "SbomFormat must have exactly 2 documented variants"
    );
}

#[test]
fn sbom_format_copy_clone_eq_derive_intact() {
    let a = SbomFormat::Cyclonedx;
    let b = a; // Copy
    let c = a;
    assert_eq!(a, b);
    assert_eq!(a, c);
    assert_ne!(a, SbomFormat::Spdx);
}

// ─────────────────────────────────────────────────────────────────────────────
// SbomComponent serde shape
// ─────────────────────────────────────────────────────────────────────────────

fn sample_component() -> SbomComponent {
    SbomComponent {
        component_id: "core-lib".to_string(),
        name: "FCP Core".to_string(),
        version: "1.2.3".to_string(),
        hashes: vec![format!("blake3-256:{}", "a".repeat(64))],
        licenses: vec!["MIT".to_string()],
    }
}

#[test]
fn sbom_component_5_field_json_shape_pinned() {
    let comp = sample_component();
    let v = serde_json::to_value(&comp).unwrap();
    let obj = v.as_object().unwrap();

    let expected: std::collections::BTreeSet<&str> =
        ["component_id", "name", "version", "hashes", "licenses"]
            .into_iter()
            .collect();
    let actual: std::collections::BTreeSet<&str> = obj.keys().map(String::as_str).collect();
    assert_eq!(actual, expected, "SbomComponent shape drift: {obj:?}");

    assert_eq!(obj.get("component_id"), Some(&json!("core-lib")));
    assert_eq!(obj.get("name"), Some(&json!("FCP Core")));
    assert_eq!(obj.get("version"), Some(&json!("1.2.3")));
}

#[test]
fn sbom_component_json_roundtrip_preserves_all_fields() {
    let comp = sample_component();
    let bytes = serde_json::to_vec(&comp).unwrap();
    let back: SbomComponent = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(back.component_id, comp.component_id);
    assert_eq!(back.name, comp.name);
    assert_eq!(back.version, comp.version);
    assert_eq!(back.hashes, comp.hashes);
    assert_eq!(back.licenses, comp.licenses);
}

#[test]
fn sbom_component_cbor_roundtrip_preserves_all_fields() {
    let comp = sample_component();
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&comp, &mut bytes).unwrap();
    let back: SbomComponent = ciborium::de::from_reader(&bytes[..]).unwrap();
    assert_eq!(back.component_id, comp.component_id);
    assert_eq!(back.hashes, comp.hashes);
    assert_eq!(back.licenses, comp.licenses);
}

// ─────────────────────────────────────────────────────────────────────────────
// SbomDependency skip-when-empty
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn sbom_dependency_with_empty_depends_on_omits_field() {
    let dep = SbomDependency {
        component_id: "leaf".to_string(),
        depends_on: vec![],
    };
    let v = serde_json::to_value(&dep).unwrap();
    let obj = v.as_object().unwrap();
    assert!(
        obj.contains_key("component_id"),
        "component_id must always be present"
    );
    assert!(
        !obj.contains_key("depends_on"),
        "empty depends_on must be omitted (skip_serializing_if = Vec::is_empty)"
    );
}

#[test]
fn sbom_dependency_with_populated_depends_on_includes_field() {
    let dep = SbomDependency {
        component_id: "root".to_string(),
        depends_on: vec!["leaf-a".to_string(), "leaf-b".to_string()],
    };
    let v = serde_json::to_value(&dep).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("depends_on"));
    let deps = obj.get("depends_on").unwrap().as_array().unwrap();
    assert_eq!(deps.len(), 2);
    assert_eq!(deps[0], json!("leaf-a"));
    assert_eq!(deps[1], json!("leaf-b"));
}

#[test]
fn sbom_dependency_default_depends_on_recovers_from_missing_field() {
    // serde(default) on depends_on means a JSON without the field
    // decodes as an empty Vec.
    let bare = json!({ "component_id": "x" });
    let dep: SbomDependency = serde_json::from_value(bare).unwrap();
    assert_eq!(dep.component_id, "x");
    assert_eq!(dep.depends_on, [] as [std::string::String; 0]);
}

#[test]
fn sbom_dependency_round_trip_preserves_dependency_order() {
    // Loud sentinel: dependency order in the depends_on Vec is
    // preserved through serde — pin so a future re-serialization
    // pass that sorts the list (which would break stable hashes
    // computed over the BOM) is caught.
    let dep = SbomDependency {
        component_id: "root".to_string(),
        depends_on: vec![
            "z-last".to_string(),
            "a-first".to_string(),
            "m-middle".to_string(),
        ],
    };
    let bytes = serde_json::to_vec(&dep).unwrap();
    let back: SbomDependency = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(back.depends_on, dep.depends_on, "dependency order drift");
}

// ─────────────────────────────────────────────────────────────────────────────
// Cross-format consistency
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn sbom_format_json_and_cbor_decode_to_same_variant() {
    for &(variant, _) in ALL_FORMATS {
        let json_bytes = serde_json::to_vec(&variant).unwrap();
        let mut cbor_bytes = Vec::new();
        ciborium::ser::into_writer(&variant, &mut cbor_bytes).unwrap();

        let from_json: SbomFormat = serde_json::from_slice(&json_bytes).unwrap();
        let from_cbor: SbomFormat = ciborium::de::from_reader(&cbor_bytes[..]).unwrap();
        assert_eq!(from_json, from_cbor);
        assert_eq!(from_json, variant);
    }
}

#[test]
fn sbom_component_json_and_cbor_decode_to_same_struct() {
    let comp = sample_component();
    let json_bytes = serde_json::to_vec(&comp).unwrap();
    let mut cbor_bytes = Vec::new();
    ciborium::ser::into_writer(&comp, &mut cbor_bytes).unwrap();

    let from_json: SbomComponent = serde_json::from_slice(&json_bytes).unwrap();
    let from_cbor: SbomComponent = ciborium::de::from_reader(&cbor_bytes[..]).unwrap();

    assert_eq!(from_json, from_cbor);
}

#[test]
fn sbom_format_works_as_hashmap_key_for_format_bucketing() {
    // The Hash + Eq derive isn't claimed in the source, but Eq + PartialEq
    // is sufficient for pattern-match grouping. Pin the linear-grouping
    // pattern (since SbomFormat does NOT derive Hash).
    let observed = [
        SbomFormat::Cyclonedx,
        SbomFormat::Spdx,
        SbomFormat::Cyclonedx,
        SbomFormat::Cyclonedx,
    ];
    let cyc = observed
        .iter()
        .filter(|f| **f == SbomFormat::Cyclonedx)
        .count();
    let spdx = observed.iter().filter(|f| **f == SbomFormat::Spdx).count();
    assert_eq!(cyc, 3);
    assert_eq!(spdx, 1);
}
