//! Pin the fcp-core manifest subset serde surface.
//!
//! There is no literal `ManifestSubset` type in fcp-core. The exported
//! manifest-only subset is `ConnectorManifestObject`: manifest TOML plus
//! manifest hash, with no binary payload.

use ciborium::value::Value as CborValue;
use fcp_core::ConnectorManifestObject;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const MANIFEST_TOML: &str = r#"name = "github"
version = "1.2.3"

[capabilities]
read = ["issues", "pull_requests"]
"#;
const MANIFEST_HASH: &str =
    "blake3-256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn sample_manifest_subset() -> ConnectorManifestObject {
    ConnectorManifestObject {
        manifest_toml: MANIFEST_TOML.to_string(),
        manifest_hash: MANIFEST_HASH.to_string(),
    }
}

#[test]
fn manifest_subset_json_shape_and_roundtrip_are_pinned() -> TestResult {
    let subset = sample_manifest_subset();
    let value = serde_json::to_value(&subset)?;

    assert_eq!(
        value,
        serde_json::json!({
            "manifest_toml": MANIFEST_TOML,
            "manifest_hash": MANIFEST_HASH,
        })
    );

    let decoded: ConnectorManifestObject = serde_json::from_value(value)?;
    assert_eq!(decoded, subset);
    assert_eq!(decoded.manifest_toml, MANIFEST_TOML);
    assert_eq!(decoded.manifest_hash, MANIFEST_HASH);

    Ok(())
}

#[test]
fn manifest_subset_cbor_shape_and_roundtrip_are_pinned() -> TestResult {
    let subset = sample_manifest_subset();
    let mut encoded = Vec::new();
    ciborium::into_writer(&subset, &mut encoded)?;
    assert_ne!(encoded, [] as [u8; 0]);

    let value: CborValue = ciborium::from_reader(encoded.as_slice())?;
    let CborValue::Map(entries) = value else {
        panic!("ConnectorManifestObject must CBOR-encode as a map");
    };
    assert_eq!(entries.len(), 2);
    assert!(entries.contains(&(
        CborValue::Text("manifest_toml".to_string()),
        CborValue::Text(MANIFEST_TOML.to_string()),
    )));
    assert!(entries.contains(&(
        CborValue::Text("manifest_hash".to_string()),
        CborValue::Text(MANIFEST_HASH.to_string()),
    )));

    let mut encoded_again = Vec::new();
    ciborium::into_writer(&subset, &mut encoded_again)?;
    let decoded: ConnectorManifestObject = ciborium::from_reader(encoded_again.as_slice())?;
    assert_eq!(decoded, subset);

    Ok(())
}
