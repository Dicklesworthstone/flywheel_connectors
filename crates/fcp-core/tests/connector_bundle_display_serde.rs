use fcp_core::{ConnectorBundle, ConnectorTarget};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const MANIFEST_TOML: &str = "name = \"github\"\nversion = \"1.2.3\"\n";

fn sample_bundle() -> ConnectorBundle {
    ConnectorBundle::new(
        MANIFEST_TOML,
        vec![0xde, 0xad, 0xbe, 0xef, 0x00],
        ConnectorTarget {
            os: "linux".to_string(),
            arch: "amd64".to_string(),
        },
    )
}

#[test]
fn connector_bundle_display_format_is_pinned() {
    let bundle = sample_bundle();

    assert_eq!(
        bundle.to_string(),
        "linux-amd64 connector bundle (manifest_toml=34 bytes, binary=5 bytes)"
    );
}

#[test]
fn connector_bundle_json_roundtrip_shape_is_pinned() -> TestResult {
    let bundle = sample_bundle();
    let value = serde_json::to_value(&bundle)?;

    assert_eq!(
        value,
        serde_json::json!({
            "manifest_toml": MANIFEST_TOML,
            "binary": [222, 173, 190, 239, 0],
            "target": {
                "os": "linux",
                "arch": "amd64"
            }
        })
    );

    let decoded: ConnectorBundle = serde_json::from_value(value)?;
    assert_eq!(decoded, bundle);
    assert_eq!(decoded.to_string(), bundle.to_string());

    Ok(())
}

#[test]
fn connector_bundle_cbor_roundtrip_preserves_fields_and_display() -> TestResult {
    let bundle = sample_bundle();
    let mut encoded = Vec::new();
    ciborium::into_writer(&bundle, &mut encoded)?;

    assert_ne!(encoded, [] as [u8; 0]);

    let decoded: ConnectorBundle = ciborium::from_reader(encoded.as_slice())?;
    assert_eq!(decoded, bundle);
    assert_eq!(decoded.to_string(), bundle.to_string());

    Ok(())
}
