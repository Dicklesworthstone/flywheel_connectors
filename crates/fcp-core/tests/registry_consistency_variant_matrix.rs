//! Pin the fcp-core registry-consistency variant matrix.
//!
//! There is no public type literally named `RegistryConsistency` in
//! fcp-core. The registry-consistency result surface is `SealValidation`:
//! a revocation-registry seal is either still valid, stale because the
//! registry head advanced, changed locally, or mismatched against another token.

use ciborium::value::Value as CborValue;
use fcp_core::SealValidation;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn err(message: impl Into<String>) -> Box<dyn std::error::Error> {
    std::io::Error::other(message.into()).into()
}

struct Case {
    value: SealValidation,
    display: &'static str,
    json: serde_json::Value,
}

fn cases() -> [Case; 4] {
    [
        Case {
            value: SealValidation::Valid,
            display: "valid",
            json: serde_json::json!({"type": "valid"}),
        },
        Case {
            value: SealValidation::Stale {
                seal_seq: 7,
                current_seq: 11,
            },
            display: "stale",
            json: serde_json::json!({
                "type": "stale",
                "seal_seq": 7,
                "current_seq": 11,
            }),
        },
        Case {
            value: SealValidation::StateChanged,
            display: "state_changed",
            json: serde_json::json!({"type": "state_changed"}),
        },
        Case {
            value: SealValidation::TokenMismatch,
            display: "token_mismatch",
            json: serde_json::json!({"type": "token_mismatch"}),
        },
    ]
}

fn cbor_type_tag(value: &SealValidation) -> TestResult<String> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes)?;
    let cbor: CborValue = ciborium::de::from_reader(bytes.as_slice())?;
    let CborValue::Map(map) = cbor else {
        return Err(err(format!(
            "SealValidation must encode as a CBOR map, got {cbor:?}"
        )));
    };

    map.iter()
        .find_map(|(key, value)| match (key, value) {
            (CborValue::Text(key), CborValue::Text(value)) if key == "type" => Some(value.clone()),
            _ => None,
        })
        .ok_or_else(|| err("SealValidation CBOR map is missing type tag"))
}

#[test]
fn registry_consistency_display_tokens_are_pinned() {
    for case in cases() {
        assert_eq!(case.value.as_str(), case.display);
        assert_eq!(case.value.to_string(), case.display);
    }
}

#[test]
fn registry_consistency_json_shapes_are_pinned_and_roundtrip() -> TestResult {
    for case in cases() {
        let json = serde_json::to_value(case.value)?;
        assert_eq!(json, case.json);

        let decoded: SealValidation = serde_json::from_value(json)?;
        assert_eq!(decoded, case.value);
    }

    Ok(())
}

#[test]
fn registry_consistency_cbor_tags_are_pinned_and_roundtrip() -> TestResult {
    for case in cases() {
        assert_eq!(cbor_type_tag(&case.value)?, case.display);

        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&case.value, &mut bytes)?;
        let decoded: SealValidation = ciborium::de::from_reader(bytes.as_slice())?;
        assert_eq!(decoded, case.value);
    }

    Ok(())
}

#[test]
fn registry_consistency_rejects_noncanonical_json_tags() {
    for invalid in [
        r#"{"type":"Valid"}"#,
        r#"{"type":"token-mismatch"}"#,
        r#"{"type":"stale","seal_seq":7}"#,
        r#"{"type":"forked"}"#,
    ] {
        assert!(
            serde_json::from_str::<SealValidation>(invalid).is_err(),
            "{invalid}"
        );
    }
}
