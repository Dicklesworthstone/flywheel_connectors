use chrono::{TimeZone, Utc};
use fcp_core::{
    AttestationMaterial, AttestationMetadata, AttestationPredicateType,
    SUPPLY_CHAIN_ATTESTATION_FORMAT, SUPPLY_CHAIN_ATTESTATION_SCHEMA_VERSION,
    SUPPLY_CHAIN_ATTESTATION_SIGNED_FIELDS, SupplyChainAttestation, SupplyChainSignature,
    TrustRootBinding, VerificationReasonCode,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn sample_connector_attestation() -> SupplyChainAttestation {
    SupplyChainAttestation {
        format: SUPPLY_CHAIN_ATTESTATION_FORMAT.to_string(),
        schema_version: SUPPLY_CHAIN_ATTESTATION_SCHEMA_VERSION.to_string(),
        subject_digest: format!("blake3-256:{}", "1".repeat(64)),
        predicate_type: AttestationPredicateType::SlsaProvenanceV1,
        builder_id: "builder://github/actions".to_string(),
        build_type: "https://slsa.dev/container-based-build/v1".to_string(),
        materials: vec![AttestationMaterial {
            uri: "git+https://github.com/flywheel/connectors@refs/tags/v1.2.3".to_string(),
            digest: format!("blake3-256:{}", "2".repeat(64)),
        }],
        metadata: AttestationMetadata {
            build_started_at: Utc.with_ymd_and_hms(2026, 4, 30, 12, 0, 0).unwrap(),
            build_finished_at: Utc.with_ymd_and_hms(2026, 4, 30, 12, 4, 0).unwrap(),
            invocation_id: Some("gh-run-connector-attestation-42".to_string()),
        },
        slsa_level: 3,
        provenance_hash: format!("blake3-256:{}", "3".repeat(64)),
        trust_root: TrustRootBinding {
            root_type: "sigstore".to_string(),
            root_id: "sigstore-public-good".to_string(),
        },
        builder_allowlist: vec!["builder://github/actions".to_string()],
        signature: SupplyChainSignature::new(
            "sigstore-key-1",
            hex::encode([0xa5; 64]),
            SUPPLY_CHAIN_ATTESTATION_SIGNED_FIELDS
                .iter()
                .map(|field| (*field).to_string())
                .collect(),
        ),
    }
}

#[test]
fn connector_attestation_json_shape_and_roundtrip_are_pinned() -> TestResult {
    let attestation = sample_connector_attestation();
    let value = serde_json::to_value(&attestation)?;

    assert_eq!(
        value.get("format"),
        Some(&serde_json::json!(SUPPLY_CHAIN_ATTESTATION_FORMAT))
    );
    assert_eq!(
        value.get("schema_version"),
        Some(&serde_json::json!(SUPPLY_CHAIN_ATTESTATION_SCHEMA_VERSION))
    );
    assert_eq!(
        value.get("predicate_type"),
        Some(&serde_json::json!("https://slsa.dev/provenance/v1"))
    );
    assert_eq!(value.get("slsa_level"), Some(&serde_json::json!(3)));
    assert_eq!(
        value.pointer("/trust_root/root_type"),
        Some(&serde_json::json!("sigstore"))
    );
    assert_eq!(
        value.pointer("/signature/algorithm"),
        Some(&serde_json::json!("ed25519"))
    );

    let decoded: SupplyChainAttestation = serde_json::from_value(value)?;
    assert_eq!(decoded, attestation);
    decoded.validate()?;

    Ok(())
}

#[test]
fn connector_attestation_cbor_roundtrip_preserves_display_fields() -> TestResult {
    let attestation = sample_connector_attestation();
    let mut encoded = Vec::new();
    ciborium::into_writer(&attestation, &mut encoded)?;

    assert_ne!(encoded, [] as [u8; 0]);

    let decoded: SupplyChainAttestation = ciborium::from_reader(encoded.as_slice())?;
    assert_eq!(decoded, attestation);
    assert_eq!(
        decoded.predicate_type,
        AttestationPredicateType::SlsaProvenanceV1
    );
    assert_eq!(decoded.trust_root.root_type, "sigstore");
    assert_eq!(decoded.signature.algorithm, "ed25519");
    decoded.validate()?;

    Ok(())
}

#[test]
fn connector_attestation_display_reason_codes_match_serde_tags() -> TestResult {
    let cases = [
        (
            VerificationReasonCode::AttestationMissing,
            "ATTESTATION_MISSING",
        ),
        (
            VerificationReasonCode::AttestationInvalid,
            "ATTESTATION_INVALID",
        ),
        (
            VerificationReasonCode::SubjectDigestMismatch,
            "SUBJECT_DIGEST_MISMATCH",
        ),
        (
            VerificationReasonCode::SignatureInvalid,
            "SIGNATURE_INVALID",
        ),
    ];

    for (code, tag) in cases {
        assert_eq!(code.to_string(), tag);

        let json = serde_json::to_string(&code)?;
        assert_eq!(json, format!(r#""{tag}""#));
        let from_json: VerificationReasonCode = serde_json::from_str(&json)?;
        assert_eq!(from_json, code);

        let mut cbor = Vec::new();
        ciborium::into_writer(&code, &mut cbor)?;
        let from_cbor: VerificationReasonCode = ciborium::from_reader(cbor.as_slice())?;
        assert_eq!(from_cbor, code);
    }

    Ok(())
}
