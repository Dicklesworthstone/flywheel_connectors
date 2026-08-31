//! Golden artifact snapshots for fcp-registry wire formats.

use fcp_cbor::SchemaId;
use fcp_manifest::AttestationType;
use fcp_prelude::{
    EpochId, NodeId, NodeSignature, ObjectHeader, ObjectId, Provenance, RevocationHead,
    RevocationObject, RevocationScope, SignatureSet, ZoneId,
};
use fcp_registry::{
    ConnectorTarget, ManifestSignatureArtifact, RegistryConnectorDescriptor,
    RegistryTargetDescriptor, RegistryVersionDescriptor, SupplyChainVerificationConfig,
    TufRootMetadata,
};
use semver::Version;
use serde::Serialize;

#[derive(Serialize)]
struct RevocationListSnapshot {
    head: RevocationHead,
    revocations: Vec<RevocationObject>,
}

fn pretty_json<T: Serialize>(value: &T) -> String {
    serde_json::to_string_pretty(value).expect("serialize snapshot payload")
}

fn deterministic_signature_artifact(
    target: ConnectorTarget,
    binary_name: &str,
) -> ManifestSignatureArtifact {
    ManifestSignatureArtifact {
        key_id: "pub1".to_string(),
        verifying_key: "6ee7c3c7f4bb5752ef4994a82d3af7e0d4ce99f64f8d1d8f8f6cf0b28b3d7d4f"
            .to_string(),
        context: "fcp.registry.manifest.v1".to_string(),
        manifest_signing_hash:
            "sha256:9b4b2e6bb4c26f6d7466f4b9ce43d1d9d6f4a0d1fc88d5c1b5cdb9f11ecf7a21".to_string(),
        binary_hash: "sha256:46fbcf3f0f0d3e6f8c0c8060c0b881f3d25b235fc31dd8206dfa81857232ece2"
            .to_string(),
        signature: "base64:Z29sZGVuLXJlZ2lzdHJ5LXNpZ25hdHVyZS1wYXlsb2FkLWRlbW8=".to_string(),
        target,
        binary_name: binary_name.to_string(),
    }
}

fn revocation_header(schema_name: &str, created_at: u64) -> ObjectHeader {
    ObjectHeader {
        encryption_kind: Default::default(),
        schema: SchemaId::new("fcp.core", schema_name, Version::new(1, 0, 0)),
        zone_id: ZoneId::work(),
        created_at,
        provenance: Provenance::new(ZoneId::work()),
        refs: Vec::new(),
        foreign_refs: Vec::new(),
        ttl_secs: None,
        placement: None,
    }
}

#[test]
fn registry_golden_manifest_lookup_response() {
    let target = ConnectorTarget {
        os: "linux".to_string(),
        arch: "amd64".to_string(),
    };
    let descriptor = RegistryConnectorDescriptor {
        connector_id: "fcp.minimal".to_string(),
        latest_version: "0.1.0".to_string(),
        versions: vec![RegistryVersionDescriptor {
            version: "0.1.0".to_string(),
            is_latest: true,
            targets: vec![RegistryTargetDescriptor {
                os: target.os.clone(),
                arch: target.arch.clone(),
                target: target.as_string(),
                manifest_sha256:
                    "sha256:0d9db6b3d66a92e74a6f1f5f4d9687df7a85ceef0f3d8d2b7183762c508d57f9"
                        .to_string(),
                binary_sha256:
                    "sha256:46fbcf3f0f0d3e6f8c0c8060c0b881f3d25b235fc31dd8206dfa81857232ece2"
                        .to_string(),
                manifest_url:
                    "/v1/connectors/fcp.minimal/versions/0.1.0/targets/linux/amd64/manifest"
                        .to_string(),
                binary_url: "/v1/connectors/fcp.minimal/versions/0.1.0/targets/linux/amd64/binary"
                    .to_string(),
                signature_url:
                    "/v1/connectors/fcp.minimal/versions/0.1.0/targets/linux/amd64/signature"
                        .to_string(),
                attestation_url: Some(
                    "/v1/connectors/fcp.minimal/versions/0.1.0/targets/linux/amd64/attestation"
                        .to_string(),
                ),
                signature: deterministic_signature_artifact(target, "registry-golden"),
            }],
        }],
    };

    insta::assert_snapshot!("manifest_lookup_response", pretty_json(&descriptor));
}

#[test]
fn registry_golden_supply_chain_verification_config() {
    let config = SupplyChainVerificationConfig {
        tuf_pinned_root: Some(TufRootMetadata {
            version: 7,
            root_hash: "sha256:root-golden".to_string(),
            expires: 1_750_000_000,
            key_ids: vec!["root-a".to_string(), "root-b".to_string()],
            threshold: 2,
        }),
        trusted_sigstore_identities: vec![
            "https://github.com/flywheel/build/.github/workflows/release.yml@refs/tags/v1.2.3"
                .to_string(),
        ],
        trusted_sigstore_issuers: vec!["https://token.actions.githubusercontent.com".to_string()],
        require_transparency: true,
        require_tuf: true,
        require_sigstore: true,
        require_attestation_types: vec![AttestationType::InToto],
        min_slsa_level: Some(3),
        trusted_builders: vec!["github-actions".to_string()],
        require_attestation_expiry: true,
    };

    insta::assert_snapshot!("supply_chain_verification_config", pretty_json(&config));
}

#[test]
fn registry_golden_signed_artifact_descriptor() {
    let artifact = deterministic_signature_artifact(
        ConnectorTarget {
            os: "linux".to_string(),
            arch: "amd64".to_string(),
        },
        "registry-golden",
    );

    insta::assert_snapshot!("signed_artifact_descriptor", pretty_json(&artifact));
}

#[test]
fn registry_golden_revocation_list_format() {
    let revocation_a = RevocationObject {
        header: revocation_header("RevocationObject", 1_730_000_000),
        revoked: vec![
            ObjectId::from_bytes([0x11; 32]),
            ObjectId::from_bytes([0x22; 32]),
        ],
        scope: RevocationScope::ConnectorBinary,
        reason: "registry bundle superseded by security release".to_string(),
        effective_at: 1_730_000_120,
        expires_at: None,
        signature: [0xAA; 64],
    };
    let revocation_b = RevocationObject {
        header: revocation_header("RevocationObject", 1_730_000_300),
        revoked: vec![ObjectId::from_bytes([0x33; 32])],
        scope: RevocationScope::IssuerKey,
        reason: "publisher key rotated after incident response".to_string(),
        effective_at: 1_730_000_360,
        expires_at: Some(1_830_000_360),
        signature: [0xBB; 64],
    };

    let mut quorum_signatures = SignatureSet::new();
    assert!(quorum_signatures.add(NodeSignature::new(
        NodeId::new("node-a"),
        [0x01; 64],
        1_730_000_500,
    )));
    assert!(quorum_signatures.add(NodeSignature::new(
        NodeId::new("node-b"),
        [0x02; 64],
        1_730_000_501,
    )));

    let list = RevocationListSnapshot {
        head: RevocationHead {
            header: revocation_header("RevocationHead", 1_730_000_600),
            zone_id: ZoneId::work(),
            head_event: ObjectId::from_bytes([0x44; 32]),
            head_seq: 99,
            epoch_id: EpochId::new("epoch-registry-golden"),
            quorum_signatures,
        },
        revocations: vec![revocation_a, revocation_b],
    };

    insta::assert_snapshot!("revocation_list_format", pretty_json(&list));
}
