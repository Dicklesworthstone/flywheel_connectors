//! Integration tests for fcp-registry verification and mirroring.
//!
//! These tests exercise real code paths: Ed25519 key generation/signing,
//! manifest parsing, capability ceiling enforcement, supply chain policy,
//! and object store mirroring without mocks.

use base64::Engine;
use fcp_cbor::MAX_CANONICAL_OBJECT_BYTES;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_manifest::{AttestationType, Base64Bytes, ConnectorManifest};
use fcp_prelude::{
    CapabilityId, DecisionReceiptPolicy, ObjectIdKey, Provenance, ZoneId, ZonePolicyObject,
    ZoneTransportPolicy,
};
use fcp_raptorq::RaptorQConfig;
use fcp_registry::{
    AttestationEvidence, ConnectorBinaryObject, ConnectorBinarySymbolSet, ConnectorBundle,
    ConnectorManifestObject, ConnectorTarget, ReconstructedConnectorBinary, RegistryError,
    RegistryTrustPolicy, RegistryVerificationReport, RegistryVerifier, SupplyChainEvidence,
    SupplyChainVerificationConfig, SupplyChainVerificationError,
};
use fcp_store::{
    MemoryObjectStore, MemoryObjectStoreConfig, MemorySymbolStore, MemorySymbolStoreConfig,
    ObjectStore, ObjectSymbolMeta, ObjectTransmissionInfo, SymbolStore,
};
use semver::Version;

const PLACEHOLDER_HASH: &str =
    "blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000";

// ── helpers ──

fn base_manifest_toml() -> String {
    let raw = include_str!("../../../tests/vectors/manifest/manifest_minimal.toml");
    let unchecked = ConnectorManifest::parse_str_unchecked(raw).expect("manifest");
    let hash = unchecked.compute_interface_hash().expect("interface hash");
    raw.replace(PLACEHOLDER_HASH, &hash.to_string())
}

fn unsigned_manifest_toml(extra: &str) -> String {
    if extra.trim().is_empty() {
        base_manifest_toml()
    } else {
        format!("{}\n{}", base_manifest_toml(), extra)
    }
}

fn sign_manifest(
    manifest_toml: &str,
    signing_key: &Ed25519SigningKey,
    binary_hash: &str,
) -> Base64Bytes {
    // Parse UNCHECKED: this helper signs the still-unsigned manifest, and full
    // validation rejects shapes that only become legal once the `[signatures]`
    // section is appended (e.g. `policy.require_transparency_log = true`
    // demands `signatures.transparency_log_entry`). Signing bytes are computed
    // over the manifest signing view; validation is `verify_bundle`'s job.
    let manifest = ConnectorManifest::parse_str_unchecked(manifest_toml).expect("manifest");
    let signing_bytes = fcp_registry::manifest_signing_bytes(&manifest).expect("signing bytes");
    let message = fcp_registry::signature_message(&signing_bytes, binary_hash);
    let signature =
        signing_key.sign_with_context(fcp_registry::MANIFEST_SIGNATURE_CONTEXT, &message);
    Base64Bytes::try_from(format!(
        "base64:{}",
        base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
    ))
    .expect("base64 sig")
}

fn publisher_sig_toml(kid: &str, sig: &Base64Bytes) -> String {
    format!(
        r#"[signatures]
publisher_threshold = "1-of-1"

[[signatures.publisher_signatures]]
kid = "{kid}"
sig = "{sig}"
"#,
        sig = String::from(sig.clone())
    )
}

fn registry_sig_toml(kid: &str, sig: &Base64Bytes) -> String {
    format!(
        r#"[signatures.registry_signature]
kid = "{kid}"
sig = "{sig}"
"#,
        sig = String::from(sig.clone())
    )
}

fn test_target() -> ConnectorTarget {
    ConnectorTarget {
        os: "linux".to_string(),
        arch: "amd64".to_string(),
    }
}

fn test_binary() -> Vec<u8> {
    b"fake-binary-payload-for-tests".to_vec()
}

fn patterned_binary(size: usize) -> Vec<u8> {
    (0..size)
        .map(|idx| u8::try_from(idx % 251).expect("pattern byte fits u8"))
        .collect()
}

fn binary_hash(binary: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(binary);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn signed_bundle(kid: &str) -> (ConnectorBundle, RegistryTrustPolicy) {
    signed_bundle_with_binary(kid, test_binary())
}

fn signed_bundle_with_binary(kid: &str, binary: Vec<u8>) -> (ConnectorBundle, RegistryTrustPolicy) {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let b_hash = binary_hash(&binary);
    let unsigned = unsigned_manifest_toml("");
    let sig = sign_manifest(&unsigned, &signing_key, &b_hash);
    let sig_section = publisher_sig_toml(kid, &sig);
    let manifest_toml = format!("{unsigned}\n{sig_section}");

    let bundle = ConnectorBundle {
        manifest_toml,
        binary,
        target: test_target(),
    };

    let mut trust = RegistryTrustPolicy::default();
    trust.publisher_keys.insert(kid.to_string(), verifying_key);

    (bundle, trust)
}

fn symbol_config() -> RaptorQConfig {
    RaptorQConfig {
        symbol_size: 128,
        repair_ratio_bps: 10_000,
        ..RaptorQConfig::default()
    }
}

fn zone_policy_with_ceiling(caps: &[&str]) -> ZonePolicyObject {
    let zone = ZoneId::work();
    ZonePolicyObject {
        header: fcp_core::ObjectHeader {
            schema: fcp_cbor::SchemaId::new("fcp.test", "ZonePolicyObject", Version::new(1, 0, 0)),
            zone_id: zone.clone(),
            created_at: 1_700_000_000,
            provenance: Provenance::new(zone.clone()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        },
        zone_id: zone,
        principal_allow: vec![],
        principal_deny: vec![],
        connector_allow: vec![],
        connector_deny: vec![],
        capability_allow: vec![],
        capability_deny: vec![],
        capability_ceiling: caps
            .iter()
            .map(|c| CapabilityId::new(c.to_string()).expect("valid cap"))
            .collect(),
        transport_policy: ZoneTransportPolicy::default(),
        decision_receipts: DecisionReceiptPolicy::default(),
        usage_budget: None,
        requires_posture: None,
    }
}

// ── verify_bundle: signature validation ──

#[test]
fn verify_bundle_valid_publisher_signature() {
    let (bundle, trust) = signed_bundle("pub1");
    let verifier = RegistryVerifier::new(trust);

    let result = verifier.verify_bundle(&bundle, None, None, None);
    assert!(
        result.is_ok(),
        "valid publisher sig should pass: {result:?}"
    );

    let verified = result.unwrap();
    assert_eq!(verified.manifest.connector.id.to_string(), "fcp.minimal");
    assert!(verified.binary_hash.starts_with("sha256:"));
    assert!(verified.manifest_hash.starts_with("sha256:"));
}

#[test]
fn verify_bundle_wrong_key_fails() {
    let (bundle, mut trust) = signed_bundle("pub1");
    // Replace with different key
    let wrong_key = Ed25519SigningKey::generate().verifying_key();
    trust.publisher_keys.insert("pub1".to_string(), wrong_key);

    let verifier = RegistryVerifier::new(trust);
    let result = verifier.verify_bundle(&bundle, None, None, None);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("signature verification failed") || err.contains("threshold unmet"),
        "expected sig invalid or threshold unmet: {err}"
    );
}

#[test]
fn verify_bundle_unknown_kid_fails() {
    let (bundle, mut trust) = signed_bundle("pub1");
    // Remove the key so kid is unknown
    trust.publisher_keys.clear();

    let verifier = RegistryVerifier::new(trust);
    let result = verifier.verify_bundle(&bundle, None, None, None);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("no trusted key for kid") || err.contains("threshold unmet"),
        "expected unknown kid or threshold unmet: {err}"
    );
}

#[test]
fn verify_bundle_missing_signatures_fails() {
    let unsigned = unsigned_manifest_toml("");
    let bundle = ConnectorBundle {
        manifest_toml: unsigned,
        binary: test_binary(),
        target: test_target(),
    };
    let trust = RegistryTrustPolicy::default();
    let verifier = RegistryVerifier::new(trust);

    let result = verifier.verify_bundle(&bundle, None, None, None);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("signature section missing"),
        "expected missing sigs: {err}"
    );
}

#[test]
fn verify_bundle_empty_publisher_list_with_threshold_fails_threshold_check() {
    let manifest_toml = format!(
        "{}\n[signatures]\npublisher_threshold = \"1-of-1\"\n",
        unsigned_manifest_toml("")
    );
    let bundle = ConnectorBundle {
        manifest_toml,
        binary: test_binary(),
        target: test_target(),
    };
    let verifier = RegistryVerifier::new(RegistryTrustPolicy::default());

    let result = verifier.verify_bundle(&bundle, None, None, None);
    assert!(
        result.is_err(),
        "expected failure for empty publisher list, got {result:?}"
    );
}

#[test]
fn verify_bundle_empty_signature_section_fails_no_trusted_signature() {
    let manifest_toml = format!("{}\n[signatures]\n", unsigned_manifest_toml(""));
    let bundle = ConnectorBundle {
        manifest_toml,
        binary: test_binary(),
        target: test_target(),
    };
    let verifier = RegistryVerifier::new(RegistryTrustPolicy::default());

    let result = verifier.verify_bundle(&bundle, None, None, None);
    assert!(
        matches!(result, Err(RegistryError::NoTrustedSignature)),
        "expected no trusted signature failure, got {result:?}"
    );
}

#[test]
fn verify_bundle_tampered_binary_fails() {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let binary = test_binary();
    let b_hash = binary_hash(&binary);
    let unsigned = unsigned_manifest_toml("");
    let sig = sign_manifest(&unsigned, &signing_key, &b_hash);
    let sig_section = publisher_sig_toml("pub1", &sig);
    let manifest_toml = format!("{unsigned}\n{sig_section}");

    // Tamper with binary
    let tampered = b"tampered-binary-content".to_vec();

    let bundle = ConnectorBundle {
        manifest_toml,
        binary: tampered,
        target: test_target(),
    };

    let mut trust = RegistryTrustPolicy::default();
    trust
        .publisher_keys
        .insert("pub1".to_string(), verifying_key);

    let verifier = RegistryVerifier::new(trust);
    let result = verifier.verify_bundle(&bundle, None, None, None);
    assert!(
        matches!(
            result,
            Err(RegistryError::PublisherThresholdUnmet {
                required: 1,
                valid: 0,
            })
        ),
        "tampered binary should fail structured threshold validation: {result:?}"
    );
}

// ── verify_bundle: registry signature ──

#[test]
fn verify_bundle_registry_signature_required_and_present() {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let binary = test_binary();
    let b_hash = binary_hash(&binary);
    let unsigned = unsigned_manifest_toml("");
    let sig = sign_manifest(&unsigned, &signing_key, &b_hash);
    let pub_section = publisher_sig_toml("pub1", &sig);
    let reg_sig = sign_manifest(&unsigned, &signing_key, &b_hash);
    let reg_section = registry_sig_toml("reg1", &reg_sig);
    let manifest_toml = format!("{unsigned}\n{pub_section}\n{reg_section}");

    let bundle = ConnectorBundle {
        manifest_toml,
        binary,
        target: test_target(),
    };

    let mut trust = RegistryTrustPolicy {
        require_registry_signature: true,
        ..Default::default()
    };
    trust
        .publisher_keys
        .insert("pub1".to_string(), verifying_key.clone());
    trust
        .registry_keys
        .insert("reg1".to_string(), verifying_key);

    let verifier = RegistryVerifier::new(trust);
    let result = verifier.verify_bundle(&bundle, None, None, None);
    assert!(
        result.is_ok(),
        "registry sig present+valid should pass: {result:?}"
    );
}

#[test]
fn verify_bundle_registry_signature_required_but_missing() {
    let (bundle, mut trust) = signed_bundle("pub1");
    trust.require_registry_signature = true;

    let verifier = RegistryVerifier::new(trust);
    let result = verifier.verify_bundle(&bundle, None, None, None);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("registry signature required"),
        "expected registry sig required: {err}"
    );
}

// ── verify_bundle: target matching ──

#[test]
fn verify_bundle_target_mismatch_fails() {
    let (bundle, trust) = signed_bundle("pub1");
    let wrong_target = ConnectorTarget {
        os: "windows".to_string(),
        arch: "arm64".to_string(),
    };
    let expected_target = wrong_target.as_string();
    let actual_target = test_target().as_string();

    let verifier = RegistryVerifier::new(trust);
    let result = verifier.verify_bundle(&bundle, None, None, Some(&wrong_target));
    assert!(
        matches!(
            result,
            Err(RegistryError::TargetMismatch {
                ref expected,
                ref found,
            })
                if expected == &expected_target && found == &actual_target
        ),
        "expected structured target mismatch: {result:?}"
    );
}

#[test]
fn verify_bundle_target_match_passes() {
    let (bundle, trust) = signed_bundle("pub1");
    let expected = test_target();

    let verifier = RegistryVerifier::new(trust);
    let result = verifier.verify_bundle(&bundle, None, None, Some(&expected));
    assert!(result.is_ok(), "matching target should pass: {result:?}");
}

#[test]
fn verify_bundle_no_expected_target_passes() {
    let (bundle, trust) = signed_bundle("pub1");
    let verifier = RegistryVerifier::new(trust);
    let result = verifier.verify_bundle(&bundle, None, None, None);
    assert!(result.is_ok(), "no expected target should pass: {result:?}");
}

// ── verify_bundle: capability ceiling ──

#[test]
fn verify_bundle_capability_ceiling_allows_matching_caps() {
    let (bundle, trust) = signed_bundle("pub1");
    // The minimal manifest requires "network.dns" and uses "minimal.op"
    let policy = zone_policy_with_ceiling(&["network.dns", "minimal.op"]);

    let verifier = RegistryVerifier::new(trust);
    let result = verifier.verify_bundle(&bundle, Some(&policy), None, None);
    assert!(
        result.is_ok(),
        "caps within ceiling should pass: {result:?}"
    );
}

#[test]
fn verify_bundle_capability_ceiling_violation() {
    let (bundle, trust) = signed_bundle("pub1");
    // Ceiling only includes "network.dns" but not "minimal.op"
    let policy = zone_policy_with_ceiling(&["network.dns"]);

    let verifier = RegistryVerifier::new(trust);
    let result = verifier.verify_bundle(&bundle, Some(&policy), None, None);
    assert!(
        matches!(
            result,
            Err(RegistryError::CapabilityCeilingViolation {
                ref capability,
            })
                if capability == "minimal.op"
        ),
        "expected structured capability ceiling violation: {result:?}"
    );
}

#[test]
fn verify_bundle_empty_capability_ceiling_passes() {
    let (bundle, trust) = signed_bundle("pub1");
    // Empty ceiling means no restriction
    let policy = zone_policy_with_ceiling(&[]);

    let verifier = RegistryVerifier::new(trust);
    let result = verifier.verify_bundle(&bundle, Some(&policy), None, None);
    assert!(result.is_ok(), "empty ceiling should pass: {result:?}");
}

#[test]
fn verify_bundle_no_zone_policy_passes() {
    let (bundle, trust) = signed_bundle("pub1");
    let verifier = RegistryVerifier::new(trust);
    let result = verifier.verify_bundle(&bundle, None, None, None);
    assert!(result.is_ok(), "no zone policy should pass: {result:?}");
}

// ── verify_bundle: supply chain policy enforcement ──

#[test]
fn verify_bundle_transparency_log_required_but_missing() {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let binary = test_binary();
    let b_hash = binary_hash(&binary);

    let policy_section = r#"
[policy]
require_transparency_log = true
require_attestation_types = []
trusted_builders = []
"#;
    let unsigned = unsigned_manifest_toml(policy_section);
    let sig = sign_manifest(&unsigned, &signing_key, &b_hash);
    let sig_section = publisher_sig_toml("pub1", &sig);
    let manifest_toml = format!("{unsigned}\n{sig_section}");

    let bundle = ConnectorBundle {
        manifest_toml,
        binary,
        target: test_target(),
    };

    let mut trust = RegistryTrustPolicy::default();
    trust
        .publisher_keys
        .insert("pub1".to_string(), verifying_key);

    let verifier = RegistryVerifier::new(trust);
    let result = verifier.verify_bundle(&bundle, None, None, None);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    // Fail-closed on the missing transparency-log entry. Manifest validation
    // now refuses this shape before the registry's own
    // `RegistryError::TransparencyLogMissing` gate is reached, so assert on the
    // subject of the refusal rather than on which layer produced it.
    assert!(
        err.contains("transparency"),
        "expected transparency log error: {err}"
    );
}

#[test]
fn verify_bundle_slsa_level_insufficient() {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let binary = test_binary();
    let b_hash = binary_hash(&binary);

    let policy_section = r#"
[policy]
require_transparency_log = false
require_attestation_types = []
trusted_builders = []
min_slsa_level = 3
"#;
    let unsigned = unsigned_manifest_toml(policy_section);
    let sig = sign_manifest(&unsigned, &signing_key, &b_hash);
    let sig_section = publisher_sig_toml("pub1", &sig);
    let manifest_toml = format!("{unsigned}\n{sig_section}");

    let bundle = ConnectorBundle {
        manifest_toml,
        binary,
        target: test_target(),
    };

    let mut trust = RegistryTrustPolicy::default();
    trust
        .publisher_keys
        .insert("pub1".to_string(), verifying_key);

    // Evidence with SLSA level 1 (below required 3)
    let evidence = SupplyChainEvidence::new().with_attestations(vec![AttestationEvidence {
        attestation_type: AttestationType::InToto,
        slsa_level: Some(1),
        builder_id: None,
        expires_at: None,
    }]);

    let verifier = RegistryVerifier::new(trust);
    let result = verifier.verify_bundle(&bundle, None, Some(&evidence), None);
    assert!(
        matches!(
            result,
            Err(RegistryError::SlsaLevelInsufficient { required: 3 })
        ),
        "expected structured SLSA level error: {result:?}"
    );
}

#[test]
fn verify_bundle_untrusted_builder() {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let binary = test_binary();
    let b_hash = binary_hash(&binary);

    let policy_section = r#"
[policy]
require_transparency_log = false
require_attestation_types = []
trusted_builders = ["github-actions"]
"#;
    let unsigned = unsigned_manifest_toml(policy_section);
    let sig = sign_manifest(&unsigned, &signing_key, &b_hash);
    let sig_section = publisher_sig_toml("pub1", &sig);
    let manifest_toml = format!("{unsigned}\n{sig_section}");

    let bundle = ConnectorBundle {
        manifest_toml,
        binary,
        target: test_target(),
    };

    let mut trust = RegistryTrustPolicy::default();
    trust
        .publisher_keys
        .insert("pub1".to_string(), verifying_key);

    let evidence = SupplyChainEvidence::new().with_attestations(vec![AttestationEvidence {
        attestation_type: AttestationType::InToto,
        slsa_level: None,
        builder_id: Some("evil-builder".to_string()),
        expires_at: None,
    }]);

    let verifier = RegistryVerifier::new(trust);
    let result = verifier.verify_bundle(&bundle, None, Some(&evidence), None);
    assert!(
        matches!(
            result,
            Err(RegistryError::UntrustedBuilder { ref builder }) if builder == "evil-builder"
        ),
        "expected structured untrusted builder error: {result:?}"
    );
}

#[test]
fn verify_bundle_expired_attestation_fails() {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let binary = test_binary();
    let b_hash = binary_hash(&binary);

    let policy_section = r#"
[policy]
require_transparency_log = false
require_attestation_types = ["in-toto"]
"#;
    let unsigned = unsigned_manifest_toml(policy_section);
    let sig = sign_manifest(&unsigned, &signing_key, &b_hash);
    let sig_section = publisher_sig_toml("pub1", &sig);
    let manifest_toml = format!("{unsigned}\n{sig_section}");

    let bundle = ConnectorBundle {
        manifest_toml,
        binary,
        target: test_target(),
    };

    let mut trust = RegistryTrustPolicy::default();
    trust
        .publisher_keys
        .insert("pub1".to_string(), verifying_key);

    let evidence = SupplyChainEvidence::new().with_attestations(vec![AttestationEvidence {
        attestation_type: AttestationType::InToto,
        slsa_level: Some(3),
        builder_id: Some("trusted-builder".to_string()),
        expires_at: Some(0),
    }]);

    let verifier = RegistryVerifier::new(trust);
    let result = verifier.verify_bundle(&bundle, None, Some(&evidence), None);
    assert!(
        matches!(
            result,
            Err(RegistryError::AttestationExpired {
                ref attestation,
                expired_at: 0,
            }) if attestation == "in-toto"
        ),
        "expected structured attestation expiry error: {result:?}"
    );
}

// ── signature_message determinism ──

#[test]
fn signature_message_deterministic() {
    let signing_bytes = b"test-signing-bytes";
    let binary_hash = "sha256:abcdef";
    let msg1 = fcp_registry::signature_message(signing_bytes, binary_hash);
    let msg2 = fcp_registry::signature_message(signing_bytes, binary_hash);
    assert_eq!(msg1, msg2, "signature_message must be deterministic");
}

#[test]
fn signature_message_different_inputs_differ() {
    let msg1 = fcp_registry::signature_message(b"aaa", "sha256:111");
    let msg2 = fcp_registry::signature_message(b"bbb", "sha256:222");
    assert_ne!(msg1, msg2);
}

#[test]
fn signature_message_empty_inputs() {
    let msg = fcp_registry::signature_message(b"", "");
    // Two u64 LE length prefixes (8 bytes each) + zero payload bytes = 16.
    assert_eq!(msg.len(), 16);
    assert_eq!(
        &msg[..8],
        &[0u8; 8],
        "signing_bytes length prefix should be zero"
    );
    assert_eq!(
        &msg[8..16],
        &[0u8; 8],
        "binary_hash length prefix should be zero"
    );
}

// ── manifest_signing_bytes ──

#[test]
fn manifest_signing_bytes_excludes_signatures() {
    let signing_key = Ed25519SigningKey::generate();
    let binary = test_binary();
    let b_hash = binary_hash(&binary);
    let unsigned = unsigned_manifest_toml("");
    let sig = sign_manifest(&unsigned, &signing_key, &b_hash);
    let sig_section = publisher_sig_toml("pub1", &sig);
    let manifest_toml = format!("{unsigned}\n{sig_section}");

    let manifest_with_sig = ConnectorManifest::parse_str(&manifest_toml).expect("parse");
    let manifest_without_sig = ConnectorManifest::parse_str(&unsigned).expect("parse");

    let bytes_with = fcp_registry::manifest_signing_bytes(&manifest_with_sig).expect("with");
    let bytes_without =
        fcp_registry::manifest_signing_bytes(&manifest_without_sig).expect("without");

    assert_eq!(
        bytes_with, bytes_without,
        "signing bytes must be identical regardless of signatures section"
    );
}

#[test]
fn manifest_signing_bytes_deterministic() {
    let manifest = ConnectorManifest::parse_str(&unsigned_manifest_toml("")).expect("parse");
    let bytes1 = fcp_registry::manifest_signing_bytes(&manifest).expect("bytes1");
    let bytes2 = fcp_registry::manifest_signing_bytes(&manifest).expect("bytes2");
    assert_eq!(bytes1, bytes2, "signing bytes must be deterministic");
}

// ── ConnectorTarget ──

#[test]
fn connector_target_from_env() {
    let target = ConnectorTarget::from_env();
    assert!(!target.os.is_empty());
    assert!(!target.arch.is_empty());
}

#[test]
fn connector_target_as_string() {
    let target = ConnectorTarget {
        os: "linux".to_string(),
        arch: "amd64".to_string(),
    };
    assert_eq!(target.as_string(), "linux-amd64");
}

#[test]
fn connector_target_equality() {
    let a = ConnectorTarget {
        os: "linux".to_string(),
        arch: "amd64".to_string(),
    };
    let b = a.clone();
    assert_eq!(a, b);

    let c = ConnectorTarget {
        os: "macos".to_string(),
        arch: "arm64".to_string(),
    };
    assert_ne!(a, c);
}

#[test]
fn connector_target_serde_roundtrip() {
    let target = test_target();
    let json = serde_json::to_string(&target).expect("serialize");
    let deserialized: ConnectorTarget = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(target, deserialized);
}

// ── VerifiedConnectorBundle::report ──

#[test]
fn verified_bundle_report_fields() {
    let (bundle, trust) = signed_bundle("pub1");
    let verifier = RegistryVerifier::new(trust);
    let verified = verifier
        .verify_bundle(&bundle, None, None, None)
        .expect("verify");

    let report = verified.report("success");
    assert_eq!(report.connector_id, "fcp.minimal");
    assert_eq!(report.outcome, "success");
    assert!(report.manifest_hash.starts_with("sha256:"));
    assert!(report.binary_hash.starts_with("sha256:"));
    assert_eq!(report.target, test_target());
    assert!(report.verified_at > 0);
}

#[test]
fn verified_bundle_report_serde_roundtrip() {
    let (bundle, trust) = signed_bundle("pub1");
    let verifier = RegistryVerifier::new(trust);
    let verified = verifier
        .verify_bundle(&bundle, None, None, None)
        .expect("verify");

    let report = verified.report("verified");
    let json = serde_json::to_string(&report).expect("serialize");
    let deserialized: fcp_registry::RegistryVerificationReport =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(deserialized.connector_id, report.connector_id);
    assert_eq!(deserialized.outcome, report.outcome);
}

// ── mirror_bundle ──

#[fcp_async_core::runtime::test]
async fn mirror_bundle_stores_two_objects() {
    let (bundle, trust) = signed_bundle("pub1");
    let verifier = RegistryVerifier::new(trust);
    let verified = verifier
        .verify_bundle(&bundle, None, None, None)
        .expect("verify");

    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    let zone = ZoneId::work();
    let object_id_key = ObjectIdKey::from_bytes([1u8; 32]);

    let result = verifier
        .mirror_bundle(&verified, &bundle, zone, &object_id_key, &store)
        .await
        .expect("mirror");

    assert!(result.manifest_hash.starts_with("sha256:"));
    assert!(result.binary_hash.starts_with("sha256:"));
    // Object IDs should be distinct
    assert_ne!(result.manifest_object_id, result.binary_object_id);

    // Objects should be retrievable from store
    let _manifest_obj = store
        .get(&result.manifest_object_id)
        .await
        .expect("manifest should be in store");
    let _binary_obj = store
        .get(&result.binary_object_id)
        .await
        .expect("binary should be in store");
}

#[fcp_async_core::runtime::test]
async fn mirror_bundle_binary_refs_manifest() {
    let (bundle, trust) = signed_bundle("pub1");
    let verifier = RegistryVerifier::new(trust);
    let verified = verifier
        .verify_bundle(&bundle, None, None, None)
        .expect("verify");

    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    let zone = ZoneId::work();
    let object_id_key = ObjectIdKey::from_bytes([1u8; 32]);

    let result = verifier
        .mirror_bundle(&verified, &bundle, zone, &object_id_key, &store)
        .await
        .expect("mirror");

    let binary_obj = store
        .get(&result.binary_object_id)
        .await
        .expect("binary present");

    // Binary object should reference manifest
    assert!(
        binary_obj.header.refs.contains(&result.manifest_object_id),
        "binary should ref manifest"
    );
}

#[fcp_async_core::runtime::test]
async fn test_registry_uses_canonical_schemas() {
    let (bundle, trust) = signed_bundle("pub1");
    let verifier = RegistryVerifier::new(trust);
    let verified = verifier
        .verify_bundle(&bundle, None, None, None)
        .expect("verify");

    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    let symbol_store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
    let zone = ZoneId::work();
    let object_id_key = ObjectIdKey::from_bytes([1u8; 32]);

    let mirror = verifier
        .mirror_bundle(&verified, &bundle, zone.clone(), &object_id_key, &store)
        .await
        .expect("mirror");
    let symbol_result = verifier
        .mirror_bundle_symbols(
            &verified,
            &bundle,
            &mirror,
            zone,
            &object_id_key,
            &store,
            &symbol_store,
            &symbol_config(),
            Some(17),
        )
        .await
        .expect("mirror symbols");

    let manifest = store
        .get(&mirror.manifest_object_id)
        .await
        .expect("manifest");
    let binary = store.get(&mirror.binary_object_id).await.expect("binary");
    let descriptor = store
        .get(&symbol_result.descriptor_object_id)
        .await
        .expect("descriptor");

    assert_eq!(manifest.header.schema, ConnectorManifestObject::schema());
    assert_eq!(binary.header.schema, ConnectorBinaryObject::schema());
    assert_eq!(descriptor.header.schema, ConnectorBinarySymbolSet::schema());
    assert_eq!(manifest.header.schema.namespace, "fcp.core");
    assert_eq!(binary.header.schema.namespace, "fcp.core");
    assert_eq!(descriptor.header.schema.namespace, "fcp.core");
}

#[fcp_async_core::runtime::test]
async fn mirror_bundle_deterministic_hashes() {
    let (bundle, trust) = signed_bundle("pub1");
    let verifier = RegistryVerifier::new(trust.clone());
    let verified = verifier
        .verify_bundle(&bundle, None, None, None)
        .expect("verify");

    let store1 = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    let store2 = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    let zone = ZoneId::work();
    let key = ObjectIdKey::from_bytes([1u8; 32]);

    let r1 = verifier
        .mirror_bundle(&verified, &bundle, zone.clone(), &key, &store1)
        .await
        .expect("mirror1");
    let r2 = verifier
        .mirror_bundle(&verified, &bundle, zone, &key, &store2)
        .await
        .expect("mirror2");

    assert_eq!(r1.manifest_hash, r2.manifest_hash);
    assert_eq!(r1.binary_hash, r2.binary_hash);
    assert_eq!(r1.manifest_object_id, r2.manifest_object_id);
    assert_eq!(r1.binary_object_id, r2.binary_object_id);
}

// ── full pipeline: verify + mirror ──

#[fcp_async_core::runtime::test]
async fn full_pipeline_verify_and_mirror() {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let binary = test_binary();
    let b_hash = binary_hash(&binary);
    let unsigned = unsigned_manifest_toml("");
    let sig = sign_manifest(&unsigned, &signing_key, &b_hash);
    let sig_section = publisher_sig_toml("pub1", &sig);
    let manifest_toml = format!("{unsigned}\n{sig_section}");

    let bundle = ConnectorBundle {
        manifest_toml,
        binary,
        target: test_target(),
    };

    let mut trust = RegistryTrustPolicy::default();
    trust
        .publisher_keys
        .insert("pub1".to_string(), verifying_key);

    let expected_target = test_target();
    let zone_policy = zone_policy_with_ceiling(&["network.dns", "minimal.op"]);

    let verifier = RegistryVerifier::new(trust);
    let verified = verifier
        .verify_bundle(&bundle, Some(&zone_policy), None, Some(&expected_target))
        .expect("verify");

    assert_eq!(verified.manifest.connector.id.to_string(), "fcp.minimal");

    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    let zone = ZoneId::work();
    let key = ObjectIdKey::from_bytes([1u8; 32]);

    let result = verifier
        .mirror_bundle(&verified, &bundle, zone, &key, &store)
        .await
        .expect("mirror");

    let report = verified.report("verified");
    assert_eq!(report.binary_hash, result.binary_hash);
    assert_eq!(report.manifest_hash, result.manifest_hash);
}

#[fcp_async_core::runtime::test]
async fn full_pipeline_denied_by_ceiling_never_mirrors() {
    let (bundle, trust) = signed_bundle("pub1");
    // Ceiling missing "minimal.op"
    let policy = zone_policy_with_ceiling(&["network.dns"]);

    let verifier = RegistryVerifier::new(trust);
    let result = verifier.verify_bundle(&bundle, Some(&policy), None, None);
    assert!(result.is_err(), "should be denied by ceiling");

    // No mirror should happen since verify failed
}

// ── mirror_bundle_symbols / reconstruct_binary_from_symbols ──

#[fcp_async_core::runtime::test]
async fn mirror_bundle_symbols_stores_descriptor_and_symbols() {
    let large_binary = patterned_binary(4096);
    let (bundle, trust) = signed_bundle_with_binary("pub1", large_binary);
    let verifier = RegistryVerifier::new(trust);
    let verified = verifier
        .verify_bundle(&bundle, None, None, None)
        .expect("verify");

    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    let symbol_store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
    let zone = ZoneId::work();
    let object_id_key = ObjectIdKey::from_bytes([1u8; 32]);

    let mirror = verifier
        .mirror_bundle(&verified, &bundle, zone.clone(), &object_id_key, &store)
        .await
        .expect("mirror");
    let result = verifier
        .mirror_bundle_symbols(
            &verified,
            &bundle,
            &mirror,
            zone,
            &object_id_key,
            &store,
            &symbol_store,
            &symbol_config(),
            Some(7),
        )
        .await
        .expect("mirror symbols");

    let descriptor = verifier
        .load_symbol_descriptor(&result.descriptor_object_id, &store)
        .await
        .expect("load descriptor");

    assert_eq!(descriptor.binary_object_id, mirror.binary_object_id);
    assert_eq!(descriptor.manifest_object_id, mirror.manifest_object_id);
    assert_eq!(descriptor.source_symbols, result.source_symbols);
    assert_eq!(descriptor.total_symbols, result.total_symbols);
    assert!(descriptor.encoded_body_hash.starts_with("sha256:"));

    let meta = symbol_store
        .get_object_meta(&mirror.binary_object_id)
        .await
        .expect("symbol meta");
    assert_eq!(meta.object_id, mirror.binary_object_id);
    assert_eq!(meta.source_symbols, result.source_symbols);
    assert_eq!(descriptor.oti.payload_hash, meta.oti.payload_hash);
    assert_eq!(
        symbol_store.symbol_count(&mirror.binary_object_id).await,
        result.total_symbols
    );
    assert!(symbol_store.can_reconstruct(&mirror.binary_object_id).await);
}

#[fcp_async_core::runtime::test]
async fn reconstruct_binary_from_symbols_roundtrips_without_binary_object() {
    let large_binary = patterned_binary(6144);
    let (bundle, trust) = signed_bundle_with_binary("pub1", large_binary.clone());
    let verifier = RegistryVerifier::new(trust);
    let verified = verifier
        .verify_bundle(&bundle, None, None, None)
        .expect("verify");

    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    let symbol_store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
    let zone = ZoneId::work();
    let object_id_key = ObjectIdKey::from_bytes([1u8; 32]);

    let mirror = verifier
        .mirror_bundle(&verified, &bundle, zone.clone(), &object_id_key, &store)
        .await
        .expect("mirror");
    let symbol_result = verifier
        .mirror_bundle_symbols(
            &verified,
            &bundle,
            &mirror,
            zone,
            &object_id_key,
            &store,
            &symbol_store,
            &symbol_config(),
            Some(9),
        )
        .await
        .expect("mirror symbols");

    // Simulate peer-side recovery where only descriptor + symbols remain.
    store
        .delete(&mirror.binary_object_id)
        .await
        .expect("delete binary object");

    let descriptor = verifier
        .load_symbol_descriptor(&symbol_result.descriptor_object_id, &store)
        .await
        .expect("load descriptor");
    let reconstructed = verifier
        .reconstruct_binary_from_symbols(&descriptor, &symbol_store, &symbol_config())
        .await
        .expect("reconstruct");

    assert_eq!(
        reconstructed,
        ReconstructedConnectorBinary {
            manifest_object_id: mirror.manifest_object_id,
            binary_object_id: mirror.binary_object_id,
            target: bundle.target.clone(),
            binary_hash: verified.binary_hash.clone(),
            binary: large_binary,
        }
    );
}

#[fcp_async_core::runtime::test]
async fn reconstruct_binary_from_symbol_subset_uses_repairs() {
    let large_binary = patterned_binary(8192);
    let (bundle, trust) = signed_bundle_with_binary("pub1", large_binary.clone());
    let verifier = RegistryVerifier::new(trust);
    let verified = verifier
        .verify_bundle(&bundle, None, None, None)
        .expect("verify");

    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    let full_symbol_store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
    let subset_symbol_store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
    let zone = ZoneId::work();
    let object_id_key = ObjectIdKey::from_bytes([1u8; 32]);
    let config = symbol_config();

    let mirror = verifier
        .mirror_bundle(&verified, &bundle, zone.clone(), &object_id_key, &store)
        .await
        .expect("mirror");
    let symbol_result = verifier
        .mirror_bundle_symbols(
            &verified,
            &bundle,
            &mirror,
            zone.clone(),
            &object_id_key,
            &store,
            &full_symbol_store,
            &config,
            Some(11),
        )
        .await
        .expect("mirror symbols");
    let descriptor = verifier
        .load_symbol_descriptor(&symbol_result.descriptor_object_id, &store)
        .await
        .expect("load descriptor");

    subset_symbol_store
        .put_object_meta(ObjectSymbolMeta {
            object_id: descriptor.binary_object_id,
            zone_id: zone,
            oti: ObjectTransmissionInfo {
                transfer_length: descriptor.oti.transfer_length,
                symbol_size: descriptor.oti.symbol_size,
                source_blocks: descriptor.oti.source_blocks,
                sub_blocks: descriptor.oti.sub_blocks,
                alignment: descriptor.oti.alignment,
                payload_hash: descriptor.oti.payload_hash,
            },
            source_symbols: descriptor.source_symbols,
            first_symbol_at: descriptor.mirrored_at,
        })
        .await
        .expect("subset meta");

    let mut symbols = full_symbol_store
        .get_all_symbols(&descriptor.binary_object_id)
        .await;
    symbols.sort_by_key(|symbol| symbol.meta.esi);
    let keep_count = usize::try_from(descriptor.source_symbols)
        .expect("source symbols fit usize")
        .saturating_add(3)
        .min(symbols.len());
    for symbol in symbols.into_iter().skip(2).take(keep_count) {
        subset_symbol_store
            .put_symbol(symbol)
            .await
            .expect("subset symbol");
    }

    let reconstructed = verifier
        .reconstruct_binary_from_symbols(&descriptor, &subset_symbol_store, &config)
        .await
        .expect("subset reconstruct");
    assert_eq!(reconstructed.binary, large_binary);
}

#[fcp_async_core::runtime::test]
async fn reconstruct_binary_from_symbols_rejects_hash_mismatch() {
    let large_binary = patterned_binary(4096);
    let (bundle, trust) = signed_bundle_with_binary("pub1", large_binary);
    let verifier = RegistryVerifier::new(trust);
    let verified = verifier
        .verify_bundle(&bundle, None, None, None)
        .expect("verify");

    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    let symbol_store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
    let zone = ZoneId::work();
    let object_id_key = ObjectIdKey::from_bytes([1u8; 32]);

    let mirror = verifier
        .mirror_bundle(&verified, &bundle, zone.clone(), &object_id_key, &store)
        .await
        .expect("mirror");
    let symbol_result = verifier
        .mirror_bundle_symbols(
            &verified,
            &bundle,
            &mirror,
            zone,
            &object_id_key,
            &store,
            &symbol_store,
            &symbol_config(),
            Some(13),
        )
        .await
        .expect("mirror symbols");
    let mut descriptor = verifier
        .load_symbol_descriptor(&symbol_result.descriptor_object_id, &store)
        .await
        .expect("load descriptor");
    descriptor.binary_hash = "sha256:deadbeef".to_string();

    let err = verifier
        .reconstruct_binary_from_symbols(&descriptor, &symbol_store, &symbol_config())
        .await
        .expect_err("hash mismatch should fail");
    assert!(matches!(
        err,
        RegistryError::ReconstructedBinaryHashMismatch { .. }
    ));
}

#[fcp_async_core::runtime::test]
async fn reconstruct_binary_from_symbols_rejects_absurd_transfer_length_before_fetch() {
    let large_binary = patterned_binary(4096);
    let (bundle, trust) = signed_bundle_with_binary("pub1", large_binary);
    let verifier = RegistryVerifier::new(trust);
    let verified = verifier
        .verify_bundle(&bundle, None, None, None)
        .expect("verify");

    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    let symbol_store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
    let zone = ZoneId::work();
    let object_id_key = ObjectIdKey::from_bytes([1u8; 32]);

    let mirror = verifier
        .mirror_bundle(&verified, &bundle, zone.clone(), &object_id_key, &store)
        .await
        .expect("mirror");
    let symbol_result = verifier
        .mirror_bundle_symbols(
            &verified,
            &bundle,
            &mirror,
            zone,
            &object_id_key,
            &store,
            &symbol_store,
            &symbol_config(),
            Some(14),
        )
        .await
        .expect("mirror symbols");
    let mut descriptor = verifier
        .load_symbol_descriptor(&symbol_result.descriptor_object_id, &store)
        .await
        .expect("load descriptor");
    descriptor.oti.transfer_length = u64::try_from(MAX_CANONICAL_OBJECT_BYTES)
        .expect("canonical limit fits u64")
        .saturating_add(1);

    let err = verifier
        .reconstruct_binary_from_symbols(&descriptor, &symbol_store, &symbol_config())
        .await
        .expect_err("oversized reconstructed body should fail");
    assert!(matches!(
        err,
        RegistryError::ReconstructedBodyTooLarge {
            len,
            max: MAX_CANONICAL_OBJECT_BYTES,
        } if len == MAX_CANONICAL_OBJECT_BYTES + 1
    ));
}

#[fcp_async_core::runtime::test]
async fn reconstruct_bundle_from_symbol_descriptor_roundtrips_and_reverifies() {
    let large_binary = patterned_binary(9216);
    let (bundle, trust) = signed_bundle_with_binary("pub1", large_binary.clone());
    let verifier = RegistryVerifier::new(trust);
    let verified = verifier
        .verify_bundle(&bundle, None, None, None)
        .expect("verify");

    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    let symbol_store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
    let zone = ZoneId::work();
    let object_id_key = ObjectIdKey::from_bytes([1u8; 32]);

    let mirror = verifier
        .mirror_bundle(&verified, &bundle, zone.clone(), &object_id_key, &store)
        .await
        .expect("mirror");
    let symbol_result = verifier
        .mirror_bundle_symbols(
            &verified,
            &bundle,
            &mirror,
            zone,
            &object_id_key,
            &store,
            &symbol_store,
            &symbol_config(),
            Some(15),
        )
        .await
        .expect("mirror symbols");

    store
        .delete(&mirror.binary_object_id)
        .await
        .expect("delete binary object");

    let recovered = verifier
        .reconstruct_bundle_from_symbol_descriptor(
            &symbol_result.descriptor_object_id,
            &store,
            &symbol_store,
            &symbol_config(),
        )
        .await
        .expect("recover bundle");

    assert_eq!(recovered.manifest_toml, bundle.manifest_toml);
    assert_eq!(recovered.binary, large_binary);
    assert_eq!(recovered.target, bundle.target);

    let reverified = verifier
        .verify_bundle(&recovered, None, None, None)
        .expect("reverify recovered bundle");
    assert_eq!(reverified.manifest_hash, verified.manifest_hash);
    assert_eq!(reverified.binary_hash, verified.binary_hash);
}

#[fcp_async_core::runtime::test]
async fn reconstruct_bundle_from_symbol_descriptor_rejects_manifest_hash_mismatch() {
    let large_binary = patterned_binary(4096);
    let (bundle, trust) = signed_bundle_with_binary("pub1", large_binary);
    let verifier = RegistryVerifier::new(trust);
    let verified = verifier
        .verify_bundle(&bundle, None, None, None)
        .expect("verify");

    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    let symbol_store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
    let zone = ZoneId::work();
    let object_id_key = ObjectIdKey::from_bytes([1u8; 32]);

    let mirror = verifier
        .mirror_bundle(&verified, &bundle, zone.clone(), &object_id_key, &store)
        .await
        .expect("mirror");
    let symbol_result = verifier
        .mirror_bundle_symbols(
            &verified,
            &bundle,
            &mirror,
            zone,
            &object_id_key,
            &store,
            &symbol_store,
            &symbol_config(),
            Some(17),
        )
        .await
        .expect("mirror symbols");

    let mut manifest_record = store
        .get(&mirror.manifest_object_id)
        .await
        .expect("get manifest");
    let replacement_hash = format!("sha256:{}", "0".repeat(64));
    let original_hash = verified.manifest_hash.as_bytes();
    let replacement_hash_bytes = replacement_hash.as_bytes();
    let position = manifest_record
        .body
        .windows(original_hash.len())
        .position(|window| window == original_hash)
        .expect("manifest hash bytes present");
    manifest_record.body[position..position + original_hash.len()]
        .copy_from_slice(replacement_hash_bytes);

    store
        .delete(&mirror.manifest_object_id)
        .await
        .expect("delete manifest");
    store
        .put(manifest_record)
        .await
        .expect("put tampered manifest");

    let err = verifier
        .reconstruct_bundle_from_symbol_descriptor(
            &symbol_result.descriptor_object_id,
            &store,
            &symbol_store,
            &symbol_config(),
        )
        .await
        .expect_err("tampered manifest hash should fail");
    assert!(matches!(
        err,
        RegistryError::ReconstructedManifestHashMismatch { .. }
    ));
}

// ── RegistryError display ──

#[test]
fn registry_error_display_missing_signatures() {
    let err = RegistryError::MissingSignatures;
    assert_eq!(err.to_string(), "signature section missing from manifest");
}

#[test]
fn registry_error_display_unknown_kid() {
    let err = RegistryError::UnknownKid {
        kid: "abc123".to_string(),
    };
    assert!(err.to_string().contains("abc123"));
}

#[test]
fn registry_error_display_threshold_unmet() {
    let err = RegistryError::PublisherThresholdUnmet {
        required: 3,
        valid: 1,
    };
    let msg = err.to_string();
    assert!(msg.contains("3"));
    assert!(msg.contains("1"));
}

#[test]
fn registry_error_display_no_trusted_signature() {
    let err = RegistryError::NoTrustedSignature;
    assert_eq!(
        err.to_string(),
        "no trusted publisher or registry signature verified"
    );
}

#[test]
fn registry_error_display_capability_violation() {
    let err = RegistryError::CapabilityCeilingViolation {
        capability: "system.exec".to_string(),
    };
    assert!(err.to_string().contains("system.exec"));
}

#[test]
fn registry_error_display_slsa_insufficient() {
    let err = RegistryError::SlsaLevelInsufficient { required: 3 };
    assert!(err.to_string().contains("3"));
}

#[test]
fn registry_error_display_untrusted_builder() {
    let err = RegistryError::UntrustedBuilder {
        builder: "evil-ci".to_string(),
    };
    assert!(err.to_string().contains("evil-ci"));
}

// ── publisher threshold ──

#[test]
fn verify_bundle_publisher_threshold_2_of_3() {
    let key1 = Ed25519SigningKey::generate();
    let key2 = Ed25519SigningKey::generate();
    let key3 = Ed25519SigningKey::generate();

    let binary = test_binary();
    let b_hash = binary_hash(&binary);
    let unsigned = unsigned_manifest_toml("");
    let manifest = ConnectorManifest::parse_str(&unsigned).expect("parse");
    let signing_bytes = fcp_registry::manifest_signing_bytes(&manifest).expect("signing bytes");
    let message = fcp_registry::signature_message(&signing_bytes, &b_hash);

    let sig1 = key1.sign_with_context(fcp_registry::MANIFEST_SIGNATURE_CONTEXT, &message);
    let sig2 = key2.sign_with_context(fcp_registry::MANIFEST_SIGNATURE_CONTEXT, &message);

    let b64_sig1 = Base64Bytes::try_from(format!(
        "base64:{}",
        base64::engine::general_purpose::STANDARD.encode(sig1.to_bytes())
    ))
    .expect("b64");
    let b64_sig2 = Base64Bytes::try_from(format!(
        "base64:{}",
        base64::engine::general_purpose::STANDARD.encode(sig2.to_bytes())
    ))
    .expect("b64");

    let sig_section = format!(
        r#"[signatures]
publisher_threshold = "2-of-3"

[[signatures.publisher_signatures]]
kid = "key1"
sig = "{}"

[[signatures.publisher_signatures]]
kid = "key2"
sig = "{}"
"#,
        String::from(b64_sig1),
        String::from(b64_sig2),
    );
    let manifest_toml = format!("{unsigned}\n{sig_section}");

    let bundle = ConnectorBundle {
        manifest_toml,
        binary,
        target: test_target(),
    };

    let mut trust = RegistryTrustPolicy::default();
    trust
        .publisher_keys
        .insert("key1".to_string(), key1.verifying_key());
    trust
        .publisher_keys
        .insert("key2".to_string(), key2.verifying_key());
    trust
        .publisher_keys
        .insert("key3".to_string(), key3.verifying_key());

    let verifier = RegistryVerifier::new(trust);
    let result = verifier.verify_bundle(&bundle, None, None, None);
    assert!(
        result.is_ok(),
        "2-of-3 with 2 valid sigs should pass: {result:?}"
    );
}

#[test]
fn verify_bundle_publisher_threshold_counts_unique_verifiers() {
    let signing_key = Ed25519SigningKey::generate();

    let binary = test_binary();
    let b_hash = binary_hash(&binary);
    let unsigned = unsigned_manifest_toml("");
    let manifest = ConnectorManifest::parse_str(&unsigned).expect("parse");
    let signing_bytes = fcp_registry::manifest_signing_bytes(&manifest).expect("signing bytes");
    let message = fcp_registry::signature_message(&signing_bytes, &b_hash);
    let signature =
        signing_key.sign_with_context(fcp_registry::MANIFEST_SIGNATURE_CONTEXT, &message);
    let b64_signature = Base64Bytes::try_from(format!(
        "base64:{}",
        base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
    ))
    .expect("b64");

    let sig_section = format!(
        r#"[signatures]
publisher_threshold = "2-of-2"

[[signatures.publisher_signatures]]
kid = "key1"
sig = "{sig}"

[[signatures.publisher_signatures]]
kid = "key2"
sig = "{sig}"
"#,
        sig = String::from(b64_signature),
    );
    let manifest_toml = format!("{unsigned}\n{sig_section}");

    let bundle = ConnectorBundle {
        manifest_toml,
        binary,
        target: test_target(),
    };

    let verifying_key = signing_key.verifying_key();
    let mut trust = RegistryTrustPolicy::default();
    trust
        .publisher_keys
        .insert("key1".to_string(), verifying_key.clone());
    trust
        .publisher_keys
        .insert("key2".to_string(), verifying_key);

    let verifier = RegistryVerifier::new(trust);
    let result = verifier.verify_bundle(&bundle, None, None, None);
    assert!(
        matches!(
            result,
            Err(RegistryError::PublisherThresholdUnmet {
                required: 2,
                valid: 1,
            })
        ),
        "one verifier registered under two kids must not satisfy a 2-of-2 threshold: {result:?}"
    );
}

// ── NoOp verifiers ──

#[fcp_async_core::runtime::test]
async fn noop_transparency_verifier_fails_closed() {
    use fcp_registry::{NoOpTransparencyVerifier, TransparencyLogVerifier};

    let verifier = NoOpTransparencyVerifier;
    let err = verifier
        .verify_entry("sha256:abc", None)
        .await
        .expect_err("noop verify must fail closed");
    assert!(matches!(
        err,
        fcp_registry::SupplyChainVerificationError::NotConfigured
    ));
}

#[fcp_async_core::runtime::test]
async fn noop_tuf_verifier_fails_closed() {
    use fcp_registry::{NoOpTufVerifier, TufRootMetadata, TufVerifier};

    let verifier = NoOpTufVerifier;
    let root = TufRootMetadata {
        version: 1,
        root_hash: String::new(),
        expires: u64::MAX,
        key_ids: vec![],
        threshold: 1,
    };
    let err = verifier
        .verify_target(&root, "some/target")
        .await
        .expect_err("noop verify must fail closed");
    assert!(matches!(
        err,
        fcp_registry::SupplyChainVerificationError::NotConfigured
    ));
}

#[fcp_async_core::runtime::test]
async fn noop_sigstore_verifier_fails_closed() {
    use fcp_registry::{NoOpSigstoreVerifier, SigstoreBundle, SigstoreVerifier};

    let verifier = NoOpSigstoreVerifier;
    let bundle = SigstoreBundle {
        signature: "sig".to_string(),
        certificate: "cert".to_string(),
        rekor_entry: None,
        identity: "test@test.com".to_string(),
        issuer: "https://issuer".to_string(),
    };
    let err = verifier
        .verify_bundle(&bundle, "sha256:artifact", &[], &[])
        .await
        .expect_err("noop verify must fail closed");
    assert!(matches!(
        err,
        fcp_registry::SupplyChainVerificationError::NotConfigured
    ));
}

// ── Mock verifiers ──

#[fcp_async_core::runtime::test]
async fn mock_transparency_verifier_accepts_valid_entry() {
    use fcp_registry::{
        InclusionProof, MockTransparencyVerifier, TransparencyLogEntry, TransparencyLogVerifier,
    };

    let verifier = MockTransparencyVerifier::new();
    let entry = TransparencyLogEntry {
        log_index: 42,
        entry_hash: "sha256:abc".to_string(),
        inclusion_proof: InclusionProof {
            root_hash: "sha256:root".to_string(),
            tree_size: 100,
            hashes: vec![],
            leaf_index: 42,
        },
        signed_entry_timestamp: vec![],
        log_id: "test-log".to_string(),
    };
    verifier.add_valid_entry("sha256:abc".to_string(), entry);
    let result = verifier
        .verify_entry("sha256:abc", None)
        .await
        .expect("mock verify");
    assert!(result.verified());
    assert_eq!(result.log_index(), Some(42));
}

#[fcp_async_core::runtime::test]
async fn mock_transparency_verifier_rejects_mismatched_expected_entry() {
    use fcp_registry::{
        InclusionProof, MockTransparencyVerifier, TransparencyLogEntry, TransparencyLogVerifier,
    };

    let verifier = MockTransparencyVerifier::new();
    let entry = TransparencyLogEntry {
        log_index: 42,
        entry_hash: "sha256:abc".to_string(),
        inclusion_proof: InclusionProof {
            root_hash: "sha256:root".to_string(),
            tree_size: 100,
            hashes: vec![],
            leaf_index: 42,
        },
        signed_entry_timestamp: vec![],
        log_id: "test-log".to_string(),
    };
    verifier.add_valid_entry("sha256:abc".to_string(), entry);

    let expected = TransparencyLogEntry {
        log_index: 7,
        entry_hash: "sha256:abc".to_string(),
        inclusion_proof: InclusionProof {
            root_hash: "sha256:other-root".to_string(),
            tree_size: 100,
            hashes: vec![],
            leaf_index: 42,
        },
        signed_entry_timestamp: vec![],
        log_id: "test-log".to_string(),
    };

    let result = verifier.verify_entry("sha256:abc", Some(&expected)).await;
    assert!(matches!(
        result,
        Err(fcp_registry::SupplyChainVerificationError::TransparencyEntryMismatch)
    ));
}

#[fcp_async_core::runtime::test]
async fn mock_transparency_verifier_rejects_unknown_entry() {
    use fcp_registry::{MockTransparencyVerifier, TransparencyLogVerifier};

    let verifier = MockTransparencyVerifier::new();
    let result = verifier.verify_entry("sha256:unknown", None).await;
    assert!(result.is_err(), "unknown entry should fail");
}

#[fcp_async_core::runtime::test]
async fn mock_tuf_verifier_accepts_valid_target() {
    use fcp_registry::{MockTufVerifier, TufRootMetadata, TufTargetInfo, TufVerifier};

    let root = TufRootMetadata {
        version: 5,
        root_hash: "sha256:root".to_string(),
        expires: 9999999999,
        key_ids: vec![],
        threshold: 1,
    };
    let verifier = MockTufVerifier::new(root.clone());
    let target_info = TufTargetInfo {
        target_path: "connectors/test".to_string(),
        hash: "sha256:abc".to_string(),
        length: 1024,
        delegations: vec!["root".to_string()],
    };
    verifier.add_valid_target("connectors/test".to_string(), target_info);

    let result = verifier
        .verify_target(&root, "connectors/test")
        .await
        .expect("mock verify");
    assert!(result.verified());
    assert_eq!(result.root_version(), 5);
    assert!(result.target().is_some());
}

#[fcp_async_core::runtime::test]
async fn mock_tuf_verifier_rejects_unknown_target() {
    use fcp_registry::{MockTufVerifier, TufRootMetadata, TufVerifier};

    let root = TufRootMetadata {
        version: 1,
        root_hash: "sha256:root".to_string(),
        expires: 9999999999,
        key_ids: vec![],
        threshold: 1,
    };
    let verifier = MockTufVerifier::new(root.clone());
    let result = verifier.verify_target(&root, "missing/target").await;
    assert!(result.is_err(), "unknown target should fail");
}

#[fcp_async_core::runtime::test]
async fn mock_sigstore_verifier_accepts_valid_bundle() {
    use fcp_registry::{MockSigstoreVerifier, SigstoreBundle, SigstoreVerifier};

    let verifier = MockSigstoreVerifier::new();
    verifier.add_valid_bundle_claims(
        "sha256:artifact".to_string(),
        Some("github-actions".to_string()),
        Some("https://token.actions.githubusercontent.com".to_string()),
        Some(12345),
    );

    let bundle = SigstoreBundle {
        signature: "sig".to_string(),
        certificate: "cert".to_string(),
        rekor_entry: None,
        identity: "github-actions".to_string(),
        issuer: "https://token.actions.githubusercontent.com".to_string(),
    };
    let result = verifier
        .verify_bundle(&bundle, "sha256:artifact", &[], &[])
        .await
        .expect("mock verify");
    assert!(result.verified());
    assert_eq!(result.identity(), Some("github-actions"));
}

#[fcp_async_core::runtime::test]
async fn mock_sigstore_verifier_rejects_unknown_artifact() {
    use fcp_registry::{MockSigstoreVerifier, SigstoreBundle, SigstoreVerifier};

    let verifier = MockSigstoreVerifier::new();
    let bundle = SigstoreBundle {
        signature: "sig".to_string(),
        certificate: "cert".to_string(),
        rekor_entry: None,
        identity: "test".to_string(),
        issuer: "https://issuer".to_string(),
    };
    let result = verifier
        .verify_bundle(&bundle, "sha256:unknown", &[], &[])
        .await;
    assert!(result.is_err(), "unknown artifact should fail");
}

// ─────────────────────────────────────────────────────────────────────────────
// SupplyChainVerificationError Display for all variants
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn supply_chain_error_display_all_variants() {
    let cases: Vec<(SupplyChainVerificationError, &str)> = vec![
        (
            SupplyChainVerificationError::TransparencyEntryNotFound,
            "entry not found",
        ),
        (
            SupplyChainVerificationError::TransparencyProofInvalid,
            "proof invalid",
        ),
        (
            SupplyChainVerificationError::TransparencySignatureInvalid,
            "signature invalid",
        ),
        (
            SupplyChainVerificationError::TufRootMismatch {
                expected: "abc".into(),
                actual: "xyz".into(),
            },
            "abc",
        ),
        (SupplyChainVerificationError::TufExpired, "expired"),
        (
            SupplyChainVerificationError::TufTargetNotFound {
                target: "fcp.test".into(),
            },
            "fcp.test",
        ),
        (
            SupplyChainVerificationError::TufRollback { current: 5, got: 3 },
            "rollback",
        ),
        (SupplyChainVerificationError::TufFreeze, "freeze"),
        (
            SupplyChainVerificationError::SigstoreSignatureInvalid,
            "signature invalid",
        ),
        (
            SupplyChainVerificationError::SigstoreCertificateInvalid,
            "certificate",
        ),
        (
            SupplyChainVerificationError::SigstoreIdentityMismatch {
                expected: "a".into(),
                actual: "b".into(),
            },
            "identity mismatch",
        ),
        (
            SupplyChainVerificationError::SigstoreIssuerUntrusted {
                issuer: "evil.com".into(),
            },
            "evil.com",
        ),
        (
            SupplyChainVerificationError::Network("timeout".into()),
            "timeout",
        ),
        (
            SupplyChainVerificationError::NotConfigured,
            "not configured",
        ),
    ];

    for (err, substr) in cases {
        let display = err.to_string();
        assert!(
            display.to_lowercase().contains(substr),
            "expected '{substr}' in '{display}'"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SupplyChainVerificationError is Send + Sync
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn supply_chain_error_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SupplyChainVerificationError>();
}

// ─────────────────────────────────────────────────────────────────────────────
// SupplyChainVerificationConfig defaults
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn supply_chain_config_default() {
    let config = SupplyChainVerificationConfig::default();
    assert!(config.tuf_pinned_root.is_none());
    assert!(config.trusted_sigstore_identities.is_empty());
    assert!(config.trusted_sigstore_issuers.is_empty());
    assert!(!config.require_transparency);
    assert!(!config.require_tuf);
    assert!(!config.require_sigstore);
}

// ─────────────────────────────────────────────────────────────────────────────
// RegistryError Display for additional variants
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn registry_error_display_transparency_log_missing() {
    let err = RegistryError::TransparencyLogMissing;
    assert!(err.to_string().contains("transparency log"));
}

#[test]
fn registry_error_display_transparency_evidence_missing() {
    let err = RegistryError::TransparencyEvidenceMissing;
    assert!(err.to_string().contains("evidence"));
}

#[test]
fn registry_error_display_required_attestation_missing() {
    let err = RegistryError::RequiredAttestationMissing {
        attestation: "in-toto".to_string(),
    };
    assert!(err.to_string().contains("in-toto"));
}

#[test]
fn registry_error_display_attestation_evidence_missing() {
    let err = RegistryError::AttestationEvidenceMissing;
    assert!(err.to_string().contains("evidence"));
}

#[test]
fn registry_error_display_attestation_expired() {
    let err = RegistryError::AttestationExpired {
        attestation: "in-toto".to_string(),
        expired_at: 0,
    };
    let msg = err.to_string();
    assert!(msg.contains("in-toto"));
    assert!(msg.contains("expired"));
}

#[test]
fn registry_error_display_signature_bytes() {
    let err = RegistryError::SignatureBytes;
    assert!(err.to_string().contains("signature"));
}

// ─────────────────────────────────────────────────────────────────────────────
// RegistryError is Send + Sync + std::error::Error
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn registry_error_trait_bounds() {
    fn assert_bounds<T: Send + Sync + std::error::Error>() {}
    assert_bounds::<RegistryError>();
}

// ─────────────────────────────────────────────────────────────────────────────
// RegistryVerificationReport serde roundtrip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn registry_verification_report_serde_roundtrip() {
    let report = RegistryVerificationReport {
        connector_id: "fcp.slack:social:1.0.0".to_string(),
        manifest_hash: "sha256:abc123".to_string(),
        binary_hash: "sha256:def456".to_string(),
        target: ConnectorTarget {
            os: "linux".to_string(),
            arch: "amd64".to_string(),
        },
        verified_at: 1_700_000_000,
        outcome: "verified".to_string(),
    };

    let json = serde_json::to_string(&report).unwrap();
    let back: RegistryVerificationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back.connector_id, "fcp.slack:social:1.0.0");
    assert_eq!(back.verified_at, 1_700_000_000);
    assert_eq!(back.outcome, "verified");
    assert_eq!(back.target.os, "linux");
    assert_eq!(back.target.arch, "amd64");
}

// ─────────────────────────────────────────────────────────────────────────────
// ConnectorTarget as_string and equality
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn connector_target_as_string_format() {
    let t = ConnectorTarget {
        os: "darwin".to_string(),
        arch: "arm64".to_string(),
    };
    assert_eq!(t.as_string(), "darwin-arm64");
}

#[test]
fn connector_target_clone_eq() {
    let t1 = ConnectorTarget {
        os: "linux".to_string(),
        arch: "amd64".to_string(),
    };
    let t2 = t1.clone();
    assert_eq!(t1, t2);
}

#[test]
fn connector_target_ne_different_arch() {
    let t1 = ConnectorTarget {
        os: "linux".to_string(),
        arch: "amd64".to_string(),
    };
    let t2 = ConnectorTarget {
        os: "linux".to_string(),
        arch: "arm64".to_string(),
    };
    assert_ne!(t1, t2);
}

// ─────────────────────────────────────────────────────────────────────────────
// TransparencyLogEntry serde roundtrip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn transparency_log_entry_serde_roundtrip() {
    use fcp_registry::{InclusionProof, TransparencyLogEntry};

    let entry = TransparencyLogEntry {
        log_index: 42,
        entry_hash: "sha256:abc".to_string(),
        inclusion_proof: InclusionProof {
            root_hash: "sha256:root".to_string(),
            tree_size: 100,
            hashes: vec!["h1".into(), "h2".into()],
            leaf_index: 42,
        },
        signed_entry_timestamp: vec![1, 2, 3],
        log_id: "log-1".to_string(),
    };

    let json = serde_json::to_string(&entry).unwrap();
    let back: TransparencyLogEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back.log_index, 42);
    assert_eq!(back.inclusion_proof.tree_size, 100);
    assert_eq!(back.inclusion_proof.hashes.len(), 2);
}

// ─────────────────────────────────────────────────────────────────────────────
// TufRootMetadata serde roundtrip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn tuf_root_metadata_serde_roundtrip() {
    use fcp_registry::TufRootMetadata;

    let root = TufRootMetadata {
        version: 3,
        root_hash: "sha256:root".to_string(),
        expires: 1_700_000_000,
        key_ids: vec!["key-1".into(), "key-2".into()],
        threshold: 2,
    };

    let json = serde_json::to_string(&root).unwrap();
    let back: TufRootMetadata = serde_json::from_str(&json).unwrap();
    assert_eq!(back.version, 3);
    assert_eq!(back.threshold, 2);
    assert_eq!(back.key_ids.len(), 2);
}

// ─────────────────────────────────────────────────────────────────────────────
// TufTargetInfo serde roundtrip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn tuf_target_info_serde_roundtrip() {
    use fcp_registry::TufTargetInfo;

    let target = TufTargetInfo {
        target_path: "connectors/fcp.slack/1.0.0/linux-amd64".to_string(),
        hash: "sha256:binary_hash".to_string(),
        length: 1024,
        delegations: vec!["root".into(), "targets".into()],
    };

    let json = serde_json::to_string(&target).unwrap();
    let back: TufTargetInfo = serde_json::from_str(&json).unwrap();
    assert_eq!(back.target_path, target.target_path);
    assert_eq!(back.length, 1024);
}

// ─────────────────────────────────────────────────────────────────────────────
// SigstoreBundle serde roundtrip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn sigstore_bundle_serde_roundtrip() {
    use fcp_registry::SigstoreBundle;

    let bundle = SigstoreBundle {
        signature: "base64sig".to_string(),
        certificate: "PEM_CERT".to_string(),
        rekor_entry: None,
        identity: "github-actions".to_string(),
        issuer: "https://token.actions.githubusercontent.com".to_string(),
    };

    let json = serde_json::to_string(&bundle).unwrap();
    let back: SigstoreBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(back.identity, "github-actions");
    assert!(back.rekor_entry.is_none());
}

// ─────────────────────────────────────────────────────────────────────────────
// RegistryTrustPolicy defaults
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn registry_trust_policy_default() {
    let policy = RegistryTrustPolicy::default();
    assert!(policy.publisher_keys.is_empty());
    assert!(policy.registry_keys.is_empty());
    assert!(!policy.require_registry_signature);
}

// ─────────────────────────────────────────────────────────────────────────────
// SupplyChainEvidence defaults
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn supply_chain_evidence_default() {
    let evidence = SupplyChainEvidence::default();
    assert!(!evidence.transparency_log_present());
    assert!(evidence.attestations.is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// Verify bundle with real keys: transparency log required but missing
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn verify_bundle_transparency_required_but_missing_evidence() {
    let signing_key = Ed25519SigningKey::generate();
    let kid = "pub-1".to_string();
    let binary = test_binary();
    let binary_hash = binary_hash(&binary);

    let policy_section = r#"
[policy]
require_transparency_log = true
"#
    .to_string();
    let manifest_toml = unsigned_manifest_toml(&policy_section);
    let sig = sign_manifest(&manifest_toml, &signing_key, &binary_hash);

    let manifest_with_sigs = format!("{}\n{}", manifest_toml, publisher_sig_toml(&kid, &sig));

    let bundle = ConnectorBundle {
        manifest_toml: manifest_with_sigs,
        binary,
        target: test_target(),
    };

    let mut policy = RegistryTrustPolicy::default();
    policy
        .publisher_keys
        .insert(kid, signing_key.verifying_key().clone());

    let verifier = RegistryVerifier::new(policy);

    // No evidence provided → should fail
    let result = verifier.verify_bundle(&bundle, None, None, None);
    assert!(result.is_err());
    let err_str = result.unwrap_err().to_string();
    assert!(
        err_str.contains("transparency"),
        "expected transparency error, got: {err_str}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Verify bundle with real attestation requirement
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn verify_bundle_attestation_required_but_missing() {
    let signing_key = Ed25519SigningKey::generate();
    let kid = "pub-1".to_string();
    let binary = test_binary();
    let binary_hash = binary_hash(&binary);

    let policy_section = r#"
[policy]
require_attestation_types = ["in-toto"]
"#
    .to_string();
    let manifest_toml = unsigned_manifest_toml(&policy_section);
    let sig = sign_manifest(&manifest_toml, &signing_key, &binary_hash);

    let manifest_with_sigs = format!("{}\n{}", manifest_toml, publisher_sig_toml(&kid, &sig));

    let bundle = ConnectorBundle {
        manifest_toml: manifest_with_sigs,
        binary,
        target: test_target(),
    };

    let mut policy = RegistryTrustPolicy::default();
    policy
        .publisher_keys
        .insert(kid, signing_key.verifying_key().clone());

    let verifier = RegistryVerifier::new(policy);

    // No evidence provided → should fail
    let result = verifier.verify_bundle(&bundle, None, None, None);
    assert!(
        matches!(result, Err(RegistryError::AttestationEvidenceMissing)),
        "expected structured attestation evidence error, got: {result:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Verify bundle with attestation evidence that meets requirement
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn verify_bundle_attestation_present_passes() {
    let signing_key = Ed25519SigningKey::generate();
    let kid = "pub-1".to_string();
    let binary = test_binary();
    let binary_hash = binary_hash(&binary);

    let policy_section = r#"
[policy]
require_attestation_types = ["in-toto"]
"#
    .to_string();
    let manifest_toml = unsigned_manifest_toml(&policy_section);
    let sig = sign_manifest(&manifest_toml, &signing_key, &binary_hash);

    let manifest_with_sigs = format!("{}\n{}", manifest_toml, publisher_sig_toml(&kid, &sig));

    let bundle = ConnectorBundle {
        manifest_toml: manifest_with_sigs,
        binary,
        target: test_target(),
    };

    let mut policy = RegistryTrustPolicy::default();
    policy
        .publisher_keys
        .insert(kid, signing_key.verifying_key().clone());

    let verifier = RegistryVerifier::new(policy);
    let evidence = SupplyChainEvidence::new().with_attestations(vec![AttestationEvidence {
        attestation_type: AttestationType::InToto,
        slsa_level: Some(2),
        builder_id: None,
        expires_at: None,
    }]);

    let result = verifier.verify_bundle(&bundle, None, Some(&evidence), None);
    assert!(result.is_ok(), "in-toto attestation present should pass");
}

// ─────────────────────────────────────────────────────────────────────────────
// MANIFEST_SIGNATURE_CONTEXT is correct
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn manifest_signature_context_value() {
    assert_eq!(
        fcp_registry::MANIFEST_SIGNATURE_CONTEXT,
        b"fcp.registry.manifest.v1"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// ConnectorTarget serde roundtrip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn connector_target_serde_roundtrip_full() {
    let target = ConnectorTarget {
        os: "windows".to_string(),
        arch: "amd64".to_string(),
    };
    let json = serde_json::to_string(&target).unwrap();
    let back: ConnectorTarget = serde_json::from_str(&json).unwrap();
    assert_eq!(target, back);
}

// ─────────────────────────────────────────────────────────────────────────────
// signature_message length encoding
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn signature_message_length_prefix_encoding() {
    let signing_bytes = b"hello";
    let binary_hash = "sha256:abc";
    let msg = fcp_registry::signature_message(signing_bytes, binary_hash);

    // The message must contain both inputs and be deterministic.
    let msg2 = fcp_registry::signature_message(signing_bytes, binary_hash);
    assert_eq!(msg, msg2, "signature message must be deterministic");

    // Different inputs must produce different messages.
    let different = fcp_registry::signature_message(b"world", binary_hash);
    assert_ne!(msg, different);
}

// ─────────────────────────────────────────────────────────────────────────────
// SupplyChainVerificationConfig with all fields set
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn supply_chain_config_all_fields() {
    use fcp_registry::TufRootMetadata;

    let config = SupplyChainVerificationConfig {
        tuf_pinned_root: Some(TufRootMetadata {
            version: 1,
            root_hash: "sha256:root".to_string(),
            expires: 9_999_999_999,
            key_ids: vec!["k1".into()],
            threshold: 1,
        }),
        trusted_sigstore_identities: vec!["github-actions".into()],
        trusted_sigstore_issuers: vec!["https://token.actions.githubusercontent.com".into()],
        require_transparency: true,
        require_tuf: true,
        require_sigstore: true,
        require_attestation_types: vec![AttestationType::InToto],
        min_slsa_level: Some(2),
        trusted_builders: vec!["github-actions".into()],
        require_attestation_expiry: true,
    };

    assert!(config.tuf_pinned_root.is_some());
    assert!(config.require_transparency);
    assert!(config.require_tuf);
    assert!(config.require_sigstore);
    assert_eq!(config.trusted_sigstore_identities.len(), 1);
    assert_eq!(config.min_slsa_level, Some(2));
    assert_eq!(config.trusted_builders.len(), 1);
    assert!(config.require_attestation_expiry);
    assert_eq!(config.require_attestation_types.len(), 1);
}
