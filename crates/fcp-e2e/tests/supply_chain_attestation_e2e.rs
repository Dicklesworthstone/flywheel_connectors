//! Supply-chain attestation E2E (flywheel_connectors-ug1c1, [E.8]).
//!
//! This test exercises the production supply-chain boundary without mock
//! verifier shortcuts:
//!
//! 1. A connector binary is signed with the real `cosign sign-blob` CLI.
//! 2. Real TUF role metadata (`root.json`, `targets.json`) pins the binary.
//! 3. The connector manifest carries supply-chain object refs and a publisher
//!    signature over the exact binary digest.
//! 4. `fcp-registry` verifies the signed package and promotes only evidence
//!    produced by the real TUF/cosign verifier adapters.
//! 5. `fcp-host` refuses unsigned and tampered launch attempts with structured
//!    audit events.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use chrono::{Duration as ChronoDuration, Utc};
use fcp_core::{
    AttestationMaterial, AttestationMetadata, AttestationPredicateType, ObjectId,
    SBOM_SIGNED_FIELDS, SUPPLY_CHAIN_ATTESTATION_SIGNED_FIELDS, SbomComponent, SbomDependency,
};
use fcp_crypto::Ed25519SigningKey;
use fcp_evidence::{
    ConnectorId, SbomFormat, SoftwareBillOfMaterials, SupplyChainAttestation, SupplyChainSignature,
    TrustRootBinding, VerificationDecision, VerificationReasonCode,
};
use fcp_host::{SupplyChainGate, SupplyChainGateConfig};
use fcp_manifest::{AttestationType, Base64Bytes, ConnectorManifest};
use fcp_registry::{
    AttestationEvidence, ConnectorBundle, ConnectorTarget, CosignBlobVerifier,
    LocalRegistryCatalog, LocalTufVerifier, MANIFEST_SIGNATURE_CONTEXT, ManifestSignatureArtifact,
    REGISTRY_ATTESTATION_FILENAME, REGISTRY_MANIFEST_FILENAME,
    REGISTRY_MANIFEST_SIGNATURE_FILENAME, RegistryError, RegistryTrustPolicy, RegistryVerifier,
    SupplyChainEvidence, SupplyChainVerificationConfig, TufRootMetadata, manifest_signing_bytes,
    signature_message,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

const PLACEHOLDER_HASH: &str =
    "blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000";
const CONNECTOR_ID: &str = "fcp.supply-chain-e2e";
const CONNECTOR_VERSION: &str = "1.0.0";
const BUILDER_ID: &str = "fcp-e2e-real-builder";

#[derive(Default)]
struct AuditTrail {
    events: Vec<Value>,
}

impl AuditTrail {
    fn record(&mut self, phase: &str, outcome: &str, details: &Value) {
        let entry = json!({
            "ts": Utc::now().to_rfc3339(),
            "scenario_id": "supply_chain_attestation_e2e",
            "bead": "ug1c1",
            "phase": phase,
            "outcome": outcome,
            "details": details,
        });
        println!("{entry}");
        self.events.push(entry);
    }

    fn assert_phase(&self, phase: &str) {
        assert!(
            self.events
                .iter()
                .any(|event| event.get("phase").and_then(Value::as_str) == Some(phase)),
            "structured audit trail missing phase `{phase}`: {:#?}",
            self.events
        );
    }

    fn assert_jsonl_clean(&self) {
        let jsonl = self
            .events
            .iter()
            .map(serde_json::to_string)
            .collect::<Result<Vec<_>, _>>()
            .expect("audit trail serializes")
            .join("\n");
        let scan = fcp_e2e::scan_log_jsonl(&jsonl);
        assert!(
            scan.passed(),
            "structured E2E logs must parse and avoid secret leakage: {scan:?}"
        );
    }
}

struct ScenarioPaths {
    root: PathBuf,
    metadata: PathBuf,
    package: PathBuf,
    binary: PathBuf,
    tampered_binary: PathBuf,
    cosign_key_prefix: PathBuf,
    cosign_key: PathBuf,
    cosign_pub: PathBuf,
    cosign_sig: PathBuf,
}

impl ScenarioPaths {
    fn create() -> Self {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "fcp-supply-chain-attestation-e2e-{}-{suffix}",
            std::process::id()
        ));
        let metadata = root.join("tuf-metadata");
        let package = root.join("registry-package");
        std::fs::create_dir_all(&metadata).expect("create metadata dir");
        std::fs::create_dir_all(&package).expect("create package dir");

        let cosign_key_prefix = root.join("cosign-e2e");
        Self {
            binary: root.join("connector-bin"),
            tampered_binary: root.join("connector-bin-tampered"),
            cosign_key: cosign_key_prefix.with_extension("key"),
            cosign_pub: cosign_key_prefix.with_extension("pub"),
            cosign_sig: root.join("connector-bin.sig"),
            cosign_key_prefix,
            metadata,
            package,
            root,
        }
    }
}

fn hash_sha256_prefixed(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex_lower(&hasher.finalize()))
}

fn hash_blake3_prefixed(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"host-gate-blake3-fixture-domain");
    hasher.update(bytes);
    format!("blake3-256:{}", hex_lower(&hasher.finalize()))
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").expect("write hex");
    }
    out
}

fn tuf_metadata_signature(signed: &Value, signing_key: &Ed25519SigningKey) -> String {
    let signed_bytes = serde_json::to_vec(signed).expect("canonical TUF signed bytes");
    hex_lower(&signing_key.sign(&signed_bytes).to_bytes())
}

/// Build a TUF `meta` entry pinning a role file's version, length, and hash.
fn tuf_meta_entry(version: u32, role_bytes: &[u8]) -> Value {
    let hash = hash_sha256_prefixed(role_bytes)
        .strip_prefix("sha256:")
        .expect("sha256 prefix")
        .to_string();
    json!({
        "version": version,
        "length": role_bytes.len(),
        "hashes": { "sha256": hash },
    })
}

fn find_cosign() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("COSIGN_BIN") {
        let path = PathBuf::from(path);
        if command_succeeds(&path, &["version"]) {
            return Some(path);
        }
    }

    let candidates = vec![
        PathBuf::from("cosign"),
        PathBuf::from("/opt/homebrew/bin/cosign"),
        PathBuf::from("/usr/local/bin/cosign"),
        PathBuf::from("/usr/bin/cosign"),
    ];

    candidates
        .into_iter()
        .find(|candidate| command_succeeds(candidate, &["version"]))
}

fn command_succeeds(program: &Path, args: &[&str]) -> bool {
    let Some(mut command) = cosign_command(program) else {
        return false;
    };
    command
        .args(args)
        .output()
        .is_ok_and(|output| output.status.success())
}

fn cosign_command(program: &Path) -> Option<Command> {
    match program.to_str()? {
        "cosign" => Some(Command::new("cosign")),
        "/opt/homebrew/bin/cosign" => Some(Command::new("/opt/homebrew/bin/cosign")),
        "/usr/local/bin/cosign" => Some(Command::new("/usr/local/bin/cosign")),
        "/usr/bin/cosign" => Some(Command::new("/usr/bin/cosign")),
        _ => None,
    }
}

fn run_command(trail: &mut AuditTrail, phase: &str, command: &mut Command) {
    let output = command.output().expect("scenario command executes");
    let stderr = String::from_utf8_lossy(&output.stderr);
    trail.record(
        phase,
        if output.status.success() {
            "passed"
        } else {
            "failed"
        },
        &json!({
            "status": output.status.to_string(),
            "stderr": stderr.trim(),
        }),
    );
    assert!(
        output.status.success(),
        "{phase} failed with status {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        stderr,
    );
}

fn sign_with_cosign(paths: &ScenarioPaths, cosign: &Path, trail: &mut AuditTrail) {
    let passphrase = "fcp-e2e-cosign";
    let mut keygen = cosign_command(cosign).expect("cosign path came from allowlist");
    keygen
        .arg("generate-key-pair")
        .arg("--output-key-prefix")
        .arg(&paths.cosign_key_prefix)
        .env("COSIGN_PASSWORD", passphrase);
    run_command(trail, "cosign_generate_key_pair", &mut keygen);

    let mut sign = cosign_command(cosign).expect("cosign path came from allowlist");
    sign.arg("sign-blob")
        .arg("--key")
        .arg(&paths.cosign_key)
        .arg("--output-signature")
        .arg(&paths.cosign_sig)
        .arg("--tlog-upload=false")
        .arg(&paths.binary)
        .env("COSIGN_PASSWORD", passphrase);
    run_command(trail, "cosign_sign_blob", &mut sign);
}

fn base_manifest_with_hash() -> String {
    let raw = include_str!("../../../tests/vectors/manifest/manifest_minimal.toml");
    let renamed = raw
        .replace(
            r#"id = "fcp.minimal""#,
            &format!(r#"id = "{CONNECTOR_ID}""#),
        )
        .replace(
            r#"name = "Minimal Connector""#,
            r#"name = "Supply Chain E2E""#,
        )
        .replace(
            r#"version = "0.1.0""#,
            &format!(r#"version = "{CONNECTOR_VERSION}""#),
        );
    let unchecked =
        ConnectorManifest::parse_str_unchecked(&renamed).expect("unchecked manifest parse");
    let hash = unchecked
        .compute_interface_hash()
        .expect("compute interface hash");
    renamed.replace(PLACEHOLDER_HASH, &hash.to_string())
}

fn object_ref(label: &str) -> ObjectId {
    ObjectId::from_unscoped_bytes(label.as_bytes())
}

fn unsigned_manifest_toml(attestation_ref: ObjectId) -> String {
    format!(
        r#"{}

[supply_chain]
[[supply_chain.attestations]]
type = "in-toto"
object_id = "{}"

[policy]
require_attestation_types = ["in-toto"]
min_slsa_level = 2
trusted_builders = ["{BUILDER_ID}"]
"#,
        base_manifest_with_hash(),
        attestation_ref.to_prefixed_string(),
    )
}

fn sign_manifest_toml(
    manifest_toml: &str,
    signing_key: &Ed25519SigningKey,
    binary_hash: &str,
) -> Base64Bytes {
    let manifest = ConnectorManifest::parse_str(manifest_toml).expect("manifest parses");
    let signing_bytes = manifest_signing_bytes(&manifest).expect("manifest signing bytes");
    let signature = signing_key.sign_with_context(
        MANIFEST_SIGNATURE_CONTEXT,
        &signature_message(&signing_bytes, binary_hash),
    );
    Base64Bytes::try_from(format!(
        "base64:{}",
        base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
    ))
    .expect("base64 signature")
}

fn signed_manifest_toml(
    unsigned: &str,
    signing_key: &Ed25519SigningKey,
    binary_hash: &str,
    transparency_log_ref: ObjectId,
) -> String {
    let signature = sign_manifest_toml(unsigned, signing_key, binary_hash);
    format!(
        r#"{unsigned}

[signatures]
publisher_threshold = "1-of-1"
transparency_log_entry = "{}"

[[signatures.publisher_signatures]]
kid = "publisher-e2e"
sig = "{signature}"
"#,
        transparency_log_ref.to_prefixed_string(),
        signature = String::from(signature),
    )
}

#[allow(clippy::too_many_lines)]
fn write_tuf_metadata(
    metadata_dir: &Path,
    target_path: &str,
    binary_bytes: &[u8],
    trail: &mut AuditTrail,
) -> TufRootMetadata {
    let expires = (Utc::now() + ChronoDuration::days(7)).to_rfc3339();
    let binary_sha256 = hash_sha256_prefixed(binary_bytes);
    let binary_sha256_hex = binary_sha256
        .strip_prefix("sha256:")
        .expect("sha256 prefix")
        .to_string();
    let target_len = u64::try_from(binary_bytes.len()).expect("binary length fits u64");
    let key_id = "tuf-root-e2e";
    let tuf_signing_key = Ed25519SigningKey::generate();
    let public_hex = hex_lower(&tuf_signing_key.verifying_key().to_bytes());

    let mut keys = serde_json::Map::new();
    keys.insert(
        key_id.to_string(),
        json!({
            "keytype": "ed25519",
            "scheme": "ed25519",
            "keyval": { "public": public_hex }
        }),
    );
    let mut roles = serde_json::Map::new();
    for role in ["root", "targets", "snapshot", "timestamp"] {
        roles.insert(
            role.to_string(),
            json!({ "keyids": [key_id], "threshold": 1 }),
        );
    }

    let root_signed = json!({
        "_type": "root",
        "version": 1,
        "expires": expires.clone(),
        "keys": keys,
        "roles": roles,
    });
    let root_signature = tuf_metadata_signature(&root_signed, &tuf_signing_key);
    let root_json = json!({
        "signed": root_signed,
        "signatures": [{ "keyid": key_id, "sig": root_signature }]
    });
    let root_bytes = serde_json::to_vec_pretty(&root_json).expect("root json");
    std::fs::write(metadata_dir.join("root.json"), &root_bytes).expect("write root metadata");

    let targets_signed = json!({
        "_type": "targets",
        "version": 1,
        "expires": expires.clone(),
        "targets": {
            target_path: {
                "length": target_len,
                "hashes": { "sha256": binary_sha256_hex }
            }
        }
    });
    let targets_signature = tuf_metadata_signature(&targets_signed, &tuf_signing_key);
    let targets_json = json!({
        "signed": targets_signed,
        "signatures": [{ "keyid": key_id, "sig": targets_signature }]
    });
    let targets_bytes = serde_json::to_vec_pretty(&targets_json).expect("targets json");
    std::fs::write(metadata_dir.join("targets.json"), &targets_bytes)
        .expect("write targets metadata");

    // snapshot vouches for targets.json, timestamp vouches for snapshot.json:
    // the full TUF role chain the LocalTufVerifier walks. Each is written
    // after the file it pins so the declared length/hash match on-disk bytes.
    let snapshot_signed = json!({
        "_type": "snapshot",
        "version": 1,
        "expires": expires.clone(),
        "meta": { "targets.json": tuf_meta_entry(1, &targets_bytes) },
    });
    let snapshot_signature = tuf_metadata_signature(&snapshot_signed, &tuf_signing_key);
    let snapshot_json = json!({
        "signed": snapshot_signed,
        "signatures": [{ "keyid": key_id, "sig": snapshot_signature }]
    });
    let snapshot_bytes = serde_json::to_vec_pretty(&snapshot_json).expect("snapshot json");
    std::fs::write(metadata_dir.join("snapshot.json"), &snapshot_bytes)
        .expect("write snapshot metadata");

    let timestamp_signed = json!({
        "_type": "timestamp",
        "version": 1,
        "expires": expires,
        "meta": { "snapshot.json": tuf_meta_entry(1, &snapshot_bytes) },
    });
    let timestamp_signature = tuf_metadata_signature(&timestamp_signed, &tuf_signing_key);
    let timestamp_json = json!({
        "signed": timestamp_signed,
        "signatures": [{ "keyid": key_id, "sig": timestamp_signature }]
    });
    std::fs::write(
        metadata_dir.join("timestamp.json"),
        serde_json::to_vec_pretty(&timestamp_json).expect("timestamp json"),
    )
    .expect("write timestamp metadata");

    let pinned = TufRootMetadata {
        version: 1,
        root_hash: hash_sha256_prefixed(&root_bytes),
        expires: u64::try_from((Utc::now() + ChronoDuration::days(7)).timestamp())
            .expect("future timestamp"),
        key_ids: vec![key_id.to_string()],
        threshold: 1,
    };
    trail.record(
        "tuf_metadata_written",
        "passed",
        &json!({
            "metadata_dir": metadata_dir.display().to_string(),
            "target_path": target_path,
            "root_hash": pinned.root_hash,
            "binary_sha256": binary_sha256,
        }),
    );
    pinned
}

fn write_signed_package(
    paths: &ScenarioPaths,
    manifest_toml: &str,
    binary_bytes: &[u8],
    signing_key: &Ed25519SigningKey,
    binary_sha256: &str,
    target: &ConnectorTarget,
) {
    let signing_bytes = manifest_signing_bytes(
        &ConnectorManifest::parse_str(manifest_toml).expect("signed manifest parses"),
    )
    .expect("signing bytes");
    let artifact = ManifestSignatureArtifact {
        key_id: "publisher-e2e".to_string(),
        verifying_key: hex_lower(&signing_key.verifying_key().to_bytes()),
        context: String::from_utf8_lossy(MANIFEST_SIGNATURE_CONTEXT).into_owned(),
        manifest_signing_hash: hash_sha256_prefixed(&signing_bytes),
        binary_hash: binary_sha256.to_string(),
        signature: String::from(sign_manifest_toml(
            &unsigned_manifest_toml(object_ref("attestation")),
            signing_key,
            binary_sha256,
        )),
        target: target.clone(),
        binary_name: "connector-bin".to_string(),
    };
    std::fs::write(
        paths.package.join(REGISTRY_MANIFEST_FILENAME),
        manifest_toml,
    )
    .expect("write package manifest");
    std::fs::write(paths.package.join("connector-bin"), binary_bytes)
        .expect("write package binary");
    std::fs::write(
        paths.package.join(REGISTRY_MANIFEST_SIGNATURE_FILENAME),
        serde_json::to_vec_pretty(&artifact).expect("signature artifact json"),
    )
    .expect("write signature artifact");
    std::fs::write(
        paths.package.join(REGISTRY_ATTESTATION_FILENAME),
        serde_json::to_vec_pretty(&json!({
            "predicate_type": "https://slsa.dev/provenance/v1",
            "builder_id": BUILDER_ID,
        }))
        .expect("attestation sidecar json"),
    )
    .expect("write attestation sidecar");
}

fn supply_chain_attestation(artifact_digest: &str) -> SupplyChainAttestation {
    SupplyChainAttestation {
        format: "fcp-supply-chain-attestation".to_string(),
        schema_version: "1.0".to_string(),
        subject_digest: artifact_digest.to_string(),
        predicate_type: AttestationPredicateType::SlsaProvenanceV1,
        builder_id: BUILDER_ID.to_string(),
        build_type: "cargo-release".to_string(),
        materials: vec![AttestationMaterial {
            uri: "git+file:///flywheel_connectors".to_string(),
            digest: artifact_digest.to_string(),
        }],
        metadata: AttestationMetadata {
            build_started_at: Utc::now(),
            build_finished_at: Utc::now(),
            invocation_id: Some("ug1c1-e2e".to_string()),
        },
        slsa_level: 2,
        provenance_hash: artifact_digest.to_string(),
        trust_root: TrustRootBinding {
            root_type: "sigstore".to_string(),
            root_id: "ug1c1-local-root".to_string(),
        },
        builder_allowlist: vec![BUILDER_ID.to_string()],
        signature: SupplyChainSignature {
            algorithm: "ed25519".to_string(),
            key_id: "publisher-e2e".to_string(),
            signature: "f".repeat(128),
            signed_fields: SUPPLY_CHAIN_ATTESTATION_SIGNED_FIELDS
                .iter()
                .map(|field| (*field).to_string())
                .collect(),
        },
    }
}

fn sbom(artifact_digest: &str) -> SoftwareBillOfMaterials {
    SoftwareBillOfMaterials {
        format: "fcp-sbom".to_string(),
        schema_version: "1.0".to_string(),
        bom_format: SbomFormat::Cyclonedx,
        bom_version: "1.6".to_string(),
        tool_chain: vec!["cargo".to_string(), "cosign".to_string()],
        components: vec![SbomComponent {
            component_id: "connector-bin".to_string(),
            name: CONNECTOR_ID.to_string(),
            version: CONNECTOR_VERSION.to_string(),
            hashes: vec![artifact_digest.to_string()],
            licenses: vec!["Apache-2.0".to_string()],
        }],
        dependencies: vec![SbomDependency {
            component_id: "connector-bin".to_string(),
            depends_on: Vec::new(),
        }],
        trust_root: TrustRootBinding {
            root_type: "sigstore".to_string(),
            root_id: "ug1c1-local-root".to_string(),
        },
        signature: SupplyChainSignature {
            algorithm: "ed25519".to_string(),
            key_id: "publisher-e2e".to_string(),
            signature: "f".repeat(128),
            signed_fields: SBOM_SIGNED_FIELDS
                .iter()
                .map(|field| (*field).to_string())
                .collect(),
        },
    }
}

fn registry_evidence(
    tuf_result: &fcp_registry::TufVerificationResult,
    sigstore_result: &fcp_registry::SigstoreVerificationResult,
) -> SupplyChainEvidence {
    let expires_at = u64::try_from((Utc::now() + ChronoDuration::days(7)).timestamp())
        .expect("future timestamp");
    SupplyChainEvidence::new()
        .with_tuf_verification_result(tuf_result)
        .with_sigstore_verification_result(sigstore_result)
        .with_attestations(vec![AttestationEvidence {
            attestation_type: AttestationType::InToto,
            slsa_level: Some(2),
            builder_id: Some(BUILDER_ID.to_string()),
            expires_at: Some(expires_at),
        }])
}

#[test]
#[allow(clippy::too_many_lines)]
fn supply_chain_attestation_e2e() {
    let mut trail = AuditTrail::default();
    let paths = ScenarioPaths::create();
    let cosign = find_cosign().expect(
        "supply_chain_attestation_e2e requires the real cosign CLI on PATH, \
         an allowed system path, or COSIGN_BIN set to one of those locations",
    );
    trail.record(
        "setup",
        "started",
        &json!({
            "root": paths.root.display().to_string(),
            "cosign": cosign.display().to_string(),
        }),
    );

    let binary_bytes = b"#!/bin/sh\nprintf 'fcp supply chain e2e connector\\n'\n".to_vec();
    std::fs::write(&paths.binary, &binary_bytes).expect("write connector binary");
    let mut tampered = binary_bytes.clone();
    tampered.extend_from_slice(b"# tampered after signing\n");
    std::fs::write(&paths.tampered_binary, &tampered).expect("write tampered connector binary");

    sign_with_cosign(&paths, &cosign, &mut trail);

    let binary_sha256 = hash_sha256_prefixed(&binary_bytes);
    let binary_blake3 = hash_blake3_prefixed(&binary_bytes);
    let target_path = format!("connectors/{CONNECTOR_ID}/{CONNECTOR_VERSION}/connector-bin");
    let pinned_root = write_tuf_metadata(&paths.metadata, &target_path, &binary_bytes, &mut trail);
    let tuf_verifier = LocalTufVerifier::new(&paths.metadata);
    let tuf_result = tuf_verifier
        .verify_target_bytes(&pinned_root, &target_path, &binary_bytes)
        .expect("real local TUF metadata verifies connector binary");
    assert!(tuf_result.verified());
    trail.record(
        "tuf_verify_target",
        "passed",
        &json!({
            "root_version": tuf_result.root_version(),
            "target": tuf_result.target().map(|target| target.target_path.clone()),
        }),
    );

    let sigstore_result = CosignBlobVerifier::new(&paths.cosign_pub, &paths.cosign_sig)
        .with_cosign_binary(&cosign)
        .require_transparency_log(false)
        .verify_blob_path(
            &paths.binary,
            &binary_sha256,
            Some("local-cosign-key".to_string()),
            Some("cosign-key-pair".to_string()),
        )
        .expect("real cosign verify-blob verifies connector binary");
    assert!(sigstore_result.verified());
    trail.record(
        "cosign_verify_blob",
        "passed",
        &json!({
            "identity": sigstore_result.identity(),
            "issuer": sigstore_result.issuer(),
            "rekor_log_index": sigstore_result.rekor_log_index(),
        }),
    );

    let signing_key = Ed25519SigningKey::generate();
    let attestation_ref = object_ref("attestation");
    let transparency_ref = object_ref("cosign-transparency-log-entry");
    let unsigned_manifest = unsigned_manifest_toml(attestation_ref);
    let signed_manifest = signed_manifest_toml(
        &unsigned_manifest,
        &signing_key,
        &binary_sha256,
        transparency_ref,
    );
    let parsed_manifest = ConnectorManifest::parse_str(&signed_manifest)
        .expect("signed manifest with supply-chain refs parses");
    assert!(parsed_manifest.supply_chain.is_some());
    assert!(
        parsed_manifest
            .signatures
            .as_ref()
            .and_then(|signatures| signatures.transparency_log_entry)
            .is_some(),
        "manifest must carry a transparency-log object reference"
    );
    trail.record(
        "manifest_signed",
        "passed",
        &json!({
            "connector_id": parsed_manifest.connector.id.to_string(),
            "attestation_ref": attestation_ref.to_prefixed_string(),
            "transparency_ref": transparency_ref.to_prefixed_string(),
        }),
    );

    let target = ConnectorTarget {
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
    };
    write_signed_package(
        &paths,
        &signed_manifest,
        &binary_bytes,
        &signing_key,
        &binary_sha256,
        &target,
    );
    let catalog =
        LocalRegistryCatalog::from_signed_package_dirs(std::slice::from_ref(&paths.package))
            .expect("local registry install catalog verifies detached package signature");
    let descriptor = catalog
        .release(CONNECTOR_ID, CONNECTOR_VERSION)
        .expect("signed package release appears in catalog");
    assert_eq!(descriptor.targets.len(), 1);
    trail.record(
        "registry_catalog_install",
        "passed",
        &json!({
            "latest": descriptor.is_latest,
            "target": descriptor.targets[0].target,
            "binary_sha256": descriptor.targets[0].binary_sha256,
        }),
    );

    let evidence = registry_evidence(&tuf_result, &sigstore_result);
    let mut trust = RegistryTrustPolicy::default();
    trust
        .publisher_keys
        .insert("publisher-e2e".to_string(), signing_key.verifying_key());
    let registry = RegistryVerifier::new(trust).with_supply_chain_verification_config(
        SupplyChainVerificationConfig {
            tuf_pinned_root: Some(pinned_root.clone()),
            trusted_sigstore_identities: vec!["local-cosign-key".to_string()],
            trusted_sigstore_issuers: vec!["cosign-key-pair".to_string()],
            require_tuf: true,
            require_sigstore: true,
            require_transparency: false,
            // Owner-side attestation floor, enforced independently of the
            // connector manifest's own [policy] table (br-g7jhf finding 1).
            require_attestation_types: vec![AttestationType::InToto],
            min_slsa_level: Some(2),
            trusted_builders: vec![BUILDER_ID.to_string()],
            require_attestation_expiry: true,
        },
    );
    let bundle = ConnectorBundle {
        manifest_toml: signed_manifest.clone(),
        binary: binary_bytes.clone(),
        target: target.clone(),
    };
    let verified = registry
        .verify_bundle(&bundle, None, Some(&evidence), Some(&target))
        .expect("registry verifies signed package with real TUF and cosign evidence");
    let report = verified.report("install-verified");
    trail.record(
        "registry_verify_install",
        "passed",
        &serde_json::to_value(&report).expect("registry report json"),
    );

    let unsigned_bundle = ConnectorBundle {
        manifest_toml: unsigned_manifest,
        binary: binary_bytes.clone(),
        target: target.clone(),
    };
    let unsigned_err = registry
        .verify_bundle(&unsigned_bundle, None, Some(&evidence), Some(&target))
        .expect_err("unsigned registry bundle must fail closed");
    assert!(matches!(unsigned_err, RegistryError::MissingSignatures));
    trail.record(
        "registry_refuse_unsigned",
        "passed",
        &json!({ "error": unsigned_err.to_string() }),
    );

    let tampered_bundle = ConnectorBundle {
        manifest_toml: signed_manifest,
        binary: tampered.clone(),
        target,
    };
    let tampered_err = registry
        .verify_bundle(&tampered_bundle, None, Some(&evidence), None)
        .expect_err("tampered registry bundle must fail closed");
    assert!(
        matches!(
            tampered_err,
            RegistryError::SignatureInvalid { .. } | RegistryError::PublisherThresholdUnmet { .. }
        ),
        "expected signature failure for tampered binary, got {tampered_err:?}"
    );
    let cosign_tamper_err = CosignBlobVerifier::new(&paths.cosign_pub, &paths.cosign_sig)
        .with_cosign_binary(&cosign)
        .require_transparency_log(false)
        .verify_blob_path(
            &paths.tampered_binary,
            &hash_sha256_prefixed(&tampered),
            None,
            None,
        )
        .expect_err("cosign must reject tampered connector binary");
    trail.record(
        "registry_refuse_tampered",
        "passed",
        &json!({
            "registry_error": tampered_err.to_string(),
            "cosign_error": cosign_tamper_err.to_string(),
        }),
    );

    let connector_id = ConnectorId::from_static(CONNECTOR_ID);
    let host_gate = SupplyChainGate::with_config(SupplyChainGateConfig::default());
    let attestation = supply_chain_attestation(&binary_blake3);
    let sbom = sbom(&binary_blake3);
    let allowed = host_gate
        .verify_at(
            &connector_id,
            CONNECTOR_VERSION,
            &binary_blake3,
            Some(&attestation),
            Some(&sbom),
            Utc::now(),
        )
        .expect("host gate verifies signed launch");
    assert!(allowed.allowed);
    assert_eq!(allowed.audit_event.decision, VerificationDecision::Allow);
    trail.record(
        "host_launch_allowed_signed",
        "passed",
        &serde_json::to_value(&allowed.audit_event).expect("host audit event json"),
    );

    let unsigned_refusal = host_gate
        .verify_at(
            &connector_id,
            CONNECTOR_VERSION,
            &binary_blake3,
            None,
            None,
            Utc::now(),
        )
        .expect("host unsigned refusal returns audit event");
    assert!(!unsigned_refusal.allowed);
    assert_eq!(
        unsigned_refusal.audit_event.reason_code,
        VerificationReasonCode::AttestationMissing
    );
    trail.record(
        "host_refuse_unsigned",
        "passed",
        &serde_json::to_value(&unsigned_refusal.audit_event).expect("host unsigned audit json"),
    );

    let tampered_refusal = host_gate
        .verify_at(
            &connector_id,
            CONNECTOR_VERSION,
            &hash_blake3_prefixed(&tampered),
            Some(&attestation),
            Some(&sbom),
            Utc::now(),
        )
        .expect("host tamper refusal returns audit event");
    assert!(!tampered_refusal.allowed);
    assert_eq!(
        tampered_refusal.audit_event.reason_code,
        VerificationReasonCode::SubjectDigestMismatch
    );
    trail.record(
        "host_refuse_tampered",
        "passed",
        &serde_json::to_value(&tampered_refusal.audit_event).expect("host tamper audit json"),
    );

    let phases: BTreeSet<_> = [
        "setup",
        "cosign_generate_key_pair",
        "cosign_sign_blob",
        "tuf_metadata_written",
        "tuf_verify_target",
        "cosign_verify_blob",
        "manifest_signed",
        "registry_catalog_install",
        "registry_verify_install",
        "registry_refuse_unsigned",
        "registry_refuse_tampered",
        "host_launch_allowed_signed",
        "host_refuse_unsigned",
        "host_refuse_tampered",
    ]
    .into_iter()
    .collect();
    for phase in phases {
        trail.assert_phase(phase);
    }
    trail.assert_jsonl_clean();
}
