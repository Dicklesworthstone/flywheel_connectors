#![no_main]
//! Structure-aware fuzz harness for fcp-registry manifest verification.
//!
//! Targets the narrow in-memory verification boundary rather than the HTTP or
//! filesystem wrappers:
//!
//! - raw manifest parsing + signing-byte derivation
//! - valid signed-bundle verification
//! - deterministic verify -> verify relation on identical inputs

use base64::Engine;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_manifest::ConnectorManifest;
use fcp_registry::{
    ConnectorBundle, ConnectorTarget, MANIFEST_SIGNATURE_CONTEXT, RegistryTrustPolicy,
    RegistryVerifier, manifest_signing_bytes, signature_message,
};
use libfuzzer_sys::fuzz_target;
use serde::Deserialize;
use sha2::{Digest, Sha256};

const MAX_MANIFEST_BYTES: usize = 8 * 1024;
const MAX_BINARY_BYTES: usize = 8 * 1024;
const PLACEHOLDER_HASH: &str =
    "blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct RegistryManifestSeed {
    raw_manifest: String,
    connector_id: String,
    version_major: u8,
    version_minor: u8,
    version_patch: u8,
    binary: Vec<u8>,
    tamper_binary_after_sign: bool,
}

fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    format!("sha256:{}", hex::encode(digest))
}

fn safe_connector_id(raw: &str) -> String {
    let filtered: String = raw
        .chars()
        .filter(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '.' | '-'))
        .collect();
    if filtered.is_empty() {
        "fcp.fuzz-target".to_string()
    } else if filtered.starts_with("fcp.") {
        filtered
    } else {
        format!("fcp.{filtered}")
    }
}

fn manifest_template(connector_id: &str, version: &str) -> String {
    let raw = include_str!("../../tests/vectors/manifest/manifest_minimal.toml");
    let patched = raw
        .replacen(
            "required = [\"network.dns\"]\noptional = []",
            "required = [\"network.dns\"]\noptional = [\"minimal.op\"]",
            1,
        )
        .replace(
            r#"id = "fcp.minimal""#,
            &format!(r#"id = "{connector_id}""#),
        )
        .replace(r#"version = "0.1.0""#, &format!(r#"version = "{version}""#));
    let unchecked = ConnectorManifest::parse_str_unchecked(&patched).expect("template must parse");
    let interface_hash = unchecked.compute_interface_hash().expect("interface hash");
    patched.replace(PLACEHOLDER_HASH, &interface_hash.to_string())
}

fn sign_manifest_toml(
    manifest_toml: &str,
    signing_key: &Ed25519SigningKey,
    binary_hash: &str,
) -> String {
    let manifest = ConnectorManifest::parse_str(manifest_toml).expect("manifest");
    let signing_bytes = manifest_signing_bytes(&manifest).expect("signing bytes");
    let message = signature_message(&signing_bytes, binary_hash);
    let signature = signing_key.sign_with_context(MANIFEST_SIGNATURE_CONTEXT, &message);
    format!(
        "base64:{}",
        base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
    )
}

fn publisher_signature_section(kid: &str, sig: &str) -> String {
    format!(
        r#"[signatures]
publisher_threshold = "1-of-1"

[[signatures.publisher_signatures]]
kid = "{kid}"
sig = "{sig}"
"#,
    )
}

fn parse_and_signing_bytes(manifest_toml: &str) {
    if manifest_toml.len() > MAX_MANIFEST_BYTES {
        return;
    }
    if let Ok(manifest) = ConnectorManifest::parse_str(manifest_toml) {
        let _ = manifest_signing_bytes(&manifest);
    }
}

fn verify_valid_signed_bundle(seed: &RegistryManifestSeed) {
    let version = format!(
        "{}.{}.{}",
        seed.version_major % 8,
        seed.version_minor % 16,
        seed.version_patch % 32
    );
    let connector_id = safe_connector_id(&seed.connector_id);
    let binary = if seed.binary.is_empty() {
        b"registry-fuzz-binary".to_vec()
    } else {
        seed.binary[..seed.binary.len().min(MAX_BINARY_BYTES)].to_vec()
    };
    let signed_binary_hash = hash_bytes(&binary);
    let unsigned = manifest_template(&connector_id, &version);
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let sig = sign_manifest_toml(&unsigned, &signing_key, &signed_binary_hash);
    let manifest_toml = format!(
        "{}\n{}",
        unsigned,
        publisher_signature_section("pub1", &sig)
    );
    let bundle = ConnectorBundle {
        manifest_toml,
        binary: if seed.tamper_binary_after_sign {
            [binary.as_slice(), b"-tampered"].concat()
        } else {
            binary
        },
        target: ConnectorTarget {
            os: "linux".to_string(),
            arch: "amd64".to_string(),
        },
    };

    let mut trust = RegistryTrustPolicy::default();
    trust
        .publisher_keys
        .insert("pub1".to_string(), verifying_key);
    let verifier = RegistryVerifier::new(trust);

    match verifier.verify_bundle(&bundle, None, None, None) {
        Ok(verified) => {
            let again = verifier
                .verify_bundle(&bundle, None, None, None)
                .expect("repeat verify of same bundle must stay stable");
            assert_eq!(again.manifest_hash(), verified.manifest_hash());
            assert_eq!(again.binary_hash(), verified.binary_hash());
            assert_eq!(again.target(), verified.target());
        }
        Err(_) => {
            assert!(
                seed.tamper_binary_after_sign,
                "generated non-tampered bundle must reach the valid verification path"
            );
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(seed) = serde_json::from_slice::<RegistryManifestSeed>(data) {
        parse_and_signing_bytes(&seed.raw_manifest);
        verify_valid_signed_bundle(&seed);
        return;
    }

    if data.len() > MAX_MANIFEST_BYTES {
        return;
    }
    if let Ok(raw_manifest) = std::str::from_utf8(data) {
        parse_and_signing_bytes(raw_manifest);
    }
});
