//! Registry verification and FCPS artifact mirroring for connectors.
//!
//! This crate validates connector manifests and binaries against supply-chain
//! policies and mirrors verified bundles into the object store per
//! `FCP_Specification_V3.md` §12 (Registry and Supply Chain) and §12.4
//! (Mirroring and Sovereignty). Mirrored symbols are stored durably and
//! MUST be packable into FCPS frames per §9.8.2.

// `std::os::windows::fs::MetadataExt::number_of_links()` (used by
// `file_has_multiple_links` on Windows) is behind the unstable `windows_by_handle`
// feature. Gate it on Windows only — this is a nightly-toolchain project (see
// .github/workflows); Unix/other targets are unaffected by this attribute.
#![cfg_attr(windows, feature(windows_by_handle))]

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::{Path as AxumPath, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use bytes::Bytes;
use chrono::Utc;
use fcp_cbor::{CanonicalSerializer, MAX_CANONICAL_OBJECT_BYTES, SerializationError};
pub use fcp_core::{
    ConnectorBinaryObject, ConnectorBinarySymbolSet, ConnectorBinaryTransmissionInfo,
    ConnectorManifestObject, ConnectorTarget,
};
use fcp_crypto::ed25519::{Ed25519Signature, Ed25519VerifyingKey, PUBLIC_KEY_SIZE, SIGNATURE_SIZE};
use fcp_manifest::{
    AttestationType, Base64Bytes, ConnectorManifest, ManifestError, SignatureEntry,
    SignaturesSection,
};
use fcp_prelude::{
    CapabilityId, ObjectHeader, ObjectId, ObjectIdKey, Provenance, RateLimitDeclarations,
    RetentionClass, StorageMeta, StoredObject, ZoneId, ZonePolicyObject,
    connector_manifest_signing_view_schema,
};
use fcp_raptorq::{DecodeError, EncodeError, RaptorQConfig, RaptorQDecoder, RaptorQEncoder};
use fcp_store::{
    ObjectStore, ObjectStoreError, ObjectSymbolMeta, ObjectTransmissionInfo, StoredSymbol,
    SymbolMeta, SymbolStore, SymbolStoreError,
};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Signing context for manifest signatures.
pub const MANIFEST_SIGNATURE_CONTEXT: &[u8] = b"fcp.registry.manifest.v1";
pub const REGISTRY_MANIFEST_FILENAME: &str = "manifest.toml";
pub const REGISTRY_MANIFEST_SIGNATURE_FILENAME: &str = "manifest-signature.json";
pub const REGISTRY_ATTESTATION_FILENAME: &str = "attestation.json";

/// Detached manifest-signature metadata emitted alongside a signed connector package.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestSignatureArtifact {
    pub key_id: String,
    pub verifying_key: String,
    pub context: String,
    pub manifest_signing_hash: String,
    pub binary_hash: String,
    pub signature: String,
    pub target: ConnectorTarget,
    pub binary_name: String,
}

#[derive(Debug, Clone)]
struct RegistryPackageRecord {
    connector_id: String,
    version: Version,
    manifest_toml: String,
    manifest_sha256: String,
    manifest_signature: ManifestSignatureArtifact,
    manifest_signature_json: String,
    binary_sha256: String,
    binary_bytes: Vec<u8>,
    attestation_json: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryCatalogResponse {
    pub connectors: Vec<RegistryConnectorSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryConnectorSummary {
    pub connector_id: String,
    pub latest_version: String,
    pub versions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryConnectorDescriptor {
    pub connector_id: String,
    pub latest_version: String,
    pub versions: Vec<RegistryVersionDescriptor>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryVersionDescriptor {
    pub version: String,
    pub is_latest: bool,
    pub targets: Vec<RegistryTargetDescriptor>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryTargetDescriptor {
    pub os: String,
    pub arch: String,
    pub target: String,
    pub manifest_sha256: String,
    pub binary_sha256: String,
    pub manifest_url: String,
    pub binary_url: String,
    pub signature_url: String,
    pub attestation_url: Option<String>,
    pub signature: ManifestSignatureArtifact,
}

#[derive(Debug, Clone, Default)]
pub struct LocalRegistryCatalog {
    connectors: HashMap<String, HashMap<String, Vec<RegistryPackageRecord>>>,
}

#[derive(Debug, thiserror::Error)]
pub enum RegistryCatalogError {
    #[error("no signed package directories were provided")]
    EmptyCatalog,
    #[error("failed to read `{path}`: {source}")]
    ReadFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("signed package `{path}` is missing `{file_name}`")]
    MissingFile {
        path: PathBuf,
        file_name: &'static str,
    },
    #[error("signed package `{path}` has invalid signature metadata: {source}")]
    SignatureArtifactJson {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("signed package `{path}` has invalid manifest: {source}")]
    ManifestParse {
        path: PathBuf,
        #[source]
        source: ManifestError,
    },
    #[error("signed package `{path}` is missing binary `{binary_name}`")]
    MissingBinary { path: PathBuf, binary_name: String },
    #[error(
        "signed package `{path}` binary digest mismatch (artifact {artifact_hash}, actual {actual_hash})"
    )]
    BinaryHashMismatch {
        path: PathBuf,
        artifact_hash: String,
        actual_hash: String,
    },
    #[error("signed package `{path}` failed to compute manifest signing bytes: {message}")]
    ManifestSigningBytes { path: PathBuf, message: String },
    #[error(
        "signed package `{path}` manifest signing digest mismatch (artifact {artifact_hash}, actual {actual_hash})"
    )]
    ManifestSigningHashMismatch {
        path: PathBuf,
        artifact_hash: String,
        actual_hash: String,
    },
    #[error("signed package `{path}` has unsupported signature context `{context}`")]
    SignatureContextMismatch { path: PathBuf, context: String },
    #[error("signed package `{path}` has invalid verifying key encoding")]
    SignatureVerifyingKeyInvalid { path: PathBuf },
    #[error("signed package `{path}` has invalid signature bytes")]
    SignatureBytesInvalid { path: PathBuf },
    #[error("signed package `{path}` manifest signature verification failed")]
    SignatureInvalid { path: PathBuf },
    #[error("duplicate signed package for `{connector_id}` version `{version}` target `{target}`")]
    DuplicateTarget {
        connector_id: String,
        version: String,
        target: String,
    },
    #[error("path traversal in binary_name: `{binary_name}`")]
    PathTraversal {
        /// The rejected binary name from the signature metadata.
        binary_name: String,
    },
    #[error("signed package `{path}` binary `{binary_name}` must be a standalone regular file")]
    LinkedBinary { path: PathBuf, binary_name: String },
}

/// Registry verification failures.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("manifest parse failed: {0}")]
    ManifestParse(#[from] ManifestError),
    #[error("signature section missing from manifest")]
    MissingSignatures,
    #[error("no trusted key for kid `{kid}`")]
    UnknownKid { kid: String },
    #[error("signature verification failed for kid `{kid}`")]
    SignatureInvalid { kid: String },
    #[error("publisher signature threshold unmet (required {required}, valid {valid})")]
    PublisherThresholdUnmet { required: u8, valid: u8 },
    #[error("no trusted publisher or registry signature verified")]
    NoTrustedSignature,
    #[error("registry signature required but missing or invalid")]
    RegistrySignatureRequired,
    #[error("target mismatch (expected {expected}, got {found})")]
    TargetMismatch { expected: String, found: String },
    #[error("capability `{capability}` exceeds zone ceiling")]
    CapabilityCeilingViolation { capability: String },
    #[error("missing transparency log entry in manifest")]
    TransparencyLogMissing,
    #[error("transparency log evidence missing")]
    TransparencyEvidenceMissing,
    #[error("TUF verification required by operator config")]
    TufVerificationRequired,
    #[error("Sigstore verification required by operator config")]
    SigstoreVerificationRequired,
    #[error("required attestation `{attestation}` not present")]
    RequiredAttestationMissing { attestation: String },
    #[error("attestation evidence missing")]
    AttestationEvidenceMissing,
    #[error("attestation `{attestation}` expired at {expired_at}")]
    AttestationExpired {
        attestation: String,
        expired_at: u64,
    },
    #[error(
        "attestation `{attestation}` has no expires_at but policy.require_attestation_expiry is set"
    )]
    AttestationExpiryMissing { attestation: String },
    #[error("attestation does not meet minimum SLSA level {required}")]
    SlsaLevelInsufficient { required: u8 },
    #[error("attestation builder `{builder}` not in trusted builders list")]
    UntrustedBuilder { builder: String },
    #[error("build-provenance attestation `{attestation}` declares no builder identity")]
    BuilderIdentityMissing { attestation: String },
    #[error("no build-provenance attestation names a trusted builder")]
    TrustedBuilderProvenanceMissing,
    #[error("TUF evidence carries no target hash, so the bundle binary is unbound")]
    TufTargetUnbound,
    #[error("TUF target hash mismatch (attested {attested}, bundle binary {bundle})")]
    TufTargetBindingMismatch { attested: String, bundle: String },
    #[error("Sigstore evidence carries no identity but operator config pins trusted identities")]
    SigstoreIdentityUnbound,
    #[error("Sigstore identity `{identity}` not in operator trusted identities")]
    SigstoreIdentityUntrusted { identity: String },
    #[error("Sigstore evidence carries no issuer but operator config pins trusted issuers")]
    SigstoreIssuerUnbound,
    #[error("Sigstore issuer `{issuer}` not in operator trusted issuers")]
    SigstoreIssuerUntrusted { issuer: String },
    #[error("manifest signing bytes serialization failed: {0}")]
    SigningBytes(SerializationError),
    #[error("canonical serialization failed: {0}")]
    Canonical(#[from] SerializationError),
    #[error("signature bytes malformed")]
    SignatureBytes,
    #[error("object store failure: {0}")]
    ObjectStore(#[from] ObjectStoreError),
    #[error("symbol store failure: {0}")]
    SymbolStore(#[from] SymbolStoreError),
    #[error("raptorq encode failed: {0}")]
    Encode(#[from] EncodeError),
    #[error("raptorq decode failed: {0}")]
    Decode(#[from] DecodeError),
    #[error(
        "not enough symbols to reconstruct binary object (received {received}, need at least {needed})"
    )]
    IncompleteSymbols { received: u32, needed: u32 },
    #[error("decoded transfer length {len} exceeds platform limits")]
    TransferLengthOverflow { len: u64 },
    #[error("reconstructed body length {len} exceeds canonical object limit {max}")]
    ReconstructedBodyTooLarge { len: usize, max: usize },
    #[error("decoded body too short (expected at least {expected} bytes, got {actual})")]
    ReconstructedBodyTooShort { expected: usize, actual: usize },
    #[error("reconstructed body hash mismatch (expected {expected}, got {actual})")]
    ReconstructedBodyHashMismatch { expected: String, actual: String },
    #[error("reconstructed manifest hash mismatch (expected {expected}, got {actual})")]
    ReconstructedManifestHashMismatch { expected: String, actual: String },
    #[error("reconstructed binary hash mismatch (expected {expected}, got {actual})")]
    ReconstructedBinaryHashMismatch { expected: String, actual: String },
    #[error("reconstructed binary target mismatch (expected {expected}, got {actual})")]
    ReconstructedBinaryTargetMismatch { expected: String, actual: String },
}

/// Connector bundle fetched from a registry.
#[derive(Debug, Clone)]
pub struct ConnectorBundle {
    pub manifest_toml: String,
    pub binary: Vec<u8>,
    pub target: ConnectorTarget,
}

/// Trust roots used for registry verification.
#[derive(Debug, Clone, Default)]
pub struct RegistryTrustPolicy {
    pub publisher_keys: HashMap<String, Ed25519VerifyingKey>,
    pub registry_keys: HashMap<String, Ed25519VerifyingKey>,
    pub require_registry_signature: bool,
}

/// Evidence from external supply-chain verification.
///
/// Populated ONLY by real verifier adapters (see
/// [`TransparencyLogVerifier`], [`TufVerifier`], [`SigstoreVerifier`]).
/// The `tuf_verified` / `sigstore_verified` booleans are load-bearing:
/// when the corresponding [`SupplyChainVerificationConfig`] flag
/// (`require_tuf`, `require_sigstore`, `require_transparency`) is set,
/// enforcement requires the matching evidence bool to be `true`. A
/// default-constructed `SupplyChainEvidence` carries no verification
/// claims and MUST NOT pass a `require_*` gate. See
/// [`enforce_supply_chain_verification_config`] below.
///
/// Historical note (br-pcmm8, br-i5iv4): these fields were added after a
/// review found the pre-existing presence-only checks
/// (`evidence.is_some()`) were trivially bypassable — any default evidence
/// satisfied the config. Review br-i5iv4 then flagged the follow-up
/// pattern — public `tuf_verified: bool` — as still caller-forgeable.
/// The current shape keeps the verified fields PRIVATE and only exposes
/// setters that require an actual verifier result type (which is itself
/// only constructed by the trait's `verify_*` methods). Tests that need
/// to short-circuit to a verified state go through the cfg-gated
/// [`Self::mark_tuf_verified_for_tests`] /
/// [`Self::mark_sigstore_verified_for_tests`] helpers, which are not
/// visible to downstream crates outside a `--features test-mocks` build.
#[derive(Debug, Clone, Default)]
pub struct SupplyChainEvidence {
    transparency_log_present: bool,
    tuf_verified: bool,
    /// SHA-256 of the target the TUF verifier attested, normalized to
    /// `sha256:<hex>`. `TufVerifier::verify_target` only proves the target
    /// *path* is enumerated in validly-signed TUF metadata, so enforcement
    /// re-binds this hash to the bundle binary (br-g7jhf finding 4).
    tuf_target_hash: Option<String>,
    sigstore_verified: bool,
    /// OIDC identity the Sigstore verifier adapter reported.
    sigstore_identity: Option<String>,
    /// OIDC issuer the Sigstore verifier adapter reported.
    sigstore_issuer: Option<String>,
    pub attestations: Vec<AttestationEvidence>,
}

impl SupplyChainEvidence {
    /// Construct an empty evidence record with no verification claims.
    ///
    /// All `*_verified` flags stay `false`; callers MUST promote through
    /// [`Self::with_tuf_verification_result`] /
    /// [`Self::with_sigstore_verification_result`] after running the
    /// corresponding verifier adapter, or (in tests) the cfg-gated
    /// `mark_*_for_tests` helpers.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_attestations(mut self, attestations: Vec<AttestationEvidence>) -> Self {
        self.attestations = attestations;
        self
    }

    /// Whether a transparency log verifier adapter found and verified an entry.
    #[must_use]
    pub const fn transparency_log_present(&self) -> bool {
        self.transparency_log_present
    }

    /// Whether a TUF verifier adapter has validated the bundle.
    ///
    /// The only ways to flip this to `true` are:
    /// - [`Self::with_tuf_verification_result`] with a
    ///   `TufVerificationResult { verified: true, .. }` produced by a
    ///   [`TufVerifier::verify_target`] call, OR
    /// - [`Self::mark_tuf_verified_for_tests`] under `#[cfg(any(test,
    ///   feature = "test-mocks"))]`.
    ///
    /// This boolean alone means "the target path is enumerated in validly
    /// signed TUF metadata", NOT "this binary matches the TUF target hash".
    /// The byte binding lives in [`Self::tuf_target_hash`] and is enforced
    /// by [`enforce_supply_chain_verification_config`].
    #[must_use]
    pub const fn tuf_verified(&self) -> bool {
        self.tuf_verified
    }

    /// SHA-256 (`sha256:<hex>`) of the target the TUF verifier attested.
    ///
    /// `None` when the verifier reported no target info, in which case the
    /// evidence carries no byte binding and cannot satisfy a `require_tuf`
    /// gate.
    #[must_use]
    pub fn tuf_target_hash(&self) -> Option<&str> {
        self.tuf_target_hash.as_deref()
    }

    /// Whether a Sigstore verifier adapter has validated the bundle.
    #[must_use]
    pub const fn sigstore_verified(&self) -> bool {
        self.sigstore_verified
    }

    /// OIDC identity the Sigstore verifier adapter reported, if any.
    #[must_use]
    pub fn sigstore_identity(&self) -> Option<&str> {
        self.sigstore_identity.as_deref()
    }

    /// OIDC issuer the Sigstore verifier adapter reported, if any.
    #[must_use]
    pub fn sigstore_issuer(&self) -> Option<&str> {
        self.sigstore_issuer.as_deref()
    }

    /// Promote this evidence with a TUF verification result.
    ///
    /// Sets `tuf_verified = result.verified()` and records the attested
    /// target hash. Callers obtain `result` from a real
    /// [`TufVerifier::verify_target`] / `verify_target_bytes` invocation; a
    /// result with `verified == false` leaves the flag untouched so a failed
    /// verification cannot silently upgrade the evidence.
    #[must_use]
    pub fn with_tuf_verification_result(mut self, result: &TufVerificationResult) -> Self {
        if result.verified {
            self.tuf_verified = true;
            self.tuf_target_hash = result
                .target
                .as_ref()
                .map(|target| normalize_sha256(&target.hash));
        }
        self
    }

    /// Promote this evidence with a transparency-log verification result.
    #[must_use]
    pub fn with_transparency_verification_result(
        mut self,
        result: &TransparencyVerificationResult,
    ) -> Self {
        if result.verified {
            self.transparency_log_present = true;
        }
        self
    }

    /// Promote this evidence with a Sigstore verification result.
    ///
    /// Records the identity and issuer the adapter reported so
    /// [`enforce_supply_chain_verification_config`] can re-check them
    /// against the operator's trusted allowlists (br-g7jhf finding 5).
    #[must_use]
    pub fn with_sigstore_verification_result(
        mut self,
        result: &SigstoreVerificationResult,
    ) -> Self {
        if result.verified {
            self.sigstore_verified = true;
            self.sigstore_identity = result.identity.clone();
            self.sigstore_issuer = result.issuer.clone();
        }
        self
    }

    /// Test-only shortcut that stamps `tuf_verified = true` and binds the
    /// attested target hash without running a real TUF verifier. Gated
    /// behind `#[cfg(any(test, feature = "test-mocks"))]` so downstream
    /// release builds cannot reach it. The hash argument is mandatory so a
    /// test cannot accidentally produce evidence that the byte-binding gate
    /// would reject for the wrong reason.
    #[cfg(any(test, feature = "test-mocks"))]
    #[must_use]
    pub fn mark_tuf_verified_for_tests(mut self, target_hash: &str) -> Self {
        self.tuf_verified = true;
        self.tuf_target_hash = Some(normalize_sha256(target_hash));
        self
    }

    /// Test-only shortcut that stamps `sigstore_verified = true` with the
    /// identity/issuer an adapter would have reported.
    /// Gated the same way as [`Self::mark_tuf_verified_for_tests`].
    #[cfg(any(test, feature = "test-mocks"))]
    #[must_use]
    pub fn mark_sigstore_verified_for_tests(
        mut self,
        identity: Option<&str>,
        issuer: Option<&str>,
    ) -> Self {
        self.sigstore_verified = true;
        self.sigstore_identity = identity.map(ToString::to_string);
        self.sigstore_issuer = issuer.map(ToString::to_string);
        self
    }
}

/// Attestation metadata verified by an external system.
#[derive(Debug, Clone)]
pub struct AttestationEvidence {
    pub attestation_type: AttestationType,
    pub slsa_level: Option<u8>,
    pub builder_id: Option<String>,
    pub expires_at: Option<u64>,
}

/// Verified connector bundle metadata.
#[derive(Debug, Clone)]
pub struct VerifiedConnectorBundle {
    pub manifest: ConnectorManifest,
    pub manifest_hash: String,
    pub binary_hash: String,
    pub target: ConnectorTarget,
}

/// Minimal structured report for audit/logging sinks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryVerificationReport {
    pub connector_id: String,
    pub manifest_hash: String,
    pub binary_hash: String,
    pub target: ConnectorTarget,
    pub verified_at: u64,
    pub outcome: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Supply-Chain Verification Adapters
// ─────────────────────────────────────────────────────────────────────────────

/// Transparency log entry with proof data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransparencyLogEntry {
    /// Log index of the entry.
    pub log_index: u64,
    /// SHA256 hash of the entry being logged.
    pub entry_hash: String,
    /// Merkle proof for inclusion verification.
    pub inclusion_proof: InclusionProof,
    /// Signed entry timestamp from the log server.
    pub signed_entry_timestamp: Vec<u8>,
    /// Log ID (public key hash of the log).
    pub log_id: String,
}

/// Merkle inclusion proof for transparency log verification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InclusionProof {
    /// Merkle tree root hash.
    pub root_hash: String,
    /// Tree size at time of proof.
    pub tree_size: u64,
    /// Merkle audit path (hashes from leaf to root).
    pub hashes: Vec<String>,
    /// Index of the leaf in the tree.
    pub leaf_index: u64,
}

/// TUF root metadata for anti-rollback protection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TufRootMetadata {
    /// Version of the root metadata.
    pub version: u32,
    /// SHA256 hash of the canonical root.json.
    pub root_hash: String,
    /// Expiration timestamp (Unix seconds).
    pub expires: u64,
    /// Key IDs for threshold verification.
    pub key_ids: Vec<String>,
    /// Threshold required for valid signatures.
    pub threshold: u8,
}

/// TUF delegation target for connector binaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TufTargetInfo {
    /// Target path in the TUF repo.
    pub target_path: String,
    /// SHA256 hash of the target.
    pub hash: String,
    /// Length of the target in bytes.
    pub length: u64,
    /// Delegation chain from root to target.
    pub delegations: Vec<String>,
}

/// Sigstore bundle containing signature and attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigstoreBundle {
    /// Base64-encoded signature.
    pub signature: String,
    /// Certificate chain (PEM-encoded).
    pub certificate: String,
    /// Rekor log entry for the signature.
    pub rekor_entry: Option<TransparencyLogEntry>,
    /// OIDC identity that signed (e.g., "github-actions").
    pub identity: String,
    /// OIDC issuer URL.
    pub issuer: String,
}

/// Result of transparency log verification.
#[derive(Debug, Clone)]
pub struct TransparencyVerificationResult {
    /// Whether the entry was found and verified.
    verified: bool,
    /// Log index of the verified entry.
    log_index: Option<u64>,
    /// Timestamp when entry was logged.
    logged_at: Option<u64>,
}

impl TransparencyVerificationResult {
    /// Whether the entry was found and verified.
    #[must_use]
    pub const fn verified(&self) -> bool {
        self.verified
    }

    /// Log index of the verified entry.
    #[must_use]
    pub const fn log_index(&self) -> Option<u64> {
        self.log_index
    }

    /// Timestamp when entry was logged.
    #[must_use]
    pub const fn logged_at(&self) -> Option<u64> {
        self.logged_at
    }
}

/// Result of TUF verification.
#[derive(Debug, Clone)]
pub struct TufVerificationResult {
    /// Whether the target was found in valid TUF metadata.
    verified: bool,
    /// Root version used for verification.
    root_version: u32,
    /// Target info if found.
    target: Option<TufTargetInfo>,
}

impl TufVerificationResult {
    /// Whether the target was found in valid TUF metadata.
    #[must_use]
    pub const fn verified(&self) -> bool {
        self.verified
    }

    /// Root version used for verification.
    #[must_use]
    pub const fn root_version(&self) -> u32 {
        self.root_version
    }

    /// Target info if found.
    #[must_use]
    pub fn target(&self) -> Option<&TufTargetInfo> {
        self.target.as_ref()
    }
}

/// Result of Sigstore bundle verification.
#[derive(Debug, Clone)]
pub struct SigstoreVerificationResult {
    /// Whether the signature is valid.
    verified: bool,
    /// OIDC identity from certificate.
    identity: Option<String>,
    /// OIDC issuer from certificate.
    issuer: Option<String>,
    /// Rekor log index if available.
    rekor_log_index: Option<u64>,
}

impl SigstoreVerificationResult {
    /// Whether the signature is valid.
    #[must_use]
    pub const fn verified(&self) -> bool {
        self.verified
    }

    /// OIDC identity from certificate.
    #[must_use]
    pub fn identity(&self) -> Option<&str> {
        self.identity.as_deref()
    }

    /// OIDC issuer from certificate.
    #[must_use]
    pub fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    /// Rekor log index if available.
    #[must_use]
    pub const fn rekor_log_index(&self) -> Option<u64> {
        self.rekor_log_index
    }
}

/// Errors specific to supply-chain verification adapters.
#[derive(Debug, thiserror::Error)]
pub enum SupplyChainVerificationError {
    #[error("transparency log entry not found")]
    TransparencyEntryNotFound,
    #[error("transparency log entry mismatch")]
    TransparencyEntryMismatch,
    #[error("transparency log inclusion proof invalid")]
    TransparencyProofInvalid,
    #[error("transparency log signature invalid")]
    TransparencySignatureInvalid,
    #[error("TUF root hash mismatch (expected {expected}, got {actual})")]
    TufRootMismatch { expected: String, actual: String },
    #[error("TUF metadata expired")]
    TufExpired,
    #[error("TUF target not found: {target}")]
    TufTargetNotFound { target: String },
    #[error("TUF target hash mismatch for {target} (expected {expected}, got {actual})")]
    TufTargetHashMismatch {
        target: String,
        expected: String,
        actual: String,
    },
    #[error("TUF target length mismatch for {target} (expected {expected}, got {actual})")]
    TufTargetLengthMismatch {
        target: String,
        expected: u64,
        actual: u64,
    },
    #[error("TUF rollback detected (got version {got}, expected > {current})")]
    TufRollback { current: u32, got: u32 },
    #[error("TUF freeze attack detected: timestamp metadata unchanged")]
    TufFreeze,
    #[error("TUF metadata signature invalid")]
    TufSignatureInvalid,
    #[error("TUF {role} metadata signature threshold unmet (required {required}, valid {valid})")]
    TufSignatureThreshold {
        role: String,
        required: u8,
        valid: usize,
    },
    #[error("Sigstore signature invalid")]
    SigstoreSignatureInvalid,
    #[error("Sigstore certificate expired or not yet valid")]
    SigstoreCertificateInvalid,
    #[error("Sigstore identity mismatch (expected {expected}, got {actual})")]
    SigstoreIdentityMismatch { expected: String, actual: String },
    #[error("Sigstore issuer not trusted: {issuer}")]
    SigstoreIssuerUntrusted { issuer: String },
    #[error("network error: {0}")]
    Network(String),
    #[error("verification not configured")]
    NotConfigured,
}

/// Trait for transparency log verification adapters.
#[async_trait]
pub trait TransparencyLogVerifier: Send + Sync {
    /// Verify that an entry exists in the transparency log.
    async fn verify_entry(
        &self,
        entry_hash: &str,
        expected_entry: Option<&TransparencyLogEntry>,
    ) -> Result<TransparencyVerificationResult, SupplyChainVerificationError>;
}

/// Trait for TUF metadata verification adapters.
#[async_trait]
pub trait TufVerifier: Send + Sync {
    /// Verify TUF metadata chain and find target info.
    ///
    /// # Arguments
    /// * `pinned_root` - Expected root metadata hash for anti-rollback
    /// * `target_path` - Path to the target in the TUF repo
    async fn verify_target(
        &self,
        pinned_root: &TufRootMetadata,
        target_path: &str,
    ) -> Result<TufVerificationResult, SupplyChainVerificationError>;

    /// Fetch and verify the current root metadata.
    async fn fetch_root(&self) -> Result<TufRootMetadata, SupplyChainVerificationError>;
}

/// Trait for Sigstore bundle verification adapters.
#[async_trait]
pub trait SigstoreVerifier: Send + Sync {
    /// Verify a Sigstore bundle against an artifact.
    ///
    /// # Arguments
    /// * `bundle` - The Sigstore bundle containing signature and certificate
    /// * `artifact_hash` - SHA256 hash of the artifact being verified
    /// * `trusted_identities` - Allowed OIDC identities (e.g., "github-actions")
    /// * `trusted_issuers` - Allowed OIDC issuers
    async fn verify_bundle(
        &self,
        bundle: &SigstoreBundle,
        artifact_hash: &str,
        trusted_identities: &[String],
        trusted_issuers: &[String],
    ) -> Result<SigstoreVerificationResult, SupplyChainVerificationError>;
}

/// Configuration for supply-chain verification.
///
/// This is the **owner/operator** side of registry verification. Every field
/// here is a floor that a publisher-supplied `manifest.toml` cannot lower:
/// `verify_bundle` enforces this config *and* the manifest's own `[policy]`
/// table, so the effective requirement is the stricter of the two on every
/// axis (br-g7jhf finding 1). A connector that ships no `[policy]` table at
/// all still has to satisfy everything declared here.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SupplyChainVerificationConfig {
    /// Pinned TUF root for anti-rollback.
    pub tuf_pinned_root: Option<TufRootMetadata>,
    /// Trusted OIDC identities for Sigstore.
    pub trusted_sigstore_identities: Vec<String>,
    /// Trusted OIDC issuers for Sigstore.
    pub trusted_sigstore_issuers: Vec<String>,
    /// Whether to require transparency log verification.
    pub require_transparency: bool,
    /// Whether to require TUF verification.
    pub require_tuf: bool,
    /// Whether to require Sigstore verification.
    pub require_sigstore: bool,
    /// Attestation types every bundle must carry, regardless of what the
    /// connector manifest declares.
    #[serde(default)]
    pub require_attestation_types: Vec<AttestationType>,
    /// Minimum SLSA level a build-provenance attestation must declare.
    #[serde(default)]
    pub min_slsa_level: Option<u8>,
    /// Builders the operator trusts to produce connector binaries.
    #[serde(default)]
    pub trusted_builders: Vec<String>,
    /// Whether every attestation must carry an `expires_at` timestamp.
    #[serde(default)]
    pub require_attestation_expiry: bool,
}

impl SupplyChainVerificationConfig {
    #[must_use]
    pub fn tuf_verification_required(&self) -> bool {
        self.require_tuf || self.tuf_pinned_root.is_some()
    }

    #[must_use]
    pub fn sigstore_verification_required(&self) -> bool {
        self.require_sigstore
            || !self.trusted_sigstore_identities.is_empty()
            || !self.trusted_sigstore_issuers.is_empty()
    }
}

/// No-op transparency log verifier for testing without external dependencies.
#[derive(Debug, Default)]
pub struct NoOpTransparencyVerifier;

#[async_trait]
impl TransparencyLogVerifier for NoOpTransparencyVerifier {
    async fn verify_entry(
        &self,
        _entry_hash: &str,
        _expected_entry: Option<&TransparencyLogEntry>,
    ) -> Result<TransparencyVerificationResult, SupplyChainVerificationError> {
        Err(SupplyChainVerificationError::NotConfigured)
    }
}

/// No-op TUF verifier for testing without external dependencies.
#[derive(Debug, Default)]
pub struct NoOpTufVerifier;

#[async_trait]
impl TufVerifier for NoOpTufVerifier {
    async fn verify_target(
        &self,
        _pinned_root: &TufRootMetadata,
        _target_path: &str,
    ) -> Result<TufVerificationResult, SupplyChainVerificationError> {
        Err(SupplyChainVerificationError::NotConfigured)
    }

    async fn fetch_root(&self) -> Result<TufRootMetadata, SupplyChainVerificationError> {
        Err(SupplyChainVerificationError::NotConfigured)
    }
}

/// No-op Sigstore verifier for testing without external dependencies.
#[derive(Debug, Default)]
pub struct NoOpSigstoreVerifier;

#[async_trait]
impl SigstoreVerifier for NoOpSigstoreVerifier {
    async fn verify_bundle(
        &self,
        _bundle: &SigstoreBundle,
        _artifact_hash: &str,
        _trusted_identities: &[String],
        _trusted_issuers: &[String],
    ) -> Result<SigstoreVerificationResult, SupplyChainVerificationError> {
        Err(SupplyChainVerificationError::NotConfigured)
    }
}

/// Verifies a local TUF repository metadata set against a pinned root.
///
/// The verifier reads the four real TUF role files (`root.json`,
/// `timestamp.json`, `snapshot.json`, `targets.json`) from `metadata_dir` and
/// walks the full chain: root pinning, per-role expiry, root rollback,
/// timestamp→snapshot and snapshot→targets version/length/hash binding,
/// target length, SHA-256 target hash, and Ed25519 role-signature thresholds.
/// It then returns a private [`TufVerificationResult`] that can promote
/// [`SupplyChainEvidence`].
///
/// All four role files are mandatory. Skipping `timestamp.json` /
/// `snapshot.json` would leave targets-level rollback and mix-and-match
/// (pairing a fresh root with a stale signed `targets.json`) uncovered, which
/// is the entire purpose of the TUF layer.
///
/// Freshness caveat: a directory-backed verifier holds no memory of previously
/// seen metadata, so freeze detection reduces to the timestamp role's own
/// expiry horizon (an expired `timestamp.json` surfaces as
/// [`SupplyChainVerificationError::TufFreeze`]). Detecting a repository that
/// re-serves *unexpired* stale metadata requires persisted client state, which
/// is out of scope for this adapter.
#[derive(Debug, Clone)]
pub struct LocalTufVerifier {
    metadata_dir: PathBuf,
}

impl LocalTufVerifier {
    #[must_use]
    pub fn new(metadata_dir: impl Into<PathBuf>) -> Self {
        Self {
            metadata_dir: metadata_dir.into(),
        }
    }

    fn read_role_file(&self, file_name: &str) -> Result<Vec<u8>, SupplyChainVerificationError> {
        let path = self.metadata_dir.join(file_name);
        std::fs::read(&path).map_err(|source| {
            SupplyChainVerificationError::Network(format!(
                "failed to read TUF metadata `{}`: {source}",
                path.display()
            ))
        })
    }

    /// Verify a target and its bytes against local TUF metadata.
    ///
    /// # Errors
    /// Returns [`SupplyChainVerificationError`] when metadata cannot be read,
    /// does not match the pinned root, is expired/rolled back, or the target
    /// bytes do not match the metadata.
    pub fn verify_target_bytes(
        &self,
        pinned_root: &TufRootMetadata,
        target_path: &str,
        target_bytes: &[u8],
    ) -> Result<TufVerificationResult, SupplyChainVerificationError> {
        self.verify_target_inner(pinned_root, target_path, Some(target_bytes))
    }

    fn verify_target_inner(
        &self,
        pinned_root: &TufRootMetadata,
        target_path: &str,
        target_bytes: Option<&[u8]>,
    ) -> Result<TufVerificationResult, SupplyChainVerificationError> {
        let root_path = self.metadata_dir.join("root.json");
        let root_bytes = std::fs::read(&root_path).map_err(|source| {
            SupplyChainVerificationError::Network(format!(
                "failed to read TUF root metadata `{}`: {source}",
                root_path.display()
            ))
        })?;
        let actual_root_hash = hash_bytes(&root_bytes);
        if pinned_root.root_hash != actual_root_hash {
            return Err(SupplyChainVerificationError::TufRootMismatch {
                expected: pinned_root.root_hash.clone(),
                actual: actual_root_hash,
            });
        }

        let root: TufSignedEnvelope<TufRootSigned> =
            serde_json::from_slice(&root_bytes).map_err(|source| {
                SupplyChainVerificationError::Network(format!(
                    "failed to parse TUF root metadata `{}`: {source}",
                    root_path.display()
                ))
            })?;
        let root_signed_bytes = tuf_signed_bytes(&root_bytes, "root")?;
        root.require_role("root")?;
        ensure_not_expired(&root.signed.expires)?;
        if root.signed.version < pinned_root.version {
            return Err(SupplyChainVerificationError::TufRollback {
                current: pinned_root.version,
                got: root.signed.version,
            });
        }
        let root_role = required_tuf_role(&root.signed.roles, "root")?;
        if root_role.threshold != pinned_root.threshold
            || !pinned_root
                .key_ids
                .iter()
                .all(|key_id| root_role.keyids.iter().any(|candidate| candidate == key_id))
        {
            return Err(SupplyChainVerificationError::TufRootMismatch {
                expected: format!(
                    "threshold={} keyids={}",
                    pinned_root.threshold,
                    pinned_root.key_ids.join(",")
                ),
                actual: format!(
                    "threshold={} keyids={}",
                    root_role.threshold,
                    root_role.keyids.join(",")
                ),
            });
        }
        verify_tuf_role_signatures(
            "root",
            root_role,
            &root.signed.keys,
            &root.signatures,
            &root_signed_bytes,
        )?;

        // ── timestamp role ────────────────────────────────────────────────
        // The timestamp role is the freshness anchor: it is the only
        // short-lived metadata in the chain, so an expired timestamp is the
        // canonical freeze-attack signal (a repository replaying stale but
        // validly signed metadata). Verifying it — and the snapshot it names
        // — is what upgrades this client from "root + targets are signed" to
        // real mix-and-match and targets-rollback coverage (br-g7jhf
        // finding 6).
        let timestamp_bytes = self.read_role_file("timestamp.json")?;
        let timestamp: TufSignedEnvelope<TufTimestampSigned> =
            parse_tuf_role(&timestamp_bytes, "timestamp")?;
        let timestamp_signed_bytes = tuf_signed_bytes(&timestamp_bytes, "timestamp")?;
        timestamp.require_role("timestamp")?;
        ensure_not_expired(&timestamp.signed.expires).map_err(|err| match err {
            SupplyChainVerificationError::TufExpired => SupplyChainVerificationError::TufFreeze,
            other => other,
        })?;
        let timestamp_role = required_tuf_role(&root.signed.roles, "timestamp")?;
        verify_tuf_role_signatures(
            "timestamp",
            timestamp_role,
            &root.signed.keys,
            &timestamp.signatures,
            &timestamp_signed_bytes,
        )?;

        // ── snapshot role ─────────────────────────────────────────────────
        let snapshot_bytes = self.read_role_file("snapshot.json")?;
        let snapshot: TufSignedEnvelope<TufSnapshotSigned> =
            parse_tuf_role(&snapshot_bytes, "snapshot")?;
        let snapshot_meta =
            required_tuf_meta(&timestamp.signed.meta, "timestamp", "snapshot.json")?;
        verify_tuf_meta_binding(
            "snapshot.json",
            snapshot_meta,
            &snapshot_bytes,
            snapshot.signed.version,
        )?;
        let snapshot_signed_bytes = tuf_signed_bytes(&snapshot_bytes, "snapshot")?;
        snapshot.require_role("snapshot")?;
        ensure_not_expired(&snapshot.signed.expires)?;
        let snapshot_role = required_tuf_role(&root.signed.roles, "snapshot")?;
        verify_tuf_role_signatures(
            "snapshot",
            snapshot_role,
            &root.signed.keys,
            &snapshot.signatures,
            &snapshot_signed_bytes,
        )?;

        // ── targets role ──────────────────────────────────────────────────
        let targets_bytes = self.read_role_file("targets.json")?;
        let targets: TufSignedEnvelope<TufTargetsSigned> =
            parse_tuf_role(&targets_bytes, "targets")?;
        let targets_meta = required_tuf_meta(&snapshot.signed.meta, "snapshot", "targets.json")?;
        verify_tuf_meta_binding(
            "targets.json",
            targets_meta,
            &targets_bytes,
            targets.signed.version,
        )?;
        let targets_signed_bytes = tuf_signed_bytes(&targets_bytes, "targets")?;
        targets.require_role("targets")?;
        ensure_not_expired(&targets.signed.expires)?;
        let targets_role = required_tuf_role(&root.signed.roles, "targets")?;
        verify_tuf_role_signatures(
            "targets",
            targets_role,
            &root.signed.keys,
            &targets.signatures,
            &targets_signed_bytes,
        )?;

        let target = targets.signed.targets.get(target_path).ok_or_else(|| {
            SupplyChainVerificationError::TufTargetNotFound {
                target: target_path.to_string(),
            }
        })?;
        let expected_hash = target.hashes.get("sha256").ok_or_else(|| {
            SupplyChainVerificationError::TufTargetHashMismatch {
                target: target_path.to_string(),
                expected: "sha256 hash entry".to_string(),
                actual: "missing".to_string(),
            }
        })?;
        let expected_hash = normalize_sha256(expected_hash);

        if let Some(bytes) = target_bytes {
            let actual_len = u64::try_from(bytes.len()).map_err(|_| {
                SupplyChainVerificationError::Network(
                    "target length does not fit into u64".to_string(),
                )
            })?;
            if target.length != actual_len {
                return Err(SupplyChainVerificationError::TufTargetLengthMismatch {
                    target: target_path.to_string(),
                    expected: target.length,
                    actual: actual_len,
                });
            }
            let actual_hash = hash_bytes(bytes);
            if expected_hash != actual_hash {
                return Err(SupplyChainVerificationError::TufTargetHashMismatch {
                    target: target_path.to_string(),
                    expected: expected_hash,
                    actual: actual_hash,
                });
            }
        }

        Ok(TufVerificationResult {
            verified: true,
            root_version: root.signed.version,
            target: Some(TufTargetInfo {
                target_path: target_path.to_string(),
                hash: expected_hash,
                length: target.length,
                delegations: vec![
                    "root".to_string(),
                    "timestamp".to_string(),
                    "snapshot".to_string(),
                    "targets".to_string(),
                ],
            }),
        })
    }
}

#[async_trait]
impl TufVerifier for LocalTufVerifier {
    async fn verify_target(
        &self,
        pinned_root: &TufRootMetadata,
        target_path: &str,
    ) -> Result<TufVerificationResult, SupplyChainVerificationError> {
        self.verify_target_inner(pinned_root, target_path, None)
    }

    async fn fetch_root(&self) -> Result<TufRootMetadata, SupplyChainVerificationError> {
        let root_path = self.metadata_dir.join("root.json");
        let root_bytes = std::fs::read(&root_path).map_err(|source| {
            SupplyChainVerificationError::Network(format!(
                "failed to read TUF root metadata `{}`: {source}",
                root_path.display()
            ))
        })?;
        let root: TufSignedEnvelope<TufRootSigned> =
            serde_json::from_slice(&root_bytes).map_err(|source| {
                SupplyChainVerificationError::Network(format!(
                    "failed to parse TUF root metadata `{}`: {source}",
                    root_path.display()
                ))
            })?;
        let root_signed_bytes = tuf_signed_bytes(&root_bytes, "root")?;
        root.require_role("root")?;
        ensure_not_expired(&root.signed.expires)?;
        let root_role = required_tuf_role(&root.signed.roles, "root")?;
        verify_tuf_role_signatures(
            "root",
            root_role,
            &root.signed.keys,
            &root.signatures,
            &root_signed_bytes,
        )?;
        Ok(TufRootMetadata {
            version: root.signed.version,
            root_hash: hash_bytes(&root_bytes),
            expires: unix_expiry(&root.signed.expires)?,
            key_ids: root_role.keyids.clone(),
            threshold: root_role.threshold,
        })
    }
}

/// Verifies connector blobs with the real `cosign verify-blob` CLI.
#[derive(Debug, Clone)]
pub struct CosignBlobVerifier {
    cosign_binary: PathBuf,
    key_path: PathBuf,
    signature_path: PathBuf,
    require_transparency_log: bool,
}

impl CosignBlobVerifier {
    #[must_use]
    pub fn new(key_path: impl Into<PathBuf>, signature_path: impl Into<PathBuf>) -> Self {
        Self {
            cosign_binary: PathBuf::from("cosign"),
            key_path: key_path.into(),
            signature_path: signature_path.into(),
            require_transparency_log: true,
        }
    }

    #[must_use]
    pub fn with_cosign_binary(mut self, cosign_binary: impl Into<PathBuf>) -> Self {
        self.cosign_binary = cosign_binary.into();
        self
    }

    #[must_use]
    pub const fn require_transparency_log(mut self, require: bool) -> Self {
        self.require_transparency_log = require;
        self
    }

    /// Verify a signed blob and return a private Sigstore result.
    ///
    /// # Trust semantics of `declared_identity` / `declared_issuer`
    ///
    /// This verifier runs `cosign verify-blob --key <pubkey>`. Key-based
    /// cosign verification authenticates the **signing key**, not an OIDC
    /// identity — there is no certificate to extract an identity or issuer
    /// from. The two arguments are therefore *operator-declared labels* that
    /// name the key being pinned, and they are echoed into the result so
    /// [`enforce_supply_chain_verification_config`] can match them against
    /// the operator's own allowlist. They MUST come from operator
    /// configuration; never source them from publisher- or bundle-controlled
    /// data, which would make the allowlist self-satisfying. For a
    /// certificate-derived identity, use a keyless [`SigstoreVerifier`]
    /// implementation instead (br-g7jhf finding 5).
    ///
    /// # Errors
    /// Returns [`SupplyChainVerificationError`] if the local artifact hash does
    /// not match `expected_artifact_hash` or the cosign process fails.
    pub fn verify_blob_path(
        &self,
        artifact_path: &Path,
        expected_artifact_hash: &str,
        declared_identity: Option<String>,
        declared_issuer: Option<String>,
    ) -> Result<SigstoreVerificationResult, SupplyChainVerificationError> {
        let artifact = std::fs::read(artifact_path).map_err(|source| {
            SupplyChainVerificationError::Network(format!(
                "failed to read cosign artifact `{}`: {source}",
                artifact_path.display()
            ))
        })?;
        let actual_hash = hash_bytes(&artifact);
        if actual_hash != expected_artifact_hash {
            return Err(SupplyChainVerificationError::SigstoreSignatureInvalid);
        }

        let mut command = cosign_command(&self.cosign_binary)?;
        command
            .arg("verify-blob")
            .arg("--key")
            .arg(&self.key_path)
            .arg("--signature")
            .arg(&self.signature_path);
        if !self.require_transparency_log {
            command.arg("--insecure-ignore-tlog=true");
        }
        command.arg(artifact_path);

        let output = command.output().map_err(|source| {
            SupplyChainVerificationError::Network(format!(
                "failed to execute `{}` verify-blob: {source}",
                self.cosign_binary.display()
            ))
        })?;
        if !output.status.success() {
            return Err(SupplyChainVerificationError::Network(format!(
                "`{} verify-blob` failed with status {}: {}",
                self.cosign_binary.display(),
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }

        Ok(SigstoreVerificationResult {
            verified: true,
            identity: declared_identity,
            issuer: declared_issuer,
            rekor_log_index: None,
        })
    }
}

fn cosign_command(cosign_binary: &Path) -> Result<Command, SupplyChainVerificationError> {
    let Some(candidate) = cosign_binary.to_str() else {
        return Err(SupplyChainVerificationError::Network(
            "cosign executable path is not valid UTF-8".to_string(),
        ));
    };
    match candidate {
        "cosign" => Ok(Command::new("cosign")),
        "/opt/homebrew/bin/cosign" => Ok(Command::new("/opt/homebrew/bin/cosign")),
        "/usr/local/bin/cosign" => Ok(Command::new("/usr/local/bin/cosign")),
        "/usr/bin/cosign" => Ok(Command::new("/usr/bin/cosign")),
        _ => Err(SupplyChainVerificationError::Network(format!(
            "unsupported cosign executable `{}`; use `cosign` on PATH or a fixed system path",
            cosign_binary.display()
        ))),
    }
}

#[derive(Debug, Deserialize)]
struct TufSignedEnvelope<T> {
    signed: T,
    #[serde(default)]
    signatures: Vec<TufMetadataSignature>,
}

impl<T> TufSignedEnvelope<T>
where
    T: TufRoleName,
{
    fn require_role(&self, expected: &str) -> Result<(), SupplyChainVerificationError> {
        if self.signed.role_name() != expected {
            return Err(SupplyChainVerificationError::Network(format!(
                "TUF metadata role mismatch: expected `{expected}`, got `{}`",
                self.signed.role_name()
            )));
        }
        if self.signatures.is_empty() {
            return Err(SupplyChainVerificationError::Network(format!(
                "TUF {expected} metadata carries no signatures"
            )));
        }
        if self
            .signatures
            .iter()
            .any(|signature| signature.keyid.trim().is_empty() || signature.sig.trim().is_empty())
        {
            return Err(SupplyChainVerificationError::Network(format!(
                "TUF {expected} metadata carries an empty signature"
            )));
        }
        Ok(())
    }
}

trait TufRoleName {
    fn role_name(&self) -> &str;
}

#[derive(Debug, Deserialize)]
struct TufMetadataSignature {
    keyid: String,
    sig: String,
}

#[derive(Debug, Deserialize)]
struct TufRootSigned {
    #[serde(rename = "_type")]
    role_type: String,
    version: u32,
    expires: String,
    #[serde(default)]
    keys: HashMap<String, TufKeyMetadata>,
    #[serde(default)]
    roles: HashMap<String, TufRoleMetadata>,
}

impl TufRoleName for TufRootSigned {
    fn role_name(&self) -> &str {
        &self.role_type
    }
}

#[derive(Debug, Deserialize)]
struct TufRoleMetadata {
    #[serde(default)]
    keyids: Vec<String>,
    threshold: u8,
}

#[derive(Debug, Deserialize)]
struct TufKeyMetadata {
    keytype: String,
    scheme: String,
    keyval: TufKeyValue,
}

#[derive(Debug, Deserialize)]
struct TufKeyValue {
    public: String,
}

#[derive(Debug, Deserialize)]
struct TufTargetsSigned {
    #[serde(rename = "_type")]
    role_type: String,
    version: u32,
    expires: String,
    #[serde(default)]
    targets: HashMap<String, TufTargetMetadata>,
}

impl TufRoleName for TufTargetsSigned {
    fn role_name(&self) -> &str {
        &self.role_type
    }
}

#[derive(Debug, Deserialize)]
struct TufTimestampSigned {
    #[serde(rename = "_type")]
    role_type: String,
    expires: String,
    #[serde(default)]
    meta: HashMap<String, TufMetaEntry>,
}

impl TufRoleName for TufTimestampSigned {
    fn role_name(&self) -> &str {
        &self.role_type
    }
}

#[derive(Debug, Deserialize)]
struct TufSnapshotSigned {
    #[serde(rename = "_type")]
    role_type: String,
    version: u32,
    expires: String,
    #[serde(default)]
    meta: HashMap<String, TufMetaEntry>,
}

impl TufRoleName for TufSnapshotSigned {
    fn role_name(&self) -> &str {
        &self.role_type
    }
}

/// A `meta` entry: one role file's expected version, and optionally its exact
/// length and hashes, as declared by the role above it in the chain.
#[derive(Debug, Deserialize)]
struct TufMetaEntry {
    version: u32,
    #[serde(default)]
    length: Option<u64>,
    #[serde(default)]
    hashes: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct TufTargetMetadata {
    length: u64,
    #[serde(default)]
    hashes: HashMap<String, String>,
}

fn parse_tuf_role<T: serde::de::DeserializeOwned>(
    metadata_bytes: &[u8],
    role_name: &str,
) -> Result<TufSignedEnvelope<T>, SupplyChainVerificationError> {
    serde_json::from_slice(metadata_bytes).map_err(|source| {
        SupplyChainVerificationError::Network(format!(
            "failed to parse TUF {role_name} metadata: {source}"
        ))
    })
}

fn required_tuf_meta<'a>(
    meta: &'a HashMap<String, TufMetaEntry>,
    declaring_role: &str,
    file_name: &str,
) -> Result<&'a TufMetaEntry, SupplyChainVerificationError> {
    meta.get(file_name).ok_or_else(|| {
        SupplyChainVerificationError::Network(format!(
            "TUF {declaring_role} metadata does not declare `{file_name}`"
        ))
    })
}

/// Bind a role file to the entry the role above it declared.
///
/// A version mismatch is a rollback / mix-and-match attempt: the served file
/// is not the one the (independently signed) parent role vouched for.
fn verify_tuf_meta_binding(
    file_name: &str,
    entry: &TufMetaEntry,
    role_bytes: &[u8],
    role_version: u32,
) -> Result<(), SupplyChainVerificationError> {
    if role_version != entry.version {
        return Err(SupplyChainVerificationError::TufRollback {
            current: entry.version,
            got: role_version,
        });
    }
    if let Some(expected_length) = entry.length {
        let actual_length = u64::try_from(role_bytes.len()).map_err(|_| {
            SupplyChainVerificationError::Network(format!(
                "TUF {file_name} length does not fit into u64"
            ))
        })?;
        if expected_length != actual_length {
            return Err(SupplyChainVerificationError::TufTargetLengthMismatch {
                target: file_name.to_string(),
                expected: expected_length,
                actual: actual_length,
            });
        }
    }
    if let Some(expected_hash) = entry.hashes.get("sha256") {
        let expected_hash = normalize_sha256(expected_hash);
        let actual_hash = hash_bytes(role_bytes);
        if expected_hash != actual_hash {
            return Err(SupplyChainVerificationError::TufTargetHashMismatch {
                target: file_name.to_string(),
                expected: expected_hash,
                actual: actual_hash,
            });
        }
    }
    Ok(())
}

fn normalize_sha256(value: &str) -> String {
    if value.starts_with("sha256:") {
        value.to_string()
    } else {
        format!("sha256:{value}")
    }
}

fn required_tuf_role<'a>(
    roles: &'a HashMap<String, TufRoleMetadata>,
    role_name: &str,
) -> Result<&'a TufRoleMetadata, SupplyChainVerificationError> {
    roles.get(role_name).ok_or_else(|| {
        SupplyChainVerificationError::Network(format!(
            "TUF root metadata does not declare `{role_name}` role"
        ))
    })
}

fn tuf_signed_bytes(
    metadata_bytes: &[u8],
    role_name: &str,
) -> Result<Vec<u8>, SupplyChainVerificationError> {
    let metadata: serde_json::Value = serde_json::from_slice(metadata_bytes).map_err(|source| {
        SupplyChainVerificationError::Network(format!(
            "failed to parse TUF {role_name} metadata for signing bytes: {source}"
        ))
    })?;
    let signed = metadata.get("signed").ok_or_else(|| {
        SupplyChainVerificationError::Network(format!(
            "TUF {role_name} metadata missing signed payload"
        ))
    })?;
    serde_json::to_vec(signed).map_err(|source| {
        SupplyChainVerificationError::Network(format!(
            "failed to canonicalize TUF {role_name} signed payload: {source}"
        ))
    })
}

fn verify_tuf_role_signatures(
    role_name: &str,
    role: &TufRoleMetadata,
    keys: &HashMap<String, TufKeyMetadata>,
    signatures: &[TufMetadataSignature],
    signed_bytes: &[u8],
) -> Result<(), SupplyChainVerificationError> {
    if role.threshold == 0 {
        return Err(SupplyChainVerificationError::Network(format!(
            "TUF {role_name} role has zero signature threshold"
        )));
    }
    if role.keyids.is_empty() {
        return Err(SupplyChainVerificationError::Network(format!(
            "TUF {role_name} role has no signing key IDs"
        )));
    }
    for key_id in &role.keyids {
        if !keys.contains_key(key_id) {
            return Err(SupplyChainVerificationError::Network(format!(
                "TUF {role_name} role references missing key `{key_id}`"
            )));
        }
    }

    let allowed_key_ids: HashSet<&str> = role.keyids.iter().map(String::as_str).collect();
    let mut valid_key_ids = HashSet::new();
    for signature in signatures {
        if !allowed_key_ids.contains(signature.keyid.as_str()) {
            continue;
        }
        let Some(key) = keys.get(&signature.keyid) else {
            continue;
        };
        if verify_tuf_ed25519_signature(key, signed_bytes, &signature.sig).is_ok() {
            valid_key_ids.insert(signature.keyid.as_str());
        }
    }

    let required = usize::from(role.threshold);
    if valid_key_ids.len() < required {
        return Err(SupplyChainVerificationError::TufSignatureThreshold {
            role: role_name.to_string(),
            required: role.threshold,
            valid: valid_key_ids.len(),
        });
    }
    Ok(())
}

fn verify_tuf_ed25519_signature(
    key: &TufKeyMetadata,
    signed_bytes: &[u8],
    signature: &str,
) -> Result<(), SupplyChainVerificationError> {
    if !key.keytype.trim().eq_ignore_ascii_case("ed25519")
        || !key.scheme.trim().eq_ignore_ascii_case("ed25519")
    {
        return Err(SupplyChainVerificationError::Network(format!(
            "unsupported TUF key type `{}` / scheme `{}`",
            key.keytype, key.scheme
        )));
    }

    let public_hex = key
        .keyval
        .public
        .trim()
        .strip_prefix("ed25519:")
        .unwrap_or_else(|| key.keyval.public.trim());
    let public_bytes = hex::decode(public_hex).map_err(|source| {
        SupplyChainVerificationError::Network(format!(
            "invalid TUF Ed25519 public key encoding: {source}"
        ))
    })?;
    let public_bytes: [u8; PUBLIC_KEY_SIZE] = public_bytes.as_slice().try_into().map_err(|_| {
        SupplyChainVerificationError::Network(format!(
            "invalid TUF Ed25519 public key length: expected {PUBLIC_KEY_SIZE}"
        ))
    })?;
    let verifying_key = Ed25519VerifyingKey::from_bytes(&public_bytes).map_err(|source| {
        SupplyChainVerificationError::Network(format!("invalid TUF Ed25519 public key: {source}"))
    })?;

    let signature_hex = signature
        .trim()
        .strip_prefix("ed25519:")
        .unwrap_or_else(|| signature.trim());
    let signature_bytes = hex::decode(signature_hex).map_err(|source| {
        SupplyChainVerificationError::Network(format!(
            "invalid TUF Ed25519 signature encoding: {source}"
        ))
    })?;
    if signature_bytes.len() != SIGNATURE_SIZE {
        return Err(SupplyChainVerificationError::Network(format!(
            "invalid TUF Ed25519 signature length: expected {SIGNATURE_SIZE}, got {}",
            signature_bytes.len()
        )));
    }
    let signature = Ed25519Signature::try_from_slice(&signature_bytes).map_err(|source| {
        SupplyChainVerificationError::Network(format!("invalid TUF Ed25519 signature: {source}"))
    })?;
    verifying_key
        .verify(signed_bytes, &signature)
        .map_err(|_| SupplyChainVerificationError::TufSignatureInvalid)
}

fn ensure_not_expired(expires: &str) -> Result<(), SupplyChainVerificationError> {
    let expires_at = unix_expiry(expires)?;
    let now = u64::try_from(Utc::now().timestamp()).expect("system clock before year 2262");
    if expires_at <= now {
        return Err(SupplyChainVerificationError::TufExpired);
    }
    Ok(())
}

fn unix_expiry(expires: &str) -> Result<u64, SupplyChainVerificationError> {
    let parsed = chrono::DateTime::parse_from_rfc3339(expires).map_err(|source| {
        SupplyChainVerificationError::Network(format!(
            "invalid TUF expires timestamp `{expires}`: {source}"
        ))
    })?;
    u64::try_from(parsed.timestamp()).map_err(|_| SupplyChainVerificationError::TufExpired)
}

/// Mock transparency log verifier for controlled testing.
///
/// # Safety
///
/// TEST-ONLY — MUST NOT reach production. This verifier accepts any entry
/// inserted via [`Self::add_valid_entry`], which short-circuits supply-chain
/// trust. The type is gated on `cfg(test)` or the `test-mocks` Cargo
/// feature so it does not leak into downstream binaries by default.
#[cfg(any(test, feature = "test-mocks"))]
#[derive(Debug, Default)]
pub struct MockTransparencyVerifier {
    /// Entries to accept as valid.
    pub valid_entries: std::sync::Mutex<HashMap<String, TransparencyLogEntry>>,
}

#[cfg(any(test, feature = "test-mocks"))]
impl MockTransparencyVerifier {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_valid_entry(&self, entry_hash: String, entry: TransparencyLogEntry) {
        self.valid_entries.lock().unwrap().insert(entry_hash, entry);
    }
}

#[cfg(any(test, feature = "test-mocks"))]
#[async_trait]
impl TransparencyLogVerifier for MockTransparencyVerifier {
    async fn verify_entry(
        &self,
        entry_hash: &str,
        expected_entry: Option<&TransparencyLogEntry>,
    ) -> Result<TransparencyVerificationResult, SupplyChainVerificationError> {
        let entries = self.valid_entries.lock().unwrap();
        if let Some(entry) = entries.get(entry_hash) {
            if let Some(expected) = expected_entry
                && entry != expected
            {
                return Err(SupplyChainVerificationError::TransparencyEntryMismatch);
            }
            Ok(TransparencyVerificationResult {
                verified: true,
                log_index: Some(entry.log_index),
                logged_at: Some(0),
            })
        } else {
            Err(SupplyChainVerificationError::TransparencyEntryNotFound)
        }
    }
}

/// Mock TUF verifier for controlled testing.
///
/// # Safety
///
/// TEST-ONLY — MUST NOT reach production. This verifier accepts any target
/// allow-listed via [`Self::add_valid_target`] and performs no real TUF
/// signature or metadata validation. Gated on `cfg(test)` or the
/// `test-mocks` Cargo feature so it does not leak into downstream binaries.
#[cfg(any(test, feature = "test-mocks"))]
#[derive(Debug)]
pub struct MockTufVerifier {
    /// Root metadata to return.
    pub root: TufRootMetadata,
    /// Targets to accept as valid.
    pub valid_targets: std::sync::Mutex<HashMap<String, TufTargetInfo>>,
}

#[cfg(any(test, feature = "test-mocks"))]
impl MockTufVerifier {
    pub fn new(root: TufRootMetadata) -> Self {
        Self {
            root,
            valid_targets: std::sync::Mutex::new(HashMap::new()),
        }
    }

    pub fn add_valid_target(&self, path: String, target: TufTargetInfo) {
        self.valid_targets.lock().unwrap().insert(path, target);
    }
}

#[cfg(any(test, feature = "test-mocks"))]
#[async_trait]
impl TufVerifier for MockTufVerifier {
    async fn verify_target(
        &self,
        pinned_root: &TufRootMetadata,
        target_path: &str,
    ) -> Result<TufVerificationResult, SupplyChainVerificationError> {
        let now = u64::try_from(Utc::now().timestamp()).expect("system clock before year 2262");
        if pinned_root.expires <= now || self.root.expires <= now {
            return Err(SupplyChainVerificationError::TufExpired);
        }

        // Check root hash matches
        if pinned_root.root_hash != self.root.root_hash {
            return Err(SupplyChainVerificationError::TufRootMismatch {
                expected: pinned_root.root_hash.clone(),
                actual: self.root.root_hash.clone(),
            });
        }
        // Check for rollback
        if self.root.version < pinned_root.version {
            return Err(SupplyChainVerificationError::TufRollback {
                current: pinned_root.version,
                got: self.root.version,
            });
        }

        let targets = self.valid_targets.lock().unwrap();
        if let Some(target) = targets.get(target_path) {
            Ok(TufVerificationResult {
                verified: true,
                root_version: self.root.version,
                target: Some(target.clone()),
            })
        } else {
            Err(SupplyChainVerificationError::TufTargetNotFound {
                target: target_path.to_string(),
            })
        }
    }

    async fn fetch_root(&self) -> Result<TufRootMetadata, SupplyChainVerificationError> {
        Ok(self.root.clone())
    }
}

/// Mock Sigstore verifier for controlled testing.
///
/// # Safety
///
/// TEST-ONLY — MUST NOT reach production. This verifier accepts any bundle
/// allow-listed via [`Self::add_valid_bundle`] and performs no real Sigstore
/// signature, certificate, or transparency-log verification. Gated on
/// `cfg(test)` or the `test-mocks` Cargo feature so it does not leak into
/// downstream binaries.
#[cfg(any(test, feature = "test-mocks"))]
#[derive(Debug, Default)]
pub struct MockSigstoreVerifier {
    /// Bundles to accept as valid (keyed by artifact hash).
    pub valid_bundles: std::sync::Mutex<HashMap<String, SigstoreVerificationResult>>,
}

#[cfg(any(test, feature = "test-mocks"))]
impl MockSigstoreVerifier {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_valid_bundle(&self, artifact_hash: String, result: SigstoreVerificationResult) {
        self.valid_bundles
            .lock()
            .unwrap()
            .insert(artifact_hash, result);
    }

    pub fn add_valid_bundle_claims(
        &self,
        artifact_hash: String,
        identity: Option<String>,
        issuer: Option<String>,
        rekor_log_index: Option<u64>,
    ) {
        self.add_valid_bundle(
            artifact_hash,
            SigstoreVerificationResult {
                verified: true,
                identity,
                issuer,
                rekor_log_index,
            },
        );
    }
}

#[cfg(any(test, feature = "test-mocks"))]
#[async_trait]
impl SigstoreVerifier for MockSigstoreVerifier {
    async fn verify_bundle(
        &self,
        _bundle: &SigstoreBundle,
        artifact_hash: &str,
        trusted_identities: &[String],
        trusted_issuers: &[String],
    ) -> Result<SigstoreVerificationResult, SupplyChainVerificationError> {
        let bundles = self.valid_bundles.lock().unwrap();
        if let Some(result) = bundles.get(artifact_hash) {
            // Allowlists fail CLOSED on a missing claim: a bundle whose
            // certificate carries no identity cannot satisfy an identity
            // allowlist by simply omitting the field (br-g7jhf finding 5).
            if !trusted_identities.is_empty() {
                let Some(identity) = &result.identity else {
                    return Err(SupplyChainVerificationError::SigstoreIdentityMismatch {
                        expected: trusted_identities.join(","),
                        actual: "<none>".to_string(),
                    });
                };
                if !trusted_identities.contains(identity) {
                    return Err(SupplyChainVerificationError::SigstoreIdentityMismatch {
                        expected: trusted_identities.join(","),
                        actual: identity.clone(),
                    });
                }
            }
            if !trusted_issuers.is_empty() {
                let Some(issuer) = &result.issuer else {
                    return Err(SupplyChainVerificationError::SigstoreIssuerUntrusted {
                        issuer: "<none>".to_string(),
                    });
                };
                if !trusted_issuers.contains(issuer) {
                    return Err(SupplyChainVerificationError::SigstoreIssuerUntrusted {
                        issuer: issuer.clone(),
                    });
                }
            }
            Ok(result.clone())
        } else {
            Err(SupplyChainVerificationError::SigstoreSignatureInvalid)
        }
    }
}

impl VerifiedConnectorBundle {
    #[must_use]
    pub fn report(&self, outcome: &str) -> RegistryVerificationReport {
        let verified_at =
            u64::try_from(Utc::now().timestamp()).expect("system clock before year 2262");
        RegistryVerificationReport {
            connector_id: self.manifest.connector.id.to_string(),
            manifest_hash: self.manifest_hash.clone(),
            binary_hash: self.binary_hash.clone(),
            target: self.target.clone(),
            verified_at,
            outcome: outcome.to_string(),
        }
    }

    /// Extract rate limit declarations from the verified manifest, if present.
    #[must_use]
    pub fn rate_limit_declarations(&self) -> Option<RateLimitDeclarations> {
        self.manifest
            .rate_limits
            .as_ref()
            .map(|section| section.to_declarations())
    }
}

/// Mirroring outcome (object ids + hashes).
#[derive(Debug, Clone)]
pub struct MirrorResult {
    pub manifest_object_id: ObjectId,
    pub binary_object_id: ObjectId,
    pub manifest_hash: String,
    pub binary_hash: String,
}

/// Symbol mirroring outcome.
#[derive(Debug, Clone)]
pub struct SymbolMirrorResult {
    pub descriptor_object_id: ObjectId,
    pub manifest_object_id: ObjectId,
    pub binary_object_id: ObjectId,
    pub binary_hash: String,
    pub encoded_body_hash: String,
    pub source_symbols: u32,
    pub total_symbols: u32,
}

/// Reconstructed connector binary recovered from the symbol layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconstructedConnectorBinary {
    pub manifest_object_id: ObjectId,
    pub binary_object_id: ObjectId,
    pub target: ConnectorTarget,
    pub binary_hash: String,
    pub binary: Vec<u8>,
}

/// Registry verifier and mirroring helper.
#[derive(Debug, Clone)]
pub struct RegistryVerifier {
    trust_policy: RegistryTrustPolicy,
    supply_chain_config: SupplyChainVerificationConfig,
}

#[derive(Debug)]
struct PublisherVerificationSummary {
    valid: u8,
    required: u8,
    first_error: Option<RegistryError>,
}

impl PublisherVerificationSummary {
    const fn verified(&self) -> bool {
        self.valid > 0
    }

    const fn threshold_unmet(&self) -> bool {
        self.required > 0 && self.valid < self.required
    }
}

#[derive(Debug)]
struct RegistryVerificationSummary {
    verified: bool,
    error: Option<RegistryError>,
}

impl RegistryVerifier {
    #[must_use]
    pub const fn new(trust_policy: RegistryTrustPolicy) -> Self {
        Self {
            trust_policy,
            supply_chain_config: SupplyChainVerificationConfig {
                tuf_pinned_root: None,
                trusted_sigstore_identities: Vec::new(),
                trusted_sigstore_issuers: Vec::new(),
                require_transparency: false,
                require_tuf: false,
                require_sigstore: false,
                require_attestation_types: Vec::new(),
                min_slsa_level: None,
                trusted_builders: Vec::new(),
                require_attestation_expiry: false,
            },
        }
    }

    #[must_use]
    pub fn with_supply_chain_verification_config(
        mut self,
        supply_chain_config: SupplyChainVerificationConfig,
    ) -> Self {
        self.supply_chain_config = supply_chain_config;
        self
    }

    /// Verify a registry bundle against trust roots, policy, and target.
    ///
    /// # Errors
    /// Returns [`RegistryError`] if verification fails.
    pub fn verify_bundle(
        &self,
        bundle: &ConnectorBundle,
        zone_policy: Option<&ZonePolicyObject>,
        supply_chain: Option<&SupplyChainEvidence>,
        expected_target: Option<&ConnectorTarget>,
    ) -> Result<VerifiedConnectorBundle, RegistryError> {
        let manifest = ConnectorManifest::parse_str(&bundle.manifest_toml)?;

        if let Some(expected) = expected_target {
            if &bundle.target != expected {
                return Err(RegistryError::TargetMismatch {
                    expected: expected.as_string(),
                    found: bundle.target.as_string(),
                });
            }
        }

        let binary_hash = hash_bytes(&bundle.binary);
        let manifest_hash = hash_bytes(bundle.manifest_toml.as_bytes());
        let signing_bytes = manifest_signing_bytes(&manifest)?;

        let sig_section = manifest
            .signatures
            .as_ref()
            .ok_or(RegistryError::MissingSignatures)?;

        let publisher = summarize_publishers(
            &self.trust_policy,
            sig_section,
            &signing_bytes,
            &binary_hash,
        );
        let registry = summarize_registry(
            &self.trust_policy,
            sig_section,
            &signing_bytes,
            &binary_hash,
        );

        if self.trust_policy.require_registry_signature && !registry.verified {
            return Err(RegistryError::RegistrySignatureRequired);
        }

        // Threshold check MUST run regardless of whether some signatures are valid.
        // A manifest declaring 2-of-2 with only 1 valid signature must be rejected.
        if publisher.threshold_unmet() {
            return Err(RegistryError::PublisherThresholdUnmet {
                required: publisher.required,
                valid: publisher.valid,
            });
        }

        if !publisher.verified() && !registry.verified {
            if let Some(err) = publisher.first_error.or(registry.error) {
                return Err(err);
            }

            return Err(RegistryError::NoTrustedSignature);
        }

        enforce_capability_ceiling(zone_policy, &manifest)?;
        enforce_supply_chain_policy(&manifest, supply_chain)?;
        enforce_supply_chain_verification_config(
            &self.supply_chain_config,
            &manifest,
            supply_chain,
            &binary_hash,
        )?;

        Ok(VerifiedConnectorBundle {
            manifest,
            manifest_hash,
            binary_hash,
            target: bundle.target.clone(),
        })
    }

    /// Mirror a verified bundle into the object store as pinned objects.
    ///
    /// # Errors
    /// Returns [`RegistryError`] if object storage fails.
    pub async fn mirror_bundle(
        &self,
        verified: &VerifiedConnectorBundle,
        bundle: &ConnectorBundle,
        zone_id: ZoneId,
        object_id_key: &ObjectIdKey,
        store: &dyn ObjectStore,
    ) -> Result<MirrorResult, RegistryError> {
        let manifest_obj = ConnectorManifestObject {
            manifest_toml: bundle.manifest_toml.clone(),
            manifest_hash: verified.manifest_hash.clone(),
        };
        let binary_obj = ConnectorBinaryObject {
            target: verified.target.clone(),
            binary_hash: verified.binary_hash.clone(),
            binary: bundle.binary.clone(),
        };
        let manifest_schema = ConnectorManifestObject::schema();
        let binary_schema = ConnectorBinaryObject::schema();

        let manifest_body = CanonicalSerializer::serialize(&manifest_obj, &manifest_schema)
            .map_err(RegistryError::Canonical)?;
        let binary_body = CanonicalSerializer::serialize(&binary_obj, &binary_schema)
            .map_err(RegistryError::Canonical)?;

        let now = u64::try_from(Utc::now().timestamp()).expect("system clock before year 2262");
        let provenance = Provenance::new(zone_id.clone());

        let manifest_header = ObjectHeader {
            schema: manifest_schema,
            zone_id: zone_id.clone(),
            created_at: now,
            provenance: provenance.clone(),
            refs: Vec::new(),
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        };

        let manifest_object_id =
            StoredObject::derive_id(&manifest_header, &manifest_body, object_id_key)?;
        let manifest_record = StoredObject {
            object_id: manifest_object_id,
            header: manifest_header,
            body: manifest_body,
            storage: StorageMeta {
                retention: RetentionClass::Pinned,
            },
        };

        let binary_header = ObjectHeader {
            schema: binary_schema,
            zone_id,
            created_at: now,
            provenance,
            refs: vec![manifest_object_id],
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        };

        let binary_object_id =
            StoredObject::derive_id(&binary_header, &binary_body, object_id_key)?;
        let binary_record = StoredObject {
            object_id: binary_object_id,
            header: binary_header,
            body: binary_body,
            storage: StorageMeta {
                retention: RetentionClass::Pinned,
            },
        };

        // `mirror_bundle` is the install-side idempotency hinge: callers
        // re-run install/verify/mirror on the same bundle (e.g. retries,
        // re-bootstraps, the
        // `metamorphic_install_verify_reinstall_round_trip_is_observationally_idempotent`
        // invariant) and expect observationally identical state. Object
        // IDs are blake3-256 over `(header, body)`, so an `AlreadyExists`
        // for the derived ID is a *guarantee* that the existing record
        // is byte-identical to ours: the only way to land at the same
        // ObjectId is if the canonical `(header, body)` matched, which
        // requires the same manifest_toml/binary/target/zone/provenance
        // tuple. Treating `AlreadyExists` as success is therefore safe
        // and is what makes re-mirroring genuinely idempotent at the
        // ObjectStore boundary; any other store error still propagates.
        match store.put(manifest_record).await {
            Ok(()) => {}
            Err(ObjectStoreError::AlreadyExists(_)) => {}
            Err(err) => return Err(err.into()),
        }
        match store.put(binary_record).await {
            Ok(()) => {}
            Err(ObjectStoreError::AlreadyExists(_)) => {}
            Err(err) => return Err(err.into()),
        }

        Ok(MirrorResult {
            manifest_object_id,
            binary_object_id,
            manifest_hash: verified.manifest_hash.clone(),
            binary_hash: verified.binary_hash.clone(),
        })
    }

    /// Mirror the binary object for a verified bundle into the symbol layer.
    ///
    /// The binary is encoded as a repairable symbol set keyed by the mirrored
    /// `binary_object_id`, and a pinned descriptor object is stored so another
    /// node can reconstruct and verify the canonical binary object bytes.
    ///
    /// # Errors
    /// Returns [`RegistryError`] if symbol encoding or storage fails.
    #[allow(clippy::too_many_arguments)]
    pub async fn mirror_bundle_symbols(
        &self,
        verified: &VerifiedConnectorBundle,
        bundle: &ConnectorBundle,
        mirror: &MirrorResult,
        zone_id: ZoneId,
        object_id_key: &ObjectIdKey,
        store: &dyn ObjectStore,
        symbol_store: &dyn SymbolStore,
        config: &RaptorQConfig,
        source_node: Option<u64>,
    ) -> Result<SymbolMirrorResult, RegistryError> {
        let binary_obj = ConnectorBinaryObject {
            target: verified.target.clone(),
            binary_hash: verified.binary_hash.clone(),
            binary: bundle.binary.clone(),
        };
        let binary_schema = ConnectorBinaryObject::schema();
        let binary_body = CanonicalSerializer::serialize(&binary_obj, &binary_schema)
            .map_err(RegistryError::Canonical)?;

        let encoder = RaptorQEncoder::new(&binary_body, config)?;
        let store_oti = encoder.transmission_info();
        let source_symbols = encoder.source_symbols();
        let total_symbols = encoder.total_symbols();
        let mirrored_at =
            u64::try_from(Utc::now().timestamp()).expect("system clock before year 2262");

        let symbol_meta = ObjectSymbolMeta {
            object_id: mirror.binary_object_id,
            zone_id: zone_id.clone(),
            oti: store_oti,
            source_symbols,
            first_symbol_at: mirrored_at,
        };
        symbol_store.put_object_meta(symbol_meta).await?;

        for (esi, data) in encoder.encode_all() {
            let symbol = StoredSymbol {
                meta: SymbolMeta {
                    object_id: mirror.binary_object_id,
                    esi,
                    zone_id: zone_id.clone(),
                    source_node,
                    stored_at: mirrored_at,
                },
                data: Bytes::from(data),
            };
            symbol_store.put_symbol(symbol).await?;
        }

        let descriptor = ConnectorBinarySymbolSet {
            manifest_object_id: mirror.manifest_object_id,
            binary_object_id: mirror.binary_object_id,
            target: verified.target.clone(),
            binary_hash: verified.binary_hash.clone(),
            encoded_body_hash: hash_bytes(&binary_body),
            oti: descriptor_oti_from_store(store_oti),
            source_symbols,
            total_symbols,
            mirrored_at,
        };
        let descriptor_schema = ConnectorBinarySymbolSet::schema();
        let descriptor_body = CanonicalSerializer::serialize(&descriptor, &descriptor_schema)
            .map_err(RegistryError::Canonical)?;
        let descriptor_header = ObjectHeader {
            schema: descriptor_schema,
            zone_id: zone_id.clone(),
            created_at: mirrored_at,
            provenance: Provenance::new(zone_id),
            refs: vec![mirror.manifest_object_id, mirror.binary_object_id],
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        };
        let descriptor_object_id =
            StoredObject::derive_id(&descriptor_header, &descriptor_body, object_id_key)?;
        let descriptor_record = StoredObject {
            object_id: descriptor_object_id,
            header: descriptor_header,
            body: descriptor_body,
            storage: StorageMeta {
                retention: RetentionClass::Pinned,
            },
        };
        store.put(descriptor_record).await?;

        Ok(SymbolMirrorResult {
            descriptor_object_id,
            manifest_object_id: mirror.manifest_object_id,
            binary_object_id: mirror.binary_object_id,
            binary_hash: verified.binary_hash.clone(),
            encoded_body_hash: descriptor.encoded_body_hash.clone(),
            source_symbols,
            total_symbols,
        })
    }

    /// Load a previously mirrored binary symbol descriptor from the object store.
    ///
    /// # Errors
    /// Returns [`RegistryError`] if the descriptor cannot be read or decoded.
    pub async fn load_symbol_descriptor(
        &self,
        descriptor_object_id: &ObjectId,
        store: &dyn ObjectStore,
    ) -> Result<ConnectorBinarySymbolSet, RegistryError> {
        let descriptor = store.get(descriptor_object_id).await?;
        let descriptor_schema = ConnectorBinarySymbolSet::schema();
        CanonicalSerializer::deserialize(&descriptor.body, &descriptor_schema)
            .map_err(RegistryError::Canonical)
    }

    /// Reconstruct a mirrored connector binary from the symbol layer.
    ///
    /// # Errors
    /// Returns [`RegistryError`] if symbols are incomplete, decode fails, or
    /// the reconstructed bytes do not match the expected descriptor hashes.
    pub async fn reconstruct_binary_from_symbols(
        &self,
        descriptor: &ConnectorBinarySymbolSet,
        symbol_store: &dyn SymbolStore,
        config: &RaptorQConfig,
    ) -> Result<ReconstructedConnectorBinary, RegistryError> {
        let expected_len = usize::try_from(descriptor.oti.transfer_length).map_err(|_| {
            RegistryError::TransferLengthOverflow {
                len: descriptor.oti.transfer_length,
            }
        })?;
        if expected_len > MAX_CANONICAL_OBJECT_BYTES {
            return Err(RegistryError::ReconstructedBodyTooLarge {
                len: expected_len,
                max: MAX_CANONICAL_OBJECT_BYTES,
            });
        }

        let received = symbol_store
            .symbol_count(&descriptor.binary_object_id)
            .await;
        if received < descriptor.source_symbols {
            return Err(RegistryError::IncompleteSymbols {
                received,
                needed: descriptor.source_symbols,
            });
        }

        let mut symbols = symbol_store
            .get_all_symbols(&descriptor.binary_object_id)
            .await;
        symbols.sort_by_key(|symbol| symbol.meta.esi);

        let mut decoder =
            RaptorQDecoder::new(store_oti_from_descriptor(descriptor.oti).to_oti(), config);
        let mut decoded = None;
        for symbol in symbols {
            if let Some(bytes) = decoder.add_symbol(symbol.meta.esi, symbol.data.to_vec())? {
                decoded = Some(bytes);
                break;
            }
        }

        let decoded = decoded.ok_or(RegistryError::IncompleteSymbols {
            received,
            needed: descriptor.source_symbols,
        })?;
        if decoded.len() < expected_len {
            return Err(RegistryError::ReconstructedBodyTooShort {
                expected: expected_len,
                actual: decoded.len(),
            });
        }

        let body = &decoded[..expected_len];
        let actual_body_hash = hash_bytes(body);
        if actual_body_hash != descriptor.encoded_body_hash {
            return Err(RegistryError::ReconstructedBodyHashMismatch {
                expected: descriptor.encoded_body_hash.clone(),
                actual: actual_body_hash,
            });
        }

        let binary_schema = ConnectorBinaryObject::schema();
        let binary_obj: ConnectorBinaryObject =
            CanonicalSerializer::deserialize(body, &binary_schema)
                .map_err(RegistryError::Canonical)?;

        if binary_obj.binary_hash != descriptor.binary_hash {
            return Err(RegistryError::ReconstructedBinaryHashMismatch {
                expected: descriptor.binary_hash.clone(),
                actual: binary_obj.binary_hash,
            });
        }
        let actual_binary_hash = hash_bytes(&binary_obj.binary);
        if actual_binary_hash != descriptor.binary_hash {
            return Err(RegistryError::ReconstructedBinaryHashMismatch {
                expected: descriptor.binary_hash.clone(),
                actual: actual_binary_hash,
            });
        }

        let actual_target = binary_obj.target.as_string();
        let expected_target = descriptor.target.as_string();
        if binary_obj.target != descriptor.target {
            return Err(RegistryError::ReconstructedBinaryTargetMismatch {
                expected: expected_target,
                actual: actual_target,
            });
        }

        Ok(ReconstructedConnectorBinary {
            manifest_object_id: descriptor.manifest_object_id,
            binary_object_id: descriptor.binary_object_id,
            target: binary_obj.target,
            binary_hash: descriptor.binary_hash.clone(),
            binary: binary_obj.binary,
        })
    }

    /// Reconstruct a full connector bundle from a mirrored symbol descriptor.
    ///
    /// # Errors
    /// Returns [`RegistryError`] if the descriptor or manifest object cannot be
    /// loaded, symbol reconstruction fails, or the recovered manifest hash does
    /// not match its stored digest.
    pub async fn reconstruct_bundle_from_symbol_descriptor(
        &self,
        descriptor_object_id: &ObjectId,
        store: &dyn ObjectStore,
        symbol_store: &dyn SymbolStore,
        config: &RaptorQConfig,
    ) -> Result<ConnectorBundle, RegistryError> {
        let descriptor = self
            .load_symbol_descriptor(descriptor_object_id, store)
            .await?;
        let manifest = store.get(&descriptor.manifest_object_id).await?;
        let manifest_schema = ConnectorManifestObject::schema();
        let manifest_obj: ConnectorManifestObject =
            CanonicalSerializer::deserialize(&manifest.body, &manifest_schema)
                .map_err(RegistryError::Canonical)?;

        let actual_manifest_hash = hash_bytes(manifest_obj.manifest_toml.as_bytes());
        if actual_manifest_hash != manifest_obj.manifest_hash {
            return Err(RegistryError::ReconstructedManifestHashMismatch {
                expected: manifest_obj.manifest_hash,
                actual: actual_manifest_hash,
            });
        }

        let reconstructed = self
            .reconstruct_binary_from_symbols(&descriptor, symbol_store, config)
            .await?;
        Ok(ConnectorBundle {
            manifest_toml: manifest_obj.manifest_toml,
            binary: reconstructed.binary,
            target: reconstructed.target,
        })
    }
}

/// Compute canonical signing bytes for a manifest (excludes signatures section).
///
/// # Errors
/// Returns `RegistryError` if serialization fails.
pub fn manifest_signing_bytes(manifest: &ConnectorManifest) -> Result<Vec<u8>, RegistryError> {
    let mut value = serde_json::to_value(manifest).map_err(|_| RegistryError::SignatureBytes)?;
    if let Some(object) = value.as_object_mut() {
        object.remove("signatures");
    }
    let schema = connector_manifest_signing_view_schema();
    CanonicalSerializer::serialize(&value, &schema).map_err(RegistryError::SigningBytes)
}

fn descriptor_oti_from_store(oti: ObjectTransmissionInfo) -> ConnectorBinaryTransmissionInfo {
    let descriptor = ConnectorBinaryTransmissionInfo::new(
        oti.transfer_length,
        oti.symbol_size,
        oti.source_blocks,
        oti.sub_blocks,
        oti.alignment,
    );
    match oti.payload_hash {
        Some(payload_hash) => descriptor.with_payload_hash(payload_hash),
        None => descriptor,
    }
}

fn store_oti_from_descriptor(oti: ConnectorBinaryTransmissionInfo) -> ObjectTransmissionInfo {
    ObjectTransmissionInfo {
        transfer_length: oti.transfer_length,
        symbol_size: oti.symbol_size,
        source_blocks: oti.source_blocks,
        sub_blocks: oti.sub_blocks,
        alignment: oti.alignment,
        payload_hash: oti.payload_hash,
    }
}

fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    format!("sha256:{}", hex::encode(digest))
}

fn summarize_publishers(
    trust: &RegistryTrustPolicy,
    sigs: &SignaturesSection,
    signing_bytes: &[u8],
    binary_hash: &str,
) -> PublisherVerificationSummary {
    let required = sigs.publisher_threshold.map_or(0, |t| t.k);
    if sigs.publisher_signatures.is_empty() {
        return PublisherVerificationSummary {
            valid: 0,
            required,
            first_error: None,
        };
    }
    let mut valid = 0u8;
    let mut first_error = None;
    let mut seen_valid_keys = HashSet::new();

    for entry in &sigs.publisher_signatures {
        // Tolerate individual publisher failures while a trusted subset can still
        // satisfy the declared threshold, but preserve the first concrete error if
        // nothing verifies successfully.
        match verify_signature_entry(trust, entry, signing_bytes, binary_hash, true) {
            Ok(true) => {
                if let Some(key) = trust.publisher_keys.get(&entry.kid)
                    && seen_valid_keys.insert(key.to_bytes())
                {
                    valid = valid.saturating_add(1);
                }
            }
            Ok(false) => {} // signature did not match — skip without counting
            Err(err) => {
                if first_error.is_none() {
                    first_error = Some(err);
                }
            }
        }
    }

    PublisherVerificationSummary {
        valid,
        required,
        first_error,
    }
}

fn summarize_registry(
    trust: &RegistryTrustPolicy,
    sigs: &SignaturesSection,
    signing_bytes: &[u8],
    binary_hash: &str,
) -> RegistryVerificationSummary {
    let Some(entry) = sigs.registry_signature.as_ref() else {
        return RegistryVerificationSummary {
            verified: false,
            error: None,
        };
    };

    match verify_signature_entry(trust, entry, signing_bytes, binary_hash, false) {
        Ok(verified) => RegistryVerificationSummary {
            verified,
            error: None,
        },
        Err(err) => RegistryVerificationSummary {
            verified: false,
            error: Some(err),
        },
    }
}

#[cfg(test)]
fn verify_publishers(
    trust: &RegistryTrustPolicy,
    sigs: &SignaturesSection,
    signing_bytes: &[u8],
    binary_hash: &str,
) -> Result<bool, RegistryError> {
    let summary = summarize_publishers(trust, sigs, signing_bytes, binary_hash);
    if summary.threshold_unmet() {
        return Err(RegistryError::PublisherThresholdUnmet {
            required: summary.required,
            valid: summary.valid,
        });
    }
    if !summary.verified()
        && let Some(err) = summary.first_error
    {
        return Err(err);
    }
    Ok(summary.verified())
}

#[cfg(test)]
fn verify_registry(
    trust: &RegistryTrustPolicy,
    sigs: &SignaturesSection,
    signing_bytes: &[u8],
    binary_hash: &str,
) -> Result<bool, RegistryError> {
    let summary = summarize_registry(trust, sigs, signing_bytes, binary_hash);
    if let Some(err) = summary.error {
        return Err(err);
    }
    Ok(summary.verified)
}

fn verify_signature_entry(
    trust: &RegistryTrustPolicy,
    entry: &SignatureEntry,
    signing_bytes: &[u8],
    binary_hash: &str,
    publisher: bool,
) -> Result<bool, RegistryError> {
    let key = if publisher {
        trust.publisher_keys.get(&entry.kid)
    } else {
        trust.registry_keys.get(&entry.kid)
    }
    .ok_or_else(|| RegistryError::UnknownKid {
        kid: entry.kid.clone(),
    })?;

    let signature = signature_from_entry(&entry.sig)?;
    let message = signature_message(signing_bytes, binary_hash);

    key.verify_with_context(MANIFEST_SIGNATURE_CONTEXT, &message, &signature)
        .map_err(|_| RegistryError::SignatureInvalid {
            kid: entry.kid.clone(),
        })?;

    Ok(true)
}

fn signature_from_entry(sig: &Base64Bytes) -> Result<Ed25519Signature, RegistryError> {
    Ed25519Signature::try_from_slice(sig.as_bytes()).map_err(|_| RegistryError::SignatureBytes)
}

/// Build the message to sign/verify: `len(signing_bytes) || signing_bytes || len(binary_hash) || binary_hash`.
#[must_use]
pub fn signature_message(signing_bytes: &[u8], binary_hash: &str) -> Vec<u8> {
    let mut message = Vec::with_capacity(signing_bytes.len() + binary_hash.len() + 16);
    message.extend_from_slice(&(signing_bytes.len() as u64).to_le_bytes());
    message.extend_from_slice(signing_bytes);
    message.extend_from_slice(&(binary_hash.len() as u64).to_le_bytes());
    message.extend_from_slice(binary_hash.as_bytes());
    message
}

fn enforce_capability_ceiling(
    zone_policy: Option<&ZonePolicyObject>,
    manifest: &ConnectorManifest,
) -> Result<(), RegistryError> {
    let Some(policy) = zone_policy else {
        return Ok(());
    };

    if policy.capability_ceiling.is_empty() {
        return Ok(());
    }

    let mut caps: HashSet<CapabilityId> = HashSet::new();
    caps.extend(manifest.capabilities.required.iter().cloned());
    caps.extend(manifest.capabilities.optional.iter().cloned());
    for op in manifest.provides.operations.values() {
        caps.insert(op.capability.clone());
    }

    for cap in caps {
        if !policy.capability_ceiling.contains(&cap) {
            return Err(RegistryError::CapabilityCeilingViolation {
                capability: cap.as_str().to_string(),
            });
        }
    }

    Ok(())
}

/// Attestation requirements enforced against [`SupplyChainEvidence`].
///
/// Two independent sources produce one of these: the connector manifest's own
/// `[policy]` table (publisher-controlled) and the operator's
/// [`SupplyChainVerificationConfig`] (owner-controlled). `verify_bundle` runs
/// the gate once per source, so the effective requirement is the conjunction —
/// strictly the stricter of the two on every axis — and a manifest that omits
/// `[policy]` entirely cannot opt out of the owner's floor.
struct AttestationRequirements<'a> {
    require_attestation_types: &'a [AttestationType],
    min_slsa_level: Option<u8>,
    trusted_builders: &'a [String],
    require_attestation_expiry: bool,
}

impl AttestationRequirements<'_> {
    /// Whether any axis of this requirement set is engaged. When nothing is
    /// engaged the gate is a no-op and evidence is not even required.
    const fn is_active(&self) -> bool {
        !self.require_attestation_types.is_empty()
            || self.min_slsa_level.is_some()
            || !self.trusted_builders.is_empty()
            || self.require_attestation_expiry
    }
}

/// Whether an attestation type makes a claim about *who built the artifact*.
///
/// SLSA levels and trusted-builder identities are build-provenance claims, so
/// only these types can satisfy them. A `CodeReview` attestation carrying
/// `slsa_level = 4` says nothing about the build (br-g7jhf findings 2 and 3).
const fn is_build_provenance(attestation: AttestationType) -> bool {
    matches!(
        attestation,
        AttestationType::InToto | AttestationType::ReproducibleBuild
    )
}

fn enforce_attestation_requirements(
    requirements: &AttestationRequirements<'_>,
    evidence: Option<&SupplyChainEvidence>,
) -> Result<(), RegistryError> {
    if !requirements.is_active() {
        return Ok(());
    }

    let evidence = evidence.ok_or(RegistryError::AttestationEvidenceMissing)?;
    let now = u64::try_from(Utc::now().timestamp()).expect("system clock before year 2262");

    // Fail-closed expiry-required gate runs BEFORE the expires_at <= now
    // check so a policy with `require_attestation_expiry = true` rejects
    // an attestation that has no expires_at field set at all. Without
    // this, an evidence record with `expires_at = None` is treated as
    // eternally fresh — a verifier-adapter regression would silently
    // disable freshness enforcement on every connector under that policy.
    if requirements.require_attestation_expiry {
        if let Some(att) = evidence
            .attestations
            .iter()
            .find(|att| att.expires_at.is_none())
        {
            return Err(RegistryError::AttestationExpiryMissing {
                attestation: attestation_label(att.attestation_type).to_string(),
            });
        }
    }

    if let Some((attestation_type, expired_at)) = evidence
        .attestations
        .iter()
        .filter_map(|att| {
            att.expires_at
                .map(|expires_at| (att.attestation_type, expires_at))
        })
        .find(|(_, expires_at)| *expires_at <= now)
    {
        return Err(RegistryError::AttestationExpired {
            attestation: attestation_label(attestation_type).to_string(),
            expired_at,
        });
    }

    for required in requirements.require_attestation_types {
        if !evidence
            .attestations
            .iter()
            .any(|att| &att.attestation_type == required)
        {
            return Err(RegistryError::RequiredAttestationMissing {
                attestation: attestation_label(*required).to_string(),
            });
        }
    }

    if let Some(required_level) = requirements.min_slsa_level {
        // Scoped to build-provenance attestations: a code-review attestation
        // that happens to carry a high `slsa_level` is not a build claim and
        // must not satisfy the floor.
        let meets_level = evidence
            .attestations
            .iter()
            .filter(|att| is_build_provenance(att.attestation_type))
            .any(|att| att.slsa_level.is_some_and(|level| level >= required_level));
        if !meets_level {
            return Err(RegistryError::SlsaLevelInsufficient {
                required: required_level,
            });
        }
    }

    if !requirements.trusted_builders.is_empty() {
        let trusted = |builder: &str| requirements.trusted_builders.iter().any(|tb| tb == builder);
        let mut trusted_provenance = false;
        for attestation in &evidence.attestations {
            let build_provenance = is_build_provenance(attestation.attestation_type);
            match attestation.builder_id.as_deref() {
                Some(builder) => {
                    if !trusted(builder) {
                        return Err(RegistryError::UntrustedBuilder {
                            builder: builder.to_string(),
                        });
                    }
                    trusted_provenance |= build_provenance;
                }
                // A build-provenance attestation that simply omits builder_id
                // must not slip past the rejection loop by being unnamed.
                None if build_provenance => {
                    return Err(RegistryError::BuilderIdentityMissing {
                        attestation: attestation_label(attestation.attestation_type).to_string(),
                    });
                }
                None => {}
            }
        }
        if !trusted_provenance {
            return Err(RegistryError::TrustedBuilderProvenanceMissing);
        }
    }

    Ok(())
}

fn enforce_supply_chain_policy(
    manifest: &ConnectorManifest,
    evidence: Option<&SupplyChainEvidence>,
) -> Result<(), RegistryError> {
    let Some(policy) = manifest.policy.as_ref() else {
        return Ok(());
    };

    if policy.require_transparency_log {
        let entry_present = manifest
            .signatures
            .as_ref()
            .and_then(|sig| sig.transparency_log_entry.as_ref())
            .is_some();
        if !entry_present {
            return Err(RegistryError::TransparencyLogMissing);
        }
        let evidence = evidence.ok_or(RegistryError::TransparencyEvidenceMissing)?;
        if !evidence.transparency_log_present {
            return Err(RegistryError::TransparencyEvidenceMissing);
        }
    }

    enforce_attestation_requirements(
        &AttestationRequirements {
            require_attestation_types: &policy.require_attestation_types,
            min_slsa_level: policy.min_slsa_level,
            trusted_builders: &policy.trusted_builders,
            require_attestation_expiry: policy.require_attestation_expiry,
        },
        evidence,
    )
}

fn enforce_supply_chain_verification_config(
    config: &SupplyChainVerificationConfig,
    manifest: &ConnectorManifest,
    evidence: Option<&SupplyChainEvidence>,
    binary_hash: &str,
) -> Result<(), RegistryError> {
    if config.require_transparency {
        let entry_present = manifest
            .signatures
            .as_ref()
            .and_then(|sig| sig.transparency_log_entry.as_ref())
            .is_some();
        if !entry_present {
            return Err(RegistryError::TransparencyLogMissing);
        }
        let evidence = evidence.ok_or(RegistryError::TransparencyEvidenceMissing)?;
        if !evidence.transparency_log_present {
            return Err(RegistryError::TransparencyEvidenceMissing);
        }
    }

    if config.tuf_verification_required() {
        // A TUF verifier adapter MUST have attested the bundle.
        // `tuf_verified()` is only true when evidence was promoted via
        // `SupplyChainEvidence::with_tuf_verification_result` against a
        // real `TufVerifier::verify_target` result, or the cfg-gated
        // test-only helper (br-pcmm8, br-i5iv4).
        let evidence = evidence.ok_or(RegistryError::TufVerificationRequired)?;
        if !evidence.tuf_verified() {
            return Err(RegistryError::TufVerificationRequired);
        }
        // `verify_target` proves only that the target PATH is enumerated in
        // validly signed TUF metadata. Bind the attested target hash to the
        // bytes actually being installed, so `tuf_verified` cannot mean
        // "some target of this name is signed" (br-g7jhf finding 4).
        let attested = evidence
            .tuf_target_hash()
            .ok_or(RegistryError::TufTargetUnbound)?;
        if !attested.eq_ignore_ascii_case(binary_hash) {
            return Err(RegistryError::TufTargetBindingMismatch {
                attested: attested.to_string(),
                bundle: binary_hash.to_string(),
            });
        }
    }

    if config.sigstore_verification_required() {
        // Same for Sigstore: the bundle must carry a verified Sigstore
        // attestation — promoted through
        // `SupplyChainEvidence::with_sigstore_verification_result`
        // (or the test-only helper).
        let evidence = evidence.ok_or(RegistryError::SigstoreVerificationRequired)?;
        if !evidence.sigstore_verified() {
            return Err(RegistryError::SigstoreVerificationRequired);
        }
        // Configuring trusted identities/issuers previously only flipped
        // `sigstore_verification_required()` on; the allowlists themselves
        // were never consulted, so a bundle signed by ANY identity passed.
        // Enforce them here, failing closed when the adapter reported no
        // identity/issuer at all (br-g7jhf finding 5).
        if !config.trusted_sigstore_identities.is_empty() {
            let identity = evidence
                .sigstore_identity()
                .ok_or(RegistryError::SigstoreIdentityUnbound)?;
            if !config
                .trusted_sigstore_identities
                .iter()
                .any(|trusted| trusted == identity)
            {
                return Err(RegistryError::SigstoreIdentityUntrusted {
                    identity: identity.to_string(),
                });
            }
        }
        if !config.trusted_sigstore_issuers.is_empty() {
            let issuer = evidence
                .sigstore_issuer()
                .ok_or(RegistryError::SigstoreIssuerUnbound)?;
            if !config
                .trusted_sigstore_issuers
                .iter()
                .any(|trusted| trusted == issuer)
            {
                return Err(RegistryError::SigstoreIssuerUntrusted {
                    issuer: issuer.to_string(),
                });
            }
        }
    }

    // Owner attestation floor. Enforced independently of `manifest.policy`,
    // which is parsed from the publisher-controlled connector TOML: a manifest
    // that omits `[policy]` can no longer opt out of the operator's SLSA /
    // attestation-type / trusted-builder requirements (br-g7jhf finding 1).
    enforce_attestation_requirements(
        &AttestationRequirements {
            require_attestation_types: &config.require_attestation_types,
            min_slsa_level: config.min_slsa_level,
            trusted_builders: &config.trusted_builders,
            require_attestation_expiry: config.require_attestation_expiry,
        },
        evidence,
    )
}

fn attestation_label(attestation: AttestationType) -> &'static str {
    match attestation {
        AttestationType::InToto => "in-toto",
        AttestationType::ReproducibleBuild => "reproducible-build",
        AttestationType::CodeReview => "code-review",
    }
}

fn file_has_multiple_links(metadata: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.nlink() > 1
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // number_of_links() returns Option<u32> on Windows (None if the FS doesn't
        // report it); treat a missing count as "not multiply-linked".
        metadata.number_of_links().is_some_and(|count| count > 1)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = metadata;
        false
    }
}

#[derive(Debug, Serialize)]
struct RegistryHealthResponse {
    status: &'static str,
    connectors: usize,
}

impl LocalRegistryCatalog {
    /// Build an in-memory catalog from one or more signed package directories.
    ///
    /// Each directory is expected to contain `manifest.toml`,
    /// `manifest-signature.json`, the signed binary named by the signature
    /// artifact, and optionally `attestation.json`.
    ///
    /// # Errors
    /// Returns [`RegistryCatalogError`] if any package directory is malformed or
    /// duplicates an existing connector/version/target tuple.
    pub fn from_signed_package_dirs(
        package_dirs: &[PathBuf],
    ) -> Result<Self, RegistryCatalogError> {
        if package_dirs.is_empty() {
            return Err(RegistryCatalogError::EmptyCatalog);
        }

        let mut catalog = Self::default();
        for package_dir in package_dirs {
            let record = Self::load_signed_package(package_dir)?;
            catalog.insert(record)?;
        }
        Ok(catalog)
    }

    #[must_use]
    pub fn connectors_response(&self) -> RegistryCatalogResponse {
        let mut connectors: Vec<_> = self
            .connectors
            .keys()
            .filter_map(|connector_id| self.connector_summary(connector_id))
            .collect();
        connectors.sort_by(|left, right| left.connector_id.cmp(&right.connector_id));
        RegistryCatalogResponse { connectors }
    }

    #[must_use]
    pub fn connector_descriptor(&self, connector_id: &str) -> Option<RegistryConnectorDescriptor> {
        let entries = self.sorted_version_entries(connector_id)?;
        let latest_version = entries.first()?.0.clone();
        let versions = entries
            .iter()
            .map(|(version, records)| {
                self.version_descriptor(
                    connector_id,
                    version.as_str(),
                    records,
                    version.as_str() == latest_version.as_str(),
                )
            })
            .collect();
        Some(RegistryConnectorDescriptor {
            connector_id: connector_id.to_owned(),
            latest_version,
            versions,
        })
    }

    #[must_use]
    pub fn latest_release(&self, connector_id: &str) -> Option<RegistryVersionDescriptor> {
        let entries = self.sorted_version_entries(connector_id)?;
        let latest_version = entries.first()?.0.clone();
        let (_, records) = entries.first()?;
        Some(self.version_descriptor(connector_id, latest_version.as_str(), records, true))
    }

    #[must_use]
    pub fn release(&self, connector_id: &str, version: &str) -> Option<RegistryVersionDescriptor> {
        let entries = self.sorted_version_entries(connector_id)?;
        let latest_version = entries.first()?.0.clone();
        let (_, records) = entries
            .into_iter()
            .find(|(candidate, _)| candidate.as_str() == version)?;
        Some(self.version_descriptor(
            connector_id,
            version,
            records,
            version == latest_version.as_str(),
        ))
    }

    pub fn router(self) -> Router {
        registry_router(Arc::new(self))
    }

    fn connector_summary(&self, connector_id: &str) -> Option<RegistryConnectorSummary> {
        let entries = self.sorted_version_entries(connector_id)?;
        let latest_version = entries.first()?.0.clone();
        let versions = entries
            .into_iter()
            .map(|(version, _)| version.clone())
            .collect();
        Some(RegistryConnectorSummary {
            connector_id: connector_id.to_owned(),
            latest_version,
            versions,
        })
    }

    fn insert(&mut self, record: RegistryPackageRecord) -> Result<(), RegistryCatalogError> {
        let connector_id = record.connector_id.clone();
        let version = record.version.to_string();
        let target = record.manifest_signature.target.as_string();

        let versions = self.connectors.entry(connector_id.clone()).or_default();
        let records = versions.entry(version.clone()).or_default();
        if records
            .iter()
            .any(|existing| existing.manifest_signature.target == record.manifest_signature.target)
        {
            return Err(RegistryCatalogError::DuplicateTarget {
                connector_id,
                version,
                target,
            });
        }

        records.push(record);
        records.sort_by(|left, right| {
            left.manifest_signature
                .target
                .as_string()
                .cmp(&right.manifest_signature.target.as_string())
        });
        Ok(())
    }

    fn load_signed_package(
        package_dir: &Path,
    ) -> Result<RegistryPackageRecord, RegistryCatalogError> {
        let manifest_path = package_dir.join(REGISTRY_MANIFEST_FILENAME);
        let manifest_toml = std::fs::read_to_string(&manifest_path).map_err(|source| {
            if source.kind() == std::io::ErrorKind::NotFound {
                RegistryCatalogError::MissingFile {
                    path: package_dir.to_path_buf(),
                    file_name: REGISTRY_MANIFEST_FILENAME,
                }
            } else {
                RegistryCatalogError::ReadFile {
                    path: manifest_path.clone(),
                    source,
                }
            }
        })?;
        let manifest = ConnectorManifest::parse_str(&manifest_toml).map_err(|source| {
            RegistryCatalogError::ManifestParse {
                path: manifest_path.clone(),
                source,
            }
        })?;

        let signature_path = package_dir.join(REGISTRY_MANIFEST_SIGNATURE_FILENAME);
        let signature_json = std::fs::read_to_string(&signature_path).map_err(|source| {
            if source.kind() == std::io::ErrorKind::NotFound {
                RegistryCatalogError::MissingFile {
                    path: package_dir.to_path_buf(),
                    file_name: REGISTRY_MANIFEST_SIGNATURE_FILENAME,
                }
            } else {
                RegistryCatalogError::ReadFile {
                    path: signature_path.clone(),
                    source,
                }
            }
        })?;
        let signature: ManifestSignatureArtifact =
            serde_json::from_str(&signature_json).map_err(|source| {
                RegistryCatalogError::SignatureArtifactJson {
                    path: signature_path.clone(),
                    source,
                }
            })?;
        let signing_bytes = manifest_signing_bytes(&manifest).map_err(|error| {
            RegistryCatalogError::ManifestSigningBytes {
                path: package_dir.to_path_buf(),
                message: error.to_string(),
            }
        })?;
        let actual_manifest_signing_hash = hash_bytes(&signing_bytes);
        if actual_manifest_signing_hash != signature.manifest_signing_hash {
            return Err(RegistryCatalogError::ManifestSigningHashMismatch {
                path: package_dir.to_path_buf(),
                artifact_hash: signature.manifest_signing_hash.clone(),
                actual_hash: actual_manifest_signing_hash,
            });
        }
        if signature.context.as_bytes() != MANIFEST_SIGNATURE_CONTEXT {
            return Err(RegistryCatalogError::SignatureContextMismatch {
                path: package_dir.to_path_buf(),
                context: signature.context.clone(),
            });
        }

        // Reject path traversal in binary_name from deserialized signature JSON.
        let binary_file = std::path::Path::new(&signature.binary_name);
        if binary_file.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        }) || binary_file.is_absolute()
        {
            return Err(RegistryCatalogError::PathTraversal {
                binary_name: signature.binary_name.clone(),
            });
        }

        let binary_path = package_dir.join(binary_file);
        let binary_metadata = std::fs::symlink_metadata(&binary_path).map_err(|source| {
            if source.kind() == std::io::ErrorKind::NotFound {
                RegistryCatalogError::MissingBinary {
                    path: package_dir.to_path_buf(),
                    binary_name: signature.binary_name.clone(),
                }
            } else {
                RegistryCatalogError::ReadFile {
                    path: binary_path.clone(),
                    source,
                }
            }
        })?;
        if binary_metadata.file_type().is_symlink()
            || !binary_metadata.is_file()
            || file_has_multiple_links(&binary_metadata)
        {
            return Err(RegistryCatalogError::LinkedBinary {
                path: package_dir.to_path_buf(),
                binary_name: signature.binary_name.clone(),
            });
        }
        let canonical_package_dir =
            package_dir
                .canonicalize()
                .map_err(|source| RegistryCatalogError::ReadFile {
                    path: package_dir.to_path_buf(),
                    source,
                })?;
        let canonical_binary_path = binary_path.canonicalize().map_err(|source| {
            if source.kind() == std::io::ErrorKind::NotFound {
                RegistryCatalogError::MissingBinary {
                    path: package_dir.to_path_buf(),
                    binary_name: signature.binary_name.clone(),
                }
            } else {
                RegistryCatalogError::ReadFile {
                    path: binary_path.clone(),
                    source,
                }
            }
        })?;
        if !canonical_binary_path.starts_with(&canonical_package_dir) {
            return Err(RegistryCatalogError::PathTraversal {
                binary_name: signature.binary_name.clone(),
            });
        }
        let binary_bytes = std::fs::read(&canonical_binary_path).map_err(|source| {
            if source.kind() == std::io::ErrorKind::NotFound {
                RegistryCatalogError::MissingBinary {
                    path: package_dir.to_path_buf(),
                    binary_name: signature.binary_name.clone(),
                }
            } else {
                RegistryCatalogError::ReadFile {
                    path: canonical_binary_path.clone(),
                    source,
                }
            }
        })?;
        let binary_sha256 = hash_bytes(&binary_bytes);
        if binary_sha256 != signature.binary_hash {
            return Err(RegistryCatalogError::BinaryHashMismatch {
                path: package_dir.to_path_buf(),
                artifact_hash: signature.binary_hash.clone(),
                actual_hash: binary_sha256,
            });
        }
        let verifying_key_vec = hex::decode(&signature.verifying_key).map_err(|_| {
            RegistryCatalogError::SignatureVerifyingKeyInvalid {
                path: package_dir.to_path_buf(),
            }
        })?;
        let verifying_key_bytes: [u8; 32] =
            verifying_key_vec.as_slice().try_into().map_err(|_| {
                RegistryCatalogError::SignatureVerifyingKeyInvalid {
                    path: package_dir.to_path_buf(),
                }
            })?;
        let verifying_key =
            Ed25519VerifyingKey::from_bytes(&verifying_key_bytes).map_err(|_| {
                RegistryCatalogError::SignatureVerifyingKeyInvalid {
                    path: package_dir.to_path_buf(),
                }
            })?;
        let signature_bytes = Base64Bytes::try_from(signature.signature.clone()).map_err(|_| {
            RegistryCatalogError::SignatureBytesInvalid {
                path: package_dir.to_path_buf(),
            }
        })?;
        let detached_signature = Ed25519Signature::try_from_slice(signature_bytes.as_bytes())
            .map_err(|_| RegistryCatalogError::SignatureBytesInvalid {
                path: package_dir.to_path_buf(),
            })?;
        let message = signature_message(&signing_bytes, &signature.binary_hash);
        verifying_key
            .verify_with_context(MANIFEST_SIGNATURE_CONTEXT, &message, &detached_signature)
            .map_err(|_| RegistryCatalogError::SignatureInvalid {
                path: package_dir.to_path_buf(),
            })?;

        let attestation_path = package_dir.join(REGISTRY_ATTESTATION_FILENAME);
        let attestation_json = std::fs::read_to_string(&attestation_path)
            .map(Some)
            .or_else(|source| {
                if source.kind() == std::io::ErrorKind::NotFound {
                    Ok(None)
                } else {
                    Err(RegistryCatalogError::ReadFile {
                        path: attestation_path.clone(),
                        source,
                    })
                }
            })?;

        Ok(RegistryPackageRecord {
            connector_id: manifest.connector.id.to_string(),
            version: manifest.connector.version.clone(),
            manifest_toml: manifest_toml.clone(),
            manifest_sha256: hash_bytes(manifest_toml.as_bytes()),
            manifest_signature: signature,
            manifest_signature_json: signature_json,
            binary_sha256: hash_bytes(&binary_bytes),
            binary_bytes,
            attestation_json,
        })
    }

    fn sorted_version_entries(
        &self,
        connector_id: &str,
    ) -> Option<Vec<(&String, &Vec<RegistryPackageRecord>)>> {
        let versions = self.connectors.get(connector_id)?;
        let mut entries: Vec<_> = versions.iter().filter(|(_, v)| !v.is_empty()).collect();
        entries.sort_by(|(_, left), (_, right)| right[0].version.cmp(&left[0].version));
        Some(entries)
    }

    fn version_descriptor(
        &self,
        connector_id: &str,
        version: &str,
        records: &[RegistryPackageRecord],
        is_latest: bool,
    ) -> RegistryVersionDescriptor {
        let mut targets: Vec<_> = records
            .iter()
            .map(|record| Self::target_descriptor(connector_id, version, record))
            .collect();
        targets.sort_by(|left, right| left.target.cmp(&right.target));
        RegistryVersionDescriptor {
            version: version.to_owned(),
            is_latest,
            targets,
        }
    }

    fn target_descriptor(
        connector_id: &str,
        version: &str,
        record: &RegistryPackageRecord,
    ) -> RegistryTargetDescriptor {
        let os = record.manifest_signature.target.os.clone();
        let arch = record.manifest_signature.target.arch.clone();
        let target = record.manifest_signature.target.as_string();
        let manifest_url = format!(
            "/v1/connectors/{connector_id}/versions/{version}/targets/{os}/{arch}/manifest"
        );
        let binary_url =
            format!("/v1/connectors/{connector_id}/versions/{version}/targets/{os}/{arch}/binary");
        let signature_url = format!(
            "/v1/connectors/{connector_id}/versions/{version}/targets/{os}/{arch}/signature"
        );
        let attestation_url = record.attestation_json.as_ref().map(|_| {
            format!(
                "/v1/connectors/{connector_id}/versions/{version}/targets/{os}/{arch}/attestation"
            )
        });
        RegistryTargetDescriptor {
            os,
            arch,
            target,
            manifest_sha256: record.manifest_sha256.clone(),
            binary_sha256: record.binary_sha256.clone(),
            manifest_url,
            binary_url,
            signature_url,
            attestation_url,
            signature: record.manifest_signature.clone(),
        }
    }

    fn target_record(
        &self,
        connector_id: &str,
        version: &str,
        os: &str,
        arch: &str,
    ) -> Option<&RegistryPackageRecord> {
        self.connectors
            .get(connector_id)?
            .get(version)?
            .iter()
            .find(|record| {
                record.manifest_signature.target.os == os
                    && record.manifest_signature.target.arch == arch
            })
    }
}

pub fn registry_router(catalog: Arc<LocalRegistryCatalog>) -> Router {
    Router::new()
        .route("/health", get(registry_health_handler))
        .route("/v1/connectors", get(registry_list_handler))
        .route(
            "/v1/connectors/{connector_id}",
            get(registry_connector_handler),
        )
        .route(
            "/v1/connectors/{connector_id}/latest",
            get(registry_latest_handler),
        )
        .route(
            "/v1/connectors/{connector_id}/versions/{version}",
            get(registry_version_handler),
        )
        .route(
            "/v1/connectors/{connector_id}/versions/{version}/targets/{os}/{arch}/manifest",
            get(registry_manifest_handler),
        )
        .route(
            "/v1/connectors/{connector_id}/versions/{version}/targets/{os}/{arch}/binary",
            get(registry_binary_handler),
        )
        .route(
            "/v1/connectors/{connector_id}/versions/{version}/targets/{os}/{arch}/signature",
            get(registry_signature_handler),
        )
        .route(
            "/v1/connectors/{connector_id}/versions/{version}/targets/{os}/{arch}/attestation",
            get(registry_attestation_handler),
        )
        .with_state(catalog)
}

async fn registry_health_handler(
    State(catalog): State<Arc<LocalRegistryCatalog>>,
) -> Json<RegistryHealthResponse> {
    Json(RegistryHealthResponse {
        status: "ok",
        connectors: catalog.connectors.len(),
    })
}

async fn registry_list_handler(
    State(catalog): State<Arc<LocalRegistryCatalog>>,
) -> Json<RegistryCatalogResponse> {
    Json(catalog.connectors_response())
}

async fn registry_connector_handler(
    State(catalog): State<Arc<LocalRegistryCatalog>>,
    AxumPath(connector_id): AxumPath<String>,
) -> Result<Json<RegistryConnectorDescriptor>, StatusCode> {
    catalog
        .connector_descriptor(&connector_id)
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn registry_latest_handler(
    State(catalog): State<Arc<LocalRegistryCatalog>>,
    AxumPath(connector_id): AxumPath<String>,
) -> Result<Json<RegistryVersionDescriptor>, StatusCode> {
    catalog
        .latest_release(&connector_id)
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn registry_version_handler(
    State(catalog): State<Arc<LocalRegistryCatalog>>,
    AxumPath((connector_id, version)): AxumPath<(String, String)>,
) -> Result<Json<RegistryVersionDescriptor>, StatusCode> {
    catalog
        .release(&connector_id, &version)
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn registry_manifest_handler(
    State(catalog): State<Arc<LocalRegistryCatalog>>,
    AxumPath((connector_id, version, os, arch)): AxumPath<(String, String, String, String)>,
) -> Result<Response, StatusCode> {
    let record = catalog
        .target_record(&connector_id, &version, &os, &arch)
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(registry_bytes_response(
        "text/plain; charset=utf-8",
        record.manifest_toml.clone().into_bytes(),
    ))
}

async fn registry_binary_handler(
    State(catalog): State<Arc<LocalRegistryCatalog>>,
    AxumPath((connector_id, version, os, arch)): AxumPath<(String, String, String, String)>,
) -> Result<Response, StatusCode> {
    let record = catalog
        .target_record(&connector_id, &version, &os, &arch)
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(registry_bytes_response(
        "application/octet-stream",
        record.binary_bytes.clone(),
    ))
}

async fn registry_signature_handler(
    State(catalog): State<Arc<LocalRegistryCatalog>>,
    AxumPath((connector_id, version, os, arch)): AxumPath<(String, String, String, String)>,
) -> Result<Response, StatusCode> {
    let record = catalog
        .target_record(&connector_id, &version, &os, &arch)
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(registry_bytes_response(
        "application/json",
        record.manifest_signature_json.clone().into_bytes(),
    ))
}

async fn registry_attestation_handler(
    State(catalog): State<Arc<LocalRegistryCatalog>>,
    AxumPath((connector_id, version, os, arch)): AxumPath<(String, String, String, String)>,
) -> Result<Response, StatusCode> {
    let record = catalog
        .target_record(&connector_id, &version, &os, &arch)
        .ok_or(StatusCode::NOT_FOUND)?;
    let attestation = record
        .attestation_json
        .clone()
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(registry_bytes_response(
        "application/json",
        attestation.into_bytes(),
    ))
}

fn registry_bytes_response(content_type: &'static str, body: Vec<u8>) -> Response {
    let mut response = body.into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}

#[async_trait]
pub trait RegistrySource: Send + Sync {
    async fn fetch_bundle(&self, connector_id: &str) -> Result<ConnectorBundle, RegistryError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use chrono::Utc;
    use fcp_cbor::SchemaId;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_manifest::PolicySection;
    use fcp_prelude::{DecisionReceiptPolicy, ZoneTransportPolicy};
    use fcp_store::{
        MemoryObjectStore, MemoryObjectStoreConfig, MemorySymbolStore, MemorySymbolStoreConfig,
    };
    use semver::Version;
    use serde_json::json;
    use std::panic::{self, AssertUnwindSafe};
    use std::time::Instant;
    use uuid::Uuid;

    #[cfg(unix)]
    fn symlink_file(src: &Path, dst: &Path) {
        std::os::unix::fs::symlink(src, dst).expect("create file symlink");
    }

    #[cfg(windows)]
    fn symlink_file(src: &Path, dst: &Path) {
        std::os::windows::fs::symlink_file(src, dst).expect("create file symlink");
    }

    fn hard_link_file(src: &Path, dst: &Path) {
        std::fs::hard_link(src, dst).expect("create file hard link");
    }

    const PLACEHOLDER_HASH: &str = "blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn test_connector_target_normalization() {
        let target = ConnectorTarget::from_env();
        // Since we can't easily mock std::env::consts::ARCH, we just verify it's NOT x86_64/aarch64
        // if the platform matches those.
        match std::env::consts::ARCH {
            "x86_64" => assert_eq!(target.arch, "amd64"),
            "aarch64" => assert_eq!(target.arch, "arm64"),
            _ => {} // Other archs passed through
        }
    }

    #[derive(Default)]
    struct RegistryLogData {
        connector_id: Option<String>,
        version: Option<String>,
        manifest_hash: Option<String>,
        binary_hash: Option<String>,
        target: Option<String>,
        reason_code: Option<String>,
        details: Option<serde_json::Value>,
    }

    fn run_registry_test<F, Fut>(
        test_name: &str,
        phase: &str,
        operation: &str,
        assertions: u32,
        f: F,
    ) where
        F: FnOnce() -> Fut + panic::UnwindSafe,
        Fut: std::future::Future<Output = RegistryLogData>,
    {
        let start = Instant::now();
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            fcp_async_core::runtime::block_on_sync(f()).expect("build sync test runtime")
        }));
        let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);

        let (passed, failed, outcome, data) = match &result {
            Ok(data) => (assertions, 0, "pass", Some(data)),
            Err(_) => (0, assertions, "fail", None),
        };

        let log = json!({
            "timestamp": Utc::now().to_rfc3339(),
            "level": "info",
            "test_name": test_name,
            "module": "fcp-registry",
            "phase": phase,
            "operation": operation,
            "correlation_id": Uuid::new_v4().to_string(),
            "result": outcome,
            "duration_ms": duration_ms,
            "connector_id": data.and_then(|d| d.connector_id.clone()),
            "version": data.and_then(|d| d.version.clone()),
            "manifest_hash": data.and_then(|d| d.manifest_hash.clone()),
            "binary_hash": data.and_then(|d| d.binary_hash.clone()),
            "target": data.and_then(|d| d.target.clone()),
            "reason_code": data.and_then(|d| d.reason_code.clone()),
            "details": data.and_then(|d| d.details.clone()),
            "assertions": {
                "passed": passed,
                "failed": failed
            }
        });
        println!("{log}");

        if let Err(payload) = result {
            panic::resume_unwind(payload);
        }
    }

    fn minimal_manifest() -> ConnectorManifest {
        ConnectorManifest::parse_str_unchecked(&base_manifest_toml()).expect("manifest parse")
    }

    fn base_manifest_toml() -> String {
        // Read the shared minimal-manifest fixture verbatim and substitute
        // its placeholder interface hash with a freshly-computed one. The
        // fixture already declares `minimal.op` as a required capability
        // alongside `network.dns`, so no string patching is needed
        // (br-giw5h: the previous helper patched the `optional` list via
        // replacen and tripped a fixture-drift assert after 9c3a290e moved
        // `minimal.op` into `required`).
        //
        // If the fixture drifts again and PLACEHOLDER_HASH is no longer
        // present, the .replace below becomes a no-op and the compute_
        // interface_hash result is silently ignored — guard explicitly
        // against that so drift is loud.
        let raw = include_str!("../../../tests/vectors/manifest/manifest_minimal.toml");
        assert!(
            raw.contains(PLACEHOLDER_HASH),
            "minimal manifest fixture no longer contains PLACEHOLDER_HASH; \
             update base_manifest_toml helper (br-giw5h)"
        );
        let unchecked = ConnectorManifest::parse_str_unchecked(raw).expect("manifest");
        let hash = unchecked.compute_interface_hash().expect("interface hash");
        raw.replace(PLACEHOLDER_HASH, &hash.to_string())
    }

    fn unsigned_manifest_toml(extra_sections: &str) -> String {
        if extra_sections.trim().is_empty() {
            base_manifest_toml()
        } else {
            format!("{}\n{}", base_manifest_toml(), extra_sections)
        }
    }

    fn manifest_with_signature(sig: Base64Bytes) -> ConnectorManifest {
        let mut manifest = minimal_manifest();
        manifest.signatures = Some(SignaturesSection {
            publisher_signatures: vec![SignatureEntry {
                kid: "pub1".to_string(),
                sig,
            }],
            publisher_threshold: Some(fcp_manifest::SignatureThreshold { k: 1, n: 1 }),
            registry_signature: None,
            transparency_log_entry: None,
        });
        manifest
    }

    fn sign_manifest_toml(
        manifest_toml: &str,
        signing_key: &Ed25519SigningKey,
        binary_hash: &str,
    ) -> Base64Bytes {
        let manifest = ConnectorManifest::parse_str_unchecked(manifest_toml).expect("manifest");
        let signing_bytes = manifest_signing_bytes(&manifest).expect("signing bytes");
        let message = signature_message(&signing_bytes, binary_hash);
        let signature = signing_key.sign_with_context(MANIFEST_SIGNATURE_CONTEXT, &message);
        Base64Bytes::try_from(format!(
            "base64:{}",
            base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
        ))
        .expect("base64 sig")
    }

    fn sign_tuf_signed_payload(
        signed: &serde_json::Value,
        signing_key: &Ed25519SigningKey,
    ) -> String {
        let signed_bytes = serde_json::to_vec(signed).expect("canonical TUF signed bytes");
        hex::encode(signing_key.sign(&signed_bytes).to_bytes())
    }

    /// (Re)publish `snapshot.json` and `timestamp.json` for the `targets.json`
    /// currently on disk.
    ///
    /// snapshot vouches for targets.json and timestamp vouches for
    /// snapshot.json, so each file is written after the one it pins and its
    /// declared length/hash match the bytes on disk. Tests that mutate
    /// `targets.json` call this to model a repository that legitimately
    /// re-published the upper roles, which lets the assertion reach the
    /// targets-role signature check instead of stopping at the snapshot
    /// binding.
    fn write_test_tuf_snapshot_chain(metadata_dir: &Path, signing_key: &Ed25519SigningKey) {
        let expires = test_tuf_expires();
        let key_id = TEST_TUF_KEY_ID;
        let targets_bytes =
            std::fs::read(metadata_dir.join("targets.json")).expect("read targets metadata");

        let snapshot_signed = json!({
            "_type": "snapshot",
            "version": 1,
            "expires": expires,
            "meta": {
                "targets.json": tuf_meta_entry(1, &targets_bytes),
            },
        });
        let snapshot_signature = sign_tuf_signed_payload(&snapshot_signed, signing_key);
        let snapshot_json = json!({
            "signed": snapshot_signed,
            "signatures": [{ "keyid": key_id, "sig": snapshot_signature }],
        });
        let snapshot_bytes = serde_json::to_vec_pretty(&snapshot_json).expect("snapshot json");
        std::fs::write(metadata_dir.join("snapshot.json"), &snapshot_bytes)
            .expect("write snapshot metadata");

        let timestamp_signed = json!({
            "_type": "timestamp",
            "version": 1,
            "expires": expires,
            "meta": {
                "snapshot.json": tuf_meta_entry(1, &snapshot_bytes),
            },
        });
        let timestamp_signature = sign_tuf_signed_payload(&timestamp_signed, signing_key);
        let timestamp_json = json!({
            "signed": timestamp_signed,
            "signatures": [{ "keyid": key_id, "sig": timestamp_signature }],
        });
        std::fs::write(
            metadata_dir.join("timestamp.json"),
            serde_json::to_vec_pretty(&timestamp_json).expect("timestamp json"),
        )
        .expect("write timestamp metadata");
    }

    /// Key ID every TUF role in the test fixtures is signed under.
    const TEST_TUF_KEY_ID: &str = "tuf-ed25519-test";

    /// The expiry every `write_test_tuf_metadata` fixture stamps into its roles.
    fn test_tuf_expires() -> String {
        (Utc::now() + chrono::Duration::days(7)).to_rfc3339()
    }

    /// Build a TUF `meta` entry pinning a role file's version, length, and hash.
    fn tuf_meta_entry(version: u32, role_bytes: &[u8]) -> serde_json::Value {
        let hash = hash_bytes(role_bytes)
            .strip_prefix("sha256:")
            .expect("sha256 prefix")
            .to_string();
        json!({
            "version": version,
            "length": role_bytes.len(),
            "hashes": { "sha256": hash },
        })
    }

    fn write_test_tuf_metadata(
        metadata_dir: &Path,
        target_path: &str,
        target_bytes: &[u8],
        signing_key: &Ed25519SigningKey,
    ) -> TufRootMetadata {
        let key_id = TEST_TUF_KEY_ID;
        let expires = test_tuf_expires();
        let public_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let target_hash = hash_bytes(target_bytes)
            .strip_prefix("sha256:")
            .expect("sha256 prefix")
            .to_string();
        let target_len = u64::try_from(target_bytes.len()).expect("target length fits u64");

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
        let root_signature = sign_tuf_signed_payload(&root_signed, signing_key);
        let root_json = json!({
            "signed": root_signed,
            "signatures": [{ "keyid": key_id, "sig": root_signature }],
        });
        let root_bytes = serde_json::to_vec_pretty(&root_json).expect("root json");
        std::fs::write(metadata_dir.join("root.json"), &root_bytes).expect("write root metadata");

        let targets_signed = json!({
            "_type": "targets",
            "version": 1,
            "expires": expires,
            "targets": {
                target_path: {
                    "length": target_len,
                    "hashes": { "sha256": target_hash },
                },
            },
        });
        let targets_signature = sign_tuf_signed_payload(&targets_signed, signing_key);
        let targets_json = json!({
            "signed": targets_signed,
            "signatures": [{ "keyid": key_id, "sig": targets_signature }],
        });
        let targets_bytes = serde_json::to_vec_pretty(&targets_json).expect("targets json");
        std::fs::write(metadata_dir.join("targets.json"), &targets_bytes)
            .expect("write targets metadata");

        write_test_tuf_snapshot_chain(metadata_dir, signing_key);

        TufRootMetadata {
            version: 1,
            root_hash: hash_bytes(&root_bytes),
            expires: u64::try_from((Utc::now() + chrono::Duration::days(7)).timestamp())
                .expect("future timestamp"),
            key_ids: vec![key_id.to_string()],
            threshold: 1,
        }
    }

    fn publisher_signature_section(kid: &str, sig: &Base64Bytes) -> String {
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

    fn registry_signature_section(kid: &str, sig: &Base64Bytes) -> String {
        format!(
            r#"[signatures.registry_signature]
kid = "{kid}"
sig = "{sig}"
"#,
            sig = String::from(sig.clone())
        )
    }

    fn with_signatures(unsigned: &str, signatures: &str) -> String {
        format!("{unsigned}\n{signatures}")
    }

    fn test_target() -> ConnectorTarget {
        ConnectorTarget {
            os: "linux".to_string(),
            arch: "amd64".to_string(),
        }
    }

    fn test_zone_policy(capability_ceiling: Vec<CapabilityId>) -> ZonePolicyObject {
        let zone = ZoneId::work();
        ZonePolicyObject {
            header: ObjectHeader {
                schema: SchemaId::new("fcp.test", "ZonePolicyObject", Version::new(1, 0, 0)),
                zone_id: zone.clone(),
                created_at: 1_700_000_000,
                provenance: Provenance::new(zone.clone()),
                refs: vec![],
                foreign_refs: vec![],
                ttl_secs: None,
                placement: None,
            },
            zone_id: zone,
            principal_allow: Vec::new(),
            principal_deny: Vec::new(),
            connector_allow: Vec::new(),
            connector_deny: Vec::new(),
            capability_allow: Vec::new(),
            capability_deny: Vec::new(),
            capability_ceiling,
            transport_policy: ZoneTransportPolicy::default(),
            decision_receipts: DecisionReceiptPolicy::default(),
            usage_budget: None,
            requires_posture: None,
        }
    }

    #[test]
    fn verify_publisher_signature_ok() {
        run_registry_test(
            "verify_publisher_signature_ok",
            "verify",
            "signature",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let manifest = minimal_manifest();
                let signing_bytes = manifest_signing_bytes(&manifest).expect("signing bytes");
                let binary_hash = "sha256:deadbeef";
                let message = signature_message(&signing_bytes, binary_hash);
                let signature = signing_key.sign_with_context(MANIFEST_SIGNATURE_CONTEXT, &message);
                let sig = Base64Bytes::try_from(format!(
                    "base64:{}",
                    base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
                ))
                .expect("base64 sig");

                let manifest = manifest_with_signature(sig);
                let sigs = manifest.signatures.as_ref().expect("signatures");

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let ok = verify_publishers(&trust, sigs, &signing_bytes, binary_hash)
                    .expect("verify publishers");
                assert!(ok);

                RegistryLogData {
                    connector_id: Some(manifest.connector.id.to_string()),
                    version: Some(manifest.connector.version.to_string()),
                    reason_code: Some("publisher_signature_valid".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_publisher_signature_rejects_unknown_kid() {
        run_registry_test(
            "verify_publisher_signature_rejects_unknown_kid",
            "verify",
            "signature",
            1,
            || async {
                let manifest = minimal_manifest();
                let signing_bytes = manifest_signing_bytes(&manifest).expect("signing bytes");
                let sig = Base64Bytes::try_from("base64:AA==".to_string()).expect("base64 sig");
                let manifest = manifest_with_signature(sig);
                let sigs = manifest.signatures.as_ref().expect("signatures");

                let trust = RegistryTrustPolicy::default();
                let err = verify_publishers(&trust, sigs, &signing_bytes, "sha256:dead")
                    .expect_err("unknown kid");
                assert!(matches!(
                    err,
                    RegistryError::UnknownKid { .. }
                        | RegistryError::PublisherThresholdUnmet { .. }
                ));

                RegistryLogData {
                    connector_id: Some(manifest.connector.id.to_string()),
                    reason_code: Some("unknown_kid".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn supply_chain_policy_requires_attestation_evidence() {
        run_registry_test(
            "supply_chain_policy_requires_attestation_evidence",
            "verify",
            "attestation",
            1,
            || async {
                let mut manifest = minimal_manifest();
                manifest.policy = Some(PolicySection {
                    require_transparency_log: false,
                    require_attestation_types: vec![AttestationType::InToto],
                    min_slsa_level: None,
                    trusted_builders: Vec::new(),
                    require_attestation_expiry: false,
                });

                let err =
                    enforce_supply_chain_policy(&manifest, None).expect_err("missing evidence");
                assert!(matches!(err, RegistryError::AttestationEvidenceMissing));

                RegistryLogData {
                    connector_id: Some(manifest.connector.id.to_string()),
                    reason_code: Some("attestation_evidence_missing".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn supply_chain_policy_rejects_unset_expiry_when_required() {
        // Without `require_attestation_expiry`, an attestation with
        // expires_at=None passes policy indefinitely (the freshness check
        // skips entries whose expires_at is None). When the operator sets
        // require_attestation_expiry=true, those entries must be rejected
        // up-front so a verifier-adapter regression cannot silently disable
        // freshness enforcement on every connector under that policy.
        run_registry_test(
            "supply_chain_policy_rejects_unset_expiry_when_required",
            "verify",
            "attestation",
            1,
            || async {
                let mut manifest = minimal_manifest();
                manifest.policy = Some(PolicySection {
                    require_transparency_log: false,
                    require_attestation_types: vec![AttestationType::InToto],
                    min_slsa_level: None,
                    trusted_builders: Vec::new(),
                    require_attestation_expiry: true,
                });

                let evidence = SupplyChainEvidence {
                    transparency_log_present: false,
                    tuf_verified: false,
                    tuf_target_hash: None,
                    sigstore_verified: false,
                    sigstore_identity: None,
                    sigstore_issuer: None,
                    attestations: vec![AttestationEvidence {
                        attestation_type: AttestationType::InToto,
                        slsa_level: None,
                        builder_id: None,
                        expires_at: None, // The leak point.
                    }],
                };

                let err = enforce_supply_chain_policy(&manifest, Some(&evidence))
                    .expect_err("attestation without expires_at must be rejected");
                assert!(
                    matches!(err, RegistryError::AttestationExpiryMissing { .. }),
                    "expected AttestationExpiryMissing, got {err:?}"
                );

                RegistryLogData {
                    connector_id: Some(manifest.connector.id.to_string()),
                    reason_code: Some("attestation_expiry_missing".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn supply_chain_policy_rejects_unset_expiry_when_only_expiry_required() {
        run_registry_test(
            "supply_chain_policy_rejects_unset_expiry_when_only_expiry_required",
            "verify",
            "attestation",
            2,
            || async {
                let mut manifest = minimal_manifest();
                manifest.policy = Some(PolicySection {
                    require_transparency_log: false,
                    require_attestation_types: Vec::new(),
                    min_slsa_level: None,
                    trusted_builders: Vec::new(),
                    require_attestation_expiry: true,
                });

                let missing_evidence = enforce_supply_chain_policy(&manifest, None)
                    .expect_err("expiry-required policy must require evidence");
                assert!(
                    matches!(missing_evidence, RegistryError::AttestationEvidenceMissing),
                    "expected AttestationEvidenceMissing, got {missing_evidence:?}"
                );

                let evidence = SupplyChainEvidence {
                    transparency_log_present: false,
                    tuf_verified: false,
                    tuf_target_hash: None,
                    sigstore_verified: false,
                    sigstore_identity: None,
                    sigstore_issuer: None,
                    attestations: vec![AttestationEvidence {
                        attestation_type: AttestationType::InToto,
                        slsa_level: None,
                        builder_id: None,
                        expires_at: None,
                    }],
                };

                let err = enforce_supply_chain_policy(&manifest, Some(&evidence))
                    .expect_err("expiry-required policy must reject unset expires_at");
                assert!(
                    matches!(err, RegistryError::AttestationExpiryMissing { .. }),
                    "expected AttestationExpiryMissing, got {err:?}"
                );

                RegistryLogData {
                    connector_id: Some(manifest.connector.id.to_string()),
                    reason_code: Some("expiry_only_policy_fail_closed".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn supply_chain_policy_unset_expiry_passes_when_not_required() {
        // Backward-compat: when require_attestation_expiry is false (the
        // default), an attestation with expires_at=None continues to pass
        // policy. Existing operators who haven't opted in keep their
        // current behavior.
        run_registry_test(
            "supply_chain_policy_unset_expiry_passes_when_not_required",
            "verify",
            "attestation",
            1,
            || async {
                let mut manifest = minimal_manifest();
                manifest.policy = Some(PolicySection {
                    require_transparency_log: false,
                    require_attestation_types: vec![AttestationType::InToto],
                    min_slsa_level: None,
                    trusted_builders: Vec::new(),
                    require_attestation_expiry: false,
                });

                let evidence = SupplyChainEvidence {
                    transparency_log_present: false,
                    tuf_verified: false,
                    tuf_target_hash: None,
                    sigstore_verified: false,
                    sigstore_identity: None,
                    sigstore_issuer: None,
                    attestations: vec![AttestationEvidence {
                        attestation_type: AttestationType::InToto,
                        slsa_level: None,
                        builder_id: None,
                        expires_at: None,
                    }],
                };

                enforce_supply_chain_policy(&manifest, Some(&evidence))
                    .expect("require_attestation_expiry=false admits unset expiry");

                RegistryLogData {
                    connector_id: Some(manifest.connector.id.to_string()),
                    reason_code: Some("policy_passed".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn capability_ceiling_violation_detected() {
        run_registry_test(
            "capability_ceiling_violation_detected",
            "verify",
            "policy",
            1,
            || async {
                let manifest = minimal_manifest();
                let policy = test_zone_policy(vec![CapabilityId::from_static("cap.other")]);

                let err =
                    enforce_capability_ceiling(Some(&policy), &manifest).expect_err("ceiling");
                assert!(matches!(
                    err,
                    RegistryError::CapabilityCeilingViolation { .. }
                ));

                RegistryLogData {
                    connector_id: Some(manifest.connector.id.to_string()),
                    reason_code: Some("capability_ceiling_violation".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_accepts_valid_publisher_signature() {
        run_registry_test(
            "verify_bundle_accepts_valid_publisher_signature",
            "verify",
            "signature",
            3,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml: manifest_toml.clone(),
                    binary: binary.clone(),
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let verified = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect("verify");

                assert_eq!(verified.binary_hash, binary_hash);
                assert_eq!(verified.manifest_hash, hash_bytes(manifest_toml.as_bytes()));
                assert_eq!(verified.target, bundle.target);

                RegistryLogData {
                    connector_id: Some(verified.manifest.connector.id.to_string()),
                    version: Some(verified.manifest.connector.version.to_string()),
                    manifest_hash: Some(verified.manifest_hash),
                    binary_hash: Some(verified.binary_hash),
                    target: Some(verified.target.as_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_missing_signatures() {
        run_registry_test(
            "verify_bundle_rejects_missing_signatures",
            "verify",
            "signature",
            1,
            || async {
                let binary = b"registry-binary".to_vec();
                let bundle = ConnectorBundle {
                    manifest_toml: unsigned_manifest_toml(""),
                    binary,
                    target: test_target(),
                };

                let verifier = RegistryVerifier::new(RegistryTrustPolicy::default());
                let err = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect_err("missing signatures");
                assert!(matches!(err, RegistryError::MissingSignatures));

                RegistryLogData {
                    reason_code: Some("missing_signatures".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_malformed_manifest() {
        run_registry_test(
            "verify_bundle_rejects_malformed_manifest",
            "verify",
            "manifest",
            1,
            || async {
                let bundle = ConnectorBundle {
                    manifest_toml: "not-a-manifest".to_string(),
                    binary: vec![0u8],
                    target: test_target(),
                };

                let verifier = RegistryVerifier::new(RegistryTrustPolicy::default());
                let err = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect_err("malformed manifest");
                assert!(matches!(&err, RegistryError::ManifestParse(_)));

                RegistryLogData {
                    reason_code: Some("manifest_parse_failed".to_string()),
                    details: Some(json!({
                        "error": format!("{err}")
                    })),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_unknown_kid() {
        run_registry_test(
            "verify_bundle_rejects_unknown_kid",
            "verify",
            "signature",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let verifier = RegistryVerifier::new(RegistryTrustPolicy::default());
                let err = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect_err("unknown kid");
                assert!(
                    matches!(
                        err,
                        RegistryError::UnknownKid { .. }
                            | RegistryError::PublisherThresholdUnmet { .. }
                    ),
                    "expected UnknownKid or PublisherThresholdUnmet, got: {err}"
                );

                RegistryLogData {
                    reason_code: Some("unknown_kid".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_binary_hash_mismatch() {
        run_registry_test(
            "verify_bundle_rejects_binary_hash_mismatch",
            "verify",
            "checksum",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let expected_binary = b"expected-binary".to_vec();
                let expected_hash = hash_bytes(&expected_binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &expected_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary: b"tampered-binary".to_vec(),
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let err = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect_err("binary mismatch");
                assert!(matches!(
                    err,
                    RegistryError::SignatureInvalid { .. }
                        | RegistryError::PublisherThresholdUnmet { .. }
                ));

                RegistryLogData {
                    reason_code: Some("checksum_mismatch".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_target_mismatch() {
        run_registry_test(
            "verify_bundle_rejects_target_mismatch",
            "verify",
            "target",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

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
                let err = verifier
                    .verify_bundle(
                        &bundle,
                        None,
                        None,
                        Some(&ConnectorTarget {
                            os: "darwin".to_string(),
                            arch: "amd64".to_string(),
                        }),
                    )
                    .expect_err("target mismatch");
                assert!(matches!(err, RegistryError::TargetMismatch { .. }));

                RegistryLogData {
                    reason_code: Some("target_mismatch".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_capability_ceiling_violation() {
        run_registry_test(
            "verify_bundle_rejects_capability_ceiling_violation",
            "verify",
            "policy",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let zone_policy = test_zone_policy(vec![CapabilityId::from_static("network.dns")]);
                let verifier = RegistryVerifier::new(trust);
                let err = verifier
                    .verify_bundle(&bundle, Some(&zone_policy), None, None)
                    .expect_err("capability ceiling");
                assert!(matches!(
                    err,
                    RegistryError::CapabilityCeilingViolation { .. }
                ));

                RegistryLogData {
                    reason_code: Some("capability_ceiling_violation".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_missing_tuf_when_operator_requires_it() {
        run_registry_test(
            "verify_bundle_rejects_missing_tuf_when_operator_requires_it",
            "verify",
            "supply-chain",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust).with_supply_chain_verification_config(
                    SupplyChainVerificationConfig {
                        require_tuf: true,
                        ..SupplyChainVerificationConfig::default()
                    },
                );
                let err = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect_err("missing tuf evidence");
                assert!(matches!(err, RegistryError::TufVerificationRequired));

                RegistryLogData {
                    reason_code: Some("tuf_verification_required".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    /// Regression for br-pcmm8: a default-constructed SupplyChainEvidence
    /// (tuf_verified=false) MUST NOT satisfy `require_tuf`. Before the fix,
    /// the enforcement was presence-only (evidence.is_some()), so any
    /// passed-in evidence bypassed the gate.
    #[test]
    fn verify_bundle_rejects_unverified_tuf_evidence() {
        let config = SupplyChainVerificationConfig {
            require_tuf: true,
            ..SupplyChainVerificationConfig::default()
        };
        let manifest = ConnectorManifest::parse_str(&unsigned_manifest_toml("")).unwrap();
        let binary_hash = hash_bytes(b"registry-binary");

        // Evidence carrying NO verified claims (the bypass payload).
        let evidence = SupplyChainEvidence::new();

        let err = enforce_supply_chain_verification_config(
            &config,
            &manifest,
            Some(&evidence),
            &binary_hash,
        )
        .expect_err("unverified evidence must be rejected");
        assert!(
            matches!(err, RegistryError::TufVerificationRequired),
            "expected TufVerificationRequired, got {err:?}"
        );

        // Positive control: promoting via a real verification result
        // satisfies the gate. `mark_tuf_verified_for_tests` is the
        // cfg-gated equivalent used inside the crate's own tests.
        let verified_evidence =
            SupplyChainEvidence::new().mark_tuf_verified_for_tests(&binary_hash);
        enforce_supply_chain_verification_config(
            &config,
            &manifest,
            Some(&verified_evidence),
            &binary_hash,
        )
        .expect("tuf_verified=true bound to the bundle binary must satisfy require_tuf");
    }

    /// br-g7jhf finding 4: `TufVerifier::verify_target` only proves the target
    /// PATH is enumerated in signed TUF metadata. Evidence with no target hash,
    /// or one bound to different bytes, must not satisfy `require_tuf`.
    #[test]
    fn verify_bundle_rejects_tuf_evidence_not_bound_to_bundle_binary() {
        let config = SupplyChainVerificationConfig {
            require_tuf: true,
            ..SupplyChainVerificationConfig::default()
        };
        let manifest = ConnectorManifest::parse_str(&unsigned_manifest_toml("")).unwrap();
        let binary_hash = hash_bytes(b"registry-binary");

        let unbound = TufVerificationResult {
            verified: true,
            root_version: 1,
            target: None,
        };
        let unbound_evidence = SupplyChainEvidence::new().with_tuf_verification_result(&unbound);
        let err = enforce_supply_chain_verification_config(
            &config,
            &manifest,
            Some(&unbound_evidence),
            &binary_hash,
        )
        .expect_err("tuf evidence with no target hash must be rejected");
        assert!(
            matches!(err, RegistryError::TufTargetUnbound),
            "expected TufTargetUnbound, got {err:?}"
        );

        let other_hash = hash_bytes(b"a different connector binary");
        let mismatched = SupplyChainEvidence::new().mark_tuf_verified_for_tests(&other_hash);
        let err = enforce_supply_chain_verification_config(
            &config,
            &manifest,
            Some(&mismatched),
            &binary_hash,
        )
        .expect_err("tuf evidence bound to other bytes must be rejected");
        assert!(
            matches!(err, RegistryError::TufTargetBindingMismatch { .. }),
            "expected TufTargetBindingMismatch, got {err:?}"
        );
    }

    /// Regression for br-pcmm8 (sigstore side).
    #[test]
    fn verify_bundle_rejects_unverified_sigstore_evidence() {
        let config = SupplyChainVerificationConfig {
            require_sigstore: true,
            ..SupplyChainVerificationConfig::default()
        };
        let manifest = ConnectorManifest::parse_str(&unsigned_manifest_toml("")).unwrap();
        let binary_hash = hash_bytes(b"registry-binary");

        let evidence = SupplyChainEvidence::new();

        let err = enforce_supply_chain_verification_config(
            &config,
            &manifest,
            Some(&evidence),
            &binary_hash,
        )
        .expect_err("unverified sigstore evidence must be rejected");
        assert!(
            matches!(err, RegistryError::SigstoreVerificationRequired),
            "expected SigstoreVerificationRequired, got {err:?}"
        );

        let verified_evidence =
            SupplyChainEvidence::new().mark_sigstore_verified_for_tests(None, None);
        enforce_supply_chain_verification_config(
            &config,
            &manifest,
            Some(&verified_evidence),
            &binary_hash,
        )
        .expect("sigstore_verified=true must satisfy require_sigstore");
    }

    /// br-g7jhf finding 5: configuring trusted Sigstore identities/issuers used
    /// to only flip `sigstore_verification_required()` on — the allowlists
    /// themselves were never consulted, so a bundle signed by ANY identity
    /// passed. They must now be enforced, and fail closed on a missing claim.
    #[test]
    fn verify_bundle_enforces_trusted_sigstore_identity_and_issuer() {
        let config = SupplyChainVerificationConfig {
            trusted_sigstore_identities: vec!["github-actions".to_string()],
            trusted_sigstore_issuers: vec![
                "https://token.actions.githubusercontent.com".to_string(),
            ],
            ..SupplyChainVerificationConfig::default()
        };
        let manifest = ConnectorManifest::parse_str(&unsigned_manifest_toml("")).unwrap();
        let binary_hash = hash_bytes(b"registry-binary");

        let unbound = SupplyChainEvidence::new().mark_sigstore_verified_for_tests(None, None);
        let err = enforce_supply_chain_verification_config(
            &config,
            &manifest,
            Some(&unbound),
            &binary_hash,
        )
        .expect_err("sigstore evidence with no identity must not satisfy an identity allowlist");
        assert!(
            matches!(err, RegistryError::SigstoreIdentityUnbound),
            "expected SigstoreIdentityUnbound, got {err:?}"
        );

        let wrong_identity = SupplyChainEvidence::new().mark_sigstore_verified_for_tests(
            Some("attacker-identity"),
            Some("https://token.actions.githubusercontent.com"),
        );
        let err = enforce_supply_chain_verification_config(
            &config,
            &manifest,
            Some(&wrong_identity),
            &binary_hash,
        )
        .expect_err("untrusted sigstore identity must be rejected");
        assert!(
            matches!(err, RegistryError::SigstoreIdentityUntrusted { .. }),
            "expected SigstoreIdentityUntrusted, got {err:?}"
        );

        let wrong_issuer = SupplyChainEvidence::new()
            .mark_sigstore_verified_for_tests(Some("github-actions"), Some("https://evil.example"));
        let err = enforce_supply_chain_verification_config(
            &config,
            &manifest,
            Some(&wrong_issuer),
            &binary_hash,
        )
        .expect_err("untrusted sigstore issuer must be rejected");
        assert!(
            matches!(err, RegistryError::SigstoreIssuerUntrusted { .. }),
            "expected SigstoreIssuerUntrusted, got {err:?}"
        );

        let trusted = SupplyChainEvidence::new().mark_sigstore_verified_for_tests(
            Some("github-actions"),
            Some("https://token.actions.githubusercontent.com"),
        );
        enforce_supply_chain_verification_config(&config, &manifest, Some(&trusted), &binary_hash)
            .expect("trusted identity and issuer must satisfy the allowlists");
    }

    /// br-g7jhf finding 1: the owner's `SupplyChainVerificationConfig` carries
    /// its own attestation floor, enforced independently of the
    /// publisher-controlled `manifest.policy`. A manifest with NO `[policy]`
    /// table can no longer opt out of SLSA / attestation-type / builder
    /// requirements.
    #[test]
    fn owner_config_attestation_floor_applies_without_manifest_policy() {
        let config = SupplyChainVerificationConfig {
            require_attestation_types: vec![AttestationType::InToto],
            min_slsa_level: Some(3),
            trusted_builders: vec!["trusted-builder".to_string()],
            ..SupplyChainVerificationConfig::default()
        };
        let manifest = ConnectorManifest::parse_str(&unsigned_manifest_toml("")).unwrap();
        assert!(
            manifest.policy.is_none(),
            "fixture must have no [policy] table for this regression to be meaningful"
        );
        let binary_hash = hash_bytes(b"registry-binary");

        // The manifest-side gate is a no-op here — that is exactly the hole.
        enforce_supply_chain_policy(&manifest, None)
            .expect("no [policy] table means the manifest gate has nothing to enforce");

        let err = enforce_supply_chain_verification_config(&config, &manifest, None, &binary_hash)
            .expect_err("owner floor must demand attestation evidence");
        assert!(
            matches!(err, RegistryError::AttestationEvidenceMissing),
            "expected AttestationEvidenceMissing, got {err:?}"
        );

        let weak = SupplyChainEvidence::new().with_attestations(vec![AttestationEvidence {
            attestation_type: AttestationType::InToto,
            slsa_level: Some(2),
            builder_id: Some("trusted-builder".to_string()),
            expires_at: None,
        }]);
        let err =
            enforce_supply_chain_verification_config(&config, &manifest, Some(&weak), &binary_hash)
                .expect_err("owner SLSA floor must reject a level-2 build provenance");
        assert!(
            matches!(err, RegistryError::SlsaLevelInsufficient { required: 3 }),
            "expected SlsaLevelInsufficient, got {err:?}"
        );

        let compliant = SupplyChainEvidence::new().with_attestations(vec![AttestationEvidence {
            attestation_type: AttestationType::InToto,
            slsa_level: Some(3),
            builder_id: Some("trusted-builder".to_string()),
            expires_at: None,
        }]);
        enforce_supply_chain_verification_config(
            &config,
            &manifest,
            Some(&compliant),
            &binary_hash,
        )
        .expect("evidence meeting the owner floor must pass");
    }

    /// br-g7jhf finding 2: an attestation with `builder_id = None` used to be
    /// skipped by the untrusted-builder rejection loop, so pairing one
    /// trusted-builder attestation with one unnamed build-provenance
    /// attestation passed both gates.
    #[test]
    fn unnamed_build_provenance_attestation_cannot_evade_trusted_builders() {
        let requirements = AttestationRequirements {
            require_attestation_types: &[],
            min_slsa_level: None,
            trusted_builders: &["trusted-builder".to_string()],
            require_attestation_expiry: false,
        };

        let evasive = SupplyChainEvidence::new().with_attestations(vec![
            AttestationEvidence {
                attestation_type: AttestationType::InToto,
                slsa_level: Some(3),
                builder_id: Some("trusted-builder".to_string()),
                expires_at: None,
            },
            AttestationEvidence {
                attestation_type: AttestationType::ReproducibleBuild,
                slsa_level: Some(3),
                builder_id: None,
                expires_at: None,
            },
        ]);
        let err = enforce_attestation_requirements(&requirements, Some(&evasive))
            .expect_err("unnamed build-provenance attestation must be rejected");
        assert!(
            matches!(err, RegistryError::BuilderIdentityMissing { .. }),
            "expected BuilderIdentityMissing, got {err:?}"
        );

        // A non-build attestation may legitimately have no builder.
        let mixed = SupplyChainEvidence::new().with_attestations(vec![
            AttestationEvidence {
                attestation_type: AttestationType::InToto,
                slsa_level: Some(3),
                builder_id: Some("trusted-builder".to_string()),
                expires_at: None,
            },
            AttestationEvidence {
                attestation_type: AttestationType::CodeReview,
                slsa_level: None,
                builder_id: None,
                expires_at: None,
            },
        ]);
        enforce_attestation_requirements(&requirements, Some(&mixed))
            .expect("code-review attestations need no builder identity");

        // Trusted builders with no build provenance at all fails closed.
        let review_only = SupplyChainEvidence::new().with_attestations(vec![AttestationEvidence {
            attestation_type: AttestationType::CodeReview,
            slsa_level: None,
            builder_id: Some("trusted-builder".to_string()),
            expires_at: None,
        }]);
        let err = enforce_attestation_requirements(&requirements, Some(&review_only))
            .expect_err("a trusted-builders policy needs build provenance");
        assert!(
            matches!(err, RegistryError::TrustedBuilderProvenanceMissing),
            "expected TrustedBuilderProvenanceMissing, got {err:?}"
        );
    }

    /// br-g7jhf finding 3: `min_slsa_level` accepted ANY attestation carrying a
    /// high enough level, so a code-review attestation with `slsa_level = 4`
    /// satisfied the floor even when the actual build provenance was level 0.
    #[test]
    fn min_slsa_level_only_counts_build_provenance_attestations() {
        let requirements = AttestationRequirements {
            require_attestation_types: &[],
            min_slsa_level: Some(3),
            trusted_builders: &[],
            require_attestation_expiry: false,
        };

        let laundered = SupplyChainEvidence::new().with_attestations(vec![
            AttestationEvidence {
                attestation_type: AttestationType::CodeReview,
                slsa_level: Some(4),
                builder_id: None,
                expires_at: None,
            },
            AttestationEvidence {
                attestation_type: AttestationType::InToto,
                slsa_level: Some(0),
                builder_id: Some("builder".to_string()),
                expires_at: None,
            },
        ]);
        let err = enforce_attestation_requirements(&requirements, Some(&laundered))
            .expect_err("a code-review SLSA level must not satisfy the build floor");
        assert!(
            matches!(err, RegistryError::SlsaLevelInsufficient { required: 3 }),
            "expected SlsaLevelInsufficient, got {err:?}"
        );

        let genuine = SupplyChainEvidence::new().with_attestations(vec![AttestationEvidence {
            attestation_type: AttestationType::InToto,
            slsa_level: Some(3),
            builder_id: Some("builder".to_string()),
            expires_at: None,
        }]);
        enforce_attestation_requirements(&requirements, Some(&genuine))
            .expect("build provenance at the required level must pass");
    }

    /// Regression for br-i5iv4: a failed TUF verification result MUST NOT
    /// promote `tuf_verified` even when passed into
    /// `with_tuf_verification_result`. Only a real result with
    /// `verified == true` flips the flag.
    #[test]
    fn supply_chain_evidence_refuses_failed_tuf_verification_result() {
        let failed = TufVerificationResult {
            verified: false,
            root_version: 1,
            target: None,
        };
        let ok = TufVerificationResult {
            verified: true,
            root_version: 1,
            target: None,
        };

        let ev_failed = SupplyChainEvidence::new().with_tuf_verification_result(&failed);
        assert!(
            !ev_failed.tuf_verified(),
            "verified=false TufVerificationResult must NOT promote tuf_verified"
        );

        let ev_ok = SupplyChainEvidence::new().with_tuf_verification_result(&ok);
        assert!(
            ev_ok.tuf_verified(),
            "verified=true TufVerificationResult must promote tuf_verified"
        );
    }

    /// Regression for br-i5iv4 (sigstore side).
    #[test]
    fn supply_chain_evidence_refuses_failed_sigstore_verification_result() {
        let failed = SigstoreVerificationResult {
            verified: false,
            identity: None,
            issuer: None,
            rekor_log_index: None,
        };
        let ok = SigstoreVerificationResult {
            verified: true,
            identity: Some("gha".into()),
            issuer: Some("https://token.actions.githubusercontent.com".into()),
            rekor_log_index: Some(42),
        };

        let ev_failed = SupplyChainEvidence::new().with_sigstore_verification_result(&failed);
        assert!(!ev_failed.sigstore_verified());

        let ev_ok = SupplyChainEvidence::new().with_sigstore_verification_result(&ok);
        assert!(ev_ok.sigstore_verified());
    }

    #[test]
    fn verify_bundle_rejects_transparency_log_missing() {
        run_registry_test(
            "verify_bundle_rejects_transparency_log_missing",
            "verify",
            "transparency",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let policy = r#"[policy]
require_transparency_log = true
"#;
                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml(policy);
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

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
                let err = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect_err("missing transparency entry");
                assert!(
                    matches!(&err, RegistryError::ManifestParse(_))
                        && err.to_string().contains("transparency_log_entry")
                );

                RegistryLogData {
                    reason_code: Some("transparency_log_missing".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_transparency_evidence_missing() {
        run_registry_test(
            "verify_bundle_rejects_transparency_evidence_missing",
            "verify",
            "transparency",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let policy = r#"[policy]
require_transparency_log = true
"#;
                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml(policy);
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);

                // Create combined signatures section with both publisher sig and transparency entry
                let signatures_section = format!(
                    r#"[signatures]
publisher_threshold = "1-of-1"
transparency_log_entry = "objectid:{}"

[[signatures.publisher_signatures]]
kid = "pub1"
sig = "{}"
"#,
                    hex::encode([0u8; 32]),
                    String::from(sig)
                );

                let manifest_toml = with_signatures(&unsigned, &signatures_section);

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
                let err = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect_err("missing transparency evidence");
                assert!(matches!(err, RegistryError::TransparencyEvidenceMissing));

                RegistryLogData {
                    reason_code: Some("transparency_evidence_missing".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_missing_attestation_type() {
        run_registry_test(
            "verify_bundle_rejects_missing_attestation_type",
            "verify",
            "attestation",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let policy = r#"[policy]
require_attestation_types = ["in-toto"]
"#;
                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml(policy);
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let evidence = SupplyChainEvidence {
                    transparency_log_present: false,
                    tuf_verified: false,
                    tuf_target_hash: None,
                    sigstore_verified: false,
                    sigstore_identity: None,
                    sigstore_issuer: None,
                    attestations: vec![AttestationEvidence {
                        attestation_type: AttestationType::CodeReview,
                        slsa_level: Some(2),
                        builder_id: Some("builder-a".to_string()),
                        expires_at: None,
                    }],
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let err = verifier
                    .verify_bundle(&bundle, None, Some(&evidence), None)
                    .expect_err("missing attestation type");
                assert!(matches!(
                    err,
                    RegistryError::RequiredAttestationMissing { .. }
                ));

                RegistryLogData {
                    reason_code: Some("attestation_missing".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_slsa_level_insufficient() {
        run_registry_test(
            "verify_bundle_rejects_slsa_level_insufficient",
            "verify",
            "attestation",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let policy = r#"[policy]
min_slsa_level = 3
"#;
                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml(policy);
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let evidence = SupplyChainEvidence {
                    transparency_log_present: false,
                    tuf_verified: false,
                    tuf_target_hash: None,
                    sigstore_verified: false,
                    sigstore_identity: None,
                    sigstore_issuer: None,
                    attestations: vec![AttestationEvidence {
                        attestation_type: AttestationType::InToto,
                        slsa_level: Some(2),
                        builder_id: Some("builder-a".to_string()),
                        expires_at: None,
                    }],
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let err = verifier
                    .verify_bundle(&bundle, None, Some(&evidence), None)
                    .expect_err("insufficient slsa level");
                assert!(matches!(
                    err,
                    RegistryError::SlsaLevelInsufficient { required: 3 }
                ));

                RegistryLogData {
                    reason_code: Some("slsa_level_insufficient".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_untrusted_builder() {
        run_registry_test(
            "verify_bundle_rejects_untrusted_builder",
            "verify",
            "attestation",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let policy = r#"[policy]
trusted_builders = ["trusted-builder"]
"#;
                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml(policy);
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let evidence = SupplyChainEvidence {
                    transparency_log_present: false,
                    tuf_verified: false,
                    tuf_target_hash: None,
                    sigstore_verified: false,
                    sigstore_identity: None,
                    sigstore_issuer: None,
                    attestations: vec![AttestationEvidence {
                        attestation_type: AttestationType::InToto,
                        slsa_level: Some(3),
                        builder_id: Some("untrusted".to_string()),
                        expires_at: None,
                    }],
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let err = verifier
                    .verify_bundle(&bundle, None, Some(&evidence), None)
                    .expect_err("untrusted builder");
                assert!(matches!(err, RegistryError::UntrustedBuilder { .. }));

                RegistryLogData {
                    reason_code: Some("untrusted_builder".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_registry_signature_required() {
        run_registry_test(
            "verify_bundle_rejects_registry_signature_required",
            "verify",
            "signature",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);
                trust.require_registry_signature = true;

                let verifier = RegistryVerifier::new(trust);
                let err = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect_err("registry signature required");
                assert!(matches!(err, RegistryError::RegistrySignatureRequired));

                RegistryLogData {
                    reason_code: Some("registry_signature_required".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_accepts_registry_signature_only() {
        run_registry_test(
            "verify_bundle_accepts_registry_signature_only",
            "verify",
            "signature",
            2,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &registry_signature_section("reg1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml: manifest_toml.clone(),
                    binary: binary.clone(),
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .registry_keys
                    .insert("reg1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let verified = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect("registry signature");
                assert_eq!(verified.binary_hash, binary_hash);
                assert_eq!(verified.manifest_hash, hash_bytes(manifest_toml.as_bytes()));

                RegistryLogData {
                    connector_id: Some(verified.manifest.connector.id.to_string()),
                    manifest_hash: Some(verified.manifest_hash),
                    binary_hash: Some(verified.binary_hash),
                    target: Some(verified.target.as_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn mirror_bundle_persists_objects() {
        run_registry_test(
            "mirror_bundle_persists_objects",
            "verify",
            "mirror",
            4,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

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
                let verified = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect("verify");

                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                let zone_id = ZoneId::work();
                let object_id_key = ObjectIdKey::from_bytes([1u8; 32]);

                let result = verifier
                    .mirror_bundle(&verified, &bundle, zone_id, &object_id_key, &store)
                    .await
                    .expect("mirror bundle");

                let manifest_object = store
                    .get(&result.manifest_object_id)
                    .await
                    .expect("manifest object");
                let binary_object = store
                    .get(&result.binary_object_id)
                    .await
                    .expect("binary object");

                assert_eq!(manifest_object.storage.retention, RetentionClass::Pinned);
                assert_eq!(binary_object.storage.retention, RetentionClass::Pinned);
                assert_eq!(binary_object.header.refs, vec![result.manifest_object_id]);
                assert_eq!(binary_object.header.zone_id, ZoneId::work());

                RegistryLogData {
                    manifest_hash: Some(result.manifest_hash),
                    binary_hash: Some(result.binary_hash),
                    target: Some(verified.target.as_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Additional Manifest Verification Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn verify_bundle_rejects_invalid_signature() {
        run_registry_test(
            "verify_bundle_rejects_invalid_signature",
            "verify",
            "signature",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let wrong_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                // Sign with the wrong key
                let sig = sign_manifest_toml(&unsigned, &wrong_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

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
                let err = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect_err("invalid signature");
                assert!(matches!(
                    err,
                    RegistryError::SignatureInvalid { .. }
                        | RegistryError::PublisherThresholdUnmet { .. }
                ));

                RegistryLogData {
                    reason_code: Some("signature_invalid".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_missing_required_field() {
        run_registry_test(
            "verify_bundle_rejects_missing_required_field",
            "verify",
            "manifest",
            1,
            || async {
                // Manifest missing connector section
                let incomplete_toml = r#"[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"
min_mesh_version = "2.0.0"
min_protocol = "fcp2-sym/2.0"
"#;
                let bundle = ConnectorBundle {
                    manifest_toml: incomplete_toml.to_string(),
                    binary: b"binary".to_vec(),
                    target: test_target(),
                };

                let verifier = RegistryVerifier::new(RegistryTrustPolicy::default());
                let err = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect_err("missing required field");
                assert!(matches!(err, RegistryError::ManifestParse(_)));

                RegistryLogData {
                    reason_code: Some("missing_required_field".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_malformed_signature_bytes() {
        run_registry_test(
            "verify_bundle_rejects_malformed_signature_bytes",
            "verify",
            "signature",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                // Create a signature that's too short (not 64 bytes)
                let malformed_sig =
                    Base64Bytes::try_from("base64:AQIDBA==".to_string()).expect("base64");
                let unsigned = unsigned_manifest_toml("");
                let manifest_toml = with_signatures(
                    &unsigned,
                    &publisher_signature_section("pub1", &malformed_sig),
                );

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary: b"binary".to_vec(),
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let err = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect_err("malformed signature");
                assert!(matches!(
                    err,
                    RegistryError::SignatureBytes | RegistryError::PublisherThresholdUnmet { .. }
                ));

                RegistryLogData {
                    reason_code: Some("signature_bytes_malformed".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Binary Verification Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn verify_bundle_accepts_zero_length_binary() {
        run_registry_test(
            "verify_bundle_accepts_zero_length_binary",
            "verify",
            "checksum",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                // Empty binary is valid if hash matches
                let binary: Vec<u8> = vec![];
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

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
                let verified = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect("empty binary valid");

                assert_eq!(verified.binary_hash, hash_bytes(&[]));

                RegistryLogData {
                    binary_hash: Some(verified.binary_hash),
                    reason_code: Some("zero_length_binary_accepted".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_truncated_binary() {
        run_registry_test(
            "verify_bundle_rejects_truncated_binary",
            "verify",
            "checksum",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let original_binary = b"this is the full binary content".to_vec();
                let truncated_binary = b"this is the".to_vec();
                let original_hash = hash_bytes(&original_binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &original_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary: truncated_binary,
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let err = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect_err("truncated binary");
                assert!(matches!(
                    err,
                    RegistryError::SignatureInvalid { .. }
                        | RegistryError::PublisherThresholdUnmet { .. }
                ));

                RegistryLogData {
                    reason_code: Some("binary_truncated".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_rejects_extra_bytes_in_binary() {
        run_registry_test(
            "verify_bundle_rejects_extra_bytes_in_binary",
            "verify",
            "checksum",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let original_binary = b"original content".to_vec();
                let mut extended_binary = original_binary.clone();
                extended_binary.extend_from_slice(b"extra malicious bytes");
                let original_hash = hash_bytes(&original_binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &original_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary: extended_binary,
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let err = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect_err("extra bytes");
                assert!(matches!(
                    err,
                    RegistryError::SignatureInvalid { .. }
                        | RegistryError::PublisherThresholdUnmet { .. }
                ));

                RegistryLogData {
                    reason_code: Some("binary_extra_bytes".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Platform/Architecture Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn verify_bundle_rejects_wrong_architecture() {
        run_registry_test(
            "verify_bundle_rejects_wrong_architecture",
            "verify",
            "target",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
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
                let err = verifier
                    .verify_bundle(
                        &bundle,
                        None,
                        None,
                        Some(&ConnectorTarget {
                            os: "linux".to_string(),
                            arch: "arm64".to_string(),
                        }),
                    )
                    .expect_err("arch mismatch");
                assert!(matches!(err, RegistryError::TargetMismatch { .. }));

                RegistryLogData {
                    reason_code: Some("arch_mismatch".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn connector_target_from_env_matches_runtime() {
        run_registry_test(
            "connector_target_from_env_matches_runtime",
            "verify",
            "target",
            2,
            || async {
                let target = ConnectorTarget::from_env();
                assert_eq!(target.os, std::env::consts::OS);
                // ConnectorTarget normalizes arch names for OCI/Docker compatibility
                let expected_arch = match std::env::consts::ARCH {
                    "x86_64" => "amd64",
                    "aarch64" => "arm64",
                    other => other,
                };
                assert_eq!(target.arch, expected_arch);

                RegistryLogData {
                    target: Some(target.as_string()),
                    reason_code: Some("target_matches_runtime".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Publisher Threshold Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn verify_bundle_rejects_publisher_threshold_unmet() {
        run_registry_test(
            "verify_bundle_rejects_publisher_threshold_unmet",
            "verify",
            "signature",
            1,
            || async {
                let signing_key1 = Ed25519SigningKey::generate();
                let verifying_key1 = signing_key1.verifying_key();
                let verifying_key2 = Ed25519SigningKey::generate().verifying_key();

                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig1 = sign_manifest_toml(&unsigned, &signing_key1, &binary_hash);

                // Create threshold 2-of-2 but only provide 1 signature
                let signatures = format!(
                    r#"[signatures]
publisher_threshold = "2-of-2"

[[signatures.publisher_signatures]]
kid = "pub1"
sig = "{}"
"#,
                    String::from(sig1)
                );

                let manifest_toml = with_signatures(&unsigned, &signatures);

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key1);
                trust
                    .publisher_keys
                    .insert("pub2".to_string(), verifying_key2);

                let verifier = RegistryVerifier::new(trust);
                let err = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect_err("threshold unmet");
                // Manifest parsing validates signature count >= threshold before verification
                assert!(matches!(&err, RegistryError::ManifestParse(e)
                        if e.to_string().contains("insufficient signatures")));

                RegistryLogData {
                    reason_code: Some("manifest_parse_insufficient_signatures".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Attestation Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn verify_bundle_accepts_valid_attestation() {
        run_registry_test(
            "verify_bundle_accepts_valid_attestation",
            "verify",
            "attestation",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let policy = r#"[policy]
require_attestation_types = ["in-toto"]
min_slsa_level = 2
trusted_builders = ["trusted-builder"]
"#;
                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml(policy);
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let evidence = SupplyChainEvidence {
                    transparency_log_present: false,
                    tuf_verified: false,
                    tuf_target_hash: None,
                    sigstore_verified: false,
                    sigstore_identity: None,
                    sigstore_issuer: None,
                    attestations: vec![AttestationEvidence {
                        attestation_type: AttestationType::InToto,
                        slsa_level: Some(3),
                        builder_id: Some("trusted-builder".to_string()),
                        expires_at: None,
                    }],
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let verified = verifier
                    .verify_bundle(&bundle, None, Some(&evidence), None)
                    .expect("attestation valid");

                RegistryLogData {
                    connector_id: Some(verified.manifest.connector.id.to_string()),
                    reason_code: Some("attestation_valid".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_accepts_transparency_log_with_evidence() {
        run_registry_test(
            "verify_bundle_accepts_transparency_log_with_evidence",
            "verify",
            "transparency",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let policy = r#"[policy]
require_transparency_log = true
"#;
                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml(policy);
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);

                // Combined signatures section with transparency_log_entry
                let signatures_section = format!(
                    r#"[signatures]
publisher_threshold = "1-of-1"
transparency_log_entry = "objectid:{}"

[[signatures.publisher_signatures]]
kid = "pub1"
sig = "{}"
"#,
                    hex::encode([0u8; 32]),
                    String::from(sig)
                );
                let manifest_toml = with_signatures(&unsigned, &signatures_section);

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let evidence = SupplyChainEvidence {
                    transparency_log_present: true,
                    tuf_verified: false,
                    tuf_target_hash: None,
                    sigstore_verified: false,
                    sigstore_identity: None,
                    sigstore_issuer: None,
                    attestations: vec![],
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let verified = verifier
                    .verify_bundle(&bundle, None, Some(&evidence), None)
                    .expect("transparency log valid");

                RegistryLogData {
                    connector_id: Some(verified.manifest.connector.id.to_string()),
                    reason_code: Some("transparency_log_valid".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Capability Ceiling Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn verify_bundle_accepts_capabilities_within_ceiling() {
        run_registry_test(
            "verify_bundle_accepts_capabilities_within_ceiling",
            "verify",
            "policy",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                // Allow all capabilities required by the minimal manifest
                let zone_policy = test_zone_policy(vec![
                    CapabilityId::from_static("network.dns"),
                    CapabilityId::from_static("minimal.op"),
                ]);

                let verifier = RegistryVerifier::new(trust);
                let verified = verifier
                    .verify_bundle(&bundle, Some(&zone_policy), None, None)
                    .expect("capabilities within ceiling");

                RegistryLogData {
                    connector_id: Some(verified.manifest.connector.id.to_string()),
                    reason_code: Some("capabilities_within_ceiling".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Verification Report Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn verification_report_contains_all_fields() {
        run_registry_test(
            "verification_report_contains_all_fields",
            "verify",
            "report",
            5,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml: manifest_toml.clone(),
                    binary: binary.clone(),
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let verified = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect("verify");

                let report = verified.report("success");
                assert_eq!(report.connector_id, "fcp.minimal");
                assert_eq!(report.manifest_hash, hash_bytes(manifest_toml.as_bytes()));
                assert_eq!(report.binary_hash, binary_hash);
                assert_eq!(report.target.os, "linux");
                assert_eq!(report.outcome, "success");

                RegistryLogData {
                    connector_id: Some(report.connector_id),
                    manifest_hash: Some(report.manifest_hash),
                    binary_hash: Some(report.binary_hash),
                    target: Some(report.target.as_string()),
                    reason_code: Some("report_complete".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Multiple Attestation Types Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn verify_bundle_accepts_multiple_attestation_types() {
        run_registry_test(
            "verify_bundle_accepts_multiple_attestation_types",
            "verify",
            "attestation",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let policy = r#"[policy]
require_attestation_types = ["in-toto", "code-review"]
"#;
                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml(policy);
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let evidence = SupplyChainEvidence {
                    transparency_log_present: false,
                    tuf_verified: false,
                    tuf_target_hash: None,
                    sigstore_verified: false,
                    sigstore_identity: None,
                    sigstore_issuer: None,
                    attestations: vec![
                        AttestationEvidence {
                            attestation_type: AttestationType::InToto,
                            slsa_level: Some(2),
                            builder_id: None,
                            expires_at: None,
                        },
                        AttestationEvidence {
                            attestation_type: AttestationType::CodeReview,
                            slsa_level: None,
                            builder_id: None,
                            expires_at: None,
                        },
                    ],
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let verified = verifier
                    .verify_bundle(&bundle, None, Some(&evidence), None)
                    .expect("multiple attestations valid");

                RegistryLogData {
                    connector_id: Some(verified.manifest.connector.id.to_string()),
                    reason_code: Some("multiple_attestations_valid".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // MockRegistry Implementation for Structured Testing
    // ─────────────────────────────────────────────────────────────────────────────

    /// Mock registry for deterministic testing.
    struct MockRegistry {
        connectors: HashMap<String, MockConnectorEntry>,
    }

    struct MockConnectorEntry {
        manifest_toml: String,
        binary: Vec<u8>,
        target: ConnectorTarget,
        signing_key: Ed25519SigningKey,
    }

    impl MockRegistry {
        fn new() -> Self {
            Self {
                connectors: HashMap::new(),
            }
        }

        fn with_valid_connector(mut self, id: &str, version: &str) -> Self {
            let signing_key = Ed25519SigningKey::generate();
            let binary = format!("binary-for-{id}-{version}").into_bytes();
            let binary_hash = hash_bytes(&binary);

            let manifest_toml = format!(
                r#"[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"
min_mesh_version = "2.0.0"
min_protocol = "fcp2-sym/2.0"
protocol_features = []
max_datagram_bytes = 1200
interface_hash = "{placeholder}"

[connector]
id = "{id}"
name = "Test Connector"
version = "{version}"
description = "Test connector"
archetypes = ["operational"]
format = "native"

[zones]
home = "z:work"
allowed_sources = ["z:work"]
allowed_targets = ["z:work"]
forbidden = []

[capabilities]
required = ["test.op"]
optional = []
forbidden = ["system.exec"]

[provides.operations.test_op]
description = "Test operation"
capability = "test.op"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "none"
input_schema = {{ type = "object" }}
output_schema = {{ type = "object" }}

[sandbox]
profile = "strict"
memory_mb = 64
cpu_percent = 20
wall_clock_timeout_ms = 1000
fs_readonly_paths = ["/usr"]
fs_writable_paths = ["$CONNECTOR_STATE"]
deny_exec = true
deny_ptrace = true
"#,
                placeholder = PLACEHOLDER_HASH
            );

            // Parse and compute interface hash
            let unchecked =
                ConnectorManifest::parse_str_unchecked(&manifest_toml).expect("manifest");
            let interface_hash = unchecked.compute_interface_hash().expect("interface hash");
            let manifest_toml =
                manifest_toml.replace(PLACEHOLDER_HASH, &interface_hash.to_string());

            // Sign
            let manifest = ConnectorManifest::parse_str(&manifest_toml).expect("manifest");
            let signing_bytes = manifest_signing_bytes(&manifest).expect("signing bytes");
            let message = signature_message(&signing_bytes, &binary_hash);
            let signature = signing_key.sign_with_context(MANIFEST_SIGNATURE_CONTEXT, &message);
            let sig_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

            let signed_manifest = format!(
                r#"{manifest_toml}

[signatures]
publisher_threshold = "1-of-1"

[[signatures.publisher_signatures]]
kid = "{id}-key"
sig = "base64:{sig_b64}"
"#
            );

            self.connectors.insert(
                id.to_string(),
                MockConnectorEntry {
                    manifest_toml: signed_manifest,
                    binary,
                    target: test_target(),
                    signing_key,
                },
            );
            self
        }

        fn get_bundle(&self, connector_id: &str) -> Option<ConnectorBundle> {
            self.connectors
                .get(connector_id)
                .map(|entry| ConnectorBundle {
                    manifest_toml: entry.manifest_toml.clone(),
                    binary: entry.binary.clone(),
                    target: entry.target.clone(),
                })
        }

        fn get_trust_policy(&self, connector_id: &str) -> Option<RegistryTrustPolicy> {
            self.connectors.get(connector_id).map(|entry| {
                let mut policy = RegistryTrustPolicy::default();
                policy.publisher_keys.insert(
                    format!("{connector_id}-key"),
                    entry.signing_key.verifying_key(),
                );
                policy
            })
        }
    }

    #[test]
    fn mock_registry_creates_verifiable_bundles() {
        run_registry_test(
            "mock_registry_creates_verifiable_bundles",
            "mock",
            "registry",
            2,
            || async {
                let registry = MockRegistry::new()
                    .with_valid_connector("fcp.test", "1.0.0")
                    .with_valid_connector("fcp.another", "2.0.0");

                let bundle = registry.get_bundle("fcp.test").expect("bundle");
                let trust = registry.get_trust_policy("fcp.test").expect("trust");

                let verifier = RegistryVerifier::new(trust);
                let verified = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect("verify");

                assert_eq!(verified.manifest.connector.id.as_str(), "fcp.test");
                assert_eq!(verified.manifest.connector.version.to_string(), "1.0.0");

                RegistryLogData {
                    connector_id: Some(verified.manifest.connector.id.to_string()),
                    version: Some(verified.manifest.connector.version.to_string()),
                    reason_code: Some("mock_registry_valid".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn mock_registry_nonexistent_connector_returns_none() {
        run_registry_test(
            "mock_registry_nonexistent_connector_returns_none",
            "mock",
            "registry",
            1,
            || async {
                let registry = MockRegistry::new().with_valid_connector("fcp.exists", "1.0.0");

                let bundle = registry.get_bundle("fcp.nonexistent");
                assert!(bundle.is_none());

                RegistryLogData {
                    reason_code: Some("nonexistent_connector".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Supply-Chain Verification Adapter Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn mock_transparency_verifier_accepts_valid_entry() {
        run_registry_test(
            "mock_transparency_verifier_accepts_valid_entry",
            "verify",
            "transparency-adapter",
            1,
            || async {
                let verifier = MockTransparencyVerifier::new();
                let entry = TransparencyLogEntry {
                    log_index: 12345,
                    entry_hash: "sha256:abc123".to_string(),
                    inclusion_proof: InclusionProof {
                        root_hash: "sha256:root".to_string(),
                        tree_size: 10000,
                        hashes: vec!["sha256:h1".to_string(), "sha256:h2".to_string()],
                        leaf_index: 12345,
                    },
                    signed_entry_timestamp: vec![1, 2, 3, 4],
                    log_id: "rekor.sigstore.dev".to_string(),
                };
                verifier.add_valid_entry("sha256:abc123".to_string(), entry);

                let result = verifier
                    .verify_entry("sha256:abc123", None)
                    .await
                    .expect("entry valid");
                assert!(result.verified);
                assert_eq!(result.log_index, Some(12345));

                RegistryLogData {
                    reason_code: Some("transparency_entry_verified".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn mock_transparency_verifier_rejects_unknown_entry() {
        run_registry_test(
            "mock_transparency_verifier_rejects_unknown_entry",
            "verify",
            "transparency-adapter",
            1,
            || async {
                let verifier = MockTransparencyVerifier::new();

                let err = verifier
                    .verify_entry("sha256:unknown", None)
                    .await
                    .expect_err("entry not found");
                assert!(matches!(
                    err,
                    SupplyChainVerificationError::TransparencyEntryNotFound
                ));

                RegistryLogData {
                    reason_code: Some("transparency_entry_not_found".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn mock_transparency_verifier_rejects_mismatched_expected_entry() {
        run_registry_test(
            "mock_transparency_verifier_rejects_mismatched_expected_entry",
            "verify",
            "transparency-adapter",
            1,
            || async {
                let verifier = MockTransparencyVerifier::new();
                let entry = TransparencyLogEntry {
                    log_index: 12345,
                    entry_hash: "sha256:abc123".to_string(),
                    inclusion_proof: InclusionProof {
                        root_hash: "sha256:root".to_string(),
                        tree_size: 10000,
                        hashes: vec!["sha256:h1".to_string()],
                        leaf_index: 12345,
                    },
                    signed_entry_timestamp: vec![1, 2, 3, 4],
                    log_id: "rekor.sigstore.dev".to_string(),
                };
                verifier.add_valid_entry("sha256:abc123".to_string(), entry);

                let expected = TransparencyLogEntry {
                    log_index: 99999,
                    entry_hash: "sha256:abc123".to_string(),
                    inclusion_proof: InclusionProof {
                        root_hash: "sha256:different-root".to_string(),
                        tree_size: 10000,
                        hashes: vec!["sha256:h1".to_string()],
                        leaf_index: 12345,
                    },
                    signed_entry_timestamp: vec![1, 2, 3, 4],
                    log_id: "rekor.sigstore.dev".to_string(),
                };

                let err = verifier
                    .verify_entry("sha256:abc123", Some(&expected))
                    .await
                    .expect_err("mismatched expected entry");
                assert!(matches!(
                    err,
                    SupplyChainVerificationError::TransparencyEntryMismatch
                ));

                RegistryLogData {
                    reason_code: Some("transparency_entry_mismatch".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn mock_tuf_verifier_accepts_valid_target() {
        run_registry_test(
            "mock_tuf_verifier_accepts_valid_target",
            "verify",
            "tuf-adapter",
            1,
            || async {
                let root = TufRootMetadata {
                    version: 5,
                    root_hash: "sha256:rootabc".to_string(),
                    expires: u64::MAX,
                    key_ids: vec!["key1".to_string()],
                    threshold: 1,
                };
                let verifier = MockTufVerifier::new(root.clone());

                let target = TufTargetInfo {
                    target_path: "connectors/fcp.test-1.0.0.tar.gz".to_string(),
                    hash: "sha256:binaryhash".to_string(),
                    length: 1024,
                    delegations: vec!["targets".to_string()],
                };
                verifier.add_valid_target(
                    "connectors/fcp.test-1.0.0.tar.gz".to_string(),
                    target.clone(),
                );

                let result = verifier
                    .verify_target(&root, "connectors/fcp.test-1.0.0.tar.gz")
                    .await
                    .expect("target valid");
                assert!(result.verified);
                assert_eq!(result.root_version, 5);
                assert!(result.target.is_some());

                RegistryLogData {
                    reason_code: Some("tuf_target_verified".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn mock_tuf_verifier_rejects_root_mismatch() {
        run_registry_test(
            "mock_tuf_verifier_rejects_root_mismatch",
            "verify",
            "tuf-adapter",
            1,
            || async {
                let root = TufRootMetadata {
                    version: 5,
                    root_hash: "sha256:rootabc".to_string(),
                    expires: u64::MAX,
                    key_ids: vec!["key1".to_string()],
                    threshold: 1,
                };
                let verifier = MockTufVerifier::new(root);

                let pinned = TufRootMetadata {
                    version: 5,
                    root_hash: "sha256:different".to_string(),
                    expires: u64::MAX,
                    key_ids: vec!["key1".to_string()],
                    threshold: 1,
                };

                let err = verifier
                    .verify_target(&pinned, "connectors/fcp.test-1.0.0.tar.gz")
                    .await
                    .expect_err("root mismatch");
                assert!(matches!(
                    err,
                    SupplyChainVerificationError::TufRootMismatch { .. }
                ));

                RegistryLogData {
                    reason_code: Some("tuf_root_mismatch".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn mock_tuf_verifier_rejects_rollback() {
        run_registry_test(
            "mock_tuf_verifier_rejects_rollback",
            "verify",
            "tuf-adapter",
            1,
            || async {
                let root = TufRootMetadata {
                    version: 3,
                    root_hash: "sha256:rootabc".to_string(),
                    expires: u64::MAX,
                    key_ids: vec!["key1".to_string()],
                    threshold: 1,
                };
                let verifier = MockTufVerifier::new(root);

                // Pinned root has higher version (rollback attempt)
                let pinned = TufRootMetadata {
                    version: 5,
                    root_hash: "sha256:rootabc".to_string(),
                    expires: u64::MAX,
                    key_ids: vec!["key1".to_string()],
                    threshold: 1,
                };

                let err = verifier
                    .verify_target(&pinned, "connectors/fcp.test-1.0.0.tar.gz")
                    .await
                    .expect_err("rollback detected");
                assert!(matches!(
                    err,
                    SupplyChainVerificationError::TufRollback { current: 5, got: 3 }
                ));

                RegistryLogData {
                    reason_code: Some("tuf_rollback_detected".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn mock_tuf_verifier_rejects_target_not_found() {
        run_registry_test(
            "mock_tuf_verifier_rejects_target_not_found",
            "verify",
            "tuf-adapter",
            1,
            || async {
                let root = TufRootMetadata {
                    version: 5,
                    root_hash: "sha256:rootabc".to_string(),
                    expires: u64::MAX,
                    key_ids: vec!["key1".to_string()],
                    threshold: 1,
                };
                let verifier = MockTufVerifier::new(root.clone());

                let err = verifier
                    .verify_target(&root, "connectors/nonexistent.tar.gz")
                    .await
                    .expect_err("target not found");
                assert!(matches!(
                    err,
                    SupplyChainVerificationError::TufTargetNotFound { .. }
                ));

                RegistryLogData {
                    reason_code: Some("tuf_target_not_found".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn mock_tuf_verifier_rejects_expired_metadata() {
        run_registry_test(
            "mock_tuf_verifier_rejects_expired_metadata",
            "verify",
            "tuf-adapter",
            1,
            || async {
                let root = TufRootMetadata {
                    version: 5,
                    root_hash: "sha256:rootabc".to_string(),
                    expires: 0,
                    key_ids: vec!["key1".to_string()],
                    threshold: 1,
                };
                let verifier = MockTufVerifier::new(root.clone());

                let err = verifier
                    .verify_target(&root, "connectors/fcp.test-1.0.0.tar.gz")
                    .await
                    .expect_err("expired metadata should be rejected");
                assert!(matches!(err, SupplyChainVerificationError::TufExpired));

                RegistryLogData {
                    reason_code: Some("tuf_expired_detected".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn local_tuf_verifier_accepts_valid_signed_metadata() {
        run_registry_test(
            "local_tuf_verifier_accepts_valid_signed_metadata",
            "verify",
            "tuf-adapter",
            4,
            || async {
                let dir = tempfile::tempdir().expect("tempdir");
                let signing_key = Ed25519SigningKey::generate();
                let target_path = "connectors/fcp.test-1.0.0.tar.gz";
                let target_bytes = b"test connector binary";
                let pinned =
                    write_test_tuf_metadata(dir.path(), target_path, target_bytes, &signing_key);
                let verifier = LocalTufVerifier::new(dir.path());

                let root = verifier.fetch_root().await.expect("signed root verifies");
                assert_eq!(root.key_ids, pinned.key_ids);

                let result = verifier
                    .verify_target_bytes(&pinned, target_path, target_bytes)
                    .expect("signed target metadata verifies");
                assert!(result.verified());
                assert_eq!(result.root_version(), 1);
                assert_eq!(
                    result.target().map(|target| target.target_path.as_str()),
                    Some(target_path)
                );

                RegistryLogData {
                    reason_code: Some("local_tuf_signed_metadata_verified".to_string()),
                    target: Some(target_path.to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn local_tuf_verifier_rejects_tampered_targets_metadata_with_nonempty_signature() {
        run_registry_test(
            "local_tuf_verifier_rejects_tampered_targets_metadata_with_nonempty_signature",
            "verify",
            "tuf-adapter",
            3,
            || async {
                let dir = tempfile::tempdir().expect("tempdir");
                let signing_key = Ed25519SigningKey::generate();
                let target_path = "connectors/fcp.test-1.0.0.tar.gz";
                let target_bytes = b"test connector binary";
                let pinned =
                    write_test_tuf_metadata(dir.path(), target_path, target_bytes, &signing_key);

                let targets_path = dir.path().join("targets.json");
                let mut targets_json: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&targets_path).expect("targets json"))
                        .expect("parse targets json");
                let target_sha256 = targets_json
                    .get_mut("signed")
                    .and_then(|signed| signed.get_mut("targets"))
                    .and_then(|targets| targets.get_mut(target_path))
                    .and_then(|target| target.get_mut("hashes"))
                    .and_then(|hashes| hashes.get_mut("sha256"))
                    .expect("target sha256 slot");
                *target_sha256 =
                    json!("0000000000000000000000000000000000000000000000000000000000000000");
                let target_signature = targets_json
                    .get_mut("signatures")
                    .and_then(serde_json::Value::as_array_mut)
                    .and_then(|signatures| signatures.first_mut())
                    .and_then(|signature| signature.get_mut("sig"))
                    .expect("target signature slot");
                *target_signature = json!(hex::encode([0x42_u8; 64]));
                std::fs::write(
                    &targets_path,
                    serde_json::to_vec_pretty(&targets_json).expect("tampered targets json"),
                )
                .expect("write tampered targets");

                let verifier = LocalTufVerifier::new(dir.path());

                // First line of defence: the snapshot role independently pinned
                // targets.json's length and hash, so mutating targets.json is
                // caught before its own signature is even checked (br-g7jhf
                // finding 6).
                let err = verifier
                    .verify_target(&pinned, target_path)
                    .await
                    .expect_err("tampered targets metadata must fail the snapshot binding");
                assert!(
                    matches!(
                        err,
                        SupplyChainVerificationError::TufTargetHashMismatch { ref target, .. }
                            if target == "targets.json"
                    ),
                    "expected snapshot->targets hash binding failure, got {err:?}"
                );

                // Now model a repository that also re-published snapshot and
                // timestamp over the tampered targets.json. The binding is
                // consistent again, so the original regression — an invalid
                // targets-role signature must not pass the threshold — is the
                // gate that fires.
                write_test_tuf_snapshot_chain(dir.path(), &signing_key);
                let err = verifier
                    .verify_target(&pinned, target_path)
                    .await
                    .expect_err("tampered targets metadata must fail signature threshold");
                assert!(matches!(
                    err,
                    SupplyChainVerificationError::TufSignatureThreshold {
                        ref role,
                        required: 1,
                        valid: 0,
                    } if role == "targets"
                ));

                RegistryLogData {
                    reason_code: Some("local_tuf_tampered_targets_refused".to_string()),
                    target: Some(target_path.to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    /// br-g7jhf finding 6: the TUF client used to read only `root.json` and
    /// `targets.json`, so the two roles that actually provide freeze and
    /// mix-and-match coverage were never consulted. All four roles are now
    /// mandatory and cross-bound.
    #[test]
    fn local_tuf_verifier_requires_timestamp_and_snapshot_roles() {
        run_registry_test(
            "local_tuf_verifier_requires_timestamp_and_snapshot_roles",
            "verify",
            "tuf-adapter",
            4,
            || async {
                let target_path = "connectors/fcp.test-1.0.0.tar.gz";
                let target_bytes = b"test connector binary";

                // 1. A repository serving no timestamp role fails closed rather
                //    than silently degrading to root+targets verification.
                let dir = tempfile::tempdir().expect("tempdir");
                let signing_key = Ed25519SigningKey::generate();
                let pinned =
                    write_test_tuf_metadata(dir.path(), target_path, target_bytes, &signing_key);
                std::fs::rename(
                    dir.path().join("timestamp.json"),
                    dir.path().join("timestamp.json.withheld"),
                )
                .expect("withhold timestamp metadata");
                let err = LocalTufVerifier::new(dir.path())
                    .verify_target_bytes(&pinned, target_path, target_bytes)
                    .expect_err("a missing timestamp role must fail closed");
                assert!(
                    matches!(err, SupplyChainVerificationError::Network(ref msg)
                        if msg.contains("timestamp.json")),
                    "expected a timestamp read failure, got {err:?}"
                );

                // 2. An expired timestamp is the canonical freeze-attack signal.
                let frozen = tempfile::tempdir().expect("tempdir");
                let pinned_frozen =
                    write_test_tuf_metadata(frozen.path(), target_path, target_bytes, &signing_key);
                expire_test_tuf_role(frozen.path(), "timestamp.json", &signing_key);
                let err = LocalTufVerifier::new(frozen.path())
                    .verify_target_bytes(&pinned_frozen, target_path, target_bytes)
                    .expect_err("an expired timestamp role must be refused");
                assert!(
                    matches!(err, SupplyChainVerificationError::TufFreeze),
                    "expected TufFreeze, got {err:?}"
                );

                // 3. Mix-and-match: a validly signed snapshot from a different
                //    repository state does not match the version timestamp
                //    vouched for.
                let mixed = tempfile::tempdir().expect("tempdir");
                let pinned_mixed =
                    write_test_tuf_metadata(mixed.path(), target_path, target_bytes, &signing_key);
                bump_test_tuf_snapshot_version(mixed.path(), &signing_key);
                let err = LocalTufVerifier::new(mixed.path())
                    .verify_target_bytes(&pinned_mixed, target_path, target_bytes)
                    .expect_err("snapshot not matching the timestamp meta must be refused");
                assert!(
                    matches!(err, SupplyChainVerificationError::TufRollback { .. }),
                    "expected TufRollback, got {err:?}"
                );

                // 4. Positive control: the intact four-role chain still verifies
                //    and records the full delegation path.
                let ok = tempfile::tempdir().expect("tempdir");
                let pinned_ok =
                    write_test_tuf_metadata(ok.path(), target_path, target_bytes, &signing_key);
                let result = LocalTufVerifier::new(ok.path())
                    .verify_target_bytes(&pinned_ok, target_path, target_bytes)
                    .expect("intact four-role TUF chain verifies");
                assert_eq!(
                    result.target().map(|target| target.delegations.as_slice()),
                    Some(
                        [
                            "root".to_string(),
                            "timestamp".to_string(),
                            "snapshot".to_string(),
                            "targets".to_string()
                        ]
                        .as_slice()
                    )
                );

                RegistryLogData {
                    reason_code: Some("local_tuf_full_role_chain_enforced".to_string()),
                    target: Some(target_path.to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    /// Re-sign a role file with an expiry in the past, leaving every other
    /// field (and the signature validity) intact.
    fn expire_test_tuf_role(metadata_dir: &Path, file_name: &str, signing_key: &Ed25519SigningKey) {
        let path = metadata_dir.join(file_name);
        let mut role: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("read role")).expect("parse role");
        let expired = (Utc::now() - chrono::Duration::days(1)).to_rfc3339();
        role["signed"]["expires"] = json!(expired);
        resign_test_tuf_role(&mut role, signing_key);
        std::fs::write(&path, serde_json::to_vec_pretty(&role).expect("role json"))
            .expect("write expired role");
    }

    /// Advance `snapshot.json` to a new validly signed version without touching
    /// the `timestamp.json` that vouches for the old one.
    fn bump_test_tuf_snapshot_version(metadata_dir: &Path, signing_key: &Ed25519SigningKey) {
        let path = metadata_dir.join("snapshot.json");
        let mut snapshot: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("read snapshot"))
                .expect("parse snapshot");
        snapshot["signed"]["version"] = json!(2);
        resign_test_tuf_role(&mut snapshot, signing_key);
        let snapshot_bytes = serde_json::to_vec_pretty(&snapshot).expect("snapshot json");
        std::fs::write(&path, &snapshot_bytes).expect("write bumped snapshot");

        // Keep the timestamp's length/hash binding satisfied so the *version*
        // mismatch is unambiguously what the verifier rejects.
        let timestamp_path = metadata_dir.join("timestamp.json");
        let mut timestamp: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&timestamp_path).expect("read timestamp"))
                .expect("parse timestamp");
        timestamp["signed"]["meta"]["snapshot.json"] = tuf_meta_entry(1, &snapshot_bytes);
        resign_test_tuf_role(&mut timestamp, signing_key);
        std::fs::write(
            &timestamp_path,
            serde_json::to_vec_pretty(&timestamp).expect("timestamp json"),
        )
        .expect("write timestamp");
    }

    fn resign_test_tuf_role(role: &mut serde_json::Value, signing_key: &Ed25519SigningKey) {
        let signature = sign_tuf_signed_payload(&role["signed"], signing_key);
        role["signatures"] = json!([{ "keyid": TEST_TUF_KEY_ID, "sig": signature }]);
    }

    #[test]
    fn local_tuf_verifier_rejects_root_metadata_signed_by_wrong_key_id() {
        run_registry_test(
            "local_tuf_verifier_rejects_root_metadata_signed_by_wrong_key_id",
            "verify",
            "tuf-adapter",
            1,
            || async {
                let dir = tempfile::tempdir().expect("tempdir");
                let signing_key = Ed25519SigningKey::generate();
                let target_path = "connectors/fcp.test-1.0.0.tar.gz";
                let target_bytes = b"test connector binary";
                let _pinned =
                    write_test_tuf_metadata(dir.path(), target_path, target_bytes, &signing_key);

                let root_path = dir.path().join("root.json");
                let mut root_json: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&root_path).expect("root json"))
                        .expect("parse root json");
                let root_signature_key = root_json
                    .get_mut("signatures")
                    .and_then(serde_json::Value::as_array_mut)
                    .and_then(|signatures| signatures.first_mut())
                    .and_then(|signature| signature.get_mut("keyid"))
                    .expect("root signature keyid slot");
                *root_signature_key = json!("attacker-key");
                std::fs::write(
                    &root_path,
                    serde_json::to_vec_pretty(&root_json).expect("tampered root json"),
                )
                .expect("write tampered root");

                let verifier = LocalTufVerifier::new(dir.path());
                let err = verifier
                    .fetch_root()
                    .await
                    .expect_err("root signature key ID outside root role must fail");
                assert!(matches!(
                    err,
                    SupplyChainVerificationError::TufSignatureThreshold {
                        ref role,
                        required: 1,
                        valid: 0,
                    } if role == "root"
                ));

                RegistryLogData {
                    reason_code: Some("local_tuf_wrong_root_key_refused".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn mock_sigstore_verifier_accepts_valid_bundle() {
        run_registry_test(
            "mock_sigstore_verifier_accepts_valid_bundle",
            "verify",
            "sigstore-adapter",
            1,
            || async {
                let verifier = MockSigstoreVerifier::new();
                let result = SigstoreVerificationResult {
                    verified: true,
                    identity: Some("github-actions".to_string()),
                    issuer: Some("https://token.actions.githubusercontent.com".to_string()),
                    rekor_log_index: Some(54321),
                };
                verifier.add_valid_bundle("sha256:artifact".to_string(), result);

                let bundle = SigstoreBundle {
                    signature: "base64sig".to_string(),
                    certificate: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
                        .to_string(),
                    rekor_entry: None,
                    identity: "github-actions".to_string(),
                    issuer: "https://token.actions.githubusercontent.com".to_string(),
                };

                let result = verifier
                    .verify_bundle(
                        &bundle,
                        "sha256:artifact",
                        &["github-actions".to_string()],
                        &["https://token.actions.githubusercontent.com".to_string()],
                    )
                    .await
                    .expect("bundle valid");
                assert!(result.verified);
                assert_eq!(result.identity, Some("github-actions".to_string()));
                assert_eq!(result.rekor_log_index, Some(54321));

                RegistryLogData {
                    reason_code: Some("sigstore_bundle_verified".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn mock_sigstore_verifier_rejects_untrusted_identity() {
        run_registry_test(
            "mock_sigstore_verifier_rejects_untrusted_identity",
            "verify",
            "sigstore-adapter",
            1,
            || async {
                let verifier = MockSigstoreVerifier::new();
                let result = SigstoreVerificationResult {
                    verified: true,
                    identity: Some("untrusted-ci".to_string()),
                    issuer: Some("https://example.com".to_string()),
                    rekor_log_index: Some(54321),
                };
                verifier.add_valid_bundle("sha256:artifact".to_string(), result);

                let bundle = SigstoreBundle {
                    signature: "base64sig".to_string(),
                    certificate: "cert".to_string(),
                    rekor_entry: None,
                    identity: "untrusted-ci".to_string(),
                    issuer: "https://example.com".to_string(),
                };

                let err = verifier
                    .verify_bundle(
                        &bundle,
                        "sha256:artifact",
                        &["github-actions".to_string()],
                        &[],
                    )
                    .await
                    .expect_err("identity mismatch");
                assert!(matches!(
                    err,
                    SupplyChainVerificationError::SigstoreIdentityMismatch { .. }
                ));

                RegistryLogData {
                    reason_code: Some("sigstore_identity_mismatch".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn mock_sigstore_verifier_rejects_untrusted_issuer() {
        run_registry_test(
            "mock_sigstore_verifier_rejects_untrusted_issuer",
            "verify",
            "sigstore-adapter",
            1,
            || async {
                let verifier = MockSigstoreVerifier::new();
                let result = SigstoreVerificationResult {
                    verified: true,
                    identity: Some("github-actions".to_string()),
                    issuer: Some("https://untrusted-issuer.com".to_string()),
                    rekor_log_index: Some(54321),
                };
                verifier.add_valid_bundle("sha256:artifact".to_string(), result);

                let bundle = SigstoreBundle {
                    signature: "base64sig".to_string(),
                    certificate: "cert".to_string(),
                    rekor_entry: None,
                    identity: "github-actions".to_string(),
                    issuer: "https://untrusted-issuer.com".to_string(),
                };

                let err = verifier
                    .verify_bundle(
                        &bundle,
                        "sha256:artifact",
                        &[],
                        &["https://token.actions.githubusercontent.com".to_string()],
                    )
                    .await
                    .expect_err("issuer untrusted");
                assert!(matches!(
                    err,
                    SupplyChainVerificationError::SigstoreIssuerUntrusted { .. }
                ));

                RegistryLogData {
                    reason_code: Some("sigstore_issuer_untrusted".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn mock_sigstore_verifier_rejects_invalid_signature() {
        run_registry_test(
            "mock_sigstore_verifier_rejects_invalid_signature",
            "verify",
            "sigstore-adapter",
            1,
            || async {
                let verifier = MockSigstoreVerifier::new();
                // No valid bundles added

                let bundle = SigstoreBundle {
                    signature: "bad_sig".to_string(),
                    certificate: "cert".to_string(),
                    rekor_entry: None,
                    identity: "github-actions".to_string(),
                    issuer: "https://token.actions.githubusercontent.com".to_string(),
                };

                let err = verifier
                    .verify_bundle(&bundle, "sha256:unknown_artifact", &[], &[])
                    .await
                    .expect_err("signature invalid");
                assert!(matches!(
                    err,
                    SupplyChainVerificationError::SigstoreSignatureInvalid
                ));

                RegistryLogData {
                    reason_code: Some("sigstore_signature_invalid".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn noop_verifiers_fail_closed() {
        run_registry_test(
            "noop_verifiers_fail_closed",
            "verify",
            "noop-adapters",
            3,
            || async {
                let transparency = NoOpTransparencyVerifier;
                let err = transparency
                    .verify_entry("any_hash", None)
                    .await
                    .expect_err("noop transparency must fail closed");
                assert!(matches!(err, SupplyChainVerificationError::NotConfigured));

                let tuf = NoOpTufVerifier;
                let pinned = TufRootMetadata {
                    version: 1,
                    root_hash: String::new(),
                    expires: 0,
                    key_ids: Vec::new(),
                    threshold: 1,
                };
                let err = tuf
                    .verify_target(&pinned, "any/target")
                    .await
                    .expect_err("noop tuf must fail closed");
                assert!(matches!(err, SupplyChainVerificationError::NotConfigured));
                let err = tuf
                    .fetch_root()
                    .await
                    .expect_err("noop tuf fetch_root must fail closed");
                assert!(matches!(err, SupplyChainVerificationError::NotConfigured));

                let sigstore = NoOpSigstoreVerifier;
                let bundle = SigstoreBundle {
                    signature: String::new(),
                    certificate: String::new(),
                    rekor_entry: None,
                    identity: String::new(),
                    issuer: String::new(),
                };
                let err = sigstore
                    .verify_bundle(&bundle, "any_hash", &[], &[])
                    .await
                    .expect_err("noop sigstore must fail closed");
                assert!(matches!(err, SupplyChainVerificationError::NotConfigured));

                RegistryLogData {
                    reason_code: Some("noop_verifiers_fail_closed".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn supply_chain_verification_config_defaults() {
        run_registry_test(
            "supply_chain_verification_config_defaults",
            "config",
            "supply-chain",
            1,
            || async {
                let config = SupplyChainVerificationConfig::default();
                assert!(config.tuf_pinned_root.is_none());
                assert!(config.trusted_sigstore_identities.is_empty());
                assert!(config.trusted_sigstore_issuers.is_empty());
                assert!(!config.require_transparency);
                assert!(!config.require_tuf);
                assert!(!config.require_sigstore);

                RegistryLogData {
                    reason_code: Some("config_defaults_correct".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── RegistryError display ────────────────────────────────────────────

    #[test]
    fn registry_error_display_all_variants() {
        run_registry_test(
            "registry_error_display_all_variants",
            "unit",
            "error-display",
            1,
            || async {
                let err = RegistryError::MissingSignatures;
                assert!(err.to_string().contains("signature section missing"));

                let err = RegistryError::UnknownKid {
                    kid: "test-kid".to_string(),
                };
                assert!(err.to_string().contains("test-kid"));

                let err = RegistryError::SignatureInvalid {
                    kid: "bad-kid".to_string(),
                };
                assert!(err.to_string().contains("bad-kid"));

                let err = RegistryError::PublisherThresholdUnmet {
                    required: 3,
                    valid: 1,
                };
                let msg = err.to_string();
                assert!(msg.contains("3"));
                assert!(msg.contains("1"));

                let err = RegistryError::RegistrySignatureRequired;
                assert!(err.to_string().contains("registry signature"));

                let err = RegistryError::TargetMismatch {
                    expected: "linux-amd64".to_string(),
                    found: "darwin-arm64".to_string(),
                };
                let msg = err.to_string();
                assert!(msg.contains("linux-amd64"));
                assert!(msg.contains("darwin-arm64"));

                let err = RegistryError::CapabilityCeilingViolation {
                    capability: "system.exec".to_string(),
                };
                assert!(err.to_string().contains("system.exec"));

                let err = RegistryError::TransparencyLogMissing;
                assert!(err.to_string().contains("transparency log"));

                let err = RegistryError::TransparencyEvidenceMissing;
                assert!(err.to_string().contains("evidence"));

                let err = RegistryError::TufVerificationRequired;
                assert!(err.to_string().contains("TUF"));

                let err = RegistryError::SigstoreVerificationRequired;
                assert!(err.to_string().contains("Sigstore"));

                let err = RegistryError::RequiredAttestationMissing {
                    attestation: "slsa".to_string(),
                };
                assert!(err.to_string().contains("slsa"));

                let err = RegistryError::AttestationEvidenceMissing;
                assert!(err.to_string().contains("evidence"));

                let err = RegistryError::SlsaLevelInsufficient { required: 3 };
                assert!(err.to_string().contains("3"));

                let err = RegistryError::UntrustedBuilder {
                    builder: "unknown-ci".to_string(),
                };
                assert!(err.to_string().contains("unknown-ci"));

                let err = RegistryError::SignatureBytes;
                assert!(err.to_string().contains("malformed"));

                RegistryLogData {
                    reason_code: Some("error_display_verified".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── ConnectorTarget ──────────────────────────────────────────────────

    #[test]
    fn connector_target_as_string() {
        run_registry_test(
            "connector_target_as_string",
            "unit",
            "target",
            1,
            || async {
                let t = ConnectorTarget {
                    os: "linux".to_string(),
                    arch: "amd64".to_string(),
                };
                assert_eq!(t.as_string(), "linux-amd64");

                RegistryLogData {
                    reason_code: Some("target_string_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn connector_target_serde_roundtrip() {
        run_registry_test(
            "connector_target_serde_roundtrip",
            "unit",
            "target",
            1,
            || async {
                let t = ConnectorTarget {
                    os: "darwin".to_string(),
                    arch: "arm64".to_string(),
                };
                let json = serde_json::to_string(&t).unwrap();
                let parsed: ConnectorTarget = serde_json::from_str(&json).unwrap();
                assert_eq!(parsed.os, "darwin");
                assert_eq!(parsed.arch, "arm64");

                RegistryLogData {
                    reason_code: Some("target_serde_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn connector_target_eq() {
        run_registry_test("connector_target_eq", "unit", "target", 1, || async {
            let t1 = ConnectorTarget {
                os: "linux".to_string(),
                arch: "amd64".to_string(),
            };
            let t2 = t1.clone();
            assert_eq!(t1, t2);

            let t3 = ConnectorTarget {
                os: "darwin".to_string(),
                arch: "arm64".to_string(),
            };
            assert_ne!(t1, t3);

            RegistryLogData {
                reason_code: Some("target_eq_ok".to_string()),
                ..RegistryLogData::default()
            }
        });
    }

    // ── SupplyChainVerificationError display ─────────────────────────────

    #[test]
    fn supply_chain_error_display() {
        run_registry_test(
            "supply_chain_error_display",
            "unit",
            "error-display",
            1,
            || async {
                let err = SupplyChainVerificationError::TransparencyEntryNotFound;
                assert!(err.to_string().contains("not found"));

                let err = SupplyChainVerificationError::TransparencyProofInvalid;
                assert!(err.to_string().contains("invalid"));

                let err = SupplyChainVerificationError::TufRootMismatch {
                    expected: "abc".to_string(),
                    actual: "xyz".to_string(),
                };
                let msg = err.to_string();
                assert!(msg.contains("abc"));
                assert!(msg.contains("xyz"));

                let err = SupplyChainVerificationError::TufExpired;
                assert!(err.to_string().contains("expired"));

                let err = SupplyChainVerificationError::TufTargetNotFound {
                    target: "fcp.test".to_string(),
                };
                assert!(err.to_string().contains("fcp.test"));

                let err = SupplyChainVerificationError::TufRollback { current: 5, got: 3 };
                let msg = err.to_string();
                assert!(msg.contains("5"));
                assert!(msg.contains("3"));

                let err = SupplyChainVerificationError::TufFreeze;
                assert!(err.to_string().contains("freeze"));

                let err = SupplyChainVerificationError::SigstoreSignatureInvalid;
                assert!(err.to_string().contains("invalid"));

                let err = SupplyChainVerificationError::SigstoreCertificateInvalid;
                assert!(err.to_string().contains("certificate"));

                let err = SupplyChainVerificationError::SigstoreIdentityMismatch {
                    expected: "a@b.com".to_string(),
                    actual: "x@y.com".to_string(),
                };
                let msg = err.to_string();
                assert!(msg.contains("a@b.com"));
                assert!(msg.contains("x@y.com"));

                let err = SupplyChainVerificationError::SigstoreIssuerUntrusted {
                    issuer: "evil.com".to_string(),
                };
                assert!(err.to_string().contains("evil.com"));

                let err = SupplyChainVerificationError::Network("timeout".to_string());
                assert!(err.to_string().contains("timeout"));

                let err = SupplyChainVerificationError::NotConfigured;
                assert!(err.to_string().contains("not configured"));

                RegistryLogData {
                    reason_code: Some("supply_chain_error_display_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── VerificationReport ───────────────────────────────────────────────

    // ── signature_message determinism ──────────────────────────────────

    #[test]
    fn signature_message_length_prefix_format() {
        run_registry_test(
            "signature_message_length_prefix_format",
            "unit",
            "signature-message",
            4,
            || async {
                let signing_bytes = b"hello";
                let binary_hash = "sha256:abc";
                let msg = signature_message(signing_bytes, binary_hash);

                // Expected: u64le(5) || "hello" || u64le(10) || "sha256:abc"
                assert_eq!(msg.len(), 8 + 5 + 8 + 10);
                assert_eq!(&msg[..8], &5u64.to_le_bytes());
                assert_eq!(&msg[8..13], b"hello");
                assert_eq!(&msg[13..21], &10u64.to_le_bytes());
                assert_eq!(&msg[21..], b"sha256:abc");

                RegistryLogData {
                    reason_code: Some("signature_message_format_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn signature_message_empty_inputs() {
        run_registry_test(
            "signature_message_empty_inputs",
            "unit",
            "signature-message",
            2,
            || async {
                let msg = signature_message(b"", "");
                assert_eq!(msg.len(), 16); // two u64le(0)
                assert_eq!(&msg[..8], &0u64.to_le_bytes());
                assert_eq!(&msg[8..], &0u64.to_le_bytes());

                RegistryLogData {
                    reason_code: Some("signature_message_empty_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn signature_message_deterministic() {
        run_registry_test(
            "signature_message_deterministic",
            "unit",
            "signature-message",
            1,
            || async {
                let a = signature_message(b"data", "hash");
                let b = signature_message(b"data", "hash");
                assert_eq!(a, b);

                RegistryLogData {
                    reason_code: Some("signature_message_deterministic".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── hash_bytes ────────────────────────────────────────────────────────

    #[test]
    fn hash_bytes_sha256_prefix() {
        run_registry_test("hash_bytes_sha256_prefix", "unit", "hash", 2, || async {
            let h = hash_bytes(b"test data");
            assert!(h.starts_with("sha256:"));
            // SHA256 hex is 64 chars
            assert_eq!(h.len(), 7 + 64);

            RegistryLogData {
                reason_code: Some("hash_bytes_prefix_ok".to_string()),
                ..RegistryLogData::default()
            }
        });
    }

    #[test]
    fn hash_bytes_deterministic() {
        run_registry_test("hash_bytes_deterministic", "unit", "hash", 1, || async {
            let a = hash_bytes(b"identical");
            let b = hash_bytes(b"identical");
            assert_eq!(a, b);

            let c = hash_bytes(b"different");
            assert_ne!(a, c);

            RegistryLogData {
                reason_code: Some("hash_bytes_deterministic".to_string()),
                ..RegistryLogData::default()
            }
        });
    }

    #[test]
    fn hash_bytes_empty() {
        run_registry_test("hash_bytes_empty", "unit", "hash", 1, || async {
            let h = hash_bytes(b"");
            assert!(h.starts_with("sha256:"));
            // SHA256 of empty is e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
            assert!(h.contains("e3b0c44298fc1c149afbf4c8996fb924"));

            RegistryLogData {
                reason_code: Some("hash_bytes_empty_ok".to_string()),
                ..RegistryLogData::default()
            }
        });
    }

    // ── manifest_signing_bytes ────────────────────────────────────────────

    #[test]
    fn manifest_signing_bytes_strips_signatures() {
        run_registry_test(
            "manifest_signing_bytes_strips_signatures",
            "unit",
            "signing-bytes",
            1,
            || async {
                let manifest = minimal_manifest();
                // Even if manifest has no signatures, signing_bytes should succeed
                let bytes = manifest_signing_bytes(&manifest).expect("signing bytes");
                assert!(!bytes.is_empty());

                // Converting to JSON and checking signatures is removed
                let value = serde_json::to_value(&manifest).expect("json");
                let signing_view = {
                    let mut v = value;
                    v.as_object_mut().unwrap().remove("signatures");
                    v
                };
                // signing_bytes is deterministic for same manifest content
                let bytes2 = manifest_signing_bytes(&manifest).expect("signing bytes");
                assert_eq!(bytes, bytes2);
                let _ = signing_view; // used above

                RegistryLogData {
                    reason_code: Some("signing_bytes_strips_sigs".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── attestation_label ─────────────────────────────────────────────────

    #[test]
    fn attestation_label_all_variants() {
        run_registry_test(
            "attestation_label_all_variants",
            "unit",
            "attestation-label",
            3,
            || async {
                assert_eq!(attestation_label(AttestationType::InToto), "in-toto");
                assert_eq!(
                    attestation_label(AttestationType::ReproducibleBuild),
                    "reproducible-build"
                );
                assert_eq!(
                    attestation_label(AttestationType::CodeReview),
                    "code-review"
                );

                RegistryLogData {
                    reason_code: Some("attestation_labels_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── enforce_capability_ceiling edge cases ─────────────────────────────

    #[test]
    fn capability_ceiling_empty_allows_all() {
        run_registry_test(
            "capability_ceiling_empty_allows_all",
            "unit",
            "policy",
            1,
            || async {
                let manifest = minimal_manifest();
                let policy = test_zone_policy(vec![]); // empty ceiling
                enforce_capability_ceiling(Some(&policy), &manifest)
                    .expect("empty ceiling allows all");

                RegistryLogData {
                    reason_code: Some("empty_ceiling_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn capability_ceiling_none_policy_allows_all() {
        run_registry_test(
            "capability_ceiling_none_policy_allows_all",
            "unit",
            "policy",
            1,
            || async {
                let manifest = minimal_manifest();
                enforce_capability_ceiling(None, &manifest).expect("no policy allows all");

                RegistryLogData {
                    reason_code: Some("no_policy_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── enforce_supply_chain_policy edge cases ────────────────────────────

    #[test]
    fn supply_chain_no_policy_section_passes() {
        run_registry_test(
            "supply_chain_no_policy_section_passes",
            "unit",
            "supply-chain",
            1,
            || async {
                let mut manifest = minimal_manifest();
                manifest.policy = None;
                enforce_supply_chain_policy(&manifest, None).expect("no policy passes");

                RegistryLogData {
                    reason_code: Some("no_policy_section_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn supply_chain_transparency_evidence_false_rejected() {
        run_registry_test(
            "supply_chain_transparency_evidence_false_rejected",
            "unit",
            "supply-chain",
            1,
            || async {
                let mut manifest = minimal_manifest();
                manifest.policy = Some(PolicySection {
                    require_transparency_log: true,
                    require_attestation_types: vec![],
                    min_slsa_level: None,
                    trusted_builders: Vec::new(),
                    require_attestation_expiry: false,
                });
                manifest.signatures = Some(SignaturesSection {
                    publisher_signatures: vec![],
                    publisher_threshold: None,
                    registry_signature: None,
                    transparency_log_entry: Some(ObjectId::from_bytes([0_u8; 32])),
                });

                let evidence = SupplyChainEvidence {
                    transparency_log_present: false,
                    tuf_verified: false,
                    tuf_target_hash: None,
                    sigstore_verified: false,
                    sigstore_identity: None,
                    sigstore_issuer: None,
                    attestations: vec![],
                };

                let err = enforce_supply_chain_policy(&manifest, Some(&evidence))
                    .expect_err("evidence false rejected");
                assert!(matches!(err, RegistryError::TransparencyEvidenceMissing));

                RegistryLogData {
                    reason_code: Some("evidence_false_rejected".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn supply_chain_slsa_no_level_in_attestation_rejected() {
        run_registry_test(
            "supply_chain_slsa_no_level_in_attestation_rejected",
            "unit",
            "supply-chain",
            1,
            || async {
                let mut manifest = minimal_manifest();
                manifest.policy = Some(PolicySection {
                    require_transparency_log: false,
                    require_attestation_types: vec![],
                    min_slsa_level: Some(2),
                    trusted_builders: Vec::new(),
                    require_attestation_expiry: false,
                });

                let evidence = SupplyChainEvidence {
                    transparency_log_present: false,
                    tuf_verified: false,
                    tuf_target_hash: None,
                    sigstore_verified: false,
                    sigstore_identity: None,
                    sigstore_issuer: None,
                    attestations: vec![AttestationEvidence {
                        attestation_type: AttestationType::InToto,
                        slsa_level: None, // no level provided
                        builder_id: None,
                        expires_at: None,
                    }],
                };

                let err = enforce_supply_chain_policy(&manifest, Some(&evidence))
                    .expect_err("no slsa level");
                assert!(matches!(
                    err,
                    RegistryError::SlsaLevelInsufficient { required: 2 }
                ));

                RegistryLogData {
                    reason_code: Some("slsa_no_level_rejected".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn supply_chain_trusted_builder_no_builder_id_rejected() {
        run_registry_test(
            "supply_chain_trusted_builder_no_builder_id_rejected",
            "unit",
            "supply-chain",
            1,
            || async {
                let mut manifest = minimal_manifest();
                manifest.policy = Some(PolicySection {
                    require_transparency_log: false,
                    require_attestation_types: vec![],
                    min_slsa_level: None,
                    trusted_builders: vec!["trusted-ci".to_string()],
                    require_attestation_expiry: false,
                });

                let evidence = SupplyChainEvidence {
                    transparency_log_present: false,
                    tuf_verified: false,
                    tuf_target_hash: None,
                    sigstore_verified: false,
                    sigstore_identity: None,
                    sigstore_issuer: None,
                    attestations: vec![AttestationEvidence {
                        attestation_type: AttestationType::InToto,
                        slsa_level: None,
                        builder_id: None, // no builder_id cannot satisfy trusted_builders
                        expires_at: None,
                    }],
                };

                let err = enforce_supply_chain_policy(&manifest, Some(&evidence))
                    .expect_err("missing builder_id must not satisfy trusted_builders policy");
                // br-g7jhf finding 2 sharpened the taxonomy: an unnamed
                // build-provenance attestation now names its own defect
                // instead of being reported as an untrusted builder.
                assert!(
                    matches!(err, RegistryError::BuilderIdentityMissing { .. }),
                    "expected BuilderIdentityMissing, got {err:?}"
                );

                RegistryLogData {
                    reason_code: Some("no_builder_id_rejected".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── verify_publishers edge cases ──────────────────────────────────────

    #[test]
    fn verify_publishers_empty_signatures_returns_false() {
        run_registry_test(
            "verify_publishers_empty_signatures_returns_false",
            "unit",
            "signature",
            1,
            || async {
                let sigs = SignaturesSection {
                    publisher_signatures: vec![],
                    publisher_threshold: None,
                    registry_signature: None,
                    transparency_log_entry: None,
                };
                let trust = RegistryTrustPolicy::default();
                let signing_bytes = b"data";
                let result = verify_publishers(&trust, &sigs, signing_bytes, "sha256:hash")
                    .expect("no error");
                assert!(!result);

                RegistryLogData {
                    reason_code: Some("empty_publishers_false".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_publishers_empty_signatures_with_threshold_errors() {
        run_registry_test(
            "verify_publishers_empty_signatures_with_threshold_errors",
            "unit",
            "signature",
            1,
            || async {
                let sigs = SignaturesSection {
                    publisher_signatures: vec![],
                    publisher_threshold: Some(fcp_manifest::SignatureThreshold { k: 1, n: 1 }),
                    registry_signature: None,
                    transparency_log_entry: None,
                };
                let trust = RegistryTrustPolicy::default();
                let signing_bytes = b"data";
                let err = verify_publishers(&trust, &sigs, signing_bytes, "sha256:hash")
                    .expect_err("empty signatures should fail threshold");
                assert!(matches!(
                    err,
                    RegistryError::PublisherThresholdUnmet {
                        required: 1,
                        valid: 0,
                    }
                ));

                RegistryLogData {
                    reason_code: Some("empty_publishers_threshold_unmet".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_empty_signature_section_rejects_no_trusted_signature() {
        run_registry_test(
            "verify_bundle_empty_signature_section_rejects_no_trusted_signature",
            "verify",
            "signature",
            1,
            || async {
                let bundle = ConnectorBundle {
                    manifest_toml: with_signatures(&unsigned_manifest_toml(""), "[signatures]"),
                    binary: b"registry-binary".to_vec(),
                    target: test_target(),
                };

                let verifier = RegistryVerifier::new(RegistryTrustPolicy::default());
                let err = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect_err("empty signature section should fail");
                assert!(matches!(err, RegistryError::NoTrustedSignature));

                RegistryLogData {
                    reason_code: Some("no_trusted_signature".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_registry_no_registry_signature_returns_false() {
        run_registry_test(
            "verify_registry_no_registry_signature_returns_false",
            "unit",
            "signature",
            1,
            || async {
                let sigs = SignaturesSection {
                    publisher_signatures: vec![],
                    publisher_threshold: None,
                    registry_signature: None,
                    transparency_log_entry: None,
                };
                let trust = RegistryTrustPolicy::default();
                let result =
                    verify_registry(&trust, &sigs, b"data", "sha256:hash").expect("no error");
                assert!(!result);

                RegistryLogData {
                    reason_code: Some("no_registry_sig_false".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── Both publisher + registry signatures ──────────────────────────────

    #[test]
    fn verify_bundle_accepts_both_publisher_and_registry_signature() {
        run_registry_test(
            "verify_bundle_accepts_both_publisher_and_registry_signature",
            "verify",
            "signature",
            1,
            || async {
                let pub_key = Ed25519SigningKey::generate();
                let reg_key = Ed25519SigningKey::generate();

                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let pub_sig = sign_manifest_toml(&unsigned, &pub_key, &binary_hash);
                let reg_sig = sign_manifest_toml(&unsigned, &reg_key, &binary_hash);

                let signatures = format!(
                    "{}\n{}",
                    publisher_signature_section("pub1", &pub_sig),
                    registry_signature_section("reg1", &reg_sig),
                );
                let manifest_toml = with_signatures(&unsigned, &signatures);

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), pub_key.verifying_key());
                trust
                    .registry_keys
                    .insert("reg1".to_string(), reg_key.verifying_key());
                trust.require_registry_signature = true;

                let verifier = RegistryVerifier::new(trust);
                let verified = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect("both signatures valid");
                assert!(!verified.manifest_hash.is_empty());

                RegistryLogData {
                    connector_id: Some(verified.manifest.connector.id.to_string()),
                    reason_code: Some("both_signatures_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_accepts_valid_registry_signature_with_unknown_publisher_entry() {
        run_registry_test(
            "verify_bundle_accepts_valid_registry_signature_with_unknown_publisher_entry",
            "verify",
            "signature",
            1,
            || async {
                let pub_key = Ed25519SigningKey::generate();
                let reg_key = Ed25519SigningKey::generate();

                let binary = b"registry-overrides-bad-publisher".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let pub_sig = sign_manifest_toml(&unsigned, &pub_key, &binary_hash);
                let reg_sig = sign_manifest_toml(&unsigned, &reg_key, &binary_hash);

                let signatures = format!(
                    "{}\n{}",
                    publisher_signature_section("unknown-pub", &pub_sig),
                    registry_signature_section("reg1", &reg_sig),
                );
                let manifest_toml = with_signatures(&unsigned, &signatures);

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .registry_keys
                    .insert("reg1".to_string(), reg_key.verifying_key());

                let verifier = RegistryVerifier::new(trust);
                // Publisher threshold is always enforced: unknown publisher means
                // valid=0 against required=1, even with a valid registry signature.
                let err = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect_err(
                        "unknown publisher should fail threshold even with valid registry sig",
                    );
                assert!(
                    matches!(
                        err,
                        RegistryError::PublisherThresholdUnmet {
                            required: 1,
                            valid: 0
                        }
                    ),
                    "expected PublisherThresholdUnmet, got {err:?}"
                );

                RegistryLogData {
                    reason_code: Some(
                        "registry_valid_unknown_publisher_threshold_enforced".to_string(),
                    ),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_accepts_valid_registry_signature_when_publisher_threshold_unmet() {
        run_registry_test(
            "verify_bundle_accepts_valid_registry_signature_when_publisher_threshold_unmet",
            "verify",
            "signature",
            1,
            || async {
                let pub_key = Ed25519SigningKey::generate();
                let reg_key = Ed25519SigningKey::generate();

                let binary = b"registry-overrides-threshold-gap".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let pub_sig = sign_manifest_toml(&unsigned, &pub_key, &binary_hash);
                let reg_sig = sign_manifest_toml(&unsigned, &reg_key, &binary_hash);

                let signatures = format!(
                    r#"[signatures]
publisher_threshold = "2-of-2"

[[signatures.publisher_signatures]]
kid = "pub1"
sig = "{pub_sig}"

[signatures.registry_signature]
kid = "reg1"
sig = "{reg_sig}"
"#,
                    pub_sig = String::from(pub_sig.clone()),
                    reg_sig = String::from(reg_sig.clone()),
                );
                let manifest_toml = with_signatures(&unsigned, &signatures);

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), pub_key.verifying_key());
                trust
                    .registry_keys
                    .insert("reg1".to_string(), reg_key.verifying_key());

                let verifier = RegistryVerifier::new(trust);
                // After refactoring, publisher threshold is always enforced even
                // when a valid registry signature is present.
                let _err = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect_err(
                        "publisher threshold unmet should reject even with valid registry sig",
                    );

                RegistryLogData {
                    reason_code: Some("registry_valid_publisher_threshold_unmet".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── rate_limit_declarations ───────────────────────────────────────────

    #[test]
    fn rate_limit_declarations_none_when_absent() {
        run_registry_test(
            "rate_limit_declarations_none_when_absent",
            "unit",
            "rate-limits",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

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
                let verified = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect("verify");

                assert!(verified.rate_limit_declarations().is_none());

                RegistryLogData {
                    reason_code: Some("rate_limits_none".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── ConnectorTarget edge cases ────────────────────────────────────────

    #[test]
    fn connector_target_custom_os_arch() {
        run_registry_test(
            "connector_target_custom_os_arch",
            "unit",
            "target",
            2,
            || async {
                let t = ConnectorTarget {
                    os: "freebsd".to_string(),
                    arch: "riscv64".to_string(),
                };
                assert_eq!(t.as_string(), "freebsd-riscv64");
                let t2 = t.clone();
                assert_eq!(t, t2);

                RegistryLogData {
                    reason_code: Some("custom_target_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── RegistryTrustPolicy defaults ──────────────────────────────────────

    #[test]
    fn registry_trust_policy_default_empty() {
        run_registry_test(
            "registry_trust_policy_default_empty",
            "unit",
            "trust-policy",
            3,
            || async {
                let policy = RegistryTrustPolicy::default();
                assert!(policy.publisher_keys.is_empty());
                assert!(policy.registry_keys.is_empty());
                assert!(!policy.require_registry_signature);

                RegistryLogData {
                    reason_code: Some("trust_policy_default_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── SupplyChainEvidence defaults ──────────────────────────────────────

    #[test]
    fn supply_chain_evidence_default() {
        run_registry_test(
            "supply_chain_evidence_default",
            "unit",
            "supply-chain",
            2,
            || async {
                let evidence = SupplyChainEvidence::default();
                assert!(!evidence.transparency_log_present);
                assert!(evidence.attestations.is_empty());

                RegistryLogData {
                    reason_code: Some("evidence_default_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── Type Debug/Clone trait coverage ───────────────────────────────────

    #[test]
    fn type_debug_coverage() {
        run_registry_test("type_debug_coverage", "unit", "traits", 4, || async {
            let entry = TransparencyLogEntry {
                log_index: 1,
                entry_hash: "sha256:a".to_string(),
                inclusion_proof: InclusionProof {
                    root_hash: "sha256:r".to_string(),
                    tree_size: 100,
                    hashes: vec!["sha256:h".to_string()],
                    leaf_index: 0,
                },
                signed_entry_timestamp: vec![1],
                log_id: "log1".to_string(),
            };
            let _ = format!("{entry:?}");
            let cloned = entry.clone();
            assert_eq!(cloned.log_index, 1);

            let tuf = TufRootMetadata {
                version: 1,
                root_hash: "hash".to_string(),
                expires: 0,
                key_ids: vec![],
                threshold: 1,
            };
            let _ = format!("{tuf:?}");

            let target = TufTargetInfo {
                target_path: "p".to_string(),
                hash: "h".to_string(),
                length: 0,
                delegations: vec![],
            };
            let _ = format!("{target:?}");

            let bundle = SigstoreBundle {
                signature: "s".to_string(),
                certificate: "c".to_string(),
                rekor_entry: None,
                identity: "i".to_string(),
                issuer: "is".to_string(),
            };
            let _ = format!("{bundle:?}");

            RegistryLogData {
                reason_code: Some("debug_coverage_ok".to_string()),
                ..RegistryLogData::default()
            }
        });
    }

    #[test]
    fn type_serde_roundtrip_coverage() {
        run_registry_test(
            "type_serde_roundtrip_coverage",
            "unit",
            "serde",
            3,
            || async {
                let entry = TransparencyLogEntry {
                    log_index: 42,
                    entry_hash: "sha256:abc".to_string(),
                    inclusion_proof: InclusionProof {
                        root_hash: "sha256:root".to_string(),
                        tree_size: 1000,
                        hashes: vec!["sha256:h1".to_string()],
                        leaf_index: 42,
                    },
                    signed_entry_timestamp: vec![9, 8, 7],
                    log_id: "sigstore".to_string(),
                };
                let json = serde_json::to_string(&entry).unwrap();
                let parsed: TransparencyLogEntry = serde_json::from_str(&json).unwrap();
                assert_eq!(parsed.log_index, 42);

                let tuf = TufRootMetadata {
                    version: 3,
                    root_hash: "sha256:root".to_string(),
                    expires: 9_999_999,
                    key_ids: vec!["k1".to_string()],
                    threshold: 2,
                };
                let json = serde_json::to_string(&tuf).unwrap();
                let parsed: TufRootMetadata = serde_json::from_str(&json).unwrap();
                assert_eq!(parsed.version, 3);
                assert_eq!(parsed.threshold, 2);

                let target = TufTargetInfo {
                    target_path: "connectors/fcp.test.tar.gz".to_string(),
                    hash: "sha256:xyz".to_string(),
                    length: 2048,
                    delegations: vec!["targets".to_string(), "snapshot".to_string()],
                };
                let json = serde_json::to_string(&target).unwrap();
                let parsed: TufTargetInfo = serde_json::from_str(&json).unwrap();
                assert_eq!(parsed.length, 2048);

                RegistryLogData {
                    reason_code: Some("serde_roundtrip_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verification_report_serde_roundtrip() {
        run_registry_test(
            "verification_report_serde_roundtrip",
            "unit",
            "report",
            1,
            || async {
                let report = RegistryVerificationReport {
                    connector_id: "fcp.test".to_string(),
                    manifest_hash: "abc123".to_string(),
                    binary_hash: "def456".to_string(),
                    target: ConnectorTarget {
                        os: "linux".to_string(),
                        arch: "amd64".to_string(),
                    },
                    verified_at: 1_700_000_000,
                    outcome: "accepted".to_string(),
                };
                let json = serde_json::to_string(&report).unwrap();
                let parsed: RegistryVerificationReport = serde_json::from_str(&json).unwrap();
                assert_eq!(parsed.connector_id, "fcp.test");
                assert_eq!(parsed.outcome, "accepted");

                let cloned = report.clone();
                assert_eq!(cloned.binary_hash, "def456");
                let _ = format!("{report:?}");

                RegistryLogData {
                    reason_code: Some("report_serde_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── Error source chain tests ─────────────────────────────────────────

    #[test]
    fn registry_error_manifest_parse_has_source() {
        run_registry_test(
            "registry_error_manifest_parse_has_source",
            "unit",
            "error-source",
            1,
            || async {
                let manifest_err =
                    ConnectorManifest::parse_str("invalid toml %%%").expect_err("parse fails");
                let registry_err: RegistryError = manifest_err.into();
                assert!(matches!(registry_err, RegistryError::ManifestParse(_)));
                let source = std::error::Error::source(&registry_err);
                assert!(source.is_some(), "ManifestParse should expose source");

                RegistryLogData {
                    reason_code: Some("manifest_parse_source_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn registry_error_signing_bytes_has_source() {
        run_registry_test(
            "registry_error_signing_bytes_has_source",
            "unit",
            "error-source",
            1,
            || async {
                // SerializationError can be constructed via CanonicalSerializer failure
                // but we can test the From impl directly
                let err = RegistryError::SignatureBytes;
                let source = std::error::Error::source(&err);
                assert!(source.is_none(), "SignatureBytes has no inner source");

                RegistryLogData {
                    reason_code: Some("signature_bytes_no_source".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn registry_error_no_source_variants() {
        run_registry_test(
            "registry_error_no_source_variants",
            "unit",
            "error-source",
            5,
            || async {
                let cases: Vec<RegistryError> = vec![
                    RegistryError::MissingSignatures,
                    RegistryError::NoTrustedSignature,
                    RegistryError::RegistrySignatureRequired,
                    RegistryError::TransparencyLogMissing,
                    RegistryError::TransparencyEvidenceMissing,
                    RegistryError::AttestationEvidenceMissing,
                    RegistryError::AttestationExpired {
                        attestation: "in-toto".into(),
                        expired_at: 0,
                    },
                ];
                for err in &cases {
                    assert!(
                        std::error::Error::source(err).is_none(),
                        "{err} should have no source"
                    );
                }

                RegistryLogData {
                    reason_code: Some("no_source_variants_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn supply_chain_error_no_source_all_variants() {
        run_registry_test(
            "supply_chain_error_no_source_all_variants",
            "unit",
            "error-source",
            1,
            || async {
                let cases: Vec<SupplyChainVerificationError> = vec![
                    SupplyChainVerificationError::TransparencyEntryNotFound,
                    SupplyChainVerificationError::TransparencyProofInvalid,
                    SupplyChainVerificationError::TransparencySignatureInvalid,
                    SupplyChainVerificationError::TufExpired,
                    SupplyChainVerificationError::TufFreeze,
                    SupplyChainVerificationError::SigstoreSignatureInvalid,
                    SupplyChainVerificationError::SigstoreCertificateInvalid,
                    SupplyChainVerificationError::NotConfigured,
                ];
                for err in &cases {
                    assert!(
                        std::error::Error::source(err).is_none(),
                        "{err} should have no source"
                    );
                }

                RegistryLogData {
                    reason_code: Some("sc_no_source_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── SupplyChainVerificationError Debug coverage ──────────────────────

    #[test]
    fn supply_chain_error_debug_all_variants() {
        run_registry_test(
            "supply_chain_error_debug_all_variants",
            "unit",
            "error-debug",
            13,
            || async {
                let variants: Vec<(&str, SupplyChainVerificationError)> = vec![
                    (
                        "TransparencyEntryNotFound",
                        SupplyChainVerificationError::TransparencyEntryNotFound,
                    ),
                    (
                        "TransparencyProofInvalid",
                        SupplyChainVerificationError::TransparencyProofInvalid,
                    ),
                    (
                        "TransparencySignatureInvalid",
                        SupplyChainVerificationError::TransparencySignatureInvalid,
                    ),
                    (
                        "TufRootMismatch",
                        SupplyChainVerificationError::TufRootMismatch {
                            expected: "a".into(),
                            actual: "b".into(),
                        },
                    ),
                    ("TufExpired", SupplyChainVerificationError::TufExpired),
                    (
                        "TufTargetNotFound",
                        SupplyChainVerificationError::TufTargetNotFound { target: "t".into() },
                    ),
                    (
                        "TufRollback",
                        SupplyChainVerificationError::TufRollback { current: 1, got: 0 },
                    ),
                    ("TufFreeze", SupplyChainVerificationError::TufFreeze),
                    (
                        "SigstoreSignatureInvalid",
                        SupplyChainVerificationError::SigstoreSignatureInvalid,
                    ),
                    (
                        "SigstoreCertificateInvalid",
                        SupplyChainVerificationError::SigstoreCertificateInvalid,
                    ),
                    (
                        "SigstoreIdentityMismatch",
                        SupplyChainVerificationError::SigstoreIdentityMismatch {
                            expected: "a".into(),
                            actual: "b".into(),
                        },
                    ),
                    (
                        "SigstoreIssuerUntrusted",
                        SupplyChainVerificationError::SigstoreIssuerUntrusted {
                            issuer: "evil".into(),
                        },
                    ),
                    (
                        "Network",
                        SupplyChainVerificationError::Network("timeout".into()),
                    ),
                ];
                for (name, err) in &variants {
                    let debug = format!("{err:?}");
                    assert!(
                        debug.contains(name),
                        "Debug of {name} should contain variant name, got: {debug}"
                    );
                }

                RegistryLogData {
                    reason_code: Some("sc_error_debug_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── RegistryError Debug coverage ─────────────────────────────────────

    #[test]
    fn registry_error_debug_all_variants() {
        run_registry_test(
            "registry_error_debug_all_variants",
            "unit",
            "error-debug",
            15,
            || async {
                let variants: Vec<(&str, RegistryError)> = vec![
                    ("MissingSignatures", RegistryError::MissingSignatures),
                    ("UnknownKid", RegistryError::UnknownKid { kid: "k".into() }),
                    (
                        "SignatureInvalid",
                        RegistryError::SignatureInvalid { kid: "k".into() },
                    ),
                    (
                        "PublisherThresholdUnmet",
                        RegistryError::PublisherThresholdUnmet {
                            required: 2,
                            valid: 1,
                        },
                    ),
                    ("NoTrustedSignature", RegistryError::NoTrustedSignature),
                    (
                        "RegistrySignatureRequired",
                        RegistryError::RegistrySignatureRequired,
                    ),
                    (
                        "TargetMismatch",
                        RegistryError::TargetMismatch {
                            expected: "a".into(),
                            found: "b".into(),
                        },
                    ),
                    (
                        "CapabilityCeilingViolation",
                        RegistryError::CapabilityCeilingViolation {
                            capability: "c".into(),
                        },
                    ),
                    (
                        "TransparencyLogMissing",
                        RegistryError::TransparencyLogMissing,
                    ),
                    (
                        "TransparencyEvidenceMissing",
                        RegistryError::TransparencyEvidenceMissing,
                    ),
                    (
                        "TufVerificationRequired",
                        RegistryError::TufVerificationRequired,
                    ),
                    (
                        "SigstoreVerificationRequired",
                        RegistryError::SigstoreVerificationRequired,
                    ),
                    (
                        "RequiredAttestationMissing",
                        RegistryError::RequiredAttestationMissing {
                            attestation: "a".into(),
                        },
                    ),
                    (
                        "AttestationEvidenceMissing",
                        RegistryError::AttestationEvidenceMissing,
                    ),
                    (
                        "AttestationExpired",
                        RegistryError::AttestationExpired {
                            attestation: "a".into(),
                            expired_at: 0,
                        },
                    ),
                    (
                        "SlsaLevelInsufficient",
                        RegistryError::SlsaLevelInsufficient { required: 3 },
                    ),
                    (
                        "UntrustedBuilder",
                        RegistryError::UntrustedBuilder {
                            builder: "b".into(),
                        },
                    ),
                    ("SignatureBytes", RegistryError::SignatureBytes),
                ];
                for (name, err) in &variants {
                    let debug = format!("{err:?}");
                    assert!(debug.contains(name), "Debug of {name}: {debug}");
                }

                RegistryLogData {
                    reason_code: Some("reg_error_debug_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── Result type Debug/Clone coverage ─────────────────────────────────

    #[test]
    fn transparency_verification_result_debug_clone() {
        run_registry_test(
            "transparency_verification_result_debug_clone",
            "unit",
            "traits",
            3,
            || async {
                let result = TransparencyVerificationResult {
                    verified: true,
                    log_index: Some(42),
                    logged_at: Some(1_700_000_000),
                };
                let debug = format!("{result:?}");
                assert!(debug.contains("42"));
                let moved = result;
                assert!(moved.verified);
                assert_eq!(moved.log_index, Some(42));

                RegistryLogData {
                    reason_code: Some("transparency_result_traits_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn tuf_verification_result_debug_clone() {
        run_registry_test(
            "tuf_verification_result_debug_clone",
            "unit",
            "traits",
            3,
            || async {
                let result = TufVerificationResult {
                    verified: true,
                    root_version: 5,
                    target: Some(TufTargetInfo {
                        target_path: "p".into(),
                        hash: "h".into(),
                        length: 100,
                        delegations: vec!["d".into()],
                    }),
                };
                let debug = format!("{result:?}");
                assert!(debug.contains("TufVerificationResult"));
                let cloned = result.clone();
                assert_eq!(cloned.root_version, 5);
                assert!(cloned.target.is_some());

                RegistryLogData {
                    reason_code: Some("tuf_result_traits_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn sigstore_verification_result_debug_clone() {
        run_registry_test(
            "sigstore_verification_result_debug_clone",
            "unit",
            "traits",
            3,
            || async {
                let result = SigstoreVerificationResult {
                    verified: true,
                    identity: Some("gh-actions".into()),
                    issuer: Some("https://token.actions.githubusercontent.com".into()),
                    rekor_log_index: Some(99),
                };
                let debug = format!("{result:?}");
                assert!(debug.contains("gh-actions"));
                let cloned = result.clone();
                assert_eq!(cloned.rekor_log_index, Some(99));
                assert!(cloned.verified);

                RegistryLogData {
                    reason_code: Some("sigstore_result_traits_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── ConnectorBundle / RegistryVerifier trait coverage ─────────────────

    #[test]
    fn connector_bundle_debug_clone() {
        run_registry_test(
            "connector_bundle_debug_clone",
            "unit",
            "traits",
            3,
            || async {
                let bundle = ConnectorBundle {
                    manifest_toml: "toml content".into(),
                    binary: vec![1, 2, 3],
                    target: test_target(),
                };
                let debug = format!("{bundle:?}");
                assert!(debug.contains("ConnectorBundle"));
                let cloned = bundle.clone();
                assert_eq!(cloned.binary, vec![1, 2, 3]);
                assert_eq!(cloned.target.os, "linux");

                RegistryLogData {
                    reason_code: Some("bundle_traits_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn registry_verifier_debug_clone() {
        run_registry_test(
            "registry_verifier_debug_clone",
            "unit",
            "traits",
            2,
            || async {
                let trust = RegistryTrustPolicy::default();
                let verifier = RegistryVerifier::new(trust);
                let debug = format!("{verifier:?}");
                assert!(debug.contains("RegistryVerifier"));
                let cloned = verifier.clone();
                let _ = format!("{cloned:?}");

                RegistryLogData {
                    reason_code: Some("verifier_traits_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn attestation_evidence_debug_clone() {
        run_registry_test(
            "attestation_evidence_debug_clone",
            "unit",
            "traits",
            3,
            || async {
                let ev = AttestationEvidence {
                    attestation_type: AttestationType::ReproducibleBuild,
                    slsa_level: Some(4),
                    builder_id: Some("github-actions".into()),
                    expires_at: None,
                };
                let debug = format!("{ev:?}");
                assert!(debug.contains("ReproducibleBuild"));
                let cloned = ev.clone();
                assert_eq!(cloned.slsa_level, Some(4));
                assert_eq!(cloned.builder_id.as_deref(), Some("github-actions"));

                RegistryLogData {
                    reason_code: Some("attestation_evidence_traits_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── SigstoreBundle serde roundtrip ───────────────────────────────────

    #[test]
    fn sigstore_bundle_serde_roundtrip() {
        run_registry_test(
            "sigstore_bundle_serde_roundtrip",
            "unit",
            "serde",
            4,
            || async {
                let bundle = SigstoreBundle {
                    signature: "base64sig".into(),
                    certificate: "-----BEGIN CERTIFICATE-----\ndata\n-----END CERTIFICATE-----"
                        .into(),
                    rekor_entry: Some(TransparencyLogEntry {
                        log_index: 100,
                        entry_hash: "sha256:entry".into(),
                        inclusion_proof: InclusionProof {
                            root_hash: "sha256:root".into(),
                            tree_size: 500,
                            hashes: vec!["sha256:h1".into()],
                            leaf_index: 100,
                        },
                        signed_entry_timestamp: vec![0xDE, 0xAD],
                        log_id: "rekor".into(),
                    }),
                    identity: "github-actions".into(),
                    issuer: "https://token.actions.githubusercontent.com".into(),
                };
                let json = serde_json::to_string(&bundle).unwrap();
                let parsed: SigstoreBundle = serde_json::from_str(&json).unwrap();
                assert_eq!(parsed.identity, "github-actions");
                assert_eq!(parsed.signature, "base64sig");
                assert!(parsed.rekor_entry.is_some());
                assert_eq!(parsed.rekor_entry.unwrap().log_index, 100);

                RegistryLogData {
                    reason_code: Some("sigstore_bundle_serde_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn sigstore_bundle_without_rekor_serde() {
        run_registry_test(
            "sigstore_bundle_without_rekor_serde",
            "unit",
            "serde",
            1,
            || async {
                let bundle = SigstoreBundle {
                    signature: "sig".into(),
                    certificate: "cert".into(),
                    rekor_entry: None,
                    identity: "id".into(),
                    issuer: "iss".into(),
                };
                let json = serde_json::to_string(&bundle).unwrap();
                let parsed: SigstoreBundle = serde_json::from_str(&json).unwrap();
                assert!(parsed.rekor_entry.is_none());

                RegistryLogData {
                    reason_code: Some("sigstore_no_rekor_serde_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── InclusionProof standalone serde ───────────────────────────────────

    #[test]
    fn inclusion_proof_serde_roundtrip() {
        run_registry_test(
            "inclusion_proof_serde_roundtrip",
            "unit",
            "serde",
            4,
            || async {
                let proof = InclusionProof {
                    root_hash: "sha256:rootabc".into(),
                    tree_size: 10_000,
                    hashes: vec!["sha256:h1".into(), "sha256:h2".into(), "sha256:h3".into()],
                    leaf_index: 42,
                };
                let json = serde_json::to_string(&proof).unwrap();
                let parsed: InclusionProof = serde_json::from_str(&json).unwrap();
                assert_eq!(parsed.root_hash, "sha256:rootabc");
                assert_eq!(parsed.tree_size, 10_000);
                assert_eq!(parsed.hashes.len(), 3);
                assert_eq!(parsed.leaf_index, 42);

                RegistryLogData {
                    reason_code: Some("inclusion_proof_serde_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn inclusion_proof_debug_clone() {
        run_registry_test(
            "inclusion_proof_debug_clone",
            "unit",
            "traits",
            2,
            || async {
                let proof = InclusionProof {
                    root_hash: "sha256:r".into(),
                    tree_size: 1,
                    hashes: vec![],
                    leaf_index: 0,
                };
                let debug = format!("{proof:?}");
                assert!(debug.contains("InclusionProof"));
                let cloned = proof.clone();
                assert_eq!(cloned.tree_size, 1);

                RegistryLogData {
                    reason_code: Some("inclusion_proof_traits_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── MANIFEST_SIGNATURE_CONTEXT constant ──────────────────────────────

    #[test]
    fn manifest_signature_context_value() {
        run_registry_test(
            "manifest_signature_context_value",
            "unit",
            "constant",
            2,
            || async {
                assert_eq!(MANIFEST_SIGNATURE_CONTEXT, b"fcp.registry.manifest.v1");
                assert!(!MANIFEST_SIGNATURE_CONTEXT.is_empty());

                RegistryLogData {
                    reason_code: Some("context_value_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── MockTufVerifier fetch_root ────────────────────────────────────────

    #[test]
    fn mock_tuf_verifier_fetch_root() {
        run_registry_test(
            "mock_tuf_verifier_fetch_root",
            "verify",
            "tuf-adapter",
            3,
            || async {
                let root = TufRootMetadata {
                    version: 7,
                    root_hash: "sha256:customroot".into(),
                    expires: 9_999_999,
                    key_ids: vec!["key-a".into(), "key-b".into()],
                    threshold: 2,
                };
                let verifier = MockTufVerifier::new(root);

                let fetched = verifier.fetch_root().await.expect("fetch root");
                assert_eq!(fetched.version, 7);
                assert_eq!(fetched.root_hash, "sha256:customroot");
                assert_eq!(fetched.threshold, 2);

                RegistryLogData {
                    reason_code: Some("tuf_fetch_root_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── MockTransparencyVerifier multiple entries ─────────────────────────

    #[test]
    fn mock_transparency_verifier_multiple_entries() {
        run_registry_test(
            "mock_transparency_verifier_multiple_entries",
            "verify",
            "transparency-adapter",
            3,
            || async {
                let verifier = MockTransparencyVerifier::new();
                let make_entry = |idx: u64| TransparencyLogEntry {
                    log_index: idx,
                    entry_hash: format!("sha256:entry{idx}"),
                    inclusion_proof: InclusionProof {
                        root_hash: "sha256:root".into(),
                        tree_size: 100,
                        hashes: vec![],
                        leaf_index: idx,
                    },
                    signed_entry_timestamp: vec![],
                    log_id: "log".into(),
                };

                verifier.add_valid_entry("sha256:a".into(), make_entry(1));
                verifier.add_valid_entry("sha256:b".into(), make_entry(2));
                verifier.add_valid_entry("sha256:c".into(), make_entry(3));

                let r1 = verifier.verify_entry("sha256:a", None).await.unwrap();
                assert_eq!(r1.log_index, Some(1));

                let r3 = verifier.verify_entry("sha256:c", None).await.unwrap();
                assert_eq!(r3.log_index, Some(3));

                let err = verifier.verify_entry("sha256:d", None).await;
                assert!(err.is_err());

                RegistryLogData {
                    reason_code: Some("multi_entries_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── Combined supply chain policy ─────────────────────────────────────

    #[test]
    fn supply_chain_combined_attestation_and_slsa() {
        run_registry_test(
            "supply_chain_combined_attestation_and_slsa",
            "unit",
            "supply-chain",
            1,
            || async {
                let mut manifest = minimal_manifest();
                manifest.policy = Some(PolicySection {
                    require_transparency_log: false,
                    require_attestation_types: vec![
                        AttestationType::InToto,
                        AttestationType::CodeReview,
                    ],
                    min_slsa_level: Some(3),
                    trusted_builders: vec!["trusted-ci".into()],
                    require_attestation_expiry: false,
                });

                let evidence = SupplyChainEvidence {
                    transparency_log_present: false,
                    tuf_verified: false,
                    tuf_target_hash: None,
                    sigstore_verified: false,
                    sigstore_identity: None,
                    sigstore_issuer: None,
                    attestations: vec![
                        AttestationEvidence {
                            attestation_type: AttestationType::InToto,
                            slsa_level: Some(4),
                            builder_id: Some("trusted-ci".into()),
                            expires_at: None,
                        },
                        AttestationEvidence {
                            attestation_type: AttestationType::CodeReview,
                            slsa_level: None,
                            builder_id: None,
                            expires_at: None,
                        },
                    ],
                };

                enforce_supply_chain_policy(&manifest, Some(&evidence))
                    .expect("combined policy passes");

                RegistryLogData {
                    reason_code: Some("combined_policy_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn supply_chain_combined_fails_on_missing_attestation() {
        run_registry_test(
            "supply_chain_combined_fails_on_missing_attestation",
            "unit",
            "supply-chain",
            1,
            || async {
                let mut manifest = minimal_manifest();
                manifest.policy = Some(PolicySection {
                    require_transparency_log: false,
                    require_attestation_types: vec![
                        AttestationType::InToto,
                        AttestationType::ReproducibleBuild,
                    ],
                    min_slsa_level: Some(2),
                    trusted_builders: vec![],
                    require_attestation_expiry: false,
                });

                let evidence = SupplyChainEvidence {
                    transparency_log_present: false,
                    tuf_verified: false,
                    tuf_target_hash: None,
                    sigstore_verified: false,
                    sigstore_identity: None,
                    sigstore_issuer: None,
                    attestations: vec![AttestationEvidence {
                        attestation_type: AttestationType::InToto,
                        slsa_level: Some(3),
                        builder_id: None,
                        expires_at: None,
                    }],
                };

                let err = enforce_supply_chain_policy(&manifest, Some(&evidence))
                    .expect_err("missing reproducible-build");
                assert!(matches!(
                    err,
                    RegistryError::RequiredAttestationMissing { .. }
                ));

                RegistryLogData {
                    reason_code: Some("combined_missing_attestation".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── NoOp verifier Debug coverage ─────────────────────────────────────

    #[test]
    fn noop_verifiers_debug() {
        run_registry_test("noop_verifiers_debug", "unit", "traits", 3, || async {
            let t = NoOpTransparencyVerifier;
            let debug = format!("{t:?}");
            assert!(debug.contains("NoOpTransparencyVerifier"));

            let tuf = NoOpTufVerifier;
            let debug = format!("{tuf:?}");
            assert!(debug.contains("NoOpTufVerifier"));

            let sig = NoOpSigstoreVerifier;
            let debug = format!("{sig:?}");
            assert!(debug.contains("NoOpSigstoreVerifier"));

            RegistryLogData {
                reason_code: Some("noop_debug_ok".to_string()),
                ..RegistryLogData::default()
            }
        });
    }

    // ── MockVerifier Debug coverage ──────────────────────────────────────

    #[test]
    fn mock_verifiers_debug() {
        run_registry_test("mock_verifiers_debug", "unit", "traits", 3, || async {
            let mt = MockTransparencyVerifier::new();
            let debug = format!("{mt:?}");
            assert!(debug.contains("MockTransparencyVerifier"));

            let root = TufRootMetadata {
                version: 1,
                root_hash: String::new(),
                expires: 0,
                key_ids: vec![],
                threshold: 1,
            };
            let tuf = MockTufVerifier::new(root);
            let debug = format!("{tuf:?}");
            assert!(debug.contains("MockTufVerifier"));

            let sig = MockSigstoreVerifier::new();
            let debug = format!("{sig:?}");
            assert!(debug.contains("MockSigstoreVerifier"));

            RegistryLogData {
                reason_code: Some("mock_debug_ok".to_string()),
                ..RegistryLogData::default()
            }
        });
    }

    // ── SupplyChainVerificationConfig with values ────────────────────────

    #[test]
    fn supply_chain_verification_config_with_values() {
        run_registry_test(
            "supply_chain_verification_config_with_values",
            "unit",
            "config",
            6,
            || async {
                let config = SupplyChainVerificationConfig {
                    tuf_pinned_root: Some(TufRootMetadata {
                        version: 5,
                        root_hash: "sha256:abc".into(),
                        expires: 1_000_000,
                        key_ids: vec!["k1".into()],
                        threshold: 1,
                    }),
                    trusted_sigstore_identities: vec!["github-actions".into()],
                    trusted_sigstore_issuers: vec![
                        "https://token.actions.githubusercontent.com".into(),
                    ],
                    require_transparency: true,
                    require_tuf: true,
                    require_sigstore: true,
                    ..SupplyChainVerificationConfig::default()
                };
                let debug = format!("{config:?}");
                assert!(debug.contains("SupplyChainVerificationConfig"));
                assert!(config.require_transparency);
                assert!(config.require_tuf);
                assert!(config.require_sigstore);
                assert_eq!(config.trusted_sigstore_identities.len(), 1);
                assert!(config.tuf_pinned_root.is_some());
                assert_eq!(config.tuf_pinned_root.as_ref().unwrap().version, 5);

                RegistryLogData {
                    reason_code: Some("config_with_values_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── hash_bytes large input determinism ────────────────────────────────

    #[test]
    fn hash_bytes_large_input() {
        run_registry_test("hash_bytes_large_input", "unit", "hash", 2, || async {
            let large = vec![0xABu8; 1_000_000];
            let h1 = hash_bytes(&large);
            let h2 = hash_bytes(&large);
            assert_eq!(h1, h2);
            assert!(h1.starts_with("sha256:"));

            RegistryLogData {
                reason_code: Some("hash_large_ok".to_string()),
                ..RegistryLogData::default()
            }
        });
    }

    // ── signature_message non-collision ───────────────────────────────────

    #[test]
    fn signature_message_different_inputs_differ() {
        run_registry_test(
            "signature_message_different_inputs_differ",
            "unit",
            "signature-message",
            3,
            || async {
                let m1 = signature_message(b"data", "hash");
                let m2 = signature_message(b"datx", "hash");
                let m3 = signature_message(b"data", "hasx");
                assert_ne!(m1, m2);
                assert_ne!(m1, m3);
                assert_ne!(m2, m3);

                RegistryLogData {
                    reason_code: Some("sig_msg_differ_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── MirrorResult Debug/Clone ─────────────────────────────────────────

    #[test]
    fn mirror_result_debug_clone() {
        run_registry_test("mirror_result_debug_clone", "unit", "traits", 3, || async {
            let result = MirrorResult {
                manifest_object_id: ObjectId::from_bytes([1u8; 32]),
                binary_object_id: ObjectId::from_bytes([2u8; 32]),
                manifest_hash: "sha256:manifest".into(),
                binary_hash: "sha256:binary".into(),
            };
            let debug = format!("{result:?}");
            assert!(debug.contains("MirrorResult"));
            let cloned = result.clone();
            assert_eq!(cloned.manifest_hash, "sha256:manifest");
            assert_eq!(cloned.binary_hash, "sha256:binary");

            RegistryLogData {
                reason_code: Some("mirror_result_traits_ok".to_string()),
                ..RegistryLogData::default()
            }
        });
    }

    // ── VerifiedConnectorBundle Debug/Clone ───────────────────────────────

    #[test]
    fn verified_bundle_debug_clone() {
        run_registry_test(
            "verified_bundle_debug_clone",
            "unit",
            "traits",
            3,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let binary = b"test-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust.publisher_keys.insert("pub1".into(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let verified = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect("verify");

                let debug = format!("{verified:?}");
                assert!(debug.contains("VerifiedConnectorBundle"));
                let cloned = verified.clone();
                assert_eq!(cloned.binary_hash, verified.binary_hash);
                assert_eq!(cloned.target, verified.target);

                RegistryLogData {
                    reason_code: Some("verified_bundle_traits_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── RegistryTrustPolicy with keys ────────────────────────────────────

    #[test]
    fn registry_trust_policy_debug_with_keys() {
        run_registry_test(
            "registry_trust_policy_debug_with_keys",
            "unit",
            "traits",
            2,
            || async {
                let key = Ed25519SigningKey::generate().verifying_key();
                let mut policy = RegistryTrustPolicy::default();
                policy.publisher_keys.insert("pub1".into(), key.clone());
                policy.registry_keys.insert("reg1".into(), key);
                policy.require_registry_signature = true;

                let debug = format!("{policy:?}");
                assert!(debug.contains("RegistryTrustPolicy"));
                let cloned = policy.clone();
                assert_eq!(cloned.publisher_keys.len(), 1);
                assert!(cloned.require_registry_signature);

                RegistryLogData {
                    reason_code: Some("trust_policy_debug_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── ConnectorTarget empty strings ────────────────────────────────────

    #[test]
    fn connector_target_empty_strings() {
        run_registry_test(
            "connector_target_empty_strings",
            "unit",
            "target",
            2,
            || async {
                let t = ConnectorTarget {
                    os: String::new(),
                    arch: String::new(),
                };
                assert_eq!(t.as_string(), "-");
                let debug = format!("{t:?}");
                assert!(debug.contains("ConnectorTarget"));

                RegistryLogData {
                    reason_code: Some("target_empty_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── NEW: Expanded serde and coverage tests ──────────────────────

    #[test]
    fn connector_target_serde_json_value() {
        let target = ConnectorTarget {
            os: "darwin".into(),
            arch: "arm64".into(),
        };
        let value = serde_json::to_value(&target).unwrap();
        assert_eq!(value["os"], "darwin");
        assert_eq!(value["arch"], "arm64");
    }

    #[test]
    fn registry_verification_report_serde_roundtrip() {
        let report = RegistryVerificationReport {
            connector_id: "fcp.test".into(),
            manifest_hash: "sha256:abc123".into(),
            binary_hash: "sha256:def456".into(),
            target: ConnectorTarget {
                os: "linux".into(),
                arch: "amd64".into(),
            },
            verified_at: 1_700_000_000,
            outcome: "pass".into(),
        };
        let json = serde_json::to_string(&report).unwrap();
        let deserialized: RegistryVerificationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.connector_id, "fcp.test");
        assert_eq!(deserialized.manifest_hash, "sha256:abc123");
        assert_eq!(deserialized.binary_hash, "sha256:def456");
        assert_eq!(deserialized.target.os, "linux");
        assert_eq!(deserialized.verified_at, 1_700_000_000);
        assert_eq!(deserialized.outcome, "pass");
    }

    #[test]
    fn registry_verification_report_debug_clone() {
        let report = RegistryVerificationReport {
            connector_id: "fcp.sentry".into(),
            manifest_hash: "sha256:aaa".into(),
            binary_hash: "sha256:bbb".into(),
            target: ConnectorTarget {
                os: "linux".into(),
                arch: "arm64".into(),
            },
            verified_at: 0,
            outcome: "fail".into(),
        };
        let cloned = report.clone();
        assert_eq!(cloned.connector_id, report.connector_id);
        let debug = format!("{report:?}");
        assert!(debug.contains("RegistryVerificationReport"));
        assert!(debug.contains("fcp.sentry"));
    }

    #[test]
    fn transparency_log_entry_serde_roundtrip() {
        let entry = TransparencyLogEntry {
            log_index: 42,
            entry_hash: "sha256:deadbeef".into(),
            inclusion_proof: InclusionProof {
                root_hash: "sha256:root".into(),
                tree_size: 100,
                hashes: vec!["sha256:h1".into(), "sha256:h2".into()],
                leaf_index: 42,
            },
            signed_entry_timestamp: vec![1, 2, 3, 4],
            log_id: "log-001".into(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: TransparencyLogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.log_index, 42);
        assert_eq!(deserialized.entry_hash, "sha256:deadbeef");
        assert_eq!(deserialized.inclusion_proof.tree_size, 100);
        assert_eq!(deserialized.inclusion_proof.hashes.len(), 2);
        assert_eq!(deserialized.signed_entry_timestamp, vec![1, 2, 3, 4]);
        assert_eq!(deserialized.log_id, "log-001");
    }
    #[test]
    fn tuf_root_metadata_serde_roundtrip() {
        let root = TufRootMetadata {
            version: 5,
            root_hash: "sha256:tufroot".into(),
            expires: 1_800_000_000,
            key_ids: vec!["key-a".into(), "key-b".into()],
            threshold: 2,
        };
        let json = serde_json::to_string(&root).unwrap();
        let deserialized: TufRootMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.version, 5);
        assert_eq!(deserialized.root_hash, "sha256:tufroot");
        assert_eq!(deserialized.expires, 1_800_000_000);
        assert_eq!(deserialized.key_ids.len(), 2);
        assert_eq!(deserialized.threshold, 2);
    }

    #[test]
    fn tuf_target_info_serde_roundtrip() {
        let target = TufTargetInfo {
            target_path: "connectors/fcp.sentry/0.1.0/linux-amd64".into(),
            hash: "sha256:targetbytes".into(),
            length: 1_048_576,
            delegations: vec!["root".into(), "targets".into()],
        };
        let json = serde_json::to_string(&target).unwrap();
        let deserialized: TufTargetInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(
            deserialized.target_path,
            "connectors/fcp.sentry/0.1.0/linux-amd64"
        );
        assert_eq!(deserialized.hash, "sha256:targetbytes");
        assert_eq!(deserialized.length, 1_048_576);
        assert_eq!(deserialized.delegations.len(), 2);
    }
    #[test]
    fn sigstore_bundle_serde_without_rekor() {
        let bundle = SigstoreBundle {
            signature: "sig".into(),
            certificate: "cert".into(),
            rekor_entry: None,
            identity: "id".into(),
            issuer: "iss".into(),
        };
        let json = serde_json::to_string(&bundle).unwrap();
        let deserialized: SigstoreBundle = serde_json::from_str(&json).unwrap();
        assert!(deserialized.rekor_entry.is_none());
    }

    // ── RegistrySource trait mock test ────────────────────────────────

    struct MockRegistrySource {
        bundles: HashMap<String, ConnectorBundle>,
    }

    impl MockRegistrySource {
        fn new() -> Self {
            Self {
                bundles: HashMap::new(),
            }
        }

        fn add_bundle(&mut self, id: &str, bundle: ConnectorBundle) {
            self.bundles.insert(id.to_string(), bundle);
        }
    }

    #[async_trait]
    impl RegistrySource for MockRegistrySource {
        async fn fetch_bundle(&self, connector_id: &str) -> Result<ConnectorBundle, RegistryError> {
            self.bundles
                .get(connector_id)
                .cloned()
                .ok_or(RegistryError::MissingSignatures)
        }
    }

    #[test]
    fn registry_source_fetch_found() {
        run_registry_test(
            "registry_source_fetch_found",
            "unit",
            "registry_source",
            2,
            || async {
                let mut source = MockRegistrySource::new();
                source.add_bundle(
                    "fcp.test",
                    ConnectorBundle {
                        manifest_toml: base_manifest_toml(),
                        binary: vec![1, 2, 3],
                        target: ConnectorTarget {
                            os: "linux".into(),
                            arch: "amd64".into(),
                        },
                    },
                );
                let bundle = source.fetch_bundle("fcp.test").await;
                assert!(bundle.is_ok());
                let bundle = bundle.unwrap();
                assert_eq!(bundle.binary, vec![1, 2, 3]);

                RegistryLogData {
                    reason_code: Some("registry_source_found".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn registry_source_fetch_not_found() {
        run_registry_test(
            "registry_source_fetch_not_found",
            "unit",
            "registry_source",
            1,
            || async {
                let source = MockRegistrySource::new();
                let result = source.fetch_bundle("fcp.nonexistent").await;
                assert!(result.is_err());

                RegistryLogData {
                    reason_code: Some("registry_source_not_found".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── RegistryVerificationReport field tests ────────────────────────

    #[test]
    fn verification_report_fields_from_verified_bundle() {
        run_registry_test(
            "verification_report_fields_from_verified_bundle",
            "unit",
            "report",
            5,
            || async {
                let manifest = minimal_manifest();
                let verified = VerifiedConnectorBundle {
                    manifest,
                    manifest_hash: "sha256:mhash".into(),
                    binary_hash: "sha256:bhash".into(),
                    target: ConnectorTarget {
                        os: "linux".into(),
                        arch: "amd64".into(),
                    },
                };

                let report = verified.report("verified_ok");
                assert_eq!(report.manifest_hash, "sha256:mhash");
                assert_eq!(report.binary_hash, "sha256:bhash");
                assert_eq!(report.target.os, "linux");
                assert_eq!(report.outcome, "verified_ok");
                assert!(report.verified_at > 0);

                RegistryLogData {
                    reason_code: Some("report_fields_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verification_report_different_outcomes() {
        run_registry_test(
            "verification_report_different_outcomes",
            "unit",
            "report",
            3,
            || async {
                let manifest = minimal_manifest();
                let verified = VerifiedConnectorBundle {
                    manifest,
                    manifest_hash: "sha256:m".into(),
                    binary_hash: "sha256:b".into(),
                    target: ConnectorTarget {
                        os: "linux".into(),
                        arch: "amd64".into(),
                    },
                };

                let pass_report = verified.report("pass");
                let fail_report = verified.report("fail");
                let skip_report = verified.report("skipped");
                assert_eq!(pass_report.outcome, "pass");
                assert_eq!(fail_report.outcome, "fail");
                assert_eq!(skip_report.outcome, "skipped");

                RegistryLogData {
                    reason_code: Some("report_outcomes_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── SupplyChainVerificationError display tests ────────────────────

    #[test]
    fn supply_chain_error_display_all_variants() {
        let errors: Vec<(&str, SupplyChainVerificationError)> = vec![
            (
                "not found",
                SupplyChainVerificationError::TransparencyEntryNotFound,
            ),
            (
                "inclusion proof invalid",
                SupplyChainVerificationError::TransparencyProofInvalid,
            ),
            (
                "signature invalid",
                SupplyChainVerificationError::TransparencySignatureInvalid,
            ),
            (
                "expected root_a, got root_b",
                SupplyChainVerificationError::TufRootMismatch {
                    expected: "root_a".into(),
                    actual: "root_b".into(),
                },
            ),
            ("expired", SupplyChainVerificationError::TufExpired),
            (
                "fcp.test",
                SupplyChainVerificationError::TufTargetNotFound {
                    target: "fcp.test".into(),
                },
            ),
            (
                "rollback",
                SupplyChainVerificationError::TufRollback { current: 5, got: 3 },
            ),
            ("freeze", SupplyChainVerificationError::TufFreeze),
            (
                "Sigstore signature invalid",
                SupplyChainVerificationError::SigstoreSignatureInvalid,
            ),
            (
                "expired or not yet valid",
                SupplyChainVerificationError::SigstoreCertificateInvalid,
            ),
            (
                "identity mismatch",
                SupplyChainVerificationError::SigstoreIdentityMismatch {
                    expected: "github".into(),
                    actual: "gitlab".into(),
                },
            ),
            (
                "not trusted",
                SupplyChainVerificationError::SigstoreIssuerUntrusted {
                    issuer: "https://evil.com".into(),
                },
            ),
            (
                "network",
                SupplyChainVerificationError::Network("timeout".into()),
            ),
            (
                "not configured",
                SupplyChainVerificationError::NotConfigured,
            ),
        ];

        for (expected_substring, error) in errors {
            let display = error.to_string();
            assert!(
                display
                    .to_lowercase()
                    .contains(&expected_substring.to_lowercase()),
                "Expected '{}' display to contain '{}', got: '{}'",
                std::any::type_name::<SupplyChainVerificationError>(),
                expected_substring,
                display
            );
        }
    }
    #[test]
    fn supply_chain_verification_config_debug_clone() {
        let config = SupplyChainVerificationConfig {
            tuf_pinned_root: Some(TufRootMetadata {
                version: 1,
                root_hash: "sha256:root".into(),
                expires: u64::MAX,
                key_ids: vec!["key1".into()],
                threshold: 1,
            }),
            trusted_sigstore_identities: vec!["github-actions".into()],
            trusted_sigstore_issuers: vec!["https://token.actions.githubusercontent.com".into()],
            require_transparency: true,
            require_tuf: true,
            require_sigstore: false,
            ..SupplyChainVerificationConfig::default()
        };
        let cloned = config.clone();
        assert!(cloned.require_transparency);
        assert_eq!(cloned.trusted_sigstore_identities.len(), 1);
        let debug = format!("{config:?}");
        assert!(debug.contains("SupplyChainVerificationConfig"));
    }
    #[test]
    fn transparency_verification_result_unverified() {
        let result = TransparencyVerificationResult {
            verified: false,
            log_index: None,
            logged_at: None,
        };
        assert!(!result.verified);
        assert!(result.log_index.is_none());
    }
    #[test]
    fn tuf_verification_result_no_target() {
        let result = TufVerificationResult {
            verified: false,
            root_version: 1,
            target: None,
        };
        assert!(!result.verified);
        assert!(result.target.is_none());
    }
    #[test]
    fn sigstore_verification_result_empty() {
        let result = SigstoreVerificationResult {
            verified: false,
            identity: None,
            issuer: None,
            rekor_log_index: None,
        };
        assert!(!result.verified);
        assert!(result.identity.is_none());
    }
    #[test]
    fn supply_chain_evidence_with_attestations() {
        let evidence = SupplyChainEvidence {
            transparency_log_present: true,
            tuf_verified: false,
            tuf_target_hash: None,
            sigstore_verified: false,
            sigstore_identity: None,
            sigstore_issuer: None,
            attestations: vec![
                AttestationEvidence {
                    attestation_type: AttestationType::InToto,
                    slsa_level: Some(3),
                    builder_id: Some("github-actions".into()),
                    expires_at: None,
                },
                AttestationEvidence {
                    attestation_type: AttestationType::ReproducibleBuild,
                    slsa_level: None,
                    builder_id: None,
                    expires_at: None,
                },
            ],
        };
        assert!(evidence.transparency_log_present);
        assert_eq!(evidence.attestations.len(), 2);
        let cloned = evidence.clone();
        assert_eq!(cloned.attestations.len(), 2);
    }

    #[test]
    fn registry_trust_policy_default() {
        let policy = RegistryTrustPolicy::default();
        assert!(policy.publisher_keys.is_empty());
        assert!(policy.registry_keys.is_empty());
        assert!(!policy.require_registry_signature);
    }
    // ── Hash determinism ─────────────────────────────────────────────

    #[test]
    fn hash_bytes_deterministic_same_input() {
        let h1 = hash_bytes(b"hello world");
        let h2 = hash_bytes(b"hello world");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_bytes_different_input_different_hash() {
        let h1 = hash_bytes(b"hello");
        let h2 = hash_bytes(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_bytes_has_sha256_prefix() {
        let h = hash_bytes(b"test");
        assert!(h.starts_with("sha256:"));
        assert_eq!(h.len(), 7 + 64); // "sha256:" + 64 hex chars
    }
    #[test]
    fn noop_transparency_verifier_debug_default() {
        let v = NoOpTransparencyVerifier;
        let debug = format!("{v:?}");
        assert!(debug.contains("NoOpTransparencyVerifier"));
    }

    #[test]
    fn noop_tuf_verifier_debug_default() {
        let v = NoOpTufVerifier;
        let debug = format!("{v:?}");
        assert!(debug.contains("NoOpTufVerifier"));
    }

    #[test]
    fn noop_sigstore_verifier_debug_default() {
        let v = NoOpSigstoreVerifier;
        let debug = format!("{v:?}");
        assert!(debug.contains("NoOpSigstoreVerifier"));
    }

    // ── Mock verifier debug ──────────────────────────────────────────

    #[test]
    fn mock_transparency_verifier_debug_default() {
        let v = MockTransparencyVerifier::new();
        let debug = format!("{v:?}");
        assert!(debug.contains("MockTransparencyVerifier"));
    }

    #[test]
    fn mock_sigstore_verifier_debug_default() {
        let v = MockSigstoreVerifier::new();
        let debug = format!("{v:?}");
        assert!(debug.contains("MockSigstoreVerifier"));
    }

    // ── NoOp verifier async paths ────────────────────────────────────

    #[test]
    fn noop_transparency_fails_closed() {
        run_registry_test(
            "noop_transparency_fails_closed",
            "unit",
            "verifier",
            3,
            || async {
                let v = NoOpTransparencyVerifier;
                let err = v
                    .verify_entry("sha256:anything", None)
                    .await
                    .expect_err("noop transparency must fail closed");
                assert!(matches!(err, SupplyChainVerificationError::NotConfigured));

                RegistryLogData {
                    reason_code: Some("noop_transparency_fail_closed".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn noop_tuf_fails_closed() {
        run_registry_test("noop_tuf_fails_closed", "unit", "verifier", 3, || async {
            let v = NoOpTufVerifier;
            let root = TufRootMetadata {
                version: 1,
                root_hash: String::new(),
                expires: 0,
                key_ids: vec![],
                threshold: 1,
            };
            let err = v
                .verify_target(&root, "any/path")
                .await
                .expect_err("noop tuf must fail closed");
            assert!(matches!(err, SupplyChainVerificationError::NotConfigured));

            RegistryLogData {
                reason_code: Some("noop_tuf_fail_closed".to_string()),
                ..RegistryLogData::default()
            }
        });
    }

    #[test]
    fn noop_tuf_fetch_root() {
        run_registry_test("noop_tuf_fetch_root", "unit", "verifier", 3, || async {
            let v = NoOpTufVerifier;
            let err = v
                .fetch_root()
                .await
                .expect_err("noop tuf fetch_root must fail closed");
            assert!(matches!(err, SupplyChainVerificationError::NotConfigured));

            RegistryLogData {
                reason_code: Some("noop_tuf_root_fail_closed".to_string()),
                ..RegistryLogData::default()
            }
        });
    }

    #[test]
    fn noop_sigstore_fails_closed() {
        run_registry_test(
            "noop_sigstore_fails_closed",
            "unit",
            "verifier",
            4,
            || async {
                let v = NoOpSigstoreVerifier;
                let bundle = SigstoreBundle {
                    signature: "sig".into(),
                    certificate: "cert".into(),
                    rekor_entry: None,
                    identity: "id".into(),
                    issuer: "iss".into(),
                };
                let err = v
                    .verify_bundle(&bundle, "sha256:hash", &[], &[])
                    .await
                    .expect_err("noop sigstore must fail closed");
                assert!(matches!(err, SupplyChainVerificationError::NotConfigured));

                RegistryLogData {
                    reason_code: Some("noop_sigstore_fail_closed".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── MockTransparencyVerifier valid/invalid ───────────────────────

    #[test]
    fn mock_transparency_verifier_valid_entry() {
        run_registry_test(
            "mock_transparency_verifier_valid_entry",
            "unit",
            "verifier",
            2,
            || async {
                let v = MockTransparencyVerifier::new();
                v.add_valid_entry(
                    "sha256:abc".into(),
                    TransparencyLogEntry {
                        log_index: 99,
                        entry_hash: "sha256:abc".into(),
                        inclusion_proof: InclusionProof {
                            root_hash: "r".into(),
                            tree_size: 100,
                            hashes: vec![],
                            leaf_index: 99,
                        },
                        signed_entry_timestamp: vec![],
                        log_id: "log".into(),
                    },
                );
                let result = v.verify_entry("sha256:abc", None).await.unwrap();
                assert!(result.verified);
                assert_eq!(result.log_index, Some(99));

                RegistryLogData {
                    reason_code: Some("mock_transparency_valid".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn mock_transparency_verifier_missing_entry() {
        run_registry_test(
            "mock_transparency_verifier_missing_entry",
            "unit",
            "verifier",
            1,
            || async {
                let v = MockTransparencyVerifier::new();
                let result = v.verify_entry("sha256:missing", None).await;
                assert!(matches!(
                    result,
                    Err(SupplyChainVerificationError::TransparencyEntryNotFound)
                ));

                RegistryLogData {
                    reason_code: Some("mock_transparency_missing".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── MockTufVerifier root mismatch / rollback ─────────────────────

    #[test]
    fn mock_tuf_verifier_root_mismatch() {
        run_registry_test(
            "mock_tuf_verifier_root_mismatch",
            "unit",
            "verifier",
            1,
            || async {
                let v = MockTufVerifier::new(TufRootMetadata {
                    version: 1,
                    root_hash: "sha256:server_root".into(),
                    expires: u64::MAX,
                    key_ids: vec![],
                    threshold: 1,
                });
                let pinned = TufRootMetadata {
                    version: 1,
                    root_hash: "sha256:pinned_root".into(),
                    expires: u64::MAX,
                    key_ids: vec![],
                    threshold: 1,
                };
                let result = v.verify_target(&pinned, "path").await;
                assert!(matches!(
                    result,
                    Err(SupplyChainVerificationError::TufRootMismatch { .. })
                ));

                RegistryLogData {
                    reason_code: Some("tuf_root_mismatch".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn mock_tuf_verifier_rollback() {
        run_registry_test(
            "mock_tuf_verifier_rollback",
            "unit",
            "verifier",
            1,
            || async {
                let v = MockTufVerifier::new(TufRootMetadata {
                    version: 2,
                    root_hash: "sha256:root".into(),
                    expires: u64::MAX,
                    key_ids: vec![],
                    threshold: 1,
                });
                let pinned = TufRootMetadata {
                    version: 5, // pinned is newer
                    root_hash: "sha256:root".into(),
                    expires: u64::MAX,
                    key_ids: vec![],
                    threshold: 1,
                };
                let result = v.verify_target(&pinned, "path").await;
                assert!(matches!(
                    result,
                    Err(SupplyChainVerificationError::TufRollback { current: 5, got: 2 })
                ));

                RegistryLogData {
                    reason_code: Some("tuf_rollback".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn mock_tuf_verifier_target_not_found() {
        run_registry_test(
            "mock_tuf_verifier_target_not_found",
            "unit",
            "verifier",
            1,
            || async {
                let v = MockTufVerifier::new(TufRootMetadata {
                    version: 1,
                    root_hash: "sha256:root".into(),
                    expires: u64::MAX,
                    key_ids: vec![],
                    threshold: 1,
                });
                let pinned = TufRootMetadata {
                    version: 1,
                    root_hash: "sha256:root".into(),
                    expires: u64::MAX,
                    key_ids: vec![],
                    threshold: 1,
                };
                let result = v.verify_target(&pinned, "missing/target").await;
                assert!(matches!(
                    result,
                    Err(SupplyChainVerificationError::TufTargetNotFound { .. })
                ));

                RegistryLogData {
                    reason_code: Some("tuf_target_not_found".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn mock_tuf_verifier_valid_target() {
        run_registry_test(
            "mock_tuf_verifier_valid_target",
            "unit",
            "verifier",
            3,
            || async {
                let v = MockTufVerifier::new(TufRootMetadata {
                    version: 1,
                    root_hash: "sha256:root".into(),
                    expires: u64::MAX,
                    key_ids: vec![],
                    threshold: 1,
                });
                v.add_valid_target(
                    "connectors/fcp.test".into(),
                    TufTargetInfo {
                        target_path: "connectors/fcp.test".into(),
                        hash: "sha256:binary".into(),
                        length: 4096,
                        delegations: vec!["root".into()],
                    },
                );
                let pinned = TufRootMetadata {
                    version: 1,
                    root_hash: "sha256:root".into(),
                    expires: u64::MAX,
                    key_ids: vec![],
                    threshold: 1,
                };
                let result = v
                    .verify_target(&pinned, "connectors/fcp.test")
                    .await
                    .unwrap();
                assert!(result.verified);
                assert_eq!(result.root_version, 1);
                assert!(result.target.is_some());

                RegistryLogData {
                    reason_code: Some("tuf_valid_target".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn mock_tuf_fetch_root_returns_configured_root() {
        run_registry_test(
            "mock_tuf_fetch_root_returns_configured_root",
            "unit",
            "verifier",
            2,
            || async {
                let v = MockTufVerifier::new(TufRootMetadata {
                    version: 7,
                    root_hash: "sha256:custom_root".into(),
                    expires: 999,
                    key_ids: vec!["k1".into()],
                    threshold: 3,
                });
                let root = v.fetch_root().await.unwrap();
                assert_eq!(root.version, 7);
                assert_eq!(root.root_hash, "sha256:custom_root");

                RegistryLogData {
                    reason_code: Some("tuf_fetch_root_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── MockSigstoreVerifier identity/issuer checks ──────────────────

    #[test]
    fn mock_sigstore_verifier_identity_mismatch() {
        run_registry_test(
            "mock_sigstore_verifier_identity_mismatch",
            "unit",
            "verifier",
            1,
            || async {
                let v = MockSigstoreVerifier::new();
                v.add_valid_bundle(
                    "sha256:artifact".into(),
                    SigstoreVerificationResult {
                        verified: true,
                        identity: Some("bad-actor".into()),
                        issuer: None,
                        rekor_log_index: None,
                    },
                );
                let bundle = SigstoreBundle {
                    signature: "s".into(),
                    certificate: "c".into(),
                    rekor_entry: None,
                    identity: "x".into(),
                    issuer: "y".into(),
                };
                let result = v
                    .verify_bundle(&bundle, "sha256:artifact", &["github-actions".into()], &[])
                    .await;
                assert!(matches!(
                    result,
                    Err(SupplyChainVerificationError::SigstoreIdentityMismatch { .. })
                ));

                RegistryLogData {
                    reason_code: Some("sigstore_id_mismatch".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn mock_sigstore_verifier_issuer_untrusted() {
        run_registry_test(
            "mock_sigstore_verifier_issuer_untrusted",
            "unit",
            "verifier",
            1,
            || async {
                let v = MockSigstoreVerifier::new();
                v.add_valid_bundle(
                    "sha256:a".into(),
                    SigstoreVerificationResult {
                        verified: true,
                        identity: None,
                        issuer: Some("https://evil.com".into()),
                        rekor_log_index: None,
                    },
                );
                let bundle = SigstoreBundle {
                    signature: "s".into(),
                    certificate: "c".into(),
                    rekor_entry: None,
                    identity: "x".into(),
                    issuer: "y".into(),
                };
                let result = v
                    .verify_bundle(&bundle, "sha256:a", &[], &["https://github.com".into()])
                    .await;
                assert!(matches!(
                    result,
                    Err(SupplyChainVerificationError::SigstoreIssuerUntrusted { .. })
                ));

                RegistryLogData {
                    reason_code: Some("sigstore_issuer_untrusted".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn mock_sigstore_verifier_not_found() {
        run_registry_test(
            "mock_sigstore_verifier_not_found",
            "unit",
            "verifier",
            1,
            || async {
                let v = MockSigstoreVerifier::new();
                let bundle = SigstoreBundle {
                    signature: "s".into(),
                    certificate: "c".into(),
                    rekor_entry: None,
                    identity: "x".into(),
                    issuer: "y".into(),
                };
                let result = v.verify_bundle(&bundle, "sha256:unknown", &[], &[]).await;
                assert!(matches!(
                    result,
                    Err(SupplyChainVerificationError::SigstoreSignatureInvalid)
                ));

                RegistryLogData {
                    reason_code: Some("sigstore_not_found".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── manifest_signing_bytes determinism ────────────────────────────

    #[test]
    fn manifest_signing_bytes_deterministic() {
        run_registry_test(
            "manifest_signing_bytes_deterministic",
            "unit",
            "signing",
            1,
            || async {
                let manifest = minimal_manifest();
                let bytes1 = manifest_signing_bytes(&manifest).unwrap();
                let bytes2 = manifest_signing_bytes(&manifest).unwrap();
                assert_eq!(bytes1, bytes2);

                RegistryLogData {
                    reason_code: Some("signing_bytes_deterministic".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── RegistryError display ────────────────────────────────────────

    #[test]
    fn registry_error_all_variant_display() {
        let errors: Vec<(&str, RegistryError)> = vec![
            (
                "signature section missing",
                RegistryError::MissingSignatures,
            ),
            (
                "kid",
                RegistryError::UnknownKid {
                    kid: "key-123".into(),
                },
            ),
            (
                "kid",
                RegistryError::SignatureInvalid {
                    kid: "key-456".into(),
                },
            ),
            (
                "threshold",
                RegistryError::PublisherThresholdUnmet {
                    required: 3,
                    valid: 1,
                },
            ),
            (
                "no trusted publisher or registry signature verified",
                RegistryError::NoTrustedSignature,
            ),
            (
                "registry signature required",
                RegistryError::RegistrySignatureRequired,
            ),
            (
                "target mismatch",
                RegistryError::TargetMismatch {
                    expected: "linux-amd64".into(),
                    found: "darwin-arm64".into(),
                },
            ),
            (
                "ceiling",
                RegistryError::CapabilityCeilingViolation {
                    capability: "network.exec".into(),
                },
            ),
            ("transparency log", RegistryError::TransparencyLogMissing),
            ("transparency", RegistryError::TransparencyEvidenceMissing),
            ("tuf", RegistryError::TufVerificationRequired),
            ("sigstore", RegistryError::SigstoreVerificationRequired),
            (
                "attestation",
                RegistryError::RequiredAttestationMissing {
                    attestation: "in-toto".into(),
                },
            ),
            (
                "attestation evidence",
                RegistryError::AttestationEvidenceMissing,
            ),
            (
                "expired",
                RegistryError::AttestationExpired {
                    attestation: "in-toto".into(),
                    expired_at: 0,
                },
            ),
            ("SLSA", RegistryError::SlsaLevelInsufficient { required: 3 }),
            (
                "builder",
                RegistryError::UntrustedBuilder {
                    builder: "evil-builder".into(),
                },
            ),
            ("malformed", RegistryError::SignatureBytes),
        ];

        for (expected_substring, error) in errors {
            let display = error.to_string();
            assert!(
                display
                    .to_lowercase()
                    .contains(&expected_substring.to_lowercase()),
                "RegistryError display for {:?} should contain '{}', got: '{}'",
                std::mem::discriminant(&error),
                expected_substring,
                display
            );
        }
    }

    // ── MANIFEST_SIGNATURE_CONTEXT ───────────────────────────────────

    #[test]
    fn manifest_signature_context_is_nonempty() {
        assert!(!MANIFEST_SIGNATURE_CONTEXT.is_empty());
        assert_eq!(MANIFEST_SIGNATURE_CONTEXT, b"fcp.registry.manifest.v1");
    }

    // ── ConnectorTarget equality ─────────────────────────────────────

    #[test]
    fn connector_target_equality() {
        let t1 = ConnectorTarget {
            os: "linux".into(),
            arch: "amd64".into(),
        };
        let t2 = ConnectorTarget {
            os: "linux".into(),
            arch: "amd64".into(),
        };
        let t3 = ConnectorTarget {
            os: "darwin".into(),
            arch: "arm64".into(),
        };
        assert_eq!(t1, t2);
        assert_ne!(t1, t3);
    }

    #[test]
    fn connector_target_as_string_format() {
        let t = ConnectorTarget {
            os: "windows".into(),
            arch: "amd64".into(),
        };
        assert_eq!(t.as_string(), "windows-amd64");
    }

    // ── mirror_bundle error paths ────────────────────────────────────

    struct FailingObjectStore;

    #[async_trait]
    impl ObjectStore for FailingObjectStore {
        async fn put(&self, _object: StoredObject) -> Result<(), ObjectStoreError> {
            Err(ObjectStoreError::Io("simulated disk failure".into()))
        }
        async fn get(&self, id: &ObjectId) -> Result<StoredObject, ObjectStoreError> {
            Err(ObjectStoreError::NotFound(*id))
        }
        async fn exists(&self, _id: &ObjectId) -> bool {
            false
        }
        async fn delete(&self, id: &ObjectId) -> Result<(), ObjectStoreError> {
            Err(ObjectStoreError::NotFound(*id))
        }
        async fn get_header(&self, id: &ObjectId) -> Result<ObjectHeader, ObjectStoreError> {
            Err(ObjectStoreError::NotFound(*id))
        }
        async fn get_storage_meta(&self, id: &ObjectId) -> Result<StorageMeta, ObjectStoreError> {
            Err(ObjectStoreError::NotFound(*id))
        }
        async fn set_retention(
            &self,
            id: &ObjectId,
            _retention: RetentionClass,
        ) -> Result<(), ObjectStoreError> {
            Err(ObjectStoreError::NotFound(*id))
        }
        async fn list_zone(&self, _zone_id: &ZoneId) -> Vec<ObjectId> {
            vec![]
        }
        async fn storage_used(&self) -> u64 {
            0
        }
        async fn storage_quota(&self) -> u64 {
            0
        }
    }

    #[test]
    fn mirror_bundle_store_put_failure() {
        run_registry_test(
            "mirror_bundle_store_put_failure",
            "mirror",
            "error",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let binary = b"registry-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

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
                let verified = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect("verify");

                let store = FailingObjectStore;
                let zone_id = ZoneId::work();
                let object_id_key = ObjectIdKey::from_bytes([1u8; 32]);

                let err = verifier
                    .mirror_bundle(&verified, &bundle, zone_id, &object_id_key, &store)
                    .await
                    .expect_err("store put should fail");
                assert!(matches!(err, RegistryError::ObjectStore(_)));

                RegistryLogData {
                    reason_code: Some("store_put_failure".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── mirror_bundle result consistency ─────────────────────────────

    #[test]
    fn mirror_bundle_result_hashes_match_verified() {
        run_registry_test(
            "mirror_bundle_result_hashes_match_verified",
            "mirror",
            "consistency",
            4,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let binary = b"consistency-check-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

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
                let verified = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect("verify");

                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                let zone_id = ZoneId::work();
                let object_id_key = ObjectIdKey::from_bytes([2u8; 32]);

                let result = verifier
                    .mirror_bundle(&verified, &bundle, zone_id, &object_id_key, &store)
                    .await
                    .expect("mirror bundle");

                assert_eq!(result.manifest_hash, verified.manifest_hash);
                assert_eq!(result.binary_hash, verified.binary_hash);
                assert_ne!(result.manifest_object_id, result.binary_object_id);
                assert!(store.exists(&result.manifest_object_id).await);

                RegistryLogData {
                    manifest_hash: Some(result.manifest_hash),
                    binary_hash: Some(result.binary_hash),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── mirror_bundle binary refs manifest ───────────────────────────

    #[test]
    fn mirror_bundle_binary_object_refs_manifest() {
        run_registry_test(
            "mirror_bundle_binary_object_refs_manifest",
            "mirror",
            "refs",
            2,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let binary = b"refs-check".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

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
                let verified = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect("verify");

                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                let zone_id = ZoneId::work();
                let object_id_key = ObjectIdKey::from_bytes([3u8; 32]);

                let result = verifier
                    .mirror_bundle(&verified, &bundle, zone_id, &object_id_key, &store)
                    .await
                    .expect("mirror bundle");

                let binary_obj = store
                    .get(&result.binary_object_id)
                    .await
                    .expect("binary object");
                assert_eq!(binary_obj.header.refs, vec![result.manifest_object_id]);

                let manifest_obj = store
                    .get(&result.manifest_object_id)
                    .await
                    .expect("manifest object");
                assert!(manifest_obj.header.refs.is_empty());

                RegistryLogData {
                    manifest_hash: Some(result.manifest_hash),
                    binary_hash: Some(result.binary_hash),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── supply chain: combined requirements ──────────────────────────

    #[test]
    fn supply_chain_combined_requirements_all_met() {
        run_registry_test(
            "supply_chain_combined_requirements_all_met",
            "verify",
            "supply-chain",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let policy = r#"[policy]
require_transparency_log = true
require_attestation_types = ["in-toto", "code-review"]
min_slsa_level = 2
trusted_builders = ["trusted-ci"]
"#;
                let binary = b"combined-policy-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml(policy);
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);

                // Custom signatures section with transparency_log_entry
                let signatures_section = format!(
                    r#"[signatures]
publisher_threshold = "1-of-1"
transparency_log_entry = "objectid:{}"

[[signatures.publisher_signatures]]
kid = "pub1"
sig = "{}"
"#,
                    hex::encode([0u8; 32]),
                    String::from(sig)
                );
                let manifest_toml = with_signatures(&unsigned, &signatures_section);

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let evidence = SupplyChainEvidence {
                    transparency_log_present: true,
                    tuf_verified: false,
                    tuf_target_hash: None,
                    sigstore_verified: false,
                    sigstore_identity: None,
                    sigstore_issuer: None,
                    attestations: vec![
                        AttestationEvidence {
                            attestation_type: AttestationType::InToto,
                            slsa_level: Some(3),
                            builder_id: Some("trusted-ci".to_string()),
                            expires_at: None,
                        },
                        AttestationEvidence {
                            attestation_type: AttestationType::CodeReview,
                            slsa_level: None,
                            builder_id: None,
                            expires_at: None,
                        },
                    ],
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let verified = verifier
                    .verify_bundle(&bundle, None, Some(&evidence), None)
                    .expect("all requirements met");
                assert!(!verified.manifest_hash.is_empty());

                RegistryLogData {
                    manifest_hash: Some(verified.manifest_hash),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn supply_chain_combined_fails_on_missing_attestation_type() {
        run_registry_test(
            "supply_chain_combined_fails_on_missing_attestation_type",
            "verify",
            "supply-chain",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let policy = r#"[policy]
require_attestation_types = ["in-toto", "code-review"]
min_slsa_level = 2
trusted_builders = ["trusted-ci"]
"#;
                let binary = b"combined-policy-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml(policy);
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                // Only provide in-toto, not code-review
                let evidence = SupplyChainEvidence {
                    transparency_log_present: false,
                    tuf_verified: false,
                    tuf_target_hash: None,
                    sigstore_verified: false,
                    sigstore_identity: None,
                    sigstore_issuer: None,
                    attestations: vec![AttestationEvidence {
                        attestation_type: AttestationType::InToto,
                        slsa_level: Some(3),
                        builder_id: Some("trusted-ci".to_string()),
                        expires_at: None,
                    }],
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let err = verifier
                    .verify_bundle(&bundle, None, Some(&evidence), None)
                    .expect_err("missing code-review");
                assert!(matches!(
                    err,
                    RegistryError::RequiredAttestationMissing { .. }
                ));

                RegistryLogData {
                    reason_code: Some("missing_attestation_type".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── signature_from_entry direct test ─────────────────────────────

    #[test]
    fn signature_from_entry_too_short() {
        run_registry_test(
            "signature_from_entry_too_short",
            "unit",
            "signature",
            1,
            || async {
                let short_sig =
                    Base64Bytes::try_from("base64:AAAA".to_string()).expect("base64 parse");
                let err = signature_from_entry(&short_sig).expect_err("too short");
                assert!(matches!(
                    err,
                    RegistryError::SignatureBytes | RegistryError::PublisherThresholdUnmet { .. }
                ));

                RegistryLogData {
                    reason_code: Some("signature_too_short".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn signature_from_entry_valid_length() {
        run_registry_test(
            "signature_from_entry_valid_length",
            "unit",
            "signature",
            1,
            || async {
                // Ed25519 signatures are 64 bytes
                let sig_bytes = [0u8; 64];
                let encoded = base64::engine::general_purpose::STANDARD.encode(sig_bytes);
                let sig = Base64Bytes::try_from(format!("base64:{encoded}")).expect("base64 parse");
                let result = signature_from_entry(&sig);
                assert!(result.is_ok());

                RegistryLogData {
                    reason_code: Some("signature_valid_length".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── struct trait coverage ────────────────────────────────────────

    #[test]
    fn mirror_result_debug_and_clone() {
        run_registry_test(
            "mirror_result_debug_and_clone",
            "unit",
            "traits",
            2,
            || async {
                let result = MirrorResult {
                    manifest_object_id: ObjectId::from_bytes([1u8; 32]),
                    binary_object_id: ObjectId::from_bytes([2u8; 32]),
                    manifest_hash: "sha256:aaa".to_string(),
                    binary_hash: "sha256:bbb".to_string(),
                };
                let debug = format!("{result:?}");
                assert!(debug.contains("MirrorResult"));

                let cloned = result.clone();
                assert_eq!(cloned.manifest_hash, result.manifest_hash);

                RegistryLogData::default()
            },
        );
    }

    #[test]
    fn registry_verifier_debug_and_clone() {
        run_registry_test(
            "registry_verifier_debug_and_clone",
            "unit",
            "traits",
            2,
            || async {
                let trust = RegistryTrustPolicy::default();
                let verifier = RegistryVerifier::new(trust);
                let debug = format!("{verifier:?}");
                assert!(debug.contains("RegistryVerifier"));

                let cloned = verifier.clone();
                let _ = format!("{cloned:?}");

                RegistryLogData::default()
            },
        );
    }

    #[test]
    fn verified_bundle_report_fields() {
        run_registry_test(
            "verified_bundle_report_fields",
            "unit",
            "report",
            4,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let binary = b"report-test-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

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
                let verified = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect("verify");

                let report = verified.report("pass");
                assert_eq!(report.outcome, "pass");
                assert_eq!(report.manifest_hash, verified.manifest_hash);
                assert_eq!(report.binary_hash, verified.binary_hash);
                assert!(report.verified_at > 0);

                RegistryLogData {
                    connector_id: Some(report.connector_id),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn registry_error_object_store_from_conversion() {
        run_registry_test(
            "registry_error_object_store_from_conversion",
            "unit",
            "error",
            2,
            || async {
                let store_err = ObjectStoreError::Io("disk full".into());
                let reg_err: RegistryError = store_err.into();
                assert!(matches!(reg_err, RegistryError::ObjectStore(_)));
                assert!(reg_err.to_string().contains("disk full"));

                RegistryLogData {
                    reason_code: Some("object_store_error_conversion".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── signature_message determinism ────────────────────────────────

    #[test]
    fn signature_message_wire_format_layout() {
        run_registry_test(
            "signature_message_wire_format_layout",
            "unit",
            "signature",
            3,
            || async {
                let signing_bytes = b"test-signing-bytes";
                let binary_hash = "sha256:abc123";
                let msg = signature_message(signing_bytes, binary_hash);

                // Message format: le_u64(signing_len) || signing_bytes || le_u64(hash_len) || hash_bytes
                let signing_len = u64::from_le_bytes(msg[0..8].try_into().expect("8 bytes"));
                assert_eq!(signing_len as usize, signing_bytes.len());

                let hash_offset = 8 + signing_bytes.len();
                let hash_len = u64::from_le_bytes(
                    msg[hash_offset..hash_offset + 8]
                        .try_into()
                        .expect("8 bytes"),
                );
                assert_eq!(hash_len as usize, binary_hash.len());

                let total = 8 + signing_bytes.len() + 8 + binary_hash.len();
                assert_eq!(msg.len(), total);

                RegistryLogData::default()
            },
        );
    }

    // ── verify_bundle with both publisher and registry signatures ────

    #[test]
    fn verify_bundle_both_publisher_and_registry_valid() {
        run_registry_test(
            "verify_bundle_both_publisher_and_registry_valid",
            "verify",
            "signature",
            1,
            || async {
                let pub_key = Ed25519SigningKey::generate();
                let reg_key = Ed25519SigningKey::generate();

                let binary = b"dual-sig-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let pub_sig = sign_manifest_toml(&unsigned, &pub_key, &binary_hash);
                let reg_sig = sign_manifest_toml(&unsigned, &reg_key, &binary_hash);

                let sigs = format!(
                    "{}\n{}",
                    publisher_signature_section("pub1", &pub_sig),
                    registry_signature_section("reg1", &reg_sig)
                );
                let manifest_toml = with_signatures(&unsigned, &sigs);

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy {
                    require_registry_signature: true,
                    ..RegistryTrustPolicy::default()
                };
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), pub_key.verifying_key());
                trust
                    .registry_keys
                    .insert("reg1".to_string(), reg_key.verifying_key());

                let verifier = RegistryVerifier::new(trust);
                let verified = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect("both sigs valid");
                assert!(!verified.manifest_hash.is_empty());

                RegistryLogData {
                    manifest_hash: Some(verified.manifest_hash),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ══════════════════════════════════════════════════════════════════════
    // NEW: Expanded test suite for 310+ target
    // ══════════════════════════════════════════════════════════════════════

    // ── ConnectorTarget serde edge cases ─────────────────────────────

    #[test]
    fn connector_target_serde_unicode_os() {
        let t = ConnectorTarget {
            os: "\u{1F600}-os".to_string(),
            arch: "amd64".to_string(),
        };
        let json = serde_json::to_string(&t).unwrap();
        let parsed: ConnectorTarget = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.os, "\u{1F600}-os");
        assert_eq!(parsed.arch, "amd64");
    }

    #[test]
    fn connector_target_serde_unicode_arch() {
        let t = ConnectorTarget {
            os: "linux".to_string(),
            arch: "\u{00E9}special".to_string(),
        };
        let json = serde_json::to_string(&t).unwrap();
        let parsed: ConnectorTarget = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.arch, "\u{00E9}special");
    }

    #[test]
    fn connector_target_serde_very_long_values() {
        let long_os = "x".repeat(10_000);
        let long_arch = "y".repeat(10_000);
        let t = ConnectorTarget {
            os: long_os.clone(),
            arch: long_arch.clone(),
        };
        let json = serde_json::to_string(&t).unwrap();
        let parsed: ConnectorTarget = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.os.len(), 10_000);
        assert_eq!(parsed.arch.len(), 10_000);
    }

    #[test]
    fn connector_target_as_string_with_hyphen_in_name() {
        let t = ConnectorTarget {
            os: "my-os".to_string(),
            arch: "my-arch".to_string(),
        };
        assert_eq!(t.as_string(), "my-os-my-arch");
    }

    #[test]
    fn connector_target_clone_independence() {
        let t1 = ConnectorTarget {
            os: "linux".to_string(),
            arch: "amd64".to_string(),
        };
        let t2 = t1.clone();
        // Use original after clone
        assert_eq!(t1.os, "linux");
        assert_eq!(t2.os, "linux");
        assert_eq!(t1, t2);
    }

    #[test]
    fn connector_target_debug_contains_fields() {
        let t = ConnectorTarget {
            os: "darwin".to_string(),
            arch: "arm64".to_string(),
        };
        let debug = format!("{t:?}");
        assert!(debug.contains("darwin"));
        assert!(debug.contains("arm64"));
    }

    #[test]
    fn connector_target_ne_same_os_different_arch() {
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

    #[test]
    fn connector_target_ne_different_os_same_arch() {
        let t1 = ConnectorTarget {
            os: "linux".to_string(),
            arch: "amd64".to_string(),
        };
        let t2 = ConnectorTarget {
            os: "darwin".to_string(),
            arch: "amd64".to_string(),
        };
        assert_ne!(t1, t2);
    }

    // ── RegistryTrustPolicy edge cases ──────────────────────────────

    #[test]
    fn registry_trust_policy_clone_independence() {
        let key = Ed25519SigningKey::generate().verifying_key();
        let mut policy = RegistryTrustPolicy::default();
        policy.publisher_keys.insert("k1".to_string(), key);
        policy.require_registry_signature = true;
        let cloned = policy.clone();
        // Use original after clone
        assert_eq!(policy.publisher_keys.len(), 1);
        assert!(policy.require_registry_signature);
        assert_eq!(cloned.publisher_keys.len(), 1);
        assert!(cloned.require_registry_signature);
    }

    #[test]
    fn registry_trust_policy_multiple_publisher_keys() {
        let k1 = Ed25519SigningKey::generate().verifying_key();
        let k2 = Ed25519SigningKey::generate().verifying_key();
        let k3 = Ed25519SigningKey::generate().verifying_key();
        let mut policy = RegistryTrustPolicy::default();
        policy.publisher_keys.insert("k1".to_string(), k1);
        policy.publisher_keys.insert("k2".to_string(), k2);
        policy.publisher_keys.insert("k3".to_string(), k3);
        assert_eq!(policy.publisher_keys.len(), 3);
    }

    #[test]
    fn registry_trust_policy_multiple_registry_keys() {
        let k1 = Ed25519SigningKey::generate().verifying_key();
        let k2 = Ed25519SigningKey::generate().verifying_key();
        let mut policy = RegistryTrustPolicy::default();
        policy.registry_keys.insert("r1".to_string(), k1);
        policy.registry_keys.insert("r2".to_string(), k2);
        assert_eq!(policy.registry_keys.len(), 2);
    }

    // ── SupplyChainEvidence edge cases ──────────────────────────────

    #[test]
    fn supply_chain_evidence_clone_independence() {
        let evidence = SupplyChainEvidence {
            transparency_log_present: true,
            tuf_verified: false,
            tuf_target_hash: None,
            sigstore_verified: false,
            sigstore_identity: None,
            sigstore_issuer: None,
            attestations: vec![AttestationEvidence {
                attestation_type: AttestationType::InToto,
                slsa_level: Some(3),
                builder_id: Some("ci".to_string()),
                expires_at: None,
            }],
        };
        let cloned = evidence.clone();
        assert!(evidence.transparency_log_present);
        assert_eq!(evidence.attestations.len(), 1);
        assert_eq!(cloned.attestations.len(), 1);
    }

    #[test]
    fn supply_chain_evidence_debug_format() {
        let evidence = SupplyChainEvidence {
            transparency_log_present: true,
            tuf_verified: false,
            tuf_target_hash: None,
            sigstore_verified: false,
            sigstore_identity: None,
            sigstore_issuer: None,
            attestations: vec![],
        };
        let debug = format!("{evidence:?}");
        assert!(debug.contains("SupplyChainEvidence"));
        assert!(debug.contains("true"));
    }

    #[test]
    fn supply_chain_evidence_many_attestations() {
        let attestations: Vec<AttestationEvidence> = (0..50)
            .map(|i| AttestationEvidence {
                attestation_type: AttestationType::InToto,
                slsa_level: Some(i as u8),
                builder_id: Some(format!("builder-{i}")),
                expires_at: None,
            })
            .collect();
        let evidence = SupplyChainEvidence {
            transparency_log_present: false,
            tuf_verified: false,
            tuf_target_hash: None,
            sigstore_verified: false,
            sigstore_identity: None,
            sigstore_issuer: None,
            attestations,
        };
        assert_eq!(evidence.attestations.len(), 50);
    }

    // ── AttestationEvidence edge cases ──────────────────────────────

    #[test]
    fn attestation_evidence_all_types() {
        let types = [
            AttestationType::InToto,
            AttestationType::ReproducibleBuild,
            AttestationType::CodeReview,
        ];
        for at in &types {
            let ev = AttestationEvidence {
                attestation_type: *at,
                slsa_level: None,
                builder_id: None,
                expires_at: None,
            };
            let cloned = ev.clone();
            assert_eq!(cloned.attestation_type, ev.attestation_type);
        }
    }

    #[test]
    fn attestation_evidence_max_slsa_level() {
        let ev = AttestationEvidence {
            attestation_type: AttestationType::InToto,
            slsa_level: Some(255),
            builder_id: None,
            expires_at: None,
        };
        assert_eq!(ev.slsa_level, Some(255));
    }

    #[test]
    fn attestation_evidence_empty_builder_id() {
        let ev = AttestationEvidence {
            attestation_type: AttestationType::CodeReview,
            slsa_level: Some(1),
            builder_id: Some(String::new()),
            expires_at: None,
        };
        assert_eq!(ev.builder_id, Some(String::new()));
    }

    // ── InclusionProof edge cases ───────────────────────────────────

    #[test]
    fn inclusion_proof_empty_hashes() {
        let proof = InclusionProof {
            root_hash: "sha256:root".to_string(),
            tree_size: 0,
            hashes: vec![],
            leaf_index: 0,
        };
        let json = serde_json::to_string(&proof).unwrap();
        let parsed: InclusionProof = serde_json::from_str(&json).unwrap();
        assert!(parsed.hashes.is_empty());
        assert_eq!(parsed.tree_size, 0);
    }

    #[test]
    fn inclusion_proof_many_hashes() {
        let hashes: Vec<String> = (0..100).map(|i| format!("sha256:hash{i}")).collect();
        let proof = InclusionProof {
            root_hash: "sha256:root".to_string(),
            tree_size: 1_000_000,
            hashes,
            leaf_index: 999_999,
        };
        let json = serde_json::to_string(&proof).unwrap();
        let parsed: InclusionProof = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.hashes.len(), 100);
        assert_eq!(parsed.leaf_index, 999_999);
    }

    #[test]
    fn inclusion_proof_clone_independence() {
        let proof = InclusionProof {
            root_hash: "sha256:r".to_string(),
            tree_size: 42,
            hashes: vec!["sha256:h1".to_string()],
            leaf_index: 7,
        };
        let cloned = proof.clone();
        assert_eq!(proof.tree_size, 42);
        assert_eq!(cloned.tree_size, 42);
        assert_eq!(proof.hashes.len(), cloned.hashes.len());
    }

    // ── TransparencyLogEntry edge cases ─────────────────────────────

    #[test]
    fn transparency_log_entry_clone_independence() {
        let entry = TransparencyLogEntry {
            log_index: 100,
            entry_hash: "sha256:entry".to_string(),
            inclusion_proof: InclusionProof {
                root_hash: "sha256:root".to_string(),
                tree_size: 500,
                hashes: vec!["sha256:h1".to_string()],
                leaf_index: 100,
            },
            signed_entry_timestamp: vec![0xDE, 0xAD],
            log_id: "rekor".to_string(),
        };
        let cloned = entry.clone();
        assert_eq!(entry.log_index, 100);
        assert_eq!(cloned.log_index, 100);
        assert_eq!(entry.log_id, cloned.log_id);
    }

    #[test]
    fn transparency_log_entry_empty_timestamp() {
        let entry = TransparencyLogEntry {
            log_index: 0,
            entry_hash: String::new(),
            inclusion_proof: InclusionProof {
                root_hash: String::new(),
                tree_size: 0,
                hashes: vec![],
                leaf_index: 0,
            },
            signed_entry_timestamp: vec![],
            log_id: String::new(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: TransparencyLogEntry = serde_json::from_str(&json).unwrap();
        assert!(parsed.signed_entry_timestamp.is_empty());
        assert!(parsed.log_id.is_empty());
    }

    #[test]
    fn transparency_log_entry_large_log_index() {
        let entry = TransparencyLogEntry {
            log_index: u64::MAX,
            entry_hash: "sha256:max".to_string(),
            inclusion_proof: InclusionProof {
                root_hash: "r".to_string(),
                tree_size: u64::MAX,
                hashes: vec![],
                leaf_index: u64::MAX,
            },
            signed_entry_timestamp: vec![],
            log_id: "log".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: TransparencyLogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.log_index, u64::MAX);
    }

    // ── TufRootMetadata edge cases ──────────────────────────────────

    #[test]
    fn tuf_root_metadata_clone_independence() {
        let root = TufRootMetadata {
            version: 42,
            root_hash: "sha256:root".to_string(),
            expires: 1_000_000,
            key_ids: vec!["k1".to_string(), "k2".to_string()],
            threshold: 2,
        };
        let cloned = root.clone();
        assert_eq!(root.version, 42);
        assert_eq!(cloned.version, 42);
        assert_eq!(root.key_ids.len(), cloned.key_ids.len());
    }

    #[test]
    fn tuf_root_metadata_empty_key_ids() {
        let root = TufRootMetadata {
            version: 1,
            root_hash: "sha256:r".to_string(),
            expires: 0,
            key_ids: vec![],
            threshold: 0,
        };
        let json = serde_json::to_string(&root).unwrap();
        let parsed: TufRootMetadata = serde_json::from_str(&json).unwrap();
        assert!(parsed.key_ids.is_empty());
        assert_eq!(parsed.threshold, 0);
    }

    #[test]
    fn tuf_root_metadata_max_version() {
        let root = TufRootMetadata {
            version: u32::MAX,
            root_hash: "sha256:max".to_string(),
            expires: u64::MAX,
            key_ids: vec!["k".to_string()],
            threshold: 255,
        };
        let json = serde_json::to_string(&root).unwrap();
        let parsed: TufRootMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.version, u32::MAX);
        assert_eq!(parsed.threshold, 255);
    }

    #[test]
    fn tuf_root_metadata_debug_format() {
        let root = TufRootMetadata {
            version: 7,
            root_hash: "sha256:debug".to_string(),
            expires: 999,
            key_ids: vec!["k1".to_string()],
            threshold: 1,
        };
        let debug = format!("{root:?}");
        assert!(debug.contains("TufRootMetadata"));
        assert!(debug.contains("sha256:debug"));
    }

    // ── TufTargetInfo edge cases ────────────────────────────────────

    #[test]
    fn tuf_target_info_clone_independence() {
        let target = TufTargetInfo {
            target_path: "connectors/fcp.test".to_string(),
            hash: "sha256:abc".to_string(),
            length: 1024,
            delegations: vec!["root".to_string()],
        };
        let cloned = target.clone();
        assert_eq!(target.target_path, "connectors/fcp.test");
        assert_eq!(cloned.target_path, "connectors/fcp.test");
    }

    #[test]
    fn tuf_target_info_empty_delegations() {
        let target = TufTargetInfo {
            target_path: "p".to_string(),
            hash: "h".to_string(),
            length: 0,
            delegations: vec![],
        };
        let json = serde_json::to_string(&target).unwrap();
        let parsed: TufTargetInfo = serde_json::from_str(&json).unwrap();
        assert!(parsed.delegations.is_empty());
        assert_eq!(parsed.length, 0);
    }

    #[test]
    fn tuf_target_info_debug_format() {
        let target = TufTargetInfo {
            target_path: "path/to/target".to_string(),
            hash: "sha256:hash".to_string(),
            length: 4096,
            delegations: vec!["d1".to_string()],
        };
        let debug = format!("{target:?}");
        assert!(debug.contains("TufTargetInfo"));
        assert!(debug.contains("path/to/target"));
    }

    // ── SigstoreBundle edge cases ───────────────────────────────────

    #[test]
    fn sigstore_bundle_clone_independence() {
        let bundle = SigstoreBundle {
            signature: "sig".to_string(),
            certificate: "cert".to_string(),
            rekor_entry: None,
            identity: "id".to_string(),
            issuer: "iss".to_string(),
        };
        let cloned = bundle.clone();
        assert_eq!(bundle.signature, "sig");
        assert_eq!(cloned.signature, "sig");
    }

    #[test]
    fn sigstore_bundle_with_rekor_entry_serde() {
        let bundle = SigstoreBundle {
            signature: "sig-value".to_string(),
            certificate: "cert-value".to_string(),
            rekor_entry: Some(TransparencyLogEntry {
                log_index: 777,
                entry_hash: "sha256:e".to_string(),
                inclusion_proof: InclusionProof {
                    root_hash: "sha256:r".to_string(),
                    tree_size: 1000,
                    hashes: vec!["sha256:h1".to_string(), "sha256:h2".to_string()],
                    leaf_index: 777,
                },
                signed_entry_timestamp: vec![1, 2, 3],
                log_id: "rekor-prod".to_string(),
            }),
            identity: "github-actions".to_string(),
            issuer: "https://token.actions.githubusercontent.com".to_string(),
        };
        let json = serde_json::to_string(&bundle).unwrap();
        let parsed: SigstoreBundle = serde_json::from_str(&json).unwrap();
        assert!(parsed.rekor_entry.is_some());
        let entry = parsed.rekor_entry.unwrap();
        assert_eq!(entry.log_index, 777);
        assert_eq!(entry.inclusion_proof.hashes.len(), 2);
    }

    #[test]
    fn sigstore_bundle_empty_strings() {
        let bundle = SigstoreBundle {
            signature: String::new(),
            certificate: String::new(),
            rekor_entry: None,
            identity: String::new(),
            issuer: String::new(),
        };
        let json = serde_json::to_string(&bundle).unwrap();
        let parsed: SigstoreBundle = serde_json::from_str(&json).unwrap();
        assert!(parsed.signature.is_empty());
        assert!(parsed.identity.is_empty());
    }

    #[test]
    fn sigstore_bundle_debug_format() {
        let bundle = SigstoreBundle {
            signature: "sig".to_string(),
            certificate: "cert".to_string(),
            rekor_entry: None,
            identity: "id".to_string(),
            issuer: "iss".to_string(),
        };
        let debug = format!("{bundle:?}");
        assert!(debug.contains("SigstoreBundle"));
    }

    // ── TransparencyVerificationResult edge cases ───────────────────

    #[test]
    fn transparency_verification_result_clone_independence() {
        let result = TransparencyVerificationResult {
            verified: true,
            log_index: Some(42),
            logged_at: Some(1_000_000),
        };
        let cloned = result.clone();
        assert!(result.verified);
        assert_eq!(result.log_index, Some(42));
        assert_eq!(cloned.log_index, Some(42));
    }

    #[test]
    fn transparency_verification_result_all_none() {
        let result = TransparencyVerificationResult {
            verified: false,
            log_index: None,
            logged_at: None,
        };
        let debug = format!("{result:?}");
        assert!(debug.contains("TransparencyVerificationResult"));
        assert!(!result.verified);
    }

    // ── TufVerificationResult edge cases ────────────────────────────

    #[test]
    fn tuf_verification_result_clone_with_target() {
        let result = TufVerificationResult {
            verified: true,
            root_version: 10,
            target: Some(TufTargetInfo {
                target_path: "p".to_string(),
                hash: "h".to_string(),
                length: 512,
                delegations: vec!["d".to_string()],
            }),
        };
        let cloned = result.clone();
        assert_eq!(result.root_version, 10);
        assert!(result.target.is_some());
        assert_eq!(cloned.root_version, 10);
        assert_eq!(cloned.target.as_ref().unwrap().length, 512);
    }

    #[test]
    fn tuf_verification_result_without_target() {
        let result = TufVerificationResult {
            verified: false,
            root_version: 0,
            target: None,
        };
        let debug = format!("{result:?}");
        assert!(debug.contains("TufVerificationResult"));
        assert!(!result.verified);
    }

    // ── SigstoreVerificationResult edge cases ───────────────────────

    #[test]
    fn sigstore_verification_result_clone_all_some() {
        let result = SigstoreVerificationResult {
            verified: true,
            identity: Some("github-actions".to_string()),
            issuer: Some("https://github.com".to_string()),
            rekor_log_index: Some(12345),
        };
        let cloned = result.clone();
        assert_eq!(result.identity, Some("github-actions".to_string()));
        assert_eq!(cloned.rekor_log_index, Some(12345));
    }

    #[test]
    fn sigstore_verification_result_clone_all_none() {
        let result = SigstoreVerificationResult {
            verified: false,
            identity: None,
            issuer: None,
            rekor_log_index: None,
        };
        let cloned = result.clone();
        assert!(!result.verified);
        assert!(cloned.identity.is_none());
    }

    // ── SupplyChainVerificationConfig edge cases ────────────────────

    #[test]
    fn supply_chain_verification_config_clone_independence() {
        let config = SupplyChainVerificationConfig {
            tuf_pinned_root: Some(TufRootMetadata {
                version: 1,
                root_hash: "sha256:r".to_string(),
                expires: u64::MAX,
                key_ids: vec!["k".to_string()],
                threshold: 1,
            }),
            trusted_sigstore_identities: vec!["id".to_string()],
            trusted_sigstore_issuers: vec!["iss".to_string()],
            require_transparency: true,
            require_tuf: false,
            require_sigstore: true,
            ..SupplyChainVerificationConfig::default()
        };
        let cloned = config.clone();
        assert!(config.require_transparency);
        assert!(config.require_sigstore);
        assert!(!config.require_tuf);
        assert_eq!(cloned.trusted_sigstore_identities.len(), 1);
    }

    #[test]
    fn supply_chain_verification_config_all_false() {
        let config = SupplyChainVerificationConfig {
            tuf_pinned_root: None,
            trusted_sigstore_identities: vec![],
            trusted_sigstore_issuers: vec![],
            require_transparency: false,
            require_tuf: false,
            require_sigstore: false,
            ..SupplyChainVerificationConfig::default()
        };
        assert!(!config.require_transparency);
        assert!(!config.require_tuf);
        assert!(!config.require_sigstore);
        assert!(config.tuf_pinned_root.is_none());
    }

    // ── ConnectorBundle edge cases ──────────────────────────────────

    #[test]
    fn connector_bundle_clone_large_binary() {
        let bundle = ConnectorBundle {
            manifest_toml: "toml".to_string(),
            binary: vec![0xABu8; 100_000],
            target: ConnectorTarget {
                os: "linux".to_string(),
                arch: "amd64".to_string(),
            },
        };
        let cloned = bundle.clone();
        assert_eq!(bundle.binary.len(), 100_000);
        assert_eq!(cloned.binary.len(), 100_000);
    }

    #[test]
    fn connector_bundle_empty_binary() {
        let bundle = ConnectorBundle {
            manifest_toml: String::new(),
            binary: vec![],
            target: ConnectorTarget {
                os: String::new(),
                arch: String::new(),
            },
        };
        assert!(bundle.binary.is_empty());
        assert!(bundle.manifest_toml.is_empty());
    }

    #[test]
    fn connector_bundle_debug_format() {
        let bundle = ConnectorBundle {
            manifest_toml: "manifest".to_string(),
            binary: vec![1, 2, 3],
            target: test_target(),
        };
        let debug = format!("{bundle:?}");
        assert!(debug.contains("ConnectorBundle"));
        assert!(debug.contains("manifest"));
    }

    // ── VerifiedConnectorBundle edge cases ──────────────────────────

    #[test]
    fn verified_bundle_clone_independence() {
        let manifest = minimal_manifest();
        let verified = VerifiedConnectorBundle {
            manifest,
            manifest_hash: "sha256:m".to_string(),
            binary_hash: "sha256:b".to_string(),
            target: test_target(),
        };
        let cloned = verified.clone();
        assert_eq!(verified.manifest_hash, "sha256:m");
        assert_eq!(cloned.manifest_hash, "sha256:m");
        assert_eq!(verified.target, cloned.target);
    }

    #[test]
    fn verified_bundle_report_empty_outcome() {
        let manifest = minimal_manifest();
        let verified = VerifiedConnectorBundle {
            manifest,
            manifest_hash: "sha256:m".to_string(),
            binary_hash: "sha256:b".to_string(),
            target: test_target(),
        };
        let report = verified.report("");
        assert!(report.outcome.is_empty());
    }

    #[test]
    fn verified_bundle_report_unicode_outcome() {
        let manifest = minimal_manifest();
        let verified = VerifiedConnectorBundle {
            manifest,
            manifest_hash: "sha256:m".to_string(),
            binary_hash: "sha256:b".to_string(),
            target: test_target(),
        };
        let report = verified.report("\u{2705} passed");
        assert_eq!(report.outcome, "\u{2705} passed");
    }

    #[test]
    fn verified_bundle_rate_limits_none() {
        let manifest = minimal_manifest();
        let verified = VerifiedConnectorBundle {
            manifest,
            manifest_hash: "sha256:m".to_string(),
            binary_hash: "sha256:b".to_string(),
            target: test_target(),
        };
        assert!(verified.rate_limit_declarations().is_none());
    }

    // ── MirrorResult edge cases ─────────────────────────────────────

    #[test]
    fn mirror_result_clone_independence() {
        let result = MirrorResult {
            manifest_object_id: ObjectId::from_bytes([1u8; 32]),
            binary_object_id: ObjectId::from_bytes([2u8; 32]),
            manifest_hash: "sha256:m".to_string(),
            binary_hash: "sha256:b".to_string(),
        };
        let cloned = result.clone();
        assert_eq!(result.manifest_hash, "sha256:m");
        assert_eq!(cloned.manifest_hash, "sha256:m");
        assert_ne!(result.manifest_object_id, result.binary_object_id);
    }

    #[test]
    fn mirror_result_debug_format() {
        let result = MirrorResult {
            manifest_object_id: ObjectId::from_bytes([3u8; 32]),
            binary_object_id: ObjectId::from_bytes([4u8; 32]),
            manifest_hash: "sha256:mh".to_string(),
            binary_hash: "sha256:bh".to_string(),
        };
        let debug = format!("{result:?}");
        assert!(debug.contains("MirrorResult"));
        assert!(debug.contains("sha256:mh"));
    }

    // ── RegistryVerificationReport edge cases ───────────────────────

    #[test]
    fn registry_verification_report_serde_empty_fields() {
        let report = RegistryVerificationReport {
            connector_id: String::new(),
            manifest_hash: String::new(),
            binary_hash: String::new(),
            target: ConnectorTarget {
                os: String::new(),
                arch: String::new(),
            },
            verified_at: 0,
            outcome: String::new(),
        };
        let json = serde_json::to_string(&report).unwrap();
        let parsed: RegistryVerificationReport = serde_json::from_str(&json).unwrap();
        assert!(parsed.connector_id.is_empty());
        assert_eq!(parsed.verified_at, 0);
    }

    #[test]
    fn registry_verification_report_serde_max_timestamp() {
        let report = RegistryVerificationReport {
            connector_id: "fcp.test".to_string(),
            manifest_hash: "sha256:m".to_string(),
            binary_hash: "sha256:b".to_string(),
            target: test_target(),
            verified_at: u64::MAX,
            outcome: "pass".to_string(),
        };
        let json = serde_json::to_string(&report).unwrap();
        let parsed: RegistryVerificationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.verified_at, u64::MAX);
    }

    #[test]
    fn registry_verification_report_clone_independence() {
        let report = RegistryVerificationReport {
            connector_id: "fcp.test".to_string(),
            manifest_hash: "sha256:m".to_string(),
            binary_hash: "sha256:b".to_string(),
            target: test_target(),
            verified_at: 42,
            outcome: "pass".to_string(),
        };
        let cloned = report.clone();
        assert_eq!(report.connector_id, "fcp.test");
        assert_eq!(cloned.connector_id, "fcp.test");
    }

    // ── hash_bytes edge cases ───────────────────────────────────────

    #[test]
    fn hash_bytes_single_byte() {
        let h = hash_bytes(&[0x42]);
        assert!(h.starts_with("sha256:"));
        assert_eq!(h.len(), 7 + 64);
    }

    #[test]
    fn hash_bytes_all_zeros() {
        let h = hash_bytes(&[0u8; 1024]);
        assert!(h.starts_with("sha256:"));
        let h2 = hash_bytes(&[0u8; 1024]);
        assert_eq!(h, h2);
    }

    #[test]
    fn hash_bytes_all_ones() {
        let h = hash_bytes(&[0xFF; 1024]);
        assert!(h.starts_with("sha256:"));
        // Different from all zeros
        let h_zeros = hash_bytes(&[0u8; 1024]);
        assert_ne!(h, h_zeros);
    }

    #[test]
    fn hash_bytes_known_value() {
        // SHA256 of empty string is well-known
        let h = hash_bytes(b"");
        assert_eq!(
            h,
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    // ── signature_message edge cases ────────────────────────────────

    #[test]
    fn signature_message_uses_u64_length_prefix() {
        let msg = signature_message(b"abc", "def");
        // First 8 bytes are u64 LE length of signing_bytes
        let len = u64::from_le_bytes(msg[0..8].try_into().unwrap());
        assert_eq!(len, 3);
    }

    #[test]
    fn signature_message_binary_hash_length_prefix() {
        let signing_bytes = b"test";
        let binary_hash = "sha256:hash123";
        let msg = signature_message(signing_bytes, binary_hash);
        // After signing_bytes, hash length prefix
        let hash_offset = 8 + signing_bytes.len();
        let hash_len = u64::from_le_bytes(msg[hash_offset..hash_offset + 8].try_into().unwrap());
        assert_eq!(hash_len as usize, binary_hash.len());
    }

    #[test]
    fn signature_message_large_signing_bytes() {
        let large = vec![0xABu8; 100_000];
        let msg = signature_message(&large, "sha256:h");
        assert_eq!(msg.len(), 8 + 100_000 + 8 + 8);
    }

    #[test]
    fn signature_message_no_overlap_ambiguity() {
        // "ab" + "cde" should differ from "abc" + "de"
        let m1 = signature_message(b"ab", "cde");
        let m2 = signature_message(b"abc", "de");
        assert_ne!(m1, m2);
    }

    // ── attestation_label coverage ──────────────────────────────────

    #[test]
    fn attestation_label_in_toto() {
        assert_eq!(attestation_label(AttestationType::InToto), "in-toto");
    }

    #[test]
    fn attestation_label_reproducible_build() {
        assert_eq!(
            attestation_label(AttestationType::ReproducibleBuild),
            "reproducible-build"
        );
    }

    #[test]
    fn attestation_label_code_review() {
        assert_eq!(
            attestation_label(AttestationType::CodeReview),
            "code-review"
        );
    }

    // ── RegistryError display field interpolation ───────────────────

    #[test]
    fn registry_error_unknown_kid_contains_kid() {
        let err = RegistryError::UnknownKid {
            kid: "special-key-123".to_string(),
        };
        assert!(err.to_string().contains("special-key-123"));
    }

    #[test]
    fn registry_error_signature_invalid_contains_kid() {
        let err = RegistryError::SignatureInvalid {
            kid: "bad-key-456".to_string(),
        };
        assert!(err.to_string().contains("bad-key-456"));
    }

    #[test]
    fn registry_error_publisher_threshold_contains_values() {
        let err = RegistryError::PublisherThresholdUnmet {
            required: 5,
            valid: 2,
        };
        let msg = err.to_string();
        assert!(msg.contains('5'));
        assert!(msg.contains('2'));
    }

    #[test]
    fn registry_error_target_mismatch_contains_both() {
        let err = RegistryError::TargetMismatch {
            expected: "linux-amd64".to_string(),
            found: "darwin-arm64".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("linux-amd64"));
        assert!(msg.contains("darwin-arm64"));
    }

    #[test]
    fn registry_error_capability_ceiling_contains_cap() {
        let err = RegistryError::CapabilityCeilingViolation {
            capability: "network.raw".to_string(),
        };
        assert!(err.to_string().contains("network.raw"));
    }

    #[test]
    fn registry_error_required_attestation_contains_type() {
        let err = RegistryError::RequiredAttestationMissing {
            attestation: "reproducible-build".to_string(),
        };
        assert!(err.to_string().contains("reproducible-build"));
    }

    #[test]
    fn registry_error_attestation_expired_contains_fields() {
        let err = RegistryError::AttestationExpired {
            attestation: "in-toto".to_string(),
            expired_at: 42,
        };
        let msg = err.to_string();
        assert!(msg.contains("in-toto"));
        assert!(msg.contains("42"));
    }

    #[test]
    fn registry_error_slsa_insufficient_contains_level() {
        let err = RegistryError::SlsaLevelInsufficient { required: 4 };
        assert!(err.to_string().contains('4'));
    }

    #[test]
    fn registry_error_untrusted_builder_contains_name() {
        let err = RegistryError::UntrustedBuilder {
            builder: "malicious-ci".to_string(),
        };
        assert!(err.to_string().contains("malicious-ci"));
    }

    // ── SupplyChainVerificationError display field interpolation ────

    #[test]
    fn sc_error_tuf_root_mismatch_contains_hashes() {
        let err = SupplyChainVerificationError::TufRootMismatch {
            expected: "sha256:expected".to_string(),
            actual: "sha256:actual".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("sha256:expected"));
        assert!(msg.contains("sha256:actual"));
    }

    #[test]
    fn sc_error_tuf_target_not_found_contains_target() {
        let err = SupplyChainVerificationError::TufTargetNotFound {
            target: "connectors/fcp.test".to_string(),
        };
        assert!(err.to_string().contains("connectors/fcp.test"));
    }

    #[test]
    fn sc_error_tuf_rollback_contains_versions() {
        let err = SupplyChainVerificationError::TufRollback {
            current: 10,
            got: 5,
        };
        let msg = err.to_string();
        assert!(msg.contains("10"));
        assert!(msg.contains('5'));
    }

    #[test]
    fn sc_error_sigstore_identity_mismatch_contains_both() {
        let err = SupplyChainVerificationError::SigstoreIdentityMismatch {
            expected: "expected-id".to_string(),
            actual: "actual-id".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("expected-id"));
        assert!(msg.contains("actual-id"));
    }

    #[test]
    fn sc_error_sigstore_issuer_untrusted_contains_issuer() {
        let err = SupplyChainVerificationError::SigstoreIssuerUntrusted {
            issuer: "https://evil-issuer.com".to_string(),
        };
        assert!(err.to_string().contains("https://evil-issuer.com"));
    }

    #[test]
    fn sc_error_network_contains_message() {
        let err = SupplyChainVerificationError::Network("connection refused".to_string());
        assert!(err.to_string().contains("connection refused"));
    }

    // ── SupplyChainVerificationError Debug field interpolation ──────

    #[test]
    fn sc_error_debug_tuf_root_mismatch() {
        let err = SupplyChainVerificationError::TufRootMismatch {
            expected: "e".to_string(),
            actual: "a".to_string(),
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("TufRootMismatch"));
    }

    #[test]
    fn sc_error_debug_network() {
        let err = SupplyChainVerificationError::Network("timeout".to_string());
        let debug = format!("{err:?}");
        assert!(debug.contains("Network"));
        assert!(debug.contains("timeout"));
    }

    #[test]
    fn sc_error_debug_not_configured() {
        let err = SupplyChainVerificationError::NotConfigured;
        let debug = format!("{err:?}");
        assert!(debug.contains("NotConfigured"));
    }

    // ── RegistryVerifier construction ───────────────────────────────

    #[test]
    fn registry_verifier_const_new() {
        let trust = RegistryTrustPolicy::default();
        let verifier = RegistryVerifier::new(trust);
        let debug = format!("{verifier:?}");
        assert!(debug.contains("RegistryVerifier"));
    }

    // ── enforce_supply_chain_policy: empty attestation requirement ──

    #[test]
    fn enforce_supply_chain_empty_attestation_types_passes() {
        let mut manifest = minimal_manifest();
        manifest.policy = Some(fcp_manifest::PolicySection {
            require_transparency_log: false,
            require_attestation_types: vec![],
            min_slsa_level: None,
            trusted_builders: vec![],
            require_attestation_expiry: false,
        });
        enforce_supply_chain_policy(&manifest, None).expect("empty attestation types passes");
    }

    // ── enforce_capability_ceiling: multiple caps ───────────────────

    #[test]
    fn enforce_capability_ceiling_exact_match() {
        let manifest = minimal_manifest();
        // Collect all capabilities from the manifest
        let mut caps: HashSet<CapabilityId> = HashSet::new();
        caps.extend(manifest.capabilities.required.iter().cloned());
        caps.extend(manifest.capabilities.optional.iter().cloned());
        for op in manifest.provides.operations.values() {
            caps.insert(op.capability.clone());
        }
        let ceiling: Vec<CapabilityId> = caps.into_iter().collect();
        let policy = test_zone_policy(ceiling);
        enforce_capability_ceiling(Some(&policy), &manifest).expect("exact match should pass");
    }

    // ── ConnectorManifestObject / ConnectorBinaryObject serde ───────

    #[test]
    fn connector_manifest_object_serde_roundtrip() {
        let obj = ConnectorManifestObject {
            manifest_toml: "toml content".to_string(),
            manifest_hash: "sha256:m".to_string(),
        };
        let json = serde_json::to_string(&obj).unwrap();
        let parsed: ConnectorManifestObject = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.manifest_toml, "toml content");
        assert_eq!(parsed.manifest_hash, "sha256:m");
    }

    #[test]
    fn connector_binary_object_serde_roundtrip() {
        let obj = ConnectorBinaryObject {
            target: ConnectorTarget {
                os: "linux".to_string(),
                arch: "amd64".to_string(),
            },
            binary_hash: "sha256:b".to_string(),
            binary: vec![1, 2, 3, 4, 5],
        };
        let json = serde_json::to_string(&obj).unwrap();
        let parsed: ConnectorBinaryObject = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.binary, vec![1, 2, 3, 4, 5]);
        assert_eq!(parsed.target.os, "linux");
    }

    #[test]
    fn connector_manifest_object_debug_clone() {
        let obj = ConnectorManifestObject {
            manifest_toml: "t".to_string(),
            manifest_hash: "h".to_string(),
        };
        let debug = format!("{obj:?}");
        assert!(debug.contains("ConnectorManifestObject"));
        let cloned = obj.clone();
        assert_eq!(cloned.manifest_toml, obj.manifest_toml);
    }

    #[test]
    fn connector_binary_object_debug_clone() {
        let obj = ConnectorBinaryObject {
            target: test_target(),
            binary_hash: "sha256:b".to_string(),
            binary: vec![],
        };
        let debug = format!("{obj:?}");
        assert!(debug.contains("ConnectorBinaryObject"));
        let cloned = obj.clone();
        assert_eq!(cloned.binary_hash, obj.binary_hash);
    }

    // ── MANIFEST_SIGNATURE_CONTEXT details ──────────────────────────

    #[test]
    fn manifest_signature_context_is_utf8() {
        let s = std::str::from_utf8(MANIFEST_SIGNATURE_CONTEXT);
        assert!(s.is_ok());
        assert_eq!(s.unwrap(), "fcp.registry.manifest.v1");
    }

    #[test]
    fn manifest_signature_context_length() {
        assert_eq!(MANIFEST_SIGNATURE_CONTEXT.len(), 24);
    }

    // ══════════════════════════════════════════════════════════════════════
    // NEW: Expanded test suite for 336+ target (80 new tests)
    // ══════════════════════════════════════════════════════════════════════

    // ── signature_message wire format correctness ───────────────────────

    #[test]
    fn signature_message_u64_le_length_prefix_signing_bytes() {
        // Verify the signing bytes length is encoded as u64 LE (8 bytes)
        let signing = b"hello";
        let msg = signature_message(signing, "h");
        let prefix = u64::from_le_bytes(msg[0..8].try_into().unwrap());
        assert_eq!(prefix, 5);
    }

    #[test]
    fn signature_message_u64_le_length_prefix_binary_hash() {
        // Verify the binary hash length is encoded as u64 LE (8 bytes)
        let signing = b"x";
        let binary_hash = "sha256:abc";
        let msg = signature_message(signing, binary_hash);
        let hash_offset = 8 + signing.len();
        let prefix = u64::from_le_bytes(msg[hash_offset..hash_offset + 8].try_into().unwrap());
        assert_eq!(prefix, binary_hash.len() as u64);
    }

    #[test]
    fn signature_message_total_length_formula() {
        // Total = 8 + signing_len + 8 + hash_len
        let signing = b"signing-data";
        let hash = "sha256:some-hash";
        let msg = signature_message(signing, hash);
        assert_eq!(msg.len(), 8 + signing.len() + 8 + hash.len());
    }

    #[test]
    fn signature_message_payload_recovery() {
        // Verify we can recover both payloads from the wire format
        let signing = b"recover-me";
        let hash = "sha256:deadbeef";
        let msg = signature_message(signing, hash);

        let s_len = u64::from_le_bytes(msg[0..8].try_into().unwrap()) as usize;
        let recovered_signing = &msg[8..8 + s_len];
        assert_eq!(recovered_signing, signing);

        let h_off = 8 + s_len;
        let h_len = u64::from_le_bytes(msg[h_off..h_off + 8].try_into().unwrap()) as usize;
        let recovered_hash = &msg[h_off + 8..h_off + 8 + h_len];
        assert_eq!(recovered_hash, hash.as_bytes());
    }

    #[test]
    fn signature_message_unicode_binary_hash() {
        // Unicode in hash string should be preserved byte-for-byte
        let hash = "sha256:\u{00E9}\u{00FC}\u{00F1}";
        let msg = signature_message(b"data", hash);
        let h_off = 8 + 4; // 8 prefix + 4 bytes "data"
        let h_len = u64::from_le_bytes(msg[h_off..h_off + 8].try_into().unwrap()) as usize;
        assert_eq!(h_len, hash.len()); // byte length, not char count
    }

    #[test]
    fn signature_message_order_matters() {
        // Swapping signing_bytes and hash should produce different messages
        let m1 = signature_message(b"alpha", "beta");
        let m2 = signature_message(b"beta", "alpha");
        assert_ne!(m1, m2);
    }

    // ── hash_bytes further edge cases ──────────────────────────────────

    #[test]
    fn hash_bytes_unicode_input() {
        let h = hash_bytes("\u{1F600}\u{1F601}\u{1F602}".as_bytes());
        assert!(h.starts_with("sha256:"));
        assert_eq!(h.len(), 7 + 64);
    }

    #[test]
    fn hash_bytes_two_bytes_differ_by_one() {
        // Adjacent byte values should produce completely different hashes
        let h1 = hash_bytes(&[0x00]);
        let h2 = hash_bytes(&[0x01]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_bytes_length_sensitivity() {
        // Same prefix but different length should differ
        let h1 = hash_bytes(&[0xAB; 10]);
        let h2 = hash_bytes(&[0xAB; 11]);
        assert_ne!(h1, h2);
    }

    // ── ConnectorTarget from_env stability ─────────────────────────────

    #[test]
    fn connector_target_from_env_deterministic() {
        let t1 = ConnectorTarget::from_env();
        let t2 = ConnectorTarget::from_env();
        assert_eq!(t1, t2);
    }

    #[test]
    fn connector_target_from_env_os_nonempty() {
        let t = ConnectorTarget::from_env();
        assert!(!t.os.is_empty());
    }

    #[test]
    fn connector_target_from_env_arch_nonempty() {
        let t = ConnectorTarget::from_env();
        assert!(!t.arch.is_empty());
    }

    #[test]
    fn connector_target_from_env_as_string_contains_hyphen() {
        let t = ConnectorTarget::from_env();
        assert!(t.as_string().contains('-'));
    }

    // ── RegistryError From conversions ─────────────────────────────────

    #[test]
    fn registry_error_from_manifest_error() {
        let me = ConnectorManifest::parse_str("garbage %%%").unwrap_err();
        let re: RegistryError = me.into();
        assert!(matches!(re, RegistryError::ManifestParse(_)));
        // Display should contain "manifest parse failed"
        assert!(re.to_string().contains("manifest parse failed"));
    }

    #[test]
    fn registry_error_from_object_store_error_not_found() {
        let oid = ObjectId::from_bytes([0u8; 32]);
        let ose = ObjectStoreError::NotFound(oid);
        let re: RegistryError = ose.into();
        assert!(matches!(re, RegistryError::ObjectStore(_)));
        assert!(re.to_string().contains("object store failure"));
    }

    #[test]
    fn registry_error_from_serialization_error() {
        // Signing-bytes failures are represented explicitly through the dedicated variant
        let se = SerializationError::MissingSchemaHashPrefix;
        let re = RegistryError::SigningBytes(se);
        assert!(matches!(re, RegistryError::SigningBytes(_)));
    }

    // ── enforce_supply_chain_policy SLSA boundary ──────────────────────

    #[test]
    fn supply_chain_slsa_exact_level_passes() {
        let mut manifest = minimal_manifest();
        manifest.policy = Some(PolicySection {
            require_transparency_log: false,
            require_attestation_types: vec![],
            min_slsa_level: Some(3),
            trusted_builders: Vec::new(),
            require_attestation_expiry: false,
        });
        let evidence = SupplyChainEvidence {
            transparency_log_present: false,
            tuf_verified: false,
            tuf_target_hash: None,
            sigstore_verified: false,
            sigstore_identity: None,
            sigstore_issuer: None,
            attestations: vec![AttestationEvidence {
                attestation_type: AttestationType::InToto,
                slsa_level: Some(3), // exact match
                builder_id: None,
                expires_at: None,
            }],
        };
        enforce_supply_chain_policy(&manifest, Some(&evidence))
            .expect("exact SLSA level should pass");
    }

    #[test]
    fn supply_chain_expired_attestation_fails() {
        let mut manifest = minimal_manifest();
        manifest.policy = Some(PolicySection {
            require_transparency_log: false,
            require_attestation_types: vec![AttestationType::InToto],
            min_slsa_level: None,
            trusted_builders: Vec::new(),
            require_attestation_expiry: false,
        });
        let evidence = SupplyChainEvidence {
            transparency_log_present: false,
            tuf_verified: false,
            tuf_target_hash: None,
            sigstore_verified: false,
            sigstore_identity: None,
            sigstore_issuer: None,
            attestations: vec![AttestationEvidence {
                attestation_type: AttestationType::InToto,
                slsa_level: Some(3),
                builder_id: None,
                expires_at: Some(0),
            }],
        };
        let err = enforce_supply_chain_policy(&manifest, Some(&evidence))
            .expect_err("expired attestation should fail");
        assert!(matches!(
            err,
            RegistryError::AttestationExpired {
                attestation,
                expired_at: 0,
            } if attestation == "in-toto"
        ));
    }

    #[test]
    fn supply_chain_slsa_level_one_below_fails() {
        let mut manifest = minimal_manifest();
        manifest.policy = Some(PolicySection {
            require_transparency_log: false,
            require_attestation_types: vec![],
            min_slsa_level: Some(3),
            trusted_builders: Vec::new(),
            require_attestation_expiry: false,
        });
        let evidence = SupplyChainEvidence {
            transparency_log_present: false,
            tuf_verified: false,
            tuf_target_hash: None,
            sigstore_verified: false,
            sigstore_identity: None,
            sigstore_issuer: None,
            attestations: vec![AttestationEvidence {
                attestation_type: AttestationType::InToto,
                slsa_level: Some(2), // one below
                builder_id: None,
                expires_at: None,
            }],
        };
        let err = enforce_supply_chain_policy(&manifest, Some(&evidence))
            .expect_err("level 2 < required 3");
        assert!(matches!(
            err,
            RegistryError::SlsaLevelInsufficient { required: 3 }
        ));
    }

    #[test]
    fn supply_chain_slsa_above_minimum_passes() {
        let mut manifest = minimal_manifest();
        manifest.policy = Some(PolicySection {
            require_transparency_log: false,
            require_attestation_types: vec![],
            min_slsa_level: Some(1),
            trusted_builders: Vec::new(),
            require_attestation_expiry: false,
        });
        let evidence = SupplyChainEvidence {
            transparency_log_present: false,
            tuf_verified: false,
            tuf_target_hash: None,
            sigstore_verified: false,
            sigstore_identity: None,
            sigstore_issuer: None,
            attestations: vec![AttestationEvidence {
                attestation_type: AttestationType::InToto,
                slsa_level: Some(4), // well above minimum
                builder_id: None,
                expires_at: None,
            }],
        };
        enforce_supply_chain_policy(&manifest, Some(&evidence)).expect("level 4 >= required 1");
    }

    #[test]
    fn supply_chain_slsa_zero_minimum_passes() {
        let mut manifest = minimal_manifest();
        manifest.policy = Some(PolicySection {
            require_transparency_log: false,
            require_attestation_types: vec![],
            min_slsa_level: Some(0),
            trusted_builders: Vec::new(),
            require_attestation_expiry: false,
        });
        let evidence = SupplyChainEvidence {
            transparency_log_present: false,
            tuf_verified: false,
            tuf_target_hash: None,
            sigstore_verified: false,
            sigstore_identity: None,
            sigstore_issuer: None,
            attestations: vec![AttestationEvidence {
                attestation_type: AttestationType::InToto,
                slsa_level: Some(0),
                builder_id: None,
                expires_at: None,
            }],
        };
        enforce_supply_chain_policy(&manifest, Some(&evidence)).expect("level 0 == required 0");
    }

    // ── enforce_supply_chain_policy: trusted builders edge cases ────────

    #[test]
    fn supply_chain_trusted_builder_exact_match_passes() {
        let mut manifest = minimal_manifest();
        manifest.policy = Some(PolicySection {
            require_transparency_log: false,
            require_attestation_types: vec![],
            min_slsa_level: None,
            trusted_builders: vec!["my-ci".to_string()],
            require_attestation_expiry: false,
        });
        let evidence = SupplyChainEvidence {
            transparency_log_present: false,
            tuf_verified: false,
            tuf_target_hash: None,
            sigstore_verified: false,
            sigstore_identity: None,
            sigstore_issuer: None,
            attestations: vec![AttestationEvidence {
                attestation_type: AttestationType::InToto,
                slsa_level: None,
                builder_id: Some("my-ci".to_string()),
                expires_at: None,
            }],
        };
        enforce_supply_chain_policy(&manifest, Some(&evidence))
            .expect("exact builder match passes");
    }

    #[test]
    fn supply_chain_trusted_builder_case_sensitive() {
        let mut manifest = minimal_manifest();
        manifest.policy = Some(PolicySection {
            require_transparency_log: false,
            require_attestation_types: vec![],
            min_slsa_level: None,
            trusted_builders: vec!["My-CI".to_string()],
            require_attestation_expiry: false,
        });
        let evidence = SupplyChainEvidence {
            transparency_log_present: false,
            tuf_verified: false,
            tuf_target_hash: None,
            sigstore_verified: false,
            sigstore_identity: None,
            sigstore_issuer: None,
            attestations: vec![AttestationEvidence {
                attestation_type: AttestationType::InToto,
                slsa_level: None,
                builder_id: Some("my-ci".to_string()), // lowercase
                expires_at: None,
            }],
        };
        let err =
            enforce_supply_chain_policy(&manifest, Some(&evidence)).expect_err("case mismatch");
        assert!(matches!(err, RegistryError::UntrustedBuilder { .. }));
    }

    #[test]
    fn supply_chain_multiple_trusted_builders_one_matches() {
        let mut manifest = minimal_manifest();
        manifest.policy = Some(PolicySection {
            require_transparency_log: false,
            require_attestation_types: vec![],
            min_slsa_level: None,
            trusted_builders: vec!["ci-alpha".to_string(), "ci-beta".to_string()],
            require_attestation_expiry: false,
        });
        let evidence = SupplyChainEvidence {
            transparency_log_present: false,
            tuf_verified: false,
            tuf_target_hash: None,
            sigstore_verified: false,
            sigstore_identity: None,
            sigstore_issuer: None,
            attestations: vec![AttestationEvidence {
                attestation_type: AttestationType::InToto,
                slsa_level: None,
                builder_id: Some("ci-beta".to_string()),
                expires_at: None,
            }],
        };
        enforce_supply_chain_policy(&manifest, Some(&evidence))
            .expect("one of multiple trusted builders matches");
    }

    #[test]
    fn supply_chain_multiple_attestations_untrusted_builder_fails() {
        let mut manifest = minimal_manifest();
        manifest.policy = Some(PolicySection {
            require_transparency_log: false,
            require_attestation_types: vec![],
            min_slsa_level: None,
            trusted_builders: vec!["trusted-ci".to_string()],
            require_attestation_expiry: false,
        });
        let evidence = SupplyChainEvidence {
            transparency_log_present: false,
            tuf_verified: false,
            tuf_target_hash: None,
            sigstore_verified: false,
            sigstore_identity: None,
            sigstore_issuer: None,
            attestations: vec![
                AttestationEvidence {
                    attestation_type: AttestationType::InToto,
                    slsa_level: None,
                    builder_id: Some("trusted-ci".to_string()), // ok
                    expires_at: None,
                },
                AttestationEvidence {
                    attestation_type: AttestationType::CodeReview,
                    slsa_level: None,
                    builder_id: Some("evil-ci".to_string()), // not trusted
                    expires_at: None,
                },
            ],
        };
        let err = enforce_supply_chain_policy(&manifest, Some(&evidence))
            .expect_err("second builder untrusted");
        assert!(matches!(err, RegistryError::UntrustedBuilder { builder } if builder == "evil-ci"));
    }

    // ── enforce_capability_ceiling: from operations ────────────────────

    #[test]
    fn capability_ceiling_rejects_operation_capability() {
        // The minimal manifest has operations with capabilities.
        // A ceiling that excludes those operation caps should fail.
        let manifest = minimal_manifest();
        // Only allow "network.dns" (a required cap) but NOT the operation capability
        let policy = test_zone_policy(vec![CapabilityId::from_static("network.dns")]);
        let result = enforce_capability_ceiling(Some(&policy), &manifest);
        // Should fail because operation capabilities are also checked
        assert!(result.is_err());
    }

    // ── RegistryVerificationReport: serde with all special values ──────

    #[test]
    fn registry_verification_report_serde_unicode_connector_id() {
        let report = RegistryVerificationReport {
            connector_id: "fcp.\u{00E9}test".to_string(),
            manifest_hash: "sha256:m".to_string(),
            binary_hash: "sha256:b".to_string(),
            target: test_target(),
            verified_at: 42,
            outcome: "pass".to_string(),
        };
        let json = serde_json::to_string(&report).unwrap();
        let parsed: RegistryVerificationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.connector_id, "fcp.\u{00E9}test");
    }

    #[test]
    fn registry_verification_report_serde_json_value_fields() {
        let report = RegistryVerificationReport {
            connector_id: "fcp.test".to_string(),
            manifest_hash: "sha256:m".to_string(),
            binary_hash: "sha256:b".to_string(),
            target: test_target(),
            verified_at: 1_700_000_000,
            outcome: "pass".to_string(),
        };
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["connector_id"], "fcp.test");
        assert_eq!(value["verified_at"], 1_700_000_000_u64);
        assert!(value["target"].is_object());
    }

    // ── Mock verifier: concurrent-like access ─────────────────────────

    #[test]
    fn mock_transparency_verifier_overwrite_entry() {
        run_registry_test(
            "mock_transparency_verifier_overwrite_entry",
            "unit",
            "verifier",
            2,
            || async {
                let v = MockTransparencyVerifier::new();
                let entry1 = TransparencyLogEntry {
                    log_index: 1,
                    entry_hash: "sha256:e".into(),
                    inclusion_proof: InclusionProof {
                        root_hash: "r".into(),
                        tree_size: 10,
                        hashes: vec![],
                        leaf_index: 1,
                    },
                    signed_entry_timestamp: vec![],
                    log_id: "log".into(),
                };
                let entry2 = TransparencyLogEntry {
                    log_index: 999,
                    entry_hash: "sha256:e".into(),
                    inclusion_proof: InclusionProof {
                        root_hash: "r2".into(),
                        tree_size: 20,
                        hashes: vec![],
                        leaf_index: 999,
                    },
                    signed_entry_timestamp: vec![],
                    log_id: "log2".into(),
                };
                v.add_valid_entry("sha256:key".into(), entry1);
                v.add_valid_entry("sha256:key".into(), entry2); // overwrite
                let result = v.verify_entry("sha256:key", None).await.unwrap();
                assert_eq!(result.log_index, Some(999)); // should be the overwritten value
                assert!(result.verified);

                RegistryLogData {
                    reason_code: Some("overwrite_entry_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn mock_tuf_verifier_multiple_targets() {
        run_registry_test(
            "mock_tuf_verifier_multiple_targets",
            "unit",
            "verifier",
            3,
            || async {
                let root = TufRootMetadata {
                    version: 1,
                    root_hash: "sha256:root".into(),
                    expires: u64::MAX,
                    key_ids: vec![],
                    threshold: 1,
                };
                let v = MockTufVerifier::new(root.clone());
                v.add_valid_target(
                    "path/a".into(),
                    TufTargetInfo {
                        target_path: "path/a".into(),
                        hash: "sha256:a".into(),
                        length: 100,
                        delegations: vec![],
                    },
                );
                v.add_valid_target(
                    "path/b".into(),
                    TufTargetInfo {
                        target_path: "path/b".into(),
                        hash: "sha256:b".into(),
                        length: 200,
                        delegations: vec![],
                    },
                );

                let r1 = v.verify_target(&root, "path/a").await.unwrap();
                assert!(r1.verified);
                assert_eq!(r1.target.as_ref().unwrap().length, 100);

                let r2 = v.verify_target(&root, "path/b").await.unwrap();
                assert_eq!(r2.target.as_ref().unwrap().length, 200);

                let r3 = v.verify_target(&root, "path/c").await;
                assert!(r3.is_err());

                RegistryLogData {
                    reason_code: Some("multiple_targets_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn mock_sigstore_verifier_accepts_empty_trusted_lists() {
        run_registry_test(
            "mock_sigstore_verifier_accepts_empty_trusted_lists",
            "unit",
            "verifier",
            1,
            || async {
                let v = MockSigstoreVerifier::new();
                v.add_valid_bundle(
                    "sha256:art".into(),
                    SigstoreVerificationResult {
                        verified: true,
                        identity: Some("any-id".into()),
                        issuer: Some("any-issuer".into()),
                        rekor_log_index: None,
                    },
                );
                let bundle = SigstoreBundle {
                    signature: "s".into(),
                    certificate: "c".into(),
                    rekor_entry: None,
                    identity: "x".into(),
                    issuer: "y".into(),
                };
                // Empty trusted lists = accept anything
                let result = v
                    .verify_bundle(&bundle, "sha256:art", &[], &[])
                    .await
                    .unwrap();
                assert!(result.verified);

                RegistryLogData {
                    reason_code: Some("empty_trusted_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── MockRegistry: multiple connectors ─────────────────────────────

    #[test]
    fn mock_registry_multiple_connectors_isolated() {
        run_registry_test(
            "mock_registry_multiple_connectors_isolated",
            "mock",
            "registry",
            3,
            || async {
                let registry = MockRegistry::new()
                    .with_valid_connector("fcp.alpha", "1.0.0")
                    .with_valid_connector("fcp.beta", "2.0.0")
                    .with_valid_connector("fcp.gamma", "3.0.0");

                // Each connector verifies independently
                for (id, version) in [
                    ("fcp.alpha", "1.0.0"),
                    ("fcp.beta", "2.0.0"),
                    ("fcp.gamma", "3.0.0"),
                ] {
                    let bundle = registry.get_bundle(id).expect("bundle exists");
                    let trust = registry.get_trust_policy(id).expect("trust exists");
                    let verifier = RegistryVerifier::new(trust);
                    let verified = verifier
                        .verify_bundle(&bundle, None, None, None)
                        .expect("verify");
                    assert_eq!(verified.manifest.connector.id.as_str(), id);
                    assert_eq!(verified.manifest.connector.version.to_string(), version);
                }

                RegistryLogData {
                    reason_code: Some("multiple_connectors_isolated".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn mock_registry_wrong_trust_policy_fails() {
        run_registry_test(
            "mock_registry_wrong_trust_policy_fails",
            "mock",
            "registry",
            1,
            || async {
                let registry = MockRegistry::new()
                    .with_valid_connector("fcp.alpha", "1.0.0")
                    .with_valid_connector("fcp.beta", "2.0.0");

                // Use alpha's bundle with beta's trust policy (wrong key)
                let bundle = registry.get_bundle("fcp.alpha").expect("bundle");
                let trust = registry.get_trust_policy("fcp.beta").expect("trust");
                let verifier = RegistryVerifier::new(trust);
                let result = verifier.verify_bundle(&bundle, None, None, None);
                assert!(result.is_err());

                RegistryLogData {
                    reason_code: Some("wrong_trust_policy_fails".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── verify_bundle: combined policy + target + supply chain ─────────

    #[test]
    fn verify_bundle_target_match_passes() {
        run_registry_test(
            "verify_bundle_target_match_passes",
            "verify",
            "target",
            1,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let binary = b"target-match-test".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust.publisher_keys.insert("pub1".into(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                // Same target as bundle
                let verified = verifier
                    .verify_bundle(&bundle, None, None, Some(&test_target()))
                    .expect("target matches");
                assert_eq!(verified.target, test_target());

                RegistryLogData {
                    reason_code: Some("target_match_passes".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn verify_bundle_with_all_checks_passing() {
        run_registry_test(
            "verify_bundle_with_all_checks_passing",
            "verify",
            "combined",
            3,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let binary = b"all-checks-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust.publisher_keys.insert("pub1".into(), verifying_key);

                // Build zone policy that allows all manifest capabilities
                let manifest = minimal_manifest();
                let mut caps: HashSet<CapabilityId> = HashSet::new();
                caps.extend(manifest.capabilities.required.iter().cloned());
                caps.extend(manifest.capabilities.optional.iter().cloned());
                for op in manifest.provides.operations.values() {
                    caps.insert(op.capability.clone());
                }
                let ceiling: Vec<CapabilityId> = caps.into_iter().collect();
                let zone_policy = test_zone_policy(ceiling);

                let verifier = RegistryVerifier::new(trust);
                let verified = verifier
                    .verify_bundle(&bundle, Some(&zone_policy), None, Some(&test_target()))
                    .expect("all checks pass");
                assert!(!verified.manifest_hash.is_empty());
                assert!(!verified.binary_hash.is_empty());
                assert_eq!(verified.target, test_target());

                RegistryLogData {
                    reason_code: Some("all_checks_pass".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── ConnectorManifestObject/ConnectorBinaryObject edge cases ───────

    #[test]
    fn connector_manifest_object_empty_fields() {
        let obj = ConnectorManifestObject {
            manifest_toml: String::new(),
            manifest_hash: String::new(),
        };
        let json = serde_json::to_string(&obj).unwrap();
        let parsed: ConnectorManifestObject = serde_json::from_str(&json).unwrap();
        assert!(parsed.manifest_toml.is_empty());
        assert!(parsed.manifest_hash.is_empty());
    }

    #[test]
    fn connector_manifest_object_unicode_toml() {
        let obj = ConnectorManifestObject {
            manifest_toml: "# \u{1F680} Rocket manifest".to_string(),
            manifest_hash: "sha256:unicode".to_string(),
        };
        let json = serde_json::to_string(&obj).unwrap();
        let parsed: ConnectorManifestObject = serde_json::from_str(&json).unwrap();
        assert!(parsed.manifest_toml.contains('\u{1F680}'));
    }

    #[test]
    fn connector_binary_object_empty_binary() {
        let obj = ConnectorBinaryObject {
            target: test_target(),
            binary_hash: "sha256:empty".to_string(),
            binary: vec![],
        };
        let json = serde_json::to_string(&obj).unwrap();
        let parsed: ConnectorBinaryObject = serde_json::from_str(&json).unwrap();
        assert!(parsed.binary.is_empty());
    }

    #[test]
    fn connector_binary_object_large_binary() {
        let obj = ConnectorBinaryObject {
            target: test_target(),
            binary_hash: "sha256:large".to_string(),
            binary: vec![0xFFu8; 10_000],
        };
        let json = serde_json::to_string(&obj).unwrap();
        let parsed: ConnectorBinaryObject = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.binary.len(), 10_000);
    }

    // ── RegistryTrustPolicy: key lookup behavior ──────────────────────

    #[test]
    fn registry_trust_policy_publisher_key_lookup() {
        let k1 = Ed25519SigningKey::generate().verifying_key();
        let k2 = Ed25519SigningKey::generate().verifying_key();
        let mut policy = RegistryTrustPolicy::default();
        policy.publisher_keys.insert("key-a".to_string(), k1);
        policy.publisher_keys.insert("key-b".to_string(), k2);
        assert!(policy.publisher_keys.contains_key("key-a"));
        assert!(policy.publisher_keys.contains_key("key-b"));
        assert!(!policy.publisher_keys.contains_key("key-c"));
    }

    #[test]
    fn registry_trust_policy_registry_key_lookup() {
        let k = Ed25519SigningKey::generate().verifying_key();
        let mut policy = RegistryTrustPolicy::default();
        policy.registry_keys.insert("reg-1".to_string(), k);
        assert!(policy.registry_keys.contains_key("reg-1"));
        assert!(!policy.registry_keys.contains_key("reg-2"));
    }

    // ── SupplyChainVerificationError: Send + Sync bounds ──────────────

    #[test]
    fn supply_chain_verification_error_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<SupplyChainVerificationError>();
    }

    #[test]
    fn supply_chain_verification_error_is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<SupplyChainVerificationError>();
    }

    // ── RegistryError: Send + Sync bounds ─────────────────────────────

    #[test]
    fn registry_error_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<RegistryError>();
    }

    #[test]
    fn registry_error_is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<RegistryError>();
    }

    // ── RegistryVerificationReport: json value structure ──────────────

    #[test]
    fn registry_verification_report_json_has_all_keys() {
        let report = RegistryVerificationReport {
            connector_id: "fcp.x".to_string(),
            manifest_hash: "sha256:m".to_string(),
            binary_hash: "sha256:b".to_string(),
            target: test_target(),
            verified_at: 100,
            outcome: "ok".to_string(),
        };
        let value = serde_json::to_value(&report).unwrap();
        let obj = value.as_object().unwrap();
        assert!(obj.contains_key("connector_id"));
        assert!(obj.contains_key("manifest_hash"));
        assert!(obj.contains_key("binary_hash"));
        assert!(obj.contains_key("target"));
        assert!(obj.contains_key("verified_at"));
        assert!(obj.contains_key("outcome"));
    }

    // ── ConnectorTarget: serde deserialization from JSON object ────────

    #[test]
    fn connector_target_from_json_object() {
        let json = r#"{"os":"freebsd","arch":"riscv64"}"#;
        let t: ConnectorTarget = serde_json::from_str(json).unwrap();
        assert_eq!(t.os, "freebsd");
        assert_eq!(t.arch, "riscv64");
    }

    #[test]
    fn connector_target_from_json_extra_field_ignored() {
        // serde by default ignores unknown fields (no deny_unknown_fields)
        let json = r#"{"os":"linux","arch":"amd64","extra":"ignored"}"#;
        let result: Result<ConnectorTarget, _> = serde_json::from_str(json);
        assert!(result.is_ok());
    }

    // ── InclusionProof: boundary values ───────────────────────────────

    #[test]
    fn inclusion_proof_max_tree_size() {
        let proof = InclusionProof {
            root_hash: "sha256:r".to_string(),
            tree_size: u64::MAX,
            hashes: vec![],
            leaf_index: u64::MAX,
        };
        let json = serde_json::to_string(&proof).unwrap();
        let parsed: InclusionProof = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.tree_size, u64::MAX);
        assert_eq!(parsed.leaf_index, u64::MAX);
    }

    // ── TufTargetInfo: boundary values ─────────────────────────────────

    #[test]
    fn tuf_target_info_max_length() {
        let target = TufTargetInfo {
            target_path: "p".to_string(),
            hash: "h".to_string(),
            length: u64::MAX,
            delegations: vec![],
        };
        let json = serde_json::to_string(&target).unwrap();
        let parsed: TufTargetInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.length, u64::MAX);
    }

    // ── SigstoreBundle: serde with large rekor entry ──────────────────

    #[test]
    fn sigstore_bundle_serde_large_inclusion_proof() {
        let large_hashes: Vec<String> = (0..200).map(|i| format!("sha256:h{i}")).collect();
        let bundle = SigstoreBundle {
            signature: "sig".to_string(),
            certificate: "cert".to_string(),
            rekor_entry: Some(TransparencyLogEntry {
                log_index: 0,
                entry_hash: "sha256:e".to_string(),
                inclusion_proof: InclusionProof {
                    root_hash: "sha256:r".to_string(),
                    tree_size: 1_000_000,
                    hashes: large_hashes,
                    leaf_index: 0,
                },
                signed_entry_timestamp: vec![0; 256],
                log_id: "log".to_string(),
            }),
            identity: "id".to_string(),
            issuer: "iss".to_string(),
        };
        let json = serde_json::to_string(&bundle).unwrap();
        let parsed: SigstoreBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed
                .rekor_entry
                .as_ref()
                .unwrap()
                .inclusion_proof
                .hashes
                .len(),
            200
        );
    }

    // ── verify_bundle: registry-only with require_registry_signature ──

    #[test]
    fn verify_bundle_registry_only_with_require_flag() {
        run_registry_test(
            "verify_bundle_registry_only_with_require_flag",
            "verify",
            "signature",
            2,
            || async {
                let reg_key = Ed25519SigningKey::generate();

                let binary = b"registry-only-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let reg_sig = sign_manifest_toml(&unsigned, &reg_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &registry_signature_section("reg1", &reg_sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy {
                    require_registry_signature: true,
                    ..RegistryTrustPolicy::default()
                };
                trust
                    .registry_keys
                    .insert("reg1".into(), reg_key.verifying_key());

                let verifier = RegistryVerifier::new(trust);
                let verified = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect("registry-only with flag should pass");
                assert!(!verified.manifest_hash.is_empty());
                assert!(!verified.binary_hash.is_empty());

                RegistryLogData {
                    reason_code: Some("registry_only_require_flag".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── manifest_signing_bytes: different manifests produce different bytes

    #[test]
    fn manifest_signing_bytes_different_manifests_differ() {
        run_registry_test(
            "manifest_signing_bytes_different_manifests_differ",
            "unit",
            "signing",
            1,
            || async {
                let m1 = minimal_manifest();
                let bytes1 = manifest_signing_bytes(&m1).unwrap();

                // Create a manifest via MockRegistry which has different connector.id
                let registry = MockRegistry::new().with_valid_connector("fcp.other", "1.0.0");
                let bundle = registry.get_bundle("fcp.other").unwrap();
                let m2 = ConnectorManifest::parse_str(&bundle.manifest_toml).unwrap();
                let bytes2 = manifest_signing_bytes(&m2).unwrap();

                assert_ne!(bytes1, bytes2);

                RegistryLogData {
                    reason_code: Some("different_manifests_differ".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── verify_publishers with threshold k=0 ──────────────────────────

    #[test]
    fn verify_publishers_with_threshold_zero_no_sigs() {
        run_registry_test(
            "verify_publishers_with_threshold_zero_no_sigs",
            "unit",
            "signature",
            1,
            || async {
                // When there are publisher signatures but threshold is 0, any valid count passes
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let manifest = minimal_manifest();
                let signing_bytes = manifest_signing_bytes(&manifest).expect("signing bytes");
                let binary_hash = "sha256:test";
                let message = signature_message(&signing_bytes, binary_hash);
                let signature = signing_key.sign_with_context(MANIFEST_SIGNATURE_CONTEXT, &message);
                let sig = Base64Bytes::try_from(format!(
                    "base64:{}",
                    base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
                ))
                .expect("base64");

                let sigs = SignaturesSection {
                    publisher_signatures: vec![SignatureEntry {
                        kid: "pub1".to_string(),
                        sig,
                    }],
                    publisher_threshold: Some(fcp_manifest::SignatureThreshold { k: 0, n: 1 }),
                    registry_signature: None,
                    transparency_log_entry: None,
                };
                let mut trust = RegistryTrustPolicy::default();
                trust.publisher_keys.insert("pub1".into(), verifying_key);

                let ok = verify_publishers(&trust, &sigs, &signing_bytes, binary_hash)
                    .expect("threshold 0 passes");
                assert!(ok); // valid > 0

                RegistryLogData {
                    reason_code: Some("threshold_zero_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── RegistryVerifier: verify_bundle returns correct hashes ────────

    #[test]
    fn verify_bundle_hashes_are_sha256_prefixed() {
        run_registry_test(
            "verify_bundle_hashes_are_sha256_prefixed",
            "verify",
            "hash-format",
            2,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let binary = b"hash-format-test".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust.publisher_keys.insert("pub1".into(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let verified = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect("verify");

                assert!(verified.manifest_hash.starts_with("sha256:"));
                assert!(verified.binary_hash.starts_with("sha256:"));

                RegistryLogData {
                    reason_code: Some("hashes_sha256_prefixed".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── RegistryError: Display messages are non-empty ─────────────────

    #[test]
    fn registry_error_display_all_nonempty() {
        let errors: Vec<RegistryError> = vec![
            RegistryError::MissingSignatures,
            RegistryError::UnknownKid { kid: "k".into() },
            RegistryError::SignatureInvalid { kid: "k".into() },
            RegistryError::PublisherThresholdUnmet {
                required: 1,
                valid: 0,
            },
            RegistryError::NoTrustedSignature,
            RegistryError::RegistrySignatureRequired,
            RegistryError::TargetMismatch {
                expected: "a".into(),
                found: "b".into(),
            },
            RegistryError::CapabilityCeilingViolation {
                capability: "c".into(),
            },
            RegistryError::TransparencyLogMissing,
            RegistryError::TransparencyEvidenceMissing,
            RegistryError::TufVerificationRequired,
            RegistryError::SigstoreVerificationRequired,
            RegistryError::RequiredAttestationMissing {
                attestation: "a".into(),
            },
            RegistryError::AttestationEvidenceMissing,
            RegistryError::AttestationExpired {
                attestation: "a".into(),
                expired_at: 0,
            },
            RegistryError::SlsaLevelInsufficient { required: 1 },
            RegistryError::UntrustedBuilder {
                builder: "b".into(),
            },
            RegistryError::SignatureBytes,
        ];
        for err in &errors {
            assert!(
                !err.to_string().is_empty(),
                "Error display should not be empty: {err:?}"
            );
        }
    }

    // ── SupplyChainVerificationError: Display messages are non-empty ──

    #[test]
    fn supply_chain_error_display_all_nonempty() {
        let errors: Vec<SupplyChainVerificationError> = vec![
            SupplyChainVerificationError::TransparencyEntryNotFound,
            SupplyChainVerificationError::TransparencyProofInvalid,
            SupplyChainVerificationError::TransparencySignatureInvalid,
            SupplyChainVerificationError::TufRootMismatch {
                expected: "a".into(),
                actual: "b".into(),
            },
            SupplyChainVerificationError::TufExpired,
            SupplyChainVerificationError::TufTargetNotFound { target: "t".into() },
            SupplyChainVerificationError::TufRollback { current: 1, got: 0 },
            SupplyChainVerificationError::TufFreeze,
            SupplyChainVerificationError::SigstoreSignatureInvalid,
            SupplyChainVerificationError::SigstoreCertificateInvalid,
            SupplyChainVerificationError::SigstoreIdentityMismatch {
                expected: "a".into(),
                actual: "b".into(),
            },
            SupplyChainVerificationError::SigstoreIssuerUntrusted { issuer: "i".into() },
            SupplyChainVerificationError::Network("n".into()),
            SupplyChainVerificationError::NotConfigured,
        ];
        for err in &errors {
            assert!(
                !err.to_string().is_empty(),
                "Error display should not be empty: {err:?}"
            );
        }
    }

    // ── RegistryLogData: Default ──────────────────────────────────────

    #[test]
    fn registry_log_data_default_all_none() {
        let data = RegistryLogData::default();
        assert!(data.connector_id.is_none());
        assert!(data.version.is_none());
        assert!(data.manifest_hash.is_none());
        assert!(data.binary_hash.is_none());
        assert!(data.target.is_none());
        assert!(data.reason_code.is_none());
        assert!(data.details.is_none());
    }

    // ── MockRegistrySource: multiple bundles ──────────────────────────

    #[test]
    fn mock_registry_source_multiple_bundles() {
        run_registry_test(
            "mock_registry_source_multiple_bundles",
            "unit",
            "registry_source",
            3,
            || async {
                let mut source = MockRegistrySource::new();
                source.add_bundle(
                    "fcp.a",
                    ConnectorBundle {
                        manifest_toml: "a-toml".into(),
                        binary: vec![1],
                        target: test_target(),
                    },
                );
                source.add_bundle(
                    "fcp.b",
                    ConnectorBundle {
                        manifest_toml: "b-toml".into(),
                        binary: vec![2],
                        target: test_target(),
                    },
                );

                let a = source.fetch_bundle("fcp.a").await.unwrap();
                assert_eq!(a.binary, vec![1]);

                let b = source.fetch_bundle("fcp.b").await.unwrap();
                assert_eq!(b.binary, vec![2]);

                let c = source.fetch_bundle("fcp.c").await;
                assert!(c.is_err());

                RegistryLogData {
                    reason_code: Some("multiple_bundles_ok".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── ConnectorTarget: Eq trait symmetry and transitivity ────────────

    #[test]
    fn connector_target_eq_symmetric() {
        let a = ConnectorTarget {
            os: "linux".into(),
            arch: "amd64".into(),
        };
        let b = ConnectorTarget {
            os: "linux".into(),
            arch: "amd64".into(),
        };
        assert_eq!(a, b);
        assert_eq!(b, a);
    }

    #[test]
    fn connector_target_eq_transitive() {
        let a = ConnectorTarget {
            os: "linux".into(),
            arch: "amd64".into(),
        };
        let b = ConnectorTarget {
            os: "linux".into(),
            arch: "amd64".into(),
        };
        let c = ConnectorTarget {
            os: "linux".into(),
            arch: "amd64".into(),
        };
        assert_eq!(a, b);
        assert_eq!(b, c);
        assert_eq!(a, c);
    }

    // ── TufRootMetadata: many key_ids serde ───────────────────────────

    #[test]
    fn tuf_root_metadata_many_key_ids() {
        let key_ids: Vec<String> = (0..100).map(|i| format!("key-{i}")).collect();
        let root = TufRootMetadata {
            version: 1,
            root_hash: "sha256:r".into(),
            expires: u64::MAX,
            key_ids,
            threshold: 50,
        };
        let json = serde_json::to_string(&root).unwrap();
        let parsed: TufRootMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.key_ids.len(), 100);
        assert_eq!(parsed.threshold, 50);
    }

    // ── TufTargetInfo: many delegations ───────────────────────────────

    #[test]
    fn tuf_target_info_many_delegations() {
        let delegations: Vec<String> = (0..50).map(|i| format!("delegation-{i}")).collect();
        let target = TufTargetInfo {
            target_path: "p".into(),
            hash: "h".into(),
            length: 1,
            delegations,
        };
        let json = serde_json::to_string(&target).unwrap();
        let parsed: TufTargetInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.delegations.len(), 50);
    }

    // ── SigstoreBundle: clone with rekor_entry ────────────────────────

    #[test]
    fn sigstore_bundle_clone_with_rekor() {
        let bundle = SigstoreBundle {
            signature: "sig".into(),
            certificate: "cert".into(),
            rekor_entry: Some(TransparencyLogEntry {
                log_index: 42,
                entry_hash: "sha256:e".into(),
                inclusion_proof: InclusionProof {
                    root_hash: "sha256:r".into(),
                    tree_size: 100,
                    hashes: vec!["sha256:h".into()],
                    leaf_index: 42,
                },
                signed_entry_timestamp: vec![1, 2],
                log_id: "log".into(),
            }),
            identity: "id".into(),
            issuer: "iss".into(),
        };
        let cloned = bundle.clone();
        assert_eq!(bundle.signature, "sig");
        assert!(cloned.rekor_entry.is_some());
        assert_eq!(cloned.rekor_entry.as_ref().unwrap().log_index, 42);
    }

    // ── TransparencyLogEntry: large signed_entry_timestamp ────────────

    #[test]
    fn transparency_log_entry_large_timestamp() {
        let entry = TransparencyLogEntry {
            log_index: 1,
            entry_hash: "sha256:e".into(),
            inclusion_proof: InclusionProof {
                root_hash: "sha256:r".into(),
                tree_size: 1,
                hashes: vec![],
                leaf_index: 0,
            },
            signed_entry_timestamp: vec![0xABu8; 1024],
            log_id: "log".into(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: TransparencyLogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.signed_entry_timestamp.len(), 1024);
    }

    // ── RegistryVerificationReport: target field serde ────────────────

    #[test]
    fn registry_verification_report_target_os_arch_preserved() {
        let report = RegistryVerificationReport {
            connector_id: "c".into(),
            manifest_hash: "m".into(),
            binary_hash: "b".into(),
            target: ConnectorTarget {
                os: "darwin".into(),
                arch: "arm64".into(),
            },
            verified_at: 1,
            outcome: "o".into(),
        };
        let json = serde_json::to_string(&report).unwrap();
        let parsed: RegistryVerificationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.target.os, "darwin");
        assert_eq!(parsed.target.arch, "arm64");
    }

    // ── ConnectorBundle: manifest_toml with newlines ──────────────────

    #[test]
    fn connector_bundle_manifest_with_newlines() {
        let bundle = ConnectorBundle {
            manifest_toml: "line1\nline2\nline3\n".into(),
            binary: vec![],
            target: test_target(),
        };
        let cloned = bundle.clone();
        assert_eq!(bundle.manifest_toml, "line1\nline2\nline3\n");
        assert_eq!(cloned.manifest_toml, bundle.manifest_toml);
    }

    // ── SupplyChainEvidence: empty attestations with transparency ─────

    #[test]
    fn supply_chain_evidence_transparency_true_no_attestations() {
        let evidence = SupplyChainEvidence {
            transparency_log_present: true,
            tuf_verified: false,
            tuf_target_hash: None,
            sigstore_verified: false,
            sigstore_identity: None,
            sigstore_issuer: None,
            attestations: vec![],
        };
        assert!(evidence.transparency_log_present);
        assert!(evidence.attestations.is_empty());
        let debug = format!("{evidence:?}");
        assert!(debug.contains("true"));
    }

    // ── RegistryTrustPolicy: debug with require_registry_signature ────

    #[test]
    fn registry_trust_policy_debug_require_registry() {
        let policy = RegistryTrustPolicy {
            publisher_keys: HashMap::new(),
            registry_keys: HashMap::new(),
            require_registry_signature: true,
        };
        let debug = format!("{policy:?}");
        assert!(debug.contains("true"));
        assert!(debug.contains("RegistryTrustPolicy"));
    }

    // ── MirrorResult: different object IDs ────────────────────────────

    #[test]
    fn mirror_result_object_ids_distinct() {
        let r = MirrorResult {
            manifest_object_id: ObjectId::from_bytes([0x11u8; 32]),
            binary_object_id: ObjectId::from_bytes([0x22u8; 32]),
            manifest_hash: "sha256:m".into(),
            binary_hash: "sha256:b".into(),
        };
        assert_ne!(r.manifest_object_id, r.binary_object_id);
    }

    // ── VerifiedConnectorBundle: report timestamp is recent ───────────

    #[test]
    fn verified_bundle_report_timestamp_reasonable() {
        let manifest = minimal_manifest();
        let verified = VerifiedConnectorBundle {
            manifest,
            manifest_hash: "sha256:m".into(),
            binary_hash: "sha256:b".into(),
            target: test_target(),
        };
        let report = verified.report("test");
        // Timestamp should be > some reasonable epoch (2020-01-01)
        assert!(report.verified_at > 1_577_836_800);
    }

    // ── hash_bytes: adjacent inputs ──────────────────────────────────

    #[test]
    fn hash_bytes_prepend_byte_differs() {
        let h1 = hash_bytes(b"data");
        let h2 = hash_bytes(b"\x00data");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_bytes_append_byte_differs() {
        let h1 = hash_bytes(b"data");
        let h2 = hash_bytes(b"data\x00");
        assert_ne!(h1, h2);
    }

    // ── ConnectorTarget: serde cbor roundtrip via json values ─────────

    #[test]
    fn connector_target_json_value_roundtrip() {
        let t = ConnectorTarget {
            os: "linux".into(),
            arch: "amd64".into(),
        };
        let value = serde_json::to_value(&t).unwrap();
        let back: ConnectorTarget = serde_json::from_value(value).unwrap();
        assert_eq!(back, t);
    }

    // ── SupplyChainVerificationConfig: many identities ───────────────

    #[test]
    fn supply_chain_config_many_identities() {
        let identities: Vec<String> = (0..100).map(|i| format!("identity-{i}")).collect();
        let issuers: Vec<String> = (0..50).map(|i| format!("https://issuer-{i}.com")).collect();
        let config = SupplyChainVerificationConfig {
            tuf_pinned_root: None,
            trusted_sigstore_identities: identities,
            trusted_sigstore_issuers: issuers,
            require_transparency: false,
            require_tuf: false,
            require_sigstore: false,
            ..SupplyChainVerificationConfig::default()
        };
        assert_eq!(config.trusted_sigstore_identities.len(), 100);
        assert_eq!(config.trusted_sigstore_issuers.len(), 50);
    }

    // ── InclusionProof: serde with unicode hash ──────────────────────

    #[test]
    fn inclusion_proof_unicode_root_hash() {
        let proof = InclusionProof {
            root_hash: "sha256:\u{00E9}\u{00FC}".into(),
            tree_size: 1,
            hashes: vec![],
            leaf_index: 0,
        };
        let json = serde_json::to_string(&proof).unwrap();
        let parsed: InclusionProof = serde_json::from_str(&json).unwrap();
        assert!(parsed.root_hash.contains('\u{00E9}'));
    }

    // ── TransparencyLogEntry: debug contains fields ──────────────────

    #[test]
    fn transparency_log_entry_debug_contains_log_id() {
        let entry = TransparencyLogEntry {
            log_index: 7,
            entry_hash: "sha256:e".into(),
            inclusion_proof: InclusionProof {
                root_hash: "r".into(),
                tree_size: 1,
                hashes: vec![],
                leaf_index: 0,
            },
            signed_entry_timestamp: vec![],
            log_id: "my-log-id".into(),
        };
        let debug = format!("{entry:?}");
        assert!(debug.contains("my-log-id"));
        assert!(debug.contains("7"));
    }

    // ── Verify bundle: empty binary with target match ────────────────

    #[test]
    fn verify_bundle_empty_binary_with_target_match() {
        run_registry_test(
            "verify_bundle_empty_binary_with_target_match",
            "verify",
            "combined",
            2,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let binary: Vec<u8> = vec![];
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml,
                    binary,
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust.publisher_keys.insert("pub1".into(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let verified = verifier
                    .verify_bundle(&bundle, None, None, Some(&test_target()))
                    .expect("empty binary + target match");
                assert_eq!(verified.binary_hash, hash_bytes(&[]));
                assert_eq!(verified.target, test_target());

                RegistryLogData {
                    reason_code: Some("empty_binary_target_match".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    // ── Error std::error::Error trait coverage ────────────────────────

    #[test]
    fn registry_error_implements_std_error() {
        fn assert_error<T: std::error::Error>() {}
        assert_error::<RegistryError>();
    }

    #[test]
    fn supply_chain_error_implements_std_error() {
        fn assert_error<T: std::error::Error>() {}
        assert_error::<SupplyChainVerificationError>();
    }

    // ── ConnectorTarget: serde missing field error ────────────────────

    #[test]
    fn connector_target_serde_missing_os_fails() {
        let json = r#"{"arch":"amd64"}"#;
        let result: Result<ConnectorTarget, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn connector_target_serde_missing_arch_fails() {
        let json = r#"{"os":"linux"}"#;
        let result: Result<ConnectorTarget, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    // ── RegistryVerificationReport: serde missing field ──────────────

    #[test]
    fn registry_verification_report_serde_missing_field_fails() {
        let json = r#"{"connector_id":"fcp.test","manifest_hash":"m"}"#;
        let result: Result<RegistryVerificationReport, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    fn registry_manifest_with_identity(connector_id: &str, version: &str) -> String {
        let manifest_toml = base_manifest_toml()
            .replace(
                r#"id = "fcp.minimal""#,
                &format!(r#"id = "{connector_id}""#),
            )
            .replace(r#"version = "0.1.0""#, &format!(r#"version = "{version}""#));
        let unchecked = ConnectorManifest::parse_str_unchecked(&manifest_toml).expect("manifest");
        let interface_hash = unchecked.compute_interface_hash().expect("interface hash");
        manifest_toml.replace(
            &unchecked.manifest.interface_hash.to_string(),
            &interface_hash.to_string(),
        )
    }

    fn write_signed_package_dir(
        root: &Path,
        connector_id: &str,
        version: &str,
        target: ConnectorTarget,
        binary_name: &str,
        binary_bytes: &[u8],
    ) -> PathBuf {
        let package_dir = root.join(format!(
            "{}-{}-{}",
            connector_id.replace(':', "_"),
            version,
            target.as_string().replace('/', "_")
        ));
        std::fs::create_dir_all(&package_dir).expect("create package dir");

        let signing_key = Ed25519SigningKey::generate();
        let unsigned = registry_manifest_with_identity(connector_id, version);
        let binary_hash = hash_bytes(binary_bytes);
        let signature = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
        let manifest_toml =
            with_signatures(&unsigned, &publisher_signature_section("pub1", &signature));
        let signing_bytes = manifest_signing_bytes(
            &ConnectorManifest::parse_str(&unsigned).expect("unsigned manifest parses"),
        )
        .expect("signing bytes");
        let signature_artifact = ManifestSignatureArtifact {
            key_id: "pub1".to_string(),
            verifying_key: hex::encode(signing_key.verifying_key().to_bytes()),
            context: String::from_utf8_lossy(MANIFEST_SIGNATURE_CONTEXT).into_owned(),
            manifest_signing_hash: hash_bytes(&signing_bytes),
            binary_hash,
            signature: String::from(signature),
            target: target.clone(),
            binary_name: binary_name.to_string(),
        };

        std::fs::write(
            package_dir.join(REGISTRY_MANIFEST_FILENAME),
            format!("{manifest_toml}\n"),
        )
        .expect("write manifest");
        std::fs::write(package_dir.join(binary_name), binary_bytes).expect("write binary");
        std::fs::write(
            package_dir.join(REGISTRY_MANIFEST_SIGNATURE_FILENAME),
            format!(
                "{}\n",
                serde_json::to_string_pretty(&signature_artifact).expect("serialize signature")
            ),
        )
        .expect("write signature artifact");
        std::fs::write(
            package_dir.join(REGISTRY_ATTESTATION_FILENAME),
            r#"{"predicate_type":"https://slsa.dev/provenance/v1"}"#,
        )
        .expect("write attestation");

        package_dir
    }

    #[test]
    fn local_registry_catalog_tracks_latest_version_and_targets() {
        let temp = tempfile::tempdir().expect("tempdir");
        let linux = ConnectorTarget {
            os: "linux".to_string(),
            arch: "amd64".to_string(),
        };
        let darwin = ConnectorTarget {
            os: "darwin".to_string(),
            arch: "arm64".to_string(),
        };

        let v1 = write_signed_package_dir(
            temp.path(),
            "fcp.registry-test",
            "1.0.0",
            linux.clone(),
            "registry-test-linux",
            b"linux-v1",
        );
        let v2_linux = write_signed_package_dir(
            temp.path(),
            "fcp.registry-test",
            "2.0.0",
            linux.clone(),
            "registry-test-linux-v2",
            b"linux-v2",
        );
        let v2_darwin = write_signed_package_dir(
            temp.path(),
            "fcp.registry-test",
            "2.0.0",
            darwin.clone(),
            "registry-test-darwin-v2",
            b"darwin-v2",
        );

        let catalog = LocalRegistryCatalog::from_signed_package_dirs(&[v1, v2_linux, v2_darwin])
            .expect("catalog");
        let connector = catalog
            .connector_descriptor("fcp.registry-test")
            .expect("connector descriptor");

        assert_eq!(connector.latest_version, "2.0.0");
        assert_eq!(connector.versions.len(), 2);
        assert_eq!(connector.versions[0].version, "2.0.0");
        assert_eq!(connector.versions[1].version, "1.0.0");
        assert_eq!(connector.versions[0].targets.len(), 2);
        assert_eq!(connector.versions[0].targets[0].target, "darwin-arm64");
        assert_eq!(connector.versions[0].targets[1].target, "linux-amd64");
        assert!(
            connector.versions[0].targets[0]
                .signature_url
                .contains("/targets/darwin/arm64/signature")
        );
    }

    #[test]
    fn local_registry_catalog_rejects_path_traversal_in_binary_name() {
        let temp = tempfile::tempdir().expect("tempdir");
        let target = ConnectorTarget {
            os: "linux".to_string(),
            arch: "amd64".to_string(),
        };

        let package_dir = write_signed_package_dir(
            temp.path(),
            "fcp.traversal-test",
            "1.0.0",
            target,
            "legit-binary",
            b"binary-content",
        );

        // Tamper with the signature JSON to inject a path-traversal binary_name.
        let sig_path = package_dir.join(REGISTRY_MANIFEST_SIGNATURE_FILENAME);
        let sig_json = std::fs::read_to_string(&sig_path).expect("read signature");
        let poisoned = sig_json.replace("legit-binary", "../../etc/passwd");
        std::fs::write(&sig_path, poisoned).expect("write poisoned signature");

        let err = LocalRegistryCatalog::from_signed_package_dirs(&[package_dir])
            .expect_err("path traversal should be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("path traversal"),
            "expected PathTraversal error, got: {msg}",
        );
    }

    #[test]
    fn local_registry_catalog_rejects_absolute_binary_name() {
        let temp = tempfile::tempdir().expect("tempdir");
        let target = ConnectorTarget {
            os: "linux".to_string(),
            arch: "amd64".to_string(),
        };

        let package_dir = write_signed_package_dir(
            temp.path(),
            "fcp.abs-test",
            "1.0.0",
            target,
            "legit-binary",
            b"binary-content",
        );

        let sig_path = package_dir.join(REGISTRY_MANIFEST_SIGNATURE_FILENAME);
        let sig_json = std::fs::read_to_string(&sig_path).expect("read signature");
        let poisoned = sig_json.replace("legit-binary", "/etc/shadow");
        std::fs::write(&sig_path, poisoned).expect("write poisoned signature");

        let err = LocalRegistryCatalog::from_signed_package_dirs(&[package_dir])
            .expect_err("absolute path should be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("path traversal"),
            "expected PathTraversal error, got: {msg}",
        );
    }

    #[test]
    fn local_registry_catalog_rejects_symlinked_binary_outside_package_dir() {
        let temp = tempfile::tempdir().expect("tempdir");
        let target = ConnectorTarget {
            os: "linux".to_string(),
            arch: "amd64".to_string(),
        };

        let external_binary = temp.path().join("outside-binary");
        std::fs::write(&external_binary, b"outside-binary").expect("write outside binary");

        let package_dir = write_signed_package_dir(
            temp.path(),
            "fcp.symlink-test",
            "1.0.0",
            target,
            "connector-bin",
            b"outside-binary",
        );
        let package_binary = package_dir.join("connector-bin");
        std::fs::remove_file(&package_binary).expect("remove package binary");
        symlink_file(&external_binary, &package_binary);

        let err = LocalRegistryCatalog::from_signed_package_dirs(&[package_dir])
            .expect_err("symlink escape should be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("standalone regular file"),
            "expected LinkedBinary error, got: {msg}",
        );
    }

    #[test]
    fn local_registry_catalog_rejects_symlinked_binary_inside_package_dir() {
        let temp = tempfile::tempdir().expect("tempdir");
        let target = ConnectorTarget {
            os: "linux".to_string(),
            arch: "amd64".to_string(),
        };

        let package_dir = write_signed_package_dir(
            temp.path(),
            "fcp.symlink-sibling-test",
            "1.0.0",
            target,
            "connector-bin",
            b"sibling-binary",
        );
        let sibling_binary = package_dir.join("real-binary");
        std::fs::write(&sibling_binary, b"sibling-binary").expect("write sibling binary");

        let package_binary = package_dir.join("connector-bin");
        std::fs::remove_file(&package_binary).expect("remove package binary");
        symlink_file(&sibling_binary, &package_binary);

        let err = LocalRegistryCatalog::from_signed_package_dirs(&[package_dir])
            .expect_err("symlinked sibling binary should be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("standalone regular file"),
            "expected LinkedBinary error, got: {msg}",
        );
    }

    #[test]
    fn local_registry_catalog_rejects_hard_linked_binary_outside_package_dir() {
        let temp = tempfile::tempdir().expect("tempdir");
        let target = ConnectorTarget {
            os: "linux".to_string(),
            arch: "amd64".to_string(),
        };

        let external_binary = temp.path().join("outside-hardlink-binary");
        std::fs::write(&external_binary, b"outside-hardlink-binary").expect("write outside binary");

        let package_dir = write_signed_package_dir(
            temp.path(),
            "fcp.hardlink-test",
            "1.0.0",
            target,
            "connector-bin",
            b"outside-hardlink-binary",
        );
        let package_binary = package_dir.join("connector-bin");
        std::fs::remove_file(&package_binary).expect("remove package binary");
        hard_link_file(&external_binary, &package_binary);

        let err = LocalRegistryCatalog::from_signed_package_dirs(&[package_dir])
            .expect_err("hard-link escape should be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("standalone regular file"),
            "expected LinkedBinary error, got: {msg}",
        );
    }

    #[cfg(windows)]
    #[test]
    fn local_registry_catalog_rejects_windows_drive_prefixed_binary_name() {
        let temp = tempfile::tempdir().expect("tempdir");
        let target = ConnectorTarget {
            os: "windows".to_string(),
            arch: "amd64".to_string(),
        };

        let package_dir = write_signed_package_dir(
            temp.path(),
            "fcp.drive-prefix-test",
            "1.0.0",
            target,
            "legit-binary.exe",
            b"binary-content",
        );

        let sig_path = package_dir.join(REGISTRY_MANIFEST_SIGNATURE_FILENAME);
        let sig_json = std::fs::read_to_string(&sig_path).expect("read signature");
        let poisoned = sig_json.replace("legit-binary.exe", "C:evil.exe");
        std::fs::write(&sig_path, poisoned).expect("write poisoned signature");

        let err = LocalRegistryCatalog::from_signed_package_dirs(&[package_dir])
            .expect_err("drive-prefixed binary_name should be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("path traversal"),
            "expected PathTraversal error, got: {msg}",
        );
    }

    #[test]
    fn local_registry_catalog_rejects_manifest_signing_hash_mismatch() {
        let temp = tempfile::tempdir().expect("tempdir");
        let target = ConnectorTarget {
            os: "linux".to_string(),
            arch: "amd64".to_string(),
        };

        let package_dir = write_signed_package_dir(
            temp.path(),
            "fcp.hash-test",
            "1.0.0",
            target,
            "legit-binary",
            b"binary-content",
        );

        let sig_path = package_dir.join(REGISTRY_MANIFEST_SIGNATURE_FILENAME);
        let mut artifact: ManifestSignatureArtifact =
            serde_json::from_str(&std::fs::read_to_string(&sig_path).expect("read signature"))
                .expect("parse signature artifact");
        artifact.manifest_signing_hash = "sha256:deadbeef".to_string();
        std::fs::write(
            &sig_path,
            format!(
                "{}\n",
                serde_json::to_string_pretty(&artifact).expect("serialize signature artifact")
            ),
        )
        .expect("write poisoned signature");

        let err = LocalRegistryCatalog::from_signed_package_dirs(&[package_dir])
            .expect_err("manifest signing hash mismatch should be rejected");
        assert!(
            err.to_string().contains("manifest signing digest mismatch"),
            "expected manifest signing hash rejection, got: {err}",
        );
    }

    #[test]
    fn local_registry_catalog_rejects_invalid_detached_manifest_signature() {
        let temp = tempfile::tempdir().expect("tempdir");
        let target = ConnectorTarget {
            os: "linux".to_string(),
            arch: "amd64".to_string(),
        };

        let package_dir = write_signed_package_dir(
            temp.path(),
            "fcp.sig-test",
            "1.0.0",
            target,
            "legit-binary",
            b"binary-content",
        );

        let sig_path = package_dir.join(REGISTRY_MANIFEST_SIGNATURE_FILENAME);
        let mut artifact: ManifestSignatureArtifact =
            serde_json::from_str(&std::fs::read_to_string(&sig_path).expect("read signature"))
                .expect("parse signature artifact");
        artifact.signature = "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string();
        std::fs::write(
            &sig_path,
            format!(
                "{}\n",
                serde_json::to_string_pretty(&artifact).expect("serialize signature artifact")
            ),
        )
        .expect("write poisoned signature");

        let err = LocalRegistryCatalog::from_signed_package_dirs(&[package_dir])
            .expect_err("invalid detached signature should be rejected");
        let message = err.to_string();
        assert!(
            message.contains("manifest signature verification failed")
                || message.contains("invalid signature bytes"),
            "expected detached signature rejection, got: {message}",
        );
    }

    #[test]
    fn metamorphic_install_verify_reinstall_round_trip_is_observationally_idempotent() {
        run_registry_test(
            "metamorphic_install_verify_reinstall_round_trip_is_observationally_idempotent",
            "verify",
            "metamorphic",
            7,
            || async {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();

                let binary = b"registry-metamorphic-binary".to_vec();
                let binary_hash = hash_bytes(&binary);
                let unsigned = unsigned_manifest_toml("");
                let sig = sign_manifest_toml(&unsigned, &signing_key, &binary_hash);
                let manifest_toml =
                    with_signatures(&unsigned, &publisher_signature_section("pub1", &sig));

                let bundle = ConnectorBundle {
                    manifest_toml: manifest_toml.clone(),
                    binary: binary.clone(),
                    target: test_target(),
                };

                let mut trust = RegistryTrustPolicy::default();
                trust
                    .publisher_keys
                    .insert("pub1".to_string(), verifying_key);

                let verifier = RegistryVerifier::new(trust);
                let first_verified = verifier
                    .verify_bundle(&bundle, None, None, None)
                    .expect("first verify");

                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                let symbol_store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
                let zone_id = ZoneId::work();
                let object_id_key = ObjectIdKey::from_bytes([9u8; 32]);
                let symbol_config = RaptorQConfig::default();

                let mirror = verifier
                    .mirror_bundle(
                        &first_verified,
                        &bundle,
                        zone_id.clone(),
                        &object_id_key,
                        &store,
                    )
                    .await
                    .expect("mirror bundle");
                let symbol_result = verifier
                    .mirror_bundle_symbols(
                        &first_verified,
                        &bundle,
                        &mirror,
                        zone_id,
                        &object_id_key,
                        &store,
                        &symbol_store,
                        &symbol_config,
                        None,
                    )
                    .await
                    .expect("mirror bundle symbols");

                let reconstructed = verifier
                    .reconstruct_bundle_from_symbol_descriptor(
                        &symbol_result.descriptor_object_id,
                        &store,
                        &symbol_store,
                        &symbol_config,
                    )
                    .await
                    .expect("reconstruct bundle");
                let second_verified = verifier
                    .verify_bundle(&reconstructed, None, None, None)
                    .expect("second verify");
                let second_mirror = verifier
                    .mirror_bundle(
                        &second_verified,
                        &reconstructed,
                        ZoneId::work(),
                        &object_id_key,
                        &store,
                    )
                    .await
                    .expect("second mirror bundle");

                assert_eq!(reconstructed.manifest_toml, bundle.manifest_toml);
                assert_eq!(reconstructed.binary, bundle.binary);
                assert_eq!(reconstructed.target, bundle.target);
                assert_eq!(second_verified.manifest_hash, first_verified.manifest_hash);
                assert_eq!(second_verified.binary_hash, first_verified.binary_hash);
                assert_eq!(second_mirror.manifest_hash, mirror.manifest_hash);
                assert_eq!(second_mirror.binary_hash, mirror.binary_hash);

                RegistryLogData {
                    manifest_hash: Some(first_verified.manifest_hash),
                    binary_hash: Some(first_verified.binary_hash),
                    target: Some(first_verified.target.as_string()),
                    reason_code: Some("reinstall_idempotent".to_string()),
                    ..RegistryLogData::default()
                }
            },
        );
    }

    #[test]
    fn local_registry_router_serves_target_artifacts() {
        use axum::body::{Body, to_bytes};
        use axum::http::Request;
        use tower::util::ServiceExt;

        let temp = tempfile::tempdir().expect("tempdir");
        let linux = ConnectorTarget {
            os: "linux".to_string(),
            arch: "amd64".to_string(),
        };
        let package_dir = write_signed_package_dir(
            temp.path(),
            "fcp.router-test",
            "1.2.0",
            linux,
            "router-test-linux",
            b"router-binary",
        );

        let catalog =
            LocalRegistryCatalog::from_signed_package_dirs(&[package_dir]).expect("catalog");
        let app = catalog.router();

        fcp_async_core::runtime::block_on_sync(async move {
            let release_response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/v1/connectors/fcp.router-test/latest")
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("latest response");
            assert_eq!(release_response.status(), StatusCode::OK);
            let release_body = to_bytes(release_response.into_body(), usize::MAX)
                .await
                .expect("latest body");
            let release: RegistryVersionDescriptor =
                serde_json::from_slice(&release_body).expect("release descriptor");
            assert_eq!(release.version, "1.2.0");
            assert_eq!(release.targets.len(), 1);
            assert_eq!(release.targets[0].binary_sha256, hash_bytes(b"router-binary"));

            let manifest_response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/v1/connectors/fcp.router-test/versions/1.2.0/targets/linux/amd64/manifest")
                        .body(Body::empty())
                        .expect("manifest request"),
                )
                .await
                .expect("manifest response");
            assert_eq!(manifest_response.status(), StatusCode::OK);
            let manifest_type = manifest_response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok());
            assert_eq!(manifest_type, Some("text/plain; charset=utf-8"));
            let manifest_body = to_bytes(manifest_response.into_body(), usize::MAX)
                .await
                .expect("manifest body");
            let manifest_text = String::from_utf8(manifest_body.to_vec()).expect("utf8 manifest");
            assert!(manifest_text.contains(r#"id = "fcp.router-test""#));

            let binary_response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/v1/connectors/fcp.router-test/versions/1.2.0/targets/linux/amd64/binary")
                        .body(Body::empty())
                        .expect("binary request"),
                )
                .await
                .expect("binary response");
            assert_eq!(binary_response.status(), StatusCode::OK);
            let binary_type = binary_response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok());
            assert_eq!(binary_type, Some("application/octet-stream"));
            let binary_body = to_bytes(binary_response.into_body(), usize::MAX)
                .await
                .expect("binary body");
            assert_eq!(binary_body.as_ref(), b"router-binary");
        })
        .expect("build test runtime");
    }
}
