//! Canonical process-snapshot manifest stored through the mesh object plane.
//!
//! A live process snapshot is represented as a signed manifest whose payload is
//! a [`fcp_raptorq::ChunkedObjectManifest`]. The manifest itself has stable
//! canonical CBOR bytes and can be wrapped in a normal [`StoredObject`], while
//! the snapshot chunks remain regular content-addressed mesh objects.

use fcp_cbor::{CanonicalSerializer, SchemaId, SerializationError};
use fcp_crypto::{Ed25519Signature, Ed25519SigningKey, Ed25519VerifyingKey};
use fcp_prelude::{
    ObjectHeader, ObjectId, ObjectIdKey, Provenance, RetentionClass, StorageMeta, StoredObject,
    ZoneId,
};
use fcp_raptorq::ChunkedObjectManifest;
use semver::Version;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const SNAPSHOT_ID_DOMAIN: &[u8] = b"FCP-STORE-PROCESS-SNAPSHOT-ID-V1";
const SNAPSHOT_SIGNATURE_CONTEXT: &[u8] = b"FCP-STORE-PROCESS-SNAPSHOT-SIGNATURE-V1";

/// Errors raised by process-snapshot manifest validation.
#[derive(Debug, Error)]
pub enum ProcessSnapshotError {
    /// Canonical CBOR encoding or decoding failed.
    #[error("canonical serialization error: {0}")]
    Serialization(#[from] SerializationError),

    /// Manifest carried a `snapshot_id` that does not match its unsigned
    /// identity fields.
    #[error("snapshot id mismatch: claimed {claimed}, computed {computed}")]
    SnapshotIdMismatch {
        /// ID carried by the manifest.
        claimed: ObjectId,
        /// ID derived from the manifest identity fields.
        computed: ObjectId,
    },

    /// No configured trust anchor verified the manifest signature.
    #[error("snapshot signature was not accepted by any configured trust anchor")]
    NoTrustedSignature,

    /// Presented capability token bytes do not match the pinned token hash.
    #[error("capability token pin mismatch for process snapshot {snapshot_id}")]
    CapabilityTokenMismatch {
        /// Snapshot that rejected restore authorization.
        snapshot_id: ObjectId,
    },
}

/// Stable snapshot format tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessSnapshotFormat {
    /// Linux CRIU image directory.
    Criu,
    /// macOS Mach task state captured through Mach APIs.
    MachoMach,
    /// FCP-defined connector-specific snapshot format.
    Custom,
}

/// Trust anchors allowed to authorize process-snapshot restore.
#[derive(Debug, Clone, Default)]
pub struct ProcessSnapshotTrustAnchors {
    anchors: Vec<Ed25519VerifyingKey>,
}

impl ProcessSnapshotTrustAnchors {
    /// Build a trust-anchor set.
    #[must_use]
    pub fn new(anchors: impl Into<Vec<Ed25519VerifyingKey>>) -> Self {
        Self {
            anchors: anchors.into(),
        }
    }

    /// Build a singleton trust-anchor set.
    #[must_use]
    pub fn single(anchor: Ed25519VerifyingKey) -> Self {
        Self {
            anchors: vec![anchor],
        }
    }

    /// Whether no trust anchors are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }
}

/// Signed manifest for a live connector process snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessSnapshotManifest {
    /// Content-derived snapshot identifier over unsigned identity fields.
    pub snapshot_id: ObjectId,
    /// Original root process ID captured by the snapshotter.
    pub original_pid: u32,
    /// Canonical node identifier that produced the snapshot.
    pub originating_node: String,
    /// Snapshot image format.
    pub snapshot_format: ProcessSnapshotFormat,
    /// Chunk manifest for the process-state bytes.
    pub chunk_manifest: ChunkedObjectManifest,
    /// BLAKE3 hash of the capability token authorized to restore this snapshot.
    pub capability_token_pinned: [u8; 32],
    /// Ed25519 signature over the canonical signed payload.
    pub signature: Ed25519Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProcessSnapshotIdentityPayload {
    original_pid: u32,
    originating_node: String,
    snapshot_format: ProcessSnapshotFormat,
    chunk_manifest: ChunkedObjectManifest,
    capability_token_pinned: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProcessSnapshotSignedPayload {
    snapshot_id: ObjectId,
    original_pid: u32,
    originating_node: String,
    snapshot_format: ProcessSnapshotFormat,
    chunk_manifest: ChunkedObjectManifest,
    capability_token_pinned: [u8; 32],
}

impl ProcessSnapshotManifest {
    /// Canonical schema for the signed process-snapshot manifest.
    #[must_use]
    pub fn schema_id() -> SchemaId {
        SchemaId::new(
            "fcp.store",
            "ProcessSnapshotManifest",
            Version::new(1, 0, 0),
        )
    }

    fn identity_schema_id() -> SchemaId {
        SchemaId::new(
            "fcp.store",
            "ProcessSnapshotIdentityPayload",
            Version::new(1, 0, 0),
        )
    }

    fn signed_payload_schema_id() -> SchemaId {
        SchemaId::new(
            "fcp.store",
            "ProcessSnapshotSignedPayload",
            Version::new(1, 0, 0),
        )
    }

    /// Sign a process snapshot manifest, pinning restore to
    /// `capability_token_bytes`.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessSnapshotError::Serialization`] if canonical signing
    /// bytes cannot be constructed.
    pub fn sign(
        original_pid: u32,
        originating_node: impl Into<String>,
        snapshot_format: ProcessSnapshotFormat,
        chunk_manifest: ChunkedObjectManifest,
        capability_token_bytes: &[u8],
        signing_key: &Ed25519SigningKey,
    ) -> Result<Self, ProcessSnapshotError> {
        Self::sign_with_capability_pin(
            original_pid,
            originating_node,
            snapshot_format,
            chunk_manifest,
            pin_capability_token(capability_token_bytes),
            signing_key,
        )
    }

    /// Sign a process snapshot manifest with an already computed capability
    /// token pin.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessSnapshotError::Serialization`] if canonical signing
    /// bytes cannot be constructed.
    pub fn sign_with_capability_pin(
        original_pid: u32,
        originating_node: impl Into<String>,
        snapshot_format: ProcessSnapshotFormat,
        chunk_manifest: ChunkedObjectManifest,
        capability_token_pinned: [u8; 32],
        signing_key: &Ed25519SigningKey,
    ) -> Result<Self, ProcessSnapshotError> {
        let originating_node = originating_node.into();
        let snapshot_id = Self::derive_snapshot_id_from_parts(
            original_pid,
            &originating_node,
            snapshot_format.clone(),
            chunk_manifest.clone(),
            capability_token_pinned,
        )?;
        let payload = ProcessSnapshotSignedPayload {
            snapshot_id,
            original_pid,
            originating_node: originating_node.clone(),
            snapshot_format: snapshot_format.clone(),
            chunk_manifest: chunk_manifest.clone(),
            capability_token_pinned,
        };
        let signing_bytes =
            CanonicalSerializer::serialize(&payload, &Self::signed_payload_schema_id())?;
        let signature = signing_key.sign_with_context(SNAPSHOT_SIGNATURE_CONTEXT, &signing_bytes);

        Ok(Self {
            snapshot_id,
            original_pid,
            originating_node,
            snapshot_format,
            chunk_manifest,
            capability_token_pinned,
            signature,
        })
    }

    /// Decode a canonical manifest and reject non-canonical byte forms.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessSnapshotError::Serialization`] if schema verification,
    /// canonical decoding, or serde decoding fails.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ProcessSnapshotError> {
        Ok(CanonicalSerializer::deserialize(bytes, &Self::schema_id())?)
    }

    /// Decode canonical bytes and verify both signature and capability pin
    /// before a caller unmarshals process-state chunks.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessSnapshotError`] when canonical decoding, signature
    /// validation, snapshot-id validation, or token pinning fails.
    pub fn decode_verified(
        bytes: &[u8],
        capability_token_bytes: &[u8],
        trust_anchors: &ProcessSnapshotTrustAnchors,
    ) -> Result<Self, ProcessSnapshotError> {
        let manifest = Self::from_canonical_bytes(bytes)?;
        manifest.verify_restore_authorization(capability_token_bytes, trust_anchors)?;
        Ok(manifest)
    }

    /// Encode the signed manifest as schema-prefixed canonical CBOR.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessSnapshotError::Serialization`] when canonical encoding
    /// fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProcessSnapshotError> {
        Ok(CanonicalSerializer::serialize(self, &Self::schema_id())?)
    }

    /// Content-addressed ID for the signed manifest bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessSnapshotError::Serialization`] when canonical encoding
    /// fails.
    pub fn manifest_object_id(&self) -> Result<ObjectId, ProcessSnapshotError> {
        Ok(ObjectId::from_unscoped_bytes(&self.canonical_bytes()?))
    }

    /// Validate the deterministic `snapshot_id` carried by the manifest.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessSnapshotError::SnapshotIdMismatch`] if identity fields
    /// no longer match `snapshot_id`.
    pub fn verify_snapshot_id(&self) -> Result<(), ProcessSnapshotError> {
        let computed = self.derive_snapshot_id()?;
        if computed != self.snapshot_id {
            return Err(ProcessSnapshotError::SnapshotIdMismatch {
                claimed: self.snapshot_id,
                computed,
            });
        }
        Ok(())
    }

    /// Verify the manifest signature against configured trust anchors.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessSnapshotError::SnapshotIdMismatch`] if identity fields
    /// were tampered with, or [`ProcessSnapshotError::NoTrustedSignature`] if
    /// no trust anchor verifies the signature.
    pub fn verify_signature(
        &self,
        trust_anchors: &ProcessSnapshotTrustAnchors,
    ) -> Result<(), ProcessSnapshotError> {
        self.verify_snapshot_id()?;
        let signing_bytes = CanonicalSerializer::serialize(
            &self.signed_payload(),
            &Self::signed_payload_schema_id(),
        )?;

        for anchor in &trust_anchors.anchors {
            if anchor
                .verify_with_context(SNAPSHOT_SIGNATURE_CONTEXT, &signing_bytes, &self.signature)
                .is_ok()
            {
                return Ok(());
            }
        }

        Err(ProcessSnapshotError::NoTrustedSignature)
    }

    /// Verify signature and capability-token pin for restore.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessSnapshotError`] when signature validation fails or the
    /// presented token does not match the pinned token hash.
    pub fn verify_restore_authorization(
        &self,
        capability_token_bytes: &[u8],
        trust_anchors: &ProcessSnapshotTrustAnchors,
    ) -> Result<(), ProcessSnapshotError> {
        self.verify_signature(trust_anchors)?;
        let presented = pin_capability_token(capability_token_bytes);
        if presented != self.capability_token_pinned {
            return Err(ProcessSnapshotError::CapabilityTokenMismatch {
                snapshot_id: self.snapshot_id,
            });
        }
        Ok(())
    }

    /// Wrap the signed manifest as a normal mesh [`StoredObject`].
    ///
    /// The stored object's header references every snapshot chunk so object GC,
    /// repair, and lifecycle snapshots see the process-state dependency graph.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessSnapshotError::Serialization`] when the manifest or
    /// resulting stored-object bytes cannot be encoded canonically.
    pub fn to_stored_object(
        &self,
        zone_id: ZoneId,
        created_at: u64,
        provenance: Provenance,
        retention: RetentionClass,
        object_id_key: &ObjectIdKey,
    ) -> Result<StoredObject, ProcessSnapshotError> {
        let body = self.canonical_bytes()?;
        let header = ObjectHeader {
            encryption_kind: Default::default(),
            schema: Self::schema_id(),
            zone_id,
            created_at,
            provenance,
            refs: self.chunk_manifest.chunks.clone(),
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        };
        let object_id = StoredObject::derive_id(&header, &body, object_id_key)?;

        Ok(StoredObject {
            object_id,
            header,
            body,
            storage: StorageMeta { retention },
        })
    }

    fn derive_snapshot_id(&self) -> Result<ObjectId, ProcessSnapshotError> {
        Self::derive_snapshot_id_from_parts(
            self.original_pid,
            &self.originating_node,
            self.snapshot_format.clone(),
            self.chunk_manifest.clone(),
            self.capability_token_pinned,
        )
    }

    fn derive_snapshot_id_from_parts(
        original_pid: u32,
        originating_node: &str,
        snapshot_format: ProcessSnapshotFormat,
        chunk_manifest: ChunkedObjectManifest,
        capability_token_pinned: [u8; 32],
    ) -> Result<ObjectId, ProcessSnapshotError> {
        let identity = ProcessSnapshotIdentityPayload {
            original_pid,
            originating_node: originating_node.to_owned(),
            snapshot_format,
            chunk_manifest,
            capability_token_pinned,
        };
        let identity_bytes =
            CanonicalSerializer::serialize(&identity, &Self::identity_schema_id())?;
        let mut content = Vec::with_capacity(SNAPSHOT_ID_DOMAIN.len() + identity_bytes.len());
        content.extend_from_slice(SNAPSHOT_ID_DOMAIN);
        content.extend_from_slice(&identity_bytes);
        Ok(ObjectId::from_unscoped_bytes(&content))
    }

    fn signed_payload(&self) -> ProcessSnapshotSignedPayload {
        ProcessSnapshotSignedPayload {
            snapshot_id: self.snapshot_id,
            original_pid: self.original_pid,
            originating_node: self.originating_node.clone(),
            snapshot_format: self.snapshot_format.clone(),
            chunk_manifest: self.chunk_manifest.clone(),
            capability_token_pinned: self.capability_token_pinned,
        }
    }
}

/// Compute the stable restore token pin stored in process-snapshot manifests.
#[must_use]
pub fn pin_capability_token(capability_token_bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(capability_token_bytes).as_bytes()
}

#[cfg(test)]
mod tests {
    use fcp_raptorq::{RaptorQConfig, RaptorQDecoder, RaptorQEncoder};

    use super::*;

    const TOKEN: &[u8] = b"capability-token-alpha";

    fn fixed_signing_key() -> Ed25519SigningKey {
        Ed25519SigningKey::from_bytes(&[7_u8; 32]).unwrap()
    }

    fn sample_chunk_manifest() -> ChunkedObjectManifest {
        let payload = b"criu-image-state:pid=4242;fds=3,4;memory=stable";
        let (manifest, _chunks) = ChunkedObjectManifest::from_payload(payload, 11);
        manifest
    }

    fn sample_manifest() -> ProcessSnapshotManifest {
        ProcessSnapshotManifest::sign(
            4242,
            "node-alpha",
            ProcessSnapshotFormat::Criu,
            sample_chunk_manifest(),
            TOKEN,
            &fixed_signing_key(),
        )
        .unwrap()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().fold(String::new(), |mut acc, byte| {
            use std::fmt::Write;
            write!(acc, "{byte:02x}").unwrap();
            acc
        })
    }

    #[test]
    fn canonical_cbor_roundtrip_is_byte_equivalent() {
        let manifest = sample_manifest();
        let bytes = manifest.canonical_bytes().unwrap();
        let decoded = ProcessSnapshotManifest::from_canonical_bytes(&bytes).unwrap();
        let encoded_again = decoded.canonical_bytes().unwrap();

        assert_eq!(decoded, manifest);
        assert_eq!(encoded_again, bytes);
    }

    #[test]
    fn sample_snapshot_canonical_cbor_matches_golden_vector() {
        let bytes = sample_manifest().canonical_bytes().unwrap();
        let expected = "f5eeb5f6cb8e9d29982664a022258e24bc2b9b1ac517a155395409f86b5dc438a7697369676e617475726558405c68cc26e004c0e23de05fb98115522bfa914b00805e3069cb30dbacd60981ab1c41c8bec13b14fe8d2a2596067eff6879ff232c56e19197c7b5b8f9c7d1470d6b736e617073686f745f69645820d44e3d4c2e97ec59461c47790d9bfd71f9bb6b8bafb333415a3ecd5765ced1ed6c6f726967696e616c5f7069641910926e6368756e6b5f6d616e6966657374a4666368756e6b73855820b3f66b832b7dafd60679470803e80d2e847b0238fd81e16fc69eb94c49a25ee458205b2e8ba8c24dcc21ae42260e1c755d978d735f85782c89a81ccfa1cfaf923a515820ebac793dd9834568a354eae46cc83b96f4910054c5133d5954fe6f5bd29518595820e4c9c0b4652a5d0bbb5ef8c17a8d45d2d0c477258b411dbe4327dd2815dd95545820d81d2dad75bebe85a02e669579292d590603b71f6e24fcf0e1cb8e12769228c069746f74616c5f6c656e182f6a6368756e6b5f73697a650b6c7061796c6f61645f68617368982018fe18fc11184a18cf185d188b182005181d18df1898186e18b91859181c184e18df18d0188d18d018881821181e18cb18d018e5182018c7189b182018386f736e617073686f745f666f726d61746463726975706f726967696e6174696e675f6e6f64656a6e6f64652d616c706861776361706162696c6974795f746f6b656e5f70696e6e6564982018b5183c18bc1864189a18fb182218361877185618a71863160c183318f81844181e18cb1858189c18dd182318a318d81830185018c118c1188918980f";

        assert_eq!(hex(&bytes), expected);
    }

    #[test]
    fn tampered_snapshot_signature_is_rejected() {
        let mut tampered = sample_manifest();
        tampered.original_pid += 1;
        tampered.snapshot_id = tampered.derive_snapshot_id().unwrap();
        let anchors = ProcessSnapshotTrustAnchors::single(fixed_signing_key().verifying_key());

        let err = tampered.verify_signature(&anchors).unwrap_err();

        assert!(matches!(err, ProcessSnapshotError::NoTrustedSignature));
    }

    #[test]
    fn capability_token_pin_prevents_unauthorized_restore() {
        let manifest = sample_manifest();
        let anchors = ProcessSnapshotTrustAnchors::single(fixed_signing_key().verifying_key());

        let err = manifest
            .verify_restore_authorization(b"wrong-token", &anchors)
            .unwrap_err();

        assert!(matches!(
            err,
            ProcessSnapshotError::CapabilityTokenMismatch { .. }
        ));
    }

    #[test]
    fn decode_verified_checks_signature_before_restore_authorization() {
        let manifest = sample_manifest();
        let bytes = manifest.canonical_bytes().unwrap();
        let wrong_anchor = Ed25519SigningKey::from_bytes(&[8_u8; 32])
            .unwrap()
            .verifying_key();
        let anchors = ProcessSnapshotTrustAnchors::single(wrong_anchor);

        let err = ProcessSnapshotManifest::decode_verified(&bytes, TOKEN, &anchors).unwrap_err();

        assert!(matches!(err, ProcessSnapshotError::NoTrustedSignature));
    }

    #[test]
    fn decode_verified_accepts_matching_trust_anchor_and_token_pin() {
        let manifest = sample_manifest();
        let bytes = manifest.canonical_bytes().unwrap();
        let anchors = ProcessSnapshotTrustAnchors::single(fixed_signing_key().verifying_key());

        let decoded = ProcessSnapshotManifest::decode_verified(&bytes, TOKEN, &anchors).unwrap();

        assert_eq!(decoded.snapshot_id, manifest.snapshot_id);
    }

    #[test]
    fn stored_object_refs_snapshot_chunks() {
        let manifest = sample_manifest();
        let zone = ZoneId::work();
        let object = manifest
            .to_stored_object(
                zone.clone(),
                1_700_000_000,
                Provenance::new(zone.clone()),
                RetentionClass::Pinned,
                &ObjectIdKey::from_bytes([3_u8; 32]),
            )
            .unwrap();

        assert_eq!(object.header.schema, ProcessSnapshotManifest::schema_id());
        assert_eq!(object.header.zone_id, zone);
        assert_eq!(object.header.refs, manifest.chunk_manifest.chunks);
        assert_eq!(object.body, manifest.canonical_bytes().unwrap());
        assert_eq!(
            object.object_id,
            StoredObject::derive_id(
                &object.header,
                &object.body,
                &ObjectIdKey::from_bytes([3_u8; 32])
            )
            .unwrap()
        );
    }

    #[test]
    fn k_snapshot_symbols_reconstruct_original_manifest_bytes() {
        let bytes = sample_manifest().canonical_bytes().unwrap();
        let config = RaptorQConfig {
            symbol_size: 64,
            repair_ratio_bps: 500,
            ..Default::default()
        };
        let encoder = RaptorQEncoder::new(&bytes, &config).unwrap();
        let source_symbols = encoder.encode_source();
        assert_eq!(source_symbols.len() as u32, encoder.source_symbols());

        let mut decoder = RaptorQDecoder::new(encoder.transmission_info(), &config);
        let mut reconstructed = None;
        for (esi, data) in source_symbols.into_iter().rev() {
            if let Some(payload) = decoder.add_symbol(esi, data).unwrap() {
                reconstructed = Some(payload);
            }
        }

        assert_eq!(reconstructed.unwrap(), bytes);
    }
}
