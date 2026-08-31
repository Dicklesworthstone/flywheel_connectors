//! Mesh object primitives: `ObjectId`, `ObjectHeader`, and storage metadata.
//!
//! This module implements the foundational primitives from `FCP_Specification_V3.md`
//! §3.3 (Object Header) and §3.1 (Canonical Identifiers).

use std::fmt;

use fcp_cbor::{SchemaId, SerializationError};
use serde::{Deserialize, Serialize};

use crate::{Provenance, ZoneId};

/// Content-addressed identifier (NORMATIVE).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)] // Use transparent to delegate to the inner array via hex_or_bytes
pub struct ObjectId(#[serde(with = "crate::util::hex_or_bytes")] [u8; 32]);

impl ObjectId {
    /// Construct an `ObjectId` from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Parse a human-facing object id string.
    ///
    /// Accepts either raw lowercase/uppercase hex or the manifest-facing
    /// `objectid:<hex>` form used in TOML/JSON payloads.
    ///
    /// # Errors
    /// Returns [`ObjectIdParseError`] if the string is not valid hex or does
    /// not decode to exactly 32 bytes.
    pub fn parse_prefixed(value: &str) -> Result<Self, ObjectIdParseError> {
        let hex_str = value.strip_prefix("objectid:").unwrap_or(value);
        let bytes = hex::decode(hex_str).map_err(|_| ObjectIdParseError::InvalidHex)?;
        if bytes.len() != 32 {
            return Err(ObjectIdParseError::WrongLength {
                actual: bytes.len(),
            });
        }

        let mut object_id = [0_u8; 32];
        object_id.copy_from_slice(&bytes);
        Ok(Self::from_bytes(object_id))
    }

    /// Render the object id in the manifest-facing `objectid:<hex>` form.
    #[must_use]
    pub fn to_prefixed_string(&self) -> String {
        format!("objectid:{self}")
    }

    /// Create `ObjectId` from content, zone, and schema (NORMATIVE for security objects).
    #[must_use]
    pub fn new(content: &[u8], zone: &ZoneId, schema: &SchemaId, key: &ObjectIdKey) -> Self {
        let mut h = blake3::Hasher::new_keyed(&key.0);
        h.update(b"FCP2-OBJECT-V2");
        h.update(zone.as_bytes());
        h.update(schema.hash().as_bytes());
        h.update(content);
        Self(*h.finalize().as_bytes())
    }

    /// Unscoped content hash (NON-NORMATIVE; MUST NOT be used for security objects).
    #[must_use]
    pub fn from_unscoped_bytes(content: &[u8]) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(b"FCP2-CONTENT-V2");
        h.update(content);
        Self(*h.finalize().as_bytes())
    }

    /// Create a test `ObjectId` from a string identifier.
    ///
    /// This is a convenience method for tests only.
    #[cfg(test)]
    #[must_use]
    pub fn test_id(name: &str) -> Self {
        Self::from_unscoped_bytes(name.as_bytes())
    }
}

impl fmt::Debug for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ObjectId").field(&self.to_string()).finish()
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl std::str::FromStr for ObjectId {
    type Err = ObjectIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse_prefixed(value)
    }
}

impl AsRef<[u8]> for ObjectId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Parse failures for manifest-facing object id references.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ObjectIdParseError {
    #[error("object id must be hex")]
    InvalidHex,
    #[error("object id must be 32 bytes")]
    WrongLength { actual: usize },
}

/// Secret per-zone object-id key (NORMATIVE).
///
/// This key is distributed to zone members via `ZoneKeyManifest` (NORMATIVE) and remains stable
/// across routine zone key rotations. It provides privacy against dictionary attacks on
/// low-entropy objects.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjectIdKey([u8; 32]);

impl ObjectIdKey {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ObjectIdKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ObjectIdKey")
            .field(&"[redacted; 32 bytes]")
            .finish()
    }
}

/// Typed device selector for placement policies (NORMATIVE).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceSelector {
    Tag(String),
    Class(String),
    NodeId(u64),
    Zone(ZoneId),
    HasCapability(String),
}

/// Stable mesh placement preference hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshPlacementHint {
    /// Prefer nodes that already hold required object data or symbols.
    DataLocality,
    /// Prefer the lowest-latency eligible node.
    LowLatency,
    /// Prefer nodes with the most available compute resources.
    HighResources,
    /// Prefer nodes that can satisfy secret reconstruction locally.
    SecretReconstructable,
    /// Prefer direct placement over DERP-relayed placement when possible.
    AvoidDerp,
}

impl MeshPlacementHint {
    /// Stable text token used by serde and Display.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::DataLocality => "data_locality",
            Self::LowLatency => "low_latency",
            Self::HighResources => "high_resources",
            Self::SecretReconstructable => "secret_reconstructable",
            Self::AvoidDerp => "avoid_derp",
        }
    }
}

impl fmt::Display for MeshPlacementHint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Object placement policy (NORMATIVE when used).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectPlacementPolicy {
    pub min_nodes: u8,
    pub max_node_fraction_bps: u16,
    #[serde(default)]
    pub preferred_devices: Vec<DeviceSelector>,
    #[serde(default)]
    pub excluded_devices: Vec<DeviceSelector>,
    pub target_coverage_bps: u32,
    /// Minimum distinct source nodes required for reconstruction (diversity enforcement).
    /// When set, objects MUST have symbols from at least this many distinct nodes
    /// before reconstruction is permitted. Default is 0 (no diversity requirement).
    #[serde(default)]
    pub min_source_diversity: u8,
}

/// Universal object header (NORMATIVE).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectHeader {
    pub schema: SchemaId,
    pub zone_id: ZoneId,
    pub created_at: u64,
    pub provenance: Provenance,
    #[serde(default)]
    pub refs: Vec<ObjectId>,
    #[serde(default)]
    pub foreign_refs: Vec<ObjectId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placement: Option<ObjectPlacementPolicy>,
    /// How the object body is encrypted (`flywheel_connectors-angoc.11.6.1`).
    /// `Plain` (the default) is the content-addressed plaintext body;
    /// `ThresholdHpkeQuorum` marks a body sealed with the threshold-HPKE
    /// KEM so that only a `threshold`-of-`epoch` quorum holding FROST
    /// decap shares can recover it.
    #[serde(default, skip_serializing_if = "ObjectEncryptionKind::is_plain")]
    pub encryption_kind: ObjectEncryptionKind,
}

/// Encryption state of an object body (NORMATIVE,
/// `flywheel_connectors-angoc.11.6.1`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectEncryptionKind {
    /// Body is stored as plaintext content-addressed bytes.
    #[default]
    Plain,
    /// Body was sealed with the threshold-HPKE KEM; recovery requires
    /// `threshold` decap shares from the ceremony `epoch`.
    ThresholdHpkeQuorum {
        /// Decap shares required to open the body.
        threshold: u16,
        /// FROST ceremony epoch that produced the group key.
        epoch: u64,
    },
}

impl ObjectEncryptionKind {
    /// Whether this kind is the default plaintext form.
    #[must_use]
    pub const fn is_plain(&self) -> bool {
        matches!(self, Self::Plain)
    }
}

/// Eviction policy for garbage collection (NORMATIVE).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvictionPolicy {
    Pinned,
    Lease { expires_at: u64 },
    Ephemeral,
}

impl fmt::Display for EvictionPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pinned => f.write_str("pinned"),
            Self::Lease { expires_at } => write!(f, "lease(expires_at={expires_at})"),
            Self::Ephemeral => f.write_str("ephemeral"),
        }
    }
}

/// Retention class for garbage collection (NORMATIVE).
pub type RetentionClass = EvictionPolicy;

/// Node-local storage metadata (NOT content-addressed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageMeta {
    pub retention: RetentionClass,
}

/// Stored object record (NORMATIVE).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredObject {
    pub object_id: ObjectId,
    pub header: ObjectHeader,
    /// Canonical CBOR body (schema-prefixed).
    pub body: Vec<u8>,
    /// Node-local storage policy.
    pub storage: StorageMeta,
}

impl StoredObject {
    /// Canonical bytes used for `ObjectId` derivation (NORMATIVE).
    ///
    /// Format: `b"FCP2-OBJECT-V1" || canonical_cbor(header) || body`.
    ///
    /// # Errors
    /// Returns a serialization error if the header cannot be encoded canonically or if the
    /// resulting bytes exceed `fcp_cbor::MAX_CANONICAL_OBJECT_BYTES`.
    pub fn canonical_bytes(
        header: &ObjectHeader,
        body: &[u8],
    ) -> Result<Vec<u8>, SerializationError> {
        let mut out = Vec::new();
        out.extend_from_slice(b"FCP2-OBJECT-V1");
        out.extend_from_slice(&fcp_cbor::to_canonical_cbor(header)?);
        out.extend_from_slice(body);

        if out.len() > fcp_cbor::MAX_CANONICAL_OBJECT_BYTES {
            return Err(SerializationError::PayloadTooLarge {
                len: out.len(),
                max: fcp_cbor::MAX_CANONICAL_OBJECT_BYTES,
            });
        }

        Ok(out)
    }

    /// Derive the object id for a stored object (NORMATIVE).
    ///
    /// # Errors
    /// Returns a serialization error if canonical bytes cannot be constructed.
    pub fn derive_id(
        header: &ObjectHeader,
        body: &[u8],
        key: &ObjectIdKey,
    ) -> Result<ObjectId, SerializationError> {
        let content = Self::canonical_bytes(header, body)?;
        Ok(ObjectId::new(
            &content,
            &header.zone_id,
            &header.schema,
            key,
        ))
    }

    /// Structural validation that does not require an `ObjectIdKey`.
    ///
    /// `ObjectId` is a *keyed* derivation (HMAC-style with the zone's
    /// `ObjectIdKey`), so the storage layer cannot independently verify
    /// `self.object_id == derive_id(self.header, self.body, key)` without
    /// access to the zone keys (which live in `ZoneKeyMaterial`, outside
    /// the store). Full content-ID verification is the runtime-API layer's
    /// responsibility (e.g., `MeshNode` at the put boundary).
    ///
    /// This method provides the strongest *key-free* check available:
    /// run the canonical encoding pipeline that `derive_id` would run, so
    /// that any object which could not have been produced by a legitimate
    /// `derive_id` call is rejected. It catches:
    ///
    ///   - Headers that fail canonical-CBOR encoding (NaN/Infinity floats,
    ///     duplicate map keys, non-canonical structure, `serde` errors).
    ///   - `body` lengths that, combined with the canonical header, exceed
    ///     [`fcp_cbor::MAX_CANONICAL_OBJECT_BYTES`] (64 MiB) — protects
    ///     downstream allocators from oversized objects smuggled through a
    ///     deserialized envelope (e.g., a 500 MiB `Put` in the WAL).
    ///
    /// This is a NECESSARY but not SUFFICIENT check for content-addressing
    /// integrity. Storage backends should call this on every write
    /// (runtime API + WAL replay + snapshot recovery) for defense in depth.
    ///
    /// # Errors
    /// Returns the same `SerializationError` that `canonical_bytes` would
    /// return for a malformed or oversized object.
    pub fn validate_structure(&self) -> Result<(), SerializationError> {
        Self::canonical_bytes(&self.header, &self.body)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use semver::Version;

    // ─────────────────────────────────────────────────────────────────────────
    // ObjectId Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn object_id_golden_vector_smoke() {
        let key = ObjectIdKey::from_bytes([0_u8; 32]);
        let zone: ZoneId = "z:work".parse().unwrap();
        let schema = SchemaId::new("fcp.core", "CapabilityObject", Version::new(1, 0, 0));

        let object_id = ObjectId::new(b"hello", &zone, &schema, &key);

        // Golden vector: keyed BLAKE3 with domain separation.
        //
        // Input: key=[0;32], zone="z:work",
        //        schema=SchemaId::new("fcp.core", "CapabilityObject", 1.0.0),
        //        content=b"hello"
        // Hash:  blake3_keyed(key, "FCP2-OBJECT-V2" || zone_bytes ||
        //                          schema.hash().as_bytes() || content)
        //
        // Updated for br-wyq8x: the previous golden
        // `5fc04a5e6c6b549580a78b9dd99d7f92208022873def22441f58b8df8dd84f7e`
        // matched the pre-mzi9x SchemaId::hash() which concatenated
        // `namespace || ':' || name || '@' || version` raw, allowing
        // distinct (namespace, name) tuples to collide on the same hash
        // (separator-collision). Commit 72a0975f fixed that by
        // length-prefixing each component before feeding the hasher; the
        // schema_hash bytes therefore changed, which propagates through
        // the keyed-BLAKE3 derivation here. The new value below is the
        // post-fix derivation and SHOULD remain stable until the wire
        // format itself bumps via a new domain separator.
        assert_eq!(
            object_id.to_string(),
            "6d766e3dd7615531c490254cf35644c0c21bb734cbaf26938a8edcf2da6ca36a"
        );
    }

    #[test]
    fn object_id_from_bytes_roundtrip() {
        let bytes = [42_u8; 32];
        let object_id = ObjectId::from_bytes(bytes);
        assert_eq!(object_id.as_bytes(), &bytes);
    }

    #[test]
    fn object_id_display_is_hex() {
        let bytes = [0xab_u8; 32];
        let object_id = ObjectId::from_bytes(bytes);
        assert_eq!(object_id.to_string(), "ab".repeat(32));
    }

    #[test]
    fn object_id_prefixed_roundtrip() {
        let prefixed = format!("objectid:{}", "ab".repeat(32));
        let object_id = ObjectId::parse_prefixed(&prefixed).unwrap();
        assert_eq!(object_id.to_prefixed_string(), prefixed);
    }

    #[test]
    fn object_id_prefixed_accepts_raw_hex() {
        let hex = "cd".repeat(32);
        let object_id = ObjectId::parse_prefixed(&hex).unwrap();
        assert_eq!(object_id.to_string(), hex);
        assert_eq!(object_id.to_prefixed_string(), format!("objectid:{hex}"));
    }

    #[test]
    fn object_id_prefixed_rejects_invalid_hex() {
        let err = ObjectId::parse_prefixed("objectid:gg").unwrap_err();
        assert!(matches!(err, ObjectIdParseError::InvalidHex));
    }

    #[test]
    fn object_id_prefixed_rejects_wrong_length() {
        let err = ObjectId::parse_prefixed("objectid:aabb").unwrap_err();
        assert!(matches!(err, ObjectIdParseError::WrongLength { actual: 2 }));
    }

    #[test]
    fn object_id_debug_shows_hex() {
        let bytes = [0xff_u8; 32];
        let object_id = ObjectId::from_bytes(bytes);
        let debug = format!("{object_id:?}");
        assert!(debug.contains("ObjectId"));
        assert!(debug.contains(&"ff".repeat(32)));
    }

    #[test]
    fn object_id_as_ref_slice() {
        let bytes = [1_u8; 32];
        let object_id = ObjectId::from_bytes(bytes);
        let slice: &[u8] = object_id.as_ref();
        assert_eq!(slice, &bytes);
    }

    #[test]
    fn object_id_unscoped_deterministic() {
        let content = b"test content";
        let id1 = ObjectId::from_unscoped_bytes(content);
        let id2 = ObjectId::from_unscoped_bytes(content);
        assert_eq!(id1, id2);
    }

    #[test]
    fn object_id_unscoped_differs_by_content() {
        let id1 = ObjectId::from_unscoped_bytes(b"content a");
        let id2 = ObjectId::from_unscoped_bytes(b"content b");
        assert_ne!(id1, id2);
    }

    #[test]
    fn object_id_keyed_differs_by_key() {
        let zone: ZoneId = "z:work".parse().unwrap();
        let schema = SchemaId::new("fcp.test", "Test", Version::new(1, 0, 0));
        let content = b"same content";

        let key1 = ObjectIdKey::from_bytes([1_u8; 32]);
        let key2 = ObjectIdKey::from_bytes([2_u8; 32]);

        let id1 = ObjectId::new(content, &zone, &schema, &key1);
        let id2 = ObjectId::new(content, &zone, &schema, &key2);
        assert_ne!(id1, id2);
    }

    #[test]
    fn object_id_keyed_differs_by_zone() {
        let key = ObjectIdKey::from_bytes([0_u8; 32]);
        let schema = SchemaId::new("fcp.test", "Test", Version::new(1, 0, 0));
        let content = b"same content";

        let zone1: ZoneId = "z:work".parse().unwrap();
        let zone2: ZoneId = "z:private".parse().unwrap();

        let id1 = ObjectId::new(content, &zone1, &schema, &key);
        let id2 = ObjectId::new(content, &zone2, &schema, &key);
        assert_ne!(id1, id2);
    }

    #[test]
    fn object_id_keyed_differs_by_schema() {
        let key = ObjectIdKey::from_bytes([0_u8; 32]);
        let zone: ZoneId = "z:work".parse().unwrap();
        let content = b"same content";

        let schema1 = SchemaId::new("fcp.test", "TestA", Version::new(1, 0, 0));
        let schema2 = SchemaId::new("fcp.test", "TestB", Version::new(1, 0, 0));

        let id1 = ObjectId::new(content, &zone, &schema1, &key);
        let id2 = ObjectId::new(content, &zone, &schema2, &key);
        assert_ne!(id1, id2);
    }

    #[test]
    fn object_id_equality_and_hash() {
        use std::collections::HashSet;

        let bytes = [7_u8; 32];
        let id1 = ObjectId::from_bytes(bytes);
        let id2 = ObjectId::from_bytes(bytes);

        assert_eq!(id1, id2);

        let mut set = HashSet::new();
        set.insert(id1);
        assert!(set.contains(&id2));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ObjectIdKey Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn object_id_key_from_bytes_roundtrip() {
        let bytes = [99_u8; 32];
        let key = ObjectIdKey::from_bytes(bytes);
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn object_id_key_debug_redacts() {
        let key = ObjectIdKey::from_bytes([0xde_u8; 32]);
        let debug = format!("{key:?}");
        assert!(debug.contains("ObjectIdKey"));
        assert!(debug.contains("redacted"));
        // MUST NOT contain actual key bytes
        assert!(!debug.contains("de"));
    }

    #[test]
    fn object_id_key_equality_and_hash() {
        use std::collections::HashSet;

        let bytes = [42_u8; 32];
        let key1 = ObjectIdKey::from_bytes(bytes);
        let key2 = ObjectIdKey::from_bytes(bytes);

        assert_eq!(key1, key2);

        let mut set = HashSet::new();
        set.insert(key1);
        assert!(set.contains(&key2));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DeviceSelector Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn device_selector_serialization() {
        let tag = DeviceSelector::Tag("gpu".into());
        let json = serde_json::to_string(&tag).unwrap();
        assert!(json.contains("Tag"));
        assert!(json.contains("gpu"));

        let class = DeviceSelector::Class("high-mem".into());
        let json = serde_json::to_string(&class).unwrap();
        assert!(json.contains("Class"));

        let node = DeviceSelector::NodeId(12345);
        let json = serde_json::to_string(&node).unwrap();
        assert!(json.contains("NodeId"));
        assert!(json.contains("12345"));

        let zone = DeviceSelector::Zone(ZoneId::work());
        let json = serde_json::to_string(&zone).unwrap();
        assert!(json.contains("Zone"));
        assert!(json.contains("z:work"));

        let cap = DeviceSelector::HasCapability("gpu.compute".into());
        let json = serde_json::to_string(&cap).unwrap();
        assert!(json.contains("HasCapability"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ObjectPlacementPolicy Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn object_placement_policy_serialization_roundtrip() {
        let policy = ObjectPlacementPolicy {
            min_nodes: 3,
            max_node_fraction_bps: 5000, // 50%
            preferred_devices: vec![DeviceSelector::Tag("ssd".into())],
            excluded_devices: vec![DeviceSelector::Class("low-mem".into())],
            target_coverage_bps: 10000, // 100%
            min_source_diversity: 2,
        };

        let json = serde_json::to_string(&policy).unwrap();
        let deserialized: ObjectPlacementPolicy = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.min_nodes, 3);
        assert_eq!(deserialized.max_node_fraction_bps, 5000);
        assert_eq!(deserialized.target_coverage_bps, 10000);
        assert_eq!(deserialized.preferred_devices.len(), 1);
        assert_eq!(deserialized.excluded_devices.len(), 1);
        assert_eq!(deserialized.min_source_diversity, 2);
    }

    #[test]
    fn object_placement_policy_default_vectors() {
        let minimal = ObjectPlacementPolicy {
            min_nodes: 1,
            max_node_fraction_bps: 10000,
            preferred_devices: vec![],
            excluded_devices: vec![],
            target_coverage_bps: 10000,
            min_source_diversity: 0,
        };

        let json = serde_json::to_string(&minimal).unwrap();
        let deserialized: ObjectPlacementPolicy = serde_json::from_str(&json).unwrap();
        assert!(deserialized.preferred_devices.is_empty());
        assert!(deserialized.excluded_devices.is_empty());
        assert_eq!(deserialized.min_source_diversity, 0);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ObjectHeader Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn object_header_serialization_roundtrip() {
        let header = ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.core", "TestObject", Version::new(1, 2, 3)),
            zone_id: ZoneId::work(),
            created_at: 1_700_000_000,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![ObjectId::from_bytes([1_u8; 32])],
            foreign_refs: vec![],
            ttl_secs: Some(3600),
            placement: None,
        };

        let json = serde_json::to_string(&header).unwrap();
        let deserialized: ObjectHeader = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.zone_id.as_str(), "z:work");
        assert_eq!(deserialized.created_at, 1_700_000_000);
        assert_eq!(deserialized.refs.len(), 1);
        assert_eq!(deserialized.ttl_secs, Some(3600));
    }

    #[test]
    fn object_header_optional_fields_omitted() {
        let header = ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.core", "Test", Version::new(1, 0, 0)),
            zone_id: ZoneId::public(),
            created_at: 0,
            provenance: Provenance::new(ZoneId::public()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };

        let json = serde_json::to_string(&header).unwrap();
        // ttl_secs should be omitted when None
        assert!(!json.contains("ttl_secs"));
        // placement should be omitted when None
        assert!(!json.contains("placement"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RetentionClass Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn retention_class_pinned() {
        let retention = RetentionClass::Pinned;
        let json = serde_json::to_string(&retention).unwrap();
        assert!(json.contains("Pinned"));

        let deserialized: RetentionClass = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, RetentionClass::Pinned);
    }

    #[test]
    fn retention_class_lease() {
        let retention = RetentionClass::Lease {
            expires_at: 1_700_000_000,
        };
        let json = serde_json::to_string(&retention).unwrap();
        assert!(json.contains("Lease"));
        assert!(json.contains("1700000000"));

        let deserialized: RetentionClass = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            deserialized,
            RetentionClass::Lease {
                expires_at: 1_700_000_000
            }
        ));
    }

    #[test]
    fn retention_class_ephemeral() {
        let retention = RetentionClass::Ephemeral;
        let json = serde_json::to_string(&retention).unwrap();
        assert!(json.contains("Ephemeral"));

        let deserialized: RetentionClass = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, RetentionClass::Ephemeral);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // StoredObject Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn stored_object_canonical_bytes_format() {
        let header = ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.test", "Test", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 1_000_000,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let body = b"test body content";

        let canonical = StoredObject::canonical_bytes(&header, body).unwrap();

        // Must start with domain separator
        assert!(canonical.starts_with(b"FCP2-OBJECT-V1"));
        // Must end with body
        assert!(canonical.ends_with(body));
    }

    #[test]
    fn stored_object_derive_id_deterministic() {
        let header = ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.test", "Test", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 1_000_000,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let body = b"test body";
        let key = ObjectIdKey::from_bytes([0_u8; 32]);

        let id1 = StoredObject::derive_id(&header, body, &key).unwrap();
        let id2 = StoredObject::derive_id(&header, body, &key).unwrap();

        assert_eq!(id1, id2);
    }

    #[test]
    fn stored_object_derive_id_differs_by_body() {
        let header = ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.test", "Test", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 1_000_000,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let key = ObjectIdKey::from_bytes([0_u8; 32]);

        let id1 = StoredObject::derive_id(&header, b"body a", &key).unwrap();
        let id2 = StoredObject::derive_id(&header, b"body b", &key).unwrap();

        assert_ne!(id1, id2);
    }

    #[test]
    fn stored_object_serialization_roundtrip() {
        let key = ObjectIdKey::from_bytes([0_u8; 32]);
        let header = ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.test", "Test", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 1_000_000,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let body = b"body bytes".to_vec();

        let object_id = StoredObject::derive_id(&header, &body, &key).unwrap();

        let stored = StoredObject {
            object_id,
            header,
            body: body.clone(),
            storage: StorageMeta {
                retention: RetentionClass::Pinned,
            },
        };

        let json = serde_json::to_string(&stored).unwrap();
        let deserialized: StoredObject = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.body, body);
        assert_eq!(deserialized.object_id, object_id);
    }

    #[test]
    fn stored_object_canonical_bytes_rejects_oversized() {
        let header = ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.test", "Test", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 0,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        // Create a body that exceeds MAX_CANONICAL_OBJECT_BYTES
        let oversized_body = vec![0_u8; fcp_cbor::MAX_CANONICAL_OBJECT_BYTES + 1];

        let result = StoredObject::canonical_bytes(&header, &oversized_body);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SerializationError::PayloadTooLarge { .. }
        ));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ObjectId serde roundtrip
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn object_id_json_serde_roundtrip() {
        let bytes = [0xab_u8; 32];
        let id = ObjectId::from_bytes(bytes);
        let json = serde_json::to_string(&id).unwrap();
        let back: ObjectId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn object_id_json_serde_zero_bytes() {
        let id = ObjectId::from_bytes([0_u8; 32]);
        let json = serde_json::to_string(&id).unwrap();
        let back: ObjectId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
        assert!(json.contains(&"00".repeat(32)));
    }

    #[test]
    fn object_id_json_serde_max_bytes() {
        let id = ObjectId::from_bytes([0xff_u8; 32]);
        let json = serde_json::to_string(&id).unwrap();
        let back: ObjectId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ObjectId ordering
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn object_id_ordering_lexicographic() {
        let a = ObjectId::from_bytes([0_u8; 32]);
        let mut b_bytes = [0_u8; 32];
        b_bytes[0] = 1;
        let b = ObjectId::from_bytes(b_bytes);
        assert!(a < b);
    }

    #[test]
    fn object_id_ordering_stable_sort() {
        let mut ids: Vec<ObjectId> = (0..5)
            .map(|i| {
                let mut bytes = [0_u8; 32];
                bytes[31] = 4 - i;
                ObjectId::from_bytes(bytes)
            })
            .collect();
        ids.sort();
        // Lowest byte value first
        assert_eq!(ids[0].as_bytes()[31], 0);
        assert_eq!(ids[4].as_bytes()[31], 4);
    }

    #[test]
    fn object_id_btreemap_key() {
        use std::collections::BTreeMap;
        let mut map = BTreeMap::new();
        let id1 = ObjectId::from_bytes([1_u8; 32]);
        let id2 = ObjectId::from_bytes([2_u8; 32]);
        map.insert(id1, "first");
        map.insert(id2, "second");
        assert_eq!(map.len(), 2);
        assert_eq!(map[&id1], "first");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ObjectId domain separation
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn object_id_keyed_vs_unscoped_differ() {
        let key = ObjectIdKey::from_bytes([0_u8; 32]);
        let zone: ZoneId = "z:work".parse().unwrap();
        let schema = SchemaId::new("fcp.test", "Test", Version::new(1, 0, 0));
        let content = b"same content";

        let keyed = ObjectId::new(content, &zone, &schema, &key);
        let unscoped = ObjectId::from_unscoped_bytes(content);

        assert_ne!(keyed, unscoped);
    }

    #[test]
    fn object_id_test_id_deterministic() {
        let id1 = ObjectId::test_id("my-test");
        let id2 = ObjectId::test_id("my-test");
        assert_eq!(id1, id2);
    }

    #[test]
    fn object_id_test_id_differs_by_name() {
        let id1 = ObjectId::test_id("test-a");
        let id2 = ObjectId::test_id("test-b");
        assert_ne!(id1, id2);
    }

    #[test]
    fn object_id_empty_content_is_valid() {
        let id = ObjectId::from_unscoped_bytes(b"");
        // Should produce a valid hash (not all zeros)
        assert_ne!(id, ObjectId::from_bytes([0_u8; 32]));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ObjectIdKey additional tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn object_id_key_different_keys_not_equal() {
        let key1 = ObjectIdKey::from_bytes([0_u8; 32]);
        let key2 = ObjectIdKey::from_bytes([1_u8; 32]);
        assert_ne!(key1, key2);
    }

    #[test]
    fn object_id_key_debug_never_leaks_bytes() {
        let key = ObjectIdKey::from_bytes([0x41_u8; 32]); // 'A' repeated
        let debug = format!("{key:?}");
        // Must NOT contain hex of 0x41 = "41" or "AAAA"
        assert!(debug.contains("redacted"));
        assert!(!debug.contains("4141"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DeviceSelector additional tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn device_selector_serde_roundtrip_all_variants() {
        let variants = vec![
            DeviceSelector::Tag("gpu".into()),
            DeviceSelector::Class("high-mem".into()),
            DeviceSelector::NodeId(42),
            DeviceSelector::Zone(ZoneId::private()),
            DeviceSelector::HasCapability("compute.v2".into()),
        ];
        for variant in &variants {
            let json = serde_json::to_string(variant).unwrap();
            let back: DeviceSelector = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&back).unwrap();
            assert_eq!(json, json2);
        }
    }

    #[test]
    fn device_selector_node_id_zero() {
        let sel = DeviceSelector::NodeId(0);
        let json = serde_json::to_string(&sel).unwrap();
        let back: DeviceSelector = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, DeviceSelector::NodeId(0)));
    }

    #[test]
    fn device_selector_node_id_max() {
        let sel = DeviceSelector::NodeId(u64::MAX);
        let json = serde_json::to_string(&sel).unwrap();
        let back: DeviceSelector = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, DeviceSelector::NodeId(v) if v == u64::MAX));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ObjectPlacementPolicy edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn placement_policy_defaults_on_deserialize() {
        let json = r#"{
            "min_nodes": 1,
            "max_node_fraction_bps": 10000,
            "target_coverage_bps": 10000
        }"#;
        let policy: ObjectPlacementPolicy = serde_json::from_str(json).unwrap();
        assert!(policy.preferred_devices.is_empty());
        assert!(policy.excluded_devices.is_empty());
        assert_eq!(policy.min_source_diversity, 0);
    }

    #[test]
    fn placement_policy_with_all_fields() {
        let policy = ObjectPlacementPolicy {
            min_nodes: 5,
            max_node_fraction_bps: 2000,
            preferred_devices: vec![
                DeviceSelector::Tag("ssd".into()),
                DeviceSelector::Class("high-mem".into()),
            ],
            excluded_devices: vec![DeviceSelector::NodeId(999)],
            target_coverage_bps: 8000,
            min_source_diversity: 3,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let back: ObjectPlacementPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back.min_nodes, 5);
        assert_eq!(back.max_node_fraction_bps, 2000);
        assert_eq!(back.preferred_devices.len(), 2);
        assert_eq!(back.excluded_devices.len(), 1);
        assert_eq!(back.target_coverage_bps, 8000);
        assert_eq!(back.min_source_diversity, 3);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ObjectHeader additional tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn object_header_with_multiple_refs() {
        let header = ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.test", "Multi", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 1_700_000_000,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![
                ObjectId::from_bytes([1_u8; 32]),
                ObjectId::from_bytes([2_u8; 32]),
                ObjectId::from_bytes([3_u8; 32]),
            ],
            foreign_refs: vec![ObjectId::from_bytes([10_u8; 32])],
            ttl_secs: None,
            placement: None,
        };
        let json = serde_json::to_string(&header).unwrap();
        let back: ObjectHeader = serde_json::from_str(&json).unwrap();
        assert_eq!(back.refs.len(), 3);
        assert_eq!(back.foreign_refs.len(), 1);
    }

    #[test]
    fn object_header_with_placement_policy() {
        let header = ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.test", "Placed", Version::new(1, 0, 0)),
            zone_id: ZoneId::community(),
            created_at: 2_000_000_000,
            provenance: Provenance::new(ZoneId::community()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: Some(86400),
            placement: Some(ObjectPlacementPolicy {
                min_nodes: 3,
                max_node_fraction_bps: 5000,
                preferred_devices: vec![],
                excluded_devices: vec![],
                target_coverage_bps: 10000,
                min_source_diversity: 2,
            }),
        };
        let json = serde_json::to_string(&header).unwrap();
        let back: ObjectHeader = serde_json::from_str(&json).unwrap();
        assert!(back.placement.is_some());
        assert_eq!(back.placement.unwrap().min_nodes, 3);
    }

    #[test]
    fn object_header_default_refs_on_deserialize() {
        let json = r#"{
            "schema": {"namespace":"fcp.test","name":"T","version":"1.0.0"},
            "zone_id": "z:work",
            "created_at": 0,
            "provenance": {"origin_zone":"z:work"}
        }"#;
        let header: ObjectHeader = serde_json::from_str(json).unwrap();
        assert!(header.refs.is_empty());
        assert!(header.foreign_refs.is_empty());
        assert!(header.ttl_secs.is_none());
        assert!(header.placement.is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RetentionClass additional tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn retention_class_equality() {
        assert_eq!(RetentionClass::Pinned, RetentionClass::Pinned);
        assert_eq!(RetentionClass::Ephemeral, RetentionClass::Ephemeral);
        assert_eq!(
            RetentionClass::Lease { expires_at: 100 },
            RetentionClass::Lease { expires_at: 100 }
        );
        assert_ne!(
            RetentionClass::Lease { expires_at: 100 },
            RetentionClass::Lease { expires_at: 200 }
        );
        assert_ne!(RetentionClass::Pinned, RetentionClass::Ephemeral);
    }

    #[test]
    fn retention_class_lease_zero_expiry() {
        let r = RetentionClass::Lease { expires_at: 0 };
        let json = serde_json::to_string(&r).unwrap();
        let back: RetentionClass = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, RetentionClass::Lease { expires_at: 0 }));
    }

    #[test]
    fn retention_class_lease_max_expiry() {
        let r = RetentionClass::Lease {
            expires_at: u64::MAX,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: RetentionClass = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            back,
            RetentionClass::Lease { expires_at } if expires_at == u64::MAX
        ));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // StoredObject additional tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn stored_object_canonical_bytes_deterministic() {
        let header = ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.test", "Det", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 999,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let body = b"deterministic body";
        let bytes1 = StoredObject::canonical_bytes(&header, body).unwrap();
        let bytes2 = StoredObject::canonical_bytes(&header, body).unwrap();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn stored_object_canonical_bytes_differ_by_header() {
        let header1 = ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.test", "A", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 100,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let header2 = ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.test", "B", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 100,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let body = b"same body";
        let bytes1 = StoredObject::canonical_bytes(&header1, body).unwrap();
        let bytes2 = StoredObject::canonical_bytes(&header2, body).unwrap();
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn stored_object_canonical_bytes_empty_body() {
        let header = ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.test", "Empty", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 0,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let result = StoredObject::canonical_bytes(&header, b"");
        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert!(bytes.starts_with(b"FCP2-OBJECT-V1"));
    }

    #[test]
    fn stored_object_derive_id_differs_by_key() {
        let header = ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.test", "Key", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 0,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let body = b"same body";
        let key1 = ObjectIdKey::from_bytes([1_u8; 32]);
        let key2 = ObjectIdKey::from_bytes([2_u8; 32]);

        let id1 = StoredObject::derive_id(&header, body, &key1).unwrap();
        let id2 = StoredObject::derive_id(&header, body, &key2).unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn stored_object_with_all_retention_classes() {
        let header = ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.test", "Ret", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 0,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let body = b"body".to_vec();
        let key = ObjectIdKey::from_bytes([0_u8; 32]);
        let object_id = StoredObject::derive_id(&header, &body, &key).unwrap();

        for retention in [
            RetentionClass::Pinned,
            RetentionClass::Ephemeral,
            RetentionClass::Lease {
                expires_at: 1_000_000,
            },
        ] {
            let stored = StoredObject {
                object_id,
                header: header.clone(),
                body: body.clone(),
                storage: StorageMeta { retention },
            };
            let json = serde_json::to_string(&stored).unwrap();
            let back: StoredObject = serde_json::from_str(&json).unwrap();
            assert_eq!(back.storage.retention, retention);
        }
    }

    #[test]
    fn stored_object_serde_preserves_refs() {
        let key = ObjectIdKey::from_bytes([0_u8; 32]);
        let ref1 = ObjectId::from_bytes([1_u8; 32]);
        let ref2 = ObjectId::from_bytes([2_u8; 32]);
        let foreign = ObjectId::from_bytes([10_u8; 32]);

        let header = ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.test", "Refs", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 500,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![ref1, ref2],
            foreign_refs: vec![foreign],
            ttl_secs: Some(7200),
            placement: None,
        };
        let body = b"ref-body".to_vec();
        let object_id = StoredObject::derive_id(&header, &body, &key).unwrap();

        let stored = StoredObject {
            object_id,
            header,
            body,
            storage: StorageMeta {
                retention: RetentionClass::Pinned,
            },
        };
        let json = serde_json::to_string(&stored).unwrap();
        let back: StoredObject = serde_json::from_str(&json).unwrap();

        assert_eq!(back.header.refs.len(), 2);
        assert_eq!(back.header.foreign_refs.len(), 1);
        assert_eq!(back.header.ttl_secs, Some(7200));
        assert_eq!(back.header.refs[0], ref1);
        assert_eq!(back.header.foreign_refs[0], foreign);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // StorageMeta tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn storage_meta_serde_roundtrip() {
        let meta = StorageMeta {
            retention: RetentionClass::Lease { expires_at: 42_000 },
        };
        let json = serde_json::to_string(&meta).unwrap();
        let back: StorageMeta = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            back.retention,
            RetentionClass::Lease { expires_at: 42_000 }
        ));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ObjectId copy/clone semantics
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn object_id_copy_semantics() {
        let id = ObjectId::from_bytes([5_u8; 32]);
        let copied = id;
        assert_eq!(id, copied);
    }

    #[test]
    fn object_id_clone_equals_copy() {
        let id = ObjectId::from_bytes([9_u8; 32]);
        let cloned = Clone::clone(&id);
        assert_eq!(id, cloned);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ObjectId additional hashing
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn object_id_different_bytes_not_equal() {
        let a = ObjectId::from_bytes([0_u8; 32]);
        let b = ObjectId::from_bytes([1_u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn object_id_hashset_dedup() {
        use std::collections::HashSet;
        let id = ObjectId::from_bytes([42_u8; 32]);
        let mut set = HashSet::new();
        set.insert(id);
        set.insert(id);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn object_id_hashmap_lookup() {
        use std::collections::HashMap;
        let id = ObjectId::from_bytes([77_u8; 32]);
        let mut map = HashMap::new();
        map.insert(id, "found");
        assert_eq!(map.get(&id), Some(&"found"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ObjectId ordering additional tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn object_id_ordering_equal() {
        let a = ObjectId::from_bytes([10_u8; 32]);
        let b = ObjectId::from_bytes([10_u8; 32]);
        assert!(a >= b);
        assert!(b >= a);
    }

    #[test]
    fn object_id_ordering_last_byte_differs() {
        let mut bytes_a = [0_u8; 32];
        bytes_a[31] = 5;
        let mut bytes_b = [0_u8; 32];
        bytes_b[31] = 6;
        let a = ObjectId::from_bytes(bytes_a);
        let b = ObjectId::from_bytes(bytes_b);
        assert!(a < b);
    }

    #[test]
    fn object_id_ordering_first_byte_dominates() {
        let mut bytes_a = [0_u8; 32];
        bytes_a[0] = 1;
        bytes_a[31] = 255;
        let mut bytes_b = [0_u8; 32];
        bytes_b[0] = 2;
        bytes_b[31] = 0;
        let a = ObjectId::from_bytes(bytes_a);
        let b = ObjectId::from_bytes(bytes_b);
        assert!(a < b);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ObjectId display and debug edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn object_id_display_all_zeros() {
        let id = ObjectId::from_bytes([0_u8; 32]);
        assert_eq!(id.to_string(), "00".repeat(32));
    }

    #[test]
    fn object_id_display_length() {
        let id = ObjectId::from_bytes([0xAB_u8; 32]);
        assert_eq!(id.to_string().len(), 64);
    }

    #[test]
    fn object_id_debug_contains_display() {
        let id = ObjectId::from_bytes([0x12_u8; 32]);
        let debug = format!("{id:?}");
        let display = id.to_string();
        assert!(debug.contains(&display));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ObjectId keyed constructor edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn object_id_keyed_empty_content() {
        let key = ObjectIdKey::from_bytes([0_u8; 32]);
        let zone: ZoneId = "z:work".parse().unwrap();
        let schema = SchemaId::new("fcp.test", "Test", Version::new(1, 0, 0));
        let id = ObjectId::new(b"", &zone, &schema, &key);
        assert_ne!(id, ObjectId::from_bytes([0_u8; 32]));
    }

    #[test]
    fn object_id_keyed_large_content() {
        let key = ObjectIdKey::from_bytes([0_u8; 32]);
        let zone: ZoneId = "z:work".parse().unwrap();
        let schema = SchemaId::new("fcp.test", "Test", Version::new(1, 0, 0));
        let large = vec![0xAB_u8; 10_000];
        let id = ObjectId::new(&large, &zone, &schema, &key);
        assert_ne!(id, ObjectId::from_bytes([0_u8; 32]));
    }

    #[test]
    fn object_id_keyed_same_content_same_result() {
        let key = ObjectIdKey::from_bytes([7_u8; 32]);
        let zone: ZoneId = "z:private".parse().unwrap();
        let schema = SchemaId::new("fcp.test", "Dup", Version::new(2, 0, 0));
        let id1 = ObjectId::new(b"dup", &zone, &schema, &key);
        let id2 = ObjectId::new(b"dup", &zone, &schema, &key);
        assert_eq!(id1, id2);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ObjectId unscoped edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn object_id_unscoped_single_byte() {
        let id = ObjectId::from_unscoped_bytes(&[42]);
        assert_ne!(id, ObjectId::from_bytes([0_u8; 32]));
    }

    #[test]
    fn object_id_unscoped_large_content() {
        let large = vec![0xFF_u8; 100_000];
        let id = ObjectId::from_unscoped_bytes(&large);
        assert_ne!(id, ObjectId::from_bytes([0_u8; 32]));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ObjectId serde additional tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn object_id_json_serde_mixed_bytes() {
        let mut bytes = [0_u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = u8::try_from(i).unwrap();
        }
        let id = ObjectId::from_bytes(bytes);
        let json = serde_json::to_string(&id).unwrap();
        let back: ObjectId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn object_id_cbor_serde_roundtrip() {
        let id = ObjectId::from_bytes([0xBE_u8; 32]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&id, &mut buf).unwrap();
        let back: ObjectId = ciborium::de::from_reader(&buf[..]).unwrap();
        assert_eq!(id, back);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ObjectIdKey additional tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn object_id_key_copy_semantics() {
        let key = ObjectIdKey::from_bytes([0xAA_u8; 32]);
        let copied = key;
        assert_eq!(key, copied);
    }

    #[test]
    fn object_id_key_zero_bytes() {
        let key = ObjectIdKey::from_bytes([0_u8; 32]);
        assert_eq!(key.as_bytes(), &[0_u8; 32]);
    }

    #[test]
    fn object_id_key_max_bytes() {
        let key = ObjectIdKey::from_bytes([0xFF_u8; 32]);
        assert_eq!(key.as_bytes(), &[0xFF_u8; 32]);
    }

    #[test]
    fn object_id_key_debug_format_consistent() {
        let key1 = ObjectIdKey::from_bytes([1_u8; 32]);
        let key2 = ObjectIdKey::from_bytes([2_u8; 32]);
        let debug1 = format!("{key1:?}");
        let debug2 = format!("{key2:?}");
        // Both should have the same redacted format regardless of content
        assert_eq!(debug1, debug2);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DeviceSelector additional tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn device_selector_tag_empty_string() {
        let sel = DeviceSelector::Tag(String::new());
        let json = serde_json::to_string(&sel).unwrap();
        let back: DeviceSelector = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, DeviceSelector::Tag(ref s) if s.is_empty()));
    }

    #[test]
    fn device_selector_class_with_special_chars() {
        let sel = DeviceSelector::Class("high-mem-v2.1".into());
        let json = serde_json::to_string(&sel).unwrap();
        let back: DeviceSelector = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, DeviceSelector::Class(ref s) if s == "high-mem-v2.1"));
    }

    #[test]
    fn device_selector_has_capability_with_dots() {
        let sel = DeviceSelector::HasCapability("gpu.compute.v3".into());
        let json = serde_json::to_string(&sel).unwrap();
        let back: DeviceSelector = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, DeviceSelector::HasCapability(ref s) if s == "gpu.compute.v3"));
    }

    #[test]
    fn device_selector_zone_different_zones() {
        for zone in [ZoneId::work(), ZoneId::private(), ZoneId::public()] {
            let sel = DeviceSelector::Zone(zone.clone());
            let json = serde_json::to_string(&sel).unwrap();
            let back: DeviceSelector = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&back).unwrap();
            assert_eq!(json, json2);
        }
    }

    #[test]
    fn device_selector_debug_format() {
        let sel = DeviceSelector::Tag("test".into());
        let debug = format!("{sel:?}");
        assert!(debug.contains("Tag"));
        assert!(debug.contains("test"));
    }

    #[test]
    fn device_selector_clone() {
        let sel = DeviceSelector::Class("high-mem".into());
        let cloned = sel.clone();
        let json_orig = serde_json::to_string(&sel).unwrap();
        let json_clone = serde_json::to_string(&cloned).unwrap();
        assert_eq!(json_orig, json_clone);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ObjectPlacementPolicy additional tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn placement_policy_boundary_min_nodes_max() {
        let policy = ObjectPlacementPolicy {
            min_nodes: u8::MAX,
            max_node_fraction_bps: 10000,
            preferred_devices: vec![],
            excluded_devices: vec![],
            target_coverage_bps: 10000,
            min_source_diversity: u8::MAX,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let back: ObjectPlacementPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back.min_nodes, u8::MAX);
        assert_eq!(back.min_source_diversity, u8::MAX);
    }

    #[test]
    fn placement_policy_max_node_fraction_boundary() {
        let policy = ObjectPlacementPolicy {
            min_nodes: 1,
            max_node_fraction_bps: u16::MAX,
            preferred_devices: vec![],
            excluded_devices: vec![],
            target_coverage_bps: u32::MAX,
            min_source_diversity: 0,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let back: ObjectPlacementPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back.max_node_fraction_bps, u16::MAX);
        assert_eq!(back.target_coverage_bps, u32::MAX);
    }

    #[test]
    fn placement_policy_many_preferred_devices() {
        let policy = ObjectPlacementPolicy {
            min_nodes: 2,
            max_node_fraction_bps: 5000,
            preferred_devices: (0..10)
                .map(|i| DeviceSelector::Tag(format!("tag-{i}")))
                .collect(),
            excluded_devices: (0..5).map(DeviceSelector::NodeId).collect(),
            target_coverage_bps: 8000,
            min_source_diversity: 1,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let back: ObjectPlacementPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back.preferred_devices.len(), 10);
        assert_eq!(back.excluded_devices.len(), 5);
    }

    #[test]
    fn placement_policy_clone() {
        let policy = ObjectPlacementPolicy {
            min_nodes: 3,
            max_node_fraction_bps: 5000,
            preferred_devices: vec![DeviceSelector::Tag("ssd".into())],
            excluded_devices: vec![],
            target_coverage_bps: 10000,
            min_source_diversity: 2,
        };
        let cloned = Clone::clone(&policy);
        assert_eq!(cloned.min_nodes, 3);
        assert_eq!(cloned.preferred_devices.len(), 1);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ObjectHeader additional edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn object_header_large_refs_list() {
        let header = ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.test", "BigRefs", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 1_000,
            provenance: Provenance::new(ZoneId::work()),
            refs: (0..50)
                .map(|i| {
                    let mut bytes = [0_u8; 32];
                    bytes[0] = i;
                    ObjectId::from_bytes(bytes)
                })
                .collect(),
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let json = serde_json::to_string(&header).unwrap();
        let back: ObjectHeader = serde_json::from_str(&json).unwrap();
        assert_eq!(back.refs.len(), 50);
    }

    #[test]
    fn object_header_ttl_zero() {
        let header = ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.test", "TTL0", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 0,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: Some(0),
            placement: None,
        };
        let json = serde_json::to_string(&header).unwrap();
        let back: ObjectHeader = serde_json::from_str(&json).unwrap();
        assert_eq!(back.ttl_secs, Some(0));
    }

    #[test]
    fn object_header_ttl_max() {
        let header = ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.test", "TTLMax", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 0,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: Some(u64::MAX),
            placement: None,
        };
        let json = serde_json::to_string(&header).unwrap();
        let back: ObjectHeader = serde_json::from_str(&json).unwrap();
        assert_eq!(back.ttl_secs, Some(u64::MAX));
    }

    #[test]
    fn object_header_clone() {
        let header = ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.test", "Clonable", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 42,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![ObjectId::from_bytes([1_u8; 32])],
            foreign_refs: vec![ObjectId::from_bytes([2_u8; 32])],
            ttl_secs: Some(100),
            placement: None,
        };
        let cloned = Clone::clone(&header);
        assert_eq!(cloned.created_at, 42);
        assert_eq!(cloned.refs.len(), 1);
        assert_eq!(cloned.foreign_refs.len(), 1);
        assert_eq!(cloned.ttl_secs, Some(100));
    }

    #[test]
    fn object_header_different_zones() {
        for zone in [
            ZoneId::work(),
            ZoneId::private(),
            ZoneId::public(),
            ZoneId::community(),
        ] {
            let header = ObjectHeader {
                encryption_kind: Default::default(),
                schema: SchemaId::new("fcp.test", "Zone", Version::new(1, 0, 0)),
                zone_id: zone.clone(),
                created_at: 0,
                provenance: Provenance::new(zone.clone()),
                refs: vec![],
                foreign_refs: vec![],
                ttl_secs: None,
                placement: None,
            };
            let json = serde_json::to_string(&header).unwrap();
            let back: ObjectHeader = serde_json::from_str(&json).unwrap();
            assert_eq!(back.zone_id, zone);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RetentionClass additional tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn retention_class_copy_semantics() {
        let r = RetentionClass::Pinned;
        let copied = r;
        assert_eq!(r, copied);
    }

    #[test]
    fn retention_class_clone_lease() {
        let r = RetentionClass::Lease { expires_at: 500 };
        let cloned = r;
        assert_eq!(r, cloned);
    }

    #[test]
    fn retention_class_debug_format() {
        let pinned = RetentionClass::Pinned;
        assert_eq!(format!("{pinned:?}"), "Pinned");

        let eph = RetentionClass::Ephemeral;
        assert_eq!(format!("{eph:?}"), "Ephemeral");

        let lease = RetentionClass::Lease { expires_at: 100 };
        let debug = format!("{lease:?}");
        assert!(debug.contains("Lease"));
        assert!(debug.contains("100"));
    }

    #[test]
    fn retention_class_cbor_roundtrip() {
        for r in [
            RetentionClass::Pinned,
            RetentionClass::Ephemeral,
            RetentionClass::Lease { expires_at: 42 },
        ] {
            let mut buf = Vec::new();
            ciborium::ser::into_writer(&r, &mut buf).unwrap();
            let back: RetentionClass = ciborium::de::from_reader(&buf[..]).unwrap();
            assert_eq!(r, back);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // StoredObject additional tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn stored_object_canonical_bytes_includes_header_cbor() {
        let header = ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.test", "CborCheck", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 42,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let body = b"body";
        let canonical = StoredObject::canonical_bytes(&header, body).unwrap();
        let header_cbor = fcp_cbor::to_canonical_cbor(&header).unwrap();
        // The canonical bytes should contain the header CBOR after the prefix
        let prefix_len = b"FCP2-OBJECT-V1".len();
        let header_section = &canonical[prefix_len..prefix_len + header_cbor.len()];
        assert_eq!(header_section, &header_cbor[..]);
    }

    #[test]
    fn stored_object_derive_id_differs_by_zone() {
        let key = ObjectIdKey::from_bytes([0_u8; 32]);
        let body = b"same body";

        let header1 = ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.test", "Zone", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 0,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let header2 = ObjectHeader {
            encryption_kind: Default::default(),
            zone_id: ZoneId::private(),
            provenance: Provenance::new(ZoneId::private()),
            ..header1.clone()
        };

        let id1 = StoredObject::derive_id(&header1, body, &key).unwrap();
        let id2 = StoredObject::derive_id(&header2, body, &key).unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn stored_object_clone() {
        let key = ObjectIdKey::from_bytes([0_u8; 32]);
        let header = ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.test", "Clone", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 0,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let body = b"body".to_vec();
        let object_id = StoredObject::derive_id(&header, &body, &key).unwrap();
        let stored = StoredObject {
            object_id,
            header,
            body: body.clone(),
            storage: StorageMeta {
                retention: RetentionClass::Ephemeral,
            },
        };
        let cloned = Clone::clone(&stored);
        assert_eq!(cloned.object_id, object_id);
        assert_eq!(cloned.body, body);
        assert_eq!(cloned.storage.retention, RetentionClass::Ephemeral);
    }

    #[test]
    fn stored_object_empty_body_derive_id() {
        let key = ObjectIdKey::from_bytes([0_u8; 32]);
        let header = ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.test", "Empty", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 0,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let id = StoredObject::derive_id(&header, b"", &key);
        assert!(id.is_ok());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // StorageMeta additional tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn storage_meta_clone() {
        let meta = StorageMeta {
            retention: RetentionClass::Pinned,
        };
        let cloned = Clone::clone(&meta);
        assert_eq!(cloned.retention, RetentionClass::Pinned);
    }

    #[test]
    fn storage_meta_debug_format() {
        let meta = StorageMeta {
            retention: RetentionClass::Ephemeral,
        };
        let debug = format!("{meta:?}");
        assert!(debug.contains("StorageMeta"));
        assert!(debug.contains("Ephemeral"));
    }

    #[test]
    fn storage_meta_with_lease_retention() {
        let meta = StorageMeta {
            retention: RetentionClass::Lease {
                expires_at: 1_700_000_000,
            },
        };
        let json = serde_json::to_string(&meta).unwrap();
        assert!(json.contains("1700000000"));
        let back: StorageMeta = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            back.retention,
            RetentionClass::Lease {
                expires_at: 1_700_000_000
            }
        ));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ObjectId as_ref identity
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn object_id_as_ref_length() {
        let id = ObjectId::from_bytes([0_u8; 32]);
        let slice: &[u8] = id.as_ref();
        assert_eq!(slice.len(), 32);
    }

    #[test]
    fn object_id_as_ref_matches_as_bytes() {
        let bytes = [0xCD_u8; 32];
        let id = ObjectId::from_bytes(bytes);
        let as_ref: &[u8] = id.as_ref();
        let as_bytes: &[u8; 32] = id.as_bytes();
        assert_eq!(as_ref, as_bytes.as_slice());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ObjectId test_id edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn object_id_test_id_empty_name() {
        let id = ObjectId::test_id("");
        assert_ne!(id, ObjectId::from_bytes([0_u8; 32]));
    }

    #[test]
    fn object_id_test_id_long_name() {
        let long_name = "a".repeat(1000);
        let id = ObjectId::test_id(&long_name);
        assert_ne!(id, ObjectId::from_bytes([0_u8; 32]));
    }

    #[test]
    fn object_id_test_id_unicode_name() {
        let id = ObjectId::test_id("hello-world");
        assert_ne!(id, ObjectId::from_bytes([0_u8; 32]));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ObjectId golden vector with different schema versions
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn object_id_differs_by_schema_version() {
        let key = ObjectIdKey::from_bytes([0_u8; 32]);
        let zone: ZoneId = "z:work".parse().unwrap();
        let schema_v1 = SchemaId::new("fcp.test", "Test", Version::new(1, 0, 0));
        let schema_v2 = SchemaId::new("fcp.test", "Test", Version::new(2, 0, 0));
        let content = b"same";

        let id_v1 = ObjectId::new(content, &zone, &schema_v1, &key);
        let id_v2 = ObjectId::new(content, &zone, &schema_v2, &key);
        assert_ne!(id_v1, id_v2);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ObjectHeader with cbor roundtrip
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn object_header_cbor_roundtrip() {
        let header = ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.test", "Cbor", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 555,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![ObjectId::from_bytes([1_u8; 32])],
            foreign_refs: vec![],
            ttl_secs: Some(300),
            placement: None,
        };
        let cbor = fcp_cbor::to_canonical_cbor(&header).unwrap();
        let back: ObjectHeader = ciborium::de::from_reader(&cbor[..]).unwrap();
        assert_eq!(back.created_at, 555);
        assert_eq!(back.refs.len(), 1);
        assert_eq!(back.ttl_secs, Some(300));
    }
}
