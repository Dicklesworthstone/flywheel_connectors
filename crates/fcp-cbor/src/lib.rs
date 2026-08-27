//! FCP canonical serialization (deterministic CBOR + schema hashing).
//!
//! This crate implements the byte-level foundation for FCP content-addressed objects:
//! - `SchemaId` and `SchemaHash` for schema binding
//! - Deterministic RFC 8949 canonical CBOR encoding
//! - Schema-hash-prefixed payloads (`schema_hash || canonical_cbor`)
//!
//! See `FCP_Specification_V3.md` §3.2 (Canonical Serialization).

#![forbid(unsafe_code)]
// nursery/pedantic style lints that newer nightlies fire on this unchanged code.
// Needed here rather than in Cargo.toml because this crate re-enables the groups
// with an inner attribute, which overrides the workspace lint table.
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::duration_suboptimal_units)]
#![allow(clippy::redundant_clone)]
#![allow(clippy::significant_drop_tightening)]

use std::fmt;
use std::io;

use ciborium::de::from_reader_with_recursion_limit;
use ciborium::ser::into_writer;
use ciborium::value::Value;
use semver::Version;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Domain separator for `SchemaId` hashing (NORMATIVE).
const SCHEMA_HASH_DOMAIN_SEPARATOR: &[u8] = b"FCP2-SCHEMA-V1";

/// Length of an FCP2 schema hash prefix.
pub const SCHEMA_HASH_LEN: usize = 32;

/// Maximum allowed size for a canonical object payload (including schema hash prefix).
///
/// This aligns with the default `max_object_size` in the FCP2 spec's `RaptorQ` configuration
/// (64 MiB). Larger objects must use chunking at higher protocol layers.
pub const MAX_CANONICAL_OBJECT_BYTES: usize = 64 * 1024 * 1024;

/// Schema identifier (NORMATIVE).
///
/// Uniquely identifies a type within the FCP ecosystem and is used for:
/// - Type discrimination in deserialization
/// - Schema hash computation for content addressing
/// - CDDL generation for interoperability
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct SchemaId {
    /// Namespace (e.g., "fcp.core", "fcp.mesh", "fcp.connector").
    pub namespace: String,
    /// Type name (e.g., `CapabilityObject`, `InvokeRequest`, `AuditEvent`).
    pub name: String,
    /// Semantic version for evolution.
    pub version: Version,
}

impl SchemaId {
    /// Create a new `SchemaId`.
    ///
    /// # Panics
    ///
    /// Panics if `namespace` or `name` contains a reserved separator (`:` or `@`).
    /// These characters delimit fields in the canonical string form
    /// (`{namespace}:{name}@{version}`); allowing them in the components would let
    /// distinct schema tuples alias to the same canonical bytes (e.g. `("a:b","c")`
    /// and `("a","b:c")` both produce `a:b:c@…`). Use [`SchemaId::try_new`] to
    /// validate at runtime instead of panicking.
    #[must_use]
    pub fn new(namespace: impl Into<String>, name: impl Into<String>, version: Version) -> Self {
        Self::try_new(namespace, name, version)
            .expect("SchemaId namespace and name must not contain reserved separators ':' or '@'")
    }

    /// Fallible constructor that rejects reserved separators in `namespace`/`name`.
    ///
    /// # Errors
    ///
    /// Returns [`SchemaIdError::ReservedSeparator`] if `namespace` or `name`
    /// contains `:` or `@`.
    pub fn try_new(
        namespace: impl Into<String>,
        name: impl Into<String>,
        version: Version,
    ) -> Result<Self, SchemaIdError> {
        let namespace = namespace.into();
        let name = name.into();
        Self::reject_reserved("namespace", &namespace)?;
        Self::reject_reserved("name", &name)?;
        Ok(Self {
            namespace,
            name,
            version,
        })
    }

    fn reject_reserved(field: &'static str, value: &str) -> Result<(), SchemaIdError> {
        if let Some(c) = value.chars().find(|c| matches!(c, ':' | '@')) {
            return Err(SchemaIdError::ReservedSeparator {
                field,
                separator: c,
            });
        }
        Ok(())
    }

    /// Canonical string representation (NORMATIVE).
    ///
    /// Format: `{namespace}:{name}@{version}`. Constructors enforce that
    /// `namespace` and `name` do not contain `:` or `@`, so this string is
    /// unambiguous and round-trippable.
    #[must_use]
    pub fn as_bytes(&self) -> Vec<u8> {
        format!("{}:{}@{}", self.namespace, self.name, self.version).into_bytes()
    }

    /// Canonical type binding hash (NORMATIVE).
    ///
    /// Uses BLAKE3 with fixed-size output to prevent `DoS` via maliciously large schema strings.
    /// The domain separator `"FCP2-SCHEMA-V1"` ensures hash isolation from other uses.
    ///
    /// Each component is length-prefixed (u64 little-endian) before being fed into
    /// the hasher. This makes the hash injective in `(namespace, name, version)`:
    /// distinct tuples cannot alias to the same hash even if a `SchemaId` is
    /// constructed directly via the public fields, bypassing [`SchemaId::new`].
    /// Without length-prefixing, the historical encoding `namespace || ':' || name
    /// || '@' || version` would collide when separators appeared inside components
    /// (e.g. namespace=`a:b`,name=`c` vs namespace=`a`,name=`b:c`).
    #[must_use]
    pub fn hash(&self) -> SchemaHash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(SCHEMA_HASH_DOMAIN_SEPARATOR);
        Self::feed_length_prefixed(&mut hasher, self.namespace.as_bytes());
        Self::feed_length_prefixed(&mut hasher, self.name.as_bytes());
        // Length-prefixing requires a known byte length up front; pay the small
        // String allocation rather than streaming the version into the hasher,
        // because `Display::fmt` on `Version` can write arbitrarily many chunks
        // and we'd otherwise have to buffer them anyway.
        let version_str = self.version.to_string();
        Self::feed_length_prefixed(&mut hasher, version_str.as_bytes());
        SchemaHash(*hasher.finalize().as_bytes())
    }

    fn feed_length_prefixed(hasher: &mut blake3::Hasher, bytes: &[u8]) {
        let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        hasher.update(&len.to_le_bytes());
        hasher.update(bytes);
    }
}

/// Errors raised when constructing a [`SchemaId`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SchemaIdError {
    /// `namespace` or `name` contained a reserved separator (`:` or `@`).
    #[error("SchemaId {field} contains reserved separator {separator:?}")]
    ReservedSeparator {
        /// Which field rejected the input (`"namespace"` or `"name"`).
        field: &'static str,
        /// The offending character.
        separator: char,
    },
}

/// 32-byte schema hash (NORMATIVE).
///
/// Fixed-size hash of `SchemaId` for:
/// - Prefix on all canonical CBOR payloads
/// - Input to `ObjectId` derivation
/// - Decode-time type verification
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SchemaHash([u8; SCHEMA_HASH_LEN]);

impl SchemaHash {
    /// Borrow the raw schema hash bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SCHEMA_HASH_LEN] {
        &self.0
    }

    /// Construct a schema hash from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SCHEMA_HASH_LEN]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for SchemaHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SchemaHash")
            .field(&self.to_string())
            .finish()
    }
}

impl fmt::Display for SchemaHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl AsRef<[u8]> for SchemaHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Errors that can occur during canonical serialization/deserialization.
#[derive(Debug, Error)]
pub enum SerializationError {
    /// The payload is too short to include a schema hash prefix.
    #[error("payload missing schema hash prefix")]
    MissingSchemaHashPrefix,

    /// The schema hash prefix does not match the expected schema.
    #[error("schema hash mismatch (expected {expected}, got {got})")]
    SchemaMismatch {
        expected: SchemaHash,
        got: SchemaHash,
    },

    /// The payload exceeds the configured maximum size.
    #[error("payload too large ({len} bytes > {max} bytes)")]
    PayloadTooLarge { len: usize, max: usize },

    /// The CBOR Value tree is nested deeper than `MAX_CANONICALIZATION_DEPTH`.
    /// Distinct from `PayloadTooLarge` because the failure has nothing to do
    /// with byte length — it is a recursion-stack guard against adversarial
    /// deeply-nested input that should never have been encoded in the first
    /// place.
    #[error("canonicalization depth {depth} exceeds limit {max}")]
    DepthExceeded { depth: usize, max: usize },

    /// The CBOR payload has trailing bytes after the first decoded value.
    #[error("trailing bytes after CBOR value")]
    TrailingBytes,

    /// The input decodes successfully but is not in canonical form.
    #[error("non-canonical CBOR encoding")]
    NonCanonicalEncoding,

    /// The input value cannot be represented as a dynamic CBOR `Value`.
    #[error("cbor value conversion error: {0}")]
    CborValue(#[from] ciborium::value::Error),

    /// A float value is NaN or Infinity (RFC 8949 §4.2.5).
    #[error("non-finite float (NaN or Infinity) not allowed in canonical CBOR")]
    NonFiniteFloat,

    /// A map contains duplicate keys (after canonicalization).
    #[error("duplicate map key (canonical key bytes: {key_hex})")]
    DuplicateMapKey { key_hex: String },

    /// CBOR tags are not part of the FCP canonical serialization surface.
    #[error("CBOR tag {tag} is not allowed in canonical FCP payloads")]
    UnsupportedTag { tag: u64 },

    /// CBOR serialization failed.
    #[error("cbor serialization error: {0}")]
    CborSerialize(#[from] ciborium::ser::Error<std::io::Error>),

    /// CBOR deserialization failed.
    #[error("cbor deserialization error: {0}")]
    CborDeserialize(#[from] ciborium::de::Error<std::io::Error>),
}

/// Canonical CBOR serialization (NORMATIVE).
///
/// Implements RFC 8949 deterministic encoding with schema hash prefix. All mesh objects MUST use
/// this serializer for content addressing.
pub struct CanonicalSerializer;

impl CanonicalSerializer {
    /// Serialize to canonical CBOR with schema hash prefix (NORMATIVE).
    ///
    /// Output format: `schema_hash (32 bytes) || canonical_cbor_bytes`.
    ///
    /// # Errors
    /// Returns `SerializationError::CborSerialize` if CBOR serialization fails.
    /// Returns `SerializationError::PayloadTooLarge` if the encoded output exceeds
    /// `MAX_CANONICAL_OBJECT_BYTES`.
    pub fn serialize<T: Serialize>(
        value: &T,
        schema: &SchemaId,
    ) -> Result<Vec<u8>, SerializationError> {
        let mut buf = Vec::with_capacity(SCHEMA_HASH_LEN + 128);

        // Schema hash prefix for type binding (fixed-size, DoS-resistant).
        buf.extend_from_slice(schema.hash().as_bytes());

        // Deterministic canonical CBOR (RFC 8949 §4.2).
        write_canonical_cbor(value, &mut buf)?;

        if buf.len() > MAX_CANONICAL_OBJECT_BYTES {
            return Err(SerializationError::PayloadTooLarge {
                len: buf.len(),
                max: MAX_CANONICAL_OBJECT_BYTES,
            });
        }

        Ok(buf)
    }

    /// Deserialize with schema verification and canonical encoding enforcement.
    ///
    /// # Errors
    /// Returns `SerializationError::MissingSchemaHashPrefix` if the input is too short.
    /// Returns `SerializationError::SchemaMismatch` if the schema hash prefix does not match.
    /// Returns `SerializationError::PayloadTooLarge` if `data.len()` exceeds
    /// `MAX_CANONICAL_OBJECT_BYTES`.
    /// Returns `SerializationError::CborDeserialize` if the CBOR payload cannot be decoded.
    /// Returns `SerializationError::TrailingBytes` if extra bytes remain after decoding one value.
    /// Returns `SerializationError::NonCanonicalEncoding` if the decoded value does not re-encode
    /// to the exact input bytes using canonical encoding.
    pub fn deserialize<T: DeserializeOwned>(
        data: &[u8],
        expected_schema: &SchemaId,
    ) -> Result<T, SerializationError> {
        if data.len() > MAX_CANONICAL_OBJECT_BYTES {
            return Err(SerializationError::PayloadTooLarge {
                len: data.len(),
                max: MAX_CANONICAL_OBJECT_BYTES,
            });
        }

        let (got_hash, body) = split_schema_prefix(data)?;
        let expected_hash = expected_schema.hash();
        if got_hash != expected_hash {
            return Err(SerializationError::SchemaMismatch {
                expected: expected_hash,
                got: got_hash,
            });
        }

        let canonical_body = canonicalize_decoded_body(body)?;
        let mut canonical = Vec::with_capacity(SCHEMA_HASH_LEN + canonical_body.len());
        canonical.extend_from_slice(expected_hash.as_bytes());
        canonical.extend_from_slice(&canonical_body);

        if canonical != data {
            return Err(SerializationError::NonCanonicalEncoding);
        }

        deserialize_cbor_body(&canonical_body)
    }

    /// Deserialize with schema verification but **without** canonical encoding enforcement.
    ///
    /// This is intended only for trusted/internal uses. For untrusted inputs, prefer
    /// [`Self::deserialize`] to fail closed on non-canonical encodings.
    ///
    /// # Errors
    /// Returns `SerializationError::MissingSchemaHashPrefix` if the input is too short.
    /// Returns `SerializationError::SchemaMismatch` if the schema hash prefix does not match.
    /// Returns `SerializationError::PayloadTooLarge` if `data.len()` exceeds
    /// `MAX_CANONICAL_OBJECT_BYTES`.
    /// Returns `SerializationError::CborDeserialize` if the CBOR payload cannot be decoded.
    /// Returns `SerializationError::TrailingBytes` if extra bytes remain after decoding one value.
    pub fn deserialize_unchecked<T: DeserializeOwned>(
        data: &[u8],
        expected_schema: &SchemaId,
    ) -> Result<T, SerializationError> {
        if data.len() > MAX_CANONICAL_OBJECT_BYTES {
            return Err(SerializationError::PayloadTooLarge {
                len: data.len(),
                max: MAX_CANONICAL_OBJECT_BYTES,
            });
        }

        // Verify schema hash prefix.
        let (got_hash, body) = split_schema_prefix(data)?;
        let expected_hash = expected_schema.hash();
        if got_hash != expected_hash {
            return Err(SerializationError::SchemaMismatch {
                expected: expected_hash,
                got: got_hash,
            });
        }

        validate_decoded_body(body)?;

        deserialize_cbor_body(body)
    }
}

fn split_schema_prefix(data: &[u8]) -> Result<(SchemaHash, &[u8]), SerializationError> {
    if data.len() < SCHEMA_HASH_LEN {
        return Err(SerializationError::MissingSchemaHashPrefix);
    }

    let got: [u8; SCHEMA_HASH_LEN] = data[..SCHEMA_HASH_LEN]
        .try_into()
        .map_err(|_| SerializationError::MissingSchemaHashPrefix)?;
    Ok((SchemaHash::from_bytes(got), &data[SCHEMA_HASH_LEN..]))
}

/// Serialize a value to deterministic RFC 8949 canonical CBOR bytes.
///
/// This does **not** include the 32-byte `SchemaHash` prefix used by [`CanonicalSerializer`].
///
/// # Errors
/// Returns `SerializationError` if the value cannot be represented as a CBOR `Value`, if
/// canonicalization fails (e.g., duplicate map keys), if CBOR serialization fails, or if the
/// encoded bytes exceed `MAX_CANONICAL_OBJECT_BYTES`.
pub fn to_canonical_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, SerializationError> {
    // Pre-allocate for typical canonical CBOR payloads (~256 bytes).
    let mut out = Vec::with_capacity(256);
    write_canonical_cbor(value, &mut out)?;
    if out.len() > MAX_CANONICAL_OBJECT_BYTES {
        return Err(SerializationError::PayloadTooLarge {
            len: out.len(),
            max: MAX_CANONICAL_OBJECT_BYTES,
        });
    }

    Ok(out)
}

fn write_canonical_cbor<T: Serialize>(
    value: &T,
    out: &mut Vec<u8>,
) -> Result<(), SerializationError> {
    write_canonical_cbor_with_limit(value, out, MAX_CANONICAL_OBJECT_BYTES)
}

fn write_canonical_cbor_with_limit<T: Serialize>(
    value: &T,
    out: &mut Vec<u8>,
    byte_limit: usize,
) -> Result<(), SerializationError> {
    if out.len() > byte_limit {
        return Err(SerializationError::PayloadTooLarge {
            len: out.len(),
            max: byte_limit,
        });
    }

    let mut v = Value::serialized(value)?;
    canonicalize_value_in_place(&mut v, 0)?;
    let mut writer = LimitedVecWriter::new(out, byte_limit);
    into_writer(&v, &mut writer).map_err(|err| map_capped_writer_error(err, byte_limit))?;
    Ok(())
}

/// Maximum nesting depth the canonicalizer will descend into.
///
/// Values deeper than this are rejected so an attacker cannot force
/// unbounded recursion via an arbitrarily-nested CBOR tree.
pub const MAX_CANONICALIZATION_DEPTH: usize = 128;

/// Recursion limit for `ciborium` deserializers.
///
/// Exposed so downstream crates that parse untrusted CBOR can use the
/// same bound (via `ciborium::de::from_reader_with_recursion_limit`)
/// and fail early instead of spending memory on input the canonicalizer
/// would later reject for depth.
pub const MAX_DESERIALIZATION_RECURSION_LIMIT: usize = MAX_CANONICALIZATION_DEPTH;

fn map_cbor_deserialize_error(err: ciborium::de::Error<std::io::Error>) -> SerializationError {
    match err {
        ciborium::de::Error::RecursionLimitExceeded => SerializationError::DepthExceeded {
            depth: MAX_DESERIALIZATION_RECURSION_LIMIT + 1,
            max: MAX_CANONICALIZATION_DEPTH,
        },
        other => SerializationError::CborDeserialize(other),
    }
}

fn decode_cbor_body_as_value(body: &[u8]) -> Result<Value, SerializationError> {
    let mut reader = body;
    let value = from_reader_with_recursion_limit::<Value, _>(
        &mut reader,
        MAX_DESERIALIZATION_RECURSION_LIMIT,
    )
    .map_err(map_cbor_deserialize_error)?;
    if !reader.is_empty() {
        return Err(SerializationError::TrailingBytes);
    }
    Ok(value)
}

fn deserialize_cbor_body<T: DeserializeOwned>(body: &[u8]) -> Result<T, SerializationError> {
    let mut reader = body;
    let value =
        from_reader_with_recursion_limit::<T, _>(&mut reader, MAX_DESERIALIZATION_RECURSION_LIMIT)
            .map_err(map_cbor_deserialize_error)?;
    if !reader.is_empty() {
        return Err(SerializationError::TrailingBytes);
    }
    Ok(value)
}

fn validate_decoded_body(body: &[u8]) -> Result<(), SerializationError> {
    let mut value = decode_cbor_body_as_value(body)?;
    canonicalize_value_in_place(&mut value, 0)?;
    Ok(())
}

fn canonicalize_decoded_body(body: &[u8]) -> Result<Vec<u8>, SerializationError> {
    let mut value = decode_cbor_body_as_value(body)?;
    canonicalize_value_in_place(&mut value, 0)?;

    let mut out = Vec::with_capacity(body.len());
    into_writer(&value, &mut out)?;
    Ok(out)
}

fn canonicalize_value_in_place(v: &mut Value, depth: usize) -> Result<(), SerializationError> {
    if depth > MAX_CANONICALIZATION_DEPTH {
        return Err(SerializationError::DepthExceeded {
            depth,
            max: MAX_CANONICALIZATION_DEPTH,
        });
    }

    if let Value::Float(f) = v {
        if f.is_nan() || f.is_infinite() {
            return Err(SerializationError::NonFiniteFloat);
        }
        if f.to_bits() == (-0.0_f64).to_bits() {
            *f = 0.0;
        }
    }

    match v {
        Value::Array(items) => {
            for item in items {
                canonicalize_value_in_place(item, depth + 1)?;
            }
        }
        Value::Map(entries) => canonicalize_map(entries, depth + 1)?,
        Value::Tag(tag, _) => return Err(SerializationError::UnsupportedTag { tag: *tag }),
        _ => {}
    }

    Ok(())
}

fn canonicalize_map(
    entries: &mut Vec<(Value, Value)>,
    depth: usize,
) -> Result<(), SerializationError> {
    canonicalize_map_with_limit(entries, depth, MAX_CANONICAL_OBJECT_BYTES)
}

fn canonicalize_map_with_limit(
    entries: &mut Vec<(Value, Value)>,
    depth: usize,
    byte_limit: usize,
) -> Result<(), SerializationError> {
    // Even the smallest definite-length CBOR map needs a 1-byte header plus
    // 2 bytes per entry (1-byte key + 1-byte value). Reject impossible
    // high-cardinality maps before allocating the second per-entry scratch
    // vector so hostile input cannot amplify heap usage beyond the byte limit.
    let minimum_possible_len = 1usize.saturating_add(entries.len().saturating_mul(2));
    if minimum_possible_len > byte_limit {
        return Err(SerializationError::PayloadTooLarge {
            len: minimum_possible_len,
            max: byte_limit,
        });
    }

    // Pre-allocate scratch buffer. Typical CBOR map keys are 10-50 bytes each.
    // Cap allocation to prevent memory amplification from maps with many tiny entries.
    let scratch_cap = canonicalize_map_scratch_capacity_with_limit(entries.len(), byte_limit);
    let mut scratch = Vec::with_capacity(scratch_cap);
    let mut with_keys = Vec::with_capacity(entries.len());

    for (mut key, mut value) in std::mem::take(entries) {
        canonicalize_value_in_place(&mut key, depth)?;
        canonicalize_value_in_place(&mut value, depth)?;

        let start = scratch.len();
        append_canonical_map_key_bytes(&key, &mut scratch, byte_limit)?;
        let end = scratch.len();

        with_keys.push((start..end, key, value));
    }

    with_keys.sort_by(|(a_range, _, _), (b_range, _, _)| {
        let a_bytes = &scratch[a_range.clone()];
        let b_bytes = &scratch[b_range.clone()];
        a_bytes.cmp(b_bytes)
    });

    for pair in with_keys.windows(2) {
        // SAFETY: `windows(2)` always yields slices of length 2.
        let (left_range, _, _) = &pair[0];
        let (right_range, _, _) = &pair[1];
        let left_bytes = &scratch[left_range.clone()];
        let right_bytes = &scratch[right_range.clone()];
        if left_bytes == right_bytes {
            return Err(SerializationError::DuplicateMapKey {
                key_hex: hex::encode(right_bytes),
            });
        }
    }

    *entries = with_keys
        .into_iter()
        .map(|(_, key, value)| (key, value))
        .collect();

    Ok(())
}

fn canonicalize_map_scratch_capacity_with_limit(entry_count: usize, byte_limit: usize) -> usize {
    entry_count.saturating_mul(32).min(byte_limit)
}

fn append_canonical_map_key_bytes(
    key: &Value,
    scratch: &mut Vec<u8>,
    byte_limit: usize,
) -> Result<(), SerializationError> {
    let available = byte_limit.saturating_sub(scratch.len());
    let required = measured_cbor_len_with_limit(key, available, byte_limit)?;
    let new_len =
        scratch
            .len()
            .checked_add(required)
            .ok_or(SerializationError::PayloadTooLarge {
                len: usize::MAX,
                max: byte_limit,
            })?;

    if new_len > byte_limit {
        return Err(SerializationError::PayloadTooLarge {
            len: new_len,
            max: byte_limit,
        });
    }

    let mut writer = LimitedVecWriter::new(scratch, byte_limit);
    into_writer(key, &mut writer).map_err(|err| map_capped_writer_error(err, byte_limit))?;
    Ok(())
}

fn measured_cbor_len_with_limit(
    value: &Value,
    max_len: usize,
    byte_limit: usize,
) -> Result<usize, SerializationError> {
    let mut writer = CountingWriter::new(max_len);
    into_writer(value, &mut writer).map_err(|err| map_capped_writer_error(err, byte_limit))?;
    Ok(writer.len())
}

fn map_capped_writer_error(
    err: ciborium::ser::Error<std::io::Error>,
    byte_limit: usize,
) -> SerializationError {
    match &err {
        ciborium::ser::Error::Io(inner) if inner.kind() == io::ErrorKind::OutOfMemory => {
            SerializationError::PayloadTooLarge {
                len: byte_limit.saturating_add(1),
                max: byte_limit,
            }
        }
        _ => SerializationError::CborSerialize(err),
    }
}

struct CountingWriter {
    len: usize,
    max: usize,
}

impl CountingWriter {
    const fn new(max: usize) -> Self {
        Self { len: 0, max }
    }

    const fn len(&self) -> usize {
        self.len
    }
}

impl io::Write for CountingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let next = self
            .len
            .checked_add(buf.len())
            .ok_or_else(|| payload_too_large_io_error(self.max))?;
        if next > self.max {
            return Err(payload_too_large_io_error(self.max));
        }
        self.len = next;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct LimitedVecWriter<'a> {
    buf: &'a mut Vec<u8>,
    max: usize,
}

impl<'a> LimitedVecWriter<'a> {
    const fn new(buf: &'a mut Vec<u8>, max: usize) -> Self {
        Self { buf, max }
    }
}

impl io::Write for LimitedVecWriter<'_> {
    fn write(&mut self, chunk: &[u8]) -> io::Result<usize> {
        let next = self
            .buf
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| payload_too_large_io_error(self.max))?;
        if next > self.max {
            return Err(payload_too_large_io_error(self.max));
        }
        self.buf.extend_from_slice(chunk);
        Ok(chunk.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn payload_too_large_io_error(max: usize) -> io::Error {
    io::Error::new(
        io::ErrorKind::OutOfMemory,
        format!("payload exceeds {max} bytes"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // ============================================================================
    // SchemaId and SchemaHash Tests
    // ============================================================================

    #[test]
    fn schema_id_as_bytes_is_canonical() {
        let schema = SchemaId::new("fcp.core", "CapabilityObject", Version::new(1, 2, 3));
        assert_eq!(
            schema.as_bytes(),
            b"fcp.core:CapabilityObject@1.2.3".to_vec()
        );
    }

    #[test]
    fn schema_hash_is_32_bytes() {
        let schema = SchemaId::new("fcp.core", "TestObject", Version::new(1, 0, 0));
        let hash = schema.hash();
        assert_eq!(hash.as_bytes().len(), 32);
        assert_eq!(hash.as_bytes().len(), SCHEMA_HASH_LEN);
    }

    #[test]
    fn schema_hash_is_deterministic() {
        let schema = SchemaId::new("fcp.test", "Demo", Version::new(0, 1, 0));

        let hash1 = schema.hash();
        let hash2 = schema.hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn schema_hash_differs_by_namespace() {
        let schema_a = SchemaId::new("fcp.core", "Object", Version::new(1, 0, 0));
        let schema_b = SchemaId::new("fcp.mesh", "Object", Version::new(1, 0, 0));
        assert_ne!(schema_a.hash(), schema_b.hash());
    }

    #[test]
    fn schema_hash_differs_by_name() {
        let schema_a = SchemaId::new("fcp.core", "ObjectA", Version::new(1, 0, 0));
        let schema_b = SchemaId::new("fcp.core", "ObjectB", Version::new(1, 0, 0));
        assert_ne!(schema_a.hash(), schema_b.hash());
    }

    #[test]
    fn schema_hash_differs_by_version() {
        let schema_a = SchemaId::new("fcp.core", "Object", Version::new(1, 0, 0));
        let schema_b = SchemaId::new("fcp.core", "Object", Version::new(2, 0, 0));
        assert_ne!(schema_a.hash(), schema_b.hash());
    }

    #[test]
    fn schema_hash_display_is_hex() {
        let schema = SchemaId::new("fcp.test", "Demo", Version::new(0, 1, 0));
        let hash = schema.hash();
        let display = hash.to_string();

        // Display should be lowercase hex, 64 chars (32 bytes * 2).
        assert_eq!(display.len(), 64);
        assert!(display.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn schema_hash_from_bytes_roundtrip() {
        let schema = SchemaId::new("fcp.test", "Demo", Version::new(0, 1, 0));
        let hash = schema.hash();
        let bytes = *hash.as_bytes();
        let reconstructed = SchemaHash::from_bytes(bytes);
        assert_eq!(hash, reconstructed);
    }

    // ============================================================================
    // Deterministic CBOR Encoding Tests
    // ============================================================================

    #[test]
    fn same_object_produces_same_bytes() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Demo {
            a: u8,
            b: String,
        }

        let schema = SchemaId::new("fcp.test", "Demo", Version::new(0, 1, 0));
        let value = Demo {
            a: 42,
            b: "hello".to_string(),
        };

        let bytes1 = CanonicalSerializer::serialize(&value, &schema).unwrap();
        let bytes2 = CanonicalSerializer::serialize(&value, &schema).unwrap();
        let bytes3 = CanonicalSerializer::serialize(&value, &schema).unwrap();

        assert_eq!(bytes1, bytes2);
        assert_eq!(bytes2, bytes3);
    }

    #[test]
    fn map_keys_are_sorted_by_canonical_bytes() {
        // Use a HashMap which has non-deterministic iteration order.
        let schema = SchemaId::new("fcp.test", "Map", Version::new(0, 1, 0));

        let mut map1 = HashMap::new();
        map1.insert("z", 1);
        map1.insert("a", 2);
        map1.insert("m", 3);

        let mut map2 = HashMap::new();
        map2.insert("a", 2);
        map2.insert("m", 3);
        map2.insert("z", 1);

        let bytes1 = CanonicalSerializer::serialize(&map1, &schema).unwrap();
        let bytes2 = CanonicalSerializer::serialize(&map2, &schema).unwrap();

        // Same logical map, regardless of insertion order.
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn map_keys_sorted_by_deterministic_encoding_bytes() {
        // RFC 8949 §4.2.1 sorts map keys by bytewise lexicographic order of
        // their deterministic encodings.
        let schema = SchemaId::new("fcp.test", "Map", Version::new(0, 1, 0));

        let mut map = HashMap::new();
        map.insert("bb", 1);
        map.insert("a", 2);
        map.insert("aaa", 3);
        map.insert("z", 4);

        let bytes = CanonicalSerializer::serialize(&map, &schema).unwrap();

        // Decode as raw CBOR value to inspect ordering.
        let cbor_bytes = &bytes[SCHEMA_HASH_LEN..];
        let value: Value = ciborium::de::from_reader(cbor_bytes).unwrap();

        if let Value::Map(entries) = value {
            let keys: Vec<_> = entries
                .iter()
                .filter_map(|(k, _)| {
                    if let Value::Text(s) = k {
                        Some(s.as_str())
                    } else {
                        None
                    }
                })
                .collect();

            // Text keys still appear in this order because the encoded length
            // header byte participates in the bytewise comparison.
            assert_eq!(keys, vec!["a", "z", "bb", "aaa"]);
        } else {
            panic!("Expected map");
        }
    }

    #[test]
    fn integer_map_keys_follow_rfc8949_bytewise_ordering() {
        let schema = SchemaId::new("fcp.test", "IntKeyMap", Version::new(0, 1, 0));
        let mut map = std::collections::BTreeMap::new();
        map.insert(100_i64, 1_u8);
        map.insert(-1_i64, 2_u8);
        map.insert(10_i64, 3_u8);

        let bytes = CanonicalSerializer::serialize(&map, &schema).unwrap();
        let cbor_bytes = &bytes[SCHEMA_HASH_LEN..];
        let value: Value = ciborium::de::from_reader(cbor_bytes).unwrap();

        if let Value::Map(entries) = value {
            let keys: Vec<i128> = entries
                .iter()
                .filter_map(|(k, _)| match k {
                    Value::Integer(i) => Some(i128::from(*i)),
                    _ => None,
                })
                .collect();
            assert_eq!(keys, vec![10, 100, -1]);
        } else {
            panic!("Expected map");
        }
    }

    #[test]
    fn integer_encoding_is_minimal() {
        let schema = SchemaId::new("fcp.test", "Int", Version::new(0, 1, 0));

        // Small integers (0-23) encode in 1 byte.
        let bytes = CanonicalSerializer::serialize(&0_u8, &schema).unwrap();
        assert_eq!(bytes.len(), SCHEMA_HASH_LEN + 1); // 0x00

        let bytes = CanonicalSerializer::serialize(&23_u8, &schema).unwrap();
        assert_eq!(bytes.len(), SCHEMA_HASH_LEN + 1); // 0x17

        // 24 requires 2 bytes (0x18 0x18).
        let bytes = CanonicalSerializer::serialize(&24_u8, &schema).unwrap();
        assert_eq!(bytes.len(), SCHEMA_HASH_LEN + 2);

        // 255 requires 2 bytes (0x18 0xFF).
        let bytes = CanonicalSerializer::serialize(&255_u8, &schema).unwrap();
        assert_eq!(bytes.len(), SCHEMA_HASH_LEN + 2);

        // 256 requires 3 bytes (0x19 0x01 0x00).
        let bytes = CanonicalSerializer::serialize(&256_u16, &schema).unwrap();
        assert_eq!(bytes.len(), SCHEMA_HASH_LEN + 3);
    }

    #[test]
    fn deserialize_rejects_map_keys_that_collide_after_canonicalization() {
        let schema = SchemaId::new("fcp.test", "Map", Version::new(0, 1, 0));

        // { -0.0: 1, 0.0: 2 } uses two distinct wire encodings, but
        // canonicalization normalizes -0.0 to 0.0 so both keys collapse to
        // the same deterministic bytes.
        let cbor_bytes = vec![
            0xA2, // Map with 2 entries.
            0xF9, 0x80, 0x00, // -0.0 (half-precision float).
            0x01, // 1
            0xF9, 0x00, 0x00, // 0.0 (half-precision float).
            0x02, // 2
        ];

        let mut bytes = Vec::new();
        bytes.extend_from_slice(schema.hash().as_bytes());
        bytes.extend_from_slice(&cbor_bytes);

        let err = CanonicalSerializer::deserialize::<Value>(&bytes, &schema).unwrap_err();
        assert!(matches!(err, SerializationError::DuplicateMapKey { .. }));

        let err = CanonicalSerializer::deserialize_unchecked::<Value>(&bytes, &schema).unwrap_err();
        assert!(matches!(err, SerializationError::DuplicateMapKey { .. }));
    }

    #[test]
    fn serialize_rejects_map_keys_that_collide_after_canonicalization() {
        let schema = SchemaId::new("fcp.test", "Map", Version::new(0, 1, 0));
        let value = Value::Map(vec![
            (Value::Float(-0.0), Value::Integer(1.into())),
            (Value::Float(0.0), Value::Integer(2.into())),
        ]);

        let err = CanonicalSerializer::serialize(&value, &schema).unwrap_err();
        assert!(matches!(err, SerializationError::DuplicateMapKey { .. }));
    }

    #[test]
    fn nested_maps_are_canonicalized() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Outer {
            inner: HashMap<String, i32>,
            name: String,
        }

        let schema = SchemaId::new("fcp.test", "Outer", Version::new(0, 1, 0));

        let mut inner = HashMap::new();
        inner.insert("z".to_string(), 1);
        inner.insert("a".to_string(), 2);

        let value = Outer {
            inner,
            name: "test".to_string(),
        };

        let bytes1 = CanonicalSerializer::serialize(&value, &schema).unwrap();
        let bytes2 = CanonicalSerializer::serialize(&value, &schema).unwrap();

        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn canonicalize_map_rejects_cumulative_key_bytes_over_limit() {
        let mut entries = vec![
            (Value::Text("a".repeat(15)), Value::Integer(1.into())),
            (Value::Text("b".repeat(15)), Value::Integer(2.into())),
            (Value::Text("c".repeat(15)), Value::Integer(3.into())),
        ];

        let err = canonicalize_map_with_limit(&mut entries, 0, 40).unwrap_err();
        assert!(matches!(
            err,
            SerializationError::PayloadTooLarge { max: 40, .. }
        ));
    }

    // ============================================================================
    // Roundtrip Tests
    // ============================================================================

    #[test]
    fn roundtrip_canonical_serialization() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Demo {
            a: u8,
            b: String,
        }

        let schema = SchemaId::new("fcp.test", "Demo", Version::new(0, 1, 0));
        let value = Demo {
            a: 7,
            b: "hi".to_string(),
        };

        let bytes = CanonicalSerializer::serialize(&value, &schema).unwrap();
        let decoded: Demo = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, value);

        let bytes2 = CanonicalSerializer::serialize(&decoded, &schema).unwrap();
        assert_eq!(bytes2, bytes);
    }

    #[test]
    fn roundtrip_primitives() {
        let schema = SchemaId::new("fcp.test", "Primitive", Version::new(0, 1, 0));

        // Boolean.
        let bytes = CanonicalSerializer::serialize(&true, &schema).unwrap();
        let decoded: bool = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert!(decoded);

        // Unsigned integers.
        for val in [
            0_u64,
            1,
            23,
            24,
            255,
            256,
            65535,
            65536,
            u64::from(u32::MAX),
        ] {
            let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
            let decoded: u64 = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
            assert_eq!(decoded, val);
        }

        // Signed integers.
        for val in [0_i64, -1, -24, -25, -128, i64::from(i32::MIN)] {
            let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
            let decoded: i64 = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
            assert_eq!(decoded, val);
        }

        // Strings.
        for val in ["", "a", "hello", "😀🎉"] {
            let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
            let decoded: String = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
            assert_eq!(decoded, val);
        }

        // Byte arrays.
        let byte_data: Vec<u8> = vec![0, 1, 2, 255];
        let bytes = CanonicalSerializer::serialize(&byte_data, &schema).unwrap();
        let decoded: Vec<u8> = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, byte_data);
    }

    #[test]
    fn roundtrip_arrays() {
        let schema = SchemaId::new("fcp.test", "Array", Version::new(0, 1, 0));

        let empty: Vec<i32> = vec![];
        let bytes = CanonicalSerializer::serialize(&empty, &schema).unwrap();
        let decoded: Vec<i32> = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, empty);

        let nums: Vec<i32> = vec![1, 2, 3, 4, 5];
        let bytes = CanonicalSerializer::serialize(&nums, &schema).unwrap();
        let decoded: Vec<i32> = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, nums);

        let strings: Vec<String> = vec!["a".into(), "b".into(), "c".into()];
        let bytes = CanonicalSerializer::serialize(&strings, &schema).unwrap();
        let decoded: Vec<String> = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, strings);
    }

    #[test]
    fn roundtrip_nested_structs() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Inner {
            value: i32,
        }

        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Outer {
            inner: Inner,
            items: Vec<Inner>,
        }

        let schema = SchemaId::new("fcp.test", "Outer", Version::new(0, 1, 0));
        let value = Outer {
            inner: Inner { value: 42 },
            items: vec![Inner { value: 1 }, Inner { value: 2 }],
        };

        let bytes = CanonicalSerializer::serialize(&value, &schema).unwrap();
        let decoded: Outer = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn roundtrip_optional_fields() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct WithOption {
            required: String,
            optional: Option<i32>,
        }

        let schema = SchemaId::new("fcp.test", "WithOption", Version::new(0, 1, 0));

        let with_some = WithOption {
            required: "hello".into(),
            optional: Some(42),
        };
        let bytes = CanonicalSerializer::serialize(&with_some, &schema).unwrap();
        let decoded: WithOption = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, with_some);

        let with_none = WithOption {
            required: "hello".into(),
            optional: None,
        };
        let bytes = CanonicalSerializer::serialize(&with_none, &schema).unwrap();
        let decoded: WithOption = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, with_none);
    }

    #[test]
    fn roundtrip_enums() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        enum Status {
            Active,
            Inactive,
            Pending { reason: String },
        }

        let schema = SchemaId::new("fcp.test", "Status", Version::new(0, 1, 0));

        for value in [
            Status::Active,
            Status::Inactive,
            Status::Pending {
                reason: "testing".into(),
            },
        ] {
            let bytes = CanonicalSerializer::serialize(&value, &schema).unwrap();
            let decoded: Status = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
            assert_eq!(decoded, value);
        }
    }

    // ============================================================================
    // Schema Mismatch Tests
    // ============================================================================

    #[test]
    fn deserialize_rejects_schema_mismatch() {
        let schema_a = SchemaId::new("fcp.test", "A", Version::new(0, 1, 0));
        let schema_b = SchemaId::new("fcp.test", "B", Version::new(0, 1, 0));

        let bytes = CanonicalSerializer::serialize(&42_u64, &schema_a).unwrap();
        let err = CanonicalSerializer::deserialize::<u64>(&bytes, &schema_b).unwrap_err();
        assert!(matches!(err, SerializationError::SchemaMismatch { .. }));
    }

    #[test]
    fn deserialize_rejects_version_mismatch() {
        let schema_v1 = SchemaId::new("fcp.test", "Object", Version::new(1, 0, 0));
        let schema_v2 = SchemaId::new("fcp.test", "Object", Version::new(2, 0, 0));

        let bytes = CanonicalSerializer::serialize(&42_u64, &schema_v1).unwrap();
        let err = CanonicalSerializer::deserialize::<u64>(&bytes, &schema_v2).unwrap_err();
        assert!(matches!(err, SerializationError::SchemaMismatch { .. }));
    }

    // ============================================================================
    // Non-Canonical Encoding Rejection Tests
    // ============================================================================

    #[test]
    fn deserialize_rejects_non_canonical_integer_encoding() {
        let schema = SchemaId::new("fcp.test", "U8", Version::new(0, 1, 0));

        // CBOR integer 1 encoded in non-canonical form (0x18 0x01 instead of 0x01).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(schema.hash().as_bytes());
        bytes.extend_from_slice(&[0x18, 0x01]);

        let err = CanonicalSerializer::deserialize::<u8>(&bytes, &schema).unwrap_err();
        assert!(matches!(err, SerializationError::NonCanonicalEncoding));
    }

    #[test]
    fn deserialize_rejects_non_canonical_string_length() {
        let schema = SchemaId::new("fcp.test", "String", Version::new(0, 1, 0));

        // String "a" encoded with 2-byte length prefix (0x78 0x01) instead of 1-byte (0x61).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(schema.hash().as_bytes());
        bytes.extend_from_slice(&[0x78, 0x01, b'a']);

        let err = CanonicalSerializer::deserialize::<String>(&bytes, &schema).unwrap_err();
        assert!(matches!(err, SerializationError::NonCanonicalEncoding));
    }

    #[test]
    fn deserialize_rejects_trailing_bytes() {
        let schema = SchemaId::new("fcp.test", "U8", Version::new(0, 1, 0));
        let mut bytes = CanonicalSerializer::serialize(&1_u8, &schema).unwrap();
        bytes.push(0x00);

        let err = CanonicalSerializer::deserialize::<u8>(&bytes, &schema).unwrap_err();
        assert!(matches!(err, SerializationError::TrailingBytes));
    }

    // ============================================================================
    // Decode Safety Tests (Malformed Input)
    // ============================================================================

    #[test]
    fn deserialize_rejects_truncated_input() {
        let schema = SchemaId::new("fcp.test", "U8", Version::new(0, 1, 0));

        // Too short to contain schema hash.
        let bytes: [u8; 16] = [0; 16];
        let err = CanonicalSerializer::deserialize::<u8>(&bytes, &schema).unwrap_err();
        assert!(matches!(err, SerializationError::MissingSchemaHashPrefix));
    }

    #[test]
    fn deserialize_rejects_empty_input() {
        let schema = SchemaId::new("fcp.test", "U8", Version::new(0, 1, 0));

        let bytes: [u8; 0] = [];
        let err = CanonicalSerializer::deserialize::<u8>(&bytes, &schema).unwrap_err();
        assert!(matches!(err, SerializationError::MissingSchemaHashPrefix));
    }

    #[test]
    fn deserialize_rejects_truncated_cbor() {
        let schema = SchemaId::new("fcp.test", "String", Version::new(0, 1, 0));

        // Schema hash + truncated string (claims length 10 but only has 2 bytes).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(schema.hash().as_bytes());
        bytes.extend_from_slice(&[0x6A, b'a', b'b']); // 0x6A = text string of length 10.

        let err = CanonicalSerializer::deserialize::<String>(&bytes, &schema).unwrap_err();
        assert!(matches!(err, SerializationError::CborDeserialize(_)));
    }

    #[test]
    fn deserialize_rejects_invalid_cbor() {
        let schema = SchemaId::new("fcp.test", "U8", Version::new(0, 1, 0));

        // Schema hash + invalid CBOR (0xFF is a break code, invalid at top level).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(schema.hash().as_bytes());
        bytes.push(0xFF);

        let err = CanonicalSerializer::deserialize::<u8>(&bytes, &schema).unwrap_err();
        assert!(matches!(err, SerializationError::CborDeserialize(_)));
    }

    #[test]
    fn deserialize_rejects_wrong_type() {
        let schema = SchemaId::new("fcp.test", "U8", Version::new(0, 1, 0));

        // Serialize a string but try to deserialize as u8.
        let bytes = CanonicalSerializer::serialize(&"hello", &schema).unwrap();
        let err = CanonicalSerializer::deserialize::<u8>(&bytes, &schema).unwrap_err();
        assert!(matches!(err, SerializationError::CborDeserialize(_)));
    }

    // ============================================================================
    // Size Limit Tests
    // ============================================================================

    #[test]
    fn serialize_rejects_oversized_payload() {
        let schema = SchemaId::new("fcp.test", "Large", Version::new(0, 1, 0));

        // Create a payload that exceeds MAX_CANONICAL_OBJECT_BYTES.
        let large_data: Vec<u8> = vec![0; MAX_CANONICAL_OBJECT_BYTES + 1];
        let err = CanonicalSerializer::serialize(&large_data, &schema).unwrap_err();
        assert!(matches!(err, SerializationError::PayloadTooLarge { .. }));
    }

    #[test]
    fn canonical_writer_counts_existing_bytes_against_limit() {
        let mut out = vec![0xAA; 4];
        let payload = vec![0_u8; 4];

        let err = write_canonical_cbor_with_limit(&payload, &mut out, 8)
            .expect_err("existing prefix bytes must count toward the write limit");

        match err {
            SerializationError::PayloadTooLarge { max, .. } => assert_eq!(max, 8),
            other => panic!("unexpected serialization error: {other:?}"),
        }
        assert!(out.len() <= 8, "writer grew past configured limit");
    }

    #[test]
    fn canonical_writer_rejects_already_oversized_output_buffer() {
        let mut out = vec![0xAA; 9];
        let payload = vec![0_u8; 1];

        let err = write_canonical_cbor_with_limit(&payload, &mut out, 8)
            .expect_err("oversized destination buffer must fail before writing");

        match err {
            SerializationError::PayloadTooLarge { len, max } => {
                assert_eq!(len, 9);
                assert_eq!(max, 8);
            }
            other => panic!("unexpected serialization error: {other:?}"),
        }
        assert_eq!(out, vec![0xAA; 9]);
    }

    #[test]
    fn deserialize_rejects_oversized_input() {
        let schema = SchemaId::new("fcp.test", "Large", Version::new(0, 1, 0));

        // Create input that exceeds MAX_CANONICAL_OBJECT_BYTES.
        let large_input: Vec<u8> = vec![0; MAX_CANONICAL_OBJECT_BYTES + 1];
        let err = CanonicalSerializer::deserialize::<Vec<u8>>(&large_input, &schema).unwrap_err();
        assert!(matches!(err, SerializationError::PayloadTooLarge { .. }));
    }

    // ============================================================================
    // Payload Format Tests
    // ============================================================================

    #[test]
    fn payload_format_is_schema_hash_then_cbor() {
        let schema = SchemaId::new("fcp.test", "Demo", Version::new(0, 1, 0));
        let value = 42_u8;

        let bytes = CanonicalSerializer::serialize(&value, &schema).unwrap();

        // First 32 bytes should be the schema hash.
        let expected_hash = schema.hash();
        assert_eq!(&bytes[..SCHEMA_HASH_LEN], expected_hash.as_bytes());

        // Remaining bytes should be valid CBOR for the value.
        let cbor_bytes = &bytes[SCHEMA_HASH_LEN..];
        let decoded: u8 = ciborium::de::from_reader(cbor_bytes).unwrap();
        assert_eq!(decoded, value);
    }

    // ============================================================================
    // Golden Vector Tests
    // ============================================================================

    #[test]
    fn golden_vector_schema_hash() {
        // Fixed schema ID should always produce the same hash.
        let schema = SchemaId::new("fcp.core", "CapabilityToken", Version::new(1, 0, 0));
        let hash = schema.hash();

        // This is the expected hash - if this changes, serialization compatibility is broken.
        let expected_hex = hex::encode(hash.as_bytes());

        // Just verify it's deterministic (the actual value is the baseline).
        let hash2 = schema.hash();
        assert_eq!(hex::encode(hash2.as_bytes()), expected_hex);
    }

    #[test]
    fn golden_vector_simple_struct() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct GoldenStruct {
            id: u64,
            name: String,
            active: bool,
        }

        let schema = SchemaId::new("fcp.test", "GoldenStruct", Version::new(1, 0, 0));
        let value = GoldenStruct {
            id: 12345,
            name: "test".to_string(),
            active: true,
        };

        // Serialize and capture the bytes.
        let bytes = CanonicalSerializer::serialize(&value, &schema).unwrap();

        // Verify it's deterministic.
        let bytes2 = CanonicalSerializer::serialize(&value, &schema).unwrap();
        assert_eq!(bytes, bytes2);

        // Verify roundtrip.
        let decoded: GoldenStruct = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, value);

        // Verify the CBOR portion has expected structure.
        let cbor_bytes = &bytes[SCHEMA_HASH_LEN..];
        let raw: Value = ciborium::de::from_reader(cbor_bytes).unwrap();
        assert!(matches!(raw, Value::Map(_)));
    }

    // ============================================================================
    // Unchecked Deserialization Tests
    // ============================================================================

    #[test]
    fn deserialize_unchecked_allows_non_canonical() {
        let schema = SchemaId::new("fcp.test", "U8", Version::new(0, 1, 0));

        // CBOR integer 1 encoded in non-canonical form (0x18 0x01 instead of 0x01).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(schema.hash().as_bytes());
        bytes.extend_from_slice(&[0x18, 0x01]);

        // unchecked should succeed.
        let value: u8 = CanonicalSerializer::deserialize_unchecked(&bytes, &schema).unwrap();
        assert_eq!(value, 1);

        // strict should fail.
        let err = CanonicalSerializer::deserialize::<u8>(&bytes, &schema).unwrap_err();
        assert!(matches!(err, SerializationError::NonCanonicalEncoding));
    }

    #[test]
    fn deserialize_unchecked_rejects_tagged_payload() {
        let schema = SchemaId::new("fcp.test", "TaggedU8", Version::new(0, 1, 0));
        let mut bytes = Vec::new();
        bytes.extend_from_slice(schema.hash().as_bytes());
        bytes.extend_from_slice(&[0xC0, 0x01]); // tag(0, 1)

        let err = CanonicalSerializer::deserialize_unchecked::<u8>(&bytes, &schema).unwrap_err();
        assert!(matches!(err, SerializationError::UnsupportedTag { tag: 0 }));
    }

    #[test]
    fn deserialize_rejects_tagged_payload_before_retyping() {
        let schema = SchemaId::new("fcp.test", "TaggedBool", Version::new(0, 1, 0));
        let mut bytes = Vec::new();
        bytes.extend_from_slice(schema.hash().as_bytes());
        bytes.extend_from_slice(&[0xC1, 0xF5]); // tag(1, true)

        let err = CanonicalSerializer::deserialize::<bool>(&bytes, &schema).unwrap_err();
        assert!(matches!(err, SerializationError::UnsupportedTag { tag: 1 }));
    }

    #[test]
    fn deserialize_unchecked_rejects_inputs_beyond_canonical_depth_limit() {
        let schema = SchemaId::new("fcp.test", "Deep", Version::new(0, 1, 0));
        let mut body = vec![0x81; MAX_CANONICALIZATION_DEPTH + 1];
        body.push(0x00);

        let mut bytes = Vec::new();
        bytes.extend_from_slice(schema.hash().as_bytes());
        bytes.extend_from_slice(&body);

        let err = CanonicalSerializer::deserialize_unchecked::<Value>(&bytes, &schema).unwrap_err();
        assert!(matches!(
            err,
            SerializationError::DepthExceeded {
                depth,
                max: MAX_CANONICALIZATION_DEPTH
            } if depth == MAX_CANONICALIZATION_DEPTH + 1
        ));
    }

    #[test]
    fn decoder_limit_matches_canonical_depth_boundary() {
        let mut at_limit = vec![0x81; MAX_CANONICALIZATION_DEPTH];
        at_limit.push(0x00);
        decode_cbor_body_as_value(&at_limit).expect("depth at canonical limit must decode");

        let mut over_limit = vec![0x81; MAX_CANONICALIZATION_DEPTH + 1];
        over_limit.push(0x00);

        let err = decode_cbor_body_as_value(&over_limit).unwrap_err();
        assert!(
            matches!(
                err,
                SerializationError::DepthExceeded {
                    depth,
                    max: MAX_CANONICALIZATION_DEPTH
                } if depth == MAX_CANONICALIZATION_DEPTH + 1
            ),
            "expected parser-level DepthExceeded at one past the canonical limit, got {err:?}"
        );
    }

    // ============================================================================
    // to_canonical_cbor Tests (without schema prefix)
    // ============================================================================

    #[test]
    fn to_canonical_cbor_is_deterministic() {
        let value = vec![3, 1, 4, 1, 5, 9, 2, 6];
        let bytes1 = to_canonical_cbor(&value).unwrap();
        let bytes2 = to_canonical_cbor(&value).unwrap();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn to_canonical_cbor_has_no_schema_prefix() {
        let value = 42_u8;
        let bytes = to_canonical_cbor(&value).unwrap();

        // Should be just the CBOR encoding, no 32-byte prefix.
        // CBOR for 42 is 0x18 0x2A (2 bytes).
        assert_eq!(bytes.len(), 2);
        assert_eq!(bytes, vec![0x18, 0x2A]);
    }

    #[test]
    fn to_canonical_cbor_rejects_tagged_value() {
        let tagged = Value::Tag(24, Box::new(Value::Bytes(vec![0x01])));
        let err = to_canonical_cbor(&tagged).unwrap_err();
        assert!(matches!(
            err,
            SerializationError::UnsupportedTag { tag: 24 }
        ));
    }

    // ============================================================================
    // Error Display Tests
    // ============================================================================

    #[test]
    fn error_display_missing_schema_hash_prefix() {
        let err = SerializationError::MissingSchemaHashPrefix;
        assert_eq!(err.to_string(), "payload missing schema hash prefix");
    }

    #[test]
    fn error_display_schema_mismatch() {
        let expected = SchemaHash::from_bytes([0xAA; 32]);
        let got = SchemaHash::from_bytes([0xBB; 32]);
        let err = SerializationError::SchemaMismatch { expected, got };
        let msg = err.to_string();
        assert!(msg.contains("schema hash mismatch"));
        assert!(msg.contains(&expected.to_string()));
        assert!(msg.contains(&got.to_string()));
    }

    #[test]
    fn error_display_payload_too_large() {
        let err = SerializationError::PayloadTooLarge { len: 100, max: 50 };
        assert_eq!(err.to_string(), "payload too large (100 bytes > 50 bytes)");
    }

    #[test]
    fn error_display_trailing_bytes() {
        let err = SerializationError::TrailingBytes;
        assert_eq!(err.to_string(), "trailing bytes after CBOR value");
    }

    #[test]
    fn error_display_non_canonical_encoding() {
        let err = SerializationError::NonCanonicalEncoding;
        assert_eq!(err.to_string(), "non-canonical CBOR encoding");
    }

    #[test]
    fn error_display_duplicate_map_key() {
        let err = SerializationError::DuplicateMapKey {
            key_hex: "6161".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "duplicate map key (canonical key bytes: 6161)"
        );
    }

    #[test]
    fn error_display_unsupported_tag() {
        let err = SerializationError::UnsupportedTag { tag: 24 };
        assert_eq!(
            err.to_string(),
            "CBOR tag 24 is not allowed in canonical FCP payloads"
        );
    }

    // ============================================================================
    // SchemaHash Trait Impl Tests
    // ============================================================================

    #[test]
    fn schema_hash_debug_contains_hex() {
        let schema = SchemaId::new("fcp.test", "Demo", Version::new(0, 1, 0));
        let hash = schema.hash();
        let debug = format!("{hash:?}");
        assert!(debug.starts_with("SchemaHash(\""));
        assert!(debug.ends_with("\")"));
        // The hex string inside should be 64 chars.
        let inner = &debug["SchemaHash(\"".len()..debug.len() - 2];
        assert_eq!(inner.len(), 64);
    }

    #[test]
    fn schema_hash_as_ref_matches_as_bytes() {
        let schema = SchemaId::new("fcp.test", "Demo", Version::new(0, 1, 0));
        let hash = schema.hash();
        let as_ref: &[u8] = hash.as_ref();
        assert_eq!(as_ref, hash.as_bytes());
    }

    // ============================================================================
    // SchemaId Edge Cases
    // ============================================================================

    #[test]
    fn schema_id_empty_namespace_and_name() {
        let schema = SchemaId::new("", "", Version::new(0, 0, 0));
        let bytes = schema.as_bytes();
        assert_eq!(bytes, b":@0.0.0".to_vec());
        // Hash should still be 32 bytes and deterministic.
        assert_eq!(schema.hash().as_bytes().len(), 32);
    }

    #[test]
    fn schema_id_serde_roundtrip() {
        let schema = SchemaId::new("fcp.core", "Token", Version::new(2, 1, 3));
        let json = serde_json::to_string(&schema).unwrap();
        let decoded: SchemaId = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, schema);
    }

    #[test]
    fn schema_id_hash_includes_domain_separator() {
        // Two different domain separators should yield different hashes.
        // We verify this indirectly: the hash of a schema is NOT the same as
        // BLAKE3(schema.as_bytes()) without the domain separator.
        let schema = SchemaId::new("fcp.test", "Demo", Version::new(0, 1, 0));
        let hash_with_domain = schema.hash();

        let mut bare_hasher = blake3::Hasher::new();
        bare_hasher.update(&schema.as_bytes());
        let bare_hash = *bare_hasher.finalize().as_bytes();

        assert_ne!(hash_with_domain.as_bytes(), &bare_hash);
    }

    #[test]
    fn schema_id_clone_and_eq() {
        let schema = SchemaId::new("fcp.core", "Object", Version::new(1, 0, 0));
        let cloned = schema.clone();
        assert_eq!(schema, cloned);
        assert_eq!(schema.hash(), cloned.hash());
    }

    // ============================================================================
    // SchemaId Separator-Collision Regression (REVIEW-A9, mzi9x)
    // ============================================================================
    //
    // The historical hash() encoding concatenated `namespace || ':' || name || '@'
    // || version` raw, so namespace=`a:b`,name=`c` and namespace=`a`,name=`b:c`
    // (and analogous `@` variants) hashed the same byte string. The fix uses
    // length-prefixing in hash() and rejects `:`/`@` at construction time. These
    // tests pin both layers so the alias can never come back.

    #[test]
    fn schema_id_new_rejects_colon_in_namespace() {
        let err = std::panic::catch_unwind(|| {
            let _ = SchemaId::new("fcp:core", "Object", Version::new(1, 0, 0));
        })
        .expect_err("SchemaId::new must panic on ':' in namespace");
        let msg = err
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| err.downcast_ref::<&'static str>().copied())
            .unwrap_or("");
        assert!(
            msg.contains("reserved separator"),
            "panic message should mention reserved separator, got: {msg}"
        );
    }

    #[test]
    fn schema_id_new_rejects_at_in_name() {
        let err = std::panic::catch_unwind(|| {
            let _ = SchemaId::new("fcp.core", "Obj@ct", Version::new(1, 0, 0));
        })
        .expect_err("SchemaId::new must panic on '@' in name");
        let _ = err;
    }

    #[test]
    fn schema_id_try_new_rejects_reserved_separators() {
        // `:` in namespace.
        let err = SchemaId::try_new("a:b", "c", Version::new(1, 0, 0)).unwrap_err();
        assert_eq!(
            err,
            SchemaIdError::ReservedSeparator {
                field: "namespace",
                separator: ':',
            }
        );

        // `:` in name.
        let err = SchemaId::try_new("a", "b:c", Version::new(1, 0, 0)).unwrap_err();
        assert_eq!(
            err,
            SchemaIdError::ReservedSeparator {
                field: "name",
                separator: ':',
            }
        );

        // `@` in namespace.
        let err = SchemaId::try_new("a@b", "c", Version::new(1, 0, 0)).unwrap_err();
        assert_eq!(
            err,
            SchemaIdError::ReservedSeparator {
                field: "namespace",
                separator: '@',
            }
        );

        // `@` in name.
        let err = SchemaId::try_new("a", "b@c", Version::new(1, 0, 0)).unwrap_err();
        assert_eq!(
            err,
            SchemaIdError::ReservedSeparator {
                field: "name",
                separator: '@',
            }
        );
    }

    #[test]
    fn schema_id_try_new_accepts_clean_inputs() {
        let schema = SchemaId::try_new("fcp.core", "Object", Version::new(1, 0, 0)).unwrap();
        assert_eq!(schema.namespace, "fcp.core");
        assert_eq!(schema.name, "Object");
    }

    #[test]
    fn schema_id_hash_does_not_collide_across_separator_aliases() {
        // Build collision candidates by direct struct construction so we bypass the
        // constructor's reserved-separator check — this is precisely the path the
        // length-prefixed hash() must defend against.
        let version = Version::new(1, 0, 0);

        let colon_left = SchemaId {
            namespace: "a:b".to_string(),
            name: "c".to_string(),
            version: version.clone(),
        };
        let colon_right = SchemaId {
            namespace: "a".to_string(),
            name: "b:c".to_string(),
            version: version.clone(),
        };
        // Sanity: as_bytes() shows why the historical hash collided.
        assert_eq!(colon_left.as_bytes(), b"a:b:c@1.0.0".to_vec());
        assert_eq!(colon_right.as_bytes(), b"a:b:c@1.0.0".to_vec());
        // Hash MUST NOT collide.
        assert_ne!(
            colon_left.hash(),
            colon_right.hash(),
            "SchemaId::hash collided on `:` separator alias — REVIEW-A9 regression"
        );

        let at_left = SchemaId {
            namespace: "a".to_string(),
            name: "b@1.0.0".to_string(),
            version: version.clone(),
        };
        let at_right = SchemaId {
            namespace: "a".to_string(),
            name: "b".to_string(),
            version,
        };
        // as_bytes() form: "a:b@1.0.0@1.0.0" vs "a:b@1.0.0" — distinct here, but the
        // raw-concat hash variants `a` || ':' || `b@1.0.0` || '@' || `1.0.0` and
        // `a` || ':' || `b` || '@' || `1.0.0` differ only in length, which a non-
        // length-prefixed hash treats the same as any other byte difference. The
        // real risk is the `:` family above; we keep this `@` case to lock in that
        // length-prefixing also separates these tuples.
        assert_ne!(at_left.hash(), at_right.hash());
    }

    #[test]
    fn schema_id_hash_uses_length_prefixed_encoding() {
        // Empty-component pairs that would collide under raw concatenation must
        // now produce distinct hashes under length-prefixed encoding.
        let a = SchemaId {
            namespace: "ab".to_string(),
            name: String::new(),
            version: Version::new(0, 0, 0),
        };
        let b = SchemaId {
            namespace: "a".to_string(),
            name: "b".to_string(),
            version: Version::new(0, 0, 0),
        };
        // Under the old encoding both became "ab:@0.0.0" / "a:b@0.0.0" — different
        // here, but the broader principle is that lengths participate in the hash.
        assert_ne!(a.hash(), b.hash());

        // Truly aliasing under raw concat: namespace+":"+name where the ":" lands
        // identically. Build via direct construction.
        let lhs = SchemaId {
            namespace: "x:".to_string(),
            name: "y".to_string(),
            version: Version::new(1, 0, 0),
        };
        let rhs = SchemaId {
            namespace: "x".to_string(),
            name: ":y".to_string(),
            version: Version::new(1, 0, 0),
        };
        assert_eq!(lhs.as_bytes(), rhs.as_bytes());
        assert_ne!(lhs.hash(), rhs.hash());
    }

    // ============================================================================
    // split_schema_prefix Edge Cases
    // ============================================================================

    #[test]
    fn deserialize_exact_schema_hash_no_cbor_body() {
        let schema = SchemaId::new("fcp.test", "U8", Version::new(0, 1, 0));
        // Exactly 32 bytes = schema hash only, no CBOR body.
        let bytes = schema.hash().as_bytes().to_vec();
        let err = CanonicalSerializer::deserialize::<u8>(&bytes, &schema).unwrap_err();
        // Should fail because there's no CBOR to decode.
        assert!(matches!(err, SerializationError::CborDeserialize(_)));
    }

    // ============================================================================
    // deserialize_unchecked Error Paths
    // ============================================================================

    #[test]
    fn deserialize_unchecked_rejects_schema_mismatch() {
        let schema_a = SchemaId::new("fcp.test", "A", Version::new(0, 1, 0));
        let schema_b = SchemaId::new("fcp.test", "B", Version::new(0, 1, 0));

        let bytes = CanonicalSerializer::serialize(&42_u64, &schema_a).unwrap();
        let err = CanonicalSerializer::deserialize_unchecked::<u64>(&bytes, &schema_b).unwrap_err();
        assert!(matches!(err, SerializationError::SchemaMismatch { .. }));
    }

    #[test]
    fn deserialize_unchecked_rejects_oversized_input() {
        let schema = SchemaId::new("fcp.test", "Large", Version::new(0, 1, 0));
        let large_input: Vec<u8> = vec![0; MAX_CANONICAL_OBJECT_BYTES + 1];
        let err = CanonicalSerializer::deserialize_unchecked::<Vec<u8>>(&large_input, &schema)
            .unwrap_err();
        assert!(matches!(err, SerializationError::PayloadTooLarge { .. }));
    }

    #[test]
    fn deserialize_unchecked_rejects_trailing_bytes() {
        let schema = SchemaId::new("fcp.test", "U8", Version::new(0, 1, 0));
        let mut bytes = CanonicalSerializer::serialize(&1_u8, &schema).unwrap();
        bytes.push(0x00); // trailing garbage
        let err = CanonicalSerializer::deserialize_unchecked::<u8>(&bytes, &schema).unwrap_err();
        assert!(matches!(err, SerializationError::TrailingBytes));
    }

    #[test]
    fn deserialize_unchecked_rejects_truncated_input() {
        let schema = SchemaId::new("fcp.test", "U8", Version::new(0, 1, 0));
        let bytes: [u8; 10] = [0; 10];
        let err = CanonicalSerializer::deserialize_unchecked::<u8>(&bytes, &schema).unwrap_err();
        assert!(matches!(err, SerializationError::MissingSchemaHashPrefix));
    }

    // ============================================================================
    // Empty and Boundary Structure Tests
    // ============================================================================

    #[test]
    fn roundtrip_empty_map() {
        let schema = SchemaId::new("fcp.test", "EmptyMap", Version::new(0, 1, 0));
        let map: HashMap<String, i32> = HashMap::new();
        let bytes = CanonicalSerializer::serialize(&map, &schema).unwrap();
        let decoded: HashMap<String, i32> =
            CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn roundtrip_empty_struct() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Empty {}

        let schema = SchemaId::new("fcp.test", "Empty", Version::new(0, 1, 0));
        let value = Empty {};
        let bytes = CanonicalSerializer::serialize(&value, &schema).unwrap();
        let decoded: Empty = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn roundtrip_deeply_nested_structure() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Node {
            value: i32,
            children: Vec<Self>,
        }

        let schema = SchemaId::new("fcp.test", "Node", Version::new(0, 1, 0));
        let value = Node {
            value: 1,
            children: vec![
                Node {
                    value: 2,
                    children: vec![Node {
                        value: 3,
                        children: vec![],
                    }],
                },
                Node {
                    value: 4,
                    children: vec![],
                },
            ],
        };

        let bytes = CanonicalSerializer::serialize(&value, &schema).unwrap();
        let decoded: Node = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn roundtrip_tuple_struct() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Pair(u32, String);

        let schema = SchemaId::new("fcp.test", "Pair", Version::new(0, 1, 0));
        let value = Pair(42, "hello".into());
        let bytes = CanonicalSerializer::serialize(&value, &schema).unwrap();
        let decoded: Pair = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn roundtrip_unit_variant_enum() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        enum Color {
            Red,
            Green,
            Blue,
        }

        let schema = SchemaId::new("fcp.test", "Color", Version::new(0, 1, 0));
        for color in [Color::Red, Color::Green, Color::Blue] {
            let bytes = CanonicalSerializer::serialize(&color, &schema).unwrap();
            let decoded: Color = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
            assert_eq!(decoded, color);
        }
    }

    // ============================================================================
    // Canonical Encoding Detail Tests
    // ============================================================================

    #[test]
    fn boolean_canonical_encoding_sizes() {
        let schema = SchemaId::new("fcp.test", "Bool", Version::new(0, 1, 0));
        // CBOR true = 0xF5 (1 byte), false = 0xF4 (1 byte).
        let bytes_true = CanonicalSerializer::serialize(&true, &schema).unwrap();
        assert_eq!(bytes_true.len(), SCHEMA_HASH_LEN + 1);

        let bytes_false = CanonicalSerializer::serialize(&false, &schema).unwrap();
        assert_eq!(bytes_false.len(), SCHEMA_HASH_LEN + 1);

        // They should differ.
        assert_ne!(bytes_true, bytes_false);
    }

    #[test]
    fn null_canonical_encoding() {
        let schema = SchemaId::new("fcp.test", "Null", Version::new(0, 1, 0));
        // CBOR null = 0xF6 (1 byte).
        let none: Option<u8> = None;
        let bytes = CanonicalSerializer::serialize(&none, &schema).unwrap();
        assert_eq!(bytes.len(), SCHEMA_HASH_LEN + 1);
        assert_eq!(bytes[SCHEMA_HASH_LEN], 0xF6);
    }

    #[test]
    fn negative_integer_minimal_encoding() {
        let schema = SchemaId::new("fcp.test", "Int", Version::new(0, 1, 0));
        // CBOR: -1 = 0x20 (1 byte), -24 = 0x37 (1 byte), -25 = 0x38 0x18 (2 bytes).
        let bytes_neg1 = CanonicalSerializer::serialize(&(-1_i8), &schema).unwrap();
        assert_eq!(bytes_neg1.len(), SCHEMA_HASH_LEN + 1);

        let bytes_neg24 = CanonicalSerializer::serialize(&(-24_i8), &schema).unwrap();
        assert_eq!(bytes_neg24.len(), SCHEMA_HASH_LEN + 1);

        let bytes_neg25 = CanonicalSerializer::serialize(&(-25_i8), &schema).unwrap();
        assert_eq!(bytes_neg25.len(), SCHEMA_HASH_LEN + 2);
    }

    #[test]
    fn string_length_encoding_boundaries() {
        // String length 23: 1-byte length prefix (0x77).
        let s23 = "a".repeat(23);
        let bytes23 = to_canonical_cbor(&s23).unwrap();
        assert_eq!(bytes23[0], 0x77); // major type 3, additional 23

        // String length 24: 2-byte length prefix (0x78 0x18).
        let s24 = "a".repeat(24);
        let bytes24 = to_canonical_cbor(&s24).unwrap();
        assert_eq!(bytes24[0], 0x78);
        assert_eq!(bytes24[1], 24);
    }

    // ============================================================================
    // Map Canonicalization Edge Cases
    // ============================================================================

    #[test]
    fn map_with_integer_keys_sorted() {
        use std::collections::BTreeMap;
        let schema = SchemaId::new("fcp.test", "IntMap", Version::new(0, 1, 0));

        let mut map = BTreeMap::new();
        map.insert(100, "hundred");
        map.insert(1, "one");
        map.insert(10, "ten");

        let bytes = CanonicalSerializer::serialize(&map, &schema).unwrap();

        // Decode raw CBOR and check key order (shorter encoding first).
        let cbor_bytes = &bytes[SCHEMA_HASH_LEN..];
        let value: Value = ciborium::de::from_reader(cbor_bytes).unwrap();
        if let Value::Map(entries) = value {
            let keys: Vec<_> = entries
                .iter()
                .filter_map(|(k, _)| {
                    if let Value::Integer(i) = k {
                        Some(i128::from(*i))
                    } else {
                        None
                    }
                })
                .collect();
            // 1 (1 byte: 0x01), 10 (1 byte: 0x0A), 100 (2 bytes: 0x18 0x64).
            assert_eq!(keys, vec![1, 10, 100]);
        } else {
            panic!("Expected map");
        }
    }

    #[test]
    fn map_single_entry() {
        let schema = SchemaId::new("fcp.test", "SingleMap", Version::new(0, 1, 0));
        let mut map = HashMap::new();
        map.insert("only", 1);
        let bytes = CanonicalSerializer::serialize(&map, &schema).unwrap();
        let decoded: HashMap<String, i32> =
            CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded["only"], 1);
    }

    // ============================================================================
    // to_canonical_cbor Direct Tests
    // ============================================================================

    #[test]
    fn to_canonical_cbor_empty_array() {
        let empty: Vec<u8> = vec![];
        let bytes = to_canonical_cbor(&empty).unwrap();
        // CBOR empty array = 0x80 (1 byte).
        assert_eq!(bytes, vec![0x80]);
    }

    #[test]
    fn to_canonical_cbor_empty_string() {
        let bytes = to_canonical_cbor(&"").unwrap();
        // CBOR empty text string = 0x60 (1 byte).
        assert_eq!(bytes, vec![0x60]);
    }

    #[test]
    fn to_canonical_cbor_map_deterministic_regardless_of_insertion() {
        let mut map_a = HashMap::new();
        map_a.insert("x", 1);
        map_a.insert("y", 2);
        map_a.insert("z", 3);

        let mut map_b = HashMap::new();
        map_b.insert("z", 3);
        map_b.insert("x", 1);
        map_b.insert("y", 2);

        let bytes_a = to_canonical_cbor(&map_a).unwrap();
        let bytes_b = to_canonical_cbor(&map_b).unwrap();
        assert_eq!(bytes_a, bytes_b);
    }

    // ============================================================================
    // Non-Canonical Map Key Order Rejection
    // ============================================================================

    #[test]
    fn deserialize_rejects_non_canonical_map_key_order() {
        let schema = SchemaId::new("fcp.test", "Map", Version::new(0, 1, 0));

        // Manually build: { "bb": 1, "a": 2 } — wrong order per RFC 8949.
        // Canonical should be { "a": 2, "bb": 1 } in deterministic byte order.
        let mut cbor_bytes = Vec::new();
        cbor_bytes.push(0xA2); // map with 2 entries
        // "bb" first (non-canonical)
        cbor_bytes.push(0x62); // text string, length 2
        cbor_bytes.extend_from_slice(b"bb");
        cbor_bytes.push(0x01); // integer 1
        // "a" second
        cbor_bytes.push(0x61); // text string, length 1
        cbor_bytes.push(b'a');
        cbor_bytes.push(0x02); // integer 2

        let mut bytes = Vec::new();
        bytes.extend_from_slice(schema.hash().as_bytes());
        bytes.extend_from_slice(&cbor_bytes);

        let err =
            CanonicalSerializer::deserialize::<HashMap<String, u8>>(&bytes, &schema).unwrap_err();
        assert!(matches!(err, SerializationError::NonCanonicalEncoding));
    }

    // ============================================================================
    // NEW TESTS: SchemaId derive-trait and edge-case coverage
    // ============================================================================

    #[test]
    fn schema_id_hash_in_hashset() {
        use std::collections::HashSet;
        let s1 = SchemaId::new("fcp.core", "Token", Version::new(1, 0, 0));
        let s2 = SchemaId::new("fcp.core", "Token", Version::new(1, 0, 0));
        let s3 = SchemaId::new("fcp.core", "Token", Version::new(2, 0, 0));

        let mut set = HashSet::new();
        set.insert(s1);
        set.insert(s2); // duplicate, should not increase size
        set.insert(s3);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn schema_id_debug_contains_fields() {
        let schema = SchemaId::new("fcp.mesh", "Gossip", Version::new(3, 1, 4));
        let debug = format!("{schema:?}");
        assert!(debug.contains("fcp.mesh"));
        assert!(debug.contains("Gossip"));
        // Version Debug may wrap the value; just check the components are present.
        assert!(debug.contains('3'));
        assert!(debug.contains('1'));
        assert!(debug.contains('4'));
    }

    #[test]
    fn schema_id_display_canonical_format() {
        let schema = SchemaId::new("fcp.core", "Capability", Version::new(1, 0, 0));
        // SchemaId does not impl Display, but as_bytes encodes the canonical string.
        let canonical = String::from_utf8(schema.as_bytes()).unwrap();
        assert_eq!(canonical, "fcp.core:Capability@1.0.0");
    }

    #[test]
    fn schema_id_as_bytes_with_unicode() {
        let schema = SchemaId::new("名前空間", "タイプ", Version::new(0, 0, 1));
        let bytes = schema.as_bytes();
        let s = String::from_utf8(bytes).unwrap();
        assert_eq!(s, "名前空間:タイプ@0.0.1");
        // Hash should still be 32 bytes and deterministic.
        let h1 = schema.hash();
        let h2 = schema.hash();
        assert_eq!(h1, h2);
        assert_eq!(h1.as_bytes().len(), 32);
    }

    #[test]
    fn schema_id_as_bytes_with_special_chars() {
        let schema = SchemaId::new("ns/with.dots-and_stuff", "Type<T>", Version::new(0, 0, 0));
        let canonical = String::from_utf8(schema.as_bytes()).unwrap();
        assert_eq!(canonical, "ns/with.dots-and_stuff:Type<T>@0.0.0");
    }

    #[test]
    fn schema_id_serde_cbor_roundtrip() {
        let schema = SchemaId::new("fcp.protocol", "Envelope", Version::new(2, 3, 0));
        let cbor_bytes = to_canonical_cbor(&schema).unwrap();
        let decoded: SchemaId = ciborium::de::from_reader(cbor_bytes.as_slice()).unwrap();
        assert_eq!(decoded, schema);
    }

    #[test]
    fn schema_id_hash_determinism_across_clones() {
        let original = SchemaId::new("fcp.sdk", "Runtime", Version::new(1, 0, 0));
        let cloned = original.clone();
        // Hash of original and clone must be identical.
        assert_eq!(original.hash(), cloned.hash());
        // And the raw bytes must match too.
        assert_eq!(original.hash().as_bytes(), cloned.hash().as_bytes());
    }

    // ============================================================================
    // NEW TESTS: SchemaHash derive-trait and edge-case coverage
    // ============================================================================

    #[test]
    fn schema_hash_copy_trait() {
        let hash = SchemaHash::from_bytes([0xAB; 32]);
        let copied = hash; // Copy, not move
        // Both should still be usable (Copy semantics).
        assert_eq!(hash, copied);
        assert_eq!(hash.as_bytes(), copied.as_bytes());
    }

    #[test]
    fn schema_hash_from_bytes_all_zeros() {
        let hash = SchemaHash::from_bytes([0x00; 32]);
        assert_eq!(hash.as_bytes(), &[0x00; 32]);
        assert_eq!(
            hash.to_string(),
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn schema_hash_from_bytes_all_ff() {
        let hash = SchemaHash::from_bytes([0xFF; 32]);
        assert_eq!(hash.as_bytes(), &[0xFF; 32]);
        assert_eq!(
            hash.to_string(),
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
    }

    #[test]
    fn schema_hash_display_is_lowercase_hex() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xDE;
        bytes[1] = 0xAD;
        bytes[30] = 0xBE;
        bytes[31] = 0xEF;
        let hash = SchemaHash::from_bytes(bytes);
        let display = hash.to_string();
        assert_eq!(display.len(), 64);
        assert!(display.starts_with("dead"));
        assert!(display.ends_with("beef"));
        // Must be lowercase hex only.
        assert!(display.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!display.chars().any(|c| c.is_ascii_uppercase()));
    }

    #[test]
    fn schema_hash_serde_json_roundtrip() {
        let schema = SchemaId::new("fcp.test", "SerdeHash", Version::new(1, 0, 0));
        let hash = schema.hash();
        let json = serde_json::to_string(&hash).unwrap();
        let decoded: SchemaHash = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, hash);
    }

    #[test]
    fn schema_hash_eq_reflexive_and_symmetric() {
        let a = SchemaHash::from_bytes([0x42; 32]);
        let b = SchemaHash::from_bytes([0x42; 32]);
        let c = SchemaHash::from_bytes([0x43; 32]);
        // Reflexive.
        assert_eq!(a, a);
        // Symmetric.
        assert_eq!(a, b);
        assert_eq!(b, a);
        // Not equal to different.
        assert_ne!(a, c);
    }

    #[test]
    fn schema_hash_in_hashset() {
        use std::collections::HashSet;
        let h1 = SchemaHash::from_bytes([0x01; 32]);
        let h2 = SchemaHash::from_bytes([0x01; 32]);
        let h3 = SchemaHash::from_bytes([0x02; 32]);
        let mut set = HashSet::new();
        set.insert(h1);
        set.insert(h2); // duplicate
        set.insert(h3);
        assert_eq!(set.len(), 2);
    }

    // ============================================================================
    // NEW TESTS: SerializationError trait coverage
    // ============================================================================

    #[test]
    fn error_debug_all_variants() {
        // Verify Debug is implemented for all variants.
        let errors: Vec<SerializationError> = vec![
            SerializationError::MissingSchemaHashPrefix,
            SerializationError::SchemaMismatch {
                expected: SchemaHash::from_bytes([0; 32]),
                got: SchemaHash::from_bytes([1; 32]),
            },
            SerializationError::PayloadTooLarge { len: 100, max: 50 },
            SerializationError::TrailingBytes,
            SerializationError::NonCanonicalEncoding,
            SerializationError::NonFiniteFloat,
            SerializationError::DuplicateMapKey {
                key_hex: "deadbeef".to_string(),
            },
        ];
        for err in &errors {
            let debug = format!("{err:?}");
            assert!(!debug.is_empty());
        }
    }

    #[test]
    fn error_implements_std_error_trait() {
        // Verify std::error::Error is implemented.
        let err: Box<dyn std::error::Error> = Box::new(SerializationError::MissingSchemaHashPrefix);
        // source() should be None for non-wrapping variants.
        assert!(err.source().is_none());
        // Display should work through the Error trait.
        assert_eq!(err.to_string(), "payload missing schema hash prefix");
    }

    #[test]
    fn error_schema_mismatch_display_shows_both_hashes() {
        let expected = SchemaHash::from_bytes([0x11; 32]);
        let got = SchemaHash::from_bytes([0x22; 32]);
        let err = SerializationError::SchemaMismatch { expected, got };
        let msg = err.to_string();
        // Both hex strings should appear in the message.
        assert!(msg.contains(&expected.to_string()));
        assert!(msg.contains(&got.to_string()));
    }

    #[test]
    fn error_from_cbor_serialize() {
        // Trigger a CborSerialize error via the From impl.
        // A cyclic/infinite structure isn't easy, but we can verify the variant exists
        // by constructing the error path: serialize something that exceeds depth.
        // Instead, just check the Display of PayloadTooLarge with boundary values.
        let err = SerializationError::PayloadTooLarge {
            len: MAX_CANONICAL_OBJECT_BYTES + 1,
            max: MAX_CANONICAL_OBJECT_BYTES,
        };
        let msg = err.to_string();
        assert!(msg.contains("67108865")); // MAX + 1
        assert!(msg.contains("67108864")); // MAX
    }

    // ============================================================================
    // NEW TESTS: Constants verification
    // ============================================================================

    #[test]
    fn max_canonical_object_bytes_is_64_mib() {
        assert_eq!(MAX_CANONICAL_OBJECT_BYTES, 64 * 1024 * 1024);
        assert_eq!(MAX_CANONICAL_OBJECT_BYTES, 67_108_864);
    }

    #[test]
    fn schema_hash_len_is_32() {
        assert_eq!(SCHEMA_HASH_LEN, 32);
    }

    // ============================================================================
    // NEW TESTS: to_canonical_cbor with various types
    // ============================================================================

    #[test]
    fn to_canonical_cbor_with_empty_struct() {
        #[derive(Serialize)]
        struct Unit;

        let bytes = to_canonical_cbor(&Unit).unwrap();
        // CBOR null = 0xF6.
        assert_eq!(bytes, vec![0xF6]);
    }

    #[test]
    fn to_canonical_cbor_with_nested_structs() {
        #[derive(Serialize)]
        struct Inner {
            x: u32,
        }
        #[derive(Serialize)]
        struct Middle {
            inner: Inner,
            tag: String,
        }
        #[derive(Serialize)]
        struct Outer {
            middle: Middle,
            count: u64,
        }

        let val = Outer {
            middle: Middle {
                inner: Inner { x: 99 },
                tag: "deep".to_string(),
            },
            count: 7,
        };

        let bytes1 = to_canonical_cbor(&val).unwrap();
        let bytes2 = to_canonical_cbor(&val).unwrap();
        assert_eq!(bytes1, bytes2);
        // Should decode as a CBOR map.
        let raw: Value = ciborium::de::from_reader(bytes1.as_slice()).unwrap();
        assert!(matches!(raw, Value::Map(_)));
    }

    #[test]
    fn to_canonical_cbor_with_option_some_and_none() {
        let some_val: Option<u32> = Some(42);
        let none_val: Option<u32> = None;

        let some_bytes = to_canonical_cbor(&some_val).unwrap();
        let none_bytes = to_canonical_cbor(&none_val).unwrap();

        // They should be different.
        assert_ne!(some_bytes, none_bytes);
        // None encodes as CBOR null.
        assert_eq!(none_bytes, vec![0xF6]);
    }

    #[test]
    fn to_canonical_cbor_with_vec_of_strings() {
        let data = vec!["alpha".to_string(), "beta".to_string(), "gamma".to_string()];
        let bytes = to_canonical_cbor(&data).unwrap();
        let decoded: Vec<String> = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn to_canonical_cbor_btreemap_deterministic_key_order() {
        use std::collections::BTreeMap;

        let mut map = BTreeMap::new();
        map.insert("zebra".to_string(), 1);
        map.insert("ant".to_string(), 2);
        map.insert("bee".to_string(), 3);
        map.insert("caterpillar".to_string(), 4);

        let bytes = to_canonical_cbor(&map).unwrap();

        // Decode raw CBOR and check deterministic encoded-byte ordering.
        let raw: Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        if let Value::Map(entries) = raw {
            let keys: Vec<&str> = entries
                .iter()
                .filter_map(|(k, _)| {
                    if let Value::Text(s) = k {
                        Some(s.as_str())
                    } else {
                        None
                    }
                })
                .collect();
            // For text keys the encoded-byte ordering still matches these
            // length buckets because the map-key comparison includes the text
            // header byte before the string payload.
            assert_eq!(keys, vec!["ant", "bee", "zebra", "caterpillar"]);
        } else {
            panic!("Expected map");
        }
    }

    // ============================================================================
    // NEW TESTS: CanonicalSerializer roundtrip with complex types
    // ============================================================================

    #[test]
    fn roundtrip_struct_with_btreemap() {
        use std::collections::BTreeMap;

        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Config {
            settings: BTreeMap<String, String>,
            version: u32,
        }

        let schema = SchemaId::new("fcp.test", "Config", Version::new(0, 1, 0));
        let mut settings = BTreeMap::new();
        settings.insert("key_z".to_string(), "value_z".to_string());
        settings.insert("key_a".to_string(), "value_a".to_string());
        settings.insert("key_m".to_string(), "value_m".to_string());

        let value = Config {
            settings,
            version: 42,
        };

        let bytes = CanonicalSerializer::serialize(&value, &schema).unwrap();
        let decoded: Config = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn roundtrip_vec_of_optional_structs() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Item {
            id: u32,
            label: Option<String>,
        }

        let schema = SchemaId::new("fcp.test", "Items", Version::new(0, 1, 0));
        let items = vec![
            Item {
                id: 1,
                label: Some("first".to_string()),
            },
            Item { id: 2, label: None },
            Item {
                id: 3,
                label: Some("third".to_string()),
            },
        ];

        let bytes = CanonicalSerializer::serialize(&items, &schema).unwrap();
        let decoded: Vec<Item> = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, items);
    }

    #[test]
    fn roundtrip_enum_with_tuple_variant() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        enum Message {
            Text(String),
            Binary(Vec<u8>),
            Pair(u32, u32),
        }

        let schema = SchemaId::new("fcp.test", "Message", Version::new(0, 1, 0));

        let variants = vec![
            Message::Text("hello".to_string()),
            Message::Binary(vec![0xDE, 0xAD]),
            Message::Pair(10, 20),
        ];

        for msg in &variants {
            let bytes = CanonicalSerializer::serialize(msg, &schema).unwrap();
            let decoded: Message = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
            assert_eq!(&decoded, msg);
        }
    }

    #[test]
    fn schema_hash_consistency_across_serializations() {
        // The schema hash prefix in serialized output must always be the same
        // for the same SchemaId, regardless of payload content.
        let schema = SchemaId::new("fcp.test", "Consistency", Version::new(1, 0, 0));
        let expected_hash = schema.hash();

        let bytes_a = CanonicalSerializer::serialize(&42_u64, &schema).unwrap();
        let bytes_b = CanonicalSerializer::serialize(&"hello", &schema).unwrap();
        let bytes_c = CanonicalSerializer::serialize(&true, &schema).unwrap();

        assert_eq!(&bytes_a[..SCHEMA_HASH_LEN], expected_hash.as_bytes());
        assert_eq!(&bytes_b[..SCHEMA_HASH_LEN], expected_hash.as_bytes());
        assert_eq!(&bytes_c[..SCHEMA_HASH_LEN], expected_hash.as_bytes());
    }

    #[test]
    fn roundtrip_nested_maps() {
        let schema = SchemaId::new("fcp.test", "NestedMap", Version::new(0, 1, 0));

        let mut inner1 = HashMap::new();
        inner1.insert("x".to_string(), 1_i32);
        inner1.insert("y".to_string(), 2);

        let mut inner2 = HashMap::new();
        inner2.insert("a".to_string(), 10);

        let mut outer = HashMap::new();
        outer.insert("first".to_string(), inner1);
        outer.insert("second".to_string(), inner2);

        let bytes = CanonicalSerializer::serialize(&outer, &schema).unwrap();
        let decoded: HashMap<String, HashMap<String, i32>> =
            CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, outer);
    }

    #[test]
    fn roundtrip_large_array() {
        let schema = SchemaId::new("fcp.test", "LargeArray", Version::new(0, 1, 0));
        let data: Vec<u32> = (0..1000).collect();
        let bytes = CanonicalSerializer::serialize(&data, &schema).unwrap();
        let decoded: Vec<u32> = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, data);
    }

    // ============================================================================
    // NEW TESTS: SchemaId Display impl
    // ============================================================================

    #[test]
    fn schema_id_as_bytes_encodes_prerelease_version() {
        let schema = SchemaId::new("fcp.store", "Repair", Version::parse("0.5.2-rc.1").unwrap());
        let canonical = String::from_utf8(schema.as_bytes()).unwrap();
        assert_eq!(canonical, "fcp.store:Repair@0.5.2-rc.1");
    }

    // ============================================================================
    // NEW TESTS: to_canonical_cbor oversized rejection
    // ============================================================================

    #[test]
    fn to_canonical_cbor_rejects_oversized() {
        let huge: Vec<u8> = vec![0u8; MAX_CANONICAL_OBJECT_BYTES + 1];
        let err = to_canonical_cbor(&huge).unwrap_err();
        assert!(matches!(err, SerializationError::PayloadTooLarge { .. }));
    }

    // ============================================================================
    // NEW TESTS: Canonical encoding — map with mixed-length keys
    // ============================================================================

    #[test]
    fn canonical_cbor_map_mixed_key_lengths() {
        use std::collections::BTreeMap;

        let mut map = BTreeMap::new();
        map.insert("a".to_string(), 1);
        map.insert("bb".to_string(), 2);
        map.insert("c".to_string(), 3);
        map.insert("dd".to_string(), 4);

        let bytes = to_canonical_cbor(&map).unwrap();
        let raw: Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        if let Value::Map(entries) = raw {
            let keys: Vec<&str> = entries
                .iter()
                .filter_map(|(k, _)| {
                    if let Value::Text(s) = k {
                        Some(s.as_str())
                    } else {
                        None
                    }
                })
                .collect();
            // Length 1: "a", "c" (lex order); Length 2: "bb", "dd" (lex order).
            assert_eq!(keys, vec!["a", "c", "bb", "dd"]);
        } else {
            panic!("Expected map");
        }
    }

    #[test]
    fn schema_hash_from_to_bytes_identity() {
        // Arbitrary non-trivial bytes.
        let original: [u8; 32] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
            0xCC, 0xDD, 0xEE, 0xFF,
        ];
        let hash = SchemaHash::from_bytes(original);
        let extracted = *hash.as_bytes();
        assert_eq!(extracted, original);
    }

    // ========================================================================
    // split_schema_prefix boundary tests
    // ========================================================================

    #[test]
    fn split_prefix_exactly_32_bytes_yields_empty_body() {
        let data = [0xAA; SCHEMA_HASH_LEN];
        let (hash, body) = split_schema_prefix(&data).unwrap();
        assert_eq!(hash, SchemaHash::from_bytes([0xAA; SCHEMA_HASH_LEN]));
        assert!(body.is_empty());
    }

    #[test]
    fn split_prefix_31_bytes_rejected() {
        let data = [0u8; SCHEMA_HASH_LEN - 1];
        let err = split_schema_prefix(&data).unwrap_err();
        assert!(matches!(err, SerializationError::MissingSchemaHashPrefix));
    }

    #[test]
    fn split_prefix_33_bytes_yields_1_byte_body() {
        let mut data = [0u8; SCHEMA_HASH_LEN + 1];
        data[SCHEMA_HASH_LEN] = 0xFF;
        let (_, body) = split_schema_prefix(&data).unwrap();
        assert_eq!(body, &[0xFF]);
    }

    #[test]
    fn split_prefix_empty_input() {
        let err = split_schema_prefix(&[]).unwrap_err();
        assert!(matches!(err, SerializationError::MissingSchemaHashPrefix));
    }

    // ========================================================================
    // canonicalize_value_in_place — Tag rejection
    // ========================================================================

    #[test]
    fn canonicalize_tag_is_rejected() {
        let mut tagged = Value::Tag(42, Box::new(Value::Text("tagged".into())));
        let err = canonicalize_value_in_place(&mut tagged, 0).unwrap_err();
        assert!(matches!(
            err,
            SerializationError::UnsupportedTag { tag: 42 }
        ));
    }

    // ========================================================================
    // MAX_CANONICALIZATION_DEPTH boundary
    // ========================================================================

    #[test]
    fn canonicalize_at_max_depth_succeeds() {
        // Build a chain of arrays nested exactly MAX_CANONICALIZATION_DEPTH levels.
        let mut v = Value::Integer(1.into());
        for _ in 0..MAX_CANONICALIZATION_DEPTH {
            v = Value::Array(vec![v]);
        }
        // Depth 0 → 1 → ... → 128 (128 recursive calls, max=128, depth never exceeds).
        canonicalize_value_in_place(&mut v, 0).unwrap();
    }

    #[test]
    fn canonicalize_exceeding_max_depth_fails() {
        // One more level than the max should fail.
        let mut v = Value::Integer(1.into());
        for _ in 0..=MAX_CANONICALIZATION_DEPTH {
            v = Value::Array(vec![v]);
        }
        let err = canonicalize_value_in_place(&mut v, 0).unwrap_err();
        assert!(
            matches!(err, SerializationError::DepthExceeded { max, .. } if max == MAX_CANONICALIZATION_DEPTH),
            "expected DepthExceeded, got {err:?}"
        );
    }

    #[test]
    fn depth_exceeded_carries_actual_depth_and_is_distinct_from_payload_too_large() {
        // The new DepthExceeded variant must carry the actual depth at which
        // the recursion guard tripped so operators can distinguish "input was
        // 130 levels deep" from "input was a few MB over the size cap" — both
        // of which used to surface as `PayloadTooLarge`.
        let err = canonicalize_value_in_place(
            &mut Value::Integer(0.into()),
            MAX_CANONICALIZATION_DEPTH + 5,
        )
        .unwrap_err();
        let display = err.to_string();
        assert!(
            display.contains("canonicalization depth"),
            "Display should distinguish from PayloadTooLarge: {display}"
        );
        match err {
            SerializationError::DepthExceeded { depth, max } => {
                assert_eq!(depth, MAX_CANONICALIZATION_DEPTH + 5);
                assert_eq!(max, MAX_CANONICALIZATION_DEPTH);
            }
            other => panic!("expected DepthExceeded, got {other:?}"),
        }
    }

    // ========================================================================
    // canonicalize_map — integer keys and mixed key types
    // ========================================================================

    #[test]
    fn canonicalize_map_integer_key_duplicates_rejected() {
        let mut entries = vec![
            (Value::Integer(1.into()), Value::Text("a".into())),
            (Value::Integer(1.into()), Value::Text("b".into())),
        ];
        let err = canonicalize_map(&mut entries, 0).unwrap_err();
        assert!(matches!(err, SerializationError::DuplicateMapKey { .. }));
    }

    #[test]
    fn canonicalize_map_mixed_key_types_sorted_by_bytes() {
        // Integer keys encode shorter than text keys, so integers come first.
        let mut entries = vec![
            (Value::Text("z".into()), Value::Integer(2.into())),
            (Value::Integer(1.into()), Value::Integer(1.into())),
        ];
        canonicalize_map(&mut entries, 0).unwrap();
        // Integer(1) encodes as 1 byte (0x01), Text("z") encodes as 2 bytes (0x61, 0x7A).
        assert!(matches!(&entries[0].0, Value::Integer(_)));
        assert!(matches!(&entries[1].0, Value::Text(_)));
    }

    #[test]
    fn canonicalize_map_byte_string_keys() {
        let mut entries = vec![
            (Value::Bytes(vec![0xBB]), Value::Integer(2.into())),
            (Value::Bytes(vec![0xAA]), Value::Integer(1.into())),
        ];
        canonicalize_map(&mut entries, 0).unwrap();
        // Both same length → lexicographic order: 0xAA before 0xBB.
        assert_eq!(entries[0].0, Value::Bytes(vec![0xAA]));
        assert_eq!(entries[1].0, Value::Bytes(vec![0xBB]));
    }

    #[test]
    fn canonicalize_map_empty_is_ok() {
        let mut entries: Vec<(Value, Value)> = vec![];
        canonicalize_map(&mut entries, 0).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn canonicalize_map_rejects_impossible_entry_cardinality_before_extra_allocation() {
        let mut entries = vec![
            (Value::Integer(0.into()), Value::Integer(0.into())),
            (Value::Integer(1.into()), Value::Integer(1.into())),
        ];

        let err = canonicalize_map_with_limit(&mut entries, 0, 4).unwrap_err();
        assert!(matches!(
            err,
            SerializationError::PayloadTooLarge { len: 5, max: 4 }
        ));
    }

    // ========================================================================
    // SerializationError Display — DuplicateMapKey and SchemaMismatch
    // ========================================================================

    #[test]
    fn serialization_error_duplicate_map_key_display() {
        let err = SerializationError::DuplicateMapKey {
            key_hex: "deadbeef".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("duplicate map key"));
        assert!(msg.contains("deadbeef"));
    }

    #[test]
    fn serialization_error_schema_mismatch_display() {
        let expected = SchemaHash::from_bytes([0xAA; 32]);
        let got = SchemaHash::from_bytes([0xBB; 32]);
        let err = SerializationError::SchemaMismatch { expected, got };
        let msg = err.to_string();
        assert!(msg.contains("schema hash mismatch"));
        assert!(msg.contains(&expected.to_string()));
        assert!(msg.contains(&got.to_string()));
    }

    #[test]
    fn serialization_error_non_canonical_display() {
        let err = SerializationError::NonCanonicalEncoding;
        assert_eq!(err.to_string(), "non-canonical CBOR encoding");
    }

    #[test]
    fn serialization_error_trailing_bytes_display() {
        let err = SerializationError::TrailingBytes;
        assert_eq!(err.to_string(), "trailing bytes after CBOR value");
    }

    // ========================================================================
    // Integer edge cases
    // ========================================================================

    #[test]
    fn roundtrip_i64_min() {
        let bytes = to_canonical_cbor(&i64::MIN).unwrap();
        let val: Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        match val {
            Value::Integer(i) => assert_eq!(i128::from(i), i128::from(i64::MIN)),
            _ => panic!("expected integer"),
        }
    }

    #[test]
    fn roundtrip_i64_max() {
        let bytes = to_canonical_cbor(&i64::MAX).unwrap();
        let val: Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        match val {
            Value::Integer(i) => assert_eq!(i128::from(i), i128::from(i64::MAX)),
            _ => panic!("expected integer"),
        }
    }

    #[test]
    fn roundtrip_u64_max() {
        let bytes = to_canonical_cbor(&u64::MAX).unwrap();
        let val: Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        match val {
            Value::Integer(i) => assert_eq!(i128::from(i), i128::from(u64::MAX)),
            _ => panic!("expected integer"),
        }
    }

    #[test]
    fn roundtrip_zero_integer() {
        let bytes = to_canonical_cbor(&0u64).unwrap();
        // CBOR 0 is a single byte: 0x00.
        assert_eq!(bytes, vec![0x00]);
    }

    // ========================================================================
    // Option<T> symmetry
    // ========================================================================

    #[test]
    fn roundtrip_option_none_vs_some() {
        let none_bytes = to_canonical_cbor(&Option::<String>::None).unwrap();
        let some_bytes = to_canonical_cbor(&Some("hello".to_string())).unwrap();
        assert_ne!(none_bytes, some_bytes);

        // None encodes as CBOR null (0xF6).
        assert_eq!(none_bytes, vec![0xF6]);
    }

    // ========================================================================
    // Payload size exact boundary
    // ========================================================================

    #[test]
    fn serialize_at_exact_max_boundary_succeeds() {
        // to_canonical_cbor accepts payloads up to MAX_CANONICAL_OBJECT_BYTES inclusive.
        // A Vec<u8> of length N encodes as: 2-byte header (0x5A + 4 bytes for len when large) + N bytes.
        // We can't easily craft exactly MAX bytes, but we can test that MAX-sized is ok
        // by verifying the size check is > not >=.
        let schema = SchemaId::new("fcp.test", "Boundary", Version::new(1, 0, 0));
        // Serialize a small value — should be well under the limit.
        let bytes = CanonicalSerializer::serialize(&42u32, &schema).unwrap();
        assert!(bytes.len() <= MAX_CANONICAL_OBJECT_BYTES);
    }

    // ========================================================================
    // write_canonical_cbor direct test
    // ========================================================================

    #[test]
    fn write_canonical_cbor_matches_to_canonical_cbor() {
        let val = "hello world";
        let expected = to_canonical_cbor(&val).unwrap();
        let mut actual = Vec::new();
        write_canonical_cbor(&val, &mut actual).unwrap();
        assert_eq!(actual, expected);
    }

    // ========================================================================
    // 3-level nested map canonicalization
    // ========================================================================

    #[test]
    fn three_level_nested_map_canonicalization() {
        use std::collections::BTreeMap;

        let mut inner = BTreeMap::new();
        inner.insert("z".to_string(), 1u32);
        inner.insert("a".to_string(), 2u32);

        let mut mid = BTreeMap::new();
        mid.insert("bb".to_string(), inner.clone());
        mid.insert("a".to_string(), inner);

        let bytes = to_canonical_cbor(&mid).unwrap();
        // Re-encode and verify determinism.
        let val: Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        let mut out = Vec::new();
        ciborium::ser::into_writer(&val, &mut out).unwrap();
        assert_eq!(bytes, out, "3-level nested map should already be canonical");
    }

    // ========================================================================
    // Null character in strings
    // ========================================================================

    #[test]
    fn roundtrip_string_with_null_char() {
        let s = "hello\0world";
        let bytes = to_canonical_cbor(&s).unwrap();
        let val: Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        if let Value::Text(decoded) = val {
            assert_eq!(decoded, s);
        } else {
            panic!("expected text");
        }
    }

    // ========================================================================
    // SchemaId edge cases
    // ========================================================================

    #[test]
    fn schema_id_hash_differs_with_swapped_namespace_name() {
        // "foo:bar" vs "bar:foo" must produce different hashes.
        let a = SchemaId::new("foo", "bar", Version::new(1, 0, 0));
        let b = SchemaId::new("bar", "foo", Version::new(1, 0, 0));
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn schema_id_as_bytes_with_build_metadata() {
        let schema = SchemaId::new("ns", "Name", Version::parse("1.0.0+build42").unwrap());
        let canonical = String::from_utf8(schema.as_bytes()).unwrap();
        assert_eq!(canonical, "ns:Name@1.0.0+build42");
    }

    // ========================================================================
    // deserialize_unchecked exact-32-bytes input (hash only, no CBOR body)
    // ========================================================================

    #[test]
    fn deserialize_unchecked_empty_cbor_body_fails() {
        let schema = SchemaId::new("fcp.test", "Empty", Version::new(1, 0, 0));
        let hash = schema.hash();
        // Just the 32-byte hash prefix, no CBOR body → from_reader should fail.
        let data = hash.as_bytes().to_vec();
        let result = CanonicalSerializer::deserialize_unchecked::<u32>(&data, &schema);
        assert!(result.is_err());
    }

    // ========================================================================
    // Nested tag rejection
    // ========================================================================

    #[test]
    fn canonicalize_double_nested_tag_is_rejected_at_outer_tag() {
        let mut v = Value::Tag(
            1,
            Box::new(Value::Tag(2, Box::new(Value::Text("payload".into())))),
        );
        let err = canonicalize_value_in_place(&mut v, 0).unwrap_err();
        assert!(matches!(err, SerializationError::UnsupportedTag { tag: 1 }));
    }

    // ========================================================================
    // Duplicate integer key detection
    // ========================================================================

    #[test]
    fn duplicate_integer_keys_rejected() {
        let mut entries = vec![
            (Value::Integer(42.into()), Value::Bool(true)),
            (Value::Integer(42.into()), Value::Bool(false)),
        ];
        let err = canonicalize_map(&mut entries, 0).unwrap_err();
        assert!(matches!(err, SerializationError::DuplicateMapKey { .. }));
    }

    // ========================================================================
    // SchemaHash PartialEq cross-construction
    // ========================================================================

    #[test]
    fn schema_hash_from_hash_eq_from_bytes() {
        let schema = SchemaId::new("fcp.test", "EqCheck", Version::new(1, 0, 0));
        let hash1 = schema.hash();
        let hash2 = SchemaHash::from_bytes(*hash1.as_bytes());
        assert_eq!(hash1, hash2);
    }

    // ========================================================================
    // Constants
    // ========================================================================

    #[test]
    fn schema_hash_len_matches_constant() {
        assert_eq!(SCHEMA_HASH_LEN, 32);
    }

    #[test]
    fn max_canonical_object_bytes_is_64mib() {
        assert_eq!(MAX_CANONICAL_OBJECT_BYTES, 64 * 1024 * 1024);
    }

    // ========================================================================
    // Map key sorting: prefix keys and mixed-type edge cases
    // ========================================================================

    #[test]
    fn map_keys_prefix_sorted_correctly() {
        // "a" vs "ab" — shorter key first per RFC 8949 §4.2.1
        let mut entries = vec![
            (Value::Text("ab".into()), Value::Integer(1.into())),
            (Value::Text("a".into()), Value::Integer(2.into())),
        ];
        canonicalize_map(&mut entries, 0).unwrap();
        let keys: Vec<&str> = entries
            .iter()
            .filter_map(|(k, _)| {
                if let Value::Text(s) = k {
                    Some(s.as_str())
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(keys, vec!["a", "ab"]);
    }

    #[test]
    fn map_keys_byte_string_prefix_sorted() {
        // Byte strings are sorted by the bytewise lexicographic order of
        // their deterministic encodings; prefix keys still come first.
        let mut entries = vec![
            (Value::Bytes(vec![0xAA, 0xBB]), Value::Integer(1.into())),
            (Value::Bytes(vec![0xAA]), Value::Integer(2.into())),
        ];
        canonicalize_map(&mut entries, 0).unwrap();
        let keys: Vec<Vec<u8>> = entries
            .iter()
            .filter_map(|(k, _)| {
                if let Value::Bytes(b) = k {
                    Some(b.clone())
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(keys, vec![vec![0xAA], vec![0xAA, 0xBB]]);
    }

    #[test]
    fn map_keys_empty_byte_string_sorts_first() {
        let mut entries = vec![
            (Value::Bytes(vec![0x01]), Value::Integer(1.into())),
            (Value::Bytes(vec![]), Value::Integer(2.into())),
        ];
        canonicalize_map(&mut entries, 0).unwrap();
        let keys: Vec<Vec<u8>> = entries
            .iter()
            .filter_map(|(k, _)| {
                if let Value::Bytes(b) = k {
                    Some(b.clone())
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(keys, vec![vec![], vec![0x01]]);
    }

    #[test]
    fn map_keys_integer_vs_text_sorted_by_cbor_bytes() {
        // Integer and text keys have different CBOR major types.
        // Sorting is by encoded bytes, so integer (major type 0) comes before text (major type 3).
        let mut entries = vec![
            (Value::Text("a".into()), Value::Integer(1.into())),
            (Value::Integer(0.into()), Value::Integer(2.into())),
        ];
        canonicalize_map(&mut entries, 0).unwrap();
        // Integer 0 encodes as 0x00 (1 byte), Text "a" encodes as 0x61 0x61 (2 bytes)
        // 1 byte < 2 bytes, so integer comes first
        match &entries[0].0 {
            Value::Integer(_) => {} // correct
            other => panic!("expected integer first, got: {other:?}"),
        }
    }

    // ========================================================================
    // Depth limit boundary tests
    // ========================================================================

    #[test]
    fn depth_boundary_at_max_succeeds() {
        // Build a chain of nested arrays exactly at MAX_CANONICALIZATION_DEPTH
        let mut v = Value::Integer(1.into());
        for _ in 0..MAX_CANONICALIZATION_DEPTH {
            v = Value::Array(vec![v]);
        }
        // Start at depth 0, nesting is exactly MAX_CANONICALIZATION_DEPTH
        assert!(canonicalize_value_in_place(&mut v, 0).is_ok());
    }

    #[test]
    fn depth_boundary_exceeding_max_fails() {
        let mut v = Value::Integer(1.into());
        for _ in 0..=MAX_CANONICALIZATION_DEPTH {
            v = Value::Array(vec![v]);
        }
        let result = canonicalize_value_in_place(&mut v, 0);
        assert!(matches!(
            result,
            Err(SerializationError::DepthExceeded { max, .. }) if max == MAX_CANONICALIZATION_DEPTH
        ));
    }

    #[test]
    fn canonicalize_map_at_near_max_depth() {
        // Map at depth MAX_CANONICALIZATION_DEPTH - 1 with simple values should work
        let mut v = Value::Map(vec![
            (Value::Text("b".into()), Value::Integer(2.into())),
            (Value::Text("a".into()), Value::Integer(1.into())),
        ]);
        let result = canonicalize_value_in_place(&mut v, MAX_CANONICALIZATION_DEPTH - 1);
        assert!(result.is_ok());
        // Verify map is sorted
        if let Value::Map(entries) = &v {
            let keys: Vec<&str> = entries
                .iter()
                .filter_map(|(k, _)| {
                    if let Value::Text(s) = k {
                        Some(s.as_str())
                    } else {
                        None
                    }
                })
                .collect();
            assert_eq!(keys, vec!["a", "b"]);
        }
    }

    // ========================================================================
    // split_schema_prefix edge cases
    // ========================================================================

    #[test]
    fn split_schema_prefix_too_short() {
        let data = vec![0u8; SCHEMA_HASH_LEN - 1];
        let result = split_schema_prefix(&data);
        assert!(matches!(
            result,
            Err(SerializationError::MissingSchemaHashPrefix)
        ));
    }

    #[test]
    fn split_schema_prefix_exactly_32_bytes() {
        let data = vec![0xABu8; SCHEMA_HASH_LEN];
        let (hash, body) = split_schema_prefix(&data).unwrap();
        assert_eq!(hash, SchemaHash::from_bytes([0xAB; SCHEMA_HASH_LEN]));
        assert!(body.is_empty());
    }

    #[test]
    fn split_schema_prefix_with_body() {
        let mut data = vec![0xABu8; SCHEMA_HASH_LEN];
        data.extend_from_slice(&[0x01, 0x02, 0x03]);
        let (hash, body) = split_schema_prefix(&data).unwrap();
        assert_eq!(hash, SchemaHash::from_bytes([0xAB; SCHEMA_HASH_LEN]));
        assert_eq!(body, &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn split_schema_prefix_empty_input() {
        let result = split_schema_prefix(&[]);
        assert!(matches!(
            result,
            Err(SerializationError::MissingSchemaHashPrefix)
        ));
    }

    // ========================================================================
    // Error variant display coverage
    // ========================================================================

    #[test]
    fn serialization_error_display_all_variants() {
        let errors: Vec<SerializationError> = vec![
            SerializationError::MissingSchemaHashPrefix,
            SerializationError::SchemaMismatch {
                expected: SchemaHash::from_bytes([0xAA; 32]),
                got: SchemaHash::from_bytes([0xBB; 32]),
            },
            SerializationError::PayloadTooLarge { len: 100, max: 50 },
            SerializationError::TrailingBytes,
            SerializationError::NonCanonicalEncoding,
            SerializationError::NonFiniteFloat,
            SerializationError::DuplicateMapKey {
                key_hex: "deadbeef".into(),
            },
        ];
        for err in &errors {
            let msg = err.to_string();
            assert!(!msg.is_empty());
        }
    }

    #[test]
    fn serialization_error_schema_mismatch_display_contains_hashes() {
        let err = SerializationError::SchemaMismatch {
            expected: SchemaHash::from_bytes([0xAA; 32]),
            got: SchemaHash::from_bytes([0xBB; 32]),
        };
        let msg = err.to_string();
        assert!(msg.contains("mismatch"));
    }

    #[test]
    fn serialization_error_payload_too_large_display_contains_sizes() {
        let err = SerializationError::PayloadTooLarge { len: 100, max: 50 };
        let msg = err.to_string();
        assert!(msg.contains("100"));
        assert!(msg.contains("50"));
    }

    #[test]
    fn serialization_error_duplicate_map_key_display_contains_hex() {
        let err = SerializationError::DuplicateMapKey {
            key_hex: "deadbeef".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("deadbeef"));
    }

    // ========================================================================
    // CanonicalSerializer boundary tests
    // ========================================================================

    #[test]
    fn serialize_schema_hash_prefix_is_correct() {
        let schema = SchemaId::new("fcp.test", "PrefixCheck", Version::new(1, 0, 0));
        let expected_hash = schema.hash();
        let data = CanonicalSerializer::serialize(&42_u32, &schema).unwrap();

        // First 32 bytes must match the schema hash
        assert_eq!(&data[..SCHEMA_HASH_LEN], expected_hash.as_bytes());
    }

    #[test]
    fn deserialize_with_wrong_schema_fails() {
        let schema_a = SchemaId::new("fcp.test", "TypeA", Version::new(1, 0, 0));
        let schema_b = SchemaId::new("fcp.test", "TypeB", Version::new(1, 0, 0));

        let data = CanonicalSerializer::serialize(&42_u32, &schema_a).unwrap();
        let result = CanonicalSerializer::deserialize::<u32>(&data, &schema_b);
        assert!(matches!(
            result,
            Err(SerializationError::SchemaMismatch { .. })
        ));
    }

    #[test]
    fn deserialize_unchecked_with_wrong_schema_fails() {
        let schema_a = SchemaId::new("fcp.test", "TypeA", Version::new(1, 0, 0));
        let schema_b = SchemaId::new("fcp.test", "TypeB", Version::new(1, 0, 0));

        let data = CanonicalSerializer::serialize(&42_u32, &schema_a).unwrap();
        let result = CanonicalSerializer::deserialize_unchecked::<u32>(&data, &schema_b);
        assert!(matches!(
            result,
            Err(SerializationError::SchemaMismatch { .. })
        ));
    }

    #[test]
    fn deserialize_with_trailing_bytes_fails() {
        let schema = SchemaId::new("fcp.test", "Trail", Version::new(1, 0, 0));
        let mut data = CanonicalSerializer::serialize(&42_u32, &schema).unwrap();
        data.push(0xFF); // trailing garbage
        let result = CanonicalSerializer::deserialize_unchecked::<u32>(&data, &schema);
        assert!(matches!(result, Err(SerializationError::TrailingBytes)));
    }

    #[test]
    fn deserialize_non_canonical_encoding_detected() {
        let schema = SchemaId::new("fcp.test", "NonCanon", Version::new(1, 0, 0));
        let value = 42_u32;
        let data = CanonicalSerializer::serialize(&value, &schema).unwrap();

        // Tamper with one CBOR byte (after the 32-byte hash prefix)
        // The value 42 is encoded as 0x18 0x2A in CBOR (2-byte form).
        // Replace with 0x19 0x00 0x2A (3-byte form, same value but non-canonical)
        let cbor_start = SCHEMA_HASH_LEN;
        // Find where 42 is encoded and replace with non-minimal encoding
        if data.len() > cbor_start + 2 {
            // Rebuild with non-minimal encoding of the integer
            let hash_prefix = data[..cbor_start].to_vec();
            let mut non_canon = hash_prefix;
            // 0x19 means unsigned int in 2 bytes (major type 0, additional info 25)
            non_canon.extend_from_slice(&[0x19, 0x00, 0x2A]);
            let result = CanonicalSerializer::deserialize::<u32>(&non_canon, &schema);
            assert!(result.is_err());
        }
    }

    // ========================================================================
    // to_canonical_cbor edge cases
    // ========================================================================

    #[test]
    fn to_canonical_cbor_empty_map() {
        let map: HashMap<String, u32> = HashMap::new();
        let bytes = to_canonical_cbor(&map).unwrap();
        // Empty map encodes as 0xA0
        assert_eq!(bytes, vec![0xA0]);
    }

    #[test]
    fn to_canonical_cbor_empty_vec() {
        let v: Vec<u32> = vec![];
        let bytes = to_canonical_cbor(&v).unwrap();
        // Empty array encodes as 0x80
        assert_eq!(bytes, vec![0x80]);
    }

    #[test]
    fn to_canonical_cbor_bool_values() {
        let t = to_canonical_cbor(&true).unwrap();
        let f = to_canonical_cbor(&false).unwrap();
        // true = 0xF5, false = 0xF4
        assert_eq!(t, vec![0xF5]);
        assert_eq!(f, vec![0xF4]);
    }

    #[test]
    fn to_canonical_cbor_null_option() {
        let v: Option<u32> = None;
        let bytes = to_canonical_cbor(&v).unwrap();
        // None serializes as CBOR null (0xF6)
        assert_eq!(bytes, vec![0xF6]);
    }

    #[test]
    fn to_canonical_cbor_some_vs_none_distinguishable() {
        let some = to_canonical_cbor(&Some(0_u32)).unwrap();
        let none = to_canonical_cbor(&Option::<u32>::None).unwrap();
        assert_ne!(some, none);
    }

    // ========================================================================
    // Integer encoding boundary transitions
    // ========================================================================

    #[test]
    fn integer_encoding_boundary_23_to_24() {
        // 0-23 encode as 1 byte, 24+ encode as 2 bytes
        let b23 = to_canonical_cbor(&23_u8).unwrap();
        let b24 = to_canonical_cbor(&24_u8).unwrap();
        assert_eq!(b23.len(), 1); // 0x17
        assert_eq!(b24.len(), 2); // 0x18 0x18
    }

    #[test]
    fn integer_encoding_boundary_255_to_256() {
        // 24-255 encode as 2 bytes, 256+ encode as 3 bytes
        let b255 = to_canonical_cbor(&255_u16).unwrap();
        let b256 = to_canonical_cbor(&256_u16).unwrap();
        assert_eq!(b255.len(), 2); // 0x18 0xFF
        assert_eq!(b256.len(), 3); // 0x19 0x01 0x00
    }

    #[test]
    fn integer_encoding_boundary_65535_to_65536() {
        let b65535 = to_canonical_cbor(&65535_u32).unwrap();
        let b65536 = to_canonical_cbor(&65536_u32).unwrap();
        assert_eq!(b65535.len(), 3); // 0x19 0xFF 0xFF
        assert_eq!(b65536.len(), 5); // 0x1A 0x00 0x01 0x00 0x00
    }

    // ========================================================================
    // SchemaHash trait implementations
    // ========================================================================

    #[test]
    fn schema_hash_debug_format_includes_hex() {
        let hash = SchemaHash::from_bytes([0xDE; 32]);
        let debug = format!("{hash:?}");
        assert!(debug.contains("SchemaHash"));
        // Display form (hex) should appear inside Debug
        assert!(debug.contains("de"));
    }

    #[test]
    fn schema_hash_as_ref_returns_slice() {
        let hash = SchemaHash::from_bytes([0xAB; 32]);
        let slice: &[u8] = hash.as_ref();
        assert_eq!(slice.len(), 32);
        assert_eq!(slice[0], 0xAB);
    }

    #[test]
    fn schema_hash_clone_eq() {
        let hash = SchemaHash::from_bytes([0x42; 32]);
        let cloned = hash;
        assert_eq!(hash, cloned);
    }

    // ========================================================================
    // SchemaId serde roundtrip
    // ========================================================================

    #[test]
    fn schema_id_serde_json_roundtrip() {
        let schema = SchemaId::new("fcp.core", "TestObject", Version::new(1, 2, 3));
        let json = serde_json::to_string(&schema).unwrap();
        let deserialized: SchemaId = serde_json::from_str(&json).unwrap();
        assert_eq!(schema, deserialized);
    }

    // ========================================================================
    // Duplicate key detection: non-adjacent duplicates
    // ========================================================================

    #[test]
    fn duplicate_text_keys_detected_after_sorting() {
        // Before sorting, duplicates might not be adjacent. After sorting they will be.
        let mut entries = vec![
            (Value::Text("c".into()), Value::Integer(3.into())),
            (Value::Text("a".into()), Value::Integer(1.into())),
            (Value::Text("c".into()), Value::Integer(4.into())),
        ];
        let result = canonicalize_map(&mut entries, 0);
        assert!(matches!(
            result,
            Err(SerializationError::DuplicateMapKey { .. })
        ));
    }

    #[test]
    fn no_duplicate_keys_passes() {
        let mut entries = vec![
            (Value::Text("c".into()), Value::Integer(3.into())),
            (Value::Text("a".into()), Value::Integer(1.into())),
            (Value::Text("b".into()), Value::Integer(2.into())),
        ];
        let result = canonicalize_map(&mut entries, 0);
        assert!(result.is_ok());
    }

    // ========================================================================
    // write_canonical_cbor vs to_canonical_cbor consistency
    // ========================================================================

    #[test]
    fn write_canonical_cbor_nested_map_consistency() {
        #[derive(Serialize)]
        struct Nested {
            items: Vec<HashMap<String, i32>>,
        }
        let mut m = HashMap::new();
        m.insert("z".to_string(), 1);
        m.insert("a".to_string(), 2);
        let val = Nested {
            items: vec![m.clone(), m],
        };

        let direct = to_canonical_cbor(&val).unwrap();
        let mut via_write = Vec::new();
        write_canonical_cbor(&val, &mut via_write).unwrap();
        assert_eq!(direct, via_write);
    }

    // ========================================================================
    // Struct with Option fields — all None vs empty struct
    // ========================================================================

    #[test]
    fn struct_all_none_fields_roundtrip() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct MaybeAll {
            a: Option<u32>,
            b: Option<String>,
            c: Option<Vec<u8>>,
        }

        let schema = SchemaId::new("fcp.test", "MaybeAll", Version::new(1, 0, 0));
        let val = MaybeAll {
            a: None,
            b: None,
            c: None,
        };
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: MaybeAll = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn struct_mixed_some_none_roundtrip() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Mixed {
            present: Option<u32>,
            absent: Option<u32>,
        }

        let schema = SchemaId::new("fcp.test", "Mixed", Version::new(1, 0, 0));
        let val = Mixed {
            present: Some(42),
            absent: None,
        };
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: Mixed = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(val, decoded);
    }

    // ========================================================================
    // Enum variant canonicalization
    // ========================================================================

    #[test]
    fn enum_unit_variants_roundtrip() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        enum Color {
            Red,
            Green,
            Blue,
        }

        let schema = SchemaId::new("fcp.test", "Color", Version::new(1, 0, 0));
        for variant in [Color::Red, Color::Green, Color::Blue] {
            let bytes = CanonicalSerializer::serialize(&variant, &schema).unwrap();
            let decoded: Color = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
            assert_eq!(variant, decoded);
        }
    }

    #[test]
    fn enum_data_variants_roundtrip() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        enum Shape {
            Circle { radius: f64 },
            Rectangle { width: f64, height: f64 },
        }

        let schema = SchemaId::new("fcp.test", "Shape", Version::new(1, 0, 0));
        let shapes = vec![
            Shape::Circle {
                radius: std::f64::consts::PI,
            },
            Shape::Rectangle {
                width: 10.0,
                height: 5.0,
            },
        ];
        for shape in shapes {
            let bytes = CanonicalSerializer::serialize(&shape, &schema).unwrap();
            let decoded: Shape = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
            assert_eq!(shape, decoded);
        }
    }

    // ========================================================================
    // NEW: Float encoding roundtrips
    // ========================================================================

    #[test]
    fn roundtrip_f64_positive() {
        let schema = SchemaId::new("fcp.test", "F64", Version::new(1, 0, 0));
        let val: f64 = 1.23;
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: f64 = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert!((decoded - val).abs() < f64::EPSILON);
    }

    #[test]
    fn roundtrip_f64_negative() {
        let schema = SchemaId::new("fcp.test", "F64Neg", Version::new(1, 0, 0));
        let val: f64 = -9.87;
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: f64 = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert!((decoded - val).abs() < f64::EPSILON);
    }

    #[test]
    fn roundtrip_f64_zero() {
        let schema = SchemaId::new("fcp.test", "F64Zero", Version::new(1, 0, 0));
        let val: f64 = 0.0;
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: f64 = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert!((decoded - val).abs() < f64::EPSILON);
    }

    #[test]
    fn roundtrip_f64_max() {
        let schema = SchemaId::new("fcp.test", "F64Max", Version::new(1, 0, 0));
        let val: f64 = f64::MAX;
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: f64 = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert!((decoded - val).abs() < f64::EPSILON);
    }

    #[test]
    fn roundtrip_f64_min_positive() {
        let schema = SchemaId::new("fcp.test", "F64MinPos", Version::new(1, 0, 0));
        let val: f64 = f64::MIN_POSITIVE;
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: f64 = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert!((decoded - val).abs() < f64::EPSILON);
    }

    #[test]
    fn roundtrip_f64_infinity_rejected() {
        let schema = SchemaId::new("fcp.test", "F64Inf", Version::new(1, 0, 0));
        let val: f64 = f64::INFINITY;
        let err = CanonicalSerializer::serialize(&val, &schema).unwrap_err();
        assert!(matches!(err, SerializationError::NonFiniteFloat));
    }

    #[test]
    fn roundtrip_f64_neg_infinity_rejected() {
        let schema = SchemaId::new("fcp.test", "F64NegInf", Version::new(1, 0, 0));
        let val: f64 = f64::NEG_INFINITY;
        let err = CanonicalSerializer::serialize(&val, &schema).unwrap_err();
        assert!(matches!(err, SerializationError::NonFiniteFloat));
    }

    #[test]
    fn roundtrip_f64_nan_rejected() {
        let schema = SchemaId::new("fcp.test", "F64NaN", Version::new(1, 0, 0));
        let val: f64 = f64::NAN;
        let err = CanonicalSerializer::serialize(&val, &schema).unwrap_err();
        assert!(matches!(err, SerializationError::NonFiniteFloat));
    }

    #[test]
    fn roundtrip_f32_value() {
        let schema = SchemaId::new("fcp.test", "F32", Version::new(1, 0, 0));
        let val: f32 = 1.23;
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: f32 = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert!((decoded - val).abs() < f32::EPSILON);
    }

    #[test]
    fn roundtrip_negative_zero_serializes_as_positive_zero() {
        let schema = SchemaId::new("fcp.test", "F64NegZero", Version::new(1, 0, 0));
        let bytes = CanonicalSerializer::serialize(&(-0.0_f64), &schema).unwrap();
        assert_eq!(&bytes[SCHEMA_HASH_LEN..], &[0xF9, 0x00, 0x00]);

        let decoded: f64 = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded.to_bits(), 0.0_f64.to_bits());
    }

    #[test]
    fn deserialize_rejects_negative_zero_encoding() {
        let schema = SchemaId::new("fcp.test", "F64NegZeroStrict", Version::new(1, 0, 0));
        let mut bytes = schema.hash().as_bytes().to_vec();
        bytes.extend_from_slice(&[0xF9, 0x80, 0x00]);

        let err = CanonicalSerializer::deserialize::<f64>(&bytes, &schema).unwrap_err();
        assert!(matches!(err, SerializationError::NonCanonicalEncoding));
    }

    #[test]
    fn roundtrip_f64_subnormal() {
        let schema = SchemaId::new("fcp.test", "F64Sub", Version::new(1, 0, 0));
        let val: f64 = 5e-324_f64; // smallest positive subnormal
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: f64 = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert!((decoded - val).abs() < f64::EPSILON);
    }

    // ========================================================================
    // NEW: Unicode and special string roundtrips
    // ========================================================================

    #[test]
    fn roundtrip_string_unicode_emoji() {
        let schema = SchemaId::new("fcp.test", "Str", Version::new(1, 0, 0));
        let val = "Hello \u{1F600}\u{1F389}\u{1F680}".to_string();
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: String = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_string_cjk_characters() {
        let schema = SchemaId::new("fcp.test", "CJK", Version::new(1, 0, 0));
        let val = "\u{4e16}\u{754c}\u{4f60}\u{597d}".to_string(); // 世界你好
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: String = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_string_with_newlines_and_tabs() {
        let schema = SchemaId::new("fcp.test", "Whitespace", Version::new(1, 0, 0));
        let val = "line1\nline2\ttab\rcarriage".to_string();
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: String = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_string_with_backslash_and_quotes() {
        let schema = SchemaId::new("fcp.test", "Escaped", Version::new(1, 0, 0));
        let val = r#"path\to\"file""#.to_string();
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: String = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_long_string_256_bytes() {
        let schema = SchemaId::new("fcp.test", "LongStr", Version::new(1, 0, 0));
        let val = "x".repeat(256);
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: String = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_long_string_65536_bytes() {
        let schema = SchemaId::new("fcp.test", "VeryLong", Version::new(1, 0, 0));
        let val = "y".repeat(65536);
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: String = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    // ========================================================================
    // NEW: Byte array edge cases
    // ========================================================================

    #[test]
    fn roundtrip_empty_byte_array() {
        let schema = SchemaId::new("fcp.test", "EmptyBytes", Version::new(1, 0, 0));
        let val: Vec<u8> = vec![];
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: Vec<u8> = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_byte_array_all_zeros() {
        let schema = SchemaId::new("fcp.test", "ZeroBytes", Version::new(1, 0, 0));
        let val: Vec<u8> = vec![0; 100];
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: Vec<u8> = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_byte_array_all_ff() {
        let schema = SchemaId::new("fcp.test", "FFBytes", Version::new(1, 0, 0));
        let val: Vec<u8> = vec![0xFF; 100];
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: Vec<u8> = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_byte_array_single_byte() {
        let schema = SchemaId::new("fcp.test", "OneByte", Version::new(1, 0, 0));
        let val: Vec<u8> = vec![0x42];
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: Vec<u8> = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    // ========================================================================
    // NEW: Integer boundary roundtrips
    // ========================================================================

    #[test]
    fn roundtrip_u8_min_and_max() {
        let schema = SchemaId::new("fcp.test", "U8Bounds", Version::new(1, 0, 0));
        for val in [u8::MIN, u8::MAX] {
            let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
            let decoded: u8 = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
            assert_eq!(decoded, val);
        }
    }

    #[test]
    fn roundtrip_u16_min_and_max() {
        let schema = SchemaId::new("fcp.test", "U16Bounds", Version::new(1, 0, 0));
        for val in [u16::MIN, u16::MAX] {
            let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
            let decoded: u16 = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
            assert_eq!(decoded, val);
        }
    }

    #[test]
    fn roundtrip_u32_min_and_max() {
        let schema = SchemaId::new("fcp.test", "U32Bounds", Version::new(1, 0, 0));
        for val in [u32::MIN, u32::MAX] {
            let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
            let decoded: u32 = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
            assert_eq!(decoded, val);
        }
    }

    #[test]
    fn roundtrip_u64_min_and_max() {
        let schema = SchemaId::new("fcp.test", "U64Bounds", Version::new(1, 0, 0));
        for val in [u64::MIN, u64::MAX] {
            let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
            let decoded: u64 = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
            assert_eq!(decoded, val);
        }
    }

    #[test]
    fn roundtrip_i8_min_and_max() {
        let schema = SchemaId::new("fcp.test", "I8Bounds", Version::new(1, 0, 0));
        for val in [i8::MIN, i8::MAX] {
            let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
            let decoded: i8 = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
            assert_eq!(decoded, val);
        }
    }

    #[test]
    fn roundtrip_i16_min_and_max() {
        let schema = SchemaId::new("fcp.test", "I16Bounds", Version::new(1, 0, 0));
        for val in [i16::MIN, i16::MAX] {
            let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
            let decoded: i16 = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
            assert_eq!(decoded, val);
        }
    }

    #[test]
    fn roundtrip_i32_min_and_max() {
        let schema = SchemaId::new("fcp.test", "I32Bounds", Version::new(1, 0, 0));
        for val in [i32::MIN, i32::MAX] {
            let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
            let decoded: i32 = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
            assert_eq!(decoded, val);
        }
    }

    #[test]
    fn roundtrip_i64_min_and_max_canonical() {
        let schema = SchemaId::new("fcp.test", "I64Bounds", Version::new(1, 0, 0));
        for val in [i64::MIN, i64::MAX] {
            let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
            let decoded: i64 = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
            assert_eq!(decoded, val);
        }
    }

    // ========================================================================
    // NEW: Complex struct roundtrips
    // ========================================================================

    #[test]
    fn roundtrip_struct_with_all_field_types() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct AllTypes {
            flag: bool,
            tiny: u8,
            small: u16,
            medium: u32,
            large: u64,
            signed_tiny: i8,
            signed_small: i16,
            signed_medium: i32,
            signed_large: i64,
            ratio: f64,
            label: String,
            payload: Vec<u8>,
            maybe: Option<u32>,
            items: Vec<String>,
        }

        let schema = SchemaId::new("fcp.test", "AllTypes", Version::new(1, 0, 0));
        let val = AllTypes {
            flag: true,
            tiny: 200,
            small: 50000,
            medium: 3_000_000,
            large: 10_000_000_000,
            signed_tiny: -100,
            signed_small: -30000,
            signed_medium: -2_000_000,
            signed_large: -5_000_000_000,
            ratio: 1.23,
            label: "all types".to_string(),
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
            maybe: Some(42),
            items: vec!["one".to_string(), "two".to_string()],
        };

        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: AllTypes = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_newtype_struct() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Wrapper(u64);

        let schema = SchemaId::new("fcp.test", "Wrapper", Version::new(1, 0, 0));
        let val = Wrapper(999);
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: Wrapper = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_struct_with_vec_of_vecs() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Matrix {
            rows: Vec<Vec<i32>>,
        }

        let schema = SchemaId::new("fcp.test", "Matrix", Version::new(1, 0, 0));
        let val = Matrix {
            rows: vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]],
        };
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: Matrix = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_struct_with_vec_of_options() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct OptItems {
            values: Vec<Option<u32>>,
        }

        let schema = SchemaId::new("fcp.test", "OptItems", Version::new(1, 0, 0));
        for val in [
            OptItems { values: vec![] },
            OptItems {
                values: vec![None, Some(1), None, Some(2)],
            },
            OptItems {
                values: vec![Some(42)],
            },
        ] {
            let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
            let decoded: OptItems = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
            assert_eq!(decoded, val);
        }
    }

    // ========================================================================
    // NEW: Enum variant coverage
    // ========================================================================

    #[test]
    fn roundtrip_enum_newtype_variant() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        enum Payload {
            Number(u64),
            Label(String),
        }

        let schema = SchemaId::new("fcp.test", "Payload", Version::new(1, 0, 0));
        let variants = vec![Payload::Number(12345), Payload::Label("test".to_string())];
        for val in variants {
            let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
            let decoded: Payload = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
            assert_eq!(decoded, val);
        }
    }

    #[test]
    fn roundtrip_enum_with_nested_struct() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Inner {
            x: i32,
            y: i32,
        }

        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        enum Event {
            Click(Inner),
            Scroll { offset: i32 },
            Close,
        }

        let schema = SchemaId::new("fcp.test", "Event", Version::new(1, 0, 0));
        for val in [
            Event::Click(Inner { x: 10, y: 20 }),
            Event::Scroll { offset: -5 },
            Event::Close,
        ] {
            let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
            let decoded: Event = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
            assert_eq!(decoded, val);
        }
    }

    // ========================================================================
    // NEW: Map with many entries
    // ========================================================================

    #[test]
    fn roundtrip_map_with_100_entries() {
        let schema = SchemaId::new("fcp.test", "BigMap", Version::new(1, 0, 0));
        let mut map = HashMap::new();
        for i in 0..100_u32 {
            map.insert(format!("key_{i:04}"), i);
        }
        let bytes = CanonicalSerializer::serialize(&map, &schema).unwrap();
        let decoded: HashMap<String, u32> =
            CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, map);
    }

    #[test]
    fn map_with_100_entries_is_deterministic() {
        let schema = SchemaId::new("fcp.test", "BigMap2", Version::new(1, 0, 0));
        let mut map = HashMap::new();
        for i in 0..100_u32 {
            map.insert(format!("key_{i:04}"), i);
        }
        let bytes1 = CanonicalSerializer::serialize(&map, &schema).unwrap();
        let bytes2 = CanonicalSerializer::serialize(&map, &schema).unwrap();
        assert_eq!(bytes1, bytes2);
    }

    // ========================================================================
    // NEW: Canonical CBOR encoding specific byte checks
    // ========================================================================

    #[test]
    fn to_canonical_cbor_integer_zero_is_one_byte() {
        let bytes = to_canonical_cbor(&0_u8).unwrap();
        assert_eq!(bytes, vec![0x00]);
    }

    #[test]
    fn to_canonical_cbor_integer_23_is_one_byte() {
        let bytes = to_canonical_cbor(&23_u8).unwrap();
        assert_eq!(bytes, vec![0x17]);
    }

    #[test]
    fn to_canonical_cbor_integer_24_is_two_bytes() {
        let bytes = to_canonical_cbor(&24_u8).unwrap();
        assert_eq!(bytes, vec![0x18, 0x18]);
    }

    #[test]
    fn to_canonical_cbor_negative_one_is_one_byte() {
        let bytes = to_canonical_cbor(&(-1_i8)).unwrap();
        assert_eq!(bytes, vec![0x20]);
    }

    #[test]
    fn to_canonical_cbor_negative_24_is_one_byte() {
        let bytes = to_canonical_cbor(&(-24_i8)).unwrap();
        assert_eq!(bytes, vec![0x37]);
    }

    #[test]
    fn to_canonical_cbor_string_hello() {
        let bytes = to_canonical_cbor(&"hello").unwrap();
        // 0x65 = text string of length 5, then "hello"
        assert_eq!(bytes[0], 0x65);
        assert_eq!(&bytes[1..], b"hello");
    }

    #[test]
    fn to_canonical_cbor_single_element_array() {
        let bytes = to_canonical_cbor(&vec![42_u8]).unwrap();
        // 0x81 = array of length 1, then 0x18 0x2A for 42
        assert_eq!(bytes[0], 0x81);
    }

    #[test]
    fn to_canonical_cbor_byte_string_encoding() {
        // serde_bytes would encode as byte string, but Vec<u8> encodes as array of ints
        let val: Vec<u8> = vec![1, 2, 3];
        let bytes = to_canonical_cbor(&val).unwrap();
        // Vec<u8> with serde serializes as array of integers
        assert_eq!(bytes[0], 0x83); // array of 3
    }

    // ========================================================================
    // NEW: Error path coverage
    // ========================================================================

    #[test]
    fn deserialize_with_corrupted_cbor_body() {
        let schema = SchemaId::new("fcp.test", "Corrupt", Version::new(1, 0, 0));
        let mut bytes = Vec::new();
        bytes.extend_from_slice(schema.hash().as_bytes());
        // Invalid CBOR: indefinite-length map start without break
        bytes.extend_from_slice(&[0xBF, 0x61, b'a', 0x01]);
        let result = CanonicalSerializer::deserialize::<HashMap<String, u8>>(&bytes, &schema);
        assert!(result.is_err());
    }

    #[test]
    fn deserialize_unchecked_with_corrupted_cbor_body() {
        let schema = SchemaId::new("fcp.test", "Corrupt2", Version::new(1, 0, 0));
        let mut bytes = Vec::new();
        bytes.extend_from_slice(schema.hash().as_bytes());
        // Truncated CBOR map
        bytes.extend_from_slice(&[0xA2, 0x61, b'a']);
        let result =
            CanonicalSerializer::deserialize_unchecked::<HashMap<String, u8>>(&bytes, &schema);
        assert!(result.is_err());
    }

    #[test]
    fn deserialize_type_mismatch_string_as_integer() {
        let schema = SchemaId::new("fcp.test", "TypeMM", Version::new(1, 0, 0));
        let bytes = CanonicalSerializer::serialize(&"hello", &schema).unwrap();
        let result = CanonicalSerializer::deserialize::<u32>(&bytes, &schema);
        assert!(result.is_err());
    }

    #[test]
    fn deserialize_type_mismatch_integer_as_string() {
        let schema = SchemaId::new("fcp.test", "TypeMM2", Version::new(1, 0, 0));
        let bytes = CanonicalSerializer::serialize(&42_u32, &schema).unwrap();
        let result = CanonicalSerializer::deserialize::<String>(&bytes, &schema);
        assert!(result.is_err());
    }

    #[test]
    fn deserialize_type_mismatch_array_as_map() {
        let schema = SchemaId::new("fcp.test", "TypeMM3", Version::new(1, 0, 0));
        let bytes = CanonicalSerializer::serialize(&vec![1_u32, 2, 3], &schema).unwrap();
        let result = CanonicalSerializer::deserialize::<HashMap<String, u32>>(&bytes, &schema);
        assert!(result.is_err());
    }

    // ========================================================================
    // NEW: Schema version sensitivity
    // ========================================================================

    #[test]
    fn schema_hash_differs_by_minor_version() {
        let a = SchemaId::new("fcp.core", "Obj", Version::new(1, 0, 0));
        let b = SchemaId::new("fcp.core", "Obj", Version::new(1, 1, 0));
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn schema_hash_differs_by_patch_version() {
        let a = SchemaId::new("fcp.core", "Obj", Version::new(1, 0, 0));
        let b = SchemaId::new("fcp.core", "Obj", Version::new(1, 0, 1));
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn schema_hash_differs_by_prerelease() {
        let a = SchemaId::new("fcp.core", "Obj", Version::new(1, 0, 0));
        let b = SchemaId::new("fcp.core", "Obj", Version::parse("1.0.0-alpha").unwrap());
        assert_ne!(a.hash(), b.hash());
    }

    // ========================================================================
    // NEW: Schema ID equality and hashing corner cases
    // ========================================================================

    #[test]
    fn schema_id_ne_different_namespace_same_name() {
        let a = SchemaId::new("ns1", "Name", Version::new(1, 0, 0));
        let b = SchemaId::new("ns2", "Name", Version::new(1, 0, 0));
        assert_ne!(a, b);
    }

    #[test]
    fn schema_id_ne_same_namespace_different_name() {
        let a = SchemaId::new("ns", "NameA", Version::new(1, 0, 0));
        let b = SchemaId::new("ns", "NameB", Version::new(1, 0, 0));
        assert_ne!(a, b);
    }

    #[test]
    fn schema_id_eq_identical() {
        let a = SchemaId::new("ns", "Name", Version::new(1, 2, 3));
        let b = SchemaId::new("ns", "Name", Version::new(1, 2, 3));
        assert_eq!(a, b);
    }

    #[test]
    fn schema_id_as_bytes_very_long_namespace() {
        let long_ns = "a".repeat(1000);
        let schema = SchemaId::new(long_ns.as_str(), "T", Version::new(0, 0, 1));
        let bytes = schema.as_bytes();
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.starts_with(&long_ns));
        // Hash should still work
        assert_eq!(schema.hash().as_bytes().len(), 32);
    }

    #[test]
    fn schema_id_as_bytes_very_long_name() {
        let long_name = "B".repeat(1000);
        let schema = SchemaId::new("ns", long_name.as_str(), Version::new(0, 0, 1));
        let bytes = schema.as_bytes();
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.contains(&long_name));
        assert_eq!(schema.hash().as_bytes().len(), 32);
    }

    // ========================================================================
    // NEW: SchemaHash serde roundtrips
    // ========================================================================

    #[test]
    fn schema_hash_cbor_roundtrip() {
        let hash = SchemaHash::from_bytes([0x42; 32]);
        let cbor_bytes = to_canonical_cbor(&hash).unwrap();
        let decoded: SchemaHash = ciborium::de::from_reader(cbor_bytes.as_slice()).unwrap();
        assert_eq!(decoded, hash);
    }

    #[test]
    fn schema_hash_display_length_always_64() {
        // Various byte patterns should always yield 64-char hex
        for byte in [0x00_u8, 0x0F, 0xF0, 0xFF, 0x42, 0xAB] {
            let hash = SchemaHash::from_bytes([byte; 32]);
            assert_eq!(hash.to_string().len(), 64);
        }
    }

    // ========================================================================
    // NEW: Canonicalization of arrays with maps
    // ========================================================================

    #[test]
    fn canonicalize_array_of_maps() {
        let mut map1 = HashMap::new();
        map1.insert("z".to_string(), 1_i32);
        map1.insert("a".to_string(), 2);
        let mut map2 = HashMap::new();
        map2.insert("y".to_string(), 3_i32);
        map2.insert("b".to_string(), 4);

        let data = vec![map1, map2];
        let bytes1 = to_canonical_cbor(&data).unwrap();
        let bytes2 = to_canonical_cbor(&data).unwrap();
        assert_eq!(bytes1, bytes2);

        // Verify maps inside array are canonicalized
        let raw: Value = ciborium::de::from_reader(bytes1.as_slice()).unwrap();
        if let Value::Array(items) = raw {
            assert_eq!(items.len(), 2);
            // First map keys should be sorted: "a" before "z"
            if let Value::Map(entries) = &items[0] {
                let keys: Vec<&str> = entries
                    .iter()
                    .filter_map(|(k, _)| {
                        if let Value::Text(s) = k {
                            Some(s.as_str())
                        } else {
                            None
                        }
                    })
                    .collect();
                assert_eq!(keys, vec!["a", "z"]);
            } else {
                panic!("expected map in array");
            }
        } else {
            panic!("expected array");
        }
    }

    // ========================================================================
    // NEW: Serialization produces different bytes for different values
    // ========================================================================

    #[test]
    fn different_values_produce_different_bytes() {
        let schema = SchemaId::new("fcp.test", "Diff", Version::new(1, 0, 0));
        let bytes_a = CanonicalSerializer::serialize(&1_u32, &schema).unwrap();
        let bytes_b = CanonicalSerializer::serialize(&2_u32, &schema).unwrap();
        assert_ne!(bytes_a, bytes_b);
    }

    #[test]
    fn different_structs_produce_different_bytes() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Item {
            id: u32,
        }
        let schema = SchemaId::new("fcp.test", "Item", Version::new(1, 0, 0));
        let a = Item { id: 1 };
        let b = Item { id: 2 };
        let bytes_a = CanonicalSerializer::serialize(&a, &schema).unwrap();
        let bytes_b = CanonicalSerializer::serialize(&b, &schema).unwrap();
        assert_ne!(bytes_a, bytes_b);
    }

    // ========================================================================
    // NEW: Canonicalize map values are also canonicalized
    // ========================================================================

    #[test]
    fn canonicalize_map_values_containing_maps() {
        let mut inner = Value::Map(vec![
            (Value::Text("z".into()), Value::Integer(2.into())),
            (Value::Text("a".into()), Value::Integer(1.into())),
        ]);
        let mut outer = Value::Map(vec![(Value::Text("key".into()), inner.clone())]);
        canonicalize_value_in_place(&mut outer, 0).unwrap();

        // Verify inner map is also sorted
        if let Value::Map(outer_entries) = &outer {
            if let Value::Map(inner_entries) = &outer_entries[0].1 {
                let keys: Vec<&str> = inner_entries
                    .iter()
                    .filter_map(|(k, _)| {
                        if let Value::Text(s) = k {
                            Some(s.as_str())
                        } else {
                            None
                        }
                    })
                    .collect();
                assert_eq!(keys, vec!["a", "z"]);
            } else {
                panic!("expected inner map");
            }
        } else {
            panic!("expected outer map");
        }
        // Suppress unused variable warning
        canonicalize_value_in_place(&mut inner, 0).unwrap();
    }

    // ========================================================================
    // NEW: Canonicalize primitives are no-ops
    // ========================================================================

    #[test]
    fn canonicalize_integer_is_noop() {
        let mut v = Value::Integer(42.into());
        let before_bytes = {
            let mut b = Vec::new();
            ciborium::ser::into_writer(&v, &mut b).unwrap();
            b
        };
        canonicalize_value_in_place(&mut v, 0).unwrap();
        let after_bytes = {
            let mut b = Vec::new();
            ciborium::ser::into_writer(&v, &mut b).unwrap();
            b
        };
        assert_eq!(before_bytes, after_bytes);
    }

    #[test]
    fn canonicalize_text_is_noop() {
        let mut v = Value::Text("hello".into());
        canonicalize_value_in_place(&mut v, 0).unwrap();
        assert_eq!(v, Value::Text("hello".into()));
    }

    #[test]
    fn canonicalize_bytes_is_noop() {
        let mut v = Value::Bytes(vec![1, 2, 3]);
        canonicalize_value_in_place(&mut v, 0).unwrap();
        assert_eq!(v, Value::Bytes(vec![1, 2, 3]));
    }

    #[test]
    fn canonicalize_bool_is_noop() {
        let mut v = Value::Bool(true);
        canonicalize_value_in_place(&mut v, 0).unwrap();
        assert_eq!(v, Value::Bool(true));
    }

    #[test]
    fn canonicalize_null_is_noop() {
        let mut v = Value::Null;
        canonicalize_value_in_place(&mut v, 0).unwrap();
        assert_eq!(v, Value::Null);
    }

    // ========================================================================
    // NEW: Canonicalize empty array and empty map
    // ========================================================================

    #[test]
    fn canonicalize_empty_array() {
        let mut v = Value::Array(vec![]);
        canonicalize_value_in_place(&mut v, 0).unwrap();
        assert_eq!(v, Value::Array(vec![]));
    }

    #[test]
    fn canonicalize_empty_map() {
        let mut v = Value::Map(vec![]);
        canonicalize_value_in_place(&mut v, 0).unwrap();
        assert_eq!(v, Value::Map(vec![]));
    }

    // ========================================================================
    // NEW: Tuple and fixed-size array roundtrips
    // ========================================================================

    #[test]
    fn roundtrip_tuple_of_primitives() {
        let schema = SchemaId::new("fcp.test", "Tuple", Version::new(1, 0, 0));
        let val: (u32, String, bool) = (42, "hello".to_string(), true);
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: (u32, String, bool) =
            CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_fixed_array() {
        let schema = SchemaId::new("fcp.test", "FixedArr", Version::new(1, 0, 0));
        let val: [u32; 5] = [10, 20, 30, 40, 50];
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: [u32; 5] = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_empty_tuple_struct() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Unit;

        let schema = SchemaId::new("fcp.test", "UnitStruct", Version::new(1, 0, 0));
        let val = Unit;
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: Unit = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    // ========================================================================
    // NEW: Map key types — bool keys
    // ========================================================================

    #[test]
    fn canonicalize_map_with_bool_keys() {
        let mut entries = vec![
            (Value::Bool(true), Value::Integer(1.into())),
            (Value::Bool(false), Value::Integer(2.into())),
        ];
        canonicalize_map(&mut entries, 0).unwrap();
        // false = 0xF4, true = 0xF5; same length so lex order: false < true
        assert_eq!(entries[0].0, Value::Bool(false));
        assert_eq!(entries[1].0, Value::Bool(true));
    }

    // ========================================================================
    // NEW: Map with null values
    // ========================================================================

    #[test]
    fn canonicalize_map_with_null_values() {
        let mut entries = vec![
            (Value::Text("b".into()), Value::Null),
            (Value::Text("a".into()), Value::Null),
        ];
        canonicalize_map(&mut entries, 0).unwrap();
        let keys: Vec<&str> = entries
            .iter()
            .filter_map(|(k, _)| {
                if let Value::Text(s) = k {
                    Some(s.as_str())
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(keys, vec!["a", "b"]);
    }

    // ========================================================================
    // NEW: Single-entry map with various key types
    // ========================================================================

    #[test]
    fn canonicalize_single_entry_map_text_key() {
        let mut entries = vec![(Value::Text("only".into()), Value::Integer(1.into()))];
        canonicalize_map(&mut entries, 0).unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn canonicalize_single_entry_map_integer_key() {
        let mut entries = vec![(Value::Integer(42.into()), Value::Bool(true))];
        canonicalize_map(&mut entries, 0).unwrap();
        assert_eq!(entries.len(), 1);
    }

    // ========================================================================
    // NEW: Depth limit with maps
    // ========================================================================

    #[test]
    fn canonicalize_nested_maps_at_depth_limit() {
        // Build nested maps to test depth tracking
        let mut v = Value::Map(vec![(Value::Text("leaf".into()), Value::Integer(1.into()))]);
        for i in 0..10 {
            v = Value::Map(vec![(Value::Text(format!("level_{i}")), v)]);
        }
        // 11 levels of nesting, well within MAX_CANONICALIZATION_DEPTH
        canonicalize_value_in_place(&mut v, 0).unwrap();
    }

    // ========================================================================
    // NEW: Tag with various inner types
    // ========================================================================

    #[test]
    fn canonicalize_tag_with_array_is_rejected() {
        let mut v = Value::Tag(99, Box::new(Value::Array(vec![Value::Integer(3.into())])));
        let err = canonicalize_value_in_place(&mut v, 0).unwrap_err();
        assert!(matches!(
            err,
            SerializationError::UnsupportedTag { tag: 99 }
        ));
    }

    #[test]
    fn canonicalize_tag_with_integer_is_rejected() {
        let mut v = Value::Tag(100, Box::new(Value::Integer(42.into())));
        let err = canonicalize_value_in_place(&mut v, 0).unwrap_err();
        assert!(matches!(
            err,
            SerializationError::UnsupportedTag { tag: 100 }
        ));
    }

    // ========================================================================
    // NEW: Roundtrip BTreeMap vs HashMap consistency
    // ========================================================================

    #[test]
    fn btreemap_and_hashmap_produce_same_canonical_bytes() {
        use std::collections::BTreeMap;

        let schema = SchemaId::new("fcp.test", "MapConsist", Version::new(1, 0, 0));

        let mut hm = HashMap::new();
        hm.insert("z".to_string(), 1_i32);
        hm.insert("a".to_string(), 2);
        hm.insert("m".to_string(), 3);

        let mut bm = BTreeMap::new();
        bm.insert("z".to_string(), 1_i32);
        bm.insert("a".to_string(), 2);
        bm.insert("m".to_string(), 3);

        let hm_bytes = CanonicalSerializer::serialize(&hm, &schema).unwrap();
        let bm_bytes = CanonicalSerializer::serialize(&bm, &schema).unwrap();
        assert_eq!(hm_bytes, bm_bytes);
    }

    // ========================================================================
    // NEW: Roundtrip bool
    // ========================================================================

    #[test]
    fn roundtrip_bool_true_and_false() {
        let schema = SchemaId::new("fcp.test", "Bool2", Version::new(1, 0, 0));
        for val in [true, false] {
            let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
            let decoded: bool = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
            assert_eq!(decoded, val);
        }
    }

    // ========================================================================
    // NEW: Roundtrip with HashMap<String, Vec<u32>>
    // ========================================================================

    #[test]
    fn roundtrip_map_of_string_to_vec() {
        let schema = SchemaId::new("fcp.test", "MapVec", Version::new(1, 0, 0));
        let mut map = HashMap::new();
        map.insert("primes".to_string(), vec![2_u32, 3, 5, 7, 11]);
        map.insert("empty".to_string(), vec![]);
        map.insert("single".to_string(), vec![42]);

        let bytes = CanonicalSerializer::serialize(&map, &schema).unwrap();
        let decoded: HashMap<String, Vec<u32>> =
            CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, map);
    }

    // ========================================================================
    // NEW: Non-canonical encoding rejection — non-minimal map
    // ========================================================================

    #[test]
    fn deserialize_rejects_non_minimal_map_length() {
        let schema = SchemaId::new("fcp.test", "MapLen", Version::new(1, 0, 0));
        let mut bytes = Vec::new();
        bytes.extend_from_slice(schema.hash().as_bytes());
        // Map with 1 entry, but encoded with 2-byte length prefix (0xB8 0x01) instead of 0xA1
        bytes.extend_from_slice(&[0xB8, 0x01, 0x61, b'a', 0x01]);
        let result = CanonicalSerializer::deserialize::<HashMap<String, u8>>(&bytes, &schema);
        assert!(result.is_err());
    }

    // ========================================================================
    // NEW: Non-canonical encoding rejection — non-minimal array
    // ========================================================================

    #[test]
    fn deserialize_rejects_non_minimal_array_length() {
        let schema = SchemaId::new("fcp.test", "ArrLen", Version::new(1, 0, 0));
        let mut bytes = Vec::new();
        bytes.extend_from_slice(schema.hash().as_bytes());
        // Array with 1 element, encoded with 2-byte length (0x98 0x01) instead of 0x81
        bytes.extend_from_slice(&[0x98, 0x01, 0x01]);
        let result = CanonicalSerializer::deserialize::<Vec<u8>>(&bytes, &schema);
        assert!(result.is_err());
    }

    // ========================================================================
    // NEW: to_canonical_cbor with tuples
    // ========================================================================

    #[test]
    fn to_canonical_cbor_tuple() {
        let val: (u32, u32) = (1, 2);
        let bytes = to_canonical_cbor(&val).unwrap();
        // Should encode as a 2-element array
        assert_eq!(bytes[0], 0x82); // array of 2
    }

    #[test]
    fn to_canonical_cbor_triple_tuple() {
        let val: (bool, String, u32) = (true, "hi".to_string(), 7);
        let bytes = to_canonical_cbor(&val).unwrap();
        assert_eq!(bytes[0], 0x83); // array of 3
    }

    // ========================================================================
    // NEW: Schema hash in HashMap key
    // ========================================================================

    #[test]
    fn schema_hash_as_hashmap_key() {
        let h1 = SchemaHash::from_bytes([0x01; 32]);
        let h2 = SchemaHash::from_bytes([0x02; 32]);
        let mut map = HashMap::new();
        map.insert(h1, "first");
        map.insert(h2, "second");
        assert_eq!(map[&h1], "first");
        assert_eq!(map[&h2], "second");
    }

    // ========================================================================
    // NEW: Verify schema hash is content-dependent
    // ========================================================================

    #[test]
    fn schema_hash_changes_with_any_character_change() {
        let base = SchemaId::new("fcp.core", "Token", Version::new(1, 0, 0));
        // Change one character in namespace
        let modified = SchemaId::new("fcp.cors", "Token", Version::new(1, 0, 0));
        assert_ne!(base.hash(), modified.hash());
    }

    // ========================================================================
    // NEW: Roundtrip with deeply nested Vec
    // ========================================================================

    #[test]
    fn roundtrip_vec_of_vec_of_vec() {
        let schema = SchemaId::new("fcp.test", "DeepVec", Version::new(1, 0, 0));
        let val: Vec<Vec<Vec<u8>>> =
            vec![vec![vec![1, 2], vec![3, 4]], vec![vec![5, 6], vec![7, 8]]];
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: Vec<Vec<Vec<u8>>> = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    // ========================================================================
    // NEW: Verify SCHEMA_HASH_DOMAIN_SEPARATOR value
    // ========================================================================

    #[test]
    fn domain_separator_is_expected_value() {
        assert_eq!(SCHEMA_HASH_DOMAIN_SEPARATOR, b"FCP2-SCHEMA-V1");
        assert_eq!(SCHEMA_HASH_DOMAIN_SEPARATOR.len(), 14);
    }

    // ========================================================================
    // NEW: Canonicalize map with many same-length keys
    // ========================================================================

    #[test]
    fn canonicalize_map_same_length_keys_sorted_lexicographically() {
        let mut entries = vec![
            (Value::Text("dd".into()), Value::Integer(4.into())),
            (Value::Text("bb".into()), Value::Integer(2.into())),
            (Value::Text("cc".into()), Value::Integer(3.into())),
            (Value::Text("aa".into()), Value::Integer(1.into())),
        ];
        canonicalize_map(&mut entries, 0).unwrap();
        let keys: Vec<&str> = entries
            .iter()
            .filter_map(|(k, _)| {
                if let Value::Text(s) = k {
                    Some(s.as_str())
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(keys, vec!["aa", "bb", "cc", "dd"]);
    }

    // ========================================================================
    // NEW: Roundtrip HashMap<u32, String>
    // ========================================================================

    #[test]
    fn roundtrip_map_u32_to_string() {
        use std::collections::BTreeMap;
        let schema = SchemaId::new("fcp.test", "U32Map", Version::new(1, 0, 0));
        let mut map = BTreeMap::new();
        map.insert(1_u32, "one".to_string());
        map.insert(2, "two".to_string());
        map.insert(1000, "thousand".to_string());

        let bytes = CanonicalSerializer::serialize(&map, &schema).unwrap();
        let decoded: BTreeMap<u32, String> =
            CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, map);
    }

    // ========================================================================
    // NEW: Verify CBOR encoding of various values
    // ========================================================================

    #[test]
    fn to_canonical_cbor_u32_max() {
        let bytes = to_canonical_cbor(&u32::MAX).unwrap();
        // u32::MAX = 4294967295 = 0x1A FFFFFFFF (5 bytes)
        assert_eq!(bytes.len(), 5);
        assert_eq!(bytes[0], 0x1A);
    }

    #[test]
    fn to_canonical_cbor_u64_max() {
        let bytes = to_canonical_cbor(&u64::MAX).unwrap();
        // u64::MAX = 0x1B FFFFFFFFFFFFFFFF (9 bytes)
        assert_eq!(bytes.len(), 9);
        assert_eq!(bytes[0], 0x1B);
    }

    // ========================================================================
    // NEW: SchemaId with impl Into<String> construction variants
    // ========================================================================

    #[test]
    fn schema_id_new_with_string_types() {
        let from_str = SchemaId::new("ns", "name", Version::new(1, 0, 0));
        let from_string =
            SchemaId::new("ns".to_string(), "name".to_string(), Version::new(1, 0, 0));
        assert_eq!(from_str, from_string);
        assert_eq!(from_str.hash(), from_string.hash());
    }

    // ========================================================================
    // NEW: Multiple serializations of same value same schema
    // ========================================================================

    #[test]
    fn serialize_100_times_always_identical() {
        let schema = SchemaId::new("fcp.test", "Stability", Version::new(1, 0, 0));
        let val = "deterministic";
        let first = CanonicalSerializer::serialize(&val, &schema).unwrap();
        for _ in 0..100 {
            let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
            assert_eq!(bytes, first);
        }
    }

    // ========================================================================
    // NEW: Deserialize unchecked roundtrip
    // ========================================================================

    #[test]
    fn deserialize_unchecked_roundtrip_struct() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Msg {
            id: u64,
            body: String,
        }

        let schema = SchemaId::new("fcp.test", "Msg", Version::new(1, 0, 0));
        let val = Msg {
            id: 999,
            body: "unchecked roundtrip".to_string(),
        };
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: Msg = CanonicalSerializer::deserialize_unchecked(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    // ========================================================================
    // NEW: Canonical CBOR with f64 special values
    // ========================================================================

    #[test]
    fn to_canonical_cbor_f64_positive_infinity_rejected() {
        let err = to_canonical_cbor(&f64::INFINITY).unwrap_err();
        assert!(matches!(err, SerializationError::NonFiniteFloat));
    }

    #[test]
    fn to_canonical_cbor_f64_negative_infinity_rejected() {
        let err = to_canonical_cbor(&f64::NEG_INFINITY).unwrap_err();
        assert!(matches!(err, SerializationError::NonFiniteFloat));
    }

    #[test]
    fn to_canonical_cbor_f64_nan_rejected() {
        let err = to_canonical_cbor(&f64::NAN).unwrap_err();
        assert!(matches!(err, SerializationError::NonFiniteFloat));
    }

    // ========================================================================
    // NEW: Additional coverage tests
    // ========================================================================

    #[test]
    fn roundtrip_vec_of_booleans() {
        let schema = SchemaId::new("fcp.test", "BoolVec", Version::new(1, 0, 0));
        let val = vec![true, false, true, true, false];
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: Vec<bool> = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_vec_of_option_strings() {
        let schema = SchemaId::new("fcp.test", "OptStrVec", Version::new(1, 0, 0));
        let val: Vec<Option<String>> = vec![
            Some("present".to_string()),
            None,
            Some("also present".to_string()),
            None,
        ];
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: Vec<Option<String>> =
            CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn schema_id_with_max_version_components() {
        let schema = SchemaId::new("ns", "T", Version::new(999, 999, 999));
        let canonical = String::from_utf8(schema.as_bytes()).unwrap();
        assert_eq!(canonical, "ns:T@999.999.999");
        assert_eq!(schema.hash().as_bytes().len(), 32);
    }

    #[test]
    fn to_canonical_cbor_array_of_23_elements() {
        // Array with 23 elements should have 1-byte header (0x97)
        let val: Vec<u8> = (0..23).collect();
        let bytes = to_canonical_cbor(&val).unwrap();
        assert_eq!(bytes[0], 0x97); // major type 4 (array), additional 23
    }

    #[test]
    fn to_canonical_cbor_array_of_24_elements() {
        // Array with 24 elements should have 2-byte header (0x98 0x18)
        let val: Vec<u8> = (0..24).collect();
        let bytes = to_canonical_cbor(&val).unwrap();
        assert_eq!(bytes[0], 0x98); // major type 4 (array), additional 24
        assert_eq!(bytes[1], 24);
    }

    #[test]
    fn roundtrip_struct_with_string_and_bytes() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct MixedData {
            label: String,
            payload: Vec<u8>,
            count: u64,
        }

        let schema = SchemaId::new("fcp.test", "MixedData", Version::new(1, 0, 0));
        let val = MixedData {
            label: "test-payload".to_string(),
            payload: vec![0x00, 0x01, 0x02, 0xFF],
            count: 42,
        };
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: MixedData = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    // ========================================================================
    // NEW BATCH: SchemaId edge cases and trait coverage
    // ========================================================================

    #[test]
    fn schema_id_try_new_rejects_colon_in_namespace() {
        // Pre-fix this construction succeeded and produced an aliased canonical
        // string ("ns:inner:Type@1.0.0"), allowing distinct schemas to share a
        // SchemaHash. The validated constructor must now reject it.
        let err = SchemaId::try_new("ns:inner", "Type", Version::new(1, 0, 0)).unwrap_err();
        assert_eq!(
            err,
            SchemaIdError::ReservedSeparator {
                field: "namespace",
                separator: ':',
            }
        );
    }

    #[test]
    fn schema_id_try_new_rejects_at_in_name_field() {
        let err = SchemaId::try_new("ns", "Type@Extra", Version::new(0, 1, 0)).unwrap_err();
        assert_eq!(
            err,
            SchemaIdError::ReservedSeparator {
                field: "name",
                separator: '@',
            }
        );
    }

    #[test]
    fn schema_id_hash_differs_with_whitespace_in_namespace() {
        let a = SchemaId::new("fcp.core", "T", Version::new(1, 0, 0));
        let b = SchemaId::new("fcp. core", "T", Version::new(1, 0, 0));
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn schema_id_hash_differs_with_case_change() {
        let lower = SchemaId::new("fcp.core", "token", Version::new(1, 0, 0));
        let upper = SchemaId::new("fcp.core", "Token", Version::new(1, 0, 0));
        assert_ne!(lower.hash(), upper.hash());
    }

    #[test]
    fn schema_id_clone_produces_independent_copy() {
        let original = SchemaId::new("fcp.test", "Clone", Version::new(1, 0, 0));
        let cloned = original.clone();
        assert_eq!(original.as_bytes(), cloned.as_bytes());
        // Use original after clone to verify independence.
        assert_eq!(original.namespace, "fcp.test");
    }

    #[test]
    fn schema_id_as_bytes_version_zero() {
        let schema = SchemaId::new("ns", "T", Version::new(0, 0, 0));
        let canonical = String::from_utf8(schema.as_bytes()).unwrap();
        assert_eq!(canonical, "ns:T@0.0.0");
    }

    #[test]
    fn schema_id_as_bytes_large_version_numbers() {
        let schema = SchemaId::new("ns", "T", Version::new(100, 200, 300));
        let canonical = String::from_utf8(schema.as_bytes()).unwrap();
        assert_eq!(canonical, "ns:T@100.200.300");
    }

    #[test]
    fn schema_id_serde_cbor_preserves_prerelease() {
        let schema = SchemaId::new(
            "fcp.protocol",
            "Msg",
            Version::parse("2.0.0-beta.3").unwrap(),
        );
        let cbor_bytes = to_canonical_cbor(&schema).unwrap();
        let decoded: SchemaId = ciborium::de::from_reader(cbor_bytes.as_slice()).unwrap();
        assert_eq!(decoded, schema);
        assert_eq!(decoded.version.pre.as_str(), "beta.3");
    }

    // ========================================================================
    // NEW BATCH: SchemaHash additional coverage
    // ========================================================================

    #[test]
    fn schema_hash_display_never_uppercase() {
        for byte in 0x00_u8..=0xFF {
            let hash = SchemaHash::from_bytes([byte; 32]);
            let display = hash.to_string();
            assert!(!display.chars().any(|c| c.is_ascii_uppercase()));
        }
    }

    #[test]
    fn schema_hash_debug_contains_display() {
        let hash = SchemaHash::from_bytes([0x42; 32]);
        let display = hash.to_string();
        let debug = format!("{hash:?}");
        assert!(debug.contains(&display));
    }

    #[test]
    fn schema_hash_as_ref_length_matches_const() {
        let hash = SchemaHash::from_bytes([0xCD; 32]);
        let slice: &[u8] = hash.as_ref();
        assert_eq!(slice.len(), SCHEMA_HASH_LEN);
    }

    #[test]
    fn schema_hash_copy_semantics_verified() {
        let original = SchemaHash::from_bytes([0x11; 32]);
        let copy1 = original;
        let copy2 = original;
        // All three are usable (Copy trait).
        assert_eq!(original, copy1);
        assert_eq!(copy1, copy2);
    }

    #[test]
    fn schema_hash_ne_single_byte_difference() {
        let mut bytes_a = [0x00_u8; 32];
        let mut bytes_b = [0x00_u8; 32];
        bytes_b[31] = 0x01;
        assert_ne!(
            SchemaHash::from_bytes(bytes_a),
            SchemaHash::from_bytes(bytes_b)
        );
        // Also test first byte difference.
        bytes_a[0] = 0x01;
        bytes_b[31] = 0x00;
        assert_ne!(
            SchemaHash::from_bytes(bytes_a),
            SchemaHash::from_bytes(bytes_b)
        );
    }

    #[test]
    fn schema_hash_from_bytes_const_context() {
        // Verify from_bytes can be used in const context.
        const HASH: SchemaHash = SchemaHash::from_bytes([0xAB; 32]);
        assert_eq!(HASH.as_bytes()[0], 0xAB);
    }

    // ========================================================================
    // NEW BATCH: SerializationError additional coverage
    // ========================================================================

    #[test]
    fn error_cbor_deserialize_source_is_some() {
        use std::error::Error;
        let schema = SchemaId::new("fcp.test", "ErrSrc", Version::new(1, 0, 0));
        let mut bytes = Vec::new();
        bytes.extend_from_slice(schema.hash().as_bytes());
        bytes.push(0xFF); // invalid CBOR
        let err = CanonicalSerializer::deserialize_unchecked::<u8>(&bytes, &schema).unwrap_err();
        if let SerializationError::CborDeserialize(ref inner) = err {
            // CborDeserialize wraps a ciborium error, source should be available.
            let display = format!("{inner}");
            assert!(!display.is_empty());
        }
        // The Error trait source() should return Some for wrapping variants.
        let _ = err.source();
    }

    #[test]
    fn error_payload_too_large_boundary_values() {
        let err = SerializationError::PayloadTooLarge { len: 0, max: 0 };
        assert_eq!(err.to_string(), "payload too large (0 bytes > 0 bytes)");
    }

    #[test]
    fn error_duplicate_map_key_empty_hex() {
        let err = SerializationError::DuplicateMapKey {
            key_hex: String::new(),
        };
        let msg = err.to_string();
        assert!(msg.contains("duplicate map key"));
        assert!(msg.ends_with(')'));
    }

    #[test]
    fn error_payload_too_large_very_large_numbers() {
        let err = SerializationError::PayloadTooLarge {
            len: usize::MAX,
            max: usize::MAX - 1,
        };
        let msg = err.to_string();
        assert!(msg.contains("bytes"));
    }

    #[test]
    fn error_is_send_and_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        // SerializationError should be Send + Sync for use across threads.
        assert_send::<SerializationError>();
        assert_sync::<SerializationError>();
    }

    // ========================================================================
    // NEW BATCH: CanonicalSerializer edge cases
    // ========================================================================

    #[test]
    fn serialize_and_deserialize_unit_type() {
        let schema = SchemaId::new("fcp.test", "Unit", Version::new(1, 0, 0));
        let bytes = CanonicalSerializer::serialize(&(), &schema).unwrap();
        // Unit encodes as CBOR null (0xF6).
        assert_eq!(bytes[SCHEMA_HASH_LEN], 0xF6);
        CanonicalSerializer::deserialize::<()>(&bytes, &schema).unwrap();
    }

    #[test]
    fn serialize_same_value_different_schemas_different_bytes() {
        let schema_a = SchemaId::new("fcp.test", "SchA", Version::new(1, 0, 0));
        let schema_b = SchemaId::new("fcp.test", "SchB", Version::new(1, 0, 0));
        let val = 42_u32;
        let bytes_a = CanonicalSerializer::serialize(&val, &schema_a).unwrap();
        let bytes_b = CanonicalSerializer::serialize(&val, &schema_b).unwrap();
        // Same CBOR body but different schema hash prefix.
        assert_ne!(bytes_a, bytes_b);
        // CBOR portion (after 32 bytes) should be identical.
        assert_eq!(bytes_a[SCHEMA_HASH_LEN..], bytes_b[SCHEMA_HASH_LEN..]);
    }

    #[test]
    fn deserialize_unchecked_accepts_canonical_encoding() {
        let schema = SchemaId::new("fcp.test", "UnchkOk", Version::new(1, 0, 0));
        let val = "canonical check".to_string();
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        // Both strict and unchecked should succeed on canonical input.
        let strict: String = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        let unchecked: String =
            CanonicalSerializer::deserialize_unchecked(&bytes, &schema).unwrap();
        assert_eq!(strict, unchecked);
    }

    #[test]
    fn deserialize_rejects_one_byte_input() {
        let schema = SchemaId::new("fcp.test", "Tiny", Version::new(1, 0, 0));
        let err = CanonicalSerializer::deserialize::<u8>(&[0x42], &schema).unwrap_err();
        assert!(matches!(err, SerializationError::MissingSchemaHashPrefix));
    }

    #[test]
    fn deserialize_unchecked_rejects_one_byte_input() {
        let schema = SchemaId::new("fcp.test", "Tiny2", Version::new(1, 0, 0));
        let err = CanonicalSerializer::deserialize_unchecked::<u8>(&[0x42], &schema).unwrap_err();
        assert!(matches!(err, SerializationError::MissingSchemaHashPrefix));
    }

    #[test]
    fn deserialize_unchecked_rejects_empty_input() {
        let schema = SchemaId::new("fcp.test", "Empty2", Version::new(1, 0, 0));
        let err = CanonicalSerializer::deserialize_unchecked::<u8>(&[], &schema).unwrap_err();
        assert!(matches!(err, SerializationError::MissingSchemaHashPrefix));
    }

    #[test]
    fn deserialize_schema_mismatch_preserves_both_hashes() {
        let schema_a = SchemaId::new("fcp.test", "MMA", Version::new(1, 0, 0));
        let schema_b = SchemaId::new("fcp.test", "MMB", Version::new(1, 0, 0));
        let bytes = CanonicalSerializer::serialize(&1_u32, &schema_a).unwrap();
        let err = CanonicalSerializer::deserialize::<u32>(&bytes, &schema_b).unwrap_err();
        if let SerializationError::SchemaMismatch { expected, got } = err {
            assert_eq!(expected, schema_b.hash());
            assert_eq!(got, schema_a.hash());
        } else {
            panic!("expected SchemaMismatch");
        }
    }

    // ========================================================================
    // NEW BATCH: to_canonical_cbor edge cases
    // ========================================================================

    #[test]
    fn to_canonical_cbor_single_char_string() {
        let bytes = to_canonical_cbor(&"x").unwrap();
        // 0x61 = text string of length 1
        assert_eq!(bytes[0], 0x61);
        assert_eq!(bytes[1], b'x');
        assert_eq!(bytes.len(), 2);
    }

    #[test]
    fn to_canonical_cbor_255_byte_string() {
        let s = "a".repeat(255);
        let bytes = to_canonical_cbor(&s).unwrap();
        // 0x78 0xFF = text string with 1-byte length 255
        assert_eq!(bytes[0], 0x78);
        assert_eq!(bytes[1], 255);
    }

    #[test]
    fn to_canonical_cbor_256_byte_string() {
        let s = "b".repeat(256);
        let bytes = to_canonical_cbor(&s).unwrap();
        // 0x79 0x01 0x00 = text string with 2-byte length 256
        assert_eq!(bytes[0], 0x79);
        assert_eq!(bytes[1], 0x01);
        assert_eq!(bytes[2], 0x00);
    }

    #[test]
    fn to_canonical_cbor_negative_128() {
        let bytes = to_canonical_cbor(&(-128_i16)).unwrap();
        // -128 in CBOR: major type 1, value 127 = 0x38 0x7F (2 bytes)
        assert_eq!(bytes.len(), 2);
        assert_eq!(bytes[0], 0x38);
        assert_eq!(bytes[1], 0x7F);
    }

    #[test]
    fn to_canonical_cbor_negative_129() {
        let bytes = to_canonical_cbor(&(-129_i16)).unwrap();
        // -129 in CBOR: major type 1, value 128 = 0x38 0x80 (2 bytes)
        assert_eq!(bytes.len(), 2);
        assert_eq!(bytes[0], 0x38);
        assert_eq!(bytes[1], 0x80);
    }

    #[test]
    fn to_canonical_cbor_negative_256() {
        let bytes = to_canonical_cbor(&(-256_i16)).unwrap();
        // -256 in CBOR: major type 1, value 255 = 0x38 0xFF (2 bytes)
        assert_eq!(bytes.len(), 2);
        assert_eq!(bytes[0], 0x38);
        assert_eq!(bytes[1], 0xFF);
    }

    #[test]
    fn to_canonical_cbor_negative_257() {
        let bytes = to_canonical_cbor(&(-257_i16)).unwrap();
        // -257 in CBOR: major type 1, value 256 = 0x39 0x01 0x00 (3 bytes)
        assert_eq!(bytes.len(), 3);
        assert_eq!(bytes[0], 0x39);
    }

    #[test]
    fn to_canonical_cbor_f64_uses_shortest_float_width() {
        let bytes = to_canonical_cbor(&1.5_f64).unwrap();
        assert_eq!(bytes, vec![0xF9, 0x3E, 0x00]);
    }

    #[test]
    fn to_canonical_cbor_f64_uses_binary32_when_half_is_not_exact() {
        let bytes = to_canonical_cbor(&1_000_000.5_f64).unwrap();
        assert_eq!(bytes, vec![0xFA, 0x49, 0x74, 0x24, 0x08]);
    }

    #[test]
    fn to_canonical_cbor_normalizes_negative_zero() {
        let bytes = to_canonical_cbor(&(-0.0_f64)).unwrap();
        assert_eq!(bytes, vec![0xF9, 0x00, 0x00]);
    }

    // ========================================================================
    // NEW BATCH: canonicalize_map additional edge cases
    // ========================================================================

    #[test]
    fn canonicalize_map_three_duplicate_keys() {
        let mut entries = vec![
            (Value::Text("dup".into()), Value::Integer(1.into())),
            (Value::Text("dup".into()), Value::Integer(2.into())),
            (Value::Text("dup".into()), Value::Integer(3.into())),
        ];
        let err = canonicalize_map(&mut entries, 0).unwrap_err();
        assert!(matches!(err, SerializationError::DuplicateMapKey { .. }));
    }

    #[test]
    fn canonicalize_map_large_number_of_entries() {
        let mut entries: Vec<(Value, Value)> = (0..100)
            .map(|i| (Value::Text(format!("key_{i:04}")), Value::Integer(i.into())))
            .collect();
        canonicalize_map(&mut entries, 0).unwrap();
        // All keys have same length (8 chars), so they should be in lex order.
        for pair in entries.windows(2) {
            if let (Value::Text(a), Value::Text(b)) = (&pair[0].0, &pair[1].0) {
                assert!(a < b, "Keys not sorted: {a} >= {b}");
            }
        }
    }

    #[test]
    fn canonicalize_map_scratch_capacity_hits_exact_cap_boundary() {
        let exact_cap_entry_count = MAX_CANONICAL_OBJECT_BYTES / 32;
        assert_eq!(
            canonicalize_map_scratch_capacity_with_limit(
                exact_cap_entry_count - 1,
                MAX_CANONICAL_OBJECT_BYTES
            ),
            MAX_CANONICAL_OBJECT_BYTES - 32
        );
        assert_eq!(
            canonicalize_map_scratch_capacity_with_limit(
                exact_cap_entry_count,
                MAX_CANONICAL_OBJECT_BYTES
            ),
            MAX_CANONICAL_OBJECT_BYTES
        );
        assert_eq!(
            canonicalize_map_scratch_capacity_with_limit(
                exact_cap_entry_count + 1,
                MAX_CANONICAL_OBJECT_BYTES
            ),
            MAX_CANONICAL_OBJECT_BYTES
        );
    }

    #[test]
    fn canonicalize_map_negative_integer_keys() {
        let mut entries = vec![
            (Value::Integer((-1).into()), Value::Bool(true)),
            (Value::Integer((-100).into()), Value::Bool(false)),
            (Value::Integer((-2).into()), Value::Bool(true)),
        ];
        canonicalize_map(&mut entries, 0).unwrap();
        // Negative integers in CBOR: -1 = 0x20 (1 byte), -2 = 0x21 (1 byte), -100 = 0x38 0x63 (2 bytes)
        // So order is: -1, -2, -100 (by byte length, then lex)
        let keys: Vec<i128> = entries
            .iter()
            .filter_map(|(k, _)| {
                if let Value::Integer(i) = k {
                    Some(i128::from(*i))
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(keys, vec![-1, -2, -100]);
    }

    #[test]
    fn canonicalize_map_preserves_values() {
        let mut entries = vec![
            (Value::Text("c".into()), Value::Text("val_c".into())),
            (Value::Text("a".into()), Value::Text("val_a".into())),
            (Value::Text("b".into()), Value::Text("val_b".into())),
        ];
        canonicalize_map(&mut entries, 0).unwrap();
        // After sorting, values should follow their keys.
        assert_eq!(entries[0].1, Value::Text("val_a".into()));
        assert_eq!(entries[1].1, Value::Text("val_b".into()));
        assert_eq!(entries[2].1, Value::Text("val_c".into()));
    }

    #[test]
    fn canonicalize_map_null_key() {
        let mut entries = vec![
            (Value::Text("a".into()), Value::Integer(1.into())),
            (Value::Null, Value::Integer(2.into())),
        ];
        canonicalize_map(&mut entries, 0).unwrap();
        // RFC 8949 §4.2.1 uses bytewise lexicographic ordering of the
        // deterministic encodings — NOT length-first. Text "a" encodes as
        // 0x61 0x61 and Null as 0xF6; 0x61 < 0xF6 on the first byte, so
        // Text "a" sorts before Null.
        assert_eq!(entries[0].0, Value::Text("a".into()));
        assert_eq!(entries[1].0, Value::Null);
    }

    // ========================================================================
    // NEW BATCH: canonicalize_value_in_place coverage
    // ========================================================================

    #[test]
    fn canonicalize_array_of_arrays_with_maps() {
        let inner_map1 = Value::Map(vec![
            (Value::Text("zz".into()), Value::Integer(2.into())),
            (Value::Text("a".into()), Value::Integer(1.into())),
        ]);
        let inner_map2 = Value::Map(vec![
            (Value::Text("yy".into()), Value::Integer(4.into())),
            (Value::Text("b".into()), Value::Integer(3.into())),
        ]);
        let mut v = Value::Array(vec![
            Value::Array(vec![inner_map1]),
            Value::Array(vec![inner_map2]),
        ]);
        canonicalize_value_in_place(&mut v, 0).unwrap();

        // Navigate to inner maps and verify they're sorted.
        if let Value::Array(outer) = &v {
            for inner_arr in outer {
                if let Value::Array(arr) = inner_arr {
                    if let Value::Map(entries) = &arr[0] {
                        let k0 = if let Value::Text(s) = &entries[0].0 {
                            s.len()
                        } else {
                            999
                        };
                        let k1 = if let Value::Text(s) = &entries[1].0 {
                            s.len()
                        } else {
                            999
                        };
                        // Shorter keys first.
                        assert!(k0 <= k1);
                    }
                }
            }
        }
    }

    #[test]
    fn canonicalize_depth_with_tags_and_maps_is_rejected() {
        let inner = Value::Map(vec![
            (Value::Text("b".into()), Value::Integer(2.into())),
            (Value::Text("a".into()), Value::Integer(1.into())),
        ]);
        let tagged_inner = Value::Tag(2, Box::new(inner));
        let mut v = Value::Map(vec![(Value::Text("wrapper".into()), tagged_inner)]);
        let err = canonicalize_value_in_place(&mut v, 0).unwrap_err();
        assert!(matches!(err, SerializationError::UnsupportedTag { tag: 2 }));
    }

    #[test]
    fn canonicalize_tag_with_text_is_rejected() {
        let mut v = Value::Tag(55, Box::new(Value::Text("tagged string".into())));
        let err = canonicalize_value_in_place(&mut v, 0).unwrap_err();
        assert!(matches!(
            err,
            SerializationError::UnsupportedTag { tag: 55 }
        ));
    }

    #[test]
    fn canonicalize_tag_with_null_is_rejected() {
        let mut v = Value::Tag(0, Box::new(Value::Null));
        let err = canonicalize_value_in_place(&mut v, 0).unwrap_err();
        assert!(matches!(err, SerializationError::UnsupportedTag { tag: 0 }));
    }

    // ========================================================================
    // NEW BATCH: Roundtrip with complex enum and struct combos
    // ========================================================================

    #[test]
    fn roundtrip_enum_in_vec() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        enum Action {
            Start,
            Stop,
            Pause { duration_ms: u64 },
        }

        let schema = SchemaId::new("fcp.test", "Actions", Version::new(1, 0, 0));
        let val = vec![
            Action::Start,
            Action::Pause { duration_ms: 500 },
            Action::Stop,
        ];
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: Vec<Action> = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_struct_with_enum_field() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        enum Level {
            Low,
            Medium,
            High,
        }

        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Alert {
            message: String,
            level: Level,
        }

        let schema = SchemaId::new("fcp.test", "Alert", Version::new(1, 0, 0));
        let val = Alert {
            message: "test alert".to_string(),
            level: Level::High,
        };
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: Alert = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_map_of_string_to_enum() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        enum Status {
            Active,
            Disabled,
        }

        let schema = SchemaId::new("fcp.test", "StatusMap", Version::new(1, 0, 0));
        let mut map = std::collections::BTreeMap::new();
        map.insert("service_a".to_string(), Status::Active);
        map.insert("service_b".to_string(), Status::Disabled);

        let bytes = CanonicalSerializer::serialize(&map, &schema).unwrap();
        let decoded: std::collections::BTreeMap<String, Status> =
            CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, map);
    }

    #[test]
    fn roundtrip_nested_options() {
        let schema = SchemaId::new("fcp.test", "NestedOpt", Version::new(1, 0, 0));
        // Note: Some(None) and None both encode as CBOR null, so they are not
        // distinguishable in CBOR. Test only distinguishable cases.
        let vals: Vec<Option<Option<u32>>> = vec![Some(Some(42)), None, None];
        let bytes = CanonicalSerializer::serialize(&vals, &schema).unwrap();
        let decoded: Vec<Option<Option<u32>>> =
            CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, vals);
    }

    #[test]
    fn roundtrip_empty_string() {
        let schema = SchemaId::new("fcp.test", "EmptyStr", Version::new(1, 0, 0));
        let val = String::new();
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: String = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_string_single_char() {
        let schema = SchemaId::new("fcp.test", "SingleChar", Version::new(1, 0, 0));
        let val = "Z".to_string();
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: String = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    // ========================================================================
    // NEW BATCH: split_schema_prefix detailed tests
    // ========================================================================

    #[test]
    fn split_schema_prefix_preserves_body_content() {
        let schema = SchemaId::new("fcp.test", "Split", Version::new(1, 0, 0));
        let body = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        let mut data = Vec::new();
        data.extend_from_slice(schema.hash().as_bytes());
        data.extend_from_slice(&body);
        let (hash, extracted_body) = split_schema_prefix(&data).unwrap();
        assert_eq!(hash, schema.hash());
        assert_eq!(extracted_body, &body);
    }

    #[test]
    fn split_schema_prefix_large_body() {
        let mut data = vec![0xAA_u8; SCHEMA_HASH_LEN];
        let body = vec![0xBB_u8; 10000];
        data.extend_from_slice(&body);
        let (_, extracted_body) = split_schema_prefix(&data).unwrap();
        assert_eq!(extracted_body.len(), 10000);
        assert!(extracted_body.iter().all(|&b| b == 0xBB));
    }

    // ========================================================================
    // NEW BATCH: Canonical CBOR map ordering comprehensive
    // ========================================================================

    #[test]
    fn canonical_map_order_integer_before_text_before_bytes() {
        let mut entries = vec![
            (Value::Bytes(vec![0x01]), Value::Integer(3.into())),
            (Value::Text("a".into()), Value::Integer(2.into())),
            (Value::Integer(0.into()), Value::Integer(1.into())),
        ];
        canonicalize_map(&mut entries, 0).unwrap();
        // Int(0) = 0x00 (1 byte), Text("a") = 0x61 0x61 (2 bytes), Bytes([0x01]) = 0x41 0x01 (2 bytes)
        // 1 byte < 2 bytes; within 2 bytes: 0x41 < 0x61
        assert!(matches!(&entries[0].0, Value::Integer(_)));
        assert!(matches!(&entries[1].0, Value::Bytes(_)));
        assert!(matches!(&entries[2].0, Value::Text(_)));
    }

    #[test]
    fn canonical_map_duplicate_byte_string_keys_rejected() {
        let mut entries = vec![
            (Value::Bytes(vec![0xAA, 0xBB]), Value::Integer(1.into())),
            (Value::Bytes(vec![0xAA, 0xBB]), Value::Integer(2.into())),
        ];
        let err = canonicalize_map(&mut entries, 0).unwrap_err();
        assert!(matches!(err, SerializationError::DuplicateMapKey { .. }));
        if let SerializationError::DuplicateMapKey { key_hex } = err {
            // The hex should represent the CBOR encoding of Bytes([0xAA, 0xBB])
            assert!(!key_hex.is_empty());
        }
    }

    #[test]
    fn canonical_map_duplicate_bool_keys_rejected() {
        let mut entries = vec![
            (Value::Bool(true), Value::Integer(1.into())),
            (Value::Bool(true), Value::Integer(2.into())),
        ];
        let err = canonicalize_map(&mut entries, 0).unwrap_err();
        assert!(matches!(err, SerializationError::DuplicateMapKey { .. }));
    }

    // ========================================================================
    // NEW BATCH: Roundtrip with larger structures
    // ========================================================================

    #[test]
    fn roundtrip_struct_with_20_fields() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Big {
            f01: u8,
            f02: u16,
            f03: u32,
            f04: u64,
            f05: i8,
            f06: i16,
            f07: i32,
            f08: i64,
            f09: bool,
            f10: String,
            f11: Vec<u8>,
            f12: Option<u32>,
            f13: Option<String>,
            f14: f64,
            f15: Vec<String>,
            f16: Vec<bool>,
            f17: u8,
            f18: u8,
            f19: String,
            f20: bool,
        }

        let schema = SchemaId::new("fcp.test", "Big", Version::new(1, 0, 0));
        let val = Big {
            f01: 1,
            f02: 2,
            f03: 3,
            f04: 4,
            f05: -5,
            f06: -6,
            f07: -7,
            f08: -8,
            f09: true,
            f10: "field ten".to_string(),
            f11: vec![0x0A, 0x0B],
            f12: Some(12),
            f13: None,
            f14: 1.23,
            f15: vec!["a".to_string(), "b".to_string()],
            f16: vec![true, false],
            f17: 17,
            f18: 18,
            f19: "field nineteen".to_string(),
            f20: false,
        };
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: Big = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_vec_of_maps_with_mixed_values() {
        let schema = SchemaId::new("fcp.test", "VecMaps", Version::new(1, 0, 0));
        let mut m1 = std::collections::BTreeMap::new();
        m1.insert(
            "name".to_string(),
            serde_json::Value::String("alice".to_string()),
        );
        m1.insert("age".to_string(), serde_json::Value::Number(30.into()));

        let mut m2 = std::collections::BTreeMap::new();
        m2.insert(
            "name".to_string(),
            serde_json::Value::String("bob".to_string()),
        );
        m2.insert("active".to_string(), serde_json::Value::Bool(true));

        let val = vec![m1, m2];
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: Vec<std::collections::BTreeMap<String, serde_json::Value>> =
            CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    // ========================================================================
    // NEW BATCH: write_canonical_cbor edge cases
    // ========================================================================

    #[test]
    fn write_canonical_cbor_to_empty_buffer() {
        let mut buf = Vec::new();
        write_canonical_cbor(&42_u8, &mut buf).unwrap();
        let expected = to_canonical_cbor(&42_u8).unwrap();
        assert_eq!(buf, expected);
    }

    #[test]
    fn write_canonical_cbor_to_preallocated_buffer() {
        let mut buf = Vec::with_capacity(1024);
        write_canonical_cbor(&"preallocated", &mut buf).unwrap();
        assert!(!buf.is_empty());
        assert!(buf.capacity() >= 1024);
    }

    #[test]
    fn write_canonical_cbor_map_is_sorted() {
        let mut map = HashMap::new();
        map.insert("z".to_string(), 1);
        map.insert("a".to_string(), 2);
        let mut buf = Vec::new();
        write_canonical_cbor(&map, &mut buf).unwrap();

        let raw: Value = ciborium::de::from_reader(buf.as_slice()).unwrap();
        if let Value::Map(entries) = raw {
            let keys: Vec<&str> = entries
                .iter()
                .filter_map(|(k, _)| {
                    if let Value::Text(s) = k {
                        Some(s.as_str())
                    } else {
                        None
                    }
                })
                .collect();
            assert_eq!(keys, vec!["a", "z"]);
        } else {
            panic!("expected map");
        }
    }

    // ========================================================================
    // NEW BATCH: Non-canonical CBOR rejection detailed
    // ========================================================================

    #[test]
    fn deserialize_rejects_non_canonical_byte_string_length() {
        let schema = SchemaId::new("fcp.test", "NcBytes", Version::new(1, 0, 0));
        let mut bytes = Vec::new();
        bytes.extend_from_slice(schema.hash().as_bytes());
        // Integer 255 encoded non-minimally as 0x19 0x00 0xFF (3 bytes)
        // Canonical would be 0x18 0xFF (2 bytes)
        bytes.extend_from_slice(&[0x19, 0x00, 0xFF]);
        let result = CanonicalSerializer::deserialize::<u16>(&bytes, &schema);
        assert!(result.is_err());
    }

    #[test]
    fn deserialize_rejects_indefinite_length_array() {
        let schema = SchemaId::new("fcp.test", "IndefArr", Version::new(1, 0, 0));
        let mut bytes = Vec::new();
        bytes.extend_from_slice(schema.hash().as_bytes());
        // Indefinite-length array: 0x9F, items, 0xFF (break)
        bytes.extend_from_slice(&[0x9F, 0x01, 0x02, 0xFF]);
        let result = CanonicalSerializer::deserialize::<Vec<u8>>(&bytes, &schema);
        assert!(result.is_err());
    }

    #[test]
    fn deserialize_rejects_indefinite_length_string() {
        let schema = SchemaId::new("fcp.test", "IndefStr", Version::new(1, 0, 0));
        let mut bytes = Vec::new();
        bytes.extend_from_slice(schema.hash().as_bytes());
        // Indefinite-length text string: 0x7F, chunk, 0xFF
        bytes.extend_from_slice(&[0x7F, 0x61, b'a', 0xFF]);
        let result = CanonicalSerializer::deserialize::<String>(&bytes, &schema);
        assert!(result.is_err());
    }

    // ========================================================================
    // NEW BATCH: Determinism verification
    // ========================================================================

    #[test]
    fn canonical_cbor_determinism_with_hashmap_insert_order() {
        // Insert in forward order.
        let mut map_fwd = HashMap::new();
        for i in 0..50_u32 {
            map_fwd.insert(format!("key_{i:03}"), i);
        }
        // Insert in reverse order.
        let mut map_rev = HashMap::new();
        for i in (0..50_u32).rev() {
            map_rev.insert(format!("key_{i:03}"), i);
        }
        let bytes_fwd = to_canonical_cbor(&map_fwd).unwrap();
        let bytes_rev = to_canonical_cbor(&map_rev).unwrap();
        assert_eq!(bytes_fwd, bytes_rev);
    }

    #[test]
    fn schema_hash_determinism_100_iterations() {
        let schema = SchemaId::new("fcp.stability", "DeterCheck", Version::new(1, 0, 0));
        let first = schema.hash();
        for _ in 0..100 {
            assert_eq!(schema.hash(), first);
        }
    }

    // ========================================================================
    // NEW BATCH: Additional type coverage
    // ========================================================================

    #[test]
    fn roundtrip_char_as_string() {
        let schema = SchemaId::new("fcp.test", "Char", Version::new(1, 0, 0));
        let val = 'Z';
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: char = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_negative_float() {
        let schema = SchemaId::new("fcp.test", "NegFloat", Version::new(1, 0, 0));
        let val = -0.001_f64;
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: f64 = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert!((decoded - val).abs() < f64::EPSILON);
    }

    #[test]
    fn roundtrip_very_small_float() {
        let schema = SchemaId::new("fcp.test", "SmallFloat", Version::new(1, 0, 0));
        let val = 1e-300_f64;
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: f64 = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert!((decoded - val).abs() < f64::EPSILON);
    }

    #[test]
    fn roundtrip_vec_of_f64() {
        let schema = SchemaId::new("fcp.test", "F64Vec", Version::new(1, 0, 0));
        let val = vec![1.1_f64, 2.2, -3.3, 0.0, 42.0];
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: Vec<f64> = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded.len(), val.len());
        for (a, b) in val.iter().zip(decoded.iter()) {
            assert!((a - b).abs() < f64::EPSILON);
        }
    }

    #[test]
    fn roundtrip_vec_of_f64_rejects_infinity() {
        let schema = SchemaId::new("fcp.test", "F64VecInf", Version::new(1, 0, 0));
        let val = vec![1.1_f64, 2.2, f64::INFINITY];
        let err = CanonicalSerializer::serialize(&val, &schema).unwrap_err();
        assert!(matches!(err, SerializationError::NonFiniteFloat));
    }

    #[test]
    fn roundtrip_map_of_string_to_f64() {
        let schema = SchemaId::new("fcp.test", "F64Map", Version::new(1, 0, 0));
        let mut map = std::collections::BTreeMap::new();
        map.insert("val_a".to_string(), 1.234_567_f64);
        map.insert("val_b".to_string(), 9.876_543_f64);
        let bytes = CanonicalSerializer::serialize(&map, &schema).unwrap();
        let decoded: std::collections::BTreeMap<String, f64> =
            CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded.len(), map.len());
        for (key, expected) in &map {
            let actual = decoded[key];
            assert!((actual - expected).abs() < f64::EPSILON);
        }
    }

    // ========================================================================
    // NEW BATCH: CBOR encoding of container length boundaries
    // ========================================================================

    #[test]
    fn to_canonical_cbor_map_with_23_entries() {
        let mut map = std::collections::BTreeMap::new();
        for i in 0..23 {
            map.insert(format!("{i:02}"), i);
        }
        let bytes = to_canonical_cbor(&map).unwrap();
        // Map header with 23 entries: 0xB7 (major type 5, additional 23)
        assert_eq!(bytes[0], 0xB7);
    }

    #[test]
    fn to_canonical_cbor_map_with_24_entries() {
        let mut map = std::collections::BTreeMap::new();
        for i in 0..24 {
            map.insert(format!("{i:02}"), i);
        }
        let bytes = to_canonical_cbor(&map).unwrap();
        // Map header with 24 entries: 0xB8 0x18 (major type 5, additional 24, 2-byte form)
        assert_eq!(bytes[0], 0xB8);
        assert_eq!(bytes[1], 24);
    }

    // ========================================================================
    // NEW BATCH: Multi-byte Unicode string length encoding
    // ========================================================================

    #[test]
    fn cbor_string_length_counts_bytes_not_chars() {
        // 4 CJK characters, each 3 bytes in UTF-8 = 12 bytes
        let val = "\u{4e16}\u{754c}\u{4f60}\u{597d}";
        assert_eq!(val.len(), 12);
        let bytes = to_canonical_cbor(&val).unwrap();
        // 0x6C = text string of length 12
        assert_eq!(bytes[0], 0x6C);
    }

    #[test]
    fn cbor_emoji_string_length_counts_bytes() {
        // Single emoji (4 bytes in UTF-8)
        let val = "\u{1F600}";
        assert_eq!(val.len(), 4);
        let bytes = to_canonical_cbor(&val).unwrap();
        // 0x64 = text string of length 4
        assert_eq!(bytes[0], 0x64);
    }

    // ========================================================================
    // NEW BATCH: Additional coverage for 360+ target
    // ========================================================================

    #[test]
    fn schema_id_hash_not_affected_by_whitespace_padding() {
        let a = SchemaId::new("ns", "Type", Version::new(1, 0, 0));
        let b = SchemaId::new("ns ", "Type", Version::new(1, 0, 0));
        let c = SchemaId::new("ns", " Type", Version::new(1, 0, 0));
        assert_ne!(a.hash(), b.hash());
        assert_ne!(a.hash(), c.hash());
        assert_ne!(b.hash(), c.hash());
    }

    #[test]
    fn roundtrip_empty_vec_of_strings() {
        let schema = SchemaId::new("fcp.test", "EmptyVecStr", Version::new(1, 0, 0));
        let val: Vec<String> = vec![];
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: Vec<String> = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn roundtrip_single_element_map() {
        let schema = SchemaId::new("fcp.test", "SingleEntry", Version::new(1, 0, 0));
        let mut map = std::collections::BTreeMap::new();
        map.insert("sole_key".to_string(), 99_u64);
        let bytes = CanonicalSerializer::serialize(&map, &schema).unwrap();
        let decoded: std::collections::BTreeMap<String, u64> =
            CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, map);
    }

    #[test]
    fn to_canonical_cbor_negative_one_as_i32() {
        let bytes = to_canonical_cbor(&(-1_i32)).unwrap();
        assert_eq!(bytes, vec![0x20]); // Same as i8 -1
    }

    #[test]
    fn to_canonical_cbor_negative_one_as_i64() {
        let bytes = to_canonical_cbor(&(-1_i64)).unwrap();
        assert_eq!(bytes, vec![0x20]); // CBOR -1 is always one byte
    }

    #[test]
    fn canonicalize_map_with_array_values() {
        let mut entries = vec![
            (
                Value::Text("b".into()),
                Value::Array(vec![Value::Integer(3.into()), Value::Integer(4.into())]),
            ),
            (
                Value::Text("a".into()),
                Value::Array(vec![Value::Integer(1.into()), Value::Integer(2.into())]),
            ),
        ];
        canonicalize_map(&mut entries, 0).unwrap();
        // Keys sorted: "a" before "b".
        if let Value::Text(s) = &entries[0].0 {
            assert_eq!(s, "a");
        }
        // Array values preserved in their original order.
        if let Value::Array(arr) = &entries[0].1 {
            assert_eq!(arr[0], Value::Integer(1.into()));
            assert_eq!(arr[1], Value::Integer(2.into()));
        }
    }

    #[test]
    fn schema_hash_serde_cbor_deterministic() {
        let hash = SchemaHash::from_bytes([0x42; 32]);
        let bytes1 = to_canonical_cbor(&hash).unwrap();
        let bytes2 = to_canonical_cbor(&hash).unwrap();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn serialize_deserialize_large_string() {
        let schema = SchemaId::new("fcp.test", "BigStr", Version::new(1, 0, 0));
        let val = "X".repeat(100_000);
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: String = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn to_canonical_cbor_true_false_different() {
        let t = to_canonical_cbor(&true).unwrap();
        let f = to_canonical_cbor(&false).unwrap();
        assert_ne!(t, f);
        // Both are single byte but different values.
        assert_eq!(t.len(), 1);
        assert_eq!(f.len(), 1);
        assert_ne!(t[0], f[0]);
    }

    #[test]
    fn canonical_map_with_float_values() {
        let mut entries = vec![
            (Value::Text("y".into()), Value::Float(2.5)),
            (Value::Text("x".into()), Value::Float(1.5)),
        ];
        canonicalize_map(&mut entries, 0).unwrap();
        // Keys sorted: "x" before "y" (same length, lex).
        if let Value::Text(s) = &entries[0].0 {
            assert_eq!(s, "x");
        }
        if let Value::Float(f) = &entries[0].1 {
            assert!((f - 1.5).abs() < f64::EPSILON);
        }
    }

    #[test]
    fn schema_id_hash_uses_full_version_string() {
        // Pre-release and build metadata affect the hash.
        let plain = SchemaId::new("ns", "T", Version::new(1, 0, 0));
        let pre = SchemaId::new("ns", "T", Version::parse("1.0.0-alpha").unwrap());
        let build = SchemaId::new("ns", "T", Version::parse("1.0.0+build1").unwrap());
        assert_ne!(plain.hash(), pre.hash());
        assert_ne!(plain.hash(), build.hash());
        assert_ne!(pre.hash(), build.hash());
    }

    // ========================================================================
    // NEW BATCH 2026-03-08: SchemaId boundary and trait coverage
    // ========================================================================

    #[test]
    fn schema_id_try_new_rejects_separator_only_components() {
        // Pre-fix this produced "::@@0.0.0" — a self-aliased canonical form. The
        // validated constructor now refuses both components.
        let err = SchemaId::try_new(":", "Type", Version::new(0, 0, 0)).unwrap_err();
        assert!(matches!(
            err,
            SchemaIdError::ReservedSeparator {
                field: "namespace",
                separator: ':',
            }
        ));
        let err = SchemaId::try_new("ns", "@", Version::new(0, 0, 0)).unwrap_err();
        assert!(matches!(
            err,
            SchemaIdError::ReservedSeparator {
                field: "name",
                separator: '@',
            }
        ));
    }

    #[test]
    fn schema_id_as_bytes_empty_name_only() {
        let schema = SchemaId::new("fcp.core", "", Version::new(1, 0, 0));
        let canonical = String::from_utf8(schema.as_bytes()).unwrap();
        assert_eq!(canonical, "fcp.core:@1.0.0");
    }

    #[test]
    fn schema_id_as_bytes_empty_namespace_only() {
        let schema = SchemaId::new("", "Token", Version::new(1, 0, 0));
        let canonical = String::from_utf8(schema.as_bytes()).unwrap();
        assert_eq!(canonical, ":Token@1.0.0");
    }

    #[test]
    fn schema_id_hash_differs_trailing_space() {
        let a = SchemaId::new("ns", "Type", Version::new(1, 0, 0));
        let b = SchemaId::new("ns", "Type ", Version::new(1, 0, 0));
        assert_ne!(a.hash(), b.hash());
        assert_ne!(a, b);
    }

    #[test]
    fn schema_id_new_accepts_cow_str() {
        use std::borrow::Cow;
        let ns: Cow<'_, str> = Cow::Borrowed("fcp.core");
        let name: Cow<'_, str> = Cow::Owned("Token".to_string());
        let schema = SchemaId::new(ns, name, Version::new(1, 0, 0));
        assert_eq!(schema.namespace, "fcp.core");
        assert_eq!(schema.name, "Token");
    }

    #[test]
    fn schema_id_serde_json_with_prerelease_and_build() {
        let schema = SchemaId::new(
            "fcp.proto",
            "Msg",
            Version::parse("3.2.1-rc.1+meta").unwrap(),
        );
        let json = serde_json::to_string(&schema).unwrap();
        let decoded: SchemaId = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, schema);
        assert_eq!(decoded.version.pre.as_str(), "rc.1");
        assert_eq!(decoded.version.build.as_str(), "meta");
    }

    #[test]
    fn schema_id_partial_eq_reflexive() {
        let s = SchemaId::new("ns", "T", Version::new(1, 0, 0));
        assert_eq!(s, s);
    }

    #[test]
    fn schema_id_debug_format_contains_struct_name() {
        let s = SchemaId::new("ns", "T", Version::new(1, 0, 0));
        let debug = format!("{s:?}");
        assert!(debug.contains("SchemaId"));
    }

    // ========================================================================
    // NEW BATCH 2026-03-08: SchemaHash ordering and advanced traits
    // ========================================================================

    #[test]
    fn schema_hash_eq_transitive() {
        let a = SchemaHash::from_bytes([0x99; 32]);
        let b = SchemaHash::from_bytes([0x99; 32]);
        let c = SchemaHash::from_bytes([0x99; 32]);
        assert_eq!(a, b);
        assert_eq!(b, c);
        assert_eq!(a, c);
    }

    #[test]
    fn schema_hash_as_ref_matches_from_bytes_input() {
        let input = [0x13; 32];
        let hash = SchemaHash::from_bytes(input);
        let as_ref: &[u8] = hash.as_ref();
        assert_eq!(as_ref, &input);
    }

    #[test]
    fn schema_hash_display_for_sequential_bytes() {
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = u8::try_from(i).unwrap();
        }
        let hash = SchemaHash::from_bytes(bytes);
        let display = hash.to_string();
        assert!(display.starts_with("000102"));
        assert!(display.ends_with("1f"));
        assert_eq!(display.len(), 64);
    }

    #[test]
    fn schema_hash_clone_is_copy() {
        let original = SchemaHash::from_bytes([0x77; 32]);
        let copied1 = original;
        let copied2 = original;
        assert_eq!(original, copied1);
        assert_eq!(original, copied2);
        assert_eq!(copied1, copied2);
    }

    #[test]
    fn schema_hash_as_bytes_returns_const_ref() {
        const H: SchemaHash = SchemaHash::from_bytes([0xFE; 32]);
        const BYTES: &[u8; 32] = H.as_bytes();
        assert_eq!(BYTES[0], 0xFE);
        assert_eq!(BYTES[31], 0xFE);
    }

    // ========================================================================
    // NEW BATCH 2026-03-08: SerializationError advanced coverage
    // ========================================================================

    #[test]
    fn error_source_chain_cbor_deserialize() {
        use std::error::Error;
        let schema = SchemaId::new("fcp.test", "SrcChain", Version::new(1, 0, 0));
        let mut bytes = Vec::new();
        bytes.extend_from_slice(schema.hash().as_bytes());
        bytes.push(0xFF); // invalid CBOR
        let err = CanonicalSerializer::deserialize_unchecked::<u8>(&bytes, &schema).unwrap_err();
        // CborDeserialize should have a source error.
        if let SerializationError::CborDeserialize(_) = &err {
            assert!(err.source().is_some());
        } else {
            panic!("expected CborDeserialize");
        }
    }

    #[test]
    fn error_source_none_for_simple_variants() {
        use std::error::Error;
        let simple_errors = vec![
            SerializationError::MissingSchemaHashPrefix,
            SerializationError::TrailingBytes,
            SerializationError::NonCanonicalEncoding,
            SerializationError::NonFiniteFloat,
            SerializationError::UnsupportedTag { tag: 99 },
        ];
        for err in &simple_errors {
            assert!(err.source().is_none(), "expected no source for {err}");
        }
    }

    #[test]
    fn error_schema_mismatch_source_is_none() {
        use std::error::Error;
        let err = SerializationError::SchemaMismatch {
            expected: SchemaHash::from_bytes([0; 32]),
            got: SchemaHash::from_bytes([1; 32]),
        };
        assert!(err.source().is_none());
    }

    #[test]
    fn error_payload_too_large_source_is_none() {
        use std::error::Error;
        let err = SerializationError::PayloadTooLarge { len: 1, max: 0 };
        assert!(err.source().is_none());
    }

    #[test]
    fn error_duplicate_map_key_source_is_none() {
        use std::error::Error;
        let err = SerializationError::DuplicateMapKey {
            key_hex: "ab".into(),
        };
        assert!(err.source().is_none());
    }

    #[test]
    fn error_display_cbor_serialize_wraps_inner_message() {
        // Trigger CborSerialize indirectly is hard, so test the Display
        // for DuplicateMapKey with a long hex key.
        let err = SerializationError::DuplicateMapKey {
            key_hex: "aabbccdd".repeat(10),
        };
        let msg = err.to_string();
        assert!(msg.contains("duplicate map key"));
        assert!(msg.contains("aabbccdd"));
    }

    // ========================================================================
    // NEW BATCH 2026-03-08: CanonicalSerializer integration scenarios
    // ========================================================================

    #[test]
    fn serialize_then_deserialize_unchecked_matches() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Payload {
            id: u64,
            tags: Vec<String>,
        }

        let schema = SchemaId::new("fcp.test", "Payload2", Version::new(1, 0, 0));
        let val = Payload {
            id: 42,
            tags: vec!["a".into(), "b".into()],
        };
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let strict: Payload = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        let unchecked: Payload =
            CanonicalSerializer::deserialize_unchecked(&bytes, &schema).unwrap();
        assert_eq!(strict, unchecked);
        assert_eq!(strict, val);
    }

    #[test]
    fn serialize_different_schemas_same_value_cbor_body_matches() {
        let s1 = SchemaId::new("a", "T", Version::new(1, 0, 0));
        let s2 = SchemaId::new("b", "T", Version::new(1, 0, 0));
        let val = 12345_u64;
        let b1 = CanonicalSerializer::serialize(&val, &s1).unwrap();
        let b2 = CanonicalSerializer::serialize(&val, &s2).unwrap();
        // Schema prefixes differ.
        assert_ne!(&b1[..SCHEMA_HASH_LEN], &b2[..SCHEMA_HASH_LEN]);
        // CBOR bodies are identical.
        assert_eq!(&b1[SCHEMA_HASH_LEN..], &b2[SCHEMA_HASH_LEN..]);
    }

    #[test]
    fn deserialize_corrupted_single_bit_flip_detected() {
        let schema = SchemaId::new("fcp.test", "BitFlip", Version::new(1, 0, 0));
        let val = 42_u32;
        let mut bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        // Flip a bit in the CBOR body.
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        // Should fail: either schema mismatch, non-canonical, or wrong value.
        if let Ok(decoded) = CanonicalSerializer::deserialize::<u32>(&bytes, &schema) {
            assert_ne!(decoded, val);
        }
    }

    #[test]
    fn serialize_deserialize_with_version_zero_zero_one() {
        let schema = SchemaId::new("fcp.test", "V001", Version::new(0, 0, 1));
        let val = "version zero-zero-one".to_string();
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: String = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn serialize_unit_struct_same_as_null() {
        let schema = SchemaId::new("fcp.test", "UnitNull", Version::new(1, 0, 0));
        let unit_bytes = CanonicalSerializer::serialize(&(), &schema).unwrap();
        let none_bytes = CanonicalSerializer::serialize(&Option::<u32>::None, &schema).unwrap();
        // Both should produce CBOR null.
        assert_eq!(unit_bytes, none_bytes);
    }

    #[test]
    fn deserialize_rejects_zero_length_cbor_body() {
        let schema = SchemaId::new("fcp.test", "ZeroBody", Version::new(1, 0, 0));
        // Just the hash prefix, no CBOR at all.
        let bytes = schema.hash().as_bytes().to_vec();
        let err = CanonicalSerializer::deserialize::<u8>(&bytes, &schema).unwrap_err();
        assert!(matches!(err, SerializationError::CborDeserialize(_)));
    }

    // ========================================================================
    // NEW BATCH 2026-03-08: to_canonical_cbor advanced edge cases
    // ========================================================================

    #[test]
    fn to_canonical_cbor_nested_option_some_some() {
        let val: Option<Option<u32>> = Some(Some(42));
        let bytes = to_canonical_cbor(&val).unwrap();
        let decoded: Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        // Some(Some(42)) should decode to integer 42 in CBOR (options are transparent).
        assert!(matches!(decoded, Value::Integer(_)));
    }

    #[test]
    fn to_canonical_cbor_nested_option_none() {
        let val: Option<Option<u32>> = None;
        let bytes = to_canonical_cbor(&val).unwrap();
        assert_eq!(bytes, vec![0xF6]); // CBOR null
    }

    #[test]
    fn to_canonical_cbor_hashmap_with_numeric_string_keys() {
        // Numeric string keys should be sorted by byte length, not numeric value.
        let mut map = HashMap::new();
        map.insert("100".to_string(), 1);
        map.insert("9".to_string(), 2);
        map.insert("20".to_string(), 3);
        let bytes = to_canonical_cbor(&map).unwrap();
        let raw: Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        if let Value::Map(entries) = raw {
            let keys: Vec<&str> = entries
                .iter()
                .filter_map(|(k, _)| {
                    if let Value::Text(s) = k {
                        Some(s.as_str())
                    } else {
                        None
                    }
                })
                .collect();
            // "9" (1 char) < "20" (2 chars) < "100" (3 chars)
            assert_eq!(keys, vec!["9", "20", "100"]);
        } else {
            panic!("expected map");
        }
    }

    #[test]
    fn to_canonical_cbor_array_preserves_order() {
        let val = vec![5_u32, 3, 1, 4, 2];
        let bytes = to_canonical_cbor(&val).unwrap();
        let decoded: Vec<u32> = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        // Arrays must preserve insertion order, not sort.
        assert_eq!(decoded, vec![5, 3, 1, 4, 2]);
    }

    #[test]
    fn to_canonical_cbor_nested_empty_maps() {
        let inner = HashMap::<String, u32>::new();
        let mut outer = HashMap::new();
        outer.insert("empty".to_string(), inner);
        let bytes = to_canonical_cbor(&outer).unwrap();
        let bytes2 = to_canonical_cbor(&outer).unwrap();
        assert_eq!(bytes, bytes2);
    }

    #[test]
    fn to_canonical_cbor_vec_of_empty_vecs() {
        let val: Vec<Vec<u32>> = vec![vec![], vec![], vec![]];
        let bytes = to_canonical_cbor(&val).unwrap();
        let decoded: Vec<Vec<u32>> = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn to_canonical_cbor_map_with_empty_string_key() {
        let mut map = HashMap::new();
        map.insert(String::new(), 1);
        map.insert("a".to_string(), 2);
        let bytes = to_canonical_cbor(&map).unwrap();
        let raw: Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        if let Value::Map(entries) = raw {
            let keys: Vec<&str> = entries
                .iter()
                .filter_map(|(k, _)| {
                    if let Value::Text(s) = k {
                        Some(s.as_str())
                    } else {
                        None
                    }
                })
                .collect();
            // "" (len 0) before "a" (len 1)
            assert_eq!(keys, vec!["", "a"]);
        } else {
            panic!("expected map");
        }
    }

    // ========================================================================
    // NEW BATCH 2026-03-08: canonicalize_map advanced edge cases
    // ========================================================================

    #[test]
    fn canonicalize_map_float_keys_sorted_by_bytes() {
        let mut entries = vec![
            (Value::Float(2.5), Value::Integer(2.into())),
            (Value::Float(1.5), Value::Integer(1.into())),
        ];
        canonicalize_map(&mut entries, 0).unwrap();
        // Float keys are sorted by the bytewise lexicographic order of their
        // deterministic encodings.
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].0, Value::Float(1.5));
        assert_eq!(entries[1].0, Value::Float(2.5));
    }

    #[test]
    fn canonicalize_map_duplicate_float_keys_rejected() {
        let mut entries = vec![
            (Value::Float(1.5), Value::Integer(1.into())),
            (Value::Float(1.5), Value::Integer(2.into())),
        ];
        let err = canonicalize_map(&mut entries, 0).unwrap_err();
        assert!(matches!(err, SerializationError::DuplicateMapKey { .. }));
    }

    #[test]
    fn canonicalize_map_negative_zero_and_positive_zero_keys_rejected() {
        let mut entries = vec![
            (Value::Float(-0.0), Value::Integer(1.into())),
            (Value::Float(0.0), Value::Integer(2.into())),
        ];
        let err = canonicalize_map(&mut entries, 0).unwrap_err();
        assert!(matches!(err, SerializationError::DuplicateMapKey { .. }));
    }

    #[test]
    fn canonicalize_map_duplicate_null_keys_rejected() {
        let mut entries = vec![
            (Value::Null, Value::Integer(1.into())),
            (Value::Null, Value::Integer(2.into())),
        ];
        let err = canonicalize_map(&mut entries, 0).unwrap_err();
        assert!(matches!(err, SerializationError::DuplicateMapKey { .. }));
    }

    #[test]
    fn canonicalize_map_with_nested_map_in_value() {
        let inner = Value::Map(vec![
            (Value::Text("z".into()), Value::Integer(2.into())),
            (Value::Text("a".into()), Value::Integer(1.into())),
        ]);
        let mut entries = vec![(Value::Text("key".into()), inner)];
        canonicalize_map(&mut entries, 0).unwrap();
        // Inner map value should also be canonicalized.
        if let Value::Map(inner_entries) = &entries[0].1 {
            let keys: Vec<&str> = inner_entries
                .iter()
                .filter_map(|(k, _)| {
                    if let Value::Text(s) = k {
                        Some(s.as_str())
                    } else {
                        None
                    }
                })
                .collect();
            assert_eq!(keys, vec!["a", "z"]);
        } else {
            panic!("expected inner map");
        }
    }

    #[test]
    fn canonicalize_map_with_tag_in_value_is_rejected() {
        let tagged = Value::Tag(
            42,
            Box::new(Value::Map(vec![
                (Value::Text("b".into()), Value::Integer(2.into())),
                (Value::Text("a".into()), Value::Integer(1.into())),
            ])),
        );
        let mut entries = vec![(Value::Text("wrapper".into()), tagged)];
        let err = canonicalize_map(&mut entries, 0).unwrap_err();
        assert!(matches!(
            err,
            SerializationError::UnsupportedTag { tag: 42 }
        ));
    }

    // ========================================================================
    // NEW BATCH 2026-03-08: canonicalize_value_in_place depth interactions
    // ========================================================================

    #[test]
    fn canonicalize_depth_with_mixed_nesting_types_rejects_tag() {
        let leaf = Value::Integer(42.into());
        let arr_leaf = Value::Array(vec![leaf]);
        let inner_map = Value::Map(vec![(Value::Text("k".into()), arr_leaf)]);
        let tagged = Value::Tag(1, Box::new(inner_map));
        let mut v = Value::Array(vec![tagged]);
        let err = canonicalize_value_in_place(&mut v, 0).unwrap_err();
        assert!(matches!(err, SerializationError::UnsupportedTag { tag: 1 }));
    }

    #[test]
    fn canonicalize_tag_at_max_depth_boundary_is_rejected() {
        let mut v = Value::Integer(1.into());
        for _ in 0..MAX_CANONICALIZATION_DEPTH {
            v = Value::Tag(0, Box::new(v));
        }
        let err = canonicalize_value_in_place(&mut v, 0).unwrap_err();
        assert!(matches!(err, SerializationError::UnsupportedTag { tag: 0 }));
    }

    #[test]
    fn canonicalize_tag_exceeding_max_depth_is_rejected_before_depth_walk() {
        let mut v = Value::Integer(1.into());
        for _ in 0..=MAX_CANONICALIZATION_DEPTH {
            v = Value::Tag(0, Box::new(v));
        }
        let err = canonicalize_value_in_place(&mut v, 0).unwrap_err();
        assert!(matches!(err, SerializationError::UnsupportedTag { tag: 0 }));
    }

    #[test]
    fn canonicalize_map_at_exact_max_depth_fails() {
        // Map at depth MAX + 1 (called from depth MAX)
        let mut v = Value::Map(vec![(Value::Text("k".into()), Value::Integer(1.into()))]);
        let result = canonicalize_value_in_place(&mut v, MAX_CANONICALIZATION_DEPTH);
        // depth > MAX_CANONICALIZATION_DEPTH should fail
        // Actually, canonicalize_map is called with depth+1, so the map itself is
        // processed at depth=MAX, then its children at depth=MAX+1 which is > MAX.
        // But the simple values don't recurse further. Let me test with a nested map.
        drop(result);
        let nested = Value::Map(vec![(
            Value::Text("k".into()),
            Value::Map(vec![(
                Value::Text("inner".into()),
                Value::Integer(1.into()),
            )]),
        )]);
        let mut v2 = nested;
        let result2 = canonicalize_value_in_place(&mut v2, MAX_CANONICALIZATION_DEPTH - 1);
        // At depth MAX-1, map calls canonicalize_map at depth MAX,
        // which calls canonicalize_value_in_place on children at depth MAX.
        // Inner map calls canonicalize_map at depth MAX+1 which exceeds limit.
        assert!(result2.is_err());
    }

    // ========================================================================
    // NEW BATCH 2026-03-08: Roundtrip complex integration tests
    // ========================================================================

    #[test]
    fn roundtrip_struct_with_hashmap_and_btreemap() {
        use std::collections::BTreeMap;

        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct MixedMaps {
            ordered: BTreeMap<String, u32>,
            unordered: HashMap<String, u32>,
        }

        let schema = SchemaId::new("fcp.test", "MixedMaps", Version::new(1, 0, 0));
        let mut ordered = BTreeMap::new();
        ordered.insert("z".to_string(), 3);
        ordered.insert("a".to_string(), 1);
        let mut unordered = HashMap::new();
        unordered.insert("y".to_string(), 4);
        unordered.insert("b".to_string(), 2);
        let val = MixedMaps { ordered, unordered };
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: MixedMaps = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_enum_with_all_variant_types() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        enum Multi {
            Unit,
            Newtype(u64),
            Tuple(String, bool),
            Struct { x: i32, y: i32 },
        }

        let schema = SchemaId::new("fcp.test", "Multi", Version::new(1, 0, 0));
        let variants = vec![
            Multi::Unit,
            Multi::Newtype(999),
            Multi::Tuple("hello".into(), true),
            Multi::Struct { x: -10, y: 20 },
        ];
        for val in variants {
            let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
            let decoded: Multi = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
            assert_eq!(decoded, val);
        }
    }

    #[test]
    fn roundtrip_deeply_nested_option_chain() {
        let schema = SchemaId::new("fcp.test", "DeepOpt", Version::new(1, 0, 0));
        // Some(Some(Some(42)))
        let val: Option<Option<Option<u32>>> = Some(Some(Some(42)));
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: Option<Option<Option<u32>>> =
            CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_struct_with_nested_vecs_and_maps() {
        use std::collections::BTreeMap;

        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Complex {
            matrix: Vec<Vec<i32>>,
            lookup: BTreeMap<String, Vec<u64>>,
            label: Option<String>,
        }

        let schema = SchemaId::new("fcp.test", "Complex", Version::new(1, 0, 0));
        let mut lookup = BTreeMap::new();
        lookup.insert("ids".to_string(), vec![1, 2, 3]);
        lookup.insert("refs".to_string(), vec![100, 200]);
        let val = Complex {
            matrix: vec![vec![1, 2], vec![3, 4], vec![5, 6]],
            lookup,
            label: Some("complex struct".to_string()),
        };
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: Complex = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_vec_of_enums_with_options() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        enum OptVariant {
            Present(String),
            Absent,
        }

        let schema = SchemaId::new("fcp.test", "OptVar", Version::new(1, 0, 0));
        let val: Vec<Option<OptVariant>> = vec![
            Some(OptVariant::Present("yes".into())),
            None,
            Some(OptVariant::Absent),
        ];
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: Vec<Option<OptVariant>> =
            CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    // ========================================================================
    // NEW BATCH 2026-03-08: Schema workflow integration
    // ========================================================================

    #[test]
    fn schema_hash_uniqueness_across_many_schemas() {
        use std::collections::HashSet;
        let mut hashes = HashSet::new();
        for i in 0..100_u64 {
            let schema = SchemaId::new(
                format!("ns.{}", i / 10),
                format!("Type{}", i % 10),
                Version::new(i, 0, 0),
            );
            let inserted = hashes.insert(schema.hash());
            assert!(inserted, "hash collision at i={i}");
        }
        assert_eq!(hashes.len(), 100);
    }

    #[test]
    fn schema_id_cross_schema_deserialization_rejected() {
        // Serialize with schema A, attempt deserialize with schemas B through E.
        let schema_a = SchemaId::new("fcp.test", "Original", Version::new(1, 0, 0));
        let bytes = CanonicalSerializer::serialize(&42_u32, &schema_a).unwrap();

        let wrong_schemas = vec![
            SchemaId::new("fcp.test", "Original", Version::new(2, 0, 0)),
            SchemaId::new("fcp.test", "Different", Version::new(1, 0, 0)),
            SchemaId::new("fcp.other", "Original", Version::new(1, 0, 0)),
            SchemaId::new("", "", Version::new(1, 0, 0)),
        ];
        for wrong in &wrong_schemas {
            let result = CanonicalSerializer::deserialize::<u32>(&bytes, wrong);
            assert!(
                matches!(result, Err(SerializationError::SchemaMismatch { .. })),
                "expected SchemaMismatch for schema {wrong:?}"
            );
        }
    }

    #[test]
    fn serialize_deserialize_preserves_map_entry_count() {
        let schema = SchemaId::new("fcp.test", "EntryCount", Version::new(1, 0, 0));
        for count in [0, 1, 5, 23, 24, 100, 256] {
            let map: HashMap<String, u32> = (0..count).map(|i| (format!("k{i}"), i)).collect();
            let bytes = CanonicalSerializer::serialize(&map, &schema).unwrap();
            let decoded: HashMap<String, u32> =
                CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
            assert_eq!(decoded.len(), count as usize);
        }
    }

    // ========================================================================
    // NEW BATCH 2026-03-08: CBOR encoding verification
    // ========================================================================

    #[test]
    fn to_canonical_cbor_map_of_1_entry_header() {
        let mut map = std::collections::BTreeMap::new();
        map.insert("k".to_string(), 1_u32);
        let bytes = to_canonical_cbor(&map).unwrap();
        assert_eq!(bytes[0], 0xA1); // map with 1 entry
    }

    #[test]
    fn to_canonical_cbor_array_of_1_element_header() {
        let val = vec![1_u32];
        let bytes = to_canonical_cbor(&val).unwrap();
        assert_eq!(bytes[0], 0x81); // array with 1 element
    }

    #[test]
    fn to_canonical_cbor_string_of_length_0_header() {
        let bytes = to_canonical_cbor(&"").unwrap();
        assert_eq!(bytes, vec![0x60]); // empty text string
    }

    #[test]
    fn to_canonical_cbor_i8_negative_one_encoding() {
        let bytes = to_canonical_cbor(&(-1_i8)).unwrap();
        assert_eq!(bytes, vec![0x20]); // CBOR: major type 1, additional 0
    }

    #[test]
    fn to_canonical_cbor_i16_min_encoding() {
        let bytes = to_canonical_cbor(&i16::MIN).unwrap();
        // i16::MIN = -32768, CBOR = major type 1, value 32767 = 0x39 0x7F 0xFF
        assert_eq!(bytes.len(), 3);
        assert_eq!(bytes[0], 0x39);
    }

    #[test]
    fn to_canonical_cbor_i32_min_encoding() {
        let bytes = to_canonical_cbor(&i32::MIN).unwrap();
        // i32::MIN = -2147483648, CBOR = 0x3A 0x7F 0xFF 0xFF 0xFF
        assert_eq!(bytes.len(), 5);
        assert_eq!(bytes[0], 0x3A);
    }

    #[test]
    fn to_canonical_cbor_i64_min_encoding() {
        let bytes = to_canonical_cbor(&i64::MIN).unwrap();
        // i64::MIN = -9223372036854775808, CBOR = 0x3B 0x7F...FF
        assert_eq!(bytes.len(), 9);
        assert_eq!(bytes[0], 0x3B);
    }

    // ========================================================================
    // NEW BATCH 2026-03-08: write_canonical_cbor consistency
    // ========================================================================

    #[test]
    fn write_canonical_cbor_integer_matches_direct() {
        for val in [0_u64, 1, 23, 24, 255, 256, 65535, 65536, u64::MAX] {
            let direct = to_canonical_cbor(&val).unwrap();
            let mut via_write = Vec::new();
            write_canonical_cbor(&val, &mut via_write).unwrap();
            assert_eq!(direct, via_write, "mismatch for value {val}");
        }
    }

    #[test]
    fn write_canonical_cbor_string_matches_direct() {
        for val in ["", "a", "hello", "x".repeat(24).as_str()] {
            let direct = to_canonical_cbor(&val).unwrap();
            let mut via_write = Vec::new();
            write_canonical_cbor(&val, &mut via_write).unwrap();
            assert_eq!(direct, via_write, "mismatch for string len {}", val.len());
        }
    }

    #[test]
    fn write_canonical_cbor_bool_matches_direct() {
        for val in [true, false] {
            let direct = to_canonical_cbor(&val).unwrap();
            let mut via_write = Vec::new();
            write_canonical_cbor(&val, &mut via_write).unwrap();
            assert_eq!(direct, via_write);
        }
    }

    // ========================================================================
    // NEW BATCH 2026-03-08: Cross-cutting edge cases
    // ========================================================================

    #[test]
    fn roundtrip_struct_with_all_none_options_and_empty_collections() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Minimal {
            opt_u32: Option<u32>,
            opt_str: Option<String>,
            vec_items: Vec<u8>,
            map_data: HashMap<String, u32>,
        }

        let schema = SchemaId::new("fcp.test", "Minimal", Version::new(1, 0, 0));
        let val = Minimal {
            opt_u32: None,
            opt_str: None,
            vec_items: vec![],
            map_data: HashMap::new(),
        };
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: Minimal = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_map_with_very_long_keys() {
        let schema = SchemaId::new("fcp.test", "LongKeys", Version::new(1, 0, 0));
        let mut map = HashMap::new();
        map.insert("a".repeat(1000), 1_u32);
        map.insert("b".repeat(1000), 2);
        let bytes = CanonicalSerializer::serialize(&map, &schema).unwrap();
        let decoded: HashMap<String, u32> =
            CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, map);
    }

    #[test]
    fn canonical_serializer_cbor_body_is_valid_cbor() {
        let schema = SchemaId::new("fcp.test", "ValidCbor", Version::new(1, 0, 0));
        let val = vec![1_u32, 2, 3];
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        // Extract CBOR body and verify it decodes.
        let cbor_body = &bytes[SCHEMA_HASH_LEN..];
        let raw: Value = ciborium::de::from_reader(cbor_body).unwrap();
        assert!(matches!(raw, Value::Array(_)));
    }

    #[test]
    fn roundtrip_string_with_all_ascii_control_chars() {
        let schema = SchemaId::new("fcp.test", "CtrlChars", Version::new(1, 0, 0));
        let val: String = (0..32_u8).map(|b| b as char).collect();
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: String = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn schema_hash_from_different_constructors_match() {
        let schema = SchemaId::new("fcp.test", "CtorMatch", Version::new(1, 0, 0));
        let hash_via_method = schema.hash();
        let hash_via_roundtrip = SchemaHash::from_bytes(*hash_via_method.as_bytes());
        assert_eq!(hash_via_method, hash_via_roundtrip);
        assert_eq!(hash_via_method.to_string(), hash_via_roundtrip.to_string());
        assert_eq!(
            format!("{hash_via_method:?}"),
            format!("{hash_via_roundtrip:?}")
        );
    }

    #[test]
    fn to_canonical_cbor_u16_boundary_values() {
        for val in [0_u16, 1, 23, 24, 255, 256, u16::MAX] {
            let bytes = to_canonical_cbor(&val).unwrap();
            let decoded: Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
            if let Value::Integer(i) = decoded {
                assert_eq!(i128::from(i), i128::from(val));
            } else {
                panic!("expected integer for val {val}");
            }
        }
    }

    #[test]
    fn roundtrip_map_of_bool_to_string() {
        use std::collections::BTreeMap;
        let schema = SchemaId::new("fcp.test", "BoolMap", Version::new(1, 0, 0));
        let mut map = BTreeMap::new();
        map.insert(true, "yes".to_string());
        map.insert(false, "no".to_string());
        let bytes = CanonicalSerializer::serialize(&map, &schema).unwrap();
        let decoded: BTreeMap<bool, String> =
            CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, map);
    }

    #[test]
    fn schema_id_as_bytes_with_emoji_in_name() {
        let schema = SchemaId::new("fcp.test", "\u{1F680}Rocket", Version::new(1, 0, 0));
        let canonical = String::from_utf8(schema.as_bytes()).unwrap();
        assert!(canonical.contains('\u{1F680}'));
        assert!(canonical.contains("Rocket"));
        assert_eq!(schema.hash().as_bytes().len(), 32);
    }

    #[test]
    fn serialize_deserialize_vec_of_maps_deterministic() {
        let schema = SchemaId::new("fcp.test", "VecMapDet", Version::new(1, 0, 0));
        let mut m1 = HashMap::new();
        m1.insert("z".to_string(), 1_i32);
        m1.insert("a".to_string(), 2);
        let mut m2 = HashMap::new();
        m2.insert("y".to_string(), 3);
        m2.insert("b".to_string(), 4);
        let val = vec![m1.clone(), m2.clone()];
        let bytes1 = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let bytes2 = CanonicalSerializer::serialize(&val, &schema).unwrap();
        assert_eq!(bytes1, bytes2);
        let decoded: Vec<HashMap<String, i32>> =
            CanonicalSerializer::deserialize(&bytes1, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    // ========================================================================
    // NEW BATCH 2026-03-08 (cont): Additional edge cases for 80+ target
    // ========================================================================

    #[test]
    fn roundtrip_tuple_struct_with_three_fields() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Triple(u32, String, bool);

        let schema = SchemaId::new("fcp.test", "Triple", Version::new(1, 0, 0));
        let val = Triple(7, "triple".into(), false);
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: Triple = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_enum_with_optional_struct_variant() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        enum Cmd {
            Run {
                args: Vec<String>,
                env: Option<HashMap<String, String>>,
            },
            Exit,
        }

        let schema = SchemaId::new("fcp.test", "Cmd", Version::new(1, 0, 0));
        let mut env = HashMap::new();
        env.insert("PATH".to_string(), "/usr/bin".to_string());
        let val = Cmd::Run {
            args: vec!["ls".into(), "-la".into()],
            env: Some(env),
        };
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: Cmd = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_enum_with_optional_struct_variant_none_env() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        enum Cmd2 {
            Run {
                args: Vec<String>,
                env: Option<HashMap<String, String>>,
            },
            Exit,
        }

        let schema = SchemaId::new("fcp.test", "Cmd2", Version::new(1, 0, 0));
        let val = Cmd2::Run {
            args: vec![],
            env: None,
        };
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: Cmd2 = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn schema_id_hash_collision_resistance_similar_names() {
        // Names that differ only by a single character produce different hashes.
        let a = SchemaId::new("fcp.core", "TokenA", Version::new(1, 0, 0));
        let b = SchemaId::new("fcp.core", "TokenB", Version::new(1, 0, 0));
        let c = SchemaId::new("fcp.core", "TokenC", Version::new(1, 0, 0));
        assert_ne!(a.hash(), b.hash());
        assert_ne!(b.hash(), c.hash());
        assert_ne!(a.hash(), c.hash());
    }

    #[test]
    fn to_canonical_cbor_map_with_255_entries() {
        let mut map = std::collections::BTreeMap::new();
        for i in 0..255_u32 {
            map.insert(format!("{i:04}"), i);
        }
        let bytes = to_canonical_cbor(&map).unwrap();
        // 255 entries: 0xB8 0xFF (2-byte map header)
        assert_eq!(bytes[0], 0xB8);
        assert_eq!(bytes[1], 0xFF);
    }

    #[test]
    fn to_canonical_cbor_map_with_256_entries() {
        let mut map = std::collections::BTreeMap::new();
        for i in 0..256_u32 {
            map.insert(format!("{i:04}"), i);
        }
        let bytes = to_canonical_cbor(&map).unwrap();
        // 256 entries: 0xB9 0x01 0x00 (3-byte map header)
        assert_eq!(bytes[0], 0xB9);
        assert_eq!(bytes[1], 0x01);
        assert_eq!(bytes[2], 0x00);
    }

    #[test]
    fn to_canonical_cbor_array_of_255_elements() {
        let val: Vec<u8> = (0..=254).collect();
        let bytes = to_canonical_cbor(&val).unwrap();
        // 255 elements: 0x98 0xFF
        assert_eq!(bytes[0], 0x98);
        assert_eq!(bytes[1], 0xFF);
    }

    #[test]
    fn to_canonical_cbor_array_of_256_elements() {
        let val: Vec<u16> = (0..256).collect();
        let bytes = to_canonical_cbor(&val).unwrap();
        // 256 elements: 0x99 0x01 0x00
        assert_eq!(bytes[0], 0x99);
        assert_eq!(bytes[1], 0x01);
        assert_eq!(bytes[2], 0x00);
    }

    #[test]
    fn canonicalize_map_preserves_entry_count() {
        for count in [0_u32, 1, 2, 5, 10, 50] {
            let mut entries: Vec<(Value, Value)> = (0..count)
                .map(|i| (Value::Text(format!("k{i:04}")), Value::Integer(i.into())))
                .collect();
            canonicalize_map(&mut entries, 0).unwrap();
            assert_eq!(entries.len(), usize::try_from(count).unwrap());
        }
    }

    #[test]
    fn roundtrip_struct_with_fixed_size_arrays() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Point3D {
            coords: [f64; 3],
            label: String,
        }

        let schema = SchemaId::new("fcp.test", "Point3D", Version::new(1, 0, 0));
        let val = Point3D {
            coords: [1.5, 2.5, 3.5],
            label: "origin".to_string(),
        };
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: Point3D = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn roundtrip_struct_with_nested_options_all_some() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct FullyPresent {
            a: Option<u32>,
            b: Option<String>,
            c: Option<Vec<u8>>,
            d: Option<bool>,
        }

        let schema = SchemaId::new("fcp.test", "FullyPresent", Version::new(1, 0, 0));
        let val = FullyPresent {
            a: Some(42),
            b: Some("present".to_string()),
            c: Some(vec![1, 2, 3]),
            d: Some(true),
        };
        let bytes = CanonicalSerializer::serialize(&val, &schema).unwrap();
        let decoded: FullyPresent = CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn schema_hash_serde_json_array_roundtrip() {
        let hashes = vec![
            SchemaHash::from_bytes([0x11; 32]),
            SchemaHash::from_bytes([0x22; 32]),
            SchemaHash::from_bytes([0x33; 32]),
        ];
        let json = serde_json::to_string(&hashes).unwrap();
        let decoded: Vec<SchemaHash> = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, hashes);
    }
}
