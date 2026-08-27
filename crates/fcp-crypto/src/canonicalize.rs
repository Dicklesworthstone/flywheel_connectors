//! Signature canonicalization helpers for FCP.
//!
//! Provides a single signing-bytes procedure to prevent cross-implementation drift:
//! 1. Define an "unsigned view" of an object (remove `signature`/`quorum_signatures` fields)
//! 2. Serialize using deterministic CBOR with schema-hash prefix
//! 3. For multi-signature vectors: sort lexicographically by `node_id` before hashing/signing/verifying

use crate::error::{CryptoError, CryptoResult};

/// Domain separation prefix for canonical signing.
pub const SIGNING_DOMAIN: &[u8] = b"FCP2-SIGN-V1";

/// Schema hash size for signing context.
pub const SCHEMA_HASH_SIZE: usize = 8;

/// Compute schema hash for signing context.
///
/// Uses BLAKE3 truncated to 8 bytes: `BLAKE3(schema_id)[0..8]`.
#[must_use]
pub fn schema_hash(schema_id: &str) -> [u8; SCHEMA_HASH_SIZE] {
    let hash = blake3::hash(schema_id.as_bytes());
    let mut result = [0u8; SCHEMA_HASH_SIZE];
    result.copy_from_slice(&hash.as_bytes()[..SCHEMA_HASH_SIZE]);
    result
}

/// Build canonical signing bytes for an object.
///
/// Format: `SIGNING_DOMAIN || schema_hash || cbor_bytes`
///
/// # Arguments
///
/// * `schema_id` - Schema identifier for the object type (e.g., "fcp.zone.ZoneKeyManifest/1.0.0")
/// * `cbor_bytes` - Deterministic CBOR encoding of the unsigned object
#[must_use]
pub fn canonical_signing_bytes(schema_id: &str, cbor_bytes: &[u8]) -> Vec<u8> {
    let schema = schema_hash(schema_id);
    let mut result = Vec::with_capacity(SIGNING_DOMAIN.len() + SCHEMA_HASH_SIZE + cbor_bytes.len());
    result.extend_from_slice(SIGNING_DOMAIN);
    result.extend_from_slice(&schema);
    result.extend_from_slice(cbor_bytes);
    result
}

/// Sort node signatures lexicographically by `node_id` for multi-sig verification.
///
/// Returns indices in sorted order.
#[must_use]
pub fn sort_signatures_by_node_id(node_ids: &[&[u8]]) -> Vec<usize> {
    let mut indices: Vec<usize> = (0..node_ids.len()).collect();
    indices.sort_by_key(|&i| node_ids[i]);
    indices
}

/// Verify that signatures are properly sorted by `node_id`.
///
/// # Errors
///
/// Returns an error if signatures are not in lexicographic order.
pub fn verify_signature_order(node_ids: &[&[u8]]) -> CryptoResult<()> {
    for window in node_ids.windows(2) {
        if window[0] >= window[1] {
            return Err(CryptoError::TokenValidationError(
                "signatures not sorted by `node_id`".into(),
            ));
        }
    }
    Ok(())
}

/// Encode deterministic CBOR from a serializable value.
///
/// Uses ciborium with canonical encoding rules:
/// - Map keys sorted
/// - No indefinite-length encoding
/// - Smallest integer encoding
/// - CBOR tags rejected
///
/// # Errors
///
/// Returns an error if serialization fails.
pub fn to_deterministic_cbor<T: serde::Serialize>(value: &T) -> CryptoResult<Vec<u8>> {
    to_deterministic_cbor_with_capacity(value, 0)
}

/// Same as [`to_deterministic_cbor`] but pre-allocates the output buffer.
///
/// Use when the typical serialized size is known (e.g., AAD ~128 bytes,
/// capability tokens ~256 bytes) to avoid reallocations during encoding.
///
/// # Errors
///
/// Returns `CryptoError::SerializationError` if the value cannot be serialized
/// to deterministic CBOR.
pub fn to_deterministic_cbor_with_capacity<T: serde::Serialize>(
    value: &T,
    capacity: usize,
) -> CryptoResult<Vec<u8>> {
    let mut v = ciborium::value::Value::serialized(value)
        .map_err(|e| CryptoError::SerializationError(e.to_string()))?;
    canonicalize_value_in_place(&mut v, 0)?;

    let mut bytes = Vec::with_capacity(capacity);
    ciborium::into_writer(&v, &mut bytes)
        .map_err(|e| CryptoError::SerializationError(e.to_string()))?;
    Ok(bytes)
}

const MAX_CANONICALIZATION_DEPTH: usize = 128;

fn canonicalize_value_in_place(v: &mut ciborium::value::Value, depth: usize) -> CryptoResult<()> {
    if depth > MAX_CANONICALIZATION_DEPTH {
        return Err(CryptoError::SerializationError(format!(
            "canonicalization depth {depth} exceeds limit {MAX_CANONICALIZATION_DEPTH}"
        )));
    }

    if let ciborium::value::Value::Float(f) = v {
        if f.is_nan() || f.is_infinite() {
            return Err(CryptoError::SerializationError(
                "non-finite float not allowed in canonical CBOR".into(),
            ));
        }
        // Normalize -0.0 to 0.0 (RFC 8949 §4.2.2)
        if f.to_bits() == (-0.0_f64).to_bits() {
            *f = 0.0;
        }
    }

    match v {
        ciborium::value::Value::Array(items) => {
            for item in items {
                canonicalize_value_in_place(item, depth + 1)?;
            }
        }
        ciborium::value::Value::Map(entries) => canonicalize_map(entries, depth + 1)?,
        ciborium::value::Value::Tag(tag, _) => {
            return Err(CryptoError::SerializationError(format!(
                "CBOR tag {tag} not allowed in deterministic CBOR"
            )));
        }
        _ => {}
    }
    Ok(())
}

fn canonicalize_map(
    entries: &mut Vec<(ciborium::value::Value, ciborium::value::Value)>,
    depth: usize,
) -> CryptoResult<()> {
    // br-m7aoz: arena-based sort comparator. Pre-refactor this
    // function allocated a `Vec<u8>` per map entry just to hold the
    // serialized sort key (`key_buf.clone()` per iteration); for an
    // N-entry map the encoder paid N heap allocations purely for
    // comparator inputs, recursively, on every signed-object encode
    // in the workspace. The new layout serializes all keys
    // end-to-end into a SINGLE arena Vec and sorts an index Vec by
    // borrows into the arena — zero per-entry allocations beyond
    // the index's `usize` slots.
    //
    // Wire format is unchanged: same RFC 8949 §4.2.1 bytewise
    // lexicographic key order, same duplicate-detection semantics,
    // same canonical CBOR output bytes (golden-vector tests pin
    // this).
    let n = entries.len();

    // Pass 1: canonicalize key + value in place so the arena
    // encoding below sees the canonical form for sort-key derivation.
    for (key, value) in entries.iter_mut() {
        canonicalize_value_in_place(key, depth)?;
        canonicalize_value_in_place(value, depth)?;
    }

    // Pass 2: serialize each key into the SHARED arena, recording
    // its (start, len) slice into a parallel offsets Vec. The
    // arena owns the bytes; sort-comparator borrows live as long
    // as the function.
    //
    // Pre-allocation heuristic: typical FCP map keys are small
    // (16-32 bytes for u64 / short text / 32-byte hashes). 64 B
    // per entry covers the common case without reallocation; the
    // arena Vec grows naturally for outliers.
    let mut arena: Vec<u8> = Vec::with_capacity(n.saturating_mul(64));
    let mut key_offsets: Vec<(usize, usize)> = Vec::with_capacity(n);
    for (key, _value) in entries.iter() {
        let start = arena.len();
        ciborium::into_writer(key, &mut arena)
            .map_err(|e| CryptoError::SerializationError(e.to_string()))?;
        let len = arena.len() - start;
        key_offsets.push((start, len));
    }

    // Pass 3: sort an index Vec by bytewise comparison of the
    // arena slices. RFC 8949 §4.2.1 — pure bytewise lex order over
    // the deterministic encoded keys (NOT length-then-bytewise; the
    // workspace uses §4.2.1, not §4.2.3).
    let mut sort_idx: Vec<usize> = (0..n).collect();
    sort_idx.sort_by(|&a, &b| {
        let (a_start, a_len) = key_offsets[a];
        let (b_start, b_len) = key_offsets[b];
        arena[a_start..a_start + a_len].cmp(&arena[b_start..b_start + b_len])
    });

    // Pass 4: duplicate detection. Adjacent post-sort entries with
    // byte-equal serialized keys are duplicates; the sort makes
    // duplicates collate so a single linear scan suffices.
    for w in sort_idx.windows(2) {
        let (a_start, a_len) = key_offsets[w[0]];
        let (b_start, b_len) = key_offsets[w[1]];
        if a_len == b_len && arena[a_start..a_start + a_len] == arena[b_start..b_start + b_len] {
            return Err(CryptoError::SerializationError(format!(
                "duplicate map key: {}",
                hex::encode(&arena[a_start..a_start + a_len])
            )));
        }
    }

    // Pass 5: apply the permutation to `entries`. Take the original
    // out, wrap each slot in `Option`, then build the new Vec by
    // indexing through `sort_idx`. The Option dance avoids needing
    // `Clone` on the (Value, Value) pairs and is allocation-cheap
    // (one Vec per call vs the per-entry clones the pre-refactor
    // design did).
    let mut taken: Vec<Option<(ciborium::value::Value, ciborium::value::Value)>> =
        std::mem::take(entries).into_iter().map(Some).collect();
    let mut sorted = Vec::with_capacity(n);
    for &i in &sort_idx {
        sorted.push(
            taken[i]
                .take()
                .expect("each entry index appears exactly once in the permutation"),
        );
    }
    *entries = sorted;

    Ok(())
}

/// Object that can be canonically signed.
///
/// Implementors must provide:
/// 1. Schema ID for domain separation
/// 2. Unsigned view (without signature fields)
/// 3. Deterministic CBOR serialization
pub trait Signable {
    /// Get the schema ID for this object type.
    fn schema_id(&self) -> &str;

    /// Get the canonical CBOR bytes for signing (unsigned view).
    ///
    /// This should exclude any signature-related fields.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    fn unsigned_cbor(&self) -> CryptoResult<Vec<u8>>;

    /// Get the full signing bytes with domain separation.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    fn signing_bytes(&self) -> CryptoResult<Vec<u8>> {
        let cbor = self.unsigned_cbor()?;
        Ok(canonical_signing_bytes(self.schema_id(), &cbor))
    }
}

/// Multi-signature entry with `node_id` ordering.
#[derive(Clone, Debug)]
pub struct NodeSignature {
    /// Node identifier (for sorting).
    pub node_id: Vec<u8>,
    /// Ed25519 signature bytes.
    pub signature: Vec<u8>,
}

impl NodeSignature {
    /// Create a new node signature.
    #[must_use]
    pub const fn new(node_id: Vec<u8>, signature: Vec<u8>) -> Self {
        Self { node_id, signature }
    }
}

/// Sort a vector of node signatures by `node_id`.
pub fn sort_node_signatures(signatures: &mut [NodeSignature]) {
    signatures.sort_by(|a, b| a.node_id.cmp(&b.node_id));
}

/// Verify that node signatures are properly sorted.
///
/// # Errors
///
/// Returns an error if not sorted lexicographically by `node_id`.
pub fn verify_node_signature_order(signatures: &[NodeSignature]) -> CryptoResult<()> {
    for window in signatures.windows(2) {
        if window[0].node_id >= window[1].node_id {
            return Err(CryptoError::TokenValidationError(
                "node signatures not sorted by node_id".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_hash_deterministic() {
        let hash1 = schema_hash("fcp.zone.ZoneKeyManifest/1.0.0");
        let hash2 = schema_hash("fcp.zone.ZoneKeyManifest/1.0.0");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn schema_hash_different_schemas() {
        let hash1 = schema_hash("fcp.zone.ZoneKeyManifest/1.0.0");
        let hash2 = schema_hash("fcp.zone.ZoneDefinition/1.0.0");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn canonical_signing_bytes_format() {
        let cbor = b"test-cbor-bytes";
        let schema = "test.schema/1.0.0";

        let signing_bytes = canonical_signing_bytes(schema, cbor);

        assert!(signing_bytes.starts_with(SIGNING_DOMAIN));
        assert!(signing_bytes.ends_with(cbor));
        assert_eq!(
            signing_bytes.len(),
            SIGNING_DOMAIN.len() + SCHEMA_HASH_SIZE + cbor.len()
        );
    }

    #[test]
    fn sort_signatures() {
        let ids: Vec<&[u8]> = vec![b"charlie", b"alice", b"bob"];
        let sorted = sort_signatures_by_node_id(&ids);
        assert_eq!(sorted, vec![1, 2, 0]); // alice, bob, charlie
    }

    #[test]
    fn verify_signature_order_valid() {
        let ids: Vec<&[u8]> = vec![b"alice", b"bob", b"charlie"];
        assert!(verify_signature_order(&ids).is_ok());
    }

    #[test]
    fn verify_signature_order_invalid() {
        let ids: Vec<&[u8]> = vec![b"bob", b"alice", b"charlie"];
        assert!(verify_signature_order(&ids).is_err());
    }

    #[test]
    fn verify_signature_order_duplicate() {
        let ids: Vec<&[u8]> = vec![b"alice", b"alice"];
        assert!(verify_signature_order(&ids).is_err());
    }

    #[test]
    fn node_signature_sorting() {
        let mut sigs = vec![
            NodeSignature::new(b"charlie".to_vec(), vec![1]),
            NodeSignature::new(b"alice".to_vec(), vec![2]),
            NodeSignature::new(b"bob".to_vec(), vec![3]),
        ];

        sort_node_signatures(&mut sigs);

        assert_eq!(sigs[0].node_id, b"alice");
        assert_eq!(sigs[1].node_id, b"bob");
        assert_eq!(sigs[2].node_id, b"charlie");
    }

    #[test]
    fn deterministic_cbor() {
        use std::collections::BTreeMap;

        let mut map1 = BTreeMap::new();
        map1.insert("z", 1);
        map1.insert("a", 2);

        let mut map2 = BTreeMap::new();
        map2.insert("a", 2);
        map2.insert("z", 1);

        let cbor1 = to_deterministic_cbor(&map1).unwrap();
        let cbor2 = to_deterministic_cbor(&map2).unwrap();

        // BTreeMap guarantees same order regardless of insertion
        assert_eq!(cbor1, cbor2);
    }

    #[test]
    fn schema_hash_golden_vector() {
        let hash = schema_hash("fcp.core.CapabilityObject/1.0.0");
        // First 8 bytes of BLAKE3("fcp.core.CapabilityObject/1.0.0")
        assert_eq!(hex::encode(hash), "28cb6f0e02d0c489");
    }

    #[test]
    fn schema_hash_is_8_bytes() {
        let hash = schema_hash("test");
        assert_eq!(hash.len(), SCHEMA_HASH_SIZE);
    }

    #[test]
    fn schema_hash_empty_string() {
        let hash = schema_hash("");
        assert_eq!(hash.len(), SCHEMA_HASH_SIZE);
        // Should still produce deterministic output
        assert_eq!(hash, schema_hash(""));
    }

    #[test]
    fn canonical_signing_bytes_deterministic() {
        let bytes1 = canonical_signing_bytes("schema", b"cbor");
        let bytes2 = canonical_signing_bytes("schema", b"cbor");
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn canonical_signing_bytes_different_schemas() {
        let bytes1 = canonical_signing_bytes("schema1", b"cbor");
        let bytes2 = canonical_signing_bytes("schema2", b"cbor");
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn canonical_signing_bytes_different_cbor() {
        let bytes1 = canonical_signing_bytes("schema", b"cbor1");
        let bytes2 = canonical_signing_bytes("schema", b"cbor2");
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn canonical_signing_bytes_empty_cbor() {
        let bytes = canonical_signing_bytes("schema", b"");
        assert_eq!(bytes.len(), SIGNING_DOMAIN.len() + SCHEMA_HASH_SIZE);
    }

    #[test]
    fn sort_signatures_empty() {
        let ids: Vec<&[u8]> = vec![];
        let sorted = sort_signatures_by_node_id(&ids);
        assert_eq!(sorted, [] as [usize; 0]);
    }

    #[test]
    fn sort_signatures_single() {
        let ids: Vec<&[u8]> = vec![b"only"];
        let sorted = sort_signatures_by_node_id(&ids);
        assert_eq!(sorted, vec![0]);
    }

    #[test]
    fn verify_signature_order_empty() {
        let ids: Vec<&[u8]> = vec![];
        assert!(verify_signature_order(&ids).is_ok());
    }

    #[test]
    fn verify_signature_order_single() {
        let ids: Vec<&[u8]> = vec![b"only"];
        assert!(verify_signature_order(&ids).is_ok());
    }

    #[test]
    fn verify_node_signature_order_valid() {
        let sigs = vec![
            NodeSignature::new(b"alice".to_vec(), vec![1]),
            NodeSignature::new(b"bob".to_vec(), vec![2]),
        ];
        assert!(verify_node_signature_order(&sigs).is_ok());
    }

    #[test]
    fn verify_node_signature_order_invalid() {
        let sigs = vec![
            NodeSignature::new(b"bob".to_vec(), vec![1]),
            NodeSignature::new(b"alice".to_vec(), vec![2]),
        ];
        assert!(verify_node_signature_order(&sigs).is_err());
    }

    #[test]
    fn verify_node_signature_order_duplicate() {
        let sigs = vec![
            NodeSignature::new(b"alice".to_vec(), vec![1]),
            NodeSignature::new(b"alice".to_vec(), vec![2]),
        ];
        assert!(verify_node_signature_order(&sigs).is_err());
    }

    #[test]
    fn deterministic_cbor_hashmap_order_independent() {
        use std::collections::HashMap;

        let mut map_a = HashMap::new();
        map_a.insert("x", 1);
        map_a.insert("y", 2);

        let mut map_b = HashMap::new();
        map_b.insert("y", 2);
        map_b.insert("x", 1);

        let cbor_a = to_deterministic_cbor(&map_a).unwrap();
        let cbor_b = to_deterministic_cbor(&map_b).unwrap();
        assert_eq!(cbor_a, cbor_b);
    }

    #[test]
    fn deterministic_cbor_nested_map() {
        use std::collections::HashMap;
        let mut inner = HashMap::new();
        inner.insert("b", 2);
        inner.insert("a", 1);

        let mut outer = HashMap::new();
        outer.insert("inner", inner);

        let cbor1 = to_deterministic_cbor(&outer).unwrap();
        let cbor2 = to_deterministic_cbor(&outer).unwrap();
        assert_eq!(cbor1, cbor2);
    }

    #[test]
    fn node_signature_clone() {
        let sig = NodeSignature::new(b"node".to_vec(), vec![1, 2, 3]);
        let cloned = sig.clone();
        assert_eq!(cloned.node_id, sig.node_id);
        assert_eq!(cloned.signature, sig.signature);
    }

    // ---- Signing domain constant ----

    #[test]
    fn signing_domain_value() {
        assert_eq!(SIGNING_DOMAIN, b"FCP2-SIGN-V1");
    }

    #[test]
    fn schema_hash_size_value() {
        assert_eq!(SCHEMA_HASH_SIZE, 8);
    }

    // ---- Signable trait default impl ----

    #[test]
    fn signable_trait_signing_bytes() {
        struct TestSignable;
        impl Signable for TestSignable {
            fn schema_id(&self) -> &'static str {
                "test.schema/1.0.0"
            }
            fn unsigned_cbor(&self) -> CryptoResult<Vec<u8>> {
                Ok(b"test-payload".to_vec())
            }
        }

        let s = TestSignable;
        let signing_bytes = s.signing_bytes().unwrap();
        let expected = canonical_signing_bytes("test.schema/1.0.0", b"test-payload");
        assert_eq!(signing_bytes, expected);
    }

    // ---- NodeSignature debug ----

    #[test]
    fn node_signature_debug() {
        let sig = NodeSignature::new(b"node-1".to_vec(), vec![0xAA, 0xBB]);
        let debug = format!("{sig:?}");
        assert!(debug.contains("NodeSignature"));
        assert!(debug.contains("node_id"));
    }

    // ---- Deterministic CBOR with arrays ----

    #[test]
    fn deterministic_cbor_array() {
        let arr = vec![1u32, 2, 3, 4, 5];
        let cbor1 = to_deterministic_cbor(&arr).unwrap();
        let cbor2 = to_deterministic_cbor(&arr).unwrap();
        assert_eq!(cbor1, cbor2);
    }

    #[test]
    fn deterministic_cbor_string() {
        let s = "hello world";
        let cbor = to_deterministic_cbor(&s).unwrap();
        assert_ne!(cbor, [] as [u8; 0]);
    }

    #[test]
    fn deterministic_cbor_bool() {
        let cbor_true = to_deterministic_cbor(&true).unwrap();
        let cbor_false = to_deterministic_cbor(&false).unwrap();
        assert_ne!(cbor_true, cbor_false);
    }

    // ---- Sort node signatures with single element ----

    #[test]
    fn sort_node_signatures_single() {
        let mut sigs = vec![NodeSignature::new(b"only".to_vec(), vec![1])];
        sort_node_signatures(&mut sigs);
        assert_eq!(sigs[0].node_id, b"only");
    }

    #[test]
    fn sort_node_signatures_empty() {
        let mut sigs: Vec<NodeSignature> = vec![];
        sort_node_signatures(&mut sigs);
        assert!(sigs.is_empty());
    }

    // ---- Verify node signature order edge cases ----

    #[test]
    fn verify_node_signature_order_empty() {
        let sigs: Vec<NodeSignature> = vec![];
        assert!(verify_node_signature_order(&sigs).is_ok());
    }

    #[test]
    fn verify_node_signature_order_single() {
        let sigs = vec![NodeSignature::new(b"only".to_vec(), vec![1])];
        assert!(verify_node_signature_order(&sigs).is_ok());
    }

    // ---- Deterministic CBOR with integers ----

    #[test]
    fn deterministic_cbor_integer() {
        let cbor = to_deterministic_cbor(&42u64).unwrap();
        assert_ne!(cbor, [] as [u8; 0]);
        let cbor2 = to_deterministic_cbor(&42u64).unwrap();
        assert_eq!(cbor, cbor2);
    }

    // ---- Deterministic CBOR with null/optional ----

    #[test]
    fn deterministic_cbor_option_none() {
        let val: Option<u32> = None;
        let cbor = to_deterministic_cbor(&val).unwrap();
        assert_ne!(cbor, [] as [u8; 0]);
    }

    #[test]
    fn deterministic_cbor_option_some() {
        let val: Option<u32> = Some(42);
        let cbor = to_deterministic_cbor(&val).unwrap();
        assert_ne!(cbor, [] as [u8; 0]);
    }

    // ---- Schema hash with long input ----

    #[test]
    fn schema_hash_long_input() {
        let long_schema = "a".repeat(10_000);
        let hash = schema_hash(&long_schema);
        assert_eq!(hash.len(), SCHEMA_HASH_SIZE);
        // Deterministic
        assert_eq!(hash, schema_hash(&long_schema));
    }

    // ---- Schema hash with unicode ----

    #[test]
    fn schema_hash_unicode() {
        let hash = schema_hash("schéma.réseau/1.0.0");
        assert_eq!(hash.len(), SCHEMA_HASH_SIZE);
        // Different from ASCII variant
        let hash2 = schema_hash("schema.reseau/1.0.0");
        assert_ne!(hash, hash2);
    }

    // ---- Sort signatures with ties ----

    #[test]
    fn sort_signatures_already_sorted() {
        let ids: Vec<&[u8]> = vec![b"a", b"b", b"c"];
        let sorted = sort_signatures_by_node_id(&ids);
        assert_eq!(sorted, vec![0, 1, 2]);
    }

    #[test]
    fn sort_signatures_reverse_order() {
        let ids: Vec<&[u8]> = vec![b"c", b"b", b"a"];
        let sorted = sort_signatures_by_node_id(&ids);
        assert_eq!(sorted, vec![2, 1, 0]);
    }

    // ---- NodeSignature new const ----

    #[test]
    fn node_signature_new_preserves_fields() {
        let sig = NodeSignature::new(b"node-id".to_vec(), vec![0xAA, 0xBB, 0xCC]);
        assert_eq!(sig.node_id, b"node-id");
        assert_eq!(sig.signature, vec![0xAA, 0xBB, 0xCC]);
    }

    // ---- Verify signature order error message ----

    #[test]
    fn verify_signature_order_error_message() {
        let ids: Vec<&[u8]> = vec![b"z", b"a"];
        let err = verify_signature_order(&ids).unwrap_err();
        assert!(err.to_string().contains("not sorted"));
    }

    #[test]
    fn verify_node_signature_order_error_message() {
        let sigs = vec![
            NodeSignature::new(b"z".to_vec(), vec![1]),
            NodeSignature::new(b"a".to_vec(), vec![2]),
        ];
        let err = verify_node_signature_order(&sigs).unwrap_err();
        assert!(err.to_string().contains("not sorted"));
    }

    // ---- Canonical signing bytes with large CBOR ----

    #[test]
    fn canonical_signing_bytes_large_cbor() {
        let large_cbor = vec![0xAB; 100_000];
        let bytes = canonical_signing_bytes("big.schema/1.0.0", &large_cbor);
        assert_eq!(
            bytes.len(),
            SIGNING_DOMAIN.len() + SCHEMA_HASH_SIZE + 100_000
        );
        assert!(bytes.starts_with(SIGNING_DOMAIN));
        assert!(bytes.ends_with(&large_cbor));
    }

    #[test]
    fn deterministic_cbor_sort_order_rfc8949() {
        use std::collections::HashMap;
        // In RFC 7049 (length-first), "aa" (length 2) comes after "z" (length 1).
        // In RFC 8949 (bytewise lexicographic), "aa" comes BEFORE "z".
        // encoded "aa" is 0x62 0x61 0x61
        // encoded "z"  is 0x61 0x7a
        // 0x61 < 0x62, so "z" actually comes first in bytewise lexicographic too?
        // Wait.
        // "z" is 0x61 0x7a
        // "aa" is 0x62 0x61 0x61
        // Yes, 0x61 < 0x62.

        // Let's find keys where length-first and bytewise-lexicographic differ.
        // RFC 7049: shorter keys first.
        // RFC 8949: bytewise comparison of encoded bytes.

        // Key A: 100 (encoded: 0x18 0x64) - length 2
        // Key B: -1 (encoded: 0x20) - length 1

        // RFC 7049: B then A (1 < 2)
        // RFC 8949: A then B (0x18 < 0x20)

        let mut map = HashMap::new();
        map.insert(100i32, "a");
        map.insert(-1i32, "b");

        let cbor = to_deterministic_cbor(&map).unwrap();
        // Expected order (RFC 8949): 100 then -1
        // 100 encoded: 18 64
        // -1 encoded: 20
        // Total map: bf 18 64 ... 20 ... ff (if indefinite)
        // Or definite: a2 18 64 ... 20 ...

        assert_eq!(cbor[0], 0xa2); // Map of 2
        assert_eq!(cbor[1], 0x18); // First key 100
        assert_eq!(cbor[2], 0x64);
    }

    #[test]
    fn deterministic_cbor_depth_limit() {
        use ciborium::value::Value;
        let mut root = Value::Array(vec![]);
        for _ in 0..150 {
            root = Value::Array(vec![root]);
        }
        let err = to_deterministic_cbor(&root).unwrap_err();
        assert!(err.to_string().contains("depth"));
    }

    #[test]
    fn deterministic_cbor_rejects_nan() {
        let val = f64::NAN;
        let err = to_deterministic_cbor(&val).unwrap_err();
        assert!(err.to_string().contains("non-finite float"));
    }

    #[test]
    fn deterministic_cbor_rejects_tags() {
        use ciborium::value::Value;

        let tagged = Value::Tag(42, Box::new(Value::Text("payload".into())));
        let err = to_deterministic_cbor(&tagged).unwrap_err();
        assert!(err.to_string().contains("CBOR tag 42"));
    }
}
