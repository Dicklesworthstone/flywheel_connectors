//! Regression tests for existing reconstruction entry points.

use fcp_raptorq::{ChunkError, ChunkedObjectManifest, RawChunk};

#[test]
fn checked_reconstruction_binds_each_manifest_id_not_just_the_payload_hash() {
    let (mut manifest, chunks) = ChunkedObjectManifest::from_payload(b"abcdef", 2);
    manifest.chunks.swap(0, 1);
    assert_eq!(manifest.reconstruct(&chunks), Err(ChunkError::HashMismatch));
}

#[test]
fn neither_entry_point_accepts_shifted_boundaries_with_the_same_total_length() {
    let (manifest, _) = ChunkedObjectManifest::from_payload(b"abcdef", 2);
    let chunks = [
        RawChunk::new(b"a".to_vec()),
        RawChunk::new(b"bcd".to_vec()),
        RawChunk::new(b"ef".to_vec()),
    ];
    assert!(matches!(
        manifest.reconstruct(&chunks),
        Err(ChunkError::LengthMismatch { .. })
    ));
    assert!(matches!(
        manifest.reconstruct_unchecked(&chunks),
        Err(ChunkError::LengthMismatch { .. })
    ));
}

#[test]
fn deserialized_geometry_cannot_bypass_either_reconstruction_entry_point() {
    let (manifest, chunks) = ChunkedObjectManifest::from_payload(b"abcdef", 2);
    for chunk_size in [0, 1, 4, u32::MAX] {
        let mut encoded = serde_json::to_value(&manifest).unwrap();
        encoded["chunk_size"] = serde_json::json!(chunk_size);
        let invalid: ChunkedObjectManifest = serde_json::from_value(encoded).unwrap();
        assert!(invalid.reconstruct(&chunks).is_err());
        assert!(invalid.reconstruct_unchecked(&chunks).is_err());
        assert!(invalid.chunk_size_at(0).is_err());
    }
}

#[test]
fn final_chunk_size_uses_u64_arithmetic_before_narrowing() {
    // Two chunks describe >4 GiB without allocating any payload. The final
    // length must be 10 on 32-bit as well as 64-bit targets.
    let (mut manifest, _) = ChunkedObjectManifest::from_payload(b"ab", 1);
    manifest.chunk_size = u32::MAX;
    manifest.total_len = u64::from(u32::MAX) + 10;
    assert_eq!(manifest.chunk_size_at(0).unwrap(), u32::MAX as usize);
    assert_eq!(manifest.chunk_size_at(1).unwrap(), 10);
}

#[test]
fn payload_hash_verification_also_binds_the_declared_length() {
    let (mut manifest, _) = ChunkedObjectManifest::from_payload(b"abcdef", 2);
    manifest.total_len += 1;
    assert!(!manifest.verify_hash(b"abcdef"));
}

#[test]
fn unchecked_still_skips_hashing_but_checked_reconstruction_fails_closed() {
    let (manifest, mut chunks) = ChunkedObjectManifest::from_payload(b"abcdef", 2);
    chunks[0].bytes[0] ^= 1;
    assert!(manifest.reconstruct_unchecked(&chunks).is_ok());
    assert_eq!(manifest.reconstruct(&chunks), Err(ChunkError::HashMismatch));
}

#[test]
fn repeated_content_is_not_mistaken_for_an_invalid_duplicate() {
    let (manifest, chunks) = ChunkedObjectManifest::from_payload(b"ababab", 2);
    assert_eq!(manifest.reconstruct(&chunks).unwrap(), b"ababab");
    assert_eq!(manifest.reconstruct_unchecked(&chunks).unwrap(), b"ababab");
}

#[test]
fn count_and_total_length_errors_keep_their_existing_precedence() {
    let (mut manifest, chunks) = ChunkedObjectManifest::from_payload(b"abcdef", 2);
    manifest.total_len += 1;
    assert!(matches!(
        manifest.reconstruct(&chunks),
        Err(ChunkError::LengthMismatch { expected: 7, got: 6 })
    ));
    assert!(matches!(
        manifest.reconstruct_unchecked(&chunks),
        Err(ChunkError::LengthMismatch { expected: 7, got: 6 })
    ));
    assert!(matches!(
        manifest.reconstruct(&chunks[..2]),
        Err(ChunkError::MissingChunks { expected: 3, got: 2 })
    ));
}

#[test]
fn a_valid_full_payload_hash_does_not_authorize_an_extra_empty_chunk() {
    let (mut manifest, mut chunks) = ChunkedObjectManifest::from_payload(b"ab", 2);
    let empty = RawChunk::new(Vec::new());
    manifest.chunks.push(empty.content_id());
    chunks.push(empty);
    assert!(manifest.reconstruct(&chunks).is_err());
    assert!(manifest.reconstruct_unchecked(&chunks).is_err());
}
