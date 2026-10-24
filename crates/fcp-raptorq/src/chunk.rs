//! Chunked object manifest and raw chunk types (NORMATIVE).
//!
//! Large objects above `max_chunk_threshold` MUST be represented as a manifest
//! referencing ordered `RawChunk` objects.

// Allow truncation casts - object sizes are bounded and these are capacity hints
#![allow(clippy::cast_possible_truncation)]

use fcp_prelude::ObjectId;
use serde::{Deserialize, Serialize};

use crate::error::ChunkError;

/// Chunked object manifest (NORMATIVE for objects above `max_chunk_threshold`).
///
/// Enables:
/// - Partial retrieval (fetch chunks on demand)
/// - Targeted repair (repair one chunk, not whole object)
/// - Bounded memory reconstruction
/// - Chunk-level deduplication
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkedObjectManifest {
    /// Total byte length of the original payload.
    pub total_len: u64,
    /// Chunk size in bytes (except possibly last chunk).
    pub chunk_size: u32,
    /// Ordered chunk object IDs (each chunk is a normal `StoredObject`).
    pub chunks: Vec<ObjectId>,
    /// BLAKE3 hash of the full payload for end-to-end verification.
    pub payload_hash: [u8; 32],
}

impl ChunkedObjectManifest {
    /// Create a manifest from a large payload.
    ///
    /// Returns the manifest and the raw chunks that should be stored separately.
    /// # Panics
    ///
    /// Panics if `chunk_size` is zero.
    #[must_use]
    pub fn from_payload(payload: &[u8], chunk_size: u32) -> (Self, Vec<RawChunk>) {
        assert!(chunk_size > 0, "chunk_size must be non-zero");
        let payload_hash = *blake3::hash(payload).as_bytes();
        let chunk_count = payload.len().div_ceil(chunk_size as usize);
        let mut chunks = Vec::with_capacity(chunk_count);
        let mut chunk_ids = Vec::with_capacity(chunk_count);

        for chunk_data in payload.chunks(chunk_size as usize) {
            let chunk = RawChunk::new(chunk_data.to_vec());
            chunk_ids.push(chunk.content_id());
            chunks.push(chunk);
        }

        let manifest = Self {
            total_len: payload.len() as u64,
            chunk_size,
            chunks: chunk_ids,
            payload_hash,
        };

        (manifest, chunks)
    }

    /// Reconstruct the payload after validating geometry and both hash layers.
    ///
    /// Every chunk must match its declared position, size and content ID. The
    /// full-payload hash is checked before allocating the output buffer. For
    /// bounded-memory output, use [`Self::start_reconstruction`] instead.
    ///
    /// # Errors
    ///
    /// Returns `ChunkError` for inconsistent geometry, wrong chunk count or
    /// length, a mismatched chunk ID, or a mismatched full-payload hash.
    pub fn reconstruct(&self, chunks: &[RawChunk]) -> Result<Vec<u8>, ChunkError> {
        let capacity = self.validate_chunks(chunks)?;
        let mut hasher = blake3::Hasher::new();
        for (index, chunk) in chunks.iter().enumerate() {
            self.verify_chunk(index, chunk)?;
            hasher.update(&chunk.bytes);
        }
        if hasher.finalize().as_bytes() != &self.payload_hash {
            return Err(ChunkError::HashMismatch);
        }

        let mut payload = Vec::with_capacity(capacity);
        for chunk in chunks {
            payload.extend_from_slice(&chunk.bytes);
        }
        Ok(payload)
    }

    /// Reconstruct the payload from chunks without hash verification.
    ///
    /// Use this only when you've already verified individual chunk hashes.
    /// Manifest geometry and individual chunk lengths are still checked; this
    /// method deliberately skips both content-ID and full-payload hashing.
    ///
    /// # Errors
    ///
    /// Returns `ChunkError` for invalid geometry, chunk count or chunk length.
    pub fn reconstruct_unchecked(&self, chunks: &[RawChunk]) -> Result<Vec<u8>, ChunkError> {
        let capacity = self.validate_chunks(chunks)?;
        let mut payload = Vec::with_capacity(capacity);
        for chunk in chunks {
            payload.extend_from_slice(&chunk.bytes);
        }
        Ok(payload)
    }

    // Preserve count/total-length error precedence for existing callers while
    // rejecting malformed boundaries before allocation in both entry points.
    fn validate_chunks(&self, chunks: &[RawChunk]) -> Result<usize, ChunkError> {
        if chunks.len() != self.chunks.len() {
            return Err(ChunkError::MissingChunks {
                expected: self.chunks.len(),
                got: chunks.len(),
            });
        }
        let actual_len = chunks
            .iter()
            .try_fold(0_u64, |total, chunk| total.checked_add(chunk.len() as u64))
            .ok_or(ChunkError::LengthMismatch {
                expected: self.total_len,
                got: u64::MAX,
            })?;
        if actual_len != self.total_len {
            return Err(ChunkError::LengthMismatch {
                expected: self.total_len,
                got: actual_len,
            });
        }
        self.validate_layout()?;
        for (index, chunk) in chunks.iter().enumerate() {
            self.validate_chunk_length(index, chunk.len())?;
        }
        usize::try_from(actual_len).map_err(|_| ChunkError::LengthMismatch {
            expected: self.total_len,
            got: actual_len,
        })
    }

    /// Number of chunks in the manifest.
    #[must_use]
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }

    /// Get the expected size of a specific chunk.
    ///
    /// # Errors
    ///
    /// Returns `ChunkError::InvalidChunkIndex` if index is out of bounds, or
    /// an error if the manifest's size and chunk count are inconsistent.
    pub fn chunk_size_at(&self, index: usize) -> Result<usize, ChunkError> {
        if index >= self.chunks.len() {
            return Err(ChunkError::InvalidChunkIndex {
                index,
                count: self.chunks.len(),
            });
        }
        self.validate_layout()?;

        // Compute the remainder before narrowing: total_len can exceed usize
        // on 32-bit targets even though each individual chunk fits in memory.
        let remaining = self.total_len % u64::from(self.chunk_size);
        let size = if index == self.chunks.len() - 1 && remaining != 0 {
            remaining
        } else {
            u64::from(self.chunk_size)
        };
        usize::try_from(size).map_err(|_| ChunkError::InvalidChunkSize)
    }

    /// Verify the payload's declared length and full-payload hash match.
    #[must_use]
    pub fn verify_hash(&self, payload: &[u8]) -> bool {
        u64::try_from(payload.len()).ok() == Some(self.total_len)
            && blake3::hash(payload).as_bytes() == &self.payload_hash
    }
}

/// A chunk is a raw bytes container (NORMATIVE).
///
/// Chunks are stored as normal objects and referenced by their content-addressed ID.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawChunk {
    /// The raw bytes of this chunk.
    pub bytes: Vec<u8>,
}

impl RawChunk {
    /// Create a new raw chunk.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Derive a content-addressed ID for this chunk.
    ///
    /// Uses unscoped `ObjectId` since chunks are referenced by content hash.
    #[must_use]
    pub fn content_id(&self) -> ObjectId {
        ObjectId::from_unscoped_bytes(&self.bytes)
    }

    /// Get the length of this chunk in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if this chunk is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_chunk_creation() {
        let data = vec![1, 2, 3, 4, 5];
        let chunk = RawChunk::new(data.clone());
        assert_eq!(chunk.bytes, data);
        assert_eq!(chunk.len(), 5);
        assert!(!chunk.is_empty());
    }

    #[test]
    fn raw_chunk_empty() {
        let chunk = RawChunk::new(vec![]);
        assert!(chunk.is_empty());
        assert_eq!(chunk.len(), 0);
    }

    #[test]
    fn raw_chunk_content_id_deterministic() {
        let data = vec![1, 2, 3, 4, 5];
        let chunk1 = RawChunk::new(data.clone());
        let chunk2 = RawChunk::new(data);
        assert_eq!(chunk1.content_id(), chunk2.content_id());
    }

    #[test]
    fn raw_chunk_content_id_differs_by_content() {
        let chunk1 = RawChunk::new(vec![1, 2, 3]);
        let chunk2 = RawChunk::new(vec![4, 5, 6]);
        assert_ne!(chunk1.content_id(), chunk2.content_id());
    }

    #[test]
    fn chunk_size_at_rejects_zero_chunk_size_without_panic() {
        // Regression: `ChunkedObjectManifest` is `Deserialize`, so a peer
        // can ship `chunk_size: 0` even though `from_payload` asserts
        // non-zero. `chunk_size_at(last_index)` previously computed
        // `total_len % chunk_size`, which panics with attempt-to-divide-by-zero
        // for the last chunk. Must return `InvalidChunkSize` instead.
        let payload_hash = *blake3::hash(b"forged").as_bytes();
        let manifest = ChunkedObjectManifest {
            total_len: 1024,
            chunk_size: 0,
            chunks: vec![ObjectId::from_unscoped_bytes(b"a")],
            payload_hash,
        };

        // Last chunk: would otherwise panic on `1024 % 0`.
        assert_eq!(
            manifest.chunk_size_at(0).unwrap_err(),
            ChunkError::InvalidChunkSize
        );

        // Multi-chunk manifest with chunk_size: 0 — non-last chunks must
        // also error rather than returning a misleading `0`.
        let multi = ChunkedObjectManifest {
            total_len: 1024,
            chunk_size: 0,
            chunks: vec![
                ObjectId::from_unscoped_bytes(b"a"),
                ObjectId::from_unscoped_bytes(b"b"),
            ],
            payload_hash,
        };
        assert_eq!(
            multi.chunk_size_at(0).unwrap_err(),
            ChunkError::InvalidChunkSize
        );
        assert_eq!(
            multi.chunk_size_at(1).unwrap_err(),
            ChunkError::InvalidChunkSize
        );

        // Out-of-bounds index still wins over chunk_size check.
        assert!(matches!(
            multi.chunk_size_at(99).unwrap_err(),
            ChunkError::InvalidChunkIndex {
                index: 99,
                count: 2
            }
        ));
    }

    #[test]
    fn manifest_from_payload_single_chunk() {
        let payload = vec![0u8; 1000]; // 1000 bytes
        let (manifest, chunks) = ChunkedObjectManifest::from_payload(&payload, 64 * 1024);

        assert_eq!(manifest.total_len, 1000);
        assert_eq!(manifest.chunk_size, 64 * 1024);
        assert_eq!(manifest.chunk_count(), 1);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].bytes, payload);
    }

    #[test]
    fn manifest_from_payload_multiple_chunks() {
        let payload = vec![42u8; 200_000]; // 200KB
        let chunk_size = 64 * 1024; // 64KB chunks
        let (manifest, chunks) = ChunkedObjectManifest::from_payload(&payload, chunk_size);

        assert_eq!(manifest.total_len, 200_000);
        // 200KB / 64KB = 3.125 -> 4 chunks
        assert_eq!(manifest.chunk_count(), 4);
        assert_eq!(chunks.len(), 4);

        // First 3 chunks are full size
        assert_eq!(chunks[0].len(), 64 * 1024);
        assert_eq!(chunks[1].len(), 64 * 1024);
        assert_eq!(chunks[2].len(), 64 * 1024);
        // Last chunk is the remainder
        assert_eq!(chunks[3].len(), 200_000 - 3 * 64 * 1024);
    }

    #[test]
    fn manifest_reconstruct_success() {
        let payload: Vec<u8> = (0..200_000_u32).map(|i| (i % 256) as u8).collect();
        let (manifest, chunks) = ChunkedObjectManifest::from_payload(&payload, 64 * 1024);

        let reconstructed = manifest.reconstruct(&chunks).unwrap();
        assert_eq!(reconstructed, payload);
    }

    #[test]
    fn manifest_reconstruct_missing_chunks() {
        let payload = vec![1u8; 200_000];
        let (manifest, mut chunks) = ChunkedObjectManifest::from_payload(&payload, 64 * 1024);

        // Remove one chunk
        chunks.pop();

        let result = manifest.reconstruct(&chunks);
        assert!(matches!(result, Err(ChunkError::MissingChunks { .. })));
    }

    #[test]
    fn manifest_reconstruct_hash_mismatch() {
        let payload = vec![1u8; 200_000];
        let (manifest, mut chunks) = ChunkedObjectManifest::from_payload(&payload, 64 * 1024);

        // Corrupt one chunk
        chunks[0].bytes[0] = 255;

        let result = manifest.reconstruct(&chunks);
        assert!(matches!(result, Err(ChunkError::HashMismatch)));
    }

    #[test]
    fn manifest_reconstruct_unchecked() {
        let payload = vec![1u8; 200_000];
        let (manifest, mut chunks) = ChunkedObjectManifest::from_payload(&payload, 64 * 1024);

        // Corrupt one chunk - unchecked won't catch this
        chunks[0].bytes[0] = 255;

        // unchecked should succeed even with corruption
        let result = manifest.reconstruct_unchecked(&chunks);
        assert!(result.is_ok());
        // But hash verification should fail
        assert!(!manifest.verify_hash(&result.unwrap()));
    }

    #[test]
    fn manifest_chunk_size_at() {
        let payload = vec![42u8; 200_000];
        let chunk_size = 64 * 1024;
        let (manifest, _) = ChunkedObjectManifest::from_payload(&payload, chunk_size);

        // First chunks are full size
        assert_eq!(manifest.chunk_size_at(0).unwrap(), 64 * 1024);
        assert_eq!(manifest.chunk_size_at(1).unwrap(), 64 * 1024);
        assert_eq!(manifest.chunk_size_at(2).unwrap(), 64 * 1024);
        // Last chunk is remainder
        assert_eq!(manifest.chunk_size_at(3).unwrap(), 200_000 - 3 * 64 * 1024);

        // Invalid index
        let result = manifest.chunk_size_at(10);
        assert!(matches!(result, Err(ChunkError::InvalidChunkIndex { .. })));
    }

    #[test]
    fn manifest_verify_hash() {
        let payload = vec![1u8; 1000];
        let (manifest, _) = ChunkedObjectManifest::from_payload(&payload, 64 * 1024);

        assert!(manifest.verify_hash(&payload));
        assert!(!manifest.verify_hash(&[0u8; 1000]));
    }

    #[test]
    fn manifest_serialization_roundtrip() {
        let payload = vec![42u8; 100_000];
        let (manifest, _) = ChunkedObjectManifest::from_payload(&payload, 64 * 1024);

        let json = serde_json::to_string(&manifest).unwrap();
        let deserialized: ChunkedObjectManifest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.total_len, manifest.total_len);
        assert_eq!(deserialized.chunk_size, manifest.chunk_size);
        assert_eq!(deserialized.chunks.len(), manifest.chunks.len());
        assert_eq!(deserialized.payload_hash, manifest.payload_hash);
    }

    #[test]
    fn empty_payload_creates_empty_manifest() {
        let (manifest, chunks) = ChunkedObjectManifest::from_payload(&[], 64 * 1024);
        assert_eq!(manifest.total_len, 0);
        assert_eq!(manifest.chunk_count(), 0);
        assert!(chunks.is_empty());
    }

    #[test]
    fn exactly_chunk_size_payload() {
        let payload = vec![1u8; 64 * 1024];
        let (manifest, chunks) = ChunkedObjectManifest::from_payload(&payload, 64 * 1024);

        assert_eq!(manifest.chunk_count(), 1);
        assert_eq!(chunks[0].len(), 64 * 1024);
        assert_eq!(manifest.chunk_size_at(0).unwrap(), 64 * 1024);
    }

    // ── RawChunk additional tests ──────────────────────────────────────────

    #[test]
    fn raw_chunk_content_id_differs_from_empty() {
        let filled = RawChunk::new(vec![1, 2, 3]);
        let empty = RawChunk::new(vec![]);
        assert_ne!(filled.content_id(), empty.content_id());
    }

    #[test]
    fn raw_chunk_large_payload() {
        let data = vec![0xABu8; 1_000_000];
        let chunk = RawChunk::new(data.clone());
        assert_eq!(chunk.len(), 1_000_000);
        assert!(!chunk.is_empty());
        assert_eq!(chunk.bytes, data);
    }

    #[test]
    fn raw_chunk_single_byte() {
        let chunk = RawChunk::new(vec![0xFF]);
        assert_eq!(chunk.len(), 1);
        assert!(!chunk.is_empty());
    }

    #[test]
    fn raw_chunk_clone() {
        let chunk = RawChunk::new(vec![10, 20, 30]);
        let cloned = chunk.clone();
        assert_eq!(cloned.bytes, chunk.bytes);
        assert_eq!(cloned.content_id(), chunk.content_id());
    }

    #[test]
    fn raw_chunk_debug_format() {
        let chunk = RawChunk::new(vec![1, 2]);
        let debug = format!("{chunk:?}");
        assert!(debug.contains("RawChunk"));
    }

    #[test]
    fn raw_chunk_serde_roundtrip() {
        let chunk = RawChunk::new(vec![5, 10, 15, 20]);
        let json = serde_json::to_string(&chunk).unwrap();
        let deserialized: RawChunk = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.bytes, chunk.bytes);
    }

    // ── Manifest edge cases ────────────────────────────────────────────────

    #[test]
    fn manifest_from_payload_chunk_size_one() {
        let payload = vec![1u8, 2, 3, 4, 5];
        let (manifest, chunks) = ChunkedObjectManifest::from_payload(&payload, 1);

        assert_eq!(manifest.total_len, 5);
        assert_eq!(manifest.chunk_size, 1);
        assert_eq!(manifest.chunk_count(), 5);
        assert_eq!(chunks.len(), 5);
        for (i, chunk) in chunks.iter().enumerate() {
            assert_eq!(chunk.len(), 1);
            assert_eq!(chunk.bytes[0], (i + 1) as u8);
        }
    }

    #[test]
    fn manifest_reconstruct_empty_manifest() {
        let (manifest, chunks) = ChunkedObjectManifest::from_payload(&[], 64 * 1024);
        let reconstructed = manifest.reconstruct(&chunks).unwrap();
        assert!(reconstructed.is_empty());
    }

    #[test]
    fn manifest_reconstruct_unchecked_empty() {
        let (manifest, chunks) = ChunkedObjectManifest::from_payload(&[], 64 * 1024);
        let reconstructed = manifest.reconstruct_unchecked(&chunks).unwrap();
        assert!(reconstructed.is_empty());
    }

    #[test]
    fn manifest_reconstruct_unchecked_missing_chunks() {
        let payload = vec![1u8; 200_000];
        let (manifest, mut chunks) = ChunkedObjectManifest::from_payload(&payload, 64 * 1024);
        chunks.pop();
        let result = manifest.reconstruct_unchecked(&chunks);
        assert!(matches!(result, Err(ChunkError::MissingChunks { .. })));
    }

    #[test]
    fn manifest_reconstruct_unchecked_length_mismatch() {
        let payload = vec![1u8; 200_000];
        let (manifest, mut chunks) = ChunkedObjectManifest::from_payload(&payload, 64 * 1024);
        // Replace last chunk with a shorter one to cause length mismatch
        let last_idx = chunks.len() - 1;
        chunks[last_idx] = RawChunk::new(vec![0u8; 1]);
        let result = manifest.reconstruct_unchecked(&chunks);
        assert!(matches!(result, Err(ChunkError::LengthMismatch { .. })));
    }

    #[test]
    fn manifest_chunk_size_at_evenly_divisible() {
        // Payload that is evenly divisible by chunk size
        let payload = vec![42u8; 256 * 1024]; // 256KB / 64KB = 4 even chunks
        let chunk_size = 64 * 1024;
        let (manifest, _) = ChunkedObjectManifest::from_payload(&payload, chunk_size);

        assert_eq!(manifest.chunk_count(), 4);
        for i in 0..4 {
            assert_eq!(manifest.chunk_size_at(i).unwrap(), 64 * 1024);
        }
    }

    #[test]
    fn manifest_verify_hash_empty_payload() {
        let (manifest, _) = ChunkedObjectManifest::from_payload(&[], 64 * 1024);
        assert!(manifest.verify_hash(&[]));
        assert!(!manifest.verify_hash(&[1u8]));
    }

    #[test]
    fn manifest_payload_hash_deterministic() {
        let payload = vec![42u8; 10_000];
        let (m1, _) = ChunkedObjectManifest::from_payload(&payload, 1024);
        let (m2, _) = ChunkedObjectManifest::from_payload(&payload, 1024);
        assert_eq!(m1.payload_hash, m2.payload_hash);
    }

    #[test]
    fn manifest_payload_hash_changes_with_content() {
        let payload_a = vec![1u8; 1000];
        let payload_b = vec![2u8; 1000];
        let (m1, _) = ChunkedObjectManifest::from_payload(&payload_a, 1024);
        let (m2, _) = ChunkedObjectManifest::from_payload(&payload_b, 1024);
        assert_ne!(m1.payload_hash, m2.payload_hash);
    }

    #[test]
    fn manifest_chunk_ids_are_unique() {
        // Each chunk with different content should have a unique ID
        let payload: Vec<u8> = (0..1000_u32).map(|i| (i % 256) as u8).collect();
        let (manifest, _) = ChunkedObjectManifest::from_payload(&payload, 100);

        let mut seen = std::collections::HashSet::new();
        for id in &manifest.chunks {
            assert!(seen.insert(id), "duplicate chunk ID found");
        }
    }

    #[test]
    fn manifest_reconstruct_extra_chunks_rejected() {
        let payload = vec![1u8; 100];
        let (manifest, mut chunks) = ChunkedObjectManifest::from_payload(&payload, 50);
        // Add an extra chunk
        chunks.push(RawChunk::new(vec![0u8; 50]));
        let result = manifest.reconstruct(&chunks);
        assert!(matches!(
            result,
            Err(ChunkError::MissingChunks {
                expected: 2,
                got: 3
            })
        ));
    }

    #[test]
    fn manifest_reconstruct_length_mismatch_error() {
        let payload = vec![1u8; 200_000];
        let (manifest, mut chunks) = ChunkedObjectManifest::from_payload(&payload, 64 * 1024);
        // Replace a chunk with one of different length
        chunks[0] = RawChunk::new(vec![0u8; 1]);
        let result = manifest.reconstruct(&chunks);
        assert!(matches!(result, Err(ChunkError::LengthMismatch { .. })));
    }

    // ── Additional chunk tests ────────────────────────────────────────────

    #[test]
    fn raw_chunk_content_id_changes_with_length() {
        let c1 = RawChunk::new(vec![1, 2, 3]);
        let c2 = RawChunk::new(vec![1, 2, 3, 4]);
        assert_ne!(c1.content_id(), c2.content_id());
    }

    #[test]
    fn raw_chunk_content_id_empty_is_deterministic() {
        let c1 = RawChunk::new(vec![]);
        let c2 = RawChunk::new(vec![]);
        assert_eq!(c1.content_id(), c2.content_id());
    }

    #[test]
    fn manifest_from_payload_two_byte_chunks() {
        let payload = vec![10, 20, 30, 40, 50];
        let (manifest, chunks) = ChunkedObjectManifest::from_payload(&payload, 2);
        assert_eq!(manifest.total_len, 5);
        assert_eq!(manifest.chunk_size, 2);
        assert_eq!(manifest.chunk_count(), 3);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].bytes, vec![10, 20]);
        assert_eq!(chunks[1].bytes, vec![30, 40]);
        assert_eq!(chunks[2].bytes, vec![50]);
    }

    #[test]
    fn manifest_chunk_size_at_out_of_bounds() {
        let payload = vec![1u8; 100];
        let (manifest, _) = ChunkedObjectManifest::from_payload(&payload, 50);
        assert_eq!(manifest.chunk_count(), 2);
        let err = manifest.chunk_size_at(2).unwrap_err();
        assert!(matches!(
            err,
            ChunkError::InvalidChunkIndex { index: 2, count: 2 }
        ));
    }

    #[test]
    fn manifest_chunk_size_at_single_chunk() {
        let payload = vec![42u8; 30];
        let (manifest, _) = ChunkedObjectManifest::from_payload(&payload, 100);
        assert_eq!(manifest.chunk_count(), 1);
        assert_eq!(manifest.chunk_size_at(0).unwrap(), 30);
    }

    #[test]
    fn manifest_reconstruct_unchecked_success() {
        let payload: Vec<u8> = (0..500_u32).map(|i| (i % 256) as u8).collect();
        let (manifest, chunks) = ChunkedObjectManifest::from_payload(&payload, 100);
        let reconstructed = manifest.reconstruct_unchecked(&chunks).unwrap();
        assert_eq!(reconstructed, payload);
    }

    #[test]
    fn manifest_verify_hash_correct() {
        let payload = vec![7u8; 5000];
        let (manifest, _) = ChunkedObjectManifest::from_payload(&payload, 1000);
        assert!(manifest.verify_hash(&payload));
    }

    #[test]
    fn manifest_verify_hash_wrong_length() {
        let payload = vec![7u8; 5000];
        let (manifest, _) = ChunkedObjectManifest::from_payload(&payload, 1000);
        assert!(!manifest.verify_hash(&vec![7u8; 4999]));
    }

    #[test]
    fn manifest_debug_format() {
        let payload = vec![1u8; 100];
        let (manifest, _) = ChunkedObjectManifest::from_payload(&payload, 50);
        let debug = format!("{manifest:?}");
        assert!(debug.contains("ChunkedObjectManifest"));
        assert!(debug.contains("total_len"));
    }

    #[test]
    fn manifest_clone() {
        let payload = vec![1u8; 200];
        let (manifest, _) = ChunkedObjectManifest::from_payload(&payload, 100);
        let cloned = manifest.clone();
        assert_eq!(cloned.total_len, manifest.total_len);
        assert_eq!(cloned.chunk_size, manifest.chunk_size);
        assert_eq!(cloned.chunks.len(), manifest.chunks.len());
        assert_eq!(cloned.payload_hash, manifest.payload_hash);
    }

    #[test]
    fn manifest_serde_preserves_hash() {
        let payload = vec![42u8; 300];
        let (manifest, _) = ChunkedObjectManifest::from_payload(&payload, 100);
        let json = serde_json::to_string(&manifest).unwrap();
        let deserialized: ChunkedObjectManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.payload_hash, manifest.payload_hash);
        assert!(deserialized.verify_hash(&payload));
    }

    #[test]
    fn raw_chunk_serde_empty() {
        let chunk = RawChunk::new(vec![]);
        let json = serde_json::to_string(&chunk).unwrap();
        let deserialized: RawChunk = serde_json::from_str(&json).unwrap();
        assert!(deserialized.is_empty());
    }

    // ── Additional chunk edge-case tests ──────────────────────────────────

    #[test]
    fn manifest_different_chunk_sizes_produce_different_chunk_counts() {
        let payload = vec![42u8; 1000];
        let (m1, c1) = ChunkedObjectManifest::from_payload(&payload, 100);
        let (m2, c2) = ChunkedObjectManifest::from_payload(&payload, 200);
        assert_eq!(m1.chunk_count(), 10);
        assert_eq!(m2.chunk_count(), 5);
        assert_eq!(c1.len(), 10);
        assert_eq!(c2.len(), 5);
        // But the payload hashes should be identical
        assert_eq!(m1.payload_hash, m2.payload_hash);
    }

    #[test]
    fn manifest_reconstruct_preserves_byte_ordering() {
        let payload: Vec<u8> = (0..200_u8).collect();
        let (manifest, chunks) = ChunkedObjectManifest::from_payload(&payload, 50);
        let reconstructed = manifest.reconstruct(&chunks).unwrap();
        assert_eq!(reconstructed, payload);
        // Verify byte-by-byte ordering
        for (i, &byte) in reconstructed.iter().enumerate() {
            assert_eq!(byte, i as u8, "byte at position {i} differs");
        }
    }

    #[test]
    fn manifest_chunk_ids_differ_from_different_payloads() {
        let payload_a = vec![1u8; 100];
        let payload_b = vec![2u8; 100];
        let (m_a, _) = ChunkedObjectManifest::from_payload(&payload_a, 50);
        let (m_b, _) = ChunkedObjectManifest::from_payload(&payload_b, 50);
        // All chunk IDs should differ because content differs
        for (id_a, id_b) in m_a.chunks.iter().zip(m_b.chunks.iter()) {
            assert_ne!(id_a, id_b);
        }
    }

    #[test]
    fn raw_chunk_content_id_is_unscoped() {
        // Two identical chunks should always produce the same ID
        let data = vec![99u8; 256];
        let c1 = RawChunk::new(data.clone());
        let c2 = RawChunk::new(data);
        assert_eq!(c1.content_id(), c2.content_id());
    }

    #[test]
    fn manifest_reconstruct_wrong_order_still_works() {
        // Reconstruction uses chunks in order, so reversed chunks
        // should produce incorrect data but not error on length match
        let payload: Vec<u8> = (0..100_u8).collect();
        let (manifest, mut chunks) = ChunkedObjectManifest::from_payload(&payload, 25);
        assert_eq!(chunks.len(), 4);
        // Reverse chunks: length matches but content is wrong
        chunks.reverse();
        let result = manifest.reconstruct(&chunks);
        // Hash should not match since content order changed
        assert!(matches!(result, Err(ChunkError::HashMismatch)));
    }

    #[test]
    fn manifest_from_payload_large_chunk_size() {
        // Chunk size larger than payload -> single chunk
        let payload = vec![42u8; 100];
        let (manifest, chunks) = ChunkedObjectManifest::from_payload(&payload, u32::MAX);
        assert_eq!(manifest.chunk_count(), 1);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].bytes, payload);
    }

    #[test]
    fn manifest_serde_preserves_chunk_ids() {
        let payload = vec![42u8; 500];
        let (manifest, _) = ChunkedObjectManifest::from_payload(&payload, 100);
        let json = serde_json::to_string(&manifest).unwrap();
        let deserialized: ChunkedObjectManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.chunks, manifest.chunks);
    }

    #[test]
    fn raw_chunk_serde_large_payload() {
        let chunk = RawChunk::new(vec![0xAB; 10_000]);
        let json = serde_json::to_string(&chunk).unwrap();
        let deserialized: RawChunk = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.bytes, chunk.bytes);
    }

    #[test]
    fn manifest_chunk_size_at_with_one_byte_chunks() {
        let payload = vec![1u8, 2, 3];
        let (manifest, _) = ChunkedObjectManifest::from_payload(&payload, 1);
        assert_eq!(manifest.chunk_count(), 3);
        for i in 0..3 {
            assert_eq!(manifest.chunk_size_at(i).unwrap(), 1);
        }
    }

    #[test]
    fn manifest_reconstruct_unchecked_corrupted_data_succeeds() {
        let payload = vec![1u8; 100];
        let (manifest, mut chunks) = ChunkedObjectManifest::from_payload(&payload, 50);
        // Corrupt a byte
        chunks[0].bytes[0] = 255;
        // unchecked should succeed
        let result = manifest.reconstruct_unchecked(&chunks).unwrap();
        // But hash fails
        assert!(!manifest.verify_hash(&result));
        assert_eq!(result.len(), 100);
    }

    // ── Additional chunk edge-case tests (batch 2) ────────────────────────

    #[test]
    fn manifest_from_payload_binary_data() {
        let payload: Vec<u8> = (0..255_u8).collect();
        let (manifest, chunks) = ChunkedObjectManifest::from_payload(&payload, 64);
        assert_eq!(manifest.total_len, 255);
        // ceil(255 / 64) = 4 chunks
        assert_eq!(manifest.chunk_count(), 4);
        let reconstructed = manifest.reconstruct(&chunks).unwrap();
        assert_eq!(reconstructed, payload);
    }

    #[test]
    fn manifest_reconstruct_preserves_trailing_zeros() {
        let mut payload = vec![0xAB_u8; 50];
        payload.extend_from_slice(&[0u8; 50]);
        let (manifest, chunks) = ChunkedObjectManifest::from_payload(&payload, 30);
        let reconstructed = manifest.reconstruct(&chunks).unwrap();
        assert_eq!(reconstructed, payload);
        // Verify trailing zeros are preserved
        for &b in &reconstructed[50..] {
            assert_eq!(b, 0);
        }
    }

    #[test]
    fn manifest_chunk_size_at_two_chunks_last_smaller() {
        let payload = vec![1u8; 70];
        let (manifest, _) = ChunkedObjectManifest::from_payload(&payload, 50);
        assert_eq!(manifest.chunk_count(), 2);
        assert_eq!(manifest.chunk_size_at(0).unwrap(), 50);
        assert_eq!(manifest.chunk_size_at(1).unwrap(), 20);
    }

    #[test]
    fn manifest_reconstruct_single_byte_payload() {
        let payload = vec![42u8];
        let (manifest, chunks) = ChunkedObjectManifest::from_payload(&payload, 1024);
        assert_eq!(manifest.chunk_count(), 1);
        let reconstructed = manifest.reconstruct(&chunks).unwrap();
        assert_eq!(reconstructed, payload);
    }

    #[test]
    fn raw_chunk_debug_shows_bytes() {
        let chunk = RawChunk::new(vec![0xDE, 0xAD]);
        let debug = format!("{chunk:?}");
        assert!(debug.contains("bytes"));
    }

    #[test]
    fn manifest_serde_cbor_roundtrip_via_json() {
        let payload = vec![42u8; 500];
        let (manifest, _) = ChunkedObjectManifest::from_payload(&payload, 100);
        let json = serde_json::to_vec(&manifest).unwrap();
        let deserialized: ChunkedObjectManifest = serde_json::from_slice(&json).unwrap();
        assert_eq!(deserialized.total_len, manifest.total_len);
        assert_eq!(deserialized.chunk_size, manifest.chunk_size);
        assert_eq!(deserialized.payload_hash, manifest.payload_hash);
        assert!(deserialized.verify_hash(&payload));
    }

    #[test]
    fn manifest_reconstruct_unchecked_preserves_corrupted_data() {
        let payload = vec![0u8; 200];
        let (manifest, mut chunks) = ChunkedObjectManifest::from_payload(&payload, 100);
        chunks[0].bytes[0] = 0xFF;
        chunks[1].bytes[0] = 0xFE;
        let result = manifest.reconstruct_unchecked(&chunks).unwrap();
        assert_eq!(result[0], 0xFF);
        assert_eq!(result[100], 0xFE);
    }

    #[test]
    fn manifest_chunk_ids_stable_across_manifest_creation() {
        let payload = vec![42u8; 300];
        let (m1, _) = ChunkedObjectManifest::from_payload(&payload, 100);
        let (m2, _) = ChunkedObjectManifest::from_payload(&payload, 100);
        assert_eq!(m1.chunks, m2.chunks);
    }

    #[test]
    fn manifest_from_payload_exact_three_chunks() {
        let payload = vec![7u8; 300];
        let (manifest, chunks) = ChunkedObjectManifest::from_payload(&payload, 100);
        assert_eq!(manifest.chunk_count(), 3);
        assert_eq!(chunks.len(), 3);
        for chunk in &chunks {
            assert_eq!(chunk.len(), 100);
        }
        for i in 0..3 {
            assert_eq!(manifest.chunk_size_at(i).unwrap(), 100);
        }
    }

    #[test]
    fn raw_chunk_content_id_all_zeros() {
        let c1 = RawChunk::new(vec![0u8; 100]);
        let c2 = RawChunk::new(vec![0u8; 100]);
        assert_eq!(c1.content_id(), c2.content_id());
    }

    #[test]
    fn raw_chunk_content_id_all_ones() {
        let c1 = RawChunk::new(vec![0xFF; 100]);
        let c2 = RawChunk::new(vec![0xFF; 100]);
        assert_eq!(c1.content_id(), c2.content_id());
    }

    #[test]
    fn manifest_verify_hash_wrong_content_same_length() {
        let payload = vec![1u8; 500];
        let (manifest, _) = ChunkedObjectManifest::from_payload(&payload, 100);
        let wrong = vec![2u8; 500];
        assert!(!manifest.verify_hash(&wrong));
    }

    #[test]
    fn manifest_reconstruct_length_mismatch_with_extra_bytes() {
        let payload = vec![1u8; 100];
        let (manifest, mut chunks) = ChunkedObjectManifest::from_payload(&payload, 50);
        // Replace a chunk with a longer one (same count, different length)
        chunks[0] = RawChunk::new(vec![1u8; 55]);
        let result = manifest.reconstruct(&chunks);
        assert!(matches!(result, Err(ChunkError::LengthMismatch { .. })));
    }

    #[test]
    fn manifest_clone_then_modify_original_is_independent() {
        let payload = vec![1u8; 200];
        let (manifest, _) = ChunkedObjectManifest::from_payload(&payload, 100);
        let cloned = manifest.clone();
        // Modify via re-creation with different payload
        let payload2 = vec![2u8; 200];
        let (manifest2, _) = ChunkedObjectManifest::from_payload(&payload2, 100);
        // Clone should still match original
        assert_eq!(cloned.payload_hash, manifest.payload_hash);
        assert_ne!(cloned.payload_hash, manifest2.payload_hash);
    }
}
