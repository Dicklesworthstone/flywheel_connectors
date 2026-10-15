//! Incremental, content-verified reconstruction of large mesh objects.
//!
//! The caller owns retrieval and scheduling: fetch `next_chunk_id()`, supply one
//! chunk, then release it before fetching the next. No full-payload buffer or
//! detached worker is created here. A file destination should be a temporary
//! file and must not be published until `finish()` succeeds. Flush is not fsync.

use std::io::{self, Write};

use fcp_prelude::ObjectId;
use thiserror::Error;

use crate::{ChunkError, ChunkedObjectManifest, RawChunk};

/// Errors from bounded, incremental chunk reconstruction.
#[derive(Debug, Error)]
pub enum ChunkReconstructionError {
    /// The manifest or a supplied chunk failed validation.
    #[error(transparent)]
    Chunk(#[from] ChunkError),
    /// The advertised payload exceeds the caller's admission budget.
    #[error("payload too large: {size} bytes exceeds limit {max} bytes")]
    PayloadTooLarge {
        /// Advertised payload size.
        size: u64,
        /// Caller-selected maximum payload size.
        max: u64,
    },
    /// The destination could not accept or flush the reconstructed bytes.
    #[error("chunk destination I/O failed: {0}")]
    Io(#[from] io::Error),
    /// A prior write may have partially modified the destination.
    #[error("reconstruction cannot continue after a destination write failure")]
    WriteFailed,
}

/// A one-chunk-at-a-time reconstruction session.
///
/// Each chunk's size and content ID are checked before it reaches the writer.
/// `finish` additionally checks completeness and the full-payload hash. A caller
/// must not consume or publish the destination before that final check succeeds.
/// A rejected chunk may be fetched again; a failed write poisons the session
/// because retrying it could duplicate a partially written prefix.
#[derive(Debug)]
pub struct ChunkReconstructor<'a, W> {
    manifest: &'a ChunkedObjectManifest,
    writer: W,
    hasher: blake3::Hasher,
    next_index: usize,
    written_bytes: u64,
    write_failed: bool,
}

impl ChunkedObjectManifest {
    /// Check manifest geometry before admitting reads or allocating a payload.
    /// Empty payloads have no chunks; all non-final chunks have `chunk_size`
    /// bytes, and the final chunk is nonempty and no larger than `chunk_size`.
    ///
    /// # Errors
    /// Returns [`ChunkError::InvalidChunkSize`] for a zero chunk size, or
    /// [`ChunkError::MissingChunks`] for an inconsistent chunk count.
    pub fn validate_layout(&self) -> Result<(), ChunkError> {
        if self.chunk_size == 0 {
            return Err(ChunkError::InvalidChunkSize);
        }
        let expected = self.total_len.div_ceil(u64::from(self.chunk_size));
        if u64::try_from(self.chunks.len()).ok() != Some(expected) {
            return Err(ChunkError::MissingChunks {
                expected: usize::try_from(expected).unwrap_or(usize::MAX),
                got: self.chunks.len(),
            });
        }
        Ok(())
    }

    /// Verify a chunk against its exact position in the manifest.
    ///
    /// This supports partial retrieval and targeted repair without allocating
    /// or reconstructing the full payload. Repeated IDs are valid when repeated
    /// payload chunks really have the same contents.
    ///
    /// # Errors
    /// Returns [`ChunkError`] for invalid geometry, index, length or content ID.
    pub fn verify_chunk(&self, index: usize, chunk: &RawChunk) -> Result<(), ChunkError> {
        self.validate_chunk_length(index, chunk.len())?;
        if chunk.content_id() != self.chunks[index] {
            return Err(ChunkError::HashMismatch);
        }
        Ok(())
    }

    pub(crate) fn validate_chunk_length(
        &self,
        index: usize,
        actual_len: usize,
    ) -> Result<(), ChunkError> {
        if index >= self.chunks.len() {
            return Err(ChunkError::InvalidChunkIndex {
                index,
                count: self.chunks.len(),
            });
        }
        self.validate_layout()?;
        let remainder = self.total_len % u64::from(self.chunk_size);
        let expected = if index == self.chunks.len() - 1 && remainder != 0 {
            remainder
        } else {
            u64::from(self.chunk_size)
        };
        let got = u64::try_from(actual_len).unwrap_or(u64::MAX);
        if got != expected {
            return Err(ChunkError::LengthMismatch { expected, got });
        }
        Ok(())
    }

    /// Start bounded-memory reconstruction into a caller-owned destination.
    ///
    /// `max_payload_bytes` is checked before any destination I/O. Retained
    /// working state is constant-size, in addition to the borrowed manifest and
    /// the one chunk supplied by the caller. The writer may buffer independently.
    ///
    /// # Errors
    /// Returns an error for invalid geometry or an exceeded payload budget.
    pub fn start_reconstruction<W: Write>(
        &self,
        writer: W,
        max_payload_bytes: u64,
    ) -> Result<ChunkReconstructor<'_, W>, ChunkReconstructionError> {
        self.validate_layout()?;
        if self.total_len > max_payload_bytes {
            return Err(ChunkReconstructionError::PayloadTooLarge {
                size: self.total_len,
                max: max_payload_bytes,
            });
        }
        Ok(ChunkReconstructor {
            manifest: self,
            writer,
            hasher: blake3::Hasher::new(),
            next_index: 0,
            written_bytes: 0,
            write_failed: false,
        })
    }
}

impl<W: Write> ChunkReconstructor<'_, W> {
    /// The next content ID to fetch, or `None` when all chunks were written.
    #[must_use]
    pub fn next_chunk_id(&self) -> Option<ObjectId> {
        self.manifest.chunks.get(self.next_index).copied()
    }

    /// Number of chunks successfully written in manifest order.
    #[must_use]
    pub const fn chunks_written(&self) -> usize {
        self.next_index
    }

    /// Number of bytes accepted by successful complete writes.
    /// This excludes any partial write from a poisoned session.
    #[must_use]
    pub const fn bytes_written(&self) -> u64 {
        self.written_bytes
    }

    /// Validate and append the next chunk, without retaining its bytes.
    ///
    /// # Errors
    /// A corrupt or misplaced chunk is rejected before writing and may be
    /// replaced by a repaired chunk. An I/O error poisons the session, preventing
    /// either further writes or a successful `finish` on a partial destination.
    pub fn push(&mut self, chunk: &RawChunk) -> Result<(), ChunkReconstructionError> {
        if self.write_failed {
            return Err(ChunkReconstructionError::WriteFailed);
        }
        self.manifest.verify_chunk(self.next_index, chunk)?;
        // Also remain poisoned if a writer unwinds after modifying its output.
        self.write_failed = true;
        self.writer.write_all(&chunk.bytes)?;
        self.hasher.update(&chunk.bytes);
        // Validated geometry bounds this sum by the manifest's u64 total_len.
        self.written_bytes += u64::try_from(chunk.len()).unwrap_or(u64::MAX);
        self.next_index += 1;
        self.write_failed = false;
        Ok(())
    }

    /// Verify completeness and the end-to-end hash, flush, and return the writer.
    ///
    /// This does not make a file durable or atomically publish it. File callers
    /// should fsync and rename their temporary destination after success.
    ///
    /// # Errors
    /// Returns an error for a poisoned write, missing chunks, an inconsistent
    /// full-payload hash, or a failed flush. No success is reported for a prefix.
    pub fn finish(mut self) -> Result<W, ChunkReconstructionError> {
        if self.write_failed {
            return Err(ChunkReconstructionError::WriteFailed);
        }
        if self.next_index != self.manifest.chunks.len() {
            return Err(ChunkError::MissingChunks {
                expected: self.manifest.chunks.len(),
                got: self.next_index,
            }
            .into());
        }
        if self.written_bytes != self.manifest.total_len {
            return Err(ChunkError::LengthMismatch {
                expected: self.manifest.total_len,
                got: self.written_bytes,
            }
            .into());
        }
        if self.hasher.finalize().as_bytes() != &self.manifest.payload_hash {
            return Err(ChunkError::HashMismatch.into());
        }
        self.writer.flush()?;
        Ok(self.writer)
    }
}

#[cfg(test)]
#[path = "reconstruction_tests.rs"]
mod tests;
