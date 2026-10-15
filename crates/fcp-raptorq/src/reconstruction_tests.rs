use super::*;

#[test]
fn incremental_reconstruction_matches_every_small_chunk_size() {
    let payload: Vec<u8> = (0..251).collect();
    for size in 1..=256 {
        let (manifest, chunks) = ChunkedObjectManifest::from_payload(&payload, size);
        let mut session = manifest.start_reconstruction(Vec::new(), 251).unwrap();
        for (index, chunk) in chunks.iter().enumerate() {
            assert_eq!(session.chunks_written(), index);
            assert_eq!(session.next_chunk_id(), Some(chunk.content_id()));
            session.push(chunk).unwrap();
        }
        assert_eq!(session.next_chunk_id(), None);
        assert_eq!(session.bytes_written(), 251);
        assert_eq!(session.finish().unwrap(), payload);
    }
}

#[test]
fn payload_limit_is_checked_before_destination_io() {
    struct NoIo;
    impl Write for NoIo {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            panic!("over-budget reconstruction must not write");
        }
        fn flush(&mut self) -> io::Result<()> {
            panic!("over-budget reconstruction must not flush");
        }
    }
    let (manifest, _) = ChunkedObjectManifest::from_payload(b"abcd", 2);
    assert!(matches!(
        manifest.start_reconstruction(NoIo, 3),
        Err(ChunkReconstructionError::PayloadTooLarge { size: 4, max: 3 })
    ));
}

#[test]
fn invalid_manifest_geometry_is_rejected_before_retrieval() {
    let (manifest, _) = ChunkedObjectManifest::from_payload(b"abcde", 2);
    let mut zero = manifest.clone();
    zero.chunk_size = 0;
    assert_eq!(zero.validate_layout(), Err(ChunkError::InvalidChunkSize));
    for total_len in [0, 1, 2, 3, 4, 7, u64::MAX] {
        let mut invalid = manifest.clone();
        invalid.total_len = total_len;
        assert!(invalid.validate_layout().is_err(), "accepted {total_len}");
        assert!(invalid.start_reconstruction(io::sink(), u64::MAX).is_err());
    }
}

#[test]
fn geometry_arithmetic_does_not_overflow_at_u64_max() {
    let manifest = ChunkedObjectManifest {
        total_len: u64::MAX,
        chunk_size: u32::MAX,
        chunks: Vec::new(),
        payload_hash: [0; 32],
    };
    assert!(matches!(
        manifest.validate_layout(),
        Err(ChunkError::MissingChunks { .. })
    ));
}

#[test]
fn wrong_id_is_rejected_even_when_full_payload_hash_would_match() {
    let (mut manifest, chunks) = ChunkedObjectManifest::from_payload(b"abcd", 2);
    manifest.chunks[0] = ObjectId::from_unscoped_bytes(b"unrelated");
    assert_eq!(
        manifest.verify_chunk(0, &chunks[0]),
        Err(ChunkError::HashMismatch)
    );
    let mut output = Vec::new();
    let mut session = manifest.start_reconstruction(&mut output, 4).unwrap();
    assert!(matches!(
        session.push(&chunks[0]),
        Err(ChunkReconstructionError::Chunk(ChunkError::HashMismatch))
    ));
    assert_eq!(session.bytes_written(), 0);
    drop(session);
    assert!(output.is_empty());
}

#[test]
fn misplaced_or_corrupt_chunks_can_be_repaired_without_writing_bad_bytes() {
    let (manifest, chunks) = ChunkedObjectManifest::from_payload(b"abcdef", 2);
    let mut session = manifest.start_reconstruction(Vec::new(), 6).unwrap();
    assert!(session.push(&chunks[1]).is_err());
    assert!(session.push(&RawChunk::new(b"xx".to_vec())).is_err());
    assert_eq!(session.chunks_written(), 0);
    for chunk in &chunks {
        session.push(chunk).unwrap();
    }
    assert_eq!(session.finish().unwrap(), b"abcdef");
}

#[test]
fn shifted_boundaries_are_rejected_even_if_concatenation_matches() {
    let (manifest, _) = ChunkedObjectManifest::from_payload(b"abcd", 2);
    let mut session = manifest.start_reconstruction(Vec::new(), 4).unwrap();
    assert!(matches!(
        session.push(&RawChunk::new(b"a".to_vec())),
        Err(ChunkReconstructionError::Chunk(
            ChunkError::LengthMismatch {
                expected: 2,
                got: 1
            }
        ))
    ));
}

#[test]
fn duplicate_content_ids_are_valid_at_distinct_positions() {
    let (manifest, chunks) = ChunkedObjectManifest::from_payload(b"ababab", 2);
    assert!(manifest.chunks.windows(2).all(|pair| pair[0] == pair[1]));
    let mut session = manifest.start_reconstruction(Vec::new(), 6).unwrap();
    for chunk in &chunks {
        session.push(chunk).unwrap();
    }
    assert_eq!(session.finish().unwrap(), b"ababab");
}

#[test]
fn finish_rejects_a_valid_but_incomplete_prefix() {
    let (manifest, chunks) = ChunkedObjectManifest::from_payload(b"abcd", 2);
    let mut session = manifest.start_reconstruction(Vec::new(), 4).unwrap();
    session.push(&chunks[0]).unwrap();
    assert!(matches!(
        session.finish(),
        Err(ChunkReconstructionError::Chunk(ChunkError::MissingChunks {
            expected: 2,
            got: 1
        }))
    ));
}

#[test]
fn finish_checks_full_payload_hash_even_after_all_chunk_ids_match() {
    let (mut manifest, chunks) = ChunkedObjectManifest::from_payload(b"abcd", 2);
    manifest.payload_hash[0] ^= 1;
    let mut session = manifest.start_reconstruction(Vec::new(), 4).unwrap();
    for chunk in &chunks {
        session.push(chunk).unwrap();
    }
    assert!(matches!(
        session.finish(),
        Err(ChunkReconstructionError::Chunk(ChunkError::HashMismatch))
    ));
}

#[test]
fn empty_payload_is_verified_without_writes() {
    let (mut manifest, _) = ChunkedObjectManifest::from_payload(b"", 2);
    let session = manifest.start_reconstruction(Vec::new(), 0).unwrap();
    assert_eq!(session.next_chunk_id(), None);
    assert!(session.finish().unwrap().is_empty());
    manifest.payload_hash[0] ^= 1;
    assert!(
        manifest
            .start_reconstruction(Vec::new(), 0)
            .unwrap()
            .finish()
            .is_err()
    );
}

#[test]
fn extra_chunks_do_not_reach_the_destination() {
    let (manifest, chunks) = ChunkedObjectManifest::from_payload(b"ab", 2);
    let mut session = manifest.start_reconstruction(Vec::new(), 2).unwrap();
    session.push(&chunks[0]).unwrap();
    assert!(matches!(
        session.push(&chunks[0]),
        Err(ChunkReconstructionError::Chunk(
            ChunkError::InvalidChunkIndex { .. }
        ))
    ));
    assert_eq!(session.finish().unwrap(), b"ab");
}

#[derive(Debug, Default)]
struct PartialFailure {
    bytes: Vec<u8>,
}

impl Write for PartialFailure {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.bytes.is_empty() {
            self.bytes.push(bytes[0]);
            Ok(1)
        } else {
            Err(io::Error::other("destination failed after a partial write"))
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        panic!("poisoned destination must not be flushed");
    }
}

#[test]
fn partial_write_failure_cannot_be_retried_or_finished() {
    let (manifest, chunks) = ChunkedObjectManifest::from_payload(b"ab", 2);
    let mut destination = PartialFailure::default();
    let mut session = manifest.start_reconstruction(&mut destination, 2).unwrap();
    assert!(matches!(
        session.push(&chunks[0]),
        Err(ChunkReconstructionError::Io(_))
    ));
    assert_eq!(session.bytes_written(), 0);
    assert!(matches!(
        session.push(&chunks[0]),
        Err(ChunkReconstructionError::WriteFailed)
    ));
    assert!(matches!(
        session.finish(),
        Err(ChunkReconstructionError::WriteFailed)
    ));
    assert_eq!(destination.bytes, b"a");
}

#[test]
fn flush_failure_is_not_reported_as_success() {
    #[derive(Debug)]
    struct FlushFailure;
    impl Write for FlushFailure {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("flush failed"))
        }
    }
    let (manifest, chunks) = ChunkedObjectManifest::from_payload(b"ab", 2);
    let mut session = manifest.start_reconstruction(FlushFailure, 2).unwrap();
    session.push(&chunks[0]).unwrap();
    assert!(matches!(
        session.finish(),
        Err(ChunkReconstructionError::Io(_))
    ));
}

#[test]
fn sink_reconstruction_does_not_require_a_payload_sized_output_buffer() {
    let (manifest, chunks) = ChunkedObjectManifest::from_payload(&vec![42; 4097], 128);
    let mut session = manifest.start_reconstruction(io::sink(), 4097).unwrap();
    for chunk in chunks {
        session.push(&chunk).unwrap();
        // The only supplied chunk is dropped at this iteration boundary.
    }
    assert_eq!(session.bytes_written(), 4097);
    session.finish().unwrap();
}
