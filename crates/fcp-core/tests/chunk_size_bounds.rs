use fcp_core::{
    CheckpointChunkError, CheckpointTransferEncoding, ChunkedCheckpoint, ComputationCheckpoint,
    DEFAULT_COMPUTATION_CHECKPOINT_CHUNK_SIZE_BYTES, MigrationCapabilityContext, ObjectHeader,
    ObjectId, Provenance, TailscaleNodeId, ZoneId,
};
use std::io;
use uuid::Uuid;

fn test_zone() -> ZoneId {
    ZoneId::work()
}

fn test_object_id(label: &str) -> ObjectId {
    ObjectId::from_unscoped_bytes(label.as_bytes())
}

fn test_checkpoint() -> ComputationCheckpoint {
    let computation_id = test_object_id("chunk-size-computation");
    let lease_id = test_object_id("chunk-size-lease");
    let zone_id = test_zone();

    ComputationCheckpoint {
        header: ObjectHeader {
            encryption_kind: Default::default(),
            schema: ComputationCheckpoint::schema(),
            zone_id: zone_id.clone(),
            created_at: 1_700_000_000,
            provenance: Provenance::new(zone_id),
            refs: vec![computation_id, lease_id],
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        },
        computation_id,
        current_holder: TailscaleNodeId::new("chunk-size-node"),
        checkpoint_seq: 9,
        suspended_at: 1_700_000_100,
        lease_id,
        lease_fencing_token: 17,
        capability_context: MigrationCapabilityContext {
            capability_token_jti: Uuid::from_bytes([0xC5; 16]),
            checkpoint_id: None,
            checkpoint_seq: 9,
            audit_event_id: Some(test_object_id("chunk-size-audit")),
        },
        state_cbor: vec![0xA5; 32],
    }
}

fn chunked_with_size(
    chunk_size_bytes: usize,
) -> Result<ChunkedCheckpoint, Box<dyn std::error::Error>> {
    let encoding = test_checkpoint().to_transfer_encoding(0, chunk_size_bytes)?;

    match encoding {
        CheckpointTransferEncoding::Chunked(chunked) => Ok(chunked),
        CheckpointTransferEncoding::Inline { .. } => {
            Err(io::Error::other("threshold zero must force chunked checkpoint transfer").into())
        }
    }
}

#[test]
fn chunk_size_default_value_is_sixty_four_kib() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(DEFAULT_COMPUTATION_CHECKPOINT_CHUNK_SIZE_BYTES, 64 * 1024);

    let chunked = chunked_with_size(DEFAULT_COMPUTATION_CHECKPOINT_CHUNK_SIZE_BYTES)?;
    let default_chunk_size_u32 = u32::try_from(DEFAULT_COMPUTATION_CHECKPOINT_CHUNK_SIZE_BYTES)?;
    assert_eq!(chunked.manifest.chunk_size_bytes, default_chunk_size_u32);
    assert_eq!(chunked.manifest.chunk_count(), 1);
    assert_eq!(chunked.chunks.len(), 1);

    Ok(())
}

#[test]
fn chunk_size_accepts_minimum_one_byte() -> Result<(), Box<dyn std::error::Error>> {
    let chunked = chunked_with_size(1)?;

    assert_eq!(chunked.manifest.chunk_size_bytes, 1);
    assert!(chunked.manifest.total_bytes > 0);
    let chunk_count = u64::try_from(chunked.manifest.chunk_count())?;
    assert_eq!(chunk_count, chunked.manifest.total_bytes);
    assert!(chunked.chunks.iter().all(|chunk| chunk.len() == 1));

    Ok(())
}

#[test]
fn chunk_size_accepts_manifest_maximum_u32() -> Result<(), Box<dyn std::error::Error>> {
    let max_chunk_size = usize::try_from(u32::MAX)?;
    let chunked = chunked_with_size(max_chunk_size)?;

    assert_eq!(chunked.manifest.chunk_size_bytes, u32::MAX);
    assert_eq!(chunked.manifest.chunk_count(), 1);
    assert_eq!(chunked.chunks.len(), 1);
    let first_chunk = chunked
        .chunks
        .first()
        .ok_or_else(|| io::Error::other("expected one checkpoint chunk"))?;
    let chunk_len = u64::try_from(first_chunk.len())?;
    assert_eq!(chunk_len, chunked.manifest.total_bytes);

    Ok(())
}

#[test]
fn chunk_size_rejects_zero_and_manifest_overflow() -> Result<(), Box<dyn std::error::Error>> {
    let checkpoint = test_checkpoint();
    let Err(zero) = checkpoint.to_transfer_encoding(0, 0) else {
        return Err(io::Error::other("zero chunk size must be rejected").into());
    };
    assert!(matches!(zero, CheckpointChunkError::InvalidChunkSize));
    assert!(zero.to_string().contains("greater than zero"));

    let too_large = usize::try_from(u64::from(u32::MAX) + 1)?;
    let Err(overflow) = checkpoint.to_transfer_encoding(0, too_large) else {
        return Err(io::Error::other("manifest chunk size overflow must be rejected").into());
    };

    assert!(matches!(
        overflow,
        CheckpointChunkError::ManifestChunkSizeOverflow { chunk_size_bytes }
            if chunk_size_bytes == too_large
    ));
    assert!(overflow.to_string().contains("does not fit in manifest"));

    Ok(())
}
