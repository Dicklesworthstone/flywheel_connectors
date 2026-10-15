//! Host-facing policy wrapper for snapshot resume handshakes.
//!
//! `fcp-store` owns the canonical wire shapes because they are content-addressed
//! store objects. The host layer re-exports those shapes and adds the local
//! admission policy used before a source lease may be released.

use std::future::Future;
use std::io;
use std::time::Duration;

use fcp_async_core::io::{AsyncWrite, AsyncWriteExt};
use fcp_async_core::{AsyncError, Deadline, ExecutionContext};
use fcp_core::ObjectId;
use fcp_raptorq::{ChunkReconstructionError, RaptorQConfig, RawChunk};
use fcp_store::{ProcessSnapshotManifest, ProcessSnapshotTrustAnchors};

pub use fcp_store::{
    CapabilityAvailability, DEFAULT_RESUME_HANDSHAKE_TIMEOUT_MS, RehydrationStatus,
    ResumeHandshakeError, ResumeHandshakeMessage, ResumeHandshakeRequest,
    ResumeHandshakeTranscript, ResumeReplayOp, ResumeRollbackPlan, ResumeRollbackReason,
    ResumeSnapshotSymbol, ResumeSourceLeaseRelease, ResumeTargetAck, ResumeTargetComplete,
    SnapshotFreshness,
};

/// Host-side bounds for accepting a resume transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostResumeHandshakePolicy {
    /// Maximum end-to-end handshake duration in milliseconds.
    pub timeout_ms: u64,
}

/// Explicit admission bounds for one snapshot payload, not its manifest stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostSnapshotRestoreLimits {
    /// Maximum total payload bytes accepted by the target.
    pub max_payload_bytes: u64,
    /// Maximum bytes in any one fetched chunk.
    pub max_chunk_bytes: usize,
}

/// Inputs to target-side restoration. No completion/release message is trusted
/// as proof that these bytes have already been restored.
pub struct HostSnapshotRestoreRequest<'a> {
    /// Request, accepting preflight and manifest symbols from this handoff.
    pub transcript: &'a ResumeHandshakeTranscript,
    /// Local bounds for decoding the signed manifest's symbol stream.
    pub raptorq_config: &'a RaptorQConfig,
    /// Already-authorized restore capability bytes, checked against the pin.
    pub capability_token_bytes: &'a [u8],
    /// Locally configured manifest signing trust anchors.
    pub trust_anchors: &'a ProcessSnapshotTrustAnchors,
    /// Local payload admission policy; never take these limits from a peer.
    pub limits: HostSnapshotRestoreLimits,
    /// Trusted host clock at admission, in the transcript's millisecond domain.
    /// This must not be copied from the peer's request or completion message.
    pub observed_at_ms: u64,
}

impl std::fmt::Debug for HostSnapshotRestoreRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostSnapshotRestoreRequest")
            .field("handshake_id", &self.transcript.request.handshake_id)
            .field("limits", &self.limits)
            .field("observed_at_ms", &self.observed_at_ms)
            .finish_non_exhaustive()
    }
}

/// Local evidence produced only after complete, verified payload output and
/// successful flush. It is not a process-liveness or filesystem-fsync receipt.
#[derive(Debug)]
pub struct HostSnapshotRestoreEvidence {
    handshake_id: ObjectId,
    manifest: ProcessSnapshotManifest,
}

impl HostSnapshotRestoreEvidence {
    /// The signed manifest whose payload was successfully reconstructed.
    #[must_use]
    pub const fn manifest(&self) -> &ProcessSnapshotManifest {
        &self.manifest
    }
}

/// Target-side restore failure. No error permits publishing a partial output,
/// releasing the source lease, or blindly retrying a partially written sink.
#[derive(Debug, thiserror::Error)]
pub enum HostSnapshotRestoreError {
    /// Handshake, signature, pin or observed-clock validation failed.
    #[error(transparent)]
    Handshake(#[from] ResumeHandshakeError),
    /// Payload geometry, integrity or total-byte admission failed.
    #[error(transparent)]
    Reconstruction(#[from] ChunkReconstructionError),
    /// One chunk exceeds the target's per-fetch admission budget.
    #[error("snapshot chunk size {size} exceeds local limit {max}")]
    ChunkTooLarge {
        /// Largest actual chunk described by the manifest.
        size: u64,
        /// Target's maximum permitted chunk length.
        max: usize,
    },
    /// Fetching or writing the payload failed.
    #[error("snapshot payload I/O failed: {0}")]
    Io(#[from] io::Error),
    /// The inherited cancellation or shared absolute deadline interrupted work.
    #[error(transparent)]
    Execution(#[from] AsyncError),
}

impl Default for HostResumeHandshakePolicy {
    fn default() -> Self {
        Self {
            timeout_ms: DEFAULT_RESUME_HANDSHAKE_TIMEOUT_MS,
        }
    }
}

impl HostResumeHandshakePolicy {
    /// Create a host policy with the given timeout.
    #[must_use]
    pub const fn new(timeout_ms: u64) -> Self {
        Self { timeout_ms }
    }

    /// Validate that the target completed rehydration before the source lease
    /// release was accepted by the host.
    ///
    /// This validates transcript consistency only. Use
    /// [`Self::validate_restored_source_release`] to also require local payload
    /// reconstruction evidence; neither method proves a process is running.
    ///
    /// # Errors
    ///
    /// Returns [`ResumeHandshakeError`] if the transcript violates the
    /// canonical resume protocol or exceeds this host policy timeout.
    pub fn validate_source_release(
        &self,
        transcript: &ResumeHandshakeTranscript,
    ) -> Result<(), ResumeHandshakeError> {
        transcript.validate_success()?;
        let elapsed_ms = transcript
            .source_release
            .released_at_ms
            .saturating_sub(transcript.request.started_at_ms);
        let timeout_ms = if self.timeout_ms == 0 {
            DEFAULT_RESUME_HANDSHAKE_TIMEOUT_MS
        } else {
            self.timeout_ms
        };
        if elapsed_ms > timeout_ms {
            return Err(ResumeHandshakeError::Timeout {
                elapsed_ms,
                timeout_ms,
            });
        }
        Ok(())
    }

    /// Restore a signed snapshot through bounded asynchronous chunk retrieval.
    ///
    /// The parent context and the smaller host/request deadline cover manifest
    /// verification, every fetch, output write and final flush without resetting
    /// the budget. No tasks are spawned and no failed fetch or write is retried.
    /// `fetch` receives an exact content ID and expected byte length; it must
    /// enforce that length while reading, before allocating an unbounded body.
    /// At most one payload chunk is retained here in addition to the manifest.
    ///
    /// Use an inactive destination. Individual chunks are verified before
    /// writing, but a full-payload hash mismatch can still reject the completed
    /// destination. Do not publish or unmarshal it until this method succeeds.
    /// Flush is not fsync; no live process is activated and no lease is released.
    /// The caller must enforce peer authentication and current capability,
    /// revocation, zone and lease policy outside this byte-reconstruction step.
    ///
    /// # Errors
    /// Returns an error on invalid authority evidence, limits, clocks, integrity,
    /// I/O, cancellation or deadline. A failed destination may contain a prefix.
    pub async fn restore_snapshot<W, F, Fut>(
        &self,
        request: HostSnapshotRestoreRequest<'_>,
        context: &ExecutionContext,
        mut writer: W,
        mut fetch: F,
    ) -> Result<(W, HostSnapshotRestoreEvidence), HostSnapshotRestoreError>
    where
        W: AsyncWrite + Unpin,
        F: FnMut(ObjectId, usize) -> Fut,
        Fut: Future<Output = io::Result<RawChunk>>,
    {
        request.transcript.request.validate_identity()?;
        let source_request = &request.transcript.request;
        let timeout_ms = if self.timeout_ms == 0 {
            DEFAULT_RESUME_HANDSHAKE_TIMEOUT_MS
        } else {
            self.timeout_ms
        }
        .min(source_request.effective_timeout_ms());
        let elapsed_ms = request
            .observed_at_ms
            .checked_sub(source_request.started_at_ms)
            .ok_or_else(|| ResumeHandshakeError::OutOfOrder {
                reason: "restore observation predates the source request".into(),
            })?;
        if elapsed_ms >= timeout_ms {
            return Err(ResumeHandshakeError::Timeout {
                elapsed_ms,
                timeout_ms,
            }
            .into());
        }
        if request
            .transcript
            .symbols
            .last()
            .is_some_and(|symbol| request.observed_at_ms < symbol.sent_at_ms)
        {
            return Err(ResumeHandshakeError::OutOfOrder {
                reason: "restore observation predates the received manifest".into(),
            }
            .into());
        }
        let deadline = Deadline::after(Duration::from_millis(timeout_ms - elapsed_ms));

        context
            .run(deadline.run(async {
                let manifest = request.transcript.decode_verified_snapshot_manifest(
                    request.raptorq_config,
                    request.capability_token_bytes,
                    request.trust_anchors,
                )?;
                manifest
                    .chunk_manifest
                    .validate_layout()
                    .map_err(ChunkReconstructionError::from)?;
                let largest_chunk = manifest
                    .chunk_manifest
                    .total_len
                    .min(u64::from(manifest.chunk_manifest.chunk_size));
                if largest_chunk > u64::try_from(request.limits.max_chunk_bytes).unwrap_or(u64::MAX)
                {
                    return Err(HostSnapshotRestoreError::ChunkTooLarge {
                        size: largest_chunk,
                        max: request.limits.max_chunk_bytes,
                    });
                }
                // The shared reconstructor owns integrity accounting. Its sink
                // retains no bytes; verified bytes go to the async destination.
                let mut verifier = manifest.chunk_manifest.start_reconstruction(
                    io::sink(),
                    request.limits.max_payload_bytes,
                )?;
                while let Some(id) = verifier.next_chunk_id() {
                    check_restore_execution(context, deadline)?;
                    let expected = manifest
                        .chunk_manifest
                        .chunk_size_at(verifier.chunks_written())
                        .map_err(ChunkReconstructionError::from)?;
                    let chunk = fetch(id, expected).await?;
                    // Ready futures can cancel the parent without yielding.
                    // Recheck before writing or constructing another fetch.
                    check_restore_execution(context, deadline)?;
                    verifier.push(&chunk)?;
                    check_restore_execution(context, deadline)?;
                    writer.write_all(&chunk.bytes).await?;
                }
                verifier.finish()?;
                check_restore_execution(context, deadline)?;
                writer.flush().await?;
                check_restore_execution(context, deadline)?;
                Ok((
                    writer,
                    HostSnapshotRestoreEvidence {
                        handshake_id: source_request.handshake_id,
                        manifest,
                    },
                ))
            }))
            .await??
    }

    /// Require a locally verified payload for this exact release transcript.
    ///
    /// The evidence cannot be deserialized or constructed from peer metadata.
    /// Actual process rehydration and lease transfer remain the caller's work.
    ///
    /// # Errors
    /// Returns an error for a foreign restore receipt or invalid release.
    pub fn validate_restored_source_release(
        &self,
        transcript: &ResumeHandshakeTranscript,
        evidence: &HostSnapshotRestoreEvidence,
    ) -> Result<(), ResumeHandshakeError> {
        self.validate_source_release(transcript)?;
        if evidence.handshake_id != transcript.request.handshake_id
            || evidence.manifest.manifest_object_id()? != transcript.request.snapshot_manifest_hash
            || evidence.manifest.snapshot_id != transcript.request.snapshot_id
            || evidence.manifest.capability_token_pinned
                != transcript.request.capability_token_pinned
        {
            return Err(ResumeHandshakeError::LinkageMismatch {
                reason: "local payload restore evidence belongs to another handoff".into(),
            });
        }
        Ok(())
    }
}

fn check_restore_execution(
    context: &ExecutionContext,
    deadline: Deadline,
) -> Result<(), HostSnapshotRestoreError> {
    if context.is_cancelled() {
        return Err(AsyncError::Cancelled.into());
    }
    if deadline.is_expired()
        || context
            .remaining_budget()
            .is_some_and(|remaining| remaining.is_zero())
    {
        return Err(AsyncError::Timeout { timeout_ms: 0 }.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_policy_defaults_to_resume_timeout() {
        assert_eq!(
            HostResumeHandshakePolicy::default().timeout_ms,
            DEFAULT_RESUME_HANDSHAKE_TIMEOUT_MS
        );
    }
}
