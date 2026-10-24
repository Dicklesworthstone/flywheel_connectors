//! Host snapshot restoration crosses signature, chunk, async I/O and release gates.
//! No live credentials, remote service, or process-activation claim is involved.

use std::future::{Ready, pending, ready};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use fcp_async_core::io::AsyncWrite;
use fcp_async_core::{AsyncError, ExecutionContext};
use fcp_core::ObjectId;
use fcp_crypto::Ed25519SigningKey;
use fcp_host::{
    HostResumeHandshakePolicy, HostSnapshotRestoreError, HostSnapshotRestoreLimits,
    HostSnapshotRestoreRequest, ResumeHandshakeError, ResumeHandshakeRequest,
    ResumeHandshakeTranscript, ResumeSourceLeaseRelease, ResumeTargetAck, ResumeTargetComplete,
};
use fcp_raptorq::{
    ChunkReconstructionError, ChunkedObjectManifest, RaptorQConfig, RaptorQEncoder, RawChunk,
};
use fcp_store::{
    ObjectTransmissionInfo, ProcessSnapshotFormat, ProcessSnapshotManifest,
    ProcessSnapshotTrustAnchors,
};
use futures_util::poll;

const TOKEN: &[u8] = b"snapshot-restore-test-capability";

struct Fixture {
    transcript: ResumeHandshakeTranscript,
    config: RaptorQConfig,
    anchors: ProcessSnapshotTrustAnchors,
    chunks: Vec<RawChunk>,
}

impl Fixture {
    fn new(payload: &[u8], chunk_size: u32, poison_hash: bool) -> Self {
        let key = Ed25519SigningKey::from_bytes(&[9; 32]).unwrap();
        let (mut chunk_manifest, chunks) = ChunkedObjectManifest::from_payload(payload, chunk_size);
        if poison_hash {
            chunk_manifest.payload_hash[0] ^= 1;
        }
        let manifest = ProcessSnapshotManifest::sign(
            8080,
            "source-node",
            ProcessSnapshotFormat::Criu,
            chunk_manifest,
            TOKEN,
            &key,
        )
        .unwrap();
        let config = RaptorQConfig {
            symbol_size: 96,
            repair_ratio_bps: 500,
            max_object_size: 1024 * 1024,
            decode_timeout: Duration::from_secs(30),
            max_chunk_threshold: 1024,
            chunk_size: 256,
        };
        let bytes = manifest.canonical_bytes().unwrap();
        let encoder = RaptorQEncoder::new(&bytes, &config).unwrap();
        let request = ResumeHandshakeRequest::new(
            "source-node",
            "target-node",
            &manifest,
            ObjectTransmissionInfo::from_oti(encoder.transmission_info()),
            77,
            1_000,
            30_000,
            Vec::new(),
        )
        .unwrap();
        let ack = ResumeTargetAck::accept(&request, None, 1_001);
        let symbols = request
            .encode_snapshot_manifest_symbols(&bytes, &config, 1_002)
            .unwrap();
        let complete_at = symbols.last().unwrap().sent_at_ms + 1;
        let complete = ResumeTargetComplete::rehydrated(&request, Vec::new(), complete_at).unwrap();
        let source_release = ResumeSourceLeaseRelease::new(&request, complete_at + 1);
        Self {
            transcript: ResumeHandshakeTranscript {
                request,
                ack,
                symbols,
                complete,
                source_release,
            },
            config,
            anchors: ProcessSnapshotTrustAnchors::single(key.verifying_key()),
            chunks,
        }
    }

    fn request(&self) -> HostSnapshotRestoreRequest<'_> {
        HostSnapshotRestoreRequest {
            transcript: &self.transcript,
            raptorq_config: &self.config,
            capability_token_bytes: TOKEN,
            trust_anchors: &self.anchors,
            limits: HostSnapshotRestoreLimits {
                max_payload_bytes: 1024 * 1024,
                max_chunk_bytes: 4096,
            },
            observed_at_ms: self.transcript.symbols.last().unwrap().sent_at_ms,
        }
    }
}

#[derive(Default)]
struct Output {
    bytes: Vec<u8>,
    flushes: usize,
}

#[derive(Clone, Default)]
struct Writer {
    output: Arc<Mutex<Output>>,
    fail_after: Option<usize>,
    fail_flush: bool,
    pending_flush: bool,
}

impl AsyncWrite for Writer {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut output = self.output.lock().unwrap();
        let count = self.fail_after.map_or(bytes.len(), |max| {
            max.saturating_sub(output.bytes.len()).min(bytes.len())
        });
        if count == 0 && !bytes.is_empty() {
            return Poll::Ready(Err(io::Error::other("injected partial write failure")));
        }
        output.bytes.extend_from_slice(&bytes[..count]);
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.pending_flush {
            return Poll::Pending;
        }
        if self.fail_flush {
            return Poll::Ready(Err(io::Error::other("injected flush failure")));
        }
        self.output.lock().unwrap().flushes += 1;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

fn context() -> ExecutionContext {
    ExecutionContext::request_scoped(Duration::from_secs(30))
}

fn forbidden_fetch(_: ObjectId, _: usize) -> Ready<io::Result<RawChunk>> {
    panic!("this request must not admit a payload fetch")
}

#[fcp_async_core::runtime::test]
async fn restores_verified_payload_and_binds_release_to_the_exact_handoff() {
    let payload: Vec<u8> = (0..65_537_u32).map(|i| i.to_le_bytes()[0]).collect();
    let fixture = Fixture::new(&payload, 4096, false);
    let policy = HostResumeHandshakePolicy::default();
    let writer = Writer::default();
    let calls = AtomicUsize::new(0);
    let (writer, evidence) = policy
        .restore_snapshot(fixture.request(), &context(), writer, |id, expected| {
            let index = calls.fetch_add(1, Ordering::SeqCst);
            let chunk = &fixture.chunks[index];
            assert_eq!(id, chunk.content_id());
            assert_eq!(expected, chunk.len());
            ready(Ok(chunk.clone()))
        })
        .await
        .unwrap();
    assert_eq!(writer.output.lock().unwrap().bytes, payload);
    assert_eq!(writer.output.lock().unwrap().flushes, 1);
    assert_eq!(calls.load(Ordering::SeqCst), fixture.chunks.len());
    assert_eq!(evidence.manifest().chunk_manifest.total_len, 65_537);
    policy
        .validate_restored_source_release(&fixture.transcript, &evidence)
        .unwrap();
    let other = Fixture::new(b"another snapshot", 4, false);
    assert!(
        policy
            .validate_restored_source_release(&other.transcript, &evidence)
            .is_err()
    );

    // A valid second handoff of the SAME snapshot cannot borrow the receipt.
    let request = ResumeHandshakeRequest::new(
        "source-node",
        "other-target",
        evidence.manifest(),
        fixture.transcript.request.raptorq,
        78,
        1_000,
        30_000,
        Vec::new(),
    )
    .unwrap();
    let symbols = request
        .encode_snapshot_manifest_symbols(
            &evidence.manifest().canonical_bytes().unwrap(),
            &fixture.config,
            1_002,
        )
        .unwrap();
    let complete_at = symbols.last().unwrap().sent_at_ms + 1;
    let second_handoff = ResumeHandshakeTranscript {
        ack: ResumeTargetAck::accept(&request, None, 1_001),
        complete: ResumeTargetComplete::rehydrated(&request, Vec::new(), complete_at).unwrap(),
        source_release: ResumeSourceLeaseRelease::new(&request, complete_at + 1),
        request,
        symbols,
    };
    second_handoff.validate_success().unwrap();
    assert!(matches!(
        policy.validate_restored_source_release(&second_handoff, &evidence),
        Err(ResumeHandshakeError::LinkageMismatch { .. })
    ));
}

#[fcp_async_core::runtime::test]
async fn payload_and_chunk_limits_refuse_before_fetch_or_output() {
    let fixture = Fixture::new(b"abcdefgh", 4, false);
    for chunk_limit in [false, true] {
        let mut request = fixture.request();
        if chunk_limit {
            request.limits.max_chunk_bytes = 3;
        } else {
            request.limits.max_payload_bytes = 7;
        }
        let writer = Writer::default();
        let output = Arc::clone(&writer.output);
        let result = HostResumeHandshakePolicy::default()
            .restore_snapshot(request, &context(), writer, forbidden_fetch)
            .await;
        assert!(matches!(
            result,
            Err(HostSnapshotRestoreError::ChunkTooLarge { .. })
                | Err(HostSnapshotRestoreError::Reconstruction(
                    ChunkReconstructionError::PayloadTooLarge { .. }
                ))
        ));
        assert!(output.lock().unwrap().bytes.is_empty());
        assert_eq!(output.lock().unwrap().flushes, 0);
    }
}

#[fcp_async_core::runtime::test]
async fn signature_and_capability_failures_never_fetch_payload_bytes() {
    let fixture = Fixture::new(b"abcdefgh", 4, false);
    let no_anchors = ProcessSnapshotTrustAnchors::default();
    for wrong_token in [false, true] {
        let mut request = fixture.request();
        if wrong_token {
            request.capability_token_bytes = b"wrong-token";
        } else {
            request.trust_anchors = &no_anchors;
        }
        let writer = Writer::default();
        let output = Arc::clone(&writer.output);
        let result = HostResumeHandshakePolicy::default()
            .restore_snapshot(request, &context(), writer, forbidden_fetch)
            .await;
        assert!(matches!(
            result,
            Err(HostSnapshotRestoreError::Handshake(
                ResumeHandshakeError::Snapshot(_)
            ))
        ));
        assert!(output.lock().unwrap().bytes.is_empty());
        assert_eq!(output.lock().unwrap().flushes, 0);
    }
}

#[fcp_async_core::runtime::test]
async fn corrupted_first_chunk_is_rejected_before_writing() {
    let fixture = Fixture::new(b"abcdefgh", 4, false);
    let writer = Writer::default();
    let output = Arc::clone(&writer.output);
    let calls = AtomicUsize::new(0);
    let result = HostResumeHandshakePolicy::default()
        .restore_snapshot(fixture.request(), &context(), writer, |_, expected| {
            calls.fetch_add(1, Ordering::SeqCst);
            ready(Ok(RawChunk::new(vec![0; expected])))
        })
        .await;
    assert!(matches!(
        result,
        Err(HostSnapshotRestoreError::Reconstruction(_))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(output.lock().unwrap().bytes.is_empty());
}

#[fcp_async_core::runtime::test]
async fn signed_but_inconsistent_full_hash_never_produces_a_flushed_success() {
    let fixture = Fixture::new(b"abcdefgh", 4, true);
    let writer = Writer::default();
    let output = Arc::clone(&writer.output);
    let calls = AtomicUsize::new(0);
    let result = HostResumeHandshakePolicy::default()
        .restore_snapshot(fixture.request(), &context(), writer, |_, _| {
            let index = calls.fetch_add(1, Ordering::SeqCst);
            ready(Ok(fixture.chunks[index].clone()))
        })
        .await;
    assert!(matches!(
        result,
        Err(HostSnapshotRestoreError::Reconstruction(_))
    ));
    assert_eq!(output.lock().unwrap().bytes, b"abcdefgh");
    assert_eq!(output.lock().unwrap().flushes, 0);
}

#[fcp_async_core::runtime::test]
async fn ready_fetch_cancellation_stops_before_writing_its_chunk() {
    let fixture = Fixture::new(b"abcdefgh", 4, false);
    let context = context();
    let writer = Writer::default();
    let output = Arc::clone(&writer.output);
    let calls = AtomicUsize::new(0);
    let result = HostResumeHandshakePolicy::default()
        .restore_snapshot(fixture.request(), &context, writer, |_, _| {
            let index = calls.fetch_add(1, Ordering::SeqCst);
            if index == 1 {
                context.cancel();
            }
            ready(Ok(fixture.chunks[index].clone()))
        })
        .await;
    assert!(matches!(
        result,
        Err(HostSnapshotRestoreError::Execution(AsyncError::Cancelled))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(output.lock().unwrap().bytes, b"abcd");
    assert_eq!(output.lock().unwrap().flushes, 0);
}

struct Dropped(Arc<AtomicBool>);

impl Drop for Dropped {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[fcp_async_core::runtime::test]
async fn cancelling_a_hung_fetch_drops_it_without_orphaned_work() {
    let fixture = Fixture::new(b"abcdefgh", 4, false);
    let context = context();
    let policy = HostResumeHandshakePolicy::default();
    let dropped = Arc::new(AtomicBool::new(false));
    let mut run = Box::pin(policy.restore_snapshot(
        fixture.request(),
        &context,
        Writer::default(),
        |_, _| {
            let guard = Dropped(Arc::clone(&dropped));
            async move {
                let _guard = guard;
                pending::<io::Result<RawChunk>>().await
            }
        },
    ));
    assert!(poll!(run.as_mut()).is_pending());
    context.cancel();
    assert!(matches!(
        run.await,
        Err(HostSnapshotRestoreError::Execution(AsyncError::Cancelled))
    ));
    assert!(dropped.load(Ordering::SeqCst));
}

#[fcp_async_core::runtime::test]
async fn a_hung_fetch_obeys_the_remaining_host_deadline() {
    let fixture = Fixture::new(b"abcdefgh", 4, false);
    let elapsed = fixture.request().observed_at_ms - fixture.transcript.request.started_at_ms;
    let policy = HostResumeHandshakePolicy::new(elapsed + 100);
    let result = fcp_async_core::time::timeout(
        Duration::from_secs(2),
        policy.restore_snapshot(fixture.request(), &context(), Writer::default(), |_, _| {
            pending::<io::Result<RawChunk>>()
        }),
    )
    .await
    .expect("host deadline must bound pending fetch");
    assert!(matches!(
        result,
        Err(HostSnapshotRestoreError::Execution(AsyncError::Timeout { .. }))
    ));
}

#[fcp_async_core::runtime::test]
async fn partial_write_and_flush_failures_are_not_retried_or_certified() {
    let fixture = Fixture::new(b"abcdefgh", 4, false);
    for flush in [false, true] {
        let writer = Writer {
            fail_after: (!flush).then_some(1),
            fail_flush: flush,
            ..Writer::default()
        };
        let output = Arc::clone(&writer.output);
        let calls = AtomicUsize::new(0);
        let result = HostResumeHandshakePolicy::default()
            .restore_snapshot(fixture.request(), &context(), writer, |_, _| {
                let index = calls.fetch_add(1, Ordering::SeqCst);
                ready(Ok(fixture.chunks[index].clone()))
            })
            .await;
        assert!(matches!(result, Err(HostSnapshotRestoreError::Io(_))));
        assert_eq!(calls.load(Ordering::SeqCst), if flush { 2 } else { 1 });
        assert_eq!(output.lock().unwrap().bytes.len(), if flush { 8 } else { 1 });
        assert_eq!(output.lock().unwrap().flushes, 0);
    }
}

#[fcp_async_core::runtime::test]
async fn cancellation_covers_final_output_flush() {
    let fixture = Fixture::new(b"abcdefgh", 4, false);
    let context = context();
    let policy = HostResumeHandshakePolicy::default();
    let writer = Writer {
        pending_flush: true,
        ..Writer::default()
    };
    let output = Arc::clone(&writer.output);
    let calls = AtomicUsize::new(0);
    let mut run = Box::pin(policy.restore_snapshot(fixture.request(), &context, writer, |_, _| {
        let index = calls.fetch_add(1, Ordering::SeqCst);
        ready(Ok(fixture.chunks[index].clone()))
    }));
    assert!(poll!(run.as_mut()).is_pending());
    assert_eq!(output.lock().unwrap().bytes, b"abcdefgh");
    context.cancel();
    assert!(matches!(
        run.await,
        Err(HostSnapshotRestoreError::Execution(AsyncError::Cancelled))
    ));
    assert_eq!(output.lock().unwrap().flushes, 0);
}

#[fcp_async_core::runtime::test]
async fn parent_cancellation_and_expiration_refuse_before_fetching() {
    let fixture = Fixture::new(b"abcdefgh", 4, false);
    for cancelled in [false, true] {
        let context = if cancelled {
            context()
        } else {
            ExecutionContext::request_scoped(Duration::ZERO)
        };
        if cancelled {
            context.cancel();
        }
        let result = HostResumeHandshakePolicy::default()
            .restore_snapshot(fixture.request(), &context, Writer::default(), forbidden_fetch)
            .await;
        assert!(matches!(result, Err(HostSnapshotRestoreError::Execution(_))));
    }
}

#[fcp_async_core::runtime::test]
async fn invalid_host_observation_and_elapsed_policy_refuse_before_fetching() {
    let fixture = Fixture::new(b"abcdefgh", 4, false);
    for observed in [999, 1_001, 31_001] {
        let mut request = fixture.request();
        request.observed_at_ms = observed;
        let result = HostResumeHandshakePolicy::default()
            .restore_snapshot(request, &context(), Writer::default(), forbidden_fetch)
            .await;
        assert!(matches!(result, Err(HostSnapshotRestoreError::Handshake(_))));
    }
}

#[fcp_async_core::runtime::test]
async fn empty_snapshot_needs_no_chunk_fetch_but_still_verifies_and_flushes() {
    let fixture = Fixture::new(&[], 4, false);
    let mut request = fixture.request();
    request.limits = HostSnapshotRestoreLimits {
        max_payload_bytes: 0,
        max_chunk_bytes: 0,
    };
    let (writer, evidence) = HostResumeHandshakePolicy::default()
        .restore_snapshot(request, &context(), Writer::default(), forbidden_fetch)
        .await
        .unwrap();
    assert!(writer.output.lock().unwrap().bytes.is_empty());
    assert_eq!(writer.output.lock().unwrap().flushes, 1);
    assert_eq!(evidence.manifest().chunk_manifest.total_len, 0);
}

#[test]
fn request_debug_does_not_disclose_capability_material() {
    let fixture = Fixture::new(b"abcdefgh", 4, false);
    assert!(!format!("{:?}", fixture.request()).contains(std::str::from_utf8(TOKEN).unwrap()));
}

#[fcp_async_core::runtime::test]
async fn wrong_chunk_length_or_missing_chunk_stops_without_retrying() {
    let fixture = Fixture::new(b"abcdefgh", 4, false);
    for missing in [false, true] {
        let writer = Writer::default();
        let output = Arc::clone(&writer.output);
        let calls = AtomicUsize::new(0);
        let result = HostResumeHandshakePolicy::default()
            .restore_snapshot(fixture.request(), &context(), writer, |_, expected| {
                calls.fetch_add(1, Ordering::SeqCst);
                ready(if missing {
                    Err(io::Error::new(io::ErrorKind::NotFound, "chunk is missing"))
                } else {
                    Ok(RawChunk::new(vec![0; expected + 1]))
                })
            })
            .await;
        if missing {
            assert!(matches!(result, Err(HostSnapshotRestoreError::Io(_))));
        } else {
            assert!(matches!(
                result,
                Err(HostSnapshotRestoreError::Reconstruction(_))
            ));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(output.lock().unwrap().bytes.is_empty());
        assert_eq!(output.lock().unwrap().flushes, 0);
    }
}

#[fcp_async_core::runtime::test]
async fn dropping_the_restore_waiter_drops_the_pending_fetch() {
    let fixture = Fixture::new(b"abcdefgh", 4, false);
    let context = context();
    let policy = HostResumeHandshakePolicy::default();
    let dropped = Arc::new(AtomicBool::new(false));
    let mut run = Box::pin(policy.restore_snapshot(
        fixture.request(),
        &context,
        Writer::default(),
        |_, _| {
            let guard = Dropped(Arc::clone(&dropped));
            async move {
                let _guard = guard;
                pending::<io::Result<RawChunk>>().await
            }
        },
    ));
    assert!(poll!(run.as_mut()).is_pending());
    assert!(!dropped.load(Ordering::SeqCst));
    drop(run);
    assert!(dropped.load(Ordering::SeqCst));
}

#[fcp_async_core::runtime::test]
async fn actual_final_chunk_size_not_nominal_size_controls_admission() {
    let fixture = Fixture::new(b"tiny", u32::MAX, false);
    let mut request = fixture.request();
    request.limits = HostSnapshotRestoreLimits {
        max_payload_bytes: 4,
        max_chunk_bytes: 4,
    };
    let calls = AtomicUsize::new(0);
    let (writer, _) = HostResumeHandshakePolicy::default()
        .restore_snapshot(request, &context(), Writer::default(), |id, expected| {
            assert_eq!(calls.fetch_add(1, Ordering::SeqCst), 0);
            assert_eq!(expected, 4);
            assert_eq!(id, fixture.chunks[0].content_id());
            ready(Ok(fixture.chunks[0].clone()))
        })
        .await
        .unwrap();
    assert_eq!(writer.output.lock().unwrap().bytes, b"tiny");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[fcp_async_core::runtime::test]
async fn a_larger_host_policy_cannot_extend_the_request_deadline() {
    let fixture = Fixture::new(b"abcdefgh", 4, false);
    let mut request = fixture.request();
    request.observed_at_ms = fixture.transcript.request.started_at_ms + 30_000;
    let result = HostResumeHandshakePolicy::new(60_000)
        .restore_snapshot(request, &context(), Writer::default(), forbidden_fetch)
        .await;
    assert!(matches!(
        result,
        Err(HostSnapshotRestoreError::Handshake(
            ResumeHandshakeError::Timeout {
                timeout_ms: 30_000,
                ..
            }
        ))
    ));
}
