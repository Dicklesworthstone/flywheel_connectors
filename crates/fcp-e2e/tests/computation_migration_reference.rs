//! Reference connector migration test for `whisper.transcribe`.
//!
//! The test exercises the live migration substrate end-to-end: checkpoint a
//! multi-megabyte transcription state as a CRIU snapshot, transfer the lease to
//! another mesh node, validate resume evidence, replay in-flight effects, and
//! complete through the Whisper connector without re-uploading the audio bytes.

#![cfg(feature = "whisper")]

use std::error::Error;

use fcp_core::{
    CheckpointHandoffArtifact, CheckpointTransferEncoding, ComputationCheckpoint,
    DuplicateDeliveryClass, HandoffArtifactInputs, Lease, LeaseHandoff, LeaseId, LeaseParams,
    LeasePurpose, MigratableComputation, MigrationCapabilityContext, ObjectHeader, ObjectId,
    Provenance, ResumeCause, ResumeDisposition, ResumeEvidence, ResumeEvidenceInputs,
    ResumeOutcome as CoreResumeOutcome, SignatureSet, TailscaleNodeId, Uuid, ZoneId,
    current_timestamp,
};
use fcp_crypto::Ed25519SigningKey;
use fcp_host::HostResumeHandshakePolicy;
use fcp_kernel::ComputationPhase;
use fcp_raptorq::{
    ChunkedObjectManifest as RaptorQChunkedObjectManifest, RaptorQConfig, RaptorQEncoder, RawChunk,
};
use fcp_store::{
    DEFAULT_RESUME_HANDSHAKE_TIMEOUT_MS, ObjectTransmissionInfo, ProcessSnapshotFormat,
    ProcessSnapshotManifest, ProcessSnapshotTrustAnchors, ResumeHandshakeRequest,
    ResumeHandshakeTranscript, ResumeReplayOp, ResumeSnapshotSymbol, ResumeSourceLeaseRelease,
    ResumeTargetAck, ResumeTargetComplete,
};
use fcp_testkit::MockApiServer;
use fcp_whisper::connector::WhisperConnector;
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};
use toml::Value as TomlValue;
use wiremock::{
    Mock, ResponseTemplate,
    matchers::{method, path},
};

const OPERATION_ID: &str = "whisper.transcribe";
const SOURCE_NODE: &str = "node-alpha";
const TARGET_NODE: &str = "node-bravo";
const AUDIO_BYTES: usize = 2 * 1024 * 1024 + 257;
const TOTAL_SEGMENTS: u32 = 64;
const CHECKPOINT_AFTER_SEGMENT: u32 = 23;
const REPLAY_SEGMENTS: u32 = 3;
const CAPABILITY_TOKEN: &[u8] = b"fcp-e2e-whisper-migrate-resume-capability-token";
const AUDIO_DURATION_SECONDS: u64 = 131;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct WhisperTranscribeState {
    operation_id: String,
    model: String,
    audio_bytes: Vec<u8>,
    audio_digest: [u8; 32],
    cursor: u32,
    phase: ComputationPhase,
    transcript: String,
    completed: bool,
    retry_count: u32,
    audio_reuploads: u32,
}

impl WhisperTranscribeState {
    fn new(audio_bytes: Vec<u8>) -> Self {
        Self {
            operation_id: OPERATION_ID.to_string(),
            model: "whisper-1".to_string(),
            audio_digest: *blake3::hash(&audio_bytes).as_bytes(),
            audio_bytes,
            cursor: 0,
            phase: ComputationPhase::Initializing,
            transcript: String::new(),
            completed: false,
            retry_count: 0,
            audio_reuploads: 0,
        }
    }

    fn advance_next_segment(&mut self) -> WhisperSegmentEffect {
        assert!(
            self.cursor < TOTAL_SEGMENTS,
            "cannot advance completed transcription"
        );
        self.phase = ComputationPhase::Processing;

        let segment_index = self.cursor;
        let range = segment_range(segment_index, self.audio_bytes.len());
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"FCP-E2E-WHISPER-TRANSCRIBE-SEGMENT-V1");
        hasher.update(self.operation_id.as_bytes());
        hasher.update(&self.audio_digest);
        hasher.update(&segment_index.to_le_bytes());
        hasher.update(&self.audio_bytes[range]);
        let effect_digest = *hasher.finalize().as_bytes();
        let effect_hex = blake3::Hash::from_bytes(effect_digest).to_hex().to_string();

        if !self.transcript.is_empty() {
            self.transcript.push(' ');
        }
        self.transcript
            .push_str(&format!("w{segment_index:02}_{}", &effect_hex[..12]));
        self.cursor = self.cursor.saturating_add(1);

        if self.cursor == TOTAL_SEGMENTS {
            self.phase = ComputationPhase::Finalizing;
            self.completed = true;
            self.phase = ComputationPhase::Completed;
        }

        WhisperSegmentEffect {
            segment_index,
            effect_digest,
        }
    }

    fn advance_until(&mut self, target_cursor: u32) {
        while self.cursor < target_cursor {
            self.advance_next_segment();
        }
    }

    fn complete_remaining(&mut self) {
        while self.cursor < TOTAL_SEGMENTS {
            self.advance_next_segment();
        }
    }

    fn mark_suspended(&mut self) {
        self.phase = ComputationPhase::Suspended;
    }

    fn audio_digest_hex(&self) -> String {
        blake3::Hash::from_bytes(self.audio_digest)
            .to_hex()
            .to_string()
    }

    fn output_json(&self) -> JsonValue {
        assert!(self.completed, "cannot emit incomplete transcription");
        json!({
            "text": self.transcript,
            "language": "en",
            "duration_seconds": AUDIO_DURATION_SECONDS,
            "segments": [],
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct WhisperSegmentEffect {
    segment_index: u32,
    effect_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReplayRecord {
    segment_index: u32,
    op: ResumeReplayOp,
}

struct ResumeArtifacts {
    transcript: ResumeHandshakeTranscript,
    verified_manifest: ProcessSnapshotManifest,
    chunks: Vec<RawChunk>,
}

#[fcp_async_core::runtime::test]
async fn migrate_resume_whisper_transcribe_criu_checkpoint_migration_resume_completion()
-> Result<(), Box<dyn Error>> {
    assert_whisper_manifest_declares_migration_supported();

    let audio = deterministic_audio_bytes(AUDIO_BYTES);
    let mut baseline = WhisperTranscribeState::new(audio.clone());
    baseline.complete_remaining();
    let baseline_output = baseline.output_json();

    let mut source_state = WhisperTranscribeState::new(audio);
    source_state.advance_until(CHECKPOINT_AFTER_SEGMENT);
    source_state.mark_suspended();

    let zone_id = ZoneId::work();
    let source_holder = TailscaleNodeId::new(SOURCE_NODE);
    let target_holder = TailscaleNodeId::new(TARGET_NODE);
    let computation_id = object_id("whisper-transcribe-long-running-computation");
    let source_lease_id = object_id("whisper-transcribe-source-lease");
    let target_lease_id = object_id("whisper-transcribe-target-lease");
    let source_seq = 41;
    let target_seq = 42;
    let mut computation = MigratableComputation::new(
        computation_id,
        zone_id.clone(),
        source_holder.clone(),
        source_lease_id,
        source_seq,
        MigrationCapabilityContext {
            capability_token_jti: Uuid::from_bytes([0x32; 16]),
            checkpoint_id: None,
            checkpoint_seq: 0,
            audit_event_id: Some(object_id("whisper-transcribe-audit-event")),
        },
    );
    let source_lease = migration_lease(
        zone_id.clone(),
        source_holder.clone(),
        source_seq,
        computation_id,
    );
    let target_lease = migration_lease(
        zone_id.clone(),
        target_holder.clone(),
        target_seq,
        computation_id,
    );
    let checkpoint = computation_checkpoint(&computation, &source_state, source_lease_id)?;
    let checkpoint_object_id = checkpoint.object_id()?;
    let transfer_encoding = checkpoint.to_transfer_encoding(128 * 1024, 64 * 1024)?;
    assert!(
        matches!(transfer_encoding, CheckpointTransferEncoding::Chunked(_)),
        "multi-megabyte whisper checkpoint should use chunked transfer"
    );

    computation.suspend(&checkpoint, checkpoint_object_id)?;

    let handoff = LeaseHandoff {
        previous_lease_id: source_lease_id,
        next_lease_id: target_lease_id,
        from_holder: source_holder,
        to_holder: target_holder.clone(),
        zone_id: zone_id.clone(),
        subject_object_id: computation_id,
        purpose: LeasePurpose::ComputationMigration,
        previous_fencing_token: source_seq,
        next_fencing_token: target_seq,
        transferred_at: current_timestamp(),
        checkpoint_object_id: Some(checkpoint_object_id),
    };
    let now = current_timestamp();
    computation.begin_transfer(&source_lease, &handoff, now)?;
    let handoff_artifact = CheckpointHandoffArtifact::capture(
        &computation,
        &checkpoint,
        checkpoint_object_id,
        &transfer_encoding,
        &handoff,
        &HandoffArtifactInputs {
            state_object_id: Some(object_id("whisper-transcribe-state-object")),
            receipt_head: Some(object_id("whisper-transcribe-receipt-head")),
            resume_cause: ResumeCause::PlannedHandoff,
            observed_at_ms: 10_000,
        },
    )?;
    assert_eq!(handoff_artifact.lease_lineage.resumed_holder, target_holder);
    assert_eq!(handoff_artifact.resume_cause, ResumeCause::PlannedHandoff);

    source_state.phase = ComputationPhase::Processing;
    let replay_records = advance_source_after_checkpoint(&mut source_state, REPLAY_SEGMENTS);
    let snapshot_payload = checkpoint.state_cbor.clone();
    let resume_artifacts = run_criu_resume_handshake(&snapshot_payload, &replay_records)?;

    let mut target_state = rehydrate_whisper_state(
        &resume_artifacts.verified_manifest,
        &resume_artifacts.chunks,
    )?;
    target_state.phase = ComputationPhase::Processing;
    replay_on_target(&mut target_state, &replay_records);
    assert_eq!(
        target_state.cursor, source_state.cursor,
        "target replay must match source in-flight progress"
    );

    let resume_evidence = ResumeEvidence::evaluate(
        &computation,
        &checkpoint,
        checkpoint_object_id,
        target_lease_id,
        &target_lease,
        now,
        &ResumeEvidenceInputs {
            state_object_id: Some(object_id("whisper-transcribe-state-object")),
            receipt_head: Some(object_id("whisper-transcribe-receipt-head")),
            resume_cause: ResumeCause::PlannedHandoff,
            duplicate_delivery_class: DuplicateDeliveryClass::DuplicateCommitted,
            disposition: ResumeDisposition::Attach,
            observed_at_ms: 10_010,
        },
    )?;
    assert_eq!(resume_evidence.outcome, CoreResumeOutcome::Accepted);
    assert!(resume_evidence.validation_error.is_none());
    assert!(resume_evidence.freshness.allows_resume());

    computation.resume(
        &checkpoint,
        checkpoint_object_id,
        target_lease_id,
        &target_lease,
        now,
    )?;
    assert_eq!(computation.current_holder, target_holder);

    target_state.complete_remaining();
    assert_eq!(
        target_state.output_json(),
        baseline_output,
        "migrated whisper output must match non-migrated baseline byte-for-byte"
    );
    assert_eq!(target_state.retry_count, 0);
    assert_eq!(target_state.audio_reuploads, 0);

    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/audio/transcriptions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "text": target_state.transcript,
            "language": "en",
            "duration": AUDIO_DURATION_SECONDS,
            "segments": [],
        })))
        .mount(mock.inner())
        .await;

    let mut connector = WhisperConnector::new();
    connector
        .handle_configure(json!({
            "api_key": "test-key",
            "base_url": mock.base_url(),
        }))
        .await?;
    connector
        .handle_handshake(json!({ "session_id": "migrate-resume-whisper" }))
        .await?;

    let checkpoint_audio_url = format!(
        "fcp-checkpoint://{}/{}",
        resume_artifacts.transcript.request.handshake_id,
        target_state.audio_digest_hex()
    );
    let connector_output = connector
        .handle_invoke(json!({
            "operation_id": OPERATION_ID,
            "input": {
                "audio_url": checkpoint_audio_url,
                "model": "whisper-1",
                "language": "en",
            },
        }))
        .await?;
    assert_eq!(connector_output, baseline_output);

    let received = mock.received_requests().await;
    assert_eq!(received.len(), 1, "resume should complete with one invoke");
    let request_body: JsonValue = serde_json::from_slice(&received[0].body)?;
    assert_eq!(request_body["audio_url"], checkpoint_audio_url);
    assert!(
        request_body.get("audio_base64").is_none() || request_body["audio_base64"].is_null(),
        "resumed invoke must not re-upload audio bytes"
    );
    assert_eq!(
        resume_artifacts.verified_manifest.snapshot_format,
        ProcessSnapshotFormat::Criu
    );

    Ok(())
}

fn assert_whisper_manifest_declares_migration_supported() {
    let manifest: TomlValue =
        toml::from_str(include_str!("../../../connectors/whisper/manifest.toml"))
            .expect("whisper manifest parses");
    let operation = manifest
        .get("provides")
        .and_then(TomlValue::as_table)
        .and_then(|provides| provides.get("operations"))
        .and_then(TomlValue::as_table)
        .and_then(|operations| operations.get(OPERATION_ID))
        .and_then(TomlValue::as_table)
        .expect("whisper.transcribe operation exists");

    assert_eq!(
        operation
            .get("migration_supported")
            .and_then(TomlValue::as_bool),
        Some(true),
        "whisper.transcribe must explicitly opt into migration"
    );
}

fn deterministic_audio_bytes(len: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(len);
    let mut counter = 0_u64;
    while bytes.len() < len {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"FCP-E2E-WHISPER-MIGRATION-AUDIO-V1");
        hasher.update(&counter.to_le_bytes());
        bytes.extend_from_slice(hasher.finalize().as_bytes());
        counter = counter.saturating_add(1);
    }
    bytes.truncate(len);
    bytes
}

fn segment_range(segment_index: u32, audio_len: usize) -> std::ops::Range<usize> {
    let start = usize::try_from(segment_index)
        .unwrap_or(0)
        .saturating_mul(audio_len)
        / usize::try_from(TOTAL_SEGMENTS).unwrap_or(1);
    let end = usize::try_from(segment_index.saturating_add(1))
        .unwrap_or(usize::MAX)
        .saturating_mul(audio_len)
        / usize::try_from(TOTAL_SEGMENTS).unwrap_or(1);
    start..end.min(audio_len)
}

fn migration_lease(
    zone_id: ZoneId,
    holder: TailscaleNodeId,
    lease_seq: u64,
    subject_object_id: ObjectId,
) -> Lease {
    Lease::new(LeaseParams {
        schema: ComputationCheckpoint::schema(),
        provenance: Provenance::new(zone_id.clone()),
        zone_id,
        holder,
        lease_seq,
        ttl_secs: 600,
        subject_object_id,
        purpose: LeasePurpose::ComputationMigration,
        quorum_signatures: SignatureSet::new(),
    })
}

fn object_id(label: &str) -> ObjectId {
    ObjectId::from_unscoped_bytes(label.as_bytes())
}

fn computation_checkpoint(
    computation: &MigratableComputation,
    state: &WhisperTranscribeState,
    lease_id: LeaseId,
) -> Result<ComputationCheckpoint, Box<dyn Error>> {
    let state_cbor = encode_whisper_state(state)?;
    Ok(ComputationCheckpoint {
        header: ObjectHeader {
            encryption_kind: Default::default(),
            schema: ComputationCheckpoint::schema(),
            zone_id: computation.zone_id.clone(),
            created_at: current_timestamp(),
            provenance: Provenance::new(computation.zone_id.clone()),
            refs: vec![computation.computation_id, computation.execution_lease_id],
            foreign_refs: Vec::new(),
            ttl_secs: Some(600),
            placement: None,
        },
        computation_id: computation.computation_id,
        current_holder: computation.current_holder.clone(),
        checkpoint_seq: 1,
        suspended_at: current_timestamp(),
        lease_id,
        lease_fencing_token: computation.lease_fencing_token,
        capability_context: MigrationCapabilityContext {
            checkpoint_seq: 1,
            ..computation.capability_context.clone()
        },
        state_cbor,
    })
}

fn run_criu_resume_handshake(
    snapshot_payload: &[u8],
    replay_records: &[ReplayRecord],
) -> Result<ResumeArtifacts, Box<dyn Error>> {
    let signing_key = Ed25519SigningKey::from_bytes(&[0x57; 32])?;
    let anchors = ProcessSnapshotTrustAnchors::single(signing_key.verifying_key());
    let raptorq_config = RaptorQConfig::default();
    let (chunk_manifest, chunks) =
        RaptorQChunkedObjectManifest::from_payload(snapshot_payload, 64 * 1024);
    let manifest = ProcessSnapshotManifest::sign(
        32_103,
        SOURCE_NODE,
        ProcessSnapshotFormat::Criu,
        chunk_manifest,
        CAPABILITY_TOKEN,
        &signing_key,
    )?;
    let manifest_bytes = manifest.canonical_bytes()?;
    let encoder = RaptorQEncoder::new(&manifest_bytes, &raptorq_config)?;
    let replay_ops = replay_records
        .iter()
        .map(|record| record.op.clone())
        .collect::<Vec<_>>();
    let request = ResumeHandshakeRequest::new(
        SOURCE_NODE,
        TARGET_NODE,
        &manifest,
        ObjectTransmissionInfo::from_oti(encoder.transmission_info()),
        42,
        20_000,
        DEFAULT_RESUME_HANDSHAKE_TIMEOUT_MS,
        replay_ops.clone(),
    )?;
    let ack = ResumeTargetAck::accept(&request, Some("whisper-resume-slot".to_string()), 20_001);
    let symbols =
        request.encode_snapshot_manifest_symbols(&manifest_bytes, &raptorq_config, 20_002)?;
    let complete =
        ResumeTargetComplete::rehydrated(&request, replay_ops, last_symbol_at(&symbols) + 1)?;
    let source_release = ResumeSourceLeaseRelease::new(&request, complete.resumed_at_ms + 1);
    let transcript = ResumeHandshakeTranscript {
        request,
        ack,
        symbols,
        complete,
        source_release,
    };

    transcript.validate_success()?;
    HostResumeHandshakePolicy::default().validate_source_release(&transcript)?;
    let verified_manifest = transcript.decode_verified_snapshot_manifest(
        &raptorq_config,
        CAPABILITY_TOKEN,
        &anchors,
    )?;

    Ok(ResumeArtifacts {
        transcript,
        verified_manifest,
        chunks,
    })
}

fn advance_source_after_checkpoint(
    state: &mut WhisperTranscribeState,
    replay_segments: u32,
) -> Vec<ReplayRecord> {
    let mut records = Vec::with_capacity(usize::try_from(replay_segments).unwrap_or(0));
    for _ in 0..replay_segments {
        let effect = state.advance_next_segment();
        records.push(ReplayRecord {
            segment_index: effect.segment_index,
            op: ResumeReplayOp::from_effect(
                format!("whisper.transcribe.segment.{}", effect.segment_index),
                &effect.effect_digest,
            ),
        });
    }
    records
}

fn replay_on_target(state: &mut WhisperTranscribeState, replay_records: &[ReplayRecord]) {
    for record in replay_records {
        assert_eq!(
            state.cursor, record.segment_index,
            "target replay cursor must match source in-flight segment"
        );
        let effect = state.advance_next_segment();
        let replayed = ResumeReplayOp::from_effect(record.op.op_id.clone(), &effect.effect_digest);
        assert_eq!(replayed, record.op);
    }
}

fn encode_whisper_state(state: &WhisperTranscribeState) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(state, &mut bytes)?;
    Ok(bytes)
}

fn rehydrate_whisper_state(
    manifest: &ProcessSnapshotManifest,
    chunks: &[RawChunk],
) -> Result<WhisperTranscribeState, Box<dyn Error>> {
    let payload = manifest.chunk_manifest.reconstruct(chunks)?;
    Ok(ciborium::from_reader(&payload[..])?)
}

fn last_symbol_at(symbols: &[ResumeSnapshotSymbol]) -> u64 {
    symbols.last().map_or(0, |symbol| symbol.sent_at_ms)
}
