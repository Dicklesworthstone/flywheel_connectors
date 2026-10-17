//! Incremental observation of one append-only journal, not writer recovery.
//!
//! A partial final frame waits for a later poll. Invalid complete records and
//! observed truncation permanently fence this reader. Earlier returned batches
//! are only observed prefixes; they cannot prove that unread history is valid.

use super::{
    AuditEntry, BTreeMap, File, HybridLogicalTimestamp, INVOKE_AUDIT_MAX_ENTRIES,
    INVOKE_AUDIT_MAX_JOURNAL_BYTES, INVOKE_AUDIT_MAX_RECORD_BYTES, InvokeAuditSnapshotError,
    JOURNAL_V1_MAGIC, Path, Seek, SeekFrom, decode_record, open_snapshot_source, read_exact_at,
    source_io, valid_successor,
};

/// Maximum number of complete records retained in one follower batch.
pub const INVOKE_AUDIT_FOLLOW_BATCH_RECORDS: usize = 128;

struct ZoneTip {
    id: String,
    seq: u64,
    occurred_at: u64,
    hlc: HybridLogicalTimestamp,
}

impl From<&AuditEntry> for ZoneTip {
    fn from(entry: &AuditEntry) -> Self {
        Self {
            id: entry.id.clone(),
            seq: entry.seq,
            occurred_at: entry.occurred_at,
            hlc: entry.hlc.clone(),
        }
    }
}

/// Newly observed records and cumulative prefix evidence from one poll.
///
/// Only the complete prefix is hashed. `observed_bytes` may include a partial
/// frame or unread backlog, neither of which is validated by this batch.
/// Fields cannot be supplied by deserializing an untrusted observation claim.
pub struct InvokeAuditFollowBatch {
    entries: Vec<AuditEntry>,
    bytes: u64,
    digest: String,
    observed_bytes: u64,
    total_records: u64,
    pending_frame: bool,
}

impl std::fmt::Debug for InvokeAuditFollowBatch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InvokeAuditFollowBatch")
            .field("entries", &self.entries.len())
            .field("bytes", &self.bytes)
            .field("pending_frame", &self.pending_frame)
            .finish_non_exhaustive()
    }
}

impl InvokeAuditFollowBatch {
    /// Records that became available since the preceding successful poll.
    #[must_use]
    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// Cumulative length of the validated complete prefix, including its header.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    /// BLAKE3 fingerprint of the observed complete prefix, not a signature.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Source length sampled for this poll; bytes after `bytes()` are unchecked.
    #[must_use]
    pub const fn observed_bytes(&self) -> u64 {
        self.observed_bytes
    }

    /// Cumulative validated records across all zones and successful batches.
    #[must_use]
    pub const fn total_records(&self) -> u64 {
        self.total_records
    }

    /// Whether a sampled header or final frame is waiting for more bytes.
    #[must_use]
    pub const fn pending_frame(&self) -> bool {
        self.pending_frame
    }

    /// Whether the reader reached its sampled extent, not necessarily current EOF.
    #[must_use]
    pub const fn caught_up(&self) -> bool {
        !self.pending_frame && self.bytes == self.observed_bytes
    }
}

/// Stateful, read-only follower of a single opened host journal.
///
/// Retains only one small lineage tip per observed zone and at most one bounded
/// batch during a poll. It never accumulates old payloads, starts background
/// work, locks the writer, or reopens a replaced pathname. Complete frame bytes
/// are decoded and hashed once. Callers own poll timing, cancellation, output
/// filtering and the treatment of an indefinitely incomplete final frame.
///
/// The source must be append-only. This reader detects observed shortening and
/// invalid subsequent lineage, not same-length edits or truncate-and-regrow
/// between polls. It does not rescan earlier bytes. Its fingerprint describes
/// what was observed, not a current authenticated or crash-durable checkpoint.
/// OS writer locks that deny reads remain authoritative.
pub struct InvokeAuditFollower {
    file: File,
    offset: u64,
    high_watermark: u64,
    records: u64,
    digest: blake3::Hasher,
    tips: BTreeMap<String, ZoneTip>,
    failure: Option<InvokeAuditSnapshotError>,
}

impl std::fmt::Debug for InvokeAuditFollower {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InvokeAuditFollower")
            .field("bytes", &self.offset)
            .field("records", &self.records)
            .field("zones", &self.tips.len())
            .field("fenced", &self.failure.is_some())
            .finish_non_exhaustive()
    }
}

impl InvokeAuditFollower {
    /// Open an existing regular file without following its final symlink.
    ///
    /// # Errors
    /// Refuses missing/special sources and sources exceeding the journal limit.
    /// A newly created, incomplete header is accepted here and awaited by poll.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, InvokeAuditSnapshotError> {
        Self::from_file(open_snapshot_source(path.as_ref())?)
    }

    /// Take ownership of an already opened regular file and start at its genesis.
    /// Do not share its read cursor through an OS-duplicated handle.
    ///
    /// # Errors
    /// Refuses special files, unavailable metadata and over-budget source lengths.
    pub fn from_file(file: File) -> Result<Self, InvokeAuditSnapshotError> {
        let metadata = file.metadata().map_err(|error| source_io(&error))?;
        if !metadata.is_file() {
            return Err(InvokeAuditSnapshotError::NotRegularFile);
        }
        if metadata.len() > INVOKE_AUDIT_MAX_JOURNAL_BYTES {
            return Err(InvokeAuditSnapshotError::LimitExceeded);
        }
        Ok(Self {
            file,
            offset: 0,
            high_watermark: metadata.len(),
            records: 0,
            digest: blake3::Hasher::new(),
            tips: BTreeMap::new(),
            failure: None,
        })
    }

    /// Read at most one bounded batch without waiting for more source bytes.
    ///
    /// Incomplete trailing framing returns `pending_frame = true`; no partial
    /// payload is retained or emitted, and its bytes are not hashed. A complete
    /// bad record, read failure or observed truncation permanently fences the
    /// follower. No records from that failing poll are returned, even when an
    /// earlier record in the same poll was valid. Previously returned batches
    /// cannot be retracted and are not a proof about the unobserved remainder.
    ///
    /// # Errors
    /// Returns redaction-safe framing, integrity, lineage, source or limit errors.
    /// Every later call returns the original error without touching the source.
    pub fn poll(&mut self) -> Result<InvokeAuditFollowBatch, InvokeAuditSnapshotError> {
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        let result = self.poll_inner();
        if let Err(error) = &result {
            self.failure = Some(error.clone());
        }
        result
    }

    fn poll_inner(&mut self) -> Result<InvokeAuditFollowBatch, InvokeAuditSnapshotError> {
        let length = self
            .file
            .metadata()
            .map_err(|error| source_io(&error))?
            .len();
        if length < self.high_watermark {
            return Err(InvokeAuditSnapshotError::SourceChanged);
        }
        if length > INVOKE_AUDIT_MAX_JOURNAL_BYTES {
            return Err(InvokeAuditSnapshotError::LimitExceeded);
        }
        self.high_watermark = length;
        self.file
            .seek(SeekFrom::Start(self.offset))
            .map_err(|error| source_io(&error))?;
        let mut entries = Vec::new();
        let mut pending_frame = false;
        if self.offset == 0 {
            if length < JOURNAL_V1_MAGIC.len() as u64 {
                return self.finish_batch(entries, length, true);
            }
            let mut magic = [0; JOURNAL_V1_MAGIC.len()];
            read_exact_at(&mut self.file, &mut magic, 0)?;
            if &magic != JOURNAL_V1_MAGIC {
                return Err(InvokeAuditSnapshotError::UnsupportedFormat);
            }
            self.digest.update(&magic);
            self.offset = JOURNAL_V1_MAGIC.len() as u64;
        }
        while self.offset < length && entries.len() < INVOKE_AUDIT_FOLLOW_BATCH_RECORDS {
            if self.records >= INVOKE_AUDIT_MAX_ENTRIES {
                return Err(InvokeAuditSnapshotError::LimitExceeded);
            }
            if length - self.offset < 4 {
                pending_frame = true;
                break;
            }
            let mut prefix = [0; 4];
            read_exact_at(&mut self.file, &mut prefix, self.offset)?;
            let size = u32::from_le_bytes(prefix);
            if size == 0 || u64::from(size) > INVOKE_AUDIT_MAX_RECORD_BYTES as u64 {
                return Err(InvokeAuditSnapshotError::InvalidRecord {
                    offset: self.offset,
                });
            }
            if u64::from(size) > length - self.offset - 4 {
                pending_frame = true;
                break;
            }
            let mut payload = vec![
                0;
                usize::try_from(size)
                    .map_err(|_| InvokeAuditSnapshotError::LimitExceeded)?
            ];
            read_exact_at(&mut self.file, &mut payload, self.offset + 4)?;
            let entry = decode_record(&payload, self.offset)?;
            let valid = self.tips.get(&entry.zone_id).map_or_else(
                || entry.seq == 0 && entry.prev.is_none(),
                |tip| valid_successor(&entry, tip.seq, &tip.id, tip.occurred_at, &tip.hlc),
            );
            if !valid {
                return Err(InvokeAuditSnapshotError::InvalidLineage {
                    offset: self.offset,
                });
            }
            self.tips
                .insert(entry.zone_id.clone(), ZoneTip::from(&entry));
            self.digest.update(&prefix);
            self.digest.update(&payload);
            self.offset += 4 + u64::from(size);
            self.records += 1;
            entries.push(entry);
        }
        self.finish_batch(entries, length, pending_frame)
    }

    fn finish_batch(
        &mut self,
        entries: Vec<AuditEntry>,
        observed_bytes: u64,
        pending_frame: bool,
    ) -> Result<InvokeAuditFollowBatch, InvokeAuditSnapshotError> {
        let after = self
            .file
            .metadata()
            .map_err(|error| source_io(&error))?
            .len();
        if after < self.high_watermark {
            return Err(InvokeAuditSnapshotError::SourceChanged);
        }
        if after > INVOKE_AUDIT_MAX_JOURNAL_BYTES {
            return Err(InvokeAuditSnapshotError::LimitExceeded);
        }
        self.high_watermark = after;
        Ok(InvokeAuditFollowBatch {
            entries,
            bytes: self.offset,
            digest: format!("blake3:{}", self.digest.finalize().to_hex()),
            observed_bytes,
            total_records: self.records,
            pending_frame,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InvokeAuditChain, InvokeAuditContext, InvokePhase, read_invoke_audit_snapshot};
    use std::io::Write;

    fn context(zone: &str) -> InvokeAuditContext {
        InvokeAuditContext {
            zone_id: zone.to_owned(),
            actor: "agent:follow-test".to_owned(),
            connector_id: "github".to_owned(),
            operation: "issues.create".to_owned(),
            operation_id: "request-a".to_owned(),
            correlation_id: None,
            occurred_at: 1_700_000_000,
        }
    }

    fn frame(entry: &AuditEntry) -> Vec<u8> {
        let payload = serde_json::to_vec(entry).unwrap();
        let mut bytes = u32::try_from(payload.len()).unwrap().to_le_bytes().to_vec();
        bytes.extend_from_slice(&payload);
        bytes
    }

    fn append(file: &mut File, bytes: &[u8]) {
        file.write_all(bytes).unwrap();
        file.flush().unwrap();
    }

    fn source() -> (
        tempfile::TempDir,
        std::path::PathBuf,
        File,
        InvokeAuditFollower,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("journal");
        let writer = File::create(&path).unwrap();
        let follower = InvokeAuditFollower::open(&path).unwrap();
        (directory, path, writer, follower)
    }

    #[test]
    fn partial_header_prefix_and_payload_resume_without_duplicate_emission() {
        let (_directory, path, mut writer, mut follower) = source();
        assert!(follower.poll().unwrap().pending_frame());
        append(&mut writer, &JOURNAL_V1_MAGIC[..3]);
        assert_eq!(follower.poll().unwrap().bytes(), 0);
        append(&mut writer, &JOURNAL_V1_MAGIC[3..]);
        assert!(follower.poll().unwrap().caught_up());
        let chain = InvokeAuditChain::new();
        let entry = chain
            .append(&context("z:work"), InvokePhase::PreflightAllow)
            .unwrap();
        let bytes = frame(&entry);
        for part in [&bytes[..1], &bytes[1..3], &bytes[3..bytes.len() - 1]] {
            append(&mut writer, part);
            let batch = follower.poll().unwrap();
            assert!(batch.pending_frame());
            assert!(batch.entries().is_empty());
            assert_eq!(batch.bytes(), JOURNAL_V1_MAGIC.len() as u64);
        }
        append(&mut writer, &bytes[bytes.len() - 1..]);
        let batch = follower.poll().unwrap();
        assert_eq!(batch.entries(), &[entry]);
        assert!(batch.caught_up());
        assert_eq!(
            batch.digest(),
            read_invoke_audit_snapshot(&path).unwrap().digest()
        );
        assert!(follower.poll().unwrap().entries().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn follows_production_writer_without_releasing_its_ownership() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("journal");
        let chain = InvokeAuditChain::open_with_journal(&path).unwrap();
        let mut follower = InvokeAuditFollower::open(&path).unwrap();
        assert!(follower.poll().unwrap().caught_up());
        for phase in [
            InvokePhase::PreflightAllow,
            InvokePhase::DispatchResult {
                success: true,
                receipt_id: None,
                duration_ms: 4,
            },
        ] {
            let entry = chain.append(&context("z:work"), phase).unwrap();
            assert_eq!(follower.poll().unwrap().entries(), &[entry]);
        }
        assert!(InvokeAuditChain::open_with_journal(&path).is_err());
        assert_eq!(follower.poll().unwrap().total_records(), 2);
    }

    #[test]
    fn backlog_is_bounded_and_incremental_digest_matches_full_snapshot() {
        let (_directory, path, mut writer, mut follower) = source();
        append(&mut writer, JOURNAL_V1_MAGIC);
        let chain = InvokeAuditChain::new();
        let count = INVOKE_AUDIT_FOLLOW_BATCH_RECORDS * 2 + 1;
        for index in 0..count {
            let zone = if index % 2 == 0 {
                "z:work"
            } else {
                "z:private"
            };
            let entry = chain
                .append(&context(zone), InvokePhase::PreflightAllow)
                .unwrap();
            append(&mut writer, &frame(&entry));
        }
        let mut all = Vec::new();
        loop {
            let batch = follower.poll().unwrap();
            assert!(batch.entries().len() <= INVOKE_AUDIT_FOLLOW_BATCH_RECORDS);
            all.extend_from_slice(batch.entries());
            if batch.caught_up() {
                let snapshot = read_invoke_audit_snapshot(&path).unwrap();
                assert_eq!(all, snapshot.entries());
                assert_eq!(batch.digest(), snapshot.digest());
                assert_eq!(batch.total_records(), count as u64);
                break;
            }
        }
        assert_eq!(follower.tips.len(), 2);
        assert!(follower.poll().unwrap().entries().is_empty());
    }

    #[test]
    fn failed_poll_returns_no_prefix_and_cannot_be_repaired_into_success() {
        let (_directory, _path, mut writer, mut follower) = source();
        append(&mut writer, JOURNAL_V1_MAGIC);
        let chain = InvokeAuditChain::new();
        let entry = chain
            .append(&context("z:work"), InvokePhase::PreflightAllow)
            .unwrap();
        append(&mut writer, &frame(&entry));
        let mut bad = chain
            .append(&context("z:private"), InvokePhase::PreflightAllow)
            .unwrap();
        bad.actor = "must-not-leak".to_owned();
        append(&mut writer, &frame(&bad));
        let error = follower.poll().unwrap_err();
        assert!(matches!(
            error,
            InvokeAuditSnapshotError::InvalidRecord { .. }
        ));
        assert!(!error.to_string().contains("must-not-leak"));
        assert_eq!(follower.poll().unwrap_err(), error);
    }

    #[test]
    fn lineage_checks_span_polls_and_include_every_zone() {
        for mutation in ["sequence", "prev", "time", "hlc", "duplicate"] {
            let (_directory, _path, mut writer, mut follower) = source();
            append(&mut writer, JOURNAL_V1_MAGIC);
            let chain = InvokeAuditChain::new();
            let first = chain
                .append(&context("z:work"), InvokePhase::PreflightAllow)
                .unwrap();
            append(&mut writer, &frame(&first));
            follower.poll().unwrap();
            let mut next = chain
                .append(&context("z:work"), InvokePhase::PreflightAllow)
                .unwrap();
            match mutation {
                "sequence" => next.seq += 1,
                "prev" => next.prev = None,
                "time" => next.occurred_at -= 1,
                "hlc" => next.hlc = first.hlc.clone(),
                _ => next = first,
            }
            next.id = next.computed_id().unwrap();
            append(&mut writer, &frame(&next));
            assert!(
                matches!(
                    follower.poll(),
                    Err(InvokeAuditSnapshotError::InvalidLineage { .. })
                ),
                "{mutation}"
            );
        }
    }

    #[test]
    fn observed_truncation_fences_even_an_uncommitted_tail() {
        let (_directory, _path, mut writer, mut follower) = source();
        append(&mut writer, JOURNAL_V1_MAGIC);
        append(&mut writer, &[1, 0]);
        assert!(follower.poll().unwrap().pending_frame());
        writer.set_len(JOURNAL_V1_MAGIC.len() as u64).unwrap();
        assert_eq!(
            follower.poll().unwrap_err(),
            InvokeAuditSnapshotError::SourceChanged
        );
        assert_eq!(
            follower.poll().unwrap_err(),
            InvokeAuditSnapshotError::SourceChanged
        );
    }

    #[test]
    fn complete_bad_headers_and_frame_lengths_are_terminal() {
        for bytes in [
            b"FCPAUD9\n".to_vec(),
            [JOURNAL_V1_MAGIC.as_slice(), &[0, 0, 0, 0]].concat(),
            [JOURNAL_V1_MAGIC.as_slice(), &u32::MAX.to_le_bytes()].concat(),
        ] {
            let (_directory, _path, mut writer, mut follower) = source();
            append(&mut writer, &bytes);
            let error = follower.poll().unwrap_err();
            assert_eq!(follower.poll().unwrap_err(), error);
        }
    }

    #[test]
    fn global_entry_and_source_bounds_apply_across_polls() {
        let (_directory, _path, mut writer, mut follower) = source();
        append(&mut writer, JOURNAL_V1_MAGIC);
        follower.poll().unwrap();
        follower.records = INVOKE_AUDIT_MAX_ENTRIES;
        append(&mut writer, &[1]);
        assert_eq!(
            follower.poll().unwrap_err(),
            InvokeAuditSnapshotError::LimitExceeded
        );
        let (_directory, _path, writer, mut follower) = source();
        writer.set_len(INVOKE_AUDIT_MAX_JOURNAL_BYTES + 1).unwrap();
        assert_eq!(
            follower.poll().unwrap_err(),
            InvokeAuditSnapshotError::LimitExceeded
        );
    }

    #[cfg(unix)]
    #[test]
    fn path_replacement_never_silently_switches_source() {
        let (_directory, path, mut writer, mut follower) = source();
        append(&mut writer, JOURNAL_V1_MAGIC);
        follower.poll().unwrap();
        std::fs::rename(&path, path.with_extension("old")).unwrap();
        std::fs::write(&path, b"not-the-original-source").unwrap();
        let chain = InvokeAuditChain::new();
        let entry = chain
            .append(&context("z:work"), InvokePhase::PreflightAllow)
            .unwrap();
        append(&mut writer, &frame(&entry));
        assert_eq!(follower.poll().unwrap().entries(), &[entry]);
    }

    #[test]
    fn debug_and_missing_source_do_not_disclose_or_create_evidence() {
        let (directory, _path, mut writer, mut follower) = source();
        let missing = directory.path().join("missing").join("journal");
        assert!(InvokeAuditFollower::open(&missing).is_err());
        assert!(!missing.parent().unwrap().exists());
        append(&mut writer, JOURNAL_V1_MAGIC);
        let chain = InvokeAuditChain::new();
        append(
            &mut writer,
            &frame(
                &chain
                    .append(&context("z:work"), InvokePhase::PreflightAllow)
                    .unwrap(),
            ),
        );
        let batch = follower.poll().unwrap();
        for text in [format!("{follower:?}"), format!("{batch:?}")] {
            assert!(!text.contains("agent:follow-test"));
            assert!(!text.contains("issues.create"));
        }
    }
}
