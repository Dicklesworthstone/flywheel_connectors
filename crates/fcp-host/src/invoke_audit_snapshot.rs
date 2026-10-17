//! Read-only, bounded snapshots of the host's length-framed invoke journal.
//!
//! This is an observation API, not writer recovery. It never creates a source,
//! locks out its writer, repairs a tail, truncates a file, or synchronizes it.
//! A snapshot pins the open file and its initial length. Later appends are not
//! included; an initial length ending inside a frame refuses the whole snapshot.
//! IDs and per-zone lineage are checked before any entries are returned. These
//! checks establish internal integrity, not signer authenticity, a committed
//! fsync boundary, current authority, or protection against rollback/forgery.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use fcp_audit::{AuditEntry, HybridLogicalTimestamp};
use thiserror::Error;

use crate::{
    INVOKE_AUDIT_MAX_ENTRIES, INVOKE_AUDIT_MAX_JOURNAL_BYTES, INVOKE_AUDIT_MAX_RECORD_BYTES,
};

const JOURNAL_V1_MAGIC: &[u8; 8] = b"FCPAUD1\n";

mod follow;
pub use follow::{INVOKE_AUDIT_FOLLOW_BATCH_RECORDS, InvokeAuditFollowBatch, InvokeAuditFollower};

/// Redaction-safe failures from read-only journal observation.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InvokeAuditSnapshotError {
    /// Opening, inspecting or reading the source failed. Paths and data are omitted.
    #[error("audit snapshot source I/O failed ({kind:?})")]
    Io { kind: io::ErrorKind },
    /// Special files must not turn a bounded snapshot into a blocking stream.
    #[error("audit snapshot source must be a regular file, not a symbolic link")]
    NotRegularFile,
    /// The sampled extent contains a header or frame that is not complete.
    #[error("audit snapshot is incomplete at byte {offset}; no records were returned")]
    Incomplete { offset: u64 },
    /// This reader cannot interpret the file's framing version.
    #[error("audit snapshot has an unsupported journal header")]
    UnsupportedFormat,
    /// The input exceeds a production journal bound.
    #[error("audit snapshot exceeds the journal byte, record, or entry bound")]
    LimitExceeded,
    /// Entry decoding or canonical identity verification failed.
    #[error("audit snapshot contains an invalid record at byte {offset}")]
    InvalidRecord { offset: u64 },
    /// A zone's genesis, sequence, hash link or clocks disagree.
    #[error("audit snapshot contains invalid zone lineage at byte {offset}")]
    InvalidLineage { offset: u64 },
    /// A source shortened while the sampled extent was being read.
    #[error("audit snapshot source was shortened during observation")]
    SourceChanged,
}

impl InvokeAuditSnapshotError {
    /// Stable error code without source paths, identities or payload contents.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Io { .. } => "audit.snapshot.io",
            Self::NotRegularFile => "audit.snapshot.not_regular",
            Self::Incomplete { .. } => "audit.snapshot.incomplete",
            Self::UnsupportedFormat => "audit.snapshot.unsupported_format",
            Self::LimitExceeded => "audit.snapshot.limit_exceeded",
            Self::InvalidRecord { .. } => "audit.snapshot.invalid_record",
            Self::InvalidLineage { .. } => "audit.snapshot.invalid_lineage",
            Self::SourceChanged => "audit.snapshot.source_changed",
        }
    }
}

fn source_io(error: &io::Error) -> InvokeAuditSnapshotError {
    InvokeAuditSnapshotError::Io { kind: error.kind() }
}

/// One completely decoded, internally consistent observed journal prefix.
///
/// Entries retain physical journal order, including interleaved zones. This
/// type cannot be deserialized or constructed with unchecked evidence. It does
/// not attest authenticity or persistence: an active writer may not yet have
/// fsynced an observed complete frame. The journal's durable projection policy
/// and lifecycle semantics are separate from the integrity checks here.
pub struct InvokeAuditSnapshot {
    entries: Vec<AuditEntry>,
    bytes: u64,
    digest: String,
    tips: BTreeMap<String, usize>,
}

impl std::fmt::Debug for InvokeAuditSnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InvokeAuditSnapshot")
            .field("entries", &self.entries.len())
            .field("bytes", &self.bytes)
            .field("zones", &self.tips.len())
            .finish_non_exhaustive()
    }
}

impl InvokeAuditSnapshot {
    /// Captured records, available only after the entire sampled extent passed.
    #[must_use]
    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// Number of raw journal bytes covered by this snapshot and its digest.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    /// BLAKE3 of the raw sampled prefix, including its header and length frames.
    /// This is a content fingerprint, not an authenticated checkpoint.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Last observed record for each zone, ordered by zone identifier.
    pub fn zone_heads(&self) -> impl Iterator<Item = &AuditEntry> {
        self.tips.values().map(|index| &self.entries[*index])
    }

    /// Transfer ownership of the validated captured records to a replay consumer.
    #[must_use]
    pub fn into_entries(self) -> Vec<AuditEntry> {
        self.entries
    }
}

/// Observe a journal without acquiring or modifying its writer state.
///
/// The source must already exist. On Unix the final path component is opened
/// without following symlinks and without blocking on a substituted FIFO.
/// Parent path resolution remains the caller's responsibility. The open handle
/// pins one source; this function never switches to a replacement pathname.
/// Appends after the sampled length are ignored, not awaited or retried.
/// Operating systems that deny reads under the writer's exclusive file lock
/// return an I/O error; stop the host or use an operator-provided copy there.
///
/// # Errors
/// Returns a redaction-safe [`InvokeAuditSnapshotError`] for special files,
/// unreadable data, incomplete framing, bounds, canonical IDs or zone lineage.
/// No partial snapshot is returned after an error.
pub fn read_invoke_audit_snapshot(
    path: impl AsRef<Path>,
) -> Result<InvokeAuditSnapshot, InvokeAuditSnapshotError> {
    let mut file = open_snapshot_source(path.as_ref())?;
    read_invoke_audit_snapshot_from_file(&mut file)
}

fn open_snapshot_source(path: &Path) -> Result<File, InvokeAuditSnapshotError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| source_io(&error))?;
    if !metadata.file_type().is_file() {
        return Err(InvokeAuditSnapshotError::NotRegularFile);
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|error| source_io(&error))?;
    if !file
        .metadata()
        .map_err(|error| source_io(&error))?
        .is_file()
    {
        return Err(InvokeAuditSnapshotError::NotRegularFile);
    }
    Ok(file)
}

/// Observe the initial extent of an already opened regular file.
///
/// This repositions the supplied handle to offset zero and advances its read
/// cursor. It does not write or lock the file. The caller must not share that
/// cursor with another reader (including through an OS-duplicated handle).
/// The source is expected to be append-only; hash checks cannot authenticate a
/// hostile writer that rewrites an internally consistent chain.
///
/// # Errors
/// Returns the same integrity and I/O errors as [`read_invoke_audit_snapshot`].
pub fn read_invoke_audit_snapshot_from_file(
    file: &mut File,
) -> Result<InvokeAuditSnapshot, InvokeAuditSnapshotError> {
    let metadata = file.metadata().map_err(|error| source_io(&error))?;
    if !metadata.is_file() {
        return Err(InvokeAuditSnapshotError::NotRegularFile);
    }
    let length = metadata.len();
    validate_extent(length)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| source_io(&error))?;
    let snapshot = decode_snapshot(&mut *file, length)?;
    if file.metadata().map_err(|error| source_io(&error))?.len() < length {
        return Err(InvokeAuditSnapshotError::SourceChanged);
    }
    Ok(snapshot)
}

fn validate_extent(length: u64) -> Result<(), InvokeAuditSnapshotError> {
    if length > INVOKE_AUDIT_MAX_JOURNAL_BYTES {
        return Err(InvokeAuditSnapshotError::LimitExceeded);
    }
    if length < JOURNAL_V1_MAGIC.len() as u64 {
        return Err(InvokeAuditSnapshotError::Incomplete { offset: 0 });
    }
    Ok(())
}

fn read_exact_at(
    reader: &mut impl Read,
    bytes: &mut [u8],
    offset: u64,
) -> Result<(), InvokeAuditSnapshotError> {
    reader.read_exact(bytes).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            InvokeAuditSnapshotError::Incomplete { offset }
        } else {
            source_io(&error)
        }
    })
}

fn decode_record(payload: &[u8], offset: u64) -> Result<AuditEntry, InvokeAuditSnapshotError> {
    let entry: AuditEntry = serde_json::from_slice(payload)
        .map_err(|_| InvokeAuditSnapshotError::InvalidRecord { offset })?;
    let id = entry
        .computed_id()
        .map_err(|_| InvokeAuditSnapshotError::InvalidRecord { offset })?;
    if entry.id != id {
        return Err(InvokeAuditSnapshotError::InvalidRecord { offset });
    }
    Ok(entry)
}

fn valid_successor(
    entry: &AuditEntry,
    seq: u64,
    id: &str,
    occurred_at: u64,
    hlc: &HybridLogicalTimestamp,
) -> bool {
    seq.checked_add(1) == Some(entry.seq)
        && entry.prev.as_deref() == Some(id)
        && entry.occurred_at >= occurred_at
        && entry.hlc > *hlc
}

fn decode_snapshot(
    reader: impl Read,
    length: u64,
) -> Result<InvokeAuditSnapshot, InvokeAuditSnapshotError> {
    validate_extent(length)?;
    let mut reader = reader.take(length);
    let mut magic = [0; JOURNAL_V1_MAGIC.len()];
    read_exact_at(&mut reader, &mut magic, 0)?;
    if &magic != JOURNAL_V1_MAGIC {
        return Err(InvokeAuditSnapshotError::UnsupportedFormat);
    }
    let mut digest = blake3::Hasher::new();
    digest.update(&magic);
    let mut entries: Vec<AuditEntry> = Vec::new();
    let mut tips: BTreeMap<String, usize> = BTreeMap::new();
    let mut offset = JOURNAL_V1_MAGIC.len() as u64;
    while offset < length {
        if entries.len() as u64 >= INVOKE_AUDIT_MAX_ENTRIES {
            return Err(InvokeAuditSnapshotError::LimitExceeded);
        }
        if length - offset < 4 {
            return Err(InvokeAuditSnapshotError::Incomplete { offset });
        }
        let mut prefix = [0; 4];
        read_exact_at(&mut reader, &mut prefix, offset)?;
        let size = u32::from_le_bytes(prefix);
        if size == 0 || u64::from(size) > INVOKE_AUDIT_MAX_RECORD_BYTES as u64 {
            return Err(InvokeAuditSnapshotError::InvalidRecord { offset });
        }
        if u64::from(size) > length - offset - 4 {
            return Err(InvokeAuditSnapshotError::Incomplete { offset });
        }
        let size_usize =
            usize::try_from(size).map_err(|_| InvokeAuditSnapshotError::LimitExceeded)?;
        let mut payload = vec![0; size_usize];
        read_exact_at(&mut reader, &mut payload, offset + 4)?;
        let entry = decode_record(&payload, offset)?;
        let lineage_valid = tips.get(&entry.zone_id).map_or_else(
            || entry.seq == 0 && entry.prev.is_none(),
            |index| {
                let previous = &entries[*index];
                valid_successor(
                    &entry,
                    previous.seq,
                    &previous.id,
                    previous.occurred_at,
                    &previous.hlc,
                )
            },
        );
        if !lineage_valid {
            return Err(InvokeAuditSnapshotError::InvalidLineage { offset });
        }
        digest.update(&prefix);
        digest.update(&payload);
        tips.insert(entry.zone_id.clone(), entries.len());
        entries.push(entry);
        offset += 4 + u64::from(size);
    }
    Ok(InvokeAuditSnapshot {
        entries,
        bytes: length,
        digest: format!("blake3:{}", digest.finalize().to_hex()),
        tips,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InvokeAuditChain, InvokeAuditContext, InvokePhase};

    fn context(zone: &str, request: &str) -> InvokeAuditContext {
        InvokeAuditContext {
            zone_id: zone.to_owned(),
            actor: "agent:snapshot-test".to_owned(),
            connector_id: "github".to_owned(),
            operation: "issues.create".to_owned(),
            operation_id: request.to_owned(),
            correlation_id: Some("client-correlation".to_owned()),
            occurred_at: 1_700_000_000,
        }
    }

    fn frames(entries: &[AuditEntry]) -> Vec<u8> {
        let mut bytes = JOURNAL_V1_MAGIC.to_vec();
        for entry in entries {
            let payload = serde_json::to_vec(entry).unwrap();
            bytes.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
            bytes.extend_from_slice(&payload);
        }
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<InvokeAuditSnapshot, InvokeAuditSnapshotError> {
        decode_snapshot(bytes, bytes.len() as u64)
    }

    fn entries() -> Vec<AuditEntry> {
        let chain = InvokeAuditChain::new();
        let request = context("z:work", "request-a");
        vec![
            chain.append(&request, InvokePhase::PreflightAllow).unwrap(),
            chain
                .append(
                    &request,
                    InvokePhase::DispatchResult {
                        receipt_id: None,
                        success: true,
                        duration_ms: 12,
                    },
                )
                .unwrap(),
        ]
    }

    #[cfg(unix)]
    #[test]
    fn reads_real_journal_while_writer_keeps_exclusive_ownership() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("invoke.journal");
        let writer = InvokeAuditChain::open_with_journal(&path).unwrap();
        let first = writer
            .append(&context("z:work", "a"), InvokePhase::PreflightAllow)
            .unwrap();
        let second = writer
            .append(&context("z:private", "b"), InvokePhase::PreflightAllow)
            .unwrap();
        let before = std::fs::read(&path).unwrap();
        let snapshot = read_invoke_audit_snapshot(&path).unwrap();
        assert_eq!(snapshot.entries(), &[first, second]);
        assert_eq!(snapshot.zone_heads().count(), 2);
        assert_eq!(snapshot.bytes(), before.len() as u64);
        assert_eq!(
            snapshot.digest(),
            format!("blake3:{}", blake3::hash(&before).to_hex())
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(InvokeAuditChain::open_with_journal(&path).is_err());
        writer
            .append(
                &context("z:work", "a"),
                InvokePhase::DispatchError {
                    error: "dispatch_failed".to_owned(),
                    duration_ms: 20,
                },
            )
            .unwrap();
        assert_eq!(snapshot.entries().len(), 2);
        assert_eq!(
            read_invoke_audit_snapshot(&path).unwrap().entries().len(),
            3
        );
    }

    #[test]
    fn reads_closed_production_journal_without_recovery_or_source_mutation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("closed.journal");
        let writer = InvokeAuditChain::open_with_journal(&path).unwrap();
        let entry = writer
            .append(&context("z:work", "a"), InvokePhase::PreflightAllow)
            .unwrap();
        drop(writer);
        let before = std::fs::read(&path).unwrap();
        let snapshot = read_invoke_audit_snapshot(&path).unwrap();
        assert_eq!(snapshot.entries(), &[entry]);
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let reopened = InvokeAuditChain::open_with_journal(&path).unwrap();
        assert_eq!(reopened.len_for_zone("z:work"), 1);
    }

    #[test]
    fn sampled_extent_ignores_later_appends_and_does_not_read_past_it() {
        let entries = entries();
        let first = frames(&entries[..1]);
        let all = frames(&entries);
        let mut reader = io::Cursor::new(all);
        let snapshot = decode_snapshot(&mut reader, first.len() as u64).unwrap();
        assert_eq!(snapshot.entries(), &entries[..1]);
        assert_eq!(reader.position(), first.len() as u64);
    }

    #[test]
    fn incomplete_header_prefix_and_payload_never_return_partial_entries() {
        let entries = entries();
        let first_length = frames(&entries[..1]).len();
        let bytes = frames(&entries);
        for end in [0, 3, 7, first_length + 1, first_length + 3, bytes.len() - 1] {
            assert!(matches!(
                decode(&bytes[..end]),
                Err(InvokeAuditSnapshotError::Incomplete { .. })
            ));
        }
        assert!(matches!(
            decode_snapshot(&bytes[..first_length], bytes.len() as u64),
            Err(InvokeAuditSnapshotError::Incomplete { .. })
        ));
    }

    #[test]
    fn rejects_unsupported_format_zero_and_oversized_frames() {
        assert_eq!(
            decode(b"FCPAUD2\n").unwrap_err(),
            InvokeAuditSnapshotError::UnsupportedFormat
        );
        for size in [
            0,
            u32::try_from(INVOKE_AUDIT_MAX_RECORD_BYTES + 1).unwrap(),
            u32::MAX,
        ] {
            let mut bytes = JOURNAL_V1_MAGIC.to_vec();
            bytes.extend_from_slice(&size.to_le_bytes());
            assert!(matches!(
                decode(&bytes),
                Err(InvokeAuditSnapshotError::InvalidRecord { .. })
            ));
        }
    }

    #[test]
    fn extent_bound_is_checked_before_any_read() {
        struct Unreadable;
        impl Read for Unreadable {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                panic!("over-budget input must not be read");
            }
        }
        assert_eq!(
            decode_snapshot(Unreadable, INVOKE_AUDIT_MAX_JOURNAL_BYTES + 1).unwrap_err(),
            InvokeAuditSnapshotError::LimitExceeded
        );
    }

    #[test]
    fn corrupted_identity_in_any_zone_refuses_the_whole_snapshot() {
        let mut entries = entries();
        let other = InvokeAuditChain::new();
        let mut unrelated = other
            .append(&context("z:private", "other"), InvokePhase::PreflightAllow)
            .unwrap();
        unrelated.actor = "untrusted-secret-actor".to_owned();
        entries.insert(1, unrelated);
        let error = decode(&frames(&entries)).unwrap_err();
        assert!(matches!(
            error,
            InvokeAuditSnapshotError::InvalidRecord { .. }
        ));
        assert!(!error.to_string().contains("untrusted-secret"));
    }

    #[test]
    fn rejects_rehashed_gaps_links_genesis_and_clock_regressions() {
        for mutation in ["gap", "prev", "time", "hlc", "genesis"] {
            let mut entries = entries();
            match mutation {
                "gap" => entries[1].seq += 1,
                "prev" => entries[1].prev = None,
                "time" => entries[1].occurred_at -= 1,
                "hlc" => entries[1].hlc = entries[0].hlc.clone(),
                _ => entries[0].seq = 9,
            }
            for entry in &mut entries {
                entry.id = entry.computed_id().unwrap();
            }
            assert!(
                matches!(
                    decode(&frames(&entries)),
                    Err(InvokeAuditSnapshotError::InvalidLineage { .. })
                ),
                "{mutation}"
            );
        }
    }

    #[test]
    fn duplicate_frames_are_not_silently_deduplicated() {
        let mut entries = entries();
        entries.push(entries[1].clone());
        assert!(matches!(
            decode(&frames(&entries)),
            Err(InvokeAuditSnapshotError::InvalidLineage { .. })
        ));
    }

    #[test]
    fn empty_initialized_journal_is_valid_but_missing_path_is_not_created() {
        let snapshot = decode(JOURNAL_V1_MAGIC).unwrap();
        assert!(snapshot.entries().is_empty());
        assert_eq!(snapshot.zone_heads().count(), 0);
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing").join("journal");
        assert!(read_invoke_audit_snapshot(&missing).is_err());
        assert!(!missing.parent().unwrap().exists());
        assert!(matches!(
            read_invoke_audit_snapshot(directory.path()),
            Err(InvokeAuditSnapshotError::NotRegularFile)
        ));
    }

    #[test]
    fn read_failure_after_a_valid_prefix_is_not_success() {
        struct FailsAfterPrefix(io::Cursor<Vec<u8>>);
        impl Read for FailsAfterPrefix {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                let count = self.0.read(buffer)?;
                if count == 0 {
                    Err(io::Error::other("payload-and-path-secret"))
                } else {
                    Ok(count)
                }
            }
        }
        let bytes = frames(&entries()[..1]);
        let length = bytes.len() as u64 + 4;
        let error = decode_snapshot(FailsAfterPrefix(io::Cursor::new(bytes)), length).unwrap_err();
        assert!(matches!(error, InvokeAuditSnapshotError::Io { .. }));
        assert!(!error.to_string().contains("secret"));
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symbolic_links_without_touching_the_source() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("journal");
        std::fs::write(&source, JOURNAL_V1_MAGIC).unwrap();
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&source, &link).unwrap();
        assert_eq!(
            read_invoke_audit_snapshot(&link).unwrap_err(),
            InvokeAuditSnapshotError::NotRegularFile
        );
        assert_eq!(std::fs::read(source).unwrap(), JOURNAL_V1_MAGIC.as_slice());
    }

    #[test]
    fn debug_output_does_not_dump_captured_evidence() {
        let snapshot = decode(&frames(&entries())).unwrap();
        let debug = format!("{snapshot:?}");
        assert!(debug.contains("entries: 2"));
        assert!(!debug.contains("issues.create"));
        assert!(!debug.contains("agent:snapshot-test"));
    }
}
