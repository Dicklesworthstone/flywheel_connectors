//! Durable retention of remote membership *source bytes*, never authority.
//!
//! Every returned candidate still goes through the host's independent owner,
//! local-key, validity and checkpoint verification. Keeping the last complete
//! candidate (rather than silently reverting to a last-good document) preserves
//! denial when a publisher supplies an invalid signature or removes this node.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{MAX_SIGNED_MESH_PEER_DIRECTORY_BYTES, SignedMeshPeerDirectory, invalid};
use crate::{HostError, HostResult};

// JSON escaping can expand each byte of the retained source by at most six.
const MAX_CACHE_BYTES: usize = 6 * MAX_SIGNED_MESH_PEER_DIRECTORY_BYTES + 1024;
const MAX_JOURNAL_BYTES: usize = 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema_version: u8,
    source_digest: String,
    observed_at_ms: u64,
    // None is a durable source rejection, not permission to use an older file.
    document: Option<String>,
    checksum_hex: String,
}

impl Record {
    fn checksum(&self) -> String {
        let mut hash = blake3::Hasher::new();
        hash.update(b"FCP-MESH-RETAINED-SOURCE-V1");
        hash.update(&[self.schema_version]);
        hash.update(self.source_digest.as_bytes());
        hash.update(&self.observed_at_ms.to_be_bytes());
        match &self.document {
            Some(document) => {
                hash.update(&[1]);
                hash.update(document.as_bytes());
            }
            None => {
                hash.update(&[0]);
            }
        }
        hash.finalize().to_hex().to_string()
    }

    fn decode(bytes: &[u8], binding: &str) -> HostResult<Self> {
        let record: Self = serde_json::from_slice(bytes)
            .map_err(|_| invalid("retained membership source is corrupt"))?;
        if record.schema_version != 1
            || record.source_digest != binding
            || record.checksum_hex != record.checksum()
        {
            return Err(invalid(
                "retained membership source is corrupt or belongs to another publisher",
            ));
        }
        if let Some(document) = &record.document {
            SignedMeshPeerDirectory::from_json(document)
                .map_err(|_| invalid("retained membership envelope is malformed"))?;
        }
        Ok(record)
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema_version: u8,
    ready: Option<String>,
    pending: Option<String>,
    checksum_hex: String,
}

impl Journal {
    fn checksum(&self) -> String {
        let mut hash = blake3::Hasher::new();
        hash.update(b"FCP-MESH-RETAINED-SOURCE-JOURNAL-V1");
        hash.update(&[self.schema_version]);
        for digest in [&self.ready, &self.pending] {
            match digest {
                Some(digest) => {
                    hash.update(&[1]);
                    hash.update(digest.as_bytes());
                }
                None => {
                    hash.update(&[0]);
                }
            }
        }
        hash.finalize().to_hex().to_string()
    }

    fn decode(bytes: &[u8]) -> HostResult<Self> {
        let journal: Self = serde_json::from_slice(bytes)
            .map_err(|_| invalid("retained source journal is corrupt"))?;
        let digest_valid = |digest: &Option<String>| {
            digest.as_ref().is_none_or(|digest| {
                digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        };
        if journal.schema_version != 1
            || !digest_valid(&journal.ready)
            || !digest_valid(&journal.pending)
            || (journal.ready.is_none() && journal.pending.is_none())
            || journal.checksum_hex != journal.checksum()
        {
            return Err(invalid("retained source journal is corrupt"));
        }
        Ok(journal)
    }
}

/// One exclusive source owner, held across the fetch and durable publication.
/// No signing secret, capability token or request body is retained here.
pub(super) struct SourceCache {
    path: PathBuf,
    lock: File,
    binding: String,
    journal: Journal,
    current: Option<Record>,
    poisoned: bool,
}

pub(super) fn validate_path(path: &Path) -> HostResult<()> {
    if !path.is_absolute()
        || path.file_name().is_none()
        || path
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(invalid(
            "retained_source_file must be an absolute file path without traversal",
        ));
    }
    Ok(())
}

fn companion(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

fn options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    options
}

fn private_regular(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::other("retained source must be a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0 || metadata.nlink() != 1 {
            return Err(io::Error::other(
                "retained source must be private and not hard-linked",
            ));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    Err(io::Error::other(
        "retained source requires Unix filesystem guarantees",
    ))
}

#[allow(clippy::needless_pass_by_value)]
fn storage(stage: &'static str, error: io::Error) -> HostError {
    HostError::Internal(format!(
        "retained membership source {stage} failed ({:?})",
        error.kind()
    ))
}

fn read_file(path: &Path) -> HostResult<Option<Vec<u8>>> {
    let mut file = match options().open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(storage("open", error)),
    };
    private_regular(&file).map_err(|error| storage("metadata", error))?;
    let mut bytes = Vec::new();
    (&mut file)
        .take((MAX_CACHE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| storage("read", error))?;
    if bytes.len() > MAX_CACHE_BYTES {
        return Err(invalid("retained membership source exceeds its byte limit"));
    }
    Ok(Some(bytes))
}

fn sync_parent(path: &Path) -> HostResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("retained source has no parent"))?;
    File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|error| storage("directory_sync", error))
}

fn digest(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

impl SourceCache {
    pub(super) fn open(path: &Path, endpoint: &url::Url) -> HostResult<Self> {
        validate_path(path)?;
        let mut lock = options()
            .create(true)
            .truncate(false)
            .open(companion(path, ".lock"))
            .map_err(|error| storage("lock_open", error))?;
        private_regular(&lock).map_err(|error| storage("lock_metadata", error))?;
        lock.try_lock()
            .map_err(|_| invalid("retained source is locked or locking is unsupported"))?;
        let mut bytes = Vec::new();
        (&mut lock)
            .take((MAX_JOURNAL_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| storage("journal_read", error))?;
        if bytes.len() > MAX_JOURNAL_BYTES {
            return Err(invalid("retained source journal exceeds its byte limit"));
        }
        let journal = if bytes.is_empty() {
            Journal::default()
        } else {
            Journal::decode(&bytes)?
        };
        if journal.pending.is_some() {
            return Err(invalid(
                "retained source publication was interrupted; pending state must be recovered",
            ));
        }
        let mut cache = Self {
            path: path.to_owned(),
            lock,
            binding: hex::encode(blake3::derive_key(
                "fcp.mesh.retained-source.publisher.v1",
                endpoint.as_str().as_bytes(),
            )),
            journal,
            current: None,
            poisoned: false,
        };
        cache.current = cache.read_current()?;
        Ok(cache)
    }

    fn read_current(&self) -> HostResult<Option<Record>> {
        match (read_file(&self.path)?, self.journal.ready.as_deref()) {
            (None, None) => Ok(None),
            (Some(bytes), Some(expected)) if digest(&bytes) == expected => {
                Record::decode(&bytes, &self.binding).map(Some)
            }
            _ => Err(invalid(
                "retained source is missing or changed outside its owner; refusing reset",
            )),
        }
    }

    fn check_clock(&self, now_ms: u64) -> HostResult<()> {
        if self
            .current
            .as_ref()
            .is_some_and(|record| now_ms < record.observed_at_ms)
        {
            return Err(invalid("clock precedes retained source observation"));
        }
        Ok(())
    }

    pub(super) fn candidate(&self, now_ms: u64) -> HostResult<String> {
        if self.poisoned {
            return Err(invalid("retained source storage is unavailable"));
        }
        self.check_clock(now_ms)?;
        // Re-read under the same exclusive owner before relying on disk history.
        let current = self.read_current()?;
        current.and_then(|record| record.document).ok_or_else(|| {
            invalid("no retained source candidate is available; publisher recovery required")
        })
    }

    fn write_journal(&mut self, mut journal: Journal) -> HostResult<()> {
        journal.schema_version = 1;
        journal.checksum_hex = journal.checksum();
        let bytes = serde_json::to_vec(&journal)
            .map_err(|_| invalid("retained source journal cannot be encoded"))?;
        if bytes.len() > MAX_JOURNAL_BYTES {
            return Err(invalid("retained source journal exceeds its byte limit"));
        }
        self.lock
            .seek(SeekFrom::Start(0))
            .and_then(|_| self.lock.write_all(&bytes))
            .and_then(|()| self.lock.set_len(bytes.len() as u64))
            .and_then(|()| self.lock.sync_all())
            .map_err(|error| storage("journal_commit", error))?;
        sync_parent(&self.path)?;
        self.journal = journal;
        Ok(())
    }

    /// Publish a complete candidate or a durable refusal before returning it.
    /// The pending journal fences all later cache use after uncertain writes.
    pub(super) fn store(&mut self, document: Option<String>, now_ms: u64) -> HostResult<()> {
        if self.poisoned {
            return Err(invalid("retained source storage is unavailable"));
        }
        self.check_clock(now_ms)?;
        self.read_current()?;
        if self
            .current
            .as_ref()
            .is_some_and(|record| record.document == document)
        {
            // Re-reading an identical document cannot renew its signed lifetime.
            return Ok(());
        }
        if let Some(document) = &document {
            SignedMeshPeerDirectory::from_json(document)
                .map_err(|_| invalid("only complete membership envelopes may be retained"))?;
        }
        let mut record = Record {
            schema_version: 1,
            source_digest: self.binding.clone(),
            observed_at_ms: now_ms,
            document,
            checksum_hex: String::new(),
        };
        record.checksum_hex = record.checksum();
        let bytes = serde_json::to_vec(&record)
            .map_err(|_| invalid("retained membership source cannot be encoded"))?;
        if bytes.len() > MAX_CACHE_BYTES {
            return Err(invalid("retained membership source exceeds its byte limit"));
        }
        self.poisoned = true;
        let stage = companion(&self.path, ".next");
        let mut file = options()
            .create(true)
            .truncate(false)
            .open(&stage)
            .map_err(|error| storage("stage_open", error))?;
        private_regular(&file).map_err(|error| storage("stage_metadata", error))?;
        file.set_len(0)
            .and_then(|()| file.write_all(&bytes))
            .and_then(|()| file.sync_all())
            .map_err(|error| storage("stage_write", error))?;
        let target = digest(&bytes);
        self.write_journal(Journal {
            ready: self.journal.ready.clone(),
            pending: Some(target.clone()),
            ..Journal::default()
        })?;
        std::fs::rename(&stage, &self.path).map_err(|error| storage("replace", error))?;
        sync_parent(&self.path)?;
        self.write_journal(Journal {
            ready: Some(target),
            ..Journal::default()
        })?;
        self.current = Some(record);
        self.poisoned = false;
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn endpoint() -> url::Url {
        url::Url::parse("https://source.example/members").unwrap()
    }
    fn document() -> String {
        // Retention is deliberately not signature verification.
        "{\"signer_public_key_hex\":\"00\",\"payload_json\":\"{}\",\"signature_hex\":\"00\"}"
            .to_owned()
    }

    #[test]
    fn exact_candidate_survives_reopen_and_requires_current_clock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source");
        let mut cache = SourceCache::open(&path, &endpoint()).unwrap();
        assert!(cache.candidate(100).is_err());
        let expected = format!(" {}\n", document());
        cache.store(Some(expected.clone()), 100).unwrap();
        assert_eq!(cache.candidate(100).unwrap(), expected);
        drop(cache);
        let cache = SourceCache::open(&path, &endpoint()).unwrap();
        assert_eq!(cache.candidate(101).unwrap(), expected);
        assert!(cache.candidate(99).is_err());
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn durable_refusal_prevents_falling_back_to_the_old_document() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source");
        let mut cache = SourceCache::open(&path, &endpoint()).unwrap();
        cache.store(Some(document()), 100).unwrap();
        cache.store(None, 101).unwrap();
        drop(cache);
        let mut cache = SourceCache::open(&path, &endpoint()).unwrap();
        assert!(cache.candidate(102).is_err());
        cache.store(Some(document()), 102).unwrap();
        assert_eq!(cache.candidate(103).unwrap(), document());
    }

    #[test]
    fn source_binding_and_exclusive_ownership_are_required() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source");
        let mut cache = SourceCache::open(&path, &endpoint()).unwrap();
        cache.store(Some(document()), 100).unwrap();
        assert!(SourceCache::open(&path, &endpoint()).is_err());
        drop(cache);
        let other = url::Url::parse("https://other.example/members").unwrap();
        assert!(SourceCache::open(&path, &other).is_err());
    }

    #[test]
    fn missing_or_corrupt_initialized_source_never_resets_history() {
        for missing in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("source");
            let mut cache = SourceCache::open(&path, &endpoint()).unwrap();
            cache.store(Some(document()), 100).unwrap();
            drop(cache);
            if missing {
                std::fs::rename(&path, dir.path().join("preserved")).unwrap();
            } else {
                std::fs::write(&path, b"corrupt-source-secret").unwrap();
            }
            let error = SourceCache::open(&path, &endpoint())
                .err()
                .unwrap()
                .to_string();
            assert!(!error.contains("corrupt-source-secret"));
            assert!(!error.contains(path.to_str().unwrap()));
        }
    }

    #[test]
    fn unsafe_links_permissions_and_relative_paths_are_refused() {
        assert!(validate_path(Path::new("relative")).is_err());
        assert!(validate_path(Path::new("/tmp/../source")).is_err());
        for hard_link in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let protected = dir.path().join("protected");
            std::fs::write(&protected, b"do-not-change").unwrap();
            std::fs::set_permissions(&protected, std::fs::Permissions::from_mode(0o600)).unwrap();
            let path = dir.path().join("source");
            if hard_link {
                std::fs::hard_link(&protected, &path).unwrap();
            } else {
                std::os::unix::fs::symlink(&protected, &path).unwrap();
            }
            assert!(SourceCache::open(&path, &endpoint()).is_err());
            assert_eq!(std::fs::read(&protected).unwrap(), b"do-not-change");
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source");
        let mut cache = SourceCache::open(&path, &endpoint()).unwrap();
        cache.store(Some(document()), 100).unwrap();
        drop(cache);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(SourceCache::open(&path, &endpoint()).is_err());
    }

    #[test]
    fn identical_source_does_not_rewrite_or_renew_the_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source");
        let mut cache = SourceCache::open(&path, &endpoint()).unwrap();
        cache.store(Some(document()), 100).unwrap();
        let before = std::fs::read(&path).unwrap();
        cache.store(Some(document()), 200).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(cache.current.as_ref().unwrap().observed_at_ms, 100);
    }
}
