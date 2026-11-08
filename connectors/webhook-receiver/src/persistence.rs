//! Encrypted, exclusively owned local storage for webhook acceptance state.
//!
//! A mutation is appended and synchronized before the caller publishes it in
//! memory. Checkpoints stream bounded records into a new encrypted file, sync
//! it, replace the journal atomically, and sync its directory. A failed write
//! fences the live handle until recovery. Recovery never discards a corrupt or
//! incomplete tail: without an independent trusted commit frontier it cannot
//! prove that such bytes were never acknowledged.
//!
//! This is local durable storage, not a canonical mesh replica or an external
//! rollback anchor. Restoring a complete older valid directory cannot be
//! detected without independently retained newer authority.

use std::path::PathBuf;

use fcp_core::ZoneId;
use serde::{Deserialize, Serialize};

use crate::error::{WebhookReceiverError, WebhookReceiverResult};

/// Explicit provisioning for one receiver's durable zone and intake namespace.
///
/// The key is supplied in a separate owner-only file: exactly 32 raw bytes or
/// 64 hexadecimal characters, optionally followed by one newline. Ordinary
/// opening never initializes missing state. Set `initialize` only for the first
/// provisioning operation, then omit it when reopening the same store.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DurableStoreConfig {
    /// Absolute owner-only directory for this receiver's journal and lock.
    pub directory: PathBuf,
    /// Absolute path to a private file containing the independently retained key.
    pub key_file: PathBuf,
    /// Exact zone authorized to use the recovered state.
    pub zone: ZoneId,
    /// Create a new store. Refuses every existing store or partial initialization.
    #[serde(default)]
    pub initialize: bool,
}

fn unavailable(message: &str) -> WebhookReceiverError {
    WebhookReceiverError::Persistence {
        message: message.to_owned(),
    }
}

#[cfg(unix)]
pub(crate) use native::DurableJournal;

#[cfg(unix)]
mod native {
    use std::fs::{self, DirBuilder, File, Metadata, OpenOptions};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
    use std::path::{Component, Path};

    use fcp_crypto::aead::{AeadKey, XChaCha20Nonce, XChaCha20Poly1305Cipher};
    use rand::RngCore;
    use subtle::ConstantTimeEq;
    use zeroize::Zeroizing;

    use super::{DurableStoreConfig, PathBuf, WebhookReceiverResult, ZoneId, unavailable};
    use crate::client::{PersistedRecord, StoreRecovery, WebhookStore};

    const JOURNAL_NAME: &str = "state.journal";
    const IDENTITY_NAME: &str = "identity.bin";
    const LOCK_NAME: &str = "writer.lock";
    const IDENTITY_MAGIC: &[u8; 8] = b"FCPWHI01";
    const JOURNAL_MAGIC: &[u8; 8] = b"FCPWHJ01";
    const IDENTITY_BYTES: usize = 8 + 16 + 32;
    const HEADER_BYTES: usize = 8 + 16 + 16 + 32;
    const NONCE_BYTES: usize = 24;
    const TAG_BYTES: usize = 16;
    // One accepted event is already bounded to 16 MiB of serialized JSON.
    // Leave room for its record discriminant, digest and framing.
    const MAX_FRAME_BYTES: usize = 20 * 1024 * 1024;
    const MAX_CHECKPOINT_BYTES: u64 = 160 * 1024 * 1024;
    const MAX_JOURNAL_BYTES: u64 = 256 * 1024 * 1024;
    const CHECKPOINT_DELTA_BYTES: u64 = 64 * 1024 * 1024;
    const CHECKPOINT_MUTATIONS: u64 = 256;

    struct DirectoryAnchor {
        path: PathBuf,
        metadata: Metadata,
    }

    struct FrameState {
        header: [u8; HEADER_BYTES],
        ordinal: u64,
        previous_digest: [u8; 32],
        bytes: u64,
    }

    impl FrameState {
        fn new(store_id: &[u8; 16], scope: &[u8; 32]) -> Self {
            let mut header = [0; HEADER_BYTES];
            header[..8].copy_from_slice(JOURNAL_MAGIC);
            header[8..24].copy_from_slice(store_id);
            rand::rngs::OsRng.fill_bytes(&mut header[24..40]);
            header[40..].copy_from_slice(scope);
            Self::from_header(header)
        }

        fn from_header(header: [u8; HEADER_BYTES]) -> Self {
            Self {
                header,
                ordinal: 0,
                previous_digest: [0; 32],
                bytes: HEADER_BYTES as u64,
            }
        }

        fn associated_data(&self, next: u64) -> Vec<u8> {
            let mut aad = b"fcp.webhook.journal.record.v1\0".to_vec();
            aad.extend_from_slice(&self.header);
            aad.extend_from_slice(&next.to_be_bytes());
            aad.extend_from_slice(&self.previous_digest);
            aad
        }

        fn advance(&mut self, next: u64, length: &[u8; 4], frame: &[u8]) {
            let mut digest = blake3::Hasher::new_derive_key("fcp.webhook.journal.chain.v1");
            digest.update(&self.associated_data(next));
            digest.update(length);
            digest.update(frame);
            self.previous_digest = *digest.finalize().as_bytes();
            self.ordinal = next;
            self.bytes += 4 + frame.len() as u64;
        }
    }

    /// A writer lock and authenticated journal held for the whole store lifetime.
    pub(crate) struct DurableJournal {
        directory: PathBuf,
        directory_file: File,
        ancestors: Vec<DirectoryAnchor>,
        owner: u32,
        writer_lock: File,
        identity_file: File,
        file: File,
        key: AeadKey,
        store_id: [u8; 16],
        scope: [u8; 32],
        zone: ZoneId,
        frames: FrameState,
        checkpoint_bytes: u64,
        mutations: u64,
        fenced: bool,
    }

    impl std::fmt::Debug for DurableJournal {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter
                .debug_struct("DurableJournal")
                .field("zone", &self.zone)
                .field("fenced", &self.fenced)
                .finish_non_exhaustive()
        }
    }

    impl DurableJournal {
        pub(crate) fn open(
            config: &DurableStoreConfig,
            public_base_url: &str,
            store: &mut WebhookStore,
        ) -> WebhookReceiverResult<Self> {
            let (directory_file, ancestors, owner) =
                prepare_directory(&config.directory, config.initialize)?;
            let master_key = read_key(&config.key_file, owner)?;
            let encryption_key = AeadKey::from_bytes(blake3::derive_key(
                "fcp.webhook.persistence.encryption.v1",
                master_key.as_bytes(),
            ));
            let scope = scope_digest(&config.zone, public_base_url);
            let lock_path = config.directory.join(LOCK_NAME);
            let writer_lock = open_private(&lock_path, owner, config.initialize)?;
            writer_lock
                .try_lock()
                .map_err(|_| unavailable("another receiver owns this durable store"))?;
            verify_named_file(&writer_lock, &lock_path, owner)?;
            recheck_directories(&ancestors)?;
            if config.initialize {
                writer_lock
                    .sync_all()
                    .map_err(|_| unavailable("cannot synchronize writer ownership"))?;
                directory_file
                    .sync_all()
                    .map_err(|_| unavailable("cannot synchronize store initialization"))?;
            }

            let identity_path = config.directory.join(IDENTITY_NAME);
            let mut identity_file = open_private(&identity_path, owner, config.initialize)?;
            let store_id = if config.initialize {
                let mut store_id = [0; 16];
                rand::rngs::OsRng.fill_bytes(&mut store_id);
                let bytes = identity_bytes(&master_key, &store_id, &scope);
                identity_file
                    .write_all(&bytes)
                    .and_then(|()| identity_file.sync_all())
                    .map_err(|_| unavailable("cannot synchronize the store identity"))?;
                directory_file
                    .sync_all()
                    .map_err(|_| unavailable("cannot synchronize the store identity directory"))?;
                store_id
            } else {
                let mut bytes = [0; IDENTITY_BYTES];
                if identity_file
                    .metadata()
                    .map_err(|_| unavailable("store identity metadata is unavailable"))?
                    .len()
                    != IDENTITY_BYTES as u64
                {
                    return Err(unavailable("store identity has an invalid length"));
                }
                identity_file
                    .read_exact(&mut bytes)
                    .map_err(|_| unavailable("cannot read the complete store identity"))?;
                let mut store_id = [0; 16];
                store_id.copy_from_slice(&bytes[8..24]);
                let expected = identity_bytes(&master_key, &store_id, &scope);
                if !bool::from(expected.ct_eq(&bytes)) {
                    return Err(unavailable("store key, zone, namespace or identity does not match"));
                }
                store_id
            };

            let file = open_private(
                &config.directory.join(JOURNAL_NAME),
                owner,
                config.initialize,
            )?;
            let frames = FrameState::new(&store_id, &scope);
            let mut journal = Self {
                directory: config.directory.clone(),
                directory_file,
                ancestors,
                owner,
                writer_lock,
                identity_file,
                file,
                key: encryption_key,
                store_id,
                scope,
                zone: config.zone.clone(),
                frames,
                checkpoint_bytes: 0,
                mutations: 0,
                fenced: false,
            };
            if config.initialize {
                journal
                    .file
                    .write_all(&journal.frames.header)
                    .map_err(|_| unavailable("cannot write the journal header"))?;
                store.visit_checkpoint(|record| {
                    write_frame(
                        &journal.key,
                        &mut journal.file,
                        &mut journal.frames,
                        record,
                        MAX_CHECKPOINT_BYTES,
                    )
                })?;
                journal
                    .file
                    .sync_all()
                    .and_then(|()| journal.directory_file.sync_all())
                    .map_err(|_| unavailable("cannot synchronize the initial checkpoint"))?;
                journal.checkpoint_bytes = journal.frames.bytes;
            } else {
                *store = journal.recover(public_base_url)?;
            }
            journal.check_identity()?;
            Ok(journal)
        }

        pub(crate) const fn is_fenced(&self) -> bool {
            self.fenced
        }

        pub(crate) const fn zone(&self) -> &ZoneId {
            &self.zone
        }

        pub(crate) fn needs_checkpoint(&self) -> bool {
            self.mutations >= CHECKPOINT_MUTATIONS
                || self.frames.bytes.saturating_sub(self.checkpoint_bytes)
                    >= CHECKPOINT_DELTA_BYTES
        }

        pub(crate) fn append(&mut self, record: &PersistedRecord) -> WebhookReceiverResult<()> {
            if self.fenced {
                return Err(unavailable("writer is fenced until the store is reopened"));
            }
            if is_checkpoint_record(record) {
                return Err(unavailable("checkpoint records require a complete checkpoint"));
            }
            let result = (|| {
                self.check_identity()?;
                self.file
                    .seek(SeekFrom::End(0))
                    .map_err(|_| unavailable("cannot position the durable journal"))?;
                write_frame(
                    &self.key,
                    &mut self.file,
                    &mut self.frames,
                    record,
                    MAX_JOURNAL_BYTES,
                )?;
                self.file
                    .sync_all()
                    .map_err(|_| unavailable("journal synchronization outcome is uncertain"))?;
                self.check_identity()?;
                self.mutations = self.mutations.saturating_add(1);
                Ok(())
            })();
            if result.is_err() {
                self.fenced = true;
            }
            result
        }

        pub(crate) fn checkpoint(&mut self, store: &WebhookStore) -> WebhookReceiverResult<()> {
            if self.fenced {
                return Err(unavailable("writer is fenced until the store is reopened"));
            }
            let result = self.write_checkpoint(store);
            if result.is_err() {
                self.fenced = true;
            }
            result
        }

        fn write_checkpoint(&mut self, store: &WebhookStore) -> WebhookReceiverResult<()> {
            self.check_identity()?;
            let staging = self.directory.join(format!(
                ".checkpoint-{}.pending",
                uuid::Uuid::new_v4().simple(),
            ));
            let mut file = open_private(&staging, self.owner, true)?;
            let mut frames = FrameState::new(&self.store_id, &self.scope);
            file.write_all(&frames.header)
                .map_err(|_| unavailable("cannot write the checkpoint header"))?;
            store.visit_checkpoint(|record| {
                write_frame(
                    &self.key,
                    &mut file,
                    &mut frames,
                    record,
                    MAX_CHECKPOINT_BYTES,
                )
            })?;
            file.sync_all()
                .map_err(|_| unavailable("cannot synchronize the complete checkpoint"))?;
            self.check_identity()?;
            verify_named_file(&file, &staging, self.owner)?;
            fs::rename(&staging, self.directory.join(JOURNAL_NAME))
                .map_err(|_| unavailable("checkpoint publication outcome is uncertain"))?;
            // Install the new handle even if directory sync subsequently fails:
            // the caller fences this instance and only recovery may resume it.
            self.file = file;
            self.frames = frames;
            self.checkpoint_bytes = self.frames.bytes;
            self.mutations = 0;
            self.directory_file
                .sync_all()
                .map_err(|_| unavailable("checkpoint directory synchronization is uncertain"))?;
            self.check_identity()
        }

        fn recover(&mut self, public_base_url: &str) -> WebhookReceiverResult<WebhookStore> {
            let length = self
                .file
                .metadata()
                .map_err(|_| unavailable("journal metadata is unavailable"))?
                .len();
            if !(HEADER_BYTES as u64..=MAX_JOURNAL_BYTES).contains(&length) {
                return Err(unavailable("journal length exceeds its format bounds"));
            }
            let mut header = [0; HEADER_BYTES];
            self.file
                .read_exact(&mut header)
                .map_err(|_| unavailable("journal header is incomplete"))?;
            if &header[..8] != JOURNAL_MAGIC
                || header[8..24] != self.store_id
                || header[40..] != self.scope
            {
                return Err(unavailable("journal format, store identity or scope does not match"));
            }
            let mut frames = FrameState::from_header(header);
            let mut recovered = StoreRecovery::new(public_base_url);
            let mut checkpoint_bytes = 0;
            let mut mutations = 0_u64;
            while frames.bytes < length {
                if length - frames.bytes < 4 {
                    return Err(unavailable("journal has an incomplete final frame"));
                }
                let mut prefix = [0; 4];
                self.file
                    .read_exact(&mut prefix)
                    .map_err(|_| unavailable("journal frame length is unavailable"))?;
                let frame_length = u32::from_be_bytes(prefix) as usize;
                if !(NONCE_BYTES + TAG_BYTES..=MAX_FRAME_BYTES).contains(&frame_length)
                    || frame_length as u64 > length - frames.bytes - 4
                {
                    return Err(unavailable("journal frame is incomplete or exceeds its bound"));
                }
                let mut frame = vec![0; frame_length];
                self.file
                    .read_exact(&mut frame)
                    .map_err(|_| unavailable("cannot read the complete journal frame"))?;
                let ordinal = frames
                    .ordinal
                    .checked_add(1)
                    .ok_or_else(|| unavailable("journal ordinal is exhausted"))?;
                let nonce = XChaCha20Nonce::try_from_slice(&frame[..NONCE_BYTES])
                    .map_err(|_| unavailable("journal nonce is malformed"))?;
                let plaintext = Zeroizing::new(
                    XChaCha20Poly1305Cipher::new(&self.key)
                        .decrypt(
                            &nonce,
                            &frame[NONCE_BYTES..],
                            &frames.associated_data(ordinal),
                        )
                        .map_err(|_| unavailable("journal authentication failed"))?,
                );
                let record: PersistedRecord = serde_json::from_slice(&plaintext)
                    .map_err(|_| unavailable("authenticated journal record is malformed"))?;
                let completed_checkpoint = matches!(record, PersistedRecord::CheckpointEnd);
                let mutation = !is_checkpoint_record(&record);
                recovered.consume(record).map_err(|_| {
                    unavailable("authenticated journal violates receiver state invariants")
                })?;
                frames.advance(ordinal, &prefix, &frame);
                if completed_checkpoint {
                    checkpoint_bytes = frames.bytes;
                }
                if mutation {
                    mutations = mutations.saturating_add(1);
                }
            }
            if checkpoint_bytes == 0 || checkpoint_bytes > MAX_CHECKPOINT_BYTES {
                return Err(unavailable("journal has no complete bounded checkpoint"));
            }
            let store = recovered.finish().map_err(|_| {
                unavailable("journal cannot recover a complete valid receiver state")
            })?;
            self.frames = frames;
            self.checkpoint_bytes = checkpoint_bytes;
            self.mutations = mutations;
            Ok(store)
        }

        fn check_identity(&self) -> WebhookReceiverResult<()> {
            recheck_directories(&self.ancestors)?;
            verify_named_file(
                &self.writer_lock,
                &self.directory.join(LOCK_NAME),
                self.owner,
            )?;
            verify_named_file(
                &self.identity_file,
                &self.directory.join(IDENTITY_NAME),
                self.owner,
            )?;
            verify_named_file(&self.file, &self.directory.join(JOURNAL_NAME), self.owner)?;
            if self
                .file
                .metadata()
                .map_err(|_| unavailable("journal metadata is unavailable"))?
                .len()
                != self.frames.bytes
            {
                return Err(unavailable("journal length changed outside the owned writer"));
            }
            Ok(())
        }
    }

    fn is_checkpoint_record(record: &PersistedRecord) -> bool {
        matches!(
            record,
            PersistedRecord::CheckpointStart { .. }
                | PersistedRecord::CheckpointEndpoint { .. }
                | PersistedRecord::CheckpointReplay { .. }
                | PersistedRecord::CheckpointEvent { .. }
                | PersistedRecord::CheckpointEnd
        )
    }

    fn write_frame(
        key: &AeadKey,
        file: &mut File,
        state: &mut FrameState,
        record: &PersistedRecord,
        byte_limit: u64,
    ) -> WebhookReceiverResult<()> {
        let ordinal = state
            .ordinal
            .checked_add(1)
            .ok_or_else(|| unavailable("journal ordinal is exhausted"))?;
        let plaintext = Zeroizing::new(
            serde_json::to_vec(record)
                .map_err(|_| unavailable("receiver state could not be encoded"))?,
        );
        if plaintext.len() > MAX_FRAME_BYTES - NONCE_BYTES - TAG_BYTES {
            return Err(unavailable("receiver state record exceeds its encoded byte bound"));
        }
        let frame = XChaCha20Poly1305Cipher::new(key)
            .encrypt_with_random_nonce(&plaintext, &state.associated_data(ordinal))
            .map_err(|_| unavailable("receiver state encryption failed"))?;
        if state.bytes.saturating_add(4 + frame.len() as u64) > byte_limit {
            return Err(unavailable("durable journal exceeds its recovery byte bound"));
        }
        let length = u32::try_from(frame.len())
            .map_err(|_| unavailable("receiver state frame length is unrepresentable"))?
            .to_be_bytes();
        file.write_all(&length)
            .and_then(|()| file.write_all(&frame))
            .map_err(|_| unavailable("journal append outcome is uncertain"))?;
        state.advance(ordinal, &length, &frame);
        Ok(())
    }

    fn scope_digest(zone: &ZoneId, public_base_url: &str) -> [u8; 32] {
        let mut digest = blake3::Hasher::new_derive_key("fcp.webhook.persistence.scope.v1");
        for part in ["fcp.webhook-receiver", zone.as_str(), public_base_url] {
            digest.update(&(part.len() as u64).to_be_bytes());
            digest.update(part.as_bytes());
        }
        *digest.finalize().as_bytes()
    }

    fn identity_bytes(
        key: &AeadKey,
        store_id: &[u8; 16],
        scope: &[u8; 32],
    ) -> [u8; IDENTITY_BYTES] {
        let identity_key = Zeroizing::new(blake3::derive_key(
            "fcp.webhook.persistence.identity.v1",
            key.as_bytes(),
        ));
        let mut digest = blake3::Hasher::new_keyed(&identity_key);
        digest.update(IDENTITY_MAGIC);
        digest.update(store_id);
        digest.update(scope);
        let mut bytes = [0; IDENTITY_BYTES];
        bytes[..8].copy_from_slice(IDENTITY_MAGIC);
        bytes[8..24].copy_from_slice(store_id);
        bytes[24..].copy_from_slice(digest.finalize().as_bytes());
        bytes
    }

    fn read_key(path: &Path, owner: u32) -> WebhookReceiverResult<AeadKey> {
        require_absolute(path)?;
        let parent = path
            .parent()
            .ok_or_else(|| unavailable("key file requires a protected parent"))?;
        let ancestors = inspect_directories(parent, Some(owner))?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        let file = options
            .open(path)
            .map_err(|_| unavailable("cannot open the private key file"))?;
        verify_named_file(&file, path, owner)?;
        let mut bytes = Zeroizing::new(Vec::new());
        file.take(67)
            .read_to_end(&mut bytes)
            .map_err(|_| unavailable("cannot read the private key file"))?;
        recheck_directories(&ancestors)?;
        if bytes.len() == 32 {
            return AeadKey::try_from_slice(&bytes)
                .map_err(|_| unavailable("durable encryption key is malformed"));
        }
        let trimmed = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
        if trimmed.len() != 64 {
            return Err(unavailable("key file must contain 32 raw bytes or 64 hex characters"));
        }
        let mut decoded = Zeroizing::new([0; 32]);
        hex::decode_to_slice(trimmed, decoded.as_mut())
            .map_err(|_| unavailable("durable encryption key is malformed"))?;
        AeadKey::try_from_slice(decoded.as_ref())
            .map_err(|_| unavailable("durable encryption key is malformed"))
    }

    fn require_absolute(path: &Path) -> WebhookReceiverResult<()> {
        if !path.is_absolute()
            || path.file_name().is_none()
            || path
                .components()
                .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
        {
            return Err(unavailable("storage paths must be absolute without traversal"));
        }
        Ok(())
    }

    fn prepare_directory(
        path: &Path,
        initialize: bool,
    ) -> WebhookReceiverResult<(File, Vec<DirectoryAnchor>, u32)> {
        require_absolute(path)?;
        let parent = path
            .parent()
            .ok_or_else(|| unavailable("store directory requires a protected parent"))?;
        // Reject links and mutable shared ancestors before even creating an
        // empty directory or ownership probe through the configured path.
        let prior_parents = inspect_directories(parent, None)?;
        if initialize && !path.exists() {
            DirBuilder::new()
                .mode(0o700)
                .create(path)
                .map_err(|_| unavailable("cannot create the private store directory"))?;
        }
        let metadata = fs::symlink_metadata(path)
            .map_err(|_| unavailable("durable store directory is missing"))?;
        if !metadata.is_dir() || metadata.mode() & 0o077 != 0 {
            return Err(unavailable("durable store requires an owner-only directory"));
        }
        // The anonymous empty probe establishes the process's filesystem UID,
        // including when privileges would otherwise allow another user's files.
        let probe = tempfile::tempfile_in(path)
            .map_err(|_| unavailable("private store directory is not writable"))?;
        let owner = probe
            .metadata()
            .map_err(|_| unavailable("filesystem writer identity is unavailable"))?
            .uid();
        if metadata.uid() != owner {
            return Err(unavailable("private store directory belongs to another user"));
        }
        let ancestors = inspect_directories(path, Some(owner))?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|_| unavailable("cannot open the protected store directory"))?;
        let opened = directory
            .metadata()
            .map_err(|_| unavailable("store directory metadata is unavailable"))?;
        if !same_file(&metadata, &opened) {
            return Err(unavailable("store directory changed during opening"));
        }
        recheck_directories(&prior_parents)?;
        recheck_directories(&ancestors)?;
        if initialize {
            // Creating and syncing files inside a directory does not persist
            // that directory's own entry in its parent. A fresh store must
            // establish both before it can ever acknowledge a delivery.
            let parent_file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(parent)
                .map_err(|_| unavailable("cannot open the protected store parent"))?;
            let opened_parent = parent_file
                .metadata()
                .map_err(|_| unavailable("store parent metadata is unavailable"))?;
            let expected = prior_parents
                .last()
                .ok_or_else(|| unavailable("store parent identity is missing"))?;
            if !same_file(&expected.metadata, &opened_parent) {
                return Err(unavailable("store parent changed during initialization"));
            }
            parent_file
                .sync_all()
                .map_err(|_| unavailable("cannot synchronize the store parent directory"))?;
            recheck_directories(&ancestors)?;
        }
        Ok((directory, ancestors, owner))
    }

    fn inspect_directories(
        path: &Path,
        owner: Option<u32>,
    ) -> WebhookReceiverResult<Vec<DirectoryAnchor>> {
        let mut paths = path.ancestors().collect::<Vec<_>>();
        paths.reverse();
        let mut result = Vec::with_capacity(paths.len());
        for path in paths {
            let metadata = fs::symlink_metadata(path)
                .map_err(|_| unavailable("storage ancestor is unavailable"))?;
            if !metadata.is_dir()
                || owner.is_some_and(|owner| metadata.uid() != 0 && metadata.uid() != owner)
                || (metadata.mode() & 0o022 != 0
                    && !(metadata.uid() == 0 && metadata.mode() & 0o1000 != 0))
            {
                return Err(unavailable("storage ancestors must be trusted directories without links"));
            }
            result.push(DirectoryAnchor {
                path: path.to_path_buf(),
                metadata,
            });
        }
        Ok(result)
    }

    fn recheck_directories(ancestors: &[DirectoryAnchor]) -> WebhookReceiverResult<()> {
        for anchor in ancestors {
            let current = fs::symlink_metadata(&anchor.path)
                .map_err(|_| unavailable("protected storage directory disappeared"))?;
            if !current.is_dir()
                || !same_file(&anchor.metadata, &current)
                || current.mode() != anchor.metadata.mode()
            {
                return Err(unavailable("protected storage directory changed"));
            }
        }
        Ok(())
    }

    fn open_private(path: &Path, owner: u32, create: bool) -> WebhookReceiverResult<File> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(create)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|_| unavailable("durable file is missing, already initialized or inaccessible"))?;
        verify_named_file(&file, path, owner)?;
        Ok(file)
    }

    fn verify_named_file(file: &File, path: &Path, owner: u32) -> WebhookReceiverResult<()> {
        let opened = file
            .metadata()
            .map_err(|_| unavailable("durable file metadata is unavailable"))?;
        let named = fs::symlink_metadata(path)
            .map_err(|_| unavailable("durable file disappeared"))?;
        if !opened.is_file()
            || !named.is_file()
            || opened.uid() != owner
            || opened.nlink() != 1
            || opened.mode() & 0o077 != 0
            || named.mode() != opened.mode()
            || !same_file(&opened, &named)
        {
            return Err(unavailable("durable files must remain private, singly linked and unchanged"));
        }
        Ok(())
    }

    fn same_file(left: &Metadata, right: &Metadata) -> bool {
        left.dev() == right.dev() && left.ino() == right.ino() && left.uid() == right.uid()
    }

    #[cfg(test)]
    mod tests {
        use std::os::unix::fs::{PermissionsExt, symlink};

        use serde_json::json;

        use super::*;
        use crate::error::WebhookReceiverError;
        use crate::types::WebhookEvent;

        const BASE: &str = "https://hooks.example.test";
        const SECRET: &str = "private-signing-secret-never-written-in-clear";

        fn private_key(path: &Path, bytes: &[u8]) {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .unwrap();
            file.write_all(bytes).unwrap();
            file.sync_all().unwrap();
        }

        fn fixture() -> (tempfile::TempDir, DurableStoreConfig) {
            let root = tempfile::tempdir().unwrap();
            let key_file = root.path().join("encryption.key");
            private_key(&key_file, &[81; 32]);
            let config = DurableStoreConfig {
                directory: root.path().join("state"),
                key_file,
                zone: ZoneId::work(),
                initialize: true,
            };
            (root, config)
        }

        fn reopen(config: &DurableStoreConfig) -> DurableStoreConfig {
            DurableStoreConfig {
                initialize: false,
                ..config.clone()
            }
        }

        fn event(endpoint: &str, id: &str) -> WebhookEvent {
            let mut event = WebhookEvent::new(
                endpoint.to_owned(),
                json!({"private_payload": "provider-body-private-sentinel"}),
                true,
                None,
            );
            event.event_id = id.to_owned();
            event
        }

        #[test]
        fn durable_journal_recovers_secrets_cursors_and_authenticated_replay_without_plaintext() {
            let (_root, config) = fixture();
            let mut store = WebhookStore::open_durable(&config, BASE).unwrap();
            let endpoint = store
                .create_endpoint("/hooks/test".into(), SECRET.into(), vec![])
                .unwrap();
            let accepted = event(&endpoint.endpoint_id, "accepted-original-id");
            store
                .record_authenticated_event(accepted.clone(), [37; 32])
                .unwrap();
            let page = store
                .poll_events(&endpoint.endpoint_id, None, 10, 4096, false)
                .unwrap();
            let cursor = page.start_cursor;
            let journal = fs::read(config.directory.join(JOURNAL_NAME)).unwrap();
            for private in [SECRET, "provider-body-private-sentinel", "accepted-original-id"] {
                assert!(!journal.windows(private.len()).any(|bytes| bytes == private.as_bytes()));
            }
            drop(store);

            let mut recovered = WebhookStore::open_durable(&reopen(&config), BASE).unwrap();
            assert_eq!(recovered.durable_zone(), Some(&ZoneId::work()));
            assert_eq!(recovered.get_endpoint(&endpoint.endpoint_id).unwrap().signing_secret, SECRET);
            let page = recovered
                .poll_events(&endpoint.endpoint_id, Some(&cursor), 10, 4096, false)
                .unwrap();
            assert_eq!(page.events.len(), 1);
            assert_eq!(page.events[0].0, 0);
            assert_eq!(page.events[0].1.event_id, accepted.event_id);
            assert_eq!(page.events[0].1.payload, accepted.payload);
            assert!(matches!(
                recovered.record_event(accepted),
                Err(WebhookReceiverError::DuplicateEvent { .. })
            ));
            assert!(matches!(
                recovered.record_authenticated_event(
                    event(&endpoint.endpoint_id, "different-unsigned-transport-id"),
                    [37; 32],
                ),
                Err(WebhookReceiverError::DuplicateEvent { .. })
            ));
            assert_eq!(fs::read(config.directory.join(JOURNAL_NAME)).unwrap(), journal);
        }

        #[test]
        fn durable_journal_checkpoints_preserve_evicted_replay_ids_and_cursor_gaps() {
            let (_root, config) = fixture();
            let mut store = WebhookStore::open_durable(&config, BASE).unwrap();
            let endpoint = store
                .create_endpoint("/hooks/test".into(), SECRET.into(), vec![])
                .unwrap();
            let start = store
                .poll_events(&endpoint.endpoint_id, None, 1, 4096, false)
                .unwrap()
                .start_cursor;
            let initial = fs::read(config.directory.join(JOURNAL_NAME)).unwrap();
            for index in 0..1100_u64 {
                store
                    .record_authenticated_event(
                        event(&endpoint.endpoint_id, &format!("event-{index}")),
                        *blake3::hash(&index.to_be_bytes()).as_bytes(),
                    )
                    .unwrap();
            }
            let checkpointed = fs::read(config.directory.join(JOURNAL_NAME)).unwrap();
            assert_ne!(&checkpointed[24..40], &initial[24..40], "checkpoint changed file epoch");
            assert!(checkpointed.len() < 4 * 1024 * 1024);
            drop(store);

            let mut recovered = WebhookStore::open_durable(&reopen(&config), BASE).unwrap();
            assert!(matches!(
                recovered.poll_events(&endpoint.endpoint_id, Some(&start), 1, 4096, false),
                Err(WebhookReceiverError::ReplayGap { .. })
            ));
            let page = recovered
                .poll_events(&endpoint.endpoint_id, None, 1, 4096, false)
                .unwrap();
            assert_eq!(page.events[0].0, 100);
            assert_eq!(page.next_sequence, 1100);
            assert!(page.history_truncated);
            assert!(matches!(
                recovered.record_event(event(&endpoint.endpoint_id, "event-0")),
                Err(WebhookReceiverError::DuplicateEvent { .. })
            ));
            assert!(matches!(
                recovered.record_authenticated_event(
                    event(&endpoint.endpoint_id, "renamed-evicted-event"),
                    *blake3::hash(&0_u64.to_be_bytes()).as_bytes(),
                ),
                Err(WebhookReceiverError::DuplicateEvent { .. })
            ));
        }

        #[test]
        fn durable_journal_requires_exact_key_zone_and_intake_namespace() {
            let (root, config) = fixture();
            drop(WebhookStore::open_durable(&config, BASE).unwrap());
            let before = fs::read(config.directory.join(JOURNAL_NAME)).unwrap();
            let mut wrong_zone = reopen(&config);
            wrong_zone.zone = ZoneId::private();
            let mut wrong_key = reopen(&config);
            wrong_key.key_file = root.path().join("wrong.key");
            private_key(&wrong_key.key_file, &[82; 32]);
            for (scope, base) in [
                (wrong_zone, BASE),
                (wrong_key, BASE),
                (reopen(&config), "https://another.example.test"),
            ] {
                let error = WebhookStore::open_durable(&scope, base).unwrap_err();
                assert!(matches!(error, WebhookReceiverError::Persistence { .. }));
                assert!(!error.to_string().contains(&root.path().to_string_lossy().to_string()));
                assert_eq!(fs::read(config.directory.join(JOURNAL_NAME)).unwrap(), before);
            }
            assert!(WebhookStore::open_durable(&reopen(&config), BASE).is_ok());
        }

        #[test]
        fn durable_journal_excludes_second_writer_and_never_reinitializes_missing_state() {
            let (_root, config) = fixture();
            let store = WebhookStore::open_durable(&config, BASE).unwrap();
            assert!(WebhookStore::open_durable(&reopen(&config), BASE).is_err());
            assert!(WebhookStore::open_durable(&config, BASE).is_err());
            drop(store);
            let preserved = config.directory.join("preserved.journal");
            fs::rename(config.directory.join(JOURNAL_NAME), &preserved).unwrap();
            assert!(WebhookStore::open_durable(&reopen(&config), BASE).is_err());
            assert!(WebhookStore::open_durable(&config, BASE).is_err());
            assert!(!config.directory.join(JOURNAL_NAME).exists());
            assert!(preserved.exists());
        }

        #[test]
        fn durable_journal_corrupt_and_partial_frames_fail_without_repair() {
            let (_root, config) = fixture();
            let mut store = WebhookStore::open_durable(&config, BASE).unwrap();
            store.create_endpoint("/hooks/test".into(), SECRET.into(), vec![]).unwrap();
            drop(store);
            let path = config.directory.join(JOURNAL_NAME);
            let original = fs::read(&path).unwrap();
            let mut tampered = original.clone();
            *tampered.last_mut().unwrap() ^= 1;
            let mut truncated = original.clone();
            truncated.pop();
            let mut partial_length = original.clone();
            partial_length.extend_from_slice(&[0, 0, 0]);
            let mut oversized = original.clone();
            oversized[HEADER_BYTES..HEADER_BYTES + 4].copy_from_slice(&u32::MAX.to_be_bytes());
            for bad in [tampered, truncated, partial_length, oversized] {
                fs::write(&path, &bad).unwrap();
                assert!(WebhookStore::open_durable(&reopen(&config), BASE).is_err());
                assert_eq!(fs::read(&path).unwrap(), bad, "recovery must not discard evidence");
            }
            fs::write(&path, &original).unwrap();
            assert!(WebhookStore::open_durable(&reopen(&config), BASE).is_ok());
        }

        #[test]
        fn durable_journal_append_failure_fences_until_authenticated_reopen() {
            let (_root, config) = fixture();
            let mut memory = WebhookStore::new();
            memory.set_public_base_url(BASE).unwrap();
            let mut journal = DurableJournal::open(&config, BASE, &mut memory).unwrap();
            let path = config.directory.join(JOURNAL_NAME);
            let before = fs::read(&path).unwrap();
            // The same regular file identity remains, but this descriptor cannot
            // append. Even a definite write failure conservatively fences it.
            journal.file = File::open(&path).unwrap();
            let record = PersistedRecord::EndpointDeleted { endpoint_id: "not-committed".into() };
            assert!(journal.append(&record).is_err());
            assert!(journal.is_fenced());
            assert!(journal.append(&record).is_err());
            assert!(journal.checkpoint(&memory).is_err());
            assert_eq!(fs::read(&path).unwrap(), before);
            drop(journal);
            assert!(WebhookStore::open_durable(&reopen(&config), BASE).is_ok());
        }

        #[test]
        fn durable_journal_rejects_replaced_paths_and_shared_key_permissions() {
            let (root, config) = fixture();
            fs::set_permissions(&config.key_file, fs::Permissions::from_mode(0o640)).unwrap();
            assert!(WebhookStore::open_durable(&config, BASE).is_err());
            assert!(!config.directory.join(LOCK_NAME).exists());
            fs::set_permissions(&config.key_file, fs::Permissions::from_mode(0o600)).unwrap();
            let alias = root.path().join("key-link");
            symlink(&config.key_file, &alias).unwrap();
            let alias_config = DurableStoreConfig { key_file: alias, ..config.clone() };
            assert!(WebhookStore::open_durable(&alias_config, BASE).is_err());

            let mut store = WebhookStore::open_durable(&config, BASE).unwrap();
            let path = config.directory.join(JOURNAL_NAME);
            fs::rename(&path, config.directory.join("preserved.journal")).unwrap();
            private_key(&path, b"replacement-file");
            assert!(store.create_endpoint("/hooks/test".into(), SECRET.into(), vec![]).is_err());
            assert!(store.is_fenced());
            assert_eq!(store.endpoint_snapshots().len(), 0);
            assert_eq!(fs::read(path).unwrap(), b"replacement-file");
        }

        #[test]
        fn durable_journal_accepts_private_hex_key_and_redacts_debug_state() {
            let (root, mut config) = fixture();
            config.key_file = root.path().join("hex.key");
            private_key(&config.key_file, format!("{}\n", "4f".repeat(32)).as_bytes());
            let mut memory = WebhookStore::new();
            memory.set_public_base_url(BASE).unwrap();
            let journal = DurableJournal::open(&config, BASE, &mut memory).unwrap();
            let debug = format!("{journal:?}");
            assert!(!debug.contains("4f4f"));
            assert!(!debug.contains(&root.path().to_string_lossy().to_string()));
            drop(journal);
            assert!(WebhookStore::open_durable(&reopen(&config), BASE).is_ok());
        }
    }
}

// Protected local storage deliberately fails closed on targets without the
// required Unix permission, directory-sync and ownership boundary.
#[cfg(not(unix))]
#[derive(Debug)]
pub(crate) struct DurableJournal {
    zone: ZoneId,
}

#[cfg(not(unix))]
impl DurableJournal {
    pub(crate) fn open(
        _config: &DurableStoreConfig,
        _base: &str,
        _store: &mut crate::client::WebhookStore,
    ) -> WebhookReceiverResult<Self> {
        Err(unavailable("protected durable receiver storage requires Unix"))
    }

    pub(crate) const fn is_fenced(&self) -> bool {
        true
    }

    pub(crate) const fn zone(&self) -> &ZoneId {
        &self.zone
    }

    pub(crate) const fn needs_checkpoint(&self) -> bool {
        false
    }

    pub(crate) fn append(
        &mut self,
        _record: &crate::client::PersistedRecord,
    ) -> WebhookReceiverResult<()> {
        Err(unavailable("protected durable receiver storage requires Unix"))
    }

    pub(crate) fn checkpoint(&mut self, _store: &crate::client::WebhookStore) -> WebhookReceiverResult<()> {
        Err(unavailable("protected durable receiver storage requires Unix"))
    }
}
