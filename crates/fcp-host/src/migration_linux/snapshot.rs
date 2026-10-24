//! Bounded, deterministic CRIU image-tree accounting.
//!
//! The caller must exclusively own a quiescent image tree during inspection.
//! Metadata checks detect ordinary replacement/growth; they are not a filesystem
//! transaction against a hostile local writer. Execution consumers must copy
//! and verify into a private tree rather than trust a mutable source directory.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use fcp_prelude::ObjectId;

use super::LinuxMigrationError;

const DOMAIN: &[u8] = b"FCP-HOST-CRIU-SNAPSHOT-V2";
const BUFFER_BYTES: usize = 64 * 1024;
const MAX_ENTRIES: usize = 16_384;
const MAX_DEPTH: usize = 64;
const MAX_PATH_BYTES: usize = 4096;
const MAX_TOTAL_PATH_BYTES: usize = 4 * 1024 * 1024;

type Result<T> = std::result::Result<T, LinuxMigrationError>;

#[derive(Clone, Copy)]
struct Limits {
    bytes: u64,
    entries: usize,
    depth: usize,
    path_bytes: usize,
    total_path_bytes: usize,
}

impl Limits {
    const fn new(bytes: u64) -> Self {
        Self {
            bytes,
            entries: MAX_ENTRIES,
            depth: MAX_DEPTH,
            path_bytes: MAX_PATH_BYTES,
            total_path_bytes: MAX_TOTAL_PATH_BYTES,
        }
    }
}

#[derive(Debug)]
struct Entry {
    relative: PathBuf,
    metadata: Metadata,
}

impl Entry {
    fn length(&self) -> u64 {
        if self.metadata.is_file() { self.metadata.len() } else { 0 }
    }
}

struct Inventory {
    root_metadata: Metadata,
    entries: Vec<Entry>,
    total_bytes: u64,
    path_bytes: usize,
}

fn io_error(context: &'static str, source: io::Error) -> LinuxMigrationError {
    LinuxMigrationError::Io { context, source }
}

fn changed(path: &Path) -> LinuxMigrationError {
    LinuxMigrationError::SnapshotChanged { path: path.to_path_buf() }
}

fn structure_limit(limit: &'static str) -> LinuxMigrationError {
    LinuxMigrationError::SnapshotStructureLimit { limit }
}

fn same_metadata(before: &Metadata, after: &Metadata) -> bool {
    let same = before.is_file() == after.is_file()
        && before.is_dir() == after.is_dir()
        && before.len() == after.len()
        && before.modified().ok() == after.modified().ok();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        same && before.dev() == after.dev() && before.ino() == after.ino()
            && before.ctime() == after.ctime() && before.ctime_nsec() == after.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        same
    }
}

impl Inventory {
    fn read(root: &Path, limits: Limits) -> Result<Self> {
        let root_metadata = fs::symlink_metadata(root)
            .map_err(|error| io_error("inspecting checkpoint image root", error))?;
        if !root_metadata.is_dir() {
            return Err(LinuxMigrationError::UnsupportedSnapshotEntry { path: root.to_path_buf() });
        }
        let mut inventory = Self {
            root_metadata,
            entries: Vec::new(),
            total_bytes: 0,
            path_bytes: 0,
        };
        inventory.collect(root, Path::new(""), limits)?;
        inventory.entries.sort_by(|left, right| left.relative.cmp(&right.relative));
        Ok(inventory)
    }

    fn collect(&mut self, root: &Path, relative: &Path, limits: Limits) -> Result<()> {
        let directory = root.join(relative);
        // Check each directory immediately before traversing it. In particular,
        // never knowingly recurse through a symlink found in a received tree.
        let metadata = fs::symlink_metadata(&directory)
            .map_err(|error| io_error("inspecting checkpoint image directory", error))?;
        if !metadata.is_dir() {
            return Err(LinuxMigrationError::UnsupportedSnapshotEntry { path: directory });
        }
        for entry in fs::read_dir(&directory)
            .map_err(|error| io_error("reading checkpoint image directory", error))?
        {
            let entry = entry.map_err(|error| io_error("reading checkpoint image entry", error))?;
            if self.entries.len() >= limits.entries {
                return Err(structure_limit("entry count"));
            }
            let relative = relative.join(entry.file_name());
            if relative.components().count() > limits.depth {
                return Err(structure_limit("path depth"));
            }
            let path_bytes = relative.as_os_str().as_encoded_bytes().len();
            if path_bytes > limits.path_bytes {
                return Err(structure_limit("relative path bytes"));
            }
            if path_bytes > limits.total_path_bytes.saturating_sub(self.path_bytes) {
                return Err(structure_limit("aggregate path bytes"));
            }
            self.path_bytes += path_bytes;
            let path = root.join(&relative);
            let metadata = fs::symlink_metadata(&path)
                .map_err(|error| io_error("inspecting checkpoint image entry", error))?;
            if !metadata.is_file() && !metadata.is_dir() {
                return Err(LinuxMigrationError::UnsupportedSnapshotEntry { path });
            }
            let directory = metadata.is_dir();
            let length = if directory { 0 } else { metadata.len() };
            if length > limits.bytes.saturating_sub(self.total_bytes) {
                return Err(LinuxMigrationError::SnapshotTooLarge {
                    size_bytes: self.total_bytes.saturating_add(length),
                    max_snapshot_bytes: limits.bytes,
                });
            }
            self.total_bytes += length;
            self.entries.push(Entry { relative: relative.clone(), metadata });
            if directory {
                self.collect(root, &relative, limits)?;
            }
        }
        Ok(())
    }

    fn ensure_unchanged(&self, root: &Path, limits: Limits) -> Result<()> {
        let after = Self::read(root, limits)?;
        if !same_metadata(&self.root_metadata, &after.root_metadata)
            || self.entries.len() != after.entries.len()
            || self.entries.iter().zip(&after.entries).any(|(before, after)| {
                before.relative != after.relative || !same_metadata(&before.metadata, &after.metadata)
            })
        {
            return Err(changed(root));
        }
        Ok(())
    }
}

fn open_regular(root: &Path, entry: &Entry) -> Result<File> {
    let path = root.join(&entry.relative);
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // A replaced FIFO must not block opening; a replaced leaf symlink must
        // not be followed. Source-tree ownership remains a caller obligation.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(&path)
        .map_err(|error| io_error("opening checkpoint image file", error))?;
    let metadata = file.metadata()
        .map_err(|error| io_error("inspecting opened checkpoint image file", error))?;
    if !metadata.is_file() || !same_metadata(&entry.metadata, &metadata) {
        return Err(changed(&path));
    }
    Ok(file)
}

fn hash_header(hasher: &mut blake3::Hasher, entry: &Entry) {
    let path = entry.relative.as_os_str().as_encoded_bytes();
    hasher.update(&[u8::from(entry.metadata.is_file())]);
    // All variable fields are length-framed. V1 concatenated an unframed path
    // with a length and payload, and omitted empty directories altogether.
    hasher.update(&(path.len() as u64).to_le_bytes());
    hasher.update(path);
    hasher.update(&entry.length().to_le_bytes());
}

fn stream_file(
    root: &Path,
    entry: &Entry,
    buffer: &mut [u8],
    mut consume: impl FnMut(&[u8]) -> io::Result<()>,
) -> Result<()> {
    let mut file = open_regular(root, entry)?;
    let mut remaining = entry.length();
    while remaining != 0 {
        let count = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| structure_limit("read buffer"))?;
        let read = match file.read(&mut buffer[..count]) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result.map_err(|error| io_error("reading checkpoint image bytes", error))?,
        };
        if read == 0 {
            return Err(changed(&root.join(&entry.relative)));
        }
        consume(&buffer[..read])
            .map_err(|error| io_error("consuming checkpoint image bytes", error))?;
        remaining -= read as u64;
    }
    // Read at most one uncharged byte to detect growth; never allocate from a
    // peer-controlled file length or read indefinitely from a growing source.
    let mut extra = [0_u8; 1];
    let extra_bytes = loop {
        match file.read(&mut extra) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            result => break result.map_err(|error| io_error("checking checkpoint image EOF", error))?,
        }
    };
    let after = file.metadata()
        .map_err(|error| io_error("rechecking checkpoint image metadata", error))?;
    if extra_bytes != 0 || !same_metadata(&entry.metadata, &after) {
        return Err(changed(&root.join(&entry.relative)));
    }
    Ok(())
}

fn digest(root: &Path, inventory: &Inventory) -> Result<ObjectId> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN);
    hasher.update(&(inventory.entries.len() as u64).to_le_bytes());
    let mut buffer = [0_u8; BUFFER_BYTES];
    for entry in &inventory.entries {
        hash_header(&mut hasher, entry);
        if entry.metadata.is_file() {
            stream_file(root, entry, &mut buffer, |bytes| {
                hasher.update(bytes);
                Ok(())
            })?;
        }
    }
    Ok(ObjectId::from_unscoped_bytes(hasher.finalize().as_bytes()))
}

pub(super) fn inspect(root: &Path, max_bytes: u64) -> Result<(ObjectId, u64)> {
    let limits = Limits::new(max_bytes);
    let inventory = Inventory::read(root, limits)?;
    let id = digest(root, &inventory)?;
    inventory.ensure_unchanged(root, limits)?;
    Ok((id, inventory.total_bytes))
}

#[cfg(test)]
#[path = "snapshot_tests.rs"]
mod tests;
