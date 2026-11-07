//! Path and ownership boundaries for durable revocation checkpoints.
//!
//! Checkpoint directories are local host authority. Only this host's Unix user
//! and trusted root may replace their ancestors. Snapshot files remain signed
//! publisher input, but cannot alias a checkpoint or its reserved companions.

use std::fs::File;
use std::path::Path;

#[cfg(unix)]
use std::collections::HashSet;
#[cfg(unix)]
use std::ffi::OsString;
#[cfg(unix)]
use std::fs::{Metadata, OpenOptions};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
#[cfg(unix)]
use std::path::{Component, PathBuf};

use super::{HostResult, RuntimeRevocationConfig, invalid};

#[cfg(unix)]
struct InspectedDirectory {
    path: PathBuf,
    metadata: Metadata,
}

#[cfg(unix)]
struct NormalizedFile {
    path: PathBuf,
    parent_entry: (u64, u64, OsString),
    existing_inode: Option<(u64, u64)>,
}

/// Resolve and compare every configured path before creating checkpoint files.
#[cfg(unix)]
pub(super) fn prepare_paths(config: &mut RuntimeRevocationConfig) -> HostResult<()> {
    let mut entries = HashSet::new();
    let mut inodes = HashSet::new();
    for zone in &mut config.zones {
        let source = normalize_file(&zone.snapshot_file)?;
        let checkpoint = normalize_file(&zone.checkpoint_file)?;
        let lock = normalize_file(&super::companion(&checkpoint.path, ".lock"))?;
        let next = normalize_file(&super::companion(&checkpoint.path, ".next"))?;
        for file in [&source, &checkpoint, &lock, &next] {
            if !entries.insert(file.parent_entry.clone())
                || file
                    .existing_inode
                    .is_some_and(|inode| !inodes.insert(inode))
            {
                return Err(invalid(
                    "snapshot, checkpoint and reserved companion paths must not alias",
                ));
            }
        }
        zone.snapshot_file = source.path;
        zone.checkpoint_file = checkpoint.path;
    }
    Ok(())
}

#[cfg(unix)]
fn normalize_file(path: &Path) -> HostResult<NormalizedFile> {
    if !path.is_absolute()
        || path.file_name().is_none()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(invalid(
            "feed paths must be absolute files without parent traversal",
        ));
    }
    let name = path
        .file_name()
        .ok_or_else(|| invalid("feed path requires a filename"))?
        .to_os_string();
    let parent = path
        .parent()
        .ok_or_else(|| invalid("feed path requires a parent directory"))?;
    let inspected = inspect_ancestors(parent)?;
    let original = &inspected
        .last()
        .ok_or_else(|| invalid("feed path requires a parent directory"))?
        .metadata;
    let canonical_parent =
        std::fs::canonicalize(parent).map_err(|_| invalid("feed parent cannot be resolved"))?;
    let opened = open_directory(&canonical_parent)?;
    let metadata = opened
        .metadata()
        .map_err(|_| invalid("feed parent metadata is unavailable"))?;
    if !same_directory(original, &metadata) {
        return Err(invalid("feed parent changed while resolving its path"));
    }
    recheck_ancestors(&inspected)?;
    let path = canonical_parent.join(&name);
    let existing_inode = match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_file() => Some((metadata.dev(), metadata.ino())),
        Ok(_) => {
            return Err(invalid(
                "feed paths must name regular files, never symlinks",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err(invalid("feed path metadata is unavailable")),
    };
    Ok(NormalizedFile {
        path,
        parent_entry: (metadata.dev(), metadata.ino(), name),
        existing_inode,
    })
}

/// Establish the host's filesystem identity without trusting environment UIDs.
#[cfg(unix)]
pub(super) fn checkpoint_owner(path: &Path) -> HostResult<u32> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("checkpoint requires a private parent directory"))?;
    let inspected = inspect_ancestors(parent)?;
    let parent_metadata = &inspected
        .last()
        .ok_or_else(|| invalid("checkpoint requires a private parent directory"))?
        .metadata;
    if parent_metadata.mode() & 0o077 != 0 {
        return Err(invalid(
            "checkpoint parent must be a private owner-only directory",
        ));
    }
    let opened = open_directory(parent)?;
    let opened_metadata = opened
        .metadata()
        .map_err(|_| invalid("checkpoint parent metadata is unavailable"))?;
    if !same_directory(parent_metadata, &opened_metadata) {
        return Err(invalid(
            "checkpoint parent changed before ownership validation",
        ));
    }

    // A fresh anonymous file has the host's filesystem UID even when this
    // process is privileged enough to open files owned by another user. It
    // contains no state and leaves no named checkpoint artifact behind.
    let probe = tempfile::tempfile_in(parent)
        .map_err(|_| invalid("checkpoint parent is not writable by the host"))?;
    let owner = probe
        .metadata()
        .map_err(|_| invalid("host filesystem identity is unavailable"))?
        .uid();
    if parent_metadata.uid() != owner
        || inspected
            .iter()
            .any(|entry| entry.metadata.uid() != 0 && entry.metadata.uid() != owner)
    {
        return Err(invalid(
            "checkpoint parent must belong to the host; ancestors must belong to the host or root",
        ));
    }
    recheck_ancestors(&inspected)?;
    Ok(owner)
}

#[cfg(unix)]
fn inspect_ancestors(parent: &Path) -> HostResult<Vec<InspectedDirectory>> {
    if !parent.is_absolute() {
        return Err(invalid("feed parent must be absolute"));
    }
    let mut ancestors = parent.ancestors().collect::<Vec<_>>();
    ancestors.reverse();
    let mut inspected = Vec::with_capacity(ancestors.len());
    for ancestor in ancestors {
        let metadata = std::fs::symlink_metadata(ancestor)
            .map_err(|_| invalid("feed directory metadata is unavailable"))?;
        if !metadata.is_dir() {
            return Err(invalid(
                "feed ancestors must be directories, never symlinks",
            ));
        }
        // A root-owned sticky directory such as /tmp cannot rename another
        // user's private child; other shared writable ancestors can.
        if metadata.mode() & 0o022 != 0 && !(metadata.uid() == 0 && metadata.mode() & 0o1000 != 0) {
            return Err(invalid(
                "feed ancestors must not be writable by other users",
            ));
        }
        inspected.push(InspectedDirectory {
            path: ancestor.to_path_buf(),
            metadata,
        });
    }
    Ok(inspected)
}

#[cfg(unix)]
fn open_directory(path: &Path) -> HostResult<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| invalid("feed directory cannot be opened without following links"))
}

#[cfg(unix)]
fn same_directory(before: &Metadata, after: &Metadata) -> bool {
    after.is_dir()
        && before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.uid() == after.uid()
        && before.mode() == after.mode()
}

#[cfg(unix)]
fn recheck_ancestors(inspected: &[InspectedDirectory]) -> HostResult<()> {
    for entry in inspected {
        let current = std::fs::symlink_metadata(&entry.path)
            .map_err(|_| invalid("feed directory disappeared during validation"))?;
        if !same_directory(&entry.metadata, &current) {
            return Err(invalid("feed directory changed during validation"));
        }
    }
    Ok(())
}

/// Only the configured host UID may retain mutable durable authority files.
#[cfg(unix)]
pub(super) fn require_private(file: &File, owner: u32) -> HostResult<()> {
    let metadata = file
        .metadata()
        .map_err(|_| invalid("checkpoint metadata is unavailable"))?;
    if metadata.is_file()
        && metadata.nlink() == 1
        && metadata.uid() == owner
        && metadata.mode() & 0o077 == 0
    {
        return Ok(());
    }
    Err(invalid(
        "checkpoint requires a private, singly linked regular file owned by the host",
    ))
}

#[cfg(not(unix))]
pub(super) fn prepare_paths(_config: &mut RuntimeRevocationConfig) -> HostResult<()> {
    Err(invalid(
        "protected revocation checkpoints require Unix file permissions",
    ))
}

#[cfg(not(unix))]
pub(super) fn checkpoint_owner(_path: &Path) -> HostResult<u32> {
    Err(invalid(
        "protected revocation checkpoints require Unix file permissions",
    ))
}

#[cfg(not(unix))]
pub(super) fn require_private(_file: &File, _owner: u32) -> HostResult<()> {
    Err(invalid(
        "protected revocation checkpoints require Unix file permissions",
    ))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn config(root: &Path) -> RuntimeRevocationConfig {
        RuntimeRevocationConfig {
            zones: vec![super::super::RuntimeRevocationZoneConfig {
                zone_id: fcp_prelude::ZoneId::work(),
                owner_public_key_hex: "00".repeat(32),
                snapshot_file: root.join("source.json"),
                checkpoint_file: root.join("checkpoint.json"),
            }],
        }
    }

    #[test]
    fn normalizes_paths_and_checks_host_owned_private_files() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        std::fs::write(root.join("source.json"), b"signed source").unwrap();
        let mut config = config(&root);
        config.zones[0].checkpoint_file = root.join(".").join("checkpoint.json");
        prepare_paths(&mut config).unwrap();
        let checkpoint = &config.zones[0].checkpoint_file;
        assert_eq!(checkpoint, &root.join("checkpoint.json"));
        assert!(!checkpoint.exists());
        assert!(!super::super::companion(checkpoint, ".lock").exists());
        assert!(!super::super::companion(checkpoint, ".next").exists());
        let owner = checkpoint_owner(checkpoint).unwrap();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(checkpoint)
            .unwrap();
        require_private(&file, owner).unwrap();
        assert!(require_private(&file, owner.wrapping_add(1)).is_err());
        file.set_permissions(std::fs::Permissions::from_mode(0o640))
            .unwrap();
        assert!(require_private(&file, owner).is_err());
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .unwrap();
        std::fs::hard_link(checkpoint, root.join("checkpoint.alias")).unwrap();
        assert!(require_private(&file, owner).is_err());
    }

    #[test]
    fn rejects_symlinked_parent_alias_before_touching_the_source() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let source = root.join("source.json");
        std::fs::write(&source, b"signed source").unwrap();
        std::os::unix::fs::symlink(&root, root.join("alias")).unwrap();
        let mut config = config(&root);
        config.zones[0].checkpoint_file = root.join("alias").join("source.json");
        assert!(
            prepare_paths(&mut config)
                .unwrap_err()
                .to_string()
                .contains("symlinks")
        );
        assert_eq!(std::fs::read(&source).unwrap(), b"signed source");
        assert!(!root.join("source.json.lock").exists());
        assert!(!root.join("source.json.next").exists());
    }

    #[test]
    fn rejects_hard_link_and_reserved_companion_aliases_before_writes() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        std::fs::write(root.join("source.json"), b"signed source").unwrap();
        std::fs::hard_link(root.join("source.json"), root.join("checkpoint.json")).unwrap();
        assert!(
            prepare_paths(&mut config(&root))
                .unwrap_err()
                .to_string()
                .contains("alias")
        );
        assert!(!root.join("checkpoint.json.lock").exists());

        let mut reserved = config(&root);
        reserved.zones[0].checkpoint_file = root.join("other.json");
        reserved.zones[0].snapshot_file = root.join("other.json.next");
        assert!(
            prepare_paths(&mut reserved)
                .unwrap_err()
                .to_string()
                .contains("alias")
        );
        assert!(!root.join("other.json.lock").exists());
        assert!(!root.join("other.json.next").exists());
    }

    #[test]
    fn rejects_shared_writable_ancestors_and_nonprivate_checkpoint_parents() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let child = root.join("private");
        std::fs::create_dir(&child).unwrap();
        std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(prepare_paths(&mut config(&child)).is_err());
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        prepare_paths(&mut config(&child)).unwrap();
        std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(checkpoint_owner(&child.join("checkpoint.json")).is_err());
    }
}
