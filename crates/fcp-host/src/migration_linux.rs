//! Linux connector subprocess checkpoint/restore helpers built around CRIU.
//!
//! The host intentionally shells out to the `criu` binary instead of binding
//! libcriu. This keeps the FCP host binary free of CRIU FFI surface area while
//! still giving the migration lane a deterministic command wrapper, bounded
//! snapshot accounting, and portable trace manifests.

use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::Output;
use std::time::Instant;

use chrono::{DateTime, Utc};
use fcp_prelude::ObjectId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[path = "migration_linux/command.rs"]
mod command;
#[path = "migration_linux/snapshot.rs"]
mod snapshot;

pub use command::{CriuCommandError, CriuCommandLimits, CriuCommandStopReason};

const CRIU_DUMP_LOG: &str = "criu-dump.log";
const CRIU_RESTORE_LOG: &str = "criu-restore.log";
const DEFAULT_MAX_SNAPSHOT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_RESTORE_PID_BYTES: u64 = 32;

/// Errors returned by Linux connector migration helpers.
#[derive(Debug, Error)]
pub enum LinuxMigrationError {
    /// CRIU is Linux-only.
    #[error("CRIU connector migration is only supported on Linux hosts")]
    UnsupportedPlatform,
    /// A caller supplied PID 0, which is not a dumpable process tree.
    #[error("connector pid must be non-zero")]
    InvalidPid,
    /// A successful CRIU exit did not provide unambiguous root-PID evidence.
    /// A restored process may already exist; this must not trigger a retry.
    #[error("criu restore root PID is unconfirmed: {reason}; a process may already exist; reconcile before retrying")]
    InvalidRestorePid {
        /// Bounded classification, never untrusted PID-file or log contents.
        reason: &'static str,
    },
    /// Snapshot image directories must start empty so stale files cannot mix
    /// with a newly captured process image.
    #[error("checkpoint images directory is not empty: {path:?}")]
    ImagesDirNotEmpty {
        /// Directory that already contained entries.
        path: PathBuf,
    },
    /// Snapshot output exceeded the configured cap.
    #[error("checkpoint size {size_bytes} bytes exceeds cap {max_snapshot_bytes} bytes")]
    SnapshotTooLarge {
        /// Actual directory size.
        size_bytes: u64,
        /// Configured maximum.
        max_snapshot_bytes: u64,
    },
    /// Image metadata exceeded a structural bound before payload allocation.
    #[error("checkpoint image tree exceeds its {limit} limit")]
    SnapshotStructureLimit {
        /// Fixed classification, not source-directory contents.
        limit: &'static str,
    },
    /// A source image changed during bounded inspection or copying.
    #[error("checkpoint image tree changed during inspection: {path:?}")]
    SnapshotChanged {
        /// Changed entry or tree root.
        path: PathBuf,
    },
    /// A file descriptor path was outside the caller's migration policy.
    #[error("file descriptor {fd} path is not allowed by migration policy: {path:?}")]
    FileDescriptorNotAllowed {
        /// Descriptor number reported by the caller.
        fd: i32,
        /// Host path rejected by policy.
        path: PathBuf,
    },
    /// Portable remap roots must not be absolute or escape upward.
    #[error("portable fd root must be relative and non-escaping: {path:?}")]
    InvalidPortableRoot {
        /// Invalid portable remap root.
        path: PathBuf,
    },
    /// The snapshot directory contained an unsupported filesystem entry.
    #[error("unsupported checkpoint image entry under {path:?}")]
    UnsupportedSnapshotEntry {
        /// Entry path.
        path: PathBuf,
    },
    /// The CRIU subprocess returned a non-zero status.
    #[error("criu {action} failed with {status}: {stderr}")]
    CriuCommandFailed {
        /// CRIU action, e.g. dump or restore.
        action: &'static str,
        /// Exit status rendered by std.
        status: String,
        /// Captured stderr.
        stderr: String,
    },
    /// CRIU setup, resource admission, execution or bounded capture failed.
    #[error("criu {action}: {source}")]
    CriuExecution {
        /// CRIU action, or `configure` when validating local limits.
        action: &'static str,
        /// Subprocess-boundary failure, including exact-child reap evidence.
        #[source]
        source: CriuCommandError,
    },
    /// Filesystem or process-spawn failure.
    #[error("io error while {context}: {source}")]
    Io {
        /// Operation being attempted.
        context: &'static str,
        /// Source IO error.
        #[source]
        source: std::io::Error,
    },
}

/// Snapshot and restore limits enforced before migration artifacts are
/// published to the mesh.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorMigrationLimits {
    /// Maximum total bytes allowed in a CRIU image directory.
    pub max_snapshot_bytes: u64,
}

impl Default for ConnectorMigrationLimits {
    fn default() -> Self {
        Self {
            max_snapshot_bytes: DEFAULT_MAX_SNAPSHOT_BYTES,
        }
    }
}

/// Host file descriptor discovered before checkpointing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenFileDescriptor {
    /// Numeric file descriptor.
    pub fd: i32,
    /// Host-local path backing the descriptor.
    pub host_path: PathBuf,
}

impl OpenFileDescriptor {
    /// Build a descriptor record for policy validation.
    #[must_use]
    pub fn new(fd: i32, host_path: impl Into<PathBuf>) -> Self {
        Self {
            fd,
            host_path: host_path.into(),
        }
    }
}

/// Portable file-descriptor remap that is safe to include in trace manifests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDescriptorRemap {
    /// Numeric file descriptor.
    pub fd: i32,
    /// BLAKE3 digest of the original host path.
    pub source_path_digest: String,
    /// Portable path relative to the migrated connector bundle.
    pub portable_path: PathBuf,
}

/// Capability-aware descriptor remapping policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDescriptorRemapPolicy {
    allowed_host_prefixes: Vec<PathBuf>,
    portable_root: PathBuf,
}

impl FileDescriptorRemapPolicy {
    /// Create a policy from host prefixes already authorized by connector
    /// capabilities and a portable root such as `connector-fds`.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxMigrationError::InvalidPortableRoot`] when the portable
    /// root is absolute or contains parent-directory components.
    pub fn new(
        allowed_host_prefixes: Vec<PathBuf>,
        portable_root: impl Into<PathBuf>,
    ) -> Result<Self, LinuxMigrationError> {
        let portable_root = portable_root.into();
        if !is_safe_relative_path(&portable_root) {
            return Err(LinuxMigrationError::InvalidPortableRoot {
                path: portable_root,
            });
        }
        Ok(Self {
            allowed_host_prefixes,
            portable_root,
        })
    }

    /// Remap every descriptor through the configured policy.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxMigrationError::FileDescriptorNotAllowed`] if any
    /// descriptor is outside all allowed host prefixes.
    pub fn remap_all(
        &self,
        descriptors: &[OpenFileDescriptor],
    ) -> Result<Vec<FileDescriptorRemap>, LinuxMigrationError> {
        descriptors
            .iter()
            .map(|descriptor| self.remap_one(descriptor))
            .collect()
    }

    fn remap_one(
        &self,
        descriptor: &OpenFileDescriptor,
    ) -> Result<FileDescriptorRemap, LinuxMigrationError> {
        let allowed_prefix = self
            .allowed_host_prefixes
            .iter()
            .find(|prefix| descriptor.host_path.starts_with(prefix))
            .ok_or_else(|| LinuxMigrationError::FileDescriptorNotAllowed {
                fd: descriptor.fd,
                path: descriptor.host_path.clone(),
            })?;
        let relative = descriptor
            .host_path
            .strip_prefix(allowed_prefix)
            .map_err(|_| LinuxMigrationError::FileDescriptorNotAllowed {
                fd: descriptor.fd,
                path: descriptor.host_path.clone(),
            })?;
        let portable_path = self
            .portable_root
            .join(format!("fd-{}", descriptor.fd))
            .join(relative);
        let source_path_digest = blake3::hash(descriptor.host_path.as_os_str().as_encoded_bytes())
            .to_hex()
            .to_string();

        Ok(FileDescriptorRemap {
            fd: descriptor.fd,
            source_path_digest,
            portable_path,
        })
    }
}

/// Request to checkpoint a live connector subprocess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorCheckpointRequest {
    /// Connector ID being checkpointed.
    pub connector_id: String,
    /// Root PID of the connector process tree.
    pub pid: u32,
    /// CRIU image directory. It is created if absent and must be empty.
    pub images_dir: PathBuf,
    /// Optional CRIU work directory.
    pub work_dir: Option<PathBuf>,
    /// Pass `--leave-running` to CRIU so the source connector keeps running.
    pub leave_running: bool,
    /// Pass `--shell-job` to support connector subprocesses without a separate
    /// service manager.
    pub shell_job: bool,
    /// Pass `--tcp-established` when the connector has established sockets that
    /// the caller has decided are portable.
    pub tcp_established: bool,
    /// File descriptors discovered by the host before checkpointing.
    pub open_file_descriptors: Vec<OpenFileDescriptor>,
    /// Descriptor remapping policy. When omitted, any open descriptors are
    /// rejected because no capability scope was provided.
    pub fd_policy: Option<FileDescriptorRemapPolicy>,
}

impl ConnectorCheckpointRequest {
    /// Create a checkpoint request with conservative CRIU options.
    #[must_use]
    pub fn new(connector_id: impl Into<String>, pid: u32, images_dir: impl Into<PathBuf>) -> Self {
        Self {
            connector_id: connector_id.into(),
            pid,
            images_dir: images_dir.into(),
            work_dir: None,
            leave_running: true,
            shell_job: true,
            tcp_established: false,
            open_file_descriptors: Vec::new(),
            fd_policy: None,
        }
    }
}

/// Portable manifest returned after a successful checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorCheckpointManifest {
    /// Connector ID that was checkpointed.
    pub connector_id: String,
    /// Source process ID.
    pub source_pid: u32,
    /// V2 content address over sorted, length-framed image paths, entry types,
    /// file lengths and bytes, including empty directories. This is not a
    /// signature: authenticate this manifest before using it as a restore pin.
    pub snapshot_object_id: ObjectId,
    /// Total snapshot bytes captured under the image directory.
    pub snapshot_size_bytes: u64,
    /// Capture timestamp.
    pub captured_at: DateTime<Utc>,
    /// Captured CRIU stderr for trace/replay debugging.
    pub criu_stderr: String,
    /// Capability-filtered descriptor remaps that do not expose host paths.
    pub file_descriptors_remapped: Vec<FileDescriptorRemap>,
    /// Local image directory, intentionally omitted from serialized manifests
    /// because it is host-specific.
    #[serde(skip)]
    pub local_images_dir: PathBuf,
}

/// Request to restore a connector subprocess from CRIU images.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorRestoreRequest {
    /// Connector ID being restored.
    pub connector_id: String,
    /// Existing CRIU image directory.
    pub images_dir: PathBuf,
    /// Optional CRIU work directory.
    pub work_dir: Option<PathBuf>,
    /// Pass `--shell-job` to mirror the dump side.
    pub shell_job: bool,
    /// Pass `--tcp-established` when restoring established sockets.
    pub tcp_established: bool,
}

impl ConnectorRestoreRequest {
    /// Create a restore request with conservative CRIU options.
    #[must_use]
    pub fn new(connector_id: impl Into<String>, images_dir: impl Into<PathBuf>) -> Self {
        Self {
            connector_id: connector_id.into(),
            images_dir: images_dir.into(),
            work_dir: None,
            shell_job: true,
            tcp_established: false,
        }
    }
}

/// Report returned after a restore attempt succeeds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorRestoreReport {
    /// Connector ID restored from checkpoint images.
    pub connector_id: String,
    /// Root PID read from this attempt's private CRIU `--pidfile`.
    /// Successful restores always return `Some`; this is not an incarnation
    /// handle or proof that the process is still alive when later inspected.
    pub restored_pid: Option<u32>,
    /// Restore duration in milliseconds.
    pub restore_duration_ms: u64,
    /// Captured CRIU stdout.
    pub criu_stdout: String,
    /// Captured CRIU stderr.
    pub criu_stderr: String,
}

/// CRIU-backed Linux connector migrator.
#[derive(Debug, Clone)]
pub struct CriuConnectorMigrator {
    criu_binary: PathBuf,
    limits: ConnectorMigrationLimits,
    require_linux: bool,
    command_limits: CriuCommandLimits,
}

impl Default for CriuConnectorMigrator {
    fn default() -> Self {
        Self::new("criu", ConnectorMigrationLimits::default())
    }
}

impl CriuConnectorMigrator {
    /// Create a migrator using the provided CRIU binary path and limits.
    #[must_use]
    pub fn new(criu_binary: impl Into<PathBuf>, limits: ConnectorMigrationLimits) -> Self {
        Self {
            criu_binary: criu_binary.into(),
            limits,
            require_linux: true,
            command_limits: CriuCommandLimits::default(),
        }
    }

    /// Set independent limits for each CRIU dump/restore command.
    ///
    /// Defaults are 60 seconds and 1 MiB of combined stdout/stderr. The
    /// existing synchronous migration methods must run on a blocking worker,
    /// not an async executor thread. OS spawn/kill/wait calls cannot be forcibly
    /// preempted. Only the CRIU child is terminated on interruption; a restored
    /// process may already exist and must be reconciled before any retry.
    /// These limits do not bound CRIU's own image files or explicit log files.
    ///
    /// # Errors
    /// Returns an error when the timeout or diagnostic-byte budget is zero.
    pub fn with_command_limits(mut self, limits: CriuCommandLimits) -> Result<Self, LinuxMigrationError> {
        limits.validate().map_err(|source| LinuxMigrationError::CriuExecution {
            action: "configure", source,
        })?;
        self.command_limits = limits;
        Ok(self)
    }

    /// Checkpoint a connector subprocess with CRIU.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxMigrationError`] if the platform is unsupported, CRIU
    /// fails, the image directory is dirty, snapshot output exceeds the cap, or
    /// descriptor remapping violates the supplied policy.
    pub fn dump_connector(
        &self,
        request: &ConnectorCheckpointRequest,
    ) -> Result<ConnectorCheckpointManifest, LinuxMigrationError> {
        self.ensure_supported_platform()?;
        if request.pid == 0 {
            return Err(LinuxMigrationError::InvalidPid);
        }
        ensure_empty_directory(&request.images_dir)?;
        let remaps = match (&request.fd_policy, request.open_file_descriptors.is_empty()) {
            (Some(policy), _) => policy.remap_all(&request.open_file_descriptors)?,
            (None, true) => Vec::new(),
            (None, false) => {
                if let Some(descriptor) = request.open_file_descriptors.first() {
                    return Err(LinuxMigrationError::FileDescriptorNotAllowed {
                        fd: descriptor.fd,
                        path: descriptor.host_path.clone(),
                    });
                }
                Vec::new()
            }
        };

        let args = dump_args(request);
        let output = self.run_criu("dump", &args)?;
        let (snapshot_object_id, snapshot_size_bytes) =
            snapshot::inspect(&request.images_dir, self.limits.max_snapshot_bytes)?;

        Ok(ConnectorCheckpointManifest {
            connector_id: request.connector_id.clone(),
            source_pid: request.pid,
            snapshot_object_id,
            snapshot_size_bytes,
            captured_at: Utc::now(),
            criu_stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            file_descriptors_remapped: remaps,
            local_images_dir: request.images_dir.clone(),
        })
    }

    /// Restore a connector subprocess from CRIU images.
    ///
    /// CRIU exits after restoring the process tree (`--restore-detached`),
    /// rather than waiting for the restored connector to exit. Root-PID
    /// evidence comes only from a fresh private `--pidfile`, never stdout or
    /// a stale file in the image directory. The caller still owns process
    /// supervision, readiness checks, execution fencing and lease transfer.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxMigrationError`] if the platform is unsupported, the
    /// image directory cannot be read, CRIU restore fails, or root-PID
    /// evidence is missing or invalid. An error after launching restore does
    /// not prove that no process was created and must not authorize a retry.
    pub fn restore_connector(
        &self,
        request: &ConnectorRestoreRequest,
    ) -> Result<ConnectorRestoreReport, LinuxMigrationError> {
        self.ensure_supported_platform()?;
        let _ = fs::read_dir(&request.images_dir).map_err(|source| LinuxMigrationError::Io {
            context: "opening checkpoint images directory",
            source,
        })?;
        let control = tempfile::Builder::new()
            .prefix("fcp-criu-restore-")
            .tempdir()
            .map_err(|source| LinuxMigrationError::Io {
                context: "creating private CRIU restore control directory",
                source,
            })?;
        // Keep control files outside the content-addressed images. A fresh
        // private directory also prevents reuse of another attempt's PID.
        let pid_file = control.path().canonicalize().map_err(|source| {
            LinuxMigrationError::Io {
                context: "resolving private CRIU restore control directory",
                source,
            }
        })?.join("root.pid");
        let started_at = Instant::now();
        let args = restore_args(request, &pid_file);
        let output = self.run_criu("restore", &args)?;
        let restore_duration_ms =
            u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let restored_pid = Some(read_restored_pid(&pid_file)?);

        Ok(ConnectorRestoreReport {
            connector_id: request.connector_id.clone(),
            restored_pid,
            restore_duration_ms,
            criu_stdout: stdout,
            criu_stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }

    const fn ensure_supported_platform(&self) -> Result<(), LinuxMigrationError> {
        if self.require_linux && !cfg!(target_os = "linux") {
            return Err(LinuxMigrationError::UnsupportedPlatform);
        }
        Ok(())
    }

    fn run_criu(
        &self,
        action: &'static str,
        args: &[OsString],
    ) -> Result<Output, LinuxMigrationError> {
        let output = command::run(&self.criu_binary, args, self.command_limits)
            .map_err(|source| LinuxMigrationError::CriuExecution { action, source })?;
        if !output.status.success() {
            return Err(LinuxMigrationError::CriuCommandFailed {
                action,
                status: output.status.to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            });
        }
        Ok(output)
    }

    #[cfg(test)]
    fn for_tests(criu_binary: impl Into<PathBuf>, limits: ConnectorMigrationLimits) -> Self {
        Self {
            criu_binary: criu_binary.into(),
            limits,
            require_linux: false,
            command_limits: CriuCommandLimits::default(),
        }
    }
}

fn dump_args(request: &ConnectorCheckpointRequest) -> Vec<OsString> {
    let mut args = vec![
        OsString::from("dump"),
        OsString::from("--tree"),
        OsString::from(request.pid.to_string()),
        OsString::from("--images-dir"),
        request.images_dir.as_os_str().to_os_string(),
        OsString::from("--log-file"),
        OsString::from(CRIU_DUMP_LOG),
    ];
    if let Some(work_dir) = &request.work_dir {
        args.push(OsString::from("--work-dir"));
        args.push(work_dir.as_os_str().to_os_string());
    }
    if request.leave_running {
        args.push(OsString::from("--leave-running"));
    }
    if request.shell_job {
        args.push(OsString::from("--shell-job"));
    }
    if request.tcp_established {
        args.push(OsString::from("--tcp-established"));
    }
    args
}

fn restore_args(request: &ConnectorRestoreRequest, pid_file: &Path) -> Vec<OsString> {
    let mut args = vec![
        OsString::from("restore"),
        OsString::from("--restore-detached"),
        OsString::from("--pidfile"),
        pid_file.as_os_str().to_os_string(),
        OsString::from("--images-dir"),
        request.images_dir.as_os_str().to_os_string(),
        OsString::from("--log-file"),
        OsString::from(CRIU_RESTORE_LOG),
    ];
    if let Some(work_dir) = &request.work_dir {
        args.push(OsString::from("--work-dir"));
        args.push(work_dir.as_os_str().to_os_string());
    }
    if request.shell_job {
        args.push(OsString::from("--shell-job"));
    }
    if request.tcp_established {
        args.push(OsString::from("--tcp-established"));
    }
    args
}

fn ensure_empty_directory(path: &Path) -> Result<(), LinuxMigrationError> {
    fs::create_dir_all(path).map_err(|source| LinuxMigrationError::Io {
        context: "creating checkpoint images directory",
        source,
    })?;
    let mut entries = fs::read_dir(path).map_err(|source| LinuxMigrationError::Io {
        context: "reading checkpoint images directory",
        source,
    })?;
    if entries
        .next()
        .transpose()
        .map_err(|source| LinuxMigrationError::Io {
            context: "reading checkpoint images directory entry",
            source,
        })?
        .is_some()
    {
        return Err(LinuxMigrationError::ImagesDirNotEmpty {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn is_safe_relative_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn parse_restored_pid(contents: &str) -> Option<u32> {
    let pid = contents.trim_matches(|ch: char| ch.is_ascii_whitespace());
    if pid.is_empty() || !pid.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    pid.parse::<u32>().ok().filter(|pid| *pid > 0 && i32::try_from(*pid).is_ok())
}

fn read_restored_pid(path: &Path) -> Result<u32, LinuxMigrationError> {
    let invalid = |reason| LinuxMigrationError::InvalidRestorePid { reason };
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| invalid("PID file is missing or inaccessible"))?;
    if !metadata.is_file() {
        return Err(invalid("PID file is not a regular file"));
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Do not follow a replaced leaf symlink or block opening a FIFO.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|_| invalid("PID file cannot be opened"))?;
    let metadata = file.metadata().map_err(|_| invalid("PID file cannot be inspected"))?;
    if !metadata.is_file() || metadata.len() > MAX_RESTORE_PID_BYTES {
        return Err(invalid("PID file is not a bounded regular file"));
    }
    let mut contents = String::new();
    file.take(MAX_RESTORE_PID_BYTES + 1).read_to_string(&mut contents)
        .map_err(|_| invalid("PID file cannot be read as text"))?;
    if contents.len() as u64 > MAX_RESTORE_PID_BYTES {
        return Err(invalid("PID file exceeds its byte limit"));
    }
    parse_restored_pid(&contents).ok_or_else(|| invalid("PID file must contain one positive pid_t"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fd_policy_remaps_allowed_paths_without_serializing_host_path() {
        let policy = FileDescriptorRemapPolicy::new(
            vec![PathBuf::from("/var/lib/fcp/connectors")],
            "connector-fds",
        )
        .unwrap();
        let remaps = policy
            .remap_all(&[OpenFileDescriptor::new(
                7,
                "/var/lib/fcp/connectors/github/state.db",
            )])
            .unwrap();

        assert_eq!(remaps.len(), 1);
        assert_eq!(remaps[0].fd, 7);
        assert_eq!(
            remaps[0].portable_path,
            PathBuf::from("connector-fds/fd-7/github/state.db")
        );
        let serialized = serde_json::to_string(&remaps[0]).unwrap();
        assert!(!serialized.contains("/var/lib/fcp/connectors"));
        assert!(serialized.contains("source_path_digest"));
    }

    #[test]
    fn fd_policy_rejects_unapproved_host_paths() {
        let policy =
            FileDescriptorRemapPolicy::new(vec![PathBuf::from("/var/lib/fcp")], "fds").unwrap();
        let err = policy
            .remap_all(&[OpenFileDescriptor::new(4, "/etc/passwd")])
            .unwrap_err();

        assert!(matches!(
            err,
            LinuxMigrationError::FileDescriptorNotAllowed { fd: 4, .. }
        ));
    }

    #[test]
    fn fd_policy_rejects_absolute_portable_root() {
        let err = FileDescriptorRemapPolicy::new(vec![PathBuf::from("/var/lib/fcp")], "/tmp/fds")
            .unwrap_err();

        assert!(matches!(
            err,
            LinuxMigrationError::InvalidPortableRoot { .. }
        ));
    }

    #[test]
    fn parse_restored_pid_requires_one_positive_pid_t() {
        for valid in ["4242", "4242\n", " 4242\r\n"] {
            assert_eq!(parse_restored_pid(valid), Some(4242));
        }
        for invalid in ["", "0", "+42", "-42", "42 43", "2147483648",
            "restored pid: 4242\n", "pid=0 pid=9", "42\0", "４２"] {
            assert_eq!(parse_restored_pid(invalid), None, "{invalid:?}");
        }
    }

    #[test]
    fn restored_pid_file_must_be_present_regular_bounded_and_well_formed() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_restored_pid(&dir.path().join("absent")).is_err());
        assert!(read_restored_pid(dir.path()).is_err());
        let path = dir.path().join("root.pid");
        for invalid in [b"".as_slice(), b"0", b"123 456", b"\xff", &[b'1'; 33]] {
            fs::write(&path, invalid).unwrap();
            assert!(matches!(read_restored_pid(&path), Err(LinuxMigrationError::InvalidRestorePid { .. })));
        }
        fs::write(&path, b"4321\n").unwrap();
        assert_eq!(read_restored_pid(&path).unwrap(), 4321);
    }

    #[test]
    fn restore_command_requests_detachment_and_an_exact_pidfile() {
        let mut request = ConnectorRestoreRequest::new("connector", "images with spaces");
        request.work_dir = Some(PathBuf::from("work dir"));
        request.tcp_established = true;
        let args = restore_args(&request, Path::new("private control/root.pid"));
        assert_eq!(args, ["restore", "--restore-detached", "--pidfile",
            "private control/root.pid", "--images-dir", "images with spaces",
            "--log-file", CRIU_RESTORE_LOG, "--work-dir", "work dir",
            "--shell-job", "--tcp-established"].map(OsString::from));
        assert!(!dump_args(&ConnectorCheckpointRequest::new("connector", 1, "images"))
            .contains(&OsString::from("--restore-detached")));
    }

    #[test]
    fn dump_refuses_pid_zero() {
        let migrator = CriuConnectorMigrator::for_tests(
            "does-not-run",
            ConnectorMigrationLimits {
                max_snapshot_bytes: 1024,
            },
        );
        let dir = tempfile::tempdir().unwrap();
        let request = ConnectorCheckpointRequest::new("fcp.test.echo:utility:1.0.0", 0, dir.path());

        let err = migrator.dump_connector(&request).unwrap_err();

        assert!(matches!(err, LinuxMigrationError::InvalidPid));
    }

    #[test]
    fn dump_refuses_non_empty_images_dir_without_cleanup() {
        let migrator = CriuConnectorMigrator::for_tests(
            "does-not-run",
            ConnectorMigrationLimits {
                max_snapshot_bytes: 1024,
            },
        );
        let dir = tempfile::tempdir().unwrap();
        let stale = dir.path().join("stale.img");
        fs::write(&stale, b"stale").unwrap();
        let request =
            ConnectorCheckpointRequest::new("fcp.test.echo:utility:1.0.0", 1234, dir.path());

        let err = migrator.dump_connector(&request).unwrap_err();

        assert!(matches!(err, LinuxMigrationError::ImagesDirNotEmpty { .. }));
        assert!(stale.exists());
    }

    #[cfg(unix)]
    mod unix_tests {
        use std::os::unix::fs::PermissionsExt;

        use super::*;

        #[test]
        fn dump_and_restore_use_the_configured_command_deadline() {
            let dir = tempfile::tempdir().unwrap();
            let script = dir.path().join("blocked-criu.sh");
            fs::write(&script, "#!/bin/sh\nexec sleep 30\n").unwrap();
            fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
            let migrator = CriuConnectorMigrator::for_tests(script, ConnectorMigrationLimits::default())
                .with_command_limits(CriuCommandLimits {
                    timeout: std::time::Duration::from_millis(100),
                    max_output_bytes: 1024,
                }).unwrap();
            let images = dir.path().join("images");
            let error = migrator.dump_connector(&ConnectorCheckpointRequest::new("connector", 1234, &images))
                .unwrap_err();
            assert!(matches!(error, LinuxMigrationError::CriuExecution {
                action: "dump",
                source: CriuCommandError::Interrupted {
                    reason: CriuCommandStopReason::Timeout, child_reaped: true, ..
                },
            }));
            let error = migrator.restore_connector(&ConnectorRestoreRequest::new("connector", &images))
                .unwrap_err();
            assert!(matches!(error, LinuxMigrationError::CriuExecution {
                action: "restore",
                source: CriuCommandError::Interrupted {
                    reason: CriuCommandStopReason::Timeout, child_reaped: true, ..
                },
            }));
        }

        #[test]
        fn restore_output_limit_cannot_be_reported_as_success() {
            let dir = tempfile::tempdir().unwrap();
            let images = dir.path().join("images");
            fs::create_dir(&images).unwrap();
            let migrator = CriuConnectorMigrator::for_tests(
                fake_criu_script(dir.path(), "unused"), ConnectorMigrationLimits::default(),
            ).with_command_limits(CriuCommandLimits {
                timeout: std::time::Duration::from_secs(2), max_output_bytes: 4,
            }).unwrap();
            let error = migrator.restore_connector(&ConnectorRestoreRequest::new("connector", &images))
                .unwrap_err();
            assert!(matches!(error, LinuxMigrationError::CriuExecution {
                action: "restore",
                source: CriuCommandError::Interrupted {
                    reason: CriuCommandStopReason::OutputLimit, child_reaped: true, ..
                },
            }));
        }

        #[test]
        fn restored_pid_file_never_follows_a_symlink() {
            let dir = tempfile::tempdir().unwrap();
            let source = dir.path().join("other-attempt.pid");
            let link = dir.path().join("root.pid");
            fs::write(&source, "4321\n").unwrap();
            std::os::unix::fs::symlink(source, &link).unwrap();
            assert!(matches!(read_restored_pid(&link), Err(LinuxMigrationError::InvalidRestorePid { .. })));
        }

        #[test]
        fn successful_criu_exit_without_pidfile_never_uses_stdout_or_stale_images() {
            let dir = tempfile::tempdir().unwrap();
            let script = dir.path().join("no-pidfile.sh");
            fs::write(&script, "#!/bin/sh\necho 'restored pid: 9999'\n").unwrap();
            fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
            let images = dir.path().join("images");
            fs::create_dir(&images).unwrap();
            fs::write(images.join("root.pid"), "1111\n").unwrap();
            let migrator = CriuConnectorMigrator::for_tests(script, ConnectorMigrationLimits::default());
            let error = migrator.restore_connector(&ConnectorRestoreRequest::new("connector", &images))
                .unwrap_err();
            assert!(matches!(error, LinuxMigrationError::InvalidRestorePid { .. }));
            assert!(error.to_string().contains("reconcile before retrying"));
            assert_eq!(fs::read_to_string(images.join("root.pid")).unwrap(), "1111\n");
        }

        #[test]
        fn restore_control_paths_are_fresh_and_do_not_pollute_snapshot_images() {
            let dir = tempfile::tempdir().unwrap();
            let images = dir.path().join("images");
            fs::create_dir(&images).unwrap();
            let migrator = CriuConnectorMigrator::for_tests(
                fake_criu_script(dir.path(), "unused"), ConnectorMigrationLimits::default(),
            );
            let request = ConnectorRestoreRequest::new("connector", &images);
            migrator.restore_connector(&request).unwrap();
            let first = fs::read_to_string(images.join("args.txt")).unwrap();
            migrator.restore_connector(&request).unwrap();
            let second = fs::read_to_string(images.join("args.txt")).unwrap();
            assert_ne!(first, second, "each attempt needs fresh PID evidence");
            assert!(!images.join("root.pid").exists());
            assert_eq!(fs::read_dir(&images).unwrap().count(), 1);
        }

        fn fake_criu_script(dir: &Path, payload: &str) -> PathBuf {
            let script = dir.join("fake-criu.sh");
            let body = format!(
                r#"#!/bin/sh
set -eu
mode="$1"
shift
images_dir=""
pidfile=""
detached="no"
args="$*"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --pidfile)
      pidfile="$2"
      shift 2
      ;;
    --restore-detached)
      detached="yes"
      shift
      ;;
    --images-dir)
      images_dir="$2"
      shift 2
      ;;
    --log-file|--work-dir|--tree)
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
mkdir -p "$images_dir"
printf "%s" "$args" > "$images_dir/args.txt"
if [ "$mode" = "dump" ]; then
  printf "{payload}" > "$images_dir/core.img"
  echo "dump stderr" >&2
elif [ "$mode" = "restore" ]; then
  test "$detached" = "yes"
  test -n "$pidfile"
  test ! -e "$pidfile"
  printf '4321\n' > "$pidfile"
  echo "diagnostic 9999; restored pid is in the pidfile"
  echo "restore stderr" >&2
else
  echo "unknown mode" >&2
  exit 64
fi
"#
            );
            fs::write(&script, body).unwrap();
            let mut perms = fs::metadata(&script).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&script, perms).unwrap();
            script
        }

        #[test]
        fn dump_runs_criu_and_returns_content_addressed_manifest() {
            let tmp = tempfile::tempdir().unwrap();
            let images = tmp.path().join("images");
            let fake_criu = fake_criu_script(tmp.path(), "checkpoint-bytes");
            let migrator = CriuConnectorMigrator::for_tests(
                fake_criu,
                ConnectorMigrationLimits {
                    max_snapshot_bytes: 1024,
                },
            );
            let policy =
                FileDescriptorRemapPolicy::new(vec![tmp.path().to_path_buf()], "connector-fds")
                    .unwrap();
            let mut request =
                ConnectorCheckpointRequest::new("fcp.test.echo:utility:1.0.0", 1234, &images);
            request.open_file_descriptors =
                vec![OpenFileDescriptor::new(3, tmp.path().join("state.db"))];
            request.fd_policy = Some(policy);

            let manifest = migrator.dump_connector(&request).unwrap();

            assert_eq!(manifest.connector_id, "fcp.test.echo:utility:1.0.0");
            assert_eq!(manifest.source_pid, 1234);
            assert!(manifest.snapshot_size_bytes > 0);
            assert_eq!(manifest.file_descriptors_remapped.len(), 1);
            assert!(manifest.criu_stderr.contains("dump stderr"));
            let args = fs::read_to_string(images.join("args.txt")).unwrap();
            assert!(args.contains("--tree 1234"));
            assert!(args.contains("--leave-running"));
            assert!(args.contains("--shell-job"));
            let serialized = serde_json::to_string(&manifest).unwrap();
            assert!(!serialized.contains(tmp.path().to_str().unwrap()));
            assert_ne!(
                manifest.snapshot_object_id,
                ObjectId::from_bytes([0_u8; 32])
            );
        }

        #[test]
        fn dump_enforces_snapshot_size_cap_after_criu_succeeds() {
            let tmp = tempfile::tempdir().unwrap();
            let fake_criu = fake_criu_script(tmp.path(), "too-large");
            let migrator = CriuConnectorMigrator::for_tests(
                fake_criu,
                ConnectorMigrationLimits {
                    max_snapshot_bytes: 4,
                },
            );
            let request = ConnectorCheckpointRequest::new(
                "fcp.test.echo:utility:1.0.0",
                1234,
                tmp.path().join("images"),
            );

            let err = migrator.dump_connector(&request).unwrap_err();

            assert!(matches!(
                err,
                LinuxMigrationError::SnapshotTooLarge {
                    size_bytes,
                    max_snapshot_bytes: 4
                } if size_bytes > 4
            ));
        }

        #[test]
        fn restore_runs_criu_and_captures_output() {
            let tmp = tempfile::tempdir().unwrap();
            let images = tmp.path().join("images");
            fs::create_dir_all(&images).unwrap();
            let fake_criu = fake_criu_script(tmp.path(), "unused");
            let migrator = CriuConnectorMigrator::for_tests(
                fake_criu,
                ConnectorMigrationLimits {
                    max_snapshot_bytes: 1024,
                },
            );
            let request = ConnectorRestoreRequest::new("fcp.test.echo:utility:1.0.0", &images);

            let report = migrator.restore_connector(&request).unwrap();

            assert_eq!(report.connector_id, "fcp.test.echo:utility:1.0.0");
            assert_eq!(report.restored_pid, Some(4321));
            assert!(report.criu_stdout.contains("restored pid"));
            assert!(report.criu_stderr.contains("restore stderr"));
        }
    }
}
