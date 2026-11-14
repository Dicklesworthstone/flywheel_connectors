//! Immutable native executable images retained for an admitted deployment.
//!
//! Keeping an open source file is insufficient: another writer can still
//! modify its inode. Linux images are copied into a private executable memfd
//! and kernel-sealed before any process can be launched from them. Unsupported
//! platforms and kernels fail closed instead of executing the source path.

use std::io;
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::sync::Arc;

/// Maximum size of one retained native connector image (256 MiB).
pub const MAX_NATIVE_EXECUTABLE_BYTES: usize = 256 * 1024 * 1024;

/// A process-lifetime executable image whose bytes cannot change after capture.
///
/// This retains the executable itself, not its dynamic loader or shared
/// libraries. Production connectors must still satisfy the self-contained
/// binary distribution contract. This is not a supply-chain verification API:
/// callers must establish the authority of the admitted bytes separately.
#[derive(Clone, Debug)]
pub struct NativeExecutableSnapshot {
    #[cfg(target_os = "linux")]
    file: Arc<std::fs::File>,
    #[cfg(not(target_os = "linux"))]
    unavailable: std::convert::Infallible,
}

impl NativeExecutableSnapshot {
    /// Require effective execute access to the exact opened source inode.
    ///
    /// Copying a readable source into a host-owned executable memfd must not
    /// grant execution that the source's mode, ACL or mount policy denied.
    /// Linux uses `faccessat2` with `AT_EMPTY_PATH | AT_EACCESS` (Linux 5.8+).
    /// Missing kernel support fails closed; no pathname access check can race
    /// the already-opened source selected by the caller.
    ///
    /// # Errors
    ///
    /// Returns the kernel's access error if effective execution is denied, or
    /// [`io::ErrorKind::Unsupported`] when descriptor-bound checks are absent.
    pub fn require_source_execution(source: &std::fs::File) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;

            // SAFETY: the source descriptor stays live, the empty C string is
            // valid, and the mode/flags follow faccessat2's documented ABI.
            let result = unsafe {
                libc::syscall(
                    libc::SYS_faccessat2,
                    source.as_raw_fd(),
                    c"".as_ptr(),
                    libc::X_OK,
                    libc::AT_EMPTY_PATH | libc::AT_EACCESS,
                )
            };
            if result == 0 {
                Ok(())
            } else {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ENOSYS) {
                    Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "native source execution admission requires faccessat2 (Linux 5.8+)",
                    ))
                } else {
                    Err(error)
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = source;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "descriptor-bound native execute access requires Linux",
            ))
        }
    }

    /// Seal a bounded native ELF image for all subsequent launches.
    ///
    /// Linux requires executable memfds and immutable-byte sealing. Kernel
    /// policy that disables executable memfds is respected. Other platforms
    /// return [`io::ErrorKind::Unsupported`] without a path-based fallback.
    /// Scripts are rejected: their interpreters require different descriptor
    /// inheritance and are not self-contained connector binaries.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized or non-ELF input. Returns an I/O error if the
    /// kernel denies executable memfds, copying fails, or every required seal
    /// cannot be installed. Unsupported platforms return `Unsupported`.
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() < 16
            || bytes.len() > MAX_NATIVE_EXECUTABLE_BYTES
            || bytes.get(..4) != Some(b"\x7fELF")
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "native connector image must be a nonempty bounded ELF executable",
            ));
        }
        #[cfg(target_os = "linux")]
        {
            Self::seal_linux(bytes)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "immutable native executable admission is supported only on Linux",
            ))
        }
    }

    /// Borrow the descriptor-backed execution path while this snapshot lives.
    ///
    /// The caller MUST retain a snapshot until process creation has completed.
    /// The descriptor is close-on-exec, so it is not leaked into the connector.
    /// The path is resolved through the child's inherited descriptor table;
    /// source-path replacement and in-place source writes cannot change it.
    #[must_use]
    pub fn program(&self) -> PathBuf {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            PathBuf::from(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
        }
        #[cfg(not(target_os = "linux"))]
        {
            match self.unavailable {}
        }
    }

    #[cfg(target_os = "linux")]
    fn seal_linux(bytes: &[u8]) -> io::Result<Self> {
        use std::io::{Read, Seek, Write};
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        use std::os::unix::fs::PermissionsExt;

        // SAFETY: the static C string is NUL-terminated and lives through the
        // syscall. A successful descriptor is immediately placed in OwnedFd.
        let mut descriptor = unsafe {
            libc::memfd_create(
                c"fcp-native-connector".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING | libc::MFD_EXEC,
            )
        };
        if descriptor < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
            // MFD_EXEC was introduced after executable memfds. Older kernels
            // reject that flag with EINVAL; retry only their original API.
            // Never retry an access/policy denial. The created fd must already
            // be executable below, so a modern noexec default is not bypassed.
            // SAFETY: the same static string and documented flags are valid.
            descriptor = unsafe {
                libc::memfd_create(
                    c"fcp-native-connector".as_ptr(),
                    libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
                )
            };
        }
        if descriptor < 0 {
            return Err(io::Error::other(format!(
                "executable memfd admission unavailable: {}",
                io::Error::last_os_error()
            )));
        }
        // SAFETY: memfd_create returned this new descriptor and this is its
        // first owning wrapper; no other owner can close it.
        let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
        // Always reserve an fd above stdio. Command::spawn may replace 0..=2
        // before exec, even when the host originally started with one closed.
        // SAFETY: the source is live and the integer argument is a valid lower
        // bound. F_DUPFD_CLOEXEC returns a separate owned descriptor.
        let retained = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        if retained < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fcntl created a unique descriptor owned by this wrapper.
        let retained = unsafe { OwnedFd::from_raw_fd(retained) };
        drop(descriptor);
        let mut file = std::fs::File::from(retained);
        if file.metadata()?.permissions().mode() & 0o111 == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "kernel policy denied executable memfd admission",
            ));
        }
        file.write_all(bytes)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o500))?;
        let seals =
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        // SAFETY: the fd is live, writable, and created with ALLOW_SEALING;
        // the third argument is the documented integer seal bitmask.
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
            return Err(io::Error::other(format!(
                "immutable executable sealing unavailable: {}",
                io::Error::last_os_error()
            )));
        }
        // SAFETY: F_GET_SEALS takes only the live descriptor and command.
        let installed = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
        if installed < 0 || installed & seals != seals {
            return Err(io::Error::other(
                "native executable did not retain every required kernel seal",
            ));
        }
        // Admission fingerprints the supplied buffer. Confirm that the final
        // sealed image contains those exact bytes before that fingerprint can
        // authorize execution; copying alone is not the final trust boundary.
        if file.metadata()?.len() != bytes.len() as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sealed native executable length differs from its admitted bytes",
            ));
        }
        file.rewind()?;
        let mut buffer = [0_u8; 32 * 1024];
        for expected in bytes.chunks(buffer.len()) {
            file.read_exact(&mut buffer[..expected.len()])?;
            if &buffer[..expected.len()] != expected {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "sealed native executable differs from its admitted bytes",
                ));
            }
        }
        Ok(Self {
            file: Arc::new(file),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_scripts_and_non_native_images() {
        for image in [b"".as_slice(), b"#!/bin/sh\nexit 0\n", b"not an ELF image!"] {
            assert_eq!(
                NativeExecutableSnapshot::from_bytes(image)
                    .expect_err("invalid image must fail admission")
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sealed_image_executes_and_survives_source_changes() {
        let mut source = std::fs::read("/bin/sh").expect("read native shell fixture");
        let image = NativeExecutableSnapshot::from_bytes(&source).expect("seal native ELF");
        let retained = image.clone();
        source.fill(0);
        drop(image);
        let output = std::process::Command::new(retained.program())
            .args(["-c", "printf retained-image"])
            .output()
            .expect("spawn retained image");
        assert!(output.status.success());
        assert_eq!(output.stdout, b"retained-image");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_rejects_backing_file_changes() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::FileExt;

        let source = std::fs::read("/bin/sh").expect("read native shell fixture");
        let image = NativeExecutableSnapshot::from_bytes(&source).expect("seal native ELF");
        let reopened = image.file.try_clone().expect("duplicate the sealed fd");
        assert!(reopened.write_at(b"changed", 0).is_err());
        assert!(reopened.set_len(0).is_err());
        assert!(reopened.set_len(source.len() as u64 + 1).is_err());
        // SAFETY: F_GETFD reads flags from the snapshot's live descriptor.
        let flags = unsafe { libc::fcntl(image.file.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0 && flags & libc::FD_CLOEXEC != 0);
        assert!(image.file.as_raw_fd() > libc::STDERR_FILENO);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn source_execution_access_uses_the_opened_descriptor() {
        use std::os::unix::fs::PermissionsExt;

        let source = std::fs::File::open("/bin/sh").expect("open executable fixture");
        NativeExecutableSnapshot::require_source_execution(&source)
            .expect("native fixture is executable");
        let image = NativeExecutableSnapshot::from_bytes(
            &std::fs::read("/bin/sh").expect("read executable fixture"),
        )
        .expect("seal image");
        image
            .file
            .set_permissions(std::fs::Permissions::from_mode(0o400))
            .expect("remove every execute bit");
        assert_eq!(
            NativeExecutableSnapshot::require_source_execution(&image.file)
                .expect_err("read permission cannot grant execution")
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }
}
