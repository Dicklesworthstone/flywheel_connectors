//! Bind connector launches to operator-pinned executable bytes.
//!
//! A digest computed from a mutable pathname is not launch authority. Native
//! Linux launches copy a bounded regular file into an anonymous image, seal it,
//! and hash the sealed bytes. The owned descriptor stays alive through process
//! creation. WASI callers receive the exact checked bytes for compilation.
//!
//! These pins cover the main executable only. They do not authenticate its
//! dynamic loader, shared libraries, or other files opened by the connector.

use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

/// Upper bound for one pinned connector executable or WASI component.
pub const MAX_PINNED_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;

/// A SHA-256 pin supplied by managed inventory, never inferred from its file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutableDigest([u8; 32]);

impl ExecutableDigest {
    /// Parse exactly 64 hexadecimal characters, without a prefix or whitespace.
    ///
    /// # Errors
    /// Returns an invalid-input error for any malformed SHA-256 pin.
    pub fn parse(value: &str) -> io::Result<Self> {
        let mut digest = [0_u8; 32];
        if value.len() != 64 || hex::decode_to_slice(value, &mut digest).is_err() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "binary_sha256 must contain exactly 64 hexadecimal characters",
            ));
        }
        Ok(Self(digest))
    }

    /// Verify an already admitted byte buffer without reopening its source.
    ///
    /// # Errors
    /// Returns an invalid-data error when the supplied bytes do not match.
    pub fn verify_bytes(&self, bytes: &[u8]) -> io::Result<()> {
        self.require_match(Sha256::digest(bytes).into())
    }

    fn require_match(self, actual: [u8; 32]) -> io::Result<()> {
        if self.0 == actual {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "connector executable does not match its managed binary_sha256 pin",
            ))
        }
    }
}

fn open_bounded_executable(path: &Path) -> io::Result<File> {
    // Avoid opening a known device/FIFO at all. Recheck the opened handle, and
    // use nonblocking open on Unix so a replacement with a FIFO cannot hang.
    let before = std::fs::metadata(path)?;
    require_regular_bounded_file(&before)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    require_regular_bounded_file(&file.metadata()?)?;
    Ok(file)
}

fn require_regular_bounded_file(metadata: &std::fs::Metadata) -> io::Result<()> {
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "pinned connector executable must be a regular file",
        ));
    }
    require_bounded_length(metadata.len())
}

fn require_bounded_length(length: u64) -> io::Result<()> {
    if length == 0 || length > MAX_PINNED_EXECUTABLE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "pinned connector executable must contain between 1 byte and 512 MiB",
        ));
    }
    Ok(())
}

/// Read bounded executable bytes and check their independently supplied pin.
///
/// WASI compilation must consume the returned bytes instead of reopening the
/// pathname. Replacing or rewriting that pathname cannot change this result.
///
/// # Errors
/// Returns an error for unreadable/nonregular/oversized files or a digest mismatch.
pub fn read_pinned_executable(path: &Path, digest: &ExecutableDigest) -> io::Result<Vec<u8>> {
    let file = open_bounded_executable(path)?;
    let length = file.metadata()?.len();
    require_bounded_length(length)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(usize::try_from(length).map_err(|_| {
            io::Error::other("pinned connector executable does not fit in address space")
        })?)
        .map_err(|_| io::Error::other("cannot allocate pinned connector executable buffer"))?;
    let mut reader = file.take(MAX_PINNED_EXECUTABLE_BYTES + 1);
    let mut buffer = [0_u8; 32 * 1024];
    loop {
        let count = match reader.read(&mut buffer) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if count == 0 {
            break;
        }
        require_bounded_length(bytes.len() as u64 + count as u64)?;
        // Exact growth avoids doubling a nearly full buffer merely to detect
        // that a concurrently growing source exceeded the admission limit.
        bytes
            .try_reserve_exact(count)
            .map_err(|_| io::Error::other("cannot grow pinned connector executable buffer"))?;
        bytes.extend_from_slice(&buffer[..count]);
    }
    require_bounded_length(bytes.len() as u64)?;
    digest.verify_bytes(&bytes)?;
    Ok(bytes)
}

/// An immutable native executable image whose owned descriptor pins its path.
///
/// Keep this value alive until `Command::spawn` returns. A warm pool can share
/// one instance with `Arc` across all of its physical children. Linux supports
/// ELF images; scripts are intentionally rejected because their interpreter
/// would reopen a descriptor after close-on-exec. Other platforms fail closed
/// until they provide an equivalent immutable process-launch primitive.
#[derive(Debug)]
pub struct PinnedNativeExecutable {
    path: PathBuf,
    digest: ExecutableDigest,
    // Ownership keeps the descriptor path bound until process creation ends.
    #[cfg(target_os = "linux")]
    _image: File,
}

impl PinnedNativeExecutable {
    /// Load, seal and verify an ELF executable without starting a process.
    ///
    /// The final digest is calculated *after* write/grow/shrink seals are in
    /// place. It therefore authenticates the image the kernel will execute,
    /// even if the source file changes while it is being copied.
    ///
    /// # Errors
    /// Returns an error for an unsupported platform/image, failed seals,
    /// invalid file/length, or a digest mismatch. No pathname launch fallback
    /// is permitted after a pin has been configured.
    pub fn load(path: &Path, digest: &ExecutableDigest) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            use std::io::Seek as _;
            use std::os::fd::AsRawFd as _;

            use rustix::fs::{MemfdFlags, Mode, SealFlags};

            let source = open_bounded_executable(path)?;
            let flags = MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING;
            let descriptor =
                match rustix::fs::memfd_create("fcp-connector", flags | MemfdFlags::EXEC) {
                    // Linux before 6.3 does not recognize MFD_EXEC. Never retry
                    // EACCES: a current kernel's no-exec policy must remain final.
                    Err(rustix::io::Errno::INVAL) => {
                        rustix::fs::memfd_create("fcp-connector", flags)?
                    }
                    result => result?,
                };
            let mut image = File::from(descriptor);
            let length = io::copy(
                &mut source.take(MAX_PINNED_EXECUTABLE_BYTES + 1),
                &mut image,
            )?;
            require_bounded_length(length)?;
            rustix::fs::fchmod(&image, Mode::RUSR | Mode::XUSR)?;
            let seals = SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL;
            rustix::fs::fcntl_add_seals(&image, seals)?;
            if !rustix::fs::fcntl_get_seals(&image)?.contains(seals) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "connector executable image could not be made immutable",
                ));
            }
            image.rewind()?;
            let mut magic = [0_u8; 4];
            image.read_exact(&mut magic)?;
            let mut hasher = Sha256::new();
            hasher.update(magic);
            let mut buffer = [0_u8; 32 * 1024];
            loop {
                let count = match image.read(&mut buffer) {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    result => result?,
                };
                if count == 0 {
                    break;
                }
                hasher.update(&buffer[..count]);
            }
            digest.require_match(hasher.finalize().into())?;
            if magic != *b"\x7fELF" {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "pinned native execution requires an ELF binary; scripts and interpreters' source files are unsupported",
                ));
            }
            let path = PathBuf::from(format!("/proc/self/fd/{}", image.as_raw_fd()));
            Ok(Self {
                path,
                digest: *digest,
                _image: image,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (path, digest);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "pinned native executable launch is unavailable on this platform; no mutable-path fallback is permitted",
            ))
        }
    }

    /// Kernel path of the sealed image, valid while this owner is alive.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Digest authenticated from the sealed executable image.
    #[must_use]
    pub const fn digest(&self) -> ExecutableDigest {
        self.digest
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    fn digest(bytes: &[u8]) -> ExecutableDigest {
        ExecutableDigest(Sha256::digest(bytes).into())
    }

    #[test]
    fn pins_are_exact_hex_and_case_insensitive() {
        let pin = "a1".repeat(32);
        assert_eq!(
            ExecutableDigest::parse(&pin).unwrap(),
            ExecutableDigest::parse(&pin.to_uppercase()).unwrap()
        );
        for invalid in [
            String::new(),
            "a".repeat(63),
            "a".repeat(65),
            "gg".repeat(32),
            format!("sha256:{pin}"),
            format!("{pin} "),
        ] {
            assert_eq!(
                ExecutableDigest::parse(&invalid).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    #[test]
    fn checked_wasi_bytes_survive_origin_replacement() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        let original = b"\0asm\x01\0\0\0";
        file.write_all(original).unwrap();
        let pin = digest(original);
        let checked = read_pinned_executable(file.path(), &pin).unwrap();
        std::fs::write(file.path(), b"changed component").unwrap();
        assert_eq!(checked, original);
        assert_eq!(
            read_pinned_executable(file.path(), &pin)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn pinned_reads_reject_empty_oversized_and_nonregular_files() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let pin = digest(b"unused");
        assert!(read_pinned_executable(file.path(), &pin).is_err());
        file.as_file()
            .set_len(MAX_PINNED_EXECUTABLE_BYTES + 1)
            .unwrap();
        assert!(read_pinned_executable(file.path(), &pin).is_err());
        let directory = tempfile::tempdir().unwrap();
        assert_eq!(
            read_pinned_executable(directory.path(), &pin)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sealed_native_launch_uses_original_bytes_after_origin_replacement() {
        let original = std::fs::read("/bin/true").unwrap();
        let mut source = tempfile::NamedTempFile::new().unwrap();
        source.write_all(&original).unwrap();
        let pin = digest(&original);
        let executable = PinnedNativeExecutable::load(source.path(), &pin).unwrap();
        std::fs::write(source.path(), std::fs::read("/bin/false").unwrap()).unwrap();
        for _ in 0..2 {
            let result = std::process::Command::new(executable.path())
                .status()
                .unwrap();
            assert!(
                result.success(),
                "reused sealed image must remain /bin/true"
            );
        }
        assert_eq!(
            PinnedNativeExecutable::load(source.path(), &pin)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn native_image_is_sealed_against_writes_and_resizing() {
        let bytes = std::fs::read("/bin/true").unwrap();
        let executable =
            PinnedNativeExecutable::load(Path::new("/bin/true"), &digest(&bytes)).unwrap();
        let mut writable = executable._image.try_clone().unwrap();
        assert!(writable.write_all(b"changed").is_err());
        assert!(writable.set_len(1).is_err());
        assert!(writable.set_len(bytes.len() as u64 + 1).is_err());
        assert!(
            rustix::fs::fcntl_get_seals(&executable._image)
                .unwrap()
                .contains(
                    rustix::fs::SealFlags::WRITE
                        | rustix::fs::SealFlags::GROW
                        | rustix::fs::SealFlags::SHRINK
                        | rustix::fs::SealFlags::SEAL
                )
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn native_load_rejects_wrong_pin_and_scripts() {
        let wrong = digest(b"not /bin/true");
        assert_eq!(
            PinnedNativeExecutable::load(Path::new("/bin/true"), &wrong)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        let mut script = tempfile::NamedTempFile::new().unwrap();
        let bytes = b"#!/bin/sh\nexit 0\n";
        script.write_all(bytes).unwrap();
        let error = PinnedNativeExecutable::load(script.path(), &digest(bytes)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(error.to_string().contains("ELF"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pinned_fifo_is_rejected_without_waiting_for_a_writer() {
        let directory = tempfile::tempdir().unwrap();
        let fifo = directory.path().join("connector.fifo");
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .unwrap();
        let pin = digest(b"unused");
        assert_eq!(
            PinnedNativeExecutable::load(&fifo, &pin)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
