//! Retain the native image selected by one Linux inventory admission.
//!
//! The source is opened only for admission or explicit inventory comparison.
//! Runtime creation executes the sealed image, including warm-pool replacement
//! workers. Other platforms retain their existing native launch behavior until
//! an equivalent immutable image mechanism is implemented there.

use super::*;

#[derive(Clone, Debug)]
pub(super) struct AdmittedNativeExecutable {
    #[cfg(target_os = "linux")]
    image: fcp_sandbox::NativeExecutableSnapshot,
    digest: [u8; 32],
    bytes: u64,
}

impl AdmittedNativeExecutable {
    pub(super) fn capture_for_platform(config: &ConnectorConfig) -> HostResult<Option<Self>> {
        #[cfg(target_os = "linux")]
        {
            Self::capture(config).map(Some)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = config;
            Ok(None)
        }
    }

    #[cfg(target_os = "linux")]
    fn capture(config: &ConnectorConfig) -> HostResult<Self> {
        let file = open_source(config)?;
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(
            &mut std::io::Read::take(file, fcp_sandbox::MAX_NATIVE_EXECUTABLE_BYTES as u64 + 1),
            &mut bytes,
        )
        .map_err(|_| source_error(config))?;
        let image = fcp_sandbox::NativeExecutableSnapshot::from_bytes(&bytes).map_err(|error| {
            HostError::RegistryError(format!(
                "native connector '{}' immutable executable admission failed: {error}",
                config.id
            ))
        })?;
        Ok(Self {
            image,
            digest: *blake3::hash(&bytes).as_bytes(),
            bytes: bytes.len() as u64,
        })
    }

    #[cfg(target_os = "linux")]
    pub(super) fn program(&self) -> PathBuf {
        self.image.program()
    }

    /// Inspect current managed source only for explicit preview/apply. This
    /// digest never authorizes executing the mutable source path.
    pub(super) fn source_matches(&self, config: &ConnectorConfig) -> HostResult<bool> {
        let file = open_source(config)?;
        if file.metadata().map_err(|_| source_error(config))?.len() != self.bytes {
            return Ok(false);
        }
        let mut source = std::io::Read::take(file, self.bytes + 1);
        let mut buffer = [0_u8; 8192];
        let mut total = 0_u64;
        let mut hasher = blake3::Hasher::new();
        loop {
            let read = match std::io::Read::read(&mut source, &mut buffer) {
                Ok(read) => read,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(source_error(config)),
            };
            if read == 0 {
                break;
            }
            total += read as u64;
            if total > self.bytes {
                return Ok(false);
            }
            hasher.update(&buffer[..read]);
        }
        Ok(total == self.bytes && hasher.finalize().as_bytes() == &self.digest)
    }
}

fn source_error(config: &ConnectorConfig) -> HostError {
    HostError::RegistryError(format!(
        "native connector '{}' requires a readable, executable regular ELF file no larger than {} bytes",
        config.id,
        fcp_sandbox::MAX_NATIVE_EXECUTABLE_BYTES
    ))
}

fn source_io_error(config: &ConnectorConfig, error: &std::io::Error) -> HostError {
    if error.kind() == std::io::ErrorKind::Unsupported {
        HostError::RegistryError(format!(
            "native connector '{}' executable source admission unavailable: {error}",
            config.id
        ))
    } else {
        source_error(config)
    }
}

fn open_source(config: &ConnectorConfig) -> HostResult<std::fs::File> {
    if config.binary.contains(std::path::MAIN_SEPARATOR) {
        return open_source_path(StdPath::new(&config.binary))
            .map_err(|error| source_io_error(config, &error));
    }
    // Command's managed environment overrides its inherited PATH. Resolve it
    // once before admission; workers never search PATH again. The default is
    // the Unix exec search path used when PATH is absent, not a search of cwd.
    let path = config
        .env
        .get("PATH")
        .map(OsString::from)
        .or_else(|| std::env::var_os("PATH"))
        .unwrap_or_else(|| OsString::from("/bin:/usr/bin"));
    for directory in std::env::split_paths(&path) {
        match open_source_path(&directory.join(&config.binary)) {
            Ok(file) => return Ok(file),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound
                        | std::io::ErrorKind::NotADirectory
                        | std::io::ErrorKind::PermissionDenied
                ) => {}
            Err(error) => return Err(source_io_error(config, &error)),
        }
    }
    Err(source_error(config))
}

fn open_source_path(path: &StdPath) -> std::io::Result<std::fs::File> {
    fn check(metadata: &std::fs::Metadata) -> std::io::Result<()> {
        if !metadata.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "native image source is not a regular file",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o111 == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "native image source is not executable",
                ));
            }
        }
        if metadata.len() == 0 || metadata.len() > fcp_sandbox::MAX_NATIVE_EXECUTABLE_BYTES as u64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "native image source is empty or exceeds its admission bound",
            ));
        }
        Ok(())
    }

    check(&std::fs::metadata(path)?)?;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // A source replaced by a FIFO between metadata and open must not block
        // the host. Type, permissions and bounds are rechecked on the opened fd.
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    check(&file.metadata()?)?;
    #[cfg(target_os = "linux")]
    fcp_sandbox::NativeExecutableSnapshot::require_source_execution(&file)?;
    Ok(file)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn managed_path_is_resolved_once_and_source_writes_do_not_change_launches() {
        let directory = tempfile::tempdir().expect("native image directory");
        let binary = directory.path().join("admitted-connector");
        std::fs::copy("/bin/sh", &binary).expect("copy native fixture");
        let mut config = super::super::tests::dispatcher_test_config("fcp.webhook-receiver");
        config.binary = "admitted-connector".to_owned();
        config.env.insert(
            "PATH".to_owned(),
            directory.path().to_string_lossy().into_owned(),
        );
        let admitted = AdmittedNativeExecutable::capture(&config).expect("admit managed PATH");
        assert!(admitted.source_matches(&config).expect("source comparison"));
        let mut changed = std::fs::read(&binary).expect("read same-size replacement");
        changed[0] ^= 0xff;
        std::fs::write(&binary, changed).expect("replace same-size source bytes");
        assert!(!admitted.source_matches(&config).expect("source comparison"));
        let output = std::process::Command::new(admitted.program())
            .args(["-c", "printf retained-native"])
            .output()
            .expect("spawn retained image after source mutation");
        assert!(output.status.success());
        assert_eq!(output.stdout, b"retained-native");
    }

    #[test]
    fn rejects_unbounded_special_and_interpreted_sources() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("native image directory");
        let mut config = super::super::tests::dispatcher_test_config("fcp.webhook-receiver");
        for path in [directory.path(), StdPath::new("/dev/null")] {
            config.binary = path.to_string_lossy().into_owned();
            assert!(AdmittedNativeExecutable::capture(&config).is_err());
        }
        let binary = directory.path().join("connector");
        std::fs::write(&binary, b"#!/bin/sh\nexit 0\n").expect("write script fixture");
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700))
            .expect("set fixture mode");
        config.binary = binary.to_string_lossy().into_owned();
        assert!(AdmittedNativeExecutable::capture(&config).is_err());
        let oversized = std::fs::File::create(&binary).expect("create oversized fixture");
        oversized
            .set_len(fcp_sandbox::MAX_NATIVE_EXECUTABLE_BYTES as u64 + 1)
            .expect("set sparse file size");
        assert!(AdmittedNativeExecutable::capture(&config).is_err());
    }
}
