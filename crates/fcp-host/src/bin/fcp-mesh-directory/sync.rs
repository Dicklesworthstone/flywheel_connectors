//! Authenticated delivery into the host's existing file-backed membership path.
//!
//! Transport is never a trust root. The installed signed document is retained
//! as the installer's generation high-water mark, independently of the host's
//! checkpoint. This module does not write or claim to advance host state.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

use fcp_core::TailscaleNodeId;
use fcp_crypto::ed25519::Ed25519VerifyingKey;
use fcp_host::mesh_routing::unix_now_ms;
use fcp_mesh::peer_manifest::{
    MAX_MESH_PEER_DIRECTORY_BYTES, MAX_SIGNED_MESH_PEER_DIRECTORY_BYTES,
    MeshPeerDirectoryPayload, SignedMeshPeerDirectory, VerifiedMeshPeerDirectory,
};
use serde::Serialize;
use url::{Host, Url};

#[cfg(unix)]
#[path = "sync/watch.rs"]
mod watch;

const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
const INITIALIZED: &[u8] = b"FCP-MESH-DIRECTORY-SYNC-V1\n";

#[derive(Debug)]
enum SyncError {
    Remote(String),
    Local(&'static str),
    Storage(&'static str, io::ErrorKind),
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Remote(detail) => write!(f, "membership source refused: {detail}"),
            Self::Local(detail) => write!(f, "membership installer refused: {detail}"),
            Self::Storage(stage, kind) => write!(f, "membership install {stage} failed ({kind:?})"),
        }
    }
}

type SyncResult<T> = std::result::Result<T, SyncError>;

fn storage(stage: &'static str, error: &io::Error) -> SyncError {
    SyncError::Storage(stage, error.kind())
}

struct Trust {
    owner: Ed25519VerifyingKey,
    local: Ed25519VerifyingKey,
    mesh_id: String,
    node: TailscaleNodeId,
}

impl Trust {
    fn from_options(options: &BTreeMap<String, OsString>) -> super::Result<Self> {
        let owner = super::read_key(Path::new(&options["--owner-public-key-file"]), false)?;
        let local = super::read_key(Path::new(&options["--node-public-key-file"]), false)?;
        let mesh_id = options["--mesh-id"].to_str()
            .ok_or_else(|| "mesh id is not UTF-8".to_owned())?.to_owned();
        let node = options["--node-id"].to_str()
            .ok_or_else(|| "node id is not UTF-8".to_owned())?;
        Ok(Self {
            owner: Ed25519VerifyingKey::from_bytes(&owner)
                .map_err(|_| "owner public key is invalid".to_owned())?,
            local: Ed25519VerifyingKey::from_bytes(&local)
                .map_err(|_| "node public key is invalid".to_owned())?,
            mesh_id,
            node: TailscaleNodeId::try_new(node)
                .map_err(|_| "node id is invalid".to_owned())?,
        })
    }

    fn verify(&self, text: &str, now_ms: u64) -> SyncResult<VerifiedMeshPeerDirectory> {
        SignedMeshPeerDirectory::from_json(text)
            .and_then(|signed| signed.verify(
                std::slice::from_ref(&self.owner), &self.mesh_id, self.node.clone(),
                &self.local, now_ms,
            ))
            .map_err(|error| SyncError::Remote(error.to_string()))
    }

    fn installed(&self, text: &str, now_ms: u64) -> SyncResult<VerifiedMeshPeerDirectory> {
        // An expired installed document still protects its accepted generation.
        // Authenticate its exact bytes at a time within its past validity window;
        // NEVER use this historical verification to grant current mesh authority.
        // The new candidate is separately verified at actual current time.
        let signed = SignedMeshPeerDirectory::from_json(text)
            .map_err(|_| SyncError::Local("installed document is malformed"))?;
        if signed.payload_json.len() > MAX_MESH_PEER_DIRECTORY_BYTES {
            return Err(SyncError::Local("installed payload exceeds byte limit"));
        }
        let payload: MeshPeerDirectoryPayload = serde_json::from_str(&signed.payload_json)
            .map_err(|_| SyncError::Local("installed payload is malformed"))?;
        self.verify(text, now_ms.min(payload.expires_at_ms.saturating_sub(1)))
            .map_err(|_| SyncError::Local("installed signature, scope, or local key is invalid"))
    }
}

fn source_url(raw: &str) -> SyncResult<Url> {
    let refused = || SyncError::Local(
        "source must be HTTPS (or literal loopback HTTP), without credentials, query, or fragment",
    );
    if raw.len() > 4096 || raw.trim() != raw {
        return Err(refused());
    }
    let url = Url::parse(raw).map_err(|_| refused())?;
    let loopback = match url.host() {
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    };
    if url.host().is_none()
        || !(url.scheme() == "https" || (url.scheme() == "http" && loopback))
        || !url.username().is_empty() || url.password().is_some()
        || url.query().is_some() || url.fragment().is_some()
    {
        return Err(refused());
    }
    Ok(url)
}

fn fetch(url: &Url, timeout: Duration) -> SyncResult<String> {
    fcp_async_core::runtime::block_on_sync(async {
        // No ambient proxy credentials, redirects, implicit retries, or content
        // decompression. The deadline covers the entire streamed body, not just
        // headers or a per-read idle interval. No request body or owner secret.
        let client = reqwest::Client::builder()
            .connect_timeout(timeout.min(Duration::from_secs(3)))
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .no_gzip().no_brotli().no_deflate().no_zstd()
            .build().map_err(|_| SyncError::Local("HTTP client initialization failed"))?;
        let mut response = client.get(url.clone())
            .header(reqwest::header::ACCEPT, "application/json")
            .header(reqwest::header::ACCEPT_ENCODING, "identity")
            .send().await
            .map_err(|_| SyncError::Remote("request failed or timed out".to_owned()))?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(SyncError::Remote(format!("HTTP {}", response.status().as_u16())));
        }
        if response.headers().get(reqwest::header::CONTENT_ENCODING)
            .is_some_and(|encoding| encoding.as_bytes() != b"identity")
        {
            return Err(SyncError::Remote("encoded response is not accepted".to_owned()));
        }
        if response.content_length().is_some_and(|length|
            length > u64::try_from(MAX_SIGNED_MESH_PEER_DIRECTORY_BYTES).unwrap_or(u64::MAX))
        {
            return Err(SyncError::Remote("response exceeds byte limit".to_owned()));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await
            .map_err(|_| SyncError::Remote("body failed or timed out".to_owned()))?
        {
            if chunk.len() > MAX_SIGNED_MESH_PEER_DIRECTORY_BYTES.saturating_sub(bytes.len()) {
                return Err(SyncError::Remote("response exceeds byte limit".to_owned()));
            }
            bytes.extend_from_slice(&chunk);
        }
        String::from_utf8(bytes)
            .map_err(|_| SyncError::Remote("response is not UTF-8".to_owned()))
    }).map_err(|_| SyncError::Local("membership fetch runtime is unavailable"))?
}

#[derive(Debug, Serialize)]
struct SyncReport {
    schema_version: &'static str,
    action: &'static str,
    mesh_id: String,
    node_id: String,
    generation: u64,
    previous_generation: Option<u64>,
    member_count: usize,
    expires_at_ms: u64,
    payload_hash_hex: String,
    rollback_checked: bool,
    host_activation_verified: bool,
}

#[cfg(unix)]
mod disk {
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Write};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::{Path, PathBuf};

    use super::*;

    pub(super) struct Installer {
        path: PathBuf,
        lock: File,
        initialized: bool,
    }

    fn companion(path: &Path, suffix: &str) -> PathBuf {
        let mut value = path.as_os_str().to_os_string();
        value.push(suffix);
        PathBuf::from(value)
    }

    fn options() -> OpenOptions {
        let mut options = OpenOptions::new();
        options.read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
        options
    }

    fn regular(file: &File, private: bool) -> SyncResult<()> {
        let metadata = file.metadata().map_err(|error| storage("metadata", &error))?;
        let forbidden = if private { 0o077 } else { 0o022 };
        if !metadata.is_file() || metadata.nlink() != 1
            || metadata.permissions().mode() & forbidden != 0
        {
            return Err(SyncError::Local("unsafe installer file type, permissions, or link count"));
        }
        Ok(())
    }

    fn sync_parent(path: &Path) -> SyncResult<()> {
        let parent = path.parent().filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        File::open(parent).and_then(|file| file.sync_all())
            .map_err(|error| storage("directory_sync", &error))
    }

    impl Installer {
        pub(super) fn open(path: &Path) -> SyncResult<Self> {
            if path.file_name().is_none() {
                return Err(SyncError::Local("destination must name a file in an existing trusted directory"));
            }
            let mut lock = options().write(true).create(true).truncate(false).mode(0o600)
                .open(companion(path, ".sync-lock"))
                .map_err(|error| storage("lock_open", &error))?;
            regular(&lock, true)?;
            lock.try_lock().map_err(|_| SyncError::Local("installer is locked or locking is unsupported"))?;
            let mut marker = Vec::new();
            (&mut lock).take(u64::try_from(INITIALIZED.len() + 1).unwrap_or(u64::MAX))
                .read_to_end(&mut marker).map_err(|error| storage("lock_read", &error))?;
            if !marker.is_empty() && marker != INITIALIZED {
                return Err(SyncError::Local("installer initialization marker is corrupt"));
            }
            Ok(Self { path: path.to_path_buf(), lock, initialized: !marker.is_empty() })
        }

        pub(super) fn read_installed(&self) -> SyncResult<Option<String>> {
            let mut file = match options().open(&self.path) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound && !self.initialized => {
                    return Ok(None);
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    return Err(SyncError::Local("initialized source is missing; refusing generation reset"));
                }
                Err(error) => return Err(storage("source_open", &error)),
            };
            regular(&file, false)?;
            let mut bytes = Vec::new();
            (&mut file).take(u64::try_from(MAX_SIGNED_MESH_PEER_DIRECTORY_BYTES + 1).unwrap_or(u64::MAX))
                .read_to_end(&mut bytes).map_err(|error| storage("source_read", &error))?;
            if bytes.len() > MAX_SIGNED_MESH_PEER_DIRECTORY_BYTES {
                return Err(SyncError::Local("installed source exceeds byte limit"));
            }
            String::from_utf8(bytes).map(Some)
                .map_err(|_| SyncError::Local("installed source is not UTF-8"))
        }

        pub(super) fn mark_initialized(&mut self) -> SyncResult<()> {
            if !self.initialized {
                self.lock.write_all(INITIALIZED).and_then(|()| self.lock.sync_all())
                    .map_err(|error| storage("initialize", &error))?;
                sync_parent(&self.path)?;
                self.initialized = true;
            }
            Ok(())
        }

        pub(super) fn install(&mut self, text: &str, trust: &Trust) -> SyncResult<SyncReport> {
            let started = Instant::now();
            let now_ms = unix_now_ms();
            let incoming = trust.verify(text, now_ms)?;
            let current_text = self.read_installed()?;
            let previous = current_text.as_deref()
                .map(|text| trust.installed(text, now_ms)).transpose()?;
            if let Some(previous) = &previous {
                incoming.check_successor(previous.checkpoint())
                    .map_err(|error| SyncError::Remote(error.to_string()))?;
            }
            let report = SyncReport {
                schema_version: "fcp.mesh.directory_sync.v1",
                action: if current_text.as_deref() == Some(text) { "unchanged" } else { "installed" },
                mesh_id: trust.mesh_id.clone(),
                node_id: trust.node.as_str().to_owned(),
                generation: incoming.payload().generation,
                previous_generation: previous.as_ref().map(|entry| entry.payload().generation),
                member_count: incoming.payload().peers.len(),
                expires_at_ms: incoming.payload().expires_at_ms,
                payload_hash_hex: incoming.checkpoint().payload_hash_hex.clone(),
                rollback_checked: previous.is_some(),
                host_activation_verified: false,
            };
            let still_valid = || {
                let current_ms = unix_now_ms();
                if current_ms < now_ms || current_ms >= report.expires_at_ms
                    || started.elapsed() >= Duration::from_millis(report.expires_at_ms - now_ms)
                {
                    Err(SyncError::Remote("candidate expired or clock regressed during install".to_owned()))
                } else {
                    Ok(())
                }
            };
            if report.action == "installed" {
                let next_path = companion(&self.path, ".sync-next");
                let mut next = options().write(true).create(true).truncate(false).mode(0o600)
                    .open(&next_path).map_err(|error| storage("staging_open", &error))?;
                // Reserved staging files may survive interrupted writes. Validate
                // the inode before truncation; no symlink/hard-link target is touched.
                regular(&next, true)?;
                next.set_len(0).and_then(|()| next.write_all(text.as_bytes()))
                    .and_then(|()| next.sync_all()).map_err(|error| storage("stage", &error))?;
                if self.read_installed()? != current_text {
                    return Err(SyncError::Local("source changed outside its installer"));
                }
                still_valid()?;
                std::fs::rename(&next_path, &self.path).map_err(|error| storage("replace", &error))?;
                sync_parent(&self.path)?;
            }
            self.mark_initialized()?;
            still_valid()?;
            Ok(report)
        }
    }
}

pub(super) fn run(options: &BTreeMap<String, OsString>, output: &mut impl io::Write) -> super::Result<()> {
    #[cfg(not(unix))]
    {
        let _ = (options, output);
        Err("membership installation requires Unix filesystem guarantees".to_owned())
    }
    #[cfg(unix)]
    {
        let trust = Trust::from_options(options)?;
        let url = source_url(options["--url"].to_str().ok_or_else(|| "source URL is not UTF-8".to_owned())?)
            .map_err(|error| error.to_string())?;
        let mut installer = disk::Installer::open(Path::new(&options["--directory"]))
            .map_err(|error| error.to_string())?;
        let text = fetch(&url, FETCH_TIMEOUT).map_err(|error| error.to_string())?;
        let report = installer.install(&text, &trust).map_err(|error| error.to_string())?;
        serde_json::to_writer(&mut *output, &report).map_err(|_| "sync output failed".to_owned())?;
        writeln!(output).map_err(|_| "sync output failed".to_owned())
    }
}

pub(super) fn run_watch(options: &BTreeMap<String, OsString>, output: &mut impl io::Write) -> super::Result<()> {
    #[cfg(not(unix))]
    {
        let _ = (options, output);
        Err("membership installation requires Unix filesystem guarantees".to_owned())
    }
    #[cfg(unix)]
    watch::run(options, output)
}

#[cfg(all(test, unix))]
#[path = "sync/tests.rs"]
mod tests;
