//! Sign and atomically publish an operator-authored cumulative snapshot.
//! See docs/configuration/runtime_revocation.md for trust and renewal rules.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use fcp_crypto::Ed25519SigningKey;
use fcp_host::RuntimeRevocationSnapshot;
use zeroize::Zeroizing;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 3 {
        return Err(
            "usage: sign_revocation_snapshot OWNER_SEED_FILE PAYLOAD_JSON OUTPUT_JSON".into(),
        );
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut key_file = options.open(&args[0])?;
    let metadata = key_file.metadata()?;
    if !metadata.is_file() || metadata.len() != 32 {
        return Err("owner seed must be a regular file containing exactly 32 raw bytes".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 || metadata.nlink() != 1 {
            return Err("owner seed must be private and singly linked".into());
        }
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    key_file.read_exact(seed.as_mut())?;
    let owner = Ed25519SigningKey::from_bytes(&seed)?;
    let mut payload = Vec::new();
    File::open(&args[1])?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut payload)?;
    if payload.len() > 1024 * 1024 {
        return Err("payload exceeds 1 MiB".into());
    }
    let snapshot: RuntimeRevocationSnapshot = serde_json::from_slice(&payload)?;
    let signed = snapshot.sign(&owner)?;
    let output = Path::new(&args[2]);
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut staging = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer_pretty(&mut staging, &signed)?;
    staging.write_all(b"\n")?;
    staging.as_file().sync_all()?;
    staging.persist(output)?;
    File::open(parent)?.sync_all()?;
    println!(
        "owner_public_key_hex={}",
        hex::encode(owner.verifying_key().to_bytes())
    );
    Ok(())
}
