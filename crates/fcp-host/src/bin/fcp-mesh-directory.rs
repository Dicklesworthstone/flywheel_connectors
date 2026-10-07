//! Offline issuance and inspection of owner-authorized mesh membership.
//!
//! Owner secret material is read only from a bounded private file, zeroized
//! after use, and never accepted through command-line values or printed.

#![deny(unsafe_code)]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::Path;
use std::process::ExitCode;

use fcp_core::TailscaleNodeId;
use fcp_crypto::ed25519::{Ed25519SigningKey, Ed25519VerifyingKey};
use fcp_host::mesh_routing::unix_now_ms;
use fcp_mesh::peer_manifest::{
    MAX_MESH_PEER_DIRECTORY_BYTES, MAX_SIGNED_MESH_PEER_DIRECTORY_BYTES,
    MeshPeerDirectoryPayload, SignedMeshPeerDirectory,
};
use zeroize::Zeroizing;

const USAGE: &str = "Usage:
  fcp-mesh-directory sign --owner-key-file PATH --payload PATH
  fcp-mesh-directory verify --owner-public-key-file PATH --mesh-id ID --node-id ID --node-public-key-file PATH --directory PATH

sign writes the signed directory JSON to stdout. verify writes a JSON summary.
Key files contain 32 bytes encoded as 64 hex characters. The owner secret file
must be private (mode 0600 on Unix). Verification is offline and does not update
or replace the host's persistent anti-rollback checkpoint.
";

type Result<T> = std::result::Result<T, String>;

fn main() -> ExitCode {
    let stdout = std::io::stdout();
    match run(std::env::args_os().skip(1).collect(), &mut stdout.lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("fcp-mesh-directory: {error}");
            ExitCode::FAILURE
        }
    }
}

fn arguments(args: Vec<OsString>) -> Result<(String, BTreeMap<String, OsString>)> {
    let mut args = args.into_iter();
    let command = args
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| USAGE.to_owned())?;
    let required: &[&str] = match command.as_str() {
        "sign" => &["--owner-key-file", "--payload"],
        "verify" => &[
            "--owner-public-key-file", "--mesh-id", "--node-id",
            "--node-public-key-file", "--directory",
        ],
        _ => return Err(USAGE.to_owned()),
    };
    let mut options = BTreeMap::new();
    while let Some(name) = args.next() {
        let name = name.into_string().map_err(|_| "option name is not UTF-8".to_owned())?;
        if !required.contains(&name.as_str()) {
            return Err("unknown option for this command".to_owned());
        }
        let value = args.next().filter(|value| !value.is_empty())
            .ok_or_else(|| format!("missing value for {name}"))?;
        if options.insert(name, value).is_some() {
            return Err("duplicate option".to_owned());
        }
    }
    if required.iter().any(|name| !options.contains_key(*name)) {
        return Err("required option is missing; use --help".to_owned());
    }
    Ok((command, options))
}

fn read_bounded(path: &Path, limit: usize, secret: bool) -> Result<Zeroizing<Vec<u8>>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let mut file = options.open(path).map_err(|error| format!("input open failed ({:?})", error.kind()))?;
    let metadata = file.metadata().map_err(|_| "input metadata is unavailable".to_owned())?;
    if !metadata.is_file() {
        return Err("input must be a regular file".to_owned());
    }
    if secret {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if metadata.permissions().mode() & 0o077 != 0 || metadata.nlink() != 1 {
                return Err("owner key must be private and not hard-linked".to_owned());
            }
        }
        #[cfg(not(unix))]
        return Err("owner signing requires Unix private-file guarantees".to_owned());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    (&mut file)
        .take(u64::try_from(limit + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)
        .map_err(|_| "input read failed".to_owned())?;
    if bytes.len() > limit {
        return Err("input exceeds byte limit".to_owned());
    }
    Ok(bytes)
}

fn read_key(path: &Path, secret: bool) -> Result<Zeroizing<[u8; 32]>> {
    let bytes = read_bounded(path, 128, secret)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "key must contain 64 hex characters".to_owned())?;
    let mut key = Zeroizing::new([0; 32]);
    hex::decode_to_slice(text.trim(), &mut *key)
        .map_err(|_| "key must contain 64 hex characters".to_owned())?;
    Ok(key)
}

fn run(args: Vec<OsString>, output: &mut impl Write) -> Result<()> {
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        return output.write_all(USAGE.as_bytes()).map_err(|_| "output failed".to_owned());
    }
    let (command, options) = arguments(args)?;
    if command == "sign" {
        let key = read_key(Path::new(&options["--owner-key-file"]), true)?;
        let owner = Ed25519SigningKey::from_bytes(&key)
            .map_err(|_| "owner key is invalid".to_owned())?;
        let bytes = read_bounded(Path::new(&options["--payload"]), MAX_MESH_PEER_DIRECTORY_BYTES, false)?;
        let payload: MeshPeerDirectoryPayload = serde_json::from_slice(&bytes)
            .map_err(|_| "membership payload JSON is invalid".to_owned())?;
        let signed = SignedMeshPeerDirectory::sign(&owner, &payload)
            .map_err(|error| error.to_string())?;
        serde_json::to_writer_pretty(&mut *output, &signed)
            .map_err(|_| "signed directory output failed".to_owned())?;
    } else {
        let owner_bytes = read_key(Path::new(&options["--owner-public-key-file"]), false)?;
        let owner = Ed25519VerifyingKey::from_bytes(&owner_bytes)
            .map_err(|_| "owner public key is invalid".to_owned())?;
        let local_bytes = read_key(Path::new(&options["--node-public-key-file"]), false)?;
        let local = Ed25519VerifyingKey::from_bytes(&local_bytes)
            .map_err(|_| "node public key is invalid".to_owned())?;
        let mesh_id = options["--mesh-id"].to_str()
            .ok_or_else(|| "mesh id is not UTF-8".to_owned())?;
        let node_id = options["--node-id"].to_str()
            .ok_or_else(|| "node id is not UTF-8".to_owned())?;
        let node = TailscaleNodeId::try_new(node_id)
            .map_err(|_| "node id is invalid".to_owned())?;
        let bytes = read_bounded(
            Path::new(&options["--directory"]),
            MAX_SIGNED_MESH_PEER_DIRECTORY_BYTES,
            false,
        )?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| "signed directory is not UTF-8".to_owned())?;
        let signed = SignedMeshPeerDirectory::from_json(text).map_err(|error| error.to_string())?;
        let verified = signed.verify(&[owner], mesh_id, node, &local, unix_now_ms())
            .map_err(|error| error.to_string())?;
        let payload = verified.payload();
        serde_json::to_writer_pretty(&mut *output, &serde_json::json!({
            "verification": "signature_scope_local_key_and_validity",
            "mesh_id": payload.mesh_id,
            "node_id": node_id,
            "generation": payload.generation,
            "member_count": payload.peers.len(),
            "issued_at_ms": payload.issued_at_ms,
            "expires_at_ms": payload.expires_at_ms,
            "payload_hash_hex": verified.checkpoint().payload_hash_hex,
            "rollback_checked": false,
        })).map_err(|_| "verification output failed".to_owned())?;
    }
    writeln!(output).map_err(|_| "output failed".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(|value| OsString::from(*value)).collect()
    }

    #[test]
    fn parses_sign_paths_without_accepting_secret_material_options() {
        let (command, options) = arguments(args(&[
            "sign", "--owner-key-file", "owner.key", "--payload", "membership.json",
        ])).unwrap();
        assert_eq!(command, "sign");
        assert_eq!(options["--payload"], "membership.json");
        assert!(arguments(args(&["sign", "--owner-key", "do-not-echo-secret"])).is_err());
    }

    #[test]
    fn malformed_arguments_fail_without_echoing_values() {
        for values in [
            vec!["sign"],
            vec!["sign", "--payload"],
            vec!["sign", "--payload", "p", "--payload", "q"],
            vec!["verify", "--directory", "d"],
            vec!["unknown", "do-not-echo-secret"],
        ] {
            let error = arguments(args(&values)).unwrap_err();
            assert!(!error.contains("do-not-echo-secret"));
        }
    }

    #[test]
    fn help_and_bounded_key_errors_do_not_print_secrets() {
        let mut output = Vec::new();
        run(args(&["--help"]), &mut output).unwrap();
        assert!(String::from_utf8(output).unwrap().contains("anti-rollback"));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oversized");
        std::fs::write(&path, b"a".repeat(129)).unwrap();
        let error = read_key(&path, false).unwrap_err();
        assert_eq!(error, "input exceeds byte limit");
    }

    #[cfg(unix)]
    #[test]
    fn private_owner_key_is_required_and_never_written_to_output() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("owner.key");
        let payload_path = dir.path().join("payload.json");
        let owner = Ed25519SigningKey::from_bytes(&[51; 32]).unwrap();
        let local = Ed25519SigningKey::from_bytes(&[52; 32]).unwrap();
        let secret = hex::encode(owner.to_bytes());
        std::fs::write(&key_path, &secret).unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_key(&key_path, true).is_err());
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let now = unix_now_ms();
        let payload = serde_json::json!({
            "schema_version": "fcp.mesh.peer-directory.v1",
            "mesh_id": "operator-test",
            "generation": 1,
            "issued_at_ms": now,
            "expires_at_ms": now + 60_000,
            "peers": [{
                "node_id": "local",
                "endpoint": "http://127.0.0.1:19001",
                "public_key_hex": hex::encode(local.verifying_key().to_bytes()),
            }],
        });
        std::fs::write(&payload_path, serde_json::to_vec(&payload).unwrap()).unwrap();
        let mut output = Vec::new();
        run(vec![
            OsString::from("sign"), OsString::from("--owner-key-file"), key_path.into_os_string(),
            OsString::from("--payload"), payload_path.into_os_string(),
        ], &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(!text.contains(&secret));
        let signed = SignedMeshPeerDirectory::from_json(&text).unwrap();
        signed.verify(
            &[owner.verifying_key()], "operator-test", TailscaleNodeId::new("local"),
            &local.verifying_key(), now,
        ).unwrap();

        let owner_public = dir.path().join("owner.pub");
        let node_public = dir.path().join("node.pub");
        let directory = dir.path().join("directory.json");
        std::fs::write(&owner_public, hex::encode(owner.verifying_key().to_bytes())).unwrap();
        std::fs::write(&node_public, hex::encode(local.verifying_key().to_bytes())).unwrap();
        std::fs::write(&directory, text).unwrap();
        let mut output = Vec::new();
        run(vec![
            OsString::from("verify"),
            OsString::from("--owner-public-key-file"), owner_public.into_os_string(),
            OsString::from("--mesh-id"), OsString::from("operator-test"),
            OsString::from("--node-id"), OsString::from("local"),
            OsString::from("--node-public-key-file"), node_public.into_os_string(),
            OsString::from("--directory"), directory.into_os_string(),
        ], &mut output).unwrap();
        let summary: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(summary["generation"], 1);
        assert_eq!(summary["member_count"], 1);
        assert_eq!(summary["rollback_checked"], false);
        assert!(!String::from_utf8(output).unwrap().contains(&secret));
    }
}
