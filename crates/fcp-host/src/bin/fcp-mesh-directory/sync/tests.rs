use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::thread::{self, JoinHandle};

use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_mesh::invoke_route::MeshPeerConfig;
use fcp_mesh::peer_manifest::MESH_PEER_DIRECTORY_SCHEMA;

use super::*;
use super::disk::Installer;

struct Fixture {
    dir: tempfile::TempDir,
    owner: Ed25519SigningKey,
    local: Ed25519SigningKey,
    payload: MeshPeerDirectoryPayload,
}

impl Fixture {
    fn new() -> Self {
        let owner = Ed25519SigningKey::from_bytes(&[61; 32]).unwrap();
        let local = Ed25519SigningKey::from_bytes(&[62; 32]).unwrap();
        let peer = Ed25519SigningKey::from_bytes(&[63; 32]).unwrap();
        let now = unix_now_ms();
        Self {
            dir: tempfile::tempdir().unwrap(),
            payload: MeshPeerDirectoryPayload {
                schema_version: MESH_PEER_DIRECTORY_SCHEMA.to_owned(),
                mesh_id: "distribution-test".to_owned(),
                generation: 7,
                issued_at_ms: now - 1000,
                expires_at_ms: now + 300_000,
                peers: vec![
                    MeshPeerConfig {
                        node_id: "local".to_owned(),
                        endpoint: "http://127.0.0.1:19001".to_owned(),
                        public_key_hex: hex::encode(local.verifying_key().to_bytes()),
                    },
                    MeshPeerConfig {
                        node_id: "peer".to_owned(),
                        endpoint: "http://127.0.0.1:19002".to_owned(),
                        public_key_hex: hex::encode(peer.verifying_key().to_bytes()),
                    },
                ],
            },
            owner,
            local,
        }
    }

    fn trust(&self) -> Trust {
        Trust {
            owner: self.owner.verifying_key(),
            local: self.local.verifying_key(),
            mesh_id: "distribution-test".to_owned(),
            node: TailscaleNodeId::new("local"),
        }
    }

    fn path(&self) -> std::path::PathBuf {
        self.dir.path().join("membership.json")
    }

    fn wire(&self) -> String {
        serde_json::to_string(&SignedMeshPeerDirectory::sign(&self.owner, &self.payload).unwrap()).unwrap()
    }

    fn options(&self, url: &str) -> BTreeMap<String, OsString> {
        let owner = self.dir.path().join("owner.pub");
        let node = self.dir.path().join("node.pub");
        fs::write(&owner, hex::encode(self.owner.verifying_key().to_bytes())).unwrap();
        fs::write(&node, hex::encode(self.local.verifying_key().to_bytes())).unwrap();
        BTreeMap::from([
            ("--url".to_owned(), OsString::from(url)),
            ("--owner-public-key-file".to_owned(), owner.into_os_string()),
            ("--node-public-key-file".to_owned(), node.into_os_string()),
            ("--mesh-id".to_owned(), OsString::from("distribution-test")),
            ("--node-id".to_owned(), OsString::from("local")),
            ("--directory".to_owned(), self.path().into_os_string()),
        ])
    }
}

fn serve(respond: impl FnOnce(&mut TcpStream) + Send + 'static) -> (Url, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = source_url(&format!("http://{}/membership.json", listener.local_addr().unwrap())).unwrap();
    let thread = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "fetch never connected");
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("accept failed: {error}"),
            }
        };
        socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        socket.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut reader = BufReader::new(&mut socket);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert_eq!(line, "GET /membership.json HTTP/1.1\r\n");
        loop {
            line.clear();
            reader.read_line(&mut line).unwrap();
            assert!(!line.is_empty());
            if line == "\r\n" { break; }
            assert!(!line.to_ascii_lowercase().starts_with("authorization:"));
        }
        respond(&mut socket);
    });
    (url, thread)
}

fn serve_json(text: String) -> (Url, JoinHandle<()>) {
    serve(move |socket| {
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}", text.len(),
        );
        let _ = socket.write_all(response.as_bytes());
    })
}

#[test]
fn sync_command_fetches_authenticates_installs_and_reports_without_host_claims() {
    let fixture = Fixture::new();
    let wire = fixture.wire();
    let (url, server) = serve_json(wire.clone());
    let options = fixture.options(url.as_str());
    let mut args = vec![OsString::from("sync")];
    for (key, value) in options {
        args.push(OsString::from(key));
        args.push(value);
    }
    let mut output = Vec::new();
    let result = super::super::run(args, &mut output);
    server.join().unwrap();
    result.unwrap();
    assert_eq!(fs::read_to_string(fixture.path()).unwrap(), wire);
    assert_eq!(fs::metadata(fixture.path()).unwrap().permissions().mode() & 0o077, 0);
    let report: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(report["generation"], 7);
    assert_eq!(report["action"], "installed");
    assert_eq!(report["rollback_checked"], false);
    assert_eq!(report["host_activation_verified"], false);
    assert!(!String::from_utf8(output).unwrap().contains(&hex::encode(fixture.owner.to_bytes())));
}

#[test]
fn accepted_generation_survives_installer_restart_and_identical_fetch_does_not_replace_inode() {
    let mut fixture = Fixture::new();
    let first = fixture.wire();
    Installer::open(&fixture.path()).unwrap().install(&first, &fixture.trust()).unwrap();
    let ino = fs::metadata(fixture.path()).unwrap().ino();
    let report = Installer::open(&fixture.path()).unwrap().install(&first, &fixture.trust()).unwrap();
    assert_eq!(report.action, "unchanged");
    assert!(report.rollback_checked);
    assert_eq!(fs::metadata(fixture.path()).unwrap().ino(), ino);
    fixture.payload.generation += 1;
    fixture.payload.peers.truncate(1);
    let second = fixture.wire();
    let report = Installer::open(&fixture.path()).unwrap().install(&second, &fixture.trust()).unwrap();
    assert_eq!(report.previous_generation, Some(7));
    assert_eq!(report.member_count, 1);
    let error = Installer::open(&fixture.path()).unwrap().install(&first, &fixture.trust()).unwrap_err();
    assert!(error.to_string().contains("precedes accepted"));
    assert_eq!(fs::read_to_string(fixture.path()).unwrap(), second);
}

#[test]
fn forged_wrong_scope_wrong_key_expired_rollback_and_equivocating_sources_preserve_file() {
    for scenario in ["signature", "owner", "mesh", "key", "expired", "rollback", "reuse"] {
        let mut fixture = Fixture::new();
        let trust = fixture.trust();
        let first = fixture.wire();
        let mut installer = Installer::open(&fixture.path()).unwrap();
        installer.install(&first, &trust).unwrap();
        match scenario {
            "owner" => fixture.owner = Ed25519SigningKey::from_bytes(&[91; 32]).unwrap(),
            "mesh" => fixture.payload.mesh_id = "another-mesh".to_owned(),
            "key" => fixture.payload.peers[0].public_key_hex = hex::encode(fixture.owner.verifying_key().to_bytes()),
            "expired" => fixture.payload.expires_at_ms = unix_now_ms() - 1,
            "rollback" => fixture.payload.generation -= 1,
            "reuse" => fixture.payload.expires_at_ms += 1000,
            _ => {}
        }
        let mut candidate = fixture.wire();
        if scenario == "signature" {
            let mut signed: SignedMeshPeerDirectory = serde_json::from_str(&candidate).unwrap();
            signed.payload_json.push(' ');
            candidate = serde_json::to_string(&signed).unwrap();
        }
        assert!(installer.install(&candidate, &trust).is_err(), "{scenario} must fail");
        assert_eq!(fs::read_to_string(fixture.path()).unwrap(), first);
    }
}

#[test]
fn expired_installed_authority_still_prevents_rollback_but_allows_a_fresh_successor() {
    let mut fixture = Fixture::new();
    fixture.payload.expires_at_ms = unix_now_ms() - 1;
    let expired = fixture.wire();
    fs::write(fixture.path(), &expired).unwrap();
    let mut installer = Installer::open(&fixture.path()).unwrap();
    assert!(installer.install(&expired, &fixture.trust()).is_err());
    fixture.payload.generation = 6;
    fixture.payload.expires_at_ms = unix_now_ms() + 300_000;
    assert!(installer.install(&fixture.wire(), &fixture.trust()).is_err());
    assert_eq!(fs::read_to_string(fixture.path()).unwrap(), expired);
    fixture.payload.generation = 8;
    let report = installer.install(&fixture.wire(), &fixture.trust()).unwrap();
    assert_eq!(report.previous_generation, Some(7));
    assert_eq!(report.generation, 8);
}

#[test]
fn one_installer_owns_the_path_and_missing_initialized_sources_cannot_reset_generation() {
    let fixture = Fixture::new();
    let mut installer = Installer::open(&fixture.path()).unwrap();
    assert!(Installer::open(&fixture.path()).is_err());
    installer.install(&fixture.wire(), &fixture.trust()).unwrap();
    fs::rename(fixture.path(), fixture.dir.path().join("retained-source")).unwrap();
    drop(installer);
    let error = Installer::open(&fixture.path()).unwrap().install(&fixture.wire(), &fixture.trust()).unwrap_err();
    assert!(error.to_string().contains("refusing generation reset"));
    assert!(!fixture.path().exists());
}

#[test]
fn unsafe_destination_staging_and_lock_inodes_never_overwrite_unrelated_files() {
    for name in ["membership.json", "membership.json.sync-next", "membership.json.sync-lock"] {
        for hardlink in [false, true] {
            let fixture = Fixture::new();
            let protected = fixture.dir.path().join("protected");
            fs::write(&protected, "do-not-overwrite").unwrap();
            fs::set_permissions(&protected, fs::Permissions::from_mode(0o600)).unwrap();
            let alias = fixture.dir.path().join(name);
            if hardlink { fs::hard_link(&protected, &alias).unwrap(); }
            else { symlink(&protected, &alias).unwrap(); }
            let result = Installer::open(&fixture.path())
                .and_then(|mut installer| installer.install(&fixture.wire(), &fixture.trust()));
            assert!(result.is_err(), "{name}, hardlink={hardlink}");
            assert_eq!(fs::read_to_string(&protected).unwrap(), "do-not-overwrite");
        }
    }
}

#[test]
fn incomplete_reserved_staging_is_recovered_but_corrupt_source_or_marker_is_preserved() {
    let fixture = Fixture::new();
    let staging = fixture.dir.path().join("membership.json.sync-next");
    fs::write(&staging, "interrupted write").unwrap();
    fs::set_permissions(&staging, fs::Permissions::from_mode(0o600)).unwrap();
    Installer::open(&fixture.path()).unwrap().install(&fixture.wire(), &fixture.trust()).unwrap();
    assert!(!staging.exists());
    fs::write(fixture.path(), "{broken}").unwrap();
    assert!(Installer::open(&fixture.path()).unwrap().install(&fixture.wire(), &fixture.trust()).is_err());
    assert_eq!(fs::read_to_string(fixture.path()).unwrap(), "{broken}");
    let lock = fixture.dir.path().join("membership.json.sync-lock");
    fs::write(&lock, "broken marker").unwrap();
    assert!(Installer::open(&fixture.path()).is_err());
    assert_eq!(fs::read_to_string(&lock).unwrap(), "broken marker");
}

#[test]
fn source_urls_disallow_credentials_plaintext_nonloopback_and_redirect_targets() {
    for url in [
        "http://example.com/members", "http://localhost/members", "ftp://127.0.0.1/members",
        "https://user:SECRET@example.com/members", "https://example.com/members?SECRET",
        "https://example.com/members#SECRET", " https://example.com/members",
    ] {
        let error = source_url(url).unwrap_err().to_string();
        assert!(!error.contains("SECRET"));
    }
    assert!(source_url("https://example.com/members").is_ok());
    assert!(source_url("http://127.0.0.1:8000/members").is_ok());
    assert!(source_url("http://[::1]:8000/members").is_ok());
}

#[test]
fn http_refusals_redirects_encoding_and_oversized_content_never_supply_a_document() {
    for headers in [
        "302 Found\r\nLocation: https://example.com/SECRET\r\nContent-Length: 0".to_owned(),
        "503 Unavailable\r\nContent-Length: 0".to_owned(),
        "200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0".to_owned(),
        format!("200 OK\r\nContent-Length: {}", MAX_SIGNED_MESH_PEER_DIRECTORY_BYTES + 1),
    ] {
        let (url, server) = serve(move |socket| {
            let _ = write!(socket, "HTTP/1.1 {headers}\r\nConnection: close\r\n\r\n");
        });
        let error = fetch(&url, FETCH_TIMEOUT).unwrap_err().to_string();
        server.join().unwrap();
        assert!(!error.contains("SECRET"));
    }
}

#[test]
fn chunked_bodies_are_bounded_without_trusting_content_length() {
    let (url, server) = serve(|socket| {
        let body = "x".repeat(MAX_SIGNED_MESH_PEER_DIRECTORY_BYTES + 1);
        let _ = write!(socket, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n", body.len());
    });
    let error = fetch(&url, FETCH_TIMEOUT).unwrap_err().to_string();
    server.join().unwrap();
    assert!(error.contains("byte limit"));
}

#[test]
fn deadline_applies_while_waiting_for_body_after_successful_headers() {
    let (url, server) = serve(|socket| {
        write!(socket, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\n").unwrap();
        thread::sleep(Duration::from_secs(1));
        let _ = socket.write_all(b"x");
    });
    let result = fetch(&url, Duration::from_millis(250));
    server.join().unwrap();
    assert!(result.is_err(), "a successful status cannot disable the total deadline");
}
