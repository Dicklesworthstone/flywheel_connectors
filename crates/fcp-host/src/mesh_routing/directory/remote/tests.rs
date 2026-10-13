use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Instant;

use super::*;

fn descriptor(endpoint: &str) -> String {
    serde_json::json!({
        "schema_version": SOURCE_SCHEMA,
        "directory_url": endpoint,
    })
    .to_string()
}

fn envelope_bytes() -> Vec<u8> {
    // Deliberately not authenticated: the source reader is not the verifier.
    // Integration tests below exercise the actual owner-verification boundary.
    br#"{"signer_public_key_hex":"00","payload_json":"{}","signature_hex":"00"}"#.to_vec()
}

#[derive(Clone)]
struct Reply {
    status: u16,
    body: Vec<u8>,
    chunked: bool,
    declared_length: Option<usize>,
}

impl Reply {
    fn ok(body: Vec<u8>) -> Self {
        Self { status: 200, body, chunked: false, declared_length: None }
    }
}

/// Real loopback HTTP, with no provider credentials or production endpoints.
/// The server and each socket have bounded shutdown/I/O behavior.
struct Server {
    endpoint: String,
    reply: Arc<Mutex<Reply>>,
    requests: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Server {
    fn new(reply: Reply) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}/membership.json", listener.local_addr().unwrap());
        let reply = Arc::new(Mutex::new(reply));
        let requests = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let worker_reply = Arc::clone(&reply);
        let worker_requests = Arc::clone(&requests);
        let worker_stop = Arc::clone(&stop);
        let worker = std::thread::spawn(move || {
            while !worker_stop.load(Ordering::Acquire) {
                let mut socket = match listener.accept() {
                    Ok((socket, _)) => socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => panic!("loopback accept failed: {error}"),
                };
                socket.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
                socket.set_write_timeout(Some(Duration::from_secs(1))).unwrap();
                {
                    let mut reader = BufReader::new(&mut socket);
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    assert_eq!(line, "GET /membership.json HTTP/1.1\r\n");
                    let mut total = line.len();
                    loop {
                        line.clear();
                        reader.read_line(&mut line).unwrap();
                        assert!(!line.is_empty(), "EOF in source request headers");
                        total += line.len();
                        assert!(total < 8192);
                        if line == "\r\n" {
                            break;
                        }
                        let name = line.split_once(':').unwrap().0;
                        assert!(!name.eq_ignore_ascii_case("authorization"));
                        assert!(!name.eq_ignore_ascii_case("cookie"));
                        assert!(!name.eq_ignore_ascii_case("proxy-authorization"));
                    }
                }
                worker_requests.fetch_add(1, Ordering::Release);
                let reply = worker_reply.lock().unwrap().clone();
                let framing = if reply.chunked {
                    "Transfer-Encoding: chunked\r\n".to_owned()
                } else {
                    format!("Content-Length: {}\r\n", reply.declared_length.unwrap_or(reply.body.len()))
                };
                let headers = format!(
                    "HTTP/1.1 {} Test\r\n{}Content-Type: application/json\r\nLocation: /must-not-follow\r\nConnection: close\r\n\r\n",
                    reply.status, framing,
                );
                if socket.write_all(headers.as_bytes()).is_err() {
                    continue;
                }
                // Size/status rejection can close the client without reading.
                if reply.chunked {
                    for chunk in reply.body.chunks(4096) {
                        if write!(socket, "{:x}\r\n", chunk.len()).is_err()
                            || socket.write_all(chunk).is_err()
                            || socket.write_all(b"\r\n").is_err()
                        {
                            break;
                        }
                    }
                    let _ = socket.write_all(b"0\r\n\r\n");
                } else {
                    let _ = socket.write_all(&reply.body);
                }
            }
        });
        Self { endpoint, reply, requests, stop, worker: Some(worker) }
    }

    fn set(&self, reply: Reply) {
        *self.reply.lock().unwrap() = reply;
    }

    fn load(&self) -> HostResult<String> {
        resolve_file_source(descriptor(&self.endpoint))
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            if !std::thread::panicking() {
                result.expect("loopback source server failed");
            }
        }
    }
}

#[test]
fn ordinary_source_files_preserve_their_exact_bytes() {
    for json in [" []\n", "not json", "{\"payload_json\":\"opaque signed bytes\"}"] {
        assert_eq!(resolve_file_source(json.to_owned()).unwrap(), json);
    }
}

#[test]
fn descriptors_require_explicit_version_and_unambiguous_fields() {
    for json in [
        r#"{"directory_url":"https://example.com/directory"}"#,
        r#"{"schema_version":"fcp.mesh.directory-source.v2","directory_url":"https://example.com/directory"}"#,
        r#"{"schema_version":"fcp.mesh.directory-source.v1","directory_url":"https://example.com/directory","fallback":[]}"#,
        r#"{"schema_version":"fcp.mesh.directory-source.v1","directory_url":"https://example.com/a","directory_url":"https://example.com/b"}"#,
        r#"{"schema_version":"fcp.mesh.directory-source.v1","directory_url":null}"#,
    ] {
        assert!(source_endpoint(json).is_err());
    }
    let oversized = format!("{}{}", descriptor("https://example.com/directory"), " ".repeat(MAX_SOURCE_BYTES));
    assert!(source_endpoint(&oversized).is_err());
}

#[test]
fn endpoints_require_confidentiality_without_ambient_credentials() {
    for endpoint in [
        "https://directory.example/membership.json",
        "https://100.64.0.1:8443/membership.json",
        "http://127.0.0.1:8080/membership.json",
        "http://[::1]:8080/membership.json",
    ] {
        assert!(validate_endpoint(endpoint).is_ok(), "{endpoint}");
    }
    for endpoint in [
        "", "http://directory.example/membership.json", "http://localhost:8080/a",
        "http://127.0.0.1.example/a", "http://100.64.0.1/a", "http://0.0.0.0/a",
        "https://user:secret@example.com/a", "https://example.com/a?token=secret",
        "https://example.com/a#secret", "https://example.com:0/a",
        " https://example.com/a", "https://example.com/a\nb", "file:///etc/passwd",
    ] {
        let error = validate_endpoint(endpoint).unwrap_err().to_string();
        assert!(!error.contains("secret"));
    }
}

#[test]
fn remote_reader_preserves_signed_bytes_but_never_accepts_raw_or_recursive_sources() {
    let expected = envelope_bytes();
    let server = Server::new(Reply::ok(expected.clone()));
    assert_eq!(server.load().unwrap().as_bytes(), expected);
    for body in [
        b"[]".to_vec(), b"{}".to_vec(), b"not-json-secret".to_vec(),
        descriptor(&server.endpoint).into_bytes(), vec![0xff],
    ] {
        server.set(Reply::ok(body));
        let error = server.load().unwrap_err().to_string();
        assert!(!error.contains("not-json-secret"));
        assert!(!error.contains(&server.endpoint));
    }
    assert_eq!(server.requests.load(Ordering::Acquire), 6);
}

#[test]
fn redirects_partial_content_and_unsigned_refusals_never_become_membership() {
    let server = Server::new(Reply::ok(envelope_bytes()));
    for status in [204, 206, 301, 302, 307, 308, 304, 401, 403, 404, 429, 500, 503] {
        server.set(Reply { status, ..Reply::ok(b"private-upstream-body".to_vec()) });
        let before = server.requests.load(Ordering::Acquire);
        let error = server.load().unwrap_err().to_string();
        assert!(error.contains(&status.to_string()));
        assert!(!error.contains("private-upstream-body"));
        assert_eq!(server.requests.load(Ordering::Acquire), before + 1);
    }
}

#[test]
fn source_body_limits_cover_content_length_chunked_and_truncated_responses() {
    let server = Server::new(Reply {
        declared_length: Some(MAX_SIGNED_MESH_PEER_DIRECTORY_BYTES + 1),
        ..Reply::ok(Vec::new())
    });
    assert!(server.load().unwrap_err().to_string().contains("byte limit"));
    server.set(Reply {
        chunked: true,
        ..Reply::ok(vec![b' '; MAX_SIGNED_MESH_PEER_DIRECTORY_BYTES + 1])
    });
    assert!(server.load().unwrap_err().to_string().contains("byte limit"));
    server.set(Reply { declared_length: Some(1000), ..Reply::ok(envelope_bytes()) });
    assert!(server.load().is_err());
    assert!(decode_document(vec![b' '; MAX_SIGNED_MESH_PEER_DIRECTORY_BYTES + 1]).is_err());
}

#[cfg(unix)]
mod live {
    use fcp_core::TailscaleNodeId;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_mesh::invoke_route::{MeshForwardBody, MeshForwardEnvelope, MeshForwardError, MeshPeerConfig};
    use fcp_mesh::peer_manifest::{MESH_PEER_DIRECTORY_SCHEMA, MeshPeerDirectoryPayload};

    use crate::mesh_routing::{
        MESH_DIRECTORY_ID_ENV, MESH_DIRECTORY_OWNER_KEYS_ENV, MESH_DIRECTORY_STATE_ENV,
        MESH_NODE_ID_ENV, MESH_PEERS_FILE_ENV, MESH_REPLAY_JOURNAL_ENV,
        MESH_SIGNING_KEY_FILE_ENV, MeshRouter, unix_now_ms,
    };
    use super::*;
    use super::super::super::{private_options, read_checkpoint};

    struct Fixture {
        dir: tempfile::TempDir,
        owner: Ed25519SigningKey,
        local: Ed25519SigningKey,
        peer: Ed25519SigningKey,
        payload: MeshPeerDirectoryPayload,
    }

    impl Fixture {
        fn new() -> Self {
            let owner = Ed25519SigningKey::from_bytes(&[61; 32]).unwrap();
            let local = Ed25519SigningKey::from_bytes(&[62; 32]).unwrap();
            let peer = Ed25519SigningKey::from_bytes(&[63; 32]).unwrap();
            let now = unix_now_ms();
            let payload = MeshPeerDirectoryPayload {
                schema_version: MESH_PEER_DIRECTORY_SCHEMA.to_owned(),
                mesh_id: "distributed-test".to_owned(),
                generation: 1,
                issued_at_ms: now.saturating_sub(1000),
                expires_at_ms: now + 600_000,
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
            };
            Self { dir: tempfile::tempdir().unwrap(), owner, local, peer, payload }
        }

        fn signed(&self) -> Vec<u8> {
            serde_json::to_vec(&SignedMeshPeerDirectory::sign(&self.owner, &self.payload).unwrap()).unwrap()
        }

        fn start(&self, server: &Server, signed_mode: bool) -> HostResult<MeshRouter> {
            let key_path = self.dir.path().join("node.key");
            let mut file = private_options().create(true).truncate(true).open(&key_path).unwrap();
            file.write_all(hex::encode(self.local.to_bytes()).as_bytes()).unwrap();
            let source_path = self.dir.path().join("source.json");
            std::fs::write(&source_path, descriptor(&server.endpoint)).unwrap();
            MeshRouter::from_lookup(|name| match name {
                MESH_NODE_ID_ENV => Some("local".to_owned()),
                MESH_SIGNING_KEY_FILE_ENV => Some(key_path.display().to_string()),
                MESH_PEERS_FILE_ENV => Some(source_path.display().to_string()),
                MESH_REPLAY_JOURNAL_ENV => Some(self.dir.path().join("replay").display().to_string()),
                MESH_DIRECTORY_ID_ENV if signed_mode => Some(self.payload.mesh_id.clone()),
                MESH_DIRECTORY_OWNER_KEYS_ENV if signed_mode => Some(serde_json::json!([
                    hex::encode(self.owner.verifying_key().to_bytes())
                ]).to_string()),
                MESH_DIRECTORY_STATE_ENV if signed_mode => Some(self.dir.path().join("membership").display().to_string()),
                _ => None,
            }).map(|router| router.expect("mesh configured"))
        }

        fn generation(&self) -> Option<u64> {
            read_checkpoint(&self.dir.path().join("membership")).ok().map(|state| state.generation)
        }

        fn envelope(&self, key: &Ed25519SigningKey) -> MeshForwardEnvelope {
            MeshForwardEnvelope::sign(
                key, TailscaleNodeId::new("peer"), TailscaleNodeId::new("local"),
                unix_now_ms(), MeshForwardBody::Introspect {
                    connector_id: "fcp.test:utility:1.0.0".to_owned(),
                },
            ).unwrap()
        }
    }

    fn wait_until(mut ready: impl FnMut() -> bool) {
        let start = Instant::now();
        while !ready() {
            assert!(start.elapsed() < Duration::from_secs(10), "remote membership did not converge");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn distributed_bootstrap_requires_independent_owner_authority() {
        let fixture = Fixture::new();
        let server = Server::new(Reply::ok(fixture.signed()));
        assert!(fixture.start(&server, false).is_err());
        assert_eq!(fixture.generation(), None);
        let other = Ed25519SigningKey::from_bytes(&[99; 32]).unwrap();
        server.set(Reply::ok(serde_json::to_vec(
            &SignedMeshPeerDirectory::sign(&other, &fixture.payload).unwrap(),
        ).unwrap()));
        assert!(fixture.start(&server, true).is_err());
        assert_eq!(fixture.generation(), None);
        server.set(Reply::ok(fixture.signed()));
        let router = fixture.start(&server, true).unwrap();
        assert!(router.has_owner_signed_membership());
        assert!(router.has_durable_replay());
        assert_eq!(router.directory().len(), 1);
        assert_eq!(fixture.generation(), Some(1));
    }

    #[test]
    fn remote_rotation_and_revocation_reach_live_router_without_erasing_replay_history() {
        let mut fixture = Fixture::new();
        let server = Server::new(Reply::ok(fixture.signed()));
        let router = fixture.start(&server, true).unwrap();
        let original_peers = fixture.payload.peers.clone();
        let accepted = fixture.envelope(&fixture.peer);
        router.accept_inbound(&accepted).unwrap();
        let new_key = Ed25519SigningKey::from_bytes(&[64; 32]).unwrap();
        fixture.payload.generation = 2;
        fixture.payload.peers[1].public_key_hex = hex::encode(new_key.verifying_key().to_bytes());
        server.set(Reply::ok(fixture.signed()));
        wait_until(|| fixture.generation() == Some(2)
            && router.directory().peer(&TailscaleNodeId::new("peer")).is_some_and(|peer| {
                peer.verifying_key.to_bytes() == new_key.verifying_key().to_bytes()
            }));
        assert!(matches!(router.accept_inbound(&fixture.envelope(&fixture.peer)), Err(MeshForwardError::SignatureInvalid { .. })));
        router.accept_inbound(&fixture.envelope(&new_key)).unwrap();
        fixture.payload.generation = 3;
        fixture.payload.peers.truncate(1);
        server.set(Reply::ok(fixture.signed()));
        wait_until(|| fixture.generation() == Some(3) && router.directory().is_empty());
        assert!(matches!(router.accept_inbound(&fixture.envelope(&new_key)), Err(MeshForwardError::UnknownPeer(_))));
        fixture.payload.generation = 4;
        fixture.payload.peers = original_peers;
        server.set(Reply::ok(fixture.signed()));
        wait_until(|| fixture.generation() == Some(4) && router.directory().len() == 1);
        assert!(matches!(router.accept_inbound(&accepted), Err(MeshForwardError::Replayed { .. })));
    }

    #[test]
    fn publisher_failure_and_rollback_fence_work_until_a_valid_successor_returns() {
        let mut fixture = Fixture::new();
        let old = fixture.signed();
        let server = Server::new(Reply::ok(old.clone()));
        let router = fixture.start(&server, true).unwrap();
        fixture.payload.generation = 2;
        fixture.payload.expires_at_ms += 60_000;
        let current = fixture.signed();
        server.set(Reply::ok(current.clone()));
        wait_until(|| fixture.generation() == Some(2) && router.directory().len() == 1);
        server.set(Reply::ok(old));
        wait_until(|| router.directory().is_empty());
        assert_eq!(fixture.generation(), Some(2));
        server.set(Reply::ok(current.clone()));
        wait_until(|| router.directory().len() == 1);
        server.set(Reply { status: 503, ..Reply::ok(b"private-publisher-error".to_vec()) });
        wait_until(|| router.directory().is_empty());
        assert_eq!(fixture.generation(), Some(2));
        server.set(Reply::ok(current));
        wait_until(|| router.directory().len() == 1);
        drop(router);
        // Restart must retain the durable high-water mark as well.
        fixture.payload.generation = 1;
        server.set(Reply::ok(fixture.signed()));
        assert!(fixture.start(&server, true).is_err());
        assert_eq!(fixture.generation(), Some(2));
    }
}
