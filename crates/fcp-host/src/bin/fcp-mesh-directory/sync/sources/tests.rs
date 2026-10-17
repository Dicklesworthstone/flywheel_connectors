use std::cell::Cell;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::thread;

use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_mesh::invoke_route::MeshPeerConfig;
use fcp_mesh::peer_manifest::MESH_PEER_DIRECTORY_SCHEMA;

use super::*;

struct Fixture {
    owner: Ed25519SigningKey,
    trust: Trust,
    payload: MeshPeerDirectoryPayload,
}

impl Fixture {
    fn new() -> Self {
        let owner = Ed25519SigningKey::from_bytes(&[81; 32]).unwrap();
        let local = Ed25519SigningKey::from_bytes(&[82; 32]).unwrap();
        let now = unix_now_ms();
        Self {
            trust: Trust {
                owner: owner.verifying_key(),
                local: local.verifying_key(),
                mesh_id: "publisher-selection".to_owned(),
                node: TailscaleNodeId::new("local"),
            },
            payload: MeshPeerDirectoryPayload {
                schema_version: MESH_PEER_DIRECTORY_SCHEMA.to_owned(),
                mesh_id: "publisher-selection".to_owned(),
                generation: 7,
                issued_at_ms: now.saturating_sub(10_000),
                expires_at_ms: now + 600_000,
                peers: vec![MeshPeerConfig {
                    node_id: "local".to_owned(),
                    endpoint: "http://127.0.0.1:19001".to_owned(),
                    public_key_hex: hex::encode(local.verifying_key().to_bytes()),
                }],
            },
            owner,
        }
    }

    fn wire(&self) -> String {
        serde_json::to_string(&SignedMeshPeerDirectory::sign(&self.owner, &self.payload).unwrap())
            .unwrap()
    }

    fn choose(&self, responses: Vec<SyncResult<String>>) -> SyncResult<String> {
        let urls: Vec<_> = (0..responses.len())
            .map(|index| format!("https://publisher-{index}.example/members"))
            .collect();
        let sources = SourceSet::parse(&serde_json::to_string(&urls).unwrap()).unwrap();
        let mut responses = responses.into_iter();
        sources.fetch_with(&self.trust, FETCH_TIMEOUT, |_, _| responses.next().unwrap())
    }
}

#[test]
fn source_sets_validate_all_urls_before_network_and_bound_their_count() {
    assert_eq!(
        SourceSet::parse("https://publisher.example/members")
            .unwrap()
            .urls
            .len(),
        1
    );
    assert_eq!(
        SourceSet::parse(r#"["https://a.example/a","https://b.example/b"]"#)
            .unwrap()
            .urls
            .len(),
        2
    );
    for value in [
        "[]",
        "[null]",
        "[42]",
        "[true]",
        "[\"https://a.example\",",
        r#"["https://a.example","http://remote.example"]"#,
        r#"["https://a.example","https://a.example/"]"#,
        r#"["https://a.example","https://b.example","https://c.example","https://d.example","https://e.example"]"#,
    ] {
        assert!(SourceSet::parse(value).is_err(), "{value}");
    }
    assert!(SourceSet::parse(&"x".repeat(MAX_SOURCE_ARGUMENT_BYTES + 1)).is_err());
    let options = BTreeMap::from([(
        "--url".to_owned(),
        OsString::from(r#"["https://a.example","https://user:secret@b.example"]"#),
    )]);
    let error = SourceSet::from_options(&options).err().unwrap();
    assert!(!error.contains("secret"));
    assert!(!error.contains("b.example"));
}

#[test]
fn highest_authenticated_generation_wins_independently_of_publisher_order() {
    let mut fixture = Fixture::new();
    let old = fixture.wire();
    fixture.payload.generation = 8;
    let current = fixture.wire();
    for responses in [
        vec![Ok(old.clone()), Ok(current.clone())],
        vec![Ok(current.clone()), Ok(old.clone())],
    ] {
        assert_eq!(fixture.choose(responses).unwrap(), current);
    }
}

#[test]
fn unreachable_publisher_does_not_hide_a_healthy_mirror() {
    let fixture = Fixture::new();
    let current = fixture.wire();
    for responses in [
        vec![
            Err(SyncError::Remote("unreachable".to_owned())),
            Ok(current.clone()),
        ],
        vec![
            Ok(current.clone()),
            Err(SyncError::Remote("unreachable".to_owned())),
        ],
    ] {
        assert_eq!(fixture.choose(responses).unwrap(), current);
    }
    assert!(
        fixture
            .choose(vec![Err(SyncError::Remote(
                "private-upstream-body".to_owned()
            ))])
            .unwrap_err()
            .to_string()
            .contains("no membership source")
    );
}

#[test]
fn unauthenticated_high_generations_and_other_meshes_cannot_veto_valid_membership() {
    let mut fixture = Fixture::new();
    let current = fixture.wire();
    fixture.payload.generation = u64::MAX;
    let other_owner = Ed25519SigningKey::from_bytes(&[99; 32]).unwrap();
    let untrusted = serde_json::to_string(
        &SignedMeshPeerDirectory::sign(&other_owner, &fixture.payload).unwrap(),
    )
    .unwrap();
    let mut forged = SignedMeshPeerDirectory::sign(&fixture.owner, &fixture.payload).unwrap();
    forged.payload_json.push(' ');
    let forged = serde_json::to_string(&forged).unwrap();
    fixture.payload.mesh_id = "another-mesh".to_owned();
    let other_mesh = fixture.wire();
    for rejected in [untrusted, forged, other_mesh, "[]".to_owned()] {
        assert_eq!(
            fixture
                .choose(vec![Ok(rejected), Ok(current.clone())])
                .unwrap(),
            current
        );
    }
}

#[test]
fn same_generation_equivocation_refuses_selection_without_touching_installed_history() {
    let mut fixture = Fixture::new();
    let current = fixture.wire();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("installed.json");
    let mut installer = disk::Installer::open(&path).unwrap();
    installer.install(&current, &fixture.trust).unwrap();
    fixture.payload.expires_at_ms += 1000;
    let conflict = fixture.wire();
    let error = fixture
        .choose(vec![Ok(current.clone()), Ok(conflict)])
        .unwrap_err()
        .to_string();
    assert!(error.contains("equivocate"));
    assert_eq!(fs::read_to_string(&path).unwrap(), current);
    assert_eq!(
        fixture
            .choose(vec![Ok(current.clone()), Ok(current.clone())])
            .unwrap(),
        current
    );
}

#[test]
fn a_newer_authenticated_local_revocation_prevents_fallback_to_an_older_grant() {
    let mut fixture = Fixture::new();
    let old = fixture.wire();
    fixture.payload.generation = 8;
    fixture.payload.peers[0].node_id = "different-node".to_owned();
    let revoked = fixture.wire();
    for responses in [
        vec![Ok(old.clone()), Ok(revoked.clone())],
        vec![Ok(revoked.clone()), Ok(old.clone())],
    ] {
        assert!(
            fixture
                .choose(responses)
                .unwrap_err()
                .to_string()
                .contains("does not authorize")
        );
    }
}

#[test]
fn newer_expired_or_future_authority_cannot_be_hidden_by_a_stale_mirror() {
    let mut fixture = Fixture::new();
    let old = fixture.wire();
    fixture.payload.generation = 8;
    fixture.payload.expires_at_ms = unix_now_ms().saturating_sub(1);
    let expired = fixture.wire();
    fixture.payload.issued_at_ms = unix_now_ms() + 120_000;
    fixture.payload.expires_at_ms = fixture.payload.issued_at_ms + 600_000;
    let future = fixture.wire();
    for rejected in [expired, future] {
        assert!(
            fixture
                .choose(vec![Ok(old.clone()), Ok(rejected)])
                .unwrap_err()
                .to_string()
                .contains("validity window")
        );
    }
}

#[test]
fn an_older_refused_generation_does_not_override_a_newer_valid_renewal() {
    let mut fixture = Fixture::new();
    let current = fixture.wire();
    fixture.payload.generation = 6;
    fixture.payload.peers[0].node_id = "different-node".to_owned();
    let old = fixture.wire();
    assert_eq!(
        fixture.choose(vec![Ok(old), Ok(current.clone())]).unwrap(),
        current
    );
}

#[test]
fn each_remaining_source_gets_a_share_of_the_total_deadline() {
    let fixture = Fixture::new();
    let sources = SourceSet::parse(
        r#"["https://a.example","https://b.example","https://c.example","https://d.example"]"#,
    )
    .unwrap();
    let mut allowances = Vec::new();
    sources
        .fetch_with(&fixture.trust, Duration::from_secs(4), |_, timeout| {
            allowances.push(timeout);
            assert!(!timeout.is_zero());
            Ok(fixture.wire())
        })
        .unwrap();
    assert_eq!(allowances.len(), 4);
    for (index, allowance) in allowances.into_iter().enumerate() {
        assert!(allowance <= Duration::from_secs(4) / u32::try_from(4 - index).unwrap());
    }
    let called = Cell::new(false);
    assert!(
        sources
            .fetch_with(&fixture.trust, Duration::ZERO, |_, _| {
                called.set(true);
                Ok(fixture.wire())
            })
            .is_err()
    );
    assert!(!called.get());
}

#[test]
fn local_runtime_failure_stops_selection_instead_of_claiming_remote_recovery() {
    let fixture = Fixture::new();
    let error = fixture
        .choose(vec![
            Ok(fixture.wire()),
            Err(SyncError::Local("runtime unavailable")),
        ])
        .unwrap_err();
    assert!(matches!(error, SyncError::Local("runtime unavailable")));
}

fn serve_once(status: u16, body: String) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}/members", listener.local_addr().unwrap());
    let worker = thread::spawn(move || {
        let started = Instant::now();
        let mut socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(
                        started.elapsed() < Duration::from_secs(10),
                        "publisher never contacted"
                    );
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("loopback accept: {error}"),
            }
        };
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        {
            let mut reader = BufReader::new(&mut socket);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert_eq!(line, "GET /members HTTP/1.1\r\n");
            let mut total = line.len();
            loop {
                line.clear();
                reader.read_line(&mut line).unwrap();
                total += line.len();
                assert!(!line.is_empty() && total < 8192);
                if line == "\r\n" {
                    break;
                }
                let name = line.split_once(':').unwrap().0;
                assert!(!name.eq_ignore_ascii_case("authorization"));
                assert!(!name.eq_ignore_ascii_case("cookie"));
                assert!(!name.eq_ignore_ascii_case("proxy-authorization"));
            }
        }
        let _ = write!(
            socket,
            "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len(),
        );
    });
    (url, worker)
}

#[test]
fn real_http_mirrors_install_the_newest_signed_document_and_reject_later_rollback() {
    let mut fixture = Fixture::new();
    let old = fixture.wire();
    fixture.payload.generation = 8;
    let current = fixture.wire();
    let servers = [
        serve_once(503, "private-publisher-error".to_owned()),
        serve_once(200, old.clone()),
        serve_once(200, current.clone()),
    ];
    let urls: Vec<_> = servers.iter().map(|(url, _)| url).collect();
    let sources = SourceSet::parse(&serde_json::to_string(&urls).unwrap()).unwrap();
    let result = sources.fetch(&fixture.trust, FETCH_TIMEOUT);
    for (_, server) in servers {
        server.join().unwrap();
    }
    let chosen = result.unwrap();
    assert_eq!(chosen, current);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("members.json");
    let mut installer = disk::Installer::open(&path).unwrap();
    installer.install(&old, &fixture.trust).unwrap();
    let report = installer.install(&chosen, &fixture.trust).unwrap();
    assert_eq!(report.generation, 8);
    assert_eq!(report.previous_generation, Some(7));
    assert!(!report.host_activation_verified);
    assert!(installer.install(&old, &fixture.trust).is_err());
    assert_eq!(fs::read_to_string(path).unwrap(), current);
}
