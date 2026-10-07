//! Owner-authorized membership exercised through the production startup path.
//! Filesystem coverage is Unix-only, matching the persistence guarantee.

#![cfg(unix)]

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use fcp_core::TailscaleNodeId;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_host::mesh_routing::{
    MESH_DIRECTORY_ID_ENV, MESH_DIRECTORY_OWNER_KEYS_ENV, MESH_DIRECTORY_STATE_ENV,
    MESH_NODE_ID_ENV, MESH_PEERS_ENV, MESH_PEERS_FILE_ENV, MESH_REPLAY_JOURNAL_ENV,
    MESH_SIGNING_KEY_FILE_ENV, MeshRouter, unix_now_ms,
};
use fcp_mesh::invoke_route::{MeshForwardBody, MeshForwardEnvelope, MeshForwardError, MeshPeerConfig};
use fcp_mesh::peer_manifest::{
    MAX_SIGNED_MESH_PEER_DIRECTORY_BYTES, MESH_PEER_DIRECTORY_SCHEMA,
    MeshPeerDirectoryCheckpoint, MeshPeerDirectoryPayload, SignedMeshPeerDirectory,
};

struct Fixture {
    dir: tempfile::TempDir,
    owner: Ed25519SigningKey,
    peer: Ed25519SigningKey,
    payload: MeshPeerDirectoryPayload,
    env: BTreeMap<String, String>,
}

fn private_write(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let owner = Ed25519SigningKey::from_bytes(&[11; 32]).unwrap();
        let local = Ed25519SigningKey::from_bytes(&[12; 32]).unwrap();
        let peer = Ed25519SigningKey::from_bytes(&[13; 32]).unwrap();
        let now = unix_now_ms();
        let payload = MeshPeerDirectoryPayload {
            schema_version: MESH_PEER_DIRECTORY_SCHEMA.to_owned(),
            mesh_id: "host-membership-test".to_owned(),
            generation: 7,
            issued_at_ms: now.saturating_sub(1000),
            expires_at_ms: now + 300_000,
            peers: vec![
                MeshPeerConfig {
                    node_id: "node-local".to_owned(),
                    endpoint: "http://127.0.0.1:19001".to_owned(),
                    public_key_hex: hex::encode(local.verifying_key().to_bytes()),
                },
                MeshPeerConfig {
                    node_id: "node-peer".to_owned(),
                    endpoint: "http://127.0.0.1:19002".to_owned(),
                    public_key_hex: hex::encode(peer.verifying_key().to_bytes()),
                },
            ],
        };
        let key_path = dir.path().join("local.key");
        private_write(&key_path, hex::encode(local.to_bytes()).as_bytes());
        let env = BTreeMap::from([
            (MESH_NODE_ID_ENV.to_owned(), "node-local".to_owned()),
            (MESH_SIGNING_KEY_FILE_ENV.to_owned(), key_path.display().to_string()),
            (MESH_REPLAY_JOURNAL_ENV.to_owned(), dir.path().join("replay").display().to_string()),
            (MESH_DIRECTORY_ID_ENV.to_owned(), payload.mesh_id.clone()),
            (MESH_DIRECTORY_OWNER_KEYS_ENV.to_owned(), serde_json::json!([
                hex::encode(owner.verifying_key().to_bytes())
            ]).to_string()),
            (MESH_DIRECTORY_STATE_ENV.to_owned(), dir.path().join("membership").display().to_string()),
        ]);
        let mut fixture = Self { dir, owner, peer, payload, env };
        fixture.sign();
        fixture
    }

    fn sign(&mut self) {
        let document = SignedMeshPeerDirectory::sign(&self.owner, &self.payload).unwrap();
        self.env.insert(MESH_PEERS_ENV.to_owned(), serde_json::to_string(&document).unwrap());
    }

    fn start(&self) -> fcp_host::HostResult<Option<MeshRouter>> {
        MeshRouter::from_lookup(|name| self.env.get(name).cloned())
    }

    fn state_path(&self) -> PathBuf {
        PathBuf::from(&self.env[MESH_DIRECTORY_STATE_ENV])
    }

    fn checkpoint(&self) -> MeshPeerDirectoryCheckpoint {
        let outer: serde_json::Value = serde_json::from_slice(&fs::read(self.state_path()).unwrap()).unwrap();
        serde_json::from_str(outer["checkpoint_json"].as_str().unwrap()).unwrap()
    }

    fn request(&self) -> MeshForwardEnvelope {
        MeshForwardEnvelope::sign(
            &self.peer,
            TailscaleNodeId::try_new("node-peer").unwrap(),
            TailscaleNodeId::try_new("node-local").unwrap(),
            unix_now_ms(),
            MeshForwardBody::Introspect { connector_id: "fcp.test:utility:1.0.0".to_owned() },
        ).unwrap()
    }

    fn assert_authentication_refused_without_state(&self) {
        assert!(self.start().is_err());
        assert!(!self.state_path().exists());
        assert!(!self.dir.path().join("membership.lock").exists());
        assert!(!self.dir.path().join("replay").exists());
    }
}

#[test]
fn signed_startup_binds_membership_and_preserves_nonce_replay_across_restart() {
    let fixture = Fixture::new();
    let request = fixture.request();
    let router = fixture.start().unwrap().unwrap();
    assert!(router.has_owner_signed_membership());
    assert!(router.has_durable_replay());
    assert_eq!(router.directory().len(), 1);
    assert_eq!(router.local_node().as_str(), "node-local");
    router.accept_inbound(&request).unwrap();
    drop(router);
    let router = fixture.start().unwrap().unwrap();
    assert!(matches!(router.accept_inbound(&request), Err(MeshForwardError::Replayed { .. })));
    let checkpoint = fixture.checkpoint();
    assert_eq!(checkpoint.generation, 7);
    assert_eq!(checkpoint.mesh_id, "host-membership-test");
    assert_eq!(checkpoint.local_node, "node-local");
    assert_eq!(fs::metadata(fixture.state_path()).unwrap().permissions().mode() & 0o077, 0);
}

#[test]
fn higher_generation_removes_peer_and_restart_cannot_restore_old_membership() {
    let mut fixture = Fixture::new();
    drop(fixture.start().unwrap().unwrap());
    let original = fixture.payload.clone();
    fixture.payload.generation += 1;
    fixture.payload.peers.truncate(1);
    fixture.sign();
    let router = fixture.start().unwrap().unwrap();
    assert_eq!(router.directory().len(), 0);
    assert!(matches!(router.accept_inbound(&fixture.request()), Err(MeshForwardError::UnknownPeer(_))));
    drop(router);
    let accepted_bytes = fs::read(fixture.state_path()).unwrap();
    fixture.payload = original;
    fixture.sign();
    assert!(fixture.start().unwrap_err().to_string().contains("precedes accepted generation"));
    assert_eq!(fs::read(fixture.state_path()).unwrap(), accepted_bytes);
}

#[test]
fn same_generation_equivocation_preserves_checkpoint() {
    let mut fixture = Fixture::new();
    drop(fixture.start().unwrap().unwrap());
    let accepted_bytes = fs::read(fixture.state_path()).unwrap();
    fixture.payload.expires_at_ms += 1000;
    fixture.sign();
    assert!(fixture.start().unwrap_err().to_string().contains("reused"));
    assert_eq!(fs::read(fixture.state_path()).unwrap(), accepted_bytes);
}

#[test]
fn embedded_signer_cannot_appoint_itself_owner() {
    let mut fixture = Fixture::new();
    fixture.owner = Ed25519SigningKey::from_bytes(&[90; 32]).unwrap();
    fixture.sign();
    fixture.assert_authentication_refused_without_state();
}

#[test]
fn bad_signature_wrong_mesh_wrong_local_key_and_expired_document_fail_before_storage() {
    for scenario in ["signature", "mesh", "local_key", "expiration"] {
        let mut fixture = Fixture::new();
        match scenario {
            "signature" => {
                let mut signed: SignedMeshPeerDirectory = serde_json::from_str(&fixture.env[MESH_PEERS_ENV]).unwrap();
                signed.payload_json.push(' ');
                fixture.env.insert(MESH_PEERS_ENV.to_owned(), serde_json::to_string(&signed).unwrap());
            }
            "mesh" => {
                fixture.env.insert(MESH_DIRECTORY_ID_ENV.to_owned(), "other-mesh".to_owned());
            }
            "local_key" => {
                fixture.payload.peers[0].public_key_hex = hex::encode(fixture.peer.verifying_key().to_bytes());
                fixture.sign();
            }
            _ => {
                fixture.payload.expires_at_ms = unix_now_ms();
                fixture.sign();
            }
        }
        fixture.assert_authentication_refused_without_state();
    }
}

#[test]
fn partial_empty_or_malformed_signed_configuration_never_downgrades() {
    let options = [MESH_DIRECTORY_ID_ENV, MESH_DIRECTORY_OWNER_KEYS_ENV, MESH_DIRECTORY_STATE_ENV];
    for missing in options {
        let mut fixture = Fixture::new();
        fixture.env.remove(missing);
        assert!(fixture.start().is_err());
        fixture.env.insert(missing.to_owned(), " ".to_owned());
        assert!(fixture.start().is_err());
        assert!(MeshRouter::from_lookup(|name| (name == missing).then(|| "x".to_owned())).is_err());
    }
    for roots in ["[]", "{}", "[\"bad-key\"]", "null"] {
        let mut fixture = Fixture::new();
        fixture.env.insert(MESH_DIRECTORY_OWNER_KEYS_ENV.to_owned(), roots.to_owned());
        fixture.assert_authentication_refused_without_state();
    }
    let mut fixture = Fixture::new();
    fixture.env.insert(MESH_PEERS_ENV.to_owned(), serde_json::to_string(&fixture.payload.peers).unwrap());
    fixture.assert_authentication_refused_without_state();
}

#[test]
fn checkpoint_lock_prevents_parallel_activation_even_with_distinct_replay_storage() {
    let mut fixture = Fixture::new();
    let active = fixture.start().unwrap().unwrap();
    let bytes = fs::read(fixture.state_path()).unwrap();
    fixture.env.insert(MESH_REPLAY_JOURNAL_ENV.to_owned(), fixture.dir.path().join("other-replay").display().to_string());
    fixture.payload.generation += 1;
    fixture.sign();
    assert!(fixture.start().unwrap_err().to_string().contains("checkpoint is locked"));
    assert_eq!(fs::read(fixture.state_path()).unwrap(), bytes);
    drop(active);
    drop(fixture.start().unwrap().unwrap());
    assert_eq!(fixture.checkpoint().generation, 8);
}

#[test]
fn missing_initialized_checkpoint_is_not_silently_recreated() {
    let fixture = Fixture::new();
    drop(fixture.start().unwrap().unwrap());
    fs::rename(fixture.state_path(), fixture.dir.path().join("retained-checkpoint")).unwrap();
    assert!(fixture.start().unwrap_err().to_string().contains("initialized directory checkpoint is missing"));
    assert!(!fixture.state_path().exists());
}

#[test]
fn corrupt_or_empty_checkpoint_is_preserved_on_failure() {
    for contents in [b"".as_slice(), b"{damaged}", b"{}"] {
        let fixture = Fixture::new();
        drop(fixture.start().unwrap().unwrap());
        private_write(&fixture.state_path(), contents);
        assert!(fixture.start().is_err());
        assert_eq!(fs::read(fixture.state_path()).unwrap(), contents);
    }
}

#[test]
fn checkpoint_checksum_detects_valid_json_corruption() {
    let fixture = Fixture::new();
    drop(fixture.start().unwrap().unwrap());
    let mut stored: serde_json::Value = serde_json::from_slice(&fs::read(fixture.state_path()).unwrap()).unwrap();
    stored["checksum_hex"] = serde_json::json!("00".repeat(32));
    let corrupted = serde_json::to_vec(&stored).unwrap();
    private_write(&fixture.state_path(), &corrupted);
    assert!(fixture.start().is_err());
    assert_eq!(fs::read(fixture.state_path()).unwrap(), corrupted);
}

#[test]
fn readable_or_linked_state_is_rejected_without_overwriting_targets() {
    let fixture = Fixture::new();
    drop(fixture.start().unwrap().unwrap());
    let bytes = fs::read(fixture.state_path()).unwrap();
    fs::set_permissions(fixture.state_path(), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(fixture.start().is_err());
    assert_eq!(fs::read(fixture.state_path()).unwrap(), bytes);
    fs::set_permissions(fixture.state_path(), fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(fixture.state_path(), fixture.dir.path().join("retained-hard-link")).unwrap();
    assert!(fixture.start().is_err());
    assert_eq!(fs::read(fixture.state_path()).unwrap(), bytes);
}

#[test]
fn symlink_checkpoint_and_hardlinked_staging_do_not_modify_other_files() {
    for kind in ["checkpoint", "staging"] {
        let fixture = Fixture::new();
        let target = fixture.dir.path().join("do-not-modify");
        private_write(&target, b"private unrelated data");
        if kind == "checkpoint" {
            symlink(&target, fixture.state_path()).unwrap();
        } else {
            fs::hard_link(&target, fixture.dir.path().join("membership.next")).unwrap();
        }
        assert!(fixture.start().is_err());
        assert_eq!(fs::read(&target).unwrap(), b"private unrelated data");
    }
}

#[test]
fn reserved_staging_file_can_be_recovered_after_interrupted_write() {
    let fixture = Fixture::new();
    private_write(&fixture.dir.path().join("membership.next"), b"interrupted staging record");
    drop(fixture.start().unwrap().unwrap());
    assert_eq!(fixture.checkpoint().generation, 7);
    assert!(!fixture.dir.path().join("membership.next").exists());
}

#[test]
fn signed_file_source_works_and_oversized_input_fails_before_state() {
    let mut fixture = Fixture::new();
    let path = fixture.dir.path().join("signed-peers.json");
    private_write(&path, fixture.env.remove(MESH_PEERS_ENV).unwrap().as_bytes());
    fixture.env.insert(MESH_PEERS_FILE_ENV.to_owned(), path.display().to_string());
    drop(fixture.start().unwrap().unwrap());
    assert_eq!(fixture.checkpoint().generation, 7);

    let mut oversized = Fixture::new();
    let path = oversized.dir.path().join("oversized.json");
    private_write(&path, &vec![b' '; MAX_SIGNED_MESH_PEER_DIRECTORY_BYTES + 1]);
    oversized.env.remove(MESH_PEERS_ENV);
    oversized.env.insert(MESH_PEERS_FILE_ENV.to_owned(), path.display().to_string());
    oversized.assert_authentication_refused_without_state();
}

#[test]
fn explicit_static_directory_remains_distinct_from_owner_signed_mode() {
    let mut fixture = Fixture::new();
    for key in [MESH_DIRECTORY_ID_ENV, MESH_DIRECTORY_OWNER_KEYS_ENV, MESH_DIRECTORY_STATE_ENV] {
        fixture.env.remove(key);
    }
    fixture.env.insert(MESH_PEERS_ENV.to_owned(), serde_json::to_string(&fixture.payload.peers).unwrap());
    let router = fixture.start().unwrap().unwrap();
    assert!(!router.has_owner_signed_membership());
    assert!(router.has_durable_replay());
    assert_eq!(router.directory().len(), 1);
    assert!(!fixture.dir.path().join("membership").exists());
}
