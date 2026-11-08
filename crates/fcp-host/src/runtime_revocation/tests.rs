use super::*;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

struct Fixture {
    dir: tempfile::TempDir,
    owner: Ed25519SigningKey,
    issuer: KeyId,
    node: KeyId,
}

impl Fixture {
    fn new() -> Self {
        let fixture = Self {
            dir: tempfile::tempdir().unwrap(),
            owner: Ed25519SigningKey::generate(),
            issuer: KeyId::from_bytes([2; 8]),
            node: KeyId::from_bytes([3; 8]),
        };
        fixture.publish(&fixture.snapshot(1));
        fixture
    }

    fn config(&self) -> RuntimeRevocationConfig {
        let root = self.dir.path().canonicalize().unwrap();
        RuntimeRevocationConfig {
            zones: vec![RuntimeRevocationZoneConfig {
                zone_id: ZoneId::work(),
                owner_public_key_hex: hex::encode(self.owner.verifying_key().to_bytes()),
                snapshot_file: root.join("source.json"),
                checkpoint_file: root.join("checkpoint.json"),
            }],
        }
    }

    fn snapshot(&self, generation: u64) -> RuntimeRevocationSnapshot {
        let now = now_ms().unwrap();
        RuntimeRevocationSnapshot {
            schema: RUNTIME_REVOCATION_SCHEMA.into(),
            zone_id: ZoneId::work(),
            generation,
            issued_at_ms: now - 1000,
            expires_at_ms: now + 60_000,
            issuance_to_node: vec![(self.issuer.clone(), self.node.clone())],
            node_to_owner: vec![(self.node.clone(), self.owner.key_id())],
            tokens: vec![],
            keys: vec![],
        }
    }

    fn publish(&self, snapshot: &RuntimeRevocationSnapshot) {
        self.publish_signed(&snapshot.sign(&self.owner).unwrap());
    }

    fn publish_signed(&self, snapshot: &SignedRuntimeRevocations) {
        std::fs::write(
            self.dir.path().join("source.json"),
            serde_json::to_vec(snapshot).unwrap(),
        )
        .unwrap();
    }

    fn open(&self) -> HostResult<RuntimeRevocationService> {
        RuntimeRevocationService::open(self.config())
    }

    fn check(&self, service: &RuntimeRevocationService) -> HostResult<()> {
        service.verify(&ZoneId::work(), token(1), self.issuer.clone())
    }
}

fn token(value: u32) -> ObjectId {
    ObjectId::from_unscoped_bytes(&value.to_le_bytes())
}

fn revoke_token(snapshot: &mut RuntimeRevocationSnapshot, value: u32) {
    snapshot.tokens.push(RuntimeTokenRevocation {
        token_id: token(value),
        revoked_at_ms: snapshot.issued_at_ms - 1,
    });
}

#[test]
fn dispatch_permit_retains_both_clock_bounds_after_verification() {
    let fixture = Fixture::new();
    let service = fixture.open().unwrap();
    let mut permit = service
        .verify_for_dispatch(&ZoneId::work(), token(1), fixture.issuer.clone())
        .unwrap();
    assert!(permit.is_current());
    permit.deadline = Instant::now();
    assert!(
        !permit.is_current(),
        "wall-clock rollback cannot extend a monotonic permit"
    );
    assert!(permit.require_current().is_err());
    let mut permit = service
        .verify_for_dispatch(&ZoneId::work(), token(1), fixture.issuer.clone())
        .unwrap();
    permit.expires_at_ms = now_ms().unwrap();
    assert!(
        !permit.is_current(),
        "a forward wall-clock expiry must also win"
    );
}

#[test]
fn signed_feed_enforces_exact_zone_complete_chain_and_direct_revocation() {
    let fixture = Fixture::new();
    let service = fixture.open().unwrap();
    fixture.check(&service).unwrap();
    assert!(
        service
            .verify(&ZoneId::public(), token(1), fixture.issuer.clone())
            .is_err()
    );
    assert!(
        service
            .verify(&ZoneId::work(), token(1), KeyId::from_bytes([99; 8]))
            .is_err()
    );
    let mut snapshot = fixture.snapshot(2);
    revoke_token(&mut snapshot, 1);
    fixture.publish(&snapshot);
    assert!(
        fixture
            .check(&service)
            .unwrap_err()
            .to_string()
            .contains("directly revoked")
    );
    service
        .verify(&ZoneId::work(), token(2), fixture.issuer.clone())
        .unwrap();
}

#[test]
fn all_cascade_scopes_and_owner_issued_tokens_are_revocable() {
    for hop in [
        CascadeHop::IssuerKey,
        CascadeHop::NodeAttestation,
        CascadeHop::OwnerAttestation,
    ] {
        let fixture = Fixture::new();
        let service = fixture.open().unwrap();
        let mut snapshot = fixture.snapshot(2);
        let kid = match hop {
            CascadeHop::IssuerKey => fixture.issuer.clone(),
            CascadeHop::NodeAttestation => fixture.node.clone(),
            CascadeHop::OwnerAttestation => fixture.owner.key_id(),
        };
        snapshot.keys.push(RuntimeKeyRevocation {
            kid,
            hop,
            revoked_at_ms: snapshot.issued_at_ms,
        });
        fixture.publish(&snapshot);
        assert!(
            fixture
                .check(&service)
                .unwrap_err()
                .to_string()
                .contains("revoked at hop")
        );
        if hop == CascadeHop::OwnerAttestation {
            assert!(
                service
                    .verify(&ZoneId::work(), token(1), fixture.owner.key_id())
                    .is_err()
            );
        }
    }
}

#[test]
fn forged_wrong_zone_wrong_domain_and_incomplete_sources_never_replace_trust() {
    let fixture = Fixture::new();
    let service = fixture.open().unwrap();
    let initial = fixture.snapshot(2);
    let attacker = Ed25519SigningKey::generate();
    fixture.publish_signed(&initial.sign(&attacker).unwrap());
    assert!(fixture.check(&service).is_err());
    let mut wrong_zone = initial.clone();
    wrong_zone.zone_id = ZoneId::public();
    fixture.publish(&wrong_zone);
    assert!(fixture.check(&service).is_err());
    let mut wrong_type = initial.sign(&fixture.owner).unwrap();
    wrong_type.object_type = "unrelated.signed.object".into();
    fixture.publish_signed(&wrong_type);
    assert!(fixture.check(&service).is_err());
    let mut incomplete = initial.clone();
    incomplete.node_to_owner.clear();
    fixture.publish(&incomplete);
    assert!(fixture.check(&service).is_err());
    fixture.publish(&initial);
    fixture.check(&service).unwrap();
}

#[test]
fn missing_or_corrupt_source_after_success_fails_without_cached_fallback() {
    let fixture = Fixture::new();
    let service = fixture.open().unwrap();
    fixture.check(&service).unwrap();
    let source = fixture.dir.path().join("source.json");
    let offline = fixture.dir.path().join("source.offline");
    std::fs::rename(&source, &offline).unwrap();
    assert!(fixture.check(&service).is_err());
    std::fs::rename(&offline, &source).unwrap();
    fixture.check(&service).unwrap();
    std::fs::write(&source, b"{").unwrap();
    assert!(fixture.check(&service).is_err());
    fixture.publish(&fixture.snapshot(2));
    fixture.check(&service).unwrap();
}

#[test]
fn monotonic_clock_keeps_fractional_elapsed_time_and_expires_live_evidence() {
    let fixture = Fixture::new();
    let service = fixture.open().unwrap();
    let mut feed = service.feeds[0].lock().unwrap();
    let anchor = Instant::now();
    feed.clock_ms = 10_000;
    feed.clock_at = anchor;
    for micros in 1..=1500 {
        assert_eq!(
            feed.observe_clock_at(9000, anchor + Duration::from_micros(micros)),
            10_000 + micros / 1000
        );
    }
    feed.clock_ms = now_ms().unwrap();
    feed.clock_at = Instant::now() - Duration::from_secs(120);
    drop(feed);
    assert!(
        fixture
            .check(&service)
            .unwrap_err()
            .to_string()
            .contains("expired")
    );
}

#[test]
fn stale_authenticated_successor_and_rollback_remain_fenced_after_restart() {
    let fixture = Fixture::new();
    let original: SignedRuntimeRevocations =
        serde_json::from_slice(&std::fs::read(fixture.dir.path().join("source.json")).unwrap())
            .unwrap();
    let service = fixture.open().unwrap();
    let mut stale = fixture.snapshot(2);
    stale.issued_at_ms = now_ms().unwrap() - 10_000;
    stale.expires_at_ms = stale.issued_at_ms + 1000;
    fixture.publish(&stale);
    assert!(fixture.check(&service).is_err());
    drop(service);
    fixture.publish_signed(&original);
    assert!(
        fixture
            .open()
            .unwrap_err()
            .to_string()
            .contains("rolled back")
    );
    fixture.publish(&fixture.snapshot(3));
    fixture.open().unwrap();
}

#[test]
fn equivocation_keeps_union_of_revocations_and_requires_newer_generation_after_restart() {
    let fixture = Fixture::new();
    let service = fixture.open().unwrap();
    let mut first = fixture.snapshot(2);
    revoke_token(&mut first, 2);
    fixture.publish(&first);
    fixture.check(&service).unwrap();
    let mut conflict = first.clone();
    conflict.tokens.clear();
    revoke_token(&mut conflict, 3);
    fixture.publish(&conflict);
    assert!(fixture.check(&service).is_err());
    drop(service);
    fixture.publish(&first);
    assert!(fixture.open().is_err());
    let mut recovery = fixture.snapshot(3);
    recovery.tokens = first.tokens.clone();
    recovery.tokens.extend(conflict.tokens);
    fixture.publish(&recovery);
    let service = fixture.open().unwrap();
    fixture.check(&service).unwrap();
    for revoked in [2, 3] {
        assert!(
            service
                .verify(&ZoneId::work(), token(revoked), fixture.issuer.clone())
                .is_err()
        );
    }
    let mut weakened = recovery.clone();
    weakened.generation = 4;
    weakened.tokens[0].revoked_at_ms += 1;
    fixture.publish(&weakened);
    assert!(fixture.check(&service).is_err());
    drop(service);
    fixture.publish(&recovery);
    assert!(fixture.open().is_err());
    recovery.generation = 5;
    fixture.publish(&recovery);
    fixture.open().unwrap();
}

#[test]
fn issuer_reparenting_cannot_escape_revoked_ancestor_even_after_restart() {
    let fixture = Fixture::new();
    let service = fixture.open().unwrap();
    let mut revoked = fixture.snapshot(2);
    revoked.keys.push(RuntimeKeyRevocation {
        kid: fixture.node.clone(),
        hop: CascadeHop::NodeAttestation,
        revoked_at_ms: revoked.issued_at_ms,
    });
    fixture.publish(&revoked);
    assert!(fixture.check(&service).is_err());
    let new_node = KeyId::from_bytes([4; 8]);
    let mut bypass = revoked.clone();
    bypass.generation = 3;
    bypass.issuance_to_node[0].1 = new_node.clone();
    bypass.node_to_owner = vec![(new_node.clone(), fixture.owner.key_id())];
    fixture.publish(&bypass);
    assert!(
        fixture
            .check(&service)
            .unwrap_err()
            .to_string()
            .contains("binding")
    );
    drop(service);
    assert!(fixture.open().is_err());
    let new_issuer = KeyId::from_bytes([5; 8]);
    revoked.generation = 4;
    revoked
        .issuance_to_node
        .push((new_issuer.clone(), new_node.clone()));
    revoked
        .node_to_owner
        .push((new_node, fixture.owner.key_id()));
    fixture.publish(&revoked);
    let service = fixture.open().unwrap();
    assert!(fixture.check(&service).is_err());
    service
        .verify(&ZoneId::work(), token(1), new_issuer)
        .unwrap();
}

#[test]
fn durable_storage_rejects_second_writer_missing_corrupt_and_public_checkpoints() {
    let fixture = Fixture::new();
    let service = fixture.open().unwrap();
    assert!(fixture.open().is_err());
    drop(service);
    let checkpoint = fixture.dir.path().join("checkpoint.json");
    let saved = fixture.dir.path().join("checkpoint.saved");
    std::fs::rename(&checkpoint, &saved).unwrap();
    assert!(fixture.open().is_err());
    std::fs::rename(&saved, &checkpoint).unwrap();
    std::fs::set_permissions(&checkpoint, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(fixture.open().is_err());
    std::fs::set_permissions(&checkpoint, std::fs::Permissions::from_mode(0o600)).unwrap();
    fixture.open().unwrap();
    std::fs::write(&checkpoint, b"{}").unwrap();
    assert!(fixture.open().is_err());
}

#[test]
fn checkpoint_write_failure_latches_until_reopened_and_recovered() {
    let fixture = Fixture::new();
    let service = fixture.open().unwrap();
    let next = fixture.dir.path().join("checkpoint.json.next");
    std::fs::create_dir(&next).unwrap();
    fixture.publish(&fixture.snapshot(2));
    assert!(fixture.check(&service).is_err());
    std::fs::rename(&next, fixture.dir.path().join("unavailable-staging")).unwrap();
    assert!(fixture.check(&service).is_err());
    drop(service);
    fixture.open().unwrap();
}

#[test]
fn equivocation_capacity_overflow_is_a_durable_fence() {
    let fixture = Fixture::new();
    let mut full = fixture.snapshot(1);
    for value in 10..10 + MAX_RECORDS as u32 {
        revoke_token(&mut full, value);
    }
    fixture.publish(&full);
    let service = fixture.open().unwrap();
    let mut conflict = full.clone();
    conflict.tokens[0].token_id = token(9000);
    fixture.publish(&conflict);
    assert!(fixture.check(&service).is_err());
    drop(service);
    fixture.publish(&full);
    assert!(fixture.open().is_err());
    full.generation = 2;
    fixture.publish(&full);
    assert!(fixture.open().is_err());
}

#[test]
fn interrupted_newer_checkpoint_is_recovered_before_an_old_source_can_authorize() {
    let fixture = Fixture::new();
    let original: SignedRuntimeRevocations =
        serde_json::from_slice(&std::fs::read(fixture.dir.path().join("source.json")).unwrap())
            .unwrap();
    let service = fixture.open().unwrap();
    let checkpoint = fixture.dir.path().join("checkpoint.json");
    let old_checkpoint = fixture.dir.path().join("checkpoint.old");
    std::fs::rename(&checkpoint, &old_checkpoint).unwrap();
    std::fs::create_dir(&checkpoint).unwrap();
    let mut newer = fixture.snapshot(2);
    revoke_token(&mut newer, 1);
    fixture.publish(&newer);
    assert!(fixture.check(&service).is_err());
    assert!(fixture.dir.path().join("checkpoint.json.next").is_file());
    drop(service);
    std::fs::rename(&checkpoint, fixture.dir.path().join("blocked-publication")).unwrap();
    std::fs::rename(&old_checkpoint, &checkpoint).unwrap();
    fixture.publish_signed(&original);
    assert!(
        fixture
            .open()
            .unwrap_err()
            .to_string()
            .contains("rolled back")
    );
    fixture.publish(&newer);
    let service = fixture.open().unwrap();
    assert!(
        fixture
            .check(&service)
            .unwrap_err()
            .to_string()
            .contains("directly revoked")
    );
}

#[test]
fn revoked_node_cannot_be_reintroduced_as_an_issuer_in_later_generation() {
    let fixture = Fixture::new();
    let service = fixture.open().unwrap();
    let mut revoked = fixture.snapshot(2);
    revoked.keys.push(RuntimeKeyRevocation {
        kid: fixture.node.clone(),
        hop: CascadeHop::NodeAttestation,
        revoked_at_ms: revoked.issued_at_ms,
    });
    fixture.publish(&revoked);
    assert!(fixture.check(&service).is_err());
    let mut bypass = revoked.clone();
    bypass.generation = 3;
    bypass.issuance_to_node = vec![(fixture.node.clone(), fixture.owner.key_id())];
    bypass.node_to_owner.clear();
    fixture.publish(&bypass);
    assert!(
        service
            .verify(&ZoneId::work(), token(1), fixture.node.clone())
            .is_err()
    );
    drop(service);
    assert!(fixture.open().is_err());
    revoked.generation = 4;
    fixture.publish(&revoked);
    let service = fixture.open().unwrap();
    assert!(fixture.check(&service).is_err());
}

#[test]
fn observed_expiry_is_persisted_before_a_restart_can_rewind_time() {
    let fixture = Fixture::new();
    let service = fixture.open().unwrap();
    {
        let mut feed = service.feeds[0].lock().unwrap();
        feed.clock_at = Instant::now() - Duration::from_secs(120);
    }
    assert!(
        fixture
            .check(&service)
            .unwrap_err()
            .to_string()
            .contains("expired")
    );
    drop(service);
    assert!(
        fixture
            .open()
            .unwrap_err()
            .to_string()
            .contains("clock is older")
    );
}

#[test]
fn one_conflicting_role_cannot_erase_other_observed_node_roles_across_restart() {
    let fixture = Fixture::new();
    let service = fixture.open().unwrap();
    let newly_revoked_node = KeyId::from_bytes([87; 8]);
    let mut conflict = fixture.snapshot(2);
    conflict.issuance_to_node = vec![(fixture.node.clone(), newly_revoked_node.clone())];
    conflict.node_to_owner = vec![(newly_revoked_node.clone(), fixture.owner.key_id())];
    conflict.keys.push(RuntimeKeyRevocation {
        kid: newly_revoked_node.clone(),
        hop: CascadeHop::NodeAttestation,
        revoked_at_ms: conflict.issued_at_ms,
    });
    fixture.publish(&conflict);
    assert!(fixture.check(&service).is_err());
    {
        let feed = service.feeds[0].lock().unwrap();
        assert!(
            feed.checkpoint
                .as_ref()
                .unwrap()
                .node_to_owner
                .contains(&(newly_revoked_node.clone(), fixture.owner.key_id()))
        );
    }
    drop(service);
    let mut bypass = conflict.clone();
    bypass.generation = 3;
    bypass.issuance_to_node = vec![(newly_revoked_node.clone(), fixture.owner.key_id())];
    bypass.node_to_owner.clear();
    fixture.publish(&bypass);
    assert!(fixture.open().is_err());
    let mut recovery = fixture.snapshot(4);
    recovery.keys = conflict.keys;
    fixture.publish(&recovery);
    let service = fixture.open().unwrap();
    fixture.check(&service).unwrap();
    assert!(
        service
            .verify(&ZoneId::work(), token(1), newly_revoked_node)
            .is_err()
    );
}
