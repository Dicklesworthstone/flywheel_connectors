use super::super::tests::{ack, binding, event, ingest, instance_id, register};
use super::*;
use serde_json::json;

fn marker(path: &Path) -> Marker {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn database(path: &Path) -> PathBuf {
    parent_directory(path).join(marker(path).database)
}

fn write_legacy(path: &Path, journal: &NativeEventJournal) {
    persist_snapshot(path, &journal.lock().unwrap().snapshot).unwrap();
}

#[test]
fn exact_disk_receipts_continue_beyond_legacy_horizon_and_preserve_full_u64() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("events.json");
    let mut snapshot = JournalSnapshot::default();
    let mut record = StreamRecord {
        binding: binding(),
        instance_id: instance_id(),
        window_size: 1,
        closed: false,
        pending: VecDeque::new(),
        acknowledged: BTreeMap::new(),
    };
    // Import a valid journal at its old lifetime limit, then exercise ordinary
    // admission and ACK through the production API beyond that limit.
    for sequence in 0..NATIVE_EVENT_MAX_RECEIPTS as u64 {
        let event = event(sequence);
        record.acknowledged.insert(
            event.cursor.clone(),
            AcknowledgedEvent {
                cursor: event.cursor.clone(),
                delivery_seq: sequence,
                native_seq: Some(sequence),
                digest: event_digest(&event).unwrap(),
            },
        );
    }
    snapshot.streams.insert("stream-1".to_owned(), record);
    persist_snapshot(&path, &snapshot).unwrap();
    let journal = NativeEventJournal::open(path.clone()).unwrap();
    assert_eq!(
        journal.describe("stream-1").unwrap().acknowledged_events,
        NATIVE_EVENT_MAX_RECEIPTS
    );
    assert!(matches!(
        ingest(&journal, event(u64::MAX)).unwrap(),
        NativeEventAdmission::Accepted
    ));
    assert_eq!(
        journal
            .poll("stream-1", &binding(), &instance_id(), 1)
            .unwrap()
            .events[0]
            .seq,
        u64::MAX
    );
    assert_eq!(
        journal
            .acknowledge("stream-1", &binding(), &instance_id(), &ack(u64::MAX))
            .unwrap()
            .seqs,
        vec![u64::MAX]
    );
    assert_eq!(
        journal.describe("stream-1").unwrap().acknowledged_events,
        NATIVE_EVENT_MAX_RECEIPTS + 1
    );
    drop(journal);

    let journal = NativeEventJournal::open(path).unwrap();
    let replay = event(u64::MAX).with_seq((i64::MAX as u64) + 1);
    let NativeEventAdmission::AlreadyAcknowledged(native) = ingest(&journal, replay).unwrap()
    else {
        panic!("old receipt lost")
    };
    assert_eq!(native.seqs, vec![(i64::MAX as u64) + 1]);
    assert_eq!(
        journal
            .acknowledge("stream-1", &binding(), &instance_id(), &ack(u64::MAX))
            .unwrap()
            .seqs,
        native.seqs
    );
    assert!(matches!(
        ingest(&journal, event(0).with_seq(99)).unwrap(),
        NativeEventAdmission::AlreadyAcknowledged(_)
    ));
    let mut conflicting = event(0);
    conflicting.data.principal.id = "different-provider-user".to_owned();
    assert!(ingest(&journal, conflicting).is_err());
    assert_eq!(journal.describe("stream-1").unwrap().pending_events, 0);
    // Smaller, nonmonotonic and nonnumeric cursors remain distinct identities.
    let mut opaque = event(4);
    opaque.cursor = "opaque:earlier-than-everything/α".to_owned();
    assert!(matches!(
        ingest(&journal, opaque).unwrap(),
        NativeEventAdmission::Accepted
    ));
}

#[test]
fn closed_drained_streams_release_active_capacity_but_retain_tombstones() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("events.json");
    let journal = NativeEventJournal::open(path.clone()).unwrap();
    register(&journal, 1);
    ingest(&journal, event(1)).unwrap();
    journal
        .poll("stream-1", &binding(), &instance_id(), 1)
        .unwrap();
    journal
        .close("stream-1", &binding(), &instance_id())
        .unwrap();
    assert!(
        journal
            .register("next-stream", binding(), 1, instance_id())
            .is_err()
    );
    journal
        .acknowledge("stream-1", &binding(), &instance_id(), &ack(1))
        .unwrap();
    for index in 0..NATIVE_EVENT_MAX_STREAMS + 5 {
        let stream = format!("replacement-{index}");
        journal
            .register(&stream, binding(), 1, instance_id())
            .unwrap();
        journal.close(&stream, &binding(), &instance_id()).unwrap();
    }
    assert!(
        journal
            .register("stream-1", binding(), 1, instance_id())
            .is_err()
    );
    drop(journal);
    let journal = NativeEventJournal::open(path).unwrap();
    let retained = journal.describe("stream-1").unwrap();
    assert!(retained.closed);
    assert_eq!(retained.acknowledged_events, 1);
    assert!(
        journal
            .register("stream-1", binding(), 1, InstanceId::new())
            .is_err()
    );
    journal
        .register("after-restart", binding(), 1, instance_id())
        .unwrap();
    assert_eq!(
        journal
            .acknowledge("stream-1", &binding(), &instance_id(), &ack(1))
            .unwrap()
            .seqs,
        vec![1]
    );
}

#[test]
fn active_capacity_still_bounds_open_and_closed_undrained_streams() {
    let directory = tempfile::tempdir().unwrap();
    let journal = NativeEventJournal::open(directory.path().join("events.json")).unwrap();
    for index in 0..NATIVE_EVENT_MAX_STREAMS {
        let mut scope = binding();
        scope.connector_id = format!("fcp.source{index}:messaging:1.0.0")
            .parse()
            .unwrap();
        journal
            .register(&format!("active-{index}"), scope, 1, instance_id())
            .unwrap();
    }
    assert!(
        journal
            .register("over-capacity", binding(), 1, instance_id())
            .is_err()
    );
    let mut first = binding();
    first.connector_id = "fcp.source0:messaging:1.0.0".parse().unwrap();
    journal.close("active-0", &first, &instance_id()).unwrap();
    journal
        .register("new-capacity", binding(), 1, instance_id())
        .unwrap();
}

#[test]
fn sqlite_authority_rejections_and_partial_ack_batches_leave_custody_unchanged() {
    let directory = tempfile::tempdir().unwrap();
    let journal = NativeEventJournal::open(directory.path().join("events.json")).unwrap();
    register(&journal, 2);
    ingest(&journal, event(1)).unwrap();
    ingest(&journal, event(2)).unwrap();
    assert!(ingest(&journal, event(3)).is_err());
    assert!(
        journal
            .acknowledge("stream-1", &binding(), &instance_id(), &ack(1))
            .is_err()
    );
    let mut intruder = binding();
    intruder.principal = "agent:intruder".to_owned();
    assert!(
        journal
            .poll("stream-1", &intruder, &instance_id(), 2)
            .is_err()
    );
    assert!(
        journal
            .close("stream-1", &intruder, &instance_id())
            .is_err()
    );
    assert!(
        journal
            .acknowledge("stream-1", &intruder, &instance_id(), &ack(1))
            .is_err()
    );
    assert!(
        journal
            .poll("stream-1", &binding(), &InstanceId::new(), 2)
            .is_err()
    );
    journal
        .poll("stream-1", &binding(), &instance_id(), 2)
        .unwrap();
    let partial = EventAck::new(binding().topic, vec![1, 99])
        .with_cursors(vec!["update:1".to_owned(), "unknown".to_owned()]);
    assert!(
        journal
            .acknowledge("stream-1", &binding(), &instance_id(), &partial)
            .is_err()
    );
    let stream = journal.describe("stream-1").unwrap();
    assert_eq!(stream.pending_events, 2);
    assert_eq!(stream.acknowledged_events, 0);
    assert!(!stream.closed);
    journal
        .acknowledge("stream-1", &binding(), &instance_id(), &ack(1))
        .unwrap();
    assert!(matches!(
        ingest(&journal, event(3)).unwrap(),
        NativeEventAdmission::Accepted
    ));
}

#[test]
fn attachment_epoch_never_revives_old_mappings_when_an_instance_returns() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("events.json");
    let journal = NativeEventJournal::open(path.clone()).unwrap();
    register(&journal, 2);
    ingest(&journal, event(1)).unwrap();
    ingest(&journal, event(2)).unwrap();
    journal
        .poll("stream-1", &binding(), &instance_id(), 2)
        .unwrap();
    journal
        .acknowledge("stream-1", &binding(), &instance_id(), &ack(1))
        .unwrap();
    journal
        .register("stream-1", binding(), 2, InstanceId::new())
        .unwrap();
    journal
        .register("stream-1", binding(), 2, instance_id())
        .unwrap();
    drop(journal);
    let journal = NativeEventJournal::open(path).unwrap();
    assert!(
        journal
            .acknowledge("stream-1", &binding(), &instance_id(), &ack(1))
            .unwrap()
            .seqs
            .is_empty()
    );
    assert!(
        journal
            .acknowledge("stream-1", &binding(), &instance_id(), &ack(2))
            .unwrap()
            .seqs
            .is_empty()
    );
    let NativeEventAdmission::AlreadyAcknowledged(replayed) =
        ingest(&journal, event(2).with_seq(77)).unwrap()
    else {
        panic!("receipt lost")
    };
    assert_eq!(replayed.seqs, vec![77]);
    assert_eq!(
        journal
            .acknowledge("stream-1", &binding(), &instance_id(), &ack(2))
            .unwrap()
            .seqs,
        vec![77]
    );
}

#[test]
fn version_one_migration_preserves_pending_delivery_flags_receipts_and_native_mappings() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("events.json");
    let memory = NativeEventJournal::memory();
    register(&memory, 3);
    ingest(&memory, event(1)).unwrap();
    ingest(&memory, event(2)).unwrap();
    memory
        .poll("stream-1", &binding(), &instance_id(), 2)
        .unwrap();
    memory
        .acknowledge("stream-1", &binding(), &instance_id(), &ack(1))
        .unwrap();
    ingest(&memory, event(3)).unwrap();
    write_legacy(&path, &memory);
    let legacy = std::fs::read(&path).unwrap();
    let journal = NativeEventJournal::open(path.clone()).unwrap();
    assert_ne!(std::fs::read(&path).unwrap(), legacy);
    assert_eq!(marker(&path).version, DATABASE_VERSION);
    let stream = journal.describe("stream-1").unwrap();
    assert_eq!((stream.pending_events, stream.acknowledged_events), (2, 1));
    assert_eq!(
        journal
            .acknowledge("stream-1", &binding(), &instance_id(), &ack(1))
            .unwrap()
            .seqs,
        vec![1]
    );
    assert!(
        journal
            .acknowledge("stream-1", &binding(), &instance_id(), &ack(3))
            .is_err()
    );
    assert_eq!(
        journal
            .acknowledge("stream-1", &binding(), &instance_id(), &ack(2))
            .unwrap()
            .seqs,
        vec![2]
    );
    assert_eq!(
        journal
            .poll("stream-1", &binding(), &instance_id(), 3)
            .unwrap()
            .events[0]
            .seq,
        3
    );
}

#[test]
fn failed_migration_keeps_legacy_authoritative_and_retry_uses_a_new_database() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("events.json");
    let memory = NativeEventJournal::memory();
    register(&memory, 8);
    for sequence in 1..=7 {
        let mut event = event(sequence);
        event.data.payload = json!({"text":"x".repeat(180_000), "sequence":sequence});
        ingest(&memory, event).unwrap();
    }
    memory
        .poll("stream-1", &binding(), &instance_id(), 1)
        .unwrap();
    write_legacy(&path, &memory);
    let legacy = std::fs::read(&path).unwrap();
    assert!(
        NativeEventJournal::open_with_max_database_bytes(path.clone(), MIN_DATABASE_BYTES).is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), legacy);
    let journal =
        NativeEventJournal::open_with_max_database_bytes(path.clone(), 4 * MIN_DATABASE_BYTES)
            .unwrap();
    assert_eq!(journal.describe("stream-1").unwrap().pending_events, 7);
    journal
        .acknowledge("stream-1", &binding(), &instance_id(), &ack(1))
        .unwrap();
    assert!(
        journal
            .acknowledge("stream-1", &binding(), &instance_id(), &ack(2))
            .is_err()
    );
    let databases = std::fs::read_dir(directory.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "sqlite3")
        })
        .count();
    assert_eq!(
        databases, 2,
        "failed staging database must not be reused as authoritative"
    );
}

#[test]
fn migration_never_reconstructs_native_mappings_invalidated_before_restart() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("events.json");
    let memory = NativeEventJournal::memory();
    register(&memory, 2);
    ingest(&memory, event(1)).unwrap();
    ingest(&memory, event(2)).unwrap();
    memory
        .poll("stream-1", &binding(), &instance_id(), 2)
        .unwrap();
    memory
        .acknowledge("stream-1", &binding(), &instance_id(), &ack(1))
        .unwrap();
    let replacement = InstanceId::new();
    memory
        .register("stream-1", binding(), 2, replacement.clone())
        .unwrap();
    write_legacy(&path, &memory);
    let journal = NativeEventJournal::open(path).unwrap();
    for sequence in [1, 2] {
        assert!(
            journal
                .acknowledge("stream-1", &binding(), &replacement, &ack(sequence))
                .unwrap()
                .seqs
                .is_empty()
        );
    }
    let mut replay = event(2).with_seq(88);
    replay.data.instance_id = replacement;
    let NativeEventAdmission::AlreadyAcknowledged(native) = ingest(&journal, replay).unwrap()
    else {
        panic!("receipt lost")
    };
    assert_eq!(native.seqs, vec![88]);
}

#[test]
fn full_database_fences_without_credit_and_larger_budget_recovers_exact_custody() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("events.json");
    let journal =
        NativeEventJournal::open_with_max_database_bytes(path.clone(), MIN_DATABASE_BYTES).unwrap();
    register(&journal, 16);
    let mut accepted = 0;
    for sequence in 1..=16 {
        let mut event = event(sequence);
        event.data.payload = json!({"text":"x".repeat(200_000), "sequence":sequence});
        if ingest(&journal, event).is_err() {
            break;
        }
        accepted += 1;
    }
    assert!((1..16).contains(&accepted));
    assert!(journal.describe("stream-1").is_err());
    assert!(
        journal
            .poll("stream-1", &binding(), &instance_id(), 16)
            .is_err()
    );
    assert!(
        journal
            .acknowledge("stream-1", &binding(), &instance_id(), &ack(1))
            .is_err()
    );
    drop(journal);
    let journal =
        NativeEventJournal::open_with_max_database_bytes(path.clone(), 4 * MIN_DATABASE_BYTES)
            .unwrap();
    let stream = journal.describe("stream-1").unwrap();
    assert_eq!(stream.pending_events, accepted);
    assert_eq!(stream.acknowledged_events, 0);
    assert!(
        journal
            .acknowledge("stream-1", &binding(), &instance_id(), &ack(1))
            .is_err()
    );
    journal
        .poll("stream-1", &binding(), &instance_id(), 16)
        .unwrap();
    journal
        .acknowledge("stream-1", &binding(), &instance_id(), &ack(1))
        .unwrap();
    for sequence in accepted as u64 + 1..=accepted as u64 + 4 {
        let mut event = event(sequence);
        event.data.payload = json!({"text":"x".repeat(200_000), "sequence":sequence});
        ingest(&journal, event).unwrap();
    }
    assert!(std::fs::metadata(database(&path)).unwrap().len() > MIN_DATABASE_BYTES);
    drop(journal);
    let before = std::fs::read(&path).unwrap();
    assert!(
        NativeEventJournal::open_with_max_database_bytes(path.clone(), MIN_DATABASE_BYTES).is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let journal =
        NativeEventJournal::open_with_max_database_bytes(path, 4 * MIN_DATABASE_BYTES).unwrap();
    assert_eq!(journal.describe("stream-1").unwrap().acknowledged_events, 1);
}

#[test]
fn missing_or_symlinked_database_cannot_reset_acknowledgement_history() {
    use std::os::unix::fs::symlink;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("events.json");
    let journal = NativeEventJournal::open(path.clone()).unwrap();
    register(&journal, 1);
    ingest(&journal, event(1)).unwrap();
    journal
        .poll("stream-1", &binding(), &instance_id(), 1)
        .unwrap();
    journal
        .acknowledge("stream-1", &binding(), &instance_id(), &ack(1))
        .unwrap();
    drop(journal);
    let database = database(&path);
    let moved = directory.path().join("retained.sqlite3");
    std::fs::rename(&database, &moved).unwrap();
    assert!(NativeEventJournal::open(path.clone()).is_err());
    assert!(!database.exists());
    symlink(&moved, &database).unwrap();
    assert!(NativeEventJournal::open(path).is_err());
    assert!(moved.is_file());
}

#[test]
fn marker_database_identity_mismatch_and_pending_corruption_are_rejected() {
    for corrupt_identity in [true, false] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("events.json");
        let journal = NativeEventJournal::open(path.clone()).unwrap();
        register(&journal, 1);
        ingest(&journal, event(1)).unwrap();
        drop(journal);
        let connection = Connection::open(database(&path)).unwrap();
        if corrupt_identity {
            connection
                .execute("UPDATE journal_meta SET identity = ?1", ["0".repeat(64)])
                .unwrap();
        } else {
            connection
                .execute("UPDATE events SET digest = ?1", ["0".repeat(64)])
                .unwrap();
        }
        connection.close().unwrap();
        let before = std::fs::read(&path).unwrap();
        assert!(NativeEventJournal::open(path.clone()).is_err());
        assert_eq!(std::fs::read(path).unwrap(), before);
    }
}

#[test]
fn missing_marker_after_restart_cannot_abandon_existing_custody() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("events.json");
    // Invalid configuration must not create a lock that looks like interrupted
    // initialization when the operator subsequently corrects the budget.
    assert!(NativeEventJournal::open_with_max_database_bytes(path.clone(), 1).is_err());
    assert!(!directory.path().join("events.json.lock").exists());
    let journal = NativeEventJournal::open(path.clone()).unwrap();
    register(&journal, 2);
    ingest(&journal, event(1)).unwrap();
    ingest(&journal, event(2)).unwrap();
    journal
        .poll("stream-1", &binding(), &instance_id(), 2)
        .unwrap();
    journal
        .acknowledge("stream-1", &binding(), &instance_id(), &ack(1))
        .unwrap();
    drop(journal);
    let retained_database = database(&path);
    let restored_marker = directory.path().join("marker-backup.json");
    std::fs::rename(&path, &restored_marker).unwrap();
    assert!(NativeEventJournal::open(path.clone()).is_err());
    assert!(
        !path.exists(),
        "missing marker must not be recreated as an empty journal"
    );
    assert!(retained_database.is_file());
    std::fs::rename(&restored_marker, &path).unwrap();
    let journal = NativeEventJournal::open(path).unwrap();
    let stream = journal.describe("stream-1").unwrap();
    assert_eq!((stream.pending_events, stream.acknowledged_events), (1, 1));
    assert_eq!(
        journal
            .poll("stream-1", &binding(), &instance_id(), 2)
            .unwrap()
            .events[0]
            .seq,
        2
    );
    assert!(matches!(
        ingest(&journal, event(1)).unwrap(),
        NativeEventAdmission::AlreadyAcknowledged(_)
    ));
}

#[test]
fn database_and_rollback_files_are_private_and_unsafe_sidecars_are_refused() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("events.json");
    let journal = NativeEventJournal::open(path.clone()).unwrap();
    register(&journal, 1);
    let database = database(&path);
    assert_eq!(
        std::fs::metadata(&database).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let sidecar = PathBuf::from(format!("{}-journal", database.display()));
    if sidecar.exists() {
        assert_eq!(
            std::fs::metadata(&sidecar).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    drop(journal);
    if sidecar.exists() {
        std::fs::rename(&sidecar, directory.path().join("old-journal")).unwrap();
    }
    let target = directory.path().join("must-not-modify");
    std::fs::write(&target, "protected target").unwrap();
    symlink(&target, sidecar).unwrap();
    assert!(NativeEventJournal::open(path).is_err());
    assert_eq!(std::fs::read_to_string(target).unwrap(), "protected target");
}
