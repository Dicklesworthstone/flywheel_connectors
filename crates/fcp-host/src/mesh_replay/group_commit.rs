//! Bounded group commit for the existing replay journal format.
//!
//! All accepted identities are staged before I/O and acknowledged only after
//! one shared append/sync. Compaction retains its own durability barriers.
//! An uncertain write refuses the entire group and latches the journal closed.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Write};

use super::{
    DurableMeshReplayGuard, Entry, MeshForwardError, RECORD_LEN, ReplayKey,
    VerifiedMeshReplayNonce, encode_record, replay_unavailable,
};

pub(crate) const MAX_REPLAY_GROUP_SIZE: usize = 16;

type AdmissionResult = Result<(), MeshForwardError>;

impl DurableMeshReplayGuard {
    /// Commit up to sixteen authenticated identities with one append/sync.
    /// Results retain input order. No successful result escapes before sync.
    pub(crate) fn accept_verified_batch(
        &mut self,
        identities: &[&VerifiedMeshReplayNonce],
        now_ms: u64,
    ) -> Vec<AdmissionResult> {
        self.accept_batch_with_sync(identities, now_ms, File::sync_all)
    }

    fn accept_batch_with_sync(
        &mut self,
        identities: &[&VerifiedMeshReplayNonce],
        now_ms: u64,
        sync: impl FnOnce(&File) -> io::Result<()>,
    ) -> Vec<AdmissionResult> {
        if identities.len() > MAX_REPLAY_GROUP_SIZE {
            return vec![Err(replay_unavailable("replay_batch_too_large")); identities.len()];
        }
        let mut staged = BTreeMap::new();
        let outcomes = identities
            .iter()
            .map(|identity| self.stage_identity(identity, now_ms, &mut staged))
            .collect::<Vec<_>>();
        if staged.is_empty() {
            return outcomes;
        }

        // From here until complete publication, a panic or uncertain I/O must
        // never leave an apparently usable journal with untracked disk state.
        self.io_failed = true;
        let persisted = (|| -> io::Result<()> {
            // Compact BEFORE adding a group that would cross the disk ceiling.
            // The replacement contains all previously accepted live nonces.
            if self.record_count + staged.len() > self.capacity * 2 {
                self.compact()?;
            }
            let mut records = Vec::with_capacity(staged.len() * RECORD_LEN);
            for (key, entry) in &staged {
                records.extend_from_slice(&encode_record(&self.scope, key, *entry));
            }
            self.file.write_all(&records)?;
            sync(&self.file)
        })();
        if let Err(error) = persisted {
            tracing::error!(
                event = "mesh_replay_journal_unavailable",
                reason = "group_commit_failed",
                group_size = identities.len(),
                error_kind = ?error.kind(),
                "mesh forward group refused before dispatch"
            );
            // Some replays/capacity decisions can depend on provisional entries
            // in this same group. An uncertain commit makes the whole group
            // unavailable; never advertise a provisional success or permit retry.
            return vec![Err(replay_unavailable("commit_failed")); identities.len()];
        }
        self.record_count += staged.len();
        for (key, entry) in staged {
            self.entries.insert(key, entry);
            self.expirations
                .push(std::cmp::Reverse((entry.expires_at_ms, key)));
        }
        self.io_failed = false;
        outcomes
    }

    fn stage_identity(
        &mut self,
        identity: &VerifiedMeshReplayNonce,
        now_ms: u64,
        staged: &mut BTreeMap<ReplayKey, Entry>,
    ) -> AdmissionResult {
        if identity.scope != self.scope {
            return Err(replay_unavailable("node_scope_mismatch"));
        }
        if self.io_failed {
            return Err(replay_unavailable("storage_failed"));
        }
        if now_ms < self.high_water_ms {
            return Err(replay_unavailable("clock_rollback"));
        }
        if identity.issued_at_ms.abs_diff(now_ms) > self.window_ms {
            return Err(MeshForwardError::Stale {
                what: "forward",
                issued_at_ms: identity.issued_at_ms,
                now_ms,
                window_ms: self.window_ms,
            });
        }
        self.high_water_ms = now_ms;
        self.expire(now_ms);
        if self.entries.contains_key(&identity.key) || staged.contains_key(&identity.key) {
            return Err(MeshForwardError::Replayed {
                origin: identity.origin.clone(),
            });
        }
        if self.entries.len() + staged.len() >= self.capacity {
            return Err(MeshForwardError::ReplayCacheSaturated {
                capacity: self.capacity,
            });
        }
        staged.insert(
            identity.key,
            Entry {
                expires_at_ms: identity.issued_at_ms.saturating_add(self.window_ms),
                observed_at_ms: now_ms,
            },
        );
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    use std::cell::Cell;
    use std::path::Path;
    use std::sync::mpsc;
    use std::time::Duration;

    use fcp_core::TailscaleNodeId;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_mesh::invoke_route::{MeshForwardBody, MeshForwardEnvelope, MeshPeerDirectory};

    use super::super::HEADER_LEN;

    const NOW: u64 = 1000;
    const WINDOW: u64 = 100;

    fn open(path: &Path, capacity: usize, now: u64) -> DurableMeshReplayGuard {
        DurableMeshReplayGuard::open(
            path,
            &TailscaleNodeId::new("executor"),
            WINDOW,
            capacity,
            now,
        )
        .unwrap()
    }

    fn identity_for(target: &str, issued: u64) -> VerifiedMeshReplayNonce {
        let key = Ed25519SigningKey::generate();
        let directory = MeshPeerDirectory::from_json(
            TailscaleNodeId::new(target),
            &serde_json::json!([{
                "node_id": "origin",
                "endpoint": "http://127.0.0.1:1",
                "public_key_hex": hex::encode(key.verifying_key().to_bytes()),
            }])
            .to_string(),
        )
        .unwrap();
        let envelope = MeshForwardEnvelope::sign(
            &key,
            TailscaleNodeId::new("origin"),
            TailscaleNodeId::new(target),
            issued,
            MeshForwardBody::Introspect {
                connector_id: "fcp.test:utility:1.0.0".to_owned(),
            },
        )
        .unwrap();
        VerifiedMeshReplayNonce::verify(&envelope, &directory, issued, WINDOW).unwrap()
    }

    fn identity(issued: u64) -> VerifiedMeshReplayNonce {
        identity_for("executor", issued)
    }

    fn unavailable(result: &AdmissionResult, reason: &str) -> bool {
        matches!(result, Err(MeshForwardError::Malformed { field: "replay_journal", detail })
            if detail.contains(reason))
    }

    #[test]
    fn one_sync_commits_every_accepted_nonce_and_all_survive_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let mut guard = open(&path, MAX_REPLAY_GROUP_SIZE, NOW);
        let identities = (0..MAX_REPLAY_GROUP_SIZE)
            .map(|_| identity(NOW))
            .collect::<Vec<_>>();
        let refs = identities.iter().collect::<Vec<_>>();
        let syncs = Cell::new(0);
        let results = guard.accept_batch_with_sync(&refs, NOW, |file| {
            syncs.set(syncs.get() + 1);
            file.sync_all()
        });
        assert_eq!(results.len(), MAX_REPLAY_GROUP_SIZE);
        assert!(results.iter().all(Result::is_ok));
        assert_eq!(syncs.get(), 1);
        assert_eq!(guard.record_count, MAX_REPLAY_GROUP_SIZE);
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            u64::try_from(HEADER_LEN + MAX_REPLAY_GROUP_SIZE * RECORD_LEN).unwrap()
        );
        drop(guard);
        let mut restored = open(&path, MAX_REPLAY_GROUP_SIZE, NOW + 1);
        for nonce in &identities {
            assert!(matches!(
                restored.accept_verified(nonce, NOW + 1),
                Err(MeshForwardError::Replayed { .. })
            ));
        }
    }

    #[test]
    fn mixed_group_preserves_order_replay_scope_freshness_and_capacity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let mut guard = open(&path, 2, NOW);
        let prior = identity(NOW);
        guard.accept_verified(&prior, NOW).unwrap();
        let fresh = identity(NOW);
        let stale = identity(NOW - WINDOW - 1);
        let wrong = identity_for("other-executor", NOW);
        let overflow = identity(NOW);
        let results =
            guard.accept_verified_batch(&[&prior, &fresh, &fresh, &stale, &wrong, &overflow], NOW);
        assert_eq!(results.len(), 6);
        assert!(matches!(
            &results[0],
            Err(MeshForwardError::Replayed { .. })
        ));
        assert_eq!(results[1], Ok(()));
        assert!(matches!(
            &results[2],
            Err(MeshForwardError::Replayed { .. })
        ));
        assert!(matches!(&results[3], Err(MeshForwardError::Stale { .. })));
        assert!(unavailable(&results[4], "node_scope_mismatch"));
        assert!(matches!(
            &results[5],
            Err(MeshForwardError::ReplayCacheSaturated { capacity: 2 })
        ));
        assert_eq!(guard.entries.len(), 2);
        assert_eq!(guard.record_count, 2);
    }

    #[test]
    fn rejected_only_and_empty_groups_never_sync_or_append() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let mut guard = open(&path, 1, NOW);
        let prior = identity(NOW);
        guard.accept_verified(&prior, NOW).unwrap();
        let length = std::fs::metadata(&path).unwrap().len();
        let results = guard.accept_batch_with_sync(
            &[&prior, &identity(NOW - WINDOW - 1), &identity(NOW)],
            NOW,
            |_| panic!("rejected group must not sync"),
        );
        assert!(results.iter().all(Result::is_err));
        assert!(
            guard
                .accept_batch_with_sync(&[], u64::MAX, |_| panic!("empty group must not sync"))
                .is_empty()
        );
        assert_eq!(guard.high_water_ms, NOW);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), length);
        assert!(!guard.io_failed);
    }

    #[test]
    fn uncertain_sync_refuses_the_whole_group_and_latches_admission_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let mut guard = open(&path, 4, NOW);
        let first = identity(NOW);
        let second = identity(NOW);
        let results = guard.accept_batch_with_sync(&[&first, &first, &second], NOW, |file| {
            // Model an error after persistence may already have succeeded.
            file.sync_all()?;
            Err(io::Error::other("injected uncertain sync result"))
        });
        assert!(
            results
                .iter()
                .all(|result| unavailable(result, "commit_failed"))
        );
        assert!(guard.io_failed);
        assert!(guard.entries.is_empty());
        let later = guard.accept_batch_with_sync(&[&identity(NOW)], NOW, |_| {
            panic!("failed journal must not attempt another sync")
        });
        assert!(unavailable(&later[0], "storage_failed"));
        drop(guard);
        let mut restored = open(&path, 4, NOW);
        for nonce in [&first, &second] {
            assert!(matches!(
                restored.accept_verified(nonce, NOW),
                Err(MeshForwardError::Replayed { .. })
            ));
        }
    }

    #[test]
    fn append_failure_never_calls_sync_or_reports_a_partial_success() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let mut guard = open(&path, 4, NOW);
        guard.file = File::open(&path).unwrap();
        let results = guard.accept_batch_with_sync(&[&identity(NOW), &identity(NOW)], NOW, |_| {
            panic!("append failure must not call sync")
        });
        assert!(
            results
                .iter()
                .all(|result| unavailable(result, "commit_failed"))
        );
        assert!(guard.io_failed);
        assert!(guard.entries.is_empty());
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            u64::try_from(HEADER_LEN).unwrap()
        );
    }

    #[test]
    fn compaction_precedes_a_group_crossing_the_disk_ceiling() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let mut guard = open(&path, 4, NOW);
        let future = identity(NOW + WINDOW);
        guard.accept_verified(&future, NOW).unwrap();
        for index in 1..=7_u64 {
            let now = NOW + index * 10;
            guard.accept_verified(&identity(now - WINDOW), now).unwrap();
        }
        assert_eq!(guard.record_count, 8);
        let now = NOW + 71;
        let group = (0..3).map(|_| identity(now)).collect::<Vec<_>>();
        assert!(
            guard
                .accept_verified_batch(&group.iter().collect::<Vec<_>>(), now)
                .iter()
                .all(Result::is_ok)
        );
        assert_eq!(guard.record_count, 4);
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            u64::try_from(HEADER_LEN + 4 * RECORD_LEN).unwrap()
        );
        assert!(
            DurableMeshReplayGuard::open(&path, &TailscaleNodeId::new("executor"), WINDOW, 4, now)
                .is_err()
        );
        drop(guard);
        let mut restored = open(&path, 4, now + 1);
        for nonce in std::iter::once(&future).chain(group.iter()) {
            assert!(matches!(
                restored.accept_verified(nonce, now + 1),
                Err(MeshForwardError::Replayed { .. })
            ));
        }
    }

    #[test]
    fn grouped_nonces_keep_the_inclusive_freshness_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let mut guard = open(&path, 4, NOW);
        let oldest = identity(NOW - WINDOW);
        let future = identity(NOW + WINDOW);
        assert_eq!(
            guard.accept_verified_batch(&[&oldest, &future], NOW),
            vec![Ok(()), Ok(())]
        );
        assert!(matches!(
            guard.accept_verified(&oldest, NOW),
            Err(MeshForwardError::Replayed { .. })
        ));
        assert!(matches!(
            guard.accept_verified(&future, NOW + 2 * WINDOW),
            Err(MeshForwardError::Replayed { .. })
        ));
        assert!(matches!(
            guard.accept_verified(&future, NOW + 2 * WINDOW + 1),
            Err(MeshForwardError::Stale { .. })
        ));
    }

    #[test]
    fn rollback_and_oversized_groups_do_not_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let mut guard = open(&path, 4, NOW);
        let fresh = identity(NOW);
        let rollback =
            guard.accept_batch_with_sync(&[&fresh], NOW - 1, |_| panic!("rollback must not sync"));
        assert!(unavailable(&rollback[0], "clock_rollback"));
        let oversized = vec![&fresh; MAX_REPLAY_GROUP_SIZE + 1];
        let results = guard
            .accept_batch_with_sync(&oversized, NOW, |_| panic!("oversized group must not sync"));
        assert_eq!(results.len(), oversized.len());
        assert!(
            results
                .iter()
                .all(|result| unavailable(result, "replay_batch_too_large"))
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            u64::try_from(HEADER_LEN).unwrap()
        );
        assert!(guard.entries.is_empty());
    }

    #[test]
    fn grouped_admission_matches_serial_admission_across_expiry_and_pressure() {
        let dir = tempfile::tempdir().unwrap();
        let mut serial = open(&dir.path().join("serial"), 5, NOW);
        let mut grouped = open(&dir.path().join("grouped"), 5, NOW);
        let first = identity(NOW);
        let future = identity(NOW + WINDOW);
        let wrong = identity_for("other-executor", NOW);
        for now in [NOW, NOW + 50, NOW + 101, NOW + 202] {
            let fresh = identity(now);
            let group = [&first, &future, &fresh, &fresh, &wrong];
            let expected = group
                .iter()
                .map(|identity| serial.accept_verified(identity, now))
                .collect::<Vec<_>>();
            assert_eq!(grouped.accept_verified_batch(&group, now), expected);
            let snapshot = |guard: &DurableMeshReplayGuard| {
                guard
                    .entries
                    .iter()
                    .map(|(key, entry)| (*key, entry.expires_at_ms, entry.observed_at_ms))
                    .collect::<Vec<_>>()
            };
            assert_eq!(snapshot(&serial), snapshot(&grouped));
            assert_eq!(serial.high_water_ms, grouped.high_water_ms);
        }
    }

    #[test]
    fn no_group_success_is_visible_until_the_sync_barrier_completes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let mut guard = open(&path, 4, NOW);
        let group = [identity(NOW), identity(NOW)];
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let results =
                guard.accept_batch_with_sync(&group.iter().collect::<Vec<_>>(), NOW, |file| {
                    entered_tx.send(()).unwrap();
                    release_rx
                        .recv_timeout(Duration::from_secs(5))
                        .map_err(|_| io::Error::other("test sync barrier timed out"))?;
                    file.sync_all()
                });
            result_tx.send(results).unwrap();
        });
        let entered = entered_rx.recv_timeout(Duration::from_secs(5));
        let premature = result_rx.try_recv();
        let _ = release_tx.send(());
        let completed = result_rx.recv_timeout(Duration::from_secs(5));
        worker.join().unwrap();
        assert!(entered.is_ok());
        assert!(matches!(premature, Err(mpsc::TryRecvError::Empty)));
        assert_eq!(completed.unwrap(), vec![Ok(()), Ok(())]);
    }
}
