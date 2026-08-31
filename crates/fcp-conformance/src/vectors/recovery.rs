//! Conformance vectors for FCP recovery flows.
//!
//! These vectors test the normative recovery requirements from
//! `FCP_Specification_V3.md`:
//! - §9.7.3 (Session Replay and Rekey Policy) — replay window, rekey triggers
//! - §6.5 (Zone Checkpoints) — checkpoint freshness, recovery from checkpoint
//! - §11.5 (Offline and Repair Behavior) — repair sequence determinism
//!
//! # Coverage
//!
//! 1. `ReplayWindow` accepts fresh frames and rejects replays
//! 2. `ReplayWindow` handles out-of-order delivery within the window
//! 3. `ReplayWindow` rejects frames outside the window
//! 4. `SessionReplayPolicy` normative defaults
//! 5. Rekey trigger threshold computation
//! 6. `ZoneCheckpoint` freshness comparison
//! 7. Checkpoint-based recovery state roundtrip

#[cfg(test)]
mod tests {
    use fcp_cbor::SchemaId;
    use fcp_prelude::{
        EpochId, NodeId, NodeSignature, ObjectHeader, ObjectId, Provenance, SignatureSet,
        ZoneCheckpoint, ZoneId,
    };
    use fcp_protocol::session::{ReplayWindow, SessionReplayPolicy, TimePolicy};
    use semver::Version;

    // ── ReplayWindow Behavior ─────────────────────────────────────────

    #[test]
    fn replay_window_accepts_fresh_sequential_frames() {
        let mut window = ReplayWindow::new(64);
        for seq in 1..=100 {
            assert!(
                window.check_and_update(seq),
                "sequential frame {seq} should be accepted"
            );
        }
        assert_eq!(window.highest_seq(), 100);
    }

    #[test]
    fn replay_window_rejects_duplicate_frame() {
        let mut window = ReplayWindow::new(64);
        assert!(window.check_and_update(1));
        assert!(window.check_and_update(2));
        assert!(
            !window.check_and_update(2),
            "duplicate frame_seq=2 must be rejected"
        );
        assert!(
            !window.check_and_update(1),
            "duplicate frame_seq=1 must be rejected"
        );
    }

    #[test]
    fn replay_window_rejects_seq_zero() {
        let mut window = ReplayWindow::new(64);
        assert!(
            !window.check_and_update(0),
            "frame_seq=0 is reserved and must be rejected"
        );
    }

    #[test]
    fn replay_window_accepts_reordered_within_window() {
        let mut window = ReplayWindow::new(64);
        // Receive frames 1, 2, 5, 3, 4 (out of order but within window)
        assert!(window.check_and_update(1));
        assert!(window.check_and_update(2));
        assert!(window.check_and_update(5));
        assert!(
            window.check_and_update(3),
            "reordered frame_seq=3 within window should be accepted"
        );
        assert!(
            window.check_and_update(4),
            "reordered frame_seq=4 within window should be accepted"
        );
    }

    #[test]
    fn replay_window_rejects_frame_outside_window() {
        let mut window = ReplayWindow::new(16);
        // Advance window far ahead
        assert!(window.check_and_update(1));
        assert!(window.check_and_update(100));
        // seq=1 is now outside the window (100 - 1 = 99 > 16)
        assert!(
            !window.check_and_update(1),
            "frame_seq=1 is outside 16-frame window from highest=100"
        );
        // seq=84 is just at the boundary (100 - 84 = 16 >= window_size)
        assert!(
            !window.check_and_update(84),
            "frame_seq=84 is at window boundary and should be rejected"
        );
        // seq=85 is just inside (100 - 85 = 15 < 16)
        assert!(
            window.check_and_update(85),
            "frame_seq=85 is within window and should be accepted"
        );
    }

    #[test]
    fn replay_window_check_without_update_is_idempotent() {
        let mut window = ReplayWindow::new(64);
        assert!(window.check_and_update(1));
        assert!(window.check_and_update(5));

        // check() doesn't modify state
        assert!(window.check(3), "check-only should accept unseen frame");
        assert!(window.check(3), "second check-only should still accept");
        // Now actually accept it
        assert!(window.check_and_update(3));
        assert!(!window.check(3), "check after update should reject");
    }

    #[test]
    fn replay_window_large_gap_clears_bitmap() {
        let mut window = ReplayWindow::new(64);
        assert!(window.check_and_update(1));
        // Jump far ahead — all old frames should be outside window
        assert!(window.check_and_update(1000));
        assert_eq!(window.highest_seq(), 1000);
        // Frames near the start are long gone
        for old_seq in 1..=900 {
            assert!(
                !window.check(old_seq),
                "old frame_seq={old_seq} should be rejected after large gap"
            );
        }
    }

    #[test]
    fn replay_window_minimum_size_is_one() {
        // Window size 0 should be clamped to 1
        let mut window = ReplayWindow::new(0);
        assert!(window.check_and_update(1));
        assert!(window.check_and_update(2));
        // With window size 1, seq=1 is outside (2-1=1 >= 1)
        assert!(!window.check_and_update(1));
    }

    // ── SessionReplayPolicy Normative Defaults ────────────────────────

    #[test]
    fn session_replay_policy_normative_defaults() {
        let policy = SessionReplayPolicy::default();
        // Per spec §9.7.3
        assert_eq!(policy.max_reorder_window, 128);
        assert_eq!(policy.rekey_after_frames, 1_000_000_000);
        assert_eq!(policy.rekey_after_seconds, 86_400); // 24 hours
        assert_eq!(policy.rekey_after_bytes, 1_099_511_627_776); // 1 TiB
    }

    #[test]
    fn session_replay_policy_rekey_thresholds_are_conservative() {
        let policy = SessionReplayPolicy::default();
        // Frame threshold: 1 billion frames
        assert!(policy.rekey_after_frames >= 1_000_000_000);
        // Time threshold: at least 24 hours
        assert!(policy.rekey_after_seconds >= 86_400);
        // Byte threshold: at least 1 TiB
        assert!(policy.rekey_after_bytes >= 1 << 40);
    }

    #[test]
    fn time_policy_defaults() {
        let policy = TimePolicy::default();
        // Max skew should be reasonable (≤ 10 minutes)
        assert!(policy.max_skew_secs > 0);
        assert!(
            policy.max_skew_secs <= 600,
            "max skew should be at most 10 minutes"
        );
        // Skew events should be logged by default
        assert!(policy.log_skew_events);
    }

    #[test]
    fn session_replay_policy_equality() {
        let policy1 = SessionReplayPolicy {
            max_reorder_window: 256,
            rekey_after_frames: 500_000,
            rekey_after_seconds: 3600,
            rekey_after_bytes: 1_073_741_824,
        };
        let policy2 = policy1;
        assert_eq!(policy1, policy2);
        assert_ne!(policy1, SessionReplayPolicy::default());
    }

    // ── Zone Checkpoint Recovery ──────────────────────────────────────

    fn test_zone() -> ZoneId {
        "z:recovery".parse().unwrap()
    }

    fn test_header() -> ObjectHeader {
        ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.test", "Recovery", Version::new(0, 1, 0)),
            zone_id: test_zone(),
            created_at: 1_700_000_000,
            provenance: Provenance::new(test_zone()),
            refs: Vec::new(),
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        }
    }

    fn test_signature() -> NodeSignature {
        NodeSignature::new(NodeId::new("test-recovery-node"), [0xBB; 64], 1_700_000_000)
    }

    #[test]
    fn checkpoint_freshness_comparison() {
        let older = ZoneCheckpoint {
            header: test_header(),
            zone_id: test_zone(),
            rev_head: ObjectId::from_bytes([0xA1; 32]),
            rev_seq: 5,
            audit_head: ObjectId::from_bytes([0xA2; 32]),
            audit_seq: 10,
            zone_definition_head: ObjectId::from_bytes([0xA3; 32]),
            zone_policy_head: ObjectId::from_bytes([0xA4; 32]),
            active_zone_key_manifest: ObjectId::from_bytes([0xA5; 32]),
            checkpoint_seq: 1,
            as_of_epoch: EpochId::new("epoch-10"),
            quorum_signatures: SignatureSet::default(),
            revocation_freshness_sla_secs: 300,
        };

        let newer = ZoneCheckpoint {
            checkpoint_seq: 2,
            rev_seq: 8,
            audit_seq: 15,
            rev_head: ObjectId::from_bytes([0xB1; 32]),
            audit_head: ObjectId::from_bytes([0xB2; 32]),
            as_of_epoch: EpochId::new("epoch-20"),
            ..older.clone()
        };

        // Newer checkpoint has higher seq values
        assert!(newer.checkpoint_seq > older.checkpoint_seq);
        assert!(newer.rev_seq > older.rev_seq);
        assert!(newer.audit_seq > older.audit_seq);

        // Same zone
        assert_eq!(newer.zone_id, older.zone_id);
    }

    #[test]
    fn checkpoint_with_quorum_signatures() {
        let mut sigs = SignatureSet::default();
        for i in 0u8..3 {
            sigs.add(NodeSignature::new(
                NodeId::new(format!("node-{i}")),
                [i; 64],
                1_700_000_000 + u64::from(i),
            ));
        }
        assert_eq!(sigs.len(), 3);

        let checkpoint = ZoneCheckpoint {
            header: test_header(),
            zone_id: test_zone(),
            rev_head: ObjectId::from_bytes([0xC1; 32]),
            rev_seq: 10,
            audit_head: ObjectId::from_bytes([0xC2; 32]),
            audit_seq: 20,
            zone_definition_head: ObjectId::from_bytes([0xC3; 32]),
            zone_policy_head: ObjectId::from_bytes([0xC4; 32]),
            active_zone_key_manifest: ObjectId::from_bytes([0xC5; 32]),
            checkpoint_seq: 5,
            as_of_epoch: EpochId::new("epoch-50"),
            quorum_signatures: sigs,
            revocation_freshness_sla_secs: 300,
        };

        assert_eq!(checkpoint.quorum_signatures.len(), 3);
        assert!(!checkpoint.quorum_signatures.is_empty());
    }

    #[test]
    fn checkpoint_recovery_roundtrip_via_json() {
        let mut sigs = SignatureSet::default();
        sigs.add(test_signature());

        let checkpoint = ZoneCheckpoint {
            header: test_header(),
            zone_id: test_zone(),
            rev_head: ObjectId::from_bytes([0xD1; 32]),
            rev_seq: 7,
            audit_head: ObjectId::from_bytes([0xD2; 32]),
            audit_seq: 14,
            zone_definition_head: ObjectId::from_bytes([0xD3; 32]),
            zone_policy_head: ObjectId::from_bytes([0xD4; 32]),
            active_zone_key_manifest: ObjectId::from_bytes([0xD5; 32]),
            checkpoint_seq: 3,
            as_of_epoch: EpochId::new("epoch-30"),
            quorum_signatures: sigs,
            revocation_freshness_sla_secs: 300,
        };

        // Serialize to JSON (simulating durable storage retrieval)
        let json = serde_json::to_string(&checkpoint).unwrap();
        let recovered: ZoneCheckpoint = serde_json::from_str(&json).unwrap();

        // All enforceable heads survive roundtrip
        assert_eq!(recovered.rev_seq, 7);
        assert_eq!(recovered.audit_seq, 14);
        assert_eq!(recovered.checkpoint_seq, 3);
        assert_eq!(recovered.zone_id, test_zone());
        assert_eq!(recovered.rev_head, ObjectId::from_bytes([0xD1; 32]));
        assert_eq!(recovered.audit_head, ObjectId::from_bytes([0xD2; 32]));
        assert_eq!(recovered.quorum_signatures.len(), 1);
    }

    // ── ReplayWindow + SessionReplayPolicy Integration ────────────────

    #[test]
    fn replay_window_sized_from_policy() {
        let policy = SessionReplayPolicy::default();
        let mut window = ReplayWindow::new(policy.max_reorder_window);

        // Window should use policy's reorder window size
        assert!(window.check_and_update(1));
        // Jump ahead by exactly max_reorder_window
        let jump_target = 1 + policy.max_reorder_window;
        assert!(window.check_and_update(jump_target));
        // Frame 1 is now at the boundary and should be rejected
        assert!(
            !window.check(1),
            "frame at boundary of policy window should be rejected"
        );
    }
}
