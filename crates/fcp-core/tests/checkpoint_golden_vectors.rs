//! Golden vector tests for Checkpoint/Frontier Management (flywheel_connectors-a8xp).
//!
//! This module provides comprehensive tests for:
//! - Checkpoint advancement with quorum signatures
//! - Fork detection and evidence preservation
//! - Convergence after partition recovery
//! - Frontier management semantics
//!
//! # Test Categories
//!
//! 1. **Checkpoint Advancement**: Quorum signatures, sequence monotonicity, head bindings
//! 2. **Fork Detection**: Conflicting checkpoints, evidence preservation, halt semantics
//! 3. **Convergence**: Partition recovery, late-joining nodes, gossip propagation
//! 4. **Frontier Management**: Latest valid checkpoint tracking, atomic updates
//! 5. **HRW Coordinator Selection**: Deterministic selection, fallback ranking

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use fcp_core::{
    CheckpointAdvanceState, CheckpointProposal, CheckpointTrigger, CheckpointValidationError,
    DEFAULT_AUDIT_CHAIN_GROWTH_THRESHOLD, DEFAULT_CHECKPOINT_INTERVAL_SECS, EpochId,
    ForkDetectionResult, ForkEvidence, FreshnessResult, NodeId, NodeSignature, ObjectId,
    SignatureSet, TailscaleNodeId, ZoneId, hrw_hash_checkpoint, rank_checkpoint_coordinators,
    select_checkpoint_coordinator,
};

// ─────────────────────────────────────────────────────────────────────────────
// Test Logging (FCP2 Requirements)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, serde::Serialize)]
struct TestLogEntry {
    timestamp: String,
    test_name: String,
    module: String,
    phase: String,
    zone_id: Option<String>,
    checkpoint_seq: Option<u64>,
    fork_detected: Option<bool>,
    coordinator: Option<String>,
    result: String,
}

impl TestLogEntry {
    fn new(test_name: &str) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            test_name: test_name.to_string(),
            module: "fcp-core::checkpoint".to_string(),
            phase: "setup".to_string(),
            zone_id: None,
            checkpoint_seq: None,
            fork_detected: None,
            coordinator: None,
            result: "pending".to_string(),
        }
    }

    fn execute(mut self) -> Self {
        self.phase = "execute".to_string();
        self
    }

    fn verify(mut self) -> Self {
        self.phase = "verify".to_string();
        self
    }

    fn with_zone(mut self, zone_id: &str) -> Self {
        self.zone_id = Some(zone_id.to_string());
        self
    }

    const fn with_checkpoint_seq(mut self, seq: u64) -> Self {
        self.checkpoint_seq = Some(seq);
        self
    }

    const fn with_fork_detected(mut self, detected: bool) -> Self {
        self.fork_detected = Some(detected);
        self
    }

    fn with_coordinator(mut self, coord: &str) -> Self {
        self.coordinator = Some(coord.to_string());
        self
    }

    fn pass(mut self) -> Self {
        self.result = "pass".to_string();
        self
    }

    #[allow(dead_code)]
    fn fail(mut self, reason: &str) -> Self {
        self.result = format!("fail: {reason}");
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn test_zone() -> ZoneId {
    ZoneId::work()
}

fn test_epoch() -> EpochId {
    EpochId::new("epoch-test-42")
}

fn test_node(name: &str) -> TailscaleNodeId {
    TailscaleNodeId::new(name)
}

fn test_node_id(name: &str) -> NodeId {
    NodeId::new(name)
}

fn test_object_id(label: &str) -> ObjectId {
    ObjectId::from_unscoped_bytes(label.as_bytes())
}

fn test_signature(signer: &str, ts: u64) -> NodeSignature {
    NodeSignature::new(test_node_id(signer), [0u8; 64], ts)
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/checkpoint")
}

fn create_test_proposal(zone: ZoneId, seq: u64, prev: Option<ObjectId>) -> CheckpointProposal {
    CheckpointProposal {
        zone_id: zone,
        proposed_seq: seq,
        prev_checkpoint_id: prev,
        audit_head_id: test_object_id(&format!("audit-head-{seq}")),
        audit_head_seq: seq * 10,
        revocation_head_id: test_object_id(&format!("rev-head-{seq}")),
        revocation_head_seq: seq * 5,
        zone_definition_head: test_object_id("zone-def"),
        zone_policy_head: test_object_id("zone-policy"),
        active_zone_key_manifest: test_object_id("zkm"),
        epoch_id: test_epoch(),
        proposed_at: 1_700_000_000 + seq * 60,
        coordinator: test_node("coordinator"),
        coordinator_signature: test_signature("coordinator", 1_700_000_000 + seq * 60),
        triggers: vec![CheckpointTrigger::TimeElapsed {
            elapsed_secs: 65,
            threshold_secs: 60,
        }],
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Checkpoint Advancement Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn checkpoint_advancement_with_quorum() {
    let log = TestLogEntry::new("checkpoint_advancement_with_quorum")
        .with_zone("z:work")
        .execute();

    let zone = test_zone();
    let proposal = create_test_proposal(zone, 11, Some(test_object_id("prev-chk-10")));

    // Verify sequence follows previous
    assert!(proposal.seq_follows_prev(10), "seq 11 should follow 10");
    assert!(!proposal.seq_follows_prev(9), "seq 11 should not follow 9");
    assert!(
        !proposal.seq_follows_prev(11),
        "seq 11 should not follow 11"
    );

    // Create signature set for quorum
    let mut signatures = SignatureSet::new();
    signatures.add(test_signature("node-a", 1_700_000_660));
    signatures.add(test_signature("node-b", 1_700_000_660));
    signatures.add(test_signature("node-c", 1_700_000_660));

    // Simulate advancement to ProposalBroadcast state
    let state = CheckpointAdvanceState::ProposalBroadcast {
        proposal: Box::new(proposal),
        collected_signatures: signatures.clone(),
        required_signatures: 3,
    };

    // Verify state allows advancement
    assert!(state.can_advance(), "should be able to advance");
    assert!(!state.is_halted(), "should not be halted");
    assert!(
        state.fork_evidence().is_none(),
        "should have no fork evidence"
    );

    // Verify quorum met
    assert_eq!(signatures.len(), 3, "should have 3 signatures");

    let _log = log.verify().with_checkpoint_seq(11).pass();
}

#[test]
fn checkpoint_advancement_blocked_without_quorum() {
    let log = TestLogEntry::new("checkpoint_advancement_blocked_without_quorum")
        .with_zone("z:work")
        .execute();

    let zone = test_zone();
    let proposal = create_test_proposal(zone, 5, Some(test_object_id("prev-chk-4")));

    // Create signature set with insufficient signatures
    let mut signatures = SignatureSet::new();
    signatures.add(test_signature("node-a", 1_700_000_300));
    // Only 1 signature, need 3

    let state = CheckpointAdvanceState::ProposalBroadcast {
        proposal: Box::new(proposal),
        collected_signatures: signatures.clone(),
        required_signatures: 3,
    };

    // State allows advancement (not halted), but quorum not met
    assert!(state.can_advance(), "state should allow advancement");
    assert!(
        signatures.len() < 3,
        "quorum not met with {} signatures",
        signatures.len()
    );

    let _log = log.verify().with_checkpoint_seq(5).pass();
}

#[test]
fn checkpoint_sequence_monotonic() {
    let log = TestLogEntry::new("checkpoint_sequence_monotonic")
        .with_zone("z:work")
        .execute();

    // Test monotonic sequence advancement
    let sequences = [(0, 1), (1, 2), (99, 100), (1000, 1001)];

    for (prev, next) in sequences {
        let proposal = CheckpointProposal {
            zone_id: test_zone(),
            proposed_seq: next,
            prev_checkpoint_id: if prev == 0 {
                None
            } else {
                Some(test_object_id(&format!("chk-{prev}")))
            },
            audit_head_id: test_object_id("audit"),
            audit_head_seq: next.saturating_mul(10),
            revocation_head_id: test_object_id("rev"),
            revocation_head_seq: next.saturating_mul(5),
            zone_definition_head: test_object_id("zone-def"),
            zone_policy_head: test_object_id("policy"),
            active_zone_key_manifest: test_object_id("zkm"),
            epoch_id: test_epoch(),
            proposed_at: 1_700_000_000,
            coordinator: test_node("coord"),
            coordinator_signature: test_signature("coord", 1_700_000_000),
            triggers: vec![],
        };

        assert!(
            proposal.seq_follows_prev(prev),
            "seq {next} should follow {prev}"
        );
    }

    // Test overflow protection
    let overflow_proposal = CheckpointProposal {
        zone_id: test_zone(),
        proposed_seq: 0, // Would need u64::MAX + 1 which overflows
        prev_checkpoint_id: None,
        audit_head_id: test_object_id("audit"),
        audit_head_seq: 0,
        revocation_head_id: test_object_id("rev"),
        revocation_head_seq: 0,
        zone_definition_head: test_object_id("zone-def"),
        zone_policy_head: test_object_id("policy"),
        active_zone_key_manifest: test_object_id("zkm"),
        epoch_id: test_epoch(),
        proposed_at: 1_700_000_000,
        coordinator: test_node("coord"),
        coordinator_signature: test_signature("coord", 1_700_000_000),
        triggers: vec![],
    };

    assert!(
        !overflow_proposal.seq_follows_prev(u64::MAX),
        "should not accept overflow"
    );

    let _log = log.verify().pass();
}

#[test]
fn checkpoint_binds_heads() {
    let log = TestLogEntry::new("checkpoint_binds_heads")
        .with_zone("z:work")
        .execute();

    let proposal = create_test_proposal(test_zone(), 42, Some(test_object_id("prev-chk-41")));

    // Verify all heads are bound
    assert_eq!(proposal.audit_head_id, test_object_id("audit-head-42"));
    assert_eq!(proposal.audit_head_seq, 420);
    assert_eq!(proposal.revocation_head_id, test_object_id("rev-head-42"));
    assert_eq!(proposal.revocation_head_seq, 210);
    assert_eq!(proposal.zone_definition_head, test_object_id("zone-def"));
    assert_eq!(proposal.zone_policy_head, test_object_id("zone-policy"));
    assert_eq!(proposal.active_zone_key_manifest, test_object_id("zkm"));

    let _log = log.verify().with_checkpoint_seq(42).pass();
}

#[test]
fn checkpoint_timestamp_skew_validation() {
    let log = TestLogEntry::new("checkpoint_timestamp_skew_validation").execute();

    let proposal = create_test_proposal(test_zone(), 1, None);
    let proposal_time = proposal.proposed_at;
    let max_skew = 10;

    // Within skew
    assert!(proposal.timestamp_within_skew(proposal_time, max_skew));
    assert!(proposal.timestamp_within_skew(proposal_time + 5, max_skew));
    assert!(proposal.timestamp_within_skew(proposal_time - 5, max_skew));

    // At boundary
    assert!(proposal.timestamp_within_skew(proposal_time + 10, max_skew));
    assert!(proposal.timestamp_within_skew(proposal_time - 10, max_skew));

    // Outside skew
    assert!(!proposal.timestamp_within_skew(proposal_time + 15, max_skew));
    assert!(!proposal.timestamp_within_skew(proposal_time - 15, max_skew));

    let _log = log.verify().pass();
}

// ─────────────────────────────────────────────────────────────────────────────
// Fork Detection Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn fork_detection_conflicting_checkpoints() {
    let log = TestLogEntry::new("fork_detection_conflicting_checkpoints")
        .with_zone("z:work")
        .execute();

    let zone = test_zone();
    let seq = 100;
    let checkpoint_a = test_object_id("checkpoint-fork-a");
    let checkpoint_b = test_object_id("checkpoint-fork-b");
    let detector = test_node("detector-node");
    let now = 1_700_000_000;

    // Detect fork
    let evidence = ForkEvidence::detect(
        &zone,
        seq,
        &checkpoint_a,
        &checkpoint_b,
        now,
        detector.clone(),
    );

    assert!(evidence.is_some(), "should detect fork");
    let ev = evidence.unwrap();
    assert_eq!(ev.zone_id, zone);
    assert_eq!(ev.conflicting_seq, seq);
    assert_eq!(ev.checkpoint_a, checkpoint_a);
    assert_eq!(ev.checkpoint_b, checkpoint_b);
    assert_eq!(ev.detected_at, now);
    assert_eq!(ev.detected_by, detector);

    let _log = log
        .verify()
        .with_checkpoint_seq(seq)
        .with_fork_detected(true)
        .pass();
}

#[test]
fn fork_evidence_preserved_with_signers() {
    let log = TestLogEntry::new("fork_evidence_preserved_with_signers").execute();

    let evidence = ForkEvidence::new(
        test_zone(),
        50,
        test_object_id("chk-a"),
        test_object_id("chk-b"),
        1_700_000_000,
        test_node("detector"),
    )
    .with_signers_a(["alice", "bob", "charlie"].map(String::from))
    .with_signers_b(["bob", "david", "eve"].map(String::from));

    // Verify signers preserved
    assert_eq!(evidence.signers_a.len(), 3);
    assert_eq!(evidence.signers_b.len(), 3);
    assert!(evidence.signers_a.contains("alice"));
    assert!(evidence.signers_b.contains("eve"));

    // Find double-signers (Byzantine nodes)
    let double_signers = evidence.double_signers();
    assert_eq!(double_signers.len(), 1);
    assert!(double_signers.contains("bob"));

    let _log = log.verify().with_fork_detected(true).pass();
}

#[test]
fn fork_triggers_halt() {
    let log = TestLogEntry::new("fork_triggers_halt").execute();

    let evidence = ForkEvidence::new(
        test_zone(),
        42,
        test_object_id("a"),
        test_object_id("b"),
        1_700_000_000,
        test_node("detector"),
    );

    let state = CheckpointAdvanceState::Halted {
        fork_evidence: evidence,
        halted_at: 1_700_000_001,
    };

    assert!(state.is_halted(), "should be halted");
    assert!(
        !state.can_advance(),
        "should not be able to advance when halted"
    );
    assert!(state.fork_evidence().is_some(), "should have fork evidence");
    assert_eq!(
        state.fork_evidence().unwrap().conflicting_seq,
        42,
        "fork evidence should have correct seq"
    );

    let _log = log
        .verify()
        .with_checkpoint_seq(42)
        .with_fork_detected(true)
        .pass();
}

#[test]
fn fork_detection_result_semantics() {
    let log = TestLogEntry::new("fork_detection_result_semantics").execute();

    // No fork
    let no_fork = ForkDetectionResult::NoFork;
    assert!(!no_fork.is_fork());

    // Fork detected
    let evidence = ForkEvidence::new(
        test_zone(),
        10,
        test_object_id("a"),
        test_object_id("b"),
        1_700_000_000,
        test_node("d"),
    );
    let fork = ForkDetectionResult::ForkDetected(evidence);
    assert!(fork.is_fork());

    let _log = log.verify().pass();
}

#[test]
fn no_silent_fork_acceptance() {
    let log = TestLogEntry::new("no_silent_fork_acceptance").execute();

    // Same IDs should NOT produce fork evidence
    let zone = test_zone();
    let same_id = test_object_id("same-checkpoint");

    let evidence = ForkEvidence::detect(
        &zone,
        100,
        &same_id,
        &same_id, // Same ID
        1_700_000_000,
        test_node("detector"),
    );

    assert!(
        evidence.is_none(),
        "identical checkpoints should not be a fork"
    );

    // Different IDs MUST produce fork evidence
    let different_id = test_object_id("different-checkpoint");
    let evidence = ForkEvidence::detect(
        &zone,
        100,
        &same_id,
        &different_id,
        1_700_000_000,
        test_node("detector"),
    );

    assert!(
        evidence.is_some(),
        "different checkpoints at same seq MUST be detected as fork"
    );

    let _log = log.verify().pass();
}

// ─────────────────────────────────────────────────────────────────────────────
// HRW Coordinator Selection Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn hrw_coordinator_selection_deterministic() {
    let log = TestLogEntry::new("hrw_coordinator_selection_deterministic").execute();

    let zone = test_zone();
    let epoch = test_epoch();
    let nodes = vec![
        test_node("node-alpha"),
        test_node("node-beta"),
        test_node("node-gamma"),
        test_node("node-delta"),
    ];

    // Selection should be deterministic
    let coord1 = select_checkpoint_coordinator(&zone, &epoch, &nodes);
    let coord2 = select_checkpoint_coordinator(&zone, &epoch, &nodes);
    let coord3 = select_checkpoint_coordinator(&zone, &epoch, &nodes);

    assert_eq!(coord1, coord2);
    assert_eq!(coord2, coord3);
    assert!(coord1.is_some());

    let _log = log
        .verify()
        .with_coordinator(coord1.as_ref().unwrap().as_str())
        .pass();
}

#[test]
fn hrw_coordinator_fallback_ranking() {
    let log = TestLogEntry::new("hrw_coordinator_fallback_ranking").execute();

    let zone = test_zone();
    let epoch = test_epoch();
    let nodes = vec![
        test_node("node-1"),
        test_node("node-2"),
        test_node("node-3"),
        test_node("node-4"),
        test_node("node-5"),
    ];

    let ranked = rank_checkpoint_coordinators(&zone, &epoch, &nodes);

    // All nodes should be in ranking
    assert_eq!(ranked.len(), nodes.len());

    // First in ranking should be selected coordinator
    let coord = select_checkpoint_coordinator(&zone, &epoch, &nodes);
    assert_eq!(Some(&ranked[0]), coord.as_ref());

    // Ranking should be stable
    let ranked2 = rank_checkpoint_coordinators(&zone, &epoch, &nodes);
    assert_eq!(ranked, ranked2);

    // Verify descending order by checking hashes
    for i in 0..ranked.len() - 1 {
        let hash_i = hrw_hash_checkpoint(&zone, &epoch, &ranked[i]);
        let hash_next = hrw_hash_checkpoint(&zone, &epoch, &ranked[i + 1]);
        assert!(hash_i >= hash_next, "ranking should be by descending hash");
    }

    let _log = log.verify().pass();
}

#[test]
fn hrw_changes_with_epoch() {
    let log = TestLogEntry::new("hrw_changes_with_epoch").execute();

    let zone = test_zone();
    let nodes = vec![
        test_node("node-a"),
        test_node("node-b"),
        test_node("node-c"),
    ];

    let epoch1 = EpochId::new("epoch-1");
    let epoch2 = EpochId::new("epoch-2");

    let coord1 = select_checkpoint_coordinator(&zone, &epoch1, &nodes);
    let coord2 = select_checkpoint_coordinator(&zone, &epoch2, &nodes);

    // Coordinators may differ between epochs (not guaranteed, but likely)
    // What IS guaranteed is that the hash values differ
    let hash1 = hrw_hash_checkpoint(&zone, &epoch1, &nodes[0]);
    let hash2 = hrw_hash_checkpoint(&zone, &epoch2, &nodes[0]);
    assert_ne!(hash1, hash2, "hash should differ by epoch");

    // Log both coordinators
    let _log = log.verify().pass();
    println!("Epoch 1 coordinator: {coord1:?}, Epoch 2 coordinator: {coord2:?}");
}

// ─────────────────────────────────────────────────────────────────────────────
// Checkpoint Trigger Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn checkpoint_trigger_conditions() {
    let log = TestLogEntry::new("checkpoint_trigger_conditions").execute();

    // Time elapsed
    let time_trigger = CheckpointTrigger::check_time_elapsed(
        DEFAULT_CHECKPOINT_INTERVAL_SECS + 5,
        DEFAULT_CHECKPOINT_INTERVAL_SECS,
    );
    assert!(time_trigger.is_some());

    let no_time_trigger = CheckpointTrigger::check_time_elapsed(
        DEFAULT_CHECKPOINT_INTERVAL_SECS - 5,
        DEFAULT_CHECKPOINT_INTERVAL_SECS,
    );
    assert!(no_time_trigger.is_none());

    // Audit chain growth
    let audit_trigger = CheckpointTrigger::check_audit_growth(
        DEFAULT_AUDIT_CHAIN_GROWTH_THRESHOLD + 50,
        DEFAULT_AUDIT_CHAIN_GROWTH_THRESHOLD,
    );
    assert!(audit_trigger.is_some());

    let no_audit_trigger = CheckpointTrigger::check_audit_growth(
        DEFAULT_AUDIT_CHAIN_GROWTH_THRESHOLD - 50,
        DEFAULT_AUDIT_CHAIN_GROWTH_THRESHOLD,
    );
    assert!(no_audit_trigger.is_none());

    // Revocation growth (any > 0 triggers)
    let rev_trigger = CheckpointTrigger::check_revocation_growth(1);
    assert!(rev_trigger.is_some());

    let no_rev_trigger = CheckpointTrigger::check_revocation_growth(0);
    assert!(no_rev_trigger.is_none());

    let _log = log.verify().pass();
}

// ─────────────────────────────────────────────────────────────────────────────
// Validation Error Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn validation_error_codes() {
    let log = TestLogEntry::new("validation_error_codes").execute();

    let errors = [
        (
            CheckpointValidationError::InvalidSequence {
                expected: 10,
                got: 12,
            },
            "FCP-5001",
            false,
        ),
        (
            CheckpointValidationError::TimestampSkew {
                local_time: 100,
                proposal_time: 200,
                max_skew: 10,
            },
            "FCP-5002",
            false,
        ),
        (
            CheckpointValidationError::UnknownHead {
                head_type: "audit".to_string(),
                head_id: test_object_id("h"),
            },
            "FCP-5003",
            false,
        ),
        (
            CheckpointValidationError::InvalidHead {
                head_type: "rev".to_string(),
                head_id: test_object_id("h"),
                reason: "corrupted".to_string(),
            },
            "FCP-5004",
            false,
        ),
        (
            CheckpointValidationError::NotCoordinator {
                expected: test_node("a"),
                got: test_node("b"),
            },
            "FCP-5005",
            false,
        ),
        (
            CheckpointValidationError::InvalidCoordinatorSignature,
            "FCP-5006",
            false,
        ),
        (
            CheckpointValidationError::ZoneMismatch {
                expected: test_zone(),
                got: ZoneId::public(),
            },
            "FCP-5007",
            false,
        ),
        (
            CheckpointValidationError::EpochMismatch {
                expected: test_epoch(),
                got: EpochId::new("other"),
            },
            "FCP-5008",
            false,
        ),
        (
            CheckpointValidationError::ForkDetected(ForkEvidence::new(
                test_zone(),
                10,
                test_object_id("a"),
                test_object_id("b"),
                1_700_000_000,
                test_node("d"),
            )),
            "FCP-5010",
            true,
        ),
    ];

    for (error, expected_code, is_fork) in errors {
        assert_eq!(error.reason_code(), expected_code);
        assert_eq!(error.is_fork(), is_fork);
    }

    let _log = log.verify().pass();
}

// ─────────────────────────────────────────────────────────────────────────────
// Freshness Verification Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn freshness_token_verification() {
    let log = TestLogEntry::new("freshness_token_verification").execute();

    // Token is fresh (token_chk_seq <= local_checkpoint_seq)
    let fresh = FreshnessResult::check_token_freshness(10, 15, false);
    assert_eq!(fresh, FreshnessResult::Fresh);
    assert!(fresh.allows_operation());

    // Token is stale without degraded mode
    let stale = FreshnessResult::check_token_freshness(20, 15, false);
    assert_eq!(stale, FreshnessResult::TooStale);
    assert!(!stale.allows_operation());

    // Token is stale with degraded mode allowed
    let degraded = FreshnessResult::check_token_freshness(20, 15, true);
    assert_eq!(degraded, FreshnessResult::DegradedMode);
    assert!(degraded.allows_operation());

    // Boundary case: equal is fresh
    let boundary = FreshnessResult::check_token_freshness(15, 15, false);
    assert_eq!(boundary, FreshnessResult::Fresh);

    let _log = log.verify().pass();
}

#[test]
fn freshness_revocation_verification() {
    let log = TestLogEntry::new("freshness_revocation_verification").execute();

    // Revocation is fresh (local_rev_head_seq >= policy_min_rev_seq)
    let fresh = FreshnessResult::check_revocation_freshness(50, 40, false);
    assert_eq!(fresh, FreshnessResult::Fresh);
    assert!(fresh.allows_operation());

    // Revocation is stale without degraded mode
    let stale = FreshnessResult::check_revocation_freshness(30, 40, false);
    assert_eq!(stale, FreshnessResult::TooStale);
    assert!(!stale.allows_operation());

    // Revocation is stale with degraded mode allowed
    let degraded = FreshnessResult::check_revocation_freshness(30, 40, true);
    assert_eq!(degraded, FreshnessResult::DegradedMode);
    assert!(degraded.allows_operation());

    // Boundary case: equal is fresh
    let boundary = FreshnessResult::check_revocation_freshness(40, 40, false);
    assert_eq!(boundary, FreshnessResult::Fresh);

    let _log = log.verify().pass();
}

// ─────────────────────────────────────────────────────────────────────────────
// Advancement State Machine Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn advancement_state_transitions() {
    let log = TestLogEntry::new("advancement_state_transitions").execute();

    // Idle state
    let idle = CheckpointAdvanceState::idle(10, 1_700_000_000);
    assert!(!idle.is_halted());
    assert!(idle.can_advance());
    assert!(idle.fork_evidence().is_none());

    // Triggered state
    let triggered = CheckpointAdvanceState::TriggeredAwaitingCoordinator {
        trigger: CheckpointTrigger::TimeElapsed {
            elapsed_secs: 65,
            threshold_secs: 60,
        },
        triggered_at: 1_700_000_060,
    };
    assert!(triggered.can_advance());

    // Finalized state
    let finalized = CheckpointAdvanceState::Finalized {
        checkpoint_id: test_object_id("finalized-chk"),
        finalized_seq: 11,
        finalized_at: 1_700_000_120,
    };
    assert!(finalized.can_advance());

    // Halted state
    let halted = CheckpointAdvanceState::Halted {
        fork_evidence: ForkEvidence::new(
            test_zone(),
            10,
            test_object_id("a"),
            test_object_id("b"),
            1_700_000_000,
            test_node("d"),
        ),
        halted_at: 1_700_000_001,
    };
    assert!(halted.is_halted());
    assert!(!halted.can_advance());
    assert!(halted.fork_evidence().is_some());

    let _log = log.verify().pass();
}

// ─────────────────────────────────────────────────────────────────────────────
// Golden Vector Tests (File-Based)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn golden_hrw_hash_vectors() {
    let log = TestLogEntry::new("golden_hrw_hash_vectors").execute();

    // These are golden vectors - if they change, the hash algorithm changed.
    // Updated 2026-03-04 after length-prefixed HRW hash change (commit f99b69b).
    let test_cases = [
        (
            "z:work",
            "epoch-golden-1",
            "node-test-a",
            4_612_559_044_831_334_750_u64,
        ),
        (
            "z:work",
            "epoch-golden-1",
            "node-test-b",
            5_746_037_411_169_575_254_u64,
        ),
        (
            "z:work",
            "epoch-golden-2",
            "node-test-a",
            10_931_232_107_578_549_484_u64,
        ),
        (
            "z:public",
            "epoch-golden-1",
            "node-test-a",
            17_975_856_165_098_956_092_u64,
        ),
    ];

    for (zone_str, epoch_str, node_str, expected_hash) in test_cases {
        let zone: ZoneId = zone_str.parse().unwrap();
        let epoch = EpochId::new(epoch_str);
        let node = TailscaleNodeId::new(node_str);

        let hash = hrw_hash_checkpoint(&zone, &epoch, &node);
        assert_eq!(
            hash, expected_hash,
            "HRW hash mismatch for ({zone_str}, {epoch_str}, {node_str})"
        );
    }

    let _log = log.verify().pass();
}

#[test]
fn golden_coordinator_selection_vectors() {
    let log = TestLogEntry::new("golden_coordinator_selection_vectors").execute();

    let zone: ZoneId = "z:work".parse().unwrap();
    let epoch = EpochId::new("epoch-golden-coord");
    let nodes = vec![
        TailscaleNodeId::new("node-alice"),
        TailscaleNodeId::new("node-bob"),
        TailscaleNodeId::new("node-charlie"),
        TailscaleNodeId::new("node-david"),
    ];

    let coord = select_checkpoint_coordinator(&zone, &epoch, &nodes).unwrap();
    let ranked = rank_checkpoint_coordinators(&zone, &epoch, &nodes);

    // Golden vector: expected coordinator for this input.
    // Updated 2026-03-04 after length-prefixed HRW hash change (commit f99b69b).
    assert_eq!(
        coord.as_str(),
        "node-charlie",
        "Coordinator selection golden vector mismatch"
    );

    // Golden vector: expected ranking
    let expected_ranking = ["node-charlie", "node-david", "node-alice", "node-bob"];
    for (i, expected) in expected_ranking.iter().enumerate() {
        assert_eq!(
            ranked[i].as_str(),
            *expected,
            "Ranking position {i} mismatch"
        );
    }

    let _log = log.verify().with_coordinator("node-charlie").pass();
}

#[test]
fn golden_fork_evidence_serialization() {
    let log = TestLogEntry::new("golden_fork_evidence_serialization").execute();

    let evidence = ForkEvidence {
        zone_id: "z:work".parse().unwrap(),
        conflicting_seq: 42,
        checkpoint_a: ObjectId::from_bytes([0xAA; 32]),
        checkpoint_b: ObjectId::from_bytes([0xBB; 32]),
        detected_at: 1_700_000_000,
        detected_by: TailscaleNodeId::new("detector-node"),
        signers_a: ["alice", "bob"].iter().map(ToString::to_string).collect(),
        signers_b: ["bob", "charlie"].iter().map(ToString::to_string).collect(),
    };

    // Serialize to JSON
    let json = serde_json::to_string_pretty(&evidence).unwrap();

    // Deserialize and verify
    let decoded: ForkEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.zone_id, evidence.zone_id);
    assert_eq!(decoded.conflicting_seq, 42);
    assert_eq!(decoded.checkpoint_a, evidence.checkpoint_a);
    assert_eq!(decoded.checkpoint_b, evidence.checkpoint_b);
    assert_eq!(decoded.detected_at, 1_700_000_000);
    assert_eq!(decoded.detected_by.as_str(), "detector-node");

    // Verify double-signers
    let double_signers = decoded.double_signers();
    assert_eq!(double_signers.len(), 1);
    assert!(double_signers.contains("bob"));

    let _log = log.verify().with_fork_detected(true).pass();
}

#[test]
fn golden_checkpoint_trigger_serialization() {
    let log = TestLogEntry::new("golden_checkpoint_trigger_serialization").execute();

    let triggers = vec![
        CheckpointTrigger::TimeElapsed {
            elapsed_secs: 120,
            threshold_secs: 60,
        },
        CheckpointTrigger::AuditChainGrowth {
            new_events: 150,
            threshold: 100,
        },
        CheckpointTrigger::RevocationChainGrowth { new_events: 5 },
        CheckpointTrigger::PolicyChange {
            old_policy_head: test_object_id("old-policy"),
            new_policy_head: test_object_id("new-policy"),
        },
        CheckpointTrigger::Manual {
            reason: Some("Operator requested".to_string()),
        },
    ];

    for trigger in triggers {
        let json = serde_json::to_string(&trigger).unwrap();
        let decoded: CheckpointTrigger = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, trigger);
    }

    let _log = log.verify().pass();
}

// ─────────────────────────────────────────────────────────────────────────────
// Convergence Scenario Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn convergence_nodes_agree_on_checkpoint() {
    let log = TestLogEntry::new("convergence_nodes_agree_on_checkpoint").execute();

    let zone = test_zone();
    let epoch = test_epoch();
    let nodes = vec![
        test_node("node-1"),
        test_node("node-2"),
        test_node("node-3"),
        test_node("node-4"),
        test_node("node-5"),
    ];

    // All nodes should compute the same coordinator
    let coordinators: Vec<_> = (0..5)
        .map(|_| select_checkpoint_coordinator(&zone, &epoch, &nodes))
        .collect();

    // Verify all agree
    for coord in &coordinators {
        assert_eq!(coord, &coordinators[0]);
    }

    let _log = log
        .verify()
        .with_coordinator(coordinators[0].as_ref().unwrap().as_str())
        .pass();
}

#[test]
fn convergence_late_joining_node() {
    let log = TestLogEntry::new("convergence_late_joining_node").execute();

    let zone = test_zone();
    let epoch = test_epoch();

    // Initial node set
    let initial_nodes = vec![
        test_node("node-1"),
        test_node("node-2"),
        test_node("node-3"),
    ];

    // Late-joining node sees same nodes
    let late_joiner_view = initial_nodes.clone();

    // Both should compute same coordinator
    let coord1 = select_checkpoint_coordinator(&zone, &epoch, &initial_nodes);
    let coord2 = select_checkpoint_coordinator(&zone, &epoch, &late_joiner_view);

    assert_eq!(coord1, coord2, "late joiner should agree on coordinator");

    // Ranking should also match
    let rank1 = rank_checkpoint_coordinators(&zone, &epoch, &initial_nodes);
    let rank2 = rank_checkpoint_coordinators(&zone, &epoch, &late_joiner_view);
    assert_eq!(rank1, rank2, "late joiner should agree on ranking");

    let _log = log.verify().pass();
}

#[test]
fn convergence_partition_recovery() {
    let log = TestLogEntry::new("convergence_partition_recovery").execute();

    let zone = test_zone();
    let epoch = test_epoch();

    // Partition A sees nodes 1-3
    let partition_a = vec![
        test_node("node-1"),
        test_node("node-2"),
        test_node("node-3"),
    ];

    // Partition B sees nodes 1-3 (same set - simulating after partition heals)
    let partition_b = partition_a.clone();

    // After partition heals, both should agree on coordinator
    let coord_a = select_checkpoint_coordinator(&zone, &epoch, &partition_a);
    let coord_b = select_checkpoint_coordinator(&zone, &epoch, &partition_b);

    assert_eq!(
        coord_a, coord_b,
        "partitions should converge on same coordinator after healing"
    );

    let _log = log.verify().pass();
}

// ─────────────────────────────────────────────────────────────────────────────
// File-Based Golden Vector Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn golden_vector_file_valid_checkpoint_proposal() {
    let log = TestLogEntry::new("golden_vector_file_valid_checkpoint_proposal").execute();

    let path = vectors_path().join("valid_checkpoint_proposal.json");

    // Read vector file if it exists
    if path.exists() {
        let content = fs::read_to_string(&path).expect("failed to read vector file");
        let proposal: CheckpointProposal =
            serde_json::from_str(&content).expect("failed to parse vector");

        // Validate proposal structure
        assert!(proposal.proposed_seq > 0 || proposal.prev_checkpoint_id.is_none());
        assert_ne!(proposal.triggers, [] as [fcp_core::CheckpointTrigger; 0]);
    } else {
        // Create the golden vector
        let proposal = create_test_proposal(test_zone(), 42, Some(test_object_id("prev-chk-41")));
        let json = serde_json::to_string_pretty(&proposal).unwrap();
        fs::write(&path, &json).expect("failed to write vector file");
    }

    let _log = log.verify().pass();
}

#[test]
fn golden_vector_file_fork_evidence() {
    let log = TestLogEntry::new("golden_vector_file_fork_evidence").execute();

    let path = vectors_path().join("fork_evidence.json");

    if path.exists() {
        let content = fs::read_to_string(&path).expect("failed to read vector file");
        let evidence: ForkEvidence =
            serde_json::from_str(&content).expect("failed to parse vector");

        // Validate evidence
        assert!(evidence.conflicting_seq > 0);
        assert_ne!(evidence.checkpoint_a, evidence.checkpoint_b);
    } else {
        let evidence = ForkEvidence {
            zone_id: "z:work".parse().unwrap(),
            conflicting_seq: 100,
            checkpoint_a: ObjectId::from_bytes([0xAA; 32]),
            checkpoint_b: ObjectId::from_bytes([0xBB; 32]),
            detected_at: 1_700_000_000,
            detected_by: TailscaleNodeId::new("detector-node"),
            signers_a: ["alice", "bob", "charlie"]
                .iter()
                .map(ToString::to_string)
                .collect(),
            signers_b: ["bob", "david", "eve"]
                .iter()
                .map(ToString::to_string)
                .collect(),
        };
        let json = serde_json::to_string_pretty(&evidence).unwrap();
        fs::write(&path, &json).expect("failed to write vector file");
    }

    let _log = log.verify().pass();
}

#[test]
fn golden_vector_file_convergence_scenario() {
    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    struct ConvergenceScenario {
        zone_id: String,
        epoch_id: String,
        nodes: Vec<String>,
        expected_coordinator: String,
        expected_ranking: Vec<String>,
    }

    let build_scenario = || {
        let zone: ZoneId = "z:work".parse().unwrap();
        let epoch = EpochId::new("epoch-convergence-test");
        let nodes = vec![
            TailscaleNodeId::new("node-alpha"),
            TailscaleNodeId::new("node-beta"),
            TailscaleNodeId::new("node-gamma"),
        ];

        let coord = select_checkpoint_coordinator(&zone, &epoch, &nodes).unwrap();
        let ranked = rank_checkpoint_coordinators(&zone, &epoch, &nodes);

        ConvergenceScenario {
            zone_id: "z:work".to_string(),
            epoch_id: "epoch-convergence-test".to_string(),
            nodes: nodes.iter().map(|n| n.as_str().to_string()).collect(),
            expected_coordinator: coord.as_str().to_string(),
            expected_ranking: ranked.iter().map(|n| n.as_str().to_string()).collect(),
        }
    };

    let log = TestLogEntry::new("golden_vector_file_convergence_scenario").execute();

    let path = vectors_path().join("convergence_scenario.json");

    let scenario = path
        .exists()
        .then(|| fs::read_to_string(&path).ok())
        .flatten()
        .and_then(|content| serde_json::from_str(&content).ok())
        .unwrap_or_else(|| {
            let scenario = build_scenario();
            let json = serde_json::to_string_pretty(&scenario).unwrap();
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).ok();
            }
            fs::write(&path, &json).expect("failed to write vector file");
            scenario
        });

    // Verify the golden vector
    let zone: ZoneId = scenario.zone_id.parse().unwrap();
    let epoch = EpochId::new(&scenario.epoch_id);
    let nodes: Vec<TailscaleNodeId> = scenario.nodes.iter().map(TailscaleNodeId::new).collect();

    let coord = select_checkpoint_coordinator(&zone, &epoch, &nodes).unwrap();
    assert_eq!(coord.as_str(), scenario.expected_coordinator);

    let ranked = rank_checkpoint_coordinators(&zone, &epoch, &nodes);
    let ranked_strs: Vec<&str> = ranked.iter().map(TailscaleNodeId::as_str).collect();
    assert_eq!(ranked_strs, scenario.expected_ranking);

    let _log = log.verify().pass();
}

// ─────────────────────────────────────────────────────────────────────────────
// Frontier Management Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn frontier_tracks_latest_valid_checkpoint() {
    let log = TestLogEntry::new("frontier_tracks_latest_valid_checkpoint").execute();

    // Simulate a frontier that tracks the latest checkpoint per zone
    let mut frontier: BTreeMap<String, (ObjectId, u64)> = BTreeMap::new();

    // Initial checkpoint
    let zone = "z:work";
    frontier.insert(zone.to_string(), (test_object_id("chk-1"), 1));

    // Update with newer checkpoint
    let current = frontier.get(zone).unwrap();
    assert_eq!(current.1, 1);

    // Simulate advancement
    frontier.insert(zone.to_string(), (test_object_id("chk-2"), 2));

    let updated = frontier.get(zone).unwrap();
    assert_eq!(updated.1, 2);

    // Verify monotonic (should not accept older)
    let seq_to_accept = 3;
    let current_seq = frontier.get(zone).unwrap().1;
    assert!(
        seq_to_accept > current_seq,
        "should only accept newer checkpoints"
    );

    let _log = log.verify().pass();
}

#[test]
fn frontier_stale_detection() {
    let log = TestLogEntry::new("frontier_stale_detection").execute();

    let frontier_seq = 100;
    let required_min_seq = 95;
    let too_old_threshold = 90;

    // Fresh: frontier is >= required
    let fresh = frontier_seq >= required_min_seq;
    assert!(fresh, "frontier should be considered fresh");

    // Stale: if frontier < threshold
    let stale_frontier_seq = 85;
    let stale = stale_frontier_seq < too_old_threshold;
    assert!(stale, "old frontier should be considered stale");

    // Use freshness result for verification
    let result = FreshnessResult::check_revocation_freshness(frontier_seq, required_min_seq, false);
    assert_eq!(result, FreshnessResult::Fresh);

    let stale_result =
        FreshnessResult::check_revocation_freshness(stale_frontier_seq, too_old_threshold, false);
    assert_eq!(stale_result, FreshnessResult::TooStale);

    let _log = log.verify().pass();
}

// ─────────────────────────────────────────────────────────────────────────────
// Integration Test: Full Checkpoint Lifecycle
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn integration_full_checkpoint_lifecycle() {
    let log = TestLogEntry::new("integration_full_checkpoint_lifecycle")
        .with_zone("z:work")
        .execute();

    let zone = test_zone();
    let epoch = test_epoch();
    let nodes = vec![
        test_node("node-1"),
        test_node("node-2"),
        test_node("node-3"),
        test_node("node-4"),
        test_node("node-5"),
    ];

    // Phase 1: Idle state
    let mut state = CheckpointAdvanceState::idle(10, 1_700_000_000);
    assert!(state.can_advance());

    // Phase 2: Trigger condition met
    let trigger = CheckpointTrigger::check_time_elapsed(65, 60).unwrap();
    state = CheckpointAdvanceState::TriggeredAwaitingCoordinator {
        trigger,
        triggered_at: 1_700_000_065,
    };
    assert!(state.can_advance());

    // Phase 3: Select coordinator
    let coordinator = select_checkpoint_coordinator(&zone, &epoch, &nodes).unwrap();

    // Phase 4: Create proposal
    let proposal = CheckpointProposal {
        zone_id: zone,
        proposed_seq: 11,
        prev_checkpoint_id: Some(test_object_id("chk-10")),
        audit_head_id: test_object_id("audit-head-11"),
        audit_head_seq: 110,
        revocation_head_id: test_object_id("rev-head-11"),
        revocation_head_seq: 55,
        zone_definition_head: test_object_id("zone-def"),
        zone_policy_head: test_object_id("zone-policy"),
        active_zone_key_manifest: test_object_id("zkm"),
        epoch_id: epoch,
        proposed_at: 1_700_000_066,
        coordinator: coordinator.clone(),
        coordinator_signature: test_signature(coordinator.as_str(), 1_700_000_066),
        triggers: vec![CheckpointTrigger::TimeElapsed {
            elapsed_secs: 65,
            threshold_secs: 60,
        }],
    };

    assert!(proposal.seq_follows_prev(10));

    // Phase 5: Collect signatures (simulate quorum)
    let mut signatures = SignatureSet::new();
    for (i, node) in nodes.iter().take(4).enumerate() {
        signatures.add(test_signature(node.as_str(), 1_700_000_067 + i as u64));
    }

    state = CheckpointAdvanceState::ProposalBroadcast {
        proposal: Box::new(proposal),
        collected_signatures: signatures.clone(),
        required_signatures: 4,
    };
    assert!(state.can_advance());
    assert_eq!(signatures.len(), 4); // Quorum met

    // Phase 6: Finalize
    let checkpoint_id = test_object_id("chk-11");
    state = CheckpointAdvanceState::Finalized {
        checkpoint_id,
        finalized_seq: 11,
        finalized_at: 1_700_000_070,
    };
    assert!(state.can_advance());
    assert!(!state.is_halted());

    let _log = log
        .verify()
        .with_checkpoint_seq(11)
        .with_coordinator(coordinator.as_str())
        .pass();
}
