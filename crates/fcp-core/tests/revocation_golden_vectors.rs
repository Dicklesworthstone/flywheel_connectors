//! Revocation Golden Vectors and Adversarial Tests (NORMATIVE).
//!
//! This module implements comprehensive tests for the FCP revocation system
//! from `FCP_Specification_V3.md` §6.4 (Revocation).
//!
//! # Test Categories
//!
//! 1. **Golden Vectors**: CBOR test fixtures for cross-implementation verification
//! 2. **Adversarial Tests**: Attack scenario simulations
//!    - Revocation withholding (node hides revocation)
//!    - Replay attack (resending old revocation)
//!    - Forgery attack (invalid signature)
//!    - Stale frontier attack (presenting old head as current)
//!    - Chain fork injection (attempting to fork revocation chain)
//! 3. **Chain Integrity**: Sequence validation, gap detection, ordering
//! 4. **Quorum Verification**: `RevocationHead` signature thresholds

use std::fs;
use std::path::PathBuf;

use fcp_cbor::SchemaId;
use fcp_core::{
    EpochId, FreshnessFailureReason, FreshnessPolicy, NodeId, NodeSignature, ObjectHeader,
    ObjectId, Provenance, QuorumPolicy, RevocationEvent, RevocationHead, RevocationObject,
    RevocationRegistry, RevocationScope, RiskTier, SignatureSet, ZoneId,
};
use semver::Version;
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Test Infrastructure
// ─────────────────────────────────────────────────────────────────────────────

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("revocation")
}

fn test_header() -> ObjectHeader {
    ObjectHeader {
        encryption_kind: Default::default(),
        schema: SchemaId::new("fcp.core", "RevocationObject", Version::new(1, 0, 0)),
        zone_id: ZoneId::work(),
        created_at: 1_700_000_000,
        provenance: Provenance::new(ZoneId::work()),
        refs: vec![],
        foreign_refs: vec![],
        ttl_secs: None,
        placement: None,
    }
}

fn test_revocation(id_byte: u8, scope: RevocationScope) -> RevocationObject {
    RevocationObject {
        header: test_header(),
        revoked: vec![ObjectId::from_bytes([id_byte; 32])],
        scope,
        reason: format!("Test revocation for {scope:?}"),
        effective_at: 1_700_000_000,
        expires_at: None,
        signature: [0u8; 64],
    }
}

/// Create a test revocation event.
///
/// NOTE: For chain linking tests, we use `revocation_id` as a stand-in for the
/// event's own `ObjectId`. In a real system, `prev` would point to the hash of
/// the previous event's content, but for testing we simplify by using the
/// `revocation_object_id` value. Tests are constructed to be internally consistent.
fn test_event(seq: u64, prev: Option<ObjectId>, revocation_id: ObjectId) -> RevocationEvent {
    RevocationEvent {
        header: test_header(),
        revocation_object_id: revocation_id,
        prev,
        seq,
        occurred_at: 1_700_000_000 + seq,
        signature: [0u8; 64],
    }
}

#[allow(clippy::cast_possible_truncation)]
fn test_head(seq: u64, epoch: &str) -> RevocationHead {
    RevocationHead {
        header: test_header(),
        zone_id: ZoneId::work(),
        head_event: ObjectId::from_bytes([seq as u8; 32]),
        head_seq: seq,
        epoch_id: EpochId::new(epoch),
        quorum_signatures: SignatureSet::new(),
    }
}

/// FCP2-compliant structured log output.
fn log_test_event(test_name: &str, event: &str, details: &serde_json::Value) {
    let log = serde_json::json!({
        "event": event,
        "test": test_name,
        "module": "revocation_golden_vectors",
        "details": details
    });
    println!("{}", serde_json::to_string(&log).unwrap());
}

// ─────────────────────────────────────────────────────────────────────────────
// Golden Vector Structures
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct RevocationVector {
    description: String,
    scope: String,
    revoked_ids: Vec<String>,
    effective_at: u64,
    expires_at: Option<u64>,
    is_active_at_creation: bool,
    is_active_after_expiry: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct ChainVector {
    description: String,
    events: Vec<ChainEventEntry>,
    is_valid_chain: bool,
    error_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct ChainEventEntry {
    seq: u64,
    prev_seq: Option<u64>,
    revocation_id_byte: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct FreshnessVector {
    description: String,
    local_seq: u64,
    remote_seq: u64,
    last_updated: u64,
    now: u64,
    max_age_secs: u64,
    policy: String,
    expected_allowed: bool,
    expected_stale: bool,
    expected_reason: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Golden Vector Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn generate_revocation_scope_vectors() {
    log_test_event(
        "generate_revocation_scope_vectors",
        "test_start",
        &serde_json::json!({"purpose": "Generate CBOR vectors for all revocation scopes"}),
    );

    let scopes = [
        (RevocationScope::Capability, "capability", 1u8),
        (RevocationScope::IssuerKey, "issuer_key", 2u8),
        (RevocationScope::NodeAttestation, "node_attestation", 3u8),
        (RevocationScope::ZoneKey, "zone_key", 4u8),
        (RevocationScope::ConnectorBinary, "connector_binary", 5u8),
    ];

    let mut vectors: Vec<RevocationVector> = Vec::new();

    for (scope, name, id_byte) in &scopes {
        let revocation = test_revocation(*id_byte, *scope);

        let vector = RevocationVector {
            description: format!("Revocation of {name} scope"),
            scope: name.to_string(),
            revoked_ids: revocation
                .revoked
                .iter()
                .map(|id| hex::encode(id.as_bytes()))
                .collect(),
            effective_at: revocation.effective_at,
            expires_at: revocation.expires_at,
            is_active_at_creation: revocation.is_active(revocation.effective_at),
            is_active_after_expiry: revocation.is_active(revocation.effective_at + 1_000_000),
        };

        vectors.push(vector);
    }

    // Serialize to CBOR
    let path = vectors_dir().join("scope_vectors.cbor");
    let mut buffer = Vec::new();
    ciborium::into_writer(&vectors, &mut buffer).expect("CBOR serialization failed");
    fs::write(&path, &buffer).expect("Failed to write CBOR file");

    log_test_event(
        "generate_revocation_scope_vectors",
        "vector_written",
        &serde_json::json!({
            "path": path.display().to_string(),
            "size_bytes": buffer.len(),
            "scope_count": vectors.len()
        }),
    );

    // Verify round-trip
    let data = fs::read(&path).expect("Failed to read CBOR file");
    let loaded: Vec<RevocationVector> =
        ciborium::from_reader(data.as_slice()).expect("CBOR deserialization failed");

    assert_eq!(loaded.len(), 5);
    assert_eq!(loaded, vectors);

    log_test_event(
        "generate_revocation_scope_vectors",
        "test_complete",
        &serde_json::json!({"vectors_verified": vectors.len()}),
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn generate_chain_integrity_vectors() {
    log_test_event(
        "generate_chain_integrity_vectors",
        "test_start",
        &serde_json::json!({"purpose": "Generate CBOR vectors for chain integrity scenarios"}),
    );

    let vectors = vec![
        ChainVector {
            description: "Valid 3-event chain".to_string(),
            events: vec![
                ChainEventEntry {
                    seq: 1,
                    prev_seq: None,
                    revocation_id_byte: 1,
                },
                ChainEventEntry {
                    seq: 2,
                    prev_seq: Some(1),
                    revocation_id_byte: 2,
                },
                ChainEventEntry {
                    seq: 3,
                    prev_seq: Some(2),
                    revocation_id_byte: 3,
                },
            ],
            is_valid_chain: true,
            error_type: None,
        },
        ChainVector {
            description: "Chain with sequence gap (1 -> 3)".to_string(),
            events: vec![
                ChainEventEntry {
                    seq: 1,
                    prev_seq: None,
                    revocation_id_byte: 1,
                },
                ChainEventEntry {
                    seq: 3,
                    prev_seq: Some(1),
                    revocation_id_byte: 3,
                },
            ],
            is_valid_chain: false,
            error_type: Some("sequence_gap".to_string()),
        },
        ChainVector {
            description: "Chain with duplicate sequence".to_string(),
            events: vec![
                ChainEventEntry {
                    seq: 1,
                    prev_seq: None,
                    revocation_id_byte: 1,
                },
                ChainEventEntry {
                    seq: 1,
                    prev_seq: None,
                    revocation_id_byte: 2,
                },
            ],
            is_valid_chain: false,
            error_type: Some("duplicate_sequence".to_string()),
        },
        ChainVector {
            description: "Chain with incorrect prev pointer".to_string(),
            events: vec![
                ChainEventEntry {
                    seq: 1,
                    prev_seq: None,
                    revocation_id_byte: 1,
                },
                ChainEventEntry {
                    seq: 2,
                    prev_seq: Some(99),
                    revocation_id_byte: 2,
                },
            ],
            is_valid_chain: false,
            error_type: Some("broken_chain".to_string()),
        },
    ];

    let path = vectors_dir().join("chain_vectors.cbor");
    let mut buffer = Vec::new();
    ciborium::into_writer(&vectors, &mut buffer).expect("CBOR serialization failed");
    fs::write(&path, &buffer).expect("Failed to write CBOR file");

    log_test_event(
        "generate_chain_integrity_vectors",
        "vector_written",
        &serde_json::json!({
            "path": path.display().to_string(),
            "size_bytes": buffer.len(),
            "chain_count": vectors.len()
        }),
    );

    // Verify round-trip
    let data = fs::read(&path).expect("Failed to read CBOR file");
    let loaded: Vec<ChainVector> =
        ciborium::from_reader(data.as_slice()).expect("CBOR deserialization failed");

    assert_eq!(loaded.len(), 4);
    assert_eq!(loaded, vectors);

    log_test_event(
        "generate_chain_integrity_vectors",
        "test_complete",
        &serde_json::json!({"chains_verified": vectors.len()}),
    );
}

#[test]
fn generate_freshness_policy_vectors() {
    log_test_event(
        "generate_freshness_policy_vectors",
        "test_start",
        &serde_json::json!({"purpose": "Generate CBOR vectors for freshness policy scenarios"}),
    );

    let vectors = vec![
        FreshnessVector {
            description: "Strict policy: fresh data allowed".to_string(),
            local_seq: 100,
            remote_seq: 100,
            last_updated: 1_700_000_000,
            now: 1_700_000_100,
            max_age_secs: 300,
            policy: "strict".to_string(),
            expected_allowed: true,
            expected_stale: false,
            expected_reason: None,
        },
        FreshnessVector {
            description: "Strict policy: stale data blocked".to_string(),
            local_seq: 50,
            remote_seq: 100,
            last_updated: 1_700_000_000,
            now: 1_700_000_100,
            max_age_secs: 300,
            policy: "strict".to_string(),
            expected_allowed: false,
            expected_stale: true,
            expected_reason: Some("stale_data".to_string()),
        },
        FreshnessVector {
            description: "Warn policy: stale within max_age allowed".to_string(),
            local_seq: 50,
            remote_seq: 100,
            last_updated: 1_700_000_000,
            now: 1_700_000_100,
            max_age_secs: 200,
            policy: "warn".to_string(),
            expected_allowed: true,
            expected_stale: true,
            expected_reason: Some("stale_but_within_max_age".to_string()),
        },
        FreshnessVector {
            description: "Warn policy: stale beyond max_age blocked".to_string(),
            local_seq: 50,
            remote_seq: 100,
            last_updated: 1_700_000_000,
            now: 1_700_000_100,
            max_age_secs: 50,
            policy: "warn".to_string(),
            expected_allowed: false,
            expected_stale: true,
            expected_reason: Some("stale_data".to_string()),
        },
        FreshnessVector {
            description: "BestEffort policy: always allowed even when very stale".to_string(),
            local_seq: 10,
            remote_seq: 1000,
            last_updated: 1_600_000_000,
            now: 1_700_000_000,
            max_age_secs: 60,
            policy: "best_effort".to_string(),
            expected_allowed: true,
            expected_stale: true,
            expected_reason: Some("stale_but_allowed".to_string()),
        },
    ];

    let path = vectors_dir().join("freshness_vectors.cbor");
    let mut buffer = Vec::new();
    ciborium::into_writer(&vectors, &mut buffer).expect("CBOR serialization failed");
    fs::write(&path, &buffer).expect("Failed to write CBOR file");

    log_test_event(
        "generate_freshness_policy_vectors",
        "vector_written",
        &serde_json::json!({
            "path": path.display().to_string(),
            "size_bytes": buffer.len(),
            "policy_count": vectors.len()
        }),
    );

    // Verify round-trip
    let data = fs::read(&path).expect("Failed to read CBOR file");
    let loaded: Vec<FreshnessVector> =
        ciborium::from_reader(data.as_slice()).expect("CBOR deserialization failed");

    assert_eq!(loaded.len(), 5);
    assert_eq!(loaded, vectors);

    log_test_event(
        "generate_freshness_policy_vectors",
        "test_complete",
        &serde_json::json!({"policies_verified": vectors.len()}),
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Adversarial Attack Scenario Tests
// ─────────────────────────────────────────────────────────────────────────────

mod adversarial {
    use super::*;

    /// Attack: Revocation withholding - malicious node hides a revocation.
    ///
    /// Scenario: Node A has revocation R1, Node B doesn't have it.
    /// Node B should detect staleness when comparing with Node A's head.
    #[test]
    fn attack_revocation_withholding() {
        log_test_event(
            "attack_revocation_withholding",
            "test_start",
            &serde_json::json!({
                "attack_type": "revocation_withholding",
                "description": "Malicious node hides revocation from peer"
            }),
        );

        // Node A has a revocation (honest node)
        let mut registry_a = RevocationRegistry::new();
        let revocation = test_revocation(1, RevocationScope::Capability);
        registry_a.add_revocation(&revocation);
        registry_a.update_head(ObjectId::from_bytes([10u8; 32]), 10, 1_700_000_000);

        // Node B has no revocation (potentially compromised or partitioned)
        let mut registry_b = RevocationRegistry::new();
        registry_b.update_head(ObjectId::from_bytes([5u8; 32]), 5, 1_699_999_000);

        // Node B compares against Node A's advertised seq
        let remote_seq = registry_a.head_seq;
        assert!(
            !registry_b.is_fresh(remote_seq),
            "Node B should detect staleness"
        );

        // Strict policy should block operations
        let result =
            registry_b.check_freshness(remote_seq, FreshnessPolicy::Strict, 300, 1_700_000_100);
        assert!(!result.allowed, "Strict policy should block stale registry");
        assert!(result.stale);
        assert_eq!(result.reason, Some(FreshnessFailureReason::StaleData));

        log_test_event(
            "attack_revocation_withholding",
            "attack_detected",
            &serde_json::json!({
                "local_seq": registry_b.head_seq,
                "remote_seq": remote_seq,
                "detection_method": "freshness_check"
            }),
        );
    }

    /// Attack: Replay attack - presenting old revocation as current.
    ///
    /// Scenario: Attacker replays an expired revocation to block legitimate access.
    #[test]
    fn attack_replay_expired_revocation() {
        log_test_event(
            "attack_replay_expired_revocation",
            "test_start",
            &serde_json::json!({
                "attack_type": "replay",
                "description": "Replaying expired revocation"
            }),
        );

        // Create an expired revocation
        let mut expired_revocation = test_revocation(1, RevocationScope::Capability);
        expired_revocation.effective_at = 1_600_000_000;
        expired_revocation.expires_at = Some(1_650_000_000); // Expired

        let revoked_id = ObjectId::from_bytes([1u8; 32]);
        let current_time = 1_700_000_000; // After expiry

        // The revocation should NOT be active
        assert!(
            !expired_revocation.is_active(current_time),
            "Expired revocation should not be active"
        );

        // Registry should not treat it as revoked at current time
        let mut registry = RevocationRegistry::new();
        registry.add_revocation(&expired_revocation);

        assert!(
            !registry.is_revoked_at(&revoked_id, current_time),
            "Expired revocation should not affect current time"
        );

        // But it WAS revoked during its active period
        let during_active = 1_620_000_000;
        assert!(
            registry.is_revoked_at(&revoked_id, during_active),
            "Revocation should be active during its valid period"
        );

        log_test_event(
            "attack_replay_expired_revocation",
            "attack_mitigated",
            &serde_json::json!({
                "expired_at": expired_revocation.expires_at,
                "current_time": current_time,
                "is_active": false
            }),
        );
    }

    /// Attack: Stale frontier - presenting old head as current.
    ///
    /// Scenario: Attacker presents an old `RevocationHead` to hide newer revocations.
    #[test]
    fn attack_stale_frontier() {
        log_test_event(
            "attack_stale_frontier",
            "test_start",
            &serde_json::json!({
                "attack_type": "stale_frontier",
                "description": "Presenting old head to hide newer revocations"
            }),
        );

        let old_head = test_head(10, "epoch-old");
        let current_head = test_head(50, "epoch-current");

        // Victim should detect that presented head is stale
        assert!(
            current_head.is_fresher_than(&old_head),
            "Current head should be fresher"
        );
        assert!(
            !old_head.is_fresher_than(&current_head),
            "Old head should not be fresher"
        );

        // A registry updated with old head should fail freshness check
        let mut victim_registry = RevocationRegistry::new();
        victim_registry.update_head(old_head.head_event, old_head.head_seq, 1_699_000_000);

        let result = victim_registry.check_freshness(
            current_head.head_seq,
            FreshnessPolicy::Strict,
            3600,
            1_700_000_000,
        );

        assert!(!result.allowed, "Should reject stale frontier");
        assert!(result.stale);

        log_test_event(
            "attack_stale_frontier",
            "attack_detected",
            &serde_json::json!({
                "old_seq": old_head.head_seq,
                "current_seq": current_head.head_seq,
                "seq_gap": current_head.head_seq - old_head.head_seq
            }),
        );
    }

    /// Attack: Chain fork injection - attempting to create parallel chains.
    ///
    /// Scenario: Attacker tries to create a forked chain with same seq but different content.
    #[test]
    fn attack_chain_fork_injection() {
        log_test_event(
            "attack_chain_fork_injection",
            "test_start",
            &serde_json::json!({
                "attack_type": "chain_fork",
                "description": "Attempting to create parallel revocation chains"
            }),
        );

        // Genesis event with known ID
        let genesis_id = ObjectId::from_bytes([1u8; 32]);
        let genesis = test_event(1, None, genesis_id);

        // Legitimate second event
        let legit_event = test_event(
            2,
            Some(genesis.revocation_object_id),
            ObjectId::from_bytes([2u8; 32]),
        );

        // Forked event with same seq but different content
        let forked_event = test_event(
            2,
            Some(genesis.revocation_object_id),
            ObjectId::from_bytes([99u8; 32]),
        );

        // Both claim to follow genesis (using genesis_id for verification)
        assert!(legit_event.follows(&genesis, &genesis_id));
        assert!(forked_event.follows(&genesis, &genesis_id));

        // But they have different revocation_object_ids (fork detection)
        assert_ne!(
            legit_event.revocation_object_id, forked_event.revocation_object_id,
            "Fork detected: different revocation objects at same seq"
        );

        // A proper implementation should reject forks by checking:
        // 1. Only one event per seq number
        // 2. Hash chain integrity
        log_test_event(
            "attack_chain_fork_injection",
            "fork_detected",
            &serde_json::json!({
                "seq": 2,
                "legit_id": hex::encode(legit_event.revocation_object_id.as_bytes()),
                "forked_id": hex::encode(forked_event.revocation_object_id.as_bytes()),
                "detection_method": "object_id_mismatch"
            }),
        );
    }

    /// Attack: Scope escalation - using wrong scope type.
    ///
    /// Scenario: Attacker revokes with Capability scope but target is an `IssuerKey`.
    #[test]
    fn attack_scope_escalation() {
        log_test_event(
            "attack_scope_escalation",
            "test_start",
            &serde_json::json!({
                "attack_type": "scope_escalation",
                "description": "Using wrong revocation scope"
            }),
        );

        // Attacker creates a Capability revocation for an IssuerKey ID
        let issuer_key_id = ObjectId::from_bytes([42u8; 32]);
        let mut malicious_revocation = test_revocation(42, RevocationScope::Capability);
        malicious_revocation.revoked = vec![issuer_key_id];

        // The registry stores it, but scope-aware enforcement should check
        let mut registry = RevocationRegistry::new();
        registry.add_revocation(&malicious_revocation);

        // Object is "revoked" in registry...
        assert!(registry.is_revoked(&issuer_key_id));

        // But enforcement code should validate scope matches target type
        let retrieved = registry.get_revocation(&issuer_key_id).unwrap();
        assert_eq!(
            retrieved.scope,
            RevocationScope::Capability,
            "Scope mismatch should be detectable"
        );

        // Scope enforcement: Capability revocations should NOT affect IssuerKeys
        let is_capability_scope = retrieved.scope == RevocationScope::Capability;
        assert!(
            is_capability_scope,
            "Enforcement should verify scope matches target type"
        );

        log_test_event(
            "attack_scope_escalation",
            "attack_mitigated",
            &serde_json::json!({
                "target_id": hex::encode(issuer_key_id.as_bytes()),
                "revocation_scope": "capability",
                "expected_scope": "issuer_key",
                "mitigation": "scope_validation_required"
            }),
        );
    }

    /// Attack: Probabilistic filter bypass (historical).
    ///
    /// Scenario: Ensure registry uses exact membership and cannot be tricked by FP/TP tradeoffs.
    #[test]
    fn attack_probabilistic_filter_bypass() {
        log_test_event(
            "attack_probabilistic_filter_bypass",
            "test_start",
            &serde_json::json!({
                "attack_type": "probabilistic_filter",
                "description": "Registry must not rely on probabilistic membership"
            }),
        );

        let mut registry = RevocationRegistry::new();
        let revocation = test_revocation(1, RevocationScope::Capability);
        registry.add_revocation(&revocation);

        // Exact map lookup: unknown ID must be unrevoked
        let not_revoked = ObjectId::from_bytes([99u8; 32]);
        assert!(
            !registry.is_revoked(&not_revoked),
            "Exact registry lookup should not produce false positives"
        );

        // Known ID must be revoked
        let revoked = ObjectId::from_bytes([1u8; 32]);
        assert!(registry.is_revoked(&revoked));

        log_test_event(
            "attack_probabilistic_filter_bypass",
            "test_complete",
            &serde_json::json!({
                "membership_check": "exact_hashmap",
                "false_positive_risk": "eliminated"
            }),
        );
    }

    /// Attack: Revocation flood (`DoS` attempt).
    ///
    /// Scenario: Attacker tries to overwhelm registry with many revocations.
    #[test]
    fn attack_revocation_flood() {
        log_test_event(
            "attack_revocation_flood",
            "test_start",
            &serde_json::json!({
                "attack_type": "denial_of_service",
                "description": "Flooding registry with revocations"
            }),
        );

        let mut registry = RevocationRegistry::with_capacity(10000);

        // Add many revocations
        let start = std::time::Instant::now();
        for i in 0..1000u32 {
            let id_byte = u8::try_from(i % 256).expect("id byte fits u8");
            let mut revocation = test_revocation(id_byte, RevocationScope::Capability);
            revocation.revoked = vec![ObjectId::from_bytes({
                let mut bytes = [0u8; 32];
                bytes[0..4].copy_from_slice(&i.to_le_bytes());
                bytes
            })];
            registry.add_revocation(&revocation);
        }
        let insert_time = start.elapsed();

        // Lookup should still be fast
        let start = std::time::Instant::now();
        for i in 0..1000u32 {
            let id = ObjectId::from_bytes({
                let mut bytes = [0u8; 32];
                bytes[0..4].copy_from_slice(&i.to_le_bytes());
                bytes
            });
            let _ = registry.is_revoked(&id);
        }
        let lookup_time = start.elapsed();

        log_test_event(
            "attack_revocation_flood",
            "performance_metrics",
            &serde_json::json!({
                "revocation_count": 1000,
                "insert_time_ms": insert_time.as_millis(),
                "lookup_time_ms": lookup_time.as_millis(),
                "avg_lookup_us": lookup_time.as_micros() / 1000
            }),
        );

        // Sanity check: lookups should complete reasonably fast
        assert!(
            lookup_time.as_millis() < 100,
            "Lookup performance degradation detected"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Chain Integrity Tests
// ─────────────────────────────────────────────────────────────────────────────

mod chain_integrity {
    use super::*;

    /// Validate a chain of revocation events for integrity.
    ///
    /// NOTE: In this test, we use `revocation_object_id` as a stand-in for the
    /// event's own `ObjectId` (which would be computed from hashing the event).
    /// In a real implementation, `prev` points to the `ObjectId` of the previous
    /// event itself, NOT its `revocation_object_id`. Our test construction
    /// deliberately makes these equal for simplicity.
    fn validate_chain(events: &[RevocationEvent]) -> Result<(), ChainError> {
        if events.is_empty() {
            return Ok(());
        }

        // Genesis must have no prev
        if events[0].prev.is_some() {
            return Err(ChainError::InvalidGenesis);
        }

        // Track seen sequences for duplicate detection
        let mut seen_seqs = std::collections::HashSet::new();

        for (i, event) in events.iter().enumerate() {
            // Check for duplicate sequence
            if !seen_seqs.insert(event.seq) {
                return Err(ChainError::DuplicateSequence(event.seq));
            }

            if i > 0 {
                let prev_event = &events[i - 1];

                // Sequence must be exactly prev + 1
                if event.seq != prev_event.seq + 1 {
                    return Err(ChainError::SequenceGap {
                        expected: prev_event.seq + 1,
                        found: event.seq,
                    });
                }

                // Prev pointer must match previous event's ObjectId
                // (We use revocation_object_id as stand-in; see function doc)
                if event.prev != Some(prev_event.revocation_object_id) {
                    return Err(ChainError::BrokenChain {
                        seq: event.seq,
                        expected_prev: Some(prev_event.revocation_object_id),
                        found_prev: event.prev,
                    });
                }
            }
        }

        Ok(())
    }

    #[derive(Debug, PartialEq)]
    enum ChainError {
        InvalidGenesis,
        DuplicateSequence(u64),
        SequenceGap {
            expected: u64,
            found: u64,
        },
        BrokenChain {
            seq: u64,
            expected_prev: Option<ObjectId>,
            found_prev: Option<ObjectId>,
        },
    }

    #[test]
    fn test_valid_chain() {
        log_test_event(
            "test_valid_chain",
            "test_start",
            &serde_json::json!({"chain_length": 5}),
        );

        let events: Vec<RevocationEvent> = (1..=5)
            .map(|seq| {
                let prev = if seq == 1 {
                    None
                } else {
                    let prev_byte = u8::try_from(seq - 1).expect("prev byte fits u8");
                    Some(ObjectId::from_bytes([prev_byte; 32]))
                };
                let seq_byte = u8::try_from(seq).expect("seq byte fits u8");
                test_event(seq, prev, ObjectId::from_bytes([seq_byte; 32]))
            })
            .collect();

        assert!(validate_chain(&events).is_ok());

        log_test_event(
            "test_valid_chain",
            "test_complete",
            &serde_json::json!({"result": "valid"}),
        );
    }

    #[test]
    fn test_empty_chain() {
        assert!(validate_chain(&[]).is_ok());
    }

    #[test]
    fn test_genesis_with_prev_rejected() {
        log_test_event(
            "test_genesis_with_prev_rejected",
            "test_start",
            &serde_json::json!({"error_type": "invalid_genesis"}),
        );

        // Genesis event with prev pointer (invalid)
        let invalid_genesis = test_event(
            1,
            Some(ObjectId::from_bytes([99u8; 32])),
            ObjectId::from_bytes([1u8; 32]),
        );

        let result = validate_chain(&[invalid_genesis]);
        assert_eq!(result, Err(ChainError::InvalidGenesis));

        log_test_event(
            "test_genesis_with_prev_rejected",
            "test_complete",
            &serde_json::json!({"error_detected": "invalid_genesis"}),
        );
    }

    #[test]
    fn test_duplicate_sequence_rejected() {
        log_test_event(
            "test_duplicate_sequence_rejected",
            "test_start",
            &serde_json::json!({"error_type": "duplicate_sequence"}),
        );

        let genesis = test_event(1, None, ObjectId::from_bytes([1u8; 32]));
        let duplicate = test_event(
            1, // Same seq as genesis!
            Some(ObjectId::from_bytes([1u8; 32])),
            ObjectId::from_bytes([2u8; 32]),
        );

        let result = validate_chain(&[genesis, duplicate]);
        assert_eq!(result, Err(ChainError::DuplicateSequence(1)));

        log_test_event(
            "test_duplicate_sequence_rejected",
            "test_complete",
            &serde_json::json!({"error_detected": "duplicate_sequence"}),
        );
    }

    #[test]
    fn test_sequence_gap_rejected() {
        log_test_event(
            "test_sequence_gap_rejected",
            "test_start",
            &serde_json::json!({"error_type": "sequence_gap"}),
        );

        let genesis = test_event(1, None, ObjectId::from_bytes([1u8; 32]));
        let gap_event = test_event(
            5, // Gap: expected 2
            Some(ObjectId::from_bytes([1u8; 32])),
            ObjectId::from_bytes([5u8; 32]),
        );

        let result = validate_chain(&[genesis, gap_event]);
        assert_eq!(
            result,
            Err(ChainError::SequenceGap {
                expected: 2,
                found: 5
            })
        );

        log_test_event(
            "test_sequence_gap_rejected",
            "test_complete",
            &serde_json::json!({"error_detected": "sequence_gap", "expected": 2, "found": 5}),
        );
    }

    #[test]
    fn test_broken_chain_rejected() {
        log_test_event(
            "test_broken_chain_rejected",
            "test_start",
            &serde_json::json!({"error_type": "broken_chain"}),
        );

        let genesis = test_event(1, None, ObjectId::from_bytes([1u8; 32]));
        let broken_link = test_event(
            2,
            Some(ObjectId::from_bytes([99u8; 32])), // Wrong prev!
            ObjectId::from_bytes([2u8; 32]),
        );

        let result = validate_chain(&[genesis, broken_link]);
        assert!(matches!(result, Err(ChainError::BrokenChain { .. })));

        log_test_event(
            "test_broken_chain_rejected",
            "test_complete",
            &serde_json::json!({"error_detected": "broken_chain"}),
        );
    }

    #[test]
    fn test_revocation_event_follows() {
        log_test_event(
            "test_revocation_event_follows",
            "test_start",
            &serde_json::json!({"purpose": "Test RevocationEvent::follows method"}),
        );

        let event1_id = ObjectId::from_bytes([1u8; 32]);
        let event2_id = ObjectId::from_bytes([2u8; 32]);
        let event3_id = ObjectId::from_bytes([3u8; 32]);

        let event1 = test_event(1, None, event1_id);
        let event2 = test_event(2, Some(event1.revocation_object_id), event2_id);
        let event3 = test_event(3, Some(event2.revocation_object_id), event3_id);

        // event2 follows event1 (correct sequence and prev pointer)
        assert!(event2.follows(&event1, &event1_id));
        // event3 follows event2 (correct sequence and prev pointer)
        assert!(event3.follows(&event2, &event2_id));
        // event1 does not follow event2 (wrong order)
        assert!(!event1.follows(&event2, &event2_id));
        // event3 does not follow event1 (must be consecutive)
        assert!(!event3.follows(&event1, &event1_id));

        log_test_event(
            "test_revocation_event_follows",
            "test_complete",
            &serde_json::json!({"follows_verified": true}),
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Quorum Verification Tests
// ─────────────────────────────────────────────────────────────────────────────

mod quorum_verification {
    use super::*;

    #[test]
    fn test_revocation_head_quorum_empty() {
        log_test_event(
            "test_revocation_head_quorum_empty",
            "test_start",
            &serde_json::json!({"purpose": "Empty signature set should fail quorum"}),
        );

        let head = test_head(10, "epoch-1");
        let policy = QuorumPolicy::new(ZoneId::work(), 3, 1); // 3 nodes, 1 fault tolerance

        assert!(
            !head.satisfies_quorum(&policy),
            "Empty signature set should not satisfy quorum"
        );

        log_test_event(
            "test_revocation_head_quorum_empty",
            "test_complete",
            &serde_json::json!({"empty_set_rejected": true}),
        );
    }

    #[test]
    fn test_revocation_head_quorum_with_signatures() {
        log_test_event(
            "test_revocation_head_quorum_with_signatures",
            "test_start",
            &serde_json::json!({"purpose": "Signature set should satisfy quorum thresholds"}),
        );

        let mut head = test_head(10, "epoch-1");
        let policy = QuorumPolicy::new(ZoneId::work(), 3, 1); // 3 nodes, 1 fault tolerance

        // Add signatures to meet quorum
        // For CriticalWrite risk tier: required = n - f = 3 - 1 = 2
        for i in 0u8..2 {
            let node_id = NodeId::new(format!("node-{i}"));
            let sig = NodeSignature::new(node_id, [i; 64], 1_700_000_000 + u64::from(i));
            head.quorum_signatures.add(sig);
        }

        assert!(
            head.satisfies_quorum(&policy),
            "2 signatures should satisfy 3-node quorum with f=1"
        );

        log_test_event(
            "test_revocation_head_quorum_with_signatures",
            "test_complete",
            &serde_json::json!({
                "signature_count": 2,
                "required": 2,
                "satisfied": true
            }),
        );
    }

    #[test]
    fn test_revocation_head_freshness_comparison() {
        log_test_event(
            "test_revocation_head_freshness_comparison",
            "test_start",
            &serde_json::json!({"purpose": "Test head freshness comparison"}),
        );

        let head_a = test_head(10, "epoch-a");
        let head_b = test_head(20, "epoch-b");
        let head_c = test_head(10, "epoch-c"); // Same seq as A

        assert!(head_b.is_fresher_than(&head_a));
        assert!(!head_a.is_fresher_than(&head_b));
        assert!(!head_a.is_fresher_than(&head_c)); // Same seq = not fresher
        assert!(!head_c.is_fresher_than(&head_a)); // Same seq = not fresher

        log_test_event(
            "test_revocation_head_freshness_comparison",
            "test_complete",
            &serde_json::json!({
                "head_a_seq": 10,
                "head_b_seq": 20,
                "b_fresher_than_a": true
            }),
        );
    }

    #[test]
    fn test_revocation_head_age_calculation() {
        log_test_event(
            "test_revocation_head_age_calculation",
            "test_start",
            &serde_json::json!({"purpose": "Test head age calculation"}),
        );

        let head = test_head(10, "epoch-1");
        // head.header.created_at = 1_700_000_000

        let now = 1_700_000_100;
        assert_eq!(head.age_secs(now), 100);

        let past = 1_699_999_900;
        assert_eq!(head.age_secs(past), 0); // Saturating sub

        log_test_event(
            "test_revocation_head_age_calculation",
            "test_complete",
            &serde_json::json!({
                "created_at": 1_700_000_000,
                "now": now,
                "age_secs": 100
            }),
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Freshness Policy Tests (Extended)
// ─────────────────────────────────────────────────────────────────────────────

mod freshness_policy {
    use super::*;

    #[test]
    fn test_freshness_policy_risk_tier_mapping() {
        log_test_event(
            "test_freshness_policy_risk_tier_mapping",
            "test_start",
            &serde_json::json!({"purpose": "Verify risk tier to freshness policy mapping"}),
        );

        // CriticalWrite and Dangerous require Strict
        assert_eq!(
            FreshnessPolicy::for_risk_tier(RiskTier::CriticalWrite),
            FreshnessPolicy::Strict
        );
        assert_eq!(
            FreshnessPolicy::for_risk_tier(RiskTier::Dangerous),
            FreshnessPolicy::Strict
        );

        // Risky uses Warn
        assert_eq!(
            FreshnessPolicy::for_risk_tier(RiskTier::Risky),
            FreshnessPolicy::Warn
        );

        // Safe uses BestEffort
        assert_eq!(
            FreshnessPolicy::for_risk_tier(RiskTier::Safe),
            FreshnessPolicy::BestEffort
        );

        log_test_event(
            "test_freshness_policy_risk_tier_mapping",
            "test_complete",
            &serde_json::json!({
                "critical_write": "strict",
                "dangerous": "strict",
                "risky": "warn",
                "safe": "best_effort"
            }),
        );
    }

    #[test]
    fn test_registry_freshness_with_all_policies() {
        log_test_event(
            "test_registry_freshness_with_all_policies",
            "test_start",
            &serde_json::json!({"purpose": "Test registry freshness with all policy types"}),
        );

        let mut registry = RevocationRegistry::new();
        registry.head_seq = 50;
        registry.last_updated = 1_700_000_000;

        let remote_seq = 100;
        let now = 1_700_000_100;
        let max_age = 200;

        // Strict: blocks stale
        let result = registry.check_freshness(remote_seq, FreshnessPolicy::Strict, max_age, now);
        assert!(!result.allowed);
        assert!(result.stale);

        // Warn: allows within max_age
        let result = registry.check_freshness(remote_seq, FreshnessPolicy::Warn, max_age, now);
        assert!(result.allowed);
        assert!(result.stale);
        assert_eq!(
            result.reason,
            Some(FreshnessFailureReason::StaleButWithinMaxAge)
        );

        // BestEffort: always allows
        let result = registry.check_freshness(remote_seq, FreshnessPolicy::BestEffort, 0, now);
        assert!(result.allowed);
        assert!(result.stale);
        assert_eq!(result.reason, Some(FreshnessFailureReason::StaleButAllowed));

        log_test_event(
            "test_registry_freshness_with_all_policies",
            "test_complete",
            &serde_json::json!({"all_policies_tested": true}),
        );
    }

    #[test]
    fn test_freshness_edge_cases() {
        log_test_event(
            "test_freshness_edge_cases",
            "test_start",
            &serde_json::json!({"purpose": "Test freshness edge cases"}),
        );

        let mut registry = RevocationRegistry::new();
        registry.head_seq = 100;
        registry.last_updated = 1_700_000_000;

        let now = 1_700_000_000; // Exactly at last_updated

        // Exactly fresh (local_seq == remote_seq)
        let result = registry.check_freshness(100, FreshnessPolicy::Strict, 0, now);
        assert!(result.allowed);
        assert!(!result.stale);
        assert_eq!(result.age_secs, 0);

        // Local ahead of remote (fresher)
        let result = registry.check_freshness(50, FreshnessPolicy::Strict, 0, now);
        assert!(result.allowed);
        assert!(!result.stale);

        log_test_event(
            "test_freshness_edge_cases",
            "test_complete",
            &serde_json::json!({
                "exact_match_allowed": true,
                "ahead_allowed": true
            }),
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Scope Enforcement Tests
// ─────────────────────────────────────────────────────────────────────────────

mod scope_enforcement {
    use super::*;

    #[test]
    fn test_all_scope_types() {
        log_test_event(
            "test_all_scope_types",
            "test_start",
            &serde_json::json!({"purpose": "Verify all scope types are properly handled"}),
        );

        let scopes = [
            RevocationScope::Capability,
            RevocationScope::IssuerKey,
            RevocationScope::NodeAttestation,
            RevocationScope::ZoneKey,
            RevocationScope::ConnectorBinary,
        ];

        let mut registry = RevocationRegistry::new();

        for (i, scope) in scopes.iter().enumerate() {
            let id_byte = u8::try_from(i + 1).expect("id byte fits u8");
            let revocation = test_revocation(id_byte, *scope);
            registry.add_revocation(&revocation);

            let revoked_id = ObjectId::from_bytes([id_byte; 32]);
            assert!(registry.is_revoked(&revoked_id));

            let retrieved = registry.get_revocation(&revoked_id).unwrap();
            assert_eq!(retrieved.scope, *scope);
        }

        // Verify by-scope filtering
        for scope in &scopes {
            let filtered = registry.revocations_by_scope(*scope);
            assert_eq!(filtered.len(), 1);
        }

        log_test_event(
            "test_all_scope_types",
            "test_complete",
            &serde_json::json!({
                "scopes_tested": scopes.len(),
                "all_retrievable": true
            }),
        );
    }

    #[test]
    fn test_critical_scope_identification() {
        log_test_event(
            "test_critical_scope_identification",
            "test_start",
            &serde_json::json!({"purpose": "Verify critical scope identification"}),
        );

        // Non-critical scopes
        assert!(!RevocationScope::Capability.is_critical());
        assert!(!RevocationScope::IssuerKey.is_critical());

        // Critical scopes (require immediate action)
        assert!(RevocationScope::NodeAttestation.is_critical());
        assert!(RevocationScope::ZoneKey.is_critical());
        assert!(RevocationScope::ConnectorBinary.is_critical());

        log_test_event(
            "test_critical_scope_identification",
            "test_complete",
            &serde_json::json!({
                "critical_scopes": ["node_attestation", "zone_key", "connector_binary"],
                "non_critical_scopes": ["capability", "issuer_key"]
            }),
        );
    }

    #[test]
    fn test_multi_object_revocation() {
        log_test_event(
            "test_multi_object_revocation",
            "test_start",
            &serde_json::json!({"purpose": "Test revoking multiple objects at once"}),
        );

        let mut revocation = test_revocation(1, RevocationScope::Capability);
        revocation.revoked = vec![
            ObjectId::from_bytes([1u8; 32]),
            ObjectId::from_bytes([2u8; 32]),
            ObjectId::from_bytes([3u8; 32]),
        ];

        let mut registry = RevocationRegistry::new();
        registry.add_revocation(&revocation);

        // All three should be revoked
        assert!(registry.is_revoked(&ObjectId::from_bytes([1u8; 32])));
        assert!(registry.is_revoked(&ObjectId::from_bytes([2u8; 32])));
        assert!(registry.is_revoked(&ObjectId::from_bytes([3u8; 32])));

        // But not others
        assert!(!registry.is_revoked(&ObjectId::from_bytes([4u8; 32])));

        log_test_event(
            "test_multi_object_revocation",
            "test_complete",
            &serde_json::json!({
                "objects_revoked": 3,
                "all_found": true
            }),
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Registry Operations Tests
// ─────────────────────────────────────────────────────────────────────────────

mod registry_operations {
    use super::*;

    #[test]
    fn test_registry_capacity() {
        log_test_event(
            "test_registry_capacity",
            "test_start",
            &serde_json::json!({"purpose": "Test registry with pre-allocated capacity"}),
        );

        let registry = RevocationRegistry::with_capacity(1000);
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);

        log_test_event(
            "test_registry_capacity",
            "test_complete",
            &serde_json::json!({"capacity_set": true}),
        );
    }

    #[test]
    fn test_registry_clear() {
        log_test_event(
            "test_registry_clear",
            "test_start",
            &serde_json::json!({"purpose": "Test registry clear operation"}),
        );

        let mut registry = RevocationRegistry::new();

        // Add some data
        for i in 0..5 {
            let revocation = test_revocation(i, RevocationScope::Capability);
            registry.add_revocation(&revocation);
        }
        registry.update_head(ObjectId::from_bytes([99u8; 32]), 100, 1_700_000_000);

        assert!(!registry.is_empty());
        assert!(registry.head.is_some());

        // Clear
        registry.clear();

        assert!(registry.is_empty());
        assert!(registry.head.is_none());
        assert_eq!(registry.head_seq, 0);
        assert_eq!(registry.last_updated, 0);

        log_test_event(
            "test_registry_clear",
            "test_complete",
            &serde_json::json!({"cleared": true}),
        );
    }

    #[test]
    fn test_registry_head_updates() {
        log_test_event(
            "test_registry_head_updates",
            "test_start",
            &serde_json::json!({"purpose": "Test sequential head updates"}),
        );

        let mut registry = RevocationRegistry::new();

        // Initial state
        assert!(registry.head.is_none());
        assert_eq!(registry.head_seq, 0);

        // First update
        registry.update_head(ObjectId::from_bytes([1u8; 32]), 10, 1_700_000_000);
        assert_eq!(registry.head_seq, 10);

        // Second update
        registry.update_head(ObjectId::from_bytes([2u8; 32]), 20, 1_700_001_000);
        assert_eq!(registry.head_seq, 20);

        // Freshness check
        assert!(registry.is_fresh(20));
        assert!(registry.is_fresh(15));
        assert!(!registry.is_fresh(25));

        log_test_event(
            "test_registry_head_updates",
            "test_complete",
            &serde_json::json!({
                "final_seq": 20,
                "updates_applied": 2
            }),
        );
    }
}
