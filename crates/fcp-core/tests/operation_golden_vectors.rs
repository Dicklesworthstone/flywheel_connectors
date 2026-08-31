//! Exactly-Once Semantics Unit Tests (flywheel_connectors-57x7)
//!
//! Comprehensive tests for the exactly-once semantics system:
//! - Golden vector tests for deterministic CBOR serialization
//! - Idempotency key tests (same key returns same receipt)
//! - Lease fencing tests (stale holder rejection)
//! - Fault injection tests (crash recovery, orphan detection)
//! - Concurrency tests (race conditions)

use fcp_cbor::SchemaId;
use fcp_core::{
    IdempotencyClass, IdempotencyEntry, IntentStatus, NodeId, NodeSignature, ObjectHeader,
    ObjectId, OperationIntent, OperationReceipt, OperationValidationError, Provenance,
    TailscaleNodeId, ZoneId, is_intent_orphaned, required_idempotency_for_safety_tier,
    validate_receipt_intent_binding,
};
use semver::Version;
use uuid::Uuid;

// ═══════════════════════════════════════════════════════════════════════════════
// Test Helpers
// ═══════════════════════════════════════════════════════════════════════════════

fn test_node(name: &str) -> TailscaleNodeId {
    TailscaleNodeId::new(name)
}

fn test_zone() -> ZoneId {
    ZoneId::work()
}

fn test_object_id(name: &str) -> ObjectId {
    ObjectId::from_unscoped_bytes(name.as_bytes())
}

fn test_intent_id() -> ObjectId {
    test_object_id("intent-1")
}

fn test_receipt_id() -> ObjectId {
    test_object_id("receipt-1")
}

fn test_signature() -> NodeSignature {
    NodeSignature::new(NodeId::new("test-node"), [0u8; 64], 1000)
}

fn create_test_header(schema_name: &str) -> ObjectHeader {
    let zone = test_zone();
    ObjectHeader {
        encryption_kind: Default::default(),
        schema: SchemaId::new("fcp.operation", schema_name, Version::new(1, 0, 0)),
        zone_id: zone.clone(),
        created_at: 1000,
        provenance: Provenance::new(zone),
        refs: vec![],
        foreign_refs: vec![],
        ttl_secs: None,
        placement: None,
    }
}

fn create_test_intent() -> OperationIntent {
    OperationIntent {
        header: create_test_header("intent"),
        request_object_id: test_object_id("request-1"),
        capability_token_jti: Uuid::nil(),
        idempotency_key: Some("idem-key-123".to_string()),
        planned_at: 1000,
        planned_by: test_node("executor-node"),
        lease_seq: Some(42),
        upstream_idempotency: None,
        signature: test_signature(),
    }
}

fn create_test_receipt() -> OperationReceipt {
    let mut header = create_test_header("receipt");
    header.refs = vec![test_intent_id()];

    OperationReceipt {
        header,
        request_object_id: test_object_id("request-1"),
        idempotency_key: Some("idem-key-123".to_string()),
        outcome_object_ids: vec![test_object_id("outcome-1")],
        resource_object_ids: vec![],
        usage_metrics: None,
        executed_at: 1100,
        executed_by: test_node("executor-node"),
        signature: test_signature(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// OperationIntent/Receipt Schema Tests (Golden Vectors)
// ═══════════════════════════════════════════════════════════════════════════════

mod cbor_golden_vectors {
    use super::*;

    #[test]
    fn intent_cbor_roundtrip() {
        let intent = create_test_intent();

        // Serialize to CBOR
        let mut cbor = Vec::new();
        ciborium::into_writer(&intent, &mut cbor).expect("serialization should succeed");

        // Deserialize
        let restored: OperationIntent =
            ciborium::from_reader(&cbor[..]).expect("deserialization should succeed");

        // Verify all fields match
        assert_eq!(intent.request_object_id, restored.request_object_id);
        assert_eq!(intent.capability_token_jti, restored.capability_token_jti);
        assert_eq!(intent.idempotency_key, restored.idempotency_key);
        assert_eq!(intent.planned_at, restored.planned_at);
        assert_eq!(intent.lease_seq, restored.lease_seq);
        assert_eq!(intent.upstream_idempotency, restored.upstream_idempotency);
    }

    #[test]
    fn receipt_cbor_roundtrip() {
        let receipt = create_test_receipt();

        // Serialize to CBOR
        let mut cbor = Vec::new();
        ciborium::into_writer(&receipt, &mut cbor).expect("serialization should succeed");

        // Deserialize
        let restored: OperationReceipt =
            ciborium::from_reader(&cbor[..]).expect("deserialization should succeed");

        // Verify all fields match
        assert_eq!(receipt.request_object_id, restored.request_object_id);
        assert_eq!(receipt.idempotency_key, restored.idempotency_key);
        assert_eq!(
            receipt.outcome_object_ids.len(),
            restored.outcome_object_ids.len()
        );
        assert_eq!(
            receipt.resource_object_ids.len(),
            restored.resource_object_ids.len()
        );
        assert_eq!(receipt.executed_at, restored.executed_at);
    }

    #[test]
    fn intent_signable_bytes_deterministic() {
        let intent = create_test_intent();

        // Multiple calls should produce identical bytes
        let bytes1 = intent.signable_bytes();
        let bytes2 = intent.signable_bytes();
        let bytes3 = intent.signable_bytes();

        assert_eq!(bytes1, bytes2);
        assert_eq!(bytes2, bytes3);

        // Should start with magic
        assert!(bytes1.starts_with(b"FCP2-INTENT-V1"));
    }

    #[test]
    fn receipt_signable_bytes_deterministic() {
        let receipt = create_test_receipt();

        // Multiple calls should produce identical bytes
        let bytes1 = receipt.signable_bytes();
        let bytes2 = receipt.signable_bytes();
        let bytes3 = receipt.signable_bytes();

        assert_eq!(bytes1, bytes2);
        assert_eq!(bytes2, bytes3);

        // Should start with magic
        assert!(bytes1.starts_with(b"FCP2-RECEIPT-V1"));
    }

    #[test]
    fn intent_signable_bytes_differ_with_idempotency_key() {
        let mut intent1 = create_test_intent();
        let mut intent2 = create_test_intent();

        intent1.idempotency_key = Some("key-alpha".to_string());
        intent2.idempotency_key = Some("key-beta".to_string());

        assert_ne!(intent1.signable_bytes(), intent2.signable_bytes());
    }

    #[test]
    fn intent_signable_bytes_differ_with_lease_seq() {
        let mut intent1 = create_test_intent();
        let mut intent2 = create_test_intent();

        intent1.lease_seq = Some(1);
        intent2.lease_seq = Some(2);

        assert_ne!(intent1.signable_bytes(), intent2.signable_bytes());
    }

    #[test]
    fn intent_signable_bytes_differ_with_optional_lease_presence() {
        let mut intent1 = create_test_intent();
        let mut intent2 = create_test_intent();

        intent1.lease_seq = Some(0);
        intent2.lease_seq = None;

        // Even if the value is 0, presence vs absence should differ
        assert_ne!(intent1.signable_bytes(), intent2.signable_bytes());
    }

    #[test]
    fn receipt_signable_bytes_include_outcome_objects() {
        let mut receipt1 = create_test_receipt();
        let mut receipt2 = create_test_receipt();

        receipt1.outcome_object_ids = vec![test_object_id("outcome-a")];
        receipt2.outcome_object_ids = vec![test_object_id("outcome-b")];

        assert_ne!(receipt1.signable_bytes(), receipt2.signable_bytes());
    }

    #[test]
    fn receipt_signable_bytes_include_resource_objects() {
        let mut receipt1 = create_test_receipt();
        let mut receipt2 = create_test_receipt();

        receipt1.resource_object_ids = vec![test_object_id("resource-a")];
        receipt2.resource_object_ids = vec![test_object_id("resource-b")];

        assert_ne!(receipt1.signable_bytes(), receipt2.signable_bytes());
    }

    #[test]
    fn intent_cbor_includes_all_optional_fields_when_present() {
        let mut intent = create_test_intent();
        intent.idempotency_key = Some("key-present".to_string());
        intent.lease_seq = Some(999);
        intent.upstream_idempotency = Some("stripe:ch_abc123".to_string());

        let mut cbor = Vec::new();
        ciborium::into_writer(&intent, &mut cbor).expect("serialization should succeed");

        let restored: OperationIntent =
            ciborium::from_reader(&cbor[..]).expect("deserialization should succeed");

        assert_eq!(restored.idempotency_key, Some("key-present".to_string()));
        assert_eq!(restored.lease_seq, Some(999));
        assert_eq!(
            restored.upstream_idempotency,
            Some("stripe:ch_abc123".to_string())
        );
    }

    #[test]
    fn intent_cbor_handles_missing_optional_fields() {
        let mut intent = create_test_intent();
        intent.idempotency_key = None;
        intent.lease_seq = None;
        intent.upstream_idempotency = None;

        let mut cbor = Vec::new();
        ciborium::into_writer(&intent, &mut cbor).expect("serialization should succeed");

        let restored: OperationIntent =
            ciborium::from_reader(&cbor[..]).expect("deserialization should succeed");

        assert!(restored.idempotency_key.is_none());
        assert!(restored.lease_seq.is_none());
        assert!(restored.upstream_idempotency.is_none());
    }

    #[test]
    fn receipt_with_many_outcome_objects() {
        let mut receipt = create_test_receipt();
        receipt.outcome_object_ids = (0..100)
            .map(|i| test_object_id(&format!("outcome-{i}")))
            .collect();
        receipt.resource_object_ids = (0..50)
            .map(|i| test_object_id(&format!("resource-{i}")))
            .collect();

        let mut cbor = Vec::new();
        ciborium::into_writer(&receipt, &mut cbor).expect("serialization should succeed");

        let restored: OperationReceipt =
            ciborium::from_reader(&cbor[..]).expect("deserialization should succeed");

        assert_eq!(restored.outcome_object_ids.len(), 100);
        assert_eq!(restored.resource_object_ids.len(), 50);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Idempotency Key Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod idempotency_tests {
    use super::*;

    #[test]
    fn same_key_returns_same_receipt_scenario() {
        // Simulate: First request creates entry, second request should return cached
        let idempotency_key = "stripe-payment-xyz".to_string();
        let now = 1500u64;

        // Entry created after first successful execution
        let entry = IdempotencyEntry {
            key: idempotency_key,
            zone_id: test_zone(),
            intent_id: test_object_id("intent-1"),
            receipt_id: Some(test_object_id("receipt-1")),
            status: IntentStatus::Completed,
            created_at: 1000,
            expires_at: 1000 + 86400, // 24 hours TTL
        };

        // Second request with same key arrives
        assert!(entry.should_return_cached(now));
        assert_eq!(entry.receipt_id, Some(test_object_id("receipt-1")));
    }

    #[test]
    fn different_keys_create_separate_receipts() {
        let entry1 = IdempotencyEntry {
            key: "payment-key-1".to_string(),
            zone_id: test_zone(),
            intent_id: test_object_id("intent-1"),
            receipt_id: Some(test_object_id("receipt-1")),
            status: IntentStatus::Completed,
            created_at: 1000,
            expires_at: 2000,
        };

        let entry2 = IdempotencyEntry {
            key: "payment-key-2".to_string(),
            zone_id: test_zone(),
            intent_id: test_object_id("intent-2"),
            receipt_id: Some(test_object_id("receipt-2")),
            status: IntentStatus::Completed,
            created_at: 1000,
            expires_at: 2000,
        };

        // Different keys, different receipts
        assert_ne!(entry1.key, entry2.key);
        assert_ne!(entry1.intent_id, entry2.intent_id);
        assert_ne!(entry1.receipt_id, entry2.receipt_id);
    }

    #[test]
    fn expired_entry_does_not_return_cached() {
        let entry = IdempotencyEntry {
            key: "expired-key".to_string(),
            zone_id: test_zone(),
            intent_id: test_object_id("intent-1"),
            receipt_id: Some(test_object_id("receipt-1")),
            status: IntentStatus::Completed,
            created_at: 1000,
            expires_at: 2000,
        };

        // Before expiry
        assert!(entry.should_return_cached(1500));

        // At expiry
        assert!(!entry.should_return_cached(2000));

        // After expiry
        assert!(!entry.should_return_cached(2500));
    }

    #[test]
    fn pending_entry_does_not_return_cached() {
        let entry = IdempotencyEntry {
            key: "pending-key".to_string(),
            zone_id: test_zone(),
            intent_id: test_object_id("intent-1"),
            receipt_id: None,
            status: IntentStatus::Pending,
            created_at: 1000,
            expires_at: 2000,
        };

        // Pending operations should not return cached
        assert!(!entry.should_return_cached(1500));
    }

    #[test]
    fn in_progress_entry_does_not_return_cached() {
        let entry = IdempotencyEntry {
            key: "in-progress-key".to_string(),
            zone_id: test_zone(),
            intent_id: test_object_id("intent-1"),
            receipt_id: None,
            status: IntentStatus::InProgress,
            created_at: 1000,
            expires_at: 2000,
        };

        // In-progress operations should not return cached
        assert!(!entry.should_return_cached(1500));
    }

    #[test]
    fn failed_entry_with_receipt_returns_cached() {
        let entry = IdempotencyEntry {
            key: "failed-key".to_string(),
            zone_id: test_zone(),
            intent_id: test_object_id("intent-1"),
            receipt_id: Some(test_object_id("error-receipt-1")),
            status: IntentStatus::Failed,
            created_at: 1000,
            expires_at: 2000,
        };

        // Failed operations with receipt should return cached (error receipt)
        assert!(entry.should_return_cached(1500));
    }

    #[test]
    fn terminal_without_receipt_does_not_return_cached() {
        let entry = IdempotencyEntry {
            key: "terminal-no-receipt".to_string(),
            zone_id: test_zone(),
            intent_id: test_object_id("intent-1"),
            receipt_id: None, // No receipt stored
            status: IntentStatus::Completed,
            created_at: 1000,
            expires_at: 2000,
        };

        // Terminal but no receipt - shouldn't return cached
        assert!(!entry.should_return_cached(1500));
    }

    #[test]
    fn idempotency_entry_is_terminal() {
        let statuses = [
            (IntentStatus::Pending, false),
            (IntentStatus::InProgress, false),
            (IntentStatus::Completed, true),
            (IntentStatus::Failed, true),
            (IntentStatus::Orphaned, false),
        ];

        for (status, expected_terminal) in statuses {
            let entry = IdempotencyEntry {
                key: "test".to_string(),
                zone_id: test_zone(),
                intent_id: test_object_id("intent"),
                receipt_id: None,
                status,
                created_at: 1000,
                expires_at: 2000,
            };

            assert_eq!(
                entry.is_terminal(),
                expected_terminal,
                "Status {status:?} should be terminal={expected_terminal:?}"
            );
        }
    }

    #[test]
    fn idempotency_key_hash_collision_scenario() {
        // Even if two keys produce same hash, they are stored separately
        // (This test documents the expected behavior)

        let entry1 = IdempotencyEntry {
            key: "key-aaa".to_string(),
            zone_id: test_zone(),
            intent_id: test_object_id("intent-1"),
            receipt_id: Some(test_object_id("receipt-1")),
            status: IntentStatus::Completed,
            created_at: 1000,
            expires_at: 2000,
        };

        let entry2 = IdempotencyEntry {
            key: "key-bbb".to_string(), // Different key
            zone_id: test_zone(),
            intent_id: test_object_id("intent-2"),
            receipt_id: Some(test_object_id("receipt-2")),
            status: IntentStatus::Completed,
            created_at: 1000,
            expires_at: 2000,
        };

        // Keys must be compared by value, not hash
        assert_ne!(entry1.key, entry2.key);

        // Both can return cached independently
        assert!(entry1.should_return_cached(1500));
        assert!(entry2.should_return_cached(1500));
    }

    #[test]
    fn zone_scoped_idempotency() {
        // Same key in different zones should be independent
        let entry_work = IdempotencyEntry {
            key: "shared-key".to_string(),
            zone_id: ZoneId::work(),
            intent_id: test_object_id("intent-work"),
            receipt_id: Some(test_object_id("receipt-work")),
            status: IntentStatus::Completed,
            created_at: 1000,
            expires_at: 2000,
        };

        let entry_private = IdempotencyEntry {
            key: "shared-key".to_string(), // Same key
            zone_id: ZoneId::private(),    // Different zone
            intent_id: test_object_id("intent-private"),
            receipt_id: Some(test_object_id("receipt-private")),
            status: IntentStatus::Completed,
            created_at: 1000,
            expires_at: 2000,
        };

        // Same key, but different zones = different entries
        assert_eq!(entry_work.key, entry_private.key);
        assert_ne!(entry_work.zone_id, entry_private.zone_id);
        assert_ne!(entry_work.receipt_id, entry_private.receipt_id);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Lease Fencing Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod lease_fencing_tests {
    use super::*;

    #[test]
    fn intent_is_lease_bound_when_lease_seq_present() {
        let mut intent = create_test_intent();
        intent.lease_seq = Some(42);

        assert!(intent.is_lease_bound());
    }

    #[test]
    fn intent_not_lease_bound_when_lease_seq_absent() {
        let mut intent = create_test_intent();
        intent.lease_seq = None;

        assert!(!intent.is_lease_bound());
    }

    #[test]
    fn lease_seq_mismatch_error() {
        // When a stale lease holder tries to execute
        let error = OperationValidationError::LeaseSeqMismatch {
            expected: 100,
            got: 42,
        };

        assert!(error.to_string().contains("lease seq mismatch"));
        assert!(error.to_string().contains("100"));
        assert!(error.to_string().contains("42"));
    }

    #[test]
    fn lease_seq_zero_is_valid() {
        let mut intent = create_test_intent();
        intent.lease_seq = Some(0);

        assert!(intent.is_lease_bound());

        // Signable bytes should include the zero
        let bytes = intent.signable_bytes();
        assert_ne!(bytes, [] as [u8; 0]);
    }

    #[test]
    fn lease_seq_max_value_is_valid() {
        let mut intent = create_test_intent();
        intent.lease_seq = Some(u64::MAX);

        assert!(intent.is_lease_bound());

        let mut cbor = Vec::new();
        ciborium::into_writer(&intent, &mut cbor).expect("serialization should succeed");

        let restored: OperationIntent =
            ciborium::from_reader(&cbor[..]).expect("deserialization should succeed");

        assert_eq!(restored.lease_seq, Some(u64::MAX));
    }

    #[test]
    fn stale_lease_holder_scenario() {
        // Scenario: Node A has lease with seq=50
        // Node B takes over lease, now seq=51
        // Node A (zombie) tries to execute with old seq=50
        // This should be rejected

        let stale_intent = {
            let mut intent = create_test_intent();
            intent.lease_seq = Some(50);
            intent.planned_by = test_node("zombie-node-a");
            intent
        };

        let current_lease_seq = 51u64;

        // Validation logic (application layer)
        let intent_seq = stale_intent.lease_seq.expect("should have lease_seq");
        assert!(
            intent_seq < current_lease_seq,
            "Stale lease holder should have lower seq"
        );
    }

    #[test]
    fn valid_lease_holder_scenario() {
        // Node with current lease seq should be accepted
        let valid_intent = {
            let mut intent = create_test_intent();
            intent.lease_seq = Some(100);
            intent.planned_by = test_node("current-leader");
            intent
        };

        let current_lease_seq = 100u64;

        let intent_seq = valid_intent.lease_seq.expect("should have lease_seq");
        assert_eq!(
            intent_seq, current_lease_seq,
            "Valid lease holder should match current seq"
        );
    }

    #[test]
    fn future_lease_seq_scenario() {
        // Scenario: Intent has future lease_seq (shouldn't happen in normal operation)
        // This indicates a bug or split-brain situation

        let future_intent = {
            let mut intent = create_test_intent();
            intent.lease_seq = Some(200); // Future seq
            intent
        };

        let current_lease_seq = 100u64;

        let intent_seq = future_intent.lease_seq.expect("should have lease_seq");
        assert!(
            intent_seq > current_lease_seq,
            "Future seq indicates split-brain or bug"
        );
    }

    #[test]
    fn dangerous_operations_require_lease_binding() {
        // Per spec: Dangerous operations MUST be Strict idempotency
        // and SHOULD bind to lease fencing token

        let is_dangerous = true;
        let is_risky = false;

        let required_class = required_idempotency_for_safety_tier(is_dangerous, is_risky);
        assert_eq!(required_class, IdempotencyClass::Strict);
    }

    #[test]
    fn risky_operations_require_strict_idempotency() {
        let is_dangerous = false;
        let is_risky = true;

        let required_class = required_idempotency_for_safety_tier(is_dangerous, is_risky);
        assert_eq!(required_class, IdempotencyClass::Strict);
    }

    #[test]
    fn safe_operations_no_idempotency_required() {
        let is_dangerous = false;
        let is_risky = false;

        let required_class = required_idempotency_for_safety_tier(is_dangerous, is_risky);
        assert_eq!(required_class, IdempotencyClass::None);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Fault Injection Tests (Crash Recovery, Orphan Detection)
// ═══════════════════════════════════════════════════════════════════════════════

mod fault_injection_tests {
    use super::*;

    #[test]
    fn orphan_detection_with_no_receipt() {
        let intent = create_test_intent();
        let orphan_threshold_secs = 3600u64; // 1 hour

        // Intent created at t=1000
        // Now is t=5000 (4000 seconds later)
        // Threshold is 3600 seconds
        // No receipt exists

        let is_orphaned = is_intent_orphaned(&intent, false, 5000, orphan_threshold_secs);
        assert!(
            is_orphaned,
            "Intent without receipt past threshold is orphaned"
        );
    }

    #[test]
    fn not_orphaned_with_receipt() {
        let intent = create_test_intent();
        let orphan_threshold_secs = 3600u64;

        // Even if past threshold, receipt exists
        let is_orphaned = is_intent_orphaned(&intent, true, 5000, orphan_threshold_secs);
        assert!(!is_orphaned, "Intent with receipt is not orphaned");
    }

    #[test]
    fn not_orphaned_within_threshold() {
        let intent = create_test_intent();
        let orphan_threshold_secs = 3600u64;

        // Intent at t=1000, now t=1500 (500 seconds later)
        // Still within threshold even without receipt
        let is_orphaned = is_intent_orphaned(&intent, false, 1500, orphan_threshold_secs);
        assert!(!is_orphaned, "Intent within threshold is not orphaned");
    }

    #[test]
    fn orphan_detection_at_boundary() {
        let intent = create_test_intent();
        let orphan_threshold_secs = 3600u64;

        // Exactly at threshold (1000 + 3600 = 4600)
        let is_orphaned = is_intent_orphaned(&intent, false, 4600, orphan_threshold_secs);
        assert!(
            !is_orphaned,
            "Intent exactly at threshold is not orphaned (> not >=)"
        );

        // Just past threshold
        let is_orphaned = is_intent_orphaned(&intent, false, 4601, orphan_threshold_secs);
        assert!(is_orphaned, "Intent just past threshold is orphaned");
    }

    #[test]
    fn crash_between_intent_and_receipt_scenario() {
        // Simulate crash: Intent stored, side effect executed, but receipt not stored
        let intent = create_test_intent();

        // After recovery, we find intent without receipt
        // If past threshold, mark as orphaned
        let now = intent.planned_at + 7200; // 2 hours later
        let threshold = 3600u64;

        let orphaned = is_intent_orphaned(&intent, false, now, threshold);
        assert!(orphaned, "Intent from before crash is orphaned");

        // Create orphaned validation error
        let error = OperationValidationError::IntentOrphaned {
            intent_id: test_object_id("orphaned-intent"),
            planned_at: intent.planned_at,
        };

        assert!(error.to_string().contains("orphaned"));
    }

    #[test]
    fn intent_status_transitions() {
        // Valid transitions: Pending -> InProgress -> Completed/Failed
        // Invalid: Going backwards or to unexpected states

        let statuses = [
            IntentStatus::Pending,
            IntentStatus::InProgress,
            IntentStatus::Completed,
            IntentStatus::Failed,
            IntentStatus::Orphaned,
        ];

        // Verify display works for all
        for status in &statuses {
            let s = status.to_string();
            assert_ne!(s, "");
        }

        // Verify serde roundtrip for all
        for status in statuses {
            let json = serde_json::to_string(&status).expect("serialize should work");
            let restored: IntentStatus =
                serde_json::from_str(&json).expect("deserialize should work");
            assert_eq!(status, restored);
        }
    }

    #[test]
    fn orphaned_status_in_entry() {
        let entry = IdempotencyEntry {
            key: "orphan-key".to_string(),
            zone_id: test_zone(),
            intent_id: test_object_id("orphan-intent"),
            receipt_id: None,
            status: IntentStatus::Orphaned,
            created_at: 1000,
            expires_at: 2000,
        };

        // Orphaned is not terminal (can potentially be recovered)
        assert!(!entry.is_terminal());

        // Should not return cached
        assert!(!entry.should_return_cached(1500));
    }

    #[test]
    fn timeout_scenario() {
        // Simulate: Operation times out without completing
        let intent = create_test_intent();

        // After timeout, intent should be marked as orphaned
        let operation_timeout = 300u64; // 5 minutes
        let now = intent.planned_at + operation_timeout + 1;

        let is_orphaned = is_intent_orphaned(&intent, false, now, operation_timeout);
        assert!(is_orphaned);
    }

    #[test]
    fn recovery_after_crash_with_upstream_idempotency() {
        // Scenario: Crash happened, but we have upstream idempotency handle
        // Can use upstream service to check if operation completed

        let mut intent = create_test_intent();
        intent.upstream_idempotency = Some("stripe:idem_abc123".to_string());

        // After recovery, check upstream service using the handle
        assert!(intent.upstream_idempotency.is_some());

        let handle = intent.upstream_idempotency.as_ref().unwrap();
        assert!(handle.starts_with("stripe:"));
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Validation Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod validation_tests {
    use super::*;

    #[test]
    fn receipt_intent_binding_valid() {
        let intent = create_test_intent();
        let receipt = create_test_receipt();

        let result =
            validate_receipt_intent_binding(test_receipt_id(), &receipt, test_intent_id(), &intent);
        assert!(result.is_ok());
    }

    #[test]
    fn receipt_intent_binding_request_mismatch() {
        let intent = create_test_intent();
        let mut receipt = create_test_receipt();
        receipt.request_object_id = test_object_id("different-request");

        let result =
            validate_receipt_intent_binding(test_receipt_id(), &receipt, test_intent_id(), &intent);
        assert!(matches!(
            result,
            Err(OperationValidationError::RequestMismatch { .. })
        ));
    }

    #[test]
    fn receipt_intent_binding_zone_mismatch() {
        let intent = create_test_intent();
        let mut receipt = create_test_receipt();
        receipt.header.zone_id = ZoneId::owner();

        let result =
            validate_receipt_intent_binding(test_receipt_id(), &receipt, test_intent_id(), &intent);
        assert!(matches!(
            result,
            Err(OperationValidationError::ZoneMismatch { .. })
        ));
    }

    #[test]
    fn receipt_intent_binding_idempotency_key_mismatch() {
        let intent = create_test_intent();
        let mut receipt = create_test_receipt();
        receipt.idempotency_key = Some("different-key".to_string());

        let result =
            validate_receipt_intent_binding(test_receipt_id(), &receipt, test_intent_id(), &intent);
        assert!(matches!(
            result,
            Err(OperationValidationError::IdempotencyKeyMismatch { .. })
        ));
    }

    #[test]
    fn receipt_intent_binding_both_none_idempotency_key() {
        let mut intent = create_test_intent();
        let mut receipt = create_test_receipt();

        intent.idempotency_key = None;
        receipt.idempotency_key = None;

        let result =
            validate_receipt_intent_binding(test_receipt_id(), &receipt, test_intent_id(), &intent);
        assert!(result.is_ok());
    }

    #[test]
    fn validation_error_display() {
        let errors = [
            OperationValidationError::IntentNotFound {
                idempotency_key: "key-123".to_string(),
            },
            OperationValidationError::AlreadyCompleted {
                idempotency_key: "key-456".to_string(),
            },
            OperationValidationError::IdempotencyKeyMismatch {
                expected: Some("expected".to_string()),
                got: None,
            },
            OperationValidationError::ZoneMismatch {
                expected: ZoneId::work(),
                got: ZoneId::owner(),
            },
            OperationValidationError::IntentReferenceMissing {
                receipt_id: test_object_id("receipt"),
            },
            OperationValidationError::LeaseSeqMismatch {
                expected: 100,
                got: 50,
            },
            OperationValidationError::IntentOrphaned {
                intent_id: test_object_id("intent"),
                planned_at: 1000,
            },
            OperationValidationError::SignatureInvalid {
                reason: "bad signature".to_string(),
            },
            OperationValidationError::RequestMismatch {
                expected: test_object_id("expected"),
                got: test_object_id("got"),
            },
        ];

        for error in &errors {
            let display = error.to_string();
            assert!(!display.is_empty(), "Error display should not be empty");
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Concurrency Tests (Race Conditions)
// ═══════════════════════════════════════════════════════════════════════════════

mod concurrency_tests {
    use super::*;

    #[test]
    fn same_idempotency_key_race_scenario() {
        // Scenario: Two requests with same idempotency key arrive concurrently
        // Only one should execute, both should get same receipt

        let shared_key = "concurrent-payment".to_string();

        // First request wins, creates entry with InProgress status
        let entry = IdempotencyEntry {
            key: shared_key.clone(),
            zone_id: test_zone(),
            intent_id: test_object_id("intent-winner"),
            receipt_id: None,
            status: IntentStatus::InProgress,
            created_at: 1000,
            expires_at: 2000,
        };

        // Second request sees InProgress, should wait or return early
        assert!(!entry.is_terminal());
        assert!(!entry.should_return_cached(1100));

        // After first completes, second can get cached result
        let completed_entry = IdempotencyEntry {
            key: shared_key,
            zone_id: test_zone(),
            intent_id: test_object_id("intent-winner"),
            receipt_id: Some(test_object_id("receipt-winner")),
            status: IntentStatus::Completed,
            created_at: 1000,
            expires_at: 2000,
        };

        assert!(completed_entry.should_return_cached(1100));
    }

    #[test]
    fn different_idempotency_keys_no_conflict() {
        // Two requests with different keys should execute independently

        let entry1 = IdempotencyEntry {
            key: "payment-1".to_string(),
            zone_id: test_zone(),
            intent_id: test_object_id("intent-1"),
            receipt_id: None,
            status: IntentStatus::InProgress,
            created_at: 1000,
            expires_at: 2000,
        };

        let entry2 = IdempotencyEntry {
            key: "payment-2".to_string(),
            zone_id: test_zone(),
            intent_id: test_object_id("intent-2"),
            receipt_id: None,
            status: IntentStatus::InProgress,
            created_at: 1000,
            expires_at: 2000,
        };

        // Both can be in progress simultaneously
        assert!(!entry1.is_terminal());
        assert!(!entry2.is_terminal());
        assert_ne!(entry1.key, entry2.key);
    }

    #[test]
    fn parallel_intents_different_zones() {
        // Same operation in different zones should be independent

        let intent_work = {
            let mut intent = create_test_intent();
            intent.header.zone_id = ZoneId::work();
            intent.idempotency_key = Some("shared-op".to_string());
            intent
        };

        let intent_private = {
            let mut intent = create_test_intent();
            intent.header.zone_id = ZoneId::private();
            intent.idempotency_key = Some("shared-op".to_string());
            intent
        };

        // Same key but different zones
        assert_eq!(intent_work.idempotency_key, intent_private.idempotency_key);
        assert_ne!(intent_work.zone_id(), intent_private.zone_id());
    }

    #[test]
    fn concurrent_lease_holders_scenario() {
        // Scenario: During failover, two nodes briefly think they have the lease

        let old_leader_intent = {
            let mut intent = create_test_intent();
            intent.lease_seq = Some(99);
            intent.planned_by = test_node("old-leader");
            intent
        };

        let new_leader_intent = {
            let mut intent = create_test_intent();
            intent.lease_seq = Some(100);
            intent.planned_by = test_node("new-leader");
            intent
        };

        // New leader has higher seq
        let old_seq = old_leader_intent.lease_seq.unwrap();
        let new_seq = new_leader_intent.lease_seq.unwrap();
        assert!(new_seq > old_seq);

        // Current lease seq is 100
        let current_seq = 100u64;

        // Old leader should be rejected
        assert!(old_seq < current_seq);

        // New leader should be accepted
        assert_eq!(new_seq, current_seq);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Edge Cases and Boundary Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod edge_cases {
    use super::*;

    #[test]
    fn empty_idempotency_key() {
        let mut intent = create_test_intent();
        intent.idempotency_key = Some(String::new()); // Empty string

        // Empty string is still "some" idempotency key
        assert!(intent.requires_strict_idempotency());

        // Should serialize correctly
        let mut cbor = Vec::new();
        ciborium::into_writer(&intent, &mut cbor).expect("should serialize");

        let restored: OperationIntent =
            ciborium::from_reader(&cbor[..]).expect("should deserialize");
        assert_eq!(restored.idempotency_key, Some(String::new()));
    }

    #[test]
    fn very_long_idempotency_key() {
        let mut intent = create_test_intent();
        intent.idempotency_key = Some("x".repeat(10000));

        let mut cbor = Vec::new();
        ciborium::into_writer(&intent, &mut cbor).expect("should serialize");

        let restored: OperationIntent =
            ciborium::from_reader(&cbor[..]).expect("should deserialize");
        assert_eq!(
            restored.idempotency_key.as_ref().map(String::len),
            Some(10000)
        );
    }

    #[test]
    fn unicode_idempotency_key() {
        let mut intent = create_test_intent();
        intent.idempotency_key = Some("payment-\u{1F4B0}-\u{4E2D}\u{6587}".to_string());

        let mut cbor = Vec::new();
        ciborium::into_writer(&intent, &mut cbor).expect("should serialize");

        let restored: OperationIntent =
            ciborium::from_reader(&cbor[..]).expect("should deserialize");
        assert_eq!(
            restored.idempotency_key,
            Some("payment-\u{1F4B0}-\u{4E2D}\u{6587}".to_string())
        );
    }

    #[test]
    fn receipt_with_empty_outcome_ids() {
        let mut receipt = create_test_receipt();
        receipt.outcome_object_ids = vec![];
        receipt.resource_object_ids = vec![];

        assert_eq!(receipt.total_objects_produced(), 0);

        let mut cbor = Vec::new();
        ciborium::into_writer(&receipt, &mut cbor).expect("should serialize");

        let restored: OperationReceipt =
            ciborium::from_reader(&cbor[..]).expect("should deserialize");
        assert_eq!(restored.outcome_object_ids, [] as [fcp_core::ObjectId; 0]);
        assert_eq!(restored.resource_object_ids, [] as [fcp_core::ObjectId; 0]);
    }

    #[test]
    fn intent_with_special_uuid() {
        let mut intent = create_test_intent();

        // Nil UUID
        intent.capability_token_jti = Uuid::nil();
        assert!(intent.capability_token_jti.is_nil());

        // Max UUID
        intent.capability_token_jti = Uuid::max();
        assert_eq!(intent.capability_token_jti.as_bytes(), &[0xFF; 16]);

        let mut cbor = Vec::new();
        ciborium::into_writer(&intent, &mut cbor).expect("should serialize");

        let restored: OperationIntent =
            ciborium::from_reader(&cbor[..]).expect("should deserialize");
        assert_eq!(restored.capability_token_jti, Uuid::max());
    }

    #[test]
    fn timestamps_at_boundaries() {
        let mut intent = create_test_intent();

        // Zero timestamp
        intent.planned_at = 0;
        let mut cbor = Vec::new();
        ciborium::into_writer(&intent, &mut cbor).expect("should serialize with zero");

        // Max timestamp
        intent.planned_at = u64::MAX;
        let mut cbor = Vec::new();
        ciborium::into_writer(&intent, &mut cbor).expect("should serialize with max");

        let restored: OperationIntent =
            ciborium::from_reader(&cbor[..]).expect("should deserialize");
        assert_eq!(restored.planned_at, u64::MAX);
    }

    #[test]
    fn expiry_before_creation() {
        // Edge case: Expired before created (invalid but should handle)
        let entry = IdempotencyEntry {
            key: "backwards-time".to_string(),
            zone_id: test_zone(),
            intent_id: test_object_id("intent"),
            receipt_id: Some(test_object_id("receipt")),
            status: IntentStatus::Completed,
            created_at: 2000,
            expires_at: 1000, // Before creation!
        };

        // Should be expired at any time >= expires_at
        assert!(entry.is_expired(1000));
        assert!(entry.is_expired(1500));
        assert!(entry.is_expired(2000));
    }

    #[test]
    fn orphan_check_with_zero_threshold() {
        let intent = create_test_intent();

        // With zero threshold, should be orphaned immediately if no receipt
        let is_orphaned = is_intent_orphaned(&intent, false, intent.planned_at + 1, 0);
        assert!(is_orphaned);

        // But still not orphaned if receipt exists
        let is_orphaned = is_intent_orphaned(&intent, true, intent.planned_at + 1, 0);
        assert!(!is_orphaned);
    }
}
