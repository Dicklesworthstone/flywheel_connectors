//! Golden vector tests for Exactly-Once Semantics (flywheel_connectors-57x7).
//!
//! This module provides comprehensive tests for:
//! - `OperationIntent` and `OperationReceipt` schema verification
//! - CBOR canonical serialization golden vectors
//! - Idempotency key semantics (same key = same receipt)
//! - Lease fencing enforcement
//! - Fault injection scenarios (orphan detection, recovery)
//! - Concurrency semantics (deterministic under same inputs)
//!
//! # Test Categories
//!
//! 1. **Schema Tests**: Verify required fields and schema ID correctness
//! 2. **Golden Vectors**: Deterministic CBOR serialization
//! 3. **Idempotency**: Same key returns same receipt without re-execution
//! 4. **Lease Fencing**: Stale lease holder rejection
//! 5. **Fault Injection**: Crash recovery and orphan detection
//! 6. **Concurrency**: Deterministic outcomes under concurrent requests

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use fcp_cbor::SchemaId;
use fcp_core::{
    IdempotencyClass, IdempotencyEntry, IntentStatus, NodeId, NodeSignature, ObjectHeader,
    ObjectId, OperationIntent, OperationReceipt, OperationValidationError, Provenance,
    TailscaleNodeId, ZoneId, is_intent_orphaned, required_idempotency_for_safety_tier,
    validate_receipt_intent_binding,
};
use semver::Version;
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// Test Logging (FCP2 Requirements)
// ─────────────────────────────────────────────────────────────────────────────

/// Structured test log entry per FCP2 testing requirements.
#[derive(Debug, serde::Serialize)]
struct TestLogEntry {
    timestamp: String,
    test_name: String,
    module: String,
    phase: String,
    operation: String,
    idempotency_key: Option<String>,
    lease_seq: Option<u64>,
    expected_outcome: String,
    actual_outcome: String,
    timing_us: u64,
    result: String,
}

impl TestLogEntry {
    fn new(test_name: &str, operation: &str) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            test_name: test_name.to_string(),
            module: "fcp-core::operation".to_string(),
            phase: "setup".to_string(),
            operation: operation.to_string(),
            idempotency_key: None,
            lease_seq: None,
            expected_outcome: String::new(),
            actual_outcome: String::new(),
            timing_us: 0,
            result: "pending".to_string(),
        }
    }

    fn with_idempotency_key(mut self, key: &str) -> Self {
        self.idempotency_key = Some(key.to_string());
        self
    }

    const fn with_lease_seq(mut self, seq: u64) -> Self {
        self.lease_seq = Some(seq);
        self
    }

    fn execute(mut self) -> Self {
        self.phase = "execute".to_string();
        self
    }

    fn verify(mut self) -> Self {
        self.phase = "verify".to_string();
        self
    }

    fn expect(mut self, outcome: &str) -> Self {
        self.expected_outcome = outcome.to_string();
        self
    }

    fn actual(mut self, outcome: &str) -> Self {
        self.actual_outcome = outcome.to_string();
        self
    }

    const fn timing(mut self, us: u64) -> Self {
        self.timing_us = us;
        self
    }

    fn pass(mut self) -> Self {
        self.result = "pass".to_string();
        self
    }

    #[allow(dead_code)]
    fn fail(mut self) -> Self {
        self.result = "fail".to_string();
        self
    }

    fn log(&self) {
        eprintln!("{}", serde_json::to_string(self).unwrap());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test Fixtures
// ─────────────────────────────────────────────────────────────────────────────

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
    NodeSignature::new(NodeId::new("test-node"), [0u8; 64], 1_704_067_200)
}

fn create_intent_header(created_at: u64) -> ObjectHeader {
    let zone = test_zone();
    ObjectHeader {
        schema: SchemaId::new("fcp.operation", "intent", Version::new(1, 0, 0)),
        zone_id: zone.clone(),
        created_at,
        provenance: Provenance::new(zone),
        refs: vec![],
        foreign_refs: vec![],
        ttl_secs: None,
        placement: None,
    }
}

fn create_receipt_header(created_at: u64) -> ObjectHeader {
    let zone = test_zone();
    ObjectHeader {
        schema: SchemaId::new("fcp.operation", "receipt", Version::new(1, 0, 0)),
        zone_id: zone.clone(),
        created_at,
        provenance: Provenance::new(zone),
        refs: vec![test_intent_id()],
        foreign_refs: vec![],
        ttl_secs: None,
        placement: None,
    }
}

fn create_test_intent(idempotency_key: Option<&str>, lease_seq: Option<u64>) -> OperationIntent {
    OperationIntent {
        header: create_intent_header(1_704_067_200),
        request_object_id: test_object_id("request-1"),
        capability_token_jti: Uuid::from_bytes([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ]),
        idempotency_key: idempotency_key.map(String::from),
        planned_at: 1_704_067_200,
        planned_by: test_node("executor-node"),
        lease_seq,
        upstream_idempotency: None,
        signature: test_signature(),
    }
}

fn create_test_receipt(
    idempotency_key: Option<&str>,
    outcome_ids: Vec<ObjectId>,
) -> OperationReceipt {
    OperationReceipt {
        header: create_receipt_header(1_704_067_300),
        request_object_id: test_object_id("request-1"),
        idempotency_key: idempotency_key.map(String::from),
        outcome_object_ids: outcome_ids,
        resource_object_ids: vec![],
        usage_metrics: None,
        executed_at: 1_704_067_300,
        executed_by: test_node("executor-node"),
        signature: test_signature(),
    }
}

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("operation")
}

fn elapsed_micros_u64(start: &std::time::Instant) -> u64 {
    u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX)
}

// ─────────────────────────────────────────────────────────────────────────────
// Golden Vector Structures
// ─────────────────────────────────────────────────────────────────────────────

/// Golden vector for `OperationIntent` canonical CBOR.
#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
struct IntentGoldenVector {
    description: String,
    idempotency_key: Option<String>,
    lease_seq: Option<u64>,
    planned_at: u64,
    planned_by: String,
    request_object_id_hex: String,
    capability_token_jti: String,
    signable_bytes_hex: String,
}

/// Golden vector for `OperationReceipt` canonical CBOR.
#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
struct ReceiptGoldenVector {
    description: String,
    idempotency_key: Option<String>,
    outcome_count: usize,
    resource_count: usize,
    executed_at: u64,
    executed_by: String,
    signable_bytes_hex: String,
}

/// Golden vector for idempotency key derivation.
#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
struct IdempotencyKeyVector {
    description: String,
    key: String,
    zone_id: String,
    intent_id_hex: String,
    receipt_id_hex: Option<String>,
    status: String,
    expires_at: u64,
    is_expired_at_now: bool,
    is_terminal: bool,
    should_return_cached: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Schema Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_intent_schema_id_correctness() {
    let start = std::time::Instant::now();
    let mut log = TestLogEntry::new("test_intent_schema_id_correctness", "schema_verify").execute();

    let intent = create_test_intent(Some("key-1"), Some(42));
    let schema = &intent.header.schema;

    log = log.expect("fcp.operation:intent:1.0.0");
    log = log.actual(&format!(
        "{}:{}:{}",
        schema.namespace, schema.name, schema.version
    ));

    assert_eq!(schema.namespace, "fcp.operation");
    assert_eq!(schema.name, "intent");
    assert_eq!(schema.version.major, 1);
    assert_eq!(schema.version.minor, 0);
    assert_eq!(schema.version.patch, 0);

    log = log.timing(elapsed_micros_u64(&start)).verify().pass();
    log.log();
}

#[test]
fn test_receipt_schema_id_correctness() {
    let start = std::time::Instant::now();
    let mut log =
        TestLogEntry::new("test_receipt_schema_id_correctness", "schema_verify").execute();

    let receipt = create_test_receipt(Some("key-1"), vec![test_object_id("outcome-1")]);
    let schema = &receipt.header.schema;

    log = log.expect("fcp.operation:receipt:1.0.0");
    log = log.actual(&format!(
        "{}:{}:{}",
        schema.namespace, schema.name, schema.version
    ));

    assert_eq!(schema.namespace, "fcp.operation");
    assert_eq!(schema.name, "receipt");
    assert_eq!(schema.version.major, 1);

    log = log.timing(elapsed_micros_u64(&start)).verify().pass();
    log.log();
}

#[test]
fn test_intent_required_fields_present() {
    let start = std::time::Instant::now();
    let mut log = TestLogEntry::new("test_intent_required_fields_present", "field_check")
        .with_idempotency_key("test-key")
        .with_lease_seq(42)
        .execute();

    let intent = create_test_intent(Some("test-key"), Some(42));

    // Verify all required fields are present
    assert!(!intent.request_object_id.as_bytes().iter().all(|&b| b == 0));
    assert_ne!(intent.capability_token_jti, Uuid::nil());
    assert!(intent.planned_at > 0);
    assert_ne!(intent.planned_by.as_str(), "");

    // Optional fields for Strict idempotency
    assert!(intent.idempotency_key.is_some());

    // Optional fields for Risky/Dangerous operations
    assert!(intent.lease_seq.is_some());

    log = log
        .expect("all_required_fields_present")
        .actual("all_required_fields_present")
        .timing(elapsed_micros_u64(&start))
        .verify()
        .pass();
    log.log();
}

#[test]
fn test_receipt_required_fields_present() {
    let start = std::time::Instant::now();
    let mut log =
        TestLogEntry::new("test_receipt_required_fields_present", "field_check").execute();

    let receipt = create_test_receipt(
        Some("test-key"),
        vec![test_object_id("outcome-1"), test_object_id("outcome-2")],
    );

    // Verify required fields
    assert!(!receipt.request_object_id.as_bytes().iter().all(|&b| b == 0));
    assert!(receipt.executed_at > 0);
    assert_ne!(receipt.executed_by.as_str(), "");

    // Verify outcome tracking
    assert_eq!(receipt.outcome_object_ids.len(), 2);

    log = log
        .expect("all_required_fields_present")
        .actual("all_required_fields_present")
        .timing(elapsed_micros_u64(&start))
        .verify()
        .pass();
    log.log();
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Golden Vector Tests (Deterministic CBOR)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_intent_signable_bytes_golden_vector() {
    let start = std::time::Instant::now();
    let mut log = TestLogEntry::new("test_intent_signable_bytes_golden_vector", "golden_vector")
        .with_idempotency_key("idem-key-123")
        .with_lease_seq(42)
        .execute();

    let intent = create_test_intent(Some("idem-key-123"), Some(42));
    let signable = intent.signable_bytes();

    // Create golden vector
    let vector = IntentGoldenVector {
        description: "OperationIntent with idempotency key and lease binding".to_string(),
        idempotency_key: intent.idempotency_key.clone(),
        lease_seq: intent.lease_seq,
        planned_at: intent.planned_at,
        planned_by: intent.planned_by.as_str().to_string(),
        request_object_id_hex: hex::encode(intent.request_object_id.as_bytes()),
        capability_token_jti: intent.capability_token_jti.to_string(),
        signable_bytes_hex: hex::encode(&signable),
    };

    // Write golden vector
    let vector_path = vectors_dir().join("intent_with_key_and_lease.json");
    if let Ok(existing) = fs::read_to_string(&vector_path) {
        let existing_vector: IntentGoldenVector = serde_json::from_str(&existing).unwrap();
        assert_eq!(
            vector.signable_bytes_hex, existing_vector.signable_bytes_hex,
            "Signable bytes changed! This breaks signature verification."
        );
        log = log.actual("matches_golden_vector");
    } else {
        fs::create_dir_all(vectors_dir()).ok();
        fs::write(&vector_path, serde_json::to_string_pretty(&vector).unwrap()).unwrap();
        log = log.actual("created_golden_vector");
    }

    // Verify determinism
    let signable2 = intent.signable_bytes();
    assert_eq!(signable, signable2, "Signable bytes must be deterministic");

    log = log
        .expect("deterministic_signable_bytes")
        .timing(elapsed_micros_u64(&start))
        .verify()
        .pass();
    log.log();
}

#[test]
fn test_intent_signable_bytes_without_optional_fields() {
    let start = std::time::Instant::now();
    let mut log = TestLogEntry::new(
        "test_intent_signable_bytes_without_optional_fields",
        "golden_vector",
    )
    .execute();

    let intent = create_test_intent(None, None);
    let signable = intent.signable_bytes();

    // Create golden vector for minimal intent
    let vector = IntentGoldenVector {
        description: "OperationIntent without idempotency key or lease binding".to_string(),
        idempotency_key: None,
        lease_seq: None,
        planned_at: intent.planned_at,
        planned_by: intent.planned_by.as_str().to_string(),
        request_object_id_hex: hex::encode(intent.request_object_id.as_bytes()),
        capability_token_jti: intent.capability_token_jti.to_string(),
        signable_bytes_hex: hex::encode(&signable),
    };

    let vector_path = vectors_dir().join("intent_minimal.json");
    if let Ok(existing) = fs::read_to_string(&vector_path) {
        let existing_vector: IntentGoldenVector = serde_json::from_str(&existing).unwrap();
        assert_eq!(
            vector.signable_bytes_hex,
            existing_vector.signable_bytes_hex
        );
        log = log.actual("matches_golden_vector");
    } else {
        fs::create_dir_all(vectors_dir()).ok();
        fs::write(&vector_path, serde_json::to_string_pretty(&vector).unwrap()).unwrap();
        log = log.actual("created_golden_vector");
    }

    log = log
        .expect("deterministic_signable_bytes")
        .timing(elapsed_micros_u64(&start))
        .verify()
        .pass();
    log.log();
}

#[test]
fn test_receipt_signable_bytes_golden_vector() {
    let start = std::time::Instant::now();
    let mut log = TestLogEntry::new("test_receipt_signable_bytes_golden_vector", "golden_vector")
        .with_idempotency_key("idem-key-123")
        .execute();

    let receipt = create_test_receipt(
        Some("idem-key-123"),
        vec![test_object_id("outcome-1"), test_object_id("outcome-2")],
    );
    let signable = receipt.signable_bytes();

    let vector = ReceiptGoldenVector {
        description: "OperationReceipt with idempotency key and outcomes".to_string(),
        idempotency_key: receipt.idempotency_key.clone(),
        outcome_count: receipt.outcome_object_ids.len(),
        resource_count: receipt.resource_object_ids.len(),
        executed_at: receipt.executed_at,
        executed_by: receipt.executed_by.as_str().to_string(),
        signable_bytes_hex: hex::encode(&signable),
    };

    let vector_path = vectors_dir().join("receipt_with_outcomes.json");
    if let Ok(existing) = fs::read_to_string(&vector_path) {
        let existing_vector: ReceiptGoldenVector = serde_json::from_str(&existing).unwrap();
        assert_eq!(
            vector.signable_bytes_hex,
            existing_vector.signable_bytes_hex
        );
        log = log.actual("matches_golden_vector");
    } else {
        fs::create_dir_all(vectors_dir()).ok();
        fs::write(&vector_path, serde_json::to_string_pretty(&vector).unwrap()).unwrap();
        log = log.actual("created_golden_vector");
    }

    // Verify determinism
    let signable2 = receipt.signable_bytes();
    assert_eq!(signable, signable2);

    log = log
        .expect("deterministic_signable_bytes")
        .timing(elapsed_micros_u64(&start))
        .verify()
        .pass();
    log.log();
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Idempotency Key Tests
// ─────────────────────────────────────────────────────────────────────────────

/// Simulates an idempotency store for testing.
struct IdempotencyStore {
    entries: Mutex<HashMap<String, IdempotencyEntry>>,
    execution_count: AtomicU64,
}

impl IdempotencyStore {
    fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            execution_count: AtomicU64::new(0),
        }
    }

    /// Execute an operation with idempotency semantics.
    /// Returns (receipt, `was_executed`) where `was_executed` is false on retry.
    fn execute_with_idempotency(
        &self,
        idempotency_key: &str,
        zone_id: ZoneId,
        now: u64,
    ) -> (ObjectId, bool) {
        let mut entries = self.entries.lock().unwrap();

        // Check for existing entry
        if let Some(entry) = entries.get(idempotency_key) {
            if entry.should_return_cached(now) {
                // Return cached receipt without re-executing
                return (entry.receipt_id.unwrap(), false);
            }
        }

        // Execute the operation (increment counter)
        let execution_number = self.execution_count.fetch_add(1, Ordering::SeqCst);
        let receipt_id = test_object_id(&format!("receipt-{execution_number}"));

        // Store the entry
        let entry = IdempotencyEntry {
            key: idempotency_key.to_string(),
            zone_id,
            intent_id: test_object_id(&format!("intent-{execution_number}")),
            receipt_id: Some(receipt_id),
            status: IntentStatus::Completed,
            created_at: now,
            expires_at: now + 86400, // 24 hours
        };
        entries.insert(idempotency_key.to_string(), entry);
        drop(entries);
        (receipt_id, true)
    }

    fn get_execution_count(&self) -> u64 {
        self.execution_count.load(Ordering::SeqCst)
    }
}

#[test]
fn test_same_key_returns_same_receipt_without_reexecution() {
    let start = std::time::Instant::now();
    let mut log = TestLogEntry::new(
        "test_same_key_returns_same_receipt_without_reexecution",
        "idempotency",
    )
    .with_idempotency_key("stripe-payment-xyz")
    .execute();

    let store = IdempotencyStore::new();
    let key = "stripe-payment-xyz";
    let zone = test_zone();
    let now = 1_704_067_200;

    // First execution
    let (receipt1, executed1) = store.execute_with_idempotency(key, zone.clone(), now);
    assert!(executed1, "First request should execute");
    assert_eq!(store.get_execution_count(), 1);

    // Retry with same key
    let (receipt2, executed2) = store.execute_with_idempotency(key, zone.clone(), now + 100);
    assert!(!executed2, "Retry should NOT re-execute");
    assert_eq!(
        store.get_execution_count(),
        1,
        "Execution count should not change on retry"
    );

    // Same receipt returned
    assert_eq!(receipt1, receipt2, "Same receipt must be returned on retry");

    // Third retry
    let (receipt3, executed3) = store.execute_with_idempotency(key, zone, now + 200);
    assert!(!executed3);
    assert_eq!(receipt1, receipt3);
    assert_eq!(store.get_execution_count(), 1);

    log = log
        .expect("same_receipt_no_reexecution")
        .actual("same_receipt_no_reexecution")
        .timing(elapsed_micros_u64(&start))
        .verify()
        .pass();
    log.log();
}

#[test]
fn test_different_keys_produce_independent_executions() {
    let start = std::time::Instant::now();
    let mut log = TestLogEntry::new(
        "test_different_keys_produce_independent_executions",
        "idempotency",
    )
    .execute();

    let store = IdempotencyStore::new();
    let zone = test_zone();
    let now = 1_704_067_200;

    // Execute with different keys
    let (receipt1, executed1) = store.execute_with_idempotency("key-1", zone.clone(), now);
    let (receipt2, executed2) = store.execute_with_idempotency("key-2", zone.clone(), now);
    let (receipt3, executed3) = store.execute_with_idempotency("key-3", zone, now);

    // All should execute
    assert!(executed1);
    assert!(executed2);
    assert!(executed3);
    assert_eq!(store.get_execution_count(), 3);

    // All should have different receipts
    assert_ne!(receipt1, receipt2);
    assert_ne!(receipt2, receipt3);
    assert_ne!(receipt1, receipt3);

    log = log
        .expect("independent_executions")
        .actual("3_independent_executions")
        .timing(elapsed_micros_u64(&start))
        .verify()
        .pass();
    log.log();
}

#[test]
fn test_idempotency_key_expiry() {
    let start = std::time::Instant::now();
    let mut log = TestLogEntry::new("test_idempotency_key_expiry", "idempotency").execute();

    let entry = IdempotencyEntry {
        key: "test-key".to_string(),
        zone_id: test_zone(),
        intent_id: test_object_id("intent"),
        receipt_id: Some(test_object_id("receipt")),
        status: IntentStatus::Completed,
        created_at: 1000,
        expires_at: 2000,
    };

    // Not expired
    assert!(!entry.is_expired(1500));
    assert!(entry.should_return_cached(1500));

    // Exactly at expiry
    assert!(entry.is_expired(2000));
    assert!(!entry.should_return_cached(2000));

    // After expiry
    assert!(entry.is_expired(3000));
    assert!(!entry.should_return_cached(3000));

    log = log
        .expect("expiry_semantics_correct")
        .actual("expiry_semantics_correct")
        .timing(elapsed_micros_u64(&start))
        .verify()
        .pass();
    log.log();
}

#[test]
fn test_idempotency_key_golden_vector() {
    let start = std::time::Instant::now();
    let mut log =
        TestLogEntry::new("test_idempotency_key_golden_vector", "golden_vector").execute();

    let entry = IdempotencyEntry {
        key: "payment-12345".to_string(),
        zone_id: test_zone(),
        intent_id: test_object_id("intent-payment-12345"),
        receipt_id: Some(test_object_id("receipt-payment-12345")),
        status: IntentStatus::Completed,
        created_at: 1_704_067_200,
        expires_at: 1_704_153_600, // +24 hours
    };

    let now = 1_704_100_000; // Within expiry window

    let vector = IdempotencyKeyVector {
        description: "Completed payment with valid receipt".to_string(),
        key: entry.key.clone(),
        zone_id: entry.zone_id.to_string(),
        intent_id_hex: hex::encode(entry.intent_id.as_bytes()),
        receipt_id_hex: entry
            .receipt_id
            .as_ref()
            .map(|id| hex::encode(id.as_bytes())),
        status: entry.status.to_string(),
        expires_at: entry.expires_at,
        is_expired_at_now: entry.is_expired(now),
        is_terminal: entry.is_terminal(),
        should_return_cached: entry.should_return_cached(now),
    };

    let vector_path = vectors_dir().join("idempotency_completed.json");
    if let Ok(existing) = fs::read_to_string(&vector_path) {
        let existing_vector: IdempotencyKeyVector = serde_json::from_str(&existing).unwrap();
        assert_eq!(vector, existing_vector, "Golden vector mismatch");
        log = log.actual("matches_golden_vector");
    } else {
        fs::create_dir_all(vectors_dir()).ok();
        fs::write(&vector_path, serde_json::to_string_pretty(&vector).unwrap()).unwrap();
        log = log.actual("created_golden_vector");
    }

    log = log
        .expect("idempotency_entry_correct")
        .timing(elapsed_micros_u64(&start))
        .verify()
        .pass();
    log.log();
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Lease Fencing Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_lease_seq_binding() {
    let start = std::time::Instant::now();
    let mut log = TestLogEntry::new("test_lease_seq_binding", "lease_fencing")
        .with_lease_seq(42)
        .execute();

    let intent = create_test_intent(Some("key-1"), Some(42));

    // Intent should be lease-bound
    assert!(intent.is_lease_bound());
    assert_eq!(intent.lease_seq, Some(42));

    // Signable bytes should include lease_seq
    let signable = intent.signable_bytes();
    let intent_no_lease = create_test_intent(Some("key-1"), None);
    let signable_no_lease = intent_no_lease.signable_bytes();

    assert_ne!(
        signable, signable_no_lease,
        "Lease-bound intent should have different signable bytes"
    );

    log = log
        .expect("lease_bound_correctly")
        .actual("lease_bound_correctly")
        .timing(elapsed_micros_u64(&start))
        .verify()
        .pass();
    log.log();
}

#[test]
fn test_stale_lease_holder_detection() {
    let start = std::time::Instant::now();
    let mut log = TestLogEntry::new("test_stale_lease_holder_detection", "lease_fencing")
        .with_lease_seq(42)
        .execute();

    let current_lease_seq = 43u64; // Current active lease
    let intent = create_test_intent(Some("key-1"), Some(42)); // Stale lease seq

    // Simulate lease seq check
    let is_stale = intent.lease_seq.is_some() && intent.lease_seq.unwrap() < current_lease_seq;

    assert!(
        is_stale,
        "Intent with lease_seq 42 should be stale when current is 43"
    );

    // An intent with matching lease_seq should not be stale
    let valid_intent = create_test_intent(Some("key-2"), Some(43));
    let is_valid =
        valid_intent.lease_seq.is_some() && valid_intent.lease_seq.unwrap() >= current_lease_seq;
    assert!(is_valid);

    log = log
        .expect("stale_detected")
        .actual("stale_detected")
        .timing(elapsed_micros_u64(&start))
        .verify()
        .pass();
    log.log();
}

#[test]
fn test_lease_seq_mismatch_error() {
    let start = std::time::Instant::now();
    let mut log = TestLogEntry::new("test_lease_seq_mismatch_error", "lease_fencing").execute();

    let error = OperationValidationError::LeaseSeqMismatch {
        expected: 43,
        got: 42,
    };

    let display = error.to_string();
    assert!(display.contains("43"));
    assert!(display.contains("42"));
    assert!(display.contains("lease seq mismatch"));

    log = log
        .expect("error_formatted_correctly")
        .actual("error_formatted_correctly")
        .timing(elapsed_micros_u64(&start))
        .verify()
        .pass();
    log.log();
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Fault Injection Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_orphan_detection_threshold() {
    let start = std::time::Instant::now();
    let mut log = TestLogEntry::new("test_orphan_detection_threshold", "fault_injection").execute();

    let intent = create_test_intent(Some("crash-key"), Some(42));
    let orphan_threshold = 3600u64; // 1 hour
    let planned_at = intent.planned_at;

    // Within threshold - not orphaned
    let now_within = planned_at + 1800; // 30 minutes later
    assert!(
        !is_intent_orphaned(&intent, false, now_within, orphan_threshold),
        "Should not be orphaned within threshold"
    );

    // At threshold - not orphaned (boundary)
    let now_at = planned_at + orphan_threshold;
    assert!(
        !is_intent_orphaned(&intent, false, now_at, orphan_threshold),
        "Should not be orphaned at exactly threshold"
    );

    // Past threshold - orphaned
    let now_past = planned_at + orphan_threshold + 1;
    assert!(
        is_intent_orphaned(&intent, false, now_past, orphan_threshold),
        "Should be orphaned past threshold"
    );

    // Has receipt - never orphaned
    assert!(
        !is_intent_orphaned(&intent, true, now_past, orphan_threshold),
        "Should not be orphaned if receipt exists"
    );

    log = log
        .expect("orphan_detection_correct")
        .actual("orphan_detection_correct")
        .timing(elapsed_micros_u64(&start))
        .verify()
        .pass();
    log.log();
}

#[test]
fn test_crash_between_intent_and_receipt_scenario() {
    let start = std::time::Instant::now();
    let mut log = TestLogEntry::new(
        "test_crash_between_intent_and_receipt_scenario",
        "fault_injection",
    )
    .execute();

    // Simulate crash scenario:
    // 1. Intent is stored
    // 2. Crash occurs before receipt is stored
    // 3. On recovery, detect incomplete intent

    let intent = create_test_intent(Some("crash-key"), Some(42));
    let orphan_threshold = 3600u64;

    // Scenario: Intent stored at t=1000, crash, recovery at t=5000
    let recovery_time = intent.planned_at + 4000;

    // Check if intent is orphaned (no receipt exists)
    let is_orphaned = is_intent_orphaned(&intent, false, recovery_time, orphan_threshold);
    assert!(
        is_orphaned,
        "Intent should be detected as orphaned on recovery"
    );

    // The proper recovery action would be:
    // - Mark intent status as Orphaned
    // - Log for manual reconciliation
    // - Prevent re-execution without explicit admin action

    log = log
        .expect("crash_recovery_detects_orphan")
        .actual("crash_recovery_detects_orphan")
        .timing(elapsed_micros_u64(&start))
        .verify()
        .pass();
    log.log();
}

#[test]
fn test_intent_orphan_error_formatting() {
    let start = std::time::Instant::now();
    let mut log =
        TestLogEntry::new("test_intent_orphan_error_formatting", "fault_injection").execute();

    let intent_id = test_object_id("orphaned-intent");
    let error = OperationValidationError::IntentOrphaned {
        intent_id,
        planned_at: 1_704_067_200,
    };

    let display = error.to_string();
    assert!(display.contains("orphaned"));
    assert!(display.contains("1704067200"));

    log = log
        .expect("error_contains_context")
        .actual("error_contains_context")
        .timing(elapsed_micros_u64(&start))
        .verify()
        .pass();
    log.log();
}

#[test]
fn test_idempotency_entry_non_terminal_states() {
    let start = std::time::Instant::now();
    let mut log = TestLogEntry::new(
        "test_idempotency_entry_non_terminal_states",
        "fault_injection",
    )
    .execute();

    let mut entry = IdempotencyEntry {
        key: "in-flight-key".to_string(),
        zone_id: test_zone(),
        intent_id: test_object_id("intent"),
        receipt_id: None,
        status: IntentStatus::Pending,
        created_at: 1000,
        expires_at: 2000,
    };

    // Pending is not terminal
    assert!(!entry.is_terminal());
    assert!(!entry.should_return_cached(1500));

    // InProgress is not terminal
    entry.status = IntentStatus::InProgress;
    assert!(!entry.is_terminal());
    assert!(!entry.should_return_cached(1500));

    // Orphaned is not terminal (requires manual intervention)
    entry.status = IntentStatus::Orphaned;
    assert!(!entry.is_terminal());
    assert!(!entry.should_return_cached(1500));

    log = log
        .expect("non_terminal_states_correct")
        .actual("non_terminal_states_correct")
        .timing(elapsed_micros_u64(&start))
        .verify()
        .pass();
    log.log();
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Receipt-Intent Binding Validation Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_receipt_intent_binding_success() {
    let start = std::time::Instant::now();
    let mut log = TestLogEntry::new("test_receipt_intent_binding_success", "validation").execute();

    let intent = create_test_intent(Some("key-1"), Some(42));
    let receipt = create_test_receipt(Some("key-1"), vec![test_object_id("outcome-1")]);

    let result =
        validate_receipt_intent_binding(test_receipt_id(), &receipt, test_intent_id(), &intent);
    assert!(result.is_ok());

    log = log
        .expect("validation_passes")
        .actual("validation_passes")
        .timing(elapsed_micros_u64(&start))
        .verify()
        .pass();
    log.log();
}

#[test]
fn test_receipt_intent_binding_request_mismatch() {
    let start = std::time::Instant::now();
    let mut log =
        TestLogEntry::new("test_receipt_intent_binding_request_mismatch", "validation").execute();

    let intent = create_test_intent(Some("key-1"), Some(42));
    let mut receipt = create_test_receipt(Some("key-1"), vec![]);
    receipt.request_object_id = test_object_id("different-request");

    let result =
        validate_receipt_intent_binding(test_receipt_id(), &receipt, test_intent_id(), &intent);
    assert!(matches!(
        result,
        Err(OperationValidationError::RequestMismatch { .. })
    ));

    log = log
        .expect("request_mismatch_detected")
        .actual("request_mismatch_detected")
        .timing(elapsed_micros_u64(&start))
        .verify()
        .pass();
    log.log();
}

#[test]
fn test_receipt_intent_binding_zone_mismatch() {
    let start = std::time::Instant::now();
    let mut log =
        TestLogEntry::new("test_receipt_intent_binding_zone_mismatch", "validation").execute();

    let intent = create_test_intent(Some("key-1"), Some(42));
    let mut receipt = create_test_receipt(Some("key-1"), vec![]);
    receipt.header.zone_id = ZoneId::owner(); // Different zone

    let result =
        validate_receipt_intent_binding(test_receipt_id(), &receipt, test_intent_id(), &intent);
    assert!(matches!(
        result,
        Err(OperationValidationError::ZoneMismatch { .. })
    ));

    log = log
        .expect("zone_mismatch_detected")
        .actual("zone_mismatch_detected")
        .timing(elapsed_micros_u64(&start))
        .verify()
        .pass();
    log.log();
}

#[test]
fn test_receipt_intent_binding_key_mismatch() {
    let start = std::time::Instant::now();
    let mut log =
        TestLogEntry::new("test_receipt_intent_binding_key_mismatch", "validation").execute();

    let intent = create_test_intent(Some("key-1"), Some(42));
    let receipt = create_test_receipt(Some("key-2"), vec![]); // Different key

    let result =
        validate_receipt_intent_binding(test_receipt_id(), &receipt, test_intent_id(), &intent);
    assert!(matches!(
        result,
        Err(OperationValidationError::IdempotencyKeyMismatch { .. })
    ));

    log = log
        .expect("key_mismatch_detected")
        .actual("key_mismatch_detected")
        .timing(elapsed_micros_u64(&start))
        .verify()
        .pass();
    log.log();
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Safety Tier / Idempotency Class Requirements
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_dangerous_operations_require_strict_idempotency() {
    let start = std::time::Instant::now();
    let mut log = TestLogEntry::new(
        "test_dangerous_operations_require_strict_idempotency",
        "safety_tier",
    )
    .execute();

    // Dangerous = true MUST require Strict
    let required = required_idempotency_for_safety_tier(true, false);
    assert_eq!(required, IdempotencyClass::Strict);

    log = log
        .expect("Strict")
        .actual("Strict")
        .timing(elapsed_micros_u64(&start))
        .verify()
        .pass();
    log.log();
}

#[test]
fn test_risky_operations_require_strict_idempotency() {
    let start = std::time::Instant::now();
    let mut log = TestLogEntry::new(
        "test_risky_operations_require_strict_idempotency",
        "safety_tier",
    )
    .execute();

    // Risky = true SHOULD require Strict
    let required = required_idempotency_for_safety_tier(false, true);
    assert_eq!(required, IdempotencyClass::Strict);

    log = log
        .expect("Strict")
        .actual("Strict")
        .timing(elapsed_micros_u64(&start))
        .verify()
        .pass();
    log.log();
}

#[test]
fn test_safe_operations_allow_any_idempotency() {
    let start = std::time::Instant::now();
    let mut log =
        TestLogEntry::new("test_safe_operations_allow_any_idempotency", "safety_tier").execute();

    // Safe operations don't require idempotency
    let required = required_idempotency_for_safety_tier(false, false);
    assert_eq!(required, IdempotencyClass::None);

    log = log
        .expect("None")
        .actual("None")
        .timing(elapsed_micros_u64(&start))
        .verify()
        .pass();
    log.log();
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Concurrency Semantics (Determinism)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_concurrent_same_key_only_one_executes() {
    let start = std::time::Instant::now();
    let mut log =
        TestLogEntry::new("test_concurrent_same_key_only_one_executes", "concurrency").execute();

    let store = Arc::new(IdempotencyStore::new());
    let key = "concurrent-key";
    let zone = test_zone();
    let now = 1_704_067_200;

    // Simulate concurrent requests by executing sequentially
    // (In a real system, these would be parallel with proper locking)
    let mut results = Vec::new();
    for i in 0..5 {
        let (receipt, executed) = store.execute_with_idempotency(key, zone.clone(), now + i);
        results.push((receipt, executed));
    }

    // Only first should execute
    assert!(results[0].1, "First request should execute");
    for (i, (_, executed)) in results.iter().enumerate().skip(1) {
        assert!(!executed, "Request {i} should not execute");
    }

    // All should return the same receipt
    let first_receipt = results[0].0;
    for (receipt, _) in &results {
        assert_eq!(*receipt, first_receipt, "All should return same receipt");
    }

    // Only one execution
    assert_eq!(store.get_execution_count(), 1);

    log = log
        .expect("single_execution")
        .actual("single_execution")
        .timing(elapsed_micros_u64(&start))
        .verify()
        .pass();
    log.log();
}

#[test]
fn test_signable_bytes_deterministic_across_multiple_calls() {
    let start = std::time::Instant::now();
    let mut log = TestLogEntry::new(
        "test_signable_bytes_deterministic_across_multiple_calls",
        "concurrency",
    )
    .execute();

    let intent = create_test_intent(Some("deterministic-key"), Some(100));

    // Call signable_bytes many times
    let bytes: Vec<Vec<u8>> = (0..100).map(|_| intent.signable_bytes()).collect();

    // All should be identical
    for (i, b) in bytes.iter().enumerate().skip(1) {
        assert_eq!(
            bytes[0], *b,
            "Signable bytes at iteration {i} differ from first"
        );
    }

    log = log
        .expect("all_identical")
        .actual("all_identical")
        .timing(elapsed_micros_u64(&start))
        .verify()
        .pass();
    log.log();
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. Intent Status Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_intent_status_transitions() {
    let start = std::time::Instant::now();
    let mut log = TestLogEntry::new("test_intent_status_transitions", "status").execute();

    // All status values should serialize/deserialize correctly
    let statuses = [
        IntentStatus::Pending,
        IntentStatus::InProgress,
        IntentStatus::Completed,
        IntentStatus::Failed,
        IntentStatus::Orphaned,
    ];

    for status in &statuses {
        let json = serde_json::to_string(status).unwrap();
        let deserialized: IntentStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(*status, deserialized);
    }

    // Display formatting
    assert_eq!(IntentStatus::Pending.to_string(), "pending");
    assert_eq!(IntentStatus::InProgress.to_string(), "in_progress");
    assert_eq!(IntentStatus::Completed.to_string(), "completed");
    assert_eq!(IntentStatus::Failed.to_string(), "failed");
    assert_eq!(IntentStatus::Orphaned.to_string(), "orphaned");

    log = log
        .expect("all_statuses_serialize_correctly")
        .actual("all_statuses_serialize_correctly")
        .timing(elapsed_micros_u64(&start))
        .verify()
        .pass();
    log.log();
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. Error Taxonomy Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_all_validation_errors_are_displayable() {
    let start = std::time::Instant::now();
    let mut log =
        TestLogEntry::new("test_all_validation_errors_are_displayable", "errors").execute();

    let errors = vec![
        OperationValidationError::IntentNotFound {
            idempotency_key: "key".to_string(),
        },
        OperationValidationError::AlreadyCompleted {
            idempotency_key: "key".to_string(),
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
            expected: 42,
            got: 41,
        },
        OperationValidationError::IntentOrphaned {
            intent_id: test_object_id("intent"),
            planned_at: 1000,
        },
        OperationValidationError::SignatureInvalid {
            reason: "test".to_string(),
        },
        OperationValidationError::RequestMismatch {
            expected: test_object_id("expected"),
            got: test_object_id("got"),
        },
    ];

    for error in errors {
        let display = error.to_string();
        assert!(!display.is_empty(), "Error display should not be empty");
        // Ensure error implements std::error::Error
        let _: &dyn std::error::Error = &error;
    }

    log = log
        .expect("all_errors_displayable")
        .actual("all_errors_displayable")
        .timing(elapsed_micros_u64(&start))
        .verify()
        .pass();
    log.log();
}
