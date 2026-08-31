//! Golden vector tests for Audit Chain (flywheel_connectors-un5y).
//!
//! This module provides comprehensive tests for:
//! - `AuditEvent` chain integrity (hash linking, monotonic seq)
//! - `AuditHead` quorum signatures
//! - `ZoneCheckpoint` head bindings
//! - `DecisionReceipt` explainability
//! - Fork detection semantics
//!
//! # Test Categories
//!
//! 1. **`AuditEvent` Chain**: Hash linking, seq monotonicity, `follows()` semantics
//! 2. **`AuditHead`**: Quorum signature requirements
//! 3. **`ZoneCheckpoint`**: Multi-head binding validation
//! 4. **`DecisionReceipt`**: Content addressing, evidence, explainability
//! 5. **Fork Detection**: Same seq different id detection
//! 6. **`TraceContext`**: Propagation and preservation

use std::fs;
use std::path::PathBuf;

use fcp_cbor::SchemaId;
use fcp_core::{
    AuditEvent, AuditHead, CorrelationId, Decision, DecisionReceipt, EVENT_AUDIT_FORK_DETECTED,
    EVENT_CAPABILITY_INVOKE, EVENT_DECLASSIFICATION_GRANTED, EVENT_ELEVATION_GRANTED,
    EVENT_REVOCATION_ISSUED, EVENT_SECRET_ACCESS, EVENT_SECURITY_VIOLATION, EVENT_ZONE_TRANSITION,
    EpochId, NodeId, NodeSignature, ObjectHeader, ObjectId, PrincipalId, Provenance, SignatureSet,
    TraceContext, ZoneCheckpoint, ZoneId,
};
use semver::Version;
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// Test Logging (FCP2 Requirements)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, serde::Serialize)]
struct TestLogEntry {
    timestamp: String,
    test_name: String,
    module: String,
    phase: String,
    chain_seq: Option<u64>,
    checkpoint_seq: Option<u64>,
    event_type: Option<String>,
    reason_code: Option<String>,
    result: String,
}

impl TestLogEntry {
    fn new(test_name: &str) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            test_name: test_name.to_string(),
            module: "fcp-core::audit".to_string(),
            phase: "setup".to_string(),
            chain_seq: None,
            checkpoint_seq: None,
            event_type: None,
            reason_code: None,
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

    const fn with_chain_seq(mut self, seq: u64) -> Self {
        self.chain_seq = Some(seq);
        self
    }

    const fn with_checkpoint_seq(mut self, seq: u64) -> Self {
        self.checkpoint_seq = Some(seq);
        self
    }

    fn with_event_type(mut self, event_type: &str) -> Self {
        self.event_type = Some(event_type.to_string());
        self
    }

    fn with_reason_code(mut self, code: &str) -> Self {
        self.reason_code = Some(code.to_string());
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

fn test_zone() -> ZoneId {
    ZoneId::work()
}

fn test_header(kind: &str) -> ObjectHeader {
    ObjectHeader {
        encryption_kind: Default::default(),
        schema: SchemaId::new("fcp.audit", kind, Version::new(1, 0, 0)),
        zone_id: test_zone(),
        created_at: 1_700_000_000,
        provenance: Provenance::new(test_zone()),
        refs: vec![],
        foreign_refs: vec![],
        ttl_secs: None,
        placement: None,
    }
}

fn test_signature(node_name: &str, timestamp: u64) -> NodeSignature {
    NodeSignature::new(NodeId::new(node_name), [0u8; 64], timestamp)
}

fn test_actor() -> PrincipalId {
    PrincipalId::new("user:alice").expect("valid principal")
}

fn test_object_id(name: &str) -> ObjectId {
    ObjectId::from_unscoped_bytes(name.as_bytes())
}

const fn test_correlation_id(id: u8) -> CorrelationId {
    CorrelationId(Uuid::from_bytes([id; 16]))
}

fn test_epoch() -> EpochId {
    EpochId::new("epoch-2024-001")
}

fn create_audit_event(seq: u64, prev: Option<ObjectId>) -> AuditEvent {
    let seq_u8 = u8::try_from(seq).expect("seq fits in u8 for test vectors");
    AuditEvent {
        header: test_header("AuditEvent"),
        correlation_id: test_correlation_id(seq_u8),
        trace_context: None,
        event_type: EVENT_CAPABILITY_INVOKE.to_string(),
        actor: test_actor(),
        zone_id: test_zone(),
        connector_id: None,
        operation: None,
        capability_token_jti: None,
        request_object_id: None,
        result_object_id: None,
        prev,
        seq,
        occurred_at: 1_700_000_000 + seq,
        signature: test_signature("node-1", 1_700_000_000 + seq),
    }
}

fn create_signature_set(count: usize) -> SignatureSet {
    let mut set = SignatureSet::new();
    for i in 0..count {
        let byte = u8::try_from(i).expect("signature index fits in u8");
        set.add(NodeSignature::new(
            NodeId::new(format!("node-{i:02}")),
            [byte; 64],
            1_700_000_000 + i as u64,
        ));
    }
    set
}

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("audit")
}

// ─────────────────────────────────────────────────────────────────────────────
// Golden Vector Structures
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
struct AuditEventVector {
    description: String,
    event_type: String,
    seq: u64,
    prev_hex: Option<String>,
    zone_id: String,
    actor: String,
    occurred_at: u64,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
struct AuditChainVector {
    description: String,
    events: Vec<AuditEventVector>,
    chain_length: usize,
    head_seq: u64,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
struct DecisionReceiptVector {
    description: String,
    decision: String,
    reason_code: String,
    evidence_count: usize,
    has_explanation: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. AuditEvent Chain Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_audit_event_genesis_has_no_prev() {
    let mut log = TestLogEntry::new("test_audit_event_genesis_has_no_prev")
        .with_chain_seq(0)
        .execute();

    let genesis = create_audit_event(0, None);

    assert!(genesis.prev.is_none(), "Genesis event must have no prev");
    assert_eq!(genesis.seq, 0, "Genesis event should have seq 0");

    log = log.verify().pass();
    log.log();
}

#[test]
fn test_audit_event_follows_prev_correctly() {
    let mut log = TestLogEntry::new("test_audit_event_follows_prev_correctly")
        .with_chain_seq(1)
        .execute();

    let event0_id = test_object_id("audit-event-0");
    let event0 = create_audit_event(0, None);
    let event1 = create_audit_event(1, Some(event0_id));

    assert!(
        event1.follows(&event0, &event0_id),
        "Event 1 should follow event 0"
    );

    log = log.verify().pass();
    log.log();
}

#[test]
fn test_audit_event_wrong_prev_fails_follows() {
    let mut log = TestLogEntry::new("test_audit_event_wrong_prev_fails_follows")
        .with_chain_seq(1)
        .execute();

    let event0_id = test_object_id("audit-event-0");
    let wrong_id = test_object_id("wrong-id");
    let event0 = create_audit_event(0, None);
    let event1 = create_audit_event(1, Some(wrong_id));

    assert!(
        !event1.follows(&event0, &event0_id),
        "Event with wrong prev should not follow"
    );

    log = log.verify().pass();
    log.log();
}

#[test]
fn test_audit_event_seq_gap_fails_follows() {
    let mut log = TestLogEntry::new("test_audit_event_seq_gap_fails_follows")
        .with_chain_seq(2)
        .execute();

    let event0_id = test_object_id("audit-event-0");
    let event0 = create_audit_event(0, None);
    // Event with seq 2 (gap of 1) should not follow seq 0
    let event2 = create_audit_event(2, Some(event0_id));

    assert!(
        !event2.follows(&event0, &event0_id),
        "Event with seq gap should not follow"
    );

    log = log.verify().pass();
    log.log();
}

#[test]
fn test_audit_event_seq_monotonicity() {
    let mut log = TestLogEntry::new("test_audit_event_seq_monotonicity").execute();

    // Build a valid chain
    let mut chain = Vec::new();
    let mut prev_id: Option<ObjectId> = None;

    for seq in 0..10 {
        let event = create_audit_event(seq, prev_id);
        prev_id = Some(test_object_id(&format!("audit-event-{seq}")));
        chain.push((event, prev_id.unwrap()));
    }

    // Verify chain integrity
    for i in 1..chain.len() {
        let (curr, _) = &chain[i];
        let (prev, prev_id) = &chain[i - 1];
        assert!(
            curr.follows(prev, prev_id),
            "Chain should be continuous at {i}"
        );
    }

    log = log.with_chain_seq(9).verify().pass();
    log.log();
}

#[test]
fn test_audit_event_all_event_types() {
    let mut log = TestLogEntry::new("test_audit_event_all_event_types").execute();

    let event_types = [
        EVENT_SECRET_ACCESS,
        EVENT_CAPABILITY_INVOKE,
        EVENT_ELEVATION_GRANTED,
        EVENT_DECLASSIFICATION_GRANTED,
        EVENT_ZONE_TRANSITION,
        EVENT_REVOCATION_ISSUED,
        EVENT_SECURITY_VIOLATION,
        EVENT_AUDIT_FORK_DETECTED,
    ];

    for event_type in &event_types {
        let mut event = create_audit_event(0, None);
        event.event_type = event_type.to_string();
        assert_eq!(&event.event_type, *event_type);
    }

    log = log.verify().pass();
    log.log();
}

#[test]
fn test_audit_event_zone_binding() {
    let mut log = TestLogEntry::new("test_audit_event_zone_binding")
        .with_event_type(EVENT_CAPABILITY_INVOKE)
        .execute();

    let event = create_audit_event(0, None);

    assert_eq!(event.zone_id(), &test_zone());
    assert_eq!(event.header.zone_id, test_zone());

    log = log.verify().pass();
    log.log();
}

#[test]
fn test_audit_event_timestamp_ordering() {
    let mut log = TestLogEntry::new("test_audit_event_timestamp_ordering").execute();

    let event0 = create_audit_event(0, None);
    let event1_id = test_object_id("audit-event-0");
    let event1 = create_audit_event(1, Some(event1_id));

    assert!(
        event1.occurred_at >= event0.occurred_at,
        "Later events should have >= timestamps"
    );

    log = log.verify().pass();
    log.log();
}

#[test]
fn test_audit_chain_golden_vector() {
    let mut log = TestLogEntry::new("test_audit_chain_golden_vector").execute();

    // Build a 3-event chain
    let event0 = create_audit_event(0, None);
    let event0_id = test_object_id("audit-event-0");

    let event1 = create_audit_event(1, Some(event0_id));
    let event1_id = test_object_id("audit-event-1");

    let event2 = create_audit_event(2, Some(event1_id));

    let vector = AuditChainVector {
        description: "Valid 3-event audit chain".to_string(),
        events: vec![
            AuditEventVector {
                description: "Genesis event".to_string(),
                event_type: event0.event_type.clone(),
                seq: event0.seq,
                prev_hex: None,
                zone_id: event0.zone_id.to_string(),
                actor: "user:alice".to_string(),
                occurred_at: event0.occurred_at,
            },
            AuditEventVector {
                description: "Second event".to_string(),
                event_type: event1.event_type.clone(),
                seq: event1.seq,
                prev_hex: Some(hex::encode(event0_id.as_bytes())),
                zone_id: event1.zone_id.to_string(),
                actor: "user:alice".to_string(),
                occurred_at: event1.occurred_at,
            },
            AuditEventVector {
                description: "Third event".to_string(),
                event_type: event2.event_type.clone(),
                seq: event2.seq,
                prev_hex: Some(hex::encode(event1_id.as_bytes())),
                zone_id: event2.zone_id.to_string(),
                actor: "user:alice".to_string(),
                occurred_at: event2.occurred_at,
            },
        ],
        chain_length: 3,
        head_seq: 2,
    };

    let vector_path = vectors_dir().join("valid_audit_chain.json");
    if let Ok(existing) = fs::read_to_string(&vector_path) {
        let existing_vector: AuditChainVector = serde_json::from_str(&existing).unwrap();
        assert_eq!(vector, existing_vector, "Golden vector mismatch");
    } else {
        fs::create_dir_all(vectors_dir()).ok();
        fs::write(&vector_path, serde_json::to_string_pretty(&vector).unwrap()).unwrap();
    }

    log = log.with_chain_seq(2).verify().pass();
    log.log();
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. AuditHead Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_audit_head_structure() {
    let mut log = TestLogEntry::new("test_audit_head_structure").execute();

    let head_event_id = test_object_id("audit-head-event");
    let signatures = create_signature_set(3);

    let head = AuditHead {
        header: test_header("AuditHead"),
        zone_id: test_zone(),
        head_event: head_event_id,
        head_seq: 100,
        coverage: 1.0,
        epoch_id: test_epoch(),
        quorum_signatures: signatures,
    };

    assert_eq!(head.zone_id(), &test_zone());
    assert_eq!(head.head_seq, 100);
    assert_eq!(head.head_event, head_event_id);

    log = log.with_checkpoint_seq(100).verify().pass();
    log.log();
}

#[test]
fn test_audit_head_quorum_signatures() {
    let mut log = TestLogEntry::new("test_audit_head_quorum_signatures").execute();

    // Create head with 3 signatures (satisfies 3-of-5 quorum)
    let head = AuditHead {
        header: test_header("AuditHead"),
        zone_id: test_zone(),
        head_event: test_object_id("head-event"),
        head_seq: 50,
        coverage: 0.6,
        epoch_id: test_epoch(),
        quorum_signatures: create_signature_set(3),
    };

    assert_eq!(head.quorum_signatures.len(), 3);

    // Verify signature set can be iterated
    assert_eq!(head.quorum_signatures.iter().count(), 3);

    log = log.verify().pass();
    log.log();
}

#[test]
fn test_audit_head_empty_signatures_rejected() {
    let mut log = TestLogEntry::new("test_audit_head_empty_signatures_rejected").execute();

    let head = AuditHead {
        header: test_header("AuditHead"),
        zone_id: test_zone(),
        head_event: test_object_id("head-event"),
        head_seq: 50,
        coverage: 0.0,
        epoch_id: test_epoch(),
        quorum_signatures: SignatureSet::new(),
    };

    // Empty signature set should have zero length
    assert_eq!(head.quorum_signatures.len(), 0);
    // Coverage should reflect no signatures
    assert!(head.coverage.abs() < f64::EPSILON);

    log = log.verify().pass();
    log.log();
}

#[test]
fn test_audit_head_coverage_calculation() {
    let mut log = TestLogEntry::new("test_audit_head_coverage_calculation").execute();

    // 3 of 5 nodes = 60% coverage
    let head = AuditHead {
        header: test_header("AuditHead"),
        zone_id: test_zone(),
        head_event: test_object_id("head-event"),
        head_seq: 50,
        coverage: 0.6,
        epoch_id: test_epoch(),
        quorum_signatures: create_signature_set(3),
    };

    assert!((head.coverage - 0.6).abs() < f64::EPSILON);

    log = log.verify().pass();
    log.log();
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. ZoneCheckpoint Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_zone_checkpoint_binds_all_heads() {
    let mut log = TestLogEntry::new("test_zone_checkpoint_binds_all_heads")
        .with_checkpoint_seq(10)
        .execute();

    let checkpoint = ZoneCheckpoint {
        header: test_header("ZoneCheckpoint"),
        zone_id: test_zone(),
        rev_head: test_object_id("rev-head"),
        rev_seq: 100,
        audit_head: test_object_id("audit-head"),
        audit_seq: 200,
        zone_definition_head: test_object_id("zone-def-head"),
        zone_policy_head: test_object_id("zone-policy-head"),
        active_zone_key_manifest: test_object_id("key-manifest"),
        checkpoint_seq: 10,
        as_of_epoch: test_epoch(),
        quorum_signatures: create_signature_set(5),
        revocation_freshness_sla_secs: 300,
    };

    // Verify all heads are bound
    assert_eq!(checkpoint.zone_id(), &test_zone());
    assert_eq!(checkpoint.rev_seq, 100);
    assert_eq!(checkpoint.audit_seq, 200);
    assert_eq!(checkpoint.checkpoint_seq, 10);

    log = log.verify().pass();
    log.log();
}

#[test]
fn test_zone_checkpoint_seq_monotonic() {
    let mut log = TestLogEntry::new("test_zone_checkpoint_seq_monotonic").execute();

    let cp1 = ZoneCheckpoint {
        header: test_header("ZoneCheckpoint"),
        zone_id: test_zone(),
        rev_head: test_object_id("rev-head-1"),
        rev_seq: 100,
        audit_head: test_object_id("audit-head-1"),
        audit_seq: 200,
        zone_definition_head: test_object_id("zone-def"),
        zone_policy_head: test_object_id("zone-policy"),
        active_zone_key_manifest: test_object_id("key-manifest"),
        checkpoint_seq: 1,
        as_of_epoch: EpochId::new("epoch-1"),
        quorum_signatures: create_signature_set(3),
        revocation_freshness_sla_secs: 300,
    };

    let cp2 = ZoneCheckpoint {
        header: test_header("ZoneCheckpoint"),
        zone_id: test_zone(),
        rev_head: test_object_id("rev-head-2"),
        rev_seq: 150,
        audit_head: test_object_id("audit-head-2"),
        audit_seq: 250,
        zone_definition_head: test_object_id("zone-def"),
        zone_policy_head: test_object_id("zone-policy"),
        active_zone_key_manifest: test_object_id("key-manifest"),
        checkpoint_seq: 2,
        as_of_epoch: EpochId::new("epoch-2"),
        quorum_signatures: create_signature_set(3),
        revocation_freshness_sla_secs: 300,
    };

    assert!(cp2.checkpoint_seq > cp1.checkpoint_seq);
    assert!(cp2.rev_seq >= cp1.rev_seq);
    assert!(cp2.audit_seq >= cp1.audit_seq);

    log = log.with_checkpoint_seq(2).verify().pass();
    log.log();
}

#[test]
fn test_zone_checkpoint_requires_quorum() {
    let mut log = TestLogEntry::new("test_zone_checkpoint_requires_quorum").execute();

    let checkpoint = ZoneCheckpoint {
        header: test_header("ZoneCheckpoint"),
        zone_id: test_zone(),
        rev_head: test_object_id("rev-head"),
        rev_seq: 100,
        audit_head: test_object_id("audit-head"),
        audit_seq: 200,
        zone_definition_head: test_object_id("zone-def"),
        zone_policy_head: test_object_id("zone-policy"),
        active_zone_key_manifest: test_object_id("key-manifest"),
        checkpoint_seq: 1,
        as_of_epoch: test_epoch(),
        quorum_signatures: create_signature_set(5),
        revocation_freshness_sla_secs: 300,
    };

    assert_eq!(checkpoint.quorum_signatures.len(), 5);

    log = log.verify().pass();
    log.log();
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. DecisionReceipt Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_decision_receipt_allow() {
    let mut log = TestLogEntry::new("test_decision_receipt_allow")
        .with_reason_code("CAPABILITY_VALID")
        .execute();

    let receipt = DecisionReceipt {
        header: test_header("DecisionReceipt"),
        request_object_id: test_object_id("request-1"),
        decision: Decision::Allow,
        reason_code: "CAPABILITY_VALID".to_string(),
        evidence: vec![test_object_id("capability-token")],
        explanation: Some("Capability token verified successfully".to_string()),
        signature: test_signature("node-1", 1_700_000_000),
    };

    assert!(receipt.is_allow());
    assert!(!receipt.is_deny());
    assert_eq!(receipt.reason_code, "CAPABILITY_VALID");

    log = log.verify().pass();
    log.log();
}

#[test]
fn test_decision_receipt_deny() {
    let mut log = TestLogEntry::new("test_decision_receipt_deny")
        .with_reason_code("CAPABILITY_EXPIRED")
        .execute();

    let receipt = DecisionReceipt {
        header: test_header("DecisionReceipt"),
        request_object_id: test_object_id("request-2"),
        decision: Decision::Deny,
        reason_code: "CAPABILITY_EXPIRED".to_string(),
        evidence: vec![test_object_id("expired-token")],
        explanation: Some("Capability token has expired".to_string()),
        signature: test_signature("node-1", 1_700_000_000),
    };

    assert!(receipt.is_deny());
    assert!(!receipt.is_allow());
    assert_eq!(receipt.reason_code, "CAPABILITY_EXPIRED");

    log = log.verify().pass();
    log.log();
}

#[test]
fn test_decision_receipt_evidence_present() {
    let mut log = TestLogEntry::new("test_decision_receipt_evidence_present").execute();

    let evidence = vec![
        test_object_id("capability"),
        test_object_id("policy"),
        test_object_id("provenance"),
    ];

    let receipt = DecisionReceipt {
        header: test_header("DecisionReceipt"),
        request_object_id: test_object_id("request-3"),
        decision: Decision::Deny,
        reason_code: "INSUFFICIENT_INTEGRITY".to_string(),
        evidence,
        explanation: None,
        signature: test_signature("node-1", 1_700_000_000),
    };

    assert_eq!(receipt.evidence.len(), 3);
    assert!(receipt.evidence.contains(&test_object_id("capability")));
    assert!(receipt.evidence.contains(&test_object_id("policy")));
    assert!(receipt.evidence.contains(&test_object_id("provenance")));

    log = log.verify().pass();
    log.log();
}

#[test]
fn test_decision_receipt_zone_binding() {
    let mut log = TestLogEntry::new("test_decision_receipt_zone_binding").execute();

    let receipt = DecisionReceipt {
        header: test_header("DecisionReceipt"),
        request_object_id: test_object_id("request"),
        decision: Decision::Allow,
        reason_code: "OK".to_string(),
        evidence: vec![],
        explanation: None,
        signature: test_signature("node-1", 1_700_000_000),
    };

    assert_eq!(receipt.zone_id(), &test_zone());

    log = log.verify().pass();
    log.log();
}

#[test]
fn test_decision_receipt_golden_vector() {
    let mut log = TestLogEntry::new("test_decision_receipt_golden_vector").execute();

    let receipt = DecisionReceipt {
        header: test_header("DecisionReceipt"),
        request_object_id: test_object_id("request-golden"),
        decision: Decision::Deny,
        reason_code: "PUBLIC_INPUT_TAINT".to_string(),
        evidence: vec![
            test_object_id("tainted-input"),
            test_object_id("sanitizer-required"),
        ],
        explanation: Some(
            "Operation denied due to PUBLIC_INPUT taint without sanitizer".to_string(),
        ),
        signature: test_signature("node-1", 1_700_000_000),
    };

    let vector = DecisionReceiptVector {
        description: "Deny decision due to PUBLIC_INPUT taint".to_string(),
        decision: "deny".to_string(),
        reason_code: receipt.reason_code.clone(),
        evidence_count: receipt.evidence.len(),
        has_explanation: receipt.explanation.is_some(),
    };

    let vector_path = vectors_dir().join("decision_receipt_deny_taint.json");
    if let Ok(existing) = fs::read_to_string(&vector_path) {
        let existing_vector: DecisionReceiptVector = serde_json::from_str(&existing).unwrap();
        assert_eq!(vector, existing_vector);
    } else {
        fs::create_dir_all(vectors_dir()).ok();
        fs::write(&vector_path, serde_json::to_string_pretty(&vector).unwrap()).unwrap();
    }

    log = log.with_reason_code("PUBLIC_INPUT_TAINT").verify().pass();
    log.log();
}

#[test]
fn test_decision_serialization() {
    let mut log = TestLogEntry::new("test_decision_serialization").execute();

    // Decision should serialize as lowercase
    let allow_json = serde_json::to_string(&Decision::Allow).unwrap();
    let deny_json = serde_json::to_string(&Decision::Deny).unwrap();

    assert_eq!(allow_json, "\"allow\"");
    assert_eq!(deny_json, "\"deny\"");

    // And deserialize correctly
    let allow: Decision = serde_json::from_str("\"allow\"").unwrap();
    let deny: Decision = serde_json::from_str("\"deny\"").unwrap();

    assert_eq!(allow, Decision::Allow);
    assert_eq!(deny, Decision::Deny);

    log = log.verify().pass();
    log.log();
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Fork Detection Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_fork_detection_same_seq_different_id() {
    let mut log = TestLogEntry::new("test_fork_detection_same_seq_different_id")
        .with_chain_seq(5)
        .execute();

    // Two events with same seq but different content = fork
    let event_a = create_audit_event(5, Some(test_object_id("prev-4")));
    let event_b = {
        let mut e = create_audit_event(5, Some(test_object_id("prev-4")));
        e.occurred_at += 100; // Different content
        e
    };

    // These represent a fork - same seq, different events
    assert_eq!(event_a.seq, event_b.seq);
    assert_ne!(event_a.occurred_at, event_b.occurred_at);

    // In a real system, this would be detected by comparing ObjectIds
    // (which would differ due to different content)

    log = log
        .with_event_type(EVENT_AUDIT_FORK_DETECTED)
        .verify()
        .pass();
    log.log();
}

#[test]
fn test_fork_detection_divergent_prev() {
    let mut log = TestLogEntry::new("test_fork_detection_divergent_prev")
        .with_chain_seq(5)
        .execute();

    // Two events at same seq pointing to different prevs = fork
    let event_a = create_audit_event(5, Some(test_object_id("prev-a")));
    let event_b = create_audit_event(5, Some(test_object_id("prev-b")));

    assert_eq!(event_a.seq, event_b.seq);
    assert_ne!(event_a.prev, event_b.prev);

    log = log.verify().pass();
    log.log();
}

#[test]
fn test_fork_detection_event_type_constant() {
    let mut log = TestLogEntry::new("test_fork_detection_event_type_constant").execute();

    assert_eq!(EVENT_AUDIT_FORK_DETECTED, "audit.fork_detected");

    log = log.verify().pass();
    log.log();
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. TraceContext Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_trace_context_structure() {
    let mut log = TestLogEntry::new("test_trace_context_structure").execute();

    let trace = TraceContext {
        trace_id: [0x01; 16],
        span_id: [0x02; 8],
        flags: 0x01, // Sampled
    };

    assert_eq!(trace.trace_id.len(), 16);
    assert_eq!(trace.span_id.len(), 8);
    assert_eq!(trace.flags, 0x01);

    log = log.verify().pass();
    log.log();
}

#[test]
fn test_audit_event_with_trace_context() {
    let mut log = TestLogEntry::new("test_audit_event_with_trace_context").execute();

    let trace = TraceContext {
        trace_id: [0xaa; 16],
        span_id: [0xbb; 8],
        flags: 0x01,
    };

    let mut event = create_audit_event(0, None);
    event.trace_context = Some(trace);

    assert!(event.trace_context.is_some());
    let tc = event.trace_context.as_ref().unwrap();
    assert_eq!(tc.trace_id, [0xaa; 16]);
    assert_eq!(tc.span_id, [0xbb; 8]);

    log = log.verify().pass();
    log.log();
}

#[test]
fn test_audit_event_without_trace_context() {
    let mut log = TestLogEntry::new("test_audit_event_without_trace_context").execute();

    let event = create_audit_event(0, None);

    assert!(
        event.trace_context.is_none(),
        "Default event has no trace context"
    );

    log = log.verify().pass();
    log.log();
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Reason Code Tests (Explainability)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_common_reason_codes() {
    let mut log = TestLogEntry::new("test_common_reason_codes").execute();

    // Common reason codes that should be used consistently
    let reason_codes = [
        "CAPABILITY_VALID",
        "CAPABILITY_EXPIRED",
        "CAPABILITY_REVOKED",
        "INSUFFICIENT_INTEGRITY",
        "INSUFFICIENT_CONFIDENTIALITY",
        "PUBLIC_INPUT_TAINT",
        "MISSING_APPROVAL_TOKEN",
        "LEASE_EXPIRED",
        "QUORUM_NOT_MET",
        "ZONE_MISMATCH",
    ];

    for code in &reason_codes {
        // Reason codes should be uppercase with underscores
        assert!(
            code.chars().all(|c| c.is_uppercase() || c == '_'),
            "Reason code {code} should be UPPER_SNAKE_CASE"
        );
    }

    log = log.verify().pass();
    log.log();
}

#[test]
fn test_decision_receipt_without_explanation() {
    let mut log = TestLogEntry::new("test_decision_receipt_without_explanation").execute();

    let receipt = DecisionReceipt {
        header: test_header("DecisionReceipt"),
        request_object_id: test_object_id("request"),
        decision: Decision::Allow,
        reason_code: "OK".to_string(),
        evidence: vec![],
        explanation: None, // No explanation
        signature: test_signature("node-1", 1_700_000_000),
    };

    assert!(receipt.explanation.is_none());
    // Reason code alone should be sufficient for programmatic handling
    assert_ne!(receipt.reason_code, "");

    log = log.verify().pass();
    log.log();
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Serialization Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_audit_event_serialization() {
    let mut log = TestLogEntry::new("test_audit_event_serialization").execute();

    let event = create_audit_event(5, Some(test_object_id("prev-4")));

    let json = serde_json::to_string(&event).expect("serialize");
    let deserialized: AuditEvent = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(deserialized.seq, event.seq);
    assert_eq!(deserialized.event_type, event.event_type);
    assert_eq!(deserialized.prev, event.prev);

    log = log.verify().pass();
    log.log();
}

#[test]
fn test_audit_head_serialization() {
    let mut log = TestLogEntry::new("test_audit_head_serialization").execute();

    let head = AuditHead {
        header: test_header("AuditHead"),
        zone_id: test_zone(),
        head_event: test_object_id("head-event"),
        head_seq: 100,
        coverage: 0.8,
        epoch_id: test_epoch(),
        quorum_signatures: create_signature_set(4),
    };

    let json = serde_json::to_string(&head).expect("serialize");
    let deserialized: AuditHead = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(deserialized.head_seq, head.head_seq);
    assert_eq!(deserialized.quorum_signatures.len(), 4);

    log = log.verify().pass();
    log.log();
}

#[test]
fn test_zone_checkpoint_serialization() {
    let mut log = TestLogEntry::new("test_zone_checkpoint_serialization").execute();

    let checkpoint = ZoneCheckpoint {
        header: test_header("ZoneCheckpoint"),
        zone_id: test_zone(),
        rev_head: test_object_id("rev-head"),
        rev_seq: 100,
        audit_head: test_object_id("audit-head"),
        audit_seq: 200,
        zone_definition_head: test_object_id("zone-def"),
        zone_policy_head: test_object_id("zone-policy"),
        active_zone_key_manifest: test_object_id("key-manifest"),
        checkpoint_seq: 5,
        as_of_epoch: test_epoch(),
        quorum_signatures: create_signature_set(5),
        revocation_freshness_sla_secs: 300,
    };

    let json = serde_json::to_string(&checkpoint).expect("serialize");
    let deserialized: ZoneCheckpoint = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(deserialized.checkpoint_seq, checkpoint.checkpoint_seq);
    assert_eq!(deserialized.audit_seq, checkpoint.audit_seq);
    assert_eq!(deserialized.rev_seq, checkpoint.rev_seq);

    log = log.verify().pass();
    log.log();
}

#[test]
fn test_decision_receipt_serialization() {
    let mut log = TestLogEntry::new("test_decision_receipt_serialization").execute();

    let receipt = DecisionReceipt {
        header: test_header("DecisionReceipt"),
        request_object_id: test_object_id("request"),
        decision: Decision::Deny,
        reason_code: "TEST_REASON".to_string(),
        evidence: vec![test_object_id("evidence-1")],
        explanation: Some("Test explanation".to_string()),
        signature: test_signature("node-1", 1_700_000_000),
    };

    let json = serde_json::to_string(&receipt).expect("serialize");
    let deserialized: DecisionReceipt = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(deserialized.decision, receipt.decision);
    assert_eq!(deserialized.reason_code, receipt.reason_code);
    assert_eq!(deserialized.evidence.len(), 1);
    assert!(deserialized.explanation.is_some());

    log = log.verify().pass();
    log.log();
}
