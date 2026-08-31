//! E2E fork detection and resolution scenarios (bd-18af).
//!
//! These tests verify the connector state fork detection and resolution flow
//! when two writers produce conflicting state.
//!
//! Per `docs/STANDARD_Testing_Logging.md`, all tests emit structured JSONL logs
//! and persist artifacts for validation.
//!
//! ## Scenarios
//!
//! 1. Two writers produce conflicting state → fork detected
//! 2. Fork pauses connector execution
//! 3. Fork resolved via CLI (`ChooseByLease` or Manual)
//! 4. Connector resumes after resolution

#![forbid(unsafe_code)]

mod support;

use std::time::Instant;

use chrono::Utc;
use fcp_cbor::SchemaId;
use fcp_core::{
    ConnectorId, ConnectorStateModel, ConnectorStateObject, ForkResolution, ObjectHeader, ObjectId,
    Provenance, Signature, StateForkDetectionResult, StateForkDetector, ZoneId,
};
use semver::Version;
use serde_json::json;
use support::LogCapture;
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// Test Infrastructure
// ─────────────────────────────────────────────────────────────────────────────

/// E2E test context with structured logging.
struct E2ETestContext {
    test_name: String,
    module: String,
    correlation_id: String,
    capture: LogCapture,
    start_time: Instant,
    assertions_passed: u32,
    assertions_failed: u32,
}

impl E2ETestContext {
    fn new(test_name: &str) -> Self {
        Self {
            test_name: test_name.to_string(),
            module: "fcp-core::connector_state::fork_resolution::e2e".to_string(),
            correlation_id: Uuid::new_v4().to_string(),
            capture: LogCapture::new(),
            start_time: Instant::now(),
            assertions_passed: 0,
            assertions_failed: 0,
        }
    }

    #[allow(clippy::cast_possible_truncation)]
    fn log_phase(&self, phase: &str, details: Option<serde_json::Value>) {
        let duration_ms = self.start_time.elapsed().as_millis() as u64;
        let mut entry = json!({
            "timestamp": Utc::now().to_rfc3339(),
            "test_name": self.test_name,
            "module": self.module,
            "phase": phase,
            "correlation_id": self.correlation_id,
            "result": "pass",
            "duration_ms": duration_ms,
            "assertions": {
                "passed": self.assertions_passed,
                "failed": self.assertions_failed
            }
        });

        if let Some(d) = details {
            entry["details"] = d;
        }

        self.capture.push_value(&entry).expect("log entry");
    }

    fn log_fork_event(
        &self,
        connector_id: &ConnectorId,
        common_prev: &ObjectId,
        branch_a: &ObjectId,
        branch_b: &ObjectId,
    ) {
        self.log_phase(
            "fork_detected",
            Some(json!({
                "connector_id": connector_id.to_string(),
                "common_prev": common_prev.to_string(),
                "branch_a": branch_a.to_string(),
                "branch_b": branch_b.to_string(),
                "connector_paused": true
            })),
        );
    }

    fn log_fork_resolution(
        &self,
        connector_id: &ConnectorId,
        strategy: &str,
        winning_head: &ObjectId,
        success: bool,
    ) {
        self.log_phase(
            "fork_resolved",
            Some(json!({
                "connector_id": connector_id.to_string(),
                "resolution_strategy": strategy,
                "winning_head": winning_head.to_string(),
                "resolved": success,
                "connector_resumed": success
            })),
        );
    }

    fn assert_eq<T: std::fmt::Debug + PartialEq>(&mut self, actual: &T, expected: &T, msg: &str) {
        if actual == expected {
            self.assertions_passed += 1;
        } else {
            self.assertions_failed += 1;
            panic!("{msg}: expected {expected:?}, got {actual:?}");
        }
    }

    fn assert_true(&mut self, condition: bool, msg: &str) {
        if condition {
            self.assertions_passed += 1;
        } else {
            self.assertions_failed += 1;
            panic!("{msg}");
        }
    }

    #[allow(clippy::cast_possible_truncation)]
    fn finalize(&self, result: &str) {
        let duration_ms = self.start_time.elapsed().as_millis() as u64;
        let entry = json!({
            "timestamp": Utc::now().to_rfc3339(),
            "test_name": self.test_name,
            "module": self.module,
            "phase": "verify",
            "correlation_id": self.correlation_id,
            "result": result,
            "duration_ms": duration_ms,
            "assertions": {
                "passed": self.assertions_passed,
                "failed": self.assertions_failed
            }
        });
        self.capture.push_value(&entry).expect("final log entry");
        self.capture
            .validate_jsonl()
            .expect("JSONL schema validation");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn test_connector_id() -> ConnectorId {
    ConnectorId::from_static("fcp.test:fork-e2e:v1")
}

fn test_object_id(label: &str) -> ObjectId {
    ObjectId::from_unscoped_bytes(label.as_bytes())
}

fn test_schema_id() -> SchemaId {
    SchemaId::new("fcp.core", "ConnectorState", Version::new(1, 0, 0))
}

fn test_object_header(zone_id: &ZoneId) -> ObjectHeader {
    ObjectHeader {
        encryption_kind: Default::default(),
        schema: test_schema_id(),
        zone_id: zone_id.clone(),
        created_at: 1_700_000_000,
        provenance: Provenance::new(zone_id.clone()),
        refs: Vec::new(),
        foreign_refs: Vec::new(),
        ttl_secs: None,
        placement: None,
    }
}

/// Simulates a writer creating a state object.
fn create_state_object(
    connector_id: &ConnectorId,
    zone_id: &ZoneId,
    prev: Option<ObjectId>,
    seq: u64,
    lease_seq: u64,
    state_data: &[u8],
) -> ConnectorStateObject {
    ConnectorStateObject {
        header: test_object_header(zone_id),
        connector_id: connector_id.clone(),
        instance_id: None,
        zone_id: zone_id.clone(),
        prev,
        seq,
        state_cbor: state_data.to_vec(),
        updated_at: 1_700_000_000 + seq,
        lease_seq,
        lease_object_id: test_object_id(&format!("lease-{lease_seq}")),
        writer_public_key: [0u8; 32],
        signature: Signature::zero(),
    }
}

/// Simulates a connector execution state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectorExecutionState {
    Running,
    Paused,
    Resumed,
}

/// Mock connector that pauses on fork detection.
struct MockConnector {
    connector_id: ConnectorId,
    state: ConnectorExecutionState,
    state_chain: Vec<ConnectorStateObject>,
    fork_detector: StateForkDetector,
}

impl MockConnector {
    fn new(connector_id: ConnectorId) -> Self {
        Self {
            connector_id,
            state: ConnectorExecutionState::Running,
            state_chain: Vec::new(),
            fork_detector: StateForkDetector::new(),
        }
    }

    /// Adds a state object to the chain (simulating a write).
    fn write_state(&mut self, state: ConnectorStateObject) {
        let id = ObjectId::from_unscoped_bytes(&state.state_cbor);
        self.fork_detector
            .register(id, state.prev, state.seq, state.lease_seq);
        self.state_chain.push(state);
    }

    /// Detects fork in the current state chain.
    fn detect_fork(&self, zone_id: ZoneId) -> StateForkDetectionResult {
        self.fork_detector
            .detect_fork(zone_id, self.connector_id.clone(), 1_700_000_100)
    }

    /// Pauses the connector (on fork detection).
    const fn pause(&mut self) {
        self.state = ConnectorExecutionState::Paused;
    }

    /// Resumes the connector (after fork resolution).
    const fn resume(&mut self) {
        self.state = ConnectorExecutionState::Resumed;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// E2E Tests
// ─────────────────────────────────────────────────────────────────────────────

/// Scenario: Two writers produce conflicting state, fork detected, resolved by lease.
#[test]
fn e2e_two_writers_fork_resolved_by_lease() {
    let mut ctx = E2ETestContext::new("e2e_two_writers_fork_resolved_by_lease");
    let connector_id = test_connector_id();
    let zone_id = ZoneId::work();
    let model = ConnectorStateModel::SingletonWriter;

    // Setup: Create mock connector
    let mut connector = MockConnector::new(connector_id.clone());

    // Phase 1: Genesis state (single writer establishes initial state)
    ctx.log_phase("setup", Some(json!({"phase": "creating genesis state"})));

    let genesis = create_state_object(&connector_id, &zone_id, None, 0, 100, b"genesis-data");
    let genesis_id = test_object_id("genesis-data");
    connector.write_state(genesis);

    // Phase 2: Two writers both write state with same prev (fork scenario)
    ctx.log_phase(
        "execute",
        Some(json!({"phase": "simulating concurrent writers"})),
    );

    // Writer A writes with higher lease_seq (should win)
    let state_a = create_state_object(
        &connector_id,
        &zone_id,
        Some(genesis_id),
        1,
        200,
        b"writer-a-data",
    );
    let state_a_id = test_object_id("writer-a-data");
    connector.write_state(state_a);

    // Writer B writes with lower lease_seq (conflicting)
    let state_b = create_state_object(
        &connector_id,
        &zone_id,
        Some(genesis_id),
        1,
        150,
        b"writer-b-data",
    );
    let _state_b_id = test_object_id("writer-b-data");
    connector.write_state(state_b);

    // Phase 3: Fork detection
    let result = connector.detect_fork(zone_id);

    ctx.assert_true(result.is_fork(), "Fork should be detected");

    let fork = result.fork_event().expect("Fork event should exist");

    // Log the fork event
    ctx.log_fork_event(
        &connector_id,
        &fork.common_prev,
        &fork.branch_a,
        &fork.branch_b,
    );

    // Pause connector on fork
    connector.pause();
    ctx.assert_eq(
        &connector.state,
        &ConnectorExecutionState::Paused,
        "Connector should be paused",
    );

    // Phase 4: Resolve via ChooseByLease (CLI simulation)
    ctx.log_phase(
        "resolve",
        Some(json!({"phase": "resolving fork via ChooseByLease"})),
    );

    let outcome =
        connector
            .fork_detector
            .resolve(fork, ForkResolution::ChooseByLease, &model, 1_700_000_101);

    ctx.assert_true(outcome.resolved, "Fork should be resolved");
    ctx.assert_eq(
        &outcome.winning_head,
        &Some(state_a_id),
        "Writer A should win (higher lease_seq)",
    );

    // Log the resolution
    ctx.log_fork_resolution(&connector_id, "ChooseByLease", &state_a_id, true);

    // Phase 5: Resume connector
    connector.resume();
    ctx.assert_eq(
        &connector.state,
        &ConnectorExecutionState::Resumed,
        "Connector should be resumed",
    );

    ctx.log_phase(
        "verify",
        Some(json!({
            "final_state": "resumed",
            "winning_head": state_a_id.to_string(),
            "resolution_strategy": "ChooseByLease"
        })),
    );

    ctx.finalize("pass");
}

/// Scenario: Fork with tied `lease_seq` requires manual resolution.
#[test]
fn e2e_fork_requires_manual_resolution() {
    let mut ctx = E2ETestContext::new("e2e_fork_requires_manual_resolution");
    let connector_id = test_connector_id();
    let zone_id = ZoneId::work();
    let model = ConnectorStateModel::SingletonWriter;

    let mut connector = MockConnector::new(connector_id.clone());

    // Genesis
    let genesis = create_state_object(&connector_id, &zone_id, None, 0, 100, b"genesis-data");
    let genesis_id = test_object_id("genesis-data");
    connector.write_state(genesis);

    // Two writers with same lease_seq (tie)
    let state_a = create_state_object(
        &connector_id,
        &zone_id,
        Some(genesis_id),
        1,
        100,
        b"writer-a-tie",
    );
    let _state_a_id = test_object_id("writer-a-tie");
    connector.write_state(state_a);

    let state_b = create_state_object(
        &connector_id,
        &zone_id,
        Some(genesis_id),
        1,
        100,
        b"writer-b-tie",
    );
    let state_b_id = test_object_id("writer-b-tie");
    connector.write_state(state_b);

    // Detect fork
    let result = connector.detect_fork(zone_id);
    ctx.assert_true(result.is_fork(), "Fork should be detected");

    let fork = result.fork_event().expect("Fork event");
    ctx.log_fork_event(
        &connector_id,
        &fork.common_prev,
        &fork.branch_a,
        &fork.branch_b,
    );

    connector.pause();

    // Try ChooseByLease - should fail due to tie
    let outcome =
        connector
            .fork_detector
            .resolve(fork, ForkResolution::ChooseByLease, &model, 1_700_000_101);

    ctx.assert_true(
        !outcome.resolved,
        "ChooseByLease should fail for tied lease_seq",
    );
    ctx.assert_true(
        outcome
            .failure_reason
            .as_ref()
            .is_some_and(|r| r.contains("tie")),
        "Failure reason should mention tie",
    );

    ctx.log_phase(
        "resolve_attempt",
        Some(json!({
            "strategy": "ChooseByLease",
            "resolved": false,
            "reason": "lease_seq tie"
        })),
    );

    // Manual resolution - operator selects writer B
    let fork2 = result
        .fork_event()
        .expect("Fork event for manual resolution");
    let manual_outcome = connector
        .fork_detector
        .resolve_manual(fork2, state_b_id, 1_700_000_102);

    ctx.assert_true(manual_outcome.resolved, "Manual resolution should succeed");
    ctx.assert_eq(
        &manual_outcome.winning_head,
        &Some(state_b_id),
        "Manual selection should be writer B",
    );

    ctx.log_fork_resolution(&connector_id, "ManualResolution", &state_b_id, true);

    connector.resume();
    ctx.assert_eq(
        &connector.state,
        &ConnectorExecutionState::Resumed,
        "Connector should be resumed",
    );

    ctx.finalize("pass");
}

/// Scenario: Three-way fork (complex fork with multiple branches).
#[test]
fn e2e_three_way_fork_detection() {
    let mut ctx = E2ETestContext::new("e2e_three_way_fork_detection");
    let connector_id = test_connector_id();
    let zone_id = ZoneId::work();

    let mut connector = MockConnector::new(connector_id.clone());

    // Genesis
    let genesis = create_state_object(&connector_id, &zone_id, None, 0, 100, b"genesis");
    let genesis_id = test_object_id("genesis");
    connector.write_state(genesis);

    // Three concurrent writers
    let state_a = create_state_object(
        &connector_id,
        &zone_id,
        Some(genesis_id),
        1,
        300,
        b"branch-a",
    );
    connector.write_state(state_a);

    let state_b = create_state_object(
        &connector_id,
        &zone_id,
        Some(genesis_id),
        1,
        200,
        b"branch-b",
    );
    connector.write_state(state_b);

    let state_c = create_state_object(
        &connector_id,
        &zone_id,
        Some(genesis_id),
        1,
        100,
        b"branch-c",
    );
    connector.write_state(state_c);

    // Detect fork - should find at least two branches
    let result = connector.detect_fork(zone_id);

    ctx.assert_true(result.is_fork(), "Multi-way fork should be detected");

    let fork = result.fork_event().expect("Fork event");
    ctx.log_fork_event(
        &connector_id,
        &fork.common_prev,
        &fork.branch_a,
        &fork.branch_b,
    );

    connector.pause();

    // Note: The current fork detector finds pairwise forks (first two conflicting branches).
    // A more sophisticated implementation would handle n-way forks.
    // For this test, we verify that at least a fork is detected.

    ctx.log_phase(
        "verify",
        Some(json!({
            "fork_type": "multi_branch",
            "detected": true,
            "common_prev": genesis_id.to_string()
        })),
    );

    ctx.finalize("pass");
}

/// Scenario: Successful state chain with no fork.
#[test]
fn e2e_linear_chain_no_fork() {
    let mut ctx = E2ETestContext::new("e2e_linear_chain_no_fork");
    let connector_id = test_connector_id();
    let zone_id = ZoneId::work();

    let mut connector = MockConnector::new(connector_id.clone());

    // Genesis
    let genesis = create_state_object(&connector_id, &zone_id, None, 0, 100, b"genesis-linear");
    let genesis_id = test_object_id("genesis-linear");
    connector.write_state(genesis);

    // Linear chain: genesis -> state1 -> state2
    let state1 = create_state_object(
        &connector_id,
        &zone_id,
        Some(genesis_id),
        1,
        101,
        b"state-1",
    );
    let state1_id = test_object_id("state-1");
    connector.write_state(state1);

    let state2 = create_state_object(&connector_id, &zone_id, Some(state1_id), 2, 102, b"state-2");
    let state2_id = test_object_id("state-2");
    connector.write_state(state2);

    // Detect fork - should find no fork
    let result = connector.detect_fork(zone_id);

    ctx.assert_true(!result.is_fork(), "Linear chain should have no fork");

    if let StateForkDetectionResult::NoFork { head, seq } = result {
        ctx.assert_eq(&head, &state2_id, "Head should be latest state");
        ctx.assert_eq(&seq, &2, "Seq should be 2");
    }

    ctx.log_phase(
        "verify",
        Some(json!({
            "chain_type": "linear",
            "fork_detected": false,
            "head": state2_id.to_string(),
            "seq": 2
        })),
    );

    ctx.finalize("pass");
}
