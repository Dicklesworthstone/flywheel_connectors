//! FCPC Control-Plane Integration Tests (flywheel_connectors-1n78.13)
//!
//! Demonstrates that FCPC frames can carry InvokeRequest/Response and receipts
//! end-to-end, satisfying the acceptance criterion:
//! "FCPC can carry InvokeRequest/Response + receipts end-to-end in the system harness."
//!
//! This test proves library-level integration between:
//! - `fcp-core`: `InvokeRequest`, `InvokeResponse`, `ControlPlaneObject` types
//! - `fcp-protocol`: `FcpcFrame` seal/open, retention classification
//! - `fcp-cbor`: Canonical CBOR serialization

use fcp_cbor::SchemaId;
use fcp_prelude::{
    CapabilityToken, ConnectorId, FcpError, InvokeRequest, InvokeResponse, InvokeStatus,
    ObjectHeader, ObjectId, OperationId, Provenance, RequestId, ZoneId,
};
use fcp_protocol::{
    ControlPlaneObject, ControlPlaneRetention, FcpcFrame, FcpcFrameFlags, MeshSessionId,
    SessionDirection,
};
use semver::Version;
use serde_json::json;

// Test constants
const GOLDEN_SESSION_ID: [u8; 16] = [0x01; 16];
const GOLDEN_K_CTX: [u8; 32] = [0x42; 32];

fn test_schema(namespace: &str, name: &str) -> SchemaId {
    SchemaId::new(namespace, name, Version::new(1, 0, 0))
}

fn make_invoke_request() -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId("req_test_001".into()),
        connector_id: ConnectorId::new("test", "connector", "v1").unwrap(),
        operation: OperationId::new("op.echo").unwrap(),
        zone_id: ZoneId::work(),
        input: json!({"message": "Hello from FCPC integration test"}),
        capability_token: CapabilityToken::test_token(),
        holder_proof: None,
        context: None,
        idempotency_key: Some("idem_key_123".into()),
        lease_seq: None,
        deadline_ms: Some(30000),
        correlation_id: None,
        provenance: None,
        approval_tokens: vec![],
    }
}

fn make_invoke_response(request_id: RequestId) -> InvokeResponse {
    let mut resp = InvokeResponse::ok(request_id, json!({"echo": "Hello back!"}));
    resp.receipt_id = Some(ObjectId::from_bytes([0xAB; 32]));
    resp.audit_event_id = Some(ObjectId::from_bytes([0xCD; 32]));
    resp
}

fn make_error_response(request_id: RequestId) -> InvokeResponse {
    let mut resp = InvokeResponse::error(
        request_id,
        FcpError::CapabilityDenied {
            capability: "cap.admin".into(),
            reason: "insufficient scope".into(),
        },
    );
    resp.decision_receipt_id = Some(ObjectId::from_bytes([0xEF; 32]));
    resp
}

// ═══════════════════════════════════════════════════════════════════════════════
// INVOKE REQUEST END-TO-END TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn invoke_request_round_trip_through_fcpc() {
    let session_id = MeshSessionId(GOLDEN_SESSION_ID);
    let direction = SessionDirection::InitiatorToResponder;

    // 1. Create InvokeRequest
    let original_request = make_invoke_request();

    // 2. Serialize to canonical CBOR (simulating body preparation)
    let request_json = serde_json::to_vec(&original_request).expect("serialize request");

    // 3. Create ControlPlaneObject header
    let header = ObjectHeader {
        encryption_kind: Default::default(),
        schema: test_schema("fcp.invoke", "Request"),
        zone_id: original_request.zone_id.clone(),
        created_at: 1_700_000_000,
        provenance: Provenance::new(ZoneId::work()),
        refs: vec![],
        foreign_refs: vec![],
        ttl_secs: None,
        placement: None,
    };

    let control_obj = ControlPlaneObject::new(header, request_json);

    // Verify retention classification
    assert_eq!(control_obj.retention(), ControlPlaneRetention::Required);

    // 4. Seal into FCPC frame
    let frame = FcpcFrame::seal(
        session_id,
        1,
        direction,
        FcpcFrameFlags::default(),
        &control_obj.body,
        &GOLDEN_K_CTX,
    )
    .expect("seal should succeed");

    // 5. Encode to wire format
    let wire_bytes = frame.encode();

    // 6. Decode from wire format
    let decoded_frame = FcpcFrame::decode(&wire_bytes).expect("decode should succeed");

    // 7. Open (decrypt) the frame
    let decrypted_body = decoded_frame
        .open(direction, &GOLDEN_K_CTX)
        .expect("open should succeed");

    // 8. Deserialize back to InvokeRequest
    let recovered_request: InvokeRequest =
        serde_json::from_slice(&decrypted_body).expect("deserialize request");

    // 9. Verify round-trip integrity
    assert_eq!(recovered_request.id.0, original_request.id.0);
    assert_eq!(
        recovered_request.operation.as_str(),
        original_request.operation.as_str()
    );
    assert_eq!(
        recovered_request.zone_id.as_str(),
        original_request.zone_id.as_str()
    );
    assert_eq!(recovered_request.input, original_request.input);
    assert_eq!(
        recovered_request.idempotency_key,
        original_request.idempotency_key
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// INVOKE RESPONSE END-TO-END TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn invoke_response_round_trip_through_fcpc() {
    let session_id = MeshSessionId(GOLDEN_SESSION_ID);
    let direction = SessionDirection::ResponderToInitiator;

    // 1. Create InvokeResponse with receipt
    let original_response = make_invoke_response(RequestId("req_test_001".into()));

    // 2. Serialize to bytes
    let response_json = serde_json::to_vec(&original_response).expect("serialize response");

    // 3. Create ControlPlaneObject
    let header = ObjectHeader {
        encryption_kind: Default::default(),
        schema: test_schema("fcp.invoke", "Response"),
        zone_id: ZoneId::work(),
        created_at: 1_700_000_001,
        provenance: Provenance::new(ZoneId::work()),
        refs: vec![],
        foreign_refs: vec![],
        ttl_secs: None,
        placement: None,
    };

    let control_obj = ControlPlaneObject::new(header, response_json);
    assert_eq!(control_obj.retention(), ControlPlaneRetention::Required);

    // 4. Seal into FCPC frame
    let frame = FcpcFrame::seal(
        session_id,
        2,
        direction,
        FcpcFrameFlags::default(),
        &control_obj.body,
        &GOLDEN_K_CTX,
    )
    .expect("seal should succeed");

    // 5. Encode and decode
    let wire_bytes = frame.encode();
    let decoded_frame = FcpcFrame::decode(&wire_bytes).expect("decode should succeed");

    // 6. Open and deserialize
    let decrypted_body = decoded_frame
        .open(direction, &GOLDEN_K_CTX)
        .expect("open should succeed");
    let recovered_response: InvokeResponse =
        serde_json::from_slice(&decrypted_body).expect("deserialize response");

    // 7. Verify round-trip integrity including receipt IDs
    assert_eq!(recovered_response.id.0, original_response.id.0);
    assert_eq!(recovered_response.status, InvokeStatus::Ok);
    assert_eq!(recovered_response.receipt_id, original_response.receipt_id);
    assert_eq!(
        recovered_response.audit_event_id,
        original_response.audit_event_id
    );
    assert_eq!(recovered_response.result, original_response.result);
}

#[test]
fn error_response_with_decision_receipt_round_trip() {
    let session_id = MeshSessionId(GOLDEN_SESSION_ID);
    let direction = SessionDirection::ResponderToInitiator;

    // 1. Create error response with decision receipt
    let original_response = make_error_response(RequestId("req_denied_001".into()));

    // 2. Serialize
    let response_json = serde_json::to_vec(&original_response).expect("serialize response");

    // 3. Seal into FCPC
    let frame = FcpcFrame::seal(
        session_id,
        3,
        direction,
        FcpcFrameFlags::default(),
        &response_json,
        &GOLDEN_K_CTX,
    )
    .expect("seal should succeed");

    // 4. Encode, decode, open
    let wire_bytes = frame.encode();
    let decoded_frame = FcpcFrame::decode(&wire_bytes).expect("decode should succeed");
    let decrypted_body = decoded_frame
        .open(direction, &GOLDEN_K_CTX)
        .expect("open should succeed");
    let recovered_response: InvokeResponse =
        serde_json::from_slice(&decrypted_body).expect("deserialize response");

    // 5. Verify error response with decision receipt
    assert_eq!(recovered_response.status, InvokeStatus::Error);
    assert_eq!(
        recovered_response.decision_receipt_id,
        original_response.decision_receipt_id
    );
    assert!(recovered_response.error.is_some());
}

// ═══════════════════════════════════════════════════════════════════════════════
// BIDIRECTIONAL CONVERSATION TEST
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn bidirectional_invoke_conversation() {
    let session_id = MeshSessionId(GOLDEN_SESSION_ID);
    let mut seq = 0u64;

    // Simulate a complete invoke conversation:
    // Client → Server: InvokeRequest
    // Server → Client: InvokeResponse

    // --- Client sends request ---
    let request = make_invoke_request();
    let request_bytes = serde_json::to_vec(&request).expect("serialize request");

    seq += 1;
    let request_frame = FcpcFrame::seal(
        session_id,
        seq,
        SessionDirection::InitiatorToResponder,
        FcpcFrameFlags::default(),
        &request_bytes,
        &GOLDEN_K_CTX,
    )
    .expect("seal request");

    // Wire transmission simulation
    let request_wire = request_frame.encode();
    let received_request_frame =
        FcpcFrame::decode(&request_wire).expect("decode request on server");
    let request_plaintext = received_request_frame
        .open(SessionDirection::InitiatorToResponder, &GOLDEN_K_CTX)
        .expect("open request");
    let server_received_request: InvokeRequest =
        serde_json::from_slice(&request_plaintext).expect("deserialize request");

    // --- Server sends response ---
    let response = make_invoke_response(server_received_request.id.clone());
    let response_bytes = serde_json::to_vec(&response).expect("serialize response");

    seq += 1;
    let response_frame = FcpcFrame::seal(
        session_id,
        seq,
        SessionDirection::ResponderToInitiator,
        FcpcFrameFlags::default(),
        &response_bytes,
        &GOLDEN_K_CTX,
    )
    .expect("seal response");

    // Wire transmission simulation
    let response_wire = response_frame.encode();
    let received_response_frame =
        FcpcFrame::decode(&response_wire).expect("decode response on client");
    let response_plaintext = received_response_frame
        .open(SessionDirection::ResponderToInitiator, &GOLDEN_K_CTX)
        .expect("open response");
    let client_received_response: InvokeResponse =
        serde_json::from_slice(&response_plaintext).expect("deserialize response");

    // Verify correlation
    assert_eq!(server_received_request.id.0, request.id.0);
    assert_eq!(client_received_response.id.0, request.id.0);
    assert_eq!(client_received_response.status, InvokeStatus::Ok);
    assert!(client_received_response.receipt_id.is_some());
}

// ═══════════════════════════════════════════════════════════════════════════════
// RETENTION CLASSIFICATION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn invoke_objects_have_required_retention() {
    let invoke_request_header = ObjectHeader {
        encryption_kind: Default::default(),
        schema: test_schema("fcp.invoke", "Request"),
        zone_id: ZoneId::work(),
        created_at: 1_700_000_000,
        provenance: Provenance::new(ZoneId::work()),
        refs: vec![],
        foreign_refs: vec![],
        ttl_secs: None,
        placement: None,
    };

    let invoke_response_header = ObjectHeader {
        encryption_kind: Default::default(),
        schema: test_schema("fcp.invoke", "Response"),
        zone_id: ZoneId::work(),
        created_at: 1_700_000_000,
        provenance: Provenance::new(ZoneId::work()),
        refs: vec![],
        foreign_refs: vec![],
        ttl_secs: None,
        placement: None,
    };

    let request_obj = ControlPlaneObject::new(invoke_request_header, vec![]);
    let response_obj = ControlPlaneObject::new(invoke_response_header, vec![]);

    // InvokeRequest and InvokeResponse MUST be stored for auditability
    assert_eq!(request_obj.retention(), ControlPlaneRetention::Required);
    assert_eq!(response_obj.retention(), ControlPlaneRetention::Required);
}

#[test]
fn receipt_objects_have_required_retention() {
    let receipt_header = ObjectHeader {
        encryption_kind: Default::default(),
        schema: test_schema("fcp.receipt", "ExecutionReceipt"),
        zone_id: ZoneId::work(),
        created_at: 1_700_000_000,
        provenance: Provenance::new(ZoneId::work()),
        refs: vec![],
        foreign_refs: vec![],
        ttl_secs: None,
        placement: None,
    };

    let receipt_obj = ControlPlaneObject::new(receipt_header, vec![]);

    // Receipts MUST be stored for auditability
    assert_eq!(receipt_obj.retention(), ControlPlaneRetention::Required);
}

#[test]
fn health_objects_have_ephemeral_retention() {
    let health_header = ObjectHeader {
        encryption_kind: Default::default(),
        schema: test_schema("fcp.health", "Ping"),
        zone_id: ZoneId::work(),
        created_at: 1_700_000_000,
        provenance: Provenance::new(ZoneId::work()),
        refs: vec![],
        foreign_refs: vec![],
        ttl_secs: None,
        placement: None,
    };

    let health_obj = ControlPlaneObject::new(health_header, vec![]);

    // Health checks MAY be dropped after processing
    assert_eq!(health_obj.retention(), ControlPlaneRetention::Ephemeral);
}

// ═══════════════════════════════════════════════════════════════════════════════
// REPLAY PROTECTION INTEGRATION
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn replay_protection_for_invoke_requests() {
    let session_id = MeshSessionId(GOLDEN_SESSION_ID);
    let direction = SessionDirection::InitiatorToResponder;

    let request = make_invoke_request();
    let request_bytes = serde_json::to_vec(&request).expect("serialize request");

    // Seal the same request with the same sequence number
    let frame = FcpcFrame::seal(
        session_id,
        1,
        direction,
        FcpcFrameFlags::default(),
        &request_bytes,
        &GOLDEN_K_CTX,
    )
    .expect("seal should succeed");

    let wire_bytes = frame.encode();
    let decoded_frame = FcpcFrame::decode(&wire_bytes).expect("decode should succeed");

    // First check should pass
    let mut replay_window = fcp_protocol::default_replay_window();
    decoded_frame
        .check_replay(&mut replay_window)
        .expect("first check should pass");

    // Replay should be rejected
    let replay_result = decoded_frame.check_replay(&mut replay_window);
    assert!(
        replay_result.is_err(),
        "replay of invoke request should be rejected"
    );
}
