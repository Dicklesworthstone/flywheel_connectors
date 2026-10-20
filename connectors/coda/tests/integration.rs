//! Integration tests for the Coda connector readiness and compliance surface.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unused_async
)]

use chrono::{Duration, Utc};
use fcp_coda::{
    client::CodaClient,
    connector::{CodaConnector, operations_info},
    error::CodaError,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{
    ApprovalMode, CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector,
    HandshakeRequest, IdempotencyClass, InstanceId, InvokeRequest, InvokeStatus, OperationId,
    RequestId, SafetyTier, ZoneId,
};
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use fcp_testkit::readiness_helpers::{
    assert_doctor_response_valid, assert_self_check_not_ready, assert_self_check_ready,
};
use serde_json::json;
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const OP_DOCS_LIST: &str = "coda.docs.list";
const OP_ROWS_DELETE: &str = "coda.rows.delete";
const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/coda_connector_verification.sh";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/coda_connector/<timestamp>";
const TOKEN: &str = "tok_test";

fn handshake_req(host_public_key: [u8; 32]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [23u8; 32],
        capabilities_requested: vec![
            CapabilityId::from_static("coda.account.read"),
            CapabilityId::from_static("coda.docs.read"),
            CapabilityId::from_static("coda.tables.read"),
            CapabilityId::from_static("coda.rows.read"),
            CapabilityId::from_static("coda.rows.write"),
            CapabilityId::from_static("coda.formulas.read"),
            CapabilityId::from_static("coda.controls.read"),
            CapabilityId::from_static("coda.mutations.read"),
        ],
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    op: &'static str,
    instance_id: &InstanceId,
) -> CapabilityToken {
    let capability = match op {
        OP_DOCS_LIST => "coda.docs.read",
        OP_ROWS_DELETE => "coda.rows.write",
        _ => panic!("unsupported Coda integration operation: {op}"),
    };
    let now = Utc::now();
    // C3.4: tokens MUST include constraints (default-deny)
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[op])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should be valid")
        .target_instance(instance_id.as_str())
        .sign(signing_key)
        .expect("capability token signing should succeed");
    CapabilityToken::from_raw(raw)
}

fn invoke_req(
    op: &'static str,
    input: serde_json::Value,
    capability_token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new("coda-integration-1"),
        connector_id: ConnectorId::from_static("fcp.coda"),
        operation: OperationId::from_static(op),
        zone_id: ZoneId::work(),
        input,
        capability_token,
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: None,
        correlation_id: None,
        provenance: None,
        approval_tokens: vec![],
    }
}

async fn setup_connector(base_url: &str) -> (CodaConnector, Ed25519SigningKey) {
    let mut connector = CodaConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    connector
        .configure(json!({
            "base_url": base_url,
            "workspace_id": "ws-123",
            "allowed_doc_ids": ["doc-1"],
            "api_token": TOKEN,
            "retry": {
                "max_retries": 0,
                "initial_delay_ms": 1,
                "max_delay_ms": 1,
                "jitter_enabled": false
            },
            "request_timeout_ms": 1_000,
            "mutation_poll_interval_ms": 1,
            "mutation_deadline_ms": 100
        }))
        .await
        .unwrap();
    connector
        .handshake(handshake_req(signing_key.verifying_key().to_bytes()))
        .await
        .unwrap();
    (connector, signing_key)
}

async fn mock_whoami(server: &MockServer, status: u16) {
    let response = match status {
        200 => ResponseTemplate::new(200).set_body_json(json!({
            "name": "Coda Test User",
            "loginId": "coda-test@example.com",
            "type": "user",
            "scoped": true,
            "tokenName": "connector verification token",
            "href": "https://coda.io/apis/v1/whoami",
            "workspace": {
                "id": "ws-123",
                "type": "workspace"
            }
        })),
        429 => ResponseTemplate::new(429),
        _ => ResponseTemplate::new(status),
    };

    Mock::given(method("GET"))
        .and(path("/whoami"))
        .and(header("authorization", format!("Bearer {TOKEN}")))
        .respond_with(response)
        .mount(server)
        .await;
}

#[fcp_async_core::runtime::test]
async fn client_health_check_success() {
    let server = MockServer::start().await;
    mock_whoami(&server, 200).await;

    let runtime = ConnectorRuntime::new(ConnectorRuntimeConfig::default());
    let client = CodaClient::new(&server.uri(), TOKEN, 30_000, HttpRetryConfig::default())
        .expect("loopback Coda client should build");
    assert!(client.health_check(&runtime).await.is_ok());
}

#[fcp_async_core::runtime::test]
async fn client_health_check_401() {
    let server = MockServer::start().await;
    mock_whoami(&server, 401).await;

    let runtime = ConnectorRuntime::new(ConnectorRuntimeConfig::default());
    let client = CodaClient::new(&server.uri(), TOKEN, 30_000, HttpRetryConfig::default())
        .expect("loopback Coda client should build");
    let result = client.health_check(&runtime).await;
    assert!(matches!(result, Err(CodaError::Unauthorized(_))));
}

#[fcp_async_core::runtime::test]
async fn client_health_check_429() {
    let server = MockServer::start().await;
    mock_whoami(&server, 429).await;

    let runtime = ConnectorRuntime::new(ConnectorRuntimeConfig::default());
    let retry_config = HttpRetryConfig {
        max_retries: 0,
        initial_delay_ms: 1,
        max_delay_ms: 1,
        jitter_enabled: false,
    };
    let client = CodaClient::new(&server.uri(), TOKEN, 30_000, retry_config)
        .expect("loopback Coda client should build");
    let result = client.health_check(&runtime).await;
    assert!(matches!(result, Err(CodaError::RateLimited { .. })));
}

#[fcp_async_core::runtime::test]
async fn health_unconfigured_includes_guidance() {
    let connector = CodaConnector::new();
    let health = connector.health().await;
    assert!(!health.is_ready());
    let details = health.details.as_ref().expect("health details");
    assert!(details["operator_guidance"]["prerequisites"].is_array());
    assert!(details["operator_guidance"]["redaction_rules"].is_array());
    assert_eq!(details["verification_script"], VERIFICATION_SCRIPT_PATH);
    assert_eq!(details["artifact_root_hint"], ARTIFACT_ROOT_HINT);
    println!(
        "coda_health_evidence={}",
        serde_json::to_string_pretty(&health).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn doctor_unconfigured_reports_operator_guidance() {
    let connector = CodaConnector::new();
    let doctor = serde_json::to_value(connector.doctor()).unwrap();
    assert_doctor_response_valid(&doctor);
    assert_eq!(doctor["ready"], false);
    assert_eq!(doctor["verification_script"], VERIFICATION_SCRIPT_PATH);
    assert_eq!(
        doctor["operator_guidance"]["artifact_root_hint"],
        ARTIFACT_ROOT_HINT
    );
    println!(
        "coda_doctor_guidance_evidence={}",
        serde_json::to_string_pretty(&doctor).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_ready_with_mock_coda_api_and_evidence() {
    let server = MockServer::start().await;
    mock_whoami(&server, 200).await;

    let (connector, _signing_key) = setup_connector(&server.uri()).await;
    let doctor = serde_json::to_value(connector.doctor()).unwrap();
    assert_doctor_response_valid(&doctor);
    assert_eq!(doctor["ready"], true);
    println!(
        "coda_doctor_evidence={}",
        serde_json::to_string_pretty(&doctor).unwrap()
    );

    let report = connector.self_check().await.unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_self_check_ready(&value);
    assert_eq!(
        value["details"]["verification_script"],
        VERIFICATION_SCRIPT_PATH
    );
    assert_eq!(value["details"]["artifact_root_hint"], ARTIFACT_ROOT_HINT);
    assert_eq!(
        value["details"]["provisioning"]["auth_mode"],
        "bearer_api_token"
    );
    assert_eq!(
        value["details"]["live_probe"]["whoami"]["workspace"]["id"],
        "ws-123"
    );
    println!(
        "coda_self_check_evidence={}",
        serde_json::to_string_pretty(&value).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_retryable_coda_failure_reports_degraded() {
    let server = MockServer::start().await;
    mock_whoami(&server, 429).await;

    let (connector, _signing_key) = setup_connector(&server.uri()).await;
    let report = connector.self_check().await.unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_self_check_not_ready(&value);
    assert_eq!(value["status"], "degraded");
    assert_eq!(value["reason_code"], "self_check_retryable");
    assert_eq!(value["details"]["live_probe"]["retryable"], true);
}

#[fcp_async_core::runtime::test]
async fn invoke_docs_list_preserves_pagination_and_scope_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/docs"))
        .and(query_param("workspaceId", "ws-123"))
        .and(query_param("limit", "2"))
        .and(query_param("pageToken", "next-1"))
        .and(header("authorization", format!("Bearer {TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [
                {
                    "id": "doc-1",
                    "type": "doc",
                    "name": "Allowed Doc",
                    "workspaceId": "ws-123"
                },
                {
                    "id": "doc-2",
                    "type": "doc",
                    "name": "Filtered Doc",
                    "workspaceId": "ws-123"
                }
            ],
            "nextPageToken": "next-2",
            "nextPageLink": format!("{}/docs?pageToken=next-2", server.uri())
        })))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri()).await;
    let response = connector
        .invoke(invoke_req(
            OP_DOCS_LIST,
            json!({
                "limit": 2,
                "page_token": "next-1"
            }),
            generate_valid_token(&signing_key, OP_DOCS_LIST, connector.instance_id()),
        ))
        .await
        .unwrap();

    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.expect("docs list result");
    assert_eq!(result["items"].as_array().unwrap().len(), 1);
    assert_eq!(result["items"][0]["id"], "doc-1");
    assert_eq!(result["nextPageToken"], "next-2");
    println!(
        "coda_docs_pagination_evidence={}",
        serde_json::to_string_pretty(&result).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_rows_delete_tracks_async_mutation_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/docs/doc-1"))
        .and(header("authorization", format!("Bearer {TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "doc-1",
            "type": "doc",
            "name": "Allowed Doc",
            "workspaceId": "ws-123"
        })))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/docs/doc-1/tables/grid-tasks/rows"))
        .and(header("authorization", format!("Bearer {TOKEN}")))
        .and(body_json(json!({ "rowIds": ["row-1"] })))
        .respond_with(ResponseTemplate::new(202).set_body_json(json!({
            "requestId": "req-del",
            "rowIds": ["row-1"]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/mutationStatus/req-del"))
        .and(header("authorization", format!("Bearer {TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "requestId": "req-del",
            "completed": true,
            "resultingRowIds": ["row-1"]
        })))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri()).await;
    let response = connector
        .invoke(invoke_req(
            OP_ROWS_DELETE,
            json!({
                "doc_id": "doc-1",
                "table_id_or_name": "grid-tasks",
                "row_ids": ["row-1"]
            }),
            generate_valid_token(&signing_key, OP_ROWS_DELETE, connector.instance_id()),
        ))
        .await
        .unwrap();

    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.expect("rows delete result");
    assert_eq!(result["queued"]["requestId"], "req-del");
    assert_eq!(result["queued"]["rowIds"][0], "row-1");
    assert_eq!(result["mutation"]["completed"], true);
    assert_eq!(result["mutation"]["resultingRowIds"][0], "row-1");
    println!(
        "coda_rows_delete_evidence={}",
        serde_json::to_string_pretty(&result).unwrap()
    );
}

#[test]
fn introspection_emits_v3_compliance_evidence() {
    let connector = CodaConnector::new();
    let introspection = connector.introspect();
    let value = serde_json::to_value(&introspection).unwrap();
    let operations = value["operations"].as_array().expect("operations array");

    assert_eq!(operations.len(), 18);
    assert!(operations.iter().all(|operation| {
        operation["ai_hints"]["when_to_use"]
            .as_str()
            .is_some_and(|when_to_use| !when_to_use.is_empty())
    }));

    let delete = operations_info()
        .into_iter()
        .find(|operation| operation.id.as_str() == OP_ROWS_DELETE)
        .expect("rows delete operation");
    assert_eq!(delete.safety_tier, SafetyTier::Dangerous);
    assert_eq!(delete.requires_approval, Some(ApprovalMode::Interactive));

    let health = operations
        .iter()
        .find(|operation| operation["id"] == "coda.health")
        .expect("health operation");
    assert_eq!(
        health["idempotency"],
        serde_json::to_value(IdempotencyClass::Strict).unwrap()
    );

    println!(
        "coda_introspection_evidence={}",
        serde_json::to_string_pretty(&value).unwrap()
    );
}
