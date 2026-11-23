//! Integration tests for the FCP AWS connector.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use chrono::{Duration, Utc};
use fcp_aws::connector::AwsConnector;
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{
    ApprovalMode, CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector,
    HandshakeRequest, IdempotencyClass, InvokeRequest, OperationId, RequestId, SafetyTier, ZoneId,
};
use fcp_testkit::readiness_helpers::{
    assert_doctor_response_valid, assert_self_check_not_ready, assert_self_check_ready,
};
use serde_json::json;
use wiremock::matchers::{header_exists, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const OP_S3_LIST_OBJECTS: &str = "aws.s3.list_objects";
const OP_S3_PUT_OBJECT: &str = "aws.s3.put_object";
const OP_S3_DELETE_OBJECT: &str = "aws.s3.delete_object";
const OP_EC2_TERMINATE: &str = "aws.ec2.terminate_instance";
const OP_LAMBDA_LIST: &str = "aws.lambda.list_functions";
const OP_STS_IDENTITY: &str = "aws.sts.get_caller_identity";
const TEST_ACCESS_KEY_ID: &str = "fcp-test-access-key";
const TEST_SIGNING_MATERIAL: &str = "fcp-test-signing-material";

fn handshake_req(host_public_key: [u8; 32]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [5u8; 32],
        capabilities_requested: vec![
            CapabilityId::from_static("aws.s3.read"),
            CapabilityId::from_static("aws.s3.write"),
            CapabilityId::from_static("aws.ec2.write"),
            CapabilityId::from_static("aws.lambda.read"),
            CapabilityId::from_static("aws.iam.read"),
        ],
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

fn generate_valid_token(
    connector: &AwsConnector,
    signing_key: &Ed25519SigningKey,
    op: &'static str,
) -> CapabilityToken {
    let capability = match op {
        OP_S3_LIST_OBJECTS => "aws.s3.read",
        OP_S3_PUT_OBJECT | OP_S3_DELETE_OBJECT => "aws.s3.write",
        OP_EC2_TERMINATE => "aws.ec2.write",
        OP_LAMBDA_LIST => "aws.lambda.read",
        OP_STS_IDENTITY => "aws.iam.read",
        _ => "aws.s3.read",
    };
    assert!(
        matches!(
            op,
            OP_S3_LIST_OBJECTS
                | OP_S3_PUT_OBJECT
                | OP_S3_DELETE_OBJECT
                | OP_EC2_TERMINATE
                | OP_LAMBDA_LIST
                | OP_STS_IDENTITY
        ),
        "unsupported test operation: {op}"
    );
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
        .target_instance(connector.instance_id())
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
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
        id: RequestId::new("aws-integration-1"),
        connector_id: ConnectorId::from_static("fcp.aws"),
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

async fn setup_connector(mock_url: &str) -> (AwsConnector, Ed25519SigningKey) {
    let mut connector = AwsConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    connector
        .configure(json!({
            "access_key_id": TEST_ACCESS_KEY_ID,
            "secret_access_key": TEST_SIGNING_MATERIAL,
            "region": "us-east-1",
            "s3_base_url": mock_url,
            "ec2_base_url": mock_url,
            "lambda_base_url": mock_url,
            "sts_base_url": mock_url,
            "retry": { "max_retries": 0 }
        }))
        .await
        .unwrap();
    connector
        .handshake(handshake_req(signing_key.verifying_key().to_bytes()))
        .await
        .unwrap();
    (connector, signing_key)
}

fn assert_sigv4_headers(request: &wiremock::Request) {
    let authorization = request
        .headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .expect("authorization header should be present");
    assert!(
        authorization.starts_with(&format!(
            "AWS4-HMAC-SHA256 Credential={TEST_ACCESS_KEY_ID}/"
        )),
        "unexpected authorization header: {authorization}"
    );
    assert!(authorization.contains("SignedHeaders="));
    assert!(authorization.contains("Signature="));
    assert!(request.headers.get("x-amz-date").is_some());
    assert!(request.headers.get("x-amz-content-sha256").is_some());
    assert!(request.headers.get("x-aws-access-key-id").is_none());
    assert!(request.headers.get("x-aws-secret-access-key").is_none());
}

#[fcp_async_core::runtime::test]
async fn lifecycle_health_unconfigured_includes_guidance() {
    let connector = AwsConnector::new();
    let health = connector.health().await;
    assert!(!health.is_ready());
    let details = health.details.as_ref().expect("health details");
    assert!(details["operator_guidance"]["dedicated_environment"].is_string());
    assert!(details["operator_guidance"]["prerequisites"].is_array());
    assert!(details["operator_guidance"]["redaction_rules"].is_array());
    assert_eq!(
        details["verification_script"],
        "scripts/e2e/aws_connector_verification.sh"
    );
    assert_eq!(
        details["artifact_root_hint"],
        "artifacts/e2e/aws_connector/<timestamp>"
    );
    println!(
        "aws_health_evidence={}",
        serde_json::to_string_pretty(&health).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn doctor_unconfigured_reports_remediation() {
    let connector = AwsConnector::new();
    let doctor = serde_json::to_value(connector.doctor()).unwrap();
    assert_doctor_response_valid(&doctor);
    assert_eq!(doctor["ready"], false);
    assert_eq!(
        doctor["verification_script"],
        "scripts/e2e/aws_connector_verification.sh"
    );
    assert!(doctor["operator_guidance"]["redaction_rules"].is_array());
    assert_eq!(
        doctor["operator_guidance"]["artifact_root_hint"],
        "artifacts/e2e/aws_connector/<timestamp>"
    );
    println!(
        "aws_doctor_guidance_evidence={}",
        serde_json::to_string_pretty(&doctor).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_ready_with_custom_sts_override_and_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(query_param("Action", "GetCallerIdentity"))
        .and(query_param("Version", "2011-06-15"))
        .and(header_exists("Authorization"))
        .and(header_exists("X-Amz-Date"))
        .and(header_exists("X-Amz-Content-Sha256"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
<GetCallerIdentityResult><Account>123456789012</Account>
<Arn>arn:aws:sts::123456789012:assumed-role/test/AwsConnector</Arn>
<UserId>AIDATESTUSER</UserId></GetCallerIdentityResult>
<ResponseMetadata><RequestId>test-request</RequestId></ResponseMetadata>
</GetCallerIdentityResponse>"#,
        ))
        .mount(&server)
        .await;

    let (connector, _signing_key) = setup_connector(&server.uri()).await;
    let doctor = serde_json::to_value(connector.doctor()).unwrap();
    assert_doctor_response_valid(&doctor);
    assert_eq!(doctor["ready"], true);
    println!(
        "aws_doctor_evidence={}",
        serde_json::to_string_pretty(&doctor).unwrap()
    );

    let report = connector.self_check().await.unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_self_check_ready(&value);
    assert_eq!(
        value["details"]["provisioning"]["sts_self_check_supported"],
        true
    );
    let requests = server.received_requests().await.unwrap_or_default();
    assert_eq!(requests.len(), 1);
    assert_sigv4_headers(&requests[0]);
    println!(
        "aws_self_check_evidence={}",
        serde_json::to_string_pretty(&value).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_retryable_sts_failure_reports_degraded() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(query_param("Action", "GetCallerIdentity"))
        .and(query_param("Version", "2011-06-15"))
        .respond_with(ResponseTemplate::new(503).set_body_string("sts unavailable"))
        .mount(&server)
        .await;

    let (connector, _signing_key) = setup_connector(&server.uri()).await;
    let report = connector.self_check().await.unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_self_check_not_ready(&value);
    assert_eq!(value["status"], "degraded");
    assert_eq!(value["reason_code"], "self_check_retryable");
}

#[fcp_async_core::runtime::test]
async fn self_check_auth_failure_reports_auth_failure() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(query_param("Action", "GetCallerIdentity"))
        .and(query_param("Version", "2011-06-15"))
        .and(header_exists("Authorization"))
        .and(header_exists("X-Amz-Date"))
        .and(header_exists("X-Amz-Content-Sha256"))
        .respond_with(ResponseTemplate::new(403).set_body_string("SignatureDoesNotMatch"))
        .mount(&server)
        .await;

    let (connector, _signing_key) = setup_connector(&server.uri()).await;
    let report = connector.self_check().await.unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_eq!(value["status"], "failed");
    assert_eq!(value["reason_code"], "self_check_failed");
    let report_text = serde_json::to_string(&value).unwrap();
    assert!(report_text.contains("Authentication failed (HTTP 403)"));
    let requests = server.received_requests().await.unwrap_or_default();
    assert_eq!(requests.len(), 1);
    assert_sigv4_headers(&requests[0]);
}

#[fcp_async_core::runtime::test]
async fn invoke_s3_list_objects_parses_native_xml() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/test-bucket"))
        .and(query_param("list-type", "2"))
        .and(header_exists("Authorization"))
        .and(header_exists("X-Amz-Date"))
        .and(header_exists("X-Amz-Content-Sha256"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-bucket</Name>
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Key>fcp-live/object.txt</Key>
    <LastModified>2026-05-15T11:00:00.000Z</LastModified>
    <ETag>&quot;abc123&quot;</ETag>
    <Size>42</Size>
    <StorageClass>STANDARD</StorageClass>
  </Contents>
</ListBucketResult>"#,
        ))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri()).await;
    let response = connector
        .invoke(invoke_req(
            OP_S3_LIST_OBJECTS,
            json!({ "bucket": "test-bucket" }),
            generate_valid_token(&connector, &signing_key, OP_S3_LIST_OBJECTS),
        ))
        .await
        .unwrap();

    let result = response.result.expect("s3 list objects result");
    let objects = result.as_array().expect("objects array");
    assert_eq!(objects.len(), 1);
    assert_eq!(objects[0]["key"], "fcp-live/object.txt");
    assert_eq!(objects[0]["size"], 42);
    let requests = server.received_requests().await.unwrap_or_default();
    assert_eq!(requests.len(), 1);
    assert_sigv4_headers(&requests[0]);
}

#[fcp_async_core::runtime::test]
async fn invoke_s3_put_accepts_native_empty_response_headers() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/test-bucket/fcp-live/object.txt"))
        .and(header_exists("Authorization"))
        .and(header_exists("X-Amz-Date"))
        .and(header_exists("X-Amz-Content-Sha256"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("etag", "\"abc123\"")
                .insert_header("x-amz-version-id", "version-1"),
        )
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri()).await;
    let response = connector
        .invoke(invoke_req(
            OP_S3_PUT_OBJECT,
            json!({
                "bucket": "test-bucket",
                "key": "fcp-live/object.txt",
                "body": "hello from native s3",
                "content_type": "text/plain"
            }),
            generate_valid_token(&connector, &signing_key, OP_S3_PUT_OBJECT),
        ))
        .await
        .unwrap();

    let result = response.result.expect("s3 put result");
    assert_eq!(result["etag"], "\"abc123\"");
    assert_eq!(result["version_id"], "version-1");
    let requests = server.received_requests().await.unwrap_or_default();
    assert_eq!(requests.len(), 1);
    assert_sigv4_headers(&requests[0]);
}

#[fcp_async_core::runtime::test]
async fn invoke_dangerous_s3_delete_preserves_artifact_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/test-bucket/object.txt"))
        .and(header_exists("Authorization"))
        .and(header_exists("X-Amz-Date"))
        .and(header_exists("X-Amz-Content-Sha256"))
        .respond_with(
            ResponseTemplate::new(204)
                .insert_header("x-amz-delete-marker", "true")
                .insert_header("x-amz-version-id", "ver-123"),
        )
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri()).await;
    let response = connector
        .invoke(invoke_req(
            OP_S3_DELETE_OBJECT,
            json!({
                "bucket": "test-bucket",
                "key": "object.txt"
            }),
            generate_valid_token(&connector, &signing_key, OP_S3_DELETE_OBJECT),
        ))
        .await
        .unwrap();

    let result = response.result.expect("s3 delete result");
    assert_eq!(result["delete_marker"], true);
    let requests = server.received_requests().await.unwrap_or_default();
    assert_eq!(requests.len(), 1);
    assert_sigv4_headers(&requests[0]);
    println!(
        "aws_risky_mutation_evidence={}",
        serde_json::to_string_pretty(&result).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_s3_delete_accepts_native_empty_response_headers() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/test-bucket/fcp-live/object.txt"))
        .and(header_exists("Authorization"))
        .and(header_exists("X-Amz-Date"))
        .and(header_exists("X-Amz-Content-Sha256"))
        .respond_with(
            ResponseTemplate::new(204)
                .insert_header("x-amz-delete-marker", "true")
                .insert_header("x-amz-version-id", "version-2"),
        )
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri()).await;
    let response = connector
        .invoke(invoke_req(
            OP_S3_DELETE_OBJECT,
            json!({
                "bucket": "test-bucket",
                "key": "fcp-live/object.txt"
            }),
            generate_valid_token(&connector, &signing_key, OP_S3_DELETE_OBJECT),
        ))
        .await
        .unwrap();

    let result = response.result.expect("s3 delete result");
    assert_eq!(result["delete_marker"], true);
    assert_eq!(result["version_id"], "version-2");
    let requests = server.received_requests().await.unwrap_or_default();
    assert_eq!(requests.len(), 1);
    assert_sigv4_headers(&requests[0]);
}

#[fcp_async_core::runtime::test]
async fn invoke_ec2_terminate_preserves_state_transition_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(query_param("Action", "TerminateInstances"))
        .and(query_param("InstanceId.1", "i-0123456789abcdef0"))
        .and(query_param("Version", "2016-11-15"))
        .and(header_exists("Authorization"))
        .and(header_exists("X-Amz-Date"))
        .and(header_exists("X-Amz-Content-Sha256"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<TerminateInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
<requestId>test-request</requestId><instancesSet><item>
<instanceId>i-0123456789abcdef0</instanceId>
<previousState><code>16</code><name>running</name></previousState>
<currentState><code>32</code><name>shutting-down</name></currentState>
</item></instancesSet></TerminateInstancesResponse>"#,
        ))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri()).await;
    let response = connector
        .invoke(invoke_req(
            OP_EC2_TERMINATE,
            json!({
                "instance_id": "i-0123456789abcdef0"
            }),
            generate_valid_token(&connector, &signing_key, OP_EC2_TERMINATE),
        ))
        .await
        .unwrap();

    let result = response.result.expect("ec2 terminate result");
    assert_eq!(result["previous_state"], "running");
    assert_eq!(result["current_state"], "shutting-down");
    let requests = server.received_requests().await.unwrap_or_default();
    assert_eq!(requests.len(), 1);
    assert_sigv4_headers(&requests[0]);
    println!(
        "aws_ec2_terminate_evidence={}",
        serde_json::to_string_pretty(&result).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_lambda_list_functions_preserves_artifact_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/2015-03-31/functions"))
        .and(header_exists("Authorization"))
        .and(header_exists("X-Amz-Date"))
        .and(header_exists("X-Amz-Content-Sha256"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "Functions": [{
                "FunctionName": "sync-orders",
                "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:sync-orders",
                "Runtime": "provided.al2023",
                "Handler": "bootstrap",
                "MemorySize": 256,
                "Timeout": 30
            }]
        })))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri()).await;
    let response = connector
        .invoke(invoke_req(
            OP_LAMBDA_LIST,
            json!({}),
            generate_valid_token(&connector, &signing_key, OP_LAMBDA_LIST),
        ))
        .await
        .unwrap();

    let result = response.result.expect("lambda list result");
    assert_eq!(result.as_array().unwrap().len(), 1);
    assert_eq!(result[0]["function_name"], "sync-orders");
    let requests = server.received_requests().await.unwrap_or_default();
    assert_eq!(requests.len(), 1);
    assert_sigv4_headers(&requests[0]);
    println!(
        "aws_lambda_list_evidence={}",
        serde_json::to_string_pretty(&result).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_sts_identity_preserves_artifact_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(query_param("Action", "GetCallerIdentity"))
        .and(query_param("Version", "2011-06-15"))
        .and(header_exists("Authorization"))
        .and(header_exists("X-Amz-Date"))
        .and(header_exists("X-Amz-Content-Sha256"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
<GetCallerIdentityResult><Account>123456789012</Account>
<Arn>arn:aws:sts::123456789012:assumed-role/test/AwsConnector</Arn>
<UserId>AIDATESTUSER</UserId></GetCallerIdentityResult>
<ResponseMetadata><RequestId>test-request</RequestId></ResponseMetadata>
</GetCallerIdentityResponse>"#,
        ))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri()).await;
    let response = connector
        .invoke(invoke_req(
            OP_STS_IDENTITY,
            json!({}),
            generate_valid_token(&connector, &signing_key, OP_STS_IDENTITY),
        ))
        .await
        .unwrap();

    let result = response.result.expect("sts identity result");
    assert_eq!(result["account"], "123456789012");
    let requests = server.received_requests().await.unwrap_or_default();
    assert_eq!(requests.len(), 1);
    assert_sigv4_headers(&requests[0]);
    println!(
        "aws_sts_identity_evidence={}",
        serde_json::to_string_pretty(&result).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn introspection_emits_v3_compliance_evidence() {
    let connector = AwsConnector::new();
    let operations = connector.introspect().operations;
    assert_eq!(operations.len(), 13);

    let s3_delete = operations
        .iter()
        .find(|operation| operation.id.as_str() == OP_S3_DELETE_OBJECT)
        .expect("s3 delete operation");
    assert_eq!(s3_delete.safety_tier, SafetyTier::Dangerous);
    assert_eq!(s3_delete.idempotency, IdempotencyClass::Strict);
    assert_eq!(s3_delete.requires_approval, Some(ApprovalMode::Interactive));

    let ec2_terminate = operations
        .iter()
        .find(|operation| operation.id.as_str() == OP_EC2_TERMINATE)
        .expect("ec2 terminate operation");
    assert_eq!(ec2_terminate.safety_tier, SafetyTier::Dangerous);
    assert_eq!(ec2_terminate.idempotency, IdempotencyClass::Strict);
    assert_eq!(
        ec2_terminate.requires_approval,
        Some(ApprovalMode::Interactive)
    );

    let evidence = json!({
        "operation_ids": operations
            .iter()
            .map(|operation| operation.id.as_str())
            .collect::<Vec<_>>(),
        "dangerous_operations": operations
            .iter()
            .filter(|operation| operation.safety_tier == SafetyTier::Dangerous)
            .map(|operation| {
                json!({
                    "id": operation.id.as_str(),
                    "capability": operation.capability.as_str(),
                    "idempotency": format!("{:?}", operation.idempotency),
                    "requires_approval": serde_json::to_value(operation.requires_approval)
                        .unwrap_or(serde_json::Value::Null),
                })
            })
            .collect::<Vec<_>>(),
    });
    println!(
        "aws_v3_conformance_evidence={}",
        serde_json::to_string_pretty(&evidence).unwrap()
    );
}
