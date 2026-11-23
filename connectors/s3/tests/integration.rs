//! Integration tests for the S3 connector.
//!
//! Covers error taxonomy mapping, credential redaction, client operations
//! (put, get, delete, head, list, copy, presigned), and connector-level invoke.

use std::time::Duration;

use chrono::Utc;
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_prelude::{
    ApprovalScope, ApprovalToken, CapabilityConstraints, CapabilityToken, ExecutionScope, FcpError,
    ZoneId,
};
use fcp_s3::{client::S3Client, connector::S3Connector, error::S3Error};
use serde_json::json;
use wiremock::matchers::{body_bytes, header, header_exists, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ── Helpers ──────────────────────────────────────────────────────────

macro_rules! invoke_request {
    ($($json:tt)*) => {{
        let mut request = json!($($json)*);
        request["type"] = json!("invoke");
        request["id"] = json!("integration-request");
        request["connector_id"] = json!("fcp.s3");
        request["zone_id"] = json!("z:work");
        request
    }};
}

fn capability_for(op: &str) -> &str {
    match op {
        "s3.put_object" | "s3.create_bucket" | "s3.copy_object" | "s3.write" => "s3.write",
        "s3.delete_object" | "s3.delete_bucket" | "s3.delete" => "s3.delete",
        _ => "s3.read",
    }
}

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    op: &str,
    instance_id: &str,
) -> CapabilityToken {
    generate_scoped_token(
        signing_key,
        op,
        instance_id,
        CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        },
    )
}

fn generate_scoped_token(
    signing_key: &Ed25519SigningKey,
    op: &str,
    instance_id: &str,
    constraints: CapabilityConstraints,
) -> CapabilityToken {
    let now = Utc::now();
    let token_id = fcp_prelude::InstanceId::new();
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .token_id(token_id.as_str().as_bytes())
        .capability_id(capability_for(op))
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[op])
        .issuer("node:test")
        .validity(now, now + chrono::Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .unwrap()
        .target_instance(instance_id)
        .sign(signing_key)
        .unwrap();
    CapabilityToken::from_raw(cose)
}

fn generate_execution_approval(method_pattern: &str) -> ApprovalToken {
    let now_ms = u64::try_from(Utc::now().timestamp_millis()).unwrap_or(0);
    ApprovalToken::approved(
        format!("approval-{method_pattern}"),
        now_ms.saturating_sub(1_000),
        now_ms + 60_000,
        "approver:test",
        ApprovalScope::Execution(ExecutionScope {
            connector_id: "fcp.s3".into(),
            method_pattern: method_pattern.into(),
            request_object_id: None,
            input_hash: None,
            input_constraints: Vec::new(),
        }),
        ZoneId::work(),
        None,
    )
}

async fn setup_handshake(
    connector: &mut S3Connector,
    signing_key: &Ed25519SigningKey,
    capabilities: &[&str],
) {
    let verifying_key = signing_key.verifying_key();
    let capabilities: Vec<_> = capabilities.iter().map(|op| capability_for(op)).collect();
    connector
        .handle_handshake(json!({
            "protocol_version": "2.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": capabilities
        }))
        .await
        .unwrap();
}

async fn setup_configure(connector: &mut S3Connector, api_url: &str) {
    connector
        .handle_configure(json!({
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "region": "us-east-1",
            "base_url": api_url
        }))
        .await
        .unwrap();
}

fn make_client(server_uri: &str) -> S3Client {
    S3Client::new(
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "us-east-1",
    )
    .unwrap()
    .with_base_url(server_uri)
    .unwrap()
}

// ── Error taxonomy ──────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn error_http_maps_to_external() {
    let err = S3Error::Http(
        reqwest::Client::new()
            .get("http://[::ffff:0.0.0.0]:1")
            .send()
            .await
            .unwrap_err(),
    );
    let fcp = err.to_fcp_error();
    assert!(matches!(fcp, FcpError::External { service, .. } if service == "s3"));
    assert!(err.is_retryable());
}

#[fcp_async_core::runtime::test]
async fn error_json_maps_to_internal() {
    let bad: Result<serde_json::Value, _> = serde_json::from_str("not json");
    let err = S3Error::Json(bad.unwrap_err());
    let fcp = err.to_fcp_error();
    assert!(matches!(fcp, FcpError::Internal { .. }));
    assert!(!err.is_retryable());
}

#[fcp_async_core::runtime::test]
async fn error_api_auth_maps_to_unauthorized() {
    let err = S3Error::Api {
        code: "AccessDenied".into(),
        message: "Access Denied".into(),
        status_code: Some(403),
    };
    let fcp = err.to_fcp_error();
    assert!(matches!(fcp, FcpError::Unauthorized { .. }));
}

#[fcp_async_core::runtime::test]
async fn error_api_not_found_maps_to_resource_not_found() {
    let err = S3Error::Api {
        code: "NoSuchKey".into(),
        message: "The specified key does not exist".into(),
        status_code: Some(404),
    };
    let fcp = err.to_fcp_error();
    assert!(matches!(fcp, FcpError::ResourceNotFound { .. }));
}

#[fcp_async_core::runtime::test]
async fn error_api_rate_limited_maps_to_fcp() {
    let err = S3Error::Api {
        code: "SlowDown".into(),
        message: "Slow down".into(),
        status_code: Some(429),
    };
    let fcp = err.to_fcp_error();
    assert!(matches!(fcp, FcpError::RateLimited { .. }));
    assert!(err.is_retryable());
}

#[fcp_async_core::runtime::test]
async fn error_api_server_error_is_retryable() {
    let err = S3Error::Api {
        code: "InternalError".into(),
        message: "Internal error".into(),
        status_code: Some(500),
    };
    assert!(err.is_retryable());
    let fcp = err.to_fcp_error();
    assert!(matches!(fcp, FcpError::External { retryable, .. } if retryable));
}

#[fcp_async_core::runtime::test]
async fn error_rate_limited_maps_to_fcp_rate_limited() {
    let err = S3Error::RateLimited {
        retry_after_ms: 5000,
    };
    let fcp = err.to_fcp_error();
    assert!(matches!(
        fcp,
        FcpError::RateLimited {
            retry_after_ms: 5000,
            ..
        }
    ));
    assert!(err.is_retryable());
    assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
}

#[fcp_async_core::runtime::test]
async fn error_unauthorized_maps_to_fcp_unauthorized() {
    let err = S3Error::Unauthorized;
    let fcp = err.to_fcp_error();
    assert!(matches!(fcp, FcpError::Unauthorized { .. }));
    assert!(!err.is_retryable());
}

#[fcp_async_core::runtime::test]
async fn error_not_found_variants_map_to_resource_not_found() {
    let obj_err = S3Error::NotFound {
        key: "docs/readme.md".into(),
    };
    assert!(
        matches!(obj_err.to_fcp_error(), FcpError::ResourceNotFound { resource } if resource.contains("docs/readme.md"))
    );

    let bucket_err = S3Error::BucketNotFound {
        bucket: "my-bucket".into(),
    };
    assert!(
        matches!(bucket_err.to_fcp_error(), FcpError::ResourceNotFound { resource } if resource.contains("my-bucket"))
    );
}

// ── Redaction ───────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn error_display_does_not_leak_credentials() {
    let err = S3Error::Unauthorized;
    let msg = err.to_string();
    assert!(!msg.contains("AKIAIOSFODNN7EXAMPLE"));
    assert!(!msg.contains("wJalrXUtnFEMI"));
}

#[fcp_async_core::runtime::test]
async fn api_error_display_does_not_leak_credentials() {
    let err = S3Error::Api {
        code: "AccessDenied".into(),
        message: "Access Denied".into(),
        status_code: Some(403),
    };
    let msg = err.to_string();
    assert!(!msg.contains("AKIAIOSFODNN7EXAMPLE"));
}

// ── Client operations ───────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn client_put_object() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/my-bucket/test-key.txt"))
        .and(body_bytes(b"hello world".to_vec()))
        .and(header_exists("authorization"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("etag", "\"d41d8cd98f00b204e9800998ecf8427e\""),
        )
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let result = client
        .put_object(
            "my-bucket",
            "test-key.txt",
            b"hello world",
            Some("text/plain"),
        )
        .await
        .unwrap();
    assert!(!result.etag.is_empty());
}

#[fcp_async_core::runtime::test]
async fn client_get_object() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/my-bucket/test-key.txt"))
        .respond_with(ResponseTemplate::new(200).set_body_raw("hello world", "text/plain"))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let result = client
        .get_object("my-bucket", "test-key.txt")
        .await
        .unwrap();
    assert_eq!(result.content_type, "text/plain");
    assert_eq!(result.body, "hello world");
    assert_eq!(result.body_encoding, "utf8");
}

#[fcp_async_core::runtime::test]
async fn client_delete_object() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/my-bucket/test-key.txt"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let result = client
        .delete_object("my-bucket", "test-key.txt")
        .await
        .unwrap();
    assert!(result);
}

#[fcp_async_core::runtime::test]
async fn client_create_bucket() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/test-bucket"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let result = client.create_bucket("test-bucket").await.unwrap();

    assert_eq!(result.bucket, "test-bucket");
    assert!(result.created);
}

#[fcp_async_core::runtime::test]
async fn client_delete_bucket() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/test-bucket"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let result = client.delete_bucket("test-bucket").await.unwrap();

    assert_eq!(result.bucket, "test-bucket");
    assert!(result.deleted);
}

#[fcp_async_core::runtime::test]
async fn client_copy_object() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/dest-bucket/copy.txt"))
        .and(header("x-amz-copy-source", "/src-bucket/original.txt"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            "<CopyObjectResult><ETag>&quot;copied-etag&quot;</ETag></CopyObjectResult>",
            "application/xml",
        ))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let result = client
        .copy_object("src-bucket", "original.txt", "dest-bucket", "copy.txt")
        .await
        .unwrap();
    assert_eq!(result.etag, "\"copied-etag\"");
}

#[fcp_async_core::runtime::test]
async fn client_head_object_reads_headers_without_a_body() {
    let server = MockServer::start().await;
    Mock::given(method("HEAD"))
        .and(path("/my-bucket/test-key.txt"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/octet-stream")
                .insert_header("content-length", "314159")
                .insert_header("etag", "\"metadata-etag\""),
        )
        .mount(&server)
        .await;
    let result = make_client(&server.uri())
        .head_object("my-bucket", "test-key.txt")
        .await
        .unwrap();
    assert_eq!(result.content_type, "application/octet-stream");
    assert_eq!(result.content_length, 314159);
    assert_eq!(result.etag.as_deref(), Some("\"metadata-etag\""));
}

#[fcp_async_core::runtime::test]
async fn client_list_objects() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/my-bucket"))
        .and(query_param("list-type", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>my-bucket</Name><IsTruncated>false</IsTruncated><Contents><Key>file1.txt</Key><Size>100</Size></Contents><Contents><Key>file2.txt</Key><Size>200</Size></Contents></ListBucketResult>", "application/xml"))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let result = client
        .list_objects("my-bucket", None, None, None)
        .await
        .unwrap();
    assert_eq!(result.contents.len(), 2);
    assert!(!result.is_truncated);
}

#[fcp_async_core::runtime::test]
async fn client_list_buckets() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            "<ListAllMyBucketsResult><Buckets><Bucket><Name>bucket-a</Name><CreationDate>2025-01-01T00:00:00Z</CreationDate></Bucket><Bucket><Name>bucket-b</Name></Bucket></Buckets></ListAllMyBucketsResult>", "application/xml"))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let result = client.list_buckets().await.unwrap();
    assert_eq!(result.buckets.len(), 2);
    assert_eq!(result.buckets[0].name, "bucket-a");
}

#[fcp_async_core::runtime::test]
async fn client_unauthorized_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/my-bucket/key.txt"))
        .respond_with(ResponseTemplate::new(403).set_body_raw(
            "<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>",
            "application/xml",
        ))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let result = client.get_object("my-bucket", "key.txt").await;
    assert!(matches!(result.unwrap_err(), S3Error::Unauthorized));
}

#[fcp_async_core::runtime::test]
async fn client_not_found_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/test-bucket/missing-key"))
        .respond_with(ResponseTemplate::new(404).set_body_raw(
            "<Error><Code>NoSuchKey</Code><Message>missing-key</Message></Error>",
            "application/xml",
        ))
        .mount(&server)
        .await;

    let client = make_client(&server.uri()).with_retry_config(1, 10, 100);
    let result = client.get_object("test-bucket", "missing-key").await;

    assert!(matches!(result.unwrap_err(), S3Error::NotFound { .. }));
}

#[fcp_async_core::runtime::test]
async fn client_rate_limited_no_retry() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/my-bucket/key.txt"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "10"))
        .mount(&server)
        .await;

    let client = make_client(&server.uri()).with_retry_config(0, 100, 100);
    let result = client.get_object("my-bucket", "key.txt").await;
    assert!(matches!(result.unwrap_err(), S3Error::RateLimited { .. }));
}

// ── Connector-level invoke ──────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn invoke_put_object_through_connector() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/my-bucket/hello.txt"))
        .respond_with(ResponseTemplate::new(200).insert_header("etag", "\"abc123\""))
        .mount(&server)
        .await;

    let mut connector = S3Connector::new();
    let signing_key = Ed25519SigningKey::generate();

    setup_configure(&mut connector, &server.uri()).await;
    setup_handshake(&mut connector, &signing_key, &["s3.put_object"]).await;

    let token = generate_valid_token(
        &signing_key,
        "s3.put_object",
        connector.instance_id().as_str(),
    );
    let result = connector
        .handle_invoke(invoke_request!({
            "operation": "s3.put_object",
            "input": {
                "bucket": "my-bucket",
                "key": "hello.txt",
                "body": "hello world"
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["type"], "response");
    assert_eq!(result["id"], "integration-request");
    assert_eq!(result["resource_uris"], json!(["s3://my-bucket/hello.txt"]));
    assert_eq!(result["result"]["etag"], "\"abc123\"");
}

#[fcp_async_core::runtime::test]
async fn invoke_list_buckets_through_connector() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            "<ListAllMyBucketsResult><Buckets><Bucket><Name>test-bucket</Name></Bucket></Buckets></ListAllMyBucketsResult>", "application/xml"))
        .mount(&server)
        .await;

    let mut connector = S3Connector::new();
    let signing_key = Ed25519SigningKey::generate();

    setup_configure(&mut connector, &server.uri()).await;
    setup_handshake(&mut connector, &signing_key, &["s3.list_buckets"]).await;

    let token = generate_valid_token(
        &signing_key,
        "s3.list_buckets",
        connector.instance_id().as_str(),
    );
    let result = connector
        .handle_invoke(invoke_request!({
            "operation": "s3.list_buckets",
            "input": {},
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["result"]["buckets"][0]["name"], "test-bucket");
    assert_eq!(result["resource_uris"], json!(["s3://"]));
}

#[fcp_async_core::runtime::test]
async fn invoke_wrong_capability_rejected() {
    let mut connector = S3Connector::new();
    let signing_key = Ed25519SigningKey::generate();

    setup_configure(&mut connector, "http://localhost:1").await;
    setup_handshake(&mut connector, &signing_key, &["s3.read"]).await;

    let token = generate_valid_token(&signing_key, "s3.read", connector.instance_id().as_str());
    let result = connector
        .handle_invoke(invoke_request!({
            "operation": "s3.put_object",
            "input": {
                "bucket": "bucket",
                "key": "k",
                "body": "x"
            },
            "capability_token": token
        }))
        .await;

    assert!(matches!(result, Err(FcpError::CapabilityDenied { .. })));
}

#[fcp_async_core::runtime::test]
async fn invoke_unknown_operation_rejected() {
    let mut connector = S3Connector::new();
    let signing_key = Ed25519SigningKey::generate();

    setup_configure(&mut connector, "http://localhost:1").await;
    setup_handshake(&mut connector, &signing_key, &["s3.nonexistent"]).await;

    let token = generate_valid_token(
        &signing_key,
        "s3.nonexistent",
        connector.instance_id().as_str(),
    );
    let result = connector
        .handle_invoke(invoke_request!({
            "operation": "s3.nonexistent",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        FcpError::OperationNotGranted { .. }
    ));
}

#[fcp_async_core::runtime::test]
async fn invoke_missing_required_field_rejected() {
    let server = MockServer::start().await;

    let mut connector = S3Connector::new();
    let signing_key = Ed25519SigningKey::generate();

    setup_configure(&mut connector, &server.uri()).await;
    setup_handshake(&mut connector, &signing_key, &["s3.put_object"]).await;

    let token = generate_valid_token(
        &signing_key,
        "s3.put_object",
        connector.instance_id().as_str(),
    );
    // Missing key and body
    let result = connector
        .handle_invoke(invoke_request!({
            "operation": "s3.put_object",
            "input": { "bucket": "my-bucket" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        FcpError::InvalidRequest { .. } => {}
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn invoke_get_object_through_connector() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/my-bucket/data.json"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(r#"{"key":"value"}"#, "application/json"),
        )
        .mount(&server)
        .await;

    let mut connector = S3Connector::new();
    let signing_key = Ed25519SigningKey::generate();

    setup_configure(&mut connector, &server.uri()).await;
    setup_handshake(&mut connector, &signing_key, &["s3.get_object"]).await;

    let token = generate_valid_token(
        &signing_key,
        "s3.get_object",
        connector.instance_id().as_str(),
    );
    let result = connector
        .handle_invoke(invoke_request!({
            "operation": "s3.get_object",
            "input": {
                "bucket": "my-bucket",
                "key": "data.json"
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["result"]["content_type"], "application/json");
    assert_eq!(result["result"]["body"], r#"{"key":"value"}"#);
    assert_eq!(result["result"]["body_encoding"], "utf8");
}

#[fcp_async_core::runtime::test]
async fn invoke_delete_object_through_connector() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/my-bucket/old-file.txt"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let mut connector = S3Connector::new();
    let signing_key = Ed25519SigningKey::generate();

    setup_configure(&mut connector, &server.uri()).await;
    setup_handshake(&mut connector, &signing_key, &["s3.delete_object"]).await;

    let token = generate_valid_token(
        &signing_key,
        "s3.delete_object",
        connector.instance_id().as_str(),
    );
    let approval = generate_execution_approval("s3.delete_object");
    let result = connector
        .handle_invoke(invoke_request!({
            "operation": "s3.delete_object",
            "input": {
                "bucket": "my-bucket",
                "key": "old-file.txt"
            },
            "capability_token": token,
            "approval_tokens": [approval],
        }))
        .await
        .unwrap();

    assert_eq!(result["result"]["deleted"], true);
    assert_eq!(result["result"]["audit"]["operation"], "s3.delete_object");
    assert_eq!(result["result"]["audit"]["dangerous"], true);
    assert_eq!(result["result"]["audit"]["approval_authority"], "host");
}

#[fcp_async_core::runtime::test]
async fn invoke_create_bucket_through_connector() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/new-bucket"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let mut connector = S3Connector::new();
    let signing_key = Ed25519SigningKey::generate();

    setup_configure(&mut connector, &server.uri()).await;
    setup_handshake(&mut connector, &signing_key, &["s3.create_bucket"]).await;

    let token = generate_valid_token(
        &signing_key,
        "s3.create_bucket",
        connector.instance_id().as_str(),
    );
    let approval = generate_execution_approval("s3.create_bucket");
    let result = connector
        .handle_invoke(invoke_request!({
            "operation": "s3.create_bucket",
            "input": {
                "bucket": "new-bucket"
            },
            "capability_token": token,
            "approval_tokens": [approval],
        }))
        .await
        .unwrap();

    assert_eq!(result["result"]["bucket"], "new-bucket");
    assert_eq!(result["result"]["created"], true);
    assert_eq!(result["result"]["audit"]["operation"], "s3.create_bucket");
}

#[fcp_async_core::runtime::test]
async fn invoke_delete_bucket_through_connector() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/old-bucket"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let mut connector = S3Connector::new();
    let signing_key = Ed25519SigningKey::generate();

    setup_configure(&mut connector, &server.uri()).await;
    setup_handshake(&mut connector, &signing_key, &["s3.delete_bucket"]).await;

    let token = generate_valid_token(
        &signing_key,
        "s3.delete_bucket",
        connector.instance_id().as_str(),
    );
    let approval = generate_execution_approval("s3.delete_bucket");
    let result = connector
        .handle_invoke(invoke_request!({
            "operation": "s3.delete_bucket",
            "input": {
                "bucket": "old-bucket"
            },
            "capability_token": token,
            "approval_tokens": [approval],
        }))
        .await
        .unwrap();

    assert_eq!(result["result"]["bucket"], "old-bucket");
    assert_eq!(result["result"]["deleted"], true);
    assert_eq!(result["result"]["audit"]["operation"], "s3.delete_bucket");
}

#[fcp_async_core::runtime::test]
async fn invoke_head_object_missing_field() {
    let server = MockServer::start().await;

    let mut connector = S3Connector::new();
    let signing_key = Ed25519SigningKey::generate();

    setup_configure(&mut connector, &server.uri()).await;
    setup_handshake(&mut connector, &signing_key, &["s3.head_object"]).await;

    let token = generate_valid_token(
        &signing_key,
        "s3.head_object",
        connector.instance_id().as_str(),
    );
    let result = connector
        .handle_invoke(invoke_request!({
            "operation": "s3.head_object",
            "input": { "bucket": "my-bucket" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        FcpError::InvalidRequest { .. } => {}
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn invoke_list_objects_through_connector() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/my-bucket"))
        .and(query_param("prefix", "logs/"))
        .and(query_param("max-keys", "10"))
        .and(query_param("continuation-token", "opaque+/=cursor"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            "<ListBucketResult><Name>my-bucket</Name><IsTruncated>true</IsTruncated><NextContinuationToken>next+/=page</NextContinuationToken><Contents><Key>logs/app.log</Key><Size>500</Size></Contents><Contents><Key>logs/error.log</Key><Size>200</Size></Contents></ListBucketResult>", "application/xml"))
        .mount(&server)
        .await;

    let mut connector = S3Connector::new();
    let signing_key = Ed25519SigningKey::generate();

    setup_configure(&mut connector, &server.uri()).await;
    setup_handshake(&mut connector, &signing_key, &["s3.list_objects"]).await;

    let token = generate_valid_token(
        &signing_key,
        "s3.list_objects",
        connector.instance_id().as_str(),
    );
    let result = connector
        .handle_invoke(invoke_request!({
            "operation": "s3.list_objects",
            "input": {
                "bucket": "my-bucket",
                "prefix": "logs/",
                "max_keys": 10,
                "continuation_token": "opaque+/=cursor"
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["result"]["contents"].as_array().unwrap().len(), 2);
    assert_eq!(result["result"]["is_truncated"], true);
    assert_eq!(result["result"]["next_continuation_token"], "next+/=page");
    assert_eq!(result["next_cursor"], "next+/=page");
    assert_eq!(result["resource_uris"], json!(["s3://my-bucket"]));
}

#[fcp_async_core::runtime::test]
async fn invoke_copy_object_through_connector() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/dest-bucket/backup.txt"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            "<CopyObjectResult><ETag>&quot;copy-etag&quot;</ETag></CopyObjectResult>",
            "application/xml",
        ))
        .mount(&server)
        .await;

    let mut connector = S3Connector::new();
    let signing_key = Ed25519SigningKey::generate();

    setup_configure(&mut connector, &server.uri()).await;
    setup_handshake(&mut connector, &signing_key, &["s3.copy_object"]).await;

    let token = generate_valid_token(
        &signing_key,
        "s3.copy_object",
        connector.instance_id().as_str(),
    );
    let result = connector
        .handle_invoke(invoke_request!({
            "operation": "s3.copy_object",
            "input": {
                "source_bucket": "src-bucket",
                "source_key": "original.txt",
                "dest_bucket": "dest-bucket",
                "dest_key": "backup.txt"
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["result"]["etag"], "\"copy-etag\"");
    assert_eq!(
        result["resource_uris"],
        json!([
            "s3://src-bucket/original.txt",
            "s3://dest-bucket/backup.txt"
        ])
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_generate_presigned_url_through_connector() {
    let server = MockServer::start().await;

    let mut connector = S3Connector::new();
    let signing_key = Ed25519SigningKey::generate();

    setup_configure(&mut connector, &server.uri()).await;
    setup_handshake(&mut connector, &signing_key, &["s3.generate_presigned_url"]).await;

    let token = generate_valid_token(
        &signing_key,
        "s3.generate_presigned_url",
        connector.instance_id().as_str(),
    );
    let approval = generate_execution_approval("s3.generate_presigned_url");
    let result = connector
        .handle_invoke(invoke_request!({
            "operation": "s3.generate_presigned_url",
            "input": {
                "bucket": "my-bucket",
                "key": "report.pdf",
                "expires_in": 7200
            },
            "capability_token": token,
            "approval_tokens": [approval],
        }))
        .await
        .unwrap();

    let url = result["result"]["url"].as_str().unwrap();
    assert!(url.contains("my-bucket"));
    assert!(url.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"));
    assert!(url.contains("X-Amz-Credential="));
    assert!(url.contains("X-Amz-Date="));
    assert!(url.contains("X-Amz-Expires=7200"));
    assert!(url.contains("X-Amz-Signature="));
    assert!(url.contains("X-Amz-SignedHeaders=host"));
    assert!(!url.contains("PLACEHOLDER_SIGNATURE"));
    assert_eq!(
        result["result"]["audit"]["operation"],
        "s3.generate_presigned_url"
    );
    assert_eq!(result["result"]["audit"]["dangerous"], true);
}

#[fcp_async_core::runtime::test]
async fn credential_reference_never_produces_an_unsigned_url() {
    let server = MockServer::start().await;

    let mut connector = S3Connector::new();
    let signing_key = Ed25519SigningKey::generate();

    let configured = connector
        .handle_configure(json!({
            "credential_id": "00000000-0000-0000-0000-000000000001",
            "base_url": server.uri()
        }))
        .await;
    assert!(matches!(configured, Err(FcpError::InvalidRequest { .. })));

    let token = generate_valid_token(
        &signing_key,
        "s3.generate_presigned_url",
        connector.instance_id().as_str(),
    );
    let result = connector
        .handle_invoke(invoke_request!({
            "operation": "s3.generate_presigned_url",
            "input": {
                "bucket": "my-bucket",
                "key": "report.pdf",
                "expires_in": 7200
            },
            "capability_token": token,
        }))
        .await;
    assert!(matches!(result, Err(FcpError::NotConfigured)));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn unsigned_approval_metadata_cannot_replace_signed_authority() {
    let server = MockServer::start().await;
    let mut connector = S3Connector::new();
    let signing_key = Ed25519SigningKey::generate();

    setup_configure(&mut connector, &server.uri()).await;
    setup_handshake(&mut connector, &signing_key, &["s3.delete_object"]).await;

    let token = generate_valid_token(
        &Ed25519SigningKey::generate(),
        "s3.delete_object",
        connector.instance_id().as_str(),
    );
    let result = connector
        .handle_invoke(invoke_request!({
            "operation": "s3.delete_object",
            "input": {
                "bucket": "my-bucket",
                "key": "old-file.txt"
            },
            "capability_token": token,
            "approval_tokens": [generate_execution_approval("s3.delete_object")]
        }))
        .await;

    assert!(result.is_err());
    assert!(server.received_requests().await.unwrap().is_empty());
}

// ── Risk level verification ─────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn introspect_risk_levels() {
    let connector = S3Connector::new();
    let result = connector.handle_introspect().await.unwrap();
    let ops = result["operations"].as_array().unwrap();

    for op in ops {
        let id = op["id"].as_str().unwrap();
        let risk = op["risk_level"].as_str().unwrap();
        match id {
            "s3.get_object" | "s3.head_object" | "s3.list_objects" | "s3.list_buckets" => {
                assert_eq!(risk, "low", "Read op {id} should be low risk");
            }
            "s3.put_object" | "s3.copy_object" => {
                assert_eq!(risk, "medium", "Write op {id} should be medium risk");
            }
            "s3.delete_object"
            | "s3.create_bucket"
            | "s3.delete_bucket"
            | "s3.generate_presigned_url" => {
                assert_eq!(risk, "high", "Delete op {id} should be high risk");
            }
            _ => panic!("Unknown operation: {id}"),
        }
    }
}

// ── Copy object missing field ───────────────────────────────────

#[fcp_async_core::runtime::test]
async fn invoke_copy_object_missing_field() {
    let server = MockServer::start().await;

    let mut connector = S3Connector::new();
    let signing_key = Ed25519SigningKey::generate();

    setup_configure(&mut connector, &server.uri()).await;
    setup_handshake(&mut connector, &signing_key, &["s3.copy_object"]).await;

    let token = generate_valid_token(
        &signing_key,
        "s3.copy_object",
        connector.instance_id().as_str(),
    );
    // Missing dest_key
    let result = connector
        .handle_invoke(invoke_request!({
            "operation": "s3.copy_object",
            "input": {
                "source_bucket": "src",
                "source_key": "a.txt",
                "dest_bucket": "dst"
            },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        FcpError::InvalidRequest { .. } => {}
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn binary_objects_round_trip_as_bytes_with_explicit_encoding() {
    let server = MockServer::start().await;
    let bytes = vec![0, 255, 128, 10];
    Mock::given(method("PUT"))
        .and(path("/my-bucket/binary.bin"))
        .and(body_bytes(bytes.clone()))
        .and(header("content-type", "application/octet-stream"))
        .respond_with(ResponseTemplate::new(200).insert_header("etag", "\"binary-etag\""))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/my-bucket/binary.bin"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(bytes, "application/octet-stream"))
        .expect(1)
        .mount(&server)
        .await;
    let mut connector = S3Connector::new();
    let key = Ed25519SigningKey::generate();
    setup_configure(&mut connector, &server.uri()).await;
    setup_handshake(&mut connector, &key, &["s3.write", "s3.read"]).await;
    let put = connector.handle_invoke(invoke_request!({
        "operation": "s3.put_object",
        "input": {"bucket":"my-bucket", "key":"binary.bin", "body":"AP+ACg==", "body_encoding":"base64", "content_type":"application/octet-stream"},
        "capability_token": generate_valid_token(&key, "s3.put_object", connector.instance_id().as_str()),
    })).await.unwrap();
    assert_eq!(put["result"]["etag"], "\"binary-etag\"");
    let get = connector.handle_invoke(invoke_request!({
        "operation": "s3.get_object", "input": {"bucket":"my-bucket", "key":"binary.bin"},
        "capability_token": generate_valid_token(&key, "s3.get_object", connector.instance_id().as_str()),
    })).await.unwrap();
    assert_eq!(get["result"]["body"], "AP+ACg==");
    assert_eq!(get["result"]["body_encoding"], "base64");
    assert_eq!(get["result"]["content_type"], "application/octet-stream");
}

#[fcp_async_core::runtime::test]
async fn copy_requires_both_exact_source_and_destination_resource_authority() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/dest-bucket/copy.txt"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            "<CopyObjectResult><ETag>&quot;copied&quot;</ETag></CopyObjectResult>",
            "application/xml",
        ))
        .expect(1)
        .mount(&server)
        .await;
    let mut connector = S3Connector::new();
    let key = Ed25519SigningKey::generate();
    setup_configure(&mut connector, &server.uri()).await;
    setup_handshake(&mut connector, &key, &["s3.write"]).await;
    let source = "s3://src-bucket/original.txt";
    let destination = "s3://dest-bucket/copy.txt";
    for resources in [vec![source], vec![destination], vec![source, destination]] {
        let both = resources.len() == 2;
        let token = generate_scoped_token(
            &key,
            "s3.copy_object",
            connector.instance_id().as_str(),
            CapabilityConstraints {
                resource_allow: resources.into_iter().map(str::to_owned).collect(),
                ..Default::default()
            },
        );
        let result = connector.handle_invoke(invoke_request!({
            "operation":"s3.copy_object",
            "input":{"source_bucket":"src-bucket", "source_key":"original.txt", "dest_bucket":"dest-bucket", "dest_key":"copy.txt"},
            "capability_token":token,
        })).await;
        assert_eq!(result.is_ok(), both);
        if !both {
            assert!(server.received_requests().await.unwrap().is_empty());
        }
    }
}

#[fcp_async_core::runtime::test]
async fn rejected_input_does_not_spend_signed_call_allowance() {
    let mut connector = S3Connector::new();
    let key = Ed25519SigningKey::generate();
    setup_configure(&mut connector, "http://localhost:1").await;
    setup_handshake(&mut connector, &key, &["s3.read"]).await;
    let token = generate_scoped_token(
        &key,
        "s3.generate_presigned_url",
        connector.instance_id().as_str(),
        CapabilityConstraints {
            resource_allow: vec!["s3://my-bucket/report.pdf".into()],
            max_calls: Some(1),
            ..Default::default()
        },
    );
    for invalid in [
        json!({"bucket":"my-bucket", "key":"report.pdf", "expires_in":0}),
        json!({"bucket":"my-bucket", "key":"report.pdf", "expires_in":604801}),
        json!({"bucket":"my-bucket", "key":"report.pdf", "unrecognized":true}),
        json!({"bucket":"my-bucket", "key":"../report.pdf"}),
    ] {
        let result = connector.handle_invoke(invoke_request!({
            "operation":"s3.generate_presigned_url", "input":invalid, "capability_token":token.clone(),
        })).await;
        assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
    }
    let request = invoke_request!({
        "operation":"s3.generate_presigned_url", "input":{"bucket":"my-bucket", "key":"report.pdf"},
        "capability_token":token,
    });
    assert!(connector.handle_invoke(request.clone()).await.is_ok());
    assert!(connector.handle_invoke(request).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn signed_byte_ceiling_rejects_before_provider_io() {
    let server = MockServer::start().await;
    let mut connector = S3Connector::new();
    let key = Ed25519SigningKey::generate();
    setup_configure(&mut connector, &server.uri()).await;
    setup_handshake(&mut connector, &key, &["s3.read"]).await;
    let token = generate_scoped_token(
        &key,
        "s3.get_object",
        connector.instance_id().as_str(),
        CapabilityConstraints {
            resource_allow: vec!["s3://my-bucket/file.txt".into()],
            max_bytes: Some(1),
            ..Default::default()
        },
    );
    let error = connector.handle_invoke(invoke_request!({
        "operation":"s3.get_object", "input":{"bucket":"my-bucket", "key":"file.txt"}, "capability_token":token,
    })).await.unwrap_err();
    assert!(
        matches!(error, FcpError::CapabilityDenied { reason, .. } if reason.contains("byte budget"))
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn deadline_cancels_pending_io_without_refunding_the_signed_call() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/my-bucket/slow.txt"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw("late", "text/plain")
                .set_delay(Duration::from_secs(1)),
        )
        .mount(&server)
        .await;
    let mut connector = S3Connector::new();
    let key = Ed25519SigningKey::generate();
    setup_configure(&mut connector, &server.uri()).await;
    setup_handshake(&mut connector, &key, &["s3.read"]).await;
    let token = generate_scoped_token(
        &key,
        "s3.get_object",
        connector.instance_id().as_str(),
        CapabilityConstraints {
            resource_allow: vec!["s3://my-bucket/slow.txt".into()],
            max_calls: Some(1),
            ..Default::default()
        },
    );
    let request = invoke_request!({
        "operation":"s3.get_object", "input":{"bucket":"my-bucket", "key":"slow.txt"},
        "capability_token":token, "deadline_ms":20,
    });
    let start = std::time::Instant::now();
    let result = connector.handle_invoke(request.clone()).await;
    assert!(matches!(
        result,
        Err(FcpError::External {
            retryable: false,
            ..
        })
    ));
    assert!(start.elapsed() < Duration::from_secs(1));
    assert!(connector.handle_invoke(request).await.is_err());
    assert!(server.received_requests().await.unwrap().len() <= 1);
}
