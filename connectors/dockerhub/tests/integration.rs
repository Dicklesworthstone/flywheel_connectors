//! Connector-local no-mock Docker Hub integration proof.
//!
//! These tests exercise the real Docker Hub client against a local HTTP server.
//! No live Docker Hub service is called.

#![allow(
    clippy::missing_errors_doc,
    clippy::too_many_lines,
    clippy::unreadable_literal
)]

use std::sync::Once;
use std::time::Duration;

use fcp_dockerhub::client::DockerHubClient;
use fcp_dockerhub::connector::DockerHubConnector;
use fcp_dockerhub::error::DockerHubError;
use fcp_dockerhub::types::{CreateRepositoryRequest, DockerHubAuth, LoginRequest, LoginResponse};
use fcp_prelude::{ApprovalMode, FcpConnector, IdempotencyClass, RiskLevel, SafetyTier};
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use serde_json::{Value, json};
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_TOKEN: &str = "dockerhub-token-for-tests";
const AUTH_HEADER: &str = "Bearer dockerhub-token-for-tests";
const EXPECTED_MANIFEST_SCHEMA_OPS: [&str; 9] = [
    "repos_list",
    "repos_get",
    "repos_create",
    "repos_delete",
    "tags_list",
    "tags_get",
    "tags_delete",
    "orgs_list",
    "health",
];

static LOG_INIT: Once = Once::new();

fn init_logging() {
    LOG_INIT.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("debug")),
            )
            .json()
            .with_test_writer()
            .try_init();
    });
}

fn no_retry_config() -> HttpRetryConfig {
    HttpRetryConfig {
        max_retries: 0,
        initial_delay_ms: 1,
        max_delay_ms: 1,
        jitter_enabled: false,
    }
}

fn test_runtime() -> ConnectorRuntime {
    ConnectorRuntime::new(
        ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_millis(500)),
    )
}

fn dockerhub_manifest() -> toml::Value {
    toml::from_str(include_str!("../manifest.toml")).expect("Docker Hub manifest TOML should parse")
}

fn manifest_operations(manifest: &toml::Value) -> &toml::map::Map<String, toml::Value> {
    manifest
        .get("provides")
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .expect("manifest should declare operation tables")
}

fn operation_schema(manifest: &toml::Value, operation_id: &str, field: &str) -> Value {
    let schema = manifest_operations(manifest)
        .get(operation_id)
        .and_then(toml::Value::as_table)
        .and_then(|operation| operation.get(field))
        .expect("operation should declare schema field");
    assert!(
        schema.as_table().is_some_and(|table| !table.is_empty()),
        "{operation_id}.{field} should be a non-empty schema table"
    );
    serde_json::to_value(schema).expect("manifest schema table should convert to JSON")
}

fn validator_for(schema: &Value) -> jsonschema::Validator {
    jsonschema::Validator::new(schema).expect("manifest operation schema should compile")
}

fn assert_schema_accepts(schema: &Value, payload: &Value) {
    let validator = validator_for(schema);
    let errors = validator
        .iter_errors(payload)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(
        errors.is_empty(),
        "schema should accept {payload}; errors: {errors:?}"
    );
}

fn assert_schema_rejects(schema: &Value, payload: &Value) {
    let validator = validator_for(schema);
    assert!(
        validator.iter_errors(payload).next().is_some(),
        "schema should reject {payload}"
    );
}

fn client(server: &MockServer) -> DockerHubClient {
    DockerHubClient::new(
        &server.uri(),
        DockerHubAuth::Token {
            access_token: TEST_TOKEN.into(),
        },
        no_retry_config(),
    )
    .expect("wiremock URI should build a Docker Hub client")
}

#[fcp_async_core::runtime::test]
async fn repository_tag_org_and_create_success_paths_use_dockerhub_contracts() {
    init_logging();
    tracing::info!(
        scenario = "dockerhub_success_contracts",
        "starting Docker Hub success-path integration proof",
    );

    let server = MockServer::start().await;
    let runtime = test_runtime();

    Mock::given(method("GET"))
        .and(path("/v2/repositories/acme/"))
        .and(header("authorization", AUTH_HEADER))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "count": 1,
            "next": null,
            "previous": null,
            "results": [{
                "name": "widget",
                "namespace": "acme",
                "description": "primary image",
                "is_private": true,
                "star_count": 7,
                "pull_count": 42
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v2/repositories/acme/widget/"))
        .and(header("authorization", AUTH_HEADER))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "widget",
            "namespace": "acme",
            "description": "primary image",
            "is_private": true,
            "status": 1
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v2/repositories/acme/"))
        .and(header("authorization", AUTH_HEADER))
        .and(body_json(json!({
            "namespace": "acme",
            "name": "created-widget",
            "description": "created by test",
            "is_private": true
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "name": "created-widget",
            "namespace": "acme",
            "description": "created by test",
            "is_private": true
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v2/repositories/acme/widget/tags/"))
        .and(header("authorization", AUTH_HEADER))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "count": 1,
            "next": null,
            "previous": null,
            "results": [{
                "name": "latest",
                "full_size": 7340032,
                "digest": "sha256:abc123",
                "images": [{
                    "architecture": "amd64",
                    "os": "linux",
                    "size": 7340032
                }]
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v2/repositories/acme/widget/tags/latest/"))
        .and(header("authorization", AUTH_HEADER))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "latest",
            "full_size": 7340032,
            "digest": "sha256:abc123",
            "tag_status": "active"
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v2/user/orgs/"))
        .and(header("authorization", AUTH_HEADER))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "count": 1,
            "next": null,
            "previous": null,
            "results": [{
                "id": "org-1",
                "orgname": "acme",
                "full_name": "Acme Engineering"
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = client(&server);

    let repos = client
        .list_repos(&runtime, "acme")
        .await
        .expect("repository list should decode");
    assert_eq!(repos[0].name, "widget");
    assert_eq!(repos[0].namespace, "acme");
    assert_eq!(repos[0].pull_count, Some(42));

    let repo = client
        .get_repo(&runtime, "acme", "widget")
        .await
        .expect("repository details should decode");
    assert_eq!(repo.name, "widget");
    assert_eq!(repo.status, Some(1));

    let created = client
        .create_repo(
            &runtime,
            &CreateRepositoryRequest {
                namespace: "acme".into(),
                name: "created-widget".into(),
                description: Some("created by test".into()),
                is_private: Some(true),
                full_description: None,
            },
        )
        .await
        .expect("repository create should decode");
    assert_eq!(created.name, "created-widget");
    assert_eq!(created.is_private, Some(true));

    let tags = client
        .list_tags(&runtime, "acme", "widget")
        .await
        .expect("tag list should decode");
    assert_eq!(tags[0].name, "latest");
    assert_eq!(tags[0].digest.as_deref(), Some("sha256:abc123"));

    let tag = client
        .get_tag(&runtime, "acme", "widget", "latest")
        .await
        .expect("tag details should decode");
    assert_eq!(tag.tag_status.as_deref(), Some("active"));

    let orgs = client
        .list_orgs(&runtime)
        .await
        .expect("organization list should decode");
    assert_eq!(orgs[0].orgname.as_deref(), Some("acme"));
}

#[fcp_async_core::runtime::test]
async fn destructive_delete_requests_use_expected_delete_shapes() {
    init_logging();
    tracing::info!(
        scenario = "dockerhub_destructive_request_shape",
        "starting Docker Hub destructive request-shape proof",
    );

    let server = MockServer::start().await;
    let runtime = test_runtime();

    Mock::given(method("DELETE"))
        .and(path("/v2/repositories/acme/widget/"))
        .and(header("authorization", AUTH_HEADER))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("DELETE"))
        .and(path("/v2/repositories/acme/widget/tags/old/"))
        .and(header("authorization", AUTH_HEADER))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = client(&server);

    let repo_delete = client
        .delete_repo(&runtime, "acme", "widget")
        .await
        .expect("repository delete response should decode");
    assert!(repo_delete.is_null());

    let tag_delete = client
        .delete_tag(&runtime, "acme", "widget", "old")
        .await
        .expect("tag delete response should decode");
    assert!(tag_delete.is_null());
}

#[fcp_async_core::runtime::test]
async fn auth_missing_resource_rate_limit_and_malformed_json_are_typed() {
    init_logging();
    tracing::info!(
        scenario = "dockerhub_error_taxonomy",
        "starting Docker Hub error-taxonomy proof",
    );

    let server = MockServer::start().await;
    let runtime = test_runtime();

    Mock::given(method("GET"))
        .and(path("/v2/user"))
        .and(header("authorization", AUTH_HEADER))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "detail": "Invalid token"
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v2/repositories/acme/missing/"))
        .and(header("authorization", AUTH_HEADER))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "detail": "Not found"
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v2/repositories/acme/widget/tags/"))
        .and(header("authorization", AUTH_HEADER))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "3")
                .set_body_json(json!({ "detail": "rate limited" })),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v2/repositories/acme/widget/tags/bad-json/"))
        .and(header("authorization", AUTH_HEADER))
        .respond_with(ResponseTemplate::new(200).set_body_string("{this is not json"))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v2/repositories/acme/widget/tags/empty/"))
        .and(header("authorization", AUTH_HEADER))
        .respond_with(ResponseTemplate::new(200).set_body_string(""))
        .mount(&server)
        .await;

    let client = client(&server);

    let unauthorized = client.health_check(&runtime).await.unwrap_err();
    assert!(matches!(unauthorized, DockerHubError::Unauthorized(_)));

    let not_found = client
        .get_repo(&runtime, "acme", "missing")
        .await
        .unwrap_err();
    assert!(matches!(not_found, DockerHubError::NotFound(_)));

    let rate_limited = client
        .list_tags(&runtime, "acme", "widget")
        .await
        .unwrap_err();
    assert!(matches!(
        rate_limited,
        DockerHubError::RateLimited {
            retry_after_ms: 3000
        }
    ));

    let malformed = client
        .get_tag(&runtime, "acme", "widget", "bad-json")
        .await
        .unwrap_err();
    assert!(matches!(malformed, DockerHubError::Json(_)));

    let empty_body = client
        .get_tag(&runtime, "acme", "widget", "empty")
        .await
        .unwrap_err();
    assert!(matches!(
        empty_body,
        DockerHubError::Api {
            status: 200,
            ref message
        } if message == "empty response body"
    ));
    assert!(!empty_body.is_retryable());
}

#[fcp_async_core::runtime::test]
async fn cancelled_runtime_short_circuits_before_network_io() {
    init_logging();
    tracing::info!(
        scenario = "dockerhub_cancellation",
        "starting Docker Hub cancellation proof",
    );

    let server = MockServer::start().await;
    let runtime = test_runtime();
    runtime.shutdown();

    let client = client(&server);
    let err = client
        .get_repo(&runtime, "acme", "widget")
        .await
        .expect_err("cancelled runtime should fail before HTTP is sent");

    assert!(matches!(
        err,
        DockerHubError::Async(message) if message == "operation cancelled"
    ));
}

#[test]
fn operation_catalog_preserves_risk_and_approval_metadata() {
    init_logging();

    let introspection = DockerHubConnector::new().introspect();
    assert!(introspection.events.is_empty());

    let by_id = |id: &str| {
        introspection
            .operations
            .iter()
            .find(|operation| operation.id.as_str() == id)
            .expect("operation metadata should contain requested id")
    };

    let create_repo = by_id("dockerhub.repos.create");
    assert_eq!(create_repo.risk_level, RiskLevel::Medium);
    assert_eq!(create_repo.safety_tier, SafetyTier::Risky);
    assert_eq!(create_repo.idempotency, IdempotencyClass::Strict);
    assert_eq!(create_repo.requires_approval, None);

    let delete_repo = by_id("dockerhub.repos.delete");
    assert_eq!(delete_repo.risk_level, RiskLevel::Critical);
    assert_eq!(delete_repo.safety_tier, SafetyTier::Dangerous);
    assert_eq!(delete_repo.idempotency, IdempotencyClass::Strict);
    assert_eq!(
        delete_repo.requires_approval,
        Some(ApprovalMode::Interactive)
    );

    let delete_tag = by_id("dockerhub.tags.delete");
    assert_eq!(delete_tag.risk_level, RiskLevel::High);
    assert_eq!(delete_tag.safety_tier, SafetyTier::Dangerous);
    assert_eq!(delete_tag.idempotency, IdempotencyClass::Strict);
    assert_eq!(
        delete_tag.requires_approval,
        Some(ApprovalMode::Interactive)
    );

    let list_repos = by_id("dockerhub.repos.list");
    assert_eq!(list_repos.risk_level, RiskLevel::Low);
    assert_eq!(list_repos.safety_tier, SafetyTier::Safe);
    assert_eq!(list_repos.requires_approval, None);
}

#[test]
fn manifest_operation_schemas_compile_and_validate_core_payloads() {
    let manifest = dockerhub_manifest();
    let operations = manifest_operations(&manifest);

    for operation_id in EXPECTED_MANIFEST_SCHEMA_OPS {
        assert!(
            operations.contains_key(operation_id),
            "manifest should declare operation {operation_id}"
        );
        for field in ["input_schema", "output_schema"] {
            let schema = operation_schema(&manifest, operation_id, field);
            let _validator = validator_for(&schema);
        }
    }

    let repos_list_input = operation_schema(&manifest, "repos_list", "input_schema");
    assert_schema_accepts(&repos_list_input, &json!({"namespace": "acme"}));
    assert_schema_rejects(&repos_list_input, &json!({}));
    assert_schema_rejects(
        &repos_list_input,
        &json!({"namespace": "acme", "extra": true}),
    );

    let repos_create_input = operation_schema(&manifest, "repos_create", "input_schema");
    assert_schema_accepts(
        &repos_create_input,
        &json!({
            "namespace": "acme",
            "name": "created-widget",
            "description": "created by test",
            "is_private": true,
            "full_description": "longer description"
        }),
    );
    assert_schema_rejects(&repos_create_input, &json!({"namespace": "acme"}));

    let tags_get_input = operation_schema(&manifest, "tags_get", "input_schema");
    assert_schema_accepts(
        &tags_get_input,
        &json!({"namespace": "acme", "name": "widget", "tag": "latest"}),
    );
    assert_schema_rejects(
        &tags_get_input,
        &json!({"namespace": "acme", "name": "widget"}),
    );

    let orgs_input = operation_schema(&manifest, "orgs_list", "input_schema");
    assert_schema_accepts(&orgs_input, &json!({}));
    assert_schema_rejects(&orgs_input, &json!({"namespace": "acme"}));

    let repos_list_output = operation_schema(&manifest, "repos_list", "output_schema");
    assert_schema_accepts(
        &repos_list_output,
        &json!([{
            "name": "widget",
            "namespace": "acme",
            "description": "primary image",
            "is_private": true,
            "star_count": 7,
            "pull_count": 42,
            "last_updated": null,
            "date_registered": null,
            "status": 1,
            "full_description": null
        }]),
    );
    assert_schema_rejects(&repos_list_output, &json!([{"namespace": "acme"}]));

    let tags_list_output = operation_schema(&manifest, "tags_list", "output_schema");
    assert_schema_accepts(
        &tags_list_output,
        &json!([{
            "name": "latest",
            "full_size": 7340032,
            "images": [{
                "architecture": "amd64",
                "os": "linux",
                "size": 7340032,
                "digest": "sha256:abc123"
            }],
            "last_updated": null,
            "last_updater": null,
            "last_updater_username": null,
            "tag_status": "active",
            "digest": "sha256:abc123",
            "content_type": null
        }]),
    );

    let repos_delete_output = operation_schema(&manifest, "repos_delete", "output_schema");
    assert_schema_accepts(
        &repos_delete_output,
        &json!({"deleted": true, "namespace": "acme", "name": "widget"}),
    );
    assert_schema_rejects(
        &repos_delete_output,
        &json!({"deleted": false, "namespace": "acme", "name": "widget"}),
    );

    let health_output = operation_schema(&manifest, "health", "output_schema");
    assert_schema_accepts(
        &health_output,
        &json!({"healthy": true, "user_id": "user-1", "username": null}),
    );
}

#[fcp_async_core::runtime::test]
async fn debug_output_redacts_dockerhub_secrets() {
    init_logging();

    let auth = DockerHubAuth::Token {
        access_token: "super-secret-dockerhub-token".into(),
    };
    let debug_auth = format!("{auth:?}");
    assert!(!debug_auth.contains("super-secret-dockerhub-token"));
    assert!(debug_auth.contains("[REDACTED]"));

    let login_request = LoginRequest {
        username: "fixture-user".into(),
        password: "super-secret-dockerhub-password".into(),
    };
    let debug_request = format!("{login_request:?}");
    assert!(debug_request.contains("fixture-user"));
    assert!(!debug_request.contains("super-secret-dockerhub-password"));
    assert!(debug_request.contains("[REDACTED]"));

    let login_response = LoginResponse {
        token: "super-secret-session-token".into(),
    };
    let debug_response = format!("{login_response:?}");
    assert!(!debug_response.contains("super-secret-session-token"));
    assert!(debug_response.contains("[REDACTED]"));

    let client = DockerHubClient::new(
        "https://hub.docker.com",
        DockerHubAuth::Token {
            access_token: "super-secret-client-token".into(),
        },
        no_retry_config(),
    )
    .expect("client should build");
    let debug_client = format!("{client:?}");
    assert!(!debug_client.contains("super-secret-client-token"));
    assert!(debug_client.contains("[REDACTED]"));
}
