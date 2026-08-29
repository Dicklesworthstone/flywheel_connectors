//! Connector-local no-mock Netlify integration proof.
//!
//! These tests exercise the real Netlify client against a local HTTP server.
//! No live Netlify service is called.

#![allow(clippy::too_many_lines)]

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_netlify::client::NetlifyClient;
use fcp_netlify::connector::NetlifyConnector;
use fcp_netlify::error::NetlifyError;
use fcp_netlify::types::{CreateDeployRequest, CreateSiteRequest, NetlifyAuth, SetEnvVarRequest};
use fcp_netlify::types::{SetEnvVarValue, User};
use fcp_prelude::{ApprovalMode, FcpConnector, OperationInfo, RiskLevel, SafetyTier};
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::{ConnectorErrorMapping, ConnectorRuntime, ConnectorRuntimeConfig};
use serde_json::{Value, json};
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn sample_auth_value() -> String {
    ["netlify", "test", "access"].join("-")
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

fn client(server: &MockServer) -> NetlifyClient {
    NetlifyClient::new(
        &server.uri(),
        NetlifyAuth {
            access_token: sample_auth_value(),
        },
        no_retry_config(),
    )
    .expect("wiremock URI should build a Netlify client")
}

fn test_site(site_id: &str) -> Value {
    json!({
        "id": site_id,
        "name": "fcp-site",
        "url": "https://fcp-site.netlify.app",
        "ssl_url": "https://fcp-site.netlify.app",
        "custom_domain": "example.com",
        "state": "current"
    })
}

fn test_deploy(deploy_id: &str, site_id: &str, state: &str) -> Value {
    json!({
        "id": deploy_id,
        "site_id": site_id,
        "state": state,
        "branch": "main",
        "title": "FCP deploy"
    })
}

const SCHEMA_OPERATIONS: [&str; 13] = [
    "netlify.sites.list",
    "netlify.sites.get",
    "netlify.sites.create",
    "netlify.sites.delete",
    "netlify.deploys.list",
    "netlify.deploys.get",
    "netlify.deploys.create",
    "netlify.deploys.rollback",
    "netlify.dns.list_zones",
    "netlify.env.list",
    "netlify.env.set",
    "netlify.env.delete",
    "netlify.health",
];

fn netlify_manifest() -> toml::Value {
    toml::from_str(include_str!("../manifest.toml")).expect("Netlify manifest TOML should parse")
}

fn manifest_operations(manifest: &toml::Value) -> &toml::Table {
    manifest
        .get("provides")
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .expect("manifest should contain provides.operations")
}

fn manifest_operation_schema(
    manifest: &toml::Value,
    operation_key: &str,
    schema_key: &str,
) -> Value {
    let schema = manifest_operations(manifest)
        .get(operation_key)
        .and_then(|operation| operation.get(schema_key))
        .expect("operation should define requested schema");

    serde_json::to_value(schema).expect("manifest schema should convert to JSON")
}

fn runtime_operation<'a>(operations: &'a [OperationInfo], operation_id: &str) -> &'a OperationInfo {
    operations
        .iter()
        .find(|operation| operation.id.as_str() == operation_id)
        .expect("runtime introspection should include operation")
}

fn assert_schema_accepts(schema: &Value, payload: &Value) {
    let validator = jsonschema::validator_for(schema).expect("schema should compile");
    let errors = validator
        .iter_errors(payload)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(
        errors.is_empty(),
        "schema should accept payload {payload:#}: {errors:#?}"
    );
}

fn assert_schema_rejects(schema: &Value, payload: &Value) {
    let validator = jsonschema::validator_for(schema).expect("schema should compile");
    assert!(
        validator.iter_errors(payload).next().is_some(),
        "schema should reject payload {payload:#}"
    );
}

fn assert_manifest_runtime_schema_parity(manifest: &toml::Value, operations: &[OperationInfo]) {
    let manifest_ops = manifest_operations(manifest);
    assert_eq!(
        manifest_ops.len(),
        SCHEMA_OPERATIONS.len(),
        "manifest operation count should match schema coverage set"
    );

    for operation_id in SCHEMA_OPERATIONS {
        let operation = runtime_operation(operations, operation_id);
        let input_schema = manifest_operation_schema(manifest, operation_id, "input_schema");
        let output_schema = manifest_operation_schema(manifest, operation_id, "output_schema");

        assert_eq!(
            input_schema, operation.input_schema,
            "{operation_id} manifest input_schema should match runtime introspection"
        );
        assert_eq!(
            output_schema, operation.output_schema,
            "{operation_id} manifest output_schema should match runtime introspection"
        );
        assert!(
            jsonschema::validator_for(&input_schema).is_ok(),
            "{operation_id} manifest input_schema should compile"
        );
        assert!(
            jsonschema::validator_for(&output_schema).is_ok(),
            "{operation_id} manifest output_schema should compile"
        );
    }
}

fn assert_catalog_input_schema_examples(manifest: &toml::Value) {
    for operation_key in [
        "netlify.sites.list",
        "netlify.dns.list_zones",
        "netlify.health",
    ] {
        let schema = manifest_operation_schema(manifest, operation_key, "input_schema");
        assert_schema_accepts(&schema, &json!({}));
        assert_schema_rejects(&schema, &json!({ "unexpected": true }));
    }

    let sites_get = manifest_operation_schema(manifest, "netlify.sites.get", "input_schema");
    assert_schema_accepts(&sites_get, &json!({ "site_id": "site-1" }));
    assert_schema_rejects(&sites_get, &json!({}));
    assert_schema_rejects(&sites_get, &json!({ "site_id": "site-1", "extra": true }));

    let sites_create = manifest_operation_schema(manifest, "netlify.sites.create", "input_schema");
    assert_schema_accepts(
        &sites_create,
        &json!({ "name": "fcp-site", "custom_domain": "example.com" }),
    );
    assert_schema_rejects(&sites_create, &json!({ "custom_domain": "example.com" }));
    assert_schema_rejects(&sites_create, &json!({ "name": "fcp-site", "extra": true }));

    let sites_delete = manifest_operation_schema(manifest, "netlify.sites.delete", "input_schema");
    assert_schema_accepts(&sites_delete, &json!({ "site_id": "site-1" }));
    assert_schema_rejects(&sites_delete, &json!({}));

    let deploys_list = manifest_operation_schema(manifest, "netlify.deploys.list", "input_schema");
    assert_schema_accepts(&deploys_list, &json!({ "site_id": "site-1" }));
    assert_schema_rejects(
        &deploys_list,
        &json!({ "site_id": "site-1", "extra": true }),
    );

    let deploys_get = manifest_operation_schema(manifest, "netlify.deploys.get", "input_schema");
    assert_schema_accepts(
        &deploys_get,
        &json!({ "site_id": "site-1", "deploy_id": "deploy-1" }),
    );
    assert_schema_rejects(&deploys_get, &json!({ "site_id": "site-1" }));

    let deploys_create =
        manifest_operation_schema(manifest, "netlify.deploys.create", "input_schema");
    assert_schema_accepts(
        &deploys_create,
        &json!({ "site_id": "site-1", "branch": "main", "title": "FCP deploy" }),
    );
    assert_schema_rejects(&deploys_create, &json!({ "branch": "main" }));
    assert_schema_rejects(
        &deploys_create,
        &json!({ "site_id": "site-1", "extra": true }),
    );

    let deploys_rollback =
        manifest_operation_schema(manifest, "netlify.deploys.rollback", "input_schema");
    assert_schema_accepts(
        &deploys_rollback,
        &json!({ "site_id": "site-1", "deploy_id": "deploy-1" }),
    );
    assert_schema_rejects(&deploys_rollback, &json!({ "site_id": "site-1" }));

    let env_list = manifest_operation_schema(manifest, "netlify.env.list", "input_schema");
    assert_schema_accepts(
        &env_list,
        &json!({ "site_id": "site-1", "account_slug": "acme" }),
    );
    assert_schema_rejects(&env_list, &json!({ "site_id": "site-1" }));

    let env_set = manifest_operation_schema(manifest, "netlify.env.set", "input_schema");
    assert_schema_accepts(
        &env_set,
        &json!({
            "site_id": "site-1",
            "account_slug": "acme",
            "key": "API_KEY",
            "value": "secret-value",
            "context": "production",
            "is_secret": true
        }),
    );
    assert_schema_rejects(
        &env_set,
        &json!({
            "site_id": "site-1",
            "account_slug": "acme",
            "key": "API_KEY"
        }),
    );
    assert_schema_rejects(
        &env_set,
        &json!({
            "site_id": "site-1",
            "account_slug": "acme",
            "key": "API_KEY",
            "value": "secret-value",
            "is_secret": "yes"
        }),
    );

    let env_delete = manifest_operation_schema(manifest, "netlify.env.delete", "input_schema");
    assert_schema_accepts(
        &env_delete,
        &json!({ "site_id": "site-1", "account_slug": "acme", "key": "API_KEY" }),
    );
    assert_schema_rejects(
        &env_delete,
        &json!({ "site_id": "site-1", "account_slug": "acme" }),
    );
}

fn assert_catalog_output_schema_examples(manifest: &toml::Value) {
    for operation_key in [
        "netlify.sites.list",
        "netlify.deploys.list",
        "netlify.dns.list_zones",
        "netlify.env.list",
        "netlify.env.set",
    ] {
        let schema = manifest_operation_schema(manifest, operation_key, "output_schema");
        assert_schema_accepts(&schema, &json!([]));
        assert_schema_accepts(&schema, &json!([{}]));
        assert_schema_rejects(&schema, &json!({}));
    }

    for operation_key in [
        "netlify.sites.get",
        "netlify.sites.create",
        "netlify.deploys.get",
        "netlify.deploys.create",
        "netlify.deploys.rollback",
    ] {
        let schema = manifest_operation_schema(manifest, operation_key, "output_schema");
        assert_schema_accepts(&schema, &json!({}));
        assert_schema_accepts(&schema, &json!({ "id": "resource-1" }));
        assert_schema_rejects(&schema, &json!([]));
    }

    let sites_delete = manifest_operation_schema(manifest, "netlify.sites.delete", "output_schema");
    assert_schema_accepts(
        &sites_delete,
        &json!({ "deleted": true, "site_id": "site-1" }),
    );
    assert_schema_rejects(
        &sites_delete,
        &json!({ "deleted": false, "site_id": "site-1" }),
    );
    assert_schema_rejects(&sites_delete, &json!({ "deleted": true }));

    let env_delete = manifest_operation_schema(manifest, "netlify.env.delete", "output_schema");
    assert_schema_accepts(&env_delete, &json!({ "deleted": true, "key": "API_KEY" }));
    assert_schema_rejects(&env_delete, &json!({ "key": "API_KEY" }));

    let health = manifest_operation_schema(manifest, "netlify.health", "output_schema");
    assert_schema_accepts(
        &health,
        &json!({ "healthy": true, "user_id": "user-1", "email": null }),
    );
    assert_schema_accepts(
        &health,
        &json!({ "healthy": true, "user_id": "user-1", "email": "dev@example.com" }),
    );
    assert_schema_rejects(
        &health,
        &json!({ "healthy": false, "user_id": "user-1", "email": null }),
    );
}

#[fcp_async_core::test]
async fn site_deploy_dns_env_and_health_success_paths_use_netlify_contracts() {
    tracing::info!(
        scenario = "netlify_success_contracts",
        "starting Netlify success-path integration proof",
    );

    let server = MockServer::start().await;
    let runtime = test_runtime();

    Mock::given(method("GET"))
        .and(path("/api/v1/sites"))
        .and(header(
            "Authorization",
            format!("Bearer {}", sample_auth_value()),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([test_site("site-1")])))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/sites/site-1"))
        .and(header(
            "Authorization",
            format!("Bearer {}", sample_auth_value()),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(test_site("site-1")))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/v1/sites"))
        .and(header(
            "Authorization",
            format!("Bearer {}", sample_auth_value()),
        ))
        .and(body_json(json!({
            "name": "fcp-created",
            "custom_domain": "created.example.com"
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(test_site("site-created")))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("DELETE"))
        .and(path("/api/v1/sites/site-1"))
        .and(header(
            "Authorization",
            format!("Bearer {}", sample_auth_value()),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/sites/site-1/deploys"))
        .and(header(
            "Authorization",
            format!("Bearer {}", sample_auth_value()),
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!([test_deploy("deploy-1", "site-1", "ready")])),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/v1/sites/site-1/deploys"))
        .and(header(
            "Authorization",
            format!("Bearer {}", sample_auth_value()),
        ))
        .and(body_json(json!({
            "branch": "main",
            "title": "FCP deploy"
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(test_deploy(
            "deploy-created",
            "site-1",
            "building",
        )))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/v1/sites/site-1/rollback/deploy-1"))
        .and(header(
            "Authorization",
            format!("Bearer {}", sample_auth_value()),
        ))
        .and(body_json(json!({})))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(test_deploy("deploy-1", "site-1", "ready")),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/dns_zones"))
        .and(header(
            "Authorization",
            format!("Bearer {}", sample_auth_value()),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
            "id": "zone-1",
            "name": "example.com",
            "site_id": "site-1"
        }])))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/accounts/acme/env"))
        .and(query_param("site_id", "site-1"))
        .and(header(
            "Authorization",
            format!("Bearer {}", sample_auth_value()),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
            "key": "API_KEY",
            "is_secret": true,
            "values": [{
                "id": "value-1",
                "value": "redacted",
                "context": "production"
            }]
        }])))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/v1/accounts/acme/env"))
        .and(query_param("site_id", "site-1"))
        .and(header(
            "Authorization",
            format!("Bearer {}", sample_auth_value()),
        ))
        .and(body_json(json!([{
            "key": "API_KEY",
            "values": [{
                "value": "secret-value",
                "context": "production"
            }],
            "is_secret": true
        }])))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
            "key": "API_KEY",
            "is_secret": true,
            "values": [{
                "id": "value-2",
                "value": "redacted",
                "context": "production"
            }]
        }])))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("DELETE"))
        .and(path("/api/v1/accounts/acme/env/API_KEY"))
        .and(query_param("site_id", "site-1"))
        .and(header(
            "Authorization",
            format!("Bearer {}", sample_auth_value()),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/user"))
        .and(header(
            "Authorization",
            format!("Bearer {}", sample_auth_value()),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "user-1",
            "email": "dev@example.com"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = client(&server);

    let sites = client
        .list_sites(&runtime)
        .await
        .expect("sites should decode");
    assert_eq!(sites[0].id, "site-1");

    let site = client
        .get_site(&runtime, "site-1")
        .await
        .expect("site should decode");
    assert_eq!(site.custom_domain.as_deref(), Some("example.com"));

    let created = client
        .create_site(
            &runtime,
            &CreateSiteRequest {
                name: "fcp-created".into(),
                custom_domain: Some("created.example.com".into()),
            },
        )
        .await
        .expect("create site should decode");
    assert_eq!(created.id, "site-created");

    let deleted = client
        .delete_site(&runtime, "site-1")
        .await
        .expect("delete site should decode");
    assert_eq!(deleted, json!({}));

    let deploys = client
        .list_deploys(&runtime, "site-1")
        .await
        .expect("deploy list should decode");
    assert_eq!(deploys[0].id, "deploy-1");

    let created_deploy = client
        .create_deploy(
            &runtime,
            "site-1",
            &CreateDeployRequest {
                branch: Some("main".into()),
                title: Some("FCP deploy".into()),
            },
        )
        .await
        .expect("create deploy should decode");
    assert_eq!(created_deploy.state.as_deref(), Some("building"));

    let rollback = client
        .rollback_deploy(&runtime, "site-1", "deploy-1")
        .await
        .expect("rollback should decode");
    assert_eq!(rollback.id, "deploy-1");
    assert_eq!(rollback.state.as_deref(), Some("ready"));

    let zones = client
        .list_dns_zones(&runtime)
        .await
        .expect("DNS zones should decode");
    assert_eq!(zones[0].name, "example.com");

    let env = client
        .list_env_vars(&runtime, "acme", "site-1")
        .await
        .expect("env vars should decode");
    assert_eq!(env[0].key, "API_KEY");
    assert_eq!(env[0].is_secret, Some(true));

    let updated_env = client
        .set_env_var(
            &runtime,
            "acme",
            "site-1",
            &[SetEnvVarRequest {
                key: "API_KEY".into(),
                values: vec![SetEnvVarValue {
                    value: "secret-value".into(),
                    context: Some("production".into()),
                }],
                scopes: None,
                is_secret: Some(true),
            }],
        )
        .await
        .expect("set env var should decode");
    assert_eq!(updated_env[0].key, "API_KEY");
    assert_eq!(
        updated_env[0].values.as_ref().expect("values")[0].value,
        "redacted"
    );

    let deleted_env = client
        .delete_env_var(&runtime, "acme", "site-1", "API_KEY")
        .await
        .expect("delete env var should decode");
    assert_eq!(deleted_env, json!({}));

    let user: User = client
        .health_check(&runtime)
        .await
        .expect("health user should decode");
    assert_eq!(user.id, "user-1");
}

#[fcp_async_core::test]
async fn auth_rate_limit_malformed_json_and_invalid_input_are_typed() {
    tracing::info!(
        scenario = "netlify_error_taxonomy",
        "starting Netlify error-taxonomy integration proof",
    );

    let server = MockServer::start().await;
    let runtime = test_runtime();

    Mock::given(method("GET"))
        .and(path("/api/v1/sites/bad-auth"))
        .and(header(
            "Authorization",
            format!("Bearer {}", sample_auth_value()),
        ))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "message": "invalid token"
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/sites/rate-limited"))
        .and(header(
            "Authorization",
            format!("Bearer {}", sample_auth_value()),
        ))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "2")
                .set_body_json(json!({ "message": "rate limited" })),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/sites/malformed"))
        .and(header(
            "Authorization",
            format!("Bearer {}", sample_auth_value()),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_string("{this is not json"))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/sites/empty"))
        .and(header(
            "Authorization",
            format!("Bearer {}", sample_auth_value()),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_string(""))
        .expect(1)
        .mount(&server)
        .await;

    let client = client(&server);

    let unauthorized = client
        .get_site(&runtime, "bad-auth")
        .await
        .expect_err("401 should map to unauthorized");
    assert!(matches!(unauthorized, NetlifyError::Unauthorized(_)));
    assert!(!unauthorized.is_retryable());

    let rate_limited = client
        .get_site(&runtime, "rate-limited")
        .await
        .expect_err("429 should map to rate limit");
    assert!(matches!(
        rate_limited,
        NetlifyError::RateLimited {
            retry_after_ms: 2_000
        }
    ));
    assert_eq!(rate_limited.retry_after(), Some(Duration::from_secs(2)));

    let malformed = client
        .get_site(&runtime, "malformed")
        .await
        .expect_err("malformed JSON should be typed");
    assert!(matches!(malformed, NetlifyError::Json(_)));
    assert!(!malformed.is_retryable());

    let empty_body = client
        .get_site(&runtime, "empty")
        .await
        .expect_err("empty non-204 success body should fail closed");
    assert!(matches!(
        empty_body,
        NetlifyError::Api {
            status: 200,
            ref message
        } if message == "empty response body"
    ));
    assert!(!empty_body.is_retryable());

    let traversal = client
        .get_site(&runtime, "../site")
        .await
        .expect_err("path traversal should be rejected before outbound call");
    assert!(matches!(traversal, NetlifyError::InvalidInput(_)));

    let query_injection = client
        .list_env_vars(&runtime, "acme", "site-1&team=other")
        .await
        .expect_err("query injection should be rejected before outbound call");
    assert!(matches!(query_injection, NetlifyError::InvalidInput(_)));
}

#[test]
fn async_timeout_and_cancellation_mapping_is_bounded() {
    let timeout = NetlifyError::from_async_error(AsyncError::Timeout { timeout_ms: 250 });
    assert_eq!(
        timeout.to_string(),
        "Async error: request deadline exceeded after 250ms"
    );
    assert!(!timeout.is_retryable());

    let cancelled = NetlifyError::from_async_error(AsyncError::Cancelled);
    assert_eq!(cancelled.to_string(), "Async error: operation cancelled");
    assert!(!cancelled.is_retryable());
}

#[test]
fn manifest_operation_schemas_compile_and_validate_core_payloads() {
    let manifest = netlify_manifest();
    let introspection = NetlifyConnector::new().introspect();

    assert_manifest_runtime_schema_parity(&manifest, &introspection.operations);
    assert_catalog_input_schema_examples(&manifest);
    assert_catalog_output_schema_examples(&manifest);
}

#[test]
fn operation_catalog_manifest_and_redaction_preserve_security_posture() {
    let connector = NetlifyConnector::new();
    let introspection = connector.introspect();
    let operation = |id: &str| {
        introspection
            .operations
            .iter()
            .find(|entry| entry.id.as_str() == id)
            .expect("operation catalog should contain required Netlify operation")
    };

    let sites_list = operation("netlify.sites.list");
    assert_eq!(sites_list.risk_level, RiskLevel::Low);
    assert_eq!(sites_list.safety_tier, SafetyTier::Safe);
    assert_eq!(sites_list.requires_approval, None);

    let sites_delete = operation("netlify.sites.delete");
    assert_eq!(sites_delete.risk_level, RiskLevel::Critical);
    assert_eq!(sites_delete.safety_tier, SafetyTier::Dangerous);
    assert_eq!(
        sites_delete.requires_approval,
        Some(ApprovalMode::Interactive)
    );

    let deploy_rollback = operation("netlify.deploys.rollback");
    assert_eq!(deploy_rollback.risk_level, RiskLevel::High);
    assert_eq!(deploy_rollback.safety_tier, SafetyTier::Risky);

    let env_set = operation("netlify.env.set");
    assert_eq!(env_set.risk_level, RiskLevel::Medium);
    assert_eq!(env_set.safety_tier, SafetyTier::Risky);

    let capability_section = manifest_capability_section();
    assert!(capability_section.contains("\"network.dns\""));
    assert!(capability_section.contains("\"network.egress\""));
    assert!(capability_section.contains("\"network.tls.sni\""));
    assert!(capability_section.contains("\"system.exec\""));
    assert!(capability_section.contains("\"system.privileged\""));
    assert!(capability_section.contains("\"network.listen\""));

    let redaction_value = sample_auth_value();
    let client = NetlifyClient::new(
        "https://api.netlify.com",
        NetlifyAuth {
            access_token: redaction_value.clone(),
        },
        no_retry_config(),
    )
    .expect("redaction proof client should build");
    let debug_output = format!("{client:?}");
    assert!(!debug_output.contains(&redaction_value));
    assert!(debug_output.contains("[REDACTED]"));
}

fn manifest_capability_section() -> &'static str {
    let manifest = include_str!("../manifest.toml");
    let (_, capabilities) = manifest
        .split_once("[capabilities]")
        .expect("Netlify manifest should define capabilities");
    let (capability_section, _) = capabilities
        .split_once("[provides.operations.")
        .expect("Netlify manifest should separate capabilities from operations");
    capability_section
}

// ── Replay safety on retry (br-kxd3e) ────────────────────────────────
//
// The highest-harm case in the infra tier: a retried create_deploy does not
// leave a stray record, it starts a SECOND build and ships it to production.
// Netlify has no idempotency key. The assertion is the REQUEST COUNT.

fn retrying_client_config() -> HttpRetryConfig {
    HttpRetryConfig {
        max_retries: 3,
        initial_delay_ms: 1,
        max_delay_ms: 5,
        jitter_enabled: false,
    }
}

fn retrying_client(server: &MockServer) -> NetlifyClient {
    NetlifyClient::new(
        &server.uri(),
        NetlifyAuth {
            access_token: sample_auth_value(),
        },
        retrying_client_config(),
    )
    .expect("wiremock URI should build a Netlify client")
}

#[fcp_async_core::runtime::test]
async fn create_deploy_is_not_retried_after_a_5xx() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/sites/site-1/deploys"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;

    let result = retrying_client(&server)
        .create_deploy(
            &test_runtime(),
            "site-1",
            &CreateDeployRequest {
                branch: Some("main".into()),
                title: None,
            },
        )
        .await;
    assert!(result.is_err());

    let requests = server.received_requests().await.expect("recorded requests");
    assert_eq!(
        requests.len(),
        1,
        "a 503 means Netlify received the deploy trigger — retrying starts a \
         SECOND build and ships it"
    );
}

#[fcp_async_core::runtime::test]
async fn create_deploy_still_retries_a_429() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/sites/site-1/deploys"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "0"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/sites/site-1/deploys"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "deploy-1",
            "site_id": "site-1",
            "state": "building"
        })))
        .mount(&server)
        .await;

    retrying_client(&server)
        .create_deploy(
            &test_runtime(),
            "site-1",
            &CreateDeployRequest {
                branch: Some("main".into()),
                title: None,
            },
        )
        .await
        .expect("a rate-limited trigger was refused without building anything");

    let requests = server.received_requests().await.expect("recorded requests");
    assert_eq!(
        requests.len(),
        2,
        "429 means Netlify did NOT start the build, so backoff is preserved"
    );
}
