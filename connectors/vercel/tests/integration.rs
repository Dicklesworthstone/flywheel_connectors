//! Connector-local no-mock Vercel integration proof.
//!
//! These tests exercise the real Vercel client against a local HTTP server.
//! No live Vercel service is called.

#![allow(clippy::missing_errors_doc, clippy::too_many_lines)]

use std::sync::Once;
use std::time::Duration;

use fcp_prelude::{
    ApprovalMode, FcpConnector, IdempotencyClass, OperationInfo, RiskLevel, SafetyTier,
};
use fcp_sdk::migration::HttpRetryConfig;
use fcp_vercel::client::VercelClient;
use fcp_vercel::connector::VercelConnector;
use fcp_vercel::error::VercelError;
use fcp_vercel::types::{
    AddDomainRequest, CreateDeploymentRequest, CreateEnvVarRequest, CreateProjectRequest,
    GitSource, TeamScope, VercelAuth,
};
use serde_json::{Value, json};
use wiremock::matchers::{body_json, body_partial_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_TOKEN: &str = "vercel-token-for-tests";
const AUTH_HEADER: &str = "Bearer vercel-token-for-tests";
const TEAM_ID: &str = "team_fcp";

static LOG_INIT: Once = Once::new();

fn init_logging() {
    LOG_INIT.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| {
                        tracing_subscriber::EnvFilter::new(
                            "info,asupersync=warn,fcp_sdk=warn,hyper=warn,hyper_util=warn,reqwest=warn,wiremock=warn",
                        )
                    }),
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

fn client(server: &MockServer) -> VercelClient {
    client_with_timeout(server, Duration::from_millis(500))
}

fn client_with_timeout(server: &MockServer, request_timeout: Duration) -> VercelClient {
    VercelClient::new(
        VercelAuth::AccessToken {
            access_token: TEST_TOKEN.into(),
        },
        TeamScope {
            team_id: Some(TEAM_ID.into()),
            team_slug: None,
        },
        no_retry_config(),
        request_timeout,
    )
    .expect("wiremock URI should build a Vercel client")
    .with_base_url(&server.uri())
}

fn unscoped_client(server: &MockServer) -> VercelClient {
    VercelClient::new(
        VercelAuth::AccessToken {
            access_token: "token".into(),
        },
        TeamScope::default(),
        no_retry_config(),
        Duration::from_millis(500),
    )
    .expect("wiremock URI should build an unscoped Vercel client")
    .with_base_url(&server.uri())
}

fn test_project(project_id: &str) -> serde_json::Value {
    json!({
        "id": project_id,
        "name": "demo",
        "framework": "nextjs",
        "accountId": "team_fcp",
        "rootDirectory": "apps/web"
    })
}

fn test_deployment(deployment_id: &str, state: &str) -> serde_json::Value {
    json!({
        "uid": deployment_id,
        "name": "demo-web",
        "projectId": "prj_123",
        "url": "demo-web.vercel.app",
        "target": "production",
        "readyState": state
    })
}

fn test_domain() -> serde_json::Value {
    json!({
        "name": "demo.example.com",
        "apexName": "example.com",
        "projectId": "prj_123",
        "gitBranch": "main",
        "verified": true
    })
}

fn test_env() -> serde_json::Value {
    json!({
        "id": "env_123",
        "key": "API_KEY",
        "type": "encrypted",
        "target": ["production"],
        "gitBranch": "main",
        "configurationId": "cfg_123"
    })
}

const SCHEMA_OPERATIONS: [(&str, &str); 15] = [
    ("health", "vercel.health"),
    ("deployments_list", "vercel.deployments.list"),
    ("deployments_get", "vercel.deployments.get"),
    ("deployments_create", "vercel.deployments.create"),
    ("deployments_delete", "vercel.deployments.delete"),
    ("projects_list", "vercel.projects.list"),
    ("projects_get", "vercel.projects.get"),
    ("projects_create", "vercel.projects.create"),
    ("projects_delete", "vercel.projects.delete"),
    ("domains_list", "vercel.domains.list"),
    ("domains_add", "vercel.domains.add"),
    ("domains_remove", "vercel.domains.remove"),
    ("env_list", "vercel.env.list"),
    ("env_create", "vercel.env.create"),
    ("env_delete", "vercel.env.delete"),
];

fn vercel_manifest() -> toml::Value {
    toml::from_str(include_str!("../manifest.toml")).expect("Vercel manifest TOML should parse")
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

fn object_with_field(field: &str, value: Value) -> Value {
    let mut object = serde_json::Map::new();
    object.insert(field.to_string(), value);
    Value::Object(object)
}

fn assert_manifest_runtime_schema_parity(manifest: &toml::Value, operations: &[OperationInfo]) {
    let manifest_ops = manifest_operations(manifest);
    assert_eq!(
        manifest_ops.len(),
        SCHEMA_OPERATIONS.len(),
        "manifest operation count should match schema coverage set"
    );

    for (operation_key, operation_id) in SCHEMA_OPERATIONS {
        let operation = runtime_operation(operations, operation_id);
        let input_schema = manifest_operation_schema(manifest, operation_key, "input_schema");
        let output_schema = manifest_operation_schema(manifest, operation_key, "output_schema");

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
    let health = manifest_operation_schema(manifest, "health", "input_schema");
    assert_schema_accepts(&health, &json!({}));
    assert_schema_rejects(&health, &json!({ "unexpected": true }));

    let deployments_list = manifest_operation_schema(manifest, "deployments_list", "input_schema");
    assert_schema_accepts(&deployments_list, &json!({}));
    assert_schema_accepts(
        &deployments_list,
        &json!({ "project_id": "prj_123", "limit": 20 }),
    );
    assert_schema_rejects(&deployments_list, &json!({ "limit": "20" }));

    let deployments_get = manifest_operation_schema(manifest, "deployments_get", "input_schema");
    assert_schema_accepts(
        &deployments_get,
        &json!({ "deployment_id_or_url": "dpl_123" }),
    );
    assert_schema_rejects(&deployments_get, &json!({}));

    let deployments_create =
        manifest_operation_schema(manifest, "deployments_create", "input_schema");
    assert_schema_accepts(
        &deployments_create,
        &json!({
            "name": "demo-web",
            "project": "demo",
            "target": "production",
            "git_source": {
                "type": "github",
                "ref": "main",
                "repoId": "repo_123"
            },
            "meta": {}
        }),
    );
    assert_schema_rejects(&deployments_create, &json!({ "project": "demo" }));
    assert_schema_rejects(
        &deployments_create,
        &json!({ "name": "demo-web", "git_source": { "type": "github" } }),
    );

    let deployments_delete =
        manifest_operation_schema(manifest, "deployments_delete", "input_schema");
    assert_schema_accepts(&deployments_delete, &json!({ "deployment_id": "dpl_123" }));
    assert_schema_rejects(&deployments_delete, &json!({}));

    let projects_list = manifest_operation_schema(manifest, "projects_list", "input_schema");
    assert_schema_accepts(&projects_list, &json!({ "limit": 5 }));
    assert_schema_rejects(&projects_list, &json!({ "limit": "5" }));

    let projects_get = manifest_operation_schema(manifest, "projects_get", "input_schema");
    assert_schema_accepts(&projects_get, &json!({ "project_id_or_name": "demo" }));
    assert_schema_rejects(
        &projects_get,
        &json!({ "project_id_or_name": "demo", "extra": true }),
    );

    let projects_create = manifest_operation_schema(manifest, "projects_create", "input_schema");
    assert_schema_accepts(
        &projects_create,
        &json!({
            "name": "created-demo",
            "framework": "nextjs",
            "rootDirectory": "apps/web",
            "publicSource": false
        }),
    );
    assert_schema_rejects(&projects_create, &json!({ "framework": "nextjs" }));

    let projects_delete = manifest_operation_schema(manifest, "projects_delete", "input_schema");
    assert_schema_accepts(&projects_delete, &json!({ "project_id_or_name": "demo" }));
    assert_schema_rejects(&projects_delete, &json!({}));

    let domains_list = manifest_operation_schema(manifest, "domains_list", "input_schema");
    assert_schema_accepts(&domains_list, &json!({ "project_id_or_name": "demo" }));
    assert_schema_rejects(&domains_list, &json!({}));

    let domains_add = manifest_operation_schema(manifest, "domains_add", "input_schema");
    assert_schema_accepts(
        &domains_add,
        &json!({
            "project_id_or_name": "demo",
            "name": "demo.example.com",
            "git_branch": "main",
            "redirect_status_code": 308
        }),
    );
    assert_schema_rejects(&domains_add, &json!({ "project_id_or_name": "demo" }));

    let domains_remove = manifest_operation_schema(manifest, "domains_remove", "input_schema");
    assert_schema_accepts(
        &domains_remove,
        &json!({ "project_id_or_name": "demo", "domain_name": "demo.example.com" }),
    );
    assert_schema_rejects(&domains_remove, &json!({ "project_id_or_name": "demo" }));

    let env_list = manifest_operation_schema(manifest, "env_list", "input_schema");
    assert_schema_accepts(&env_list, &json!({ "project_id_or_name": "demo" }));
    assert_schema_rejects(&env_list, &json!({}));

    let env_create = manifest_operation_schema(manifest, "env_create", "input_schema");
    assert_schema_accepts(
        &env_create,
        &json!({
            "project_id_or_name": "demo",
            "key": "API_KEY",
            "value": "secret-value",
            "env_type": "encrypted",
            "target": ["production"],
            "git_branch": "main",
            "custom_environment_ids": ["env_prod"]
        }),
    );
    assert_schema_accepts(
        &env_create,
        &json!({
            "project_id_or_name": "demo",
            "envs": [{
                "key": "API_KEY",
                "value": "secret-value",
                "type": "encrypted",
                "target": ["production"],
                "gitBranch": "main",
                "customEnvironmentIds": ["env_prod"]
            }]
        }),
    );
    assert_schema_rejects(
        &env_create,
        &json!({ "project_id_or_name": "demo", "key": "API_KEY" }),
    );

    let env_delete = manifest_operation_schema(manifest, "env_delete", "input_schema");
    assert_schema_accepts(
        &env_delete,
        &json!({ "project_id_or_name": "demo", "environment_variable_id": "env_123" }),
    );
    assert_schema_rejects(&env_delete, &json!({ "project_id_or_name": "demo" }));
}

fn assert_catalog_output_schema_examples(manifest: &toml::Value) {
    let health = manifest_operation_schema(manifest, "health", "output_schema");
    assert_schema_accepts(&health, &json!({ "status": "ok" }));
    assert_schema_rejects(&health, &json!({ "status": "degraded" }));

    for (operation_key, field) in [
        ("deployments_list", "deployments"),
        ("projects_list", "projects"),
        ("domains_list", "domains"),
        ("env_list", "envs"),
    ] {
        let schema = manifest_operation_schema(manifest, operation_key, "output_schema");
        assert_schema_accepts(&schema, &object_with_field(field, json!([])));

        let mut payload = serde_json::Map::new();
        payload.insert(field.to_string(), json!([{}]));
        payload.insert("pagination".into(), json!({}));
        assert_schema_accepts(&schema, &Value::Object(payload));

        assert_schema_rejects(&schema, &json!({}));
        assert_schema_rejects(&schema, &json!([]));
    }

    for operation_key in [
        "deployments_get",
        "deployments_create",
        "projects_get",
        "projects_create",
        "domains_add",
    ] {
        let schema = manifest_operation_schema(manifest, operation_key, "output_schema");
        assert_schema_accepts(&schema, &json!({}));
        assert_schema_accepts(&schema, &json!({ "id": "resource-1" }));
        assert_schema_rejects(&schema, &json!([]));
    }

    for operation_key in ["deployments_delete", "domains_remove", "env_delete"] {
        let schema = manifest_operation_schema(manifest, operation_key, "output_schema");
        assert_schema_accepts(
            &schema,
            &json!({
                "deleted": true,
                "resource_id": "resource-1",
                "status": null,
                "state": null
            }),
        );
        assert_schema_rejects(&schema, &json!({ "resource_id": "resource-1" }));
    }

    let projects_delete = manifest_operation_schema(manifest, "projects_delete", "output_schema");
    assert_schema_accepts(
        &projects_delete,
        &json!({ "deleted": true, "project_id_or_name": "demo" }),
    );
    assert_schema_rejects(
        &projects_delete,
        &json!({ "deleted": false, "project_id_or_name": "demo" }),
    );

    let env_create = manifest_operation_schema(manifest, "env_create", "output_schema");
    assert_schema_accepts(&env_create, &json!([]));
    assert_schema_accepts(&env_create, &json!([{}]));
    assert_schema_rejects(&env_create, &json!({}));
}

#[test]
fn manifest_operation_schemas_compile_and_validate_core_payloads() {
    init_logging();
    let manifest = vercel_manifest();
    let introspection = VercelConnector::new().introspect();

    assert_manifest_runtime_schema_parity(&manifest, &introspection.operations);
    assert_catalog_input_schema_examples(&manifest);
    assert_catalog_output_schema_examples(&manifest);
}

#[fcp_async_core::runtime::test]
async fn client_health_check_applies_scope_and_auth() {
    init_logging();

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v9/projects"))
        .and(query_param("limit", "1"))
        .and(query_param("teamId", "team_123"))
        .and(header("authorization", "Bearer token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "projects": [],
            "pagination": { "count": 0 }
        })))
        .mount(&server)
        .await;

    let client = VercelClient::new(
        VercelAuth::AccessToken {
            access_token: "token".into(),
        },
        TeamScope {
            team_id: Some("team_123".into()),
            team_slug: None,
        },
        no_retry_config(),
        Duration::from_millis(500),
    )
    .unwrap()
    .with_base_url(&server.uri());

    client.health_check().await.unwrap();
}

#[fcp_async_core::runtime::test]
async fn client_create_deployment_posts_expected_shape() {
    init_logging();

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v13/deployments"))
        .and(body_partial_json(json!({
            "name": "demo-web",
            "gitSource": {
                "type": "github",
                "ref": "main"
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "uid": "dpl_123",
            "name": "demo-web",
            "readyState": "QUEUED"
        })))
        .mount(&server)
        .await;

    let client = unscoped_client(&server);
    let deployment = client
        .create_deployment(&CreateDeploymentRequest {
            name: "demo-web".into(),
            project: Some("demo-web".into()),
            target: Some("production".into()),
            git_source: Some(GitSource {
                source_type: "github".into(),
                git_ref: "main".into(),
                repo_id: None,
                sha: None,
                project_id: None,
            }),
            meta: None,
        })
        .await
        .unwrap();

    assert_eq!(deployment.id, "dpl_123");
    assert_eq!(deployment.ready_state.as_deref(), Some("QUEUED"));
}

#[fcp_async_core::runtime::test]
async fn client_list_projects_returns_typed_payload() {
    init_logging();

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v9/projects"))
        .and(query_param("limit", "10"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "projects": [
                { "id": "prj_1", "name": "demo", "framework": "nextjs" }
            ],
            "pagination": { "count": 1 }
        })))
        .mount(&server)
        .await;

    let client = unscoped_client(&server);
    let response = client.list_projects(Some(10)).await.unwrap();
    assert_eq!(response.projects.len(), 1);
    assert_eq!(response.projects[0].name, "demo");
}

#[fcp_async_core::runtime::test]
async fn client_add_domain_serializes_redirect_metadata() {
    init_logging();

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v10/projects/demo/domains"))
        .and(body_partial_json(json!({
            "name": "demo.example.com",
            "gitBranch": "main"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "demo.example.com",
            "projectId": "prj_123",
            "verified": true
        })))
        .mount(&server)
        .await;

    let client = unscoped_client(&server);
    let domain = client
        .add_domain(
            "demo",
            &AddDomainRequest {
                name: "demo.example.com".into(),
                git_branch: Some("main".into()),
                redirect: None,
                redirect_status_code: None,
            },
        )
        .await
        .unwrap();

    assert_eq!(domain.name, "demo.example.com");
    assert_eq!(domain.verified, Some(true));
}

#[fcp_async_core::runtime::test]
async fn client_create_env_vars_posts_array_payload() {
    init_logging();

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v10/projects/demo/env"))
        .and(body_partial_json(json!([{
            "key": "API_KEY",
            "type": "encrypted",
            "target": ["production"]
        }])))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {
                "id": "env_123",
                "key": "API_KEY",
                "type": "encrypted",
                "target": ["production"]
            }
        ])))
        .mount(&server)
        .await;

    let client = unscoped_client(&server);
    let created = client
        .create_env_vars(
            "demo",
            &[CreateEnvVarRequest {
                key: "API_KEY".into(),
                value: "redacted".into(),
                env_type: "encrypted".into(),
                target: vec!["production".into()],
                git_branch: None,
                custom_environment_ids: vec![],
            }],
        )
        .await
        .unwrap();

    assert_eq!(created.len(), 1);
    assert_eq!(created[0].key, "API_KEY");
}

#[fcp_async_core::runtime::test]
async fn deployment_project_domain_env_and_health_success_paths_use_vercel_contracts() {
    init_logging();
    tracing::info!(
        scenario = "vercel_success_contracts",
        "starting Vercel success-path integration proof",
    );

    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v6/deployments"))
        .and(query_param("projectId", "prj_123"))
        .and(query_param("limit", "2"))
        .and(query_param("teamId", TEAM_ID))
        .and(header("authorization", AUTH_HEADER))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "deployments": [test_deployment("dpl_123", "READY")],
            "pagination": { "count": 1 }
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v13/deployments/dpl_123"))
        .and(query_param("teamId", TEAM_ID))
        .and(header("authorization", AUTH_HEADER))
        .respond_with(ResponseTemplate::new(200).set_body_json(test_deployment("dpl_123", "READY")))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v13/deployments"))
        .and(query_param("teamId", TEAM_ID))
        .and(header("authorization", AUTH_HEADER))
        .and(body_json(json!({
            "name": "demo-web",
            "project": "demo",
            "target": "production",
            "gitSource": {
                "type": "github",
                "ref": "main",
                "repoId": "repo_123"
            }
        })))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(test_deployment("dpl_created", "QUEUED")),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v9/projects"))
        .and(query_param("limit", "2"))
        .and(query_param("teamId", TEAM_ID))
        .and(header("authorization", AUTH_HEADER))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "projects": [test_project("prj_123")],
            "pagination": { "count": 1 }
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v9/projects/demo"))
        .and(query_param("teamId", TEAM_ID))
        .and(header("authorization", AUTH_HEADER))
        .respond_with(ResponseTemplate::new(200).set_body_json(test_project("prj_123")))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v10/projects"))
        .and(query_param("teamId", TEAM_ID))
        .and(header("authorization", AUTH_HEADER))
        .and(body_json(json!({
            "name": "created-demo",
            "framework": "nextjs",
            "rootDirectory": "apps/web",
            "publicSource": false
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(test_project("prj_created")))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v9/projects/demo/domains"))
        .and(query_param("teamId", TEAM_ID))
        .and(header("authorization", AUTH_HEADER))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "domains": [test_domain()],
            "pagination": { "count": 1 }
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v10/projects/demo/domains"))
        .and(query_param("teamId", TEAM_ID))
        .and(header("authorization", AUTH_HEADER))
        .and(body_json(json!({
            "name": "demo.example.com",
            "gitBranch": "main",
            "redirect": "www.demo.example.com",
            "redirectStatusCode": 308
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(test_domain()))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v9/projects/demo/env"))
        .and(query_param("teamId", TEAM_ID))
        .and(header("authorization", AUTH_HEADER))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "envs": [test_env()],
            "pagination": { "count": 1 }
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v10/projects/demo/env"))
        .and(query_param("teamId", TEAM_ID))
        .and(header("authorization", AUTH_HEADER))
        .and(body_json(json!([{
            "key": "API_KEY",
            "value": "secret-value",
            "type": "encrypted",
            "target": ["production"],
            "gitBranch": "main",
            "customEnvironmentIds": ["env_prod"]
        }])))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([test_env()])))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v9/projects"))
        .and(query_param("limit", "1"))
        .and(query_param("teamId", TEAM_ID))
        .and(header("authorization", AUTH_HEADER))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "projects": [],
            "pagination": { "count": 0 }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = client(&server);

    let deployments = client
        .list_deployments(Some("prj_123"), Some(2))
        .await
        .expect("deployment list should decode");
    assert_eq!(deployments.deployments[0].id, "dpl_123");
    assert_eq!(
        deployments.deployments[0].ready_state.as_deref(),
        Some("READY")
    );

    let deployment = client
        .get_deployment("dpl_123")
        .await
        .expect("deployment detail should decode");
    assert_eq!(deployment.project_id.as_deref(), Some("prj_123"));

    let created_deployment = client
        .create_deployment(&CreateDeploymentRequest {
            name: "demo-web".into(),
            project: Some("demo".into()),
            target: Some("production".into()),
            git_source: Some(GitSource {
                source_type: "github".into(),
                git_ref: "main".into(),
                repo_id: Some("repo_123".into()),
                sha: None,
                project_id: None,
            }),
            meta: None,
        })
        .await
        .expect("deployment create should decode");
    assert_eq!(created_deployment.id, "dpl_created");
    assert_eq!(created_deployment.ready_state.as_deref(), Some("QUEUED"));

    let projects = client
        .list_projects(Some(2))
        .await
        .expect("project list should decode");
    assert_eq!(projects.projects[0].framework.as_deref(), Some("nextjs"));

    let project = client
        .get_project("demo")
        .await
        .expect("project detail should decode");
    assert_eq!(project.root_directory.as_deref(), Some("apps/web"));

    let created_project = client
        .create_project(&CreateProjectRequest {
            name: "created-demo".into(),
            framework: Some("nextjs".into()),
            root_directory: Some("apps/web".into()),
            public_source: Some(false),
            build_command: None,
            install_command: None,
            output_directory: None,
            dev_command: None,
        })
        .await
        .expect("project create should decode");
    assert_eq!(created_project.id, "prj_created");

    let domains = client
        .list_domains("demo")
        .await
        .expect("domain list should decode");
    assert_eq!(domains.domains[0].name, "demo.example.com");
    assert_eq!(domains.domains[0].verified, Some(true));

    let domain = client
        .add_domain(
            "demo",
            &AddDomainRequest {
                name: "demo.example.com".into(),
                git_branch: Some("main".into()),
                redirect: Some("www.demo.example.com".into()),
                redirect_status_code: Some(308),
            },
        )
        .await
        .expect("domain add should decode");
    assert_eq!(domain.apex_name.as_deref(), Some("example.com"));

    let env = client
        .list_env_vars("demo")
        .await
        .expect("env list should decode");
    assert_eq!(env.envs[0].key, "API_KEY");
    assert_eq!(env.envs[0].target, ["production"]);

    let created_env = client
        .create_env_vars(
            "demo",
            &[CreateEnvVarRequest {
                key: "API_KEY".into(),
                value: "secret-value".into(),
                env_type: "encrypted".into(),
                target: vec!["production".into()],
                git_branch: Some("main".into()),
                custom_environment_ids: vec!["env_prod".into()],
            }],
        )
        .await
        .expect("env create should decode");
    assert_eq!(created_env[0].configuration_id.as_deref(), Some("cfg_123"));

    client
        .health_check()
        .await
        .expect("health check should use scoped project probe");
}

#[fcp_async_core::runtime::test]
async fn destructive_delete_requests_use_expected_vercel_delete_shapes() {
    init_logging();
    tracing::info!(
        scenario = "vercel_destructive_request_shape",
        "starting Vercel destructive request-shape proof",
    );

    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v13/deployments/dpl_old"))
        .and(query_param("teamId", TEAM_ID))
        .and(header("authorization", AUTH_HEADER))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "uid": "dpl_old",
            "deleted": true
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("DELETE"))
        .and(path("/v9/projects/demo"))
        .and(query_param("teamId", TEAM_ID))
        .and(header("authorization", AUTH_HEADER))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("DELETE"))
        .and(path("/v10/projects/demo/domains/demo.example.com"))
        .and(query_param("teamId", TEAM_ID))
        .and(header("authorization", AUTH_HEADER))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "demo.example.com",
            "deleted": true
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("DELETE"))
        .and(path("/v9/projects/demo/env/env_123"))
        .and(query_param("teamId", TEAM_ID))
        .and(header("authorization", AUTH_HEADER))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "env_123",
            "deleted": true
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = client(&server);

    let deployment = client
        .delete_deployment("dpl_old")
        .await
        .expect("deployment delete should decode");
    assert_eq!(deployment.resource_id.as_deref(), Some("dpl_old"));
    assert!(deployment.deleted);

    client
        .delete_project("demo")
        .await
        .expect("project delete should accept empty success body");

    let domain = client
        .remove_domain("demo", "demo.example.com")
        .await
        .expect("domain remove should decode");
    assert_eq!(domain.resource_id.as_deref(), Some("demo.example.com"));
    assert!(domain.deleted);

    let env = client
        .delete_env_var("demo", "env_123")
        .await
        .expect("env delete should decode");
    assert_eq!(env.resource_id.as_deref(), Some("env_123"));
    assert!(env.deleted);
}

#[fcp_async_core::runtime::test]
async fn auth_missing_resource_rate_limit_malformed_json_and_invalid_input_are_typed() {
    init_logging();
    tracing::info!(
        scenario = "vercel_error_taxonomy",
        "starting Vercel error-taxonomy proof",
    );

    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v9/projects/auth-fails"))
        .and(query_param("teamId", TEAM_ID))
        .and(header("authorization", AUTH_HEADER))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": {
                "code": "unauthorized",
                "message": "invalid token"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v13/deployments/dpl_missing"))
        .and(query_param("teamId", TEAM_ID))
        .and(header("authorization", AUTH_HEADER))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": {
                "code": "not_found",
                "message": "deployment not found"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v9/projects/rate-limited/domains"))
        .and(query_param("teamId", TEAM_ID))
        .and(header("authorization", AUTH_HEADER))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "4")
                .set_body_json(json!({
                    "error": {
                        "code": "rate_limited",
                        "message": "too many requests"
                    }
                })),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v9/projects/bad-json/env"))
        .and(query_param("teamId", TEAM_ID))
        .and(header("authorization", AUTH_HEADER))
        .respond_with(ResponseTemplate::new(200).set_body_string("{this is not json"))
        .expect(1)
        .mount(&server)
        .await;

    let client = client(&server);

    let unauthorized = client
        .get_project("auth-fails")
        .await
        .expect_err("401 should map to unauthorized");
    assert!(matches!(unauthorized, VercelError::Unauthorized(_)));
    assert!(!unauthorized.is_retryable());

    let missing = client
        .get_deployment("dpl_missing")
        .await
        .expect_err("404 should map to not found");
    assert!(matches!(missing, VercelError::NotFound(_)));
    assert!(!missing.is_retryable());

    let rate_limited = client
        .list_domains("rate-limited")
        .await
        .expect_err("429 should map to rate limit");
    assert!(matches!(
        rate_limited,
        VercelError::RateLimited {
            retry_after_ms: 4_000
        }
    ));
    assert_eq!(rate_limited.retry_after(), Some(Duration::from_secs(4)));

    let malformed = client
        .list_env_vars("bad-json")
        .await
        .expect_err("malformed JSON should be typed");
    assert!(matches!(malformed, VercelError::Json(_)));
    assert!(!malformed.is_retryable());

    let traversal = client
        .get_project("../admin")
        .await
        .expect_err("path traversal should be rejected before outbound call");
    assert!(matches!(traversal, VercelError::Validation(_)));
}

#[fcp_async_core::runtime::test]
async fn slow_response_respects_bounded_request_timeout() {
    init_logging();
    tracing::info!(
        scenario = "vercel_timeout",
        "starting Vercel request-timeout proof",
    );

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v9/projects/slow"))
        .and(query_param("teamId", TEAM_ID))
        .and(header("authorization", AUTH_HEADER))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(150))
                .set_body_json(test_project("prj_slow")),
        )
        .mount(&server)
        .await;

    let client = client_with_timeout(&server, Duration::from_millis(25));
    let error = client
        .get_project("slow")
        .await
        .expect_err("slow response should respect client timeout");

    assert!(matches!(error, VercelError::Http(ref source) if source.is_timeout()));
    assert!(error.is_retryable());
}

#[test]
fn operation_catalog_preserves_risk_approval_and_event_metadata() {
    init_logging();

    let manifest = include_str!("../manifest.toml");
    assert!(manifest.contains("[sandbox]"));
    assert!(manifest.contains("profile = \"strict\""));
    assert!(manifest.contains("memory_mb = 128"));
    assert!(manifest.contains("cpu_percent = 25"));
    assert!(manifest.contains("wall_clock_timeout_ms = 60000"));
    assert!(manifest.contains("deny_exec = true"));
    assert!(manifest.contains("deny_ptrace = true"));

    let introspection = VercelConnector::new().introspect();
    assert!(introspection.events.is_empty());

    let operation = |id: &str| {
        introspection
            .operations
            .iter()
            .find(|entry| entry.id.as_str() == id)
            .expect("operation catalog should contain requested Vercel operation")
    };

    let deployments_create = operation("vercel.deployments.create");
    assert_eq!(deployments_create.risk_level, RiskLevel::High);
    assert_eq!(deployments_create.safety_tier, SafetyTier::Risky);
    assert_eq!(deployments_create.idempotency, IdempotencyClass::Strict);
    assert_eq!(deployments_create.requires_approval, None);

    let deployments_delete = operation("vercel.deployments.delete");
    assert_eq!(deployments_delete.risk_level, RiskLevel::High);
    assert_eq!(deployments_delete.safety_tier, SafetyTier::Dangerous);
    assert_eq!(deployments_delete.idempotency, IdempotencyClass::Strict);
    assert_eq!(
        deployments_delete.requires_approval,
        Some(ApprovalMode::Interactive)
    );

    let projects_delete = operation("vercel.projects.delete");
    assert_eq!(projects_delete.risk_level, RiskLevel::Critical);
    assert_eq!(projects_delete.safety_tier, SafetyTier::Dangerous);
    assert_eq!(projects_delete.idempotency, IdempotencyClass::Strict);
    assert_eq!(
        projects_delete.requires_approval,
        Some(ApprovalMode::Interactive)
    );

    let domains_remove = operation("vercel.domains.remove");
    assert_eq!(domains_remove.risk_level, RiskLevel::High);
    assert_eq!(domains_remove.safety_tier, SafetyTier::Dangerous);
    assert_eq!(
        domains_remove.requires_approval,
        Some(ApprovalMode::Interactive)
    );

    let env_create = operation("vercel.env.create");
    assert_eq!(env_create.risk_level, RiskLevel::Medium);
    assert_eq!(env_create.safety_tier, SafetyTier::Risky);
    assert_eq!(env_create.requires_approval, None);

    let projects_list = operation("vercel.projects.list");
    assert_eq!(projects_list.risk_level, RiskLevel::Low);
    assert_eq!(projects_list.safety_tier, SafetyTier::Safe);
    assert_eq!(projects_list.requires_approval, None);
}

#[test]
fn debug_output_redacts_vercel_secrets() {
    init_logging();

    let auth = VercelAuth::AccessToken {
        access_token: "super-secret-vercel-token".into(),
    };
    let debug_auth = format!("{auth:?}");
    assert!(!debug_auth.contains("super-secret-vercel-token"));
    assert!(debug_auth.contains("[REDACTED]"));

    let server = fcp_async_core::runtime::block_on_sync(MockServer::start())
        .expect("runtime should start wiremock");
    let client = VercelClient::new(
        VercelAuth::AccessToken {
            access_token: "super-secret-client-token".into(),
        },
        TeamScope::default(),
        no_retry_config(),
        Duration::from_millis(500),
    )
    .expect("redaction proof client should build")
    .with_base_url(&server.uri());

    let debug_client = format!("{client:?}");
    assert!(!debug_client.contains("super-secret-client-token"));
    assert!(debug_client.contains("[REDACTED]"));
}
