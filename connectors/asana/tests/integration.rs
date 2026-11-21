//! Integration tests for the FCP Asana connector.

#![allow(
    clippy::cast_possible_truncation,
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use std::collections::BTreeSet;

use fcp_core::{OperationId, OperationInfo, SafetyTier};
use fcp_manifest::{ConnectorManifest, ManifestApprovalMode, OperationContractSet};
use serde_json::{Value, json};
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_asana::connector::AsanaConnector;

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

async fn setup_connector(mock_url: &str) -> AsanaConnector {
    let mut c = AsanaConnector::new();
    c.handle_configure(json!({ "access_token": "1/test_pat_token_123", "base_url": mock_url }))
        .await
        .unwrap();
    c.handle_handshake(json!({"session_id": "test"}))
        .await
        .unwrap();
    c
}

// -- Lifecycle --

#[fcp_async_core::runtime::test]
async fn lifecycle_health_unconfigured() {
    let c = AsanaConnector::new();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "unconfigured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_full() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_before_configure_fails() {
    let mut c = AsanaConnector::new();
    assert!(c.handle_handshake(json!({})).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn lifecycle_reconfigure_invalidates_handshake() {
    let server = MockServer::start().await;
    let mut c = setup_connector(&server.uri()).await;
    c.handle_configure(json!({
        "access_token": "1/new_pat_token_456",
        "base_url": server.uri(),
    }))
    .await
    .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["configured"], true);
    assert_eq!(h["handshaken"], false);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_shutdown() {
    let server = MockServer::start().await;
    let mut c = setup_connector(&server.uri()).await;
    c.handle_shutdown(json!({})).await.unwrap();
    assert_eq!(c.handle_health().await.unwrap()["status"], "unconfigured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_self_check() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "ok");
    assert!(check.get("details").is_some());
    let provisioning = &check["details"]["provisioning"];
    assert_eq!(provisioning["auth_mode"], "personal_access_token");
    assert_eq!(provisioning["token_configured"], true);
    assert_eq!(provisioning["network_ok"], true);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert_eq!(c.handle_doctor().await.unwrap()["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_introspect() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    assert_eq!(intro["operations"].as_array().unwrap().len(), 10);
}

#[fcp_async_core::runtime::test]
async fn manifest_matches_runtime_operation_contracts() {
    let manifest = ConnectorManifest::parse_str(MANIFEST_TOML)
        .expect("Asana manifest and interface hash must validate");
    let server = MockServer::start().await;
    let mut connector = setup_connector(&server.uri()).await;
    let introspection = connector.handle_introspect().await.unwrap();
    let operations: Vec<OperationInfo> =
        serde_json::from_value(introspection["operations"].clone()).unwrap();
    let runtime_ids: BTreeSet<_> = operations.iter().map(|op| op.id.as_str()).collect();
    let manifest_ids: BTreeSet<_> = manifest
        .provides
        .operations
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(runtime_ids.len(), operations.len(), "unique runtime IDs");
    assert_eq!(runtime_ids, manifest_ids, "complete host-admitted catalog");
    assert_eq!(runtime_ids.len(), 10);

    let rate_limits = manifest.rate_limits.as_ref().unwrap();
    assert_eq!(rate_limits.operation_pools.len(), operations.len());
    for runtime in &operations {
        let id = runtime.id.as_str();
        let declared = manifest.provides.operations.get(id).unwrap();
        assert_eq!(declared.input_schema, runtime.input_schema, "{id} input");
        assert_eq!(declared.output_schema, runtime.output_schema, "{id} output");
        assert_eq!(declared.capability, runtime.capability, "{id} capability");
        assert_eq!(declared.risk_level, runtime.risk_level, "{id} risk");
        assert_eq!(declared.safety_tier, runtime.safety_tier, "{id} safety");
        assert_eq!(declared.idempotency, runtime.idempotency, "{id} replay");
        assert!(manifest.capabilities.optional.contains(&runtime.capability));
        let approval = match runtime.safety_tier {
            SafetyTier::Safe => ManifestApprovalMode::None,
            SafetyTier::Risky => ManifestApprovalMode::Policy,
            SafetyTier::Dangerous => ManifestApprovalMode::Interactive,
            other => panic!("review the approval contract for {id}: {other:?}"),
        };
        assert_eq!(declared.requires_approval, approval, "{id} approval");
        let pools = rate_limits.operation_pools.get(id).unwrap();
        assert_eq!(
            pools.iter().map(String::as_str).collect::<Vec<_>>(),
            vec![runtime.capability.as_str()],
            "{id} rate-limit coverage"
        );
        let network = declared.network_constraints.as_ref().unwrap();
        assert_eq!(network.host_allow, ["app.asana.com"]);
        assert_eq!(network.port_allow, [443]);
        assert!(network.require_sni && network.deny_localhost && network.deny_private_ranges);
        assert!(network.deny_tailnet_ranges && network.deny_ip_literals);
    }

    let handshake = connector
        .handle_handshake(json!({"session_id": "manifest-contract"}))
        .await
        .unwrap();
    let advertised: BTreeSet<_> = handshake["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .map(|capability| capability.as_str().unwrap())
        .collect();
    let declared: BTreeSet<_> = manifest
        .capabilities
        .optional
        .iter()
        .map(fcp_core::CapabilityId::as_str)
        .collect();
    assert_eq!(advertised, declared, "handshake and manifest authority");
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[test]
fn manifest_rejects_obsolete_gid_fields_and_invalid_operation_data() {
    let contracts = OperationContractSet::from_manifest_toml(MANIFEST_TOML)
        .expect("host operation validators must compile");
    for (id, valid, obsolete) in [
        (
            "asana.projects.list",
            json!({"workspace_gid": "123"}),
            json!({"workspace": "123"}),
        ),
        (
            "asana.tasks.list",
            json!({"project_gid": "123"}),
            json!({"project": "123"}),
        ),
        (
            "asana.tasks.delete",
            json!({"task_gid": "123"}),
            json!({"task": "123"}),
        ),
        (
            "asana.tasks.create",
            json!({"workspace": "123", "name": "Contract fixture"}),
            json!({"workspace_gid": "123", "name": "Contract fixture"}),
        ),
    ] {
        let operation = OperationId::from_static(id);
        contracts.validate_input(&operation, &valid).unwrap();
        assert!(
            contracts.validate_input(&operation, &obsolete).is_err(),
            "{id}"
        );
    }
    let search = OperationId::from_static("asana.tasks.search");
    for invalid in [
        json!({"workspace_gid": "123"}),
        json!({"workspace_gid": 123, "query": "contract"}),
        json!({"workspace_gid": "123", "query": []}),
    ] {
        assert!(contracts.validate_input(&search, &invalid).is_err());
    }
    for invalid in [json!({}), json!({"data": {}}), json!({"data": null})] {
        assert!(contracts.validate_result(&search, &invalid).is_err());
    }
    assert!(
        contracts
            .validate_input(&OperationId::from_static("asana.tasks.unknown"), &json!({}))
            .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn manifest_examples_execute_against_provider_contracts() {
    let manifest = ConnectorManifest::parse_str(MANIFEST_TOML).unwrap();
    let contracts = OperationContractSet::from_manifest(&manifest).unwrap();
    let server = MockServer::start().await;
    let connector = setup_connector(&server.uri()).await;

    for (id, declared) in &manifest.provides.operations {
        let operation: OperationId = id.parse().unwrap();
        let input: Value = serde_json::from_str(&declared.ai_hints.examples[0]).unwrap();
        let (verb, endpoint) = match id.as_str() {
            "asana.workspaces.list" => ("GET", "/workspaces"),
            "asana.projects.list" => ("GET", "/workspaces/1234567890/projects"),
            "asana.projects.get" => ("GET", "/projects/1234567890"),
            "asana.tasks.list" => ("GET", "/projects/1234567890/tasks"),
            "asana.tasks.get" => ("GET", "/tasks/1234567890"),
            "asana.tasks.create" => ("POST", "/tasks"),
            "asana.tasks.update" => ("PUT", "/tasks/1234567890"),
            "asana.tasks.delete" => ("DELETE", "/tasks/1234567890"),
            "asana.sections.list" => ("GET", "/projects/1234567890/sections"),
            "asana.tasks.search" => ("GET", "/workspaces/1234567890/tasks/search"),
            other => panic!("add a provider contract fixture for {other}"),
        };
        let expected = if id.ends_with(".list") || id.ends_with(".search") {
            json!({"data": [{"gid": "fixture-result", "name": "Contract fixture"}]})
        } else if id.ends_with(".delete") {
            json!({})
        } else {
            json!({"data": {"gid": "fixture-result", "name": "Contract fixture"}})
        };
        let mut provider = Mock::given(method(verb))
            .and(path(endpoint))
            .and(header("Authorization", "Bearer 1/test_pat_token_123"));
        if id == "asana.tasks.search" {
            provider = provider.and(query_param("text", "login bug"));
        } else if id == "asana.tasks.create" {
            provider = provider.and(body_json(json!({"data": {
                "workspace": "1234567890",
                "name": "Fix login timeout",
                "notes": "Users report 30s timeouts"
            }})));
        } else if id == "asana.tasks.update" {
            provider = provider.and(body_json(json!({"data": {"name": "Updated task name"}})));
        }
        provider
            .respond_with(ResponseTemplate::new(200).set_body_json(expected.clone()))
            .expect(1)
            .mount(&server)
            .await;

        contracts.validate_input(&operation, &input).unwrap();
        let result = connector
            .handle_invoke(json!({"operation_id": id, "input": input}))
            .await
            .unwrap();
        contracts.validate_result(&operation, &result).unwrap();
        assert_eq!(result, expected, "{id} provider result");
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 10);
}

// -- Workspaces List --

#[fcp_async_core::runtime::test]
async fn workspaces_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/workspaces"))
        .and(header("Authorization", "Bearer 1/test_pat_token_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {"gid": "ws1", "name": "My Workspace"},
                {"gid": "ws2", "name": "Another Workspace"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "asana.workspaces.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["data"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn workspaces_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/workspaces"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "asana.workspaces.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["data"].as_array().unwrap().is_empty());
}

// -- Projects List --

#[fcp_async_core::runtime::test]
async fn projects_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/workspaces/ws_123/projects"))
        .and(header("Authorization", "Bearer 1/test_pat_token_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {"gid": "p1", "name": "Backend Redesign"},
                {"gid": "p2", "name": "Mobile App"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "asana.projects.list",
            "input": {"workspace_gid": "ws_123"}
        }))
        .await
        .unwrap();
    assert_eq!(result["data"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn projects_list_missing_workspace_gid() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "asana.projects.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Projects Get --

#[fcp_async_core::runtime::test]
async fn projects_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/proj_456"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "gid": "proj_456",
                "name": "My Project",
                "notes": "Important project",
            }
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "asana.projects.get",
            "input": {"project_gid": "proj_456"}
        }))
        .await
        .unwrap();
    assert_eq!(result["data"]["gid"], "proj_456");
    assert_eq!(result["data"]["name"], "My Project");
}

#[fcp_async_core::runtime::test]
async fn projects_get_missing_project_gid() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "asana.projects.get",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Tasks List --

#[fcp_async_core::runtime::test]
async fn tasks_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/proj_789/tasks"))
        .and(header("Authorization", "Bearer 1/test_pat_token_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {"gid": "t1", "name": "Implement login"},
                {"gid": "t2", "name": "Write tests"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "asana.tasks.list",
            "input": {"project_gid": "proj_789"}
        }))
        .await
        .unwrap();
    assert_eq!(result["data"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn tasks_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/proj_789/tasks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "asana.tasks.list",
            "input": {"project_gid": "proj_789"}
        }))
        .await
        .unwrap();
    assert!(result["data"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn tasks_list_missing_project_gid() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "asana.tasks.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Tasks Get --

#[fcp_async_core::runtime::test]
async fn tasks_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/tasks/task_abc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "gid": "task_abc",
                "name": "Build the widget",
                "completed": false,
            }
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "asana.tasks.get",
            "input": {"task_gid": "task_abc"}
        }))
        .await
        .unwrap();
    assert_eq!(result["data"]["gid"], "task_abc");
    assert_eq!(result["data"]["completed"], false);
}

#[fcp_async_core::runtime::test]
async fn tasks_get_missing_task_gid() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "asana.tasks.get",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Tasks Create --

#[fcp_async_core::runtime::test]
async fn tasks_create() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/tasks"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "data": {
                "gid": "new_task_123",
                "name": "Implement login page",
            }
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "asana.tasks.create",
            "input": {
                "name": "Implement login page",
                "workspace": "ws_1"
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["data"]["gid"], "new_task_123");
}

#[fcp_async_core::runtime::test]
async fn tasks_create_missing_name() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "asana.tasks.create",
            "input": {"workspace": "ws_1"}
        }))
        .await
        .is_err()
    );
}

// -- Tasks Update --

#[fcp_async_core::runtime::test]
async fn tasks_update() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/tasks/task_xyz"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "gid": "task_xyz",
                "name": "Updated task name",
                "completed": true,
            }
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "asana.tasks.update",
            "input": {
                "task_gid": "task_xyz",
                "name": "Updated task name",
                "completed": true
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["data"]["gid"], "task_xyz");
    assert_eq!(result["data"]["completed"], true);
}

#[fcp_async_core::runtime::test]
async fn tasks_update_missing_task_gid() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "asana.tasks.update",
            "input": {"name": "Updated name"}
        }))
        .await
        .is_err()
    );
}

// -- Tasks Delete --

#[fcp_async_core::runtime::test]
async fn tasks_delete() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/tasks/task_del"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "asana.tasks.delete",
            "input": {"task_gid": "task_del"}
        }))
        .await
        .unwrap();
    assert!(result.is_object());
}

#[fcp_async_core::runtime::test]
async fn tasks_delete_missing_task_gid() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "asana.tasks.delete",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Sections List --

#[fcp_async_core::runtime::test]
async fn sections_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/proj_789/sections"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {"gid": "sec1", "name": "To Do"},
                {"gid": "sec2", "name": "In Progress"},
                {"gid": "sec3", "name": "Done"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "asana.sections.list",
            "input": {"project_gid": "proj_789"}
        }))
        .await
        .unwrap();
    assert_eq!(result["data"].as_array().unwrap().len(), 3);
}

#[fcp_async_core::runtime::test]
async fn sections_list_missing_project_gid() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "asana.sections.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Tasks Search --

#[fcp_async_core::runtime::test]
async fn tasks_search() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/workspaces/ws_123/tasks/search"))
        .and(query_param("text", "login bug"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {"gid": "t1", "name": "Fix login bug"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "asana.tasks.search",
            "input": {"workspace_gid": "ws_123", "query": "login bug"}
        }))
        .await
        .unwrap();
    assert_eq!(result["data"].as_array().unwrap().len(), 1);
    assert_eq!(result["data"][0]["name"], "Fix login bug");
}

#[fcp_async_core::runtime::test]
async fn tasks_search_missing_workspace_gid() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "asana.tasks.search",
            "input": {"query": "test"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn tasks_search_missing_query() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "asana.tasks.search",
            "input": {"workspace_gid": "ws_123"}
        }))
        .await
        .is_err()
    );
}

// -- Error handling --

#[fcp_async_core::runtime::test]
async fn error_401() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/workspaces"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "errors": [{"message": "Not Authorized"}]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "asana.workspaces.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_403() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/workspaces"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "errors": [{"message": "Forbidden"}]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "asana.workspaces.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_404() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/tasks/missing_task"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "errors": [{"message": "task: Unknown object: missing_task"}]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "asana.tasks.get",
            "input": {"task_gid": "missing_task"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/workspaces"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({
                    "errors": [{"message": "Rate limit enforced"}]
                }))
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "asana.workspaces.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_500() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/proj_789/tasks"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "asana.tasks.list",
            "input": {"project_gid": "proj_789"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_200_empty_body_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/workspaces"))
        .and(header("Authorization", "Bearer 1/test_pat_token_123"))
        .respond_with(ResponseTemplate::new(200).set_body_string(""))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "asana.workspaces.list",
            "input": {}
        }))
        .await
        .is_ok()
    );
}

// -- Unknown op / Simulate --

#[fcp_async_core::runtime::test]
async fn unknown_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "asana.nope",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "asana.tasks.list"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_unknown() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        !c.handle_simulate(json!({"operation_id": "asana.nope"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

// -- Counters --

#[fcp_async_core::runtime::test]
async fn counters_increment() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/workspaces"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "asana.workspaces.list",
        "input": {}
    }))
    .await
    .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 0);
}

#[fcp_async_core::runtime::test]
async fn counters_error_increment() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/workspaces"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "asana.workspaces.list",
            "input": {}
        }))
        .await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 1);
}
