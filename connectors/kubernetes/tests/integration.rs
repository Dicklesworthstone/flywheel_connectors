//! Integration tests for the FCP Kubernetes connector.

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

use serde_json::json;
use wiremock::matchers::{header, method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

mod common;
use common::TestConnector as KubernetesConnector;

async fn setup_connector(mock_url: &str) -> KubernetesConnector {
    setup_connector_with_config(mock_url, json!({})).await
}

async fn setup_connector_with_config(
    mock_url: &str,
    extra_config: serde_json::Value,
) -> KubernetesConnector {
    let mut c = KubernetesConnector::new();
    let mut config = json!({
        "bearer_token": "test-k8s-token",
        "base_url": mock_url,
        "allow_write_operations": true,
        "allow_pod_exec": true,
        "allowed_namespaces": ["default", "production"],
    });
    if let (Some(target), Some(extra)) = (config.as_object_mut(), extra_config.as_object()) {
        for (key, value) in extra {
            target.insert(key.clone(), value.clone());
        }
    }
    c.handle_configure(config).await.unwrap();
    c.handle_handshake(json!({"session_id": "test"}))
        .await
        .unwrap();
    c
}

// -- Lifecycle --

#[fcp_async_core::runtime::test]
async fn lifecycle_health_unconfigured() {
    let c = KubernetesConnector::new();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"]["state"], "degraded");
    assert_eq!(h["details"]["configured"], false);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_full() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert_eq!(c.handle_health().await.unwrap()["status"]["state"], "ready");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_before_configure_fails() {
    let mut c = KubernetesConnector::new();
    assert!(c.handle_handshake(json!({})).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn lifecycle_shutdown() {
    let server = MockServer::start().await;
    let mut c = setup_connector(&server.uri()).await;
    c.handle_shutdown(json!({})).await.unwrap();
    assert_eq!(
        c.handle_health().await.unwrap()["details"]["configured"],
        false
    );
}

#[fcp_async_core::runtime::test]
async fn lifecycle_self_check() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert_eq!(c.handle_self_check().await.unwrap()["status"], "ok");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert_eq!(c.handle_doctor().await.unwrap()["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_write_without_namespace_scope() {
    let server = MockServer::start().await;
    let mut c = KubernetesConnector::new();
    assert!(
        c.handle_configure(json!({
            "bearer_token": "test-k8s-token",
            "base_url": server.uri(),
            "allow_write_operations": true
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_exec_without_namespace_scope() {
    let server = MockServer::start().await;
    let mut c = KubernetesConnector::new();
    assert!(
        c.handle_configure(json!({
            "bearer_token": "test-k8s-token",
            "base_url": server.uri(),
            "allow_pod_exec": true
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn default_policy_denies_write_operations() {
    let server = MockServer::start().await;
    let mut c = KubernetesConnector::new();
    c.handle_configure(json!({
        "bearer_token": "test-k8s-token",
        "base_url": server.uri()
    }))
    .await
    .unwrap();
    c.handle_handshake(json!({"session_id": "test"}))
        .await
        .unwrap();
    assert!(
        c.handle_invoke(json!({
            "operation_id": "kubernetes.create_pod",
            "input": {
                "namespace": "default",
                "name": "debug-pod",
                "spec": {
                    "containers": [{"name": "debug", "image": "busybox"}]
                }
            }
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn default_policy_denies_exec() {
    let server = MockServer::start().await;
    let mut c = KubernetesConnector::new();
    c.handle_configure(json!({
        "bearer_token": "test-k8s-token",
        "base_url": server.uri()
    }))
    .await
    .unwrap();
    c.handle_handshake(json!({"session_id": "test"}))
        .await
        .unwrap();
    assert!(
        c.handle_invoke(json!({
            "operation_id": "kubernetes.exec",
            "input": {
                "namespace": "default",
                "name": "debug-pod",
                "command": ["ls"]
            }
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn lifecycle_introspect() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    assert_eq!(intro["operations"].as_array().unwrap().len(), 31);
}

// -- list_pods --

#[fcp_async_core::runtime::test]
async fn list_pods() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/default/pods"))
        .and(header("Authorization", "Bearer test-k8s-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "PodList",
            "items": [
                {"metadata": {"name": "nginx-abc123"}, "status": {"phase": "Running"}},
                {"metadata": {"name": "redis-xyz789"}, "status": {"phase": "Running"}},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(
            json!({"operation_id": "kubernetes.list_pods", "input": {"namespace": "default"}}),
        )
        .await
        .unwrap();
    assert_eq!(result["pods"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn list_pods_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/production/pods"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"kind": "PodList", "items": []})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(
            json!({"operation_id": "kubernetes.list_pods", "input": {"namespace": "production"}}),
        )
        .await
        .unwrap();
    assert!(result["pods"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn list_pods_missing_namespace() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({"operation_id": "kubernetes.list_pods", "input": {}}))
            .await
            .is_err()
    );
}

// -- get_pod --

#[fcp_async_core::runtime::test]
async fn get_pod() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/default/pods/nginx-abc123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "Pod", "metadata": {"name": "nginx-abc123"}, "status": {"phase": "Running"}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c.handle_invoke(json!({"operation_id": "kubernetes.get_pod", "input": {"namespace": "default", "name": "nginx-abc123"}})).await.unwrap();
    assert_eq!(result["pod"]["metadata"]["name"], "nginx-abc123");
}

#[fcp_async_core::runtime::test]
async fn get_pod_missing_namespace() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({"operation_id": "kubernetes.get_pod", "input": {"name": "nginx"}}))
            .await
            .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn get_pod_missing_name() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(
            json!({"operation_id": "kubernetes.get_pod", "input": {"namespace": "default"}})
        )
        .await
        .is_err()
    );
}

// -- delete_pod --

#[fcp_async_core::runtime::test]
async fn delete_pod() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/api/v1/namespaces/default/pods/nginx-abc123"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"kind": "Status", "status": "Success"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c.handle_invoke(json!({"operation_id": "kubernetes.delete_pod", "input": {"namespace": "default", "name": "nginx-abc123"}})).await.unwrap();
    assert_eq!(result["deleted"], true);
}

#[fcp_async_core::runtime::test]
async fn delete_pod_missing_name() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(
            json!({"operation_id": "kubernetes.delete_pod", "input": {"namespace": "default"}})
        )
        .await
        .is_err()
    );
}

// -- get_pod_logs --

#[fcp_async_core::runtime::test]
async fn get_pod_logs() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(
            r"/api/v1/namespaces/default/pods/nginx-abc123/log.*",
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("Starting nginx\nReady to accept connections"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c.handle_invoke(json!({"operation_id": "kubernetes.get_pod_logs", "input": {"namespace": "default", "name": "nginx-abc123", "tail_lines": 100}})).await.unwrap();
    assert!(result["logs"].as_str().unwrap().contains("Starting nginx"));
}

#[fcp_async_core::runtime::test]
async fn get_pod_logs_missing_namespace() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(
            json!({"operation_id": "kubernetes.get_pod_logs", "input": {"name": "nginx"}})
        )
        .await
        .is_err()
    );
}

// -- stream_pod_logs --

#[fcp_async_core::runtime::test]
async fn stream_pod_logs() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(
            r"/api/v1/namespaces/default/pods/nginx-abc123/log.*",
        ))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("live log line 1\nlive log line 2"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c.handle_invoke(json!({"operation_id": "kubernetes.stream_pod_logs", "input": {"namespace": "default", "name": "nginx-abc123"}})).await.unwrap();
    assert!(
        result["log_line"]
            .as_str()
            .unwrap()
            .contains("live log line")
    );
}

// -- list_deployments --

#[fcp_async_core::runtime::test]
async fn list_deployments() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/apis/apps/v1/namespaces/default/deployments"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "DeploymentList",
            "items": [{"metadata": {"name": "web-app"}, "spec": {"replicas": 3}}]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c.handle_invoke(json!({"operation_id": "kubernetes.list_deployments", "input": {"namespace": "default"}})).await.unwrap();
    assert_eq!(result["deployments"].as_array().unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn list_deployments_missing_namespace() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({"operation_id": "kubernetes.list_deployments", "input": {}}))
            .await
            .is_err()
    );
}

// -- get_deployment --

#[fcp_async_core::runtime::test]
async fn get_deployment() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/apis/apps/v1/namespaces/default/deployments/web-app"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"kind": "Deployment", "metadata": {"name": "web-app"}, "spec": {"replicas": 3}}),
        ))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c.handle_invoke(json!({"operation_id": "kubernetes.get_deployment", "input": {"namespace": "default", "name": "web-app"}})).await.unwrap();
    assert_eq!(result["deployment"]["metadata"]["name"], "web-app");
}

// -- scale_deployment --

#[fcp_async_core::runtime::test]
async fn scale_deployment() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path(
            "/apis/apps/v1/namespaces/default/deployments/web-app/scale",
        ))
        .and(header(
            "Content-Type",
            "application/strategic-merge-patch+json",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"kind": "Scale", "spec": {"replicas": 5}, "status": {"replicas": 5}}),
        ))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c.handle_invoke(json!({"operation_id": "kubernetes.scale_deployment", "input": {"namespace": "default", "name": "web-app", "replicas": 5}})).await.unwrap();
    assert_eq!(result["deployment"]["spec"]["replicas"], 5);
}

#[fcp_async_core::runtime::test]
async fn scale_deployment_missing_replicas() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(c.handle_invoke(json!({"operation_id": "kubernetes.scale_deployment", "input": {"namespace": "default", "name": "web-app"}})).await.is_err());
}

// -- rollout_restart --

#[fcp_async_core::runtime::test]
async fn rollout_restart() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/apis/apps/v1/namespaces/default/deployments/web-app"))
        .and(header(
            "Content-Type",
            "application/strategic-merge-patch+json",
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"kind": "Deployment", "metadata": {"name": "web-app"}})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c.handle_invoke(json!({"operation_id": "kubernetes.rollout_restart", "input": {"namespace": "default", "name": "web-app"}})).await.unwrap();
    assert_eq!(result["deployment"]["metadata"]["name"], "web-app");
}

#[fcp_async_core::runtime::test]
async fn rollout_restart_missing_name() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(
            json!({"operation_id": "kubernetes.rollout_restart", "input": {"namespace": "default"}})
        )
        .await
        .is_err()
    );
}

// -- get_service --

#[fcp_async_core::runtime::test]
async fn get_service() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/default/services/api-server"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"kind": "Service", "metadata": {"name": "api-server"}, "spec": {"type": "ClusterIP"}})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c.handle_invoke(json!({"operation_id": "kubernetes.get_service", "input": {"namespace": "default", "name": "api-server"}})).await.unwrap();
    assert_eq!(result["service"]["metadata"]["name"], "api-server");
}

// -- get_configmap --

#[fcp_async_core::runtime::test]
async fn get_configmap() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/default/configmaps/app-config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"kind": "ConfigMap", "metadata": {"name": "app-config"}, "data": {"LOG_LEVEL": "info"}})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c.handle_invoke(json!({"operation_id": "kubernetes.get_configmap", "input": {"namespace": "default", "name": "app-config"}})).await.unwrap();
    assert_eq!(result["configmap"]["data"]["LOG_LEVEL"], "info");
}

// -- update_configmap --

#[fcp_async_core::runtime::test]
async fn update_configmap() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/api/v1/namespaces/default/configmaps/app-config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"kind": "ConfigMap", "metadata": {"name": "app-config"}, "data": {"LOG_LEVEL": "debug"}})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c.handle_invoke(json!({"operation_id": "kubernetes.update_configmap", "input": {"namespace": "default", "name": "app-config", "data": {"LOG_LEVEL": "debug"}}})).await.unwrap();
    assert_eq!(result["configmap"]["data"]["LOG_LEVEL"], "debug");
}

#[fcp_async_core::runtime::test]
async fn update_configmap_missing_data() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(c.handle_invoke(json!({"operation_id": "kubernetes.update_configmap", "input": {"namespace": "default", "name": "app-config"}})).await.is_err());
}

// -- get_secret --

#[fcp_async_core::runtime::test]
async fn get_secret_redacted() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/default/secrets/db-credentials"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "Secret", "metadata": {"name": "db-credentials"}, "type": "Opaque",
            "data": {"username": "YWRtaW4=", "password": "c2VjcmV0"}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c.handle_invoke(json!({"operation_id": "kubernetes.get_secret", "input": {"namespace": "default", "name": "db-credentials"}})).await.unwrap();
    assert!(result["secret"]["data"].is_null());
    assert_eq!(result["secret"]["data_keys"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn get_secret_unmasked() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/default/secrets/db-credentials"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "Secret", "metadata": {"name": "db-credentials"},
            "data": {"username": "YWRtaW4=", "password": "c2VjcmV0"}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c.handle_invoke(json!({"operation_id": "kubernetes.get_secret", "input": {"namespace": "default", "name": "db-credentials", "unmask": true}})).await.unwrap();
    assert!(result["secret"]["data"].is_object());
}

// -- watch_events --

#[fcp_async_core::runtime::test]
async fn watch_events() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/default/events"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "EventList",
            "items": [{"reason": "Pulled", "message": "Successfully pulled image", "type": "Normal"}]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(
            json!({"operation_id": "kubernetes.watch_events", "input": {"namespace": "default"}}),
        )
        .await
        .unwrap();
    assert_eq!(result["events"].as_array().unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn watch_events_missing_namespace() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({"operation_id": "kubernetes.watch_events", "input": {}}))
            .await
            .is_err()
    );
}

// -- create_pod --

#[fcp_async_core::runtime::test]
async fn create_pod() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/namespaces/default/pods"))
        .and(header("Content-Type", "application/json"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "kind": "Pod",
            "metadata": {"name": "debug-pod", "namespace": "default"},
            "spec": {"containers": [{"name": "debug", "image": "busybox"}]}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "kubernetes.create_pod",
            "input": {
                "namespace": "default",
                "name": "debug-pod",
                "spec": {"containers": [{"name": "debug", "image": "busybox"}]}
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["pod"]["metadata"]["name"], "debug-pod");
}

#[fcp_async_core::runtime::test]
async fn create_pod_with_labels() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/namespaces/default/pods"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "kind": "Pod",
            "metadata": {"name": "labeled-pod", "namespace": "default", "labels": {"app": "test"}},
            "spec": {"containers": [{"name": "app", "image": "nginx"}]}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "kubernetes.create_pod",
            "input": {
                "namespace": "default",
                "name": "labeled-pod",
                "spec": {"containers": [{"name": "app", "image": "nginx"}]},
                "labels": {"app": "test"}
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["pod"]["metadata"]["name"], "labeled-pod");
}

#[fcp_async_core::runtime::test]
async fn create_pod_missing_spec() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "kubernetes.create_pod",
            "input": {"namespace": "default", "name": "test-pod"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn create_pod_missing_namespace() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "kubernetes.create_pod",
            "input": {"name": "test-pod", "spec": {"containers": []}}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn create_pod_rejects_host_network_injection() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "kubernetes.create_pod",
            "input": {
                "namespace": "default",
                "name": "host-net-pod",
                "spec": {
                    "hostNetwork": true,
                    "containers": [{"name": "debug", "image": "busybox"}]
                }
            }
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn create_pod_rejects_service_account_injection() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "kubernetes.create_pod",
            "input": {
                "namespace": "default",
                "name": "sa-pod",
                "spec": {
                    "serviceAccountName": "cluster-admin",
                    "containers": [{"name": "debug", "image": "busybox"}]
                }
            }
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn create_pod_rejects_projected_service_account_token_volume() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "kubernetes.create_pod",
            "input": {
                "namespace": "default",
                "name": "projected-token-pod",
                "spec": {
                    "volumes": [{
                        "name": "service-account-token",
                        "projected": {
                            "sources": [{
                                "serviceAccountToken": {"path": "token"}
                            }]
                        }
                    }],
                    "containers": [{
                        "name": "debug",
                        "image": "busybox",
                        "volumeMounts": [{
                            "name": "service-account-token",
                            "mountPath": "/var/run/secrets/tokens"
                        }]
                    }]
                }
            }
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn create_pod_rejects_host_port_binding() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "kubernetes.create_pod",
            "input": {
                "namespace": "default",
                "name": "host-port-pod",
                "spec": {
                    "containers": [{
                        "name": "debug",
                        "image": "busybox",
                        "ports": [{"containerPort": 8080, "hostPort": 8080}]
                    }]
                }
            }
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn create_pod_rejects_added_capabilities() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "kubernetes.create_pod",
            "input": {
                "namespace": "default",
                "name": "cap-add-pod",
                "spec": {
                    "containers": [{
                        "name": "debug",
                        "image": "busybox",
                        "securityContext": {
                            "capabilities": {"add": ["NET_ADMIN"]}
                        }
                    }]
                }
            }
        }))
        .await
        .is_err()
    );
}

// -- apply_deployment --

#[fcp_async_core::runtime::test]
async fn apply_deployment_create() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/apis/apps/v1/namespaces/default/deployments"))
        .and(header("Content-Type", "application/json"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "kind": "Deployment",
            "metadata": {"name": "web-app", "namespace": "default"},
            "spec": {"replicas": 3}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c.handle_invoke(json!({
        "operation_id": "kubernetes.apply_deployment",
        "input": {
            "namespace": "default",
            "name": "web-app",
            "spec": {"replicas": 3, "selector": {"matchLabels": {"app": "web"}}, "template": {"metadata": {"labels": {"app": "web"}}, "spec": {"containers": [{"name": "web", "image": "nginx"}]}}}
        }
    })).await.unwrap();
    assert_eq!(result["deployment"]["metadata"]["name"], "web-app");
}

#[fcp_async_core::runtime::test]
async fn apply_deployment_update() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/apis/apps/v1/namespaces/default/deployments/web-app"))
        .and(header("Content-Type", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "Deployment",
            "metadata": {"name": "web-app", "namespace": "default"},
            "spec": {"replicas": 5}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c.handle_invoke(json!({
        "operation_id": "kubernetes.apply_deployment",
        "input": {
            "namespace": "default",
            "name": "web-app",
            "update": true,
            "spec": {"replicas": 5, "selector": {"matchLabels": {"app": "web"}}, "template": {"metadata": {"labels": {"app": "web"}}, "spec": {"containers": [{"name": "web", "image": "nginx:1.26"}]}}}
        }
    })).await.unwrap();
    assert_eq!(result["deployment"]["spec"]["replicas"], 5);
}

#[fcp_async_core::runtime::test]
async fn apply_deployment_missing_spec() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "kubernetes.apply_deployment",
            "input": {"namespace": "default", "name": "web-app"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn apply_deployment_missing_name() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "kubernetes.apply_deployment",
            "input": {"namespace": "default", "spec": {"replicas": 1}}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn apply_deployment_rejects_host_path_template() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "kubernetes.apply_deployment",
            "input": {
                "namespace": "default",
                "name": "hostpath-app",
                "spec": {
                    "replicas": 1,
                    "selector": {"matchLabels": {"app": "hostpath-app"}},
                    "template": {
                        "metadata": {"labels": {"app": "hostpath-app"}},
                        "spec": {
                            "volumes": [{"name": "host-root", "hostPath": {"path": "/"}}],
                            "containers": [{
                                "name": "web",
                                "image": "nginx",
                                "volumeMounts": [{"name": "host-root", "mountPath": "/host"}]
                            }]
                        }
                    }
                }
            }
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn apply_deployment_rejects_privileged_container() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "kubernetes.apply_deployment",
            "input": {
                "namespace": "default",
                "name": "privileged-app",
                "spec": {
                    "replicas": 1,
                    "selector": {"matchLabels": {"app": "privileged-app"}},
                    "template": {
                        "metadata": {"labels": {"app": "privileged-app"}},
                        "spec": {
                            "containers": [{
                                "name": "web",
                                "image": "nginx",
                                "securityContext": {"privileged": true}
                            }]
                        }
                    }
                }
            }
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn rollout_rollback_rejects_unsafe_template() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "kubernetes.rollout.rollback",
            "input": {
                "namespace": "default",
                "name": "api-server",
                "template": {
                    "spec": {
                        "containers": [{
                            "name": "api",
                            "image": "api:v1.2.3",
                            "securityContext": {"allowPrivilegeEscalation": true}
                        }]
                    }
                }
            }
        }))
        .await
        .is_err()
    );
}

// -- delete_deployment --

#[fcp_async_core::runtime::test]
async fn delete_deployment() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/apis/apps/v1/namespaces/default/deployments/old-app"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"kind": "Status", "status": "Success"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "kubernetes.delete_deployment",
            "input": {"namespace": "default", "name": "old-app"}
        }))
        .await
        .unwrap();
    assert_eq!(result["deleted"], true);
}

#[fcp_async_core::runtime::test]
async fn delete_deployment_missing_name() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "kubernetes.delete_deployment",
            "input": {"namespace": "default"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn delete_deployment_missing_namespace() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "kubernetes.delete_deployment",
            "input": {"name": "old-app"}
        }))
        .await
        .is_err()
    );
}

// -- list_services --

#[fcp_async_core::runtime::test]
async fn list_services() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/default/services"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "ServiceList",
            "items": [
                {"metadata": {"name": "api-server"}, "spec": {"type": "ClusterIP"}},
                {"metadata": {"name": "frontend"}, "spec": {"type": "NodePort"}},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "kubernetes.list_services",
            "input": {"namespace": "default"}
        }))
        .await
        .unwrap();
    assert_eq!(result["services"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn list_services_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/production/services"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "ServiceList", "items": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "kubernetes.list_services",
            "input": {"namespace": "production"}
        }))
        .await
        .unwrap();
    assert!(result["services"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn list_services_missing_namespace() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "kubernetes.list_services",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- simulate new ops --

#[fcp_async_core::runtime::test]
async fn simulate_create_pod() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "kubernetes.create_pod"}))
            .await
            .unwrap()["would_succeed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_apply_deployment() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "kubernetes.apply_deployment"}))
            .await
            .unwrap()["would_succeed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_delete_deployment() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "kubernetes.delete_deployment"}))
            .await
            .unwrap()["would_succeed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_list_services() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "kubernetes.list_services"}))
            .await
            .unwrap()["would_succeed"]
            .as_bool()
            .unwrap()
    );
}

// -- Error handling --

#[fcp_async_core::runtime::test]
async fn error_401() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/default/pods"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(json!({"kind": "Status", "message": "Unauthorized", "code": 401})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(
            json!({"operation_id": "kubernetes.list_pods", "input": {"namespace": "default"}})
        )
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_403() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/kube-system/pods"))
        .respond_with(
            ResponseTemplate::new(403).set_body_json(
                json!({"kind": "Status", "message": "pods is forbidden", "code": 403}),
            ),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(
            json!({"operation_id": "kubernetes.list_pods", "input": {"namespace": "kube-system"}})
        )
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_404() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/default/pods/missing-pod"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"kind": "Status", "message": "pods not found", "code": 404})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(c.handle_invoke(json!({"operation_id": "kubernetes.get_pod", "input": {"namespace": "default", "name": "missing-pod"}})).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/default/pods"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(
                    json!({"kind": "Status", "message": "Too many requests", "code": 429}),
                )
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(
            json!({"operation_id": "kubernetes.list_pods", "input": {"namespace": "default"}})
        )
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_500() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/default/pods"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(
            json!({"operation_id": "kubernetes.list_pods", "input": {"namespace": "default"}})
        )
        .await
        .is_err()
    );
}

// -- Unknown op / Simulate --

#[fcp_async_core::runtime::test]
async fn unknown_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({"operation_id": "kubernetes.nope", "input": {}}))
            .await
            .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "kubernetes.list_pods"}))
            .await
            .unwrap()["would_succeed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_unknown() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        !c.handle_simulate(json!({"operation_id": "kubernetes.nope"}))
            .await
            .unwrap()["would_succeed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_delete_pod() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "kubernetes.delete_pod"}))
            .await
            .unwrap()["would_succeed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_get_secret() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "kubernetes.get_secret"}))
            .await
            .unwrap()["would_succeed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_watch_events() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "kubernetes.watch_events"}))
            .await
            .unwrap()["would_succeed"]
            .as_bool()
            .unwrap()
    );
}

// -- Counters --

#[fcp_async_core::runtime::test]
async fn counters_increment() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/default/pods"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"kind": "PodList", "items": []})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(
        json!({"operation_id": "kubernetes.list_pods", "input": {"namespace": "default"}}),
    )
    .await
    .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["details"]["requests"], 1);
    assert_eq!(h["details"]["errors"], 0);
}

#[fcp_async_core::runtime::test]
async fn counters_error_increment() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/default/pods"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(
            json!({"operation_id": "kubernetes.list_pods", "input": {"namespace": "default"}}),
        )
        .await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["details"]["requests"], 1);
    assert_eq!(h["details"]["errors"], 1);
}

// ── Feature 2: Exec ──────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn exec_command() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/default/pods/debug-pod"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "Pod",
            "metadata": {
                "name": "debug-pod",
                "labels": {"fcp.flywheel.ai/exec-approved": "true"}
            },
            "spec": {
                "containers": [{"name": "debug", "image": "busybox"}]
            }
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(
            r"/api/v1/namespaces/default/pods/debug-pod/exec.*",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "stdout": "total 4\ndrwxr-xr-x 2 root root 4096 Jan 1 00:00 app\n",
            "stderr": "",
            "exit_code": 0
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "kubernetes.exec",
            "input": {
                "namespace": "default",
                "name": "debug-pod",
                "command": ["ls", "-la", "/app"]
            }
        }))
        .await
        .unwrap();
    assert!(
        result["exec_result"]["stdout"]
            .as_str()
            .unwrap()
            .contains("app")
    );
    assert_eq!(result["exec_result"]["exit_code"], 0);
}

#[fcp_async_core::runtime::test]
async fn exec_with_container() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/default/pods/multi-pod"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "Pod",
            "metadata": {
                "name": "multi-pod",
                "labels": {"fcp.flywheel.ai/exec-approved": "true"}
            },
            "spec": {
                "containers": [
                    {"name": "app", "image": "nginx"},
                    {"name": "sidecar", "image": "busybox"}
                ]
            }
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(
            r"/api/v1/namespaces/default/pods/multi-pod/exec.*",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "stdout": "hello\n",
            "stderr": "",
            "exit_code": 0
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "kubernetes.exec",
            "input": {
                "namespace": "default",
                "name": "multi-pod",
                "container": "sidecar",
                "command": ["echo", "hello"]
            }
        }))
        .await
        .unwrap();
    assert!(
        result["exec_result"]["stdout"]
            .as_str()
            .unwrap()
            .contains("hello")
    );
}

#[fcp_async_core::runtime::test]
async fn exec_missing_command() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "kubernetes.exec",
            "input": {"namespace": "default", "name": "debug-pod"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn exec_empty_command() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "kubernetes.exec",
            "input": {"namespace": "default", "name": "debug-pod", "command": []}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn exec_missing_namespace() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "kubernetes.exec",
            "input": {"name": "debug-pod", "command": ["ls"]}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn exec_missing_name() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "kubernetes.exec",
            "input": {"namespace": "default", "command": ["ls"]}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_exec() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "kubernetes.exec"}))
            .await
            .unwrap()["would_succeed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn exec_rejects_unapproved_target_pod() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/default/pods/debug-pod"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "Pod",
            "metadata": {"name": "debug-pod", "labels": {"app": "debug"}},
            "spec": {"containers": [{"name": "debug", "image": "busybox"}]}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "kubernetes.exec",
            "input": {
                "namespace": "default",
                "name": "debug-pod",
                "command": ["ls", "/app"]
            }
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn exec_rejects_shell_trampoline() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "kubernetes.exec",
            "input": {
                "namespace": "default",
                "name": "debug-pod",
                "command": ["sh", "-c", "id"]
            }
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn exec_rejects_system_namespaces() {
    let server = MockServer::start().await;
    let c = setup_connector_with_config(
        &server.uri(),
        json!({"allowed_namespaces": ["default", "production", "kube-system"]}),
    )
    .await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "kubernetes.exec",
            "input": {
                "namespace": "kube-system",
                "name": "coredns",
                "command": ["cat", "/etc/resolv.conf"]
            }
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn exec_rejects_hostpath_target_pod() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/default/pods/debug-pod"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "Pod",
            "metadata": {
                "name": "debug-pod",
                "labels": {"fcp.flywheel.ai/exec-approved": "true"}
            },
            "spec": {
                "volumes": [{"name": "host-root", "hostPath": {"path": "/"}}],
                "containers": [{"name": "debug", "image": "busybox"}]
            }
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "kubernetes.exec",
            "input": {
                "namespace": "default",
                "name": "debug-pod",
                "command": ["ls", "/app"]
            }
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn exec_rejects_privileged_target_pod() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/default/pods/debug-pod"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "Pod",
            "metadata": {
                "name": "debug-pod",
                "labels": {"fcp.flywheel.ai/exec-approved": "true"}
            },
            "spec": {
                "containers": [{
                    "name": "debug",
                    "image": "busybox",
                    "securityContext": {"privileged": true}
                }]
            }
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "kubernetes.exec",
            "input": {
                "namespace": "default",
                "name": "debug-pod",
                "command": ["ls", "/app"]
            }
        }))
        .await
        .is_err()
    );
}

// ── Feature 3: ConfigMap CRUD ────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn configmap_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/default/configmaps"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "ConfigMapList",
            "items": [
                {"metadata": {"name": "app-config"}, "data": {"KEY": "value"}},
                {"metadata": {"name": "nginx-config"}, "data": {"nginx.conf": "server {}"}}
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "kubernetes.configmap.list",
            "input": {"namespace": "default"}
        }))
        .await
        .unwrap();
    assert_eq!(result["configmaps"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn configmap_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/production/configmaps"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "ConfigMapList", "items": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "kubernetes.configmap.list",
            "input": {"namespace": "production"}
        }))
        .await
        .unwrap();
    assert!(result["configmaps"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn configmap_list_missing_namespace() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "kubernetes.configmap.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn configmap_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/default/configmaps/app-config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "ConfigMap",
            "metadata": {"name": "app-config"},
            "data": {"LOG_LEVEL": "info", "DB_HOST": "postgres"}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "kubernetes.configmap.get",
            "input": {"namespace": "default", "name": "app-config"}
        }))
        .await
        .unwrap();
    assert_eq!(result["configmap"]["data"]["LOG_LEVEL"], "info");
}

#[fcp_async_core::runtime::test]
async fn configmap_get_missing_name() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "kubernetes.configmap.get",
            "input": {"namespace": "default"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn configmap_create() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/namespaces/default/configmaps"))
        .and(header("Content-Type", "application/json"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "kind": "ConfigMap",
            "metadata": {"name": "new-config", "namespace": "default"},
            "data": {"KEY": "value"}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "kubernetes.configmap.create",
            "input": {
                "namespace": "default",
                "name": "new-config",
                "data": {"KEY": "value"}
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["configmap"]["metadata"]["name"], "new-config");
}

#[fcp_async_core::runtime::test]
async fn configmap_create_with_labels() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/namespaces/default/configmaps"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "kind": "ConfigMap",
            "metadata": {"name": "labeled-cm", "labels": {"app": "test"}},
            "data": {"KEY": "val"}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "kubernetes.configmap.create",
            "input": {
                "namespace": "default",
                "name": "labeled-cm",
                "data": {"KEY": "val"},
                "labels": {"app": "test"}
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["configmap"]["metadata"]["name"], "labeled-cm");
}

#[fcp_async_core::runtime::test]
async fn configmap_create_missing_data() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "kubernetes.configmap.create",
            "input": {"namespace": "default", "name": "new-config"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn configmap_create_missing_name() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "kubernetes.configmap.create",
            "input": {"namespace": "default", "data": {"K": "V"}}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn configmap_update() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/api/v1/namespaces/default/configmaps/app-config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "ConfigMap",
            "metadata": {"name": "app-config"},
            "data": {"LOG_LEVEL": "debug"}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "kubernetes.configmap.update",
            "input": {"namespace": "default", "name": "app-config", "data": {"LOG_LEVEL": "debug"}}
        }))
        .await
        .unwrap();
    assert_eq!(result["configmap"]["data"]["LOG_LEVEL"], "debug");
}

#[fcp_async_core::runtime::test]
async fn configmap_update_missing_data() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "kubernetes.configmap.update",
            "input": {"namespace": "default", "name": "app-config"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn configmap_delete() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/api/v1/namespaces/default/configmaps/old-config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "Status", "status": "Success"
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "kubernetes.configmap.delete",
            "input": {"namespace": "default", "name": "old-config"}
        }))
        .await
        .unwrap();
    assert_eq!(result["deleted"], true);
}

#[fcp_async_core::runtime::test]
async fn configmap_delete_missing_name() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "kubernetes.configmap.delete",
            "input": {"namespace": "default"}
        }))
        .await
        .is_err()
    );
}

// ── Feature 3: Secret CRUD ───────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn secret_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/default/secrets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "SecretList",
            "items": [
                {"metadata": {"name": "db-creds"}, "type": "Opaque", "data": {"password": "c2VjcmV0"}},
                {"metadata": {"name": "tls-cert"}, "type": "kubernetes.io/tls", "data": {"tls.crt": "...", "tls.key": "..."}}
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "kubernetes.secret.list",
            "input": {"namespace": "default"}
        }))
        .await
        .unwrap();
    let secrets = result["secrets"].as_array().unwrap();
    assert_eq!(secrets.len(), 2);
    // Verify data is stripped from list results
    for s in secrets {
        assert!(
            s.get("data").is_none(),
            "secret data should be stripped in list"
        );
    }
}

#[fcp_async_core::runtime::test]
async fn secret_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/production/secrets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "SecretList", "items": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "kubernetes.secret.list",
            "input": {"namespace": "production"}
        }))
        .await
        .unwrap();
    assert!(result["secrets"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn secret_list_missing_namespace() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "kubernetes.secret.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn secret_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/default/secrets/db-creds"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "Secret",
            "metadata": {"name": "db-creds"},
            "type": "Opaque",
            "data": {"username": "YWRtaW4=", "password": "c2VjcmV0"}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "kubernetes.secret.get",
            "input": {"namespace": "default", "name": "db-creds"}
        }))
        .await
        .unwrap();
    assert!(result["secret"]["data"].is_object());
    assert_eq!(result["secret"]["data"]["username"], "YWRtaW4=");
}

#[fcp_async_core::runtime::test]
async fn secret_get_missing_name() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "kubernetes.secret.get",
            "input": {"namespace": "default"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn secret_create() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/namespaces/default/secrets"))
        .and(header("Content-Type", "application/json"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "kind": "Secret",
            "metadata": {"name": "new-secret", "namespace": "default"},
            "type": "Opaque",
            "data": {"token": "dG9rZW4="}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "kubernetes.secret.create",
            "input": {
                "namespace": "default",
                "name": "new-secret",
                "data": {"token": "dG9rZW4="}
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["secret"]["metadata"]["name"], "new-secret");
}

#[fcp_async_core::runtime::test]
async fn secret_create_with_type() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/namespaces/default/secrets"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "kind": "Secret",
            "metadata": {"name": "tls-secret"},
            "type": "kubernetes.io/tls",
            "data": {"tls.crt": "...", "tls.key": "..."}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "kubernetes.secret.create",
            "input": {
                "namespace": "default",
                "name": "tls-secret",
                "type": "kubernetes.io/tls",
                "data": {"tls.crt": "...", "tls.key": "..."}
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["secret"]["type"], "kubernetes.io/tls");
}

#[fcp_async_core::runtime::test]
async fn secret_create_with_labels() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/namespaces/default/secrets"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "kind": "Secret",
            "metadata": {"name": "labeled-secret", "labels": {"app": "test"}},
            "data": {"key": "val"}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "kubernetes.secret.create",
            "input": {
                "namespace": "default",
                "name": "labeled-secret",
                "data": {"key": "val"},
                "labels": {"app": "test"}
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["secret"]["metadata"]["name"], "labeled-secret");
}

#[fcp_async_core::runtime::test]
async fn secret_create_missing_data() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "kubernetes.secret.create",
            "input": {"namespace": "default", "name": "new-secret"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn secret_create_missing_name() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "kubernetes.secret.create",
            "input": {"namespace": "default", "data": {"k": "v"}}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn secret_delete() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/api/v1/namespaces/default/secrets/old-creds"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "Status", "status": "Success"
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "kubernetes.secret.delete",
            "input": {"namespace": "default", "name": "old-creds"}
        }))
        .await
        .unwrap();
    assert_eq!(result["deleted"], true);
}

#[fcp_async_core::runtime::test]
async fn secret_delete_missing_name() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "kubernetes.secret.delete",
            "input": {"namespace": "default"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn secret_delete_missing_namespace() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "kubernetes.secret.delete",
            "input": {"name": "old-creds"}
        }))
        .await
        .is_err()
    );
}

// ── Simulate new ops ────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn simulate_configmap_list() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "kubernetes.configmap.list"}))
            .await
            .unwrap()["would_succeed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_configmap_get() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "kubernetes.configmap.get"}))
            .await
            .unwrap()["would_succeed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_configmap_create() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "kubernetes.configmap.create"}))
            .await
            .unwrap()["would_succeed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_configmap_update() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "kubernetes.configmap.update"}))
            .await
            .unwrap()["would_succeed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_configmap_delete() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "kubernetes.configmap.delete"}))
            .await
            .unwrap()["would_succeed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_secret_list() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "kubernetes.secret.list"}))
            .await
            .unwrap()["would_succeed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_secret_get() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "kubernetes.secret.get"}))
            .await
            .unwrap()["would_succeed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_secret_create() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "kubernetes.secret.create"}))
            .await
            .unwrap()["would_succeed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_secret_delete() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "kubernetes.secret.delete"}))
            .await
            .unwrap()["would_succeed"]
            .as_bool()
            .unwrap()
    );
}
