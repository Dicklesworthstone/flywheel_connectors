//! Bounded upstream verification for the existing FCP self-check control call.
//!
//! Configuration syntax and client allocation do not prove MCP reachability.
//! Probe through the ordinary managed RPC path so version negotiation, session
//! headers, correlation, safe retries and transport bounds cannot drift apart.

use std::time::{Duration, Instant};

use serde_json::json;

use super::{McpBridgeError, McpClient, ProvisioningReadiness, SelfCheckReport, redact_url};

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) async fn check(client: &McpClient, readiness: ProvisioningReadiness) -> SelfCheckReport {
    check_with_timeout(client, readiness, PROBE_TIMEOUT).await
}

async fn check_with_timeout(
    client: &McpClient,
    mut readiness: ProvisioningReadiness,
    timeout: Duration,
) -> SelfCheckReport {
    let started = Instant::now();
    // The single outer deadline includes lazy initialization, notification,
    // ping, transport reads and retries. No second fresh budget after handshake.
    let result = fcp_async_core::time::timeout(timeout, client.rpc_call("ping", json!({}))).await;
    let (mut report, status) = match result {
        Ok(Ok(result)) if result.is_object() => (SelfCheckReport::ok(), "reachable"),
        Ok(Ok(_)) => (SelfCheckReport::failed(
            "upstream_protocol_invalid", "MCP ping returned an invalid result envelope",
        ), "protocol_error"),
        Ok(Err(McpBridgeError::Unauthorized | McpBridgeError::Forbidden)) => (
            SelfCheckReport::failed(
                "upstream_authentication_failed", "MCP server rejected the configured credentials",
            ), "authentication_failed",
        ),
        Ok(Err(_)) => (SelfCheckReport::failed(
            "upstream_probe_failed", "MCP initialization or ping failed; verify endpoint, credentials and protocol support",
        ), "failed"),
        Err(_) => (SelfCheckReport::failed(
            "upstream_probe_timeout", "MCP initialization and ping exceeded the self-check deadline",
        ), "timed_out"),
    };
    // Never return upstream error bodies, initialization instructions, session
    // headers or credentials as diagnostic authority. The existing redactor
    // handles credentials/query values in the configured endpoint.
    readiness.mcp_url = redact_url(&readiness.mcp_url).to_string();
    readiness.network_message = "Configured endpoint syntax is valid; live reachability is reported separately".into();
    report.details = Some(json!({
        "provisioning": readiness,
        "upstream": {
            "checked": true,
            "status": status,
            "probe": "managed_initialize_and_ping",
            "elapsed_ms": u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            "deadline_ms": u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
            "scope": "upstream_connectivity_only",
        },
    }));
    report
}

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use wiremock::matchers::{body_partial_json, method};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    use super::*;
    use super::super::{McpBridgeConfig, McpBridgeConnector};
    use crate::client::McpAuth;

    async fn mount_initialization(server: &MockServer) {
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method": "initialize"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0", "id": 0, "result": {
                    "protocolVersion": "2025-06-18", "capabilities": {},
                    "serverInfo": {"name": "probe", "version": "1"},
                },
            })).insert_header("Mcp-Session-Id", "probe-session"))
            .mount(server).await;
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method": "notifications/initialized"})))
            .respond_with(ResponseTemplate::new(202)).mount(server).await;
    }

    async fn mount_ping(server: &MockServer, result: Value) {
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method": "ping"})))
            .respond_with(move |request: &Request| {
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(request.headers.get("mcp-session-id").unwrap(), "probe-session");
                ResponseTemplate::new(200).set_body_json(json!({
                    "jsonrpc": "2.0", "id": body["id"], "result": result,
                }))
            }).mount(server).await;
    }

    async fn configured(server: &MockServer) -> McpBridgeConnector {
        let mut connector = McpBridgeConnector::new();
        connector.handle_configure(json!({"mcp_url": server.uri()})).await.unwrap();
        connector
    }

    async fn methods(server: &MockServer) -> Vec<String> {
        server.received_requests().await.unwrap().iter().map(|request| {
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            body["method"].as_str().unwrap().to_owned()
        }).collect()
    }

    #[fcp_async_core::runtime::test]
    async fn every_successful_self_check_performs_ping_without_granting_fcp_authority() {
        let server = MockServer::start().await;
        mount_initialization(&server).await;
        mount_ping(&server, json!({})).await;
        let connector = configured(&server).await;
        for _ in 0..2 {
            let report = connector.handle_self_check().await.unwrap();
            assert_eq!(report["status"], "ok");
            assert_eq!(report["details"]["upstream"]["status"], "reachable");
            assert_eq!(report["details"]["upstream"]["deadline_ms"], 5_000);
        }
        assert_eq!(methods(&server).await, ["initialize", "notifications/initialized", "ping", "ping"]);
        let health = connector.handle_health().await.unwrap();
        assert_eq!(health["handshaken"], false);
        assert_eq!(health["requests"], 0);
    }

    #[fcp_async_core::runtime::test]
    async fn authentication_failure_is_a_failed_report_without_upstream_body_leakage() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(401).set_body_string("private-provider-error"))
            .mount(&server).await;
        let connector = configured(&server).await;
        let report = connector.handle_self_check().await.unwrap();
        assert_eq!(report["status"], "failed");
        assert_eq!(report["reason_code"], "upstream_authentication_failed");
        assert!(!report.to_string().contains("private-provider-error"));
        assert!(!methods(&server).await.iter().any(|method| method == "ping"));
    }

    #[fcp_async_core::runtime::test]
    async fn successful_http_with_invalid_ping_result_cannot_report_ok() {
        let server = MockServer::start().await;
        mount_initialization(&server).await;
        mount_ping(&server, json!("private-result")).await;
        let connector = configured(&server).await;
        let report = connector.handle_self_check().await.unwrap();
        assert_eq!(report["status"], "failed");
        assert_eq!(report["reason_code"], "upstream_protocol_invalid");
        assert!(!report.to_string().contains("private-result"));
        assert_eq!(methods(&server).await.len(), 3);
    }

    #[fcp_async_core::runtime::test]
    async fn initialization_timeout_is_bounded_and_never_dispatches_ping() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(500)))
            .mount(&server).await;
        let client = McpClient::new(McpAuth { api_key: None }, &server.uri()).unwrap();
        let config = McpBridgeConfig::from_params(&json!({"mcp_url": server.uri()})).unwrap();
        let report = check_with_timeout(&client, config.provisioning_readiness(), Duration::from_millis(100)).await;
        assert_eq!(report.reason_code.as_deref(), Some("upstream_probe_timeout"));
        assert_eq!(methods(&server).await, ["initialize"]);
    }

    #[fcp_async_core::runtime::test]
    async fn failed_ping_does_not_reuse_an_earlier_successful_probe() {
        let server = MockServer::start().await;
        mount_initialization(&server).await;
        Mock::given(method("POST")).and(body_partial_json(json!({"method": "ping"})))
            .respond_with(|request: &Request| {
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                ResponseTemplate::new(200).set_body_json(json!({"jsonrpc": "2.0", "id": body["id"], "result": {}}))
            }).with_priority(0).up_to_n_times(1).mount(&server).await;
        Mock::given(method("POST")).and(body_partial_json(json!({"method": "ping"})))
            .respond_with(ResponseTemplate::new(403).set_body_string("private-detail"))
            .mount(&server).await;
        let connector = configured(&server).await;
        assert_eq!(connector.handle_self_check().await.unwrap()["status"], "ok");
        let failed = connector.handle_self_check().await.unwrap();
        assert_eq!(failed["status"], "failed");
        assert!(!failed.to_string().contains("private-detail"));
        assert_eq!(methods(&server).await, ["initialize", "notifications/initialized", "ping", "ping"]);
    }

    #[fcp_async_core::runtime::test]
    async fn public_fcp_self_check_cannot_establish_invocation_authority() {
        let server = MockServer::start().await;
        mount_initialization(&server).await;
        mount_ping(&server, json!({})).await;
        let mut boundary = crate::server::McpBridgeServer::new().unwrap();
        boundary.dispatch("configure", json!({"mcp_url": server.uri()})).await.unwrap();
        assert_eq!(boundary.dispatch("self_check", json!({})).await.unwrap()["status"], "ok");
        let health = boundary.dispatch("health", json!({})).await.unwrap();
        assert_eq!(health["handshaken"], false);
        assert_eq!(health["status"]["state"], "degraded");
        assert_eq!(health["requests"], 0);
        assert!(boundary.dispatch("invoke", json!({})).await.is_err());
    }
}
