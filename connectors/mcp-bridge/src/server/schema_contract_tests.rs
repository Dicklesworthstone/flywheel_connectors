//! Runtime contract enforcement against the exact embedded MCP manifest.

use super::*;
use fcp_async_core::runtime::Builder;
use fcp_core::CapabilityToken;

fn run<T>(future: impl std::future::Future<Output = T>) -> T {
    Builder::new_multi_thread().enable_all().build().unwrap().block_on(future)
}

async fn configured() -> McpBridgeServer {
    let mut server = McpBridgeServer::new().unwrap();
    server.dispatch("configure", json!({"mcp_url":"http://127.0.0.1:1"})).await.unwrap();
    server.dispatch("handshake", json!({
        "protocol_version":"2.0.0", "zone":"z:work",
        "host_public_key":vec![1_u8;32], "nonce":vec![9_u8;32],
        "capabilities_requested":["mcp.tools.write","mcp.prompts.read","mcp.resources.read","mcp.sampling.handle"],
    })).await.unwrap();
    server
}

fn request(operation: &str, input: Value) -> Value {
    json!({"type":"invoke", "id":"contract-request", "connector_id":"fcp.mcp-bridge",
        "zone_id":"z:work", "operation":operation, "input":input,
        "capability_token":CapabilityToken::test_token()})
}

fn valid_cases() -> Vec<(&'static str, Value, Value)> {
    vec![
        ("mcp.tools.list", json!({}), json!({"tools":[]})),
        ("mcp.tools.call", json!({"name":"example","arguments":{}}), json!({"content":[]})),
        ("mcp.resources.list", json!({}), json!({"resources":[]})),
        ("mcp.resources.read", json!({"uri":"urn:example"}), json!({"contents":[]})),
        ("mcp.resources.templates.list", json!({}), json!({"resourceTemplates":[]})),
        ("mcp.prompts.list", json!({}), json!({"prompts":[]})),
        ("mcp.prompts.get", json!({"name":"review","arguments":{"code":"exact/雪"}}), json!({"messages":[]})),
        ("mcp.completion.complete", json!({"ref":{"type":"ref/prompt","name":"review"},
            "argument":{"name":"language","value":""}}), json!({"completion":{"values":[]}})),
        ("mcp.sampling.handle", json!({"params":{"maxTokens":1,"messages":[]}}),
            json!({"event":"mcp_sampling_request_received","dispatch":"agent_event","request":{}})),
        ("mcp.server.metrics", json!({}), json!({"requests":0,"errors":0,"injection_scans":0,
            "injection_findings":0,"sampling_requests":0,"auth_retries":0,"session_expired_retries":0})),
    ]
}

#[test]
fn all_embedded_operations_compile_and_validate_their_own_input_and_output() {
    let contracts = OperationContractSet::from_manifest_toml(MANIFEST).unwrap();
    let manifest = fcp_manifest::ConnectorManifest::parse_str(MANIFEST).unwrap();
    let cases = valid_cases();
    assert_eq!(cases.len(), manifest.provides.operations.len());
    for (operation, input, output) in cases {
        let operation = OperationId::new(operation).unwrap();
        contracts.validate_input(&operation, &input).unwrap();
        let id = RequestId::new("contract-request");
        let reply = InvokeResponse::ok(id.clone(), output);
        let before = serde_json::to_value(&reply).unwrap();
        contracts.validate_response(&operation, &id, &reply).unwrap();
        assert_eq!(serde_json::to_value(&reply).unwrap(), before);
    }
}

#[test]
fn malformed_declared_inputs_fail_in_the_dispatcher_before_provider_work() {
    run(async {
        let mut server = configured().await;
        for (operation, input) in [
            ("mcp.tools.call", json!({"name":"write"})),
            ("mcp.tools.call", json!({"name":"write","arguments":"private-argument"})),
            ("mcp.prompts.get", json!({"name":"review","arguments":{"private-key":42}})),
            ("mcp.prompts.get", json!({"name":""})),
            ("mcp.resources.read", json!({"uri":42})),
            ("mcp.sampling.handle", json!({"request":42})),
            ("mcp.completion.complete", json!({"ref":{"type":"ref/prompt","name":"review"}})),
        ] {
            let error = server.dispatch("invoke", request(operation, input)).await.unwrap_err();
            assert!(matches!(error, FcpError::InvalidRequest {code:1003,..}));
            assert!(error.to_string().contains("declared schema"));
            assert!(!error.to_string().contains("private"));
        }
        assert_eq!(server.dispatch("health", json!({})).await.unwrap()["requests"], 0);
    });
}

#[test]
fn malformed_input_simulation_is_a_redacted_denial_without_provider_activity() {
    run(async {
        let mut server = configured().await;
        let mut invocation = request("mcp.prompts.get", json!({"name":"review","arguments":{"secret":42}}));
        invocation["type"] = json!("simulate");
        invocation["estimate_cost"] = json!(false);
        invocation["check_availability"] = json!(false);
        let result = server.dispatch("simulate", invocation).await.unwrap();
        assert_eq!(result["id"], "contract-request");
        assert_eq!(result["would_succeed"], false);
        assert!(result.to_string().contains("declared schema"));
        assert!(!result.to_string().contains("secret"));
        assert_eq!(server.dispatch("health", json!({})).await.unwrap()["requests"], 0);
    });
}

#[test]
fn valid_schema_cannot_replace_required_signed_authority() {
    run(async {
        let mut server = configured().await;
        for (operation, input, _) in valid_cases() {
            assert!(server.dispatch("invoke", request(operation, input)).await.is_err());
        }
        assert_eq!(server.dispatch("health", json!({})).await.unwrap()["requests"], 0);
    });
}

#[test]
fn every_operation_withholds_an_empty_success_without_fabricating_output() {
    let contracts = OperationContractSet::from_manifest_toml(MANIFEST).unwrap();
    for (operation, _, _) in valid_cases() {
        let operation = OperationId::new(operation).unwrap();
        let id = RequestId::new("contract-request");
        let reply = InvokeResponse::ok(id.clone(), json!({}));
        let error = contracts.validate_response(&operation, &id, &reply).unwrap_err();
        assert!(matches!(error, FcpError::External {retryable:false,retry_after:None,..}));
        assert!(error.to_string().contains("outcome is unknown"));
        contracts.validate_response(&operation, &id,
            &InvokeResponse::error(id.clone(), FcpError::NotConfigured)).unwrap();
    }
}
