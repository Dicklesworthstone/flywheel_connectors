//! Anthropic advanced e2e evidence.
//!
//! The default path is deterministic and uses a loopback Anthropic fixture for
//! beta headers, Claude Code OAuth auth headers, prompt-cache annotations,
//! service tier, model normalization, thinking redaction, and auth diagnostics.
//! Set `ANTHROPIC_API_KEY` to additionally run a tiny live API-key request.

#![cfg(feature = "anthropic")]
#![allow(clippy::too_many_lines)]

use std::io::Write as _;
use std::time::Instant;

use chrono::{Duration, Utc};
use fcp_anthropic::connector::AnthropicConnector;
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{CapabilityConstraints, CapabilityToken, FcpError, InstanceId};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

const OP_MESSAGE: &str = "anthropic.message";
const OP_AUTH_LIST: &str = "anthropic.auth.list_methods";
const OP_AUTH_REFRESH: &str = "anthropic.auth.refresh_oauth";
const OP_MODELS_NORMALIZE: &str = "anthropic.models.normalize";

const CAP_MESSAGE: &str = "anthropic.message";
const CAP_AUTH: &str = "anthropic.auth";
const CAP_MODELS: &str = "anthropic.models";

const MODEL_FIXTURE: &str = "claude-sonnet-4-6";
const MODEL_LIVE: &str = "claude-sonnet-4-6";
const ARTIFACT_PATH: &str = "target/fcp-anthropic/anthropic-advanced-e2e.jsonl";
const EXPECTED_FIXTURE_BETAS: &str = "files-api-2025-04-14,code-execution-2025-08-25,interleaved-thinking-2025-05-14,claude-code-20250219,oauth-2025-04-20";

struct ConfiguredAnthropic {
    connector: AnthropicConnector,
    signing_key: Ed25519SigningKey,
}

#[fcp_async_core::runtime::test]
async fn anthropic_connector_emits_redacted_advanced_e2e_evidence() {
    let mut records = Vec::new();
    run_fixture_script(&mut records).await;
    run_live_script_or_record_skip(&mut records)
        .await
        .expect("live Anthropic script should either skip cleanly or pass");

    let jsonl = write_jsonl_artifact(&records);
    for event in [
        "anthropic_auth_resolved",
        "anthropic_request_built",
        "anthropic_response_decoded",
        "anthropic_oauth_refresh",
        "anthropic_cli_auth_boundary",
        "audit_receipt",
    ] {
        assert!(
            jsonl.contains(&format!("\"event\":\"{event}\"")),
            "evidence log should include event {event}"
        );
    }
    assert!(jsonl.contains("\"provider_mode\":\"fixture\""));
    assert!(jsonl.contains("\"provider_mode\":\"live\"") || jsonl.contains("\"skip_reason\""));
    for forbidden in [
        "oauth-fixture-token",
        "setup-fixture-token",
        "anthropic-fixture-key",
        "ANTHROPIC_API_KEY",
        "Bearer ",
        "private prompt",
        "private system",
        "private prefill",
        "private thinking",
        "fixture answer",
    ] {
        assert!(
            !jsonl.contains(forbidden),
            "advanced Anthropic evidence leaked forbidden payload fragment {forbidden:?}"
        );
    }
    assert_eq!(fcp_e2e::scan_log_jsonl(&jsonl).error_count, 0);
}

async fn run_fixture_script(records: &mut Vec<Value>) {
    let server = MockServer::start().await;
    mount_fixture_message(&server).await;
    record_cli_auth_boundary(records).await;

    let mut configured = configured_connector(
        json!({
            "claude_code_oauth_token": "oauth-fixture-token",
            "base_url": server.uri(),
            "default_betas": ["files-api-2025-04-14"]
        }),
        &[CAP_MESSAGE, CAP_AUTH, CAP_MODELS],
    )
    .await;

    let auth_methods = invoke(
        &configured.connector,
        &configured.signing_key,
        OP_AUTH_LIST,
        CAP_AUTH,
        json!({}),
    )
    .await
    .expect("fixture auth methods should succeed");
    records.push(evidence_record(
        "anthropic_auth_resolved",
        "fixture",
        OP_AUTH_LIST,
        MODEL_FIXTURE,
        0,
        json!({
            "method": auth_methods["active_method"],
            "credential_label": "fixture-oauth",
            "configured": auth_methods["configured"],
            "oauth_refresh_available": auth_methods["oauth_refresh_available"],
            "supported_method_count": auth_methods["supported_methods"].as_array().map(Vec::len)
        }),
    ));

    let started = Instant::now();
    let message = invoke(
        &configured.connector,
        &configured.signing_key,
        OP_MESSAGE,
        CAP_MESSAGE,
        fixture_advanced_message_input(),
    )
    .await
    .expect("fixture advanced message should succeed");
    records.push(evidence_record(
        "anthropic_request_built",
        "fixture",
        OP_MESSAGE,
        MODEL_FIXTURE,
        started.elapsed().as_millis(),
        json!({
            "model_canonical": message["model_canonical"],
            "betas": message["anthropic_betas"],
            "service_tier": message["service_tier"],
            "max_tokens": 4096_u64,
            "enable_1m_context": true,
            "cache_control": "ephemeral",
            "thinking_enabled": true,
            "tool_count": 1_u64,
            "prompt_text_logged": false
        }),
    ));
    records.push(evidence_record(
        "anthropic_response_decoded",
        "fixture",
        OP_MESSAGE,
        MODEL_FIXTURE,
        0,
        json!({
            "finish_reason": message["stop_reason"],
            "cache_creation_input_tokens": message["usage"]["cache_creation_input_tokens"],
            "cache_read_input_tokens": message["usage"]["cache_read_input_tokens"],
            "cache_creation_1h_input_tokens": message["usage"]["cache_creation"]["ephemeral_1h_input_tokens"],
            "output_tokens": message["usage"]["output_tokens"],
            "service_tier": message["usage"]["service_tier"],
            "has_thinking": message["provenance"]["has_thinking"],
            "thinking_redacted": message["content_blocks"][0]["redacted"],
            "media_image_count": message["provenance"]["media_image_count"],
            "content_block_count": message["content_blocks"].as_array().map(Vec::len)
        }),
    ));

    let normalize = invoke(
        &configured.connector,
        &configured.signing_key,
        OP_MODELS_NORMALIZE,
        CAP_MODELS,
        json!({ "model": "claude-opus-4.7" }),
    )
    .await
    .expect("fixture model normalization should succeed");
    records.push(evidence_record(
        "anthropic_request_built",
        "fixture",
        OP_MODELS_NORMALIZE,
        "claude-opus-4-7",
        0,
        json!({
            "model_alias_accepted": true,
            "model_canonical": normalize["canonical"],
            "context_window_tokens": normalize["context_window_tokens"],
            "supports_1m_context": normalize["supports_1m_context"]
        }),
    ));

    let refresh = invoke(
        &configured.connector,
        &configured.signing_key,
        OP_AUTH_REFRESH,
        CAP_AUTH,
        json!({}),
    )
    .await
    .expect("fixture OAuth refresh diagnostic should succeed");
    records.push(evidence_record(
        "anthropic_oauth_refresh",
        "fixture",
        OP_AUTH_REFRESH,
        MODEL_FIXTURE,
        0,
        json!({
            "reason": "manual_diagnostic",
            "auth_method": refresh["auth_method"],
            "connector_refreshable": refresh["refreshable"],
            "host_managed": refresh["host_managed"],
            "expires_after": refresh["expires_after"],
            "refreshed": refresh["refreshed"]
        }),
    ));
    records.push(evidence_record(
        "audit_receipt",
        "fixture",
        OP_MESSAGE,
        MODEL_FIXTURE,
        0,
        json!({
            "receipt_id": audit_receipt_id_hash("fixture", OP_MESSAGE, MODEL_FIXTURE),
            "kind": "anthropic_advanced_fixture",
            "op": OP_MESSAGE
        }),
    ));

    assert_eq!(message["content_blocks"][0]["type"], "thinking");
    assert_eq!(message["content_blocks"][0]["redacted"], true);
    assert!(!message.to_string().contains("private thinking"));
    assert_eq!(message["usage"]["cache_creation_input_tokens"], 4);
    assert_eq!(message["usage"]["cache_read_input_tokens"], 6);
    assert_eq!(
        message["usage"]["cache_creation"]["ephemeral_1h_input_tokens"],
        1
    );
    assert_eq!(message["usage"]["service_tier"], "standard");

    let requests = server.received_requests().await.unwrap_or_default();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(
        request
            .headers
            .get("authorization")
            .and_then(|value| value.to_str().ok()),
        Some("Bearer oauth-fixture-token")
    );
    assert_eq!(
        request
            .headers
            .get("anthropic-beta")
            .and_then(|value| value.to_str().ok()),
        Some(EXPECTED_FIXTURE_BETAS)
    );
    let body: Value = serde_json::from_slice(&request.body).expect("request body should be JSON");
    assert_eq!(body["model"], MODEL_FIXTURE);
    assert_eq!(body["messages"].as_array().map(Vec::len), Some(1));
    assert_eq!(body["service_tier"], "auto");
    assert_eq!(body["cache_control"]["type"], "ephemeral");
    assert_eq!(
        body["messages"][0]["content"][0]["cache_control"]["type"],
        "ephemeral"
    );
    assert_eq!(body["thinking"]["type"], "enabled");
    assert_eq!(body["output_config"]["effort"], "medium");
    assert_eq!(body["tools"][0]["eager_input_streaming"], true);
    assert!(!body.to_string().contains("private prefill"));

    let cleanup_result = configured
        .connector
        .handle_shutdown(json!({ "reason": "advanced e2e complete" }))
        .await
        .map(|_| "shutdown_ok")
        .unwrap_or("shutdown_error");
    records.push(evidence_record(
        "audit_receipt",
        "fixture",
        "anthropic.cleanup",
        MODEL_FIXTURE,
        0,
        json!({
            "receipt_id": audit_receipt_id_hash("fixture", "anthropic.cleanup", MODEL_FIXTURE),
            "kind": "cleanup",
            "op": "anthropic.cleanup",
            "cleanup_result": cleanup_result
        }),
    ));
}

async fn record_cli_auth_boundary(records: &mut Vec<Value>) {
    let mut connector = AnthropicConnector::new();
    let err = connector
        .handle_configure(json!({
            "setup_token": "setup-fixture-token"
        }))
        .await
        .expect_err("setup-token must not target the direct Anthropic API origin");
    records.push(evidence_record(
        "anthropic_cli_auth_boundary",
        "fixture",
        "anthropic.configure",
        MODEL_FIXTURE,
        0,
        json!({
            "unsupported_default_api_denied": true,
            "error_mapping": classify_error(&err),
            "host_managed_runtime_required": true,
            "token_text_logged": false
        }),
    ));
}

async fn run_live_script_or_record_skip(records: &mut Vec<Value>) -> Result<(), String> {
    let env_name = ["ANTHROPIC", "API", "KEY"].join("_");
    let live_credential = std::env::var(&env_name)
        .ok()
        .filter(|value| !value.trim().is_empty());
    let Some(live_credential) = live_credential else {
        records.push(evidence_record(
            "anthropic_auth_resolved",
            "live",
            OP_MESSAGE,
            MODEL_LIVE,
            0,
            json!({
                "method": "api_key",
                "credential_label": "env:redacted_live_credential",
                "skip_reason": "missing_live_credentials"
            }),
        ));
        return Ok(());
    };

    let mut configured = configured_connector(
        json!({
            "api_key": live_credential,
            "default_betas": []
        }),
        &[CAP_MESSAGE],
    )
    .await;

    let started = Instant::now();
    let response = invoke(
        &configured.connector,
        &configured.signing_key,
        OP_MESSAGE,
        CAP_MESSAGE,
        json!({
            "model": MODEL_LIVE,
            "messages": [{"role": "user", "content": "Return the word ok."}],
            "max_tokens": 4,
            "service_tier": "standard_only"
        }),
    )
    .await;

    let live_error = match response {
        Ok(value) => {
            records.push(evidence_record(
                "anthropic_request_built",
                "live",
                OP_MESSAGE,
                MODEL_LIVE,
                started.elapsed().as_millis(),
                json!({
                    "model_canonical": value["model_canonical"],
                    "service_tier": value["service_tier"],
                    "max_tokens": 4_u64,
                    "prompt_text_logged": false
                }),
            ));
            records.push(evidence_record(
                "anthropic_response_decoded",
                "live",
                OP_MESSAGE,
                MODEL_LIVE,
                0,
                json!({
                    "finish_reason": value["stop_reason"],
                    "cache_creation_input_tokens": value["usage"]["cache_creation_input_tokens"],
                    "cache_read_input_tokens": value["usage"]["cache_read_input_tokens"],
                    "output_tokens": value["usage"]["output_tokens"],
                    "service_tier": value["usage"]["service_tier"],
                    "has_thinking": value["provenance"]["has_thinking"]
                }),
            ));
            None
        }
        Err(err) => {
            let error_message = format!(
                "live Anthropic invocation failed after live credentials were provided: {err}"
            );
            records.push(evidence_record(
                "anthropic_response_decoded",
                "live",
                OP_MESSAGE,
                MODEL_LIVE,
                started.elapsed().as_millis(),
                json!({
                    "error_mapping": classify_error(&err),
                    "provider_returned_error": true
                }),
            ));
            Some(error_message)
        }
    };

    let cleanup_result = configured
        .connector
        .handle_shutdown(json!({ "reason": "live advanced e2e complete" }))
        .await
        .map(|_| "shutdown_ok")
        .unwrap_or("shutdown_error");
    records.push(evidence_record(
        "audit_receipt",
        "live",
        "anthropic.cleanup",
        MODEL_LIVE,
        0,
        json!({
            "receipt_id": audit_receipt_id_hash("live", "anthropic.cleanup", MODEL_LIVE),
            "kind": "cleanup",
            "op": "anthropic.cleanup",
            "cleanup_result": cleanup_result
        }),
    ));
    if let Some(error) = live_error {
        return Err(error);
    }
    Ok(())
}

async fn mount_fixture_message(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "msg_anthropic_advanced_fixture",
            "type": "message",
            "role": "assistant",
            "content": [
                {"type": "thinking", "thinking": "private thinking", "signature": "sig"},
                {"type": "text", "text": "fixture answer"}
            ],
            "model": MODEL_FIXTURE,
            "stop_reason": "end_turn",
            "stop_sequence": null,
            "usage": {
                "input_tokens": 20,
                "output_tokens": 10,
                "cache_creation_input_tokens": 4,
                "cache_read_input_tokens": 6,
                "cache_creation": {
                    "ephemeral_5m_input_tokens": 3,
                    "ephemeral_1h_input_tokens": 1
                },
                "service_tier": "standard"
            }
        })))
        .expect(1)
        .mount(server)
        .await;
}

async fn configured_connector(config: Value, capabilities: &[&str]) -> ConfiguredAnthropic {
    let mut connector = AnthropicConnector::new();
    connector
        .handle_configure(config)
        .await
        .expect("Anthropic connector should configure");

    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    connector
        .handle_handshake(json!({
            "protocol_version": "2.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0_u8; 32],
            "capabilities_requested": capabilities
        }))
        .await
        .expect("Anthropic connector handshake should succeed");

    ConfiguredAnthropic {
        connector,
        signing_key,
    }
}

async fn invoke(
    connector: &AnthropicConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    capability: &'static str,
    input: Value,
) -> fcp_core::FcpResult<Value> {
    let capability_grant = valid_token(signing_key, connector.instance_id(), capability, operation);
    connector
        .handle_invoke(json!({
            "type": "invoke",
            "id": "advanced-fixture",
            "connector_id": "fcp.anthropic",
            "zone_id": "z:work",
            "operation": operation,
            "input": input,
            "capability_token": capability_grant
        }))
        .await
}

fn valid_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    capability: &str,
    operation: &str,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("constraints serialize");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:anthropic-advanced-e2e")
        .operations(&[operation])
        .issuer("node:anthropic-advanced-e2e")
        .target_instance(instance_id.as_str())
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("capability grant should sign");
    CapabilityToken::from_raw(cose)
}

fn fixture_advanced_message_input() -> Value {
    json!({
        "model": "sonnet-4.6",
        "messages": [
            {
                "role": "user",
                "content": [{
                    "type": "text",
                    "text": "private prompt",
                    "cache_control": {"type": "ephemeral", "ttl": "1h"}
                }]
            },
            {
                "role": "assistant",
                "content": "private prefill"
            }
        ],
        "system": [{
            "type": "text",
            "text": "private system",
            "cache_control": {"type": "ephemeral"}
        }],
        "max_tokens": 4096,
        "enable_1m_context": true,
        "cache_control": {"type": "ephemeral"},
        "service_tier": "auto",
        "anthropic_betas": ["code-execution-2025-08-25"],
        "thinking": {"type": "enabled", "budget_tokens": 1024},
        "output_config": {"effort": "medium"},
        "tools": [{
            "name": "lookup",
            "description": "Lookup data",
            "input_schema": {"type": "object"},
            "eager_input_streaming": true
        }],
        "tool_choice": {"type": "auto"}
    })
}

fn evidence_record(
    event: &str,
    provider_mode: &str,
    operation: &str,
    model_id: &str,
    latency_ms: u128,
    details: Value,
) -> Value {
    json!({
        "schema": "fcp.anthropic.advanced_e2e.v1",
        "event": event,
        "command_line": "cargo test -p fcp-e2e --features anthropic --test anthropic_advanced_e2e -- --nocapture",
        "git_revision": git_revision(),
        "provider_mode": provider_mode,
        "operation": operation,
        "model_id": model_id,
        "latency_ms": u64::try_from(latency_ms).unwrap_or(u64::MAX),
        "audit_receipt_id_hash": audit_receipt_id_hash(provider_mode, operation, model_id),
        "details": details
    })
}

fn classify_error(error: &FcpError) -> &'static str {
    match error {
        FcpError::RateLimited { .. } => "capability.rate_limited",
        FcpError::External {
            status_code: Some(429),
            ..
        } => "external.rate_limited",
        FcpError::External { .. } => "external.provider_error",
        FcpError::UpstreamTimeout { .. } => "external.timeout",
        FcpError::DependencyUnavailable { .. } => "external.dependency_unavailable",
        FcpError::ConnectorUnavailable { .. } => "connector.unavailable",
        FcpError::InvalidRequest { .. } => "protocol.invalid_request",
        _ => "other",
    }
}

fn audit_receipt_id_hash(provider_mode: &str, operation: &str, model_id: &str) -> String {
    let input = format!("{provider_mode}:{operation}:{model_id}");
    format!("blake3:{}", blake3::hash(input.as_bytes()).to_hex())
}

fn git_revision() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|revision| revision.trim().to_string())
        .filter(|revision| !revision.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn write_jsonl_artifact(records: &[Value]) -> String {
    let jsonl = records
        .iter()
        .map(|record| serde_json::to_string(record).expect("evidence record should serialize"))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::create_dir_all("target/fcp-anthropic").expect("artifact directory should be writable");
    let mut file = std::fs::File::create(ARTIFACT_PATH).expect("artifact should be writable");
    file.write_all(jsonl.as_bytes())
        .expect("artifact should write");
    file.write_all(b"\n")
        .expect("artifact newline should write");
    jsonl
}
