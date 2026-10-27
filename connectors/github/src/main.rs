//! FCP GitHub Connector - Main entrypoint
//!
//! A GitHub API connector implementing the Flywheel Connector Protocol.
//! Provides access to repos, issues, PRs, Actions, code search, and file content.

#![forbid(unsafe_code)]
#![allow(dead_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::derivable_impls,
    clippy::future_not_send,
    clippy::float_cmp,
    clippy::manual_unwrap_or_default,
    clippy::match_same_arms,
    clippy::option_if_let_else,
    clippy::or_fun_call,
    clippy::redundant_closure_for_method_calls,
    clippy::assertions_on_constants,
    clippy::struct_field_names,
    clippy::suboptimal_flops,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::trivially_copy_pass_by_ref,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use std::io::{BufRead, Write};

use anyhow::Result;
use fcp_async_core::runtime::Builder;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use fcp_github::connector::GitHubConnector;

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    tracing::info!("FCP GitHub Connector starting");

    run_fcp_loop()?;

    Ok(())
}

/// Run the FCP JSON-RPC style protocol loop.
fn run_fcp_loop() -> Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut connector = GitHubConnector::new();

    let runtime = Builder::new_multi_thread().enable_all().build()?;

    for line in stdin.lock().lines() {
        let line = line?;
        if should_skip_protocol_line(&line) {
            continue;
        }

        let response = runtime.block_on(async { handle_message(&mut connector, &line).await });

        let response_json = serde_json::to_string(&response)?;
        writeln!(stdout, "{response_json}")?;
        stdout.flush()?;
    }

    Ok(())
}

fn should_skip_protocol_line(line: &str) -> bool {
    line.trim().is_empty()
}

fn parse_error_response(error: impl std::fmt::Display) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": null,
        "error": {
            "code": "FCP-1001",
            "message": format!("Invalid JSON: {error}")
        }
    })
}

/// Handle a single FCP message.
async fn handle_message(connector: &mut GitHubConnector, message: &str) -> serde_json::Value {
    let request: serde_json::Value = match serde_json::from_str(message) {
        Ok(v) => v,
        Err(e) => return parse_error_response(e),
    };

    let method = request.get("method").and_then(|v| v.as_str()).unwrap_or("");
    let id = request.get("id").cloned();
    let params = request
        .get("params")
        .cloned()
        .unwrap_or(serde_json::json!({}));

    let result = match method {
        "configure" => connector.handle_configure(params).await,
        "handshake" => connector.handle_handshake(params).await,
        "health" => connector.handle_health().await,
        "doctor" => connector.handle_doctor().await,
        "self_check" => connector.handle_self_check().await,
        "introspect" => connector.handle_introspect().await,
        "invoke" => {
            fcp_sdk::prelude::dispatch_raw_invoke(params, |params| connector.handle_invoke(params))
                .await
        }
        "simulate" => connector.handle_simulate(params).await,
        "shutdown" => connector.handle_shutdown(params).await,
        _ => Err(fcp_core::FcpError::InvalidRequest {
            code: 1002,
            message: format!("Unknown method: {method}"),
        }),
    };

    match result {
        Ok(value) => {
            let mut response = serde_json::json!({
                "jsonrpc": "2.0",
                "result": value
            });
            if let Some(id) = id {
                response
                    .as_object_mut()
                    .unwrap()
                    .insert("id".to_string(), id);
            }
            response
        }
        Err(e) => {
            let err_response = e.to_response();
            let mut response = serde_json::json!({
                "jsonrpc": "2.0",
                "error": err_response
            });
            if let Some(id) = id {
                response
                    .as_object_mut()
                    .unwrap()
                    .insert("id".to_string(), id);
            }
            response
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_loop_skips_whitespace_only_lines() {
        assert!(should_skip_protocol_line(""));
        assert!(should_skip_protocol_line("   \t  "));
        assert!(!should_skip_protocol_line("{\"jsonrpc\":\"2.0\"}"));
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_requires_an_inner_id_and_preserves_handler_errors() {
        let mut connector = GitHubConnector::new();
        for params in [
            serde_json::json!({}),
            serde_json::json!({"id": null}),
            serde_json::json!({"id": 7}),
            serde_json::json!({"id": ["request"]}),
        ] {
            let request = serde_json::json!({
                "jsonrpc": "2.0", "id": "transport-7", "method": "invoke", "params": params
            });
            let response = handle_message(&mut connector, &request.to_string()).await;
            assert_eq!(response["id"], "transport-7");
            assert!(response.get("result").is_none());
            assert_eq!(response["error"]["code"], "FCP-1003");
            assert_eq!(
                response["error"]["message"],
                "Invalid request: invoke params.id must be a string"
            );
        }

        let request = serde_json::json!({
            "jsonrpc": "2.0", "id": 7, "method": "invoke", "params": {"id": "invoke-7"}
        });
        let response = handle_message(&mut connector, &request.to_string()).await;
        assert_eq!(response["id"], 7);
        assert!(response.get("result").is_none());
        assert_eq!(response["error"]["code"], "FCP-1003");
        assert_eq!(
            response["error"]["message"],
            "Invalid request: Missing operation"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn native_invoke_wraps_a_real_local_result_with_the_inner_request_id() {
        use chrono::{Duration, Utc};
        use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
        use serde_json::json;

        let mut connector = GitHubConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "550e8400-e29b-41d4-a716-446655440000"
            }))
            .await
            .unwrap();
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": signing_key.verifying_key().to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["github.process_webhook"]
            }))
            .await
            .unwrap();
        let constraints = fcp_prelude::CapabilityConstraints {
            resource_allow: vec![
                "github://octocat/hello-world/webhooks/deliveries/native-envelope-1".into(),
            ],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).unwrap();
        let now = Utc::now();
        let token = CapabilityTokenBuilder::new()
            .capability_id("github.process_webhook")
            .zone_id("z:work")
            .principal("user:test")
            .operations(&["github.process_webhook"])
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .target_instance(connector.instance_id().as_str())
            .try_constraints_cbor(&cbor)
            .unwrap()
            .sign(&signing_key)
            .unwrap();
        let request = json!({
            "jsonrpc": "2.0",
            "id": 73,
            "method": "invoke",
            "params": {
                "id": "invoke-native-1",
                "operation": "github.process_webhook",
                "capability_token": fcp_core::CapabilityToken::from_raw(token),
                "input": {
                    "signature_validated": true,
                    "payload": {
                        "event_type": "issues",
                        "delivery_id": "native-envelope-1",
                        "repository": {
                            "id": 1,
                            "full_name": "octocat/hello-world",
                            "html_url": "https://github.com/octocat/hello-world"
                        },
                        "data": {"action": "opened", "issue": {"number": 42}}
                    }
                }
            }
        });

        // Webhook processing is local: this exercises the real connector,
        // signed capability and native dispatcher without provider HTTP.
        let response = handle_message(&mut connector, &request.to_string()).await;
        assert_eq!(response["id"], 73);
        assert!(response.get("error").is_none(), "{response}");
        let invocation: fcp_core::InvokeResponse =
            serde_json::from_value(response["result"].clone()).unwrap();
        assert_eq!(invocation.r#type, "response");
        assert_eq!(invocation.id, fcp_core::RequestId::new("invoke-native-1"));
        assert_eq!(invocation.status, fcp_core::InvokeStatus::Ok);
        assert!(invocation.error.is_none());
        let result = invocation.result.unwrap();
        assert_eq!(result["event"]["delivery_id"], "native-envelope-1");
        assert_eq!(
            result["event"]["resource_uri"],
            "github://octocat/hello-world/issues/42"
        );

        // A duplicate delivery is a connector error, not a successful envelope.
        let error = handle_message(&mut connector, &request.to_string()).await;
        assert_eq!(error["id"], 73);
        assert!(error.get("result").is_none());
        assert!(
            error["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("duplicate webhook delivery_id"))
        );
    }

    #[fcp_async_core::runtime::test]
    async fn invalid_json_is_wrapped_in_jsonrpc_parse_error() {
        let mut connector = GitHubConnector::new();
        let response = handle_message(&mut connector, "{not json").await;

        assert_eq!(response["jsonrpc"], "2.0");
        assert!(response["id"].is_null());
        assert_eq!(response["error"]["code"], "FCP-1001");
        assert!(
            response["error"]["message"]
                .as_str()
                .unwrap()
                .starts_with("Invalid JSON:")
        );
    }
}
