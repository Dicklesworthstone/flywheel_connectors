//! FCP Gmail Connector - Main entrypoint
//!
//! A Gmail connector implementing the Flywheel Connector Protocol.
//! Provides access to messages, threads, labels, and drafts.

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
use fcp_sdk::prelude::dispatch_raw_invoke;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use fcp_gmail::connector::GmailConnector;

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    tracing::info!("FCP Gmail Connector starting");

    run_fcp_loop()?;

    Ok(())
}

/// Run the FCP JSON-RPC style protocol loop.
fn run_fcp_loop() -> Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut connector = GmailConnector::new();

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
async fn handle_message(connector: &mut GmailConnector, message: &str) -> serde_json::Value {
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
        "invoke" => dispatch_raw_invoke(params, |params| connector.handle_invoke(params)).await,
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

    #[fcp_async_core::runtime::test]
    async fn native_host_session_preserves_scope_budgets_and_typed_results() {
        use chrono::{Duration, Utc};
        use fcp_core::{
            CapabilityConstraints, CapabilityToken, HealthSnapshot, InvokeResponse, InvokeStatus,
        };
        use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
        use fcp_google_discovery::auth::FCP_CREDENTIAL_ID_HEADER;
        use serde_json::json;
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{header, method, path},
        };

        let server = MockServer::start().await;
        let credential = "00000000-0000-0000-0000-000000000001";
        Mock::given(method("GET"))
            .and(path("/users/me/labels"))
            .and(header(FCP_CREDENTIAL_ID_HEADER, credential))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"labels": [{"id":"INBOX", "name":"INBOX"}]})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let mut connector = GmailConnector::new();
        let configured = handle_message(
            &mut connector,
            &json!({
                "jsonrpc":"2.0", "id":"rpc-configure", "method":"configure",
                "params":{"credential_id":credential, "base_url":server.uri()},
            })
            .to_string(),
        )
        .await;
        assert!(configured.get("error").is_none(), "{configured}");
        let key = Ed25519SigningKey::generate();
        let preferred = connector.instance_id().clone();
        let handshake = handle_message(
            &mut connector,
            &json!({
                "jsonrpc":"2.0", "id":"rpc-handshake", "method":"handshake",
                "params":{
                    "protocol_version":"2.0", "zone":"z:private",
                    "host_public_key":key.verifying_key().to_bytes(), "nonce":vec![9u8;32],
                    "capabilities_requested":["gmail.read", "gmail.read", "unrelated.admin"],
                    "requested_instance_id":preferred,
                },
            })
            .to_string(),
        )
        .await;
        assert!(handshake.get("error").is_none(), "{handshake}");
        assert_eq!(
            handshake["result"]["capabilities_granted"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_ne!(connector.instance_id(), &preferred);
        assert_eq!(
            handshake["result"]["instance_id"],
            json!(connector.instance_id())
        );
        let health = handle_message(
            &mut connector,
            &json!({
                "jsonrpc":"2.0", "id":"rpc-health", "method":"health", "params":{},
            })
            .to_string(),
        )
        .await;
        let health: HealthSnapshot = serde_json::from_value(health["result"].clone()).unwrap();
        assert!(health.is_ready());
        let details = health.details.unwrap();
        assert_eq!(details["configured"], true);
        assert_eq!(details["handshaken"], true);
        assert_eq!(details["instance_id"], json!(connector.instance_id()));

        let constraints = CapabilityConstraints {
            resource_allow: vec!["gmail:labels".into()],
            max_calls: Some(1),
            idempotency_key: Some("labels-once".into()),
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).unwrap();
        let now = Utc::now();
        let token = CapabilityToken::from_raw(
            CapabilityTokenBuilder::new()
                .capability_id("gmail.read")
                .zone_id("z:private")
                .principal("user:host")
                .operations(&["gmail.list_labels"])
                .issuer("node:host")
                .token_id(b"native-gmail-one-call")
                .target_instance(connector.instance_id().as_str())
                .validity(now, now + Duration::minutes(5))
                .try_constraints_cbor(&cbor)
                .unwrap()
                .sign(&key)
                .unwrap(),
        );
        let params = json!({
            "type":"invoke", "id":"mailbox-read", "connector_id":"fcp.gmail",
            "zone_id":"z:private", "operation":"gmail.list_labels", "input":{},
            "capability_token":token, "idempotency_key":"labels-once",
        });
        for (field, value) in [
            ("connector_id", json!("fcp.other")),
            ("zone_id", json!("z:owner")),
            ("idempotency_key", json!("different-call")),
        ] {
            let mut denied = params.clone();
            denied[field] = value;
            let reply = handle_message(
                &mut connector,
                &json!({
                    "jsonrpc":"2.0", "id":"rpc-denied", "method":"invoke", "params":denied,
                })
                .to_string(),
            )
            .await;
            assert!(reply.get("error").is_some(), "scope field {field}: {reply}");
        }
        assert!(server.received_requests().await.unwrap().is_empty());
        // Authorization previews do not spend the one admitted provider call.
        for _ in 0..2 {
            let preview = handle_message(
                &mut connector,
                &json!({
                    "jsonrpc":"2.0", "id":"rpc-preview", "method":"simulate",
                    "params":{
                        "type":"simulate", "id":"mailbox-preview", "connector_id":"fcp.gmail",
                        "zone_id":"z:private", "operation":"gmail.list_labels", "input":{},
                        "capability_token":params["capability_token"],
                    },
                })
                .to_string(),
            )
            .await;
            assert_eq!(preview["result"]["would_succeed"], true, "{preview}");
        }
        let reply = handle_message(
            &mut connector,
            &json!({
                "jsonrpc":"2.0", "id":"rpc-invoke", "method":"invoke", "params":params,
            })
            .to_string(),
        )
        .await;
        assert_eq!(reply["id"], "rpc-invoke");
        let response: InvokeResponse = serde_json::from_value(reply["result"].clone()).unwrap();
        assert_eq!(response.id.0, "mailbox-read");
        assert_eq!(response.status, InvokeStatus::Ok);
        assert_eq!(response.result.unwrap()["labels"][0]["id"], "INBOX");
        let spent = handle_message(
            &mut connector,
            &json!({
                "jsonrpc":"2.0", "id":"rpc-spent", "method":"invoke", "params":params,
            })
            .to_string(),
        )
        .await;
        assert!(spent.get("error").is_some());
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_requires_an_inner_string_id_before_dispatch() {
        let mut connector = GmailConnector::new();
        for inner_id in [
            None,
            Some(serde_json::Value::Null),
            Some(serde_json::json!(7)),
            Some(serde_json::json!({"nested": "id"})),
        ] {
            let mut params = serde_json::json!({
                "operation": "gmail.list_labels",
                "input": {}
            });
            if let Some(inner_id) = inner_id {
                params["id"] = inner_id;
            }
            let response = handle_message(
                &mut connector,
                &serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": "transport:invalid",
                    "method": "invoke",
                    "params": params
                })
                .to_string(),
            )
            .await;

            assert_eq!(response["id"], "transport:invalid");
            assert_eq!(response["error"]["code"], "FCP-1003");
            assert_eq!(
                response["error"]["message"],
                "Invalid request: invoke params.id must be a string"
            );
            assert!(response.get("result").is_none());
        }
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_preserves_handler_errors_and_the_outer_id() {
        let mut connector = GmailConnector::new();
        let params = serde_json::json!({
            "id": "invocation:error",
            "operation": "gmail.list_labels",
            "input": {}
        });
        let expected = connector
            .handle_invoke(params.clone())
            .await
            .expect_err("unconfigured invocation must fail")
            .to_response();
        let response = handle_message(
            &mut connector,
            &serde_json::json!({
                "jsonrpc": "2.0",
                "id": "transport:error",
                "method": "invoke",
                "params": params
            })
            .to_string(),
        )
        .await;

        assert_eq!(response["id"], "transport:error");
        assert_eq!(response["error"], serde_json::to_value(expected).unwrap());
        assert!(response.get("result").is_none());
    }

    #[test]
    fn protocol_loop_skips_whitespace_only_lines() {
        assert!(should_skip_protocol_line(""));
        assert!(should_skip_protocol_line(" \t "));
        assert!(!should_skip_protocol_line("{\"jsonrpc\":\"2.0\"}"));
    }

    #[fcp_async_core::runtime::test]
    async fn invalid_json_is_wrapped_in_jsonrpc_parse_error() {
        let mut connector = GmailConnector::new();
        let response = handle_message(&mut connector, "{not json").await;

        assert_eq!(response["jsonrpc"], "2.0");
        assert!(response["id"].is_null());
        assert_eq!(response["error"]["code"], "FCP-1001");
        assert!(
            response["error"]["message"]
                .as_str()
                .is_some_and(|message| message.starts_with("Invalid JSON:"))
        );
    }
}
