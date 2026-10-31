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
use fcp_async_core::runtime::{Builder, Runtime};
use fcp_sdk::prelude::{JsonlConfig, dispatch_raw_invoke, serve_jsonl};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use fcp_gmail::connector::GmailConnector;

// Leave room for encoded MIME payloads while bounding the frame before allocation.
const MAX_REQUEST_BYTES: usize = 32 * 1024 * 1024;

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
    let stdout = std::io::stdout();
    let mut connector = GmailConnector::new();
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    run_fcp_io(&runtime, &mut connector, stdin.lock(), stdout.lock())
}

fn run_fcp_io(
    runtime: &Runtime,
    connector: &mut GmailConnector,
    reader: impl BufRead,
    writer: impl Write,
) -> Result<()> {
    let result = serve_jsonl(
        reader,
        writer,
        JsonlConfig {
            max_request_bytes: MAX_REQUEST_BYTES,
        },
        |method, params| runtime.block_on(handle_method(connector, method, params)),
    );
    // EOF, oversized frames, and broken transports revoke the same authority
    // and close the same client runtime as an explicit shutdown.
    runtime.block_on(connector.handle_shutdown(serde_json::json!({})))?;
    result?;
    Ok(())
}

/// Dispatch a request validated by the shared native JSONL transport.
async fn handle_method(
    connector: &mut GmailConnector,
    method: &str,
    params: serde_json::Value,
) -> fcp_core::FcpResult<serde_json::Value> {
    match method {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handle_message(
        runtime: &Runtime,
        connector: &mut GmailConnector,
        message: &str,
    ) -> serde_json::Value {
        let mut output = Vec::new();
        serve_jsonl(
            std::io::Cursor::new(format!("{message}\n")),
            &mut output,
            JsonlConfig {
                max_request_bytes: MAX_REQUEST_BYTES,
            },
            |method, params| runtime.block_on(handle_method(connector, method, params)),
        )
        .unwrap();
        serde_json::from_slice(&output).unwrap()
    }

    #[test]
    fn native_host_session_preserves_scope_budgets_and_typed_results() {
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

        let runtime = Builder::new_multi_thread().enable_all().build().unwrap();
        let server = runtime.block_on(MockServer::start());
        let credential = "00000000-0000-0000-0000-000000000001";
        runtime.block_on(
            Mock::given(method("GET"))
                .and(path("/users/me/labels"))
                .and(header(FCP_CREDENTIAL_ID_HEADER, credential))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(json!({"labels": [{"id":"INBOX", "name":"INBOX"}]})),
                )
                .expect(1)
                .mount(&server),
        );
        let mut connector = GmailConnector::new();
        let configured = handle_message(
            &runtime,
            &mut connector,
            &json!({
                "jsonrpc":"2.0", "id":"rpc-configure", "method":"configure",
                "params":{"credential_id":credential, "base_url":server.uri()},
            })
            .to_string(),
        );
        assert!(configured.get("error").is_none(), "{configured}");
        let key = Ed25519SigningKey::generate();
        let preferred = connector.instance_id().clone();
        let handshake = handle_message(
            &runtime,
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
        );
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
            &runtime,
            &mut connector,
            &json!({
                "jsonrpc":"2.0", "id":"rpc-health", "method":"health", "params":{},
            })
            .to_string(),
        );
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
                &runtime,
                &mut connector,
                &json!({
                    "jsonrpc":"2.0", "id":"rpc-denied", "method":"invoke", "params":denied,
                })
                .to_string(),
            );
            assert!(reply.get("error").is_some(), "scope field {field}: {reply}");
        }
        assert!(
            runtime
                .block_on(server.received_requests())
                .unwrap()
                .is_empty()
        );
        // Authorization previews do not spend the one admitted provider call.
        for _ in 0..2 {
            let preview = handle_message(
                &runtime,
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
            );
            assert_eq!(preview["result"]["would_succeed"], true, "{preview}");
        }
        let reply = handle_message(
            &runtime,
            &mut connector,
            &json!({
                "jsonrpc":"2.0", "id":"rpc-invoke", "method":"invoke", "params":params,
            })
            .to_string(),
        );
        assert_eq!(reply["id"], "rpc-invoke");
        let response: InvokeResponse = serde_json::from_value(reply["result"].clone()).unwrap();
        assert_eq!(response.id.0, "mailbox-read");
        assert_eq!(response.status, InvokeStatus::Ok);
        assert_eq!(response.result.unwrap()["labels"][0]["id"], "INBOX");
        let spent = handle_message(
            &runtime,
            &mut connector,
            &json!({
                "jsonrpc":"2.0", "id":"rpc-spent", "method":"invoke", "params":params,
            })
            .to_string(),
        );
        assert!(spent.get("error").is_some());
        assert_eq!(
            runtime.block_on(server.received_requests()).unwrap().len(),
            1
        );
    }

    #[test]
    fn invoke_requires_an_inner_string_id_before_dispatch() {
        let runtime = Builder::new_multi_thread().enable_all().build().unwrap();
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
                &runtime,
                &mut connector,
                &serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": "transport:invalid",
                    "method": "invoke",
                    "params": params
                })
                .to_string(),
            );

            assert_eq!(response["id"], "transport:invalid");
            assert_eq!(response["error"]["code"], "FCP-1003");
            assert_eq!(
                response["error"]["message"],
                "Invalid request: invoke params.id must be a string"
            );
            assert!(response.get("result").is_none());
        }
    }

    #[test]
    fn invoke_preserves_handler_errors_and_the_outer_id() {
        let runtime = Builder::new_multi_thread().enable_all().build().unwrap();
        let mut connector = GmailConnector::new();
        let params = serde_json::json!({
            "id": "invocation:error",
            "operation": "gmail.list_labels",
            "input": {}
        });
        let expected = runtime
            .block_on(connector.handle_invoke(params.clone()))
            .expect_err("unconfigured invocation must fail")
            .to_response();
        let response = handle_message(
            &runtime,
            &mut connector,
            &serde_json::json!({
                "jsonrpc": "2.0",
                "id": "transport:error",
                "method": "invoke",
                "params": params
            })
            .to_string(),
        );

        assert_eq!(response["id"], "transport:error");
        assert_eq!(response["error"], serde_json::to_value(expected).unwrap());
        assert!(response.get("result").is_none());
    }

    #[test]
    fn protocol_loop_skips_whitespace_only_lines() {
        let runtime = Builder::new_multi_thread().enable_all().build().unwrap();
        let mut connector = GmailConnector::new();
        let mut output = Vec::new();
        run_fcp_io(
            &runtime,
            &mut connector,
            std::io::Cursor::new("\n \t \n\r\n"),
            &mut output,
        )
        .unwrap();
        assert!(output.is_empty());
    }

    #[test]
    fn invalid_json_is_wrapped_in_jsonrpc_parse_error() {
        let runtime = Builder::new_multi_thread().enable_all().build().unwrap();
        let mut connector = GmailConnector::new();
        let response = handle_message(&runtime, &mut connector, "{not json");

        assert_eq!(response["jsonrpc"], "2.0");
        assert!(response["id"].is_null());
        assert_eq!(response["error"]["code"], "FCP-1001");
        assert!(
            response["error"]["message"]
                .as_str()
                .is_some_and(|message| message.starts_with("Invalid JSON:"))
        );
    }

    #[test]
    fn native_stream_stops_at_shutdown_and_revokes_authority_at_eof() {
        use fcp_core::HealthSnapshot;
        use fcp_crypto::ed25519::Ed25519SigningKey;
        use serde_json::{Value, json};

        let runtime = Builder::new_multi_thread().enable_all().build().unwrap();
        let key = Ed25519SigningKey::generate();
        for explicit_shutdown in [false, true] {
            let mut connector = GmailConnector::new();
            let mut requests = vec![
                json!({ "jsonrpc": "2.0", "id": "config", "method": "configure",
                    "params": { "access_token": "private-fixture-token" } }),
                json!({ "jsonrpc": "2.0", "id": "hello", "method": "handshake",
                    "params": {
                        "protocol_version": "2.0", "zone": "z:private",
                        "host_public_key": key.verifying_key().to_bytes(), "nonce": vec![7u8; 32],
                        "capabilities_requested": ["gmail.read"]
                    } }),
                json!({ "jsonrpc": "2.0", "id": "ready", "method": "health", "params": {} }),
            ];
            if explicit_shutdown {
                requests.push(json!({
                    "jsonrpc": "2.0", "id": "stop", "method": "shutdown", "params": {}
                }));
                requests.push(json!({
                    "jsonrpc": "2.0", "id": "after-stop", "method": "health", "params": {}
                }));
            }
            let input = requests
                .iter()
                .map(Value::to_string)
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
            let mut output = Vec::new();
            run_fcp_io(
                &runtime,
                &mut connector,
                std::io::Cursor::new(input),
                &mut output,
            )
            .unwrap();
            let text = String::from_utf8(output).unwrap();
            assert!(!text.contains("private-fixture-token"));
            let responses: Vec<Value> = text
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            assert_eq!(responses.len(), if explicit_shutdown { 4 } else { 3 });
            let ready: HealthSnapshot =
                serde_json::from_value(responses[2]["result"].clone()).unwrap();
            assert!(ready.is_ready());
            let stopped: HealthSnapshot =
                serde_json::from_value(runtime.block_on(connector.handle_health()).unwrap())
                    .unwrap();
            assert!(!stopped.is_ready());
            let details = stopped.details.unwrap();
            assert_eq!(details["configured"], false);
            assert_eq!(details["handshaken"], false);
        }
    }

    #[test]
    fn oversized_native_frame_closes_stream_and_revokes_configuration() {
        let runtime = Builder::new_multi_thread().enable_all().build().unwrap();
        let mut connector = GmailConnector::new();
        runtime
            .block_on(connector.handle_configure(serde_json::json!({
                "access_token": "private-fixture-token"
            })))
            .unwrap();
        let input = vec![b'x'; MAX_REQUEST_BYTES + 1];
        let mut output = Vec::new();
        let error = run_fcp_io(
            &runtime,
            &mut connector,
            std::io::Cursor::new(input),
            &mut output,
        )
        .unwrap_err();
        assert!(error.to_string().contains("byte limit"));
        let response: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(response["error"]["code"], "FCP-1004");
        let health = runtime.block_on(connector.handle_health()).unwrap();
        assert_eq!(health["details"]["configured"], false);
        assert_eq!(health["details"]["handshaken"], false);
    }
}
