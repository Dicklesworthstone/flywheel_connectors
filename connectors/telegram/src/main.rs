//! FCP Telegram Connector - Main entrypoint
//!
//! A Telegram Bot API connector implementing the Flywheel Connector Protocol.
//! Uses polling (getUpdates) for receiving messages and the Bot API for sending.

#![forbid(unsafe_code)]
#![recursion_limit = "256"]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::collapsible_if,
    clippy::doc_markdown,
    clippy::field_reassign_with_default,
    clippy::future_not_send,
    clippy::large_enum_variant,
    clippy::large_futures,
    clippy::manual_let_else,
    clippy::map_unwrap_or,
    clippy::missing_const_for_fn,
    clippy::missing_errors_doc,
    clippy::option_if_let_else,
    clippy::or_fun_call,
    clippy::redundant_closure_for_method_calls,
    clippy::single_match_else,
    clippy::single_match,
    clippy::assertions_on_constants,
    clippy::match_same_arms,
    clippy::struct_field_names,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async,
    clippy::use_self,
    clippy::wildcard_imports
)]

use std::io::BufReader;

use anyhow::Result;
use fcp_async_core::runtime::Builder;
use fcp_sdk::prelude::{
    JsonlConfig, JsonlEventStream, JsonlWriter, dispatch_raw_invoke, serve_jsonl_events,
};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use fcp_telegram::connector::TelegramConnector;

fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    tracing::info!("FCP Telegram Connector starting");

    // Run the FCP protocol loop on stdin/stdout
    run_fcp_loop()?;

    Ok(())
}

/// Run the FCP JSON-RPC style protocol loop.
fn run_fcp_loop() -> Result<()> {
    let writer = JsonlWriter::new(std::io::stdout());
    let events = JsonlEventStream::new(writer);
    let mut connector = TelegramConnector::new();
    connector.attach_event_stream(events.clone())?;
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    let result = serve_jsonl_events(
        BufReader::new(std::io::stdin()),
        events,
        JsonlConfig::default(),
        |method, params| runtime.block_on(dispatch_message(&mut connector, method, params)),
    );
    // EOF and framing failure have the same bounded cleanup as an explicit
    // shutdown. No outstanding event can turn a lost transport into an ACK.
    let _ = runtime.block_on(connector.handle_shutdown(serde_json::json!({})));
    result?;
    Ok(())
}

#[cfg(test)]
fn should_skip_protocol_line(line: &str) -> bool {
    line.trim().is_empty()
}

#[cfg(test)]
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
#[cfg(test)]
async fn handle_message(connector: &mut TelegramConnector, message: &str) -> serde_json::Value {
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

    let result = dispatch_message(connector, method, params).await;

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

async fn dispatch_message(
    connector: &mut TelegramConnector,
    method: &str,
    params: serde_json::Value,
) -> fcp_core::FcpResult<serde_json::Value> {
    match method {
        "configure" => connector.handle_configure(params).await,
        "handshake" => connector.handle_handshake(params).await,
        "health" => {
            serde_json::to_value(fcp_core::FcpConnector::health(connector).await).map_err(|_| {
                fcp_core::FcpError::Internal {
                    message: "Failed to serialize Telegram health snapshot".into(),
                }
            })
        }
        "doctor" => connector.handle_doctor().await,
        "self_check" => connector.handle_self_check().await,
        "introspect" => connector.handle_introspect().await,
        "invoke" => dispatch_raw_invoke(params, |params| connector.handle_invoke(params)).await,
        "simulate" => connector.handle_simulate(params).await,
        "subscribe" => connector.handle_subscribe(params).await,
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

    #[fcp_async_core::runtime::test]
    async fn invoke_requires_an_inner_string_id_before_dispatch() {
        let mut connector = TelegramConnector::new();
        for inner_id in [
            None,
            Some(serde_json::Value::Null),
            Some(serde_json::json!(7)),
            Some(serde_json::json!({"nested": "id"})),
        ] {
            let mut params = serde_json::json!({
                "operation": "telegram.send_message",
                "input": {"chat_id": "123", "text": "hello"}
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
        let mut connector = TelegramConnector::new();
        let params = serde_json::json!({
            "id": "invocation:error",
            "operation": "telegram.send_message",
            "input": {"chat_id": "123", "text": "hello"}
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
        let mut connector = TelegramConnector::new();
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
