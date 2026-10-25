//! FCP Discord Connector - Main entrypoint
//!
//! A Discord Bot connector implementing the Flywheel Connector Protocol.
//! Uses the Discord Gateway (WebSocket) for real-time events and REST API for operations.

#![forbid(unsafe_code)]
#![recursion_limit = "256"]
#![allow(dead_code)] // Connector API types/methods wired incrementally
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::float_cmp,
    clippy::future_not_send,
    clippy::large_enum_variant,
    clippy::map_unwrap_or,
    clippy::match_same_arms,
    clippy::match_wildcard_for_single_variants,
    clippy::missing_errors_doc,
    clippy::option_if_let_else,
    clippy::or_fun_call,
    clippy::redundant_closure_for_method_calls,
    clippy::assertions_on_constants,
    clippy::struct_field_names,
    clippy::too_many_lines,
    clippy::unnecessary_wraps,
    clippy::unreadable_literal,
    clippy::unused_async,
    clippy::wildcard_imports
)]

use std::io::{BufRead, Write};

use anyhow::Result;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

mod api;
mod config;
mod connector;
mod error;
mod gateway;
mod limits;
mod types;

use connector::DiscordConnector;

fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    tracing::info!("FCP Discord Connector starting");

    // Run the FCP protocol loop on stdin/stdout
    run_fcp_loop()?;

    Ok(())
}

/// Run the FCP JSON-RPC style protocol loop.
fn run_fcp_loop() -> Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut connector = DiscordConnector::new();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }

        let response =
            fcp_async_core::runtime::block_on_sync(handle_message(&mut connector, &line))
                .unwrap_or_else(|e| {
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "error": {
                            "code": "FCP-9001",
                            "message": format!("Runtime error: {e}")
                        }
                    })
                });

        let response_json = serde_json::to_string(&response)?;
        writeln!(stdout, "{response_json}")?;
        stdout.flush()?;
    }

    Ok(())
}

/// Handle a single FCP message.
async fn handle_message(connector: &mut DiscordConnector, message: &str) -> serde_json::Value {
    let request: serde_json::Value = match serde_json::from_str(message) {
        Ok(v) => v,
        Err(e) => {
            return serde_json::json!({
                "jsonrpc": "2.0",
                "id": serde_json::Value::Null,
                "error": {
                    "code": "FCP-1001",
                    "message": format!("Invalid JSON: {e}")
                }
            });
        }
    };

    let method = request.get("method").and_then(|v| v.as_str()).unwrap_or("");
    let id = request.get("id").cloned();
    let params = request
        .get("params")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));

    let result = match method {
        "configure" => connector.handle_configure(params).await,
        "handshake" => connector.handle_handshake(params).await,
        "health" => connector.handle_health().await,
        "doctor" => connector.handle_doctor().await,
        "self_check" => connector.handle_self_check().await,
        "introspect" => connector.handle_introspect().await,
        "invoke" => connector.handle_invoke(params).await,
        "simulate" => connector.handle_simulate(params).await,
        "subscribe" => connector.handle_subscribe(params).await,
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
    fn invalid_json_returns_jsonrpc_parse_error_shape() {
        let response = fcp_async_core::runtime::block_on_sync(async {
            let mut connector = DiscordConnector::new();
            handle_message(&mut connector, "{").await
        })
        .unwrap();

        assert_eq!(response["jsonrpc"], "2.0");
        assert!(response["id"].is_null());
        assert_eq!(response["error"]["code"], "FCP-1001");
    }
}
