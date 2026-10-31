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

use std::io::{BufRead, BufReader, Write};

use anyhow::Result;
use fcp_async_core::runtime::Builder;
use fcp_sdk::prelude::{JsonlConfig, JsonlEventStream, JsonlWriter, serve_jsonl_events};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use fcp_discord::DiscordConnector;

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
    run_fcp_loop_with_io(BufReader::new(std::io::stdin()), std::io::stdout())
}

fn run_fcp_loop_with_io<R, W>(reader: R, stdout: W) -> Result<()>
where
    R: BufRead + Send + 'static,
    W: Write + Send + 'static,
{
    let events = JsonlEventStream::new(JsonlWriter::new(stdout));
    let mut connector = DiscordConnector::new();
    connector.attach_event_stream(events.clone())?;
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    let result = serve_jsonl_events(reader, events, JsonlConfig::default(), |method, params| {
        runtime.block_on(dispatch_message(&mut connector, method, params))
    });
    // The reader closes outstanding native obligations on EOF or transport
    // failure. Join the Gateway before releasing its checkpoint writer lease.
    let shutdown = runtime.block_on(connector.handle_shutdown(serde_json::json!({})));
    result?;
    shutdown?;
    Ok(())
}

/// Handle a single FCP message.
#[cfg(test)]
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
    connector: &mut DiscordConnector,
    method: &str,
    params: serde_json::Value,
) -> fcp_core::FcpResult<serde_json::Value> {
    match method {
        "configure" => connector.handle_configure(params).await,
        "handshake" => connector.handle_handshake(params).await,
        "health" => connector.handle_native_health().await,
        "doctor" => connector.handle_doctor().await,
        "self_check" => connector.handle_self_check().await,
        "introspect" => connector.handle_introspect().await,
        "invoke" => {
            fcp_sdk::prelude::dispatch_raw_invoke(params, |params| connector.handle_invoke(params))
                .await
        }
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
    use std::{
        io,
        sync::{Arc, Mutex},
    };

    #[derive(Clone, Default)]
    struct CapturedOutput(Arc<Mutex<Vec<u8>>>);

    impl Write for CapturedOutput {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn production_loop_serves_canonical_health_and_drains_on_eof() {
        let output = CapturedOutput::default();
        run_fcp_loop_with_io(
            io::Cursor::new(
                b" \t\n{\"jsonrpc\":\"2.0\",\"id\":\"health\",\"method\":\"health\"}\n",
            ),
            output.clone(),
        )
        .expect("health RPC and EOF shutdown must complete");
        let bytes = output.0.lock().unwrap();
        let response: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(response["id"], "health");
        let snapshot: fcp_core::HealthSnapshot =
            serde_json::from_value(response["result"].clone()).unwrap();
        let details = snapshot.details.unwrap();
        assert_eq!(details["configured"], false);
        assert_eq!(details["handshaken"], false);
        assert_eq!(details["gateway_running"], false);
        assert!(details["instance_id"].is_string());
    }

    #[test]
    fn production_loop_rejects_invalid_json_and_does_not_reply_to_native_controls() {
        let output = CapturedOutput::default();
        run_fcp_loop_with_io(
            io::Cursor::new(b"{\n{\"jsonrpc\":\"2.0\",\"method\":\"ack\",\"params\":{\"stream_id\":\"unknown\"}}\n{\"jsonrpc\":\"2.0\",\"id\":\"stop\",\"method\":\"shutdown\"}\n"),
            output.clone(),
        ).unwrap();
        let bytes = output.0.lock().unwrap();
        let responses: Vec<serde_json::Value> = bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect();
        assert_eq!(
            responses.len(),
            2,
            "native controls are notifications, even when invalid"
        );
        assert!(
            responses
                .iter()
                .any(|response| response["error"]["code"] == "FCP-1001")
        );
        assert!(
            responses
                .iter()
                .any(|response| response["id"] == "stop" && response["result"].is_object())
        );
    }

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
