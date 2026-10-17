//! FCP Slack Connector - Main entrypoint
//!
//! A Slack workspace connector implementing the Flywheel Connector Protocol.
//! Provides access to channels, messages, users, files, reactions, and threads.

#![forbid(unsafe_code)]
#![recursion_limit = "256"]
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

use fcp_slack::connector::SlackConnector;

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    tracing::info!("FCP Slack Connector starting");

    run_fcp_loop()?;

    Ok(())
}

/// Run the FCP JSON-RPC style protocol loop.
fn run_fcp_loop() -> Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    run_fcp_loop_with_io(stdin.lock(), &mut stdout)
}

fn run_fcp_loop_with_io<R, W>(reader: R, stdout: &mut W) -> Result<()>
where
    R: BufRead,
    W: Write,
{
    let mut connector = SlackConnector::new();

    let runtime = Builder::new_multi_thread().enable_all().build()?;

    for line in reader.lines() {
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
async fn handle_message(connector: &mut SlackConnector, message: &str) -> serde_json::Value {
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
        "subscribe" => connector.handle_subscribe(params).await,
        "invoke" => connector.handle_invoke(params).await,
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
    use std::io::{self, BufReader, Read};

    use super::*;

    struct ErrorAfterBytes {
        bytes: &'static [u8],
        position: usize,
        error_kind: io::ErrorKind,
        error_message: &'static str,
        did_error: bool,
    }

    impl ErrorAfterBytes {
        fn new(
            bytes: &'static [u8],
            error_kind: io::ErrorKind,
            error_message: &'static str,
        ) -> Self {
            Self {
                bytes,
                position: 0,
                error_kind,
                error_message,
                did_error: false,
            }
        }
    }

    impl Read for ErrorAfterBytes {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.position < self.bytes.len() {
                let remaining = &self.bytes[self.position..];
                let bytes_to_copy = remaining.len().min(buf.len());
                buf[..bytes_to_copy].copy_from_slice(&remaining[..bytes_to_copy]);
                self.position += bytes_to_copy;
                return Ok(bytes_to_copy);
            }

            if self.did_error {
                return Ok(0);
            }

            self.did_error = true;
            Err(io::Error::new(self.error_kind, self.error_message))
        }
    }

    #[test]
    fn protocol_loop_skips_whitespace_only_lines() {
        assert!(should_skip_protocol_line(""));
        assert!(should_skip_protocol_line(" \t "));
        assert!(!should_skip_protocol_line("{\"jsonrpc\":\"2.0\"}"));
    }

    #[test]
    fn protocol_loop_propagates_input_read_errors() {
        let reader = BufReader::new(ErrorAfterBytes::new(
            b"   \n",
            io::ErrorKind::ConnectionReset,
            "simulated read failure",
        ));
        let mut output = Vec::new();
        let error = run_fcp_loop_with_io(reader, &mut output)
            .expect_err("input read error should propagate");
        let io_error = error
            .downcast_ref::<io::Error>()
            .expect("error should preserve io::Error");

        assert_eq!(io_error.kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(io_error.to_string(), "simulated read failure");
        assert!(
            output.is_empty(),
            "whitespace-only input should not emit a response"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn invalid_json_is_wrapped_in_jsonrpc_parse_error() {
        let mut connector = SlackConnector::new();
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
