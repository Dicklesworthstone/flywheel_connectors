//! FCP Anthropic Connector - Main entrypoint
//!
//! An Anthropic Claude API connector implementing the Flywheel Connector Protocol.
//! Provides access to Claude models with cost tracking and streaming support.

#![forbid(unsafe_code)]
#![allow(dead_code)] // Connector API types/methods wired incrementally
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
use fcp_core::{FcpError, FcpResult, InvokeRequest};
use fcp_sdk::prelude::{JsonlConfig, dispatch_raw_invoke, serve_jsonl};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use fcp_anthropic::connector::AnthropicConnector;

fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    tracing::info!("FCP Anthropic Connector starting");

    // Run the FCP protocol loop on stdin/stdout
    run_fcp_loop()?;

    Ok(())
}

/// Run the FCP JSON-RPC style protocol loop.
fn run_fcp_loop() -> Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    run_fcp_loop_with_io(stdin.lock(), &mut stdout)
}

fn run_fcp_loop_with_io<R: BufRead, W: Write>(reader: R, stdout: &mut W) -> Result<()> {
    let mut connector = AnthropicConnector::new();
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    let result = serve_jsonl(reader, stdout, JsonlConfig::default(), |method, params| {
        runtime.block_on(dispatch_message(&mut connector, method, params))
    });
    // Closing either transport direction terminates the account authority.
    let _ = runtime.block_on(connector.handle_shutdown(serde_json::json!({})));
    result?;
    Ok(())
}

async fn dispatch_message(
    connector: &mut AnthropicConnector,
    method: &str,
    params: serde_json::Value,
) -> FcpResult<serde_json::Value> {
    match method {
        "configure" => connector.handle_configure(params).await,
        "handshake" => connector.handle_handshake(params).await,
        "health" => connector.handle_health().await,
        "doctor" => connector.handle_doctor().await,
        "self_check" => connector.handle_self_check().await,
        "introspect" => connector.handle_introspect().await,
        "invoke" => {
            let request: InvokeRequest =
                serde_json::from_value(params.clone()).map_err(|_| FcpError::InvalidRequest {
                    code: 1003,
                    message: "Invalid invoke request".into(),
                })?;
            if request.r#type != "invoke" {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Expected invoke request type".into(),
                });
            }
            dispatch_raw_invoke(params, |params| connector.handle_invoke(params)).await
        }
        "simulate" => connector.handle_simulate(params).await,
        "shutdown" => connector.handle_shutdown(params).await,
        _ => Err(FcpError::InvalidRequest {
            code: 1002,
            message: format!("Unknown method: {method}"),
        }),
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
        let mut output = Vec::new();
        run_fcp_loop_with_io(std::io::Cursor::new(b"\n \t \n"), &mut output).unwrap();
        assert!(output.is_empty());
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

    #[test]
    fn invalid_json_is_wrapped_in_jsonrpc_parse_error() {
        let mut output = Vec::new();
        run_fcp_loop_with_io(std::io::Cursor::new(b"{not json\n"), &mut output).unwrap();
        let response: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(response["jsonrpc"], "2.0");
        assert!(response["id"].is_null());
        assert_eq!(response["error"]["code"], "FCP-1001");
    }
}
