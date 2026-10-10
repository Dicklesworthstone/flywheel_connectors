//! FCP Airtable Connector - Main entrypoint
//!
//! An Airtable connector implementing the Flywheel Connector Protocol.
//! Provides access to bases, tables, records, and attachments.

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
use fcp_sdk::prelude::{JsonlConfig, serve_jsonl};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use fcp_airtable::connector::AirtableConnector;

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    tracing::info!("FCP Airtable Connector starting");

    run_fcp_loop()?;

    Ok(())
}

/// Run the FCP JSON-RPC style protocol loop.
fn run_fcp_loop() -> Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    run_fcp_loop_with_io(stdin.lock(), stdout.lock(), JsonlConfig::default())
}

/// Share the production framing and dispatcher with in-memory regression tests.
fn run_fcp_loop_with_io(
    reader: impl BufRead,
    writer: impl Write,
    config: JsonlConfig,
) -> Result<()> {
    let mut connector = AirtableConnector::new();
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    serve_jsonl(reader, writer, config, |method, params| {
        runtime.block_on(dispatch(&mut connector, method, params))
    })?;
    Ok(())
}

/// Dispatch a validated envelope without changing operation-specific validation.
async fn dispatch(
    connector: &mut AirtableConnector,
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
        "invoke" => connector.handle_invoke(params).await,
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
    use std::io::Cursor;

    use super::*;
    use serde_json::Value;

    fn responses(bytes: &[u8]) -> Vec<Value> {
        bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).expect("JSON response"))
            .collect()
    }

    #[test]
    fn protocol_loop_skips_whitespace_only_lines() {
        let mut output = Vec::new();
        run_fcp_loop_with_io(
            Cursor::new(b"\n \t\r\n\n"),
            &mut output,
            JsonlConfig::default(),
        )
        .unwrap();
        assert!(output.is_empty());
    }

    #[test]
    fn invalid_json_is_wrapped_and_next_request_still_runs() {
        let input = b"{not json\n{\"method\":\"health\",\"id\":9}\n";
        let mut output = Vec::new();
        run_fcp_loop_with_io(Cursor::new(input), &mut output, JsonlConfig::default()).unwrap();

        let replies = responses(&output);
        assert_eq!(replies.len(), 2);
        assert_eq!(replies[0]["jsonrpc"], "2.0");
        assert!(replies[0]["id"].is_null());
        assert_eq!(replies[0]["error"]["code"], "FCP-1001");
        assert!(
            replies[0]["error"]["message"]
                .as_str()
                .is_some_and(|message| message.starts_with("Invalid JSON:"))
        );
        assert_eq!(replies[1]["id"], 9);
        assert!(replies[1].get("result").is_some());
    }

    #[test]
    fn shutdown_requests_exit_after_acknowledgement() {
        let shutdown = b"{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"shutdown\",\"params\":{}}\n";
        let mut input = shutdown.to_vec();
        input.extend_from_slice(b"{\"method\":\"invoke\",\"id\":8}\n");
        let mut reader = Cursor::new(input);
        let mut output = Vec::new();
        run_fcp_loop_with_io(&mut reader, &mut output, JsonlConfig::default()).unwrap();

        assert_eq!(reader.position(), shutdown.len() as u64);
        let replies = responses(&output);
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0]["jsonrpc"], "2.0");
        assert_eq!(replies[0]["id"], 7);
        assert_eq!(replies[0]["result"]["status"], "shutdown");
    }

    #[test]
    fn non_shutdown_requests_keep_protocol_loop_running() {
        let input = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"health\",\"params\":{}}\n",
            "{\"method\":\"health\",\"id\":10}\n",
            "{\"method\":\"shutdown\",\"id\":11}\n",
        );
        let mut output = Vec::new();
        run_fcp_loop_with_io(
            Cursor::new(input.as_bytes()),
            &mut output,
            JsonlConfig::default(),
        )
        .unwrap();

        let replies = responses(&output);
        assert_eq!(replies.len(), 3);
        for (reply, id) in replies.iter().zip([9, 10, 11]) {
            assert_eq!(reply["jsonrpc"], "2.0");
            assert_eq!(reply["id"], id);
            assert!(reply.get("result").is_some());
        }
        assert_eq!(replies[2]["result"]["status"], "shutdown");
    }

    #[test]
    fn malformed_shutdown_envelope_does_not_stop_the_connector() {
        let input = concat!(
            "{\"jsonrpc\":\"1.0\",\"method\":\"shutdown\",\"id\":1}\n",
            "{\"method\":\"health\",\"id\":2}\n",
            "{\"method\":\"shutdown\",\"id\":3}\n",
        );
        let mut output = Vec::new();
        run_fcp_loop_with_io(
            Cursor::new(input.as_bytes()),
            &mut output,
            JsonlConfig::default(),
        )
        .unwrap();

        let replies = responses(&output);
        assert_eq!(replies.len(), 3);
        assert_eq!(replies[0]["id"], 1);
        assert_eq!(replies[0]["error"]["code"], "FCP-1001");
        assert_eq!(replies[1]["id"], 2);
        assert!(replies[1].get("result").is_some());
        assert_eq!(replies[2]["result"]["status"], "shutdown");
    }

    #[test]
    fn oversized_input_stops_before_dispatch_or_follow_on_requests() {
        let input = concat!(
            "{\"method\":\"configure\",\"params\":{\"token\":\"must-not-be-used\"}}\n",
            "{\"method\":\"shutdown\"}\n",
        );
        let mut reader = Cursor::new(input.as_bytes());
        let mut output = Vec::new();
        let result = run_fcp_loop_with_io(
            &mut reader,
            &mut output,
            JsonlConfig {
                max_request_bytes: 16,
            },
        );

        assert!(result.is_err());
        assert_eq!(reader.position(), 18);
        let replies = responses(&output);
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0]["error"]["code"], "FCP-1004");
        assert!(!String::from_utf8(output).unwrap().contains("must-not-be-used"));
    }
}
