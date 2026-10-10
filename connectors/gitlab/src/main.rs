//! FCP `GitLab` Connector - Main entrypoint
//!
//! A `GitLab` connector implementing the Flywheel Connector Protocol.
//! Provides access to projects, issues, merge requests, and pipelines.

#![forbid(unsafe_code)]
#![allow(dead_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::derivable_impls,
    clippy::future_not_send,
    clippy::manual_unwrap_or_default,
    clippy::match_same_arms,
    clippy::option_if_let_else,
    clippy::or_fun_call,
    clippy::redundant_closure_for_method_calls,
    clippy::struct_field_names,
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

use fcp_gitlab::connector::GitLabConnector;

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    tracing::info!("FCP GitLab Connector starting");
    run_fcp_loop()?;
    Ok(())
}

fn run_fcp_loop() -> Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    run_fcp_loop_with_io(stdin.lock(), stdout.lock())
}

/// Use the same framing and dispatch path for stdio and in-memory regression tests.
fn run_fcp_loop_with_io(reader: impl BufRead, writer: impl Write) -> Result<()> {
    let mut connector = GitLabConnector::new();
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    serve_jsonl(reader, writer, JsonlConfig::default(), |method, params| {
        runtime.block_on(dispatch(&mut connector, method, params))
    })?;
    Ok(())
}

async fn dispatch(
    connector: &mut GitLabConnector,
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
    fn shutdown_acknowledges_and_stops_before_next_request() {
        let shutdown = b"{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"shutdown\",\"params\":{}}\n";
        let mut input = shutdown.to_vec();
        input.extend_from_slice(b"{\"method\":\"invoke\",\"id\":8}\n");
        let mut reader = Cursor::new(input);
        let mut output = Vec::new();

        run_fcp_loop_with_io(&mut reader, &mut output).unwrap();

        assert_eq!(reader.position(), shutdown.len() as u64);
        let replies = responses(&output);
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0]["jsonrpc"], "2.0");
        assert_eq!(replies[0]["id"], 7);
        assert!(replies[0].get("result").is_some());
        assert!(replies[0].get("error").is_none());
    }

    #[test]
    fn malformed_and_unknown_requests_recover_through_real_dispatch() {
        let input = concat!(
            "\n \t\r\n{not json\n",
            "{\"method\":\"unknown\",\"id\":2}\n",
            "{\"method\":\"shutdown\",\"id\":3}\n",
        );
        let mut output = Vec::new();

        run_fcp_loop_with_io(Cursor::new(input.as_bytes()), &mut output).unwrap();

        let replies = responses(&output);
        assert_eq!(replies.len(), 3);
        assert_eq!(replies[0]["jsonrpc"], "2.0");
        assert!(replies[0]["id"].is_null());
        assert_eq!(replies[0]["error"]["code"], "FCP-1001");
        assert_eq!(replies[1]["id"], 2);
        assert_eq!(replies[1]["error"]["code"], "FCP-1002");
        assert_eq!(replies[2]["id"], 3);
        assert!(replies[2].get("result").is_some());
    }
}
