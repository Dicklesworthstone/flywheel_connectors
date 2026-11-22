//! FCP OpenAI Connector - Main entrypoint
//!
//! An OpenAI API connector implementing the Flywheel Connector Protocol.
//! Provides access to GPT models with cost tracking and streaming support.

#![forbid(unsafe_code)]
#![allow(dead_code)] // Connector API types/methods wired incrementally
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::derivable_impls,
    clippy::doc_markdown,
    clippy::float_cmp,
    clippy::future_not_send,
    clippy::manual_unwrap_or_default,
    clippy::map_unwrap_or,
    clippy::needless_pass_by_value,
    clippy::option_if_let_else,
    clippy::or_fun_call,
    clippy::redundant_closure_for_method_calls,
    clippy::assertions_on_constants,
    clippy::suboptimal_flops,
    clippy::too_many_lines,
    clippy::trivially_copy_pass_by_ref,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use std::io::{BufRead, Write};

use anyhow::Result;
use fcp_async_core::runtime::Builder;
use fcp_core::{FcpError, FcpResult};
use fcp_sdk::prelude::{JsonlConfig, dispatch_raw_invoke, serve_jsonl};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use fcp_openai::connector::OpenAIConnector;

// The existing transcription API accepts 25 MiB of decoded audio. Its base64
// input alone exceeds the SDK's default 16 MiB line limit.
const MAX_REQUEST_BYTES: usize = 64 * 1024 * 1024;

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    tracing::info!("FCP OpenAI Connector starting");
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    run_fcp_loop_with_io(stdin.lock(), &mut stdout)
}

fn run_fcp_loop_with_io<R: BufRead, W: Write>(reader: R, writer: W) -> Result<()> {
    let mut connector = OpenAIConnector::new();
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    let result = serve_jsonl(
        reader,
        writer,
        JsonlConfig {
            max_request_bytes: MAX_REQUEST_BYTES,
        },
        |method, params| {
            runtime.block_on(Box::pin(dispatch_message(&mut connector, method, params)))
        },
    );
    // EOF, invalid framing and broken stdout revoke the process authority too.
    let _ = runtime.block_on(connector.handle_shutdown(serde_json::json!({})));
    result?;
    Ok(())
}

async fn dispatch_message(
    connector: &mut OpenAIConnector,
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
        // handle_invoke validates the complete typed envelope before admission.
        // The SDK preserves the inner invocation ID independently of the RPC ID.
        "invoke" => dispatch_raw_invoke(params, |params| connector.handle_invoke(params)).await,
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
    use super::*;
    use serde_json::{Value, json};

    fn exchange(input: &str) -> Vec<Value> {
        let mut output = Vec::new();
        run_fcp_loop_with_io(input.as_bytes(), &mut output).expect("protocol loop");
        String::from_utf8(output)
            .expect("UTF-8 responses")
            .lines()
            .map(|line| serde_json::from_str(line).expect("JSON response"))
            .collect()
    }

    #[test]
    fn malformed_json_has_a_correlated_protocol_error() {
        let responses = exchange("{not json\n");
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0]["jsonrpc"], "2.0");
        assert!(responses[0]["id"].is_null());
        assert_eq!(responses[0]["error"]["code"], "FCP-1001");
    }

    #[test]
    fn shutdown_stops_before_the_next_queued_request() {
        let input = format!(
            "  \n{}\n{}\n{}\n",
            json!({"jsonrpc": "2.0", "id": 1, "method": "health", "params": {}}),
            json!({"jsonrpc": "2.0", "id": 2, "method": "shutdown", "params": {}}),
            json!({"jsonrpc": "2.0", "id": 3, "method": "health", "params": {}}),
        );
        let responses = exchange(&input);
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0]["id"], 1);
        let health: fcp_core::HealthSnapshot =
            serde_json::from_value(responses[0]["result"].clone()).expect("canonical health");
        assert!(matches!(
            health.status,
            fcp_core::HealthState::Degraded { .. }
        ));
        assert_eq!(responses[1]["id"], 2);
        assert_eq!(responses[1]["result"]["status"], "shutdown");
    }
}
