//! FCP `MCP Bridge` Connector - Main entrypoint
//!
//! An MCP Bridge connector implementing the Flywheel Connector Protocol.
//! Bridges FCP operations to MCP server tools, resources, and prompts.

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

use fcp_mcp_bridge::server::McpBridgeServer;

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    tracing::info!("FCP MCP Bridge Connector starting");
    run_fcp_loop()?;
    Ok(())
}

fn run_fcp_loop() -> Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    run_fcp_loop_with_io(stdin.lock(), stdout.lock(), JsonlConfig::default())
}

/// Use the production framing and dispatch path in both the binary and tests.
fn run_fcp_loop_with_io(
    reader: impl BufRead,
    writer: impl Write,
    config: JsonlConfig,
) -> Result<()> {
    let mut server = McpBridgeServer::new()?;
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    serve_jsonl(reader, writer, config, |method, params| {
        runtime.block_on(server.dispatch(method, params))
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor};

    use serde_json::{Value, json};

    use super::*;

    fn replies(output: &[u8]) -> Vec<Value> {
        output
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).expect("JSON response"))
            .collect()
    }

    fn encode_requests(requests: &[Value]) -> String {
        let mut input = String::new();
        for request in requests {
            input.push_str(&serde_json::to_string(request).unwrap());
            input.push('\n');
        }
        input
    }

    fn handshake_request(id: u32) -> Value {
        json!({"id": id, "method": "handshake", "params": {
            "protocol_version": "2.0.0", "zone": "z:work",
            "host_public_key": vec![1_u8; 32], "nonce": vec![9_u8; 32],
            "capabilities_requested": ["mcp.tools.write"],
        }})
    }

    #[test]
    fn shutdown_flushes_ack_and_leaves_following_request_unread() {
        let shutdown = b"{\"id\":7,\"method\":\"shutdown\"}\n";
        let mut input = shutdown.to_vec();
        input.extend_from_slice(b"{\"id\":8,\"method\":\"configure\",\"params\":{}}\n");
        let mut reader = Cursor::new(input);
        let mut output = Vec::new();
        run_fcp_loop_with_io(&mut reader, &mut output, JsonlConfig::default()).unwrap();
        assert_eq!(reader.position(), shutdown.len() as u64);
        assert_eq!(replies(&output), vec![json!({"jsonrpc":"2.0","id":7,"result":{}})]);
    }

    #[test]
    fn malformed_frames_recover_without_dispatching_shutdown() {
        let input = concat!(
            "not-json\n",
            "{\"jsonrpc\":\"1.0\",\"method\":\"shutdown\",\"id\":1}\n",
            "{\"method\":\"health\",\"id\":2}\n",
            "{\"method\":\"shutdown\",\"id\":3}\n",
        );
        let mut output = Vec::new();
        run_fcp_loop_with_io(Cursor::new(input), &mut output, JsonlConfig::default()).unwrap();
        let responses = replies(&output);
        assert_eq!(responses.len(), 4);
        for response in &responses[..2] {
            assert_eq!(response["error"]["code"], "FCP-1001");
        }
        assert_eq!(responses[2]["id"], 2);
        assert_eq!(responses[2]["result"]["configured"], false);
        assert_eq!(responses[3]["id"], 3);
        assert_eq!(responses[3]["result"], json!({}));
    }

    #[test]
    fn configuration_and_nine_operation_catalog_survive_shared_framing() {
        // Configuration and FCP handshake are local; no upstream MCP call occurs.
        let input = encode_requests(&[
            json!({"id": 1, "method": "configure", "params": {"mcp_url": "http://127.0.0.1:1"}}),
            handshake_request(2),
            json!({"id": 3, "method": "health"}),
            json!({"id": 4, "method": "introspect"}),
            json!({"id": 5, "method": "shutdown"}),
        ]);
        let mut output = Vec::new();
        run_fcp_loop_with_io(Cursor::new(input), &mut output, JsonlConfig::default()).unwrap();
        let responses = replies(&output);
        assert_eq!(responses.len(), 5);
        for (index, response) in responses.iter().enumerate() {
            assert_eq!(response["id"], index + 1);
            assert!(response.get("error").is_none(), "{response}");
        }
        assert_eq!(responses[2]["result"]["configured"], true);
        assert_eq!(responses[2]["result"]["handshaken"], true);
        let operations = responses[3]["result"]["operations"].as_array().unwrap();
        assert_eq!(operations.len(), 9);
        for id in ["mcp.prompts.get", "mcp.resources.templates.list"] {
            assert!(operations.iter().any(|operation| operation["id"] == id));
        }
    }

    #[test]
    fn oversized_frame_stops_before_configure_and_hides_its_payload() {
        let input = concat!(
            "{\"method\":\"configure\",\"params\":{\"api_key\":\"do-not-echo\"}}\n",
            "{\"method\":\"health\"}\n",
        );
        let mut reader = Cursor::new(input);
        let mut output = Vec::new();
        assert!(run_fcp_loop_with_io(
            &mut reader,
            &mut output,
            JsonlConfig { max_request_bytes: 16 },
        ).is_err());
        assert_eq!(reader.position(), 18);
        let responses = replies(&output);
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0]["error"]["code"], "FCP-1004");
        assert!(!String::from_utf8(output).unwrap().contains("do-not-echo"));
    }

    #[test]
    fn production_dispatch_rejects_unsigned_invocation_before_provider_io() {
        let input = encode_requests(&[
            json!({"id": 1, "method": "configure", "params": {"mcp_url": "http://127.0.0.1:1"}}),
            handshake_request(2),
            json!({"id": 3, "method": "invoke", "params": {
                "operation_id": "mcp.tools.call", "input": {"name": "write", "arguments": {}},
            }}),
            json!({"id": 4, "method": "health"}),
            json!({"id": 5, "method": "shutdown"}),
        ]);
        let mut output = Vec::new();
        run_fcp_loop_with_io(Cursor::new(input), &mut output, JsonlConfig::default()).unwrap();
        let responses = replies(&output);
        assert_eq!(responses.len(), 5);
        assert_eq!(responses[2]["id"], 3);
        assert_eq!(responses[2]["error"]["code"], "FCP-1003");
        assert_eq!(responses[3]["result"]["requests"], 0);
        assert_eq!(responses[4]["result"], json!({}));
    }

    #[test]
    fn empty_and_whitespace_frames_are_ignored() {
        let mut output = Vec::new();
        run_fcp_loop_with_io(Cursor::new("\n \t\r\n"), &mut output, JsonlConfig::default()).unwrap();
        assert!(output.is_empty());
    }

    struct FailedOutput {
        fail_write: bool,
        bytes: Vec<u8>,
    }

    impl Write for FailedOutput {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.fail_write {
                Err(io::ErrorKind::BrokenPipe.into())
            } else {
                self.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
    }

    fn assert_output_failure_stops_dispatch(fail_write: bool) {
        let first = "{\"id\":1,\"method\":\"health\"}\n";
        let input = format!("{first}{{\"id\":2,\"method\":\"configure\",\"params\":{{}}}}\n");
        let mut reader = Cursor::new(input);
        let mut output = FailedOutput { fail_write, bytes: Vec::new() };
        assert!(run_fcp_loop_with_io(&mut reader, &mut output, JsonlConfig::default()).is_err());
        assert_eq!(reader.position(), first.len() as u64);
        if !fail_write {
            let responses = replies(&output.bytes);
            assert_eq!(responses.len(), 1);
            assert_eq!(responses[0]["id"], 1);
        }
    }

    #[test]
    fn write_failure_stops_dispatch_without_retry() {
        assert_output_failure_stops_dispatch(true);
    }

    #[test]
    fn flush_failure_stops_dispatch_without_retry() {
        assert_output_failure_stops_dispatch(false);
    }
}
