#![forbid(unsafe_code)]

use std::io::{BufRead, Write};

use anyhow::Result;
use fcp_async_core::runtime::Builder;
use fcp_core::{FcpError, FcpResult, HealthSnapshot};
use fcp_sdk::prelude::{JsonlConfig, serve_jsonl};
use serde_json::{Value, json};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use fcp_huggingface::HuggingfaceConnector;

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    run_fcp_loop()
}

fn run_fcp_loop() -> Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    run_fcp_loop_with_io(stdin.lock(), &mut stdout)
}

fn run_fcp_loop_with_io<R: BufRead, W: Write>(reader: R, output: &mut W) -> Result<()> {
    let mut connector = HuggingfaceConnector::new();
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    let result = serve_jsonl(
        reader,
        output,
        JsonlConfig {
            max_request_bytes: 1024 * 1024,
        },
        |method, params| runtime.block_on(dispatch_message(&mut connector, method, params)),
    );
    // The shared transport flushes a successful shutdown reply before returning.
    // EOF and framing/output errors revoke credentials through the same cleanup.
    let cleanup = runtime.block_on(connector.handle_shutdown(json!({
        "type": "shutdown",
        "deadline_ms": 10_000,
        "drain": false,
        "reason": "Native control channel closed"
    })));
    result?;
    cleanup?;
    Ok(())
}

/// Preserve connector diagnostics inside the host's typed health envelope.
fn native_health(details: Value) -> FcpResult<Value> {
    let mut snapshot = if details["configured"] == true
        && details["handshaken"] == true
        && matches!(details["status"].as_str(), Some("ready" | "healthy"))
    {
        HealthSnapshot::ready()
    } else {
        HealthSnapshot::degraded("Hugging Face configuration or session is not ready")
    };
    snapshot.details = Some(details);
    serde_json::to_value(snapshot).map_err(|_| FcpError::Internal {
        message: "Unable to encode Hugging Face health snapshot".into(),
    })
}

async fn dispatch_message(
    connector: &mut HuggingfaceConnector,
    method: &str,
    params: Value,
) -> FcpResult<Value> {
    match method {
        "configure" => connector.handle_configure(params).await,
        "handshake" => connector.handle_handshake(params).await,
        "health" => native_health(connector.handle_health().await?),
        "doctor" => connector.handle_doctor().await,
        "self_check" => {
            let mut report = connector.handle_self_check().await?;
            if report["status"] == "ready" {
                report["status"] = json!("ok");
            }
            Ok(report)
        }
        "introspect" => connector.handle_introspect().await,
        "invoke" => connector.handle_invoke(params).await,
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
    use std::io::Cursor;

    use super::*;

    fn responses(bytes: &[u8]) -> Vec<Value> {
        std::str::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[test]
    fn malformed_frame_does_not_corrupt_following_health_response() {
        let input = concat!(
            "{\"jsonrpc\":\"1.0\",\"id\":\"invalid\",\"method\":\"health\"}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":\"health\",\"method\":\"health\"}\n",
        );
        let mut output = Vec::new();
        run_fcp_loop_with_io(Cursor::new(input), &mut output).unwrap();
        let replies = responses(&output);
        assert_eq!(replies.len(), 2);
        assert!(replies[0].get("error").is_some());
        assert_eq!(replies[1]["id"], "health");
        let health: HealthSnapshot =
            serde_json::from_value(replies[1]["result"].clone()).unwrap();
        assert!(!health.is_ready());
        assert_eq!(health.details.unwrap()["configured"], false);
    }

    #[test]
    fn shutdown_flushes_and_stops_before_the_following_request() {
        let input = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":\"stop\",\"method\":\"shutdown\",\"params\":{\"type\":\"shutdown\"}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":\"unread\",\"method\":\"health\"}\n",
        );
        let mut output = Vec::new();
        run_fcp_loop_with_io(Cursor::new(input), &mut output).unwrap();
        let replies = responses(&output);
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0]["id"], "stop");
        assert!(replies[0].get("result").is_some());
        assert!(output.ends_with(b"\n"));
    }

    #[test]
    fn oversized_frame_closes_channel_without_dispatching_suffix() {
        let mut input = vec![b' '; 1024 * 1024 + 1];
        input.extend_from_slice(b"\n{\"method\":\"health\",\"id\":\"unread\"}\n");
        let mut output = Vec::new();
        assert!(run_fcp_loop_with_io(Cursor::new(input), &mut output).is_err());
        let replies = responses(&output);
        assert_eq!(replies.len(), 1);
        assert!(replies[0].get("error").is_some());
        assert_ne!(replies[0]["id"], "unread");
    }

    #[test]
    fn configured_credentials_without_handshake_are_not_host_ready() {
        let response = native_health(json!({
            "status": "ready",
            "configured": true,
            "handshaken": false
        }))
        .unwrap();
        let snapshot: HealthSnapshot = serde_json::from_value(response).unwrap();
        assert!(!snapshot.is_ready());
        let response = native_health(json!({
            "status": "healthy",
            "configured": true,
            "handshaken": true
        }))
        .unwrap();
        assert!(serde_json::from_value::<HealthSnapshot>(response).unwrap().is_ready());
    }
}
