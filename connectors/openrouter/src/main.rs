#![forbid(unsafe_code)]

use std::io::{BufRead, Write};

use anyhow::Result;
use fcp_async_core::runtime::Builder;
use fcp_core::{FcpError, FcpResult, InvokeRequest};
use fcp_sdk::prelude::{JsonlConfig, dispatch_raw_invoke, serve_jsonl};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use fcp_openrouter::OpenRouterConnector;

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
    let mut connector = OpenRouterConnector::new();
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    let result = serve_jsonl(reader, output, JsonlConfig::default(), |method, params| {
        runtime.block_on(dispatch_message(&mut connector, method, params))
    });
    let _ = runtime.block_on(connector.handle_shutdown(serde_json::json!({})));
    result?;
    Ok(())
}

async fn dispatch_message(
    connector: &mut OpenRouterConnector,
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
            if request.r#type != "invoke" || request.id.0.is_empty() {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Invocation requires type invoke and a nonempty ID".into(),
                });
            }
            dispatch_raw_invoke(params, |params| connector.handle_invoke(params)).await
        }
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
    use super::*;
    use serde_json::{Value, json};

    #[test]
    fn malformed_frames_recover_and_shutdown_stops_dispatch() {
        let input = concat!(
            "{bad-json\n",
            "{\"jsonrpc\":\"1.0\",\"id\":\"wrong\",\"method\":\"health\",\"params\":{}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":\"stop\",\"method\":\"shutdown\",\"params\":{}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":\"ignored\",\"method\":\"health\",\"params\":{}}\n"
        );
        let mut output = Vec::new();
        run_fcp_loop_with_io(std::io::Cursor::new(input), &mut output).unwrap();
        let frames: Vec<Value> = std::str::from_utf8(&output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0]["error"]["code"], "FCP-1001");
        assert_eq!(frames[1]["error"]["code"], "FCP-1001");
        assert_eq!(frames[2]["id"], "stop");
        assert_eq!(frames[2]["result"], json!({"status": "shutdown"}));
    }
}
