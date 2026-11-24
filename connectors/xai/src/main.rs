#![forbid(unsafe_code)]

use std::io::{self, BufRead, Write};

use anyhow::Result;
use fcp_prelude::{FcpConnector, FcpError, FcpResult};
use fcp_sdk::prelude::{JsonlConfig, serve_jsonl};
use serde_json::{Value, json};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use fcp_xai::XaiConnector;

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    run_fcp_loop()
}

fn run_fcp_loop() -> Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut connector = XaiConnector::new();
    serve(stdin.lock(), stdout.lock(), &mut connector)?;
    Ok(())
}

fn serve(reader: impl BufRead, writer: impl Write, connector: &mut XaiConnector) -> io::Result<()> {
    serve_jsonl(reader, writer, JsonlConfig::default(), |method, params| {
        fcp_async_core::runtime::block_on_sync(handle_request(connector, method, params))
            .unwrap_or_else(|error| {
                Err(FcpError::Internal {
                    message: format!("Runtime error: {error}"),
                })
            })
    })
}

async fn handle_request(
    connector: &mut XaiConnector,
    method: &str,
    params: Value,
) -> FcpResult<Value> {
    match method {
        "configure" => connector.handle_configure(params).await,
        "handshake" => connector.handle_handshake(params).await,
        "health" => {
            let mut snapshot = connector.health().await;
            let mut details = connector.handle_health().await?;
            details["instance_id"] = json!(connector.instance_id());
            snapshot.details = Some(details);
            encode_response(snapshot)
        }
        "doctor" => connector.handle_doctor().await,
        "self_check" => connector.handle_self_check().await,
        "introspect" => connector.handle_introspect().await,
        "invoke" => {
            let request = serde_json::from_value(params).map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "Invalid FCP invoke request".into(),
            })?;
            encode_response(connector.invoke(request).await?)
        }
        "simulate" => {
            let request = serde_json::from_value(params).map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "Invalid FCP simulate request".into(),
            })?;
            encode_response(connector.simulate(request).await?)
        }
        "shutdown" => connector.handle_shutdown(params).await,
        _ => Err(FcpError::InvalidRequest {
            code: 1002,
            message: format!("Unknown method: {method}"),
        }),
    }
}

fn encode_response(value: impl serde::Serialize) -> FcpResult<Value> {
    serde_json::to_value(value).map_err(|_| FcpError::Internal {
        message: "Failed to encode FCP response".into(),
    })
}
