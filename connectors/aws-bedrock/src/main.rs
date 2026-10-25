//! FCP AWS Bedrock connector entrypoint.

#![forbid(unsafe_code)]
#![recursion_limit = "256"]
#![allow(clippy::missing_errors_doc, clippy::too_many_lines)]

use std::io::{BufRead, Write};

use anyhow::Result;
use fcp_prelude::{FcpConnector, FcpError, FcpResult, SimulateRequest};
use fcp_sdk::prelude::*;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use fcp_aws_bedrock::connector::BedrockConnector;

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    tracing::info!("FCP AWS Bedrock Connector starting");
    run_fcp_loop()?;
    Ok(())
}

fn run_fcp_loop() -> Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut connector = BedrockConnector::new();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }

        let response =
            fcp_async_core::runtime::block_on_sync(handle_message(&mut connector, &line))
                .unwrap_or_else(|error| {
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "error": {
                            "code": "FCP-9001",
                            "message": format!("Runtime error: {error}")
                        }
                    })
                });

        let response_json = serde_json::to_string(&response)?;
        writeln!(stdout, "{response_json}")?;
        stdout.flush()?;
    }

    Ok(())
}

fn encode<T: serde::Serialize>(value: &T) -> FcpResult<serde_json::Value> {
    serde_json::to_value(value).map_err(|error| FcpError::Internal {
        message: format!("Failed to serialize response: {error}"),
    })
}

async fn handle_message(connector: &mut BedrockConnector, message: &str) -> serde_json::Value {
    let request: serde_json::Value = match serde_json::from_str(message) {
        Ok(value) => value,
        Err(error) => {
            return serde_json::json!({
                "jsonrpc": "2.0",
                "error": { "code": "FCP-1001", "message": format!("Invalid JSON: {error}") }
            });
        }
    };

    let method = request
        .get("method")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let id = request.get("id").cloned();
    let params = request
        .get("params")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));

    let result: FcpResult<serde_json::Value> = async {
        match method {
            "configure" => {
                connector.configure(params).await?;
                Ok(serde_json::json!({ "status": "configured" }))
            }
            "handshake" => {
                let req: fcp_core::HandshakeRequest =
                    serde_json::from_value(params).map_err(|error| FcpError::InvalidRequest {
                        code: 1003,
                        message: format!("Invalid handshake: {error}"),
                    })?;
                encode(&connector.handshake(req).await?)
            }
            "health" => encode(&connector.health().await),
            "doctor" => encode(&connector.doctor()),
            "self_check" => encode(&connector.self_check().await?),
            "introspect" => encode(&connector.introspect()),
            "invoke" => {
                let req: fcp_core::InvokeRequest =
                    serde_json::from_value(params).map_err(|error| FcpError::InvalidRequest {
                        code: 1003,
                        message: format!("Invalid invoke: {error}"),
                    })?;
                encode(&connector.invoke(req).await?)
            }
            "simulate" => {
                let req: SimulateRequest =
                    serde_json::from_value(params).map_err(|error| FcpError::InvalidRequest {
                        code: 1003,
                        message: format!("Invalid simulate: {error}"),
                    })?;
                encode(&connector.simulate(req).await?)
            }
            "subscribe" => {
                let req: SubscribeRequest =
                    serde_json::from_value(params).map_err(|error| FcpError::InvalidRequest {
                        code: 1003,
                        message: format!("Invalid subscribe: {error}"),
                    })?;
                encode(&connector.subscribe(req).await?)
            }
            "unsubscribe" => {
                let req: UnsubscribeRequest =
                    serde_json::from_value(params).map_err(|error| FcpError::InvalidRequest {
                        code: 1003,
                        message: format!("Invalid unsubscribe: {error}"),
                    })?;
                connector.unsubscribe(req).await?;
                Ok(serde_json::json!({ "status": "unsubscribed" }))
            }
            "shutdown" => {
                let req: ShutdownRequest =
                    serde_json::from_value(params).map_err(|error| FcpError::InvalidRequest {
                        code: 1003,
                        message: format!("Invalid shutdown: {error}"),
                    })?;
                connector.shutdown(req).await?;
                Ok(serde_json::json!({ "status": "shutdown" }))
            }
            _ => Err(FcpError::InvalidRequest {
                code: 1004,
                message: format!("Unknown method: {method}"),
            }),
        }
    }
    .await;

    match result {
        Ok(value) => serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": value }),
        Err(error) => serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": error.error_code(),
                "message": error.to_string()
            }
        }),
    }
}
