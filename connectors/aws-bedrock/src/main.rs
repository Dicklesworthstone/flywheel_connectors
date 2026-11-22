//! FCP AWS Bedrock connector entrypoint.

#![forbid(unsafe_code)]
#![recursion_limit = "256"]
#![allow(clippy::missing_errors_doc, clippy::too_many_lines)]

use anyhow::Result;
use fcp_async_core::runtime::Builder;
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
    let stdout = std::io::stdout();
    let mut connector = BedrockConnector::new();
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    let result = serve_jsonl(
        stdin.lock(),
        stdout.lock(),
        JsonlConfig {
            max_request_bytes: 32 * 1024 * 1024,
        },
        |method, params| runtime.block_on(dispatch_message(&mut connector, method, params)),
    );
    // Successful shutdown is acknowledged and flushed by the shared transport.
    // EOF, framing/read failures and broken stdout also retire the runtime.
    let cleanup = runtime.block_on(connector.shutdown(ShutdownRequest {
        r#type: "shutdown".into(),
        deadline_ms: 10_000,
        drain: false,
        reason: Some("Native control channel closed".into()),
    }));
    result?;
    cleanup?;
    Ok(())
}

fn encode<T: serde::Serialize>(value: &T) -> FcpResult<serde_json::Value> {
    serde_json::to_value(value).map_err(|error| FcpError::Internal {
        message: format!("Failed to serialize response: {error}"),
    })
}

async fn dispatch_message(
    connector: &mut BedrockConnector,
    method: &str,
    params: serde_json::Value,
) -> FcpResult<serde_json::Value> {
    match method {
        "configure" => {
            connector.configure(params).await?;
            Ok(serde_json::json!({ "status": "configured" }))
        }
        "handshake" => {
            connector.invalidate_session();
            let req: fcp_core::HandshakeRequest =
                serde_json::from_value(params).map_err(|error| FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid handshake: {error}"),
                })?;
            let mut response = encode(&connector.handshake(req).await?)?;
            response["connector_id"] = serde_json::json!(connector.id());
            response["instance_id"] = serde_json::json!(connector.instance_id());
            response["protocol_version"] = serde_json::json!("2.0");
            Ok(response)
        }
        "health" => encode(&connector.health().await),
        "doctor" => encode(&connector.doctor()),
        "self_check" => encode(&connector.self_check().await?),
        "introspect" => encode(&connector.introspect()),
        "invoke" => encode(&connector.handle_invoke(params).await?),
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
            connector.invalidate_session();
            let req: ShutdownRequest =
                serde_json::from_value(params).map_err(|error| FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid shutdown: {error}"),
                })?;
            if req.r#type != "shutdown" {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Shutdown requires type shutdown".into(),
                });
            }
            connector.shutdown(req).await?;
            Ok(serde_json::json!({ "status": "shutdown" }))
        }
        _ => Err(FcpError::InvalidRequest {
            code: 1004,
            message: format!("Unknown method: {method}"),
        }),
    }
}
