//! FCP Signal Connector - Main entrypoint.

#![forbid(unsafe_code)]

use std::io::BufReader;

use anyhow::Result;
use fcp_prelude::{FcpError, FcpResult, SimulateRequest};
use fcp_sdk::prelude::*;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use fcp_signal::SignalConnector;

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    tracing::info!("FCP Signal Connector starting");
    run_fcp_loop()?;
    Ok(())
}

fn run_fcp_loop() -> Result<()> {
    let events = JsonlEventStream::new(JsonlWriter::new(std::io::stdout()));
    let mut connector = SignalConnector::new();
    connector.attach_event_stream(events.clone())?;
    let runtime = fcp_async_core::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = serve_jsonl_events(
        BufReader::new(std::io::stdin()),
        events,
        JsonlConfig::default(),
        |method, params| runtime.block_on(dispatch_message(&mut connector, method, params)),
    );
    // EOF and malformed/failed transport retire every outstanding ACK and
    // fence the SSE worker just like an explicit shutdown request.
    let _ = runtime.block_on(connector.shutdown(ShutdownRequest {
        r#type: "shutdown".into(),
        deadline_ms: 1_000,
        drain: false,
        reason: Some("native transport closed".into()),
    }));
    result?;
    Ok(())
}

fn encode<T: serde::Serialize>(value: &T) -> FcpResult<serde_json::Value> {
    serde_json::to_value(value).map_err(|e| FcpError::Internal {
        message: format!("Failed to serialize response: {e}"),
    })
}

#[allow(clippy::too_many_lines)]
async fn dispatch_message(
    connector: &mut SignalConnector,
    method: &str,
    params: serde_json::Value,
) -> FcpResult<serde_json::Value> {
    match method {
        "configure" => {
            connector.configure(params).await?;
            Ok(serde_json::json!({ "status": "configured" }))
        }
        "handshake" => {
            let req: HandshakeRequest =
                serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid handshake request: {e}"),
                })?;
            encode(&connector.handshake(req).await?)
        }
        "health" => encode(&connector.health().await),
        "doctor" => encode(&connector.doctor()),
        "self_check" => encode(&connector.self_check().await?),
        "introspect" => encode(&connector.introspect()),
        "invoke" => {
            let request: InvokeRequest =
                serde_json::from_value(params).map_err(|_| FcpError::InvalidRequest {
                    code: 1003,
                    message: "Invalid Signal invoke request".into(),
                })?;
            encode(&connector.invoke(request).await?)
        }
        "simulate" => {
            let req: SimulateRequest =
                serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid simulate request: {e}"),
                })?;
            encode(&connector.simulate(req).await?)
        }
        "subscribe" => connector.handle_native_subscribe(params).await,
        "unsubscribe" => {
            let req: UnsubscribeRequest =
                serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid unsubscribe request: {e}"),
                })?;
            connector.unsubscribe(req).await?;
            Ok(serde_json::json!({ "status": "unsubscribed" }))
        }
        "shutdown" => {
            let req: ShutdownRequest =
                serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid shutdown request: {e}"),
                })?;
            connector.shutdown(req).await?;
            Ok(serde_json::json!({ "status": "shutdown_accepted" }))
        }
        _ => Err(FcpError::InvalidRequest {
            code: 1002,
            message: format!("Unknown method: {method}"),
        }),
    }
}
