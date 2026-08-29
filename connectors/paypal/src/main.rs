//! FCP `PayPal` Connector - Main entrypoint.

#![forbid(unsafe_code)]

use std::io::{BufRead, Write};

use anyhow::Result;
use fcp_prelude::{FcpError, FcpResult, SimulateRequest};
use fcp_sdk::prelude::*;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use fcp_paypal::connector::PayPalConnector;

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    tracing::info!("FCP PayPal Connector starting");
    run_fcp_loop()?;
    Ok(())
}

fn run_fcp_loop() -> Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut connector = PayPalConnector::new();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }

        let response =
            fcp_async_core::runtime::block_on_sync(handle_message(&mut connector, &line))
                .unwrap_or_else(|e| {
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "error": {
                            "code": "FCP-9001",
                            "message": format!("Runtime error: {e}")
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
    serde_json::to_value(value).map_err(|e| FcpError::Internal {
        message: format!("Failed to serialize response: {e}"),
    })
}

#[allow(clippy::too_many_lines)]
async fn handle_message(connector: &mut PayPalConnector, message: &str) -> serde_json::Value {
    let request: serde_json::Value = match serde_json::from_str(message) {
        Ok(v) => v,
        Err(e) => {
            return serde_json::json!({
                "jsonrpc": "2.0",
                "error": { "code": "FCP-1001", "message": format!("Invalid JSON: {e}") }
            });
        }
    };

    let method = request.get("method").and_then(|v| v.as_str()).unwrap_or("");
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
                    serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                        code: 1003,
                        message: format!("Invalid handshake: {e}"),
                    })?;
                encode(&connector.handshake(req).await?)
            }
            "health" => encode(&connector.health().await),
            "doctor" => encode(&connector.doctor()),
            "self_check" => encode(&connector.self_check().await?),
            "introspect" => encode(&connector.introspect()),
            "invoke" => {
                let req: fcp_core::InvokeRequest =
                    serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                        code: 1003,
                        message: format!("Invalid invoke: {e}"),
                    })?;
                encode(&connector.invoke(req).await?)
            }
            "simulate" => {
                let req: SimulateRequest =
                    serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                        code: 1003,
                        message: format!("Invalid simulate: {e}"),
                    })?;
                encode(&connector.simulate(req).await?)
            }
            "subscribe" => {
                let req: SubscribeRequest =
                    serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                        code: 1003,
                        message: format!("Invalid subscribe: {e}"),
                    })?;
                encode(&connector.subscribe(req).await?)
            }
            "unsubscribe" => {
                let req: UnsubscribeRequest =
                    serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                        code: 1003,
                        message: format!("Invalid unsubscribe: {e}"),
                    })?;
                connector.unsubscribe(req).await?;
                Ok(serde_json::json!({ "status": "unsubscribed" }))
            }
            "shutdown" => {
                let req: fcp_core::ShutdownRequest =
                    serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                        code: 1003,
                        message: format!("Invalid shutdown: {e}"),
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
    .await;

    match result {
        Ok(value) => {
            let mut response = serde_json::json!({ "jsonrpc": "2.0", "result": value });
            if let Some(id) = id
                && let Some(object) = response.as_object_mut()
            {
                object.insert("id".to_string(), id);
            }
            response
        }
        Err(e) => {
            let err_response = e.to_response();
            let mut response = serde_json::json!({ "jsonrpc": "2.0", "error": err_response });
            if let Some(id) = id
                && let Some(object) = response.as_object_mut()
            {
                object.insert("id".to_string(), id);
            }
            response
        }
    }
}
