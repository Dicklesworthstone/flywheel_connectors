//! FCP Google Drive Connector - Main entrypoint

#![forbid(unsafe_code)]
#![allow(dead_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::derivable_impls,
    clippy::future_not_send,
    clippy::float_cmp,
    clippy::manual_unwrap_or_default,
    clippy::match_same_arms,
    clippy::option_if_let_else,
    clippy::or_fun_call,
    clippy::redundant_closure_for_method_calls,
    clippy::assertions_on_constants,
    clippy::struct_field_names,
    clippy::suboptimal_flops,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::trivially_copy_pass_by_ref,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use std::io::{BufRead, Write};

use anyhow::Result;
use fcp_async_core::runtime::Builder;
use fcp_sdk::prelude::dispatch_raw_invoke;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use fcp_google_drive::connector::DriveConnector;

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    tracing::info!("FCP Google Drive Connector starting");
    run_fcp_loop()?;
    Ok(())
}

fn run_fcp_loop() -> Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut connector = DriveConnector::new();
    let runtime = Builder::new_multi_thread().enable_all().build()?;

    for line in stdin.lock().lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }
        let response = runtime.block_on(async { handle_message(&mut connector, &line).await });
        let response_json = serde_json::to_string(&response)?;
        writeln!(stdout, "{response_json}")?;
        stdout.flush()?;
    }

    Ok(())
}

async fn handle_message(connector: &mut DriveConnector, message: &str) -> serde_json::Value {
    let request: serde_json::Value = match serde_json::from_str(message) {
        Ok(v) => v,
        Err(e) => {
            return serde_json::json!({
                "error": {
                    "code": "FCP-1001",
                    "message": format!("Invalid JSON: {e}")
                }
            });
        }
    };

    let method = request.get("method").and_then(|v| v.as_str()).unwrap_or("");
    let id = request.get("id").cloned();
    let params = request
        .get("params")
        .cloned()
        .unwrap_or(serde_json::json!({}));

    let result = match method {
        "configure" => connector.handle_configure(params).await,
        "handshake" => connector.handle_handshake(params).await,
        "health" => connector.handle_health().await,
        "doctor" => connector.handle_doctor().await,
        "self_check" => connector.handle_self_check().await,
        "introspect" => connector.handle_introspect().await,
        "invoke" => dispatch_raw_invoke(params, |params| connector.handle_invoke(params)).await,
        "simulate" => connector.handle_simulate(params).await,
        "shutdown" => connector.handle_shutdown(params).await,
        _ => Err(fcp_core::FcpError::InvalidRequest {
            code: 1002,
            message: format!("Unknown method: {method}"),
        }),
    };

    match result {
        Ok(value) => {
            let mut response = serde_json::json!({
                "jsonrpc": "2.0",
                "result": value
            });
            if let Some(id) = id {
                response
                    .as_object_mut()
                    .unwrap()
                    .insert("id".to_string(), id);
            }
            response
        }
        Err(e) => {
            let err_response = e.to_response();
            let mut response = serde_json::json!({
                "jsonrpc": "2.0",
                "error": err_response
            });
            if let Some(id) = id {
                response
                    .as_object_mut()
                    .unwrap()
                    .insert("id".to_string(), id);
            }
            response
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[fcp_async_core::runtime::test]
    async fn invoke_requires_an_inner_string_id_before_dispatch() {
        let mut connector = DriveConnector::new();
        for inner_id in [
            None,
            Some(serde_json::Value::Null),
            Some(serde_json::json!(7)),
            Some(serde_json::json!({"nested": "id"})),
        ] {
            let mut params = serde_json::json!({
                "operation": "drive.list_files",
                "input": {}
            });
            if let Some(inner_id) = inner_id {
                params["id"] = inner_id;
            }
            let response = handle_message(
                &mut connector,
                &serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": "transport:invalid",
                    "method": "invoke",
                    "params": params
                })
                .to_string(),
            )
            .await;

            assert_eq!(response["id"], "transport:invalid");
            assert_eq!(response["error"]["code"], "FCP-1003");
            assert_eq!(
                response["error"]["message"],
                "Invalid request: invoke params.id must be a string"
            );
            assert!(response.get("result").is_none());
        }
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_preserves_handler_errors_and_the_outer_id() {
        let mut connector = DriveConnector::new();
        let params = serde_json::json!({
            "id": "invocation:error",
            "operation": "drive.list_files",
            "input": {}
        });
        let expected = connector
            .handle_invoke(params.clone())
            .await
            .expect_err("unconfigured invocation must fail")
            .to_response();
        let response = handle_message(
            &mut connector,
            &serde_json::json!({
                "jsonrpc": "2.0",
                "id": "transport:error",
                "method": "invoke",
                "params": params
            })
            .to_string(),
        )
        .await;

        assert_eq!(response["id"], "transport:error");
        assert_eq!(response["error"], serde_json::to_value(expected).unwrap());
        assert!(response.get("result").is_none());
    }
}
