//! FCP `SQLite` Connector - Main entrypoint.
//!
//! A local `SQLite` connector implementing the Flywheel Connector Protocol.

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
use fcp_core::{FcpError, FcpResult};
use fcp_sdk::prelude::{JsonlConfig, serve_jsonl};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use fcp_sqlite::connector::SqliteConnector;

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    tracing::info!("FCP SQLite Connector starting");
    run_fcp_loop()?;
    Ok(())
}

fn run_fcp_loop() -> Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    run_fcp_loop_with_io(stdin.lock(), &mut stdout)
}

fn run_fcp_loop_with_io<R: BufRead, W: Write>(reader: R, writer: W) -> Result<()> {
    let mut connector = SqliteConnector::new();
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    let result = serve_jsonl(reader, writer, JsonlConfig::default(), |method, params| {
        runtime.block_on(dispatch_message(&mut connector, method, params))
    });
    // Flush the shutdown acknowledgement before exit. EOF and transport errors
    // also close the connection, rolling back any uncommitted transaction.
    let cleanup = runtime.block_on(connector.handle_shutdown(serde_json::json!({
        "type": "shutdown", "drain": false, "deadline_ms": 1_000,
        "reason": "Native control channel closed",
    })));
    result?;
    cleanup?;
    Ok(())
}

async fn dispatch_message(
    connector: &mut SqliteConnector,
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
        "invoke" => connector.handle_invoke(params).await,
        "simulate" => connector.handle_simulate(params).await,
        "shutdown" => connector.handle_shutdown(params).await,
        _ => Err(FcpError::InvalidRequest {
            code: 1002,
            message: format!("Unknown method: {method}"),
        }),
    }
}
