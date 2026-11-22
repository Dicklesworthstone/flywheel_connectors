//! FCP GitHub Connector - Main entrypoint
//!
//! A GitHub API connector implementing the Flywheel Connector Protocol.
//! Provides access to repos, issues, PRs, Actions, code search, and file content.

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
use fcp_core::{FcpError, FcpResult, InvokeRequest};
use fcp_sdk::prelude::{JsonlConfig, dispatch_raw_invoke, serve_jsonl};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use fcp_github::connector::GitHubConnector;

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    tracing::info!("FCP GitHub Connector starting");
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    run_fcp_loop_with_io(stdin.lock(), &mut stdout)
}

fn run_fcp_loop_with_io<R: BufRead, W: Write>(reader: R, writer: W) -> Result<()> {
    let mut connector = GitHubConnector::new();
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    serve_jsonl(reader, writer, JsonlConfig::default(), |method, params| {
        runtime.block_on(dispatch_message(&mut connector, method, params))
    })?;
    Ok(())
}

async fn dispatch_message(
    connector: &mut GitHubConnector,
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
            // The outer JSON-RPC ID identifies transport. Validate the complete
            // inner invocation before allowing any provider or webhook effect.
            let request: InvokeRequest =
                serde_json::from_value(params.clone()).map_err(|_| FcpError::InvalidRequest {
                    code: 1003,
                    message: "Invalid invoke request".into(),
                })?;
            if request.r#type != "invoke" || request.id.0.is_empty() {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Expected invoke request with a non-empty ID".into(),
                });
            }
            request
                .validate_idempotency_key()
                .map_err(|_| FcpError::InvalidRequest {
                    code: 1003,
                    message: "Invalid invocation idempotency key".into(),
                })?;
            dispatch_raw_invoke(params, |params| connector.handle_invoke(params)).await
        }
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
    use super::*;
    use std::io::Cursor;

    #[test]
    fn bounded_dispatch_preserves_ids_and_stops_after_shutdown() {
        let requests = concat!(
            "  \t\n",
            "{invalid}\n",
            "{\"jsonrpc\":\"1.0\",\"id\":\"bad-version\",\"method\":\"health\"}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":73,\"method\":\"health\"}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":\"stop\",\"method\":\"shutdown\"}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":\"after-stop\",\"method\":\"health\"}\n"
        );
        let mut output = Vec::new();
        run_fcp_loop_with_io(Cursor::new(requests), &mut output).unwrap();
        let responses: Vec<serde_json::Value> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(responses.len(), 4);
        assert_eq!(responses[0]["error"]["code"], "FCP-1001");
        assert!(responses[0]["id"].is_null());
        assert_eq!(responses[1]["id"], "bad-version");
        assert!(responses[1].get("error").is_some());
        assert_eq!(responses[2]["id"], 73);
        let health: fcp_core::HealthSnapshot =
            serde_json::from_value(responses[2]["result"].clone()).unwrap();
        assert!(!health.is_ready());
        assert_eq!(health.details.unwrap()["configured"], false);
        assert_eq!(responses[3]["id"], "stop");
        assert_eq!(responses[3]["result"]["status"], "shutdown");
    }

    #[fcp_async_core::runtime::test]
    async fn incomplete_native_invocation_is_rejected_before_handler_dispatch() {
        let mut connector = GitHubConnector::new();
        for params in [
            serde_json::json!({}),
            serde_json::json!({"id": null}),
            serde_json::json!({"id": 7}),
            serde_json::json!({"id": ["request"]}),
            serde_json::json!({"id": "inner", "operation": "github.get_repo"}),
        ] {
            assert!(matches!(
                dispatch_message(&mut connector, "invoke", params).await,
                Err(FcpError::InvalidRequest { code: 1003, .. })
            ));
        }
    }
}
