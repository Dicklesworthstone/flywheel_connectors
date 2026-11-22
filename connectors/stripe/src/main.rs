//! FCP Stripe Connector - Main entrypoint

#![forbid(unsafe_code)]
#![allow(dead_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::derivable_impls,
    clippy::doc_markdown,
    clippy::future_not_send,
    clippy::float_cmp,
    clippy::manual_unwrap_or_default,
    clippy::match_same_arms,
    clippy::missing_const_for_fn,
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

use anyhow::Result;
use fcp_async_core::runtime::Builder;
use fcp_prelude::{FcpError, FcpResult};
use fcp_sdk::prelude::{JsonlConfig, dispatch_raw_invoke, serve_jsonl};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use fcp_stripe::connector::StripeConnector;

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    tracing::info!("FCP Stripe Connector starting");
    run_fcp_loop()
}

fn run_fcp_loop() -> Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut connector = StripeConnector::new();
    let runtime = Builder::new_multi_thread().enable_all().build()?;

    let result = serve_jsonl(
        stdin.lock(),
        stdout.lock(),
        JsonlConfig {
            max_request_bytes: 32 * 1024 * 1024,
        },
        |method, params| runtime.block_on(dispatch_message(&mut connector, method, params)),
    );
    // Retire credentials, session grants and request contexts for every exit,
    // including EOF, malformed framing and a closed output pipe.
    let cleanup = runtime.block_on(connector.handle_shutdown(serde_json::json!({})));
    result?;
    cleanup?;
    Ok(())
}

async fn dispatch_message(
    connector: &mut StripeConnector,
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
        "invoke" => dispatch_raw_invoke(params, |params| connector.handle_invoke(params)).await,
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

    #[test]
    fn protocol_loop_skips_whitespace_only_lines() {
        let mut output = Vec::new();
        serve_jsonl(
            std::io::Cursor::new(b"\n \t \n"),
            &mut output,
            JsonlConfig::default(),
            |_, _| {
                panic!("blank frames must not dispatch");
            },
        )
        .unwrap();
        assert!(output.is_empty());
    }

    #[test]
    fn invalid_json_is_wrapped_in_jsonrpc_parse_error() {
        let mut output = Vec::new();
        serve_jsonl(
            std::io::Cursor::new(b"{not json\n"),
            &mut output,
            JsonlConfig::default(),
            |_, _| {
                panic!("malformed frames must not dispatch");
            },
        )
        .unwrap();
        let response: serde_json::Value = serde_json::from_slice(&output).unwrap();

        assert_eq!(response["jsonrpc"], "2.0");
        assert!(response["id"].is_null());
        assert_eq!(response["error"]["code"], "FCP-1001");
        assert!(
            response["error"]["message"]
                .as_str()
                .is_some_and(|message| message.starts_with("Invalid JSON:"))
        );
    }
}
