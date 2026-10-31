//! FCP Google Calendar Connector - Main entrypoint
//!
//! A Google Calendar connector implementing the Flywheel Connector Protocol.
//! Provides access to calendars, events, and quick-add.

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
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::unused_async
)]

use std::io::{BufRead, Write};

use anyhow::Result;
use fcp_async_core::runtime::Builder;
use fcp_sdk::prelude::{JsonlConfig, dispatch_raw_invoke, serve_jsonl};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use fcp_google_calendar::connector::GoogleCalendarConnector;

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    tracing::info!("FCP Google Calendar Connector starting");

    run_fcp_loop()?;

    Ok(())
}

/// Run the FCP JSON-RPC style protocol loop.
fn run_fcp_loop() -> Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    run_fcp_io(stdin.lock(), stdout.lock())
}

fn run_fcp_io(reader: impl BufRead, writer: impl Write) -> Result<()> {
    let mut connector = GoogleCalendarConnector::new();
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    let result = serve_jsonl(reader, writer, JsonlConfig::default(), |method, params| {
        runtime.block_on(handle_method(&mut connector, method, params))
    });
    // EOF and broken transport close the same credential/authority lifecycle
    // as an explicit shutdown. The runtime stays alive through cleanup.
    runtime.block_on(connector.handle_shutdown(serde_json::json!({})))?;
    result?;
    Ok(())
}

/// Dispatch one validated native JSONL request.
async fn handle_method(
    connector: &mut GoogleCalendarConnector,
    method: &str,
    params: serde_json::Value,
) -> fcp_core::FcpResult<serde_json::Value> {
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
        _ => Err(fcp_core::FcpError::InvalidRequest {
            code: 1002,
            message: format!("Unknown method: {method}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use fcp_core::{
        CapabilityConstraints, CapabilityToken, HandshakeResponse, HealthSnapshot, InvokeResponse,
    };
    use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
    use serde_json::{Value, json};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    fn handshake(key: &Ed25519SigningKey) -> Value {
        json!({
            "protocol_version": "2.0.0",
            "zone": "z:work",
            "host_public_key": key.verifying_key().to_bytes(),
            "nonce": vec![9u8; 32],
            "capabilities_requested": ["gcal.read", "undeclared.capability"]
        })
    }

    #[test]
    fn jsonl_lifecycle_reports_actual_instance_and_stops_after_shutdown() {
        let key = Ed25519SigningKey::generate();
        let requests = [
            json!({ "jsonrpc": "2.0", "id": "configure", "method": "configure",
                "params": { "token": "never-log-this-token" } }),
            json!({ "jsonrpc": "2.0", "id": "hello", "method": "handshake",
                "params": handshake(&key) }),
            json!({ "jsonrpc": "2.0", "id": "health", "method": "health", "params": {} }),
            json!({ "jsonrpc": "2.0", "id": "shutdown", "method": "shutdown", "params": {} }),
            json!({ "jsonrpc": "2.0", "id": "after-stop", "method": "health", "params": {} }),
        ];
        let input = requests
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        let mut output = Vec::new();
        run_fcp_io(std::io::Cursor::new(input), &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(!text.contains("never-log-this-token"));
        let responses: Vec<Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(responses.len(), 4);
        assert_eq!(responses[1]["id"], "hello");
        let hello: HandshakeResponse =
            serde_json::from_value(responses[1]["result"].clone()).unwrap();
        assert_eq!(hello.capabilities_granted.len(), 1);
        assert_eq!(
            hello.capabilities_granted[0].capability.as_str(),
            "gcal.read"
        );
        let health: HealthSnapshot =
            serde_json::from_value(responses[2]["result"].clone()).unwrap();
        assert!(health.is_ready());
        let details = health.details.unwrap();
        assert_eq!(details["connector_id"], "fcp.google-calendar");
        assert_eq!(
            details["instance_id"],
            responses[1]["result"]["instance_id"]
        );
        assert_eq!(details["configured"], true);
        assert_eq!(details["handshaken"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn native_invoke_wraps_provider_output_with_the_inner_request_id() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/users/me/calendarList"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [{ "id": "primary", "summary": "Main" }]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let key = Ed25519SigningKey::generate();
        let mut connector = GoogleCalendarConnector::new();
        handle_method(
            &mut connector,
            "configure",
            json!({
                "token": "fixture-calendar-token", "base_url": server.uri()
            }),
        )
        .await
        .unwrap();
        let hello = handle_method(&mut connector, "handshake", handshake(&key))
            .await
            .unwrap();
        let constraints = CapabilityConstraints {
            resource_allow: vec!["gcal://calendars".into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).unwrap();
        let now = Utc::now();
        let token = CapabilityToken::from_raw(
            CapabilityTokenBuilder::new()
                .capability_id("gcal.read")
                .zone_id("z:work")
                .target_instance(hello["instance_id"].as_str().unwrap())
                .principal("user:native-calendar")
                .operations(&["gcal.list_calendars"])
                .issuer("node:native-calendar")
                .validity(now, now + Duration::hours(1))
                .try_constraints_cbor(&cbor)
                .unwrap()
                .sign(&key)
                .unwrap(),
        );
        let result = handle_method(
            &mut connector,
            "invoke",
            json!({
                "type": "invoke", "id": "business-invocation",
                "connector_id": "fcp.google-calendar", "zone_id": "z:work",
                "operation": "gcal.list_calendars", "input": {},
                "capability_token": token
            }),
        )
        .await
        .unwrap();
        let response: InvokeResponse = serde_json::from_value(result).unwrap();
        assert_eq!(response.id.0, "business-invocation");
        assert_eq!(response.result.unwrap()["calendars"][0]["id"], "primary");
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}
