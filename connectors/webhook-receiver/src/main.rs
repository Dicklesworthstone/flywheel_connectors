//! FCP Webhook Receiver Connector - Main entrypoint
//!
//! A meta-connector that manages inbound webhook endpoints and stores
//! received events in memory. Implements the Flywheel Connector Protocol.

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
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::trivially_copy_pass_by_ref,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use std::io::{BufRead, Write};

use anyhow::Result;
use fcp_async_core::runtime::Builder;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use fcp_webhook_receiver::connector::WebhookReceiverConnector;

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    tracing::info!("FCP Webhook Receiver Connector starting");
    run_fcp_loop()?;
    Ok(())
}

fn run_fcp_loop() -> Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut connector = WebhookReceiverConnector::new();

    let runtime = Builder::new_multi_thread().enable_all().build()?;

    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
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

async fn handle_message(
    connector: &mut WebhookReceiverConnector,
    message: &str,
) -> serde_json::Value {
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

    let method = request
        .get("method")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let id = request.get("id").cloned();
    let params = request
        .get("params")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));

    let result = match method {
        "configure" => connector.handle_configure(params).await,
        "handshake" => connector.handle_handshake(params).await,
        "health" => connector.handle_health().await,
        "doctor" => connector.handle_doctor().await,
        "self_check" => connector.handle_self_check().await,
        "introspect" => connector.handle_introspect().await,
        "invoke" => invoke_message(connector, params).await,
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

async fn invoke_message(
    connector: &mut WebhookReceiverConnector,
    params: serde_json::Value,
) -> fcp_core::FcpResult<serde_json::Value> {
    let request: fcp_core::InvokeRequest =
        serde_json::from_value(params.clone()).map_err(|_| fcp_core::FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid FCP invoke request".into(),
        })?;
    let response = match connector.handle_invoke(params).await {
        Ok(result) => fcp_core::InvokeResponse::ok(request.id, result),
        Err(error) => fcp_core::InvokeResponse::error(request.id, error),
    };
    serde_json::to_value(response).map_err(|_| fcp_core::FcpError::Internal {
        message: "Failed to encode FCP invoke response".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use fcp_core::{
        CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, HandshakeRequest,
        HandshakeResponse, HealthSnapshot, Introspection, InvokeRequest, InvokeResponse,
        InvokeStatus, OperationId, RequestId, ZoneId,
    };
    use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
    use serde_json::json;

    #[fcp_async_core::runtime::test]
    async fn jsonrpc_host_lifecycle_and_invoke_use_canonical_fcp_envelopes() {
        let mut connector = WebhookReceiverConnector::new();
        let configured = handle_message(
            &mut connector,
            &json!({
                "jsonrpc": "2.0", "id": 1, "method": "configure", "params": {},
            })
            .to_string(),
        )
        .await;
        assert!(configured.get("error").is_none());
        let key = Ed25519SigningKey::from_bytes(&[17; 32]).unwrap();
        let handshake = HandshakeRequest {
            protocol_version: "2.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: key.verifying_key().to_bytes(),
            nonce: [7; 32],
            capabilities_requested: vec![CapabilityId::from_static("webhook.endpoints.read")],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        };
        let reply = handle_message(
            &mut connector,
            &json!({
                "jsonrpc": "2.0", "id": 2, "method": "handshake", "params": handshake,
            })
            .to_string(),
        )
        .await;
        let response: HandshakeResponse = serde_json::from_value(reply["result"].clone()).unwrap();
        assert_eq!(response.nonce, [7; 32]);
        let instance = reply["result"]["instance_id"].as_str().unwrap().to_owned();
        let reply = handle_message(
            &mut connector,
            &json!({
                "jsonrpc": "2.0", "id": 3, "method": "health", "params": {},
            })
            .to_string(),
        )
        .await;
        let health: HealthSnapshot = serde_json::from_value(reply["result"].clone()).unwrap();
        assert!(health.is_ready());
        let details = health.details.unwrap();
        assert_eq!(details["instance_id"], instance);
        assert_eq!(details["configured"], true);
        assert_eq!(details["handshaken"], true);
        let reply = handle_message(
            &mut connector,
            &json!({
                "jsonrpc": "2.0", "id": 4, "method": "introspect", "params": {},
            })
            .to_string(),
        )
        .await;
        let catalog: Introspection = serde_json::from_value(reply["result"].clone()).unwrap();
        assert!(
            catalog
                .operations
                .iter()
                .any(|op| op.id.as_str() == "webhook.health")
        );

        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let now = Utc::now();
        let token = CapabilityTokenBuilder::new()
            .capability_id("webhook.endpoints.read")
            .zone_id("z:work")
            .principal("user:test")
            .operations(&["webhook.endpoints.list"])
            .issuer("node:test")
            .target_instance(&instance)
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&fcp_cbor::to_canonical_cbor(&constraints).unwrap())
            .unwrap()
            .sign(&key)
            .unwrap();
        let mut request = InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("typed-request"),
            connector_id: ConnectorId::from_static("fcp.webhook-receiver"),
            operation: OperationId::from_static("webhook.endpoints.list"),
            zone_id: ZoneId::work(),
            input: json!({}),
            capability_token: CapabilityToken::from_raw(token),
            holder_proof: None,
            context: None,
            idempotency_key: Some("test".into()),
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: vec![],
        };
        let reply = handle_message(
            &mut connector,
            &json!({
                "jsonrpc": "2.0", "id": 5, "method": "invoke", "params": request,
            })
            .to_string(),
        )
        .await;
        assert_eq!(reply["id"], 5);
        let response: InvokeResponse = serde_json::from_value(reply["result"].clone()).unwrap();
        assert_eq!(response.id, RequestId::new("typed-request"));
        assert_eq!(response.status, InvokeStatus::Ok);
        assert_eq!(response.result.unwrap()["endpoints"], json!([]));

        request.operation = OperationId::from_static("webhook.events.recent");
        let reply = handle_message(
            &mut connector,
            &json!({
                "jsonrpc": "2.0", "id": 6, "method": "invoke", "params": request,
            })
            .to_string(),
        )
        .await;
        let response: InvokeResponse = serde_json::from_value(reply["result"].clone()).unwrap();
        assert_eq!(response.status, InvokeStatus::Error);
        assert!(response.result.is_none());
        assert!(response.error.is_some());
    }
}
