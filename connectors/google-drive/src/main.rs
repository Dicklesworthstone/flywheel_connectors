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
use fcp_sdk::prelude::{JsonlConfig, dispatch_raw_invoke, serve_jsonl};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use fcp_google_drive::connector::DriveConnector;

// A full 16 MiB upload expands beyond the SDK's default frame limit in base64.
const MAX_NATIVE_REQUEST_BYTES: usize = 32 * 1024 * 1024;

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
    let stdout = std::io::stdout();
    let mut connector = DriveConnector::new();
    run_fcp_io(&mut connector, stdin.lock(), stdout.lock())
}

fn run_fcp_io(
    connector: &mut DriveConnector,
    reader: impl BufRead,
    writer: impl Write,
) -> Result<()> {
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    let result = serve_jsonl(
        reader,
        writer,
        JsonlConfig {
            max_request_bytes: MAX_NATIVE_REQUEST_BYTES,
        },
        |method, params| runtime.block_on(handle_method(connector, method, params)),
    );
    // EOF and framing/I/O errors revoke the same credentials and authority as
    // explicit shutdown, while the executor runtime is still alive.
    runtime.block_on(connector.handle_shutdown(serde_json::json!({})))?;
    result?;
    Ok(())
}

async fn handle_method(
    connector: &mut DriveConnector,
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

    let result = handle_method(connector, method, params).await;

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
    use chrono::{Duration, Utc};
    use fcp_core::{
        CapabilityConstraints, CapabilityToken, HealthSnapshot, InvokeResponse, InvokeStatus,
    };
    use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
    use serde_json::json;

    fn health_snapshot(connector: &DriveConnector) -> HealthSnapshot {
        let runtime = Builder::new_multi_thread().enable_all().build().unwrap();
        serde_json::from_value(runtime.block_on(connector.handle_health()).unwrap()).unwrap()
    }

    #[test]
    fn native_loop_cleans_up_eof_and_stops_after_shutdown() {
        let key = Ed25519SigningKey::generate();
        for explicit_shutdown in [false, true] {
            let mut requests = vec![
                json!({"jsonrpc":"2.0", "id":"configure", "method":"configure", "params":{
                    "credential_id":"00000000-0000-0000-0000-000000000001"
                }}),
                json!({"jsonrpc":"2.0", "id":"handshake", "method":"handshake", "params":{
                    "protocol_version":"2.0", "zone":"z:work",
                    "host_public_key":key.verifying_key().to_bytes(), "nonce":vec![7_u8;32],
                    "capabilities_requested":["drive.read"]
                }}),
                json!({"jsonrpc":"2.0", "id":"health", "method":"health", "params":{}}),
            ];
            if explicit_shutdown {
                requests
                    .push(json!({"jsonrpc":"2.0", "id":"stop", "method":"shutdown", "params":{}}));
                requests.push(
                    json!({"jsonrpc":"2.0", "id":"after-stop", "method":"health", "params":{}}),
                );
            }
            let input = requests
                .iter()
                .map(serde_json::Value::to_string)
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
            let mut connector = DriveConnector::new();
            let mut output = Vec::new();
            run_fcp_io(&mut connector, std::io::Cursor::new(input), &mut output).unwrap();
            let responses: Vec<serde_json::Value> = std::str::from_utf8(&output)
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            assert_eq!(responses.len(), if explicit_shutdown { 4 } else { 3 });
            assert!(
                responses
                    .iter()
                    .all(|response| response.get("error").is_none()),
                "{responses:?}"
            );
            let ready: HealthSnapshot =
                serde_json::from_value(responses[2]["result"].clone()).unwrap();
            assert!(ready.is_ready());
            assert_eq!(
                ready.details.unwrap()["instance_id"],
                responses[1]["result"]["instance_id"]
            );
            let stopped = health_snapshot(&connector);
            assert!(!stopped.is_ready());
            let details = stopped.details.unwrap();
            assert_eq!(details["configured"], false);
            assert_eq!(details["handshaken"], false);
            assert!(details["session_id"].is_null());
            assert_ne!(
                details["instance_id"],
                responses[1]["result"]["instance_id"]
            );
        }
    }

    #[test]
    fn native_loop_accepts_upload_sized_frames_and_closes_oversized_input() {
        use std::io::Read as _;
        let encoded_upload_bytes = fcp_google_drive::client::MAX_UPLOAD_BYTES.div_ceil(3) * 4;
        let input = json!({
            "jsonrpc":"2.0", "id":"full-upload-envelope", "method":"health",
            "params":{"content_base64":"A".repeat(encoded_upload_bytes)},
        })
        .to_string()
            + "\n";
        assert!(input.len() > JsonlConfig::default().max_request_bytes);
        let mut connector = DriveConnector::new();
        let mut output = Vec::new();
        run_fcp_io(&mut connector, std::io::Cursor::new(input), &mut output).unwrap();
        let response: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(response["id"], "full-upload-envelope");
        assert!(response.get("error").is_none());

        let configured = json!({
            "jsonrpc":"2.0", "id":"configure", "method":"configure",
            "params":{"credential_id":"00000000-0000-0000-0000-000000000001"},
        })
        .to_string()
            + "\n";
        let input = std::io::Cursor::new(configured).chain(
            std::io::repeat(b' ').take(u64::try_from(MAX_NATIVE_REQUEST_BYTES).unwrap() + 1),
        );
        let mut output = Vec::new();
        let error =
            run_fcp_io(&mut connector, std::io::BufReader::new(input), &mut output).unwrap_err();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::InvalidData
        );
        let responses: Vec<serde_json::Value> = std::str::from_utf8(&output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[1]["error"]["code"], "FCP-1004");
        let stopped = health_snapshot(&connector);
        assert!(!stopped.is_ready());
        assert_eq!(stopped.details.unwrap()["configured"], false);
    }

    async fn rpc(
        connector: &mut DriveConnector,
        method: &str,
        params: serde_json::Value,
    ) -> serde_json::Value {
        handle_message(
            connector,
            &json!({
                "jsonrpc": "2.0", "id": "transport", "method": method, "params": params,
            })
            .to_string(),
        )
        .await
    }

    #[fcp_async_core::runtime::test]
    async fn host_jsonrpc_prepares_actual_instance_and_returns_typed_provider_result() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/drive/v3/files/file-123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "file-123", "name": "host-result.txt", "mimeType": "text/plain",
            })))
            .expect(1)
            .mount(&server)
            .await;
        let mut connector = DriveConnector::new();
        let key = Ed25519SigningKey::generate();
        let preferred = fcp_core::InstanceId::new();
        let configured = rpc(&mut connector, "configure", json!({
            "access_token": "host-fixture-token", "base_url": format!("{}/drive/v3", server.uri()),
        })).await;
        assert!(configured.get("error").is_none(), "{configured}");
        let handshaken = rpc(
            &mut connector,
            "handshake",
            json!({
                "protocol_version": "2.0", "zone": "z:work",
                "host_public_key": key.verifying_key().to_bytes(),
                "capabilities_requested": ["drive.read"], "nonce": vec![7_u8; 32],
                "requested_instance_id": preferred,
            }),
        )
        .await;
        assert!(handshaken.get("error").is_none(), "{handshaken}");
        let health_response = rpc(&mut connector, "health", json!({})).await;
        let health: HealthSnapshot =
            serde_json::from_value(health_response["result"].clone()).unwrap();
        assert!(health.is_ready());
        let details = health.details.unwrap();
        assert_eq!(details["configured"], true);
        assert_eq!(details["handshaken"], true);
        assert_eq!(details["connector_id"], "fcp.google_drive");
        assert_eq!(details["instance_id"], handshaken["result"]["instance_id"]);
        assert_ne!(details["instance_id"], json!(preferred));
        let constraints = CapabilityConstraints {
            resource_allow: vec!["drive://files/file-123".into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).unwrap();
        let now = Utc::now();
        let token = CapabilityToken::from_raw(
            CapabilityTokenBuilder::new()
                .capability_id("drive.read")
                .zone_id("z:work")
                .principal("user:fixture")
                .operations(&["drive.get_file"])
                .issuer("node:fixture")
                .target_instance(details["instance_id"].as_str().unwrap())
                .validity(now, now + Duration::hours(1))
                .try_constraints_cbor(&cbor)
                .unwrap()
                .sign(&key)
                .unwrap(),
        );
        let request = json!({
            "type": "invoke", "id": "provider-invocation", "connector_id": "fcp.google_drive",
            "zone_id": "z:work", "operation": "drive.get_file",
            "input": {"file_id": "file-123"}, "capability_token": token,
        });
        let mut wrong_target = request.clone();
        wrong_target["connector_id"] = json!("fcp.not_drive");
        let denied = rpc(&mut connector, "invoke", wrong_target).await;
        assert!(denied.get("error").is_some());
        assert!(server.received_requests().await.unwrap().is_empty());
        let result = rpc(&mut connector, "invoke", request.clone()).await;
        assert_eq!(result["id"], "transport");
        let invoked: InvokeResponse = serde_json::from_value(result["result"].clone()).unwrap();
        assert_eq!(invoked.id.0, "provider-invocation");
        assert_eq!(invoked.status, InvokeStatus::Ok);
        assert_eq!(invoked.result.unwrap()["file"]["id"], "file-123");
        let stopped = rpc(&mut connector, "shutdown", json!({})).await;
        assert_eq!(stopped["result"]["status"], "shutdown");
        let health_response = rpc(&mut connector, "health", json!({})).await;
        let health: HealthSnapshot =
            serde_json::from_value(health_response["result"].clone()).unwrap();
        assert!(!health.is_ready());
        assert_eq!(health.details.unwrap()["configured"], false);
        assert!(
            rpc(&mut connector, "invoke", request)
                .await
                .get("error")
                .is_some()
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

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
