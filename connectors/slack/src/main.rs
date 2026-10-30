//! FCP Slack Connector - Main entrypoint
//!
//! A Slack workspace connector implementing the Flywheel Connector Protocol.
//! Provides access to channels, messages, users, files, reactions, and threads.

#![forbid(unsafe_code)]
#![recursion_limit = "256"]
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

use std::io::{BufRead, BufReader, Write};

use anyhow::Result;
use fcp_async_core::runtime::Builder;
use fcp_sdk::prelude::{JsonlConfig, JsonlEventStream, JsonlWriter, serve_jsonl_events};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use fcp_slack::connector::SlackConnector;

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    tracing::info!("FCP Slack Connector starting");

    run_fcp_loop()?;

    Ok(())
}

/// Run the FCP JSON-RPC style protocol loop.
fn run_fcp_loop() -> Result<()> {
    run_fcp_loop_with_io(BufReader::new(std::io::stdin()), std::io::stdout())
}

fn run_fcp_loop_with_io<R, W>(reader: R, stdout: W) -> Result<()>
where
    R: BufRead + Send + 'static,
    W: Write + Send + 'static,
{
    let events = JsonlEventStream::new(JsonlWriter::new(stdout));
    let mut connector = SlackConnector::new();
    connector.attach_event_stream(events.clone())?;
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    let result = serve_jsonl_events(reader, events, JsonlConfig::default(), |method, params| {
        runtime.block_on(dispatch_message(&mut connector, method, params))
    });
    // EOF, read failure, and a broken stdout must release outstanding event
    // obligations before the Socket Mode worker is joined. None is an ACK.
    let _ = runtime.block_on(connector.handle_shutdown(serde_json::json!({})));
    result?;
    Ok(())
}

#[cfg(test)]
fn should_skip_protocol_line(line: &str) -> bool {
    line.trim().is_empty()
}

#[cfg(test)]
fn parse_error_response(error: impl std::fmt::Display) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": null,
        "error": {
            "code": "FCP-1001",
            "message": format!("Invalid JSON: {error}")
        }
    })
}

/// Handle a single FCP message.
#[cfg(test)]
async fn handle_message(connector: &mut SlackConnector, message: &str) -> serde_json::Value {
    let request: serde_json::Value = match serde_json::from_str(message) {
        Ok(v) => v,
        Err(e) => return parse_error_response(e),
    };

    let method = request.get("method").and_then(|v| v.as_str()).unwrap_or("");
    let id = request.get("id").cloned();
    let params = request
        .get("params")
        .cloned()
        .unwrap_or(serde_json::json!({}));

    let result = dispatch_message(connector, method, params).await;

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

async fn dispatch_message(
    connector: &mut SlackConnector,
    method: &str,
    params: serde_json::Value,
) -> fcp_core::FcpResult<serde_json::Value> {
    match method {
        "configure" => connector.handle_configure(params).await,
        "handshake" => connector.handle_handshake(params).await,
        "health" => connector.handle_native_health().await,
        "doctor" => connector.handle_doctor().await,
        "self_check" => connector.handle_self_check().await,
        "introspect" => connector.handle_introspect().await,
        "subscribe" => connector.handle_subscribe(params).await,
        "invoke" => {
            fcp_sdk::prelude::dispatch_raw_invoke(params, |params| connector.handle_invoke(params))
                .await
        }
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
    use std::io::{self, BufReader, Read};
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Clone, Default)]
    struct CapturedOutput(Arc<Mutex<Vec<u8>>>);

    impl Write for CapturedOutput {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct ErrorAfterBytes {
        bytes: &'static [u8],
        position: usize,
        error_kind: io::ErrorKind,
        error_message: &'static str,
        did_error: bool,
    }

    impl ErrorAfterBytes {
        fn new(
            bytes: &'static [u8],
            error_kind: io::ErrorKind,
            error_message: &'static str,
        ) -> Self {
            Self {
                bytes,
                position: 0,
                error_kind,
                error_message,
                did_error: false,
            }
        }
    }

    impl Read for ErrorAfterBytes {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.position < self.bytes.len() {
                let remaining = &self.bytes[self.position..];
                let bytes_to_copy = remaining.len().min(buf.len());
                buf[..bytes_to_copy].copy_from_slice(&remaining[..bytes_to_copy]);
                self.position += bytes_to_copy;
                return Ok(bytes_to_copy);
            }

            if self.did_error {
                return Ok(0);
            }

            self.did_error = true;
            Err(io::Error::new(self.error_kind, self.error_message))
        }
    }

    #[test]
    fn protocol_loop_skips_whitespace_only_lines() {
        assert!(should_skip_protocol_line(""));
        assert!(should_skip_protocol_line(" \t "));
        assert!(!should_skip_protocol_line("{\"jsonrpc\":\"2.0\"}"));
    }

    #[test]
    fn protocol_loop_propagates_input_read_errors() {
        let reader = BufReader::new(ErrorAfterBytes::new(
            b"   \n",
            io::ErrorKind::ConnectionReset,
            "simulated read failure",
        ));
        let output = CapturedOutput::default();
        let error = run_fcp_loop_with_io(reader, output.clone())
            .expect_err("input read error should propagate");
        let io_error = error
            .downcast_ref::<io::Error>()
            .expect("error should preserve io::Error");

        assert_eq!(io_error.kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(io_error.to_string(), "simulated read failure");
        assert!(
            output.0.lock().unwrap().is_empty(),
            "whitespace-only input should not emit a response"
        );
    }

    #[test]
    fn production_loop_returns_a_canonical_health_snapshot() {
        let output = CapturedOutput::default();
        run_fcp_loop_with_io(
            io::Cursor::new(b"{\"jsonrpc\":\"2.0\",\"id\":\"probe\",\"method\":\"health\"}\n"),
            output.clone(),
        )
        .expect("native health RPC must complete");
        let bytes = output.0.lock().unwrap();
        let response: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(response["id"], "probe");
        let snapshot: fcp_core::HealthSnapshot =
            serde_json::from_value(response["result"].clone()).unwrap();
        let details = snapshot.details.unwrap();
        assert_eq!(details["configured"], false);
        assert_eq!(details["handshaken"], false);
        assert!(details["instance_id"].is_string());
    }

    #[cfg(unix)]
    #[test]
    fn production_loop_accepts_ack_while_events_api_invoke_is_pending() {
        use std::net::Shutdown;
        use std::os::unix::net::UnixStream;
        use std::sync::mpsc;
        use std::time::Duration;

        use fcp_core::{CapabilityConstraints, CapabilityToken, CredentialId};
        use fcp_crypto::cose::CapabilityTokenBuilder;
        use fcp_crypto::ed25519::Ed25519SigningKey;
        use serde_json::{Value, json};

        fn send(input: &mut UnixStream, frame: &Value) {
            writeln!(input, "{frame}").expect("write complete native request");
        }

        fn receive(output: &mut BufReader<UnixStream>) -> Value {
            let mut line = String::new();
            assert!(
                output
                    .read_line(&mut line)
                    .expect("bounded native response")
                    > 0
            );
            serde_json::from_str(&line).expect("complete JSONL response")
        }

        fn bound_read_token(
            key: &Ed25519SigningKey,
            instance_id: &str,
            operation: &str,
            resources: &[&str],
        ) -> CapabilityToken {
            let constraints = CapabilityConstraints {
                resource_allow: resources
                    .iter()
                    .map(|resource| (*resource).into())
                    .collect(),
                ..Default::default()
            };
            let mut cbor = Vec::new();
            ciborium::into_writer(&constraints, &mut cbor).unwrap();
            let now = chrono::Utc::now();
            CapabilityToken::from_raw(
                CapabilityTokenBuilder::new()
                    .capability_id("slack.read")
                    .zone_id("z:work")
                    .principal("user:native-wire-test")
                    .operations(&[operation])
                    .issuer("node:native-wire-test")
                    .target_instance(instance_id)
                    .validity(
                        now - chrono::Duration::seconds(30),
                        now + chrono::Duration::minutes(5),
                    )
                    .try_constraints_cbor(&cbor)
                    .unwrap()
                    .sign(key)
                    .unwrap(),
            )
        }

        let (mut host, connector) = UnixStream::pair().unwrap();
        host.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        host.set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut output = BufReader::new(host.try_clone().unwrap());
        let stdout = connector.try_clone().unwrap();
        let (stopped, stopped_rx) = mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let result = run_fcp_loop_with_io(BufReader::new(connector), stdout);
            let _ = stopped.send(result.map_err(|error| error.to_string()));
        });

        send(
            &mut host,
            &json!({
                "jsonrpc": "2.0", "id": "configure", "method": "configure",
                "params": {
                    "credential_id": CredentialId::new().to_string(),
                    "receive_mode": "events_api",
                    "monitor_policy": {"require_mention": false},
                },
            }),
        );
        let configured = receive(&mut output);
        assert_eq!(configured["id"], "configure");
        assert_eq!(configured["result"]["status"], "configured");

        let key = Ed25519SigningKey::generate();
        send(
            &mut host,
            &json!({
                "jsonrpc": "2.0", "id": "handshake", "method": "handshake",
                "params": {
                    "protocol_version": "2.0.0", "zone": "z:work",
                    "host_public_key": key.verifying_key().to_bytes(),
                    "nonce": vec![0u8; 32], "capabilities_requested": ["slack.read"],
                },
            }),
        );
        let handshaken = receive(&mut output);
        assert_eq!(handshaken["id"], "handshake");
        assert_eq!(handshaken["result"]["status"], "accepted");
        send(
            &mut host,
            &json!({
                "jsonrpc": "2.0", "id": "health", "method": "health",
            }),
        );
        let health = receive(&mut output);
        assert_eq!(health["id"], "health");
        let instance_id = health["result"]["details"]["instance_id"].as_str().unwrap();

        send(
            &mut host,
            &json!({
                "jsonrpc": "2.0", "id": "subscribe-rpc", "method": "subscribe",
                "params": {
                    "type": "subscribe", "id": "subscribe-native", "stream_id": "slack-wire-test",
                    "topics": ["slack.events"], "window_size": 1,
                    "capability_token": bound_read_token(&key, instance_id, "slack.subscribe", &["slack:events:slack.events"]),
                },
            }),
        );
        let subscribed = receive(&mut output);
        assert_eq!(subscribed["id"], "subscribe-rpc");
        assert_eq!(subscribed["result"]["id"], "subscribe-native");
        assert_eq!(
            subscribed["result"]["result"]["confirmed_topics"],
            json!(["slack.events"])
        );

        let payload = json!({
            "type": "event_callback", "event_id": "Ev-wire-1", "team_id": "T_WIRE",
            "event": {"type": "message", "user": "U_WIRE", "channel": "C_WIRE", "text": "native transport"},
        });
        send(
            &mut host,
            &json!({
                "jsonrpc": "2.0", "id": "callback-rpc", "method": "invoke",
                "params": {
                    "id": "callback-native", "operation": "slack.handle_events_api",
                    "input": {"payload": payload, "signature_result": "verified"},
                    "capability_token": bound_read_token(&key, instance_id, "slack.handle_events_api", &["slack:channel:C_WIRE", "slack:user:U_WIRE", "slack:team:T_WIRE"]),
                },
            }),
        );

        // The event must reach the real stdout path before this invoke can reply.
        let notification = receive(&mut output);
        assert_eq!(notification["method"], "event");
        assert!(notification.get("id").is_none());
        assert_eq!(notification["params"]["stream_id"], "slack-wire-test");
        let event = &notification["params"]["event"];
        assert_eq!(event["topic"], "slack.events");
        assert_eq!(event["cursor"], "Ev-wire-1");
        assert_eq!(event["requires_ack"], true);
        assert_eq!(event["data"]["connector_id"], "fcp.slack");
        assert_eq!(event["data"]["instance_id"], instance_id);
        assert_eq!(event["data"]["zone_id"], "z:work");
        assert_eq!(
            event["data"]["payload"],
            json!({"source_topic": "slack.message.new", "event": payload})
        );

        let ack = json!({
            "jsonrpc": "2.0", "method": "ack",
            "params": {
                "stream_id": "slack-wire-test",
                "ack": {"type": "ack", "topic": event["topic"], "seqs": [event["seq"]], "cursors": [event["cursor"]]},
            },
        });
        let mut wrong_ack = ack.clone();
        wrong_ack["params"]["ack"]["cursors"] = json!(["wrong-cursor"]);
        send(&mut host, &wrong_ack);
        // This invalid control receives an immediate reader-path error. Seeing
        // it proves that stdin progressed past the wrong ACK while invoke waits.
        send(
            &mut host,
            &json!({
                "jsonrpc": "2.0", "id": "control-barrier", "method": "ack", "params": {},
            }),
        );
        let barrier = receive(&mut output);
        assert_eq!(barrier["id"], "control-barrier");
        assert_eq!(barrier["error"]["code"], "FCP-1003");
        host.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let mut premature_response = String::new();
        let error = output
            .read_line(&mut premature_response)
            .expect_err("wrong ACK cannot finish invoke");
        assert!(matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ));
        assert!(premature_response.is_empty());
        host.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

        send(&mut host, &ack);
        let completed = receive(&mut output);
        assert_eq!(completed["id"], "callback-rpc");
        let response: fcp_core::InvokeResponse =
            serde_json::from_value(completed["result"].clone()).unwrap();
        assert_eq!(response.r#type, "response");
        assert_eq!(response.id.as_str(), "callback-native");
        assert_eq!(response.status, fcp_core::InvokeStatus::Ok);
        let result = response.result.unwrap();
        assert_eq!(result["acknowledged"], true);
        assert_eq!(result["event_emitted"], true);
        assert_eq!(result["event"]["data"]["zone_id"], "z:work");

        send(
            &mut host,
            &json!({
                "jsonrpc": "2.0", "id": "shutdown", "method": "shutdown",
            }),
        );
        let shutdown = receive(&mut output);
        assert_eq!(shutdown["id"], "shutdown");
        assert_eq!(shutdown["result"]["status"], "shutdown");
        host.shutdown(Shutdown::Both).unwrap();
        stopped_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("native loop must stop")
            .unwrap();
        worker.join().unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_requires_an_inner_id_and_preserves_handler_errors() {
        let mut connector = SlackConnector::new();
        for params in [
            serde_json::json!({}),
            serde_json::json!({"id": null}),
            serde_json::json!({"id": 7}),
            serde_json::json!({"id": ["request"]}),
        ] {
            let request = serde_json::json!({
                "jsonrpc": "2.0", "id": "transport-7", "method": "invoke", "params": params
            });
            let response = handle_message(&mut connector, &request.to_string()).await;
            assert_eq!(response["id"], "transport-7");
            assert!(response.get("result").is_none());
            assert_eq!(response["error"]["code"], "FCP-1003");
            assert_eq!(
                response["error"]["message"],
                "Invalid request: invoke params.id must be a string"
            );
        }

        let request = serde_json::json!({
            "jsonrpc": "2.0", "id": 7, "method": "invoke", "params": {"id": "invoke-7"}
        });
        let response = handle_message(&mut connector, &request.to_string()).await;
        assert_eq!(response["id"], 7);
        assert!(response.get("result").is_none());
        assert_eq!(response["error"]["code"], "FCP-1003");
        assert_eq!(
            response["error"]["message"],
            "Invalid request: Missing operation"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn invalid_json_is_wrapped_in_jsonrpc_parse_error() {
        let mut connector = SlackConnector::new();
        let response = handle_message(&mut connector, "{not json").await;

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
