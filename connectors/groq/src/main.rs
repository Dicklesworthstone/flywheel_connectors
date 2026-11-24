#![forbid(unsafe_code)]

use std::io::{self, BufRead, Write};

use anyhow::Result;
use fcp_prelude::{FcpConnector, FcpError, FcpResult};
use fcp_sdk::prelude::{JsonlConfig, serve_jsonl};
use serde_json::{Value, json};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use fcp_groq::GroqConnector;

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    run_fcp_loop()
}

fn run_fcp_loop() -> Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut connector = GroqConnector::new();
    serve(stdin.lock(), stdout.lock(), &mut connector)?;
    Ok(())
}

fn serve(
    reader: impl BufRead,
    writer: impl Write,
    connector: &mut GroqConnector,
) -> io::Result<()> {
    serve_jsonl(reader, writer, JsonlConfig::default(), |method, params| {
        fcp_async_core::runtime::block_on_sync(handle_request(connector, method, params))
            .unwrap_or_else(|error| {
                Err(FcpError::Internal {
                    message: format!("Runtime error: {error}"),
                })
            })
    })
}

async fn handle_request(
    connector: &mut GroqConnector,
    method: &str,
    params: Value,
) -> FcpResult<Value> {
    match method {
        "configure" => connector.handle_configure(params).await,
        "handshake" => connector.handle_handshake(params).await,
        "health" => {
            let mut snapshot = connector.health().await;
            let mut details = connector.handle_health().await?;
            details["instance_id"] = json!(connector.instance_id());
            snapshot.details = Some(details);
            encode_response(snapshot)
        }
        "doctor" => connector.handle_doctor().await,
        "self_check" => connector.handle_self_check().await,
        "introspect" => connector.handle_introspect().await,
        "invoke" => {
            let request = serde_json::from_value(params).map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "Invalid FCP invoke request".into(),
            })?;
            encode_response(connector.invoke(request).await?)
        }
        "simulate" => {
            let request = serde_json::from_value(params).map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "Invalid FCP simulate request".into(),
            })?;
            encode_response(connector.simulate(request).await?)
        }
        "shutdown" => connector.handle_shutdown(params).await,
        _ => Err(FcpError::InvalidRequest {
            code: 1002,
            message: format!("Unknown method: {method}"),
        }),
    }
}

fn encode_response(value: impl serde::Serialize) -> FcpResult<Value> {
    serde_json::to_value(value).map_err(|_| FcpError::Internal {
        message: "Failed to encode FCP response".into(),
    })
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use chrono::{Duration as ChronoDuration, Utc};
    use fcp_core::{
        ConnectorId, HealthSnapshot, HealthState, InvokeResponse, OperationId, RequestId,
        SimulateRequest, SimulateResponse, ZoneId,
    };
    use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
    use fcp_groq::connector::{CONNECTOR_ID, test_handshake_request, test_invoke_request};
    use fcp_prelude::{CapabilityConstraints, CapabilityId, CapabilityToken, InstanceId};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_partial_json, header, method, path},
    };

    use super::*;

    const OP_CHAT: &str = "groq.chat.completions";
    const OP_EMBEDDINGS: &str = "groq.embeddings.create";
    const CAP_CHAT: &str = "groq.chat";

    fn rpc(id: &str, method: &str, params: Value) -> Value {
        json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
    }

    fn frames(requests: &[Value]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for request in requests {
            serde_json::to_writer(&mut bytes, request).expect("serialize request frame");
            bytes.push(b'\n');
        }
        bytes
    }

    fn replies(output: &[u8]) -> Vec<Value> {
        std::str::from_utf8(output)
            .expect("UTF-8 response frames")
            .lines()
            .map(|line| serde_json::from_str(line).expect("JSON response frame"))
            .collect()
    }

    fn run_frames(connector: &mut GroqConnector, requests: &[Value]) -> Vec<Value> {
        let mut output = Vec::new();
        serve(Cursor::new(frames(requests)), &mut output, connector)
            .expect("serve connector requests");
        replies(&output)
    }

    fn signed_token(
        signing_key: &Ed25519SigningKey,
        instance_id: &InstanceId,
        capability: &str,
        operation: &str,
    ) -> CapabilityToken {
        let now = Utc::now();
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
        let cose = CapabilityTokenBuilder::new()
            .capability_id(capability)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[operation])
            .issuer("node:test")
            .target_instance(instance_id.as_str())
            .validity(now, now + ChronoDuration::hours(1))
            .try_constraints_cbor(&cbor)
            .expect("valid constraint CBOR")
            .sign(signing_key)
            .expect("sign capability grant");
        CapabilityToken::from_raw(cose)
    }

    #[test]
    fn jsonl_session_reports_canonical_health_and_actual_instance() {
        let mut connector = GroqConnector::new();
        let instance = json!(connector.instance_id());
        let signing_key = Ed25519SigningKey::generate();
        let handshake = test_handshake_request(
            vec![CapabilityId::from_static(CAP_CHAT)],
            signing_key.verifying_key().to_bytes(),
        );
        let responses = run_frames(
            &mut connector,
            &[
                rpc("health-start", "health", json!({})),
                rpc(
                    "configure",
                    "configure",
                    json!({"api_key": "groq-test-key"}),
                ),
                rpc("health-configured", "health", json!({})),
                rpc("handshake", "handshake", json!(handshake)),
                rpc("health-ready", "health", json!({})),
            ],
        );

        assert_eq!(responses.len(), 5);
        for (index, configured, handshaken) in
            [(0, false, false), (2, true, false), (4, true, true)]
        {
            let snapshot: HealthSnapshot =
                serde_json::from_value(responses[index]["result"].clone())
                    .expect("canonical health snapshot");
            match index {
                0 => assert!(matches!(snapshot.status, HealthState::Error { .. })),
                2 => assert!(matches!(snapshot.status, HealthState::Degraded { .. })),
                _ => assert!(matches!(snapshot.status, HealthState::Ready)),
            }
            let details = snapshot.details.expect("provider health details");
            assert_eq!(details["configured"], configured);
            assert_eq!(details["handshaken"], handshaken);
            if index == 0 {
                assert_eq!(details["instance_id"], instance);
            } else {
                assert_ne!(details["instance_id"], instance);
            }
            assert_eq!(responses[index]["jsonrpc"], "2.0");
            assert!(responses[index].get("error").is_none());
        }
        assert_eq!(responses[0]["id"], "health-start");
        assert_eq!(responses[2]["id"], "health-configured");
        assert_eq!(responses[4]["id"], "health-ready");
        assert!(responses[1].get("result").is_some());
        assert!(responses[3].get("result").is_some());
        assert_ne!(
            responses[2]["result"]["details"]["instance_id"],
            responses[4]["result"]["details"]["instance_id"]
        );
        assert_eq!(
            responses[4]["result"]["details"]["instance_id"],
            json!(connector.instance_id())
        );
    }

    #[fcp_async_core::runtime::test]
    async fn dispatch_wraps_signed_provider_result_and_keeps_instance_denials_as_errors() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/openai/v1/chat/completions"))
            .and(header("authorization", "Bearer groq-test-key"))
            .and(body_partial_json(json!({
                "model": "llama-3.1-8b-instant",
                "messages": [{"role": "user", "content": "hello"}],
                "stream": false
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "provider-chat-id",
                "object": "chat.completion",
                "created": 1,
                "model": "llama-3.1-8b-instant",
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": "hello from Groq"},
                    "finish_reason": "stop"
                }],
                "usage": {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5}
            })))
            .expect(1)
            .mount(&server)
            .await;

        let mut connector = GroqConnector::new();
        handle_request(
            &mut connector,
            "configure",
            json!({
                "api_key": "groq-test-key",
                "base_url": format!("{}/openai/v1", server.uri())
            }),
        )
        .await
        .expect("configure through production dispatch");
        let signing_key = Ed25519SigningKey::generate();
        handle_request(
            &mut connector,
            "handshake",
            json!(test_handshake_request(
                vec![CapabilityId::from_static(CAP_CHAT)],
                signing_key.verifying_key().to_bytes(),
            )),
        )
        .await
        .expect("handshake through production dispatch");

        let input = json!({"messages": [{"role": "user", "content": "hello"}]});
        let token = signed_token(&signing_key, connector.instance_id(), CAP_CHAT, OP_CHAT);
        let request = test_invoke_request("fcp-invoke-id", OP_CHAT, input.clone(), token);
        let encoded = handle_request(&mut connector, "invoke", json!(request))
            .await
            .expect("signed invocation through production dispatch");
        let response: InvokeResponse =
            serde_json::from_value(encoded.clone()).expect("canonical invoke response");
        assert_eq!(response.r#type, "response");
        assert_eq!(response.id, RequestId::new("fcp-invoke-id"));
        assert_eq!(encoded["status"], "ok");
        assert!(response.error.is_none());
        let result = response.result.expect("provider result");
        assert_eq!(result["id"], "provider-chat-id");
        assert_eq!(result["raw"]["id"], "provider-chat-id");
        assert_eq!(result["content"], "hello from Groq");
        assert_eq!(result["usage"]["total_tokens"], 5);

        let wrong_instance = signed_token(&signing_key, &InstanceId::new(), CAP_CHAT, OP_CHAT);
        let rejected = test_invoke_request("rejected-id", OP_CHAT, input, wrong_instance);
        assert!(
            handle_request(&mut connector, "invoke", json!(rejected))
                .await
                .is_err(),
            "a rejected capability remains an RPC error, not a successful response envelope"
        );
        let health = handle_request(&mut connector, "health", json!({}))
            .await
            .expect("health after invocation");
        assert_eq!(health["details"]["requests"], 1);
        assert_eq!(health["details"]["errors"], 1);
        server.verify().await;
    }

    #[test]
    fn jsonl_simulate_preserves_outer_and_inner_ids_with_typed_results() {
        let mut connector = GroqConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let setup = run_frames(
            &mut connector,
            &[
                rpc(
                    "configure",
                    "configure",
                    json!({"api_key": "groq-test-key"}),
                ),
                rpc(
                    "handshake",
                    "handshake",
                    json!(test_handshake_request(
                        vec![CapabilityId::from_static(CAP_CHAT)],
                        signing_key.verifying_key().to_bytes(),
                    )),
                ),
            ],
        );
        assert!(setup.iter().all(|response| response.get("error").is_none()));
        let token = signed_token(&signing_key, connector.instance_id(), CAP_CHAT, OP_CHAT);
        let mut request = SimulateRequest::new(
            ConnectorId::from_static(CONNECTOR_ID),
            OperationId::from_static(OP_CHAT),
            ZoneId::work(),
            json!({"messages": [{"role": "user", "content": "hello"}]}),
            token,
        );
        request.id = RequestId::new("simulate-allowed");
        let allowed = json!(request);
        request.id = RequestId::new("simulate-denied");
        request.operation = OperationId::from_static(OP_EMBEDDINGS);
        let responses = run_frames(
            &mut connector,
            &[
                rpc("rpc-allowed", "simulate", allowed),
                rpc("rpc-denied", "simulate", json!(request)),
            ],
        );

        assert_eq!(responses.len(), 2);
        let allowed: SimulateResponse = serde_json::from_value(responses[0]["result"].clone())
            .expect("typed allowed simulation");
        let denied: SimulateResponse = serde_json::from_value(responses[1]["result"].clone())
            .expect("typed denied simulation");
        assert_eq!(responses[0]["id"], "rpc-allowed");
        assert_eq!(responses[1]["id"], "rpc-denied");
        assert_eq!(allowed.r#type, "simulate_response");
        assert_eq!(allowed.id, RequestId::new("simulate-allowed"));
        assert!(allowed.would_succeed);
        assert_eq!(denied.id, RequestId::new("simulate-denied"));
        assert!(!denied.would_succeed);
        assert_eq!(denied.denial_code.as_deref(), Some("FCP-3010"));
    }

    #[test]
    fn jsonl_errors_recover_and_shutdown_stops_before_later_input() {
        let mut connector = GroqConnector::new();
        let mut input = b"{invalid-json\n".to_vec();
        input.extend(frames(&[
            rpc("unknown", "not-a-method", json!({})),
            rpc("missing-invoke-id", "invoke", json!({"operation": OP_CHAT})),
            rpc("bad-simulate", "simulate", json!({"operation": OP_CHAT})),
            rpc("stop", "shutdown", json!({})),
        ]));
        let shutdown_boundary = input.len() as u64;
        input.extend(frames(&[rpc(
            "must-not-run",
            "configure",
            json!({"api_key": "groq-test-key"}),
        )]));
        let mut reader = Cursor::new(input);
        let mut output = Vec::new();
        serve(&mut reader, &mut output, &mut connector).expect("serve recoverable errors");

        let responses = replies(&output);
        assert_eq!(responses.len(), 5);
        for response in &responses[..4] {
            assert_eq!(response["jsonrpc"], "2.0");
            assert!(response.get("error").is_some());
            assert!(response.get("result").is_none());
        }
        assert!(responses[0]["id"].is_null());
        assert_eq!(responses[1]["id"], "unknown");
        assert_eq!(responses[2]["id"], "missing-invoke-id");
        assert_eq!(responses[3]["id"], "bad-simulate");
        assert_eq!(responses[4]["id"], "stop");
        assert_eq!(responses[4]["result"]["status"], "shutdown");
        assert_eq!(reader.position(), shutdown_boundary);
        let health = run_frames(&mut connector, &[rpc("health", "health", json!({}))]);
        assert_eq!(health[0]["result"]["details"]["configured"], false);
    }

    #[test]
    fn jsonl_oversized_frame_is_bounded_and_terminal() {
        let limit = JsonlConfig::default().max_request_bytes;
        let mut input = vec![b'x'; limit + 3];
        input.push(b'\n');
        input.extend(frames(&[rpc(
            "must-not-run",
            "configure",
            json!({"api_key": "groq-test-key"}),
        )]));
        let mut reader = Cursor::new(input);
        let mut output = Vec::new();
        let mut connector = GroqConnector::new();
        let error = serve(&mut reader, &mut output, &mut connector)
            .expect_err("oversized request must terminate the transport");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(reader.position(), (limit + 2) as u64);
        let responses = replies(&output);
        assert_eq!(responses.len(), 1);
        assert!(responses[0]["id"].is_null());
        assert!(responses[0].get("error").is_some());
        assert!(responses[0].get("result").is_none());
    }

    #[test]
    fn jsonl_flush_failure_does_not_replay_invocation_or_dispatch_later_input() {
        #[derive(Default)]
        struct FailFlush {
            bytes: Vec<u8>,
            flushes: usize,
        }

        impl Write for FailFlush {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                self.flushes += 1;
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "test output failure",
                ))
            }
        }

        let mut connector = GroqConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let setup = run_frames(
            &mut connector,
            &[
                rpc(
                    "configure",
                    "configure",
                    json!({"api_key": "groq-test-key"}),
                ),
                rpc(
                    "handshake",
                    "handshake",
                    json!(test_handshake_request(
                        vec![CapabilityId::from_static("groq.embeddings")],
                        signing_key.verifying_key().to_bytes(),
                    )),
                ),
            ],
        );
        assert!(
            setup
                .iter()
                .all(|response| response.get("result").is_some())
        );
        let token = signed_token(
            &signing_key,
            connector.instance_id(),
            "groq.embeddings",
            OP_EMBEDDINGS,
        );
        // This admitted but unsupported operation increments the handler's
        // request and error counters without sending an upstream HTTP request.
        let request = json!(test_invoke_request(
            "inner-invoke",
            OP_EMBEDDINGS,
            json!({}),
            token,
        ));
        let mut input = frames(&[rpc("first-invoke", "invoke", request.clone())]);
        let first_boundary = input.len() as u64;
        input.extend(frames(&[rpc("must-not-run", "invoke", request)]));
        let mut reader = Cursor::new(input);
        let mut writer = FailFlush::default();
        let error = serve(&mut reader, &mut writer, &mut connector)
            .expect_err("a failed response flush must terminate transport");

        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(writer.flushes, 1);
        assert_eq!(reader.position(), first_boundary);
        let responses = replies(&writer.bytes);
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0]["id"], "first-invoke");
        assert!(responses[0].get("error").is_some());
        assert!(responses[0].get("result").is_none());
        let health = run_frames(&mut connector, &[rpc("health", "health", json!({}))]);
        assert_eq!(health[0]["result"]["details"]["requests"], 1);
        assert_eq!(health[0]["result"]["details"]["errors"], 1);
    }
}
