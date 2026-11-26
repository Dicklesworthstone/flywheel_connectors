#![forbid(unsafe_code)]

use std::io::{self, BufRead, Write};

use anyhow::Result;
use fcp_prelude::{FcpConnector, FcpError, FcpResult};
use fcp_sdk::prelude::{JsonlConfig, serve_jsonl};
use serde_json::{Value, json};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use fcp_cerebras::CerebrasConnector;

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
    let mut connector = CerebrasConnector::new();
    serve(stdin.lock(), stdout.lock(), &mut connector)?;
    Ok(())
}

fn serve(
    reader: impl BufRead,
    writer: impl Write,
    connector: &mut CerebrasConnector,
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
    connector: &mut CerebrasConnector,
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
    use std::io::{Cursor, Read};
    use std::net::TcpListener;
    use std::time::{Duration, Instant};

    use chrono::{Duration as ChronoDuration, Utc};
    use fcp_cerebras::connector::{test_handshake_request, test_invoke_request};
    use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
    use fcp_prelude::{CapabilityConstraints, CapabilityId, CapabilityToken};

    use super::*;

    fn roundtrip(connector: &mut CerebrasConnector, method: &str, params: Value) -> Value {
        let mut input = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": "outer-rpc",
            "method": method,
            "params": params,
        }))
        .unwrap();
        input.push(b'\n');
        let mut output = Vec::new();
        serve(Cursor::new(input), &mut output, connector).unwrap();
        serde_json::from_slice(&output).expect("one complete JSONL reply")
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn jsonl_keeps_canonical_response_evidence_and_shared_admission() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let mut connector = CerebrasConnector::new();
        let configured = roundtrip(
            &mut connector,
            "configure",
            json!({
                "api_key": "jsonl-test-key",
                "base_url": format!("http://{address}/v1"),
                "request_timeout_ms": 5_000,
            }),
        );
        assert_eq!(configured["result"]["configured"], true);
        let key = Ed25519SigningKey::generate();
        let handshake = roundtrip(
            &mut connector,
            "handshake",
            serde_json::to_value(test_handshake_request(
                vec![CapabilityId::from_static("cerebras.models.read")],
                key.verifying_key().to_bytes(),
            ))
            .unwrap(),
        );
        assert_eq!(
            handshake["result"]["instance_id"],
            json!(connector.instance_id())
        );
        let mut constraints = Vec::new();
        ciborium::into_writer(
            &CapabilityConstraints {
                resource_allow: vec!["cerebras:models".into()],
                max_calls: Some(1),
                ..Default::default()
            },
            &mut constraints,
        )
        .unwrap();
        let now = Utc::now();
        let token = CapabilityToken::from_raw(
            CapabilityTokenBuilder::new()
                .capability_id("cerebras.models.read")
                .zone_id("z:work")
                .principal("user:jsonl-test")
                .operations(&["cerebras.models.list"])
                .issuer("node:jsonl-test")
                .target_instance(connector.instance_id().as_str())
                .token_id(b"jsonl-one-call")
                .validity(now, now + ChronoDuration::hours(1))
                .try_constraints_cbor(&constraints)
                .unwrap()
                .sign(&key)
                .unwrap(),
        );
        let request = test_invoke_request("inner-invoke", "cerebras.models.list", json!({}), token);
        let params = serde_json::to_value(request).unwrap();
        for (field, value) in [
            ("connector_id", json!("fcp.other")),
            ("zone_id", json!("z:private")),
            ("deadline_ms", json!(0)),
        ] {
            let mut invalid = params.clone();
            invalid[field] = value;
            let denied = roundtrip(&mut connector, "invoke", invalid);
            assert!(denied["error"].is_object(), "accepted invalid {field}");
            assert!(
                matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock),
                "invalid envelope reached provider transport"
            );
        }
        let mut missing_id = params.clone();
        missing_id.as_object_mut().unwrap().remove("id");
        assert!(roundtrip(&mut connector, "invoke", missing_id)["error"].is_object());

        let provider = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "provider accept deadline");
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("provider accept failed: {error}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                let read = stream.read(&mut buffer).unwrap();
                assert!(read > 0);
                request.extend_from_slice(&buffer[..read]);
                assert!(request.len() < 64 * 1024);
            }
            assert!(request.starts_with(b"GET /v1/models HTTP/1.1\r\n"));
            let body = r#"{"object":"list","data":[]}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body,
            )
            .unwrap();
        });
        let reply = roundtrip(&mut connector, "invoke", params.clone());
        provider.join().unwrap();
        assert_eq!(reply["id"], "outer-rpc");
        assert_eq!(reply["result"]["type"], "response");
        assert_eq!(reply["result"]["id"], "inner-invoke");
        assert_eq!(reply["result"]["resource_uris"], json!(["cerebras:models"]));
        assert_eq!(reply["result"]["result"]["data"], json!([]));
        assert!(
            roundtrip(&mut connector, "invoke", params)["error"].is_object(),
            "JSONL replay bypassed the consumed call allowance"
        );
    }
}
