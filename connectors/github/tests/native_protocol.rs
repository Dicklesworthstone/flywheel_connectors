//! Exercise the shipped native GitHub executable through its actual JSONL boundary.

#![allow(clippy::too_many_lines)]

use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver},
    thread,
    time::{Duration, Instant},
};

use chrono::{Duration as ChronoDuration, Utc};
use fcp_core::{
    CapabilityConstraints, CapabilityToken, HealthSnapshot, InstanceId, InvokeResponse,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use serde_json::{Value, json};

const CREDENTIAL: &str = "550e8400-e29b-41d4-a716-446655440000";

struct NativeProcess {
    child: Child,
    input: Option<ChildStdin>,
    responses: Receiver<Value>,
}

impl NativeProcess {
    fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_fcp-github"))
            .env("RUST_LOG", "off")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("start shipped GitHub binary");
        let input = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (sender, responses) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                let response = serde_json::from_str(&line).expect("native response is JSON");
                if sender.send(response).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            input: Some(input),
            responses,
        }
    }

    fn write(&mut self, request: &Value) {
        let input = self.input.as_mut().expect("stdin remains open");
        serde_json::to_writer(&mut *input, request).unwrap();
        input.write_all(b"\n").unwrap();
        input.flush().unwrap();
    }

    fn receive(&self) -> Value {
        self.responses
            .recv_timeout(Duration::from_secs(5))
            .expect("native response within deadline")
    }

    fn rpc(&mut self, id: Value, method: &str, params: Value) -> Value {
        self.write(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        let response = self.receive();
        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], id, "outer request ID must survive");
        response
    }

    fn health(&mut self) -> HealthSnapshot {
        let response = self.rpc(json!("health"), "health", json!({}));
        serde_json::from_value(response["result"].clone()).expect("canonical health")
    }

    fn establish(&mut self, key: &Ed25519SigningKey, capabilities: &[&str]) -> InstanceId {
        let configured = self.rpc(
            json!("configure"),
            "configure",
            json!({"credential_id": CREDENTIAL}),
        );
        assert!(configured.get("error").is_none(), "{configured}");
        let pending = self.health();
        assert!(!pending.is_ready(), "configuration alone is not authority");

        let handshaken = self.rpc(
            json!("handshake"),
            "handshake",
            handshake(key, capabilities),
        );
        assert!(handshaken.get("error").is_none(), "{handshaken}");
        let health = self.health();
        assert!(health.is_ready());
        let details = health.details.unwrap();
        assert_eq!(details["connector_id"], "fcp.github");
        assert_eq!(details["configured"], true);
        assert_eq!(details["handshaken"], true);
        serde_json::from_value(details["instance_id"].clone()).unwrap()
    }

    fn wait_for_exit(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success(), "native binary exit: {status}");
                return;
            }
            assert!(Instant::now() < deadline, "native binary did not exit");
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for NativeProcess {
    fn drop(&mut self) {
        self.input.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn handshake(key: &Ed25519SigningKey, capabilities: &[&str]) -> Value {
    json!({
        "protocol_version": "2.0.0",
        "zone": "z:work",
        "host_public_key": key.verifying_key().to_bytes(),
        "nonce": vec![23u8; 32],
        "capabilities_requested": capabilities
    })
}

fn webhook_token(
    key: &Ed25519SigningKey,
    instance: &InstanceId,
    delivery: &str,
) -> CapabilityToken {
    let constraints = CapabilityConstraints {
        resource_allow: vec![format!(
            "github://octocat/hello-world/webhooks/deliveries/{delivery}"
        )],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).unwrap();
    let now = Utc::now();
    let raw = CapabilityTokenBuilder::new()
        .capability_id("github.process_webhook")
        .zone_id("z:work")
        .principal("user:native-test")
        .operations(&["github.process_webhook"])
        .issuer("node:native-test")
        .validity(now, now + ChronoDuration::hours(1))
        .target_instance(instance.as_str())
        .try_constraints_cbor(&cbor)
        .unwrap()
        .sign(key)
        .unwrap();
    CapabilityToken::from_raw(raw)
}

fn webhook_request(token: CapabilityToken, delivery: &str) -> Value {
    json!({
        "type": "invoke",
        "id": "inner-native-7",
        "connector_id": "fcp.github",
        "zone_id": "z:work",
        "operation": "github.process_webhook",
        "capability_token": token,
        "input": {
            "signature_validated": true,
            "payload": {
                "event_type": "issues",
                "delivery_id": delivery,
                "repository": {
                    "id": 1,
                    "full_name": "octocat/hello-world",
                    "html_url": "https://github.com/octocat/hello-world"
                },
                "data": {"action": "opened", "issue": {"number": 42}}
            }
        }
    })
}

#[test]
fn shipped_binary_validates_host_envelopes_and_preserves_local_effect_evidence() {
    let mut process = NativeProcess::start();
    let key = Ed25519SigningKey::generate();
    let instance = process.establish(&key, &["github.process_webhook"]);
    let token = webhook_token(&key, &instance, "native-envelope-1");
    let request = webhook_request(token, "native-envelope-1");

    // Each malformed envelope uses the same delivery. If dispatch runs early,
    // it consumes the replay receipt and the valid invocation below will fail.
    for (field, value) in [
        ("id", Value::Null),
        ("id", json!(7)),
        ("id", json!("")),
        ("type", json!("response")),
        ("connector_id", json!("fcp.other")),
        ("zone_id", json!("z:private")),
    ] {
        let mut invalid = request.clone();
        invalid[field] = value;
        let response = process.rpc(json!("malformed"), "invoke", invalid);
        assert!(response.get("error").is_some(), "{response}");
        assert!(response.get("result").is_none());
    }
    let mut missing = request.clone();
    missing.as_object_mut().unwrap().remove("zone_id");
    assert!(
        process
            .rpc(json!("missing"), "invoke", missing)
            .get("error")
            .is_some()
    );

    let mut simulation = request.clone();
    simulation["type"] = json!("simulate");
    for (field, value) in [("id", json!("")), ("type", json!("invoke"))] {
        let mut invalid = simulation.clone();
        invalid[field] = value;
        let response = process.rpc(json!("bad-preview"), "simulate", invalid);
        assert!(response.get("error").is_some(), "{response}");
        assert!(response.get("result").is_none());
    }
    let response = process.rpc(json!("preview"), "simulate", simulation);
    assert_eq!(response["result"]["would_succeed"], true);
    assert_eq!(response["result"]["id"], "inner-native-7");

    let response = process.rpc(json!(73), "invoke", request.clone());
    assert!(response.get("error").is_none(), "{response}");
    let result: InvokeResponse = serde_json::from_value(response["result"].clone()).unwrap();
    assert_eq!(result.id.0, "inner-native-7");
    assert_eq!(result.r#type, "response");
    let output = result.result.unwrap();
    assert_eq!(output["event"]["delivery_id"], "native-envelope-1");
    assert_eq!(
        output["event"]["resource_uri"],
        "github://octocat/hello-world/issues/42"
    );

    let duplicate = process.rpc(json!("duplicate"), "invoke", request);
    assert!(duplicate.get("result").is_none());
    assert!(
        duplicate["error"]["message"]
            .as_str()
            .unwrap()
            .contains("duplicate webhook delivery_id")
    );

    // A successful shutdown exits after flushing its acknowledgment, even
    // while the parent retains an open stdin handle.
    let stopped = process.rpc(
        json!("stop"),
        "shutdown",
        json!({"drain": true, "deadline_ms": 1000}),
    );
    assert_eq!(stopped["result"]["status"], "shutdown");
    process.wait_for_exit();
    assert!(
        process
            .responses
            .recv_timeout(Duration::from_millis(100))
            .is_err()
    );
}

#[test]
fn shipped_binary_denies_unnegotiated_and_replaced_sessions() {
    let mut process = NativeProcess::start();
    let key = Ed25519SigningKey::generate();
    let instance = process.establish(&key, &["github.read"]);
    let request = webhook_request(
        webhook_token(&key, &instance, "native-denied-1"),
        "native-denied-1",
    );
    assert!(
        process
            .rpc(json!("not-granted"), "invoke", request)
            .get("error")
            .is_some()
    );

    let response = process.rpc(
        json!("replace"),
        "handshake",
        handshake(&key, &["github.process_webhook"]),
    );
    assert!(response.get("error").is_none());
    let details = process.health().details.unwrap();
    let active: InstanceId = serde_json::from_value(details["instance_id"].clone()).unwrap();
    assert_ne!(active, instance);
    let request = webhook_request(
        webhook_token(&key, &active, "native-revoked-1"),
        "native-revoked-1",
    );
    let rejected = process.rpc(json!("bad-config"), "configure", json!({}));
    assert!(rejected.get("error").is_some());
    assert!(!process.health().is_ready());
    assert!(
        process
            .rpc(json!("stale"), "invoke", request.clone())
            .get("error")
            .is_some()
    );
    let current = process.establish(&key, &["github.process_webhook"]);
    assert_ne!(current, active);
    assert!(
        process
            .rpc(json!("still-stale"), "invoke", request)
            .get("error")
            .is_some()
    );
    let valid = webhook_request(
        webhook_token(&key, &current, "native-revoked-1"),
        "native-revoked-1",
    );
    assert!(
        process
            .rpc(json!("fresh"), "invoke", valid)
            .get("error")
            .is_none()
    );
    process.rpc(json!("stop"), "shutdown", json!({}));
    process.wait_for_exit();
}
