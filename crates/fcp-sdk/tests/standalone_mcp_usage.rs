//! Signed admission through the real MCP subprocess, not a replacement handler.
//!
//! Build `fcp-mcp-bridge` first, set FCP_MCP_BRIDGE_BIN to its absolute path, then
//! run `cargo test -p fcp-sdk --test standalone_mcp_usage -- --ignored` on the
//! same worker. These opt-in tests need no external service or credentials.
//! They live in the SDK suite to reuse its existing signing test dependencies.

use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::JoinHandle;
use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use fcp_core::{CapabilityConstraints, CapabilityToken, InvokeRequest, InvokeResponse, RequestId};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use serde_json::{Value, json};

const MAX_RESPONSE: usize = 1024 * 1024;

struct McpProcess {
    child: Child,
    input: BufWriter<ChildStdin>,
    replies: Option<Receiver<Result<Value, &'static str>>>,
    reader: Option<JoinHandle<()>>,
    sequence: u64,
}

impl McpProcess {
    fn start() -> Self {
        let binary = std::env::var_os("FCP_MCP_BRIDGE_BIN").expect(
            "build fcp-mcp-bridge and set FCP_MCP_BRIDGE_BIN before running this opt-in test",
        );
        let mut child = Command::new(binary)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("start MCP connector binary");
        let input = BufWriter::new(child.stdin.take().expect("connector stdin"));
        let stdout = child.stdout.take().expect("connector stdout");
        let (sender, replies) = mpsc::sync_channel(1);
        let reader = std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let mut frame = Vec::new();
                let read = (&mut reader)
                    .take((MAX_RESPONSE + 1) as u64)
                    .read_until(b'\n', &mut frame);
                let reply = match read {
                    Ok(0) => break,
                    Ok(_) if frame.len() <= MAX_RESPONSE && frame.last() == Some(&b'\n') => {
                        serde_json::from_slice(&frame).map_err(|_| "malformed connector response")
                    }
                    Ok(_) => Err("oversized or unterminated connector response"),
                    Err(_) => Err("connector response read failed"),
                };
                let failed = reply.is_err();
                if sender.send(reply).is_err() || failed {
                    break;
                }
            }
        });
        Self {
            child,
            input,
            replies: Some(replies),
            reader: Some(reader),
            sequence: 0,
        }
    }

    fn call(&mut self, method: &str, params: Value) -> Value {
        self.sequence += 1;
        let frame = serde_json::to_vec(&json!({
            "jsonrpc": "2.0", "id": self.sequence, "method": method, "params": params,
        }))
        .unwrap();
        // One small request is written before waiting for a response. A broken
        // child cannot accumulate arbitrarily many pending pipe writes.
        assert!(frame.len() < 16 * 1024);
        self.input.write_all(&frame).expect("write request");
        self.input.write_all(b"\n").expect("terminate request");
        self.input.flush().expect("flush request");
        let response = self
            .replies
            .as_ref()
            .unwrap()
            .recv_timeout(Duration::from_secs(20))
            .expect("bounded connector response wait")
            .expect("valid connector response");
        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], self.sequence);
        response
    }

    fn result(&mut self, method: &str, params: Value) -> Value {
        self.call(method, params)
            .get("result")
            .expect("successful FCP response")
            .clone()
    }

    fn handshake(&mut self, key: &Ed25519SigningKey) -> String {
        self.result(
            "handshake",
            json!({
                "protocol_version": "2.0.0", "zone": "z:work",
                "host_public_key": key.verifying_key().to_bytes(), "nonce": vec![7_u8; 32],
                "capabilities_requested": ["mcp.server.metrics", "mcp.prompts.read"],
            }),
        )["instance_id"]
            .as_str()
            .expect("actual instance ID")
            .to_owned()
    }

    fn requests(&mut self) -> u64 {
        self.result("health", json!({}))["requests"]
            .as_u64()
            .unwrap()
    }
}

impl Drop for McpProcess {
    fn drop(&mut self) {
        // Disconnect a possibly blocked producer before joining it. Killing and
        // reaping this test-owned child closes stdout even when a test panics.
        drop(self.replies.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

fn established() -> (McpProcess, Ed25519SigningKey, String) {
    let mut process = McpProcess::start();
    process.result("configure", json!({"mcp_url": "http://127.0.0.1:1"}));
    let key = Ed25519SigningKey::generate();
    let instance = process.handshake(&key);
    (process, key, instance)
}

fn request(
    key: &Ed25519SigningKey,
    instance: &str,
    operation: &str,
    calls: u32,
    scoped_key: Option<&str>,
) -> Value {
    request_with_bytes(key, instance, operation, Some(calls), scoped_key, None)
}

fn request_with_bytes(
    key: &Ed25519SigningKey,
    instance: &str,
    operation: &str,
    calls: Option<u32>,
    scoped_key: Option<&str>,
    bytes: Option<u64>,
) -> Value {
    let capability = if operation == "mcp.server.metrics" {
        "mcp.server.metrics"
    } else {
        "mcp.prompts.read"
    };
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        max_calls: calls,
        max_bytes: bytes,
        idempotency_key: scoped_key.map(str::to_owned),
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).unwrap();
    let now = Utc::now();
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[operation])
        .issuer("node:test")
        .target_instance(instance)
        .token_id(b"subprocess-usage-grant")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .unwrap()
        .sign(key)
        .unwrap();
    json!({
        "type": "invoke", "id": "inner-first", "connector_id": "fcp.mcp-bridge",
        "operation": operation, "zone_id": "z:work", "input": {},
        "capability_token": CapabilityToken::from_raw(raw),
        "idempotency_key": scoped_key,
    })
}

fn simulation(invoke: &Value) -> Value {
    json!({
        "type": "simulate", "id": "preview", "connector_id": invoke["connector_id"],
        "operation": invoke["operation"], "zone_id": invoke["zone_id"],
        "input": invoke["input"], "capability_token": invoke["capability_token"],
        "estimate_cost": false, "check_availability": false,
    })
}

#[test]
#[ignore = "requires a built binary in FCP_MCP_BRIDGE_BIN"]
fn signed_limits_and_non_consuming_simulation_cross_the_real_stdio_boundary() {
    let (mut process, key, instance) = established();
    let mut invoke = request(&key, &instance, "mcp.server.metrics", 2, None);
    for _ in 0..3 {
        assert_eq!(
            process.result("simulate", simulation(&invoke))["would_succeed"],
            true
        );
    }
    assert_eq!(process.requests(), 0);
    let first = process.result("invoke", invoke.clone());
    assert_eq!(first["status"], "ok");
    assert_eq!(first["id"], "inner-first");
    assert_eq!(first["result"]["requests"], 1);
    invoke["id"] = json!("inner-second");
    invoke["input"] = json!({"max_calls": 999, "token_id": "caller-decoy"});
    assert_eq!(
        process.result("invoke", invoke.clone())["result"]["requests"],
        2
    );
    assert_eq!(
        process.result("simulate", simulation(&invoke))["would_succeed"],
        false
    );
    assert_eq!(process.call("invoke", invoke)["error"]["code"], "FCP-3001");
    assert_eq!(process.requests(), 2);
    process.result("shutdown", json!({}));
}

#[test]
#[ignore = "requires a built binary in FCP_MCP_BRIDGE_BIN"]
fn key_scope_and_pre_admission_deadline_failures_do_not_spend() {
    let (mut process, key, instance) = established();
    let mut invoke = request(
        &key,
        &instance,
        "mcp.server.metrics",
        1,
        Some(" exact-key "),
    );
    invoke["deadline_ms"] = json!(0);
    assert!(
        process
            .call("invoke", invoke.clone())
            .get("error")
            .is_some()
    );
    invoke.as_object_mut().unwrap().remove("deadline_ms");
    for supplied in [Value::Null, json!("exact-key"), json!("wrong")] {
        invoke["idempotency_key"] = supplied;
        assert_eq!(
            process.call("invoke", invoke.clone())["error"]["code"],
            "FCP-3001"
        );
    }
    assert_eq!(process.requests(), 0);
    invoke["idempotency_key"] = json!(" exact-key ");
    assert_eq!(process.result("invoke", invoke.clone())["status"], "ok");
    assert_eq!(process.call("invoke", invoke)["error"]["code"], "FCP-3001");
    assert_eq!(process.requests(), 1);
}

#[test]
#[ignore = "requires a built binary in FCP_MCP_BRIDGE_BIN"]
fn rejected_targets_zones_and_signatures_leave_the_real_provider_untouched() {
    let (mut process, key, instance) = established();
    let invoke = request(&key, &instance, "mcp.server.metrics", 1, None);
    let mut wrong = invoke.clone();
    wrong["connector_id"] = json!("fcp.other");
    assert!(process.call("invoke", wrong).get("error").is_some());
    let mut wrong = invoke.clone();
    wrong["zone_id"] = json!("z:private");
    assert!(process.call("invoke", wrong).get("error").is_some());
    let mut forged = invoke.clone();
    let bytes = forged["capability_token"].as_array_mut().unwrap();
    let last = bytes.last_mut().unwrap();
    *last = json!(last.as_u64().unwrap() ^ 1);
    assert!(process.call("invoke", forged).get("error").is_some());
    assert_eq!(process.requests(), 0);
    assert_eq!(process.result("invoke", invoke)["status"], "ok");
    assert_eq!(process.requests(), 1);
}

#[test]
#[ignore = "requires a built binary in FCP_MCP_BRIDGE_BIN"]
fn admitted_provider_errors_do_not_refund_the_signed_allowance() {
    let (mut process, key, instance) = established();
    let mut invoke = request(&key, &instance, "mcp.prompts.get", 1, None);
    // The real provider validates this before any MCP network request. It is
    // still an admitted FCP invocation and must not earn a usage refund.
    invoke["input"] = json!({"name": "", "arguments": {}});
    let failure = process.result("invoke", invoke.clone());
    assert_eq!(failure["status"], "error");
    assert_eq!(failure["id"], invoke["id"]);
    assert!(failure.get("error").is_some());
    assert!(failure.get("result").is_none());
    assert_eq!(process.requests(), 1);
    assert_eq!(process.call("invoke", invoke)["error"]["code"], "FCP-3001");
    assert_eq!(process.requests(), 1);
}

#[test]
#[ignore = "requires a built binary in FCP_MCP_BRIDGE_BIN"]
fn resetting_process_authority_cannot_revive_a_spent_old_token() {
    let (mut process, key, instance) = established();
    let old = request(&key, &instance, "mcp.server.metrics", 1, None);
    process.result("invoke", old.clone());
    let next = process.handshake(&key);
    assert_ne!(next, instance);
    assert!(process.call("invoke", old).get("error").is_some());
    let fresh = request(&key, &next, "mcp.server.metrics", 1, None);
    assert_eq!(process.result("invoke", fresh)["status"], "ok");
    assert_eq!(process.requests(), 2);
}

/// Match production metering of the complete typed request, including omitted
/// optional fields, rather than the caller's original JSON object or estimates.
fn invoke_bytes(value: &Value) -> u64 {
    let request: InvokeRequest = serde_json::from_value(value.clone()).unwrap();
    u64::try_from(serde_json::to_vec(&request).unwrap().len()).unwrap()
}

#[test]
#[ignore = "requires a built binary in FCP_MCP_BRIDGE_BIN"]
fn signed_byte_only_budget_settles_success_and_exhausts_across_real_invocations() {
    const BYTES: u64 = 16 * 1024;
    let (mut process, key, instance) = established();
    let invoke = request_with_bytes(
        &key,
        &instance,
        "mcp.server.metrics",
        None,
        None,
        Some(BYTES),
    );
    for _ in 0..3 {
        assert_eq!(
            process.result("simulate", simulation(&invoke))["would_succeed"],
            true
        );
    }
    assert_eq!(process.requests(), 0);
    let request_bytes = invoke_bytes(&invoke);
    let mut succeeded = 0_u64;
    let mut charged = 0_u64;
    let mut exhausted = false;
    // This is a finite byte-only grant: call-count enforcement cannot make the
    // test pass. Bound the loop so an ignored byte ceiling fails deterministically.
    for _ in 0..64 {
        let reply = process.call("invoke", invoke.clone());
        if reply.get("error").is_some() {
            // The last response may be too large for the final reservation, or
            // admission may lack room for a complete request/response envelope.
            exhausted = true;
            break;
        }
        let response: InvokeResponse = serde_json::from_value(reply["result"].clone()).unwrap();
        assert_eq!(reply["result"]["status"], "ok");
        let response_bytes = u64::try_from(serde_json::to_vec(&response).unwrap().len()).unwrap();
        charged += request_bytes + response_bytes;
        assert!(
            charged <= BYTES,
            "released FCP messages exceeded the signed byte grant"
        );
        succeeded += 1;
    }
    assert!(exhausted, "the finite byte grant never exhausted");
    assert!(
        succeeded >= 2,
        "successful settlement did not release unused response reservations"
    );
    let dispatched = process.requests();
    assert!((succeeded..=succeeded + 1).contains(&dispatched));
    assert_eq!(process.call("invoke", invoke)["error"]["code"], "FCP-3001");
    assert_eq!(process.requests(), dispatched);
}

#[test]
#[ignore = "requires a built binary in FCP_MCP_BRIDGE_BIN"]
fn oversized_actual_request_cannot_spend_a_call_or_use_fake_byte_counters() {
    const BYTES: u64 = 8 * 1024;
    let (mut process, key, instance) = established();
    let invoke = request_with_bytes(
        &key,
        &instance,
        "mcp.server.metrics",
        Some(1),
        None,
        Some(BYTES),
    );
    let mut too_large = invoke.clone();
    too_large["input"] = json!({
        "payload": "x".repeat(8 * 1024), "request_bytes": 0, "observed_bytes": 0,
    });
    assert!(invoke_bytes(&too_large) > BYTES);
    assert_eq!(
        process.call("invoke", too_large)["error"]["code"],
        "FCP-3001"
    );
    assert_eq!(process.requests(), 0);
    assert_eq!(process.result("invoke", invoke.clone())["status"], "ok");
    assert_eq!(process.requests(), 1);
    assert_eq!(process.call("invoke", invoke)["error"]["code"], "FCP-3001");
}

#[test]
#[ignore = "requires a built binary in FCP_MCP_BRIDGE_BIN"]
fn provider_failure_returns_canonical_error_and_retains_its_byte_reservation() {
    let (mut process, key, instance) = established();
    let mut invoke = request_with_bytes(
        &key,
        &instance,
        "mcp.prompts.get",
        None,
        None,
        Some(8 * 1024),
    );
    // Invalid provider parameters fail locally after admission, with no network.
    invoke["input"] = json!({"name": "", "arguments": {}});
    let response = process.result("invoke", invoke.clone());
    assert_eq!(response["type"], "response");
    assert_eq!(response["id"], invoke["id"]);
    assert_eq!(response["status"], "error");
    assert!(response.get("error").is_some());
    assert!(response.get("result").is_none());
    assert_eq!(process.requests(), 1);
    // No max_calls exists in this token. Denial proves the error did not give
    // back its pessimistic response reservation, not merely that calls ran out.
    assert_eq!(
        process.result("simulate", simulation(&invoke))["would_succeed"],
        false
    );
    assert_eq!(process.call("invoke", invoke)["error"]["code"], "FCP-3001");
    assert_eq!(process.requests(), 1);
}

#[test]
#[ignore = "requires a built binary in FCP_MCP_BRIDGE_BIN"]
fn oversized_provider_result_is_withheld_at_the_actual_stdio_response_boundary() {
    const BYTES: u64 = 8 * 1024;
    let (mut process, key, instance) = established();
    let mut invoke = request_with_bytes(
        &key,
        &instance,
        "mcp.server.metrics",
        None,
        None,
        Some(BYTES),
    );
    invoke["input"] = json!({"padding": ""});
    let minimum_response = InvokeResponse::ok(RequestId::new("inner-first"), json!(0));
    let minimum_bytes =
        u64::try_from(serde_json::to_vec(&minimum_response).unwrap().len()).unwrap();
    let padding = BYTES
        .checked_sub(invoke_bytes(&invoke) + minimum_bytes)
        .unwrap();
    invoke["input"]["padding"] = json!("x".repeat(usize::try_from(padding).unwrap()));
    // The request leaves exactly enough bytes for the smallest legal response.
    // Metrics returns an object, not the digit 0, so the real provider executes
    // but its larger result must never be emitted or advertised as replay-safe.
    assert_eq!(invoke_bytes(&invoke) + minimum_bytes, BYTES);
    let reply = process.call("invoke", invoke.clone());
    assert!(reply.get("result").is_none());
    assert!(
        reply["error"]["message"]
            .as_str()
            .unwrap()
            .contains("outcome is unknown")
    );
    assert!(!reply.to_string().contains("injection_scans"));
    assert_eq!(process.requests(), 1);
    assert_eq!(process.call("invoke", invoke)["error"]["code"], "FCP-3001");
    assert_eq!(process.requests(), 1);
}
