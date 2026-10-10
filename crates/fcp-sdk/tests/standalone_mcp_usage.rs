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
use fcp_core::{CapabilityConstraints, CapabilityToken};
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
        let binary = std::env::var_os("FCP_MCP_BRIDGE_BIN")
            .expect("build fcp-mcp-bridge and set FCP_MCP_BRIDGE_BIN before running this opt-in test");
        let mut child = Command::new(binary)
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null())
            .spawn().expect("start MCP connector binary");
        let input = BufWriter::new(child.stdin.take().expect("connector stdin"));
        let stdout = child.stdout.take().expect("connector stdout");
        let (sender, replies) = mpsc::sync_channel(1);
        let reader = std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let mut frame = Vec::new();
                let read = (&mut reader).take((MAX_RESPONSE + 1) as u64)
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
                if sender.send(reply).is_err() || failed { break; }
            }
        });
        Self { child, input, replies: Some(replies), reader: Some(reader), sequence: 0 }
    }

    fn call(&mut self, method: &str, params: Value) -> Value {
        self.sequence += 1;
        let frame = serde_json::to_vec(&json!({
            "jsonrpc": "2.0", "id": self.sequence, "method": method, "params": params,
        })).unwrap();
        // One small request is written before waiting for a response. A broken
        // child cannot accumulate arbitrarily many pending pipe writes.
        assert!(frame.len() < 16 * 1024);
        self.input.write_all(&frame).expect("write request");
        self.input.write_all(b"\n").expect("terminate request");
        self.input.flush().expect("flush request");
        let response = self.replies.as_ref().unwrap()
            .recv_timeout(Duration::from_secs(20)).expect("bounded connector response wait")
            .expect("valid connector response");
        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], self.sequence);
        response
    }

    fn result(&mut self, method: &str, params: Value) -> Value {
        self.call(method, params).get("result").expect("successful FCP response").clone()
    }

    fn handshake(&mut self, key: &Ed25519SigningKey) -> String {
        self.result("handshake", json!({
            "protocol_version": "2.0.0", "zone": "z:work",
            "host_public_key": key.verifying_key().to_bytes(), "nonce": vec![7_u8; 32],
            "capabilities_requested": ["mcp.server.metrics", "mcp.prompts.read"],
        }))["instance_id"].as_str().expect("actual instance ID").to_owned()
    }

    fn requests(&mut self) -> u64 {
        self.result("health", json!({}))["requests"].as_u64().unwrap()
    }
}

impl Drop for McpProcess {
    fn drop(&mut self) {
        // Disconnect a possibly blocked producer before joining it. Killing and
        // reaping this test-owned child closes stdout even when a test panics.
        drop(self.replies.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() { let _ = reader.join(); }
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
    let capability = if operation == "mcp.server.metrics" {
        "mcp.server.metrics"
    } else {
        "mcp.prompts.read"
    };
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()], max_calls: Some(calls),
        idempotency_key: scoped_key.map(str::to_owned), ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).unwrap();
    let now = Utc::now();
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability).zone_id("z:work").principal("user:test")
        .operations(&[operation]).issuer("node:test").target_instance(instance)
        .token_id(b"subprocess-usage-grant").validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor).unwrap().sign(key).unwrap();
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
        assert_eq!(process.result("simulate", simulation(&invoke))["would_succeed"], true);
    }
    assert_eq!(process.requests(), 0);
    let first = process.result("invoke", invoke.clone());
    assert_eq!(first["status"], "ok");
    assert_eq!(first["id"], "inner-first");
    assert_eq!(first["result"]["requests"], 1);
    invoke["id"] = json!("inner-second");
    invoke["input"] = json!({"max_calls": 999, "token_id": "caller-decoy"});
    assert_eq!(process.result("invoke", invoke.clone())["result"]["requests"], 2);
    assert_eq!(process.result("simulate", simulation(&invoke))["would_succeed"], false);
    assert_eq!(process.call("invoke", invoke)["error"]["code"], "FCP-3001");
    assert_eq!(process.requests(), 2);
    process.result("shutdown", json!({}));
}

#[test]
#[ignore = "requires a built binary in FCP_MCP_BRIDGE_BIN"]
fn key_scope_and_pre_admission_deadline_failures_do_not_spend() {
    let (mut process, key, instance) = established();
    let mut invoke = request(&key, &instance, "mcp.server.metrics", 1, Some(" exact-key "));
    invoke["deadline_ms"] = json!(0);
    assert!(process.call("invoke", invoke.clone()).get("error").is_some());
    invoke.as_object_mut().unwrap().remove("deadline_ms");
    for supplied in [Value::Null, json!("exact-key"), json!("wrong")] {
        invoke["idempotency_key"] = supplied;
        assert_eq!(process.call("invoke", invoke.clone())["error"]["code"], "FCP-3001");
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
    assert!(process.call("invoke", invoke.clone()).get("error").is_some());
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
