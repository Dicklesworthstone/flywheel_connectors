//! Criterion benchmark for the tailnet invoke latency budget.
//!
//! This is intentionally a **stub benchmark**, not a proof of a live
//! Tailscale/DERP transport path. `fcp-host` currently exposes a real
//! host-backed `/rpc/invoke` path, but there is no production invoke route
//! that traverses `fcp-tailscale` / `fcp-mesh` end-to-end. To keep the README
//! latency target executable without falsely presenting localhost as a tailnet
//! measurement, this harness composes:
//!
//! 1. the real host-backed local invoke hot path, and
//! 2. injected transport RTT for two profiles:
//!    - direct LAN budget
//!    - DERP relay budget
//!
//! Replace this harness with a real tailnet transport benchmark once invoke is
//! actually routed across the `fcp-tailscale` / mesh transport path.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use chrono::Utc;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use fcp_core::{
    CapabilityToken, ConnectorId, DecisionReceiptPolicy, InvokeRequest, ObjectHeader, OperationId,
    Provenance, RequestId, ZoneId, ZonePolicyObject, ZoneTransportPolicy,
};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use serde_json::json;

const CONNECTOR_ID: &str = "fcp.bench.tailnet-invoke:utility:1.0.0";
const TEST_OPERATION: &str = "test.echo";
const TEST_CAPABILITY_ID: &str = "cap.test.echo";
const TEST_PRINCIPAL: &str = "user:bench";
const READINESS_TIMEOUT: Duration = Duration::from_secs(15);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Copy)]
struct TransportProfile {
    name: &'static str,
    simulated_rtt: Duration,
}

const DIRECT_LAN_PROFILE: TransportProfile = TransportProfile {
    name: "direct_lan_stub",
    simulated_rtt: Duration::from_millis(20),
};

const DERP_PROFILE: TransportProfile = TransportProfile {
    name: "derp_stub",
    simulated_rtt: Duration::from_millis(150),
};

fn cargo_bin(env_name: &str, binary_name: &str) -> PathBuf {
    if let Some(path) = std::env::var_os(env_name) {
        return PathBuf::from(path);
    }
    let current_exe = std::env::current_exe().expect("current benchmark executable path");
    let deps_dir = current_exe
        .parent()
        .expect("benchmark executable should have parent directory");
    let profile_dir = deps_dir
        .parent()
        .expect("benchmark executable should live under target/<profile>/deps");
    let candidate = profile_dir.join(format!("{binary_name}{}", std::env::consts::EXE_SUFFIX));
    assert!(
        candidate.exists(),
        "expected compiled {binary_name} at {}",
        candidate.display()
    );
    candidate
}

fn free_loopback_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral loopback port");
    listener
        .local_addr()
        .expect("read loopback listener address")
}

fn connector_inventory(connector_binary: &str) -> String {
    serde_json::to_string(&vec![json!({
        "id": CONNECTOR_ID,
        "binary": connector_binary,
        "name": "Tailnet Invoke Benchmark Connector",
        "description": "Host-backed tailnet invoke stub benchmark fixture",
        "env": {
            "FCP_TEST_CONNECTOR_ID": CONNECTOR_ID,
            "FCP_TEST_CONNECTOR_ARCHETYPE": "request_response"
        },
        "config": {}
    })])
    .expect("serialize connector inventory")
}

fn capability_public_key_hex(signing_key: &Ed25519SigningKey) -> String {
    hex::encode(signing_key.verifying_key().to_bytes())
}

fn constraints_cbor_bytes() -> Vec<u8> {
    let constraints = fcp_core::CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    cbor
}

fn build_capability_token(signing_key: &Ed25519SigningKey, zone_id: &ZoneId) -> CapabilityToken {
    let now = Utc::now();
    let cbor = constraints_cbor_bytes();
    let raw = CapabilityTokenBuilder::new()
        .capability_id(TEST_CAPABILITY_ID)
        .zone_id(zone_id.as_str())
        .principal(TEST_PRINCIPAL)
        .operations(&[TEST_OPERATION])
        .issuer("node:bench")
        .audience("*")
        .validity(now, now + chrono::Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("bench constraints CBOR should be valid")
        .sign(signing_key)
        .expect("bench capability token should sign");
    CapabilityToken::from_raw(raw)
}

fn permissive_zone_policy(zone_id: ZoneId) -> ZonePolicyObject {
    ZonePolicyObject {
        header: ObjectHeader {
            encryption_kind: Default::default(),
            schema: fcp_cbor::SchemaId::new(
                "fcp.core",
                "ZonePolicyObject",
                semver::Version::new(1, 0, 0),
            ),
            zone_id: zone_id.clone(),
            created_at: u64::try_from(Utc::now().timestamp()).unwrap_or(0),
            provenance: Provenance::new(zone_id.clone()),
            refs: Vec::new(),
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        },
        zone_id,
        principal_allow: Vec::new(),
        principal_deny: Vec::new(),
        connector_allow: Vec::new(),
        connector_deny: Vec::new(),
        capability_allow: Vec::new(),
        capability_deny: Vec::new(),
        capability_ceiling: Vec::new(),
        transport_policy: ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: true,
        },
        decision_receipts: DecisionReceiptPolicy::default(),
        usage_budget: None,
        requires_posture: None,
    }
}

fn write_zone_policies_file(dir: &Path, zone_id: ZoneId) -> PathBuf {
    let policy = permissive_zone_policy(zone_id);
    let mut policies = HashMap::new();
    policies.insert(policy.zone_id.as_str().to_string(), policy);
    let path = dir.join("zone-policies.json");
    let bytes = serde_json::to_vec_pretty(&policies).expect("serialize bench zone policies");
    std::fs::write(&path, bytes).expect("write bench zone policies");
    path
}

fn spawn_host(
    addr: SocketAddr,
    connector_binary: &str,
    state_file: &Path,
    zone_policies_file: &Path,
    capability_public_key: &str,
) -> Child {
    let host_binary = cargo_bin("CARGO_BIN_EXE_fcp-host", "fcp-host");
    Command::new(host_binary)
        .env("FCP_HOST_BIND", addr.to_string())
        .env("FCP_HOST_CONNECTORS", connector_inventory(connector_binary))
        .env("FCP_HOST_LIFECYCLE_STATE_FILE", state_file)
        .env("FCP_HOST_ZONE_POLICIES_FILE", zone_policies_file)
        .env("FCP_HOST_CAPABILITY_PUBLIC_KEY", capability_public_key)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn fcp-host")
}

fn request_health(addr: SocketAddr) -> std::io::Result<String> {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(250))?;
    stream.set_read_timeout(Some(Duration::from_millis(500)))?;
    stream.set_write_timeout(Some(Duration::from_millis(500)))?;
    write!(
        stream,
        "GET /rpc/health HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let _ = stream.shutdown(Shutdown::Both);
    Ok(response)
}

fn wait_for_connector_ready(child: &mut Child, addr: SocketAddr) {
    let deadline = Instant::now() + READINESS_TIMEOUT;
    let mut last_response = String::new();
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("poll fcp-host child") {
            panic!("fcp-host exited before readiness: {status}");
        }
        if let Ok(response) = request_health(addr) {
            let ready = response.starts_with("HTTP/1.1 200")
                && response.contains(CONNECTOR_ID)
                && response.contains("\"healthy\"");
            if ready {
                return;
            }
            last_response = response;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!(
        "timed out after {READINESS_TIMEOUT:?} waiting for activated connector in /rpc/health; last response: {last_response:?}"
    );
}

fn build_invoke_payload(
    connector_id: &ConnectorId,
    capability_token: &CapabilityToken,
    zone_id: &ZoneId,
) -> Vec<u8> {
    let request = InvokeRequest {
        r#type: "invoke".to_string(),
        id: RequestId::random(),
        connector_id: connector_id.clone(),
        operation: OperationId::from_static(TEST_OPERATION),
        zone_id: zone_id.clone(),
        input: json!({ "message": "hello" }),
        capability_token: capability_token.clone(),
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: None,
        correlation_id: None,
        provenance: None,
        approval_tokens: Vec::new(),
    };
    serde_json::to_vec(&request).expect("serialize invoke request")
}

fn invoke_once(addr: SocketAddr, body: &[u8]) -> std::io::Result<String> {
    let mut stream = TcpStream::connect_timeout(&addr, REQUEST_TIMEOUT)?;
    stream.set_read_timeout(Some(REQUEST_TIMEOUT))?;
    stream.set_write_timeout(Some(REQUEST_TIMEOUT))?;
    let header = format!(
        "POST /rpc/invoke HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let _ = stream.shutdown(Shutdown::Both);
    Ok(response)
}

fn invoke_once_with_simulated_rtt(
    addr: SocketAddr,
    body: &[u8],
    profile: TransportProfile,
) -> std::io::Result<String> {
    let outbound = profile.simulated_rtt / 2;
    let inbound = profile
        .simulated_rtt
        .checked_sub(outbound)
        .unwrap_or(Duration::ZERO);
    std::thread::sleep(outbound);
    let response = invoke_once(addr, body)?;
    std::thread::sleep(inbound);
    Ok(response)
}

struct BenchHarness {
    child: Child,
    addr: SocketAddr,
    connector_id: ConnectorId,
    capability_token: CapabilityToken,
    zone_id: ZoneId,
    _state_dir: tempfile::TempDir,
}

impl BenchHarness {
    fn start() -> Self {
        let connector_binary = cargo_bin("CARGO_BIN_EXE_fcp-test-connector", "fcp-test-connector");
        let connector_binary = connector_binary
            .to_str()
            .expect("connector binary path should be UTF-8")
            .to_owned();

        let signing_key = Ed25519SigningKey::generate();
        let capability_public_key = capability_public_key_hex(&signing_key);
        let zone_id = ZoneId::work();
        let connector_id = ConnectorId::from_static(CONNECTOR_ID);
        let capability_token = build_capability_token(&signing_key, &zone_id);

        let addr = free_loopback_addr();
        let state_dir = tempfile::tempdir().expect("create host state tempdir");
        let state_file = state_dir.path().join("lifecycle-state.json");
        let zone_policies_file = write_zone_policies_file(state_dir.path(), zone_id.clone());
        let mut child = spawn_host(
            addr,
            &connector_binary,
            &state_file,
            &zone_policies_file,
            &capability_public_key,
        );
        wait_for_connector_ready(&mut child, addr);

        Self {
            child,
            addr,
            connector_id,
            capability_token,
            zone_id,
            _state_dir: state_dir,
        }
    }

    fn build_payload(&self) -> Vec<u8> {
        build_invoke_payload(&self.connector_id, &self.capability_token, &self.zone_id)
    }

    fn assert_invoke_ok(&self) {
        let payload = self.build_payload();
        let response = invoke_once(self.addr, &payload).expect("invoke roundtrip");
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "expected 200 OK from /rpc/invoke; got: {response}"
        );
    }
}

impl Drop for BenchHarness {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn tailnet_invoke(c: &mut Criterion) {
    let harness = BenchHarness::start();
    harness.assert_invoke_ok();

    let mut group = c.benchmark_group("host_backed_tailnet_invoke_stub");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(8));

    for profile in [DIRECT_LAN_PROFILE, DERP_PROFILE] {
        group.bench_with_input(
            BenchmarkId::new("invoke_roundtrip", profile.name),
            &profile,
            |bench, profile| {
                bench.iter_custom(|iterations| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iterations {
                        let payload = harness.build_payload();
                        let started = Instant::now();
                        let response =
                            invoke_once_with_simulated_rtt(harness.addr, &payload, *profile)
                                .expect("invoke roundtrip with simulated RTT");
                        total += started.elapsed();
                        assert!(
                            response.starts_with("HTTP/1.1 200"),
                            "invoke must return 200 OK; got: {response}"
                        );
                    }
                    total
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, tailnet_invoke);
criterion_main!(benches);
