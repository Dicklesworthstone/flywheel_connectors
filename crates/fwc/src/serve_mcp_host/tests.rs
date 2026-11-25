//! Exercise the real MCP host boundary against a bounded local HTTP peer.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};

use serde_json::{Value, json};

use super::*;

const TEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
struct CapturedRequest {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Value,
}

enum Reply {
    Close,
    Body(u16, Vec<u8>),
}

impl Reply {
    fn json(status: u16, value: Value) -> Self {
        Self::Body(status, serde_json::to_vec(&value).unwrap())
    }
}

/// Own the listener thread through success and assertion unwinding. Socket and
/// accept deadlines keep a broken test from leaving a detached HTTP fixture.
struct HostPeer {
    endpoint: String,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<Vec<CapturedRequest>>>,
    expected: usize,
}

impl HostPeer {
    fn start(
        expected: usize,
        mut respond: impl FnMut(usize, &CapturedRequest) -> Reply + Send + 'static,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            let deadline = Instant::now() + TEST_TIMEOUT;
            let mut requests = Vec::new();
            while requests.len() < expected
                && !stopping.load(Ordering::SeqCst)
                && Instant::now() < deadline
            {
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("local host accept failed: {error}"),
                };
                stream.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
                stream.set_write_timeout(Some(TEST_TIMEOUT)).unwrap();
                let request = read_request(&stream);
                let reply = respond(requests.len(), &request);
                requests.push(request);
                if let Reply::Body(status, body) = reply {
                    let headers = format!(
                        "HTTP/1.1 {status} Test\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    );
                    // Rejection of an oversized response may close the peer
                    // before its body is sent; that is expected test behavior.
                    if stream.write_all(headers.as_bytes()).is_ok() {
                        let _ = stream.write_all(&body);
                    }
                }
            }
            requests
        });
        Self {
            endpoint,
            stop,
            thread: Some(handle),
            expected,
        }
    }

    fn client(&self) -> HostAdminClient {
        HostAdminClient::new(&self.endpoint).unwrap()
    }

    fn finish(mut self) -> Vec<CapturedRequest> {
        let requests = self.thread.take().unwrap().join().unwrap();
        assert_eq!(requests.len(), self.expected);
        requests
    }
}

impl Drop for HostPeer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

fn read_request(stream: &TcpStream) -> CapturedRequest {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap().to_owned();
    let path = parts.next().unwrap().to_owned();
    let mut headers = BTreeMap::new();
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).unwrap();
        if header == "\r\n" || header.is_empty() {
            break;
        }
        let (name, value) = header.split_once(':').unwrap();
        headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
    }
    let length = headers
        .get("content-length")
        .map_or(0, |length| length.parse::<usize>().unwrap());
    assert!(length <= 128 * 1024);
    let mut body = vec![0; length];
    reader.read_exact(&mut body).unwrap();
    CapturedRequest {
        method,
        path,
        headers,
        body: serde_json::from_slice(&body).unwrap(),
    }
}

fn token(owner: &str, zone: &str, capability: &str, holder: Option<&str>) -> CapabilityToken {
    let mut claims = CapabilityToken::test_token()
        .raw()
        .claims_unverified()
        .unwrap()
        .subject(owner)
        .principal_id(owner)
        .zone_id(zone)
        .capability_id(capability);
    if let Some(holder) = holder {
        claims = claims.holder_node(holder);
    }
    let key = fcp_crypto::Ed25519SigningKey::from_bytes(&[0x37; 32]).unwrap();
    CapabilityToken::from_raw(fcp_crypto::cose::CoseToken::sign(&key, &claims).unwrap())
}

fn cancellation_args(token: &CapabilityToken) -> CancellationArgs {
    CancellationArgs {
        cancel_capability_token: Some(serde_json::to_string(token).unwrap()),
        cancel_capability_token_file: None,
    }
}

fn invoke_request(id: &str, token: CapabilityToken) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".to_owned(),
        id: fcp_core::RequestId::new(id),
        connector_id: "fcp.test:utility:1.0.0".parse().unwrap(),
        operation: "test.echo".parse().unwrap(),
        zone_id: "z:work".parse().unwrap(),
        input: json!({"message": "same input"}),
        capability_token: token,
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: Some(1_000),
        correlation_id: None,
        provenance: None,
        approval_tokens: Vec::new(),
    }
}

fn cancellation_request(id: &str, token: CapabilityToken) -> HostCancellationRequest {
    HostCancellationRequest {
        operation_id: id.to_owned(),
        reason: CancelReason::UserRequested,
        cleanup: CleanupBehavior::BestEffort,
        return_partial: false,
        capability_token: Some(token),
    }
}

fn cancellation_response(id: &str, outcome: &str) -> Value {
    json!({
        "operation_id": id,
        "outcome": outcome,
        "duration_ms": 0,
    })
}

fn credential_catalog() -> HostConnectorCatalog {
    let connectors = ["fcp.github:enterprise:v1", "fcp.slack:enterprise:v1"].map(|id| {
        json!({
            "id": id, "name": id, "description": "MCP credential fixture",
            "version": "1.0.0", "categories": [], "tool_count": 1,
            "max_safety_tier": "safe", "enabled": true,
            "health": fcp_core::ConnectorHealth::healthy(),
            "last_health_check": "2026-03-10T00:00:00Z",
        })
    });
    let discovery: crate::HostDiscoveryResponse = serde_json::from_value(json!({
        "connectors": connectors, "registry_version": 1,
        "supports_streaming": false, "supports_batching": false,
        "timestamp": "2026-03-10T00:00:00Z",
    }))
    .unwrap();
    HostConnectorCatalog::from_response(&discovery)
}

fn inline_auth(grant: &CapabilityToken) -> LiveAuthArgs {
    LiveAuthArgs {
        capability_token: Some(serde_json::to_string(grant).unwrap()),
        ..LiveAuthArgs::default()
    }
}

fn connector_binding(selector: &str, grant: &CapabilityToken) -> String {
    format!("{selector}={}", serde_json::to_string(grant).unwrap())
}

#[test]
fn independent_instance_credentials_reach_their_own_host_invocations() {
    let catalog = credential_catalog();
    let key = fcp_crypto::Ed25519SigningKey::from_bytes(&[0x37; 32]).unwrap();
    let instances = [fcp_core::InstanceId::new(), fcp_core::InstanceId::new()];
    let constraints = fcp_core::CapabilityConstraints {
        resource_allow: vec!["*".to_owned()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).unwrap();
    let now = chrono::Utc::now();
    let grants = instances.each_ref().map(|instance| {
        CapabilityToken::from_raw(
            fcp_crypto::cose::CapabilityTokenBuilder::new()
                .capability_id("test.echo")
                .zone_id("z:work")
                .principal("alice")
                .operations(&["test.echo"])
                .issuer("node:mcp-test")
                .target_instance(instance.as_str())
                .validity(now, now + chrono::Duration::hours(1))
                .try_constraints_cbor(&cbor)
                .unwrap()
                .sign(&key)
                .unwrap(),
        )
    });
    let public_key = key.verifying_key().to_bytes();
    let verifiers = instances.map(|instance| {
        fcp_core::CapabilityVerifier::new(public_key, fcp_core::ZoneId::work(), instance)
    });
    let capability: fcp_core::CapabilityId = "test.echo".parse().unwrap();
    let operation: fcp_core::OperationId = "test.echo".parse().unwrap();
    assert!(
        verifiers[1]
            .verify_bound(grants[0].clone(), &capability, &operation, &[])
            .is_err(),
        "one token cannot authorize both runtime instances"
    );
    let args = ConnectorAuthArgs {
        connector_capability_token: vec![
            connector_binding("github", &grants[0]),
            connector_binding("slack", &grants[1]),
        ],
        ..Default::default()
    };
    let registry = McpAuthorityRegistry::resolve(
        &LiveAuthArgs::default(),
        &args,
        &catalog,
        &catalog.connectors,
        "z:work",
        Some("alice"),
    )
    .unwrap();
    let peer = HostPeer::start(2, move |index, recorded| {
        assert_eq!(recorded.path, "/rpc/invoke");
        let request: InvokeRequest = serde_json::from_value(recorded.body.clone()).unwrap();
        verifiers[index]
            .verify_bound(
                request.capability_token.clone(),
                &capability,
                &operation,
                &[],
            )
            .unwrap();
        Reply::json(
            200,
            serde_json::to_value(InvokeResponse::ok(request.id, json!({"ok": true}))).unwrap(),
        )
    });
    let client = peer.client();
    for (index, connector) in catalog.connectors.iter().enumerate() {
        let auth = resolve_live_auth(registry.get(connector.summary.id.as_str()).unwrap()).unwrap();
        let control =
            McpInvocationControl::new(McpCallContext::default(), &CancellationArgs::default())
                .unwrap();
        control
            .validate_authority(&auth, "z:work", Some("alice"))
            .unwrap();
        let mut request = invoke_request(&format!("independent-{index}"), auth.capability_token);
        request.connector_id = connector.summary.id.clone();
        control.invoke(&client, &request).unwrap();
    }
    for (index, request) in peer.finish().into_iter().enumerate() {
        assert_eq!(
            request.body["capability_token"],
            serde_json::to_value(&grants[index]).unwrap()
        );
        assert_eq!(
            request.body["connector_id"],
            catalog.connectors[index].summary.id.as_str()
        );
    }
}

#[test]
fn default_authority_is_pinned_to_one_identity_and_explicit_groups_never_inherit() {
    let catalog = credential_catalog();
    let grant = token("alice", "z:work", "test.echo", None);
    let defaults = inline_auth(&grant);
    let resolve = |defaults: &LiveAuthArgs, args: &ConnectorAuthArgs| {
        McpAuthorityRegistry::resolve(
            defaults,
            args,
            &catalog,
            &catalog.connectors,
            "z:work",
            None,
        )
    };
    assert!(resolve(&defaults, &ConnectorAuthArgs::default()).is_err());
    let single = McpAuthorityRegistry::resolve(
        &defaults,
        &ConnectorAuthArgs::default(),
        &catalog,
        &catalog.connectors[..1],
        "z:work",
        None,
    )
    .unwrap();
    assert!(single.contains("fcp.github:enterprise:v1"));
    assert!(!single.contains("fcp.github:enterprise:v10"));
    assert!(!single.contains("fcp.slack:enterprise:v1"));

    let explicit = ConnectorAuthArgs {
        connector_capability_token: vec![connector_binding("github", &grant)],
        ..Default::default()
    };
    let subset = resolve(&LiveAuthArgs::default(), &explicit).unwrap();
    assert!(subset.contains("fcp.github:enterprise:v1"));
    assert!(!subset.contains("fcp.slack:enterprise:v1"));

    let directory = tempfile::tempdir().unwrap();
    let key_path = directory.path().join("holder.key");
    std::fs::write(&key_path, [0x73; 32]).unwrap();
    let claims = grant
        .raw()
        .claims_unverified()
        .unwrap()
        .holder_node("node:default-holder")
        .token_id(b"mcp-default-holder");
    let key = fcp_crypto::Ed25519SigningKey::from_bytes(&[0x37; 32]).unwrap();
    let holder_grant =
        CapabilityToken::from_raw(fcp_crypto::cose::CoseToken::sign(&key, &claims).unwrap());
    let holder_defaults = LiveAuthArgs {
        holder_key_file: Some(key_path),
        approval_token: vec!["[]".to_owned()],
        ..inline_auth(&holder_grant)
    };
    let mixed = resolve(&holder_defaults, &explicit).unwrap();
    let github = mixed.get("fcp.github:enterprise:v1").unwrap();
    assert!(github.holder_key_file.is_none());
    assert!(github.approval_token.is_empty());
    assert!(
        mixed
            .get("fcp.slack:enterprise:v1")
            .unwrap()
            .holder_key_file
            .is_some()
    );

    for incomplete in [
        ConnectorAuthArgs {
            connector_approval_token: vec!["github=[]".to_owned()],
            ..Default::default()
        },
        ConnectorAuthArgs {
            connector_capability_token: vec![connector_binding("github", &holder_grant)],
            ..Default::default()
        },
    ] {
        assert!(resolve(&holder_defaults, &incomplete).is_err());
    }
}

#[test]
fn connector_bindings_reject_alias_duplicates_conflicts_and_secret_bearing_errors() {
    let catalog = credential_catalog();
    let grant = token("alice", "z:work", "test.echo", None);
    let binding = connector_binding("github", &grant);
    for args in [
        ConnectorAuthArgs {
            connector_capability_token: vec![
                binding.clone(),
                connector_binding("fcp.github:enterprise:v1", &grant),
            ],
            ..Default::default()
        },
        ConnectorAuthArgs {
            connector_capability_token: vec![binding],
            connector_capability_token_file: vec!["github=PRIVATE_PATH_SECRET".to_owned()],
            ..Default::default()
        },
        ConnectorAuthArgs {
            connector_capability_token: vec!["MALFORMED_TOKEN_SECRET=padding==".to_owned()],
            ..Default::default()
        },
        ConnectorAuthArgs {
            connector_capability_token: vec!["=PRIVATE_TOKEN_SECRET".to_owned()],
            ..Default::default()
        },
        ConnectorAuthArgs {
            connector_capability_token_file: vec!["github=PRIVATE_PATH_SECRET".to_owned()],
            ..Default::default()
        },
    ] {
        let error = McpAuthorityRegistry::resolve(
            &LiveAuthArgs::default(),
            &args,
            &catalog,
            &catalog.connectors,
            "z:work",
            None,
        )
        .err()
        .expect("invalid binding must fail");
        let diagnostics = format!(
            "{} {args:?} {}",
            error.message(),
            serde_json::to_string(&args).unwrap()
        );
        assert_eq!(error.error_type(), "invalid-mcp-auth");
        for secret in [
            "MALFORMED_TOKEN_SECRET",
            "PRIVATE_TOKEN_SECRET",
            "PRIVATE_PATH_SECRET",
        ] {
            assert!(!diagnostics.contains(secret));
        }
        assert_eq!(serde_json::to_value(&args).unwrap(), json!({}));
    }
    let args = ConnectorAuthArgs {
        connector_capability_token: vec![connector_binding("slack", &grant)],
        ..Default::default()
    };
    assert!(
        McpAuthorityRegistry::resolve(
            &LiveAuthArgs::default(),
            &args,
            &catalog,
            &catalog.connectors[..1],
            "z:work",
            None,
        )
        .is_err(),
        "explicit bindings cannot escape the connector selection"
    );
}

#[test]
fn rotating_connector_credentials_rechecks_scope_without_cancellation_authority() {
    let catalog = credential_catalog();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("invocation.token");
    let original = token("alice", "z:work", "test.echo", None);
    std::fs::write(&path, original.raw().to_cbor().unwrap()).unwrap();
    let args = ConnectorAuthArgs {
        connector_capability_token_file: vec![format!("github={}", path.display())],
        ..Default::default()
    };
    let registry = McpAuthorityRegistry::resolve(
        &LiveAuthArgs::default(),
        &args,
        &catalog,
        &catalog.connectors,
        "z:work",
        Some("alice"),
    )
    .unwrap();
    let control =
        McpInvocationControl::new(McpCallContext::default(), &CancellationArgs::default()).unwrap();
    for (owner, zone) in [("alice", "z:private"), ("bob", "z:work")] {
        let rotated = token(owner, zone, "test.echo", None);
        std::fs::write(&path, rotated.raw().to_cbor().unwrap()).unwrap();
        let auth = resolve_live_auth(registry.get("fcp.github:enterprise:v1").unwrap()).unwrap();
        assert!(
            control
                .validate_authority(&auth, "z:work", Some("alice"))
                .is_err()
        );
        assert!(
            McpAuthorityRegistry::resolve(
                &LiveAuthArgs::default(),
                &args,
                &catalog,
                &catalog.connectors,
                "z:work",
                Some("alice"),
            )
            .is_err()
        );
    }
    std::fs::write(&path, original.raw().to_cbor().unwrap()).unwrap();
    let auth = resolve_live_auth(registry.get("fcp.github:enterprise:v1").unwrap()).unwrap();
    control
        .validate_authority(&auth, "z:work", Some("alice"))
        .unwrap();
}

#[test]
fn identical_calls_and_reused_client_contexts_get_distinct_host_identities() {
    let context = McpCallContext::default();
    let first = McpInvocationControl::new(context.clone(), &CancellationArgs::default()).unwrap();
    let second = McpInvocationControl::new(context, &CancellationArgs::default()).unwrap();
    let derive = |control: &McpInvocationControl| {
        crate::derive_live_request_id(
            "fcp.test:utility:1.0.0",
            "test.echo",
            "z:work",
            &json!({"same": "input"}),
            None,
            Some(control.scope_salt()),
        )
        .unwrap()
    };
    assert_ne!(first.scope_salt(), second.scope_salt());
    assert_ne!(derive(&first), derive(&second));
    assert_eq!(derive(&first), derive(&first));
}

#[test]
fn mismatched_owners_zones_and_asserted_principals_fail_before_host_execution() {
    let auth = ResolvedLiveAuth::for_test_token(token("alice", "z:work", "test.echo", None));
    let valid = cancellation_args(&token("alice", "z:work", "host.cancel-self", None));
    let control = McpInvocationControl::new(McpCallContext::default(), &valid).unwrap();
    assert!(
        control
            .validate_authority(&auth, "z:work", Some("alice"))
            .is_ok()
    );
    assert!(
        control
            .validate_authority(&auth, "z:work", Some("bob"))
            .is_err()
    );
    assert!(
        control
            .validate_authority(&auth, "z:private", Some("alice"))
            .is_err()
    );
    for (owner, zone) in [("bob", "z:work"), ("alice", "z:private")] {
        let args = cancellation_args(&token(owner, zone, "host.cancel-self", None));
        let control = McpInvocationControl::new(McpCallContext::default(), &args).unwrap();
        assert!(control.validate_authority(&auth, "z:work", None).is_err());
    }
}

#[test]
fn cancellation_authority_is_explicit_unbound_and_size_limited() {
    assert!(CancellationArgs::default().resolve().unwrap().is_none());
    for (capability, holder) in [
        ("test.echo", None),
        ("host.cancel-self", Some("node:holder")),
    ] {
        let args = cancellation_args(&token("alice", "z:work", capability, holder));
        assert!(args.resolve().is_err());
    }
    let oversized = CancellationArgs {
        cancel_capability_token: Some("x".repeat(MAX_CANCELLATION_TOKEN_BYTES + 1)),
        cancel_capability_token_file: None,
    };
    assert!(oversized.resolve().is_err());
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("oversized.token");
    std::fs::write(&path, vec![b'x'; MAX_CANCELLATION_TOKEN_BYTES + 1]).unwrap();
    let file = CancellationArgs {
        cancel_capability_token: None,
        cancel_capability_token_file: Some(path),
    };
    assert!(file.resolve().is_err());
}

#[test]
fn self_cancel_requires_matching_bounded_response_and_never_uses_admin_routes() {
    let id = "original-operation";
    let replies = vec![
        (
            Reply::json(404, json!({"error": "registration pending"})),
            CancelAttempt::Retry,
        ),
        (Reply::json(429, json!({})), CancelAttempt::Retry),
        (Reply::json(503, json!({})), CancelAttempt::Retry),
        (
            Reply::json(403, json!({"error": "private-provider-secret"})),
            CancelAttempt::Terminal,
        ),
        (
            Reply::json(200, cancellation_response("another-operation", "cancelled")),
            CancelAttempt::Terminal,
        ),
        (
            Reply::json(200, cancellation_response(id, "cancelled")),
            CancelAttempt::Accepted,
        ),
        (
            Reply::json(200, cancellation_response(id, "pending")),
            CancelAttempt::Accepted,
        ),
        (
            Reply::json(200, cancellation_response(id, "too_late")),
            CancelAttempt::Terminal,
        ),
        (
            Reply::json(200, cancellation_response(id, "failed")),
            CancelAttempt::Terminal,
        ),
        (
            Reply::Body(200, b"not json".to_vec()),
            CancelAttempt::Terminal,
        ),
        (
            Reply::Body(
                200,
                vec![b'x'; MAX_CANCELLATION_RESPONSE_BYTES as usize + 1],
            ),
            CancelAttempt::Terminal,
        ),
    ];
    let expected = replies
        .iter()
        .map(|(_, result)| *result)
        .collect::<Vec<_>>();
    let mut replies = replies.into_iter();
    let peer = HostPeer::start(expected.len(), move |_, _| replies.next().unwrap().0);
    let client = peer.client();
    let grant = token("alice", "z:work", "host.cancel-self", None);
    let request = cancellation_request(id, grant.clone());
    for outcome in expected {
        assert_eq!(cancel_once(&client, &request), outcome);
    }
    for recorded in peer.finish() {
        assert_eq!(recorded.method, "POST");
        assert_eq!(recorded.path, "/rpc/cancel-self");
        assert_eq!(recorded.body["operation_id"], id);
        assert_eq!(
            recorded.body["capability_token"],
            serde_json::to_value(&grant).unwrap()
        );
        assert!(!recorded.headers.contains_key("authorization"));
        assert!(!recorded.headers.contains_key("x-principal"));
    }
}

#[test]
fn lost_invoke_response_retains_original_authority_through_registration_race() {
    let context = McpCallContext::default();
    let original_grant = token("alice", "z:work", "host.cancel-self", None);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cancellation.token");
    std::fs::write(&path, original_grant.raw().to_cbor().unwrap()).unwrap();
    let args = CancellationArgs {
        cancel_capability_token: None,
        cancel_capability_token_file: Some(path.clone()),
    };
    let control = McpInvocationControl::new(context.clone(), &args).unwrap();
    // Later rotation changes neither the active call's owner nor the grant it
    // presents while the host is still admitting the original invocation.
    let rotated_grant = token("bob", "z:private", "host.cancel-self", None);
    std::fs::write(&path, rotated_grant.raw().to_cbor().unwrap()).unwrap();
    let invoke_token = token("alice", "z:work", "test.echo", None);
    let auth = ResolvedLiveAuth::for_test_token(invoke_token.clone());
    control
        .validate_authority(&auth, "z:work", Some("alice"))
        .unwrap();
    let request = invoke_request("original-call-after-response-loss", invoke_token.clone());
    let original_id = request.id.to_string();
    let response_id = original_id.clone();
    let peer = HostPeer::start(3, move |index, recorded| match index {
        0 => {
            assert_eq!(recorded.path, "/rpc/invoke");
            // Cancel while host execution is still owned, then lose only the
            // HTTP reply. The invocation must not be replayed to recover it.
            context.cancel();
            Reply::Close
        }
        1 => {
            assert_eq!(recorded.path, "/rpc/cancel-self");
            Reply::json(404, json!({"error": "registration pending"}))
        }
        2 => Reply::json(200, cancellation_response(&response_id, "pending")),
        _ => unreachable!(),
    });

    assert!(control.invoke(&peer.client(), &request).is_err());
    let requests = peer.finish();
    assert_eq!(requests[0].body["id"], original_id);
    assert_eq!(requests[0].body["zone_id"], "z:work");
    assert_eq!(
        requests[0].body["capability_token"],
        serde_json::to_value(invoke_token).unwrap()
    );
    for cancel in &requests[1..] {
        assert_eq!(cancel.path, "/rpc/cancel-self");
        assert_eq!(cancel.body["operation_id"], original_id);
        assert_eq!(
            cancel.body["capability_token"],
            serde_json::to_value(&original_grant).unwrap()
        );
        assert!(!cancel.headers.contains_key("authorization"));
        assert!(!cancel.headers.contains_key("x-principal"));
    }
}

#[test]
fn cancellation_before_dispatch_sends_neither_invoke_nor_cancel() {
    let context = McpCallContext::default();
    let args = cancellation_args(&token("alice", "z:work", "host.cancel-self", None));
    let control = McpInvocationControl::new(context.clone(), &args).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let client =
        HostAdminClient::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    context.cancel();
    let request = invoke_request(
        "never-dispatched",
        token("alice", "z:work", "test.echo", None),
    );
    assert!(control.invoke(&client, &request).is_err());
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
