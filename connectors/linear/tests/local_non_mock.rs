#![allow(
    clippy::doc_markdown,
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unused_async
)]

use std::fmt::Write as FmtWrite;
use std::io::{BufRead, BufReader, Read, Write as IoWrite};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::Duration as StdDuration;

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_linear::connector::LinearConnector;
use fcp_manifest::ConnectorManifest;
use fcp_prelude::{
    ApprovalMode, CapabilityConstraints, CapabilityToken, FcpError, HealthSnapshot, InstanceId,
    Introspection, InvokeResponse, InvokeStatus, SimulateResponse,
};
use serde_json::{Value, json};

const API_KEY: &str = "lin_api_local_acceptance_key";
const OP_GET_ISSUE: &str = "linear.get_issue";
const OP_LIST_TEAMS: &str = "linear.list_teams";
const OP_SEARCH_ISSUES: &str = "linear.search_issues";

#[derive(Debug)]
struct CapturedRequest {
    head: String,
    body: Option<Value>,
}

struct LoopbackGraphqlServer {
    base_url: String,
    received: Receiver<CapturedRequest>,
    join: JoinHandle<()>,
}

impl LoopbackGraphqlServer {
    fn start(responses: Vec<HttpResponse>) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .expect("loopback listener should bind to an ephemeral port");
        let addr = listener
            .local_addr()
            .expect("loopback listener should expose its local address");
        let base_url = format!("http://{addr}");
        let (request_tx, received) = mpsc::channel();

        let join = thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener
                    .accept()
                    .expect("loopback listener should accept the expected request");
                stream
                    .set_read_timeout(Some(StdDuration::from_secs(5)))
                    .expect("loopback stream should set a read timeout");

                let request = read_complete_request(&mut stream);
                request_tx
                    .send(request)
                    .expect("captured request should be delivered to the test");

                let mut raw_response = format!("HTTP/1.1 {}\r\n", response.status);
                raw_response.push_str("content-type: application/json\r\n");
                write!(
                    &mut raw_response,
                    "content-length: {}\r\n",
                    response.body.len()
                )
                .expect("content-length header should format");
                raw_response.push_str("connection: close\r\n");
                for (name, value) in response.headers {
                    raw_response.push_str(name);
                    raw_response.push_str(": ");
                    raw_response.push_str(value);
                    raw_response.push_str("\r\n");
                }
                raw_response.push_str("\r\n");
                raw_response.push_str(response.body);

                stream
                    .write_all(raw_response.as_bytes())
                    .expect("loopback response should be writable");
            }
        });

        Self {
            base_url,
            received,
            join,
        }
    }

    fn graphql_url(&self) -> String {
        format!("{}/graphql", self.base_url)
    }

    fn take(&self) -> CapturedRequest {
        self.received
            .recv_timeout(StdDuration::from_secs(5))
            .expect("loopback request should arrive")
    }

    fn join(self) {
        self.join
            .join()
            .expect("loopback server thread should finish");
    }
}

struct HttpResponse {
    status: &'static str,
    headers: Vec<(&'static str, &'static str)>,
    body: &'static str,
}

impl HttpResponse {
    const fn json(status: &'static str, body: &'static str) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body,
        }
    }
}

fn read_complete_request(stream: &mut TcpStream) -> CapturedRequest {
    let mut bytes = Vec::new();
    let mut buffer = [0; 1024];
    let mut header_end = None;
    let mut content_length = 0usize;

    loop {
        let read = stream
            .read(&mut buffer)
            .expect("loopback request should be readable");
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);

        if header_end.is_none() {
            header_end = bytes.windows(4).position(|window| window == b"\r\n\r\n");
            if let Some(end) = header_end {
                let head = String::from_utf8_lossy(&bytes[..end]).to_string();
                content_length = parse_content_length(&head);
            }
        }

        if let Some(end) = header_end {
            let body_start = end + 4;
            if bytes.len() >= body_start + content_length {
                let head = String::from_utf8(bytes[..end].to_vec())
                    .expect("request headers should be valid UTF-8");
                let body_slice = &bytes[body_start..body_start + content_length];
                let body = if body_slice.is_empty() {
                    None
                } else {
                    Some(
                        serde_json::from_slice(body_slice)
                            .expect("request body should be JSON when present"),
                    )
                };
                return CapturedRequest { head, body };
            }
        }
    }

    panic!("loopback request ended before complete headers/body were read");
}

fn parse_content_length(head: &str) -> usize {
    head.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())
                .flatten()
        })
        .unwrap_or(0)
}

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    operation: &str,
    instance_id: &InstanceId,
) -> CapabilityToken {
    let capability = match operation {
        "linear.create_issue" | "linear.update_issue" | "linear.add_comment" => "linear.write",
        "linear.process_webhook" => "linear.process_webhook",
        _ => "linear.read",
    };
    token_for_binding(
        signing_key,
        operation,
        capability,
        "z:work",
        Some(instance_id),
        &["*"],
    )
}

fn token_for_binding(
    signing_key: &Ed25519SigningKey,
    operation: &str,
    capability: &str,
    zone: &str,
    instance_id: Option<&InstanceId>,
    resources: &[&str],
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: resources
            .iter()
            .map(|resource| (*resource).into())
            .collect(),
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("constraints should serialize as CBOR");
    let mut builder = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id(zone)
        .principal("user:local-linear-acceptance")
        .operations(&[operation])
        .issuer("node:local-linear-acceptance")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should be valid");
    if let Some(instance_id) = instance_id {
        builder = builder.target_instance(instance_id.as_str());
    }
    let cose = builder
        .sign(signing_key)
        .expect("capability token should sign");
    CapabilityToken::from_raw(cose)
}

/// Exercise the shipped JSONL executable, including its framing and adapter.
struct NativeLinear {
    child: Child,
    input: ChildStdin,
    output: Receiver<Value>,
}

impl NativeLinear {
    fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_fcp-linear"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("the built Linear executable should start");
        let input = child.stdin.take().expect("child stdin should be piped");
        let stdout = child.stdout.take().expect("child stdout should be piped");
        let (send, output) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let line = line.expect("native response line should be readable");
                let value = serde_json::from_str(&line).expect("native stdout must be JSONL");
                if send.send(value).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            input,
            output,
        }
    }

    fn rpc(&mut self, id: &str, method: &str, params: Value) -> Value {
        let request = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        serde_json::to_writer(&mut self.input, &request).expect("request should serialize");
        self.input.write_all(b"\n").expect("request should write");
        self.input.flush().expect("request should flush");
        let response = self
            .output
            .recv_timeout(StdDuration::from_secs(10))
            .expect("native response should arrive within the bounded wait");
        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], id, "outer correlation ID must be preserved");
        response
    }

    fn result(&mut self, id: &str, method: &str, params: Value) -> Value {
        let response = self.rpc(id, method, params);
        assert!(
            response.get("error").is_none(),
            "unexpected RPC error: {response}"
        );
        response
            .get("result")
            .expect("successful response should contain result")
            .clone()
    }

    fn assert_shutdown_exit(&mut self) {
        let deadline = std::time::Instant::now() + StdDuration::from_secs(5);
        loop {
            if let Some(status) = self
                .child
                .try_wait()
                .expect("child status should be available")
            {
                assert!(status.success(), "shutdown should exit cleanly: {status}");
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "shutdown must terminate the native JSONL loop"
            );
            thread::sleep(StdDuration::from_millis(10));
        }
    }
}

impl Drop for NativeLinear {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn native_request(kind: &str, operation: &str, input: Value, token: CapabilityToken) -> Value {
    json!({
        "type": kind,
        "id": "inner-linear-request",
        "connector_id": "fcp.linear",
        "operation": operation,
        "zone_id": "z:work",
        "input": input,
        "capability_token": token,
    })
}

#[test]
fn native_binary_preserves_host_contract_and_denies_before_graphql_effects() {
    let server = LoopbackGraphqlServer::start(vec![
        HttpResponse::json(
            "200 OK",
            r#"{"data":{"teams":{"nodes":[{"id":"team-eng","name":"Engineering","key":"ENG"}]}}}"#,
        ),
        HttpResponse::json(
            "200 OK",
            r#"{"data":{"issueCreate":{"success":true,"issue":{"id":"issue-new","identifier":"ENG-42","title":"Native issue"}}}}"#,
        ),
    ]);
    let mut native = NativeLinear::start();
    native.result(
        "configure",
        "configure",
        json!({
            "api_key": API_KEY,
            "api_url": server.graphql_url(),
        }),
    );
    let health: HealthSnapshot =
        serde_json::from_value(native.result("before-handshake", "health", json!({}))).unwrap();
    assert!(
        !health.is_ready(),
        "configuration alone must not advertise readiness"
    );
    assert_eq!(health.details.unwrap()["handshaken"], false);

    let manifest = ConnectorManifest::parse_str(include_str!("../manifest.toml")).unwrap();
    let catalog: Introspection =
        serde_json::from_value(native.result("catalog", "introspect", json!({}))).unwrap();
    assert_eq!(catalog.operations.len(), 10);
    assert_eq!(catalog.events.len(), 12);
    for operation in &catalog.operations {
        let declared = &manifest.provides.operations[operation.id.as_str()];
        assert_eq!(operation.capability, declared.capability);
        assert_eq!(operation.input_schema, declared.input_schema);
        assert_eq!(operation.output_schema, declared.output_schema);
        assert_eq!(operation.risk_level, declared.risk_level);
        assert_eq!(operation.safety_tier, declared.safety_tier);
        assert_eq!(operation.idempotency, declared.idempotency);
        assert_eq!(
            operation.requires_approval,
            Some(ApprovalMode::from(declared.requires_approval))
        );
    }

    let signing_key = Ed25519SigningKey::generate();
    let requested_instance = InstanceId::new();
    let handshake = native.result("handshake", "handshake", json!({
        "protocol_version": "2.0",
        "zone": "z:work",
        "host_public_key": signing_key.verifying_key().to_bytes(),
        "nonce": vec![7u8; 32],
        "requested_instance_id": requested_instance,
        "capabilities_requested": ["linear.read", "linear.write", "linear.read", "linear.unknown"],
    }));
    assert_eq!(handshake["status"], "accepted");
    assert_eq!(
        handshake["capabilities_granted"].as_array().unwrap().len(),
        2
    );
    let health: HealthSnapshot =
        serde_json::from_value(native.result("ready", "health", json!({}))).unwrap();
    assert!(health.is_ready());
    let details = health.details.unwrap();
    assert_eq!(details["configured"], true);
    assert_eq!(details["handshaken"], true);
    let instance: InstanceId = serde_json::from_value(details["instance_id"].clone()).unwrap();
    assert_ne!(
        instance, requested_instance,
        "identity must belong to the running process"
    );

    let input = json!({ "title": "Native issue", "team_id": "team-eng" });
    let foreign_key = Ed25519SigningKey::generate();
    let wrong_instance = InstanceId::new();
    let invalid_tokens = [
        (
            "foreign signer",
            token_for_binding(
                &foreign_key,
                "linear.create_issue",
                "linear.write",
                "z:work",
                Some(&instance),
                &["*"],
            ),
        ),
        (
            "wrong instance",
            token_for_binding(
                &signing_key,
                "linear.create_issue",
                "linear.write",
                "z:work",
                Some(&wrong_instance),
                &["*"],
            ),
        ),
        (
            "unbound token",
            token_for_binding(
                &signing_key,
                "linear.create_issue",
                "linear.write",
                "z:work",
                None,
                &["*"],
            ),
        ),
        (
            "wrong token zone",
            token_for_binding(
                &signing_key,
                "linear.create_issue",
                "linear.write",
                "z:private",
                Some(&instance),
                &["*"],
            ),
        ),
        (
            "wrong capability",
            token_for_binding(
                &signing_key,
                "linear.create_issue",
                "linear.read",
                "z:work",
                Some(&instance),
                &["*"],
            ),
        ),
        (
            "wrong operation",
            token_for_binding(
                &signing_key,
                "linear.add_comment",
                "linear.write",
                "z:work",
                Some(&instance),
                &["*"],
            ),
        ),
        (
            "wrong resource",
            token_for_binding(
                &signing_key,
                "linear.create_issue",
                "linear.write",
                "z:work",
                Some(&instance),
                &["linear://team/other/issues"],
            ),
        ),
    ];
    for (case, token) in invalid_tokens {
        let response = native.rpc(
            case,
            "invoke",
            native_request(
                "invoke",
                "linear.create_issue",
                input.clone(),
                token.clone(),
            ),
        );
        assert!(
            response.get("error").is_some(),
            "{case} must be refused: {response}"
        );
        let simulation: SimulateResponse = serde_json::from_value(native.result(
            case,
            "simulate",
            native_request("simulate", "linear.create_issue", input.clone(), token),
        ))
        .unwrap();
        assert!(
            !simulation.would_succeed,
            "{case} must also fail simulation"
        );
        assert!(
            simulation.denial_code.is_some(),
            "{case} needs a machine-readable denial"
        );
        assert!(
            matches!(server.received.try_recv(), Err(mpsc::TryRecvError::Empty)),
            "{case} must not make a provider request"
        );
    }

    let token = generate_valid_token(&signing_key, "linear.create_issue", &instance);
    for (case, field, value) in [
        ("wrong target", "connector_id", json!("fcp.github")),
        ("wrong request zone", "zone_id", json!("z:private")),
        (
            "invalid input",
            "input",
            json!({ "title": 42, "team_id": "team-eng" }),
        ),
        ("wrong message type", "type", json!("health")),
    ] {
        for method in ["invoke", "simulate"] {
            let mut request =
                native_request(method, "linear.create_issue", input.clone(), token.clone());
            request[field] = value.clone();
            let response = native.rpc(case, method, request);
            assert!(
                response.get("error").is_some() || response["result"]["would_succeed"] == false,
                "{case}/{method} must fail: {response}"
            );
        }
        assert!(
            matches!(server.received.try_recv(), Err(mpsc::TryRecvError::Empty)),
            "{case} must not make a provider request"
        );
    }
    let mut missing_id = native_request(
        "invoke",
        "linear.create_issue",
        input.clone(),
        token.clone(),
    );
    missing_id.as_object_mut().unwrap().remove("id");
    assert!(
        native
            .rpc("missing-inner-id", "invoke", missing_id)
            .get("error")
            .is_some()
    );
    let simulation: SimulateResponse = serde_json::from_value(native.result(
        "simulate-valid",
        "simulate",
        native_request(
            "simulate",
            "linear.create_issue",
            input.clone(),
            token.clone(),
        ),
    ))
    .unwrap();
    assert!(simulation.would_succeed);
    assert_eq!(simulation.id.0, "inner-linear-request");
    assert!(
        matches!(server.received.try_recv(), Err(mpsc::TryRecvError::Empty)),
        "simulation must not create an issue"
    );

    let read_token = generate_valid_token(&signing_key, OP_LIST_TEAMS, &instance);
    let response: InvokeResponse = serde_json::from_value(native.result(
        "outer-read",
        "invoke",
        native_request("invoke", OP_LIST_TEAMS, json!({}), read_token),
    ))
    .unwrap();
    assert_eq!(response.r#type, "response");
    assert_eq!(response.id.0, "inner-linear-request");
    assert_eq!(response.status, InvokeStatus::Ok);
    assert_eq!(response.result.unwrap()["teams"][0]["id"], "team-eng");
    let captured = server.take();
    assert!(
        assert_graphql_request(&captured)["query"]
            .as_str()
            .unwrap()
            .contains("query ListTeams")
    );

    let response: InvokeResponse = serde_json::from_value(native.result(
        "outer-write",
        "invoke",
        native_request("invoke", "linear.create_issue", input, token),
    ))
    .unwrap();
    assert_eq!(response.id.0, "inner-linear-request");
    assert_eq!(response.status, InvokeStatus::Ok);
    assert_eq!(response.result.unwrap()["issue"]["identifier"], "ENG-42");
    let captured = server.take();
    let body = assert_graphql_request(&captured);
    assert!(
        body["query"]
            .as_str()
            .unwrap()
            .contains("mutation IssueCreate")
    );
    assert_eq!(body["variables"]["title"], "Native issue");
    assert_eq!(body["variables"]["teamId"], "team-eng");
    server.join();

    native.result("shutdown", "shutdown", json!({}));
    native.assert_shutdown_exit();
}

async fn configure_and_handshake(
    connector: &mut LinearConnector,
    graphql_url: &str,
    capabilities: &[&str],
) -> Ed25519SigningKey {
    connector
        .handle_configure(json!({
            "api_key": API_KEY,
            "api_url": graphql_url
        }))
        .await
        .expect("Linear connector should configure against loopback GraphQL");

    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let capabilities: std::collections::BTreeSet<_> = capabilities
        .iter()
        .map(|operation| match *operation {
            "linear.create_issue" | "linear.update_issue" | "linear.add_comment" => "linear.write",
            "linear.process_webhook" => "linear.process_webhook",
            _ => "linear.read",
        })
        .collect();
    connector
        .handle_handshake(json!({
            "protocol_version": "2.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": capabilities
        }))
        .await
        .expect("Linear connector should establish verifier during handshake");

    signing_key
}

async fn invoke(
    connector: &LinearConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    input: Value,
) -> Result<Value, FcpError> {
    let token = generate_valid_token(signing_key, operation, connector.instance_id());
    connector
        .handle_invoke(json!({
            "operation": operation,
            "input": input,
            "capability_token": token
        }))
        .await
}

fn assert_graphql_request(captured: &CapturedRequest) -> &Value {
    let request_line = captured
        .head
        .lines()
        .next()
        .expect("captured request should include a request line");
    assert_eq!(request_line, "POST /graphql HTTP/1.1");

    let lower_head = captured.head.to_ascii_lowercase();
    assert!(
        lower_head.contains("content-type: application/json"),
        "request should be JSON; head={}",
        captured.head
    );
    assert!(
        lower_head.contains(&format!("authorization: {API_KEY}")),
        "request should carry the configured personal API key without a Bearer prefix; head={}",
        captured.head
    );

    captured
        .body
        .as_ref()
        .expect("GraphQL request should include a JSON body")
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_list_teams_posts_expected_graphql_and_maps_output() {
    let server = LoopbackGraphqlServer::start(vec![HttpResponse::json(
        "200 OK",
        r#"{
            "data": {
                "teams": {
                    "nodes": [
                        {
                            "id": "team-eng",
                            "name": "Engineering",
                            "key": "ENG",
                            "description": "Product engineering"
                        }
                    ]
                }
            }
        }"#,
    )]);
    let mut connector = LinearConnector::new();
    let signing_key =
        configure_and_handshake(&mut connector, &server.graphql_url(), &[OP_LIST_TEAMS]).await;

    let result = invoke(&connector, &signing_key, OP_LIST_TEAMS, json!({}))
        .await
        .expect("list teams should invoke against loopback GraphQL");

    let captured = server.take();
    let body = assert_graphql_request(&captured);
    let query = body["query"]
        .as_str()
        .expect("GraphQL request should include query text");
    assert!(query.contains("query ListTeams"));
    assert!(
        body.get("variables").is_none(),
        "list_teams should not send variables: {body}"
    );
    assert_eq!(result["teams"][0]["id"], "team-eng");
    assert_eq!(result["teams"][0]["key"], "ENG");
    assert_eq!(result["teams"][0]["description"], "Product engineering");
    server.join();
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_get_issue_posts_variables_and_maps_output() {
    let server = LoopbackGraphqlServer::start(vec![HttpResponse::json(
        "200 OK",
        r##"{
            "data": {
                "issue": {
                    "id": "issue-42",
                    "identifier": "LIN-42",
                    "title": "Loopback issue",
                    "description": "Loopback issue",
                    "priority": 2,
                    "priorityLabel": "High",
                    "state": {
                        "id": "state-started",
                        "name": "Started",
                        "color": "#f2c94c",
                        "type": "started"
                    },
                    "assignee": {
                        "id": "user-1",
                        "name": "Local Agent",
                        "displayName": "Local Agent",
                        "email": "agent@example.invalid"
                    },
                    "team": {
                        "id": "team-eng",
                        "name": "Engineering",
                        "key": "ENG"
                    },
                    "labels": {
                        "nodes": [
                            { "id": "label-bug", "name": "bug", "color": "#eb5757" }
                        ]
                    },
                    "createdAt": "2026-05-14T00:00:00Z",
                    "updatedAt": "2026-05-14T00:01:00Z",
                    "url": "https://linear.app/flywheel/issue/LIN-42"
                }
            }
        }"##,
    )]);
    let mut connector = LinearConnector::new();
    let signing_key =
        configure_and_handshake(&mut connector, &server.graphql_url(), &[OP_GET_ISSUE]).await;

    let result = invoke(
        &connector,
        &signing_key,
        OP_GET_ISSUE,
        json!({ "issue_id": "issue-42" }),
    )
    .await
    .expect("get issue should invoke against loopback GraphQL");

    let captured = server.take();
    let body = assert_graphql_request(&captured);
    let query = body["query"]
        .as_str()
        .expect("GraphQL request should include query text");
    assert!(query.contains("query GetIssue"));
    assert_eq!(body["variables"], json!({ "id": "issue-42" }));
    assert_eq!(result["issue"]["identifier"], "LIN-42");
    assert_eq!(result["issue"]["team"]["key"], "ENG");
    assert_eq!(result["issue"]["labels"]["nodes"][0]["name"], "bug");
    server.join();
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_search_issues_posts_query_variables_and_maps_output() {
    let server = LoopbackGraphqlServer::start(vec![HttpResponse::json(
        "200 OK",
        r##"{
            "data": {
                "searchIssues": {
                    "nodes": [
                        {
                            "id": "issue-1",
                            "identifier": "LIN-1",
                            "title": "First loopback bug",
                            "description": "Found locally",
                            "priority": 1,
                            "priorityLabel": "Urgent",
                            "state": {
                                "id": "state-triage",
                                "name": "Triage",
                                "color": "#2f80ed",
                                "type": "triage"
                            },
                            "assignee": null,
                            "team": {
                                "id": "team-eng",
                                "name": "Engineering",
                                "key": "ENG"
                            },
                            "labels": {
                                "nodes": []
                            },
                            "createdAt": "2026-05-14T00:00:00Z",
                            "updatedAt": "2026-05-14T00:01:00Z",
                            "url": "https://linear.app/flywheel/issue/LIN-1"
                        },
                        {
                            "id": "issue-2",
                            "identifier": "LIN-2",
                            "title": "Second loopback bug",
                            "description": null,
                            "priority": 3,
                            "priorityLabel": "Medium",
                            "state": null,
                            "assignee": null,
                            "team": {
                                "id": "team-ops",
                                "name": "Operations",
                                "key": "OPS"
                            },
                            "labels": {
                                "nodes": []
                            },
                            "createdAt": "2026-05-14T00:02:00Z",
                            "updatedAt": "2026-05-14T00:03:00Z",
                            "url": "https://linear.app/flywheel/issue/LIN-2"
                        }
                    ]
                }
            }
        }"##,
    )]);
    let mut connector = LinearConnector::new();
    let signing_key =
        configure_and_handshake(&mut connector, &server.graphql_url(), &[OP_SEARCH_ISSUES]).await;

    let result = invoke(
        &connector,
        &signing_key,
        OP_SEARCH_ISSUES,
        json!({ "query": "loopback bug" }),
    )
    .await
    .expect("search issues should invoke against loopback GraphQL");

    let captured = server.take();
    let body = assert_graphql_request(&captured);
    let query = body["query"]
        .as_str()
        .expect("GraphQL request should include query text");
    assert!(query.contains("query SearchIssues"));
    assert_eq!(body["variables"], json!({ "query": "loopback bug" }));
    assert_eq!(result["issues"][0]["identifier"], "LIN-1");
    assert_eq!(result["issues"][1]["team"]["key"], "OPS");
    server.join();
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_unauthorized_maps_to_fcp_error_without_leaking_key() {
    let server = LoopbackGraphqlServer::start(vec![HttpResponse::json(
        "401 Unauthorized",
        r#"{"errors":[{"message":"bad credentials"}]}"#,
    )]);
    let mut connector = LinearConnector::new();
    let signing_key =
        configure_and_handshake(&mut connector, &server.graphql_url(), &[OP_LIST_TEAMS]).await;

    let err = invoke(&connector, &signing_key, OP_LIST_TEAMS, json!({}))
        .await
        .expect_err("401 should map to an FCP authorization error");

    let captured = server.take();
    let body = assert_graphql_request(&captured);
    let query = body["query"]
        .as_str()
        .expect("GraphQL request should include query text");
    assert!(query.contains("query ListTeams"));
    assert!(
        matches!(err, FcpError::Unauthorized { code: 2001, .. }),
        "expected Unauthorized, got {err:?}"
    );
    assert!(
        !format!("{err:?}").contains(API_KEY),
        "FCP error should not include the Linear API key"
    );
    server.join();
}
