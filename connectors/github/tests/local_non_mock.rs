//! Local loopback acceptance coverage for the GitHub connector.

#![allow(clippy::too_many_lines)]

use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
};

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_github::connector::GitHubConnector;
use fcp_prelude::CapabilityConstraints;
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const CONNECTOR_ID: &str = "fcp.github";
const FIXTURE_ID: &str = "github-loopback-local-acceptance";
const TEST_CREDENTIAL_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
const OWNER: &str = "octocat";
const REPO: &str = "hello-world";

#[derive(Clone, Debug)]
struct ObservedGitHubRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl ObservedGitHubRequest {
    fn credential_header_matches(&self) -> bool {
        self.headers
            .get("x-fcp-credential-id")
            .is_some_and(|value| value == TEST_CREDENTIAL_ID)
    }

    fn github_api_version_seen(&self) -> bool {
        self.headers
            .get("x-github-api-version")
            .is_some_and(|value| value == "2022-11-28")
    }

    fn body_json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("request body should be JSON")
    }
}

struct LoopbackGitHubFixture {
    base_url: String,
    observations: Arc<Mutex<Vec<ObservedGitHubRequest>>>,
    _join: JoinHandle<()>,
}

impl LoopbackGitHubFixture {
    fn start(expected_requests: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind GitHub loopback listener");
        let address = listener.local_addr().expect("read listener address");
        let observations = Arc::new(Mutex::new(Vec::new()));
        let observations_for_thread = Arc::clone(&observations);

        let join = thread::spawn(move || {
            for _ in 0..expected_requests {
                let (mut stream, _) = listener.accept().expect("accept GitHub loopback request");
                let request = read_http_request(&mut stream);
                let response = response_for_request(&request);
                observations_for_thread
                    .lock()
                    .expect("record GitHub loopback request")
                    .push(request);
                write_http_response(&mut stream, response);
            }
        });

        Self {
            base_url: format!("http://{address}"),
            observations,
            _join: join,
        }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn observations(&self) -> Vec<ObservedGitHubRequest> {
        self.observations
            .lock()
            .expect("read GitHub loopback observations")
            .clone()
    }
}

#[derive(Debug)]
struct HttpFixtureResponse {
    status: u16,
    body: Option<Value>,
}

fn read_http_request(stream: &mut TcpStream) -> ObservedGitHubRequest {
    let mut buffer = Vec::new();
    let mut temp = [0_u8; 1024];
    let header_end = loop {
        let read = stream.read(&mut temp).expect("read GitHub HTTP request");
        assert!(read > 0, "unexpected EOF while reading GitHub request");
        buffer.extend_from_slice(&temp[..read]);
        if let Some(pos) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break pos + 4;
        }
    };

    let header_text = std::str::from_utf8(&buffer[..header_end]).expect("headers are UTF-8");
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().expect("request line present");
    let mut request_line_parts = request_line.split_whitespace();
    let method = request_line_parts
        .next()
        .expect("method present")
        .to_string();
    let path = request_line_parts.next().expect("path present").to_string();

    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':').expect("header separator");
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
    }

    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = buffer[header_end..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut temp).expect("read GitHub request body");
        assert!(read > 0, "unexpected EOF while reading GitHub body");
        body.extend_from_slice(&temp[..read]);
    }
    body.truncate(content_length);

    ObservedGitHubRequest {
        method,
        path,
        headers,
        body,
    }
}

fn response_for_request(request: &ObservedGitHubRequest) -> HttpFixtureResponse {
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/repos/octocat/hello-world") => HttpFixtureResponse {
            status: 200,
            body: Some(json!({
                "id": 1_296_269,
                "name": REPO,
                "full_name": format!("{OWNER}/{REPO}"),
                "owner": {
                    "login": OWNER,
                    "id": 1,
                    "avatar_url": "",
                    "type": "User"
                },
                "description": "Local acceptance repository",
                "private": false,
                "fork": false,
                "html_url": "https://github.example.invalid/octocat/hello-world",
                "default_branch": "main",
                "language": "Rust",
                "stargazers_count": 42,
                "forks_count": 7,
                "open_issues_count": 3,
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2026-01-15T10:00:00Z"
            })),
        },
        ("POST", "/repos/octocat/hello-world/issues") => HttpFixtureResponse {
            status: 201,
            body: Some(json!({
                "id": 10_043,
                "number": 43,
                "title": "Local acceptance issue",
                "state": "open",
                "body": "Fixture-created issue",
                "user": {
                    "login": OWNER,
                    "id": 1,
                    "avatar_url": "",
                    "type": "User"
                },
                "labels": [],
                "assignees": [],
                "created_at": "2026-01-15T10:00:00Z",
                "updated_at": "2026-01-15T10:00:01Z",
                "html_url": "https://github.example.invalid/octocat/hello-world/issues/43",
                "comments": 0
            })),
        },
        ("POST", "/repos/octocat/hello-world/actions/workflows/ci.yml/dispatches") => {
            HttpFixtureResponse {
                status: 202,
                body: None,
            }
        }
        _ => HttpFixtureResponse {
            status: 500,
            body: Some(json!({
                "message": "unexpected local acceptance request",
                "documentation_url": "https://docs.github.com"
            })),
        },
    }
}

fn write_http_response(stream: &mut TcpStream, response: HttpFixtureResponse) {
    let reason = match response.status {
        201 => "Created",
        202 => "Accepted",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let body = response
        .body
        .map_or_else(String::new, |value| value.to_string());
    write!(
        stream,
        "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        response.status,
        reason,
        body.len(),
        body
    )
    .expect("write GitHub loopback response");
}

fn capability_for_operation(operation: &str) -> &'static str {
    match operation {
        "github.create_issue" | "github.create_pull_request" => "github.write",
        "github.merge_pull_request" | "github.trigger_workflow" => "github.admin",
        "github.process_webhook" => "github.process_webhook",
        _ => "github.read",
    }
}

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    connector: &GitHubConnector,
    operation: &str,
) -> fcp_core::CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability_for_operation(operation))
        .zone_id("z:work")
        .principal("user:local-non-mock")
        .operations(&[operation])
        .issuer("node:local-non-mock")
        .validity(now, now + ChronoDuration::hours(1))
        .target_instance(connector.instance_id().as_str())
        .try_constraints_cbor(&constraints_cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("sign local acceptance token");
    fcp_core::CapabilityToken::from_raw(cose)
}

async fn setup_handshake(connector: &mut GitHubConnector, caps: &[&str]) -> Ed25519SigningKey {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    connector
        .handle_handshake(json!({
            "protocol_version": "2.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0_u8; 32],
            "capabilities_requested": caps
        }))
        .await
        .expect("handshake should succeed");

    signing_key
}

#[fcp_async_core::test]
async fn loopback_acceptance_exercises_read_write_and_admin_paths() {
    let fixture = LoopbackGitHubFixture::start(3);
    let mut connector = GitHubConnector::new();

    connector
        .handle_configure(json!({
            "credential_id": TEST_CREDENTIAL_ID,
            "base_url": fixture.base_url()
        }))
        .await
        .expect("configure connector against loopback GitHub fixture");
    let signing_key = setup_handshake(
        &mut connector,
        &["github.read", "github.write", "github.admin"],
    )
    .await;

    let repository = connector
        .handle_invoke(json!({
            "operation": "github.get_repo",
            "input": { "owner": OWNER, "repo": REPO },
            "capability_token": generate_valid_token(&signing_key, &connector, "github.get_repo")
        }))
        .await
        .expect("read repository through loopback fixture");
    let issue = connector
        .handle_invoke(json!({
            "operation": "github.create_issue",
            "input": {
                "owner": OWNER,
                "repo": REPO,
                "title": "Local acceptance issue",
                "body": "Fixture-created issue"
            },
            "capability_token": generate_valid_token(
                &signing_key,
                &connector,
                "github.create_issue"
            )
        }))
        .await
        .expect("create issue through loopback fixture");
    let workflow = connector
        .handle_invoke(json!({
            "operation": "github.trigger_workflow",
            "input": {
                "owner": OWNER,
                "repo": REPO,
                "workflow_id": "ci.yml",
                "ref": "main"
            },
            "capability_token": generate_valid_token(
                &signing_key,
                &connector,
                "github.trigger_workflow"
            )
        }))
        .await
        .expect("trigger workflow through loopback fixture");

    let observations = fixture.observations();
    assert_eq!(observations.len(), 3);
    assert_eq!(observations[0].method, "GET");
    assert_eq!(observations[0].path, "/repos/octocat/hello-world");
    assert_eq!(observations[1].method, "POST");
    assert_eq!(observations[1].path, "/repos/octocat/hello-world/issues");
    assert_eq!(observations[2].method, "POST");
    assert_eq!(
        observations[2].path,
        "/repos/octocat/hello-world/actions/workflows/ci.yml/dispatches"
    );
    assert!(
        observations
            .iter()
            .all(ObservedGitHubRequest::credential_header_matches)
    );
    assert!(
        observations
            .iter()
            .all(ObservedGitHubRequest::github_api_version_seen)
    );

    let issue_body = observations[1].body_json();
    assert_eq!(issue_body["title"], "Local acceptance issue");
    assert_eq!(issue_body["body"], "Fixture-created issue");

    let workflow_body = observations[2].body_json();
    assert_eq!(workflow_body["ref"], "main");

    assert_eq!(repository["repository"]["full_name"], "octocat/hello-world");
    assert_eq!(issue["issue"]["number"], 43);
    assert_eq!(workflow["triggered"], true);

    let artifact = json!({
        "connector": CONNECTOR_ID,
        "fixture_id": FIXTURE_ID,
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "fixture_mode": "loopback_http",
        "operations": [
            "github.get_repo",
            "github.create_issue",
            "github.trigger_workflow"
        ],
        "requests_observed": observations.len(),
        "paths": observations.iter().map(|request| request.path.clone()).collect::<Vec<_>>(),
        "credential_header_seen": observations
            .iter()
            .all(ObservedGitHubRequest::credential_header_matches),
        "github_api_version_seen": observations
            .iter()
            .all(ObservedGitHubRequest::github_api_version_seen),
        "cleanup": "loopback_fixture_completed_expected_requests",
        "result": "passed"
    });
    println!("{artifact}");
}
