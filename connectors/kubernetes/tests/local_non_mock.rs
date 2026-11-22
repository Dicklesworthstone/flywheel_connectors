//! Local loopback acceptance coverage for the FCP Kubernetes connector.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread::{self, JoinHandle},
    time::Duration,
};

mod common;
use common::TestConnector as KubernetesConnector;
use serde_json::json;

const EXPECTED_PATH: &str = "/api/v1/namespaces/default/pods";
const RESPONSE_BODY: &str = r#"{
  "kind": "PodList",
  "items": [
    {
      "metadata": {
        "name": "fixture-pod",
        "namespace": "default"
      },
      "status": {
        "phase": "Running"
      }
    }
  ]
}"#;

#[derive(Debug)]
struct FixtureObservation {
    request_line: String,
    authorization_seen: bool,
}

struct LoopbackFixture {
    base_url: String,
    handle: Option<JoinHandle<FixtureObservation>>,
}

impl LoopbackFixture {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let address = listener.local_addr().expect("read listener address");
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept connector request");
            handle_request(stream)
        });

        Self {
            base_url: format!("http://{address}"),
            handle: Some(handle),
        }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn join(mut self) -> FixtureObservation {
        self.handle
            .take()
            .expect("fixture thread present")
            .join()
            .expect("fixture thread completed")
    }
}

fn handle_request(mut stream: TcpStream) -> FixtureObservation {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");

    let mut buffer = [0_u8; 4096];
    let bytes_read = stream.read(&mut buffer).expect("read connector request");
    let request = String::from_utf8_lossy(&buffer[..bytes_read]);
    let request_line = request.lines().next().unwrap_or_default().to_string();
    let authorization_seen = request
        .lines()
        .any(|line| line.eq_ignore_ascii_case("authorization: bearer test-k8s-token"));

    write!(
        stream,
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        RESPONSE_BODY.len(),
        RESPONSE_BODY
    )
    .expect("write connector response");

    FixtureObservation {
        request_line,
        authorization_seen,
    }
}

#[fcp_async_core::runtime::test]
async fn loopback_list_pods_uses_production_client_request() {
    let fixture = LoopbackFixture::start();
    let mut connector = KubernetesConnector::new();

    connector
        .handle_configure(json!({
            "bearer_token": "test-k8s-token",
            "base_url": fixture.base_url(),
            "allowed_namespaces": ["default"]
        }))
        .await
        .expect("configure connector");
    connector
        .handle_handshake(json!({"session_id": "local-non-mock"}))
        .await
        .expect("handshake connector");

    let result = connector
        .handle_invoke(json!({
            "operation_id": "kubernetes.list_pods",
            "input": {"namespace": "default"}
        }))
        .await
        .expect("list pods through connector");
    let observation = fixture.join();

    assert_eq!(
        observation.request_line,
        format!("GET {EXPECTED_PATH} HTTP/1.1")
    );
    assert!(observation.authorization_seen);
    assert_eq!(result["pods"][0]["metadata"]["name"], "fixture-pod");
    assert_eq!(result["pods"][0]["status"]["phase"], "Running");

    let artifact = json!({
        "connector": "kubernetes",
        "suite_class": "local_non_mock",
        "acceptance_suite_class": "local_non_mock",
        "fixture_mode": "loopback_http",
        "operation": "kubernetes.list_pods",
        "method": "GET",
        "path": EXPECTED_PATH,
        "request_line": observation.request_line,
        "authorization_seen": observation.authorization_seen,
        "cleanup": "fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}
