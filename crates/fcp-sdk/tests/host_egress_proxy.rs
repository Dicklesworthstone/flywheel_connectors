#![cfg(feature = "connector-http")]

use std::io::{Error, ErrorKind, Read, Write};
use std::net::TcpListener;
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use chrono::{SecondsFormat, Utc};
use fcp_manifest::{
    Base64Bytes, HostEgressContext, HostEgressDecisionMetadata, HostEgressHttpHeader,
    HostEgressHttpRequest, HostEgressHttpResponse, HostEgressTcpRequest, HostEgressTcpResponse,
};
#[cfg(unix)]
use fcp_sdk::migration::HostEgressProxyClient;
use fcp_sdk::migration::HostEgressProxyError;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use serde_json::{Value, json};

const CONNECTOR_ID: &str = "fcp.test.b0qqv-sdk:utility:1.0.0";
const ZONE_ID: &str = "z:work";
const CAPABILITY_MATERIAL_SENTINEL: &str = "capability-material-b0qqv-redaction-sentinel";
const CREDENTIAL_ID_SENTINEL: &str = "credential-b0qqv-redaction-sentinel";
const HEADER_SENTINEL: &str = "header-b0qqv-redaction-sentinel";
const BODY_SENTINEL: &str = "body-b0qqv-redaction-sentinel";
const URL_SENTINEL: &str = "url-b0qqv-redaction-sentinel";
const TARGET_URL: &str =
    "https://api.example.test/v1/messages?proof_marker=url-b0qqv-redaction-sentinel";
const TARGET_HOST: &str = "api.example.test";

#[derive(Debug)]
struct CapturedProxyRequest {
    method: String,
    path: String,
    body: Value,
}

struct OneShotProxy {
    base_url: String,
    receiver: Receiver<Result<CapturedProxyRequest, String>>,
    handle: JoinHandle<()>,
}

impl OneShotProxy {
    fn start(status: u16, body: String, content_type: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback proxy");
        let base_url = format!("http://{}", listener.local_addr().expect("proxy address"));
        let (sender, receiver) = mpsc::channel();
        let handle = thread::spawn(move || {
            let result = serve_one_proxy_request(&listener, status, &body, content_type)
                .map_err(|error| error.to_string());
            let _ = sender.send(result);
        });
        Self {
            base_url,
            receiver,
            handle,
        }
    }

    fn start_json(status: u16, body: &Value) -> Self {
        Self::start(
            status,
            serde_json::to_string(body).expect("serialize proxy response JSON"),
            "application/json",
        )
    }

    fn start_text(status: u16, body: String) -> Self {
        Self::start(status, body, "text/plain; charset=utf-8")
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn capture(self) -> CapturedProxyRequest {
        let captured = self
            .receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("proxy must capture a request")
            .expect("proxy request must parse");
        self.handle.join().expect("proxy thread must finish");
        captured
    }
}

fn serve_one_proxy_request(
    listener: &TcpListener,
    status: u16,
    response_body: &str,
    content_type: &str,
) -> std::io::Result<CapturedProxyRequest> {
    let (mut stream, _) = listener.accept()?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let captured = read_proxy_request(&mut stream)?;
    write_proxy_response(&mut stream, status, response_body, content_type)?;
    Ok(captured)
}

fn read_proxy_request(stream: &mut impl Read) -> std::io::Result<CapturedProxyRequest> {
    let mut header_bytes = Vec::new();
    let mut byte = [0_u8; 1];
    while !header_bytes.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte)? == 0 {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "connection closed before HTTP headers completed",
            ));
        }
        header_bytes.push(byte[0]);
        if header_bytes.len() > 16_384 {
            return Err(Error::new(ErrorKind::InvalidData, "HTTP headers too large"));
        }
    }

    let headers = String::from_utf8(header_bytes)
        .map_err(|error| Error::new(ErrorKind::InvalidData, error))?;
    let request_line = headers
        .lines()
        .next()
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing request line"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing HTTP method"))?
        .to_string();
    let path = parts
        .next()
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing HTTP path"))?
        .to_string();
    let content_length = content_length_from_headers(&headers)?;
    let mut body_bytes = vec![0_u8; content_length];
    stream.read_exact(&mut body_bytes)?;
    let raw_body = String::from_utf8_lossy(&body_bytes).into_owned();
    let body = serde_json::from_str(&raw_body)
        .map_err(|error| Error::new(ErrorKind::InvalidData, error))?;

    Ok(CapturedProxyRequest { method, path, body })
}

fn content_length_from_headers(headers: &str) -> std::io::Result<usize> {
    headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>())
        })
        .transpose()
        .map_err(|error| Error::new(ErrorKind::InvalidData, error))?
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing content-length header"))
}

fn write_proxy_response(
    stream: &mut impl Write,
    status: u16,
    body: &str,
    content_type: &str,
) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 {status} {}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        reason_phrase(status),
        body.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

const fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        403 => "Forbidden",
        413 => "Payload Too Large",
        504 => "Gateway Timeout",
        _ => "Status",
    }
}

fn context(operation_id: &str, request_id: &str, correlation_id: &str) -> HostEgressContext {
    HostEgressContext {
        connector_id: CONNECTOR_ID.to_string(),
        operation_id: operation_id.to_string(),
        zone_id: ZONE_ID.to_string(),
        request_id: request_id.to_string(),
        correlation_id: Some(correlation_id.to_string()),
        capability_token_cbor_b64: CAPABILITY_MATERIAL_SENTINEL.to_string(),
    }
}

fn http_request(request_id: &str, correlation_id: &str) -> HostEgressHttpRequest {
    HostEgressHttpRequest {
        context: context("messages.create", request_id, correlation_id),
        url: TARGET_URL.to_string(),
        method: "POST".to_string(),
        headers: vec![
            HostEgressHttpHeader {
                name: "authorization".to_string(),
                value: format!("Bearer {HEADER_SENTINEL}"),
            },
            HostEgressHttpHeader {
                name: "x-fcp-correlation".to_string(),
                value: correlation_id.to_string(),
            },
        ],
        body: Some(Base64Bytes::from_vec(BODY_SENTINEL.as_bytes().to_vec())),
        credential_id: Some(CREDENTIAL_ID_SENTINEL.to_string()),
    }
}

fn tcp_request(request_id: &str, correlation_id: &str) -> HostEgressTcpRequest {
    HostEgressTcpRequest {
        context: context("socket.exchange", request_id, correlation_id),
        host: TARGET_HOST.to_string(),
        port: 443,
        tls: true,
        sni_override: Some(TARGET_HOST.to_string()),
        write: Some(Base64Bytes::from_vec(BODY_SENTINEL.as_bytes().to_vec())),
        read_limit_bytes: Some(4096),
        credential_id: Some(CREDENTIAL_ID_SENTINEL.to_string()),
    }
}

fn decision_metadata(
    context: &HostEgressContext,
    resolved_host: &str,
    resolved_port: u16,
) -> HostEgressDecisionMetadata {
    HostEgressDecisionMetadata {
        connector_id: context.connector_id.clone(),
        operation_id: context.operation_id.clone(),
        zone_id: context.zone_id.clone(),
        request_id: context.request_id.clone(),
        correlation_id: context.correlation_id.clone(),
        execution_mode: "host_egress_proxy".to_string(),
        constraint_source: "manifest.network_constraints".to_string(),
        decision: "allow".to_string(),
        resolved_host: resolved_host.to_string(),
        resolved_port,
        credential_injected: true,
        elapsed_ms: 3,
    }
}

fn http_response(request: &HostEgressHttpRequest) -> Value {
    serde_json::to_value(HostEgressHttpResponse {
        status: 202,
        headers: vec![HostEgressHttpHeader {
            name: "content-type".to_string(),
            value: "application/json".to_string(),
        }],
        body: Base64Bytes::from_vec(br#"{"accepted":true}"#.to_vec()),
        egress: decision_metadata(&request.context, TARGET_HOST, 443),
    })
    .expect("serialize HTTP response contract")
}

fn tcp_response(request: &HostEgressTcpRequest) -> Value {
    serde_json::to_value(HostEgressTcpResponse {
        bytes_written: request
            .write
            .as_ref()
            .map_or(0, |payload| payload.as_bytes().len() as u64),
        bytes_read: 4,
        read: Base64Bytes::from_vec(b"PONG".to_vec()),
        egress: decision_metadata(&request.context, &request.host, request.port),
    })
    .expect("serialize TCP response contract")
}

fn runtime_for_proxy(proxy: &OneShotProxy) -> ConnectorRuntime {
    ConnectorRuntime::new(
        ConnectorRuntimeConfig::default().with_host_egress_proxy_url(proxy.base_url()),
    )
}

fn assert_no_secret_material(text: &str) {
    for secret in [
        CAPABILITY_MATERIAL_SENTINEL,
        CREDENTIAL_ID_SENTINEL,
        HEADER_SENTINEL,
        BODY_SENTINEL,
        URL_SENTINEL,
        TARGET_URL,
    ] {
        assert!(!text.contains(secret), "secret material leaked: {secret}");
    }
}

fn emit_jsonl_record(record: &Value) {
    let line = serde_json::to_string(&record).expect("serialize SDK e2e JSONL record");
    assert_no_secret_material(&line);
    println!("RUNTIME_NETWORK_POLICY_E2E_JSONL {line}");
}

fn timestamp() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn elapsed_ms(started_at: Instant) -> u128 {
    started_at.elapsed().as_millis()
}

#[cfg(unix)]
struct UnixProxy {
    socket_path: std::path::PathBuf,
    receiver: Receiver<Result<CapturedProxyRequest, String>>,
    handle: Option<JoinHandle<()>>,
}

#[cfg(unix)]
impl UnixProxy {
    fn start(prefix: Vec<u8>, pause: Duration, suffix: Vec<u8>) -> Self {
        use std::os::unix::net::UnixListener;

        // Unix socket paths are short on macOS; its default TMPDIR can already
        // consume most of that limit. Include literal percent escapes to catch
        // accidental URL decoding.
        let socket_path = std::path::Path::new("/tmp").join(format!(
            "fcp-egress-{}-%20.sock",
            uuid::Uuid::new_v4().simple()
        ));
        let listener = UnixListener::bind(&socket_path).expect("bind Unix proxy");
        listener.set_nonblocking(true).expect("bounded Unix accept");
        let (sender, receiver) = mpsc::channel();
        let handle = thread::spawn(move || {
            let result = (|| -> std::io::Result<CapturedProxyRequest> {
                let deadline = Instant::now() + Duration::from_secs(5);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == ErrorKind::WouldBlock => {
                            if Instant::now() >= deadline {
                                return Err(Error::new(ErrorKind::TimedOut, "Unix proxy accept"));
                            }
                            thread::sleep(Duration::from_millis(1));
                        }
                        Err(error) => return Err(error),
                    }
                };
                stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                stream.set_write_timeout(Some(Duration::from_secs(5)))?;
                let captured = read_proxy_request(&mut stream)?;
                stream.write_all(&prefix)?;
                if !pause.is_zero() {
                    thread::sleep(pause);
                }
                // A deadline or size rejection may already have closed the client.
                let _ = stream.write_all(&suffix);
                Ok(captured)
            })()
            .map_err(|error| error.to_string());
            let _ = sender.send(result);
        });
        Self {
            socket_path,
            receiver,
            handle: Some(handle),
        }
    }

    fn start_json(body: &Value) -> Self {
        let mut response = Vec::new();
        write_proxy_response(
            &mut response,
            200,
            &serde_json::to_string(body).expect("Unix response JSON"),
            "application/json",
        )
        .expect("encode Unix response");
        Self::start(response, Duration::ZERO, Vec::new())
    }

    fn endpoint(&self, with_scheme: bool) -> String {
        let path = self.socket_path.to_str().expect("UTF-8 socket path");
        if with_scheme {
            format!("unix://{path}")
        } else {
            path.to_string()
        }
    }

    fn capture(mut self) -> CapturedProxyRequest {
        let captured = self
            .receiver
            .recv_timeout(Duration::from_secs(6))
            .expect("Unix proxy must capture a request")
            .expect("Unix proxy request must parse");
        self.handle
            .take()
            .expect("Unix proxy thread")
            .join()
            .expect("Unix proxy finish");
        captured
    }
}

#[cfg(unix)]
impl Drop for UnixProxy {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

#[cfg(unix)]
#[test]
fn host_egress_proxy_unix_routes_http_and_tcp_with_exact_authority() {
    fcp_async_core::runtime::block_on_sync(async {
        for with_scheme in [true, false] {
            let http_request = http_request("unix-http", "unix-http-correlation");
            let proxy = UnixProxy::start_json(&http_response(&http_request));
            let runtime = ConnectorRuntime::new(
                ConnectorRuntimeConfig::default()
                    .with_host_egress_proxy_url(proxy.endpoint(with_scheme)),
            );
            let client = runtime
                .host_egress_proxy_client()
                .expect("Unix config")
                .expect("Unix client");
            let response = client
                .http(&http_request)
                .await
                .expect("HTTP over Unix socket");
            assert_eq!(response.status, 202);
            let captured = proxy.capture();
            assert_eq!(captured.method, "POST");
            assert_eq!(captured.path, "/rpc/egress/http");
            assert_eq!(
                captured.body,
                serde_json::to_value(&http_request).expect("HTTP request")
            );

            let tcp_request = tcp_request("unix-tcp", "unix-tcp-correlation");
            let proxy = UnixProxy::start_json(&tcp_response(&tcp_request));
            let client =
                HostEgressProxyClient::new(proxy.endpoint(with_scheme)).expect("Unix client");
            let response = client
                .tcp(&tcp_request)
                .await
                .expect("TCP relay over Unix socket");
            assert_eq!(response.read.as_bytes(), b"PONG");
            let captured = proxy.capture();
            assert_eq!(captured.path, "/rpc/egress/tcp");
            assert_eq!(
                captured.body,
                serde_json::to_value(&tcp_request).expect("TCP request")
            );
        }
    })
    .expect("Unix egress runtime");
}

#[cfg(unix)]
#[test]
fn host_egress_proxy_unix_rejects_cross_request_authority_and_redirects() {
    fcp_async_core::runtime::block_on_sync(async {
        let request = http_request("unix-authority", "unix-authority-correlation");
        let mut other = http_response(&request);
        other["egress"]["request_id"] = json!("another-request");
        let proxy = UnixProxy::start_json(&other);
        let client = HostEgressProxyClient::new(proxy.endpoint(true)).expect("Unix client");
        let error = client.http(&request).await.expect_err("cross-request result rejected");
        assert!(matches!(error, HostEgressProxyError::InvalidResponse(_)));
        assert_no_secret_material(&format!("{error:?} {error}"));
        proxy.capture();

        let destination = TcpListener::bind("127.0.0.1:0").expect("redirect destination");
        destination.set_nonblocking(true).expect("nonblocking destination");
        let response = format!(
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{}/steal\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            destination.local_addr().expect("redirect address")
        );
        let proxy = UnixProxy::start(response.into_bytes(), Duration::ZERO, Vec::new());
        let client = HostEgressProxyClient::new(proxy.endpoint(true)).expect("Unix client");
        let error = client.http(&request).await.expect_err("Unix redirect rejected");
        assert_eq!(error.status(), Some(307));
        assert_eq!(destination.accept().expect_err("redirect not contacted").kind(), ErrorKind::WouldBlock);
        proxy.capture();
    }).expect("Unix rejection runtime");
}

#[cfg(unix)]
#[test]
fn host_egress_proxy_unix_keeps_body_deadlines_and_size_bounds() {
    fcp_async_core::runtime::block_on_sync(async {
        let request = http_request("unix-bounds", "unix-bounds-correlation");
        let proxy = UnixProxy::start(
            b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n".to_vec(),
            Duration::ZERO,
            Vec::new(),
        );
        let client = HostEgressProxyClient::new(proxy.endpoint(true))
            .expect("Unix client")
            .with_max_response_bytes(1024)
            .expect("response bound");
        let error = client
            .http(&request)
            .await
            .expect_err("Unix oversized body rejected");
        assert!(matches!(
            error,
            HostEgressProxyError::ResponseTooLarge { .. }
        ));
        proxy.capture();

        let body = serde_json::to_vec(&http_response(&request)).expect("response JSON");
        let prefix = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
        let proxy = UnixProxy::start(prefix.into_bytes(), Duration::from_millis(400), body);
        let mut config =
            ConnectorRuntimeConfig::default().with_host_egress_proxy_url(proxy.endpoint(false));
        config.request_timeout = Duration::from_millis(100);
        let runtime = ConnectorRuntime::new(config);
        let client = runtime
            .host_egress_proxy_client()
            .expect("Unix config")
            .expect("Unix client");
        let error = client
            .http(&request)
            .await
            .expect_err("Unix body deadline enforced");
        assert!(matches!(&error, HostEgressProxyError::Transport(error) if error.is_timeout()));
        assert_no_secret_material(&format!("{error:?} {error}"));
        proxy.capture();
    })
    .expect("Unix bounded response runtime");
}

#[cfg(unix)]
#[test]
fn host_egress_proxy_missing_unix_socket_does_not_contact_target() {
    fcp_async_core::runtime::block_on_sync(async {
        let target = TcpListener::bind("127.0.0.1:0").expect("target listener");
        target.set_nonblocking(true).expect("nonblocking target");
        let mut request = http_request("unix-missing", "unix-missing-correlation");
        request.url = format!(
            "http://{}/target",
            target.local_addr().expect("target address")
        );
        let missing = std::path::Path::new("/tmp").join(format!(
            "fcp-missing-{}.sock",
            uuid::Uuid::new_v4().simple()
        ));
        let endpoint = format!("unix://{}", missing.display());
        let client = HostEgressProxyClient::new(&endpoint)
            .expect("valid socket endpoint")
            .with_timeout(Duration::from_secs(1))
            .expect("bounded missing socket");
        let error = client
            .http(&request)
            .await
            .expect_err("missing Unix socket rejected");
        assert!(matches!(error, HostEgressProxyError::Transport(_)));
        assert_no_secret_material(&format!("{error:?} {error}"));
        assert!(!format!("{client:?}").contains(&endpoint));
        assert_eq!(
            target.accept().expect_err("target not contacted").kind(),
            ErrorKind::WouldBlock
        );
    })
    .expect("missing Unix socket runtime");
}

#[test]
#[allow(clippy::too_many_lines)]
fn host_egress_proxy_sdk_loopback_e2e_jsonl_matrix() {
    fcp_async_core::runtime::block_on_sync(async {
        let http_started_at = Instant::now();
        let http_request = http_request("req-b0qqv-sdk-http", "corr-b0qqv-sdk-http");
        let http_proxy = OneShotProxy::start_json(200, &http_response(&http_request));
        let http_runtime = runtime_for_proxy(&http_proxy);
        let http_client = http_runtime
            .host_egress_proxy_client()
            .expect("valid HTTP host egress configuration")
            .expect("configured HTTP host egress client");
        let http_response = http_client
            .http(&http_request)
            .await
            .expect("HTTP helper must route through proxy");
        let http_capture = http_proxy.capture();

        assert_eq!(http_capture.method, "POST");
        assert_eq!(http_capture.path, "/rpc/egress/http");
        assert_eq!(http_capture.body["url"], TARGET_URL);
        assert_eq!(http_capture.body["method"], "POST");
        assert_eq!(http_capture.body["credential_id"], CREDENTIAL_ID_SENTINEL);
        assert_eq!(
            http_capture.body["context"]["request_id"],
            "req-b0qqv-sdk-http"
        );
        assert_eq!(
            http_capture.body["context"]["correlation_id"],
            "corr-b0qqv-sdk-http"
        );
        assert_eq!(
            http_capture.body["body"],
            "base64:Ym9keS1iMHFxdi1yZWRhY3Rpb24tc2VudGluZWw="
        );
        assert_eq!(http_response.status, 202);
        assert_eq!(http_response.egress.request_id, "req-b0qqv-sdk-http");
        assert_eq!(
            http_response.egress.correlation_id.as_deref(),
            Some("corr-b0qqv-sdk-http")
        );

        emit_jsonl_record(&json!({
            "timestamp": timestamp(),
            "test_name": "br_b0qqv_sdk_host_egress_proxy_e2e_jsonl_matrix",
            "module": "fcp-sdk",
            "phase": "sdk_host_egress_proxy",
            "scenario_id": "sdk_https_proxy_routing",
            "correlation_id": "corr-b0qqv-sdk-http",
            "result": "pass",
            "duration_ms": elapsed_ms(http_started_at),
            "assertions": {"passed": 12, "failed": 0},
            "details": {
                "connector_id": CONNECTOR_ID,
                "operation": "messages.create",
                "zone_id": ZONE_ID,
                "request_id": "req-b0qqv-sdk-http",
                "host": TARGET_HOST,
                "port": 443,
                "transport": "https",
                "decision": "allow",
                "deny_reason": null,
                "elapsed_ms": http_response.egress.elapsed_ms,
                "proxy_endpoint_path": http_capture.path,
                "captured_proxy_requests": 1,
                "target_reached_directly": false,
                "runtime_network_enforcement": "host_egress_proxy",
                "serialized_fields": {
                    "credential_id_present": true,
                    "request_id_preserved": true,
                    "correlation_id_preserved": true,
                    "headers_preserved": true,
                    "body_base64_preserved": true
                },
                "redaction_checks": {
                    "raw_body_logged": false,
                    "credential_secret_leaked": false,
                    "token_leaked": false,
                    "pii_leaked": false
                }
            }
        }));

        let tcp_started_at = Instant::now();
        let tcp_request = tcp_request("req-b0qqv-sdk-tcp", "corr-b0qqv-sdk-tcp");
        let tcp_proxy = OneShotProxy::start_json(200, &tcp_response(&tcp_request));
        let tcp_runtime = runtime_for_proxy(&tcp_proxy);
        let tcp_client = tcp_runtime
            .host_egress_proxy_client()
            .expect("valid TCP host egress configuration")
            .expect("configured TCP host egress client");
        let tcp_response = tcp_client
            .tcp(&tcp_request)
            .await
            .expect("TCP helper must route through proxy");
        let tcp_capture = tcp_proxy.capture();

        assert_eq!(tcp_capture.method, "POST");
        assert_eq!(tcp_capture.path, "/rpc/egress/tcp");
        assert_eq!(tcp_capture.body["host"], TARGET_HOST);
        assert_eq!(tcp_capture.body["port"], 443);
        assert_eq!(tcp_capture.body["tls"], true);
        assert_eq!(tcp_capture.body["sni_override"], TARGET_HOST);
        assert_eq!(tcp_capture.body["read_limit_bytes"], 4096);
        assert_eq!(tcp_capture.body["credential_id"], CREDENTIAL_ID_SENTINEL);
        assert_eq!(
            tcp_capture.body["context"]["request_id"],
            "req-b0qqv-sdk-tcp"
        );
        assert_eq!(
            tcp_capture.body["context"]["correlation_id"],
            "corr-b0qqv-sdk-tcp"
        );
        assert_eq!(
            tcp_capture.body["write"],
            "base64:Ym9keS1iMHFxdi1yZWRhY3Rpb24tc2VudGluZWw="
        );
        assert_eq!(tcp_response.read.as_bytes(), b"PONG");
        assert_eq!(tcp_response.egress.request_id, "req-b0qqv-sdk-tcp");

        emit_jsonl_record(&json!({
            "timestamp": timestamp(),
            "test_name": "br_b0qqv_sdk_host_egress_proxy_e2e_jsonl_matrix",
            "module": "fcp-sdk",
            "phase": "sdk_host_egress_proxy",
            "scenario_id": "sdk_tls_tcp_proxy_routing",
            "correlation_id": "corr-b0qqv-sdk-tcp",
            "result": "pass",
            "duration_ms": elapsed_ms(tcp_started_at),
            "assertions": {"passed": 13, "failed": 0},
            "details": {
                "connector_id": CONNECTOR_ID,
                "operation": "socket.exchange",
                "zone_id": ZONE_ID,
                "request_id": "req-b0qqv-sdk-tcp",
                "host": TARGET_HOST,
                "port": 443,
                "transport": "tcp_tls",
                "decision": "allow",
                "deny_reason": null,
                "elapsed_ms": tcp_response.egress.elapsed_ms,
                "proxy_endpoint_path": tcp_capture.path,
                "captured_proxy_requests": 1,
                "target_reached_directly": false,
                "runtime_network_enforcement": "host_egress_proxy",
                "serialized_fields": {
                    "sni_preserved": true,
                    "request_id_preserved": true,
                    "correlation_id_preserved": true,
                    "read_limit_preserved": true,
                    "binary_write_base64_preserved": true
                },
                "redaction_checks": {
                    "raw_write_logged": false,
                    "credential_secret_leaked": false,
                    "token_leaked": false,
                    "pii_leaked": false
                }
            }
        }));
    })
    .expect("SDK host-egress proxy loopback matrix must complete");
}

struct DenialCase {
    reason: &'static str,
    status: u16,
    use_tcp: bool,
}

#[test]
#[allow(clippy::too_many_lines)]
fn host_egress_proxy_denied_decision_matrix_surfaces_structured_redacted_errors() {
    fcp_async_core::runtime::block_on_sync(async {
        let started_at = Instant::now();
        let cases = [
            DenialCase {
                reason: "denied_host",
                status: 403,
                use_tcp: false,
            },
            DenialCase {
                reason: "denied_port",
                status: 403,
                use_tcp: false,
            },
            DenialCase {
                reason: "denied_private_ip",
                status: 403,
                use_tcp: false,
            },
            DenialCase {
                reason: "denied_sni_spki",
                status: 403,
                use_tcp: true,
            },
            DenialCase {
                reason: "credential_denied",
                status: 403,
                use_tcp: false,
            },
            DenialCase {
                reason: "timeout",
                status: 504,
                use_tcp: false,
            },
            DenialCase {
                reason: "response_size",
                status: 413,
                use_tcp: false,
            },
        ];
        let mut statuses = Vec::new();
        let mut reasons = Vec::new();
        let mut paths = Vec::new();

        for case in cases {
            let body = if case.use_tcp {
                format!(
                    "deny_reason={}; capability_material={CAPABILITY_MATERIAL_SENTINEL}; credential={CREDENTIAL_ID_SENTINEL}; payload={BODY_SENTINEL}",
                    case.reason
                )
            } else {
                format!(
                    "deny_reason={}; capability_material={CAPABILITY_MATERIAL_SENTINEL}; credential={CREDENTIAL_ID_SENTINEL}; header={HEADER_SENTINEL}; payload={BODY_SENTINEL}; url={TARGET_URL}",
                    case.reason
                )
            };
            let proxy = OneShotProxy::start_text(case.status, body);
            let runtime = runtime_for_proxy(&proxy);
            let client = runtime
                .host_egress_proxy_client()
                .expect("valid denial proxy configuration")
                .expect("configured denial proxy client");

            let error = if case.use_tcp {
                let request = tcp_request("req-b0qqv-denied-tcp", "corr-b0qqv-denied");
                client
                    .tcp(&request)
                    .await
                    .expect_err("TCP denial must surface as proxy rejection")
            } else {
                let request = http_request("req-b0qqv-denied-http", "corr-b0qqv-denied");
                client
                    .http(&request)
                    .await
                    .expect_err("HTTP denial must surface as proxy rejection")
            };
            let captured = proxy.capture();
            let rejection_body = assert_rejected(&error, case.status, case.reason);
            assert_no_secret_material(&rejection_body);
            statuses.push(json!({"reason": case.reason, "status": case.status}));
            reasons.push(case.reason);
            paths.push(captured.path);
        }

        emit_jsonl_record(&json!({
            "timestamp": timestamp(),
            "test_name": "br_b0qqv_sdk_host_egress_proxy_e2e_jsonl_matrix",
            "module": "fcp-sdk",
            "phase": "sdk_host_egress_proxy",
            "scenario_id": "sdk_denied_structured_error",
            "correlation_id": "corr-b0qqv-denied",
            "result": "pass",
            "duration_ms": elapsed_ms(started_at),
            "assertions": {"passed": 28, "failed": 0},
            "details": {
                "connector_id": CONNECTOR_ID,
                "operation": "messages.create",
                "zone_id": ZONE_ID,
                "request_id": "req-b0qqv-denied-http",
                "host": TARGET_HOST,
                "port": 443,
                "transport": "https_and_tcp_tls",
                "decision": "deny",
                "deny_reason": "matrix",
                "denied_cases": reasons,
                "statuses": statuses,
                "proxy_endpoint_paths": paths,
                "elapsed_ms": elapsed_ms(started_at),
                "structured_error_fields": ["status", "redacted_body"],
                "runtime_network_enforcement": "host_egress_proxy"
            }
        }));

        emit_jsonl_record(&json!({
            "timestamp": timestamp(),
            "test_name": "br_b0qqv_sdk_host_egress_proxy_e2e_jsonl_matrix",
            "module": "fcp-sdk",
            "phase": "sdk_host_egress_proxy",
            "scenario_id": "sdk_redaction_scan",
            "correlation_id": "corr-b0qqv-redaction-scan",
            "result": "pass",
            "duration_ms": elapsed_ms(started_at),
            "assertions": {"passed": 7, "failed": 0},
            "details": {
                "connector_id": CONNECTOR_ID,
                "operation": "messages.create",
                "zone_id": ZONE_ID,
                "request_id": "req-b0qqv-denied-http",
                "host": TARGET_HOST,
                "port": 443,
                "transport": "https_and_tcp_tls",
                "decision": "deny",
                "deny_reason": "redaction_scan",
                "secret_sentinels_absent": true,
                "checked_error_count": 7,
                "checked_fields": [
                    "capability_token",
                    "credential_id",
                    "authorization_header",
                    "request_body",
                    "base64_body",
                    "target_url",
                    "query_token"
                ],
                "elapsed_ms": elapsed_ms(started_at)
            }
        }));
    })
    .expect("SDK host-egress denial matrix must complete");
}

fn assert_rejected(error: &HostEgressProxyError, status: u16, reason: &str) -> String {
    assert_eq!(error.status(), Some(status));
    let body = error
        .rejection_body()
        .expect("rejection body must be present")
        .to_string();
    assert!(
        body.contains(&format!("deny_reason={reason}")),
        "rejection body should keep actionable reason {reason}: {body}"
    );
    body
}
