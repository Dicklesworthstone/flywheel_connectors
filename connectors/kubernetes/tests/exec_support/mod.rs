//! Real HTTP upgrade and remotecommand wire fixture shared by exec tests.

#![allow(dead_code)]

use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::mpsc::{self, Receiver},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use fcp_async_core::websocket::{HttpRequest, ServerHandshake};
use serde_json::{Value, json};

pub const PROTOCOL: &str = "v5.channel.k8s.io";

pub struct Observation {
    pub method: String,
    pub target: String,
    pub headers: HashMap<String, String>,
}

pub struct ExecScript {
    pub protocol: Option<&'static str>,
    pub wire: Vec<u8>,
    pub disconnect: bool,
    pub approved: bool,
    pub http_rejection: Option<u16>,
    pub containers: Vec<&'static str>,
}

impl ExecScript {
    pub fn success(stdout: &str, stderr: &str) -> Self {
        let mut script = Self::open();
        script.message(1, stdout.as_bytes());
        script.message(2, stderr.as_bytes());
        script.status(json!({"status": "Success"}));
        script.close();
        script
    }

    pub fn open() -> Self {
        Self { protocol: Some(PROTOCOL), wire: Vec::new(), disconnect: false, approved: true, http_rejection: None, containers: vec!["app"] }
    }

    pub fn message(&mut self, channel: u8, bytes: &[u8]) {
        let mut payload = Vec::with_capacity(bytes.len() + 1);
        payload.push(channel);
        payload.extend_from_slice(bytes);
        self.wire.extend(frame(2, &payload));
    }

    pub fn status(&mut self, value: Value) {
        self.message(3, value.to_string().as_bytes());
    }

    pub fn close(&mut self) {
        self.wire.extend(frame(8, &1000_u16.to_be_bytes()));
    }

    pub fn close_stream(&mut self, channel: u8) {
        self.wire.extend(frame(2, &[255, channel]));
    }
}

pub fn frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut wire = frame_header(opcode, payload.len());
    wire.extend_from_slice(payload);
    wire
}

pub fn frame_header(opcode: u8, length: usize) -> Vec<u8> {
    let mut wire = vec![0x80 | opcode];
    if length < 126 {
        wire.push(u8::try_from(length).unwrap());
    } else if length <= usize::from(u16::MAX) {
        wire.push(126);
        wire.extend_from_slice(&u16::try_from(length).unwrap().to_be_bytes());
    } else {
        wire.push(127);
        wire.extend_from_slice(&u64::try_from(length).unwrap().to_be_bytes());
    }
    wire
}

pub struct ExecServer {
    pub url: String,
    requests: Receiver<Observation>,
    disconnected: Receiver<()>,
    stop: Option<mpsc::Sender<()>>,
    worker: Option<JoinHandle<()>>,
}

impl ExecServer {
    pub fn start(script: ExecScript) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (sender, requests) = mpsc::channel();
        let (closed, disconnected) = mpsc::channel();
        let (stop, stopped) = mpsc::channel();
        let worker = thread::spawn(move || {
            let expires = Instant::now() + Duration::from_secs(30);
            while stopped.try_recv().is_err() {
                assert!(Instant::now() < expires, "exec fixture was not released");
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                        stream.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
                        let raw = read_request(&mut stream);
                        let request = HttpRequest::parse(&raw).unwrap();
                        let observation = observe(&raw);
                        let target = observation.target.clone();
                        sender.send(observation).unwrap();
                        if target.split('?').next().unwrap().ends_with("/exec") {
                            if let Some(status) = script.http_rejection {
                                write_http(&mut stream, status, json!({"message": "fixture exec refused"}));
                                continue;
                            }
                            let mut response = ServerHandshake::new().protocol(PROTOCOL).accept(&request).unwrap();
                            response.protocol = script.protocol.map(str::to_owned);
                            // Coalesce upgrade headers and first frames: the
                            // client must not discard post-header bytes.
                            let mut wire = response.response_bytes();
                            wire.extend_from_slice(&script.wire);
                            if let Err(error) = stream.write_all(&wire).and_then(|()| stream.flush()) {
                                assert!(matches!(error.kind(), std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset), "exec write failed: {error}");
                            }
                            if script.disconnect { continue; }
                            let mut ignored = [0_u8; 256];
                            loop {
                                match stream.read(&mut ignored) {
                                    Ok(0) => { let _ = closed.send(()); break; }
                                    Ok(_) => {}
                                    Err(error) if matches!(error.kind(), std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe) => { let _ = closed.send(()); break; }
                                    Err(error) => panic!("exec socket was not retired: {error}"),
                                }
                            }
                        } else {
                            let mut labels = json!({});
                            if script.approved { labels["fcp.flywheel.ai/exec-approved"] = json!("true"); }
                            let path = target.split('?').next().unwrap();
                            let name = percent_encoding::percent_decode_str(path.rsplit('/').next().unwrap()).decode_utf8().unwrap();
                            let containers: Vec<_> = script.containers.iter().map(|name| json!({"name": name, "image": "busybox"})).collect();
                            write_http(&mut stream, 200, json!({
                                "apiVersion": "v1", "kind": "Pod",
                                "metadata": {"name": name, "namespace": "default", "labels": labels},
                                "spec": {"containers": containers}
                            }));
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(3)),
                    Err(error) => panic!("exec accept failed: {error}"),
                }
            }
        });
        Self { url, requests, disconnected, stop: Some(stop), worker: Some(worker) }
    }

    pub fn observed(&self) -> Observation {
        self.requests.recv_timeout(Duration::from_secs(3)).expect("expected Kubernetes request")
    }

    pub fn no_request(&self) {
        assert!(self.requests.recv_timeout(Duration::from_millis(75)).is_err(), "exec was retried or reached the provider without admission");
    }

    pub fn wait_for_disconnect(&self) {
        self.disconnected.recv_timeout(Duration::from_secs(3)).expect("exec transport must be retired");
    }

    pub fn finish(mut self) {
        let _ = self.stop.take().unwrap().send(());
        self.worker.take().unwrap().join().unwrap();
    }
}

impl Drop for ExecServer {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() { let _ = stop.send(()); }
        if let Some(worker) = self.worker.take() { let _ = worker.join(); }
    }
}

fn read_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut raw = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let read = stream.read(&mut buffer).unwrap();
        assert!(read > 0, "closed before HTTP request");
        raw.extend_from_slice(&buffer[..read]);
        assert!(raw.len() <= 65_536, "unbounded fixture request");
        if raw.windows(4).any(|part| part == b"\r\n\r\n") { return raw; }
    }
}

fn observe(raw: &[u8]) -> Observation {
    let text = std::str::from_utf8(raw).unwrap();
    let mut lines = text.lines();
    let mut first = lines.next().unwrap().split_whitespace();
    let method = first.next().unwrap().to_owned();
    let target = first.next().unwrap().to_owned();
    let headers = lines.filter_map(|line| {
        let (name, value) = line.split_once(':')?;
        Some((name.to_ascii_lowercase(), value.trim().to_owned()))
    }).collect();
    Observation { method, target, headers }
}

fn write_http(stream: &mut TcpStream, status: u16, value: Value) {
    let body = value.to_string();
    let wire = format!("HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    stream.write_all(wire.as_bytes()).unwrap();
    stream.flush().unwrap();
}
