//! Pull an explicitly authorized root into a host-owned connector-state replica.
//!
//! Explicit fallback donors form one bounded host-side recovery plan. The CLI
//! still sends exactly one request to the selected recipient, never retries an
//! ambiguous response, and validates the complete ordered attempt receipt.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Result;
use clap::Args;
use fcp_core::{ConnectorId, InstanceId, ObjectId, TailscaleNodeId, ZoneId};
use fcp_host::{
    CONNECTOR_STATE_RECOVERY_SCHEMA_VERSION, CONNECTOR_STATE_TRANSFER_SCHEMA_VERSION,
    ConnectorStateExportRequest, ConnectorStateRecoveryOutcome, ConnectorStateRecoveryRequest,
    ConnectorStateRecoveryResponse,
    ConnectorStatePullRequest, ConnectorStatePullResponse, ConnectorStateTransferLimits,
    ConnectorStateTransferScope, MAX_CONNECTOR_STATE_EXPORT_REQUEST_BYTES,
    MAX_CONNECTOR_STATE_TRANSFER_CANONICAL_BYTES, MAX_CONNECTOR_STATE_TRANSFER_OBJECTS,
    MAX_CONNECTOR_STATE_TRANSFER_WIRE_BYTES,
    MAX_CONNECTOR_STATE_RECOVERY_CANDIDATES, MAX_CONNECTOR_STATE_RECOVERY_REQUEST_BYTES,
    MAX_CONNECTOR_STATE_RECOVERY_TIMEOUT_MS,
};
use serde::Serialize;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::{
    CliExitCode, CommandAvailability, CommandEnvelope, DispatchOutcome, HostAdminClient,
    KnowledgeState, inject_truth_source_metadata, resolve_host_config, sha256_prefixed,
};

const ADMIN_TOKEN_ENV: &str = "FCP_HOST_ADMIN_BEARER_TOKEN";
const MAX_ADMIN_TOKEN_BYTES: u64 = 65_536;
const MAX_PULL_RESPONSE_BYTES: u64 = 16 * 1024;
const MAX_PULL_TIMEOUT_MS: u64 = 300_000;

#[derive(Args, Debug, Serialize)]
pub(crate) struct ConnectorStatePullArgs {
    /// Exact canonical connector ID; local installation is not required.
    #[arg(long)]
    connector: String,

    /// Exact state zone authorized by both peers' transfer grants.
    #[arg(long)]
    zone: String,

    /// Configured donor node ID, not a URL.
    #[arg(long)]
    peer: String,

    /// Exact grant ID configured independently at donor and recipient.
    #[arg(long)]
    grant: String,

    /// Additional donor and independent grant, as PEER=GRANT, in attempt order.
    ///
    /// Repeat at most seven times. Every donor must authorize the same root,
    /// scope and limits. Only failed downloads may move to the next donor;
    /// import failures and ambiguous recipient responses are never retried.
    #[arg(long, value_name = "PEER=GRANT")]
    fallback: Vec<String>,

    /// Complete-download deadline per donor when --fallback is present.
    ///
    /// Defaults to the smaller of 10000 and --timeout-ms. Must not exceed the
    /// total deadline. This is not a fresh timeout for each page.
    #[arg(long, requires = "fallback", value_parser = clap::value_parser!(u64).range(1..=MAX_CONNECTOR_STATE_RECOVERY_TIMEOUT_MS))]
    attempt_timeout_ms: Option<u64>,

    /// Trusted root object ID, as 64 hexadecimal digits or objectid:<hex>.
    #[arg(long)]
    root: String,

    /// Exact instance authorized by the grants; omit only for unscoped state.
    #[arg(long)]
    instance: Option<String>,

    /// Upper bound on state objects plus their root; may only narrow the grant.
    #[arg(long, default_value_t = MAX_CONNECTOR_STATE_TRANSFER_OBJECTS)]
    max_objects: usize,

    /// Upper bound on canonical headers and bodies; may only narrow the grant.
    #[arg(long, default_value_t = MAX_CONNECTOR_STATE_TRANSFER_CANONICAL_BYTES)]
    max_canonical_bytes: usize,

    /// Upper bound on the donor's complete JSON export response.
    #[arg(long, default_value_t = MAX_CONNECTOR_STATE_TRANSFER_WIRE_BYTES)]
    max_wire_bytes: usize,

    /// Deadline through response consumption, in milliseconds.
    ///
    /// With --fallback, also bounds the entire host recovery plan and must be
    /// at most 60000. A timeout does not prove that replica import did not occur.
    #[arg(long, default_value_t = 30_000, value_parser = clap::value_parser!(u64).range(1..=MAX_PULL_TIMEOUT_MS))]
    timeout_ms: u64,

    /// Read the selected host's admin bearer secret from this file.
    ///
    /// Defaults to FCP_HOST_ADMIN_BEARER_TOKEN. The secret is sent only to the
    /// selected host's protected owner-zone route, never to the donor peer.
    #[arg(long, value_name = "PATH")]
    admin_token_file: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PullFailure {
    InvalidRequest,
    InvalidRecovery,
    MissingHost,
    InvalidHost,
    MissingCredential,
    InvalidCredential,
    Transport,
    Timeout,
    Http(u16),
    InvalidResponse,
    ResponseTooLarge,
}

impl PullFailure {
    const fn description(self) -> (&'static str, &'static str, CliExitCode) {
        match self {
            Self::InvalidRequest => (
                "invalid-state-pull-request",
                "State pull requires exact canonical connector, zone and peer IDs, an exact root, a nonempty bounded grant ID and positive limits within host bounds.",
                CliExitCode::Validation,
            ),
            Self::InvalidRecovery => (
                "invalid-state-recovery-plan",
                "Recovery requires at most seven PEER=GRANT fallbacks, distinct donors and grants, and positive attempt/total deadlines with attempt <= total <= 60000 ms. --attempt-timeout-ms requires --fallback.",
                CliExitCode::Validation,
            ),
            Self::MissingHost => (
                "missing-state-pull-host",
                "State pull requires a selected recipient host. Supply --host or configure a host context.",
                CliExitCode::Transport,
            ),
            Self::InvalidHost => (
                "invalid-state-pull-host",
                "The selected recipient host endpoint or client configuration is invalid.",
                CliExitCode::Validation,
            ),
            Self::MissingCredential => (
                "missing-admin-credential",
                "State pull requires --admin-token-file or FCP_HOST_ADMIN_BEARER_TOKEN for the selected recipient host.",
                CliExitCode::PolicyDenied,
            ),
            Self::InvalidCredential => (
                "invalid-admin-credential",
                "The host admin secret could not be read or is not a nonempty bounded HTTP bearer token.",
                CliExitCode::Validation,
            ),
            Self::Transport => (
                "state-pull-unavailable",
                "The recipient did not return a readable state-pull response. Its replica may still have changed.",
                CliExitCode::Transport,
            ),
            Self::Timeout => (
                "state-pull-timeout",
                "The state pull exceeded its deadline. The recipient may still finish retaining the replica.",
                CliExitCode::Transport,
            ),
            Self::Http(401 | 403) => (
                "state-pull-denied",
                "The host denied this state pull. Check the admin credential and both peers' exact-root grants.",
                CliExitCode::PolicyDenied,
            ),
            Self::Http(_) => (
                "state-pull-rejected",
                "The recipient did not accept the state pull. Inspect its configured donor, grants and replica state before another attempt.",
                CliExitCode::Transport,
            ),
            Self::InvalidResponse => (
                "invalid-state-pull-response",
                "The host returned invalid metadata or a response for a different peer, grant, scope or root. Replica publication is unconfirmed.",
                CliExitCode::Transport,
            ),
            Self::ResponseTooLarge => (
                "state-pull-response-too-large",
                "The host's state-pull metadata response exceeded its 16 KiB limit. Replica publication is unconfirmed.",
                CliExitCode::Transport,
            ),
        }
    }
}

pub(crate) fn dispatch(
    args: &ConnectorStatePullArgs,
    explicit_host: Option<&str>,
) -> Result<DispatchOutcome> {
    let request = match prepare_request(args) {
        Ok(request) => request,
        Err(error) => return Ok(failure(error, false)),
    };
    // Validate every candidate before resolving a host or reading a credential.
    let recovery = match prepare_recovery(args, &request) {
        Ok(recovery) => recovery,
        Err(error) => return Ok(failure(error, false)),
    };
    let host = match resolve_host_config(explicit_host) {
        Ok(Some(host)) => host,
        Ok(None) => return Ok(failure(PullFailure::MissingHost, false)),
        Err(_) => return Ok(failure(PullFailure::InvalidHost, false)),
    };
    let client = match HostAdminClient::without_redirects(&host.endpoint) {
        Ok(client) => client,
        Err(_) => return Ok(failure(PullFailure::InvalidHost, false)),
    };
    let token = match read_admin_token(args.admin_token_file.as_deref()) {
        Ok(token) => token,
        Err(error) => return Ok(failure(error, false)),
    };
    if let Some(plan) = recovery {
        return Ok(match recover(&client, &plan, &token, Duration::from_millis(args.timeout_ms)) {
            Ok(response) => recovery_success(&host.endpoint, response),
            Err(error) => failure(error, true),
        });
    }
    match pull(
        &client,
        &request,
        &token,
        Duration::from_millis(args.timeout_ms),
    ) {
        Ok(response) => Ok(success(&host.endpoint, response)),
        Err(error) => Ok(failure(error, true)),
    }
}

fn prepare_request(
    args: &ConnectorStatePullArgs,
) -> std::result::Result<ConnectorStatePullRequest, PullFailure> {
    let connector_id: ConnectorId = args
        .connector
        .parse()
        .map_err(|_| PullFailure::InvalidRequest)?;
    let zone_id: ZoneId = args.zone.parse().map_err(|_| PullFailure::InvalidRequest)?;
    let peer: TailscaleNodeId = args.peer.parse().map_err(|_| PullFailure::InvalidRequest)?;
    let instance_id: Option<InstanceId> = args
        .instance
        .as_deref()
        .map(str::parse)
        .transpose()
        .map_err(|_| PullFailure::InvalidRequest)?;
    let root_object_id: ObjectId = args.root.parse().map_err(|_| PullFailure::InvalidRequest)?;
    if args.timeout_ms == 0 || args.timeout_ms > MAX_PULL_TIMEOUT_MS {
        return Err(PullFailure::InvalidRequest);
    }
    let request = ConnectorStatePullRequest {
        peer_node: peer.as_str().to_owned(),
        request: ConnectorStateExportRequest {
            grant_id: args.grant.clone(),
            scope: ConnectorStateTransferScope {
                connector_id,
                zone_id,
                instance_id,
            },
            root_object_id,
            limits: ConnectorStateTransferLimits {
                max_objects: args.max_objects,
                max_canonical_bytes: args.max_canonical_bytes,
                max_wire_bytes: args.max_wire_bytes,
            },
        },
    };
    // Reuse the protocol's metadata and resource-limit validation, then also
    // bound the complete operator wrapper before any host request is sent.
    request
        .request
        .to_json()
        .map_err(|_| PullFailure::InvalidRequest)?;
    let encoded = serde_json::to_vec(&request).map_err(|_| PullFailure::InvalidRequest)?;
    if encoded.len() > MAX_CONNECTOR_STATE_EXPORT_REQUEST_BYTES {
        return Err(PullFailure::InvalidRequest);
    }
    Ok(request)
}

fn prepare_recovery(
    args: &ConnectorStatePullArgs,
    primary: &ConnectorStatePullRequest,
) -> std::result::Result<Option<ConnectorStateRecoveryRequest>, PullFailure> {
    if args.fallback.is_empty() {
        return if args.attempt_timeout_ms.is_some() {
            Err(PullFailure::InvalidRecovery)
        } else {
            Ok(None)
        };
    }
    if args.fallback.len() >= MAX_CONNECTOR_STATE_RECOVERY_CANDIDATES {
        return Err(PullFailure::InvalidRecovery);
    }
    let mut candidates = Vec::with_capacity(args.fallback.len() + 1);
    candidates.push(primary.clone());
    for fallback in &args.fallback {
        // Bound before cloning any metadata. A grant may itself contain '=';
        // only the first separator distinguishes the canonical node ID.
        if fallback.len() > 1025 {
            return Err(PullFailure::InvalidRecovery);
        }
        let (peer, grant) = fallback.split_once('=').ok_or(PullFailure::InvalidRecovery)?;
        let mut candidate = primary.clone();
        candidate.peer_node = peer.to_owned();
        candidate.request.grant_id = grant.to_owned();
        candidates.push(candidate);
    }
    let plan = ConnectorStateRecoveryRequest {
        candidates,
        attempt_timeout_ms: args.attempt_timeout_ms.unwrap_or(10_000_u64.min(args.timeout_ms)),
        total_timeout_ms: args.timeout_ms,
    };
    plan.validate().map_err(|_| PullFailure::InvalidRecovery)?;
    let encoded = serde_json::to_vec(&plan).map_err(|_| PullFailure::InvalidRecovery)?;
    if encoded.len() > MAX_CONNECTOR_STATE_RECOVERY_REQUEST_BYTES {
        return Err(PullFailure::InvalidRecovery);
    }
    Ok(Some(plan))
}

fn read_admin_token(path: Option<&Path>) -> std::result::Result<Zeroizing<String>, PullFailure> {
    let value = if let Some(path) = path {
        let file = std::fs::File::open(path).map_err(|_| PullFailure::InvalidCredential)?;
        let mut value = Zeroizing::new(String::new());
        file.take(MAX_ADMIN_TOKEN_BYTES + 1)
            .read_to_string(&mut value)
            .map_err(|_| PullFailure::InvalidCredential)?;
        value
    } else {
        match std::env::var(ADMIN_TOKEN_ENV) {
            Ok(value) => Zeroizing::new(value),
            Err(std::env::VarError::NotPresent) => return Err(PullFailure::MissingCredential),
            Err(std::env::VarError::NotUnicode(_)) => return Err(PullFailure::InvalidCredential),
        }
    };
    let token = value.trim();
    if value.len() as u64 > MAX_ADMIN_TOKEN_BYTES
        || token.is_empty()
        || !token.is_ascii()
        || token
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(PullFailure::InvalidCredential);
    }
    Ok(Zeroizing::new(token.to_owned()))
}

fn pull(
    client: &HostAdminClient,
    request: &ConnectorStatePullRequest,
    token: &str,
    timeout: Duration,
) -> std::result::Result<ConnectorStatePullResponse, PullFailure> {
    let body = post_pull(client, &request.request.scope.connector_id, request, token, timeout)?;
    let response: ConnectorStatePullResponse =
        serde_json::from_slice(&body).map_err(|_| PullFailure::InvalidResponse)?;
    validate_response(request, &response)?;
    Ok(response)
}

fn recover(
    client: &HostAdminClient,
    request: &ConnectorStateRecoveryRequest,
    token: &str,
    timeout: Duration,
) -> std::result::Result<ConnectorStateRecoveryResponse, PullFailure> {
    request.validate().map_err(|_| PullFailure::InvalidRecovery)?;
    let body = post_pull(
        client, &request.candidates[0].request.scope.connector_id, request, token, timeout,
    )?;
    let response: ConnectorStateRecoveryResponse =
        serde_json::from_slice(&body).map_err(|_| PullFailure::InvalidResponse)?;
    validate_recovery_response(request, &response)?;
    Ok(response)
}

fn post_pull(
    client: &HostAdminClient,
    connector_id: &ConnectorId,
    request: &impl Serialize,
    token: &str,
    timeout: Duration,
) -> std::result::Result<Vec<u8>, PullFailure> {
    let path = format!(
        "/rpc/admin/connectors/{}/state/pull",
        connector_id,
    );
    // One selected-host request: no discovery, redirects or client-side retry.
    // An explicit recovery plan authorizes only host-side download failover.
    // An interrupted recipient response cannot prove no import occurred.
    let response = client
        .client
        .post(format!("{}{path}", client.base_url))
        .bearer_auth(token)
        .header("x-fcp-zone", "z:owner")
        .timeout(timeout)
        .json(request)
        .send()
        .map_err(|error| {
            if error.is_timeout() {
                PullFailure::Timeout
            } else {
                PullFailure::Transport
            }
        })?;
    let status = response.status();
    if !status.is_success() {
        return Err(PullFailure::Http(status.as_u16()));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_PULL_RESPONSE_BYTES)
    {
        return Err(PullFailure::ResponseTooLarge);
    }
    let mut body = Vec::new();
    response
        .take(MAX_PULL_RESPONSE_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::TimedOut
                || error
                    .get_ref()
                    .and_then(|cause| cause.downcast_ref::<reqwest::Error>())
                    .is_some_and(reqwest::Error::is_timeout)
            {
                PullFailure::Timeout
            } else {
                PullFailure::Transport
            }
        })?;
    if body.len() as u64 > MAX_PULL_RESPONSE_BYTES {
        return Err(PullFailure::ResponseTooLarge);
    }
    Ok(body)
}

fn validate_recovery_response(
    request: &ConnectorStateRecoveryRequest,
    response: &ConnectorStateRecoveryResponse,
) -> std::result::Result<(), PullFailure> {
    if response.schema_version != CONNECTOR_STATE_RECOVERY_SCHEMA_VERSION
        || response.attempts.is_empty()
        || response.attempts.len() > request.candidates.len()
    {
        return Err(PullFailure::InvalidResponse);
    }
    let last = response.attempts.len() - 1;
    for (index, attempt) in response.attempts.iter().enumerate() {
        let candidate = &request.candidates[index];
        if attempt.peer_node != candidate.peer_node
            || attempt.grant_id != candidate.request.grant_id
            || (index == last) != (attempt.outcome == ConnectorStateRecoveryOutcome::Retained)
        {
            return Err(PullFailure::InvalidResponse);
        }
    }
    // The final donor must supply the ordinary exact-root, bounded replica
    // receipt. A valid request prefix alone is not evidence of recovery.
    validate_response(&request.candidates[last], &response.replica)
}

fn validate_response(
    request: &ConnectorStatePullRequest,
    response: &ConnectorStatePullResponse,
) -> std::result::Result<(), PullFailure> {
    let limits = request.request.limits;
    if response.schema_version != CONNECTOR_STATE_TRANSFER_SCHEMA_VERSION
        || response.peer_node != request.peer_node
        || response.grant_id != request.request.grant_id
        || response.scope != request.request.scope
        || response.root_object_id != request.request.root_object_id
        || !response.replica_only
        || response.object_count == 0
        || response.object_count > limits.max_objects
        || response.canonical_bytes == 0
        || response.canonical_bytes > limits.max_canonical_bytes
        || response.wire_bytes == 0
        || response.wire_bytes > limits.max_wire_bytes
    {
        return Err(PullFailure::InvalidResponse);
    }
    Ok(())
}

fn success(endpoint: &str, response: ConnectorStatePullResponse) -> DispatchOutcome {
    let message = if response.replica_root_published {
        "The host published the verified requested root in its retained replica store. The pull did not activate a connector or acquire a writer lease."
    } else {
        "The host verified a duplicate or older comparable root. Its retained replica root was not replaced; the requested root is not a claim about the replica's current head."
    };
    let mut payload = json!({
        "status": "ok", "command": "connector", "subcommand": "state pull",
        "source": "host-admin-api", "host_endpoint_hash": sha256_prefixed(endpoint.as_bytes()),
        "transfer_succeeded": true, "transfer_outcome": "verified",
        "replica_only": true, "connector_activated": false, "lease_acquired": false,
        "automatic_retry_allowed": false, "message": message, "replica": response,
        "caveats": [
            "State transfer does not activate a connector, authorize execution, or establish live writer-lease ownership.",
            "This metadata does not assert storage durability or mesh-wide replica availability.",
        ],
    });
    CommandEnvelope::new(CommandAvailability::LiveRuntime, "connector").inject_into(&mut payload);
    inject_truth_source_metadata(&mut payload, KnowledgeState::HostBacked);
    DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    }
}

fn recovery_success(endpoint: &str, response: ConnectorStateRecoveryResponse) -> DispatchOutcome {
    let mut outcome = success(endpoint, response.replica);
    outcome.payload["recovery"] = json!({
        "schema_version": response.schema_version,
        "attempts": response.attempts,
    });
    outcome
}

fn failure(error: PullFailure, attempted: bool) -> DispatchOutcome {
    let (kind, message, exit_code) = error.description();
    let mut payload = json!({
        "status": "error", "command": "connector", "subcommand": "state pull",
        "source": "host-admin-api", "transfer_succeeded": false,
        "transfer_outcome": if attempted { "unknown" } else { "not-started" },
        "automatic_retry_allowed": false, "message": message,
        "error": { "type": kind, "http_status": match error { PullFailure::Http(status) => Some(status), _ => None } },
    });
    CommandEnvelope::new(CommandAvailability::LiveRuntime, "connector").inject_into(&mut payload);
    if attempted {
        inject_truth_source_metadata(&mut payload, KnowledgeState::HostBacked);
    }
    DispatchOutcome { payload, exit_code }
}

pub(crate) fn withhold_argument_echo(payload: &Value) -> bool {
    payload["command"] == "connector" && payload["subcommand"] == "state pull"
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Instant;

    use super::*;

    enum Reply {
        Json(u16, Value),
        Redirect(String),
        Oversized(bool),
        Stalled,
        Disconnect,
    }

    struct CapturedRequest {
        line: String,
        headers: BTreeMap<String, String>,
        body: Value,
    }

    struct TestHost {
        endpoint: String,
        captured: mpsc::Receiver<CapturedRequest>,
        release: mpsc::Sender<()>,
        worker: Option<thread::JoinHandle<()>>,
    }

    impl TestHost {
        fn start(reply: Reply) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let (capture, captured) = mpsc::channel();
            let (release, released) = mpsc::channel();
            let worker = thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(5);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(error) => panic!("test host accept: {error}"),
                    }
                    match released.recv_timeout(Duration::from_millis(10)) {
                        Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return,
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            assert!(Instant::now() < deadline, "state pull did not connect");
                        }
                    }
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let mut headers = BTreeMap::new();
                loop {
                    let mut header = String::new();
                    assert!(reader.read_line(&mut header).unwrap() > 0);
                    if header == "\r\n" {
                        break;
                    }
                    let (key, value) = header.split_once(':').unwrap();
                    headers.insert(key.to_ascii_lowercase(), value.trim().to_owned());
                }
                let length: usize = headers["content-length"].parse().unwrap();
                assert!(length <= MAX_CONNECTOR_STATE_RECOVERY_REQUEST_BYTES);
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                capture
                    .send(CapturedRequest {
                        line: line.trim().to_owned(),
                        headers,
                        body: serde_json::from_slice(&body).unwrap(),
                    })
                    .unwrap();
                match reply {
                    Reply::Json(status, body) => {
                        let body = body.to_string();
                        write!(stream, "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
                    }
                    Reply::Redirect(location) => {
                        write!(stream, "HTTP/1.1 307 Temporary Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                    }
                    Reply::Oversized(known_length) => {
                        let length = usize::try_from(MAX_PULL_RESPONSE_BYTES).unwrap() + 1;
                        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n").unwrap();
                        if known_length {
                            write!(stream, "Content-Length: {length}\r\n").unwrap();
                        }
                        stream.write_all(b"\r\n").unwrap();
                        let _ = stream.write_all(&vec![b' '; length]);
                    }
                    Reply::Stalled => {
                        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 512\r\nConnection: close\r\n\r\n{").unwrap();
                        stream.flush().unwrap();
                        let _ = released.recv_timeout(Duration::from_secs(5));
                    }
                    Reply::Disconnect => {}
                }
            });
            Self {
                endpoint,
                captured,
                release,
                worker: Some(worker),
            }
        }

        fn finish(mut self) -> CapturedRequest {
            let captured = self.captured.recv_timeout(Duration::from_secs(5)).unwrap();
            let _ = self.release.send(());
            self.worker.take().unwrap().join().unwrap();
            captured
        }
    }

    impl Drop for TestHost {
        fn drop(&mut self) {
            let _ = self.release.send(());
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }

    fn args() -> ConnectorStatePullArgs {
        ConnectorStatePullArgs {
            connector: "fcp.test:request-response:v1".to_owned(),
            zone: "z:work".to_owned(),
            peer: "node-donor".to_owned(),
            grant: "grant-state-root".to_owned(),
            fallback: Vec::new(),
            attempt_timeout_ms: None,
            root: "11".repeat(32),
            instance: Some("inst-source".to_owned()),
            max_objects: 128,
            max_canonical_bytes: 65_536,
            max_wire_bytes: 262_144,
            timeout_ms: 2_000,
            admin_token_file: None,
        }
    }

    fn response(
        request: &ConnectorStatePullRequest,
        published: bool,
    ) -> ConnectorStatePullResponse {
        ConnectorStatePullResponse {
            schema_version: CONNECTOR_STATE_TRANSFER_SCHEMA_VERSION.to_owned(),
            peer_node: request.peer_node.clone(),
            grant_id: request.request.grant_id.clone(),
            scope: request.request.scope.clone(),
            root_object_id: request.request.root_object_id,
            object_count: 2,
            canonical_bytes: 800,
            wire_bytes: 2_400,
            replica_root_published: published,
            replica_only: true,
        }
    }

    #[test]
    fn cli_pull_reaches_protected_route_without_connector_discovery_or_secret_echo() {
        let request = prepare_request(&args()).unwrap();
        let host = TestHost::start(Reply::Json(200, json!(response(&request, true))));
        let directory = tempfile::tempdir().unwrap();
        let token_path = directory.path().join("admin.token");
        std::fs::write(&token_path, "fixture-admin-secret\n").unwrap();
        let arguments = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "connector".to_owned(),
            "state".to_owned(),
            "pull".to_owned(),
            "--host".to_owned(),
            host.endpoint.clone(),
            "--connector".to_owned(),
            args().connector,
            "--zone".to_owned(),
            "z:work".to_owned(),
            "--peer".to_owned(),
            "node-donor".to_owned(),
            "--grant".to_owned(),
            "grant-state-root".to_owned(),
            "--root".to_owned(),
            format!("objectid:{}", args().root),
            "--instance".to_owned(),
            "inst-source".to_owned(),
            "--max-objects".to_owned(),
            "128".to_owned(),
            "--max-canonical-bytes".to_owned(),
            "65536".to_owned(),
            "--max-wire-bytes".to_owned(),
            "262144".to_owned(),
            "--timeout-ms".to_owned(),
            "2000".to_owned(),
            "--admin-token-file".to_owned(),
            token_path.to_string_lossy().into_owned(),
        ];
        let outcome = crate::execute(&arguments).unwrap();
        let captured = host.finish();
        let payload: Value = serde_json::from_str(&outcome.text).unwrap();
        assert_eq!(
            captured.line,
            "POST /rpc/admin/connectors/fcp.test:request-response:v1/state/pull HTTP/1.1"
        );
        assert_eq!(
            captured.headers["authorization"],
            "Bearer fixture-admin-secret"
        );
        assert_eq!(captured.headers["x-fcp-zone"], "z:owner");
        assert_eq!(captured.body, json!(request));
        assert_eq!(outcome.exit_code, CliExitCode::Success.into());
        assert_eq!(payload["_truth_source"], "host");
        assert_eq!(payload["replica"]["root_object_id"], args().root);
        assert_eq!(payload["replica"]["replica_root_published"], true);
        assert_eq!(payload["connector_activated"], false);
        assert_eq!(payload["lease_acquired"], false);
        assert!(!outcome.text.contains("fixture-admin-secret"));
        assert!(payload.get("state").is_none());
    }

    #[test]
    fn duplicate_or_older_root_is_not_presented_as_the_new_replica_head() {
        let request = prepare_request(&args()).unwrap();
        let outcome = success("http://127.0.0.1:8787", response(&request, false));
        assert_eq!(outcome.exit_code, CliExitCode::Success);
        assert_eq!(outcome.payload["replica"]["replica_root_published"], false);
        assert!(
            outcome.payload["message"]
                .as_str()
                .unwrap()
                .contains("not replaced")
        );
        assert_eq!(outcome.payload["automatic_retry_allowed"], false);
        assert!(outcome.payload.get("current_replica_root").is_none());
        assert!(outcome.payload.get("durable").is_none());
    }

    #[test]
    fn pull_rejects_wrong_scope_authority_resource_counts_and_unexpected_payloads() {
        let request = prepare_request(&args()).unwrap();
        let valid = json!(response(&request, true));
        let mut invalid = Vec::new();
        for (field, value) in [
            ("schema_version", json!("wrong-schema")),
            ("peer_node", json!("node-other")),
            ("grant_id", json!("other-grant")),
            ("root_object_id", json!("22".repeat(32))),
            ("object_count", json!(0)),
            ("object_count", json!(129)),
            ("canonical_bytes", json!(0)),
            ("canonical_bytes", json!(65_537)),
            ("wire_bytes", json!(0)),
            ("wire_bytes", json!(262_145)),
            ("replica_only", json!(false)),
            ("raw_state", json!("reflected-private-state")),
        ] {
            let mut body = valid.clone();
            body[field] = value;
            invalid.push(body);
        }
        for (field, value) in [
            ("connector_id", json!("fcp.other:request-response:v1")),
            ("zone_id", json!("z:private")),
            ("instance_id", json!(null)),
        ] {
            let mut body = valid.clone();
            body["scope"][field] = value;
            invalid.push(body);
        }
        for body in invalid {
            let host = TestHost::start(Reply::Json(200, body));
            let client = HostAdminClient::without_redirects(&host.endpoint).unwrap();
            assert_eq!(
                pull(
                    &client,
                    &request,
                    "fixture-admin-secret",
                    Duration::from_secs(2)
                ),
                Err(PullFailure::InvalidResponse)
            );
            host.finish();
        }
        let outcome = failure(PullFailure::InvalidResponse, true);
        assert_eq!(outcome.payload["transfer_outcome"], "unknown");
        assert!(outcome.payload.get("replica").is_none());
    }

    #[test]
    fn pull_never_follows_redirects_or_exposes_host_error_bodies() {
        let request = prepare_request(&args()).unwrap();
        let destination = TcpListener::bind("127.0.0.1:0").unwrap();
        destination.set_nonblocking(true).unwrap();
        let host = TestHost::start(Reply::Redirect(format!(
            "http://{}/capture",
            destination.local_addr().unwrap()
        )));
        let client = HostAdminClient::without_redirects(&host.endpoint).unwrap();
        assert_eq!(
            pull(
                &client,
                &request,
                "fixture-admin-secret",
                Duration::from_secs(2)
            ),
            Err(PullFailure::Http(307))
        );
        host.finish();
        assert!(
            matches!(destination.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );

        let host = TestHost::start(Reply::Json(
            403,
            json!({"message": "fixture-admin-secret reflected-private-state"}),
        ));
        let client = HostAdminClient::without_redirects(&host.endpoint).unwrap();
        let error = pull(
            &client,
            &request,
            "fixture-admin-secret",
            Duration::from_secs(2),
        )
        .unwrap_err();
        host.finish();
        let outcome = failure(error, true);
        assert_eq!(outcome.exit_code, CliExitCode::PolicyDenied);
        assert_eq!(outcome.payload["error"]["http_status"], 403);
        let encoded = outcome.payload.to_string();
        assert!(!encoded.contains("fixture-admin-secret"));
        assert!(!encoded.contains("reflected-private-state"));
    }

    #[test]
    fn pull_bounds_declared_and_streamed_metadata_and_stalled_body() {
        let request = prepare_request(&args()).unwrap();
        for known_length in [false, true] {
            let host = TestHost::start(Reply::Oversized(known_length));
            let client = HostAdminClient::without_redirects(&host.endpoint).unwrap();
            assert_eq!(
                pull(
                    &client,
                    &request,
                    "fixture-admin-secret",
                    Duration::from_secs(2)
                ),
                Err(PullFailure::ResponseTooLarge)
            );
            host.finish();
        }
        let host = TestHost::start(Reply::Stalled);
        let client = HostAdminClient::without_redirects(&host.endpoint).unwrap();
        assert_eq!(
            pull(
                &client,
                &request,
                "fixture-admin-secret",
                Duration::from_millis(200)
            ),
            Err(PullFailure::Timeout)
        );
        host.finish();
        let host = TestHost::start(Reply::Disconnect);
        let client = HostAdminClient::without_redirects(&host.endpoint).unwrap();
        assert_eq!(
            pull(
                &client,
                &request,
                "fixture-admin-secret",
                Duration::from_secs(2)
            ),
            Err(PullFailure::Transport)
        );
        host.finish();
    }

    #[test]
    fn pull_validation_refuses_path_injection_unbounded_limits_and_malformed_secrets() {
        let mut invalid = args();
        invalid.connector = "fcp.test/../../admin".to_owned();
        assert_eq!(prepare_request(&invalid), Err(PullFailure::InvalidRequest));
        let mut invalid = args();
        invalid.zone = "z:work?secret=value".to_owned();
        assert_eq!(prepare_request(&invalid), Err(PullFailure::InvalidRequest));
        let mut invalid = args();
        invalid.peer = "https://untrusted.example".to_owned();
        assert_eq!(prepare_request(&invalid), Err(PullFailure::InvalidRequest));
        let mut invalid = args();
        invalid.root = "latest".to_owned();
        assert_eq!(prepare_request(&invalid), Err(PullFailure::InvalidRequest));
        let mut invalid = args();
        invalid.grant = "x".repeat(513);
        assert_eq!(prepare_request(&invalid), Err(PullFailure::InvalidRequest));
        let mut invalid = args();
        invalid.max_objects = 0;
        assert_eq!(prepare_request(&invalid), Err(PullFailure::InvalidRequest));
        let mut invalid = args();
        invalid.max_canonical_bytes = MAX_CONNECTOR_STATE_TRANSFER_CANONICAL_BYTES + 1;
        assert_eq!(prepare_request(&invalid), Err(PullFailure::InvalidRequest));
        let mut invalid = args();
        invalid.max_wire_bytes = MAX_CONNECTOR_STATE_TRANSFER_WIRE_BYTES + 1;
        assert_eq!(prepare_request(&invalid), Err(PullFailure::InvalidRequest));
        let mut invalid = args();
        invalid.timeout_ms = MAX_PULL_TIMEOUT_MS + 1;
        assert_eq!(prepare_request(&invalid), Err(PullFailure::InvalidRequest));

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("admin.token");
        for value in [
            String::new(),
            "header\ninjection".to_owned(),
            "word with spaces".to_owned(),
            "x".repeat(65_537),
        ] {
            std::fs::write(&path, value).unwrap();
            assert!(matches!(
                read_admin_token(Some(&path)),
                Err(PullFailure::InvalidCredential)
            ));
        }
        let outcome = dispatch(
            &args(),
            Some("http://private-user:private-password@127.0.0.1:1?secret=query-value"),
        )
        .unwrap();
        let encoded = outcome.payload.to_string();
        assert_eq!(outcome.exit_code, CliExitCode::Validation);
        for secret in ["private-user", "private-password", "query-value"] {
            assert!(!encoded.contains(secret));
        }
        assert!(withhold_argument_echo(&outcome.payload));
    }

    fn recovery_args() -> ConnectorStatePullArgs {
        let mut arguments = args();
        arguments.fallback = vec![
            "node-backup=grant-backup".to_owned(),
            "node-spare=grant-spare".to_owned(),
        ];
        arguments.attempt_timeout_ms = Some(500);
        arguments
    }

    fn recovery_plan() -> ConnectorStateRecoveryRequest {
        let arguments = recovery_args();
        prepare_recovery(&arguments, &prepare_request(&arguments).unwrap())
            .unwrap()
            .unwrap()
    }

    fn recovery_response(
        plan: &ConnectorStateRecoveryRequest,
        selected: usize,
        published: bool,
    ) -> ConnectorStateRecoveryResponse {
        ConnectorStateRecoveryResponse {
            schema_version: CONNECTOR_STATE_RECOVERY_SCHEMA_VERSION.to_owned(),
            attempts: plan.candidates.iter().take(selected + 1).enumerate().map(|(index, candidate)| {
                fcp_host::ConnectorStateRecoveryAttempt {
                    peer_node: candidate.peer_node.clone(),
                    grant_id: candidate.request.grant_id.clone(),
                    outcome: if index == selected {
                        ConnectorStateRecoveryOutcome::Retained
                    } else if index == 0 {
                        ConnectorStateRecoveryOutcome::DownloadDeadline
                    } else {
                        ConnectorStateRecoveryOutcome::DownloadFailed
                    },
                }
            }).collect(),
            replica: response(&plan.candidates[selected], published),
        }
    }

    #[test]
    fn recovery_options_preserve_exact_scope_limits_and_operator_order() {
        let primary = prepare_request(&args()).unwrap();
        assert_eq!(prepare_recovery(&args(), &primary).unwrap(), None);
        let mut arguments = recovery_args();
        let plan = prepare_recovery(&arguments, &primary).unwrap().unwrap();
        assert_eq!(plan.candidates[0], primary);
        assert_eq!(plan.candidates.len(), 3);
        assert_eq!(plan.candidates[1].peer_node, "node-backup");
        assert_eq!(plan.candidates[2].peer_node, "node-spare");
        assert_eq!(plan.attempt_timeout_ms, 500);
        assert_eq!(plan.total_timeout_ms, arguments.timeout_ms);
        for candidate in &plan.candidates {
            assert_eq!(candidate.request.scope, primary.request.scope);
            assert_eq!(candidate.request.root_object_id, primary.request.root_object_id);
            assert_eq!(candidate.request.limits, primary.request.limits);
        }
        arguments.attempt_timeout_ms = None;
        arguments.timeout_ms = 15_000;
        assert_eq!(prepare_recovery(&arguments, &primary).unwrap().unwrap().attempt_timeout_ms, 10_000);
        arguments.timeout_ms = 1;
        assert_eq!(prepare_recovery(&arguments, &primary).unwrap().unwrap().attempt_timeout_ms, 1);
        arguments.fallback = vec!["node-backup=grant=with=equals".to_owned()];
        assert_eq!(
            prepare_recovery(&arguments, &primary).unwrap().unwrap().candidates[1].request.grant_id,
            "grant=with=equals",
        );
    }

    #[test]
    fn recovery_options_reject_malformed_and_duplicate_authority_before_host_access() {
        let primary = prepare_request(&args()).unwrap();
        for fallback in [
            "missing-separator".to_owned(), "=grant-backup".to_owned(),
            "node-backup=".to_owned(), "https://peer.example=grant-backup".to_owned(),
            " node-backup=grant-backup".to_owned(), "node-donor=grant-backup".to_owned(),
            "node-backup=grant-state-root".to_owned(), "node-backup=bad\ngrant".to_owned(),
            format!("node-backup={}", "x".repeat(513)), "x".repeat(1026),
        ] {
            let mut arguments = recovery_args();
            arguments.fallback = vec![fallback];
            assert_eq!(prepare_recovery(&arguments, &primary), Err(PullFailure::InvalidRecovery));
        }
        for fallbacks in [
            vec!["node-backup=grant-a", "node-backup=grant-b"],
            vec!["node-backup=grant-a", "node-spare=grant-a"],
        ] {
            let mut arguments = recovery_args();
            arguments.fallback = fallbacks.into_iter().map(str::to_owned).collect();
            assert_eq!(prepare_recovery(&arguments, &primary), Err(PullFailure::InvalidRecovery));
        }
        let mut arguments = recovery_args();
        arguments.fallback = vec!["bad/secret-peer=secret-marker".to_owned()];
        arguments.admin_token_file = Some(PathBuf::from("/not-opened/private-token"));
        let outcome = dispatch(&arguments, Some("not-a-host-secret")).unwrap();
        assert_eq!(outcome.exit_code, CliExitCode::Validation);
        assert_eq!(outcome.payload["error"]["type"], "invalid-state-recovery-plan");
        assert_eq!(outcome.payload["transfer_outcome"], "not-started");
        assert!(!outcome.payload.to_string().contains("secret"));
        assert!(withhold_argument_echo(&outcome.payload));
    }

    #[test]
    fn recovery_options_enforce_count_and_deadline_boundaries() {
        let primary = prepare_request(&args()).unwrap();
        let mut arguments = recovery_args();
        arguments.fallback = (1..MAX_CONNECTOR_STATE_RECOVERY_CANDIDATES)
            .map(|index| format!("node-{index}=grant-{index}")).collect();
        let plan = prepare_recovery(&arguments, &primary).unwrap().unwrap();
        assert_eq!(plan.candidates.len(), MAX_CONNECTOR_STATE_RECOVERY_CANDIDATES);
        arguments.fallback.push("node-extra=grant-extra".to_owned());
        assert_eq!(prepare_recovery(&arguments, &primary), Err(PullFailure::InvalidRecovery));
        for (attempt, total) in [(0, 1000), (1001, 1000), (1, 0), (1, 60_001), (u64::MAX, 1000)] {
            let mut arguments = recovery_args();
            arguments.attempt_timeout_ms = Some(attempt);
            arguments.timeout_ms = total;
            assert_eq!(prepare_recovery(&arguments, &primary), Err(PullFailure::InvalidRecovery));
        }
        let mut arguments = recovery_args();
        arguments.timeout_ms = MAX_CONNECTOR_STATE_RECOVERY_TIMEOUT_MS;
        arguments.attempt_timeout_ms = Some(arguments.timeout_ms);
        assert!(prepare_recovery(&arguments, &primary).is_ok());
        arguments.fallback.clear();
        assert_eq!(prepare_recovery(&arguments, &primary), Err(PullFailure::InvalidRecovery));
    }

    #[test]
    fn recovery_receipts_accept_any_successful_prefix_without_inventing_a_new_head() {
        let plan = recovery_plan();
        for selected in 0..plan.candidates.len() {
            for published in [false, true] {
                let receipt = recovery_response(&plan, selected, published);
                validate_recovery_response(&plan, &receipt).unwrap();
                let outcome = recovery_success("http://127.0.0.1:8787", receipt);
                assert_eq!(outcome.exit_code, CliExitCode::Success);
                assert_eq!(outcome.payload["recovery"]["attempts"].as_array().unwrap().len(), selected + 1);
                assert_eq!(outcome.payload["replica"]["peer_node"], plan.candidates[selected].peer_node);
                assert_eq!(outcome.payload["replica"]["replica_root_published"], published);
                assert_eq!(outcome.payload["automatic_retry_allowed"], false);
                assert_eq!(outcome.payload["connector_activated"], false);
                assert_eq!(outcome.payload["lease_acquired"], false);
                assert!(outcome.payload.get("current_replica_root").is_none());
            }
        }
    }

    #[test]
    fn recovery_receipts_reject_skipped_reordered_or_multiple_successful_donors() {
        let plan = recovery_plan();
        let valid = recovery_response(&plan, 2, true);
        let mut invalid = Vec::new();
        let mut receipt = valid.clone();
        receipt.attempts.clear();
        invalid.push(receipt);
        let mut receipt = valid.clone();
        receipt.attempts.swap(0, 1);
        invalid.push(receipt);
        let mut receipt = valid.clone();
        receipt.attempts.remove(0);
        invalid.push(receipt);
        let mut receipt = valid.clone();
        receipt.attempts.push(receipt.attempts[2].clone());
        invalid.push(receipt);
        let value = json!(valid);
        for (pointer, replacement) in [
            ("/schema_version", json!("wrong")),
            ("/attempts/0/peer_node", json!("node-other")),
            ("/attempts/1/grant_id", json!("other-grant")),
            ("/attempts/0/outcome", json!("retained")),
            ("/attempts/2/outcome", json!("download_failed")),
            ("/replica/peer_node", json!("node-donor")),
            ("/replica/grant_id", json!("grant-state-root")),
            ("/replica/root_object_id", json!("22".repeat(32))),
            ("/replica/scope/zone_id", json!("z:private")),
            ("/replica/scope/instance_id", json!(null)),
            ("/replica/replica_only", json!(false)),
            ("/replica/object_count", json!(129)),
            ("/replica/canonical_bytes", json!(0)),
            ("/replica/wire_bytes", json!(262_145)),
        ] {
            let mut changed = value.clone();
            *changed.pointer_mut(pointer).unwrap() = replacement;
            invalid.push(serde_json::from_value(changed).unwrap());
        }
        for receipt in invalid {
            assert_eq!(validate_recovery_response(&plan, &receipt), Err(PullFailure::InvalidResponse));
        }
    }

    #[test]
    fn cli_recovery_sends_one_protected_plan_and_reports_the_selected_donor() {
        let plan = recovery_plan();
        let host = TestHost::start(Reply::Json(200, json!(recovery_response(&plan, 1, true))));
        let directory = tempfile::tempdir().unwrap();
        let token_path = directory.path().join("admin.token");
        std::fs::write(&token_path, "fixture-admin-secret\n").unwrap();
        let mut arguments: Vec<String> = [
            "fwc", "--json", "connector", "state", "pull",
            "--connector", "fcp.test:request-response:v1", "--zone", "z:work",
            "--peer", "node-donor", "--grant", "grant-state-root",
            "--fallback", "node-backup=grant-backup", "--fallback", "node-spare=grant-spare",
            "--attempt-timeout-ms", "500", "--timeout-ms", "2000",
            "--instance", "inst-source", "--max-objects", "128",
            "--max-canonical-bytes", "65536", "--max-wire-bytes", "262144",
        ].into_iter().map(str::to_owned).collect();
        arguments.extend([
            "--host".to_owned(), host.endpoint.clone(), "--root".to_owned(), args().root,
            "--admin-token-file".to_owned(), token_path.to_string_lossy().into_owned(),
        ]);
        let outcome = crate::execute(&arguments).unwrap();
        let captured = host.finish();
        assert_eq!(captured.body, json!(plan));
        assert_eq!(captured.line, "POST /rpc/admin/connectors/fcp.test:request-response:v1/state/pull HTTP/1.1");
        assert_eq!(captured.headers["authorization"], "Bearer fixture-admin-secret");
        assert_eq!(captured.headers["x-fcp-zone"], "z:owner");
        assert_eq!(outcome.exit_code, CliExitCode::Success.into());
        let payload: Value = serde_json::from_str(&outcome.text).unwrap();
        assert_eq!(payload["replica"]["peer_node"], "node-backup");
        assert_eq!(payload["recovery"]["attempts"][0]["outcome"], "download_deadline");
        assert_eq!(payload["recovery"]["attempts"][1]["outcome"], "retained");
        assert_eq!(payload["_truth_source"], "host");
        assert_eq!(payload["automatic_retry_allowed"], false);
        assert!(!outcome.text.contains("fixture-admin-secret"));
        assert!(!outcome.text.contains("node-spare=grant-spare"));
    }

    #[test]
    fn recovery_http_rejects_single_pull_receipts_and_unexpected_payloads() {
        let plan = recovery_plan();
        let valid = json!(recovery_response(&plan, 1, true));
        let mut extra = valid.clone();
        extra["raw_state"] = json!("private-state");
        let mut attempt_extra = valid.clone();
        attempt_extra["attempts"][0]["error_body"] = json!("private-state");
        let mut wrong_winner = valid;
        wrong_winner["replica"]["peer_node"] = json!("node-other");
        for body in [json!(response(&plan.candidates[0], true)), extra, attempt_extra, wrong_winner] {
            let host = TestHost::start(Reply::Json(200, body));
            let client = HostAdminClient::without_redirects(&host.endpoint).unwrap();
            assert_eq!(
                recover(&client, &plan, "fixture-admin-secret", Duration::from_secs(2)),
                Err(PullFailure::InvalidResponse),
            );
            host.finish();
        }
        let outcome = failure(PullFailure::InvalidResponse, true);
        assert_eq!(outcome.payload["transfer_outcome"], "unknown");
        assert_eq!(outcome.payload["automatic_retry_allowed"], false);
        assert!(outcome.payload.get("replica").is_none());
        assert!(outcome.payload.get("recovery").is_none());
    }

    #[test]
    fn recovery_transport_preserves_response_bounds_redaction_and_no_redirects() {
        let plan = recovery_plan();
        let destination = TcpListener::bind("127.0.0.1:0").unwrap();
        destination.set_nonblocking(true).unwrap();
        for (reply, expected) in [
            (Reply::Redirect(format!("http://{}/capture", destination.local_addr().unwrap())), PullFailure::Http(307)),
            (Reply::Json(503, json!({"error": "private-state fixture-admin-secret"})), PullFailure::Http(503)),
            (Reply::Oversized(true), PullFailure::ResponseTooLarge),
            (Reply::Oversized(false), PullFailure::ResponseTooLarge),
            (Reply::Disconnect, PullFailure::Transport),
        ] {
            let host = TestHost::start(reply);
            let client = HostAdminClient::without_redirects(&host.endpoint).unwrap();
            let error = recover(&client, &plan, "fixture-admin-secret", Duration::from_secs(2)).unwrap_err();
            assert_eq!(error, expected);
            assert_eq!(host.finish().body, json!(plan));
            let outcome = failure(error, true);
            assert_eq!(outcome.payload["transfer_outcome"], "unknown");
            assert_eq!(outcome.payload["automatic_retry_allowed"], false);
            assert!(!outcome.payload.to_string().contains("private-state"));
            assert!(!outcome.payload.to_string().contains("fixture-admin-secret"));
        }
        assert!(matches!(destination.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock));
        let host = TestHost::start(Reply::Stalled);
        let client = HostAdminClient::without_redirects(&host.endpoint).unwrap();
        assert_eq!(
            recover(&client, &plan, "fixture-admin-secret", Duration::from_millis(200)),
            Err(PullFailure::Timeout),
        );
        host.finish();
    }
}
