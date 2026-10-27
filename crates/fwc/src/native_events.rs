//! Capability-authorized consumers for the native host's durable event journal.
//!
//! Polling is deliberately separate from acknowledgement: rendering output or
//! losing an HTTP response must never release provider credit. Stable request
//! and stream identities make explicit retries safe after an uncertain result.

use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::Result;
use clap::{Args, Subcommand};
use fcp_core::{CapabilityToken, ConnectorId, EventAck, EventEnvelope, InstanceId, ZoneId};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    CliExitCode, CommandAvailability, CommandEnvelope, DispatchOutcome, HostAdminClient,
    parse_capability_token_bytes, resolve_host_config,
};

const MAX_TOKEN_BYTES: u64 = 64 * 1024;
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_BYTES: u64 = 2 * 1024 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Args, Debug)]
pub(crate) struct StreamsArgs {
    #[command(subcommand)]
    command: StreamCommand,
}

#[derive(Subcommand, Debug)]
enum StreamCommand {
    /// Open a durable subscription, or resume the same stream with renewed authority.
    Open(OpenArgs),
    /// Read retained deliveries without acknowledging them or releasing provider credit.
    Poll(PollArgs),
    /// Commit the exact sequence/cursor pairs only after your processing succeeds.
    Ack(AckArgs),
    /// Stop new events while retaining every unacknowledged delivery.
    Close(RetainedArgs),
}

// Credentials are file-only, so command history, Debug, and parse errors cannot
// contain an inline bearer token. Never serialize the loaded authority object
// into a command result, error, or local resume artifact.
#[derive(Args, Debug)]
struct AuthorityArgs {
    /// Exact connector ID admitted by the selected host, for example fcp.telegram.
    #[arg(long, value_name = "CONNECTOR_ID")]
    connector: String,

    /// Exact zone authorized by the capability, for example z:work.
    #[arg(long, value_name = "ZONE_ID")]
    zone: String,

    /// One exact manifest event topic; wildcards are not supported.
    #[arg(long, value_name = "TOPIC")]
    topic: String,

    /// Stable request identity. Reuse it when retrying an open whose response was lost.
    #[arg(long, value_name = "REQUEST_ID")]
    request_id: String,

    /// Read the signed capability from a regular file containing base64, JSON, or COSE CBOR.
    #[arg(long, value_name = "PATH")]
    capability_token_file: PathBuf,

    /// Whole HTTP request deadline, including the response body (1-90 seconds).
    #[arg(long, default_value_t = 70, value_parser = clap::value_parser!(u64).range(1..=90))]
    timeout_seconds: u64,
}

#[derive(Args, Debug)]
struct OpenArgs {
    #[command(flatten)]
    auth: AuthorityArgs,

    /// Retained stream to resume. Omitted derives its identity from scope and request ID.
    #[arg(long, value_name = "STREAM_ID")]
    stream_id: Option<String>,

    /// Maximum outstanding events; resuming a stream must preserve its original window.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=64))]
    window_size: u32,
}

#[derive(Args, Debug)]
struct RetainedArgs {
    #[command(flatten)]
    auth: AuthorityArgs,

    /// Exact stream ID returned by open; this identifier is not authorization.
    #[arg(long, value_name = "STREAM_ID")]
    stream_id: String,
}

#[derive(Args, Debug)]
struct PollArgs {
    #[command(flatten)]
    retained: RetainedArgs,

    /// Maximum retained events to return in this batch.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=64))]
    batch_size: u32,

    /// Wait up to this many seconds for the first nonempty batch (0-60).
    /// Only successful empty polls are repeated; no event is acknowledged.
    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u64).range(0..=60))]
    wait_seconds: u64,
}

#[derive(Args, Debug)]
struct AckArgs {
    #[command(flatten)]
    retained: RetainedArgs,

    /// Delivered sequence number. Repeat together with --cursor for a batch.
    #[arg(long = "seq", required = true, value_name = "SEQUENCE")]
    seqs: Vec<u64>,

    /// Delivered cursor; entries pair with --seq in their respective order.
    #[arg(long = "cursor", required = true, value_name = "CURSOR")]
    cursors: Vec<String>,
}

impl StreamCommand {
    fn auth(&self) -> &AuthorityArgs {
        match self {
            Self::Open(args) => &args.auth,
            Self::Poll(args) => &args.retained.auth,
            Self::Ack(args) => &args.retained.auth,
            Self::Close(args) => &args.auth,
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Open(_) => "open",
            Self::Poll(_) => "poll",
            Self::Ack(_) => "ack",
            Self::Close(_) => "close",
        }
    }

    fn stream_id(&self) -> Option<&str> {
        match self {
            Self::Open(args) => args.stream_id.as_deref(),
            Self::Poll(args) => Some(&args.retained.stream_id),
            Self::Ack(args) => Some(&args.retained.stream_id),
            Self::Close(args) => Some(&args.stream_id),
        }
    }

    fn mutates_subscription(&self) -> bool {
        !matches!(self, Self::Poll(_))
    }
}

#[derive(Serialize)]
struct Authority {
    request_id: String,
    connector_id: ConnectorId,
    zone_id: ZoneId,
    topic: String,
    capability_token: CapabilityToken,
}

#[derive(Clone, Deserialize, Serialize)]
struct Binding {
    principal: String,
    connector_id: ConnectorId,
    zone_id: ZoneId,
    topic: String,
}

#[derive(Clone, Deserialize, Serialize)]
struct StreamMetadata {
    stream_id: String,
    binding: Binding,
    instance_id: InstanceId,
    window_size: u32,
    pending_events: usize,
    acknowledged_events: usize,
    closed: bool,
    durable: bool,
}

#[derive(Deserialize, Serialize)]
struct OpenResponse {
    stream: StreamMetadata,
    attached: bool,
    replay_supported: bool,
}

#[derive(Deserialize, Serialize)]
struct PollResponse {
    stream: StreamMetadata,
    events: Vec<EventEnvelope>,
}

#[derive(Deserialize, Serialize)]
struct AckResponse {
    stream: StreamMetadata,
    acknowledged: bool,
    upstream_notified: bool,
}

#[derive(Deserialize, Serialize)]
struct CloseResponse {
    stream: StreamMetadata,
    upstream_notified: bool,
}

#[derive(Clone, Copy, Debug)]
enum Failure {
    InvalidRequest,
    MissingHost,
    InvalidHost,
    Credential,
    Transport,
    Timeout,
    Http(u16),
    InvalidResponse,
    ResponseTooLarge,
}

impl Failure {
    fn details(self) -> (&'static str, &'static str, CliExitCode) {
        match self {
            Self::InvalidRequest => (
                "invalid-stream-request",
                "Stream scope, stable identities, window, deadline, or exact acknowledgement pairs are invalid or exceed their bounds.",
                CliExitCode::Validation,
            ),
            Self::MissingHost => (
                "missing-host-endpoint",
                "Native event consumption requires the host that owns the durable stream. Supply --host or configure a host context.",
                CliExitCode::Transport,
            ),
            Self::InvalidHost => (
                "invalid-stream-host",
                "The selected host endpoint or host client configuration could not be used.",
                CliExitCode::Validation,
            ),
            Self::Credential => (
                "invalid-stream-capability",
                "The capability file must be a readable regular file of at most 64 KiB containing a signed COSE capability in base64, JSON, or CBOR form.",
                CliExitCode::Validation,
            ),
            Self::Transport => (
                "stream-transport-failed",
                "The selected host did not return a complete readable response. No producer acknowledgement is implied.",
                CliExitCode::Transport,
            ),
            Self::Timeout => (
                "stream-request-timeout",
                "The stream request exceeded its bounded deadline. Reconcile using the original request and stream identities.",
                CliExitCode::Transport,
            ),
            Self::Http(401 | 403) => (
                "stream-authority-denied",
                "The selected host rejected stream authority. Check the signed subject, grant, instance, zone, resource, and current policy.",
                CliExitCode::PolicyDenied,
            ),
            Self::Http(300..=399) => (
                "stream-redirect-refused",
                "The selected host returned a redirect. The capability was not forwarded to the redirect target.",
                CliExitCode::Transport,
            ),
            Self::Http(_) => (
                "stream-host-rejected",
                "The selected host returned an unsuccessful status. Its response body is omitted because it may echo credentials.",
                CliExitCode::Connector,
            ),
            Self::InvalidResponse => (
                "invalid-stream-response",
                "The host response did not match the requested stream scope or canonical event contract.",
                CliExitCode::Transport,
            ),
            Self::ResponseTooLarge => (
                "stream-response-too-large",
                "The selected host exceeded the 2 MiB stream response limit.",
                CliExitCode::Transport,
            ),
        }
    }

    fn may_have_reached_host(self) -> bool {
        matches!(
            self,
            Self::Transport
                | Self::Timeout
                | Self::Http(_)
                | Self::InvalidResponse
                | Self::ResponseTooLarge
        )
    }
}

pub(crate) fn dispatch(args: &StreamsArgs, explicit_host: Option<&str>) -> Result<DispatchOutcome> {
    let command = &args.command;
    let auth = match authority(command) {
        Ok(auth) => auth,
        Err(error) => return Ok(failure(command, None, error)),
    };
    let host = match resolve_host_config(explicit_host) {
        Ok(Some(host)) => host,
        Ok(None) => return Ok(failure(command, None, Failure::MissingHost)),
        Err(_) => return Ok(failure(command, None, Failure::InvalidHost)),
    };
    // This existing client disables redirects and automatic retries for every
    // endpoint form, including Unix sockets. Do not use decode_response, which
    // intentionally exposes admin API error text unsuitable for bearer bodies.
    let client = match HostAdminClient::new(&host.endpoint) {
        Ok(client) => client,
        Err(_) => return Ok(failure(command, None, Failure::InvalidHost)),
    };
    match execute(command, &auth, &client) {
        Ok(mut payload) => {
            payload["status"] = json!("ok");
            payload["command"] = json!("streams");
            payload["subcommand"] = json!(command.name());
            payload["source"] = json!("selected-host-native-event-journal");
            payload["host"] = json!(client.endpoint);
            payload["request_id"] = json!(auth.request_id);
            CommandEnvelope::new(CommandAvailability::LiveRuntime, "streams")
                .inject_into(&mut payload);
            Ok(DispatchOutcome {
                payload,
                exit_code: CliExitCode::Success,
            })
        }
        Err(error) => Ok(failure(command, Some(&client.endpoint), error)),
    }
}

fn bounded_identity(value: &str, limit: usize) -> bool {
    !value.trim().is_empty() && value.len() <= limit && !value.chars().any(char::is_control)
}

fn valid_stream_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn authority(command: &StreamCommand) -> std::result::Result<Authority, Failure> {
    let args = command.auth();
    if !bounded_identity(&args.request_id, 128)
        || !bounded_identity(&args.topic, 256)
        || args.topic.chars().any(char::is_whitespace)
        || args.topic.contains('*')
        || !(1..=90).contains(&args.timeout_seconds)
        || command.stream_id().is_some_and(|id| !valid_stream_id(id))
    {
        return Err(Failure::InvalidRequest);
    }
    match command {
        StreamCommand::Open(args) if !(1..=64).contains(&args.window_size) => {
            return Err(Failure::InvalidRequest);
        }
        StreamCommand::Poll(args)
            if !(1..=64).contains(&args.batch_size) || args.wait_seconds > 60 =>
        {
            return Err(Failure::InvalidRequest);
        }
        StreamCommand::Ack(args) => validate_ack_pairs(&args.seqs, &args.cursors)?,
        _ => {}
    }
    let connector_id = args
        .connector
        .parse()
        .map_err(|_| Failure::InvalidRequest)?;
    let zone_id = args.zone.parse().map_err(|_| Failure::InvalidRequest)?;
    let metadata =
        std::fs::metadata(&args.capability_token_file).map_err(|_| Failure::Credential)?;
    if !metadata.is_file() || metadata.len() > MAX_TOKEN_BYTES {
        return Err(Failure::Credential);
    }
    let file = File::open(&args.capability_token_file).map_err(|_| Failure::Credential)?;
    if !file.metadata().map_err(|_| Failure::Credential)?.is_file() {
        return Err(Failure::Credential);
    }
    let mut bytes = Vec::new();
    file.take(MAX_TOKEN_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::Credential)?;
    if bytes.len() as u64 > MAX_TOKEN_BYTES {
        return Err(Failure::Credential);
    }
    let capability_token =
        parse_capability_token_bytes(&bytes, "capability file").map_err(|_| Failure::Credential)?;
    Ok(Authority {
        request_id: args.request_id.clone(),
        connector_id,
        zone_id,
        topic: args.topic.clone(),
        capability_token,
    })
}

fn validate_ack_pairs(seqs: &[u64], cursors: &[String]) -> std::result::Result<(), Failure> {
    let mut seen_cursors = HashSet::new();
    // Native sequences can restart across instances. The durable identity is
    // the exact sequence/cursor pair, so only duplicate cursors are ambiguous.
    if seqs.is_empty()
        || seqs.len() > 64
        || seqs.len() != cursors.len()
        || cursors
            .iter()
            .any(|cursor| !bounded_identity(cursor, 1024) || !seen_cursors.insert(cursor))
    {
        return Err(Failure::InvalidRequest);
    }
    Ok(())
}

fn check_stream(
    stream: &StreamMetadata,
    auth: &Authority,
    expected_id: Option<&str>,
) -> std::result::Result<(), Failure> {
    if !valid_stream_id(&stream.stream_id)
        || expected_id.is_some_and(|id| id != stream.stream_id)
        || stream.binding.connector_id != auth.connector_id
        || stream.binding.zone_id != auth.zone_id
        || stream.binding.topic != auth.topic
        || !bounded_identity(&stream.binding.principal, 1024)
        || !(1..=64).contains(&stream.window_size)
        || stream.pending_events > stream.window_size as usize
        || !stream.durable
    {
        return Err(Failure::InvalidResponse);
    }
    Ok(())
}

fn execute(
    command: &StreamCommand,
    auth: &Authority,
    client: &HostAdminClient,
) -> std::result::Result<Value, Failure> {
    let timeout = Duration::from_secs(command.auth().timeout_seconds);
    match command {
        StreamCommand::Open(args) => {
            let response: OpenResponse = post(
                client,
                "/rpc/streams/open",
                &json!({
                    "auth": auth, "stream_id": args.stream_id, "window_size": args.window_size,
                }),
                timeout,
            )?;
            check_stream(&response.stream, auth, args.stream_id.as_deref())?;
            if !response.attached
                || response.stream.closed
                || response.stream.window_size != args.window_size
            {
                return Err(Failure::InvalidResponse);
            }
            encode(response)
        }
        StreamCommand::Poll(args) => poll(client, auth, args, timeout),
        StreamCommand::Ack(args) => {
            let ack =
                EventAck::new(&auth.topic, args.seqs.clone()).with_cursors(args.cursors.clone());
            let response: AckResponse = post(
                client,
                "/rpc/streams/ack",
                &json!({
                    "auth": auth, "stream_id": args.retained.stream_id, "ack": ack,
                }),
                timeout,
            )?;
            check_stream(&response.stream, auth, Some(&args.retained.stream_id))?;
            if !response.acknowledged {
                return Err(Failure::InvalidResponse);
            }
            let mut payload = encode(response)?;
            payload["ack"] = encode(ack)?;
            Ok(payload)
        }
        StreamCommand::Close(args) => {
            let response: CloseResponse = post(
                client,
                "/rpc/streams/close",
                &json!({
                    "auth": auth, "stream_id": args.stream_id,
                }),
                timeout,
            )?;
            check_stream(&response.stream, auth, Some(&args.stream_id))?;
            if !response.stream.closed {
                return Err(Failure::InvalidResponse);
            }
            encode(response)
        }
    }
}

fn poll(
    client: &HostAdminClient,
    auth: &Authority,
    args: &PollArgs,
    timeout: Duration,
) -> std::result::Result<Value, Failure> {
    let deadline =
        (args.wait_seconds > 0).then(|| Instant::now() + Duration::from_secs(args.wait_seconds));
    let body =
        json!({ "auth": auth, "stream_id": args.retained.stream_id, "limit": args.batch_size });
    loop {
        let remaining = deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()));
        let response: PollResponse = post(
            client,
            "/rpc/streams/poll",
            &body,
            remaining.map_or(timeout, |remaining| timeout.min(remaining)),
        )?;
        check_stream(&response.stream, auth, Some(&args.retained.stream_id))?;
        if response.events.len() > args.batch_size as usize
            || response.events.len() > response.stream.pending_events
        {
            return Err(Failure::InvalidResponse);
        }
        let mut seqs = Vec::new();
        let mut cursors = Vec::new();
        for event in &response.events {
            // Original pending payloads retain their original instance after
            // reattachment. Validate source scope, not old-instance equality.
            if event.topic != auth.topic
                || event.data.connector_id != auth.connector_id
                || event.data.zone_id != auth.zone_id
                || !event.requires_ack
            {
                return Err(Failure::InvalidResponse);
            }
            seqs.push(event.seq);
            cursors.push(event.cursor.clone());
        }
        if !seqs.is_empty() {
            validate_ack_pairs(&seqs, &cursors).map_err(|_| Failure::InvalidResponse)?;
        }
        let wait_expired = deadline.is_some_and(|deadline| Instant::now() >= deadline);
        if !response.events.is_empty()
            || response.stream.closed
            || deadline.is_none()
            || wait_expired
        {
            let mut payload = encode(response)?;
            payload["acknowledged"] = json!(false);
            payload["wait_expired"] = json!(wait_expired);
            if !seqs.is_empty() {
                payload["ack_request"] =
                    encode(EventAck::new(&auth.topic, seqs).with_cursors(cursors))?;
            }
            return Ok(payload);
        }
        let remaining = deadline
            .expect("bounded wait")
            .saturating_duration_since(Instant::now());
        std::thread::sleep(POLL_INTERVAL.min(remaining));
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            // Preserve the last confirmed empty batch instead of starting a
            // zero-budget request when the waiting interval consumes the deadline.
            let mut payload = encode(response)?;
            payload["acknowledged"] = json!(false);
            payload["wait_expired"] = json!(true);
            return Ok(payload);
        }
    }
}

fn encode(value: impl Serialize) -> std::result::Result<Value, Failure> {
    serde_json::to_value(value).map_err(|_| Failure::InvalidResponse)
}

fn post<B: Serialize, T: DeserializeOwned>(
    client: &HostAdminClient,
    path: &'static str,
    body: &B,
    timeout: Duration,
) -> std::result::Result<T, Failure> {
    let bytes = serde_json::to_vec(body).map_err(|_| Failure::InvalidRequest)?;
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(Failure::InvalidRequest);
    }
    if timeout.is_zero() {
        return Err(Failure::Timeout);
    }
    let response = client
        .client
        .post(format!("{}{}", client.base_url, path))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .timeout(timeout)
        .body(bytes)
        .send()
        .map_err(|error| {
            if error.is_timeout() {
                Failure::Timeout
            } else {
                Failure::Transport
            }
        })?;
    if !response.status().is_success() {
        return Err(Failure::Http(response.status().as_u16()));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES)
    {
        return Err(Failure::ResponseTooLarge);
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::TimedOut
                || error
                    .get_ref()
                    .and_then(|cause| cause.downcast_ref::<reqwest::Error>())
                    .is_some_and(reqwest::Error::is_timeout)
            {
                Failure::Timeout
            } else {
                Failure::Transport
            }
        })?;
    if bytes.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(Failure::ResponseTooLarge);
    }
    serde_json::from_slice(&bytes).map_err(|_| Failure::InvalidResponse)
}

fn failure(command: &StreamCommand, endpoint: Option<&str>, failure: Failure) -> DispatchOutcome {
    let (kind, message, exit_code) = failure.details();
    let mut payload = json!({
        "status": "error", "command": "streams", "subcommand": command.name(),
        "source": "selected-host-native-event-journal", "host": endpoint,
        "error": { "type": kind, "message": message },
        "outcome_unknown": command.mutates_subscription() && failure.may_have_reached_host(),
        "request_id": command.auth().request_id, "stream_id": command.stream_id(),
        "scope": { "connector_id": command.auth().connector, "zone_id": command.auth().zone, "topic": command.auth().topic },
        "next_actions": ["Keep the original host, request ID, stream ID, and delivered sequence/cursor pairs when retrying. Polling never acknowledges events; acknowledge only after processing succeeds."],
    });
    if let Failure::Http(status) = failure {
        payload["error"]["http_status"] = json!(status);
    }
    if let StreamCommand::Ack(args) = command {
        payload["ack"] = json!({"type": "ack", "topic": args.retained.auth.topic, "seqs": args.seqs, "cursors": args.cursors});
    }
    let availability = if matches!(failure, Failure::Http(401 | 403)) {
        CommandAvailability::Denied
    } else {
        CommandAvailability::Unavailable
    };
    let mut envelope = CommandEnvelope::new(availability, "streams");
    envelope.explanation = message.to_owned();
    envelope.next_actions = vec![
        "Reconcile this stream on the selected host with its original identities and valid authority."
            .to_owned(),
    ];
    envelope.inject_into(&mut payload);
    DispatchOutcome { payload, exit_code }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;

    // Structural COSE_Sign1 fixture only. The CLI parses it; the real host
    // remains responsible for signature, grant, timing, and instance checks.
    const TOKEN_CBOR: &[u8] = &[0x84, 0x40, 0xa0, 0x40, 0x40];
    const STREAM: &str = "stream-fixture";
    const TOPIC: &str = "telegram.message.new";

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        streams: StreamsArgs,
    }

    struct Captured {
        path: String,
        body: Value,
    }

    fn read_request(stream: &mut std::net::TcpStream) -> Captured {
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let path = line.split_whitespace().nth(1).unwrap().to_owned();
        let mut length = 0;
        loop {
            line.clear();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                if name.eq_ignore_ascii_case("content-length") {
                    length = value.trim().parse().unwrap();
                }
            }
        }
        assert!(length <= MAX_REQUEST_BYTES);
        let mut body = vec![0; length];
        reader.read_exact(&mut body).unwrap();
        Captured {
            path,
            body: serde_json::from_slice(&body).unwrap(),
        }
    }

    fn host(responses: Vec<Value>) -> (String, std::thread::JoinHandle<Vec<Captured>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let task = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for response in responses {
                let (mut stream, _) = listener.accept().unwrap();
                requests.push(read_request(&mut stream));
                let body = response.to_string();
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
            requests
        });
        (endpoint, task)
    }

    fn metadata(closed: bool, pending: usize, acknowledged: usize) -> Value {
        json!({
            "stream_id": STREAM,
            "binding": {"principal":"agent:alice", "connector_id":"fcp.telegram", "zone_id":"z:work", "topic":TOPIC},
            "instance_id":"inst_current", "window_size":1,
            "pending_events":pending, "acknowledged_events":acknowledged,
            "closed":closed, "durable":true,
        })
    }

    fn event() -> Value {
        json!({
            "topic":TOPIC, "timestamp":"2026-10-27T00:00:00Z", "seq":7,
            "cursor":"provider-7", "requires_ack":true,
            "data": {
                "connector_id":"fcp.telegram", "instance_id":"inst_predecessor", "zone_id":"z:work",
                "principal":{"kind":"provider_user", "id":"user-1", "trust":"untrusted", "display":null},
                "payload":{"message":"retained event"}, "resource_uris":[],
            },
        })
    }

    fn credential() -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(TOKEN_CBOR).unwrap();
        file
    }

    fn args(file: &std::path::Path, command: &str, extra: &[&str]) -> StreamsArgs {
        let mut argv = vec![
            "streams".to_owned(),
            command.to_owned(),
            "--connector".to_owned(),
            "fcp.telegram".to_owned(),
            "--zone".to_owned(),
            "z:work".to_owned(),
            "--topic".to_owned(),
            TOPIC.to_owned(),
            "--request-id".to_owned(),
            "consumer-stable-1".to_owned(),
            "--capability-token-file".to_owned(),
            file.to_string_lossy().into_owned(),
        ];
        argv.extend(extra.iter().map(|arg| (*arg).to_owned()));
        TestCli::try_parse_from(argv).unwrap().streams
    }

    #[test]
    fn open_poll_ack_close_preserve_host_identity_and_exact_delivery_pairs() {
        let file = credential();
        let (endpoint, task) = host(vec![
            json!({"stream":metadata(false,0,0),"attached":true,"replay_supported":false,"capability_token":"SERVER_ECHO_SENTINEL"}),
            json!({"stream":metadata(false,1,0),"events":[event()]}),
            json!({"stream":metadata(false,0,1),"acknowledged":true,"upstream_notified":false}),
            json!({"stream":metadata(true,0,1),"upstream_notified":true}),
        ]);
        let opened = dispatch(&args(file.path(), "open", &[]), Some(&endpoint)).unwrap();
        assert_eq!(opened.exit_code, CliExitCode::Success);
        assert_eq!(opened.payload["host"], endpoint);
        assert_eq!(opened.payload["stream"]["stream_id"], STREAM);
        assert!(!opened.payload.to_string().contains("SERVER_ECHO_SENTINEL"));
        let polled = dispatch(
            &args(file.path(), "poll", &["--stream-id", STREAM]),
            Some(&endpoint),
        )
        .unwrap();
        assert_eq!(polled.exit_code, CliExitCode::Success);
        assert_eq!(polled.payload["acknowledged"], false);
        assert_eq!(
            polled.payload["events"][0]["data"]["instance_id"],
            "inst_predecessor"
        );
        assert_eq!(polled.payload["ack_request"]["seqs"], json!([7]));
        assert_eq!(
            polled.payload["ack_request"]["cursors"],
            json!(["provider-7"])
        );
        let acked = dispatch(
            &args(
                file.path(),
                "ack",
                &[
                    "--stream-id",
                    STREAM,
                    "--seq",
                    "7",
                    "--cursor",
                    "provider-7",
                ],
            ),
            Some(&endpoint),
        )
        .unwrap();
        assert_eq!(acked.exit_code, CliExitCode::Success);
        assert_eq!(acked.payload["acknowledged"], true);
        assert_eq!(acked.payload["upstream_notified"], false);
        let closed = dispatch(
            &args(file.path(), "close", &["--stream-id", STREAM]),
            Some(&endpoint),
        )
        .unwrap();
        assert_eq!(closed.exit_code, CliExitCode::Success);
        assert_eq!(closed.payload["stream"]["closed"], true);
        let requests = task.join().unwrap();
        assert_eq!(
            requests
                .iter()
                .map(|request| request.path.as_str())
                .collect::<Vec<_>>(),
            [
                "/rpc/streams/open",
                "/rpc/streams/poll",
                "/rpc/streams/ack",
                "/rpc/streams/close"
            ]
        );
        for request in &requests {
            assert_eq!(request.body["auth"]["request_id"], "consumer-stable-1");
            assert_eq!(request.body["auth"]["connector_id"], "fcp.telegram");
            assert!(request.body["auth"]["capability_token"].is_array());
        }
        assert_eq!(requests[2].body["ack"]["seqs"], json!([7]));
        assert_eq!(requests[2].body["ack"]["cursors"], json!(["provider-7"]));
    }

    #[test]
    fn resume_reuses_stream_request_identity_and_declared_window() {
        let file = credential();
        let response =
            json!({"stream":metadata(false,0,0),"attached":true,"replay_supported":false});
        let (endpoint, task) = host(vec![response.clone(), response]);
        let args = args(file.path(), "open", &["--stream-id", STREAM]);
        for _ in 0..2 {
            assert_eq!(
                dispatch(&args, Some(&endpoint)).unwrap().exit_code,
                CliExitCode::Success
            );
        }
        let requests = task.join().unwrap();
        assert_eq!(requests[0].body, requests[1].body);
        assert_eq!(requests[0].body["stream_id"], STREAM);
        assert_eq!(requests[0].body["window_size"], 1);
    }

    #[test]
    fn bounded_wait_stops_at_first_batch_without_acknowledging() {
        let file = credential();
        let (endpoint, task) = host(vec![
            json!({"stream":metadata(false,0,0),"events":[]}),
            json!({"stream":metadata(false,1,0),"events":[event()]}),
        ]);
        let result = dispatch(
            &args(
                file.path(),
                "poll",
                &["--stream-id", STREAM, "--wait-seconds", "2"],
            ),
            Some(&endpoint),
        )
        .unwrap();
        assert_eq!(result.exit_code, CliExitCode::Success);
        assert_eq!(result.payload["events"].as_array().unwrap().len(), 1);
        assert_eq!(result.payload["acknowledged"], false);
        let requests = task.join().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(
            requests
                .iter()
                .all(|request| request.path == "/rpc/streams/poll")
        );
    }

    #[test]
    fn bounded_wait_returns_last_empty_batch_when_deadline_expires() {
        let file = credential();
        let empty = json!({"stream":metadata(false,0,0),"events":[]});
        let (endpoint, task) = host(vec![empty.clone(), empty]);
        let started = Instant::now();
        let result = dispatch(
            &args(
                file.path(),
                "poll",
                &["--stream-id", STREAM, "--wait-seconds", "1"],
            ),
            Some(&endpoint),
        )
        .unwrap();
        assert_eq!(result.exit_code, CliExitCode::Success);
        assert_eq!(result.payload["wait_expired"], true);
        assert_eq!(result.payload["acknowledged"], false);
        assert!(started.elapsed() < Duration::from_secs(3));
        assert_eq!(task.join().unwrap().len(), 2);
    }

    #[test]
    fn poll_rejects_wrong_scope_and_ambiguous_event_identities() {
        let file = credential();
        let mut wrong_zone = event();
        wrong_zone["data"]["zone_id"] = json!("z:owner");
        let mut wrong_topic = metadata(false, 1, 0);
        wrong_topic["binding"]["topic"] = json!("telegram.callback_query");
        let mut non_durable = metadata(false, 1, 0);
        non_durable["durable"] = json!(false);
        let mut two_pending = metadata(false, 2, 0);
        two_pending["window_size"] = json!(2);
        let (endpoint, task) = host(vec![
            json!({"stream":metadata(false,1,0),"events":[wrong_zone]}),
            json!({"stream":wrong_topic,"events":[event()]}),
            json!({"stream":non_durable,"events":[event()]}),
            json!({"stream":two_pending,"events":[event(),event()]}),
        ]);
        for _ in 0..4 {
            let result = dispatch(
                &args(
                    file.path(),
                    "poll",
                    &["--stream-id", STREAM, "--batch-size", "2"],
                ),
                Some(&endpoint),
            )
            .unwrap();
            assert_eq!(result.exit_code, CliExitCode::Transport);
            assert_eq!(result.payload["error"]["type"], "invalid-stream-response");
            assert!(result.payload.get("events").is_none());
        }
        task.join().unwrap();
    }

    #[test]
    fn restarted_instances_can_share_sequences_with_distinct_cursors() {
        let file = credential();
        let mut second = event();
        second["data"]["instance_id"] = json!("inst_current");
        second["cursor"] = json!("provider-8");
        let mut pending = metadata(false, 2, 0);
        pending["window_size"] = json!(2);
        let mut acknowledged = metadata(false, 0, 2);
        acknowledged["window_size"] = json!(2);
        let (endpoint, task) = host(vec![
            json!({"stream":pending,"events":[event(),second]}),
            json!({"stream":acknowledged,"acknowledged":true,"upstream_notified":true}),
        ]);
        let polled = dispatch(
            &args(
                file.path(),
                "poll",
                &["--stream-id", STREAM, "--batch-size", "2"],
            ),
            Some(&endpoint),
        )
        .unwrap();
        assert_eq!(polled.exit_code, CliExitCode::Success);
        assert_eq!(polled.payload["ack_request"]["seqs"], json!([7, 7]));
        assert_eq!(
            polled.payload["ack_request"]["cursors"],
            json!(["provider-7", "provider-8"])
        );
        let acked = dispatch(
            &args(
                file.path(),
                "ack",
                &[
                    "--stream-id",
                    STREAM,
                    "--seq",
                    "7",
                    "--cursor",
                    "provider-7",
                    "--seq",
                    "7",
                    "--cursor",
                    "provider-8",
                ],
            ),
            Some(&endpoint),
        )
        .unwrap();
        assert_eq!(acked.exit_code, CliExitCode::Success);
        let requests = task.join().unwrap();
        assert_eq!(requests[1].body["ack"]["seqs"], json!([7, 7]));
        assert_eq!(
            requests[1].body["ack"]["cursors"],
            json!(["provider-7", "provider-8"])
        );
    }

    #[test]
    fn invalid_ack_pairs_and_oversized_credentials_fail_before_transport() {
        for (seqs, cursors) in [
            (vec![], vec![]),
            (vec![1], vec![]),
            (vec![1, 2], vec!["a".into(), "a".into()]),
            (vec![1], vec!["".into()]),
        ] {
            assert!(validate_ack_pairs(&seqs, &cursors).is_err());
        }
        let mut file = credential();
        file.as_file_mut().set_len(MAX_TOKEN_BYTES + 1).unwrap();
        let result = dispatch(&args(file.path(), "open", &[]), Some("http://127.0.0.1:1")).unwrap();
        assert_eq!(result.exit_code, CliExitCode::Validation);
        assert_eq!(result.payload["error"]["type"], "invalid-stream-capability");
        assert_eq!(result.payload["outcome_unknown"], false);
    }

    #[test]
    fn redirect_never_forwards_capability_or_echoes_error_body() {
        let file = credential();
        let sink = TcpListener::bind("127.0.0.1:0").unwrap();
        sink.set_nonblocking(true).unwrap();
        let location = format!("http://{}/credential-sink", sink.local_addr().unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let task = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_request(&mut stream);
            let echo = format!("SERVER_SECRET_ECHO {}", request.body);
            write!(stream, "HTTP/1.1 307 Temporary Redirect\r\nLocation: {location}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{echo}", echo.len()).unwrap();
            request
        });
        let result = dispatch(&args(file.path(), "open", &[]), Some(&endpoint)).unwrap();
        assert_eq!(result.payload["error"]["type"], "stream-redirect-refused");
        assert_eq!(result.payload["outcome_unknown"], true);
        assert!(!result.payload.to_string().contains("SERVER_SECRET_ECHO"));
        assert!(!result.payload.to_string().contains("capability_token"));
        assert!(
            matches!(sink.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
        assert_eq!(task.join().unwrap().path, "/rpc/streams/open");
    }

    #[test]
    fn response_size_limit_applies_with_and_without_content_length() {
        for declared in [true, false] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let task = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                read_request(&mut stream);
                write!(stream, "HTTP/1.1 200 OK\r\nConnection: close\r\n").unwrap();
                if declared {
                    write!(stream, "Content-Length: {}\r\n\r\n", MAX_RESPONSE_BYTES + 1).unwrap();
                } else {
                    stream.write_all(b"\r\n").unwrap();
                    let _ = stream.write_all(&vec![b' '; MAX_RESPONSE_BYTES as usize + 1]);
                }
            });
            let client = HostAdminClient::new(&endpoint).unwrap();
            let result: std::result::Result<Value, _> = post(
                &client,
                "/rpc/streams/poll",
                &json!({}),
                Duration::from_secs(3),
            );
            assert!(matches!(result, Err(Failure::ResponseTooLarge)));
            task.join().unwrap();
        }
    }

    #[test]
    fn deadline_includes_slow_response_body() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let task = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_request(&mut stream);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{")
                .unwrap();
            std::thread::sleep(Duration::from_millis(150));
            let _ = stream.write_all(b"}");
        });
        let client = HostAdminClient::new(&endpoint).unwrap();
        let result: std::result::Result<Value, _> = post(
            &client,
            "/rpc/streams/poll",
            &json!({}),
            Duration::from_millis(40),
        );
        assert!(matches!(result, Err(Failure::Timeout)));
        task.join().unwrap();
    }
}
