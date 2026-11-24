//! Resumable, bounded observation of the host's retained event journal.
//!
//! Cursor resolution belongs to the host and precedes filtering. A missing
//! cursor fails closed instead of silently replaying retained history. Every
//! record is flushed; closed output drops the response immediately. Only a
//! validated bounded completion permits another HTTP stream. One deadline
//! covers all connections and reads. As with other synchronous CLI writers,
//! blocked stdout must make progress before execution can return.

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use anyhow::Result;
use chrono::{DateTime, TimeDelta, Utc};
use fcp_host::HostEvent;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{
    CliExitCode, Commands, ExecutionOutcome, HostAdminClient, OutputFormat, PreparedCli, TailArgs,
    event_stream, host_event_matches_type_filter, host_event_to_connector_event, invocation_cmd,
    pipe::budget::ExecutionBudget, resolve_host_config,
};

const MAX_STREAM_EVENTS: usize = 10_000;
const MAX_FRAME_BYTES: usize = 1024 * 1024;
const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;
const FOLLOW_ROUTE: &str = "/rpc/admin/events/follow";
const TERMINAL_ALLOWANCE_MS: u64 = 250;

#[derive(Serialize)]
struct FollowRequest {
    connector_id: Option<String>,
    after_event_id: Option<String>,
    timeout_ms: u64,
    poll_interval_ms: u64,
    max_events: usize,
}

#[derive(Deserialize)]
struct WireRecord {
    source: String,
    latest_cursor: Option<String>,
    event_count: usize,
    #[serde(flatten)]
    payload: WirePayload,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WirePayload {
    Start {
        timeout_ms: u64,
        poll_interval_ms: u64,
        max_events: usize,
    },
    Event {
        event: HostEvent,
    },
    Checkpoint,
    Complete {
        reason: String,
    },
    Error {
        code: String,
    },
}

#[derive(Debug)]
struct Failure {
    kind: &'static str,
    message: &'static str,
    exit_code: CliExitCode,
}

impl Failure {
    fn validation(kind: &'static str, message: &'static str) -> Self {
        Self {
            kind,
            message,
            exit_code: CliExitCode::Validation,
        }
    }

    fn transport(kind: &'static str, message: &'static str) -> Self {
        Self {
            kind,
            message,
            exit_code: CliExitCode::Transport,
        }
    }
}

enum Stopped {
    Limit,
    Timeout,
    Failed(Failure),
    OutputClosed,
}

#[derive(Default)]
struct Progress {
    cursor: Option<String>,
    events: usize,
    polls: u64,
}

pub(super) fn execute(prepared: &PreparedCli) -> Result<ExecutionOutcome> {
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();
    Ok(ExecutionOutcome {
        text: String::new(),
        exit_code: execute_with_writer(prepared, &mut writer)?,
    })
}

pub(super) fn execute_with_writer(
    prepared: &PreparedCli,
    writer: &mut dyn Write,
) -> Result<ExitCode> {
    let Commands::Tail(args) = &prepared.cli.command else {
        anyhow::bail!("event follow requires the tail command");
    };
    let started = Instant::now();
    let mut progress = Progress {
        // Invalid user input must not be reflected as trusted resume evidence.
        cursor: args.cursor.clone().filter(|cursor| valid_cursor(cursor)),
        ..Progress::default()
    };
    let stopped = match prepare(prepared, args, started) {
        Ok((client, token, connectors, cutoff, budget)) => follow(
            &client,
            &token,
            args,
            &connectors,
            cutoff,
            budget,
            &mut progress,
            writer,
        ),
        Err(failure) => Stopped::Failed(failure),
    };
    // A partial write may already contain a frame prefix. Never append another
    // frame, renderer error or terminal summary after output failure.
    if matches!(stopped, Stopped::OutputClosed) {
        return Ok(CliExitCode::Transport.into());
    }
    let (record_type, reason, failure, exit_code) = match stopped {
        Stopped::Limit => ("complete", "event-limit", None, CliExitCode::Success),
        Stopped::Timeout => ("complete", "timeout", None, CliExitCode::Success),
        Stopped::Failed(failure) => (
            "error",
            "failed",
            Some(json!({"type": failure.kind, "message": failure.message})),
            failure.exit_code,
        ),
        Stopped::OutputClosed => unreachable!("output failure handled above"),
    };
    let record = json!({
        "type": record_type, "command": "tail", "mode": "follow",
        "source": if progress.polls == 0 { "local-validation" } else { "host-admin-api" },
        "reason": reason, "latest_cursor": progress.cursor,
        "event_count": progress.events, "polls": progress.polls,
        "elapsed_ms": started.elapsed().as_millis(), "error": failure,
    });
    if write_record(writer, &record).is_err() {
        return Ok(CliExitCode::Transport.into());
    }
    Ok(exit_code.into())
}

type PreparedFollow = (
    HostAdminClient,
    String,
    Vec<String>,
    Option<DateTime<Utc>>,
    ExecutionBudget,
);

fn prepare(
    prepared: &PreparedCli,
    args: &TailArgs,
    started: Instant,
) -> std::result::Result<PreparedFollow, Failure> {
    // Tail's --limit shares clap's global argument ID and is the event count,
    // not a buffered rendering transform. Check the actual transforms only.
    if !matches!(
        prepared.format,
        OutputFormat::Toon | OutputFormat::Ndjson | OutputFormat::Jsonl
    ) || prepared.render_options.has_template()
        || prepared.render_options.has_extract()
        || prepared.cli.token_stats
        || !prepared.cli.columns.is_empty()
        || prepared.cli.sort_by.is_some()
        || prepared.cli.no_headers
    {
        return Err(Failure::validation(
            "incompatible-follow-format",
            "--follow emits flushed NDJSON records; use the default format or --format ndjson without rendering transforms.",
        ));
    }
    if !(1..=86_400_000).contains(&args.timeout_ms)
        || !(1..=60_000).contains(&args.poll_interval_ms)
    {
        return Err(Failure::validation(
            "invalid-follow-timing",
            "Follow requires a timeout of 1..=86400000ms and a poll interval of 1..=60000ms.",
        ));
    }
    if args
        .cursor
        .as_deref()
        .is_some_and(|cursor| !valid_cursor(cursor))
    {
        return Err(Failure::validation(
            "invalid-event-cursor",
            "An event cursor must be nonempty, at most 1024 bytes, and contain no control characters.",
        ));
    }
    let cutoff = args
        .since
        .as_deref()
        .map(|raw| {
            event_stream::parse_since(raw)
                .ok()
                .and_then(|seconds| i64::try_from(seconds).ok())
                .and_then(TimeDelta::try_seconds)
                .and_then(|duration| Utc::now().checked_sub_signed(duration))
                .ok_or_else(|| {
                    Failure::validation(
                        "invalid-since-duration",
                        "The lookback must be a supported duration within the timestamp range.",
                    )
                })
        })
        .transpose()?;
    let connectors = args
        .connector
        .as_deref()
        .map(event_stream::TailConfig::parse_connectors)
        .unwrap_or_default();
    let host = resolve_host_config(prepared.cli.host.as_deref())
        .map_err(|_| {
            Failure::validation(
                "invalid-host-endpoint",
                "The selected host configuration is invalid.",
            )
        })?
        .ok_or_else(|| {
            Failure::transport(
                "missing-host-endpoint",
                "Select a host with --host or FWC_HOST before following events.",
            )
        })?;
    // Owner authority never goes to a proxy or plaintext remote transport, and
    // this dedicated client refuses redirects and automatic HTTP retries.
    let client = HostAdminClient::for_invocation_inspection(&host.endpoint)
        .map_err(|_| Failure::validation(
            "invalid-host-endpoint",
            "Event follow requires HTTPS, literal loopback HTTP, or a Unix socket with a valid host read deadline.",
        ))?;
    let token = invocation_cmd::read_admin_token(args.admin_token_file.as_deref())
        .map_err(|_| Failure::validation(
            "invalid-admin-credential",
            "Provide a bounded ASCII host admin bearer token with --admin-token-file or FCP_HOST_ADMIN_BEARER_TOKEN.",
        ))?;
    let budget = ExecutionBudget::start(Some(args.timeout_ms), started);
    Ok((
        client
            .with_read_budget(budget)
            .with_response_limit(MAX_RESPONSE_BYTES),
        token,
        connectors,
        cutoff,
        budget,
    ))
}

fn follow(
    client: &HostAdminClient,
    token: &str,
    args: &TailArgs,
    connectors: &[String],
    cutoff: Option<DateTime<Utc>>,
    budget: ExecutionBudget,
    progress: &mut Progress,
    writer: &mut dyn Write,
) -> Stopped {
    if write_record(writer, &json!({
        "type": "start", "command": "tail", "mode": "follow",
        "source": "local-validation", "latest_cursor": progress.cursor,
        "timeout_ms": args.timeout_ms, "poll_interval_ms": args.poll_interval_ms.clamp(10, 5000),
        "event_limit": args.limit,
        "filters": {"connectors": connectors, "event_type": args.event_type, "since": args.since, "since_cutoff": cutoff},
    })).is_err() {
        return Stopped::OutputClosed;
    }
    loop {
        if budget.remaining_ms(Instant::now()).is_err() {
            return Stopped::Timeout;
        }
        let Ok(timeout) = budget.preflight_timeout(client.read_timeout, Instant::now()) else {
            return Stopped::Timeout;
        };
        let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
        if timeout_ms == 0 {
            return Stopped::Timeout;
        }
        let request = FollowRequest {
            connector_id: if connectors.len() == 1 {
                Some(connectors[0].clone())
            } else {
                None
            },
            after_event_id: progress.cursor.clone(),
            // Leave room for the host's terminal record within both the
            // configured read timeout and the original command deadline.
            timeout_ms: timeout_ms
                .saturating_sub(TERMINAL_ALLOWANCE_MS)
                .clamp(1, 60_000),
            // The host owns the poll timer and admits only this range. Report
            // the effective interval in the CLI start record too.
            poll_interval_ms: args.poll_interval_ms.clamp(10, 5000),
            max_events: MAX_STREAM_EVENTS,
        };
        progress.polls = progress.polls.saturating_add(1);
        let response = match client
            .client
            .post(format!("{}{FOLLOW_ROUTE}", client.base_url))
            .bearer_auth(token)
            .header("x-fcp-zone", "z:owner")
            .header(reqwest::header::ACCEPT, "application/x-ndjson")
            .json(&request)
            .timeout(timeout)
            .send()
        {
            Ok(response) => response,
            Err(_) if budget.remaining_ms(Instant::now()).is_err() => return Stopped::Timeout,
            Err(_) => {
                return Stopped::Failed(Failure::transport(
                    "event-stream-failed",
                    "The selected host could not open an authenticated event stream. Check its admin credential and event-follow API support; resume from the retained cursor.",
                ));
            }
        };
        if !response.status().is_success()
            || !response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.split(';').next())
                .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/x-ndjson"))
            || response
                .content_length()
                .is_some_and(|bytes| bytes > MAX_RESPONSE_BYTES)
        {
            return Stopped::Failed(invalid_stream());
        }
        if let Err(stopped) = consume_stream(
            response, &request, args, connectors, cutoff, budget, progress, writer,
        ) {
            return stopped;
        }
        // A peer returning empty terminal records immediately must not cause
        // an unbounded request loop. This wait shares the original deadline.
        if progress.cursor == request.after_event_id {
            let Ok(Some(remaining)) = budget.remaining_ms(Instant::now()) else {
                return Stopped::Timeout;
            };
            std::thread::sleep(Duration::from_millis(
                request.poll_interval_ms.min(remaining),
            ));
        }
    }
}

fn valid_cursor(cursor: &str) -> bool {
    !cursor.trim().is_empty() && cursor.len() <= 1_024 && !cursor.chars().any(char::is_control)
}

fn invalid_stream() -> Failure {
    Failure::transport(
        "invalid-event-stream",
        "The host returned an invalid, incomplete, or oversized event stream. Resume explicitly from the last flushed cursor; no automatic replay was attempted.",
    )
}

fn read_record<R: BufRead>(
    reader: &mut R,
    received_bytes: &mut u64,
) -> std::result::Result<WireRecord, Failure> {
    let capacity = MAX_FRAME_BYTES.min(
        usize::try_from(MAX_RESPONSE_BYTES.saturating_sub(*received_bytes)).unwrap_or(usize::MAX),
    );
    if capacity == 0 {
        return Err(invalid_stream());
    }
    let mut line = Vec::new();
    // read_until alone is unbounded on a peer that omits the newline. Take
    // one extra byte so a limit is detected without allocating its suffix.
    (&mut *reader)
        .take(capacity as u64 + 1)
        .read_until(b'\n', &mut line)
        .map_err(|_| invalid_stream())?;
    if line.len() > capacity || line.last() != Some(&b'\n') {
        return Err(invalid_stream());
    }
    *received_bytes += line.len() as u64;
    serde_json::from_slice(&line).map_err(|_| invalid_stream())
}

#[allow(clippy::too_many_arguments)]
fn consume_stream<R: Read>(
    response: R,
    request: &FollowRequest,
    args: &TailArgs,
    connectors: &[String],
    cutoff: Option<DateTime<Utc>>,
    budget: ExecutionBudget,
    progress: &mut Progress,
    writer: &mut dyn Write,
) -> std::result::Result<(), Stopped> {
    let mut reader = BufReader::new(response.take(MAX_RESPONSE_BYTES + 1));
    let mut received_bytes = 0;
    let mut received_events = 0;
    let mut started = false;
    // Both the byte cap and server event cap bound this per-connection set.
    let mut seen = BTreeSet::new();
    if let Some(cursor) = &request.after_event_id {
        seen.insert(cursor.clone());
    }
    loop {
        if budget.remaining_ms(Instant::now()).is_err() {
            return Err(Stopped::Timeout);
        }
        let record = read_record(&mut reader, &mut received_bytes).map_err(|failure| {
            if budget.remaining_ms(Instant::now()).is_err() {
                Stopped::Timeout
            } else {
                Stopped::Failed(failure)
            }
        })?;
        if budget.remaining_ms(Instant::now()).is_err() {
            return Err(Stopped::Timeout);
        }
        if record.source != "host-admin-api"
            || record
                .latest_cursor
                .as_deref()
                .is_some_and(|cursor| !valid_cursor(cursor))
        {
            return Err(Stopped::Failed(invalid_stream()));
        }
        if !started {
            let WirePayload::Start {
                timeout_ms,
                poll_interval_ms,
                max_events,
            } = record.payload
            else {
                return Err(Stopped::Failed(invalid_stream()));
            };
            if record.event_count != 0
                || record.latest_cursor != request.after_event_id
                || timeout_ms != request.timeout_ms
                || poll_interval_ms != request.poll_interval_ms
                || max_events != request.max_events
            {
                return Err(Stopped::Failed(invalid_stream()));
            }
            started = true;
            continue;
        }
        match record.payload {
            WirePayload::Start { .. } => return Err(Stopped::Failed(invalid_stream())),
            WirePayload::Event { event } => {
                if received_events >= request.max_events
                    || record.event_count != received_events + 1
                    || record.latest_cursor.as_deref() != Some(event.event_id.as_str())
                    || !seen.insert(event.event_id.clone())
                    || request
                        .connector_id
                        .as_ref()
                        .is_some_and(|id| event.connector_id.as_ref() != Some(id))
                {
                    return Err(Stopped::Failed(invalid_stream()));
                }
                let matches = (connectors.is_empty()
                    || event
                        .connector_id
                        .as_ref()
                        .is_some_and(|id| connectors.contains(id)))
                    && cutoff.is_none_or(|cutoff| event.timestamp >= cutoff)
                    && args
                        .event_type
                        .as_deref()
                        .is_none_or(|filter| host_event_matches_type_filter(&event, filter));
                let output = if matches {
                    json!({
                        "type": "event", "command": "tail", "source": "host-admin-api",
                        "event_id": event.event_id, "latest_cursor": event.event_id,
                        "event": host_event_to_connector_event(&event),
                    })
                } else {
                    // Filtered events still advance the scan cursor. Publish
                    // that checkpoint before committing the resume position.
                    json!({
                        "type": "checkpoint", "command": "tail", "source": "host-admin-api",
                        "latest_cursor": event.event_id, "event_count": progress.events,
                        "polls": progress.polls, "caught_up": false,
                    })
                };
                write_record(writer, &output).map_err(|_| Stopped::OutputClosed)?;
                received_events += 1;
                progress.events += usize::from(matches);
                progress.cursor = Some(event.event_id);
                if args.limit != 0 && progress.events >= args.limit {
                    return Err(Stopped::Limit);
                }
            }
            WirePayload::Checkpoint => {
                if record.event_count != received_events
                    || (progress.cursor.is_some() && record.latest_cursor.is_none())
                    || (record.latest_cursor != progress.cursor
                        && record
                            .latest_cursor
                            .as_ref()
                            .is_some_and(|cursor| !seen.insert(cursor.clone())))
                {
                    return Err(Stopped::Failed(invalid_stream()));
                }
                write_record(
                    writer,
                    &json!({
                        "type": "checkpoint", "command": "tail", "source": "host-admin-api",
                        "latest_cursor": record.latest_cursor, "event_count": progress.events,
                        "polls": progress.polls, "caught_up": true,
                    }),
                )
                .map_err(|_| Stopped::OutputClosed)?;
                progress.cursor = record.latest_cursor;
            }
            terminal @ (WirePayload::Complete { .. } | WirePayload::Error { .. }) => {
                if record.event_count != received_events || record.latest_cursor != progress.cursor
                {
                    return Err(Stopped::Failed(invalid_stream()));
                }
                // A terminal record does not authorize a subsequent stream
                // until this HTTP body ends cleanly. Reject trailing data.
                let mut suffix = [0_u8; 1];
                let suffix_length = reader.read(&mut suffix).map_err(|_| {
                    if budget.remaining_ms(Instant::now()).is_err() {
                        Stopped::Timeout
                    } else {
                        Stopped::Failed(invalid_stream())
                    }
                })?;
                if budget.remaining_ms(Instant::now()).is_err() {
                    return Err(Stopped::Timeout);
                }
                if suffix_length != 0 {
                    return Err(Stopped::Failed(invalid_stream()));
                }
                return match terminal {
                    WirePayload::Complete { reason }
                        if reason == "timeout"
                            || reason == "byte-limit"
                            || (reason == "event-limit"
                                && received_events == request.max_events) =>
                    {
                        Ok(())
                    }
                    WirePayload::Error { code } if code == "cursor-not-found" => {
                        Err(Stopped::Failed(Failure::transport(
                            "event-cursor-unavailable",
                            "The host no longer retains the requested cursor. Follow stopped without restarting or skipping history; select a new starting point explicitly.",
                        )))
                    }
                    WirePayload::Error { .. } => Err(Stopped::Failed(Failure::transport(
                        "event-stream-failed",
                        "The selected host stopped event delivery. Resume explicitly from the last flushed cursor after resolving the host error.",
                    ))),
                    _ => Err(Stopped::Failed(invalid_stream())),
                };
            }
        }
    }
}

fn write_record(writer: &mut dyn Write, record: &Value) -> std::io::Result<()> {
    serde_json::to_writer(&mut *writer, record).map_err(std::io::Error::other)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::{BufRead, BufReader, Read};
    use std::net::TcpListener;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    };

    #[derive(Clone)]
    struct Request {
        route: String,
        headers: BTreeMap<String, String>,
        body: Value,
    }

    struct Server {
        endpoint: String,
        stop: Arc<AtomicBool>,
        requests: Arc<Mutex<Vec<Request>>>,
        worker: Option<std::thread::JoinHandle<()>>,
    }

    impl Server {
        fn start(replies: Vec<(Value, Duration)>) -> Self {
            Self::start_with_pause(replies, None)
        }

        fn start_with_pause(replies: Vec<(Value, Duration)>, pause: Option<Duration>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let stop = Arc::new(AtomicBool::new(false));
            let requests = Arc::new(Mutex::new(Vec::new()));
            let thread_stop = Arc::clone(&stop);
            let thread_requests = Arc::clone(&requests);
            let worker = std::thread::spawn(move || {
                let mut served = 0;
                while !thread_stop.load(Ordering::SeqCst) {
                    let (mut stream, _) = match listener.accept() {
                        Ok(pair) => pair,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(2));
                            continue;
                        }
                        Err(error) => panic!("accept failed: {error}"),
                    };
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    stream
                        .set_write_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut first = String::new();
                    reader.read_line(&mut first).unwrap();
                    let route = first
                        .split_whitespace()
                        .take(2)
                        .collect::<Vec<_>>()
                        .join(" ");
                    let mut headers = BTreeMap::new();
                    loop {
                        let mut line = String::new();
                        reader.read_line(&mut line).unwrap();
                        if line == "\r\n" || line.is_empty() {
                            break;
                        }
                        let (name, value) = line.split_once(':').unwrap();
                        headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
                    }
                    let length = headers
                        .get("content-length")
                        .map(|value| value.parse::<usize>().unwrap())
                        .unwrap_or(0);
                    let mut bytes = vec![0; length];
                    reader.read_exact(&mut bytes).unwrap();
                    let request_body: Value = serde_json::from_slice(&bytes).unwrap();
                    thread_requests.lock().unwrap().push(Request {
                        route,
                        headers,
                        body: request_body.clone(),
                    });
                    let (reply, delay) = replies.get(served).expect("unexpected extra event query");
                    std::thread::sleep(*delay);
                    let mut frames = reply.as_array().unwrap().clone();
                    for frame in &mut frames {
                        if frame["type"] == "start" {
                            for field in ["timeout_ms", "poll_interval_ms", "max_events"] {
                                if frame.get(field).is_none() {
                                    frame[field] = request_body[field].clone();
                                }
                            }
                        }
                    }
                    let frames = frames
                        .iter()
                        .map(|frame| {
                            let mut bytes = serde_json::to_vec(frame).unwrap();
                            bytes.push(b'\n');
                            bytes
                        })
                        .collect::<Vec<_>>();
                    let header = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/x-ndjson\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        frames.iter().map(Vec::len).sum::<usize>()
                    );
                    // Deadline tests intentionally close before a delayed reply.
                    if stream.write_all(header.as_bytes()).is_ok() {
                        for (index, frame) in frames.iter().enumerate() {
                            if stream
                                .write_all(frame)
                                .and_then(|()| stream.flush())
                                .is_err()
                            {
                                break;
                            }
                            if index == 1
                                && let Some(pause) = pause
                            {
                                std::thread::sleep(pause);
                            }
                        }
                    }
                    served += 1;
                }
            });
            Self {
                endpoint,
                stop,
                requests,
                worker: Some(worker),
            }
        }

        fn finish(mut self) -> Vec<Request> {
            self.stop.store(true, Ordering::SeqCst);
            self.worker.take().unwrap().join().unwrap();
            self.requests.lock().unwrap().clone()
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }

    fn prepared(endpoint: &str, extra: &[&str]) -> (tempfile::TempDir, PreparedCli) {
        let directory = tempfile::tempdir().unwrap();
        let token = directory.path().join("admin-token");
        std::fs::write(&token, "tail-test-secret\n").unwrap();
        let mut args = [
            "fwc",
            "--host",
            endpoint,
            "tail",
            "--follow",
            "--admin-token-file",
        ]
        .map(str::to_owned)
        .to_vec();
        args.push(token.display().to_string());
        args.extend(extra.iter().map(|value| (*value).to_owned()));
        (
            directory,
            crate::prepare_cli(&args).expect("valid follow args"),
        )
    }

    fn event(id: &str, connector: &str, kind: &str) -> Value {
        json!({
            "event_id": id, "connector_id": connector, "kind": kind,
            "summary": id, "payload": null, "timestamp": Utc::now().to_rfc3339(), "acknowledged": false,
        })
    }

    fn start(cursor: Option<&str>) -> Value {
        json!({"type":"start", "source":"host-admin-api", "latest_cursor":cursor, "event_count":0})
    }

    fn checkpoint(cursor: Option<&str>, count: usize) -> Value {
        json!({"type":"checkpoint", "source":"host-admin-api", "latest_cursor":cursor, "event_count":count})
    }

    fn terminal(cursor: Option<&str>, count: usize, reason: &str) -> Value {
        json!({"type":"complete", "source":"host-admin-api", "latest_cursor":cursor, "event_count":count, "reason":reason})
    }

    fn event_record(event: Value, count: usize) -> Value {
        json!({"type":"event", "source":"host-admin-api", "latest_cursor":event["event_id"], "event_count":count, "event":event})
    }

    fn batch(after: Option<&str>, next: Option<&str>, more: bool, events: Vec<Value>) -> Value {
        let count = events.len();
        let last = events
            .last()
            .and_then(|event| event["event_id"].as_str())
            .map(str::to_owned);
        let mut frames = vec![start(after)];
        frames.extend(
            events
                .into_iter()
                .enumerate()
                .map(|(index, event)| event_record(event, index + 1)),
        );
        if !more || next != last.as_deref() {
            frames.push(checkpoint(next, count));
        }
        frames.push(terminal(
            next,
            count,
            if count == 0 { "timeout" } else { "byte-limit" },
        ));
        json!(frames)
    }

    #[derive(Default)]
    struct Writer {
        bytes: Vec<u8>,
        flushes: usize,
        fail_after: Option<usize>,
    }

    impl Write for Writer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.fail_after.is_some_and(|limit| self.flushes >= limit) {
                return Err(std::io::ErrorKind::BrokenPipe.into());
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }

    fn records(writer: &Writer) -> Vec<Value> {
        std::str::from_utf8(&writer.bytes)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[test]
    fn tail_follow_streams_keep_filters_auth_and_exact_consumed_cursor() {
        let server = Server::start(vec![
            (
                batch(
                    Some("evt-1"),
                    Some("evt-4"),
                    true,
                    vec![
                        event("evt-2", "github", "lifecycle_transition"),
                        event("evt-3", "slack", "health_check"),
                        event("evt-4", "jira", "health_check"),
                    ],
                ),
                Duration::ZERO,
            ),
            (
                batch(
                    Some("evt-4"),
                    Some("evt-6"),
                    false,
                    vec![
                        event("evt-5", "github", "health_check"),
                        event("evt-6", "slack", "health_check"),
                    ],
                ),
                Duration::ZERO,
            ),
        ]);
        let (_directory, prepared) = prepared(
            &server.endpoint,
            &[
                "slack,github",
                "--event-type",
                "health",
                "--cursor",
                "evt-1",
                "--limit",
                "2",
            ],
        );
        let mut writer = Writer::default();
        assert_eq!(
            execute_with_writer(&prepared, &mut writer).unwrap(),
            CliExitCode::Success.into()
        );
        let requests = server.finish();
        assert_eq!(requests.len(), 2);
        for request in &requests {
            assert_eq!(request.route, "POST /rpc/admin/events/follow");
            assert_eq!(request.headers["authorization"], "Bearer tail-test-secret");
            assert_eq!(request.headers["x-fcp-zone"], "z:owner");
            assert_eq!(request.headers["accept"], "application/x-ndjson");
            assert_eq!(request.body["max_events"], 10_000);
            assert!(request.body["timeout_ms"].as_u64().unwrap() <= 60_000);
        }
        assert_eq!(requests[1].body["after_event_id"], "evt-4");
        let records = records(&writer);
        assert_eq!(writer.flushes, records.len());
        assert_eq!(
            records
                .iter()
                .map(|record| record["type"].as_str().unwrap())
                .collect::<Vec<_>>(),
            [
                "start",
                "checkpoint",
                "event",
                "checkpoint",
                "event",
                "complete"
            ]
        );
        assert_eq!(records[2]["event_id"], "evt-3");
        assert_eq!(records[4]["event_id"], "evt-5");
        assert_eq!(records.last().unwrap()["latest_cursor"], "evt-5");
        assert_eq!(records.last().unwrap()["event_count"], 2);
        assert!(
            !String::from_utf8(writer.bytes)
                .unwrap()
                .contains("tail-test-secret")
        );
    }

    #[test]
    fn tail_follow_refuses_gaps_invalid_framing_and_cursor_regression() {
        let missing = json!({"type":"error", "source":"host-admin-api", "latest_cursor":"anchor", "event_count":0,
            "code":"cursor-not-found", "message":"tail-test-secret"});
        let mut wrong_source = checkpoint(Some("anchor"), 0);
        wrong_source["source"] = json!("untrusted");
        let mut wrong_count = event_record(event("next", "github", "health_check"), 3);
        wrong_count["latest_cursor"] = json!("next");
        for response in [
            json!([start(Some("anchor")), missing]),
            json!([start(Some("wrong"))]),
            json!([checkpoint(Some("anchor"), 0)]),
            json!([start(Some("anchor")), start(Some("anchor"))]),
            json!([start(Some("anchor")), checkpoint(None, 0)]),
            json!([start(Some("anchor")), wrong_source]),
            json!([start(Some("anchor")), wrong_count]),
            json!([
                start(Some("anchor")),
                event_record(event("anchor", "github", "health_check"), 1)
            ]),
            json!([
                start(Some("anchor")),
                terminal(Some("anchor"), 0, "unknown")
            ]),
            json!([
                start(Some("anchor")),
                terminal(Some("anchor"), 0, "event-limit")
            ]),
            json!([
                start(Some("anchor")),
                terminal(Some("anchor"), 0, "timeout"),
                checkpoint(Some("next"), 0)
            ]),
        ] {
            let server = Server::start(vec![(response, Duration::ZERO)]);
            let (_directory, prepared) =
                prepared(&server.endpoint, &["--cursor", "anchor", "--limit", "1"]);
            let mut writer = Writer::default();
            assert_eq!(
                execute_with_writer(&prepared, &mut writer).unwrap(),
                CliExitCode::Transport.into()
            );
            assert_eq!(server.finish().len(), 1);
            let records = records(&writer);
            assert_eq!(records.len(), 2);
            assert_eq!(records[1]["type"], "error");
            assert_eq!(records[1]["latest_cursor"], "anchor");
            assert_eq!(records[1]["event_count"], 0);
            assert!(
                !String::from_utf8(writer.bytes)
                    .unwrap()
                    .contains("tail-test-secret")
            );
        }
    }

    #[test]
    fn tail_follow_shares_one_deadline_across_reads_and_poll_waits() {
        let server = Server::start(vec![
            (
                batch(
                    None,
                    Some("evt-1"),
                    true,
                    vec![event("evt-1", "github", "health_check")],
                ),
                Duration::from_millis(100),
            ),
            (
                batch(
                    Some("evt-1"),
                    Some("evt-2"),
                    false,
                    vec![event("evt-2", "github", "health_check")],
                ),
                Duration::from_millis(500),
            ),
        ]);
        let (_directory, prepared) =
            prepared(&server.endpoint, &["--limit", "0", "--timeout-ms", "300"]);
        let mut writer = Writer::default();
        let started = Instant::now();
        assert_eq!(
            execute_with_writer(&prepared, &mut writer).unwrap(),
            CliExitCode::Success.into()
        );
        assert!(started.elapsed() < Duration::from_millis(900));
        assert_eq!(server.finish().len(), 2);
        let records = records(&writer);
        assert_eq!(records.last().unwrap()["reason"], "timeout");
        assert_eq!(records.last().unwrap()["latest_cursor"], "evt-1");

        let server = Server::start(vec![(batch(None, None, false, vec![]), Duration::ZERO)]);
        let (_directory, prepared) = self::prepared(
            &server.endpoint,
            &[
                "--limit",
                "0",
                "--timeout-ms",
                "150",
                "--poll-interval-ms",
                "1000",
            ],
        );
        let mut writer = Writer::default();
        let started = Instant::now();
        assert_eq!(
            execute_with_writer(&prepared, &mut writer).unwrap(),
            CliExitCode::Success.into()
        );
        assert!(started.elapsed() < Duration::from_millis(900));
        assert_eq!(server.finish().len(), 1);
        assert_eq!(self::records(&writer).last().unwrap()["reason"], "timeout");
    }

    #[test]
    fn tail_follow_closed_output_stops_without_more_requests_or_frames() {
        for fail_after in [0, 1] {
            let server = Server::start(vec![(
                batch(
                    None,
                    Some("evt-1"),
                    true,
                    vec![event("evt-1", "github", "health_check")],
                ),
                Duration::ZERO,
            )]);
            let (_directory, prepared) = prepared(&server.endpoint, &["--limit", "2"]);
            let mut writer = Writer {
                fail_after: Some(fail_after),
                ..Writer::default()
            };
            assert_eq!(
                execute_with_writer(&prepared, &mut writer).unwrap(),
                CliExitCode::Transport.into()
            );
            assert_eq!(server.finish().len(), fail_after);
            assert_eq!(records(&writer).len(), fail_after);
        }
    }

    #[test]
    fn tail_follow_resumes_after_checkpoint_without_repeating_history() {
        let server = Server::start(vec![
            (
                batch(Some("anchor"), Some("filtered-end"), false, vec![]),
                Duration::ZERO,
            ),
            (
                batch(
                    Some("filtered-end"),
                    Some("new-event"),
                    false,
                    vec![event("new-event", "github", "health_check")],
                ),
                Duration::ZERO,
            ),
        ]);
        let (_directory, prepared) = prepared(
            &server.endpoint,
            &[
                "github",
                "--cursor",
                "anchor",
                "--limit",
                "1",
                "--poll-interval-ms",
                "10",
            ],
        );
        let mut writer = Writer::default();
        assert_eq!(
            execute_with_writer(&prepared, &mut writer).unwrap(),
            CliExitCode::Success.into()
        );
        let requests = server.finish();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1].body["after_event_id"], "filtered-end");
        assert_eq!(requests[1].body["connector_id"], "github");
        let records = records(&writer);
        assert_eq!(records[1]["type"], "checkpoint");
        assert_eq!(records[1]["latest_cursor"], "filtered-end");
        assert_eq!(records[2]["event_id"], "new-event");
    }

    #[test]
    fn tail_follow_resumes_checkpoint_only_byte_limits() {
        for cursor in ["anchor", "scanned-end"] {
            let server = Server::start(vec![
                (
                    json!([
                        start(Some("anchor")),
                        checkpoint(Some(cursor), 0),
                        terminal(Some(cursor), 0, "byte-limit"),
                    ]),
                    Duration::ZERO,
                ),
                (
                    batch(
                        Some(cursor),
                        Some("new-event"),
                        false,
                        vec![event("new-event", "github", "health_check")],
                    ),
                    Duration::ZERO,
                ),
            ]);
            let (_directory, prepared) = prepared(
                &server.endpoint,
                &[
                    "github",
                    "--cursor",
                    "anchor",
                    "--limit",
                    "1",
                    "--poll-interval-ms",
                    "10",
                ],
            );
            let mut writer = Writer::default();
            assert_eq!(
                execute_with_writer(&prepared, &mut writer).unwrap(),
                CliExitCode::Success.into()
            );
            let requests = server.finish();
            assert_eq!(requests.len(), 2);
            assert_eq!(requests[1].body["after_event_id"], cursor);
            let records = records(&writer);
            assert_eq!(records[1]["type"], "checkpoint");
            assert_eq!(records[1]["latest_cursor"], cursor);
            assert_eq!(records.last().unwrap()["latest_cursor"], "new-event");
            assert_eq!(records.last().unwrap()["event_count"], 1);
        }
    }

    #[test]
    fn tail_follow_keeps_the_initial_since_cutoff_for_later_streams() {
        let mut recent = event("evt-2", "github", "health_check");
        recent["timestamp"] = json!((Utc::now() - TimeDelta::milliseconds(100)).to_rfc3339());
        let server = Server::start(vec![
            (
                batch(
                    None,
                    Some("evt-1"),
                    true,
                    vec![event("evt-1", "jira", "health_check")],
                ),
                Duration::from_millis(1_100),
            ),
            (
                batch(Some("evt-1"), Some("evt-2"), false, vec![recent]),
                Duration::ZERO,
            ),
        ]);
        let (_directory, prepared) = prepared(
            &server.endpoint,
            &[
                "github,slack",
                "--since",
                "1s",
                "--limit",
                "1",
                "--timeout-ms",
                "4000",
            ],
        );
        let mut writer = Writer::default();
        assert_eq!(
            execute_with_writer(&prepared, &mut writer).unwrap(),
            CliExitCode::Success.into()
        );
        assert_eq!(server.finish().len(), 2);
        let records = records(&writer);
        assert_eq!(records.last().unwrap()["event_count"], 1);
        assert_eq!(records.last().unwrap()["latest_cursor"], "evt-2");
    }

    #[test]
    fn tail_follow_delivers_before_the_http_body_finishes() {
        let server = Server::start_with_pause(
            vec![(
                batch(
                    None,
                    Some("evt-1"),
                    false,
                    vec![event("evt-1", "github", "health_check")],
                ),
                Duration::ZERO,
            )],
            Some(Duration::from_millis(750)),
        );
        let (_directory, prepared) = prepared(&server.endpoint, &["--limit", "1"]);
        let mut writer = Writer::default();
        let started = Instant::now();
        assert_eq!(
            execute_with_writer(&prepared, &mut writer).unwrap(),
            CliExitCode::Success.into()
        );
        assert!(started.elapsed() < Duration::from_millis(600));
        assert_eq!(server.finish().len(), 1);
        assert_eq!(records(&writer)[1]["event_id"], "evt-1");
    }

    #[test]
    fn tail_follow_retains_flushed_evidence_after_disconnect_duplicate_or_terminal_suffix() {
        let delivered = event_record(event("evt-1", "github", "health_check"), 1);
        for frames in [
            json!([start(None), delivered]),
            json!([
                start(None),
                delivered,
                event_record(event("evt-1", "github", "health_check"), 2)
            ]),
            json!([
                start(None),
                delivered,
                terminal(Some("evt-1"), 1, "byte-limit"),
                checkpoint(Some("untrusted"), 1)
            ]),
        ] {
            let server = Server::start(vec![(frames, Duration::ZERO)]);
            let (_directory, prepared) = prepared(&server.endpoint, &["--limit", "0"]);
            let mut writer = Writer::default();
            assert_eq!(
                execute_with_writer(&prepared, &mut writer).unwrap(),
                CliExitCode::Transport.into()
            );
            assert_eq!(
                server.finish().len(),
                1,
                "uncertain streams must not reconnect"
            );
            let records = records(&writer);
            assert_eq!(records.len(), 3);
            assert_eq!(records[1]["event_id"], "evt-1");
            assert_eq!(records[2]["type"], "error");
            assert_eq!(records[2]["latest_cursor"], "evt-1");
            assert_eq!(records[2]["event_count"], 1);
        }
    }

    #[test]
    fn tail_follow_bounds_unterminated_frames_and_total_encoded_bytes() {
        let mut oversized = std::io::Cursor::new(vec![b' '; MAX_FRAME_BYTES * 2]);
        assert!(read_record(&mut oversized, &mut 0).is_err());
        assert_eq!(oversized.position(), (MAX_FRAME_BYTES + 1) as u64);

        let mut bytes = serde_json::to_vec(&checkpoint(Some("evt-1"), 0)).unwrap();
        bytes.push(b'\n');
        let mut reader = std::io::Cursor::new(&bytes);
        let mut received = MAX_RESPONSE_BYTES - bytes.len() as u64 + 1;
        assert!(read_record(&mut reader, &mut received).is_err());
        assert_eq!(received, MAX_RESPONSE_BYTES - bytes.len() as u64 + 1);

        let mut reader = std::io::Cursor::new(&bytes);
        let mut received = MAX_RESPONSE_BYTES - bytes.len() as u64;
        assert!(read_record(&mut reader, &mut received).is_ok());
        assert_eq!(received, MAX_RESPONSE_BYTES);
        assert!(read_record(&mut reader, &mut received).is_err());
    }

    #[test]
    fn tail_follow_terminal_drain_keeps_the_original_deadline() {
        struct DelayedEof {
            bytes: std::io::Cursor<Vec<u8>>,
            fail: bool,
        }

        impl Read for DelayedEof {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                if self.bytes.position() == self.bytes.get_ref().len() as u64 {
                    std::thread::sleep(Duration::from_millis(40));
                    if self.fail {
                        return Err(std::io::ErrorKind::TimedOut.into());
                    }
                    return Ok(0);
                }
                self.bytes.read(buffer)
            }
        }

        let (_directory, prepared) = prepared("http://127.0.0.1:9", &["--limit", "0"]);
        let Commands::Tail(args) = &prepared.cli.command else {
            panic!("tail command");
        };
        let request = FollowRequest {
            connector_id: None,
            after_event_id: None,
            timeout_ms: 1,
            poll_interval_ms: 10,
            max_events: MAX_STREAM_EVENTS,
        };
        let mut begin = start(None);
        begin["timeout_ms"] = json!(request.timeout_ms);
        begin["poll_interval_ms"] = json!(request.poll_interval_ms);
        begin["max_events"] = json!(request.max_events);
        let mut bytes = Vec::new();
        for record in [begin, terminal(None, 0, "timeout")] {
            serde_json::to_writer(&mut bytes, &record).unwrap();
            bytes.push(b'\n');
        }
        for fail in [false, true] {
            let budget = ExecutionBudget::start(Some(20), Instant::now());
            let result = consume_stream(
                DelayedEof {
                    bytes: std::io::Cursor::new(bytes.clone()),
                    fail,
                },
                &request,
                args,
                &[],
                None,
                budget,
                &mut Progress::default(),
                &mut Writer::default(),
            );
            assert!(matches!(result, Err(Stopped::Timeout)));
        }
    }

    #[test]
    fn tail_follow_validates_before_connecting_and_previews_offline() {
        for extra in [
            vec!["--json"],
            vec!["--cursor", "bad\ncursor"],
            vec!["--since", "18446744073709551615d"],
        ] {
            let server = Server::start(vec![]);
            let (_directory, prepared) = prepared(&server.endpoint, &extra);
            let mut writer = Writer::default();
            assert_eq!(
                execute_with_writer(&prepared, &mut writer).unwrap(),
                CliExitCode::Validation.into()
            );
            assert!(server.finish().is_empty());
            assert_eq!(records(&writer)[0]["source"], "local-validation");
        }
        let (_directory, prepared) = prepared("http://192.0.2.1", &[]);
        let mut writer = Writer::default();
        assert_eq!(
            execute_with_writer(&prepared, &mut writer).unwrap(),
            CliExitCode::Validation.into()
        );
        assert_eq!(
            records(&writer)[0]["error"]["type"],
            "invalid-host-endpoint"
        );
        let args = [
            "fwc",
            "--json",
            "tail",
            "--follow",
            "--dry-run",
            "--limit",
            "0",
        ]
        .map(str::to_owned)
        .to_vec();
        let output = crate::execute(&args).unwrap();
        assert_eq!(output.exit_code, CliExitCode::Success.into());
        let value: Value = serde_json::from_str(&output.text).unwrap();
        assert_eq!(value["follow"]["enabled"], true);
        assert_eq!(value["follow"]["event_limit"], 0);
    }
}
