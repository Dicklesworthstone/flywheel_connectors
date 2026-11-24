//! Resumable, bounded observation of the host's retained event journal.
//!
//! Cursor resolution belongs to the host and precedes filtering. A missing
//! cursor fails closed instead of silently replaying retained history. Every
//! record is flushed; closed output stops polling immediately. The deadline
//! covers network reads and poll waits. As with other synchronous CLI writers,
//! blocked stdout must make progress before execution can return.

use std::collections::BTreeSet;
use std::io::Write;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use anyhow::Result;
use chrono::{DateTime, TimeDelta, Utc};
use fcp_host::{EventPageQueryRequest, EventPageQueryResponse, EventQueryRequest};
use serde_json::{Value, json};

use super::{
    CliExitCode, Commands, ExecutionOutcome, HostAdminClient, OutputFormat, PreparedCli, TailArgs,
    event_stream, host_event_matches_type_filter, host_event_to_connector_event, invocation_cmd,
    pipe::budget::ExecutionBudget, resolve_host_config,
};

const PAGE_LIMIT: usize = 1_000;
const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;
const PAGE_ROUTE: &str = "/rpc/admin/events/page";

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
        "timeout_ms": args.timeout_ms, "poll_interval_ms": args.poll_interval_ms,
        "event_limit": args.limit,
        "filters": {"connectors": connectors, "event_type": args.event_type, "since": args.since, "since_cutoff": cutoff},
    })).is_err() {
        return Stopped::OutputClosed;
    }
    loop {
        if budget.remaining_ms(Instant::now()).is_err() {
            return Stopped::Timeout;
        }
        let request = EventPageQueryRequest {
            query: EventQueryRequest {
                connector_id: if connectors.len() == 1 {
                    Some(connectors[0].clone())
                } else {
                    None
                },
                kind: None,
                unacknowledged_only: false,
                limit: PAGE_LIMIT,
            },
            after_event_id: progress.cursor.clone(),
        };
        progress.polls = progress.polls.saturating_add(1);
        let response: EventPageQueryResponse = match client.read_json(
            client
                .client
                .post(format!("{}{PAGE_ROUTE}", client.base_url))
                .bearer_auth(token)
                .header("x-fcp-zone", "z:owner")
                .json(&request),
            "POST",
            PAGE_ROUTE,
        ) {
            Ok(response) => response,
            Err(_) if budget.remaining_ms(Instant::now()).is_err() => return Stopped::Timeout,
            Err(_) => {
                return Stopped::Failed(Failure::transport(
                    "event-query-failed",
                    "The selected host could not provide a bounded authenticated event page. Check its admin credential and event-page API support; resume from the retained cursor.",
                ));
            }
        };
        if let Err(failure) = validate_page(&request, &response) {
            return Stopped::Failed(failure);
        }
        for event in &response.events {
            if budget.remaining_ms(Instant::now()).is_err() {
                return Stopped::Timeout;
            }
            if (connectors.is_empty()
                || event
                    .connector_id
                    .as_ref()
                    .is_some_and(|id| connectors.contains(id)))
                && cutoff.is_none_or(|cutoff| event.timestamp >= cutoff)
                && args
                    .event_type
                    .as_deref()
                    .is_none_or(|filter| host_event_matches_type_filter(event, filter))
            {
                if write_record(
                    writer,
                    &json!({
                        "type": "event", "command": "tail", "source": "host-admin-api",
                        "event_id": event.event_id, "latest_cursor": event.event_id,
                        "event": host_event_to_connector_event(event),
                    }),
                )
                .is_err()
                {
                    return Stopped::OutputClosed;
                }
                progress.events = progress.events.saturating_add(1);
            }
            progress.cursor = Some(event.event_id.clone());
            if args.limit != 0 && progress.events >= args.limit {
                // Stop at the consumed event, not the host's end-of-page cursor.
                return Stopped::Limit;
            }
        }
        if let Some(cursor) = response.next_cursor {
            progress.cursor = Some(cursor);
        }
        if write_record(
            writer,
            &json!({
                "type": "checkpoint", "command": "tail", "source": "host-admin-api",
                "latest_cursor": progress.cursor, "event_count": progress.events,
                "polls": progress.polls, "caught_up": !response.has_more,
            }),
        )
        .is_err()
        {
            return Stopped::OutputClosed;
        }
        if !response.has_more {
            let Ok(Some(remaining)) = budget.remaining_ms(Instant::now()) else {
                return Stopped::Timeout;
            };
            std::thread::sleep(Duration::from_millis(args.poll_interval_ms.min(remaining)));
        }
    }
}

fn valid_cursor(cursor: &str) -> bool {
    !cursor.trim().is_empty() && cursor.len() <= 1_024 && !cursor.chars().any(char::is_control)
}

fn validate_page(
    request: &EventPageQueryRequest,
    response: &EventPageQueryResponse,
) -> std::result::Result<(), Failure> {
    let invalid = || {
        Failure::transport(
            "invalid-event-page",
            "The host returned an inconsistent event page or cursor. No events from this page were consumed; resume from the retained cursor.",
        )
    };
    if response.after_event_id != request.after_event_id {
        return Err(invalid());
    }
    if request.after_event_id.is_some() && response.cursor_found == Some(false) {
        return Err(Failure::transport(
            "event-cursor-unavailable",
            "The host no longer retains the requested cursor. Follow stopped without restarting or skipping history; select a new starting point explicitly.",
        ));
    }
    if response.cursor_found != request.after_event_id.as_ref().map(|_| true)
        || response.events.len() > PAGE_LIMIT
        || response
            .next_cursor
            .as_deref()
            .is_some_and(|cursor| !valid_cursor(cursor))
    {
        return Err(invalid());
    }
    let mut ids = BTreeSet::new();
    for event in &response.events {
        if !valid_cursor(&event.event_id)
            || Some(&event.event_id) == request.after_event_id.as_ref()
            || !ids.insert(event.event_id.as_str())
        {
            return Err(invalid());
        }
    }
    if let Some(last) = response.events.last() {
        let Some(next) = response.next_cursor.as_deref() else {
            return Err(invalid());
        };
        if response.next_cursor == request.after_event_id
            || (response.has_more && next != last.event_id)
            || (ids.contains(next) && next != last.event_id)
        {
            return Err(invalid());
        }
    } else if response.has_more {
        return Err(invalid());
    }
    Ok(())
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
                    thread_requests.lock().unwrap().push(Request {
                        route,
                        headers,
                        body: serde_json::from_slice(&bytes).unwrap(),
                    });
                    let (reply, delay) = replies.get(served).expect("unexpected extra event query");
                    std::thread::sleep(*delay);
                    let body = serde_json::to_vec(reply).unwrap();
                    let header = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    );
                    // Deadline tests intentionally close before a delayed reply.
                    let _ = stream
                        .write_all(header.as_bytes())
                        .and_then(|()| stream.write_all(&body));
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

    fn page(after: Option<&str>, next: Option<&str>, more: bool, events: Vec<Value>) -> Value {
        json!({"after_event_id": after, "cursor_found": after.map(|_| true), "next_cursor": next, "has_more": more, "events": events})
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
    fn tail_follow_pages_keep_filters_auth_and_exact_mid_page_cursor() {
        let server = Server::start(vec![
            (
                page(
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
                page(
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
            assert_eq!(request.route, "POST /rpc/admin/events/page");
            assert_eq!(request.headers["authorization"], "Bearer tail-test-secret");
            assert_eq!(request.headers["x-fcp-zone"], "z:owner");
            assert_eq!(request.body["query"]["limit"], 1_000);
        }
        assert_eq!(requests[1].body["after_event_id"], "evt-4");
        let records = records(&writer);
        assert_eq!(writer.flushes, records.len());
        assert_eq!(
            records
                .iter()
                .map(|record| record["type"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["start", "event", "checkpoint", "event", "complete"]
        );
        assert_eq!(records[1]["event_id"], "evt-3");
        assert_eq!(records[3]["event_id"], "evt-5");
        assert_eq!(records.last().unwrap()["latest_cursor"], "evt-5");
        assert_eq!(records.last().unwrap()["event_count"], 2);
        assert!(
            !String::from_utf8(writer.bytes)
                .unwrap()
                .contains("tail-test-secret")
        );
    }

    #[test]
    fn tail_follow_refuses_gaps_mismatched_pages_and_nonprogress() {
        let mut missing = page(Some("anchor"), Some("anchor"), false, vec![]);
        missing["cursor_found"] = json!(false);
        for response in [
            missing,
            page(
                Some("wrong"),
                Some("next"),
                false,
                vec![event("next", "github", "health_check")],
            ),
            page(
                Some("anchor"),
                Some("anchor"),
                false,
                vec![event("anchor", "github", "health_check")],
            ),
            page(Some("anchor"), Some("next"), true, vec![]),
            page(
                Some("anchor"),
                Some("next"),
                false,
                vec![
                    event("next", "github", "health_check"),
                    event("next", "github", "health_check"),
                ],
            ),
            page(
                Some("anchor"),
                Some("anchor"),
                true,
                vec![event("next", "github", "health_check")],
            ),
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
        }
    }

    #[test]
    fn tail_follow_shares_one_deadline_across_reads_and_poll_waits() {
        let server = Server::start(vec![
            (
                page(
                    None,
                    Some("evt-1"),
                    true,
                    vec![event("evt-1", "github", "health_check")],
                ),
                Duration::from_millis(100),
            ),
            (
                page(
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

        let server = Server::start(vec![(page(None, None, false, vec![]), Duration::ZERO)]);
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
                page(
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
    fn tail_follow_polls_after_catch_up_without_repeating_history() {
        let server = Server::start(vec![
            (
                page(Some("anchor"), Some("filtered-end"), false, vec![]),
                Duration::ZERO,
            ),
            (
                page(
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
        assert_eq!(requests[1].body["query"]["connector_id"], "github");
        let records = records(&writer);
        assert_eq!(records[1]["type"], "checkpoint");
        assert_eq!(records[1]["latest_cursor"], "filtered-end");
        assert_eq!(records[2]["event_id"], "new-event");
    }

    #[test]
    fn tail_follow_keeps_the_initial_since_cutoff_for_later_pages() {
        let mut recent = event("evt-2", "github", "health_check");
        recent["timestamp"] = json!((Utc::now() - TimeDelta::milliseconds(100)).to_rfc3339());
        let server = Server::start(vec![
            (
                page(
                    None,
                    Some("evt-1"),
                    true,
                    vec![event("evt-1", "jira", "health_check")],
                ),
                Duration::from_millis(1_100),
            ),
            (
                page(Some("evt-1"), Some("evt-2"), false, vec![recent]),
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
