//! Inspect retained local host invocation attempts and preserve uncertain invoke identity.

use std::io::Read;
use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use fcp_host::{InvocationOutcome, InvocationQueryRequest, InvocationQueryResponse};
use serde_json::{Value, json};

use crate::{
    CliExitCode, CommandAvailability, CommandEnvelope, DispatchOutcome, HostAdminClient,
    InvokeRequest, KnowledgeState, TRUTH_SOURCE_SCHEMA_VERSION, inject_truth_source_metadata,
    resolve_host_config,
};

const ADMIN_BEARER_TOKEN_ENV: &str = "FCP_HOST_ADMIN_BEARER_TOKEN";
const MAX_ADMIN_TOKEN_BYTES: u64 = 65_536;
const MAX_INVOCATION_RESPONSE_BYTES: u64 = 65_536;
const MAX_OPERATION_ID_BYTES: usize = 512;
const INVOCATION_QUERY_PATH: &str = "/rpc/admin/invocations";
const HISTORY_SCOPE: &str = "local-executor-history";
const MISSING_HISTORY_CAVEAT: &str =
    "A missing local record does not prove that the operation had no effects. A forwarded invocation may be recorded only by its actual mesh executor, and completed local history is bounded.";

#[derive(Args, Debug)]
pub(crate) struct InvocationArgs {
    /// Stable request ID from invoke output, including an uncertain invoke error.
    #[arg(value_name = "REQUEST_ID")]
    operation_id: String,

    /// Inspect one exact retained attempt; omitted selects this host's latest attempt.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    attempt_id: Option<u64>,

    /// Read the host admin bearer secret from this file.
    ///
    /// Defaults to FCP_HOST_ADMIN_BEARER_TOKEN. Sent only to the selected host's
    /// protected local invocation lookup with the z:owner admin zone.
    #[arg(long, value_name = "PATH")]
    admin_token_file: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug)]
enum LookupFailure {
    InvalidRequest,
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

impl LookupFailure {
    fn description(self) -> (&'static str, &'static str, CliExitCode) {
        match self {
            Self::InvalidRequest => (
                "invalid-invocation-query",
                "The request ID must be nonempty, contain no control characters and fit within 512 bytes; an attempt ID must be positive.",
                CliExitCode::Validation,
            ),
            Self::MissingHost => (
                "missing-host-endpoint",
                "Invocation inspection requires the host that retained the attempt. Supply --host or configure a host context.",
                CliExitCode::Transport,
            ),
            Self::InvalidHost => (
                "invalid-invocation-host",
                "The configured host endpoint or host read deadline could not be used.",
                CliExitCode::Validation,
            ),
            Self::MissingCredential => (
                "missing-admin-credential",
                "Invocation inspection requires --admin-token-file or FCP_HOST_ADMIN_BEARER_TOKEN for the selected host.",
                CliExitCode::PolicyDenied,
            ),
            Self::InvalidCredential => (
                "invalid-admin-credential",
                "The admin bearer secret could not be read or is not a nonempty, bounded HTTP bearer token.",
                CliExitCode::Validation,
            ),
            Self::Transport => (
                "invocation-query-unavailable",
                "The host invocation lookup did not return a readable response. No conclusion about execution effects is available.",
                CliExitCode::Transport,
            ),
            Self::Timeout => (
                "invocation-query-timeout",
                "The host invocation lookup exceeded its read deadline. No conclusion about execution effects is available.",
                CliExitCode::Transport,
            ),
            Self::Http(401 | 403) => (
                "invocation-query-denied",
                "The selected host denied invocation inspection. Check its admin bearer credential and owner-zone access.",
                CliExitCode::PolicyDenied,
            ),
            Self::Http(_) => (
                "invocation-query-unavailable",
                "The selected host did not accept the invocation lookup. Its response does not establish whether the operation had effects.",
                CliExitCode::Transport,
            ),
            Self::InvalidResponse => (
                "invalid-invocation-query-response",
                "The host returned an invalid invocation record or a record for a different request or attempt.",
                CliExitCode::Transport,
            ),
            Self::ResponseTooLarge => (
                "invocation-query-response-too-large",
                "The host invocation metadata response exceeded the 64 KiB read limit.",
                CliExitCode::Transport,
            ),
        }
    }
}

pub(crate) fn dispatch(
    args: &InvocationArgs,
    explicit_host: Option<&str>,
) -> Result<DispatchOutcome> {
    if args.operation_id.trim().is_empty()
        || args.operation_id.len() > MAX_OPERATION_ID_BYTES
        || args.operation_id.chars().any(char::is_control)
        || args.attempt_id == Some(0)
    {
        return Ok(lookup_failure(args, None, LookupFailure::InvalidRequest));
    }
    let host = match resolve_host_config(explicit_host) {
        Ok(Some(host)) => host,
        Ok(None) => return Ok(lookup_failure(args, None, LookupFailure::MissingHost)),
        Err(_) => return Ok(lookup_failure(args, None, LookupFailure::InvalidHost)),
    };
    let client = match HostAdminClient::without_redirects(&host.endpoint) {
        Ok(client) => client,
        Err(_) => {
            return Ok(lookup_failure(
                args,
                Some(&host.endpoint),
                LookupFailure::InvalidHost,
            ));
        }
    };
    let token = match read_admin_token(args.admin_token_file.as_deref()) {
        Ok(token) => token,
        Err(error) => return Ok(lookup_failure(args, Some(&host.endpoint), error)),
    };
    let request = InvocationQueryRequest {
        operation_id: args.operation_id.clone(),
        attempt_id: args.attempt_id,
    };
    match query_invocation(&client, &request, &token) {
        Ok(response) => Ok(lookup_result(args, &host.endpoint, response)),
        Err(error) => Ok(lookup_failure(args, Some(&host.endpoint), error)),
    }
}

fn read_admin_token(path: Option<&std::path::Path>) -> std::result::Result<String, LookupFailure> {
    let value = if let Some(path) = path {
        let file = std::fs::File::open(path).map_err(|_| LookupFailure::InvalidCredential)?;
        let mut value = String::new();
        file.take(MAX_ADMIN_TOKEN_BYTES + 1)
            .read_to_string(&mut value)
            .map_err(|_| LookupFailure::InvalidCredential)?;
        value
    } else {
        match std::env::var(ADMIN_BEARER_TOKEN_ENV) {
            Ok(value) => value,
            Err(std::env::VarError::NotPresent) => return Err(LookupFailure::MissingCredential),
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(LookupFailure::InvalidCredential);
            }
        }
    };
    if value.len() as u64 > MAX_ADMIN_TOKEN_BYTES {
        return Err(LookupFailure::InvalidCredential);
    }
    let token = value.trim();
    if token.is_empty()
        || !token.is_ascii()
        || token.bytes().any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return Err(LookupFailure::InvalidCredential);
    }
    Ok(token.to_owned())
}

fn query_invocation(
    client: &HostAdminClient,
    request: &InvocationQueryRequest,
    token: &str,
) -> std::result::Result<InvocationQueryResponse, LookupFailure> {
    // The dedicated client refuses redirects, including same-origin redirects.
    // Never attach these credentials to discovery, invoke, or a mesh peer.
    let response = client
        .client
        .post(format!("{}{}", client.base_url, INVOCATION_QUERY_PATH))
        .bearer_auth(token)
        .header("x-fcp-zone", "z:owner")
        .timeout(client.read_timeout)
        .json(request)
        .send()
        .map_err(classify_query_transport)?;
    let status = response.status();
    if !status.is_success() {
        // Error bodies may contain secrets echoed by a proxy or upstream host.
        return Err(LookupFailure::Http(status.as_u16()));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_INVOCATION_RESPONSE_BYTES)
    {
        return Err(LookupFailure::ResponseTooLarge);
    }
    let mut body = Vec::new();
    response
        .take(MAX_INVOCATION_RESPONSE_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|error| {
            // Blocking Response::read wraps reqwest errors in io::Error.
            // Inspect the wrapped error directly so the timeout kind survives.
            if error.kind() == std::io::ErrorKind::TimedOut
                || error
                    .get_ref()
                    .and_then(|cause| cause.downcast_ref::<reqwest::Error>())
                    .is_some_and(reqwest::Error::is_timeout)
            {
                LookupFailure::Timeout
            } else {
                LookupFailure::Transport
            }
        })?;
    if body.len() as u64 > MAX_INVOCATION_RESPONSE_BYTES {
        return Err(LookupFailure::ResponseTooLarge);
    }
    let response: InvocationQueryResponse =
        serde_json::from_slice(&body).map_err(|_| LookupFailure::InvalidResponse)?;
    if response.invocation.as_ref().is_some_and(|record| {
        record.ticket.operation_id != request.operation_id
            || record.admission.operation_id != request.operation_id
            || record.ticket.attempt_id == 0
            || request.attempt_id.is_some_and(|attempt| attempt != record.ticket.attempt_id)
    }) {
        return Err(LookupFailure::InvalidResponse);
    }
    Ok(response)
}

fn classify_query_transport(error: reqwest::Error) -> LookupFailure {
    if error.is_timeout() {
        LookupFailure::Timeout
    } else {
        LookupFailure::Transport
    }
}

fn lookup_result(
    args: &InvocationArgs,
    endpoint: &str,
    response: InvocationQueryResponse,
) -> DispatchOutcome {
    let record = response.invocation.as_ref();
    let terminal = record.and_then(|record| record.terminal.as_ref());
    let source_outcome_known =
        terminal.is_some_and(|terminal| terminal.outcome != InvocationOutcome::OutcomeUnknown);
    let finalization_complete = record
        .and_then(|record| record.finalization.as_ref())
        .is_some_and(|finalization| {
            finalization.response_http_status.is_some()
                && finalization.sampling_completed != Some(false)
        });
    // Host liveness is keyed by operation ID, not by durable attempt ID.
    // An exact historical attempt must never borrow a newer job's liveness.
    let latest_job_active = response.host_job_active && args.attempt_id.is_none();
    let state = match (record, terminal) {
        (None, _) if latest_job_active => "active-record-unavailable",
        (None, _) => "not-retained",
        (Some(_), None) if latest_job_active => "running",
        (Some(_), None) => "outcome-unknown",
        (_, Some(terminal)) if terminal.outcome == InvocationOutcome::OutcomeUnknown => {
            "outcome-unknown"
        }
        _ if !finalization_complete && latest_job_active => "source-observed-finalizing",
        _ if !finalization_complete => "source-observed-finalization-incomplete",
        _ => "finalized",
    };
    let message = match state {
        "not-retained" => MISSING_HISTORY_CAVEAT,
        "active-record-unavailable" => "The host reports an active job but has no retained record yet. Admission may still be queued; no conclusion about effects is available.",
        "running" => "The host reports an active job and a retained admission without a terminal observation.",
        "outcome-unknown" => "The host cannot establish the operation's final effects. This record does not authorize another execution.",
        "source-observed-finalizing" => "The source outcome was recorded and the host job is still active. Response, audit, or sampling finalization is not yet complete.",
        "source-observed-finalization-incomplete" => "The source outcome was recorded, but response, audit, or sampling finalization did not finish. Inspect the source outcome separately from finalization.",
        _ => "The host retained both the source outcome and final response status. A successful lookup does not mean the invocation itself succeeded.",
    };
    let mut payload = json!({
        "status": "ok",
        "command": "invocation",
        "source": "host-admin-api",
        "scope": HISTORY_SCOPE,
        "host": { "endpoint": safe_host_endpoint(endpoint) },
        "request": {
            "operation_id": &args.operation_id,
            "attempt_id": args.attempt_id,
        },
        "lookup_succeeded": true,
        "host_job_active": response.host_job_active,
        "host_job_active_scope": "operation-id",
        "found": record.is_some(),
        "execution_state": state,
        "source_outcome_known": source_outcome_known,
        "finalization_complete": finalization_complete,
        "automatic_retry_allowed": false,
        "message": message,
        "invocation": response.invocation,
        "caveats": [MISSING_HISTORY_CAVEAT],
        "next_actions": [
            "Use the exact attempt ID when following one retained attempt.",
            "For a forwarded request, inspect its actual mesh executor if the gateway has no local record.",
        ],
    });
    let mut envelope = CommandEnvelope::new(CommandAvailability::LiveRuntime, "invocation");
    envelope.explanation =
        "Authoritative only for retained invocation history on the selected host.".to_owned();
    envelope.inject_into(&mut payload);
    inject_truth_source_metadata(&mut payload, KnowledgeState::HostBacked);
    DispatchOutcome {
        payload,
        // This is the exit status of the read, never of the recorded invocation.
        exit_code: CliExitCode::Success,
    }
}

fn lookup_failure(
    args: &InvocationArgs,
    endpoint: Option<&str>,
    failure: LookupFailure,
) -> DispatchOutcome {
    let (error_type, message, exit_code) = failure.description();
    let next_actions = vec![
        "Inspect the configured host and its admin access, then repeat only the invocation lookup.",
        "For a forwarded request, query the actual mesh executor's local history.",
    ];
    let mut payload = json!({
        "status": "error",
        "command": "invocation",
        "schema_version": TRUTH_SOURCE_SCHEMA_VERSION,
        "_truth_source": "unavailable",
        "scope": HISTORY_SCOPE,
        "host": { "endpoint": endpoint.and_then(safe_host_endpoint) },
        "request": {
            "operation_id": &args.operation_id,
            "attempt_id": args.attempt_id,
        },
        "lookup_succeeded": false,
        "source_outcome_known": false,
        "automatic_retry_allowed": false,
        "error": {
            "type": error_type,
            "message": message,
            "recoverable": true,
        },
        "caveats": [MISSING_HISTORY_CAVEAT],
        "next_actions": next_actions,
    });
    if let LookupFailure::Http(status) = failure {
        payload["error"]["http_status"] = json!(status);
    }
    let availability = if exit_code == CliExitCode::PolicyDenied {
        CommandAvailability::Denied
    } else {
        CommandAvailability::Unavailable
    };
    let mut envelope = CommandEnvelope::new(availability, "invocation");
    envelope.next_actions = next_actions.into_iter().map(str::to_owned).collect();
    envelope.inject_into(&mut payload);
    DispatchOutcome { payload, exit_code }
}

/// Redacted identity survives every failed invoke POST, including callers that
/// propagate the error out of a pipeline. No raw response, payload, or token is
/// retained in this error.
#[derive(Debug)]
pub(crate) struct InvokeOutcomeUnknown {
    request_id: String,
    connector_id: String,
    operation: String,
    zone: String,
    host_endpoint: Option<String>,
    timed_out: bool,
}

impl InvokeOutcomeUnknown {
    pub(crate) fn from_request(
        request: &InvokeRequest,
        endpoint: &str,
        error: &anyhow::Error,
    ) -> Self {
        Self {
            request_id: request.id.to_string(),
            connector_id: request.connector_id.to_string(),
            operation: request.operation.to_string(),
            zone: request.zone_id.to_string(),
            host_endpoint: safe_host_endpoint(endpoint),
            timed_out: error.chain().any(|cause| {
                cause
                    .downcast_ref::<reqwest::Error>()
                    .is_some_and(reqwest::Error::is_timeout)
            }),
        }
    }

    pub(crate) fn dispatch(&self, command: &str) -> DispatchOutcome {
        let inspection_command = format!(
            "fwc invocation {} --host {} --json",
            shell_word(&self.request_id),
            self.host_endpoint
                .as_deref()
                .map_or_else(|| "<executor-host>".to_owned(), shell_word),
        );
        let next_actions = vec![
            inspection_command.clone(),
            "Authenticate the lookup with --admin-token-file or FCP_HOST_ADMIN_BEARER_TOKEN.".to_owned(),
            "A gateway may have forwarded the request; inspect the actual mesh executor if its local record is absent.".to_owned(),
            "Establish the prior attempt's effects before deciding whether to repeat the operation.".to_owned(),
        ];
        let mut payload = json!({
            "status": "error",
            "command": command,
            "schema_version": TRUTH_SOURCE_SCHEMA_VERSION,
            "_truth_source": "unavailable",
            "phase": "execution",
            "request_id": &self.request_id,
            "request": {
                "request_id": &self.request_id,
                "zone": &self.zone,
            },
            "connector": { "canonical_id": &self.connector_id },
            "operation": { "canonical_id": &self.operation },
            "host": { "endpoint": &self.host_endpoint },
            "outcome": "outcome_unknown",
            "source_outcome_known": false,
            "automatic_retry_allowed": false,
            "message": "The invoke response was not usable. The operation may have executed; its request identity is retained for inspection.",
            "error": {
                "type": "invoke-outcome-unknown",
                "message": "The host did not return a usable connector result for this invoke attempt. Inspect retained host history before repeating it.",
                "timed_out": self.timed_out,
                "recoverable": false,
            },
            "inspection": {
                "operation_id": &self.request_id,
                "attempt_id": null,
                "scope": HISTORY_SCOPE,
                "host_endpoint": &self.host_endpoint,
                "command": inspection_command,
            },
            "caveats": [MISSING_HISTORY_CAVEAT],
            "next_actions": next_actions,
        });
        let mut envelope = CommandEnvelope::new(CommandAvailability::Unknown, command);
        envelope.explanation =
            "The invoke outcome is unknown; repeating the execution may duplicate effects.".to_owned();
        envelope.recoverable = false;
        envelope.next_actions = next_actions;
        envelope.inject_into(&mut payload);
        DispatchOutcome {
            payload,
            exit_code: CliExitCode::Transport,
        }
    }
}

impl std::fmt::Display for InvokeOutcomeUnknown {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "invoke outcome unknown for request {}; inspect retained host history before repeating it",
            self.request_id,
        )
    }
}

impl std::error::Error for InvokeOutcomeUnknown {}

pub(crate) fn withhold_argument_echo(payload: &Value) -> bool {
    payload["command"] == "invocation" || payload["error"]["type"] == "invoke-outcome-unknown"
}

fn safe_host_endpoint(endpoint: &str) -> Option<String> {
    // Reuse the host parser's rejection of userinfo, query strings and
    // fragments. Invalid endpoint text must never be echoed into diagnostics.
    crate::normalize_host_endpoint(endpoint).ok()
}

fn shell_word(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    use chrono::Utc;
    use fcp_host::{
        InvocationAdmission, InvocationFinalization, InvocationRecord, InvocationTerminal,
        InvocationTicket,
    };

    enum Reply {
        Json(u16, Value),
        Disconnect,
        Redirect(String),
        StalledBody,
        OversizedBody,
    }

    #[derive(Debug)]
    struct CapturedRequest {
        line: String,
        headers: BTreeMap<String, String>,
        body: Value,
    }

    struct TestHost {
        endpoint: String,
        observed: mpsc::Receiver<CapturedRequest>,
        release: mpsc::Sender<()>,
        worker: Option<thread::JoinHandle<()>>,
    }

    impl TestHost {
        fn start(reply: Reply) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let (release, released) = mpsc::channel();
            let (observed_request, observed) = mpsc::channel();
            let worker = thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(5);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(error) => panic!("test host accept failed: {error}"),
                    }
                    match released.recv_timeout(Duration::from_millis(10)) {
                        Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return,
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            assert!(Instant::now() < deadline, "client did not connect");
                        }
                    }
                };
                stream.set_nonblocking(false).unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let mut headers = BTreeMap::new();
                loop {
                    let mut header = String::new();
                    if reader.read_line(&mut header).unwrap() == 0 || header == "\r\n" {
                        break;
                    }
                    let (name, value) = header.split_once(':').expect("valid header");
                    headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
                }
                let content_length = headers
                    .get("content-length")
                    .map_or(0, |value| value.parse::<usize>().unwrap());
                assert!(content_length < 1_048_576);
                let mut body = vec![0; content_length];
                reader.read_exact(&mut body).unwrap();
                observed_request
                    .send(CapturedRequest {
                        line: line.trim().to_owned(),
                        headers,
                        body: serde_json::from_slice(&body).unwrap(),
                    })
                    .unwrap();
                match reply {
                    Reply::Json(status, body) => {
                        let body = serde_json::to_string(&body).unwrap();
                        write!(
                            stream,
                            "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len(),
                        )
                        .unwrap();
                        stream.flush().unwrap();
                    }
                    Reply::Disconnect => {}
                    Reply::Redirect(location) => {
                        write!(
                            stream,
                            "HTTP/1.1 307 Temporary Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .unwrap();
                        stream.flush().unwrap();
                    }
                    Reply::StalledBody => {
                        stream
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{")
                            .unwrap();
                        stream.flush().unwrap();
                        let _ = released.recv_timeout(Duration::from_secs(5));
                    }
                    Reply::OversizedBody => {
                        stream
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n")
                            .unwrap();
                        let body = json!({
                            "invocation": null,
                            "padding": "x".repeat(MAX_INVOCATION_RESPONSE_BYTES as usize),
                        })
                        .to_string();
                        // Rejection may close the socket before the full body
                        // reaches the receiver, which is the behavior tested.
                        let _ = stream.write_all(body.as_bytes());
                    }
                }
            });
            Self {
                endpoint,
                observed,
                release,
                worker: Some(worker),
            }
        }

        fn finish(mut self) -> CapturedRequest {
            let captured = self.observed.recv_timeout(Duration::from_secs(5)).unwrap();
            let _ = self.release.send(());
            self.worker.take().unwrap().join().expect("test host completed");
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

    fn record(terminal: Option<InvocationOutcome>, finalized: bool) -> InvocationRecord {
        let now = Utc::now();
        InvocationRecord {
            ticket: InvocationTicket {
                operation_id: "req-inspect".to_owned(),
                attempt_id: 7,
            },
            admission: InvocationAdmission {
                operation_id: "req-inspect".to_owned(),
                connector_id: "fcp.github:enterprise:v1".to_owned(),
                operation: "github.create_issue".to_owned(),
                zone_id: "z:work".to_owned(),
                principal: "test-owner".to_owned(),
                correlation_id: None,
                idempotency: None,
                deadline_at: now + chrono::Duration::seconds(30),
            },
            admitted_at: now,
            terminal: terminal.map(|outcome| InvocationTerminal {
                outcome,
                receipt_id: Some("receipt-source".to_owned()),
                duration_ms: 12,
                http_status: 200,
            }),
            finished_at: terminal.map(|_| now),
            finalization: finalized.then(|| InvocationFinalization {
                budget_recorded: true,
                receipt_recorded: true,
                audit_event_id: Some("audit-source".to_owned()),
                sampling_completed: Some(true),
                response_http_status: Some(502),
                ..Default::default()
            }),
            durable: true,
        }
    }

    fn args(attempt_id: Option<u64>) -> InvocationArgs {
        InvocationArgs {
            operation_id: "req-inspect".to_owned(),
            attempt_id,
            admin_token_file: None,
        }
    }

    fn execute_lookup(host: &str, attempt: Option<&str>) -> (std::process::ExitCode, Value, String) {
        let directory = tempfile::tempdir().unwrap();
        let token_path = directory.path().join("admin.token");
        std::fs::write(&token_path, "fixture-admin-secret\n").unwrap();
        let mut arguments = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "invocation".to_owned(),
            "req-inspect".to_owned(),
            "--host".to_owned(),
            host.to_owned(),
            "--admin-token-file".to_owned(),
            token_path.to_string_lossy().into_owned(),
        ];
        if let Some(attempt) = attempt {
            arguments.extend(["--attempt-id".to_owned(), attempt.to_owned()]);
        }
        let outcome = crate::execute(&arguments).unwrap();
        let value = serde_json::from_str(&outcome.text).unwrap();
        (outcome.exit_code, value, outcome.text)
    }

    #[test]
    fn invocation_cli_queries_exact_attempt_with_scoped_auth_and_separate_source_outcome() {
        let host = TestHost::start(Reply::Json(
            200,
            json!({
                "invocation": record(Some(InvocationOutcome::Succeeded), true),
                "host_job_active": false,
            }),
        ));
        let (exit, payload, rendered) = execute_lookup(&host.endpoint, Some("7"));
        let captured = host.finish();

        assert_eq!(captured.line, "POST /rpc/admin/invocations HTTP/1.1");
        assert_eq!(captured.headers["authorization"], "Bearer fixture-admin-secret");
        assert_eq!(captured.headers["x-fcp-zone"], "z:owner");
        assert_eq!(captured.body, json!({"operation_id": "req-inspect", "attempt_id": 7}));
        assert_eq!(exit, CliExitCode::Success.into());
        assert_eq!(payload["_truth_source"], "host");
        assert_eq!(payload["scope"], HISTORY_SCOPE);
        assert_eq!(payload["lookup_succeeded"], true);
        assert_eq!(payload["source_outcome_known"], true);
        assert_eq!(payload["finalization_complete"], true);
        assert_eq!(payload["invocation"]["terminal"]["outcome"], "succeeded");
        assert_eq!(payload["invocation"]["finalization"]["response_http_status"], 502);
        assert_eq!(payload["automatic_retry_allowed"], false);
        assert!(!rendered.contains("fixture-admin-secret"));
    }

    #[test]
    fn invocation_lookup_missing_history_and_operation_liveness_never_prove_no_effect() {
        for active in [false, true] {
            let host = TestHost::start(Reply::Json(
                200,
                json!({"invocation": null, "host_job_active": active}),
            ));
            let (exit, payload, _) = execute_lookup(&host.endpoint, Some("3"));
            host.finish();
            assert_eq!(exit, CliExitCode::Success.into());
            assert_eq!(payload["found"], false);
            assert_eq!(payload["host_job_active"], active);
            assert_eq!(payload["host_job_active_scope"], "operation-id");
            assert_eq!(payload["execution_state"], "not-retained");
            assert_eq!(payload["source_outcome_known"], false);
            assert_eq!(payload["automatic_retry_allowed"], false);
            assert!(payload["caveats"][0].as_str().unwrap().contains("does not prove"));
        }
    }

    #[test]
    fn invocation_lookup_distinguishes_abandoned_admission_and_unfinished_finalization() {
        for (terminal, active, expected) in [
            (None, true, "running"),
            (None, false, "outcome-unknown"),
            (Some(InvocationOutcome::OutcomeUnknown), true, "outcome-unknown"),
            (Some(InvocationOutcome::Succeeded), true, "source-observed-finalizing"),
            (
                Some(InvocationOutcome::Succeeded),
                false,
                "source-observed-finalization-incomplete",
            ),
        ] {
            let outcome = lookup_result(
                &args(None),
                "127.0.0.1:8787",
                InvocationQueryResponse {
                    invocation: Some(record(terminal, false)),
                    host_job_active: active,
                },
            );
            assert_eq!(outcome.exit_code, CliExitCode::Success);
            assert_eq!(outcome.payload["execution_state"], expected);
            assert_eq!(outcome.payload["finalization_complete"], false);
            assert_eq!(
                outcome.payload["source_outcome_known"],
                terminal.is_some_and(|value| value != InvocationOutcome::OutcomeUnknown)
            );
        }

        // A response status cannot settle explicitly unresolved sampling.
        // This also protects records emitted by older hosts.
        for (active, expected) in [
            (true, "source-observed-finalizing"),
            (false, "source-observed-finalization-incomplete"),
        ] {
            let mut incomplete = record(Some(InvocationOutcome::Succeeded), true);
            incomplete
                .finalization
                .as_mut()
                .unwrap()
                .sampling_completed = Some(false);
            let outcome = lookup_result(
                &args(None),
                "http://127.0.0.1:8787",
                InvocationQueryResponse {
                    invocation: Some(incomplete),
                    host_job_active: active,
                },
            );
            assert_eq!(outcome.payload["execution_state"], expected);
            assert_eq!(outcome.payload["source_outcome_known"], true);
            assert_eq!(outcome.payload["finalization_complete"], false);
            assert_eq!(
                outcome.payload["invocation"]["finalization"]["response_http_status"],
                502
            );
        }

        let historical = lookup_result(
            &args(Some(7)),
            "http://127.0.0.1:8787",
            InvocationQueryResponse {
                invocation: Some(record(None, false)),
                host_job_active: true,
            },
        );
        assert_eq!(historical.payload["execution_state"], "outcome-unknown");
        assert_eq!(historical.payload["host_job_active"], true);

        // Older hosts do not prove liveness merely by omitting the new field.
        let legacy: InvocationQueryResponse =
            serde_json::from_value(json!({"invocation": record(None, false)})).unwrap();
        assert!(!legacy.host_job_active);
        assert_eq!(
            lookup_result(&args(None), "http://127.0.0.1:8787", legacy).payload["execution_state"],
            "outcome-unknown"
        );
    }

    #[test]
    fn invocation_lookup_rejects_wrong_identity_and_redacts_denied_response() {
        for (ticket_id, admission_id, attempt_id, requested_attempt) in [
            ("req-inspect", "req-inspect", 7, Some("8")),
            ("other-request", "req-inspect", 7, None),
            ("req-inspect", "other-request", 7, None),
            ("req-inspect", "req-inspect", 0, None),
        ] {
            let mut invalid = record(Some(InvocationOutcome::Succeeded), true);
            invalid.ticket.operation_id = ticket_id.to_owned();
            invalid.admission.operation_id = admission_id.to_owned();
            invalid.ticket.attempt_id = attempt_id;
            let host = TestHost::start(Reply::Json(200, json!({"invocation": invalid})));
            let (exit, payload, rendered) = execute_lookup(&host.endpoint, requested_attempt);
            host.finish();
            assert_eq!(exit, CliExitCode::Transport.into());
            assert_eq!(payload["error"]["type"], "invalid-invocation-query-response");
            assert!(payload.get("invocation").is_none());
            assert!(!rendered.contains("other-request"));
        }

        let host = TestHost::start(Reply::Json(
            403,
            json!({"message": "reflected fixture-admin-secret and raw-private-payload"}),
        ));
        let (exit, payload, rendered) = execute_lookup(&host.endpoint, None);
        host.finish();
        assert_eq!(exit, CliExitCode::PolicyDenied.into());
        assert_eq!(payload["error"]["type"], "invocation-query-denied");
        assert_eq!(payload["error"]["http_status"], 403);
        assert_eq!(payload["lookup_succeeded"], false);
        assert!(!rendered.contains("fixture-admin-secret"));
        assert!(!rendered.contains("raw-private-payload"));
        assert!(payload["error"].get("debug_chain").is_none());
    }

    #[test]
    fn invocation_lookup_refuses_redirects_and_bounds_stalled_response_bodies() {
        let destination = TcpListener::bind("127.0.0.1:0").unwrap();
        destination.set_nonblocking(true).unwrap();
        let host = TestHost::start(Reply::Redirect(format!(
            "http://{}/redirected",
            destination.local_addr().unwrap(),
        )));
        let mut client = HostAdminClient::without_redirects(&host.endpoint).unwrap();
        client.read_timeout = Duration::from_millis(250);
        let request = InvocationQueryRequest {
            operation_id: "req-inspect".to_owned(),
            attempt_id: None,
        };
        assert!(matches!(
            query_invocation(&client, &request, "fixture-admin-secret"),
            Err(LookupFailure::Http(307))
        ));
        host.finish();
        assert!(matches!(
            destination.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));

        let host = TestHost::start(Reply::StalledBody);
        let mut client = HostAdminClient::without_redirects(&host.endpoint).unwrap();
        client.read_timeout = Duration::from_millis(250);
        assert!(matches!(
            query_invocation(&client, &request, "fixture-admin-secret"),
            Err(LookupFailure::Timeout)
        ));
        host.finish();
    }

    #[test]
    fn invocation_lookup_caps_success_body_before_decoding_unknown_length_json() {
        let host = TestHost::start(Reply::OversizedBody);
        let client = HostAdminClient::without_redirects(&host.endpoint).unwrap();
        let request = InvocationQueryRequest {
            operation_id: "req-inspect".to_owned(),
            attempt_id: None,
        };
        assert!(matches!(
            query_invocation(&client, &request, "fixture-admin-secret"),
            Err(LookupFailure::ResponseTooLarge)
        ));
        host.finish();
    }

    #[test]
    fn invocation_lookup_rejects_bad_metadata_secrets_and_unsafe_endpoint_without_echoing_them() {
        let mut invalid = args(Some(0));
        let invalid_query = dispatch(&invalid, Some("http://127.0.0.1:1")).unwrap();
        assert_eq!(invalid_query.exit_code, CliExitCode::Validation);
        invalid.attempt_id = None;
        invalid.operation_id = "x".repeat(MAX_OPERATION_ID_BYTES + 1);
        assert_eq!(
            dispatch(&invalid, Some("http://127.0.0.1:1")).unwrap().exit_code,
            CliExitCode::Validation
        );

        let directory = tempfile::tempdir().unwrap();
        let token_path = directory.path().join("admin.token");
        for secret in ["", "header\ninjection", "word with spaces"] {
            std::fs::write(&token_path, secret).unwrap();
            assert!(matches!(
                read_admin_token(Some(&token_path)),
                Err(LookupFailure::InvalidCredential)
            ));
        }
        std::fs::write(&token_path, "x".repeat(MAX_ADMIN_TOKEN_BYTES as usize + 1)).unwrap();
        assert!(matches!(
            read_admin_token(Some(&token_path)),
            Err(LookupFailure::InvalidCredential)
        ));
        let invalid_host = dispatch(
            &args(None),
            Some("http://private-user:private-password@127.0.0.1:1?secret=query-value"),
        )
        .unwrap();
        let rendered = invalid_host.payload.to_string();
        for secret in ["private-user", "private-password", "query-value"] {
            assert!(!rendered.contains(secret));
        }
    }

    fn invoke_request() -> InvokeRequest {
        crate::build_live_invoke_request(
            "fcp.github:enterprise:v1",
            "github.create_issue",
            "z:work",
            json!({"private_input": "raw-private-payload"}),
            crate::RequestId::new("req-inspect"),
            crate::CapabilityToken::test_token(),
            Vec::new(),
            None,
            None,
            None,
        )
        .unwrap()
    }

    #[test]
    fn dropped_invoke_response_preserves_identity_for_generic_pipeline_errors_without_retry() {
        let host = TestHost::start(Reply::Disconnect);
        let client = HostAdminClient::new(&host.endpoint).unwrap();
        let request = invoke_request();
        let error = client.invoke(&request).expect_err("server drops response after reading body");
        let captured = host.finish();
        assert_eq!(captured.line, "POST /rpc/invoke HTTP/1.1");
        assert_eq!(captured.body["id"], "req-inspect");
        assert!(captured.headers.get("authorization").is_none());
        assert!(captured.headers.get("x-fcp-zone").is_none());

        let args = ["fwc", "--json", "pipeline", "run", "pipeline.toml"]
            .map(str::to_owned);
        let dispatch = crate::internal_error_dispatch(&args, &error);
        assert_eq!(dispatch.exit_code, CliExitCode::Transport);
        assert_eq!(dispatch.payload["request_id"], "req-inspect");
        assert_eq!(dispatch.payload["request"]["request_id"], "req-inspect");
        assert_eq!(dispatch.payload["outcome"], "outcome_unknown");
        assert_eq!(dispatch.payload["automatic_retry_allowed"], false);
        assert_eq!(dispatch.payload["inspection"]["operation_id"], "req-inspect");
        assert_eq!(dispatch.payload["_truth_source"], "unavailable");
        assert_eq!(dispatch.payload["availability"]["recoverable"], false);
        assert!(dispatch.payload["next_actions"][0].as_str().unwrap().starts_with("fwc invocation "));
        assert!(!dispatch.payload.to_string().contains("raw-private-payload"));
        assert!(!error.to_string().contains("raw-private-payload"));
        assert!(dispatch.payload["error"].get("debug_chain").is_none());
    }

    #[test]
    fn mismatched_invoke_response_cannot_replace_the_request_inspection_identity() {
        let response = crate::InvokeResponse::ok(
            crate::RequestId::new("different-attempt"),
            json!({"private_result": "raw-private-result"}),
        );
        let host = TestHost::start(Reply::Json(200, serde_json::to_value(response).unwrap()));
        let client = HostAdminClient::new(&host.endpoint).unwrap();
        let error = client.invoke(&invoke_request()).expect_err("wrong response ID");
        host.finish();
        let unknown = error.downcast_ref::<InvokeOutcomeUnknown>().unwrap();
        let outcome = unknown.dispatch("invoke");
        assert_eq!(outcome.payload["request_id"], "req-inspect");
        assert_eq!(outcome.payload["inspection"]["operation_id"], "req-inspect");
        assert_eq!(outcome.payload["outcome"], "outcome_unknown");
        assert_eq!(outcome.exit_code, CliExitCode::Transport);
        assert!(!outcome.payload.to_string().contains("different-attempt"));
        assert!(!outcome.payload.to_string().contains("raw-private-result"));
    }

    #[test]
    fn invoke_inspection_preserves_endpoint_and_withholds_argument_normalization_echoes() {
        let request = invoke_request();
        let error = anyhow::anyhow!("raw-private-payload and fixture-admin-secret");
        #[cfg(unix)]
        let endpoint = "unix:///tmp/fcp.sock";
        #[cfg(not(unix))]
        let endpoint = "http://127.0.0.1:8787";
        let unknown = InvokeOutcomeUnknown::from_request(&request, endpoint, &error);
        let mut outcome = unknown.dispatch("invoke");
        assert_eq!(outcome.payload["host"]["endpoint"], endpoint);
        let arguments = [
            "fwc",
            "invok",
            "github",
            "--input",
            "raw-private-payload",
            "--capability-token",
            "fixture-admin-secret",
        ]
        .map(str::to_owned);
        crate::annotate_with_corrections(
            &mut outcome.payload,
            &arguments,
            &arguments,
            &[crate::InputCorrection {
                from: "invok".to_owned(),
                to: "invoke".to_owned(),
                rationale: "test correction",
            }],
        );
        assert!(outcome.payload.get("input_normalization").is_none());
        assert!(!outcome.payload.to_string().contains("raw-private-payload"));
        assert!(!outcome.payload.to_string().contains("fixture-admin-secret"));
    }
}
