//! Reconcile one saved execution from durable evidence without dispatching work.

use std::path::PathBuf;
use std::time::Instant;

use anyhow::Result;
use clap::Args;
use fcp_host::InvocationQueryRequest;
use serde::Serialize;
use serde_json::{Value, json};

use crate::invocation_cmd::{self, LookupFailure};
use crate::task_reconcile::{self, ReconcileFailure};
use crate::workflow::{TaskExecutionState, TaskLease, TaskStore, WorkflowTask};
use crate::{
    CliExitCode, CommandAvailability, CommandEnvelope, DispatchOutcome, HostAdminClient,
    missing_task_dispatch, normalize_host_endpoint, resolve_host_config, task_payload_view,
};

const MAX_LOOKUPS: usize = 128;

#[derive(Args, Debug, Serialize)]
pub(crate) struct TaskReconcileArgs {
    /// Saved workflow capsule whose interrupted execution should be inspected.
    pub(crate) task_id: String,

    /// Read the selected host's admin bearer secret from this file.
    /// Defaults to FCP_HOST_ADMIN_BEARER_TOKEN. Never used for an invocation.
    #[arg(long, value_name = "PATH")]
    #[serde(skip)]
    admin_token_file: Option<PathBuf>,
}

pub(crate) fn dispatch(
    args: &TaskReconcileArgs,
    explicit_host: Option<&str>,
) -> Result<DispatchOutcome> {
    let store = TaskStore::discover()?;
    reconcile(&store, args, explicit_host)
}

/// Holding the existing exclusive lease prevents reconciliation from racing a
/// live task executor or rewriting a newer revision. Reads never grant replay.
#[allow(clippy::too_many_lines)]
fn reconcile(
    store: &TaskStore,
    args: &TaskReconcileArgs,
    explicit_host: Option<&str>,
) -> Result<DispatchOutcome> {
    let lease = store.lock_task(&args.task_id)?;
    let Some(mut task) = lease.load()? else {
        return Ok(missing_task_dispatch(&args.task_id));
    };
    let Some(fence) = task.execution_fence.clone() else {
        return Ok(refusal(
            &task,
            "task-reconciliation-unavailable",
            "This capsule has no retained execution journal to reconcile. Inspect its execution history before deciding on new work.",
            CliExitCode::Validation,
        ));
    };
    if fence.state == TaskExecutionState::Completed {
        return Ok(report(&task, Vec::new(), 0, CliExitCode::Success));
    }
    let Some(journal) = fence.journal else {
        return Ok(refusal(
            &task,
            "task-reconciliation-legacy-fence",
            "This older execution fence has no per-step request bindings. Its effects require manual host or provider inspection; the fence remains in place.",
            CliExitCode::Validation,
        ));
    };

    // A crash after saving the last primitive receipt needs no credential or
    // network access. The same applies when every required proof was already saved.
    if journal.steps.iter().all(|step| step.is_complete()) {
        return Ok(finish(&lease, &fence.attempt_id, &task, Vec::new(), 0, None));
    }
    let mut observations = Vec::new();
    let candidates = journal
        .steps
        .iter()
        .filter(|step| !step.is_complete() && step.invocation.is_some())
        .filter(|step| {
            if step.completion_conflicts_with_receipt() {
                observations.push(json!({
                    "ordinal": step.ordinal,
                    "status": "unresolved",
                    "reason": "task-step-definitive-failure",
                    "message": "The original primitive receipt records a definite refusal or failure. Reconciliation cannot replace it with success.",
                    "lookup_succeeded": false,
                }));
                false
            } else {
                true
            }
        })
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        observations.push(json!({
            "status": "unresolved",
            "reason": "task-step-evidence-unavailable",
            "message": "Unfinished steps have no eligible invocation binding. They cannot be completed or replayed by reconciliation.",
        }));
        return Ok(finish(
            &lease,
            &fence.attempt_id,
            &task,
            observations,
            0,
            None,
        ));
    }

    // Require the operator's selected host to match a saved binding before
    // reading or transmitting its admin credential. Never route credentials
    // automatically to a destination supplied by a task file or host response.
    let selected_host = match resolve_host_config(explicit_host) {
        Ok(Some(host)) => match normalize_host_endpoint(&host.endpoint) {
            Ok(endpoint) => endpoint,
            Err(_) => return Ok(lookup_refusal(&task, LookupFailure::InvalidHost)),
        },
        Ok(None) => return Ok(lookup_refusal(&task, LookupFailure::MissingHost)),
        Err(_) => return Ok(lookup_refusal(&task, LookupFailure::InvalidHost)),
    };
    if !candidates.iter().any(|step| {
        step.invocation
            .as_ref()
            .is_some_and(|binding| binding.host == selected_host)
    }) {
        return Ok(refusal(
            &task,
            ReconcileFailure::WrongHost.code(),
            ReconcileFailure::WrongHost.message(),
            CliExitCode::Validation,
        ));
    }
    let mut client = match HostAdminClient::for_invocation_inspection(&selected_host) {
        Ok(client) => client,
        Err(_) => return Ok(lookup_refusal(&task, LookupFailure::InvalidHost)),
    };
    let token = match invocation_cmd::read_admin_token(args.admin_token_file.as_deref()) {
        Ok(token) => token,
        Err(error) => return Ok(lookup_refusal(&task, error)),
    };
    // Every lookup, including its body, shares one configured host read budget.
    // A long task must not obtain a new timeout for every primitive.
    let started = Instant::now();
    let budget = client.read_timeout;
    let mut lookups = 0;
    let mut lookup_exit = None;
    for step in candidates {
        let binding = step.invocation.as_ref().expect("candidate has a binding");
        if binding.host != selected_host {
            observations.push(evidence_refusal(step.ordinal, ReconcileFailure::WrongHost));
            continue;
        }
        if lookups >= MAX_LOOKUPS {
            observations.push(json!({
                "ordinal": step.ordinal,
                "status": "unresolved",
                "reason": "task-reconciliation-lookup-limit",
                "message": "This reconciliation reached its bounded lookup count. Retained evidence remains saved; inspect the task before continuing.",
            }));
            lookup_exit = Some(CliExitCode::Validation);
            break;
        }
        let remaining = budget.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            let (kind, message, exit) = LookupFailure::Timeout.description();
            observations.push(json!({
                "ordinal": step.ordinal,
                "status": "unresolved",
                "reason": kind,
                "message": message,
            }));
            lookup_exit = Some(exit);
            break;
        }
        client.read_timeout = remaining;
        let request = InvocationQueryRequest {
            operation_id: binding.request_id.clone(),
            attempt_id: step.observed_attempt.as_ref().map(|pin| pin.attempt_id),
        };
        lookups += 1;
        let response = match invocation_cmd::query_invocation(&client, &request, &token) {
            Ok(response) => response,
            Err(error) => {
                let (kind, message, exit) = error.description();
                observations.push(json!({
                    "ordinal": step.ordinal,
                    "status": "unresolved",
                    "reason": kind,
                    "message": message,
                    "lookup_succeeded": false,
                }));
                lookup_exit = Some(exit);
                continue;
            }
        };
        let pin = match task_reconcile::bind_observation(
            binding,
            &selected_host,
            step.observed_attempt.as_ref(),
            &response,
        ) {
            Ok(pin) => pin,
            Err(error) => {
                observations.push(evidence_refusal(step.ordinal, error));
                continue;
            }
        };
        if lease
            .record_invocation_observation(&fence.attempt_id, step.ordinal, pin.clone())
            .is_err()
        {
            return Ok(persistence_refusal(&lease, &task, observations, lookups));
        }
        // Pin even active, non-durable or unknown observations before testing
        // success. A later read must never follow a newer local or mesh attempt.
        let completion = match task_reconcile::verify_completion(
            binding,
            &selected_host,
            &pin,
            &response,
        ) {
            Ok(completion) => completion,
            Err(error) => {
                let mut observation = evidence_refusal(step.ordinal, error);
                observation["observed_attempt"] = json!(pin);
                observations.push(observation);
                continue;
            }
        };
        match lease.record_invocation_completion(
            &fence.attempt_id,
            step.ordinal,
            completion.clone(),
        ) {
            Ok(saved) => task = saved,
            Err(_) => return Ok(persistence_refusal(&lease, &task, observations, lookups)),
        }
        observations.push(json!({
            "ordinal": step.ordinal,
            "status": "confirmed",
            "source": "host-admin-api",
            "lookup_succeeded": true,
            "observed_attempt": pin,
            "completion": completion,
        }));
    }
    Ok(finish(
        &lease,
        &fence.attempt_id,
        &task,
        observations,
        lookups,
        lookup_exit,
    ))
}

fn finish(
    lease: &TaskLease<'_>,
    attempt_id: &str,
    task: &WorkflowTask,
    observations: Vec<Value>,
    lookups: usize,
    lookup_exit: Option<CliExitCode>,
) -> DispatchOutcome {
    match lease.finish_reconciliation(attempt_id) {
        Ok(saved) => {
            let completed = saved.execution_blocker() == Some(TaskExecutionState::Completed);
            let exit = if completed {
                CliExitCode::Success
            } else {
                lookup_exit.unwrap_or(CliExitCode::Validation)
            };
            report(&saved, observations, lookups, exit)
        }
        Err(_) => persistence_refusal(lease, task, observations, lookups),
    }
}

fn evidence_refusal(ordinal: usize, error: ReconcileFailure) -> Value {
    json!({
        "ordinal": ordinal,
        "status": "unresolved",
        "reason": error.code(),
        "message": error.message(),
        "source": "host-admin-api",
        "lookup_succeeded": error != ReconcileFailure::WrongHost,
    })
}

fn lookup_refusal(task: &WorkflowTask, error: LookupFailure) -> DispatchOutcome {
    let (kind, message, exit) = error.description();
    refusal(task, kind, message, exit)
}

fn refusal(
    task: &WorkflowTask,
    kind: &'static str,
    message: &'static str,
    exit: CliExitCode,
) -> DispatchOutcome {
    let mut outcome = report(task, Vec::new(), 0, exit);
    outcome.payload["error"] = json!({
        "type": kind,
        "message": message,
        "recoverable": false,
    });
    outcome
}

fn persistence_refusal(
    lease: &TaskLease<'_>,
    fallback: &WorkflowTask,
    observations: Vec<Value>,
    lookups: usize,
) -> DispatchOutcome {
    let latest = lease.load().ok().flatten();
    let mut outcome = report(
        latest.as_ref().unwrap_or(fallback),
        observations,
        lookups,
        CliExitCode::Internal,
    );
    outcome.payload["error"] = json!({
        "type": "task-reconciliation-not-persisted",
        "message": "Reconciliation evidence could not be saved consistently. Execution remains fenced; inspect the retained task before deciding on further work.",
        "recoverable": false,
    });
    outcome
}

fn report(
    task: &WorkflowTask,
    observations: Vec<Value>,
    lookups: usize,
    exit_code: CliExitCode,
) -> DispatchOutcome {
    let journal = task
        .execution_fence
        .as_ref()
        .and_then(|fence| fence.journal.as_ref());
    let state = task.execution_blocker();
    let completed = state == Some(TaskExecutionState::Completed);
    let fenced = state.is_some();
    let total = journal.map(|journal| journal.steps.len());
    let covered = journal.map(|journal| {
        journal.steps.iter().filter(|step| step.is_complete()).count()
    });
    let unresolved = total.zip(covered).map(|(total, covered)| total.saturating_sub(covered));
    let status = if completed {
        "completed"
    } else if covered.is_some_and(|count| count > 0) {
        "partial"
    } else {
        "unresolved"
    };
    let message = match (completed, journal.is_some(), fenced) {
        (true, true, _) => {
            "Every planned step has retained success evidence. The capsule remains consumed. \
             Reconciliation did not resend work or reconstruct missing result bodies."
        }
        (true, false, _) => {
            "The retained execution record already marks this capsule complete and consumed. \
             Its legacy record has no per-step journal, so step coverage is unavailable. \
             Reconciliation did not resend work or recover missing outputs."
        }
        (_, _, false) => {
            "This capsule has no retained execution attempt to reconcile. No work was sent."
        }
        (false, false, true) => {
            "The saved execution remains fenced for review. Its legacy record has no per-step \
             journal, so step completion is unproven. No operation was resent."
        }
        (false, true, true) => {
            "Some planned work remains unproven. The execution fence remains in place; \
             no operation was resent."
        }
    };
    let next_actions = match (completed, journal.is_some(), fenced) {
        (true, true, _) => vec![
            "Inspect the retained receipts and completion references. Create a separate task \
             only for intended new work.",
        ],
        (true, false, _) => vec![
            "Inspect the retained execution record. This capsule is already consumed; \
             no per-step coverage is available.",
        ],
        (_, _, false) => vec![
            "Inspect the capsule's execution history. Reconciliation has no retained attempt \
             to resolve.",
        ],
        (false, false, true) => vec![
            "Inspect the retained execution record and host or provider effects. Legacy \
             records cannot establish per-step completion.",
        ],
        (false, true, true) => vec![
            "Inspect the saved task and unresolved step reasons.",
            "Reconcile again with the original host after an active invocation finishes, \
             or inspect host/provider effects when retained evidence is unavailable.",
        ],
    };
    let mut payload = json!({
        "status": status,
        "command": "task",
        "subcommand": "reconcile",
        "message": message,
        "invoke_attempted": false,
        "automatic_retry_allowed": false,
        "result_recovered": false,
        "reconciliation": {
            "complete": completed,
            "journal_available": journal.is_some(),
            "execution_fenced": fenced,
            "covered_steps": covered,
            "total_steps": total,
            "unresolved_steps": unresolved,
            "host_lookups": lookups,
            "observations": observations,
        },
        "task": task_payload_view(task),
        "caveats": [
            "Missing retained history does not prove that an operation had no effects.",
            "Local finalization and mesh origin observations are distinct evidence scopes. Neither provides a replayable result or an external exactly-once guarantee.",
        ],
        "next_actions": next_actions,
    });
    let mut envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "task");
    envelope.explanation =
        "Saved task evidence, with any successful host-history observations explicitly scoped per step."
            .to_owned();
    envelope.recoverable = false;
    envelope.inject_into(&mut payload);
    DispatchOutcome { payload, exit_code }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex, mpsc};
    use std::thread;
    use std::time::Duration;

    use chrono::{DateTime, Utc};
    use fcp_host::{
        InvocationAdmission, InvocationFinalization, InvocationIdempotency, InvocationOutcome,
        InvocationQueryResponse, InvocationRecord, InvocationTerminal, InvocationTicket,
    };
    use fcp_kernel::InvokeStatus;
    use tempfile::TempDir;

    use super::*;
    use crate::task_reconcile::{TaskInvocationCompletionSource, TaskInvocationSource};
    use crate::workflow::{
        TaskExecutionTicket, TaskInvocationBinding, TaskStepExecution, WorkflowRequest,
    };

    const OWNER_TOKEN: &str = "task-reconcile-owner-test-secret";

    struct PendingInvocation {
        task_id: String,
        ticket: TaskExecutionTicket,
        step: TaskStepExecution,
        binding: TaskInvocationBinding,
    }

    fn success_receipt(step: &TaskStepExecution) -> Value {
        json!({
            "ordinal": step.ordinal,
            "command": step.command,
            "side_effecting": step.side_effecting,
            "primitive_dispatched": true,
            "status": "executed",
            "exit_code": 0,
            "result": {"status": "ok", "phase": "execution"},
        })
    }

    fn pending_invocation(store: &TaskStore, host: &str) -> PendingInvocation {
        let task = store
            .create(WorkflowRequest {
                intent: "search GitHub issues for auth".to_owned(),
                connector_override: Some("github".to_owned()),
                zone_override: Some("z:work".to_owned()),
            })
            .unwrap();
        assert!(crate::workflow::ready_for_execution(&task));
        let lease = store.lock_task(&task.id).unwrap();
        let ticket = lease.begin_execution("run", "approve").unwrap();
        let steps = lease
            .load()
            .unwrap()
            .unwrap()
            .execution_fence
            .unwrap()
            .journal
            .unwrap()
            .steps;
        let step_count = steps.len();
        for (index, step) in steps.into_iter().enumerate() {
            lease.record_step_started(&ticket, step.ordinal).unwrap();
            if step.command != "invoke" {
                lease
                    .record_step_finished(&ticket, step.ordinal, success_receipt(&step))
                    .unwrap();
                continue;
            }
            assert_eq!(index + 1, step_count, "fixture invocation must be the last step");
            let binding = TaskInvocationBinding {
                request_id: format!("reconcile:{}:{}", ticket.attempt_id(), step.ordinal),
                host: normalize_host_endpoint(host).unwrap(),
                connector_id: "fcp.github:enterprise:v1".to_owned(),
                operation: task.compiled.operation_hint.clone().unwrap(),
                zone_id: "z:work".to_owned(),
                principal: Some("user:owner".to_owned()),
                transport_idempotency: InvocationIdempotency {
                    scope_digest: "a".repeat(64),
                    effect_digest: "b".repeat(64),
                },
            };
            lease
                .record_invocation_binding(&ticket, step.ordinal, binding.clone())
                .unwrap();
            return PendingInvocation {
                task_id: task.id,
                ticket,
                step,
                binding,
            };
        }
        panic!("natural search workflow must contain an invocation");
    }

    fn command_args(temp: &TempDir, pending: &PendingInvocation) -> TaskReconcileArgs {
        let path = temp.path().join("admin-token");
        fs::write(&path, OWNER_TOKEN).unwrap();
        TaskReconcileArgs {
            task_id: pending.task_id.clone(),
            admin_token_file: Some(path),
        }
    }

    fn missing_token_args(temp: &TempDir, pending: &PendingInvocation) -> TaskReconcileArgs {
        TaskReconcileArgs {
            task_id: pending.task_id.clone(),
            admin_token_file: Some(temp.path().join("absent-admin-token")),
        }
    }

    fn local_success(pending: &PendingInvocation, attempt_id: u64) -> InvocationQueryResponse {
        let admitted_at: DateTime<Utc> = "2026-11-21T12:00:00Z".parse().unwrap();
        InvocationQueryResponse {
            invocation: Some(InvocationRecord {
                budget_requests_reserved: false,
                budget_usage_digest: None,
                ticket: InvocationTicket {
                    operation_id: pending.binding.request_id.clone(),
                    attempt_id,
                },
                admission: InvocationAdmission {
                    operation_id: pending.binding.request_id.clone(),
                    connector_id: pending.binding.connector_id.clone(),
                    operation: pending.binding.operation.clone(),
                    zone_id: pending.binding.zone_id.clone(),
                    principal: "user:owner".to_owned(),
                    correlation_id: None,
                    deadline_at: admitted_at + chrono::Duration::seconds(30),
                    idempotency: Some(InvocationIdempotency {
                        scope_digest: "c".repeat(64),
                        effect_digest: "d".repeat(64),
                    }),
                    transport_idempotency: Some(pending.binding.transport_idempotency.clone()),
                },
                admitted_at,
                terminal: Some(InvocationTerminal {
                    outcome: InvocationOutcome::Succeeded,
                    receipt_id: None,
                    duration_ms: 1000,
                    http_status: 200,
                }),
                finished_at: Some(admitted_at + chrono::Duration::seconds(1)),
                finalization: Some(InvocationFinalization {
                    budget_recorded: false,
                    budget_finalized: true,
                    receipt_recorded: false,
                    audit_event_id: Some("audit-finished".to_owned()),
                    sampling_operation_id: None,
                    sampling_completed: None,
                    response_http_status: Some(200),
                    response_status: Some(InvokeStatus::Ok),
                }),
                durable: true,
            }),
            mesh_invocation: None,
            host_job_active: false,
        }
    }

    fn saved_step(store: &TaskStore, pending: &PendingInvocation) -> TaskStepExecution {
        store
            .load(&pending.task_id)
            .unwrap()
            .unwrap()
            .execution_fence
            .unwrap()
            .journal
            .unwrap()
            .steps
            .into_iter()
            .find(|step| step.ordinal == pending.step.ordinal)
            .unwrap()
    }

    fn assert_replay_blocked(store: &TaskStore, pending: &PendingInvocation) {
        assert!(
            store
                .lock_task(&pending.task_id)
                .unwrap()
                .begin_execution("run", "approve")
                .is_err()
        );
    }

    fn bind_history_listener() -> (String, TcpListener) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        (format!("http://{}", listener.local_addr().unwrap()), listener)
    }

    struct HistoryServer {
        stop: mpsc::Sender<()>,
        handle: thread::JoinHandle<()>,
        requests: Arc<Mutex<Vec<InvocationQueryRequest>>>,
    }

    impl HistoryServer {
        fn finish(self) -> Vec<InvocationQueryRequest> {
            let _ = self.stop.send(());
            self.handle.join().unwrap();
            let requests = self.requests.lock().unwrap().clone();
            requests
        }
    }

    fn serve_history<F>(
        listener: TcpListener,
        operation_id: String,
        responses: Vec<InvocationQueryResponse>,
        mut observe: F,
    ) -> HistoryServer
    where
        F: FnMut(&InvocationQueryRequest) + Send + 'static,
    {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&requests);
        let (stop, stopped) = mpsc::channel();
        let handle = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(30);
            let mut served = 0;
            loop {
                assert!(Instant::now() < deadline, "history test server exceeded its deadline");
                if !matches!(stopped.try_recv(), Err(mpsc::TryRecvError::Empty)) {
                    break;
                }
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("history accept failed: {error}"),
                };
                stream.set_nonblocking(false).unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                reader.read_line(&mut request_line).unwrap();
                let mut request_parts = request_line.split_whitespace();
                assert_eq!(request_parts.next(), Some("POST"));
                assert_eq!(
                    request_parts.next(),
                    Some("/rpc/admin/invocations"),
                    "reconciliation may only inspect protected invocation history"
                );
                let mut headers = Vec::new();
                loop {
                    assert!(Instant::now() < deadline, "history headers exceeded deadline");
                    assert!(headers.len() < 64, "too many history request headers");
                    let mut line = String::new();
                    assert!(reader.read_line(&mut line).unwrap() > 0);
                    assert!(line.len() <= 8192, "oversized history request header");
                    if line == "\r\n" {
                        break;
                    }
                    let (name, value) = line.split_once(':').unwrap();
                    headers.push((name.to_ascii_lowercase(), value.trim().to_owned()));
                }
                let header = |name: &str| {
                    let values = headers
                        .iter()
                        .filter(|(key, _)| key == name)
                        .map(|(_, value)| value.as_str())
                        .collect::<Vec<_>>();
                    assert_eq!(values.len(), 1, "expected exactly one {name} header");
                    values[0]
                };
                assert_eq!(header("authorization"), format!("Bearer {OWNER_TOKEN}"));
                assert_eq!(header("x-fcp-zone"), "z:owner");
                let length = header("content-length").parse::<usize>().unwrap();
                assert!(length > 0 && length <= 4096);
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                let request: InvocationQueryRequest = serde_json::from_slice(&body).unwrap();
                assert_eq!(request.operation_id, operation_id);
                let response = responses
                    .get(served)
                    .expect("reconciliation sent an unexpected additional request");
                observe(&request);
                observed.lock().unwrap().push(request);
                let body = serde_json::to_vec(response).unwrap();
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .unwrap();
                stream.write_all(&body).unwrap();
                stream.flush().unwrap();
                served += 1;
            }
            assert_eq!(served, responses.len(), "expected protected history queries");
        });
        HistoryServer { stop, handle, requests }
    }

    #[test]
    fn reconcile_confirms_exact_durable_success_and_repeats_without_network() {
        let temp = TempDir::new().unwrap();
        let store = TaskStore::at_path(temp.path().join("state"));
        let (host, listener) = bind_history_listener();
        let pending = pending_invocation(&store, &host);
        let mut unknown = success_receipt(&pending.step);
        unknown["status"] = json!("failed");
        unknown["exit_code"] = json!(CliExitCode::Transport.as_u8());
        unknown["result"] = json!({
            "request_id": pending.binding.request_id,
            "phase": "execution",
            "status": "error",
            "outcome": "outcome_unknown",
            "error": {"type": "invoke-outcome-unknown"},
        });
        store
            .lock_task(&pending.task_id)
            .unwrap()
            .record_step_finished(&pending.ticket, pending.step.ordinal, unknown.clone())
            .unwrap();
        let server = serve_history(
            listener,
            pending.binding.request_id.clone(),
            vec![local_success(&pending, 7)],
            |_| {},
        );
        let args = command_args(&temp, &pending);
        // Exercise the same normalized destination through a supported host
        // spelling that differs from the value retained before invocation.
        let selected = format!("{}/", host.strip_prefix("http://").unwrap());
        let outcome = reconcile(&store, &args, Some(&selected)).unwrap();
        assert_eq!(outcome.exit_code, CliExitCode::Success, "{}", outcome.payload);
        assert_eq!(outcome.payload["reconciliation"]["complete"], true);
        assert_eq!(outcome.payload["reconciliation"]["host_lookups"], 1);
        assert_eq!(outcome.payload["invoke_attempted"], false);
        assert_eq!(outcome.payload["automatic_retry_allowed"], false);
        assert_eq!(outcome.payload["result_recovered"], false);
        assert!(!outcome.payload.to_string().contains(OWNER_TOKEN));
        let step = saved_step(&store, &pending);
        assert_eq!(step.receipt.as_ref(), Some(&unknown));
        let completion = step.reconciliation.as_ref().unwrap();
        assert_eq!(completion.source, TaskInvocationCompletionSource::LocalFinalized);
        assert_eq!(completion.attempt_id, 7);
        assert_eq!(completion.audit_event_id.as_deref(), Some("audit-finished"));
        assert!(completion.receipt_id.is_none());
        let saved = store.load(&pending.task_id).unwrap().unwrap();
        let history_len = saved.execution_history.len();
        assert_eq!(saved.execution_blocker(), Some(TaskExecutionState::Completed));

        let repeated = reconcile(
            &store,
            &missing_token_args(&temp, &pending),
            Some("invalid://unused-after-completion"),
        )
        .unwrap();
        assert_eq!(repeated.exit_code, CliExitCode::Success);
        assert_eq!(repeated.payload["reconciliation"]["host_lookups"], 0);
        assert_eq!(
            store.load(&pending.task_id).unwrap().unwrap().execution_history.len(),
            history_len
        );
        let requests = server.finish();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].attempt_id, None);
        assert_replay_blocked(&store, &pending);
    }

    #[test]
    fn reconcile_pins_active_attempt_and_rejects_history_rollover() {
        let temp = TempDir::new().unwrap();
        let store = TaskStore::at_path(temp.path().join("state"));
        let (host, listener) = bind_history_listener();
        let pending = pending_invocation(&store, &host);
        let mut active = local_success(&pending, 7);
        let record = active.invocation.as_mut().unwrap();
        record.terminal = None;
        record.finished_at = None;
        record.finalization = None;
        active.host_job_active = true;
        let server = serve_history(
            listener,
            pending.binding.request_id.clone(),
            vec![active, local_success(&pending, 8), local_success(&pending, 7)],
            |_| {},
        );
        let args = command_args(&temp, &pending);
        let active = reconcile(&store, &args, Some(&host)).unwrap();
        assert_ne!(active.exit_code, CliExitCode::Success);
        assert_eq!(
            active.payload["reconciliation"]["observations"][0]["reason"],
            ReconcileFailure::ActiveHostJob.code()
        );
        let step = saved_step(&store, &pending);
        let pinned = step.observed_attempt.unwrap();
        assert_eq!(pinned.source, TaskInvocationSource::Local);
        assert_eq!(pinned.attempt_id, 7);
        assert!(step.reconciliation.is_none());

        let changed = reconcile(&store, &args, Some(&host)).unwrap();
        assert_ne!(changed.exit_code, CliExitCode::Success);
        assert_eq!(changed.payload["reconciliation"]["complete"], false);
        let retained = saved_step(&store, &pending);
        assert_eq!(retained.observed_attempt.as_ref(), Some(&pinned));
        assert!(retained.reconciliation.is_none());
        assert_replay_blocked(&store, &pending);

        let completed = reconcile(&store, &args, Some(&host)).unwrap();
        assert_eq!(completed.exit_code, CliExitCode::Success);
        assert_eq!(completed.payload["reconciliation"]["complete"], true);
        assert_eq!(
            saved_step(&store, &pending).reconciliation.unwrap().attempt(),
            pinned
        );
        let requests = server.finish();
        assert_eq!(
            requests.iter().map(|request| request.attempt_id).collect::<Vec<_>>(),
            vec![None, Some(7), Some(7)],
            "follow-up queries must select the original host generation"
        );
    }

    #[test]
    fn reconcile_missing_and_inconsistent_history_stay_fenced() {
        for missing in [true, false] {
            let temp = TempDir::new().unwrap();
            let store = TaskStore::at_path(temp.path().join("state"));
            let (host, listener) = bind_history_listener();
            let pending = pending_invocation(&store, &host);
            let mut response = local_success(&pending, 7);
            let expected_reason = if missing {
                response.invocation = None;
                ReconcileFailure::MissingEvidence.code()
            } else {
                response.invocation.as_mut().unwrap().finished_at = None;
                ReconcileFailure::InvalidHistory.code()
            };
            let server = serve_history(
                listener,
                pending.binding.request_id.clone(),
                vec![response],
                |_| {},
            );
            let outcome = reconcile(
                &store,
                &command_args(&temp, &pending),
                Some(&host),
            )
            .unwrap();
            assert_ne!(outcome.exit_code, CliExitCode::Success);
            assert_eq!(outcome.payload["reconciliation"]["complete"], false);
            assert_eq!(
                outcome.payload["reconciliation"]["observations"][0]["reason"],
                expected_reason
            );
            let step = saved_step(&store, &pending);
            assert!(step.observed_attempt.is_none());
            assert!(step.reconciliation.is_none());
            assert!(step.receipt.is_none());
            assert_eq!(
                store.load(&pending.task_id).unwrap().unwrap().execution_blocker(),
                Some(TaskExecutionState::NeedsReview)
            );
            assert_eq!(server.finish().len(), 1);
            assert_replay_blocked(&store, &pending);
        }
    }

    #[test]
    fn reconcile_wrong_selected_host_refuses_before_credentials_or_network() {
        let temp = TempDir::new().unwrap();
        let store = TaskStore::at_path(temp.path().join("state"));
        let (selected, listener) = bind_history_listener();
        let pending = pending_invocation(&store, "https://original-host.example");
        let server = serve_history(
            listener,
            pending.binding.request_id.clone(),
            Vec::new(),
            |_| {},
        );
        let outcome = reconcile(
            &store,
            &missing_token_args(&temp, &pending),
            Some(&selected),
        )
        .unwrap();
        assert_eq!(outcome.exit_code, CliExitCode::Validation);
        assert_eq!(outcome.payload["error"]["type"], ReconcileFailure::WrongHost.code());
        assert_eq!(outcome.payload["reconciliation"]["host_lookups"], 0);
        assert!(saved_step(&store, &pending).observed_attempt.is_none());
        assert!(server.finish().is_empty());
        assert_replay_blocked(&store, &pending);
    }

    #[test]
    fn reconcile_finishes_saved_successes_without_credentials_or_host_reads() {
        let temp = TempDir::new().unwrap();
        let store = TaskStore::at_path(temp.path().join("state"));
        let (host, listener) = bind_history_listener();
        let pending = pending_invocation(&store, &host);
        let mut receipt = success_receipt(&pending.step);
        receipt["result"]["request"] = json!({"request_id": pending.binding.request_id});
        receipt["result"]["response"] = json!({
            "id": pending.binding.request_id, "status": "ok", "error": null,
        });
        store
            .lock_task(&pending.task_id)
            .unwrap()
            .record_step_finished(&pending.ticket, pending.step.ordinal, receipt.clone())
            .unwrap();
        let server = serve_history(
            listener,
            pending.binding.request_id.clone(),
            Vec::new(),
            |_| {},
        );
        let outcome = reconcile(
            &store,
            &missing_token_args(&temp, &pending),
            Some("invalid://unused-for-saved-receipts"),
        )
        .unwrap();
        assert_eq!(outcome.exit_code, CliExitCode::Success, "{}", outcome.payload);
        assert_eq!(outcome.payload["reconciliation"]["complete"], true);
        assert_eq!(outcome.payload["reconciliation"]["host_lookups"], 0);
        let saved = store.load(&pending.task_id).unwrap().unwrap();
        assert_eq!(saved.execution_blocker(), Some(TaskExecutionState::Completed));
        assert_eq!(
            saved.last_execution().unwrap().execution["reconciled_steps"],
            json!([])
        );
        let step = saved_step(&store, &pending);
        assert_eq!(step.receipt, Some(receipt));
        assert!(step.observed_attempt.is_none());
        assert!(step.reconciliation.is_none());
        assert!(server.finish().is_empty());
        assert_replay_blocked(&store, &pending);
    }

    #[test]
    fn reconcile_preserves_definitive_failure_without_history_lookup() {
        let temp = TempDir::new().unwrap();
        let store = TaskStore::at_path(temp.path().join("state"));
        let (host, listener) = bind_history_listener();
        let pending = pending_invocation(&store, &host);
        let mut failed = success_receipt(&pending.step);
        failed["status"] = json!("failed");
        failed["exit_code"] = json!(CliExitCode::Connector.as_u8());
        failed["result"] = json!({
            "request": {"request_id": pending.binding.request_id},
            "phase": "execution",
            "status": "error",
            "response": {
                "id": pending.binding.request_id,
                "status": "error",
                "error": {"code": "connector-refused"},
            },
        });
        store
            .lock_task(&pending.task_id)
            .unwrap()
            .record_step_finished(&pending.ticket, pending.step.ordinal, failed.clone())
            .unwrap();
        let server = serve_history(
            listener,
            pending.binding.request_id.clone(),
            Vec::new(),
            |_| {},
        );
        let outcome = reconcile(
            &store,
            &missing_token_args(&temp, &pending),
            Some(&host),
        )
        .unwrap();
        assert_eq!(outcome.exit_code, CliExitCode::Validation);
        assert_eq!(outcome.payload["reconciliation"]["host_lookups"], 0);
        assert_eq!(outcome.payload["reconciliation"]["complete"], false);
        assert_eq!(
            outcome.payload["reconciliation"]["observations"][0]["reason"],
            "task-step-definitive-failure"
        );
        let step = saved_step(&store, &pending);
        assert_eq!(step.receipt, Some(failed));
        assert!(step.observed_attempt.is_none());
        assert!(step.reconciliation.is_none());
        assert!(server.finish().is_empty());
        assert_replay_blocked(&store, &pending);
    }

    #[cfg(unix)]
    #[test]
    fn reconcile_pin_persistence_failure_never_completes_task() {
        let temp = TempDir::new().unwrap();
        let store = TaskStore::at_path(temp.path().join("state"));
        let (host, listener) = bind_history_listener();
        let pending = pending_invocation(&store, &host);
        let tasks_dir = store.root_dir().join("tasks");
        let archive_dir = store.root_dir().join("interrupted-tasks");
        let observed_tasks = tasks_dir.clone();
        let observed_archive = archive_dir.clone();
        let server = serve_history(
            listener,
            pending.binding.request_id.clone(),
            vec![local_success(&pending, 7)],
            move |_| fs::rename(&observed_tasks, &observed_archive).unwrap(),
        );
        let outcome = reconcile(
            &store,
            &command_args(&temp, &pending),
            Some(&host),
        )
        .unwrap();
        assert_eq!(outcome.exit_code, CliExitCode::Internal);
        assert_eq!(
            outcome.payload["error"]["type"],
            "task-reconciliation-not-persisted"
        );
        assert_eq!(outcome.payload["reconciliation"]["complete"], false);
        assert_eq!(outcome.payload["automatic_retry_allowed"], false);
        assert_eq!(server.finish().len(), 1);
        fs::rename(&archive_dir, &tasks_dir).unwrap();
        let saved = store.load(&pending.task_id).unwrap().unwrap();
        let fence = saved.execution_fence.as_ref().unwrap();
        assert_eq!(fence.state, TaskExecutionState::Pending);
        assert_eq!(fence.attempt_id, pending.ticket.attempt_id());
        let step = saved_step(&store, &pending);
        assert!(step.observed_attempt.is_none());
        assert!(step.reconciliation.is_none());
        assert!(step.receipt.is_none());
        assert_replay_blocked(&store, &pending);
    }

    #[test]
    fn reconcile_without_execution_reports_no_fence_or_invented_coverage() {
        let temp = TempDir::new().unwrap();
        let store = TaskStore::at_path(temp.path().join("state"));
        let task = store
            .create(WorkflowRequest {
                intent: "search GitHub issues for auth".to_owned(),
                connector_override: Some("github".to_owned()),
                zone_override: Some("z:work".to_owned()),
            })
            .unwrap();
        let (host, listener) = bind_history_listener();
        let server = serve_history(listener, "never-dispatched".to_owned(), Vec::new(), |_| {});
        let args = TaskReconcileArgs {
            task_id: task.id.clone(),
            admin_token_file: Some(temp.path().join("absent-admin-token")),
        };
        let outcome = reconcile(&store, &args, Some(&host)).unwrap();
        assert_eq!(outcome.exit_code, CliExitCode::Validation);
        assert_eq!(outcome.payload["error"]["type"], "task-reconciliation-unavailable");
        assert_eq!(outcome.payload["reconciliation"]["complete"], false);
        assert_eq!(outcome.payload["reconciliation"]["execution_fenced"], false);
        assert_eq!(outcome.payload["reconciliation"]["journal_available"], false);
        assert_eq!(outcome.payload["reconciliation"]["host_lookups"], 0);
        for field in ["covered_steps", "total_steps", "unresolved_steps"] {
            assert_eq!(outcome.payload["reconciliation"].get(field), Some(&Value::Null));
        }
        assert!(
            outcome.payload["message"]
                .as_str()
                .unwrap()
                .contains("no retained execution attempt")
        );
        assert!(store.load(&task.id).unwrap().unwrap().execution_blocker().is_none());
        assert!(server.finish().is_empty());
    }

    #[test]
    fn reconcile_legacy_completed_record_does_not_invent_step_coverage() {
        let temp = TempDir::new().unwrap();
        let store = TaskStore::at_path(temp.path().join("state"));
        let (host, listener) = bind_history_listener();
        let pending = pending_invocation(&store, &host);
        let mut receipt = success_receipt(&pending.step);
        receipt["result"]["request"] = json!({"request_id": pending.binding.request_id});
        receipt["result"]["response"] = json!({
            "id": pending.binding.request_id, "status": "ok", "error": null,
        });
        let lease = store.lock_task(&pending.task_id).unwrap();
        lease
            .record_step_finished(&pending.ticket, pending.step.ordinal, receipt)
            .unwrap();
        let completed = lease.finish_reconciliation(pending.ticket.attempt_id()).unwrap();
        assert_eq!(completed.execution_blocker(), Some(TaskExecutionState::Completed));
        drop(lease);

        // Preserve the completed fence and aggregate receipt while loading the
        // older on-disk shape that did not contain a per-step journal.
        let path = store
            .root_dir()
            .join("tasks")
            .join(format!("{}.json", pending.task_id.replace(':', "_")));
        let mut legacy: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        legacy["execution_fence"].as_object_mut().unwrap().remove("journal");
        let mut file = fs::File::create(path).unwrap();
        serde_json::to_writer(&mut file, &legacy).unwrap();
        file.sync_all().unwrap();
        drop(file);

        let server = serve_history(
            listener,
            pending.binding.request_id.clone(),
            Vec::new(),
            |_| {},
        );
        let outcome = reconcile(
            &store,
            &missing_token_args(&temp, &pending),
            Some("invalid://unused-for-completed-legacy-record"),
        )
        .unwrap();
        assert_eq!(outcome.exit_code, CliExitCode::Success);
        assert_eq!(outcome.payload["reconciliation"]["complete"], true);
        assert_eq!(outcome.payload["reconciliation"]["execution_fenced"], true);
        assert_eq!(outcome.payload["reconciliation"]["journal_available"], false);
        assert_eq!(outcome.payload["reconciliation"]["host_lookups"], 0);
        for field in ["covered_steps", "total_steps", "unresolved_steps"] {
            assert_eq!(outcome.payload["reconciliation"].get(field), Some(&Value::Null));
        }
        assert!(
            outcome.payload["message"]
                .as_str()
                .unwrap()
                .contains("legacy record has no per-step journal")
        );
        assert_eq!(
            store.load(&pending.task_id).unwrap().unwrap().execution_history.len(),
            completed.execution_history.len()
        );
        assert!(server.finish().is_empty());
        assert_replay_blocked(&store, &pending);
    }
}
