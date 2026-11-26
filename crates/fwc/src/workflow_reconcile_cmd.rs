//! Reconcile durable pipeline and recipe checkpoints without replaying effects.
//!
//! Completion comes from the original host's protected invocation history.
//! Metadata-only completion has no recovered output. Explicit output recovery
//! transfers an exact, bounded response from private host custody; resume still
//! needs current authority and cannot fabricate inputs for dependent steps.

use std::path::PathBuf;
use std::time::Instant;

use anyhow::Result;
use clap::Args;
use fcp_host::{InvocationQueryRequest, InvocationResultQueryRequest};
use serde::Serialize;
use serde_json::{Value, json};

use crate::invocation_cmd::{self, LookupFailure};
use crate::pipe::checkpoint::{CheckpointReconciliationOutcome, RunCheckpoint};
use crate::task_reconcile::ReconcileFailure;
use crate::{
    CliExitCode, CommandAvailability, CommandEnvelope, DispatchOutcome, HostAdminClient,
    normalize_host_endpoint, resolve_host_config,
};

#[derive(Args, Debug, Serialize)]
pub(crate) struct WorkflowReconcileArgs {
    /// Durable checkpoint from the interrupted pipeline or recipe run.
    #[arg(value_name = "CHECKPOINT")]
    pub(crate) checkpoint: PathBuf,

    /// Read the original host's admin bearer secret from this file.
    /// Defaults to FCP_HOST_ADMIN_BEARER_TOKEN. Never used for an invocation.
    #[arg(long, value_name = "PATH")]
    #[serde(skip)]
    admin_token_file: Option<PathBuf>,

    /// Recover actual output from opt-in private host custody for completed local
    /// attempts. Writes sensitive result data into this private checkpoint.
    #[arg(long)]
    recover_output: bool,
}

pub(crate) fn dispatch(
    command: &str,
    args: &WorkflowReconcileArgs,
    explicit_host: Option<&str>,
) -> Result<DispatchOutcome> {
    // The exclusive checkpoint lease covers lookup, attempt pinning and the
    // durable completion write, so neither a live run nor another reconciler
    // can replace the evidence while it is being verified.
    let mut checkpoint = match RunCheckpoint::open_for_reconciliation(&args.checkpoint) {
        Ok(checkpoint) => checkpoint,
        Err(_) => {
            return Ok(refusal(
                command,
                None,
                "workflow-checkpoint-unavailable",
                "The checkpoint could not be locked and validated. No history was read and no work was sent.",
                CliExitCode::Validation,
            ));
        }
    };
    if checkpoint.command() != command {
        return Ok(refusal(
            command,
            Some(&checkpoint),
            "workflow-checkpoint-command-mismatch",
            "Use the command family that created this checkpoint: pipeline or recipe.",
            CliExitCode::Validation,
        ));
    }
    let uncertain = match checkpoint.reconciliation_target() {
        Ok(target) => target,
        Err(_) => {
            return Ok(refusal(
                command,
                Some(&checkpoint),
                "workflow-reconciliation-unavailable",
                "The checkpoint does not contain an eligible, consistently bound uncertain invocation. Its original evidence remains retained.",
                CliExitCode::Validation,
            ));
        }
    };
    let recoverable = if args.recover_output {
        match checkpoint.output_recovery_targets() {
            Ok(targets) => targets,
            Err(_) => return Ok(persistence_refusal(command, &checkpoint)),
        }
    } else {
        Vec::new()
    };
    let target = match uncertain.as_ref().or(recoverable.first()) {
        Some(target) => target.clone(),
        None => {
            let outcome = match checkpoint.finish_reconciliation() {
                Ok(true) => report(
                    command,
                    Some(&checkpoint),
                    Vec::new(),
                    0,
                    CliExitCode::Success,
                ),
                Ok(false) if !checkpoint.snapshot().step_results.is_empty() => report(
                    command,
                    Some(&checkpoint),
                    Vec::new(),
                    0,
                    CliExitCode::Success,
                ),
                Ok(false) => refusal(
                    command,
                    Some(&checkpoint),
                    "workflow-reconciliation-unavailable",
                    "This checkpoint has no uncertain invocation or completed prefix to reconcile. Inspect its execution evidence before explicitly resuming.",
                    CliExitCode::Validation,
                ),
                Err(_) => persistence_refusal(command, &checkpoint),
            };
            if args.recover_output
                && outcome.exit_code == CliExitCode::Success
                && has_missing_reconciled_output(&checkpoint)
            {
                return Ok(refusal(
                    command,
                    Some(&checkpoint),
                    "workflow-result-not-local",
                    "The remaining reconciled output has no executor-local custody on this selected host. Its metadata completion remains saved, and the operation was not repeated.",
                    CliExitCode::Validation,
                ));
            }
            return Ok(outcome);
        }
    };

    // Never derive a credential destination from the checkpoint itself.
    // The operator-selected host must match before even opening a token file.
    let selected_host = match resolve_host_config(explicit_host) {
        Ok(Some(host)) => match normalize_host_endpoint(&host.endpoint) {
            Ok(endpoint) => endpoint,
            Err(_) => {
                return Ok(lookup_refusal(
                    command,
                    &checkpoint,
                    LookupFailure::InvalidHost,
                ));
            }
        },
        Ok(None) => {
            return Ok(lookup_refusal(
                command,
                &checkpoint,
                LookupFailure::MissingHost,
            ));
        }
        Err(_) => {
            return Ok(lookup_refusal(
                command,
                &checkpoint,
                LookupFailure::InvalidHost,
            ));
        }
    };
    if target.binding.host != selected_host {
        return Ok(refusal(
            command,
            Some(&checkpoint),
            ReconcileFailure::WrongHost.code(),
            ReconcileFailure::WrongHost.message(),
            CliExitCode::Validation,
        ));
    }
    let mut client = match HostAdminClient::for_invocation_inspection(&selected_host) {
        Ok(client) => client,
        Err(_) => {
            return Ok(lookup_refusal(
                command,
                &checkpoint,
                LookupFailure::InvalidHost,
            ));
        }
    };
    let token = match invocation_cmd::read_admin_token(args.admin_token_file.as_deref()) {
        Ok(token) => token,
        Err(error) => return Ok(lookup_refusal(command, &checkpoint, error)),
    };
    let Some(deadline) = Instant::now().checked_add(client.read_timeout) else {
        return Ok(lookup_refusal(command, &checkpoint, LookupFailure::Timeout));
    };
    let request = InvocationQueryRequest {
        operation_id: target.binding.request_id.clone(),
        attempt_id: target
            .observed_attempt
            .as_ref()
            .map(|attempt| attempt.attempt_id),
    };
    // Completion always comes from metadata first. The separate private-output
    // read below is opt-in and must match this exact verified attempt.
    let response = match invocation_cmd::query_invocation(&client, &request, &token) {
        Ok(response) => response,
        Err(error) => return Ok(lookup_refusal(command, &checkpoint, error)),
    };
    let mut observations = Vec::new();
    let mut lookups = 1;
    if uncertain.is_some() {
        match checkpoint.reconcile_observation(&selected_host, &response) {
            Ok(CheckpointReconciliationOutcome::Confirmed {
                step_id,
                completion,
                run_completed,
            }) => observations.push(json!({
                "step_id": step_id,
                "status": "confirmed",
                "source": "host-admin-api",
                "completion": completion,
                "run_completed": run_completed,
                "output_available": false,
            })),
            Ok(CheckpointReconciliationOutcome::Unresolved { step_id, reason }) => {
                return Ok(report(
                    command,
                    Some(&checkpoint),
                    vec![json!({
                        "step_id": step_id,
                        "status": "unresolved",
                        "source": "host-admin-api",
                        "reason": reason.code(),
                        "message": reason.message(),
                    })],
                    1,
                    CliExitCode::Validation,
                ));
            }
            Err(_) => return Ok(persistence_refusal(command, &checkpoint)),
        }
    }
    let mut exit_code = CliExitCode::Success;
    if args.recover_output {
        let targets = match checkpoint.output_recovery_targets() {
            Ok(targets) => targets,
            Err(_) => return Ok(persistence_refusal(command, &checkpoint)),
        };
        for output_target in targets {
            if output_target.binding.host != selected_host {
                return Ok(refusal(
                    command,
                    Some(&checkpoint),
                    ReconcileFailure::WrongHost.code(),
                    ReconcileFailure::WrongHost.message(),
                    CliExitCode::Validation,
                ));
            }
            let history = if output_target.step_id == target.step_id {
                response.clone()
            } else {
                if let Err(error) = narrow_lookup_deadline(&mut client, deadline) {
                    return Ok(output_lookup_refusal(
                        command,
                        &checkpoint,
                        observations,
                        lookups,
                        error,
                    ));
                }
                lookups += 1;
                match invocation_cmd::query_invocation(
                    &client,
                    &InvocationQueryRequest {
                        operation_id: output_target.binding.request_id.clone(),
                        attempt_id: output_target
                            .observed_attempt
                            .as_ref()
                            .map(|attempt| attempt.attempt_id),
                    },
                    &token,
                ) {
                    Ok(history) => history,
                    Err(error) => {
                        return Ok(output_lookup_refusal(
                            command,
                            &checkpoint,
                            observations,
                            lookups,
                            error,
                        ));
                    }
                }
            };
            let binding = match checkpoint.output_recovery_binding(
                &output_target.step_id,
                &selected_host,
                &history,
            ) {
                Ok(binding) => binding,
                Err(_) => {
                    return Ok(output_lookup_refusal(
                        command,
                        &checkpoint,
                        observations,
                        lookups,
                        LookupFailure::InvalidResponse,
                    ));
                }
            };
            if let Err(error) = narrow_lookup_deadline(&mut client, deadline) {
                return Ok(output_lookup_refusal(
                    command,
                    &checkpoint,
                    observations,
                    lookups,
                    error,
                ));
            }
            lookups += 1;
            let retained = match invocation_cmd::query_invocation_result(
                &client,
                &InvocationResultQueryRequest { binding },
                &token,
            ) {
                Ok(response) => response.result,
                Err(error) => {
                    return Ok(output_lookup_refusal(
                        command,
                        &checkpoint,
                        observations,
                        lookups,
                        error,
                    ));
                }
            };
            let Some(retained) = retained else {
                exit_code = CliExitCode::Validation;
                observations.push(json!({
                    "step_id": output_target.step_id,
                    "status": "output-unavailable",
                    "output_available": false,
                    "reason": "host-result-not-retained",
                    "message": "The host has no retained result for this exact completion. Custody may be disabled, expired or outside its retention limits; the original effect was not repeated.",
                }));
                continue;
            };
            if checkpoint
                .recover_output(&output_target.step_id, &selected_host, &history, &retained)
                .is_err()
            {
                let mut outcome = report(
                    command,
                    Some(&checkpoint),
                    observations,
                    lookups,
                    CliExitCode::Internal,
                );
                outcome.payload["error"] = json!({
                    "type": "workflow-recovered-output-not-persisted",
                    "message": "The verified result could not be saved consistently in the private checkpoint. Reopen and inspect it before continuing; no invocation was sent.",
                    "recoverable": false,
                });
                return Ok(outcome);
            }
            observations.push(json!({
                "step_id": output_target.step_id,
                "status": "output-recovered",
                "source": "host-private-result-api",
                "output_available": true,
                "response_digest": retained.response_digest,
                "attempt_id": retained.binding.ticket.attempt_id,
                "invoked_during_reconciliation": false,
            }));
        }
        if has_missing_reconciled_output(&checkpoint) {
            exit_code = CliExitCode::Validation;
            for record in &checkpoint.snapshot().step_results {
                if record["status"] == "reconciled"
                    && record["output_available"] == false
                    && record["reconciliation"]["source"] == "mesh_origin_observed"
                {
                    observations.push(json!({
                        "step_id": record["id"],
                        "status": "output-unavailable",
                        "output_available": false,
                        "reason": "workflow-result-not-local",
                        "message": "The entry host's mesh completion observation does not contain an executor-local response for recovery.",
                    }));
                }
            }
        }
    }
    Ok(report(
        command,
        Some(&checkpoint),
        observations,
        lookups,
        exit_code,
    ))
}

fn has_missing_reconciled_output(checkpoint: &RunCheckpoint) -> bool {
    checkpoint
        .snapshot()
        .step_results
        .iter()
        .any(|record| record["status"] == "reconciled" && record["output_available"] == false)
}

fn narrow_lookup_deadline(
    client: &mut HostAdminClient,
    deadline: Instant,
) -> std::result::Result<(), LookupFailure> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(LookupFailure::Timeout);
    }
    client.read_timeout = remaining;
    Ok(())
}

fn output_lookup_refusal(
    command: &str,
    checkpoint: &RunCheckpoint,
    observations: Vec<Value>,
    lookups: usize,
    error: LookupFailure,
) -> DispatchOutcome {
    let (kind, message, exit_code) = error.description();
    let mut outcome = report(command, Some(checkpoint), observations, lookups, exit_code);
    outcome.payload["error"] = json!({"type": kind, "message": message, "recoverable": false});
    outcome
}

fn lookup_refusal(
    command: &str,
    checkpoint: &RunCheckpoint,
    error: LookupFailure,
) -> DispatchOutcome {
    let (kind, message, exit) = error.description();
    refusal(command, Some(checkpoint), kind, message, exit)
}

fn persistence_refusal(command: &str, checkpoint: &RunCheckpoint) -> DispatchOutcome {
    refusal(
        command,
        Some(checkpoint),
        "workflow-reconciliation-not-persisted",
        "The reconciliation evidence could not be saved consistently. Reopen and inspect the checkpoint before continuing; no invocation was sent.",
        CliExitCode::Internal,
    )
}

fn refusal(
    command: &str,
    checkpoint: Option<&RunCheckpoint>,
    kind: &'static str,
    message: &'static str,
    exit_code: CliExitCode,
) -> DispatchOutcome {
    let mut outcome = report(command, checkpoint, Vec::new(), 0, exit_code);
    outcome.payload["status"] = json!("unresolved");
    outcome.payload["error"] = json!({
        "type": kind,
        "message": message,
        "recoverable": false,
    });
    outcome
}

fn report(
    command: &str,
    checkpoint: Option<&RunCheckpoint>,
    observations: Vec<Value>,
    lookups: usize,
    exit_code: CliExitCode,
) -> DispatchOutcome {
    let completed = checkpoint.is_some_and(RunCheckpoint::completed);
    let steps = checkpoint.map(|checkpoint| {
        checkpoint
            .snapshot()
            .step_results
            .iter()
            .map(|record| {
                json!({
                    "id": record["id"],
                    "status": record["status"],
                    "output_available": record["status"] == "ok" || record["output_available"] == true,
                })
            })
            .collect::<Vec<_>>()
    });
    let mut payload = json!({
        "command": command,
        "subcommand": "reconcile",
        "status": if completed {
            "completed"
        } else if observations.iter().any(|observation| observation["status"] == "confirmed")
            || checkpoint.is_some_and(|checkpoint| {
                let records = &checkpoint.snapshot().step_results;
                !records.is_empty()
                    && records.iter().all(|record| {
                        matches!(record["status"].as_str(), Some("ok" | "skipped" | "reconciled"))
                    })
            })
        {
            "partial"
        } else {
            "unresolved"
        },
        "invoke_attempted": false,
        "automatic_retry_allowed": false,
        "result_recovered": checkpoint.is_some_and(|checkpoint| checkpoint.snapshot().step_results.iter()
            .any(|record| record["status"] == "reconciled" && record["output_available"] == true)),
        "reconciliation": {
            "complete": completed,
            "host_lookups": lookups,
            "observations": observations,
            "steps": steps,
            "retained_original_records": checkpoint.map(|checkpoint| checkpoint.retained_step_results().len()),
        },
        "caveats": [
            "Completion metadata alone does not recover output. Only an explicitly retrieved, exact-bound local response makes missing result data available; mesh-origin observations do not include executor output.",
            "Missing, failed, active, non-durable or differently bound history never authorizes replay.",
            "Explicit resume keeps the original run identity and deadline and requires current operation contracts, credentials and host preflight.",
        ],
    });
    let mut envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, command);
    envelope.explanation =
        "Durable workflow evidence, with each host-history completion scoped to the original request and pinned attempt."
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
    use std::thread;
    use std::time::{Duration, Instant};

    use chrono::{DateTime, Utc};
    use fcp_host::{
        InvocationAdmission, InvocationFinalization, InvocationIdempotency, InvocationOutcome,
        InvocationQueryResponse, InvocationRecord, InvocationTerminal, InvocationTicket,
    };
    use fcp_kernel::InvokeStatus;
    use tempfile::TempDir;

    use super::*;
    use crate::pipe::checkpoint::{PendingInvocation, RunBinding};
    use crate::task_reconcile::TaskInvocationBinding;

    const OWNER_TOKEN: &str = "workflow-reconcile-owner-test-secret";

    fn pending_checkpoint(
        directory: &TempDir,
        host: &str,
        two_steps: bool,
    ) -> (WorkflowReconcileArgs, TaskInvocationBinding) {
        let path = directory.path().join("run.json");
        let host = normalize_host_endpoint(host).unwrap();
        let steps = if two_steps {
            vec!["send".to_owned(), "next".to_owned()]
        } else {
            vec!["send".to_owned()]
        };
        let binding = TaskInvocationBinding {
            request_id: "workflow-recovery-request".to_owned(),
            host: host.clone(),
            connector_id: "fcp.github:enterprise:v1".to_owned(),
            operation: "create_issue".to_owned(),
            zone_id: "z:work".to_owned(),
            principal: Some("user:owner".to_owned()),
            transport_idempotency: InvocationIdempotency {
                scope_digest: "a".repeat(64),
                effect_digest: "b".repeat(64),
            },
        };
        let scope = RunBinding::new(
            "pipeline",
            &json!({"steps": steps}),
            &host,
            "z:work",
            &steps,
        )
        .unwrap();
        let mut checkpoint =
            RunCheckpoint::create(&path, scope, "original-run".to_owned(), None).unwrap();
        checkpoint
            .mark_pending_bound(
                PendingInvocation {
                    step_id: "send".to_owned(),
                    request_id: binding.request_id.clone(),
                    idempotency_key: Some("original-run:send".to_owned()),
                    attempt: 1,
                },
                binding.clone(),
                None,
            )
            .unwrap();
        let token_path = directory.path().join("admin-token");
        fs::write(&token_path, OWNER_TOKEN).unwrap();
        (
            WorkflowReconcileArgs {
                checkpoint: path,
                admin_token_file: Some(token_path),
                recover_output: false,
            },
            binding,
        )
    }

    fn local_success(binding: &TaskInvocationBinding) -> InvocationQueryResponse {
        let admitted_at: DateTime<Utc> = Utc::now() - chrono::Duration::seconds(2);
        InvocationQueryResponse {
            invocation: Some(InvocationRecord {
                budget_requests_reserved: false,
                budget_usage_digest: None,
                capability_response: None,
                ticket: InvocationTicket {
                    operation_id: binding.request_id.clone(),
                    attempt_id: 7,
                },
                admission: InvocationAdmission {
                    operation_id: binding.request_id.clone(),
                    connector_id: binding.connector_id.clone(),
                    operation: binding.operation.clone(),
                    zone_id: binding.zone_id.clone(),
                    principal: "user:owner".to_owned(),
                    correlation_id: None,
                    deadline_at: admitted_at + chrono::Duration::seconds(30),
                    idempotency: Some(InvocationIdempotency {
                        scope_digest: "c".repeat(64),
                        effect_digest: "d".repeat(64),
                    }),
                    transport_idempotency: Some(binding.transport_idempotency.clone()),
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
                    audit_event_id: Some("audit-workflow-finished".to_owned()),
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

    fn listener() -> (String, TcpListener) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        (
            format!("http://{}", listener.local_addr().unwrap()),
            listener,
        )
    }

    fn serve_once(
        listener: TcpListener,
        response: InvocationQueryResponse,
    ) -> thread::JoinHandle<InvocationQueryRequest> {
        thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "history lookup never arrived");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("history accept failed: {error}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            assert_eq!(
                request_line.trim_end(),
                "POST /rpc/admin/invocations HTTP/1.1",
                "reconciliation must never send an invocation"
            );
            let mut content_length = None;
            let mut authorized = false;
            for _ in 0..64 {
                let mut header = String::new();
                assert!(reader.read_line(&mut header).unwrap() > 0);
                assert!(header.len() < 8192);
                if header == "\r\n" {
                    break;
                }
                let (name, value) = header.split_once(':').unwrap();
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = Some(value.trim().parse::<usize>().unwrap());
                }
                if name.eq_ignore_ascii_case("authorization") {
                    assert_eq!(value.trim(), format!("Bearer {OWNER_TOKEN}"));
                    authorized = true;
                }
            }
            assert!(authorized, "history reads require the owner credential");
            let length = content_length.unwrap();
            assert!(length <= 4096);
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            let request: InvocationQueryRequest = serde_json::from_slice(&body).unwrap();
            let bytes = serde_json::to_vec(&response).unwrap();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                bytes.len()
            )
            .unwrap();
            stream.write_all(&bytes).unwrap();
            request
        })
    }

    fn serve_recovery_reads(
        listener: TcpListener,
        history: InvocationQueryResponse,
        result: fcp_host::InvocationResultQueryResponse,
    ) -> thread::JoinHandle<Vec<Value>> {
        thread::spawn(move || {
            let mut requests = Vec::new();
            for (path, body) in [
                (
                    "/rpc/admin/invocations",
                    serde_json::to_vec(&history).unwrap(),
                ),
                (
                    "/rpc/admin/invocations/result",
                    serde_json::to_vec(&result).unwrap(),
                ),
            ] {
                let deadline = Instant::now() + Duration::from_secs(10);
                let (mut stream, _) = loop {
                    match listener.accept() {
                        Ok(connection) => break connection,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "recovery lookup never arrived");
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("recovery accept failed: {error}"),
                    }
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                reader.read_line(&mut request_line).unwrap();
                assert_eq!(
                    request_line.trim_end(),
                    format!("POST {path} HTTP/1.1"),
                    "recovery cannot invoke or change hosts"
                );
                let mut content_length = None;
                let mut authorized = false;
                let mut owner_zone = false;
                for _ in 0..64 {
                    let mut header = String::new();
                    assert!(reader.read_line(&mut header).unwrap() > 0);
                    assert!(header.len() < 8192);
                    if header == "\r\n" {
                        break;
                    }
                    let (name, value) = header.split_once(':').unwrap();
                    match name.to_ascii_lowercase().as_str() {
                        "content-length" => {
                            content_length = Some(value.trim().parse::<usize>().unwrap())
                        }
                        "authorization" => {
                            assert_eq!(value.trim(), format!("Bearer {OWNER_TOKEN}"));
                            authorized = true;
                        }
                        "x-fcp-zone" => {
                            assert_eq!(value.trim(), "z:owner");
                            owner_zone = true;
                        }
                        _ => {}
                    }
                }
                assert!(
                    authorized && owner_zone,
                    "both private reads require owner authorization"
                );
                let length = content_length.unwrap();
                assert!(length < 16 * 1024);
                let mut request = vec![0; length];
                reader.read_exact(&mut request).unwrap();
                requests.push(serde_json::from_slice(&request).unwrap());
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
                stream.write_all(&body).unwrap();
            }
            requests
        })
    }

    #[cfg(unix)]
    fn retained_result(
        directory: &TempDir,
        history: &InvocationQueryResponse,
    ) -> fcp_host::RetainedInvocationResult {
        let store = fcp_host::InvocationResultStore::open(directory.path().join("private-custody"))
            .unwrap();
        let record = history.invocation.as_ref().unwrap();
        let response = fcp_kernel::InvokeResponse::ok(
            fcp_kernel::RequestId(record.ticket.operation_id.clone()),
            json!({"created_id": "created-exactly-once", "private": "recovery-output-secret"}),
        );
        assert!(store.retain(record, &response, Utc::now()).unwrap());
        let binding = fcp_host::InvocationResultBinding::from_record(record).unwrap();
        store.get(&binding, Utc::now()).unwrap().unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn explicit_output_recovery_transfers_real_custody_without_replaying_or_printing_secrets() {
        for previously_confirmed in [false, true] {
            let directory = TempDir::new().unwrap();
            let (host, listener) = listener();
            let (mut args, binding) = pending_checkpoint(&directory, &host, true);
            args.recover_output = true;
            let history = local_success(&binding);
            let retained = retained_result(&directory, &history);
            if previously_confirmed {
                let mut checkpoint =
                    RunCheckpoint::open_for_reconciliation(&args.checkpoint).unwrap();
                checkpoint.reconcile_observation(&host, &history).unwrap();
            }
            let server = serve_recovery_reads(
                listener,
                history,
                fcp_host::InvocationResultQueryResponse {
                    result: Some(retained.clone()),
                },
            );
            let outcome = dispatch("pipeline", &args, Some(&host)).unwrap();
            let requests = server.join().unwrap();
            assert_eq!(requests.len(), 2);
            assert_eq!(requests[0]["operation_id"], binding.request_id);
            assert_eq!(
                requests[0]["attempt_id"],
                if previously_confirmed {
                    json!(7)
                } else {
                    Value::Null
                }
            );
            assert_eq!(
                requests[1]["binding"],
                serde_json::to_value(&retained.binding).unwrap()
            );
            assert_eq!(
                outcome.exit_code,
                CliExitCode::Success,
                "{}",
                outcome.payload
            );
            assert_eq!(outcome.payload["invoke_attempted"], false);
            assert_eq!(outcome.payload["result_recovered"], true);
            assert_eq!(outcome.payload["reconciliation"]["host_lookups"], 2);
            assert!(
                !outcome
                    .payload
                    .to_string()
                    .contains("recovery-output-secret")
            );
            assert!(!outcome.payload.to_string().contains(OWNER_TOKEN));
            let checkpoint = RunCheckpoint::open_for_reconciliation(&args.checkpoint).unwrap();
            assert_eq!(
                checkpoint.snapshot().outputs["send"],
                retained.response.result.clone().unwrap()
            );
            assert_eq!(
                checkpoint.snapshot().step_results[0]["status"],
                "reconciled"
            );
            assert_eq!(
                checkpoint.snapshot().step_results[0]["output_available"],
                true
            );
            assert!(!checkpoint.completed());
            drop(checkpoint);
            args.admin_token_file = Some(directory.path().join("missing-token"));
            let repeated = dispatch("pipeline", &args, None).unwrap();
            assert_eq!(repeated.exit_code, CliExitCode::Success);
            assert_eq!(repeated.payload["reconciliation"]["host_lookups"], 0);
            assert_eq!(repeated.payload["result_recovered"], true);
        }
    }

    #[cfg(unix)]
    #[test]
    fn unavailable_or_invalid_output_preserves_confirmed_metadata_without_fabricating_results() {
        for mode in ["missing", "wrong-zone", "corrupt-response", "expired"] {
            let directory = TempDir::new().unwrap();
            let (host, listener) = listener();
            let (mut args, binding) = pending_checkpoint(&directory, &host, true);
            args.recover_output = true;
            let history = local_success(&binding);
            let mut retained = retained_result(&directory, &history);
            match mode {
                "wrong-zone" => retained.binding.zone_id = "z:private".into(),
                "corrupt-response" => {
                    retained.response.result = Some(json!({"created_id": "guessed"}))
                }
                "expired" => retained.expires_at = Utc::now() - chrono::Duration::seconds(1),
                _ => {}
            }
            let server = serve_recovery_reads(
                listener,
                history,
                fcp_host::InvocationResultQueryResponse {
                    result: (mode != "missing").then_some(retained),
                },
            );
            let outcome = dispatch("pipeline", &args, Some(&host)).unwrap();
            assert_eq!(server.join().unwrap().len(), 2);
            assert_ne!(outcome.exit_code, CliExitCode::Success, "{mode}");
            assert_eq!(outcome.payload["result_recovered"], false);
            assert_eq!(outcome.payload["invoke_attempted"], false);
            let checkpoint = RunCheckpoint::open_for_reconciliation(&args.checkpoint).unwrap();
            assert_eq!(
                checkpoint.snapshot().step_results[0]["status"],
                "reconciled"
            );
            assert_eq!(
                checkpoint.snapshot().step_results[0]["output_available"],
                false
            );
            assert!(checkpoint.snapshot().outputs.is_empty());
        }
    }

    #[test]
    fn confirms_once_without_recovering_payload_or_replaying_work() {
        let directory = TempDir::new().unwrap();
        let (host, listener) = listener();
        let (mut args, binding) = pending_checkpoint(&directory, &host, false);
        let server = serve_once(listener, local_success(&binding));

        let outcome = dispatch("pipeline", &args, Some(&host)).unwrap();
        let request = server.join().unwrap();
        assert_eq!(request.operation_id, binding.request_id);
        assert_eq!(request.attempt_id, None);
        assert_eq!(outcome.exit_code, CliExitCode::Success);
        assert_eq!(outcome.payload["status"], "completed");
        assert_eq!(outcome.payload["invoke_attempted"], false);
        assert_eq!(outcome.payload["result_recovered"], false);
        assert_eq!(outcome.payload["reconciliation"]["host_lookups"], 1);
        assert_eq!(
            outcome.payload["reconciliation"]["steps"][0]["output_available"],
            false
        );
        assert!(!outcome.payload.to_string().contains(OWNER_TOKEN));
        assert!(
            !fs::read_to_string(&args.checkpoint)
                .unwrap()
                .contains(OWNER_TOKEN)
        );

        // Saved completion must be idempotent and require no host or credential.
        args.admin_token_file = Some(directory.path().join("missing-token"));
        let repeated = dispatch("pipeline", &args, None).unwrap();
        assert_eq!(repeated.exit_code, CliExitCode::Success);
        assert_eq!(repeated.payload["reconciliation"]["host_lookups"], 0);
    }

    #[test]
    fn partial_reconciliation_does_not_invent_downstream_completion() {
        let directory = TempDir::new().unwrap();
        let (host, listener) = listener();
        let (mut args, binding) = pending_checkpoint(&directory, &host, true);
        let server = serve_once(listener, local_success(&binding));

        let outcome = dispatch("pipeline", &args, Some(&host)).unwrap();
        server.join().unwrap();
        assert_eq!(outcome.exit_code, CliExitCode::Success);
        assert_eq!(outcome.payload["status"], "partial");
        assert_eq!(outcome.payload["reconciliation"]["complete"], false);
        assert_eq!(
            outcome.payload["reconciliation"]["steps"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let checkpoint = RunCheckpoint::open_for_reconciliation(&args.checkpoint).unwrap();
        assert!(checkpoint.snapshot().outputs.is_empty());
        assert!(!checkpoint.completed());
        drop(checkpoint);

        args.admin_token_file = Some(directory.path().join("missing-token"));
        let repeated = dispatch("pipeline", &args, None).unwrap();
        assert_eq!(repeated.exit_code, CliExitCode::Success);
        assert_eq!(repeated.payload["status"], "partial");
        assert_eq!(repeated.payload["reconciliation"]["host_lookups"], 0);
    }

    #[test]
    fn wrong_host_and_wrong_command_refuse_before_reading_credentials() {
        let directory = TempDir::new().unwrap();
        let (mut args, _) = pending_checkpoint(&directory, "http://127.0.0.1:1", false);
        args.admin_token_file = Some(directory.path().join("missing-token"));
        let before = fs::read(&args.checkpoint).unwrap();

        let wrong_host = dispatch("pipeline", &args, Some("http://127.0.0.1:2")).unwrap();
        assert_eq!(
            wrong_host.payload["error"]["type"],
            ReconcileFailure::WrongHost.code()
        );
        let wrong_command = dispatch("recipe", &args, Some("http://127.0.0.1:1")).unwrap();
        assert_eq!(
            wrong_command.payload["error"]["type"],
            "workflow-checkpoint-command-mismatch"
        );
        assert_eq!(fs::read(&args.checkpoint).unwrap(), before);
    }

    #[test]
    fn active_host_job_stays_fenced_and_pins_observed_attempt() {
        let directory = TempDir::new().unwrap();
        let (host, listener) = listener();
        let (args, binding) = pending_checkpoint(&directory, &host, false);
        let mut response = local_success(&binding);
        response.host_job_active = true;
        let server = serve_once(listener, response);

        let outcome = dispatch("pipeline", &args, Some(&host)).unwrap();
        server.join().unwrap();
        assert_eq!(outcome.exit_code, CliExitCode::Validation);
        assert_eq!(outcome.payload["status"], "unresolved");
        assert_eq!(
            outcome.payload["reconciliation"]["observations"][0]["reason"],
            ReconcileFailure::ActiveHostJob.code()
        );
        let checkpoint = RunCheckpoint::open_for_reconciliation(&args.checkpoint).unwrap();
        assert!(!checkpoint.completed());
        assert_eq!(
            checkpoint
                .reconciliation_target()
                .unwrap()
                .unwrap()
                .observed_attempt
                .unwrap()
                .attempt_id,
            7
        );
    }

    #[test]
    fn concurrent_checkpoint_owner_blocks_all_network_access() {
        let directory = TempDir::new().unwrap();
        let (mut args, _) = pending_checkpoint(&directory, "http://127.0.0.1:1", false);
        args.admin_token_file = Some(directory.path().join("missing-token"));
        let _owner = RunCheckpoint::open_for_reconciliation(&args.checkpoint).unwrap();
        let outcome = dispatch("pipeline", &args, Some("http://127.0.0.1:1")).unwrap();
        assert_eq!(outcome.exit_code, CliExitCode::Validation);
        assert_eq!(
            outcome.payload["error"]["type"],
            "workflow-checkpoint-unavailable"
        );
        assert_eq!(outcome.payload["reconciliation"]["host_lookups"], 0);
    }
}
