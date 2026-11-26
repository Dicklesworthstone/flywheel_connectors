//! Submit one operator-observed sample to the live rollout controller.
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use clap::Args;
use fcp_host::{DesiredRuntimeState, RolloutEvaluateResponse};
use fcp_kernel::{LifecycleState, RolloutDecision, RolloutPolicy};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::PathBuf;

use super::{
    CliExitCode, CommandAvailability, CommandEnvelope, DispatchOutcome, HostAdminClient,
    HostConnectorRecord, ManagedConnectorConfig, ResolvedHostConfig, attach_install_contract,
    mesh_inventory_credential, read_rollback_target_config, read_rollout_file,
};

#[derive(Args, Debug, Serialize)]
pub(super) struct EvaluateArgs {
    /// Connector id, alias, or family name.
    pub(super) connector: String,
    /// Observed invocation outcome and complete rollout policy as JSON.
    #[arg(long, value_name = "FILE")]
    #[serde(skip_serializing)]
    observation: PathBuf,
    /// Complete pinned deployment to use if the host selects automatic rollback.
    #[arg(long, value_name = "FILE")]
    #[serde(skip_serializing)]
    target_config: Option<PathBuf>,
    /// Read the owner bearer from this file (default FCP_HOST_ADMIN_BEARER_TOKEN).
    #[arg(long, value_name = "FILE")]
    #[serde(skip_serializing)]
    admin_token_file: Option<PathBuf>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    #[serde(skip_serializing)]
    connector_id: Option<String>,
    invocation_succeeded: bool,
    latency_ms: Option<u32>,
    #[serde(default)]
    uptime_secs: u64,
    #[serde(default)]
    crashed: bool,
    observed_at: Option<DateTime<Utc>>,
    policy: RolloutPolicy,
}

#[derive(Serialize)]
struct Request<'a> {
    connector_id: &'a str,
    #[serde(flatten)]
    observation: Observation,
    rollback_target: Option<ManagedConnectorConfig>,
}

fn confirmed_evaluation(
    request: &Request<'_>,
    response: &RolloutEvaluateResponse,
) -> Result<Value> {
    let outcome = &response.outcome;
    let record = &outcome.record;
    let evidence = &outcome.evidence;
    let audit = &outcome.audit_event;
    let policy = &request.observation.policy;
    ensure!(
        record.connector_id.as_str() == request.connector_id
            && audit.connector_id == record.connector_id
            && evidence.connector_id == record.connector_id
            && audit.decision == outcome.decision
            && evidence.decision == outcome.decision
            && audit.state_after == record.state
            && evidence.state_after == record.state
            && audit.state_before == evidence.state_before
            && audit.reason_code == evidence.reason_code
            && audit.observed_at == evidence.observed_at
            && audit.evidence_digest == evidence.digest(),
        "host returned inconsistent rollout evidence"
    );
    ensure!(
        request
            .observation
            .observed_at
            .is_none_or(|time| time == evidence.observed_at)
            && evidence.uptime_secs == request.observation.uptime_secs
            && evidence.auto_rollback == policy.rollback_rules.auto_rollback
            && evidence.promotion_min_samples == policy.success_thresholds.min_samples
            && evidence.promotion_threshold_bps == policy.success_thresholds.min_success_rate_bps
            && evidence.promotion_max_error_bps == policy.success_thresholds.max_error_rate_bps
            && evidence.rollback_min_samples == policy.rollback_rules.min_samples
            && evidence.rollback_max_error_bps == policy.rollback_rules.max_error_rate_bps
            && evidence.rollback_max_consecutive_failures
                == policy.rollback_rules.max_consecutive_failures,
        "host evidence does not match the submitted observation and policy"
    );

    let restoration = match (outcome.decision, &response.runtime_rollback) {
        (RolloutDecision::Hold, None) if audit.state_before == record.state => None,
        (RolloutDecision::Promote, None)
            if audit.state_before == LifecycleState::Canary
                && record.state == LifecycleState::Production =>
        {
            None
        }
        (RolloutDecision::Rollback, Some(restored)) => {
            ensure!(
                policy.rollback_rules.auto_rollback
                    && audit.state_before == LifecycleState::Canary
                    && restored.runtime_restored
                    && restored.connector_id == request.connector_id
                    && record.state == LifecycleState::RolledBack
                    && restored.state == record.state
                    && restored.to_version == record.version
                    && record.previous_version.is_none()
                    && restored.desired_state != DesiredRuntimeState::Unspecified
                    && request
                        .rollback_target
                        .as_ref()
                        .and_then(|target| target.version.as_deref())
                        .and_then(|version| version.parse::<semver::Version>().ok())
                        .as_ref()
                        == Some(&restored.to_version),
                "host did not confirm restoration of the supplied deployment"
            );
            Some(
                json!({"from_version": restored.from_version, "to_version": restored.to_version,
                "runtime_restored": true, "desired_state": restored.desired_state, "registry_version": restored.registry_version}),
            )
        }
        _ => anyhow::bail!("host decision and runtime restoration evidence disagree"),
    };
    // The controller supplies stable reason codes. Free-form diagnostics and
    // unrecognized upstream strings stay out of the CLI result.
    let reason = match audit.reason_code.as_str() {
        code @ ("state_not_canary" | "promotion_thresholds_met" | "promotion_thresholds_not_met"
        | "self_check_failed" | "connector_unavailable" | "crash_loop_detected"
        | "consecutive_failures_exceeded" | "error_rate_exceeded" | "canary_expired"
        | "pinned" | "self_check_degraded" | "connector_degraded" | "self_check_required"
        | "uptime_too_low" | "canary_duration_not_met" | "insufficient_samples") => Some(code),
        _ => None,
    };
    Ok(
        json!({"decision": outcome.decision, "state_before": audit.state_before, "state_after": record.state,
        "version": record.version, "observed_at": evidence.observed_at, "evidence_digest": audit.evidence_digest,
        "reason_code": reason, "samples": evidence.samples, "success_rate_bps": evidence.success_rate_bps, "error_rate_bps": evidence.error_rate_bps,
        "runtime_rollback": restoration}),
    )
}

pub(super) fn dispatch(
    args: &EvaluateArgs,
    connector: &HostConnectorRecord,
    host: &ResolvedHostConfig,
) -> Result<DispatchOutcome> {
    let id = connector.summary.id.as_str();
    let failure = |message: String, submitted: bool| DispatchOutcome {
        payload: json!({"status":"error", "command":"rollout", "subcommand":"evaluate",
            "connector": {"slug": connector.slug, "canonical_id": id},
            "outcome": if submitted {"unconfirmed"} else {"not_submitted"},
            "error":{"message":message, "retryable":false},
            "next_actions":[format!("fwc rollout status {} --host {}", connector.slug, host.endpoint)]}),
        exit_code: if submitted {
            CliExitCode::Transport
        } else {
            CliExitCode::Validation
        },
    };
    let prepared = (|| {
        let raw = read_rollout_file(&args.observation, "--observation")?;
        let observation: Observation = serde_json::from_slice(&raw).map_err(|_| {
            anyhow::anyhow!(
                "--observation requires an invocation result and a complete rollout policy"
            )
        })?;
        ensure!(
            observation
                .connector_id
                .as_deref()
                .is_none_or(|bound| bound == id),
            "observation names a different connector"
        );
        observation
            .policy
            .validate()
            .map_err(|_| anyhow::anyhow!("invalid rollout policy"))?;
        let rollback_target = args
            .target_config
            .as_deref()
            .map(|path| read_rollback_target_config(path, id, None))
            .transpose()?;
        let token = mesh_inventory_credential(args.admin_token_file.as_deref()).map_err(|_| {
            anyhow::anyhow!(
                "supply an owner bearer via --admin-token-file or FCP_HOST_ADMIN_BEARER_TOKEN"
            )
        })?;
        let client =
            HostAdminClient::new_with_transport(&host.endpoint, Some(token.as_str()), true)
                .context("evaluation requires HTTPS, literal loopback HTTP, or a Unix socket")?
                .with_response_limit(1024 * 1024);
        Ok::<_, anyhow::Error>((
            Request {
                connector_id: id,
                observation,
                rollback_target,
            },
            client,
        ))
    })();
    let (request, client) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => return Ok(failure(error.to_string(), false)),
    };
    let confirmed = client
        .post_json_with_timeout("/rpc/rollout/evaluate", &request, client.read_timeout)
        .and_then(|response| confirmed_evaluation(&request, &response));
    let evaluation = match confirmed {
        Ok(value) => value,
        Err(error) => {
            return Ok(failure(
                format!(
                    "Evaluation was not confirmed. Inspect rollout status before submitting another sample. {error}"
                ),
                true,
            ));
        }
    };
    let evidence = json!({"kind":"rollout-evaluation","connector_id":id,
        "decision":evaluation["decision"],"evidence_digest":evaluation["evidence_digest"]});
    let mut payload = json!({"status":"ok","command":"rollout","subcommand":"evaluate","source":"host-admin-api",
        "connector":{"slug":connector.slug,"canonical_id":id}, "evaluation":evaluation,
        "next_actions":[format!("fwc rollout status {} --host {}",connector.slug,host.endpoint)]});
    attach_install_contract(
        &mut payload,
        "rollout",
        "host-admin-api",
        "node-local-root-app",
        "rollout-evaluation",
        Some(&host.endpoint),
        true,
        false,
        false,
        "The selected host recorded the observed health sample and its rollout decision.",
        vec![evidence],
    );
    CommandEnvelope::new(CommandAvailability::LiveRuntime, "rollout").inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    })
}
