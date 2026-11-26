//! Exercise rollout evaluation through CLI parsing, discovery, and HTTP dispatch.
use std::fs;
use std::process::ExitCode;

use fcp_kernel::{LifecycleRecord, RolloutEvidence, RolloutPolicy};
use serde_json::{Value, json};
use tempfile::TempDir;

use super::{
    CliExitCode, execute_json, mock_discovery_response_json, pinned_rollback_response_json,
    pinned_rollback_target_json, spawn_mock_host_sequence_with_body_log,
};

const ID: &str = "fcp.github:enterprise:v1";

fn observation() -> Value {
    json!({"connector_id": ID, "invocation_succeeded": false, "uptime_secs": 480, "latency_ms": 93,
        "observed_at": "2026-11-20T12:00:00Z", "policy": RolloutPolicy::default()})
}

fn reply(decision: &str) -> Value {
    let (state, version) = match decision {
        "hold" => ("canary", "1.2.3"),
        "promote" => ("production", "1.2.3"),
        "rollback" => ("rolled_back", "1.2.2"),
        _ => unreachable!(),
    };
    let mut record = serde_json::to_value(LifecycleRecord::new(
        ID.parse().unwrap(),
        version.parse().unwrap(),
    ))
    .unwrap();
    record["state"] = json!(state);
    let evidence = json!({
        "connector_id": ID, "state_before": "canary", "state_after":state, "decision":decision,
        "reason_code": "insufficient_samples", "message": "private-diagnostic", "pinned":false,
        "crash_loop_detected":false, "failure_streak":1,"self_check_status":"ok","connector_health_status":"healthy",
        "samples":3,"success_rate_bps":6667,"error_rate_bps":3333,"max_latency_ms":93,
        "uptime_secs":480, "promotion_threshold_bps":9500,"promotion_max_error_bps":500,"promotion_min_samples":100,
        "rollback_max_error_bps":2000,"rollback_max_consecutive_failures":5,"rollback_min_samples":10,
        "auto_rollback":true, "observed_at":"2026-11-20T12:00:00Z"
    });
    let digest = serde_json::from_value::<RolloutEvidence>(evidence.clone())
        .unwrap()
        .digest();
    json!({"record":record,"decision":decision,"evidence":evidence,
        "audit_event":{"connector_id":ID,"state_before":"canary","state_after":state,"decision":decision,
            "reason_code":"insufficient_samples","message":"private-diagnostic","observed_at":"2026-11-20T12:00:00Z","evidence_digest":digest},
        "runtime_rollback": (decision == "rollback").then(|| pinned_rollback_response_json("disabled"))})
}

fn run(
    document: &Value,
    target: Option<Value>,
    response: Option<Value>,
) -> (ExitCode, Value, Option<Value>) {
    let directory = TempDir::new().unwrap();
    let observation_file = directory.path().join("observation.json");
    let token_file = directory.path().join("token");
    let target_file = directory.path().join("target.json");
    fs::write(&observation_file, document.to_string()).unwrap();
    fs::write(&token_file, "owner-secret-sentinel").unwrap();
    let mut routes = vec![(
        "POST /rpc/discover".to_owned(),
        mock_discovery_response_json(),
    )];
    if let Some(response) = response {
        routes.push(("POST /rpc/rollout/evaluate".to_owned(), response));
    }
    let (host, server, requests) = spawn_mock_host_sequence_with_body_log(routes);
    let mut args = vec![
        "fwc",
        "--json",
        "--host",
        &host,
        "rollout",
        "evaluate",
        "github",
        "--observation",
        observation_file.to_str().unwrap(),
        "--admin-token-file",
        token_file.to_str().unwrap(),
    ];
    if let Some(target) = target {
        fs::write(&target_file, target.to_string()).unwrap();
        args.extend(["--target-config", target_file.to_str().unwrap()]);
    }
    let (exit, out) = execute_json(&args);
    server.join().unwrap();
    let requests = requests.lock().unwrap();
    let sent = requests
        .get(1)
        .map(|(_, body)| serde_json::from_str(body).unwrap());
    assert!(
        !out.to_string().contains("private-diagnostic")
            && !out.to_string().contains("secret-sentinel")
    );
    (exit, out, sent)
}

#[test]
fn rollout_evaluate_applies_one_sample_and_reports_only_confirmed_decisions() {
    for decision in ["hold", "promote", "rollback"] {
        let target = (decision == "rollback").then(pinned_rollback_target_json);
        let (exit, output, sent) = run(&observation(), target.clone(), Some(reply(decision)));
        assert_eq!(exit, CliExitCode::Success.into(), "{output}");
        assert_eq!(output["evaluation"]["decision"], decision);
        let sent = sent.unwrap();
        assert_eq!(sent["connector_id"], ID);
        assert_eq!(sent["invocation_succeeded"], false);
        assert_eq!(sent["policy"], observation()["policy"]);
        assert!(sent.get("pinned").is_none());
        if let Some(target) = target {
            assert_eq!(sent["rollback_target"]["env"], target["env"]);
            assert_eq!(
                output["evaluation"]["runtime_rollback"]["desired_state"],
                "disabled"
            );
        } else {
            assert!(sent["rollback_target"].is_null());
            assert!(output["evaluation"]["runtime_rollback"].is_null());
        }
    }
}

#[test]
fn rollout_evaluate_refuses_mismatched_inputs_before_post() {
    let mut wrong_connector = observation();
    wrong_connector["connector_id"] = json!("fcp.slack");
    let mut bad_policy = observation();
    bad_policy["policy"]["canary_percent"] = json!(101);
    let mut invalid_target = pinned_rollback_target_json();
    invalid_target["binary_sha256"] = Value::Null;
    for (document, target) in [
        (wrong_connector, None),
        (bad_policy, None),
        (observation(), Some(invalid_target)),
    ] {
        let (exit, output, sent) = run(&document, target, None);
        assert_eq!(exit, CliExitCode::Validation.into(), "{output}");
        assert_eq!(output["outcome"], "not_submitted");
        assert!(sent.is_none());
    }
}

#[test]
fn rollout_evaluate_reports_uncertainty_for_inconsistent_host_replies() {
    let mut old = reply("rollback");
    old["runtime_rollback"] = Value::Null;
    let mut wrong_target = reply("rollback");
    wrong_target["runtime_rollback"]["to_version"] = json!("1.0.0");
    let mut wrong_connector = reply("promote");
    wrong_connector["audit_event"]["connector_id"] = json!("fcp.slack:enterprise:v1");
    let mut wrong_digest = reply("hold");
    wrong_digest["evidence"]["samples"] = json!(12);
    for response in [old, wrong_target, wrong_connector, wrong_digest] {
        let (exit, output, sent) = run(
            &observation(),
            Some(pinned_rollback_target_json()),
            Some(response),
        );
        assert_eq!(exit, CliExitCode::Transport.into(), "{output}");
        assert_eq!(output["outcome"], "unconfirmed");
        assert_eq!(output["error"]["retryable"], false);
        assert!(sent.is_some());
    }
}
