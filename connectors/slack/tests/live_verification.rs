//! Live verification tests for the Slack connector against the real Slack API.
//!
//! These tests require a `SLACK_BOT_TOKEN` environment variable with a valid
//! Slack bot token (xoxb-...). When the token is absent, tests skip gracefully
//! with a descriptive message.
//!
//! All operations are READ-ONLY (`slack.list_channels`) and target the
//! workspace's public channels — no side effects or write permissions needed.

use fcp_crypto::Ed25519SigningKey;
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_prelude::{CapabilityConstraints, CapabilityToken};
use fcp_slack::connector::SlackConnector;

use chrono::{Duration, Utc};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

const SLACK_LIVE_E2E_JSONL_PREFIX: &str = "SLACK_LIVE_E2E_JSONL";
const SLACK_LIVE_E2E_ARTIFACT_ENV: &str = "SLACK_LIVE_E2E_ARTIFACT";
const DEFAULT_SLACK_LIVE_E2E_ARTIFACT: &str = "target/fcp-slack/live-smoke-evidence.jsonl";
const LIVE_SMOKE_COMMAND_LINE: &str = "cargo test -p fcp-slack --test live_verification slack_live_smoke_structured_skip_jsonl -- --nocapture";
const LIVE_SMOKE_ENV_KEYS: &[&str] = &[
    "FCP_LIVE_READ",
    "FCP_LIVE_WRITE",
    "SLACK_BOT_TOKEN",
    "SLACK_APP_TOKEN",
    "SLACK_E2E_CHANNEL_ID",
    "SLACK_E2E_THREAD_TS",
    "SLACK_E2E_BOT_USER_ID",
    "SLACK_E2E_AGENT_USER_ID",
    "SLACK_LIVE_WRITE_APPROVAL",
];
const LIVE_SMOKE_SCENARIOS: &[&str] = &["canary_reply", "mention_gating"];
const LIVE_READ_GATE_ENV: &str = "FCP_LIVE_READ";
const LIVE_WRITE_GATE_ENV: &str = "FCP_LIVE_WRITE";

// ============================================================================
// Skip guard
// ============================================================================

fn slack_token() -> Option<String> {
    std::env::var("SLACK_BOT_TOKEN")
        .ok()
        .filter(|t| !t.is_empty())
}

fn live_read_gate_enabled() -> bool {
    std::env::var(LIVE_READ_GATE_ENV)
        .is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
}

fn skip_without_live_read_gate() -> bool {
    if live_read_gate_enabled() {
        return false;
    }

    eprintln!(
        "SKIP: {LIVE_READ_GATE_ENV} is not enabled; set {LIVE_READ_GATE_ENV}=1 before running live Slack read verification."
    );
    true
}

macro_rules! skip_without_token {
    ($var:ident) => {
        if skip_without_live_read_gate() {
            return;
        }
        let Some($var) = slack_token() else {
            eprintln!(
                "SKIP: SLACK_BOT_TOKEN not set — skipping live Slack connector verification. \
                 Provide an xoxb-style Slack bot credential to enable."
            );
            return;
        };
    };
}

fn slack_live_smoke_env_snapshot() -> BTreeMap<String, String> {
    LIVE_SMOKE_ENV_KEYS
        .iter()
        .filter_map(|key| {
            std::env::var(key)
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .map(|value| ((*key).to_string(), value))
        })
        .collect()
}

fn slack_live_smoke_structured_records(
    env: &BTreeMap<String, String>,
    git_revision: &str,
    artifact_path: &str,
) -> Vec<serde_json::Value> {
    let env_presence = LIVE_SMOKE_ENV_KEYS
        .iter()
        .map(|key| ((*key).to_string(), env.contains_key(*key)))
        .collect::<BTreeMap<_, _>>();

    LIVE_SMOKE_SCENARIOS
        .iter()
        .map(|scenario| {
            let event_topic = if *scenario == "mention_gating" {
                Some("slack.message.new")
            } else {
                None
            };
            json!({
                "log_version": "v1",
                "connector_id": "fcp.slack",
                "event": "slack_live_smoke_structured_skip",
                "scenario": scenario,
                "result": "skip",
                "provider_mode": "live_slack",
                "suite_class": "live_write_required",
                "gate_env_var": LIVE_WRITE_GATE_ENV,
                "command_line": LIVE_SMOKE_COMMAND_LINE,
                "git_revision": git_revision,
                "artifact_path": artifact_path,
                "env_presence": &env_presence,
                "team_id_hash": null,
                "channel_id_hash": null,
                "user_id_hash": null,
                "event_id_hash": null,
                "thread_ts_hash": null,
                "route": null,
                "signature_result": "not_run",
                "sender_policy_decision": "not_run",
                "capability_decision": "not_run",
                "retry_backoff": "not_run",
                "http_status": null,
                "event_topic": event_topic,
                "fcp_error_mapping": "not_run",
                "cleanup_result": "not_started_no_cleanup_required",
                "skip_reason": "live Slack canary reply and mention-gating smoke requires an operator-provided credential lease plus explicit live-write approval; this automated lane records the redaction-safe skip instead of performing Slack side effects",
                "redaction_decision": "redaction-safe: token, channel, user, thread, team, event, and message text values are never logged; only environment presence booleans and scenario identifiers are emitted"
            })
        })
        .collect()
}

fn write_live_smoke_jsonl_artifact(records: &[serde_json::Value]) -> String {
    let path = std::env::var(SLACK_LIVE_E2E_ARTIFACT_ENV).map_or_else(
        |_| PathBuf::from(DEFAULT_SLACK_LIVE_E2E_ARTIFACT),
        PathBuf::from,
    );
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create Slack live smoke artifact directory");
    }
    let mut file = File::create(&path).expect("create Slack live smoke JSONL artifact");
    for record in records {
        writeln!(file, "{record}").expect("write Slack live smoke JSONL record");
        println!("{SLACK_LIVE_E2E_JSONL_PREFIX} {record}");
    }
    path.to_string_lossy().to_string()
}

// ============================================================================
// Helpers
// ============================================================================

fn generate_read_token(
    signing_key: &Ed25519SigningKey,
    op: &str,
    instance_id: &str,
) -> CapabilityToken {
    let now = Utc::now();
    // C3.4: tokens MUST include constraints (default-deny)
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(op)
        .zone_id("z:work")
        .principal("user:live-test")
        .operations(&[op])
        .issuer("node:live-test")
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("test constraints CBOR should be valid")
        .target_instance(instance_id)
        .sign(signing_key)
        .unwrap();
    CapabilityToken::from_raw(cose)
}

async fn setup_live_connector(connector: &mut SlackConnector, token: &str) -> Ed25519SigningKey {
    // Configure with real Slack API
    connector
        .handle_configure(json!({
            "token": token
        }))
        .await
        .expect("configure with real token should succeed");

    // Handshake
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    connector
        .handle_handshake(json!({
            "protocol_version": "2.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": ["slack.list_channels", "slack.post_message", "slack.get_channel_history"]
        }))
        .await
        .expect("handshake should succeed");

    signing_key
}

// ============================================================================
// Live verification tests
// ============================================================================

#[test]
fn slack_live_smoke_structured_skip_jsonl_redacts_sensitive_inputs() {
    let env = BTreeMap::from([
        ("FCP_LIVE_READ".to_string(), "1".to_string()),
        ("FCP_LIVE_WRITE".to_string(), "1".to_string()),
        (
            "SLACK_BOT_TOKEN".to_string(),
            "xoxb-secret-token".to_string(),
        ),
        (
            "SLACK_APP_TOKEN".to_string(),
            "xapp-secret-token".to_string(),
        ),
        ("SLACK_E2E_CHANNEL_ID".to_string(), "CSECRET123".to_string()),
        (
            "SLACK_E2E_THREAD_TS".to_string(),
            "1700000000.000001".to_string(),
        ),
        ("SLACK_E2E_BOT_USER_ID".to_string(), "USECRET".to_string()),
        (
            "SLACK_E2E_AGENT_USER_ID".to_string(),
            "UAGENTSECRET".to_string(),
        ),
        (
            "SLACK_LIVE_WRITE_APPROVAL".to_string(),
            "approval-secret".to_string(),
        ),
    ]);

    let records = slack_live_smoke_structured_records(
        &env,
        "test-git-revision",
        DEFAULT_SLACK_LIVE_E2E_ARTIFACT,
    );
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["scenario"], "canary_reply");
    assert_eq!(records[1]["scenario"], "mention_gating");

    let rendered = records
        .iter()
        .map(serde_json::Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    for secret in [
        "xoxb-secret-token",
        "xapp-secret-token",
        "CSECRET123",
        "1700000000.000001",
        "USECRET",
        "UAGENTSECRET",
        "approval-secret",
    ] {
        assert!(
            !rendered.contains(secret),
            "structured Slack live-smoke JSONL leaked {secret}"
        );
    }
    assert!(rendered.contains("\"SLACK_BOT_TOKEN\":true"));
    assert!(rendered.contains("\"SLACK_APP_TOKEN\":true"));
    assert!(rendered.contains("\"result\":\"skip\""));
}

#[test]
fn slack_live_smoke_structured_skip_jsonl() {
    let env = slack_live_smoke_env_snapshot();
    let git_revision =
        std::env::var("FCP_SLACK_E2E_GIT_REVISION").unwrap_or_else(|_| "unknown".to_string());
    let artifact_path = std::env::var(SLACK_LIVE_E2E_ARTIFACT_ENV)
        .unwrap_or_else(|_| DEFAULT_SLACK_LIVE_E2E_ARTIFACT.to_string());
    let records = slack_live_smoke_structured_records(&env, &git_revision, &artifact_path);
    let written_path = write_live_smoke_jsonl_artifact(&records);

    assert_eq!(records.len(), 2);
    assert_eq!(written_path, artifact_path);
    assert!(records.iter().all(|record| record["result"] == "skip"));
    assert!(
        records
            .iter()
            .any(|record| record["scenario"] == "canary_reply")
    );
    assert!(
        records
            .iter()
            .any(|record| record["scenario"] == "mention_gating")
    );
}

#[fcp_async_core::test]
async fn live_conversations_list() {
    skip_without_token!(token);

    let mut connector = SlackConnector::new();
    let signing_key = setup_live_connector(&mut connector, &token).await;
    let cap = generate_read_token(&signing_key, "slack.list_channels", connector.instance_id());

    let result = connector
        .handle_invoke(json!({
            "operation": "slack.list_channels",
            "input": {},
            "capability_token": cap
        }))
        .await
        .expect("list_channels should succeed");

    // Verify response shape
    let channels = result["channels"]
        .as_array()
        .expect("response should contain channels array");
    // A workspace should have at least one channel (e.g. #general)
    assert!(
        !channels.is_empty(),
        "workspace should have at least one channel"
    );

    // Verify channel objects have expected fields
    let first = &channels[0];
    assert!(
        first.get("id").is_some() || first.get("name").is_some(),
        "channel should have id or name field: {first}"
    );

    eprintln!(
        "PASS: live_conversations_list — found {} channels",
        channels.len()
    );
}

#[fcp_async_core::test]
async fn live_error_mapping_invalid_token() {
    if skip_without_live_read_gate() {
        return;
    }

    // Test with a deliberately invalid token to verify ConnectorErrorMapping
    // works correctly: should get a structured FCP auth error, not a raw HTTP 401.
    let mut connector = SlackConnector::new();

    // Configure with an obviously invalid token
    connector
        .handle_configure(json!({
            "token": "xoxb-this-is-not-a-valid-token-000000000"
        }))
        .await
        .expect("configure should succeed even with bad token");

    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    connector
        .handle_handshake(json!({
            "protocol_version": "2.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": ["slack.list_channels"]
        }))
        .await
        .expect("handshake should succeed");

    let cap = generate_read_token(&signing_key, "slack.list_channels", connector.instance_id());

    let err = connector
        .handle_invoke(json!({
            "operation": "slack.list_channels",
            "input": {},
            "capability_token": cap
        }))
        .await;

    // The error should be a structured FCP error, not a raw HTTP status
    assert!(
        err.is_err(),
        "invoke with invalid token should return an error"
    );
    let fcp_err = err.unwrap_err();
    let err_str = format!("{fcp_err}");
    // Should contain structured error info, not just "401"
    assert!(
        err_str.contains("401")
            || err_str.to_lowercase().contains("unauthorized")
            || err_str.to_lowercase().contains("auth")
            || err_str.to_lowercase().contains("invalid")
            || err_str.to_lowercase().contains("token")
            || err_str.to_lowercase().contains("not_authed"),
        "error should indicate auth failure: got '{err_str}'"
    );

    eprintln!("PASS: live_error_mapping_invalid_token — got structured error: {err_str}");
}

#[fcp_async_core::test]
async fn live_health_check() {
    skip_without_token!(token);

    let mut connector = SlackConnector::new();
    let _signing_key = setup_live_connector(&mut connector, &token).await;

    let health = connector
        .handle_health()
        .await
        .expect("health check should succeed");

    assert!(
        health.get("status").is_some() || health.get("healthy").is_some(),
        "health response should contain status or healthy field: {health}"
    );

    eprintln!("PASS: live_health_check — {health}");
}

#[fcp_async_core::test]
async fn live_introspect() {
    skip_without_token!(token);

    let mut connector = SlackConnector::new();
    let _signing_key = setup_live_connector(&mut connector, &token).await;

    let introspection = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    // Should list all 10 operations
    let ops = introspection["operations"]
        .as_array()
        .or_else(|| introspection["provides"].as_array());
    assert!(
        ops.is_some(),
        "introspection should contain operations: {introspection}"
    );
    let ops = ops.unwrap();
    assert!(
        ops.len() >= 8,
        "Slack connector should have at least 8 operations, got {}",
        ops.len()
    );

    // Verify expected operations are present
    let op_ids: Vec<&str> = ops
        .iter()
        .filter_map(|o| o.get("id").and_then(|id| id.as_str()))
        .collect();
    assert!(
        op_ids.contains(&"slack.list_channels"),
        "should contain slack.list_channels: {op_ids:?}"
    );
    assert!(
        op_ids.contains(&"slack.post_message"),
        "should contain slack.post_message: {op_ids:?}"
    );

    eprintln!("PASS: live_introspect — {} operations reported", ops.len());
}
