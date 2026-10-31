#![cfg(all(feature = "slack", feature = "discord"))]
#![allow(clippy::too_many_lines)]

use std::fmt::Write as _;
use std::process::Command;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{Duration, Utc};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_discord::DiscordConnector;
use fcp_e2e::{
    AssertionsSummary, E2eLogEntry, E2eLogger, scan_log_jsonl, validate_log_entry_value,
};
use fcp_prelude::{CapabilityConstraints, ConnectorId, FcpError, ZoneId};
use fcp_sdk::{
    AgentId, ChannelId, ChatCoordinationBackend, ChatCoordinationConfig,
    ChatCoordinationSendRequest, ClaimKey, ClaimOutcome, DmMode, InMemoryThreadOwnershipChecker,
    ThreadId, ThreadOwnershipChecker,
};
use fcp_slack::connector::SlackConnector;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_NAME: &str = "chat_thread_ownership_cross_connector_e2e";
const SCENARIO_ID: &str = "chat-thread-ownership-cross-connector";
const ARTIFACT_PATH: &str = "target/fcp-chat-thread-ownership/chat-thread-ownership-e2e.jsonl";
const INTENT_GUILDS: u64 = 1 << 0;
const INTENT_GUILD_MESSAGES: u64 = 1 << 9;
const INTENT_DIRECT_MESSAGES: u64 = 1 << 12;
const INTENT_MESSAGE_CONTENT: u64 = 1 << 15;
const ALL_REQUIRED_INTENTS: u64 =
    INTENT_GUILDS | INTENT_GUILD_MESSAGES | INTENT_DIRECT_MESSAGES | INTENT_MESSAGE_CONTENT;
const TEST_SLACK_BOT_CREDENTIAL_ID: &str = "550e8400-e29b-41d4-a716-446655440000";

struct BoundSigningKey {
    signing_key: Ed25519SigningKey,
    instance_id: String,
}

struct IndeterminateThreadOwnershipChecker {
    reason: &'static str,
}

#[async_trait::async_trait]
impl ThreadOwnershipChecker for IndeterminateThreadOwnershipChecker {
    async fn claim(
        &self,
        _cx: &fcp_async_core::Cx,
        _key: ClaimKey,
        _agent_id: AgentId,
    ) -> ClaimOutcome {
        ClaimOutcome::Indeterminate(self.reason.to_string())
    }
}

#[fcp_async_core::runtime::test]
async fn slack_and_discord_chat_coordination_emit_redacted_cross_connector_evidence() {
    let mut logger = E2eLogger::new();
    let git_revision = git_revision();
    let command_line = replay_command_line();

    let checker = Arc::new(InMemoryThreadOwnershipChecker::new());

    run_slack_duplicate_claim_fixture(
        Arc::clone(&checker),
        &mut logger,
        &git_revision,
        &command_line,
    )
    .await;
    run_discord_duplicate_claim_fixture(
        Arc::clone(&checker),
        &mut logger,
        &git_revision,
        &command_line,
    )
    .await;
    run_connector_namespace_isolation_fixture(&mut logger, &git_revision, &command_line);
    run_fail_open_degraded_fixture(&mut logger, &git_revision, &command_line).await;

    let jsonl = logger.to_json_lines();
    assert!(
        !jsonl.trim().is_empty(),
        "e2e JSONL evidence must not be empty"
    );
    for line in jsonl.lines() {
        let value: Value = serde_json::from_str(line).expect("e2e JSONL line should parse");
        validate_log_entry_value(&value).expect("e2e JSONL line should satisfy shared schema");
    }

    let scan = scan_log_jsonl(&jsonl);
    assert!(
        scan.findings.is_empty(),
        "redaction scanner found leaked evidence fields: {:?}",
        scan.findings
    );

    logger
        .write_json_lines(ARTIFACT_PATH)
        .expect("chat-thread ownership JSONL artifact should write");
    let persisted_jsonl =
        std::fs::read_to_string(ARTIFACT_PATH).expect("chat-thread ownership artifact should read");
    assert_eq!(persisted_jsonl.trim_end(), jsonl.as_str());

    for forbidden in [
        "xoxb-test-token-xyz",
        "test_token",
        "C01234567",
        "1234567890.123456",
        "111",
        "222",
        "agent:slack-a",
        "agent:slack-b",
        "agent:discord-a",
        "agent:discord-b",
        "agent A reply",
        "agent B reply",
        "degraded reply",
    ] {
        assert!(
            !jsonl.contains(forbidden),
            "redaction-safe JSONL must not contain raw fixture value {forbidden:?}"
        );
    }
}

async fn run_slack_duplicate_claim_fixture(
    checker: Arc<InMemoryThreadOwnershipChecker>,
    logger: &mut E2eLogger,
    git_revision: &str,
    command_line: &[String],
) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .and(body_json(json!({
            "channel": "C01234567",
            "text": "agent A reply",
            "thread_ts": "1234567890.123456"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "channel": "C01234567",
            "ts": "1234567890.654321",
            "message": {
                "type": "message",
                "user": "U01234567",
                "text": "agent A reply",
                "ts": "1234567890.654321",
                "thread_ts": "1234567890.123456"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut first = SlackConnector::new()
        .with_thread_ownership_checker(checker.clone(), ChatCoordinationBackend::InMemory);
    let mut second = SlackConnector::new()
        .with_thread_ownership_checker(checker, ChatCoordinationBackend::InMemory);
    configure_slack(&mut first, &server.uri()).await;
    configure_slack(&mut second, &server.uri()).await;
    let first_key = handshake_slack(&mut first, &["slack.write"]).await;
    let second_key = handshake_slack(&mut second, &["slack.write"]).await;

    let first_result = first
        .handle_invoke(json!({
            "operation": "slack.reply_thread",
            "input": {
                "channel": "C01234567",
                "text": "agent A reply",
                "thread_ts": "1234567890.123456"
            },
            "capability_token": build_capability_token(
                &first_key.signing_key,
                &first_key.instance_id,
                "slack.write",
                "slack.reply_thread",
                "agent:slack-a"
            )
        }))
        .await
        .expect("first Slack claimant should send");
    assert_eq!(first_result["coordination"][0]["event"], "claim_attempt");
    assert_eq!(first_result["coordination"][2]["event"], "send_executed");

    push_evidence(
        logger,
        1,
        "execute",
        json!({
            "git_revision": git_revision,
            "command_line": command_line,
            "connector_fixture_id": "slack-loopback",
            "event_topic": "slack.reply_thread",
            "conversation_thread_id_hash": evidence_hash("slack:C01234567:1234567890.123456"),
            "claimant_id_hash": evidence_hash("agent:slack-a"),
            "claim_state": "granted",
            "conflict_decision": "send_executed",
            "fcp_error_mapping": null,
            "cleanup_result": "pending",
            "skip_reason": null
        }),
    );

    let second_error = second
        .handle_invoke(json!({
            "operation": "slack.reply_thread",
            "input": {
                "channel": "C01234567",
                "text": "agent B reply",
                "thread_ts": "1234567890.123456"
            },
            "capability_token": build_capability_token(
                &second_key.signing_key,
                &second_key.instance_id,
                "slack.write",
                "slack.reply_thread",
                "agent:slack-b"
            )
        }))
        .await
        .expect_err("second Slack claimant should be denied before HTTP");
    assert_thread_owned_by_peer(&second_error, "agent:slack-a");

    push_evidence(
        logger,
        2,
        "verify",
        json!({
            "git_revision": git_revision,
            "command_line": command_line,
            "connector_fixture_id": "slack-loopback",
            "event_topic": "slack.reply_thread",
            "conversation_thread_id_hash": evidence_hash("slack:C01234567:1234567890.123456"),
            "claimant_id_hash": evidence_hash("agent:slack-b"),
            "claim_state": "already_owned",
            "conflict_decision": "send_denied",
            "fcp_error_mapping": {
                "kind": "Unauthorized",
                "code": 4090,
                "message_kind": "thread_owned_by_peer",
                "owner_agent_id_hash": evidence_hash("agent:slack-a")
            },
            "cleanup_result": "pending",
            "skip_reason": null
        }),
    );

    let requests = server.received_requests().await.unwrap_or_default();
    assert_eq!(
        requests.len(),
        1,
        "denied Slack claimant must not reach the Slack HTTP fixture"
    );
    assert!(first.handle_shutdown(json!({})).await.is_ok());
    assert!(second.handle_shutdown(json!({})).await.is_ok());
    push_evidence(
        logger,
        3,
        "teardown",
        json!({
            "git_revision": git_revision,
            "command_line": command_line,
            "connector_fixture_id": "slack-loopback",
            "event_topic": "slack.reply_thread",
            "conversation_thread_id_hash": evidence_hash("slack:C01234567:1234567890.123456"),
            "claimant_id_hash": null,
            "claim_state": "shutdown",
            "conflict_decision": "cleanup_complete",
            "fcp_error_mapping": null,
            "cleanup_result": "shutdown_ok",
            "skip_reason": null
        }),
    );
}

async fn run_discord_duplicate_claim_fixture(
    checker: Arc<InMemoryThreadOwnershipChecker>,
    logger: &mut E2eLogger,
    git_revision: &str,
    command_line: &[String],
) {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/users/@me"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "123456789",
            "username": "TestBot",
            "discriminator": "0",
            "bot": true
        })))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/channels/111/messages"))
        .and(body_json(json!({
            "content": "agent A reply",
            "message_reference": {
                "message_id": "222",
                "fail_if_not_exists": false
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "100000000000000031",
            "channel_id": "111",
            "content": "agent A reply",
            "timestamp": "2026-03-02T12:00:00.000000+00:00",
            "author": {
                "id": "123456789",
                "username": "TestBot",
                "discriminator": "0"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut first = DiscordConnector::new()
        .with_thread_ownership_checker(checker.clone(), ChatCoordinationBackend::InMemory);
    let mut second = DiscordConnector::new()
        .with_thread_ownership_checker(checker, ChatCoordinationBackend::InMemory);
    configure_discord(&mut first, &server.uri()).await;
    configure_discord(&mut second, &server.uri()).await;
    let first_key = handshake_discord(&mut first, &["discord.send"]).await;
    let second_key = handshake_discord(&mut second, &["discord.send"]).await;

    let first_result = first
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "111",
                "content": "agent A reply",
                "reply_to": "222"
            },
            "capability_token": build_capability_token(
                &first_key.signing_key,
                &first_key.instance_id,
                "discord.send",
                "discord.send_message",
                "agent:discord-a"
            )
        }))
        .await
        .expect("first Discord claimant should send");
    assert_eq!(first_result["coordination"][0]["event"], "claim_attempt");
    assert_eq!(first_result["coordination"][2]["event"], "send_executed");

    push_evidence(
        logger,
        4,
        "execute",
        json!({
            "git_revision": git_revision,
            "command_line": command_line,
            "connector_fixture_id": "discord-loopback",
            "event_topic": "discord.send_message",
            "conversation_thread_id_hash": evidence_hash("discord:111:222"),
            "claimant_id_hash": evidence_hash("agent:discord-a"),
            "claim_state": "granted",
            "conflict_decision": "send_executed",
            "fcp_error_mapping": null,
            "cleanup_result": "pending",
            "skip_reason": null
        }),
    );

    let second_error = second
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "111",
                "content": "agent B reply",
                "reply_to": "222"
            },
            "capability_token": build_capability_token(
                &second_key.signing_key,
                &second_key.instance_id,
                "discord.send",
                "discord.send_message",
                "agent:discord-b"
            )
        }))
        .await
        .expect_err("second Discord claimant should be denied before HTTP");
    assert_thread_owned_by_peer(&second_error, "agent:discord-a");

    push_evidence(
        logger,
        5,
        "verify",
        json!({
            "git_revision": git_revision,
            "command_line": command_line,
            "connector_fixture_id": "discord-loopback",
            "event_topic": "discord.send_message",
            "conversation_thread_id_hash": evidence_hash("discord:111:222"),
            "claimant_id_hash": evidence_hash("agent:discord-b"),
            "claim_state": "already_owned",
            "conflict_decision": "send_denied",
            "fcp_error_mapping": {
                "kind": "Unauthorized",
                "code": 4090,
                "message_kind": "thread_owned_by_peer",
                "owner_agent_id_hash": evidence_hash("agent:discord-a")
            },
            "cleanup_result": "pending",
            "skip_reason": null
        }),
    );

    let requests = server.received_requests().await.unwrap_or_default();
    assert_eq!(
        requests.len(),
        3,
        "denied Discord claimant must not reach the Discord HTTP fixture"
    );
    assert!(first.handle_shutdown(json!({})).await.is_ok());
    assert!(second.handle_shutdown(json!({})).await.is_ok());
    push_evidence(
        logger,
        6,
        "teardown",
        json!({
            "git_revision": git_revision,
            "command_line": command_line,
            "connector_fixture_id": "discord-loopback",
            "event_topic": "discord.send_message",
            "conversation_thread_id_hash": evidence_hash("discord:111:222"),
            "claimant_id_hash": null,
            "claim_state": "shutdown",
            "conflict_decision": "cleanup_complete",
            "fcp_error_mapping": null,
            "cleanup_result": "shutdown_ok",
            "skip_reason": null
        }),
    );
}

fn run_connector_namespace_isolation_fixture(
    logger: &mut E2eLogger,
    git_revision: &str,
    command_line: &[String],
) {
    let checker = InMemoryThreadOwnershipChecker::new();
    let slack_key = ClaimKey::for_chat_message(
        ZoneId::work(),
        ConnectorId::from_static("fcp.slack"),
        ChannelId::new("shared-conversation"),
        Some(ThreadId::new("shared-thread")),
        DmMode::TreatAsThread,
    )
    .expect("Slack fixture should produce a claim key");
    let discord_key = ClaimKey::for_chat_message(
        ZoneId::work(),
        ConnectorId::from_static("fcp.discord"),
        ChannelId::new("shared-conversation"),
        Some(ThreadId::new("shared-thread")),
        DmMode::TreatAsThread,
    )
    .expect("Discord fixture should produce a claim key");

    let now = std::time::Instant::now();
    assert!(matches!(
        checker.claim_now(slack_key, AgentId::new("agent:slack-a"), now),
        ClaimOutcome::Granted(_)
    ));
    assert!(matches!(
        checker.claim_now(discord_key, AgentId::new("agent:discord-a"), now),
        ClaimOutcome::Granted(_)
    ));

    push_evidence(
        logger,
        7,
        "verify",
        json!({
            "git_revision": git_revision,
            "command_line": command_line,
            "connector_fixture_id": "sdk-namespace-isolation",
            "event_topic": "coordination.namespace_isolation",
            "conversation_thread_id_hash": evidence_hash("shared-conversation:shared-thread"),
            "claimant_id_hash": evidence_hash("agent:discord-a"),
            "claim_state": "granted_after_other_connector_claim",
            "conflict_decision": "connector_namespace_isolated",
            "fcp_error_mapping": null,
            "cleanup_result": "not_applicable",
            "skip_reason": null
        }),
    );
}

async fn run_fail_open_degraded_fixture(
    logger: &mut E2eLogger,
    git_revision: &str,
    command_line: &[String],
) {
    let checker = IndeterminateThreadOwnershipChecker {
        reason: "agent_mail_unavailable",
    };
    let claimant = AgentId::new("agent:degraded-a");
    let decision = ChatCoordinationConfig::new()
        .with_backend(ChatCoordinationBackend::AgentMail)
        .with_fail_open(true)
        .claim_before_send(
            &fcp_async_core::compatibility_cx(),
            &checker,
            ChatCoordinationSendRequest::new(
                ZoneId::work(),
                ConnectorId::from_static("fcp.slack"),
                ChannelId::new("degraded-channel"),
                Some(ThreadId::new("degraded-thread")),
                claimant.clone(),
            ),
        )
        .await;
    assert!(decision.denial_error().is_none());
    let executed = decision
        .send_executed_audit_record(ChatCoordinationBackend::AgentMail, &claimant)
        .expect("fail-open indeterminate claim should produce degraded send audit");
    assert_eq!(executed.reason(), Some("agent_mail_unavailable"));

    push_evidence(
        logger,
        8,
        "verify",
        json!({
            "git_revision": git_revision,
            "command_line": command_line,
            "connector_fixture_id": "sdk-fail-open",
            "event_topic": "coordination.fail_open",
            "conversation_thread_id_hash": evidence_hash("degraded-channel:degraded-thread"),
            "claimant_id_hash": evidence_hash("agent:degraded-a"),
            "claim_state": "indeterminate",
            "conflict_decision": "send_executed_degraded",
            "fcp_error_mapping": null,
            "cleanup_result": "not_applicable",
            "skip_reason": null
        }),
    );
}

async fn configure_slack(connector: &mut SlackConnector, base_url: &str) {
    connector
        .handle_configure(json!({
            "credential_id": TEST_SLACK_BOT_CREDENTIAL_ID,
            "base_url": base_url,
            "chat_coordination": { "backend": "in_memory" }
        }))
        .await
        .expect("Slack configure should succeed");
}

async fn handshake_slack(connector: &mut SlackConnector, caps: &[&str]) -> BoundSigningKey {
    let signing_key = Ed25519SigningKey::generate();
    connector
        .handle_handshake(json!({
            "protocol_version": "2.0.0",
            "zone": "z:work",
            "host_public_key": signing_key.verifying_key().to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": caps
        }))
        .await
        .expect("Slack handshake should succeed");

    BoundSigningKey {
        signing_key,
        instance_id: connector.instance_id().to_owned(),
    }
}

async fn configure_discord(connector: &mut DiscordConnector, base_url: &str) {
    connector
        .handle_configure(json!({
            "bot_credential": "test_token",
            "api_url": base_url,
            "gateway_url": "ws://127.0.0.1:1/",
            "intents": ALL_REQUIRED_INTENTS,
            "chat_coordination": { "backend": "in_memory" }
        }))
        .await
        .expect("Discord configure should succeed");
}

async fn handshake_discord(connector: &mut DiscordConnector, caps: &[&str]) -> BoundSigningKey {
    let signing_key = Ed25519SigningKey::generate();
    connector
        .handle_handshake(json!({
            "protocol_version": "2.0.0",
            "zone": "z:work",
            "zone_dir": unique_zone_dir("discord"),
            "host_public_key": signing_key.verifying_key().to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": caps
        }))
        .await
        .expect("Discord handshake should succeed");

    BoundSigningKey {
        signing_key,
        instance_id: connector.instance_id().as_ref().to_owned(),
    }
}

fn build_capability_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &str,
    capability_id: &str,
    operation: &str,
    principal: &str,
) -> fcp_core::CapabilityToken {
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let now = Utc::now();
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability_id)
        .zone_id("z:work")
        .principal(principal)
        .operations(&[operation])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .target_instance(instance_id)
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should be valid")
        .sign(signing_key)
        .expect("test capability token should sign");
    fcp_core::CapabilityToken::from_raw(cose)
}

fn assert_thread_owned_by_peer(error: &FcpError, expected_owner: &str) {
    assert!(matches!(
        error,
        FcpError::Unauthorized {
            code: 4090,
            message
        } if message == &format!("thread_owned_by_peer:{expected_owner}")
    ));
}

fn push_evidence(logger: &mut E2eLogger, step_number: u32, phase: &str, context: Value) {
    let entry = E2eLogEntry::new(
        "info",
        TEST_NAME,
        "fcp-e2e",
        phase,
        "chat-thread-ownership-cross-connector",
        "pass",
        0,
        AssertionsSummary::new(1, 0),
        context,
    )
    .with_scenario_id(SCENARIO_ID)
    .with_step(format!("chat-coordination-step-{step_number}"), step_number)
    .with_artifacts([ARTIFACT_PATH]);
    entry
        .validate()
        .expect("e2e evidence entry should validate");
    logger.push(entry);
}

fn evidence_hash(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let mut output = String::from("sha256:");
    for byte in digest.iter().take(12) {
        write!(&mut output, "{byte:02x}").expect("hash formatting should not fail");
    }
    output
}

fn git_revision() -> String {
    Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                Some(String::from_utf8_lossy(&output.stdout).trim().to_owned())
            } else {
                None
            }
        })
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

fn replay_command_line() -> Vec<String> {
    [
        "cargo",
        "test",
        "-p",
        "fcp-e2e",
        "--test",
        "chat_thread_ownership_e2e",
        "--no-default-features",
        "--features",
        "slack,discord",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn unique_zone_dir(label: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    std::env::temp_dir()
        .join(format!(
            "fcp-chat-thread-ownership-{label}-{}-{nanos}",
            std::process::id()
        ))
        .to_string_lossy()
        .into_owned()
}
