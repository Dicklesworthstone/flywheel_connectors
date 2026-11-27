#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::panic,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_email_generic::EmailGenericConnector;
use fcp_email_generic::client::{EmailGenericClient, EmailInboundCursor};
use fcp_email_generic::types::{EmailGenericConfig, EmailInboundPolicyDecision, EmailSeenUidCache};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector, HealthState,
    InstanceId, InvokeRequest, OperationId, RequestId, SelfCheckStatus, ShutdownRequest,
    SimulateRequest, SubscribeRequest, ZoneId,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

const CONNECTOR_ID: &str = "fcp.email-generic";
const OP_HEALTH: &str = "email_generic.health";
const OP_SEARCH_MESSAGES: &str = "email_generic.search_messages";
const OP_POLL_INBOUND_ONCE: &str = "email_generic.poll_inbound_once";
const OP_SEND_MESSAGE: &str = "email_generic.send_message";
const CAP_READ: &str = "email_generic.read";
const CAP_WRITE: &str = "email_generic.write";

#[test]
fn imap_loopback_lists_mailboxes_searches_uids_and_emits_redacted_jsonl() {
    let list_fixture = ImapFixture::start(ImapMode::Ok);
    let list_config = config_with_ports(list_fixture.port(), 2525, false, false);
    let list_client = EmailGenericClient::from_config(&list_config).expect("client config");
    let started_at = Instant::now();

    let mailboxes = list_client
        .list_mailboxes()
        .expect("LIST fixture should succeed");
    assert_eq!(mailboxes["mailboxes"], json!(["INBOX", "Archive"]));
    let list_commands = list_fixture.join();
    assert!(
        list_commands
            .iter()
            .any(|line| line.contains("LIST \"\" \"*\"")),
        "fixture should observe LIST command"
    );

    let search_fixture = ImapFixture::start(ImapMode::Ok);
    let search_config = config_with_ports(search_fixture.port(), 2525, false, false);
    let search_client = EmailGenericClient::from_config(&search_config).expect("client config");
    let search = search_client
        .search_messages("INBOX", "deploy")
        .expect("UID SEARCH fixture should succeed");
    assert_eq!(search["uids"], json!([2, 5, 8]));
    let search_commands = search_fixture.join();
    assert!(
        search_commands
            .iter()
            .any(|line| line.contains("UID SEARCH TEXT \"deploy\"")),
        "fixture should observe UID SEARCH command"
    );

    emit_fixture_log(&ProofLog {
        event: "imap_loopback",
        operation: OP_SEARCH_MESSAGES,
        capability: CAP_READ,
        zone: "z:private",
        fixture_id: "imap-ok",
        account_id_hash: hash_id("user@example.com"),
        folder_id_hash: hash_id("INBOX"),
        message_id_hash: hash_id("uid:2,5,8"),
        sender_policy_decision: "not_exercised",
        event_topic: "email.mailbox.search",
        attachment_byte_count: None,
        fcp_error_mapping: "none",
        lifecycle_phase: "client_search",
        latency_ms: elapsed_ms(started_at),
        result: "ok",
        error_code: None,
        retry_decision: "none",
        cleanup_result: "joined",
        skip_reason: None,
    });
}

#[test]
fn failed_inbound_fetch_preserves_read_state_and_retries_every_uid_on_a_fresh_session() {
    for failure in [
        ImapMode::InboundRejectedFetch,
        ImapMode::InboundTruncatedFetch,
        ImapMode::InboundOversizedFetch,
        ImapMode::InboundWrongUid,
        ImapMode::InboundMalformedMessage,
        ImapMode::InboundMissingTrailer,
    ] {
        let fixture = ImapFixture::start_sessions(vec![failure, ImapMode::InboundFetch]);
        let config = config_with_ports(fixture.port(), 2525, false, false);
        let client = EmailGenericClient::from_config(&config).expect("client");
        let mut seen = EmailSeenUidCache::new(8).expect("UID cache");
        seen.observe("99");

        client
            .fetch_unseen_inbound_messages("Alerts", &seen)
            .expect_err("failed fetch must abort the poll");
        assert_eq!(seen.uids(), vec!["99"], "{failure:?} consumed a UID");
        assert!(
            fixture.seen_flags().is_empty(),
            "{failure:?} marked provider messages read"
        );
        let failed_commands = fixture.command_snapshot();
        assert_eq!(
            failed_commands,
            vec![
                "a1 LOGIN \"user@example.com\" \"secret\"",
                "a2 EXAMINE \"Alerts\"",
                "a3 UID SEARCH UNSEEN",
                "f11 UID FETCH 11 (UID BODY.PEEK[])",
                "f12 UID FETCH 12 (UID BODY.PEEK[])",
            ],
            "{failure:?} must not dispatch another FETCH or LOGOUT on the failed session"
        );

        let messages = client
            .fetch_unseen_inbound_messages("Alerts", &seen)
            .expect("fresh session must recover all unacknowledged messages");
        assert_eq!(
            messages
                .iter()
                .map(|message| message.uid.as_str())
                .collect::<Vec<_>>(),
            vec!["11", "12", "13"]
        );
        assert_eq!(
            seen.uids(),
            vec!["99"],
            "retrieval alone cannot acknowledge recovery"
        );
        assert!(fixture.seen_flags().is_empty());
        let commands = fixture.join();
        assert_eq!(
            &commands[..failed_commands.len()],
            failed_commands.as_slice()
        );
        assert_eq!(
            &commands[failed_commands.len()..],
            [
                "a1 LOGIN \"user@example.com\" \"secret\"",
                "a2 EXAMINE \"Alerts\"",
                "a3 UID SEARCH UNSEEN",
                "f11 UID FETCH 11 (UID BODY.PEEK[])",
                "f12 UID FETCH 12 (UID BODY.PEEK[])",
                "f13 UID FETCH 13 (UID BODY.PEEK[])",
                "az LOGOUT",
            ]
        );
    }
}

#[test]
fn inbound_fetch_accepts_uid_after_literal_without_marking_messages_read() {
    let fixture = ImapFixture::start(ImapMode::InboundUidAfterLiteral);
    let config = config_with_ports(fixture.port(), 2525, false, false);
    let client = EmailGenericClient::from_config(&config).expect("client");
    let seen = EmailSeenUidCache::new(8).expect("UID cache");
    let messages = client
        .fetch_unseen_inbound_messages("Alerts", &seen)
        .expect("UID may follow the BODY[] literal");
    assert_eq!(
        messages
            .iter()
            .map(|message| message.uid.as_str())
            .collect::<Vec<_>>(),
        vec!["11", "12", "13"]
    );
    assert!(seen.is_empty());
    assert!(fixture.seen_flags().is_empty());
    let commands = fixture.join();
    assert_eq!(
        commands
            .iter()
            .filter(|line| line.contains("BODY.PEEK[]"))
            .count(),
        3
    );
}

#[test]
fn epoch_cursor_retries_a_partial_tail_filters_reversed_range_and_handles_max_uid() {
    let fixture = ImapFixture::start_sessions(vec![ImapMode::InboundFetch; 4]);
    let client =
        EmailGenericClient::from_config(&config_with_ports(fixture.port(), 2525, false, false))
            .unwrap();
    let first = client
        .fetch_inbound_batch("Alerts", None)
        .expect("initial epoch batch");
    assert_eq!(first.cursor.uid_validity, 42);
    assert_eq!(
        first.cursor.last_uid, 0,
        "fetch must not acknowledge its tail"
    );
    let mut cursor: EmailInboundCursor = first.cursor;
    cursor.last_uid = 11; // The publication layer handled only this prefix.
    let second = client
        .fetch_inbound_batch("Alerts", Some(&cursor))
        .expect("retry unhandled tail");
    assert_eq!(second.requested_cursor.as_ref(), Some(&cursor));
    assert_eq!(second.cursor.last_uid, 11);
    assert_eq!(
        second
            .messages
            .iter()
            .map(|message| message.uid.as_str())
            .collect::<Vec<_>>(),
        vec!["12", "13"]
    );
    cursor.last_uid = 13;
    let third = client
        .fetch_inbound_batch("Alerts", Some(&cursor))
        .expect("highest UID range response");
    assert!(
        third.messages.is_empty(),
        "14:* returns highest UID13, which must not be fetched again"
    );
    assert_eq!(third.cursor.last_uid, 13);
    cursor.last_uid = u32::MAX;
    let last = client
        .fetch_inbound_batch("Alerts", Some(&cursor))
        .expect("exhausted epoch UID space");
    assert!(last.messages.is_empty());
    assert_eq!(last.cursor.last_uid, u32::MAX);
    assert!(fixture.seen_flags().is_empty());
    let commands = fixture.join();
    assert!(
        commands
            .iter()
            .any(|command| command == "a3 UID SEARCH UNSEEN UID 12:*")
    );
    assert!(
        commands
            .iter()
            .any(|command| command == "a3 UID SEARCH UNSEEN UID 14:*")
    );
    assert_eq!(
        commands
            .iter()
            .filter(|command| command.contains("UID SEARCH"))
            .count(),
        3
    );
    assert_eq!(
        commands
            .iter()
            .filter(|command| command.contains("UID FETCH"))
            .count(),
        5
    );
    assert_eq!(
        commands
            .iter()
            .filter(|command| *command == "f13 UID FETCH 13 (UID BODY.PEEK[])")
            .count(),
        2
    );
}

#[test]
fn changed_uid_validity_restarts_below_the_previous_high_water_without_reusing_identity() {
    let fixture =
        ImapFixture::start_sessions(vec![ImapMode::InboundFetch, ImapMode::InboundEpoch(43)]);
    let client =
        EmailGenericClient::from_config(&config_with_ports(fixture.port(), 2525, false, false))
            .unwrap();
    let first = client
        .fetch_inbound_batch("Alerts", None)
        .expect("first epoch");
    let mut cursor = first.cursor;
    cursor.last_uid = 13;
    let changed = client
        .fetch_inbound_batch("Alerts", Some(&cursor))
        .expect("new epoch");
    assert_eq!(cursor.uid_validity, 42);
    assert_eq!(cursor.last_uid, 13, "caller checkpoint remains immutable");
    assert_eq!(changed.requested_cursor.as_ref(), Some(&cursor));
    assert_eq!(changed.cursor.uid_validity, 43);
    assert_eq!(
        changed.cursor.last_uid, 0,
        "new epoch must discard the old UID high-water"
    );
    assert_eq!(
        changed
            .messages
            .iter()
            .map(|message| message.uid.as_str())
            .collect::<Vec<_>>(),
        vec!["11", "12", "13"]
    );
    let mut changed_cursor = changed.cursor;
    changed_cursor.last_uid = 13;
    assert_ne!(cursor.event_cursor(), changed_cursor.event_cursor());
    assert!(fixture.seen_flags().is_empty());
    let commands = fixture.join();
    assert_eq!(
        commands
            .iter()
            .filter(|command| *command == "a3 UID SEARCH UNSEEN")
            .count(),
        2
    );
    assert_eq!(
        commands
            .iter()
            .filter(|command| command.contains("UID FETCH"))
            .count(),
        6
    );
}

#[test]
fn invalid_uid_validity_aborts_before_search_and_recovers_on_a_new_connection() {
    for mode in [
        ImapMode::InboundMissingEpoch,
        ImapMode::InboundEpoch(0),
        ImapMode::InboundDuplicateEpoch,
    ] {
        let fixture = ImapFixture::start_sessions(vec![mode, ImapMode::InboundFetch]);
        let client =
            EmailGenericClient::from_config(&config_with_ports(fixture.port(), 2525, false, false))
                .unwrap();
        client
            .fetch_inbound_batch("Alerts", None)
            .expect_err("invalid epoch must fail closed");
        assert_eq!(
            fixture.command_snapshot(),
            vec![
                "a1 LOGIN \"user@example.com\" \"secret\"",
                "a2 EXAMINE \"Alerts\"",
            ]
        );
        let recovered = client
            .fetch_inbound_batch("Alerts", None)
            .expect("fresh valid epoch");
        assert_eq!(recovered.cursor.last_uid, 0);
        assert_eq!(recovered.messages.len(), 3);
        assert!(fixture.seen_flags().is_empty());
        let commands = fixture.join();
        assert_eq!(
            commands
                .iter()
                .filter(|command| command.contains("UID SEARCH"))
                .count(),
            1
        );
    }
}

#[fcp_async_core::runtime::test]
async fn inbound_epoch_cursor_drains_257_unread_messages_past_a_128_uid_cache() {
    let fixture = ImapFixture::start_sessions(vec![ImapMode::InboundBacklog; 4]);
    let mut connector = configured_monitor_with_cache(fixture.port(), 1, 128).await;
    let mut events = connector.subscribe_events();
    start_monitor(&connector).await;
    for uid in 1..=257_u32 {
        let event = fcp_async_core::time::timeout(Duration::from_secs(10), events.recv())
            .await
            .expect("backlog event timeout")
            .expect("event receiver")
            .expect("inbound event");
        assert_eq!(event.seq, u64::from(uid));
        assert_eq!(event.data.payload["uid"], uid.to_string());
        assert_eq!(event.data.payload["uid_validity"], 42);
        assert_epoch_event_cursor(&event.cursor, 42, uid);
    }
    let details = wait_monitor_polls(&connector, 4).await;
    assert_eq!(details["inbound_monitor"]["emitted_events"], 257);
    assert_eq!(details["inbound_monitor"]["dropped_events"], 0);
    assert!(
        fixture.seen_flags().is_empty(),
        "backlog draining must preserve all unread flags"
    );
    stop_monitor(&mut connector).await;
    let commands = fixture.join();
    assert_eq!(
        commands
            .iter()
            .filter(|command| command.contains("UID FETCH"))
            .count(),
        257
    );
    for start in [129, 257, 258] {
        assert!(
            commands
                .iter()
                .any(|command| command == &format!("a3 UID SEARCH UNSEEN UID {start}:*"))
        );
    }
}

#[fcp_async_core::runtime::test]
async fn one_shot_cursor_modes_preserve_legacy_behavior_and_ignore_unscoped_uid_lists() {
    let fixture = ImapFixture::start_sessions(vec![
        ImapMode::InboundFetch,
        ImapMode::InboundFetch,
        ImapMode::InboundFetch,
        ImapMode::InboundEpoch(43),
    ]);
    let mut value = config_json(fixture.port(), 2525, false, false);
    value["monitor_policy"] = json!({ "allowed_senders": ["human@example.com"] });
    let mut connector = EmailGenericConnector::new();
    connector.configure(value).await.unwrap();
    let key = Ed25519SigningKey::generate();
    connector
        .handshake(handshake_request(key.verifying_key().to_bytes()))
        .await
        .unwrap();

    let legacy = invoke_inbound_once(
        &connector,
        &key,
        json!({
            "mailbox": "Alerts", "seen_uids": ["11", "12", "13"]
        }),
    )
    .await
    .expect("legacy cache mode");
    assert_eq!(legacy["fetched_count"], 0);
    assert!(legacy["cursor"].is_null());

    let initialized = invoke_inbound_once(
        &connector,
        &key,
        json!({
            "mailbox": "Alerts", "cursor": null, "seen_uids": ["11", "12", "13", "4294967295"]
        }),
    )
    .await
    .expect("explicit cursor initialization ignores legacy entries");
    assert_eq!(initialized["fetched_count"], 3);
    assert_eq!(initialized["accepted_count"], 1);
    assert_eq!(initialized["dropped_count"], 2);
    let cursor = initialized["cursor"].clone();
    assert_eq!(cursor["uid_validity"], 42);
    assert_eq!(cursor["last_uid"], 13);
    let continued = invoke_inbound_once(
        &connector,
        &key,
        json!({
            "mailbox": "Alerts", "cursor": cursor.clone(), "seen_uids": ["4294967295"]
        }),
    )
    .await
    .expect("continue cursor without replay");
    assert_eq!(continued["fetched_count"], 0);
    assert_eq!(continued["cursor"], cursor);
    assert_eq!(continued["seen_uids"], json!([]));

    let rebuilt = invoke_inbound_once(
        &connector,
        &key,
        json!({
            "mailbox": "Alerts", "cursor": cursor.clone(), "seen_uids": ["11", "12", "13"]
        }),
    )
    .await
    .expect("new UID epoch ignores stale cache");
    assert_eq!(rebuilt["fetched_count"], 3);
    assert_eq!(rebuilt["cursor"]["uid_validity"], 43);
    assert_eq!(rebuilt["cursor"]["last_uid"], 13);
    assert_eq!(
        rebuilt["cursor"]["account_fingerprint"],
        cursor["account_fingerprint"]
    );

    let mut wrong_account = cursor;
    wrong_account["account_fingerprint"] = json!("0".repeat(64));
    let rejected = invoke_inbound_once(
        &connector,
        &key,
        json!({
            "mailbox": "Alerts", "cursor": wrong_account
        }),
    )
    .await
    .expect_err("different account cursor must fail before connecting");
    assert!(matches!(
        rejected,
        fcp_prelude::FcpError::InvalidRequest { .. }
    ));
    assert!(fixture.seen_flags().is_empty());
    stop_monitor(&mut connector).await;
    let commands = fixture.join();
    assert_eq!(
        commands
            .iter()
            .filter(|command| command.contains(" LOGIN "))
            .count(),
        4
    );
    assert_eq!(
        commands
            .iter()
            .filter(|command| command.contains("UID FETCH"))
            .count(),
        6
    );
}

async fn invoke_inbound_once(
    connector: &EmailGenericConnector,
    key: &Ed25519SigningKey,
    input: Value,
) -> fcp_prelude::FcpResult<Value> {
    let response = connector
        .invoke(InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("epoch-cursor-once"),
            connector_id: ConnectorId::from_static(CONNECTOR_ID),
            operation: OperationId::from_static(OP_POLL_INBOUND_ONCE),
            zone_id: ZoneId::private(),
            input,
            capability_token: capability_token(
                key,
                connector.instance_id(),
                CAP_READ,
                OP_POLL_INBOUND_ONCE,
                &ZoneId::private(),
            ),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: vec![],
        })
        .await?;
    Ok(response.result.expect("successful invoke result"))
}

#[test]
fn imap_loopback_fetches_unseen_inbound_previews_with_policy_and_uid_cache() {
    let fixture = ImapFixture::start(ImapMode::InboundFetch);
    let config = EmailGenericConfig::from_value(json!({
        "imap": {
            "host": "127.0.0.1",
            "port": fixture.port(),
            "username": "user@example.com",
            "password": "secret",
            "tls": false
        },
        "smtp": {
            "host": "127.0.0.1",
            "port": 2525,
            "username": "user@example.com",
            "password": "secret",
            "from_address": "user@example.com",
            "starttls": false
        },
        "request_timeout_ms": 2_000,
        "monitor_policy": {
            "allowed_senders": ["human@example.com"],
            "allow_attachments": false,
            "seen_uid_cap": 8,
            "max_body_chars": 128
        }
    }))
    .expect("loopback config should parse");
    let client = EmailGenericClient::from_config(&config).expect("client config");
    let mut seen_uids =
        EmailSeenUidCache::new(config.monitor_policy.seen_uid_cap).expect("seen UID cache");
    let started_at = Instant::now();

    let messages = client
        .fetch_unseen_inbound_messages("Alerts", &seen_uids)
        .expect("UID FETCH fixture should return inbound messages");
    assert_eq!(messages.len(), 3);
    assert!(seen_uids.is_empty(), "retrieval must not acknowledge UIDs");
    assert!(
        fixture.seen_flags().is_empty(),
        "retrieval must preserve provider read flags"
    );

    let previews = messages
        .iter()
        .map(|message| config.monitor_policy.prepare_inbound_message(message))
        .collect::<Vec<_>>();
    assert_eq!(previews[0].decision, EmailInboundPolicyDecision::Accept);
    assert_eq!(
        previews[1].decision,
        EmailInboundPolicyDecision::DropSenderNotAllowed
    );
    assert_eq!(
        previews[2].decision,
        EmailInboundPolicyDecision::DropAutomated
    );
    let accepted = &previews[0];
    assert_eq!(
        accepted
            .thread
            .as_ref()
            .expect("thread metadata")
            .reply_subject,
        "Re: Deploy ready"
    );
    assert!(
        accepted
            .text
            .as_ref()
            .expect("bounded text")
            .text
            .contains("[Subject: Deploy ready]")
    );
    assert_eq!(accepted.attachments.len(), 1);
    assert_eq!(accepted.attachments[0].filename, "plan.pdf");
    assert_eq!(accepted.attachments[0].media_type, "application/pdf");
    assert_eq!(accepted.attachments[0].size_bytes, 4);
    assert!(!accepted.attachments[0].exposed);
    assert_eq!(
        accepted.attachments[0].reason.as_deref(),
        Some("attachments_disabled")
    );
    assert!(
        !serde_json::to_string(&previews)
            .expect("preview JSON")
            .contains("cGxhbg"),
        "attachment bytes must not leak into preview JSON"
    );

    for message in &messages {
        seen_uids.observe(message.uid.clone());
    }
    let commands = fixture.join();
    assert!(
        commands.iter().any(|line| line == "a2 EXAMINE \"Alerts\""),
        "fixture should observe mailbox binding"
    );
    assert!(
        commands
            .iter()
            .filter(|line| line.contains("UID FETCH"))
            .count()
            == 3,
        "fixture should fetch each previously unseen UID"
    );

    let repeat_fixture = ImapFixture::start(ImapMode::InboundFetch);
    let repeat_config = config_with_ports(repeat_fixture.port(), 2525, false, false);
    let repeat_client = EmailGenericClient::from_config(&repeat_config).expect("client config");
    let repeat_messages = repeat_client
        .fetch_unseen_inbound_messages("Alerts", &seen_uids)
        .expect("seen cache should suppress repeated UIDs");
    assert!(repeat_messages.is_empty());
    let repeat_commands = repeat_fixture.join();
    assert!(
        repeat_commands
            .iter()
            .all(|line| !line.contains("UID FETCH")),
        "seen cache must skip duplicate UID FETCH commands"
    );

    emit_fixture_log(&ProofLog {
        event: "imap_inbound_monitor_once",
        operation: OP_SEARCH_MESSAGES,
        capability: CAP_READ,
        zone: "z:private",
        fixture_id: "imap-inbound-fetch",
        account_id_hash: hash_id("user@example.com"),
        folder_id_hash: hash_id("Alerts"),
        message_id_hash: hash_id("uid:11,12,13"),
        sender_policy_decision: "accept+drop_sender_not_allowed+drop_automated",
        event_topic: "email.inbound.preview",
        attachment_byte_count: Some(4),
        fcp_error_mapping: "none",
        lifecycle_phase: "client_inbound_poll_once",
        latency_ms: elapsed_ms(started_at),
        result: "ok",
        error_code: None,
        retry_decision: "none",
        cleanup_result: "joined",
        skip_reason: None,
    });
}

#[test]
fn smtp_loopback_sends_message_and_classifies_permanent_failure() {
    let success_fixture = SmtpFixture::start(SmtpMode::Accept);
    let success_config = config_with_ports(1993, success_fixture.port(), false, false);
    let client = EmailGenericClient::from_config(&success_config).expect("client config");
    let started_at = Instant::now();

    let sent = client
        .send_message(
            &["ops@example.com".to_owned()],
            "Deploy status",
            "Green",
            &["audit@example.com".to_owned()],
        )
        .expect("SMTP fixture should accept message");
    assert_eq!(sent["status"], "sent");
    assert_eq!(sent["to"], json!(["ops@example.com"]));
    let success_commands = success_fixture.join();
    assert!(
        success_commands
            .iter()
            .any(|line| line.starts_with("MAIL FROM:")),
        "fixture should observe MAIL FROM"
    );
    assert!(
        success_commands
            .iter()
            .any(|line| line.starts_with("RCPT TO:")),
        "fixture should observe RCPT TO"
    );
    assert!(
        success_commands.iter().any(|line| line == "DATA"),
        "fixture should observe DATA"
    );

    emit_fixture_log(&ProofLog {
        event: "smtp_loopback",
        operation: OP_SEND_MESSAGE,
        capability: CAP_WRITE,
        zone: "z:private",
        fixture_id: "smtp-accept",
        account_id_hash: hash_id("user@example.com"),
        folder_id_hash: hash_id("outbox"),
        message_id_hash: hash_id("subject:deploy-status"),
        sender_policy_decision: "not_exercised",
        event_topic: "email.smtp.send",
        attachment_byte_count: None,
        fcp_error_mapping: "none",
        lifecycle_phase: "client_send",
        latency_ms: elapsed_ms(started_at),
        result: "ok",
        error_code: None,
        retry_decision: "none",
        cleanup_result: "joined",
        skip_reason: None,
    });

    let failure_fixture = SmtpFixture::start(SmtpMode::PermanentFailure);
    let failure_config = config_with_ports(1993, failure_fixture.port(), false, false);
    let failure_client = EmailGenericClient::from_config(&failure_config).expect("client config");
    let error = failure_client
        .send_message(&["missing@example.com".to_owned()], "Status", "Body", &[])
        .expect_err("permanent SMTP failure should surface");
    assert!(!error.is_retryable());
    let failure_commands = failure_fixture.join();
    assert!(
        failure_commands
            .iter()
            .any(|line| line.starts_with("RCPT TO:")),
        "fixture should fail after recipient command"
    );
}

#[test]
fn smtp_tls_mode_fails_closed_before_sending_credentials() {
    let fixture = SmtpFixture::start(SmtpMode::StartTlsAdvertised);
    let config = config_with_ports(1993, fixture.port(), false, true);
    let client = EmailGenericClient::from_config(&config).expect("client config");

    let error = client
        .send_message(&["ops@example.com".to_owned()], "Status", "Body", &[])
        .expect_err("fixture does not complete TLS handshake");
    assert!(!error.to_string().contains("secret"));
    let commands = fixture.join();
    assert!(
        commands
            .iter()
            .any(|line| line == "TLS_HANDSHAKE_BYTES_WITHOUT_STARTTLS"),
        "client should fail during TLS setup before SMTP AUTH; observed {commands:?}"
    );
    assert!(
        commands.iter().all(|line| !line.starts_with("AUTH")),
        "client must not send credentials after TLS setup fails; observed {commands:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn connector_lifecycle_self_check_and_capability_denial() {
    let imap_fixture = ImapFixture::start(ImapMode::Ok);
    let mut connector = EmailGenericConnector::new();

    assert_eq!(connector.id().as_str(), CONNECTOR_ID);
    assert!(matches!(
        connector.health().await.status,
        HealthState::Degraded { .. }
    ));

    connector
        .configure(config_json(imap_fixture.port(), 2525, false, false))
        .await
        .expect("configure should accept loopback config");
    assert!(matches!(
        connector.health().await.status,
        HealthState::Ready
    ));

    let self_check = connector
        .self_check()
        .await
        .expect("self-check should use loopback IMAP fixture");
    assert_eq!(self_check.status, SelfCheckStatus::Ok);
    assert_eq!(
        self_check.details.expect("self-check details")["mailbox_count"],
        2
    );

    let signing_key = Ed25519SigningKey::generate();
    connector
        .handshake(handshake_request(signing_key.verifying_key().to_bytes()))
        .await
        .expect("handshake should accept read/write capability request");

    let denied = connector
        .simulate(SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(OP_HEALTH),
            ZoneId::private(),
            json!({}),
            capability_token(
                &signing_key,
                &InstanceId::new(),
                CAP_READ,
                OP_HEALTH,
                &ZoneId::private(),
            ),
        ))
        .await
        .expect("simulation should return policy denial");
    assert!(!denied.would_succeed);
    assert!(
        denied
            .failure_reason
            .as_ref()
            .is_some_and(|reason| reason.contains("instance") || reason.contains("target")),
        "denial should describe instance binding"
    );

    connector
        .shutdown(ShutdownRequest {
            r#type: "shutdown".into(),
            deadline_ms: 1_000,
            drain: true,
            reason: Some("email-generic integration test complete".into()),
        })
        .await
        .expect("shutdown should clear state");
    assert!(matches!(
        connector.health().await.status,
        HealthState::Degraded { .. }
    ));

    let _ = imap_fixture.join();
}

#[fcp_async_core::runtime::test]
async fn inbound_monitor_supervises_polling_fanout_and_shutdown() {
    let fixture = ImapFixture::start(ImapMode::InboundFetch);
    let mut connector = EmailGenericConnector::new();
    let mut events = connector.subscribe_events();
    let started_at = Instant::now();
    connector
        .configure(json!({
            "imap": {
                "host": "127.0.0.1",
                "port": fixture.port(),
                "username": "user@example.com",
                "password": "secret",
                "tls": false
            },
            "smtp": {
                "host": "127.0.0.1",
                "port": 2525,
                "username": "user@example.com",
                "password": "secret",
                "from_address": "user@example.com",
                "starttls": false
            },
            "request_timeout_ms": 2_000,
            "monitor_policy": {
                "mailbox": "Alerts",
                "allowed_senders": ["human@example.com"],
                "allow_attachments": false,
                "seen_uid_cap": 8,
                "max_body_chars": 128,
                "poll_interval_secs": 60
            }
        }))
        .await
        .expect("configure should accept loopback config");

    let signing_key = Ed25519SigningKey::generate();
    let handshake = connector
        .handshake(handshake_request(signing_key.verifying_key().to_bytes()))
        .await
        .expect("handshake should accept read/write capability request");
    let handshake_caps = handshake.event_caps.expect("handshake event caps");
    assert!(handshake_caps.streaming);
    assert!(!handshake_caps.replay);

    let introspection = connector.introspect();
    assert_eq!(introspection.events.len(), 1);
    assert_eq!(introspection.events[0].topic, "email.inbound.preview");
    let introspection_caps = introspection.event_caps.expect("introspection event caps");
    assert!(introspection_caps.streaming);
    assert_eq!(introspection_caps.min_buffer_events, 128);

    let subscribe = connector
        .subscribe(SubscribeRequest {
            r#type: "subscribe".into(),
            id: RequestId::new("email-generic-supervised-monitor"),
            topics: vec!["email.inbound.preview".into()],
            since: None,
            max_events_per_sec: Some(1),
            batch_ms: Some(100),
            window_size: Some(1),
            capability_token: None,
        })
        .await
        .expect("subscribe should start supervised inbound monitor");
    assert_eq!(
        subscribe.result.confirmed_topics,
        vec!["email.inbound.preview"]
    );
    assert!(!subscribe.result.replay_supported);

    let envelope = fcp_async_core::time::timeout(Duration::from_secs(5), events.recv())
        .await
        .expect("supervised monitor should emit within timeout")
        .expect("broadcast receive should succeed")
        .expect("event should be ok");
    assert_eq!(envelope.topic, "email.inbound.preview");
    assert_eq!(envelope.seq, 1);
    assert_epoch_event_cursor(&envelope.cursor, 42, 11);
    assert_eq!(envelope.data.payload["uid_validity"], 42);
    assert_eq!(envelope.stream_key.as_deref(), Some("Alerts"));
    assert_eq!(envelope.data.zone_id, ZoneId::private());
    assert_eq!(envelope.data.payload["mailbox"], "Alerts");
    assert_eq!(envelope.data.payload["uid"], "11");
    assert_eq!(envelope.data.payload["policy_decision"], "accept");
    assert_eq!(envelope.data.payload["preview"]["decision"], "accept");
    assert_eq!(
        envelope.data.payload["preview"]["thread"]["reply_subject"],
        "Re: Deploy ready"
    );
    assert_eq!(
        envelope.data.payload["preview"]["attachments"][0]["reason"],
        "attachments_disabled"
    );
    assert!(
        !serde_json::to_string(&envelope.data.payload)
            .expect("event JSON")
            .contains("cGxhbg"),
        "event payload must not expose attachment bytes"
    );

    let health = connector.health().await;
    let details = health.details.expect("health details");
    assert_eq!(details["inbound_monitor"]["streaming"], true);
    assert_eq!(
        details["inbound_monitor"]["event_topic"],
        "email.inbound.preview"
    );
    assert_eq!(details["inbound_monitor"]["emitted_events"], 1);
    assert_eq!(details["inbound_monitor"]["dropped_events"], 2);

    connector
        .shutdown(ShutdownRequest {
            r#type: "shutdown".into(),
            deadline_ms: 1_000,
            drain: true,
            reason: Some("email-generic supervised monitor proof complete".into()),
        })
        .await
        .expect("shutdown should stop monitor and clear connector state");
    assert!(matches!(
        connector.health().await.status,
        HealthState::Degraded { .. }
    ));

    let commands = fixture.join();
    assert!(
        commands
            .iter()
            .filter(|line| line.contains("UID FETCH"))
            .count()
            == 3,
        "supervised monitor should fetch unseen UIDs once"
    );

    emit_fixture_log(&ProofLog {
        event: "inbound_monitor_supervised",
        operation: OP_HEALTH,
        capability: CAP_READ,
        zone: "z:private",
        fixture_id: "supervised-inbound-fetch",
        account_id_hash: hash_id("user@example.com"),
        folder_id_hash: hash_id("Alerts"),
        message_id_hash: hash_id("uid:11,12,13"),
        sender_policy_decision: "emitted_accept+dropped_sender_not_allowed+dropped_automated",
        event_topic: "email.inbound.preview",
        attachment_byte_count: Some(4),
        fcp_error_mapping: "none",
        lifecycle_phase: "runtime_supervised_fanout_shutdown",
        latency_ms: elapsed_ms(started_at),
        result: "ok",
        error_code: None,
        retry_decision: "none",
        cleanup_result: "shutdown_cleared_state",
        skip_reason: None,
    });
}

#[fcp_async_core::runtime::test]
async fn inbound_monitor_retries_failed_fetch_without_losing_earlier_messages() {
    let fixture =
        ImapFixture::start_sessions(vec![ImapMode::InboundRejectedFetch, ImapMode::InboundFetch]);
    let mut connector = configured_monitor(fixture.port(), 60).await;
    let mut events = connector.subscribe_events();
    start_monitor(&connector).await;
    let event = fcp_async_core::time::timeout(Duration::from_secs(5), events.recv())
        .await
        .expect("recovery event timeout")
        .expect("event receiver")
        .expect("inbound event");
    assert_eq!(event.data.payload["uid"], "11");
    assert_eq!(event.seq, 1);
    assert_epoch_event_cursor(&event.cursor, 42, 11);
    let details = wait_monitor_polls(&connector, 1).await;
    assert_eq!(details["inbound_monitor"]["polls_started"], 2);
    assert_eq!(details["inbound_monitor"]["polls_completed"], 1);
    assert_eq!(details["inbound_monitor"]["emitted_events"], 1);
    assert_eq!(details["inbound_monitor"]["dropped_events"], 2);
    assert!(fixture.seen_flags().is_empty());
    stop_monitor(&mut connector).await;
    let commands = fixture.join();
    assert_eq!(
        commands
            .iter()
            .filter(|line| *line == "f11 UID FETCH 11 (UID BODY.PEEK[])")
            .count(),
        2,
        "a successful early fetch from the failed batch must be retrieved again"
    );
    assert_eq!(
        commands
            .iter()
            .filter(|line| *line == "f13 UID FETCH 13 (UID BODY.PEEK[])")
            .count(),
        1,
        "the failed session must stop before the next UID"
    );
}

#[fcp_async_core::runtime::test]
async fn inbound_monitor_retries_unpublished_messages_without_consuming_event_sequence() {
    let fixture = ImapFixture::start_sessions(vec![
        ImapMode::InboundFetch,
        ImapMode::InboundFetch,
        ImapMode::InboundFetch,
    ]);
    let mut connector = configured_monitor(fixture.port(), 1).await;
    // Start polling without any event receiver so the first send must fail.
    start_monitor(&connector).await;
    let details = wait_monitor_polls(&connector, 1).await;
    assert_eq!(details["inbound_monitor"]["emitted_events"], 0);
    assert_eq!(details["inbound_monitor"]["dropped_events"], 0);
    assert!(details["inbound_monitor"]["last_error"].is_string());

    let mut events = connector.subscribe_events();
    let event = fcp_async_core::time::timeout(Duration::from_secs(5), events.recv())
        .await
        .expect("publication recovery timeout")
        .expect("event receiver")
        .expect("inbound event");
    assert_eq!(event.data.payload["uid"], "11");
    assert_eq!(
        event.seq, 1,
        "a failed send cannot consume an event sequence"
    );
    assert_epoch_event_cursor(&event.cursor, 42, 11);
    // A third poll must skip both delivered and deliberately rejected UIDs.
    let details = wait_monitor_polls(&connector, 3).await;
    assert_eq!(details["inbound_monitor"]["emitted_events"], 1);
    assert_eq!(details["inbound_monitor"]["dropped_events"], 2);
    assert!(details["inbound_monitor"]["last_error"].is_null());
    assert!(fixture.seen_flags().is_empty());
    stop_monitor(&mut connector).await;
    let commands = fixture.join();
    for uid in [11, 12, 13] {
        let fetch = format!("f{uid} UID FETCH {uid} (UID BODY.PEEK[])");
        assert_eq!(
            commands
                .iter()
                .filter(|line| line.as_str() == fetch.as_str())
                .count(),
            2
        );
    }
}

async fn wait_monitor_polls(connector: &EmailGenericConnector, expected: u64) -> Value {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let details = connector.health().await.details.expect("health details");
        if details["inbound_monitor"]["polls_completed"]
            .as_u64()
            .unwrap_or(0)
            >= expected
        {
            return details;
        }
        assert!(
            Instant::now() < deadline,
            "monitor did not finish {expected} polls"
        );
        fcp_async_core::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn configured_monitor(imap_port: u16, poll_interval_secs: u64) -> EmailGenericConnector {
    configured_monitor_with_cache(imap_port, poll_interval_secs, 8).await
}

async fn configured_monitor_with_cache(
    imap_port: u16,
    poll_interval_secs: u64,
    seen_uid_cap: usize,
) -> EmailGenericConnector {
    let mut value = config_json(imap_port, 2525, false, false);
    value["monitor_policy"] = json!({
        "mailbox": "Alerts",
        "allowed_senders": ["human@example.com"],
        "seen_uid_cap": seen_uid_cap,
        "poll_interval_secs": poll_interval_secs
    });
    let mut connector = EmailGenericConnector::new();
    connector.configure(value).await.expect("configure monitor");
    let key = Ed25519SigningKey::generate();
    connector
        .handshake(handshake_request(key.verifying_key().to_bytes()))
        .await
        .expect("handshake monitor");
    connector
}

async fn start_monitor(connector: &EmailGenericConnector) {
    connector
        .subscribe(SubscribeRequest {
            r#type: "subscribe".into(),
            id: RequestId::new("inbound-recovery"),
            topics: vec!["email.inbound.preview".into()],
            since: None,
            max_events_per_sec: None,
            batch_ms: None,
            window_size: None,
            capability_token: None,
        })
        .await
        .expect("start inbound monitor");
}

async fn stop_monitor(connector: &mut EmailGenericConnector) {
    connector
        .shutdown(ShutdownRequest {
            r#type: "shutdown".into(),
            deadline_ms: 1_000,
            drain: true,
            reason: Some("inbound recovery proof complete".into()),
        })
        .await
        .expect("stop inbound monitor");
}

fn config_with_ports(
    imap_port: u16,
    smtp_port: u16,
    imap_tls: bool,
    smtp_starttls: bool,
) -> EmailGenericConfig {
    EmailGenericConfig::from_value(config_json(imap_port, smtp_port, imap_tls, smtp_starttls))
        .expect("loopback config should parse")
}

fn assert_epoch_event_cursor(cursor: &str, epoch: u32, uid: u32) {
    let parts = cursor.split(':').collect::<Vec<_>>();
    assert_eq!(parts.len(), 4);
    assert_eq!(parts[0], "v1");
    assert_eq!(parts[1].len(), 64);
    assert!(parts[1].bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(parts[2], epoch.to_string());
    assert_eq!(parts[3], uid.to_string());
}

fn config_json(imap_port: u16, smtp_port: u16, imap_tls: bool, smtp_starttls: bool) -> Value {
    json!({
        "imap": {
            "host": "127.0.0.1",
            "port": imap_port,
            "username": "user@example.com",
            "password": "secret",
            "tls": imap_tls
        },
        "smtp": {
            "host": "127.0.0.1",
            "port": smtp_port,
            "username": "user@example.com",
            "password": "secret",
            "from_address": "user@example.com",
            "starttls": smtp_starttls
        },
        "request_timeout_ms": 2_000
    })
}

fn handshake_request(host_public_key: [u8; 32]) -> fcp_prelude::HandshakeRequest {
    fcp_prelude::HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::private(),
        zone_dir: None,
        host_public_key,
        nonce: [44_u8; 32],
        capabilities_requested: vec![
            CapabilityId::from_static(CAP_READ),
            CapabilityId::from_static(CAP_WRITE),
        ],
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

fn capability_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    capability: &'static str,
    operation: &'static str,
    zone: &ZoneId,
) -> CapabilityToken {
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).expect("serialize constraints");
    let now = Utc::now();
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id(zone.as_str())
        .target_instance(instance_id.as_str())
        .principal("user:test")
        .operations(&[operation])
        .issuer("node:test")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&constraints_cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("token should sign");
    CapabilityToken::from_raw(raw)
}

#[derive(Clone, Copy, Debug)]
enum ImapMode {
    Ok,
    InboundFetch,
    InboundRejectedFetch,
    InboundTruncatedFetch,
    InboundOversizedFetch,
    InboundWrongUid,
    InboundMalformedMessage,
    InboundMissingTrailer,
    InboundUidAfterLiteral,
    InboundBacklog,
    InboundEpoch(u32),
    InboundMissingEpoch,
    InboundDuplicateEpoch,
}

struct ImapFixture {
    port: u16,
    commands: Arc<Mutex<Vec<String>>>,
    provider_seen: Arc<Mutex<BTreeSet<u32>>>,
    handle: JoinHandle<()>,
}

impl ImapFixture {
    fn start(mode: ImapMode) -> Self {
        Self::start_sessions(vec![mode])
    }

    fn start_sessions(modes: Vec<ImapMode>) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind IMAP fixture");
        listener
            .set_nonblocking(true)
            .expect("fixture nonblocking accept");
        let port = listener.local_addr().expect("fixture addr").port();
        let commands = Arc::new(Mutex::new(Vec::new()));
        let command_log = Arc::clone(&commands);
        let provider_seen = Arc::new(Mutex::new(BTreeSet::new()));
        let seen_flags = Arc::clone(&provider_seen);
        let handle = thread::spawn(move || {
            for mode in modes {
                let deadline = Instant::now() + Duration::from_secs(15);
                let stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "timed out accepting IMAP client");
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("accept IMAP client: {error}"),
                    }
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("fixture read timeout");
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .expect("fixture write timeout");
                stream.set_nodelay(true).expect("fixture no-delay writes");
                handle_imap(stream, mode, &command_log, &seen_flags);
            }
        });
        Self {
            port,
            commands,
            provider_seen,
            handle,
        }
    }

    const fn port(&self) -> u16 {
        self.port
    }

    fn seen_flags(&self) -> Vec<u32> {
        self.provider_seen
            .lock()
            .expect("provider seen flags")
            .iter()
            .copied()
            .collect()
    }

    fn command_snapshot(&self) -> Vec<String> {
        self.commands.lock().expect("command log").clone()
    }

    fn join(self) -> Vec<String> {
        self.handle.join().expect("IMAP fixture should join");
        Arc::try_unwrap(self.commands)
            .expect("fixture commands should be uniquely owned")
            .into_inner()
            .expect("commands mutex should not be poisoned")
    }
}

fn handle_imap(
    mut stream: TcpStream,
    mode: ImapMode,
    commands: &Arc<Mutex<Vec<String>>>,
    provider_seen: &Arc<Mutex<BTreeSet<u32>>>,
) {
    write_response(&mut stream, "* OK fcp email generic fixture ready");
    let mut reader = BufReader::new(stream.try_clone().expect("clone IMAP stream"));
    let mut line = String::new();
    let mut read_only = false;
    let mailbox_uids = if matches!(mode, ImapMode::InboundBacklog) {
        (1..=257).collect::<Vec<u32>>()
    } else {
        vec![11, 12, 13]
    };
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => break,
            Err(error) => panic!("read IMAP line: {error}"),
        }
        let command = line.trim_end_matches(['\r', '\n']).to_owned();
        commands
            .lock()
            .expect("commands lock")
            .push(command.clone());
        let tag = command.split_whitespace().next().unwrap_or("zz");

        if command.contains(" LOGIN ") {
            write_response(&mut stream, &format!("{tag} OK LOGIN completed"));
        } else if matches!(mode, ImapMode::Ok) && command.contains("LIST \"\" \"*\"") {
            write_response(&mut stream, "* LIST (\\HasNoChildren) \"/\" \"INBOX\"");
            write_response(&mut stream, "* LIST (\\HasNoChildren) \"/\" \"Archive\"");
            write_response(&mut stream, &format!("{tag} OK LIST completed"));
        } else if command.contains(" EXAMINE ") || command.contains(" SELECT ") {
            read_only = command.contains(" EXAMINE ");
            write_response(&mut stream, &format!("* {} EXISTS", mailbox_uids.len()));
            let epoch = if let ImapMode::InboundEpoch(epoch) = mode {
                epoch
            } else {
                42
            };
            if !matches!(mode, ImapMode::InboundMissingEpoch) {
                write_response(
                    &mut stream,
                    &format!("* OK [UIDVALIDITY {epoch}] stable UID epoch"),
                );
            }
            if matches!(mode, ImapMode::InboundDuplicateEpoch) {
                write_response(&mut stream, "* OK [UIDVALIDITY 42] duplicate epoch");
            }
            let next_uid = mailbox_uids.last().copied().unwrap_or(0).saturating_add(1);
            write_response(&mut stream, &format!("* OK [UIDNEXT {next_uid}] next UID"));
            let access = if read_only { "READ-ONLY" } else { "READ-WRITE" };
            write_response(&mut stream, &format!("{tag} OK [{access}] mailbox opened"));
        } else if matches!(mode, ImapMode::Ok) && command.contains("UID SEARCH TEXT") {
            write_response(&mut stream, "* SEARCH 2 5 8");
            write_response(&mut stream, &format!("{tag} OK SEARCH completed"));
        } else if !matches!(mode, ImapMode::Ok) && command.contains("UID SEARCH UNSEEN") {
            let seen = provider_seen.lock().expect("provider flags");
            let start = command
                .split_whitespace()
                .last()
                .and_then(|word| word.strip_suffix(":*"))
                .map(|value| value.parse::<u32>().expect("UID range"))
                .unwrap_or(0);
            // RFC sequence-set ranges include the highest UID even when the
            // requested start exceeds it. The client must independently filter.
            let lower = start.min(mailbox_uids.last().copied().unwrap_or(0));
            let unseen = mailbox_uids
                .iter()
                .filter(|uid| **uid >= lower && !seen.contains(*uid))
                .map(|uid| uid.to_string())
                .collect::<Vec<_>>()
                .join(" ");
            write_response(&mut stream, &format!("* SEARCH {unseen}"));
            write_response(&mut stream, &format!("{tag} OK SEARCH completed"));
        } else if !matches!(mode, ImapMode::Ok) && command.contains("UID FETCH ") {
            let uid = command
                .split_whitespace()
                .nth(3)
                .expect("FETCH UID")
                .parse::<u32>()
                .expect("numeric FETCH UID");
            if !read_only && !command.contains("BODY.PEEK[]") {
                provider_seen.lock().expect("provider flags").insert(uid);
            }
            let backlog_raw = matches!(mode, ImapMode::InboundBacklog).then(|| {
                format!("From: human@example.com\r\nSubject: message {uid}\r\nMessage-ID: <message-{uid}@example.com>\r\n\r\nmessage {uid}\r\n")
            });
            let raw = backlog_raw.as_deref().unwrap_or_else(|| match uid {
                11 => inbound_allowed_message(),
                12 => inbound_denied_sender_message(),
                13 => inbound_automated_message(),
                _ => panic!("unexpected fixture UID"),
            });
            if uid == 12 {
                match mode {
                    ImapMode::InboundRejectedFetch => {
                        write_response(
                            &mut stream,
                            &format!("{tag} NO FETCH failed; other commands are OK"),
                        );
                        continue;
                    }
                    ImapMode::InboundTruncatedFetch => {
                        write_response(&mut stream, "* 2 FETCH (UID 12 BODY[] {500}");
                        stream.write_all(b"From: partial").expect("partial literal");
                        stream.flush().expect("partial literal flush");
                        return;
                    }
                    ImapMode::InboundOversizedFetch => {
                        write_response(&mut stream, "* 2 FETCH (UID 12 BODY[] {1048577}");
                        continue;
                    }
                    ImapMode::InboundWrongUid => {
                        write_fetch_literal(&mut stream, 2, 999, raw);
                        write_response(&mut stream, &format!("{tag} OK FETCH completed"));
                        continue;
                    }
                    ImapMode::InboundMalformedMessage => {
                        write_fetch_literal(
                            &mut stream,
                            2,
                            uid,
                            "Subject: missing sender\r\n\r\nbody\r\n",
                        );
                        write_response(&mut stream, &format!("{tag} OK FETCH completed"));
                        continue;
                    }
                    ImapMode::InboundMissingTrailer => {
                        write_response(
                            &mut stream,
                            &format!("* 2 FETCH (UID 12 BODY[] {{{}}}", raw.len()),
                        );
                        stream.write_all(raw.as_bytes()).expect("literal body");
                        write_response(&mut stream, &format!("{tag} OK FETCH completed"));
                        continue;
                    }
                    _ => {}
                }
            }
            if matches!(mode, ImapMode::InboundUidAfterLiteral) {
                write_response(&mut stream, &format!("* 1 FETCH (BODY[] {{{}}}", raw.len()));
                stream.write_all(raw.as_bytes()).expect("literal body");
                write_response(&mut stream, &format!(" UID {uid} FLAGS ())"));
            } else {
                let sequence = if matches!(mode, ImapMode::InboundBacklog) {
                    uid
                } else {
                    uid - 10
                };
                write_fetch_literal(&mut stream, sequence, uid, raw);
            }
            write_response(&mut stream, &format!("{tag} OK FETCH completed"));
        } else if command.contains("LOGOUT") {
            write_response(&mut stream, "* BYE fixture closing");
            write_response(&mut stream, &format!("{tag} OK LOGOUT completed"));
            break;
        } else {
            write_response(&mut stream, &format!("{tag} BAD unsupported command"));
        }
    }
}

fn write_fetch_literal(stream: &mut TcpStream, sequence: u32, uid: u32, body: &str) {
    stream
        .write_all(
            format!(
                "* {sequence} FETCH (UID {uid} BODY[] {{{}}}\r\n",
                body.len()
            )
            .as_bytes(),
        )
        .expect("write FETCH literal header");
    stream
        .write_all(body.as_bytes())
        .expect("write FETCH literal body");
    stream
        .write_all(b")\r\n")
        .expect("write FETCH literal terminator");
    stream.flush().expect("flush FETCH literal");
}

const fn inbound_allowed_message() -> &'static str {
    concat!(
        "From: Human <human@example.com>\r\n",
        "Subject: Deploy ready\r\n",
        "Message-ID: <msg-11@example.com>\r\n",
        "In-Reply-To: <parent@example.com>\r\n",
        "References: <root@example.com> <parent@example.com>\r\n",
        "Content-Type: multipart/mixed; boundary=\"mix\"\r\n",
        "\r\n",
        "--mix\r\n",
        "Content-Type: text/plain; charset=utf-8\r\n",
        "\r\n",
        "green\r\n",
        "--mix\r\n",
        "Content-Type: application/pdf; name=\"plan.pdf\"\r\n",
        "Content-Disposition: attachment; filename=\"plan.pdf\"\r\n",
        "Content-Transfer-Encoding: base64\r\n",
        "\r\n",
        "cGxhbg==\r\n",
        "--mix--\r\n",
    )
}

const fn inbound_denied_sender_message() -> &'static str {
    concat!(
        "From: outsider@example.net\r\n",
        "Subject: Should be dropped\r\n",
        "Message-ID: <msg-12@example.net>\r\n",
        "Content-Type: text/plain; charset=utf-8\r\n",
        "\r\n",
        "outside sender\r\n",
    )
}

const fn inbound_automated_message() -> &'static str {
    concat!(
        "From: noreply@example.com\r\n",
        "Subject: Automated notice\r\n",
        "Message-ID: <msg-13@example.com>\r\n",
        "Auto-Submitted: auto-generated\r\n",
        "Content-Type: text/plain; charset=utf-8\r\n",
        "\r\n",
        "robot notice\r\n",
    )
}

#[derive(Clone, Copy)]
enum SmtpMode {
    Accept,
    PermanentFailure,
    StartTlsAdvertised,
}

struct SmtpFixture {
    port: u16,
    commands: Arc<Mutex<Vec<String>>>,
    handle: JoinHandle<()>,
}

impl SmtpFixture {
    fn start(mode: SmtpMode) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind SMTP fixture");
        let port = listener.local_addr().expect("fixture addr").port();
        let commands = Arc::new(Mutex::new(Vec::new()));
        let command_log = Arc::clone(&commands);
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept SMTP client");
            handle_smtp(stream, mode, &command_log);
        });
        Self {
            port,
            commands,
            handle,
        }
    }

    const fn port(&self) -> u16 {
        self.port
    }

    fn join(self) -> Vec<String> {
        self.handle.join().expect("SMTP fixture should join");
        Arc::try_unwrap(self.commands)
            .expect("fixture commands should be uniquely owned")
            .into_inner()
            .expect("commands mutex should not be poisoned")
    }
}

fn handle_smtp(mut stream: TcpStream, mode: SmtpMode, commands: &Arc<Mutex<Vec<String>>>) {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set SMTP fixture read timeout");
    write_response(&mut stream, "220 fcp email generic smtp fixture");
    let mut reader = BufReader::new(stream.try_clone().expect("clone SMTP stream"));
    let mut line = Vec::new();
    loop {
        line.clear();
        match reader.read_until(b'\n', &mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(error) if !line.is_empty() => {
                commands.lock().expect("commands lock").push(format!(
                    "TLS_HANDSHAKE_BYTES_WITHOUT_STARTTLS:{:?}",
                    error.kind()
                ));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => break,
            Err(error) => {
                commands
                    .lock()
                    .expect("commands lock")
                    .push(format!("SMTP_FIXTURE_READ_ERROR:{:?}", error.kind()));
                break;
            }
        }
        if line.starts_with(b"STARTTLS") {
            commands
                .lock()
                .expect("commands lock")
                .push("STARTTLS".to_owned());
            write_response(&mut stream, "220 begin tls");
            break;
        }
        let Ok(decoded) = std::str::from_utf8(&line) else {
            commands
                .lock()
                .expect("commands lock")
                .push("TLS_HANDSHAKE_BYTES_WITHOUT_STARTTLS".to_owned());
            break;
        };
        let command = decoded.trim_end_matches(['\r', '\n']).to_owned();
        commands
            .lock()
            .expect("commands lock")
            .push(command.clone());
        let upper = command.to_ascii_uppercase();

        if upper.starts_with("EHLO") || upper.starts_with("HELO") {
            match mode {
                SmtpMode::StartTlsAdvertised => {
                    write_response(&mut stream, "250-localhost");
                    write_response(&mut stream, "250-STARTTLS");
                    write_response(&mut stream, "250 AUTH PLAIN LOGIN");
                }
                SmtpMode::Accept | SmtpMode::PermanentFailure => {
                    write_response(&mut stream, "250-localhost");
                    write_response(&mut stream, "250 AUTH PLAIN LOGIN");
                }
            }
        } else if upper == "STARTTLS" {
            write_response(&mut stream, "220 begin tls");
            break;
        } else if upper.starts_with("AUTH") {
            write_response(&mut stream, "235 authentication ok");
        } else if upper.starts_with("MAIL FROM:") {
            write_response(&mut stream, "250 sender ok");
        } else if upper.starts_with("RCPT TO:") {
            match mode {
                SmtpMode::PermanentFailure => write_response(&mut stream, "550 no such user"),
                SmtpMode::Accept | SmtpMode::StartTlsAdvertised => {
                    write_response(&mut stream, "250 recipient ok");
                }
            }
        } else if upper == "DATA" {
            write_response(&mut stream, "354 end with dot");
            read_message_data(&mut reader, commands);
            write_response(&mut stream, "250 queued");
        } else if upper == "QUIT" {
            write_response(&mut stream, "221 bye");
            break;
        } else {
            write_response(&mut stream, "250 ok");
        }
    }
}

fn read_message_data(reader: &mut BufReader<TcpStream>, commands: &Arc<Mutex<Vec<String>>>) {
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).expect("read DATA line") == 0 {
            break;
        }
        let data = line.trim_end_matches(['\r', '\n']);
        if data == "." {
            commands
                .lock()
                .expect("commands lock")
                .push("DATA_END".to_owned());
            break;
        }
    }
}

fn write_response(stream: &mut TcpStream, line: &str) {
    stream
        .write_all(format!("{line}\r\n").as_bytes())
        .expect("write fixture response");
    stream.flush().expect("flush fixture response");
}

struct ProofLog<'a> {
    event: &'a str,
    operation: &'a str,
    capability: &'a str,
    zone: &'a str,
    fixture_id: &'a str,
    account_id_hash: String,
    folder_id_hash: String,
    message_id_hash: String,
    sender_policy_decision: &'a str,
    event_topic: &'a str,
    attachment_byte_count: Option<usize>,
    fcp_error_mapping: &'a str,
    lifecycle_phase: &'a str,
    latency_ms: u128,
    result: &'a str,
    error_code: Option<&'a str>,
    retry_decision: &'a str,
    cleanup_result: &'a str,
    skip_reason: Option<&'a str>,
}

fn emit_fixture_log(log: &ProofLog<'_>) {
    let artifact_path =
        std::env::var("EMAIL_GENERIC_FIXTURE_JSONL_ARTIFACT").unwrap_or_else(|_| "stdout".into());
    let payload = json!({
        "log_version": "v1",
        "event": log.event,
        "command": "cargo test -p fcp-email-generic --test integration -- --nocapture",
        "git_revision": option_env!("GIT_COMMIT").unwrap_or("unknown"),
        "connector_id": CONNECTOR_ID,
        "operation_id": log.operation,
        "capability": log.capability,
        "zone": log.zone,
        "instance_id": "redacted",
        "fixture_id": log.fixture_id,
        "account_id_hash": log.account_id_hash,
        "folder_id_hash": log.folder_id_hash,
        "message_id_hash": log.message_id_hash,
        "sender_policy_decision": log.sender_policy_decision,
        "event_topic": log.event_topic,
        "attachment_byte_count": log.attachment_byte_count,
        "retry_decision": log.retry_decision,
        "fcp_error_mapping": log.fcp_error_mapping,
        "lifecycle_phase": log.lifecycle_phase,
        "latency_ms": log.latency_ms,
        "result": log.result,
        "error_code": log.error_code,
        "audit_receipt_id": "not_emitted",
        "artifact_path": artifact_path,
        "cleanup_result": log.cleanup_result,
        "skip_reason": log.skip_reason,
    });
    println!(
        "EMAIL_GENERIC_FIXTURE_JSONL {}",
        serde_json::to_string(&payload).expect("proof log should serialize")
    );
}

fn hash_id(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[..8])
}

fn elapsed_ms(started_at: Instant) -> u128 {
    started_at.elapsed().as_millis()
}
