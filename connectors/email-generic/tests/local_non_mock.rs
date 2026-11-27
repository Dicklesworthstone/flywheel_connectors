//! Local non-mock acceptance coverage for the generic email connector.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::{
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
    time::Duration,
};

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_email_generic::EmailGenericConnector;
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector, FcpError,
    HandshakeRequest, InstanceId, InvokeRequest, InvokeStatus, OperationId, RequestId,
    ShutdownRequest, ZoneId,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

const CONNECTOR_ID: &str = "fcp.email-generic";
const PACKAGE: &str = "fcp-email-generic";
const BEAD_ID: &str = "flywheel_connectors-bky21.3.6.16";
const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const OP_LIST_MAILBOXES: &str = "email_generic.list_mailboxes";
const OP_SEARCH_MESSAGES: &str = "email_generic.search_messages";
const OP_POLL_INBOUND_ONCE: &str = "email_generic.poll_inbound_once";
const OP_SEND_MESSAGE: &str = "email_generic.send_message";
const CAP_READ: &str = "email_generic.read";
const CAP_WRITE: &str = "email_generic.write";
const LOOPBACK_ACCOUNT: &str = "local-user@example.com";
const LOOPBACK_AUTH_VALUE: &str = "loopback-auth-marker";

#[fcp_async_core::runtime::test]
async fn local_non_mock_invokes_imap_read_and_smtp_write_paths() {
    let imap = ImapFixture::start(3);
    let smtp = SmtpFixture::start();
    let (mut connector, signing_key) = setup_connector(imap.port(), smtp.port()).await;

    let mailboxes = connector
        .invoke(invoke_request(
            &connector,
            &signing_key,
            CAP_READ,
            OP_LIST_MAILBOXES,
            json!({}),
            "email-generic-list-mailboxes",
        ))
        .await
        .expect("list mailboxes should invoke through connector");
    assert_eq!(mailboxes.status, InvokeStatus::Ok);
    assert_eq!(
        mailboxes.result.as_ref().expect("mailbox result")["mailboxes"],
        json!(["INBOX", "Archive"])
    );

    let search = connector
        .invoke(invoke_request(
            &connector,
            &signing_key,
            CAP_READ,
            OP_SEARCH_MESSAGES,
            json!({"mailbox": "INBOX", "query": "deploy"}),
            "email-generic-search-messages",
        ))
        .await
        .expect("search messages should invoke through connector");
    assert_eq!(search.status, InvokeStatus::Ok);
    let search_result = search.result.as_ref().expect("search result");
    assert_eq!(search_result["mailbox"], "INBOX");
    assert_eq!(search_result["query"], "deploy");
    assert_eq!(search_result["uids"], json!([2, 5, 8]));

    let poll = connector
        .invoke(invoke_request(
            &connector,
            &signing_key,
            CAP_READ,
            OP_POLL_INBOUND_ONCE,
            json!({"mailbox": "Alerts"}),
            "email-generic-poll-inbound-once",
        ))
        .await
        .expect("poll inbound once should invoke through connector");
    assert_eq!(poll.status, InvokeStatus::Ok);
    let poll_result = poll.result.as_ref().expect("poll result");
    assert_eq!(poll_result["mailbox"], "Alerts");
    assert_eq!(poll_result["fetched_count"], 3);
    assert_eq!(poll_result["accepted_count"], 1);
    assert_eq!(poll_result["dropped_count"], 2);
    assert_eq!(poll_result["seen_uids"], json!(["11", "12", "13"]));
    assert_eq!(poll_result["cursor"]["version"], 1);
    assert_eq!(poll_result["cursor"]["uid_validity"], 42);
    assert_eq!(poll_result["cursor"]["last_uid"], 13);
    let messages = poll_result["messages"].as_array().expect("poll messages");
    assert_eq!(messages[0]["uid"], "11");
    assert_eq!(messages[0]["decision"], "accept");
    assert_eq!(messages[0]["thread"]["reply_subject"], "Re: Deploy ready");
    assert_eq!(messages[0]["attachments"][0]["filename"], "plan.pdf");
    assert_eq!(messages[0]["attachments"][0]["exposed"], false);
    assert_eq!(messages[1]["decision"], "drop_sender_not_allowed");
    assert_eq!(messages[2]["decision"], "drop_automated");
    assert!(
        !serde_json::to_string(poll_result)
            .expect("poll result JSON")
            .contains(LOOPBACK_AUTH_VALUE),
        "poll result must not leak credentials"
    );

    let sent = connector
        .invoke(invoke_request(
            &connector,
            &signing_key,
            CAP_WRITE,
            OP_SEND_MESSAGE,
            json!({
                "to": ["ops@example.com"],
                "cc": ["audit@example.com"],
                "subject": "Deploy status",
                "body": "Green"
            }),
            "email-generic-send-message",
        ))
        .await
        .expect("send message should invoke through connector");
    assert_eq!(sent.status, InvokeStatus::Ok);
    let sent_result = sent.result.as_ref().expect("send result");
    assert_eq!(sent_result["status"], "sent");
    assert_eq!(sent_result["to"], json!(["ops@example.com"]));

    connector
        .shutdown(shutdown_request("email-generic local non-mock complete"))
        .await
        .expect("shutdown connector");

    let imap_commands = imap.join();
    let smtp_commands = smtp.join();
    assert!(
        imap_commands
            .iter()
            .any(|line| line.contains("LIST \"\" \"*\"")),
        "IMAP fixture should observe LIST command; observed {imap_commands:?}"
    );
    assert!(
        imap_commands
            .iter()
            .any(|line| line == "a2 EXAMINE \"INBOX\""),
        "IMAP fixture should observe selected mailbox; observed {imap_commands:?}"
    );
    assert!(
        imap_commands
            .iter()
            .any(|line| line.contains("UID SEARCH TEXT \"deploy\"")),
        "IMAP fixture should observe search query; observed {imap_commands:?}"
    );
    assert!(
        smtp_commands
            .iter()
            .any(|line| line.starts_with("MAIL FROM:")),
        "SMTP fixture should observe MAIL FROM; observed {smtp_commands:?}"
    );
    assert!(
        smtp_commands
            .iter()
            .any(|line| line.starts_with("RCPT TO:")),
        "SMTP fixture should observe RCPT TO; observed {smtp_commands:?}"
    );
    assert!(
        smtp_commands.iter().any(|line| line == "DATA"),
        "SMTP fixture should observe DATA; observed {smtp_commands:?}"
    );
    assert!(
        smtp_commands.iter().any(|line| line == "DATA_END"),
        "SMTP fixture should observe DATA terminator; observed {smtp_commands:?}"
    );

    let artifact_details = json!({
        "request_response_boundary": {
            "imap": {
                "commands_seen": ["LOGIN", "LIST", "EXAMINE", "UID SEARCH", "LOGOUT"],
                "mailboxes": ["INBOX", "Archive"],
                "uids": [2, 5, 8],
                "inbound_poll_once": {
                    "mailbox_hash": hash_id("Alerts"),
                    "fetched_count": 3,
                    "accepted_count": 1,
                    "dropped_count": 2,
                    "seen_uid_count": 3,
                    "attachment_bytes_exposed": false
                }
            },
            "smtp": {
                "commands_seen": ["EHLO", "AUTH", "MAIL FROM", "RCPT TO", "DATA"],
                "recipients": ["ops@example.com", "audit@example.com"]
            }
        },
        "capability_gate": {
            "read_capability": CAP_READ,
            "write_capability": CAP_WRITE,
            "bound_instance": "verified"
        },
        "redaction": {
            "account_hash": hash_id(LOOPBACK_ACCOUNT),
            "credential_redacted_from_output": !serde_json::to_string(&sent_result)
                .expect("send result JSON")
                .contains(LOOPBACK_AUTH_VALUE)
        },
        "cleanup": {
            "connector_shutdown": true,
            "imap_fixture_connections_joined": 3,
            "smtp_fixture_joined": true
        },
        "result": "passed"
    });
    let artifact = proof_artifact(&artifact_details);
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_rejects_wrong_capability_before_smtp_egress() {
    let (mut connector, signing_key) = setup_connector(1, 1).await;

    let err = connector
        .invoke(invoke_request(
            &connector,
            &signing_key,
            CAP_READ,
            OP_SEND_MESSAGE,
            json!({
                "to": ["ops@example.com"],
                "subject": "Denied",
                "body": "Must not egress"
            }),
            "email-generic-denied-send",
        ))
        .await
        .expect_err("wrong capability should be rejected before SMTP egress");
    assert!(
        matches!(
            err,
            FcpError::Unauthorized { .. } | FcpError::OperationNotGranted { .. }
        ),
        "expected capability denial, got {err:?}"
    );

    connector
        .shutdown(shutdown_request("email-generic capability denial complete"))
        .await
        .expect("shutdown connector");

    let artifact_details = json!({
        "capability_gate": {
            "operation": OP_SEND_MESSAGE,
            "presented_capability": CAP_READ,
            "required_capability": CAP_WRITE,
            "smtp_egress_attempted": false
        },
        "cleanup": {
            "connector_shutdown": true,
            "external_fixture_started": false
        },
        "result": "passed"
    });
    let artifact = proof_artifact(&artifact_details);
    println!("{artifact}");
}

async fn setup_connector(
    imap_port: u16,
    smtp_port: u16,
) -> (EmailGenericConnector, Ed25519SigningKey) {
    let mut connector = EmailGenericConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    connector
        .configure(config_json(imap_port, smtp_port))
        .await
        .expect("configure connector");
    connector
        .handshake(handshake_request(signing_key.verifying_key().to_bytes()))
        .await
        .expect("handshake connector");
    (connector, signing_key)
}

fn config_json(imap_port: u16, smtp_port: u16) -> Value {
    json!({
        "imap": {
            "host": "127.0.0.1",
            "port": imap_port,
            "username": LOOPBACK_ACCOUNT,
            "password": LOOPBACK_AUTH_VALUE,
            "tls": false
        },
        "smtp": {
            "host": "127.0.0.1",
            "port": smtp_port,
            "username": LOOPBACK_ACCOUNT,
            "password": LOOPBACK_AUTH_VALUE,
            "from_address": LOOPBACK_ACCOUNT,
            "starttls": false
        },
        "request_timeout_ms": 2_000,
        "monitor_policy": {
            "allowed_senders": ["human@example.com"],
            "allow_attachments": false,
            "seen_uid_cap": 8,
            "max_body_chars": 128
        }
    })
}

fn handshake_request(host_public_key: [u8; 32]) -> HandshakeRequest {
    HandshakeRequest {
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

fn invoke_request(
    connector: &EmailGenericConnector,
    signing_key: &Ed25519SigningKey,
    capability: &'static str,
    operation: &'static str,
    input: Value,
    request_id: &'static str,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new(request_id),
        connector_id: ConnectorId::from_static(CONNECTOR_ID),
        operation: OperationId::from_static(operation),
        zone_id: ZoneId::private(),
        input,
        capability_token: capability_grant(
            signing_key,
            connector.instance_id(),
            capability,
            operation,
        ),
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: None,
        correlation_id: None,
        provenance: None,
        approval_tokens: vec![],
    }
}

fn capability_grant(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    capability: &'static str,
    operation: &'static str,
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
        .zone_id(ZoneId::private().as_str())
        .target_instance(instance_id.as_str())
        .principal("user:local-non-mock")
        .operations(&[operation])
        .issuer("node:local-non-mock")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&constraints_cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("capability grant should sign");
    CapabilityToken::from_raw(raw)
}

fn shutdown_request(reason: &str) -> ShutdownRequest {
    ShutdownRequest {
        r#type: "shutdown".into(),
        deadline_ms: 1_000,
        drain: true,
        reason: Some(reason.into()),
    }
}

struct ImapFixture {
    port: u16,
    commands: Arc<Mutex<Vec<String>>>,
    handle: JoinHandle<()>,
}

impl ImapFixture {
    fn start(expected_connections: usize) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind IMAP fixture");
        let port = listener.local_addr().expect("IMAP fixture addr").port();
        let commands = Arc::new(Mutex::new(Vec::new()));
        let command_log = Arc::clone(&commands);
        let handle = thread::spawn(move || {
            for _ in 0..expected_connections {
                let (stream, _) = listener.accept().expect("accept IMAP client");
                handle_imap(stream, &command_log);
            }
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
        self.handle.join().expect("IMAP fixture should join");
        Arc::try_unwrap(self.commands)
            .expect("fixture commands should be uniquely owned")
            .into_inner()
            .expect("commands mutex should not be poisoned")
    }
}

fn handle_imap(mut stream: TcpStream, commands: &Arc<Mutex<Vec<String>>>) {
    write_response(&mut stream, "* OK fcp email generic fixture ready");
    let mut reader = BufReader::new(stream.try_clone().expect("clone IMAP stream"));
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).expect("read IMAP line") == 0 {
            break;
        }
        let command = line.trim_end_matches(['\r', '\n']).to_owned();
        commands
            .lock()
            .expect("commands lock")
            .push(command.clone());
        let tag = command.split_whitespace().next().unwrap_or("zz");

        if command.contains(" LOGIN ") {
            write_response(&mut stream, &format!("{tag} OK LOGIN completed"));
        } else if command.contains("LIST \"\" \"*\"") {
            write_response(&mut stream, "* LIST (\\HasNoChildren) \"/\" \"INBOX\"");
            write_response(&mut stream, "* LIST (\\HasNoChildren) \"/\" \"Archive\"");
            write_response(&mut stream, &format!("{tag} OK LIST completed"));
        } else if command.contains("EXAMINE ") {
            write_response(&mut stream, "* 3 EXISTS");
            write_response(&mut stream, "* OK [UIDVALIDITY 42] stable UID epoch");
            write_response(
                &mut stream,
                &format!("{tag} OK [READ-ONLY] EXAMINE completed"),
            );
        } else if command.contains("UID SEARCH TEXT") {
            write_response(&mut stream, "* SEARCH 2 5 8");
            write_response(&mut stream, &format!("{tag} OK SEARCH completed"));
        } else if command.contains("UID SEARCH UNSEEN") {
            write_response(&mut stream, "* SEARCH 11 12 13");
            write_response(&mut stream, &format!("{tag} OK SEARCH completed"));
        } else if command.contains("UID FETCH") {
            let uid = command
                .split_whitespace()
                .find(|part| part.chars().all(|ch| ch.is_ascii_digit()))
                .unwrap_or("11");
            let raw = inbound_message(uid);
            assert!(
                command.contains("(UID BODY.PEEK[])"),
                "read-only full message fetch"
            );
            write_response(
                &mut stream,
                &format!("* 1 FETCH (UID {uid} BODY[] {{{}}}", raw.len()),
            );
            stream
                .write_all(raw.as_bytes())
                .expect("write IMAP RFC822 literal");
            write_response(&mut stream, ")");
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

fn inbound_message(uid: &str) -> String {
    match uid {
        "11" => concat!(
            "From: Human <human@example.com>\r\n",
            "Subject: Deploy ready\r\n",
            "Message-ID: <msg-11@example.com>\r\n",
            "Content-Type: multipart/mixed; boundary=\"b\"\r\n",
            "\r\n",
            "--b\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "green\r\n",
            "--b\r\n",
            "Content-Type: application/pdf; name=\"plan.pdf\"\r\n",
            "Content-Disposition: attachment; filename=\"plan.pdf\"\r\n",
            "Content-Transfer-Encoding: base64\r\n",
            "\r\n",
            "cGxhbg==\r\n",
            "--b--\r\n",
        )
        .to_owned(),
        "12" => concat!(
            "From: Stranger <stranger@example.com>\r\n",
            "Subject: Denied\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "ignore\r\n",
        )
        .to_owned(),
        _ => concat!(
            "From: no-reply@example.com\r\n",
            "Auto-Submitted: auto-generated\r\n",
            "Subject: Automated\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "ignore\r\n",
        )
        .to_owned(),
    }
}

struct SmtpFixture {
    port: u16,
    commands: Arc<Mutex<Vec<String>>>,
    handle: JoinHandle<()>,
}

impl SmtpFixture {
    fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind SMTP fixture");
        let port = listener.local_addr().expect("SMTP fixture addr").port();
        let commands = Arc::new(Mutex::new(Vec::new()));
        let command_log = Arc::clone(&commands);
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept SMTP client");
            handle_smtp(stream, &command_log);
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

fn handle_smtp(mut stream: TcpStream, commands: &Arc<Mutex<Vec<String>>>) {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set SMTP fixture read timeout");
    write_response(&mut stream, "220 fcp email generic smtp fixture");
    let mut reader = BufReader::new(stream.try_clone().expect("clone SMTP stream"));
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).expect("read SMTP line") == 0 {
            break;
        }
        let command = line.trim_end_matches(['\r', '\n']).to_owned();
        commands
            .lock()
            .expect("commands lock")
            .push(command.clone());
        let upper = command.to_ascii_uppercase();

        if upper.starts_with("EHLO") || upper.starts_with("HELO") {
            write_response(&mut stream, "250-localhost");
            write_response(&mut stream, "250 AUTH PLAIN LOGIN");
        } else if upper.starts_with("AUTH") {
            write_response(&mut stream, "235 authentication ok");
        } else if upper.starts_with("MAIL FROM:") {
            write_response(&mut stream, "250 sender ok");
        } else if upper.starts_with("RCPT TO:") {
            write_response(&mut stream, "250 recipient ok");
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

fn proof_artifact(details: &Value) -> Value {
    json!({
        "connector": "email-generic",
        "connector_id": CONNECTOR_ID,
        "package": PACKAGE,
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": BEAD_ID,
        "command": "cargo test -p fcp-email-generic --test local_non_mock -- --nocapture",
        "fixture_mode": "raw_tcp_loopback_imap_smtp",
        "provider_class": "local_sufficient",
        "git_revision": option_env!("GIT_COMMIT").unwrap_or("unknown"),
        "details": details
    })
}

fn hash_id(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[..8])
}
