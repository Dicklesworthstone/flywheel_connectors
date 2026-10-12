//! CLI coverage for `fwc audit chain status --json`.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::process::{Command, Output};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

fn run_fwc(args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fwc"));
    command
        .env_remove("FWC_HOST")
        .env_remove("FCP_HOST_ENDPOINT")
        .env_remove("FCP_HOST_BIND")
        .args(args);
    command.output().expect("fwc process should launch")
}

fn stdout_json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout should be JSON: {error}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn write_json(path: &std::path::Path, value: &Value) {
    std::fs::write(
        path,
        serde_json::to_vec_pretty(value).expect("fixture serializes"),
    )
    .expect("fixture writes");
}

fn spawn_mock_audit_status_host(response: &Value) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("mock host should bind");
    listener
        .set_nonblocking(true)
        .expect("mock host should configure nonblocking accept");
    let endpoint = format!(
        "http://{}",
        listener.local_addr().expect("mock host address")
    );
    let body = serde_json::to_string(&response).expect("mock response serializes");

    let handle = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let (mut stream, _) = match listener.accept() {
                Ok(connection) => connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "mock host timed out waiting for request"
                    );
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(error) => panic!("mock host accept failed: {error}"),
            };

            let mut reader = BufReader::new(stream.try_clone().expect("mock host clones socket"));
            let mut request_line = String::new();
            reader
                .read_line(&mut request_line)
                .expect("mock host reads request line");
            assert!(
                request_line.starts_with("GET /rpc/admin/audit/chain/status?"),
                "unexpected request line: {request_line}"
            );
            assert!(request_line.contains("zone=z%3Awork"));
            assert!(request_line.contains("max_age_seconds=60"));
            assert!(request_line.contains("now_unix_secs=1700000030"));

            loop {
                let mut header = String::new();
                reader
                    .read_line(&mut header)
                    .expect("mock host reads headers");
                if header == "\r\n" || header.is_empty() {
                    break;
                }
            }

            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .expect("mock host writes response");
            break;
        }
    });

    (endpoint, handle)
}

fn journal_durability() -> fcp_host::InvokeAuditDurabilityStatus {
    fcp_host::InvokeAuditDurabilityStatus {
        storage: "local_journal".to_string(),
        durable: true,
        writable: true,
        recovered_entries: 7,
        persisted_entries: 9,
        journal_bytes: 4096,
        max_journal_bytes: 268_435_456,
        max_record_bytes: 65_536,
        max_entries: 262_144,
        unavailable_reason: None,
    }
}

fn fresh_host_status(durability: Option<&fcp_host::InvokeAuditDurabilityStatus>) -> Value {
    let mut response = json!({
        "schema_version": "fcp.host.invoke_audit_chain_status.v1",
        "status": "fresh",
        "telemetry_state": "live-host",
        "source": {
            "kind": "host-invoke-audit-chain",
            "live": true
        },
        "zone_id": "z:work",
        "head_seq": 42,
        "head_entry": "entry-work-head",
        "last_quorum_height": 42,
        "quorum_signed_checkpoints": 1,
        "quorum_signers": 2,
        "quorum_signer_ids": ["node-a", "node-b"],
        "hlc_physical_drift_ms": 30_000,
        "max_age_seconds": 60,
        "live_quorum_checkpoint_snapshot": {
            "available": true,
            "height": 42,
            "signers": ["node-a", "node-b"]
        },
        "warnings": []
    });
    if let Some(durability) = durability {
        response["durability"] = json!(durability);
    }
    response
}

fn run_mock_chain_status(response: &Value, json_output: bool) -> Output {
    let (host, server) = spawn_mock_audit_status_host(response);
    let mut args = vec![
        "--host",
        &host,
        "audit",
        "chain",
        "status",
        "--zone",
        "z:work",
        "--now-unix-secs",
        "1700000030",
        "--max-age-seconds",
        "60",
        "--require-source",
        "any-live",
    ];
    if json_output {
        args.push("--json");
    }
    let output = run_fwc(&args);
    server.join().expect("mock host should complete");
    assert!(
        output.status.success(),
        "fwc failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

#[test]
fn missing_status_is_fail_closed_and_parseable() {
    let output = run_fwc(&["audit", "chain", "status", "--json"]);

    assert!(
        output.status.success(),
        "fwc failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = stdout_json(&output);
    assert_eq!(payload["schema_version"], "fcp.fwc.audit_chain_status.v1");
    assert_eq!(payload["_truth_source"], "offline");
    assert_eq!(payload["command"], "audit");
    assert_eq!(payload["subcommand"], "chain status");
    assert_eq!(payload["status"], "missing");
    assert_eq!(payload["telemetry_state"], "missing");
    assert_eq!(payload["source"]["kind"], "none");
    assert_eq!(payload["source"]["live"], false);
    assert_eq!(payload["quorum_signed_checkpoints"], 0);
    assert_eq!(payload["quorum_signers"], 0);
    assert!(payload["last_quorum_height"].is_null());
    assert_eq!(
        payload["warnings"]
            .as_array()
            .expect("warnings array")
            .len(),
        1
    );
}

#[test]
fn chain_status_text_reports_offline_answer_source_footer() {
    let output = run_fwc(&["audit", "chain", "status"]);

    assert!(
        output.status.success(),
        "fwc failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.ends_with("(answer source: offline)\n"),
        "stdout missing answer source footer:\n{stdout}"
    );
}

#[test]
fn host_backed_status_satisfies_any_live_without_fabricating_quorum() {
    let (host, server) = spawn_mock_audit_status_host(&json!({
        "schema_version": "fcp.host.invoke_audit_chain_status.v1",
        "status": "degraded",
        "telemetry_state": "live-host",
        "source": {
            "kind": "host-invoke-audit-chain",
            "live": true
        },
        "zone_id": "z:work",
        "head_seq": 7,
        "head_entry": "entry-live-head",
        "audit_entries": 8,
        "last_observed_at": 1_700_000_000,
        "quorum_signed_checkpoints": 0,
        "quorum_signers": 0,
        "quorum_signer_ids": [],
        "hlc_physical_drift_ms": 30_000,
        "max_age_seconds": 60,
        "live_quorum_checkpoint_snapshot": {
            "available": false,
            "reason_code": "quorum-checkpoint-telemetry-unwired",
            "detail": "host invoke-chain entries are live, but quorum checkpoint signing is not exposed yet"
        },
        "append_metrics": {
            "entries": 8,
            "optimistic_commits": 8,
            "stale_head_retries": 0,
            "serialized_fallbacks": 0,
            "contention_exhaustions": 0,
            "clock_anomalies": 0
        },
        "warnings": [
            "live host invoke audit chain is available, but quorum-signed checkpoint telemetry is not wired yet"
        ]
    }));

    let output = run_fwc(&[
        "--host",
        &host,
        "audit",
        "chain",
        "status",
        "--zone",
        "z:work",
        "--now-unix-secs",
        "1700000030",
        "--max-age-seconds",
        "60",
        "--require-source",
        "any-live",
        "--json",
    ]);

    server.join().expect("mock host should complete");
    assert!(
        output.status.success(),
        "fwc failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = stdout_json(&output);
    assert_eq!(payload["schema_version"], "fcp.fwc.audit_chain_status.v1");
    assert_eq!(payload["_truth_source"], "host");
    assert_eq!(payload["status"], "degraded");
    assert_eq!(payload["telemetry_state"], "live-host");
    assert_eq!(payload["source"]["kind"], "host-invoke-audit-chain");
    assert_eq!(payload["source"]["live"], true);
    assert_eq!(payload["zone_id"], "z:work");
    assert_eq!(payload["head_seq"], 7);
    assert_eq!(payload["quorum_signed_checkpoints"], 0);
    assert_eq!(payload["quorum_signers"], 0);
    assert_eq!(
        payload["live_quorum_checkpoint_snapshot"]["available"],
        false
    );
}

#[test]
fn doctor_audit_uses_host_status_for_live_truth_requirement() {
    let (host, server) = spawn_mock_audit_status_host(&json!({
        "schema_version": "fcp.host.invoke_audit_chain_status.v1",
        "status": "fresh",
        "telemetry_state": "live-host",
        "source": {
            "kind": "host-invoke-audit-chain",
            "live": true
        },
        "zone_id": "z:work",
        "head_seq": 42,
        "head_entry": "entry-work-head",
        "last_quorum_height": 42,
        "quorum_signed_checkpoints": 1,
        "quorum_signers": 2,
        "quorum_signer_ids": ["node-a", "node-b"],
        "hlc_physical_drift_ms": 30_000,
        "max_age_seconds": 60,
        "live_quorum_checkpoint_snapshot": {
            "available": true,
            "height": 42,
            "signers": ["node-a", "node-b"]
        },
        "warnings": []
    }));

    let output = run_fwc(&[
        "--json",
        "--host",
        &host,
        "doctor",
        "audit",
        "--zone",
        "z:work",
        "--audit-now-unix-secs",
        "1700000030",
        "--audit-max-age-seconds",
        "60",
        "--audit-min-quorum-signers",
        "2",
        "--audit-max-hlc-drift-ms",
        "60000",
        "--require-source",
        "any-live",
    ]);

    server.join().expect("mock host should complete");
    assert!(
        output.status.success(),
        "fwc failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = stdout_json(&output);
    assert_eq!(payload["_truth_source"], "host");
    assert_eq!(payload["status"], "ok");
    assert_eq!(payload["healthy"], true);
    assert_eq!(payload["source"], "host-audit-chain-status");
    assert_eq!(payload["coverage_scope"], "live-host-audit-chain-status");
    assert_eq!(
        payload["report"]["schema_version"],
        "fcp.fwc.doctor.audit.v1"
    );
    assert_eq!(payload["report"]["healthy"], true);
    assert_eq!(
        payload["report"]["coverage_scope"],
        "live-host-audit-chain-status"
    );
    assert_eq!(
        payload["report"]["chain_status"]["telemetry_state"],
        "live-host"
    );
    assert_eq!(
        payload["report"]["chain_status"]["source"]["kind"],
        "host-invoke-audit-chain"
    );
    assert_eq!(payload["report"]["chain_status"]["source"]["live"], true);
    assert_eq!(
        payload["report"]["chain_status"]["quorum_signed_checkpoints"],
        1
    );
    assert_eq!(payload["report"]["chain_status"]["quorum_signers"], 2);
    assert!(
        payload["report"]["commands"][0]
            .as_str()
            .expect("status command string")
            .contains("audit chain status --zone z:work --max-age-seconds 60 --require-source any-live --json")
    );
}

#[test]
fn host_journal_status_preserves_durability_and_validates_its_schema() {
    let durability = journal_durability();
    let response = fresh_host_status(Some(&durability));
    let output = run_mock_chain_status(&response, true);
    let payload = stdout_json(&output);
    assert_eq!(payload["durability"], json!(durability));
    assert_eq!(payload["status"], "fresh");
    assert_eq!(payload["_truth_source"], "host");
    assert_eq!(payload["quorum_signed_checkpoints"], 1);
    assert_eq!(payload["quorum_signers"], 2);

    let schema: Value =
        serde_json::from_str(include_str!("../schemas/audit_chain_status.schema.json"))
            .expect("audit status schema should parse");
    let validator = jsonschema::validator_for(&schema).expect("audit status schema should compile");
    assert!(validator.is_valid(&payload), "invalid status: {payload}");

    let mut missing_limit = payload.clone();
    missing_limit["durability"]
        .as_object_mut()
        .expect("durability object")
        .remove("max_record_bytes");
    assert!(!validator.is_valid(&missing_limit));

    let mut negative_bytes = payload.clone();
    negative_bytes["durability"]["journal_bytes"] = json!(-1);
    assert!(!validator.is_valid(&negative_bytes));

    let mut invented_evidence = payload.clone();
    invented_evidence["durability"]["replicated"] = json!(true);
    assert!(!validator.is_valid(&invented_evidence));

    let mut fenced_but_fresh = payload.clone();
    fenced_but_fresh["durability"]["writable"] = json!(false);
    assert!(!validator.is_valid(&fenced_but_fresh));
    fenced_but_fresh["status"] = json!("degraded");
    assert!(validator.is_valid(&fenced_but_fresh));
    fenced_but_fresh["status"] = json!("stale");
    assert!(validator.is_valid(&fenced_but_fresh));

    let mut inconsistent_admission = payload;
    inconsistent_admission["durability"]["unavailable_reason"] = json!("journal_io_failed");
    assert!(!validator.is_valid(&inconsistent_admission));
    inconsistent_admission["status"] = json!("degraded");
    assert!(validator.is_valid(&inconsistent_admission));
}

#[test]
fn fenced_journal_text_overrides_freshness_and_explains_write_admission() {
    for (writable, unavailable_reason) in [
        (false, Some("journal_io_failed")),
        (false, None),
        (true, Some("journal_io_failed")),
    ] {
        let mut durability = journal_durability();
        durability.writable = writable;
        durability.unavailable_reason = unavailable_reason.map(str::to_string);
        let response = fresh_host_status(Some(&durability));
        let output = run_mock_chain_status(&response, false);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("audit chain status: degraded\n"),
            "{stdout}"
        );
        assert!(
            stdout.contains("host audit storage: local_journal\n"),
            "{stdout}"
        );
        assert!(
            stdout.contains("host audit durability: confirmed\n"),
            "{stdout}"
        );
        assert!(
            stdout.contains("audit write admission: fenced\n"),
            "{stdout}"
        );
        assert!(!stdout.contains("audit chain status: fresh\n"), "{stdout}");
        assert!(
            stdout.contains("host journal entries: 9 persisted, 7 recovered on open\n"),
            "{stdout}"
        );
        assert!(
            stdout.contains("host journal bytes: 4096 / 268435456\n"),
            "{stdout}"
        );
        assert!(
            stdout.contains("host journal limits: 65536 bytes per record, 262144 entries\n"),
            "{stdout}"
        );
        if unavailable_reason.is_some() {
            assert!(
                stdout.contains("audit write fence reason: journal_io_failed\n"),
                "{stdout}"
            );
        } else {
            assert!(stdout.contains("host reported writable=false"), "{stdout}");
        }
    }
}

#[test]
fn doctor_audit_rejects_a_fenced_journal_even_with_fresh_quorum_evidence() {
    let mut durability = journal_durability();
    durability.writable = false;
    durability.unavailable_reason = Some("journal_io_failed".to_string());
    let (host, server) = spawn_mock_audit_status_host(&fresh_host_status(Some(&durability)));
    let output = run_fwc(&[
        "--json",
        "--host",
        &host,
        "doctor",
        "audit",
        "--zone",
        "z:work",
        "--audit-now-unix-secs",
        "1700000030",
        "--audit-max-age-seconds",
        "60",
        "--audit-min-quorum-signers",
        "2",
        "--audit-max-hlc-drift-ms",
        "60000",
        "--require-source",
        "any-live",
    ]);
    server.join().expect("mock host should complete");

    let payload = stdout_json(&output);
    assert_eq!(payload["_truth_source"], "host");
    assert_eq!(payload["healthy"], false);
    assert_eq!(payload["report"]["healthy"], false);
    let chain_status = &payload["report"]["chain_status"];
    assert_eq!(chain_status["status"], "degraded");
    assert_eq!(chain_status["durability"], json!(durability));
    assert_eq!(chain_status["quorum_signed_checkpoints"], 1);
    assert_eq!(chain_status["quorum_signers"], 2);
    let checks = payload["report"]["checks"]
        .as_array()
        .expect("doctor check array");
    let freshness = checks
        .iter()
        .find(|check| check["id"] == "audit_chain_freshness")
        .expect("freshness check");
    assert_eq!(freshness["status"], "fail");
    assert!(
        payload["report"]["warnings"]
            .as_array()
            .expect("warning array")
            .iter()
            .any(|warning| warning
                .as_str()
                .is_some_and(|text| text.contains("journal_io_failed")))
    );
}

#[test]
fn older_hosts_leave_durability_unknown_without_inventing_defaults() {
    let response = fresh_host_status(None);
    let output = run_mock_chain_status(&response, true);
    let payload = stdout_json(&output);
    assert!(payload.get("durability").is_none());
    assert_eq!(payload["status"], "fresh");
    assert_eq!(payload["_truth_source"], "host");
    assert!(
        payload["warnings"]
            .as_array()
            .expect("warning array")
            .iter()
            .any(|warning| warning
                .as_str()
                .is_some_and(|text| text.contains("durability and write admission are unknown")))
    );

    let output = run_mock_chain_status(&response, false);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("host audit persistence: unknown (not reported by host)\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains("audit write admission: unknown\n"),
        "{stdout}"
    );
    assert!(
        !stdout.contains("host audit durability: confirmed\n"),
        "{stdout}"
    );
}

#[test]
fn writable_storage_without_durability_is_reported_separately_from_a_fence() {
    let mut unsupported_journal = journal_durability();
    unsupported_journal.durable = false;
    for durability in [
        fcp_host::InvokeAuditDurabilityStatus::default(),
        unsupported_journal,
    ] {
        let response = fresh_host_status(Some(&durability));
        let output = run_mock_chain_status(&response, true);
        let payload = stdout_json(&output);
        assert_eq!(payload["durability"], json!(durability));
        assert_eq!(payload["status"], "fresh");
        assert!(
            payload["warnings"]
                .as_array()
                .expect("warning array")
                .iter()
                .any(|warning| warning
                    .as_str()
                    .is_some_and(|text| text
                        .contains("does not provide a confirmed crash-durability guarantee")))
        );

        let output = run_mock_chain_status(&response, false);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("host audit durability: not guaranteed\n"),
            "{stdout}"
        );
        assert!(
            stdout.contains("audit write admission: writable\n"),
            "{stdout}"
        );
        assert!(
            !stdout.contains("audit write admission: fenced\n"),
            "{stdout}"
        );
    }
}

#[test]
fn a_fenced_host_keeps_existing_stale_or_missing_chain_status() {
    let mut durability = journal_durability();
    durability.writable = false;
    durability.unavailable_reason = Some("journal_io_failed".to_string());
    for status in ["stale", "missing"] {
        let mut response = fresh_host_status(Some(&durability));
        response["status"] = json!(status);
        if status == "missing" {
            response["head_seq"] = Value::Null;
            response["head_entry"] = Value::Null;
            response["last_quorum_height"] = Value::Null;
            response["quorum_signed_checkpoints"] = json!(0);
            response["quorum_signers"] = json!(0);
            response["quorum_signer_ids"] = json!([]);
            response["live_quorum_checkpoint_snapshot"] = json!({"available": false});
        }
        let output = run_mock_chain_status(&response, true);
        let payload = stdout_json(&output);
        assert_eq!(payload["status"], status);
        assert_eq!(payload["durability"], json!(durability));
        assert_eq!(
            payload["quorum_signed_checkpoints"],
            response["quorum_signed_checkpoints"]
        );
        assert_eq!(payload["quorum_signers"], response["quorum_signers"]);
    }
}

#[test]
fn signed_head_status_derives_quorum_from_attached_signatures() {
    let tempdir = tempfile::tempdir().expect("tempdir creates");
    let head_path = tempdir.path().join("head.json");
    let events_path = tempdir.path().join("events.json");
    write_json(
        &head_path,
        &json!({
            "zone_id": "z:work",
            "head_entry": "entry-work-head",
            "head_seq": 42,
            "coverage": 0.95,
            "epoch_id": "epoch-7",
            "signature_count": 2,
            "signatures": [
                {"issuer_kid": "kid-a", "signature": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                {"issuer_kid": "kid-b", "signature": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
            ]
        }),
    );
    write_json(
        &events_path,
        &json!([
            {
                "id": "entry-work-head",
                "event_type": "audit.checkpoint",
                "severity": "info",
                "actor": "node-a",
                "zone_id": "z:work",
                "seq": 42,
                "occurred_at": 1_700_000_000,
                "hlc": {
                    "physical_ms": 1_700_000_000_123_u64,
                    "logical": 0,
                    "node_id": "node-a"
                }
            }
        ]),
    );

    let output = run_fwc(&[
        "audit",
        "chain",
        "status",
        "--head",
        head_path.to_str().expect("head path UTF-8"),
        "--events",
        events_path.to_str().expect("events path UTF-8"),
        "--now-unix-secs",
        "1700000030",
        "--max-age-seconds",
        "60",
        "--json",
    ]);

    assert!(
        output.status.success(),
        "fwc failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = stdout_json(&output);
    assert_eq!(payload["_truth_source"], "offline");
    assert_eq!(payload["status"], "fresh");
    assert_eq!(payload["telemetry_state"], "artifact");
    assert_eq!(payload["source"]["kind"], "signed-head-artifact");
    assert_eq!(payload["source"]["live"], false);
    assert_eq!(payload["zone_id"], "z:work");
    assert_eq!(payload["head_seq"], 42);
    assert_eq!(payload["last_quorum_height"], 42);
    assert_eq!(payload["quorum_signed_checkpoints"], 1);
    assert_eq!(payload["quorum_signers"], 2);
    assert_eq!(payload["quorum_signer_ids"], json!(["kid-a", "kid-b"]));
    assert_eq!(payload["producer_signature_count"], 2);
    assert_eq!(payload["signature_count_consistent"], true);
    assert_eq!(payload["quorum_freshness_secs"], 30);
    assert_eq!(payload["quorum_rotation_epoch"], "epoch-7");
    assert_eq!(payload["hlc_physical_drift_ms"], 29_877);
    assert_eq!(payload["warnings"], json!([]));
}

#[test]
fn bare_signature_count_does_not_create_quorum() {
    let tempdir = tempfile::tempdir().expect("tempdir creates");
    let head_path = tempdir.path().join("head.json");
    write_json(
        &head_path,
        &json!({
            "zone_id": "z:work",
            "head_entry": "entry-forged",
            "head_seq": 9,
            "coverage": 1.0,
            "epoch_id": "epoch-forged",
            "signature_count": 7
        }),
    );

    let output = run_fwc(&[
        "audit",
        "chain",
        "status",
        "--head",
        head_path.to_str().expect("head path UTF-8"),
        "--json",
    ]);

    assert!(
        output.status.success(),
        "fwc failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = stdout_json(&output);
    assert_eq!(payload["_truth_source"], "offline");
    assert_eq!(payload["status"], "degraded");
    assert_eq!(payload["quorum_signed_checkpoints"], 0);
    assert_eq!(payload["quorum_signers"], 0);
    assert!(payload["last_quorum_height"].is_null());
    assert_eq!(payload["producer_signature_count"], 7);
    assert_eq!(payload["signature_count_consistent"], false);
    let warnings = payload["warnings"].as_array().expect("warnings array");
    assert!(warnings.iter().any(|warning| {
        warning
            .as_str()
            .is_some_and(|text| text.contains("attached signatures"))
    }));
}

#[test]
fn chain_status_require_any_live_fails_with_truth_source_unavailable() {
    let output = run_fwc(&[
        "audit",
        "chain",
        "status",
        "--json",
        "--require-source",
        "any-live",
    ]);

    assert!(
        !output.status.success(),
        "fwc unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = stdout_json(&output);
    assert_eq!(payload["status"], "error");
    assert_eq!(payload["command"], "audit");
    assert_eq!(payload["subcommand"], "chain status");
    assert_eq!(payload["schema_version"], "fcp.fwc.truth-source.v1");
    assert_eq!(payload["_truth_source"], "offline");
    assert_eq!(payload["error"]["type"], "truth-source-unavailable");
    assert_eq!(payload["error"]["required"], "any-live");
    assert_eq!(payload["error"]["actual"], "offline");
}

#[test]
fn audit_verify_json_reports_offline_truth_source() {
    let tempdir = tempfile::tempdir().expect("tempdir creates");
    let events_path = tempdir.path().join("events.jsonl");
    std::fs::write(&events_path, "").expect("events writes");

    let output = run_fwc(&[
        "audit",
        "verify",
        "--events",
        events_path.to_str().expect("events path UTF-8"),
        "--json",
    ]);

    assert!(
        output.status.success(),
        "fwc failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = stdout_json(&output);
    assert_eq!(payload["schema_version"], "fcp.fwc.audit_verify.v1");
    assert_eq!(payload["_truth_source"], "offline");
    assert_eq!(payload["status"], "warn");
    assert_eq!(payload["chain_len"], 0);
    assert_eq!(payload["issues"][0]["code"], "audit.chain.empty");
}

#[test]
fn audit_verify_text_reports_offline_answer_source_footer() {
    let tempdir = tempfile::tempdir().expect("tempdir creates");
    let events_path = tempdir.path().join("events.jsonl");
    std::fs::write(&events_path, "").expect("events writes");

    let output = run_fwc(&[
        "audit",
        "verify",
        "--events",
        events_path.to_str().expect("events path UTF-8"),
    ]);

    assert!(
        output.status.success(),
        "fwc failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.ends_with("(answer source: offline)\n"),
        "stdout missing answer source footer:\n{stdout}"
    );
}

#[test]
fn audit_verify_require_any_live_fails_with_truth_source_unavailable() {
    let tempdir = tempfile::tempdir().expect("tempdir creates");
    let events_path = tempdir.path().join("events.jsonl");
    std::fs::write(&events_path, "").expect("events writes");

    let output = run_fwc(&[
        "audit",
        "verify",
        "--events",
        events_path.to_str().expect("events path UTF-8"),
        "--json",
        "--require-source",
        "any-live",
    ]);

    assert!(
        !output.status.success(),
        "fwc unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = stdout_json(&output);
    assert_eq!(payload["status"], "error");
    assert_eq!(payload["command"], "audit");
    assert_eq!(payload["subcommand"], "verify");
    assert_eq!(payload["schema_version"], "fcp.fwc.truth-source.v1");
    assert_eq!(payload["_truth_source"], "offline");
    assert_eq!(payload["error"]["type"], "truth-source-unavailable");
    assert_eq!(payload["error"]["required"], "any-live");
    assert_eq!(payload["error"]["actual"], "offline");
}
