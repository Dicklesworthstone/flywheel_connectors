//! End-to-end verification of `fwc` truth-source classification (`_truth_source`,
//! `schema_version`, degraded text footers, and `simulate` non-authoritative marker)
//! for `flywheel_connectors-hr0rr.2.5`.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Output};
use std::thread;
use std::time::{Duration, Instant};

use fwc::truth::{
    KnowledgeState, LiveTruthResolver, QueryResult, ResolutionStrategy, ResolverConfig,
    TRUTH_SOURCE_SCHEMA_VERSION,
};
use serde_json::{Value, json};

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
}

fn run_fwc(args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fwc"));
    command
        .current_dir(repo_root())
        .env_remove("FWC_HOST")
        .env_remove("FCP_HOST_ENDPOINT")
        .env_remove("FCP_HOST_BIND")
        .env_remove("FWC_TEST_FORCE_RESOLVER_INTERNAL_ERROR")
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

fn spawn_mock_audit_status_host(response: &Value) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("mock host should bind");
    listener
        .set_nonblocking(true)
        .expect("mock host should configure nonblocking accept");
    let endpoint = format!(
        "http://{}",
        listener.local_addr().expect("mock host address")
    );
    let body = serde_json::to_string(response).expect("mock response serializes");

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

#[test]
fn read_only_commands_emit_truth_source_and_schema_version_in_json() {
    let cases: &[(&[&str], &str, &str)] = &[
        (
            &["--json", "list", "--offline"],
            "offline",
            TRUTH_SOURCE_SCHEMA_VERSION,
        ),
        (
            &["--json", "show", "github", "--offline"],
            "offline",
            TRUTH_SOURCE_SCHEMA_VERSION,
        ),
        (
            &["--json", "search", "github", "--offline"],
            "offline",
            TRUTH_SOURCE_SCHEMA_VERSION,
        ),
        (
            &["--json", "schema", "github", "--offline"],
            "offline",
            TRUTH_SOURCE_SCHEMA_VERSION,
        ),
        (
            &["--json", "context", "current"],
            "node-local",
            TRUTH_SOURCE_SCHEMA_VERSION,
        ),
        (
            &["--json", "history"],
            "offline",
            TRUTH_SOURCE_SCHEMA_VERSION,
        ),
        (
            &["--json", "mesh", "explain-availability", "github"],
            "offline",
            TRUTH_SOURCE_SCHEMA_VERSION,
        ),
        (
            &[
                "--json",
                "connector",
                "state",
                "explain",
                "--connector",
                "github",
                "--offline",
            ],
            "offline",
            "1.0.0",
        ),
        (
            &[
                "--json",
                "connector",
                "lease",
                "status",
                "--connector",
                "github",
                "--offline",
            ],
            "offline",
            "1.0.0",
        ),
        (
            &["--json", "status"],
            "offline",
            TRUTH_SOURCE_SCHEMA_VERSION,
        ),
        (
            &["--json", "doctor", "--zone", "z:work"],
            "offline",
            TRUTH_SOURCE_SCHEMA_VERSION,
        ),
        (
            &["audit", "chain", "status", "--zone", "z:work", "--json"],
            "offline",
            "fcp.fwc.audit_chain_status.v1",
        ),
    ];

    for (args, expected_source, expected_schema_version) in cases {
        let output = run_fwc(args);
        let payload = stdout_json(&output);
        assert_eq!(
            payload["schema_version"].as_str(),
            Some(*expected_schema_version),
            "command {args:?} must stamp schema_version={expected_schema_version}"
        );
        assert_eq!(
            payload["_truth_source"].as_str(),
            Some(*expected_source),
            "command {args:?} must stamp _truth_source={expected_source}"
        );
    }
}

#[test]
fn host_backed_audit_chain_status_stamps_host_truth_source() {
    let host_payload = json!({
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
    let (endpoint, handle) = spawn_mock_audit_status_host(&host_payload);

    let output = run_fwc(&[
        "--host",
        &endpoint,
        "audit",
        "chain",
        "status",
        "--zone",
        "z:work",
        "--max-age-seconds",
        "60",
        "--now-unix-secs",
        "1700000030",
        "--require-source",
        "any-live",
        "--json",
    ]);
    handle.join().expect("mock host thread completes");

    assert!(output.status.success(), "host-backed audit status succeeds");
    let payload = stdout_json(&output);
    assert_eq!(payload["schema_version"], "fcp.fwc.audit_chain_status.v1");
    assert_eq!(payload["_truth_source"], "host");
}

#[test]
fn degraded_text_mode_emits_answer_source_footer_when_not_mesh() {
    let offline_list = run_fwc(&["list", "--offline"]);
    assert!(offline_list.status.success());
    let list_stdout = String::from_utf8_lossy(&offline_list.stdout);
    assert!(
        list_stdout.ends_with("(answer source: offline)\n"),
        "expected `(answer source: offline)` footer, got:\n{list_stdout}"
    );

    let context_current = run_fwc(&["context", "current"]);
    assert!(context_current.status.success());
    let ctx_stdout = String::from_utf8_lossy(&context_current.stdout);
    assert!(
        ctx_stdout.ends_with("(answer source: node-local)\n"),
        "expected `(answer source: node-local)` footer, got:\n{ctx_stdout}"
    );
}

#[test]
fn live_truth_resolver_mesh_vs_host_vs_node_local_vs_offline_classification() {
    let resolver = LiveTruthResolver::new(ResolverConfig::default().with_mesh_backed(true));

    // 1. MeshBacked wins when healthy mesh is available.
    let mesh_res = resolver
        .resolve_with_partials(ResolutionStrategy::BestAvailable, |source| match source {
            KnowledgeState::MeshBacked => QueryResult::Complete("mesh-answer"),
            KnowledgeState::HostBacked => QueryResult::Complete("host-answer"),
            _ => QueryResult::NotConfigured,
        })
        .expect("mesh resolution succeeds");
    assert_eq!(mesh_res.knowledge_state, KnowledgeState::MeshBacked);
    assert_eq!(mesh_res.knowledge_state.operator_truth_source(), "mesh");
    assert!(!mesh_res.trace.used_fallback);

    // 2. HostBacked wins when mesh is unavailable.
    let host_res = resolver
        .resolve_with_partials(ResolutionStrategy::BestAvailable, |source| match source {
            KnowledgeState::MeshBacked => QueryResult::Unavailable("no mesh quorum".into()),
            KnowledgeState::HostBacked => QueryResult::Complete("host-answer"),
            _ => QueryResult::NotConfigured,
        })
        .expect("host fallback resolution succeeds");
    assert_eq!(host_res.knowledge_state, KnowledgeState::HostBacked);
    assert_eq!(host_res.knowledge_state.operator_truth_source(), "host");
    assert!(host_res.trace.used_fallback);

    // 3. NodeLocal wins when live sources are unavailable.
    let local_res = resolver
        .resolve_with_partials(ResolutionStrategy::NodeLocalOnly, |source| match source {
            KnowledgeState::NodeLocal => QueryResult::Complete("node-local-answer"),
            _ => QueryResult::NotConfigured,
        })
        .expect("node-local resolution succeeds");
    assert_eq!(local_res.knowledge_state, KnowledgeState::NodeLocal);
    assert_eq!(
        local_res.knowledge_state.operator_truth_source(),
        "node-local"
    );

    // 4. Offline wins under OfflineOnly.
    let offline_res = resolver
        .resolve_with_partials(ResolutionStrategy::OfflineOnly, |source| match source {
            KnowledgeState::Offline => QueryResult::Complete("offline-answer"),
            _ => QueryResult::NotConfigured,
        })
        .expect("offline resolution succeeds");
    assert_eq!(offline_res.knowledge_state, KnowledgeState::Offline);
    assert_eq!(
        offline_res.knowledge_state.operator_truth_source(),
        "offline"
    );
}
