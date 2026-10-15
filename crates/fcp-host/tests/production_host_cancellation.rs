//! Release-blocker #59: production routing and native cancellation regressions.
//!
//! Run with `cargo test --locked -p fcp-host --test production_host_cancellation`.
//! Linux process tests adapt the reproduction posted on issue #59, using the
//! production host and the existing native fcp-test-connector, not a mock runner.

use std::time::Duration;

use fcp_core::TailscaleNodeId;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_host::mesh_routing::{MeshRouter, MeshRoutingSettings};
use serde_json::json;

/// Check the actual public future, including the production HTTP fetch closure.
/// A synthetic PeerDiscovery fetch alone does not check this composition.
#[test]
fn production_mesh_advertisement_future_is_send() {
    fn assert_send<T: Send>(_: T) {}

    let local_key = Ed25519SigningKey::generate();
    let peer_key = Ed25519SigningKey::generate();
    let router = MeshRouter::new(MeshRoutingSettings {
        node_id: TailscaleNodeId::new("issue-59-local"),
        signing_key: local_key,
        peers_json: json!([{
            "node_id": "issue-59-peer",
            "endpoint": "http://127.0.0.1:1",
            "public_key_hex": hex::encode(peer_key.verifying_key().to_bytes()),
        }])
        .to_string(),
        forward_timeout: Duration::from_secs(1),
    })
    .expect("valid mesh routing settings");

    // Construct but never poll: this compile-time contract needs no peer server.
    assert_send(router.peer_advertisements());
}

#[cfg(target_os = "linux")]
mod native {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use std::io;
    use std::net::TcpListener;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::Instant;

    use chrono::Utc;
    use fcp_core::{
        CapabilityConstraints, CapabilityToken, CorrelationId, DecisionReceiptPolicy,
        ObjectEncryptionKind, ObjectHeader, Provenance, ZoneId, ZonePolicyObject,
        ZoneTransportPolicy,
    };
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_host::{
        CancelReason, CancellationRequest, CancellationResponse, CleanupBehavior,
        ConnectorConfigApplyRequest, ConnectorConfigApplyResponse,
    };
    use fcp_kernel::{ConnectorId, InvokeRequest, InvokeResponse, InvokeStatus, OperationId, RequestId};
    use serde::de::DeserializeOwned;
    use serde_json::Value;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    const PRINCIPAL: &str = "agent:test";
    const ADMIN_TOKEN: &str = "issue-59-test-admin";
    const DEADLINE_MS: u64 = 500;
    // Preserve the posted regression's deadline, one 200 ms reaper sweep,
    // and 300 ms scheduling allowance. Do not expand this to the RPC timeout.
    const KILL_BUDGET: Duration = Duration::from_millis(DEADLINE_MS + 200 + 300);
    const BLOCK_MS: u64 = 600_000;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct ProcessIdentity {
        pid: u32,
        start_ticks: u64,
    }

    #[derive(Debug)]
    struct ProcessSnapshot {
        identity: ProcessIdentity,
        state: u8,
    }

    impl ProcessSnapshot {
        fn is_live_incarnation(&self, expected: ProcessIdentity) -> bool {
            self.identity == expected && !matches!(self.state, b'Z' | b'X' | b'x')
        }
    }

    fn parse_process_stat(text: &str) -> io::Result<ProcessSnapshot> {
        let invalid = || io::Error::new(io::ErrorKind::InvalidData, "malformed process stat");
        let (pid, _) = text.split_once(" (").ok_or_else(invalid)?;
        let pid = pid.parse::<u32>().map_err(|_| invalid())?;
        if pid == 0 {
            return Err(invalid());
        }
        // comm can contain spaces and parentheses. State is field 3, after
        // the LAST closing parenthesis; starttime is field 22 (index 19 here).
        let (_, suffix) = text.rsplit_once(") ").ok_or_else(invalid)?;
        let fields: Vec<_> = suffix.split_whitespace().collect();
        if fields.len() < 20 || fields[0].len() != 1 {
            return Err(invalid());
        }
        Ok(ProcessSnapshot {
            identity: ProcessIdentity {
                pid,
                start_ticks: fields[19].parse().map_err(|_| invalid())?,
            },
            state: fields[0].as_bytes()[0],
        })
    }

    impl ProcessIdentity {
        fn is_alive(self) -> io::Result<bool> {
            match fs::read_to_string(format!("/proc/{}/stat", self.pid)) {
                Ok(text) => {
                    let process = parse_process_stat(&text)?;
                    if process.identity.pid != self.pid {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "PID mismatch"));
                    }
                    Ok(process.is_live_incarnation(self))
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
                // A failed probe is never evidence of successful termination.
                Err(error) => Err(error),
            }
        }
    }

    fn spawn_history(path: &Path) -> io::Result<Vec<ProcessIdentity>> {
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        // Ignore a concurrently appended incomplete final record.
        let complete = text.rfind('\n').map_or("", |last| &text[..=last]);
        complete
            .lines()
            .map(|line| parse_process_stat(line).map(|process| process.identity))
            .collect()
    }

    struct ProductionHost {
        child: Child,
        base_url: String,
        client: reqwest::Client,
        history: PathBuf,
        marker: PathBuf,
        stderr: PathBuf,
        _root: tempfile::TempDir,
    }

    impl ProductionHost {
        async fn spawn(connector_id: &ConnectorId, key: &Ed25519SigningKey) -> TestResult<Self> {
            let root = tempfile::tempdir()?;
            let history = root.path().join("connector-spawns.stat");
            let marker = root.path().join("invoke-started.json");
            let wrapper = root.path().join("connector-wrapper.sh");
            // Record the wrapper's full identity, then exec the existing native
            // fixture in the SAME process. No pipe/proxy stands in for the runner.
            fs::write(
                &wrapper,
                "#!/bin/sh\nset -eu\ncat \"/proc/$$/stat\" >> \"$FCP_TEST_PROCESS_HISTORY\"\nexec \"$FCP_TEST_CONNECTOR_BINARY\"\n",
            )?;
            fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700))?;
            let connectors = root.path().join("connectors.json");
            fs::write(
                &connectors,
                serde_json::to_vec(&json!([{
                    "id": connector_id.as_str(),
                    "name": "Issue 59 native cancellation",
                    "description": "Real blocked native connector",
                    "binary": wrapper,
                    "config": {},
                    "categories": ["test"],
                    "allowed_zones": [ZoneId::work().as_str()],
                    "cancellation_deadline_ms": DEADLINE_MS,
                    "env": {
                        "FCP_TEST_CONNECTOR_ID": connector_id.as_str(),
                        "FCP_TEST_CONNECTOR_BINARY": env!("CARGO_BIN_EXE_fcp-test-connector"),
                        "FCP_TEST_PROCESS_HISTORY": history,
                        "FCP_TEST_INVOKE_STARTED_FILE": marker,
                        "FCP_TEST_CONNECTOR_ARCHETYPE": "request_response",
                        "FCP_TEST_CONNECTOR_REQUIRE_HANDSHAKE": "1",
                    },
                }]))?,
            )?;
            let policies = root.path().join("zone-policies.json");
            let zone = ZoneId::work();
            let policy = ZonePolicyObject {
                header: ObjectHeader {
                    encryption_kind: ObjectEncryptionKind::Plain,
                    schema: fcp_cbor::SchemaId::new(
                        "fcp.core", "ZonePolicyObject", semver::Version::new(1, 0, 0),
                    ),
                    zone_id: zone.clone(),
                    created_at: u64::try_from(Utc::now().timestamp()).unwrap_or(0),
                    provenance: Provenance::new(zone.clone()),
                    refs: Vec::new(),
                    foreign_refs: Vec::new(),
                    ttl_secs: None,
                    placement: None,
                },
                zone_id: zone.clone(),
                principal_allow: Vec::new(),
                principal_deny: Vec::new(),
                connector_allow: Vec::new(),
                connector_deny: Vec::new(),
                capability_allow: Vec::new(),
                capability_deny: Vec::new(),
                capability_ceiling: Vec::new(),
                transport_policy: ZoneTransportPolicy {
                    allow_lan: true, allow_derp: true, allow_funnel: true,
                },
                decision_receipts: DecisionReceiptPolicy::default(),
                usage_budget: None,
                requires_posture: None,
            };
            fs::write(
                &policies,
                serde_json::to_vec(&HashMap::from([(zone.as_str().to_owned(), policy)]))?,
            )?;
            let listener = TcpListener::bind("127.0.0.1:0")?;
            let address = listener.local_addr()?;
            drop(listener);
            let stderr = root.path().join("host-stderr.log");
            let client = reqwest::Client::builder().timeout(Duration::from_secs(2)).build()?;
            let child = Command::new(env!("CARGO_BIN_EXE_fcp-host"))
                .env("FCP_HOST_BIND", address.to_string())
                .env_remove("FCP_HOST_CONNECTORS")
                .env("FCP_HOST_CONNECTORS_FILE", &connectors)
                .env("FCP_HOST_ADMIN_BEARER_TOKEN", ADMIN_TOKEN)
                .env("FCP_HOST_CAPABILITY_PUBLIC_KEY", hex::encode(key.verifying_key().to_bytes()))
                .env("FCP_HOST_ZONE_POLICIES_FILE", &policies)
                .env("FCP_HOST_LIFECYCLE_STATE_FILE", root.path().join("lifecycle.json"))
                .stdout(Stdio::null())
                .stderr(Stdio::from(fs::File::create(&stderr)?))
                .spawn()?;
            // Establish cleanup ownership BEFORE any fallible readiness await.
            let mut host = Self {
                child, base_url: format!("http://{address}"), client,
                history, marker, stderr, _root: root,
            };
            let started = Instant::now();
            while started.elapsed() < Duration::from_secs(15) {
                if let Some(status) = host.child.try_wait()? {
                    return Err(format!("host exited with {status}: {}", host.logs()).into());
                }
                if let Ok(response) = host.client.get(host.url("/rpc/health")).send().await
                    && (response.status().is_success()
                        || response.status() == reqwest::StatusCode::FORBIDDEN)
                {
                    return Ok(host);
                }
                fcp_async_core::time::sleep(Duration::from_millis(25)).await;
            }
            Err(format!("host readiness timed out: {}", host.logs()).into())
        }

        fn url(&self, path: &str) -> String {
            format!("{}{path}", self.base_url)
        }

        fn logs(&self) -> String {
            fs::read_to_string(&self.stderr).unwrap_or_else(|error| error.to_string())
        }

        async fn post<T: DeserializeOwned>(
            &self, path: &str, body: &impl serde::Serialize, admin: bool,
        ) -> TestResult<T> {
            let mut request = self.client.post(self.url(path))
                .header("x-principal", PRINCIPAL).json(body);
            if admin {
                request = request.bearer_auth(ADMIN_TOKEN).header("x-fcp-zone", "z:owner");
            }
            read_response(request.send().await?).await
        }

        async fn next_process(&self, previous: Option<ProcessIdentity>) -> TestResult<ProcessIdentity> {
            let started = Instant::now();
            loop {
                if let Some(process) = spawn_history(&self.history)?.last().copied()
                    && Some(process) != previous
                    && process.is_alive()?
                {
                    return Ok(process);
                }
                if started.elapsed() >= Duration::from_secs(2) {
                    return Err(format!("no live new connector: {}", self.logs()).into());
                }
                fcp_async_core::time::sleep(Duration::from_millis(5)).await;
            }
        }

        async fn wait_for_blocked_invoke(&self, id: &str, process: ProcessIdentity) -> TestResult {
            let started = Instant::now();
            loop {
                match fs::read(&self.marker) {
                    Ok(bytes) => {
                        if let Ok(value) = serde_json::from_slice::<Value>(&bytes)
                            && value.get("request_id").and_then(Value::as_str) == Some(id)
                            && value.get("pid").and_then(Value::as_u64) == Some(u64::from(process.pid))
                            && value.get("delay_ms").and_then(Value::as_u64) == Some(BLOCK_MS)
                        {
                            assert!(process.is_alive()?, "fixture exited after invoke entry");
                            return Ok(());
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
                if started.elapsed() >= Duration::from_secs(3) {
                    return Err(format!("fixture never entered invoke {id}: {}", self.logs()).into());
                }
                fcp_async_core::time::sleep(Duration::from_millis(5)).await;
            }
        }

        async fn wait_for_forced_audit(&self, id: &str) -> TestResult {
            let started = Instant::now();
            loop {
                let logs = self.logs();
                let found = logs.lines().filter_map(|line| serde_json::from_str::<Value>(line).ok())
                    .any(|entry| {
                        let fields = entry.get("fields").unwrap_or(&entry);
                        fields.get("event").and_then(Value::as_str) == Some("cancellation_forced")
                            && fields.get("operation_id").and_then(Value::as_str) == Some(id)
                    });
                if found {
                    return Ok(());
                }
                if started.elapsed() >= Duration::from_secs(2) {
                    return Err(format!("missing forced-cancellation audit for {id}: {logs}").into());
                }
                fcp_async_core::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }

    impl Drop for ProductionHost {
        fn drop(&mut self) {
            // Stop further spawns, then clean only the exact fixture identities
            // recorded before exec. Check incarnation identity, not just a PID.
            let _ = self.child.kill();
            let _ = self.child.wait();
            if let Ok(processes) = spawn_history(&self.history) {
                for process in processes {
                    if matches!(process.is_alive(), Ok(true)) {
                        let _ = Command::new("kill")
                            .args(["-KILL", &process.pid.to_string()]).status();
                    }
                }
            }
            if std::thread::panicking() {
                eprintln!("production-host stderr:\n{}", self.logs());
            }
        }
    }

    async fn read_response<T: DeserializeOwned>(response: reqwest::Response) -> TestResult<T> {
        let status = response.status();
        let text = response.text().await?;
        if !status.is_success() {
            return Err(format!("HTTP {status}: {}", text.chars().take(1024).collect::<String>()).into());
        }
        Ok(serde_json::from_str(&text)?)
    }

    fn invoke_request(connector_id: ConnectorId, key: &Ed25519SigningKey) -> InvokeRequest {
        let zone = ZoneId::work();
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".to_owned()], ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).expect("serialize test constraints");
        let now = Utc::now();
        let raw = CapabilityTokenBuilder::new()
            .capability_id("cap.test.echo").zone_id(zone.as_str())
            .principal(PRINCIPAL).operations(&["test.echo"])
            .issuer("node:test").audience("*")
            .validity(now, now + chrono::Duration::hours(1))
            .try_constraints_cbor(&cbor).expect("valid test constraints")
            .sign(key).expect("sign test capability");
        InvokeRequest {
            r#type: "invoke".to_owned(), id: RequestId::random(), connector_id,
            operation: OperationId::from_static("test.echo"), zone_id: zone,
            input: json!({"message": "replacement"}),
            capability_token: CapabilityToken::from_raw(raw), holder_proof: None,
            context: None, idempotency_key: None, lease_seq: None, deadline_ms: None,
            correlation_id: Some(CorrelationId::new()), provenance: None, approval_tokens: Vec::new(),
        }
    }

    async fn observe_termination(process: ProcessIdentity, started: Instant) -> TestResult<Duration> {
        loop {
            if !process.is_alive()? {
                let elapsed = started.elapsed();
                if elapsed <= KILL_BUDGET {
                    return Ok(elapsed);
                }
                return Err(format!("termination observed at {elapsed:?}, budget {KILL_BUDGET:?}").into());
            }
            if started.elapsed() >= KILL_BUDGET {
                return Err(format!("hung connector {process:?} survived {KILL_BUDGET:?}").into());
            }
            fcp_async_core::time::sleep(Duration::from_millis(5)).await;
        }
    }

    async fn exercise_hung_invoke(replace: bool) -> TestResult {
        let connector_id = ConnectorId::from_static("fcp.test.cancel-hung:utility:1.0.0");
        let key = Ed25519SigningKey::generate();
        let host = ProductionHost::spawn(&connector_id, &key).await?;
        let old_process = host.next_process(None).await?;
        assert_eq!(spawn_history(&host.history)?, vec![old_process]);
        let mut request = invoke_request(connector_id.clone(), &key);
        request.input = json!({"message": "hang", "delay_ms": BLOCK_MS});
        let operation_id = request.id.to_string();
        let invoke_started = Instant::now();
        let client = reqwest::Client::builder().timeout(Duration::from_secs(30)).build()?;
        let invoke_url = host.url("/rpc/invoke");
        let hung_task = fcp_async_core::task::spawn(async move {
            let response = client.post(invoke_url).header("x-principal", PRINCIPAL)
                .json(&request).send().await.map_err(|error| error.to_string())?;
            read_response::<InvokeResponse>(response).await.map_err(|error| error.to_string())
        });
        host.wait_for_blocked_invoke(&operation_id, old_process).await?;

        let replacement = if replace {
            let response: ConnectorConfigApplyResponse = host.post(
                &format!("/rpc/connectors/{}/config/apply", connector_id.as_str()),
                &ConnectorConfigApplyRequest {
                    payload: json!({"generation": 2}), expected_active_revision_id: None,
                    created_by: Some("issue-59-regression".to_owned()),
                    change_reason: Some("replace runtime during blocked invocation".to_owned()),
                }, true,
            ).await?;
            assert!(response.changed);
            let replacement = host.next_process(Some(old_process)).await?;
            assert_eq!(spawn_history(&host.history)?, vec![old_process, replacement]);
            Some(replacement)
        } else {
            None
        };
        assert!(old_process.is_alive()?, "old invocation must still own a live process");
        // Avoid letting the ordinary ten-second runner IO timeout masquerade as
        // cancellation enforcement. Setup that consumes this margin is a failure.
        assert!(invoke_started.elapsed() < Duration::from_secs(5), "pre-cancel setup exceeded margin");
        let cancel_request = CancellationRequest {
            operation_id: operation_id.clone(), reason: CancelReason::UserRequested,
            cleanup: CleanupBehavior::BestEffort, return_partial: false, capability_token: None,
        };
        let cancel_started = Instant::now();
        let cancel = async {
            let response = host.post::<CancellationResponse>(
                "/rpc/operations/cancel", &cancel_request, true,
            ).await?;
            Ok::<_, Box<dyn std::error::Error>>((response, cancel_started.elapsed()))
        };
        // Observe process exit concurrently: a slow cancellation HTTP response
        // must not hide the actual exit time or replace process-level evidence.
        let (cancel, terminated) = futures_util::future::join(
            cancel, observe_termination(old_process, cancel_started),
        ).await;
        let (cancel, answered_after) = cancel?;
        let terminated_after = terminated?;
        assert_eq!(cancel.operation_id, operation_id);
        let hung_result = fcp_async_core::time::timeout(Duration::from_secs(3), hung_task)
            .await.map_err(|_| io::Error::other("blocked invoke did not return after termination"))?
            .map_err(io::Error::other)?;
        assert!(
            !matches!(&hung_result, Ok(response) if response.status == InvokeStatus::Ok),
            "force-terminated invocation reported success: {hung_result:?}",
        );
        host.wait_for_forced_audit(&operation_id).await?;

        if let Some(replacement) = replacement {
            fcp_async_core::time::sleep(Duration::from_secs(1)).await;
            assert!(replacement.is_alive()?, "expired old invocation killed its replacement");
            let response: InvokeResponse = host.post(
                "/rpc/invoke", &invoke_request(connector_id, &key), false,
            ).await?;
            assert_eq!(response.status, InvokeStatus::Ok);
            assert!(replacement.is_alive()?);
            assert_eq!(
                spawn_history(&host.history)?, vec![old_process, replacement],
                "follow-up invocation must be served without replacing or respawning the replacement",
            );
        }
        eprintln!(
            "ISSUE-59 PROOF: replace={replace}; deadline={DEADLINE_MS}ms; \
             cancel_answer={answered_after:?}; original={old_process:?}; \
             terminated_after={terminated_after:?}; budget={KILL_BUDGET:?}; replacement={replacement:?}",
        );
        Ok(())
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn hung_native_invoke_is_terminated_out_of_band() -> TestResult {
        exercise_hung_invoke(false).await
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn hung_native_invoke_does_not_terminate_its_replacement() -> TestResult {
        exercise_hung_invoke(true).await
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn simultaneous_expirations_preserve_the_latest_native_incarnation() -> TestResult {
        const OLD_INCARNATIONS: usize = 3;
        let connector_id = ConnectorId::from_static("fcp.test.cancel-cohort:utility:1.0.0");
        let key = Ed25519SigningKey::generate();
        let host = ProductionHost::spawn(&connector_id, &key).await?;
        let mut current = host.next_process(None).await?;
        let mut history = vec![current];
        let mut pending = Vec::with_capacity(OLD_INCARNATIONS);
        let client = reqwest::Client::builder().timeout(Duration::from_secs(30)).build()?;
        let setup_started = Instant::now();

        // These are successive incarnations of ONE registry entry, all kept
        // alive by outstanding calls in ONE production host/reaper. Separate
        // hosts or connector IDs would not exercise a stale registry lookup.
        for generation in 0..OLD_INCARNATIONS {
            let mut request = invoke_request(connector_id.clone(), &key);
            request.input = json!({"message": "cohort-hang", "delay_ms": BLOCK_MS});
            let operation_id = request.id.to_string();
            let client = client.clone();
            let url = host.url("/rpc/invoke");
            let task = fcp_async_core::task::spawn(async move {
                let response = client.post(url).header("x-principal", PRINCIPAL)
                    .json(&request).send().await.map_err(|error| error.to_string())?;
                read_response::<InvokeResponse>(response).await.map_err(|error| error.to_string())
            });
            // Consume each exact request/PID marker before the next incarnation
            // can overwrite the fixture's shared marker file.
            host.wait_for_blocked_invoke(&operation_id, current).await?;
            pending.push((operation_id, current, task));
            let response: ConnectorConfigApplyResponse = host.post(
                &format!("/rpc/connectors/{}/config/apply", connector_id.as_str()),
                &ConnectorConfigApplyRequest {
                    payload: json!({"generation": generation + 2}),
                    expected_active_revision_id: None,
                    created_by: Some("issue-59-cohort".to_owned()),
                    change_reason: Some("retain old blocked incarnation during replacement".to_owned()),
                }, true,
            ).await?;
            assert!(response.changed);
            current = host.next_process(Some(current)).await?;
            assert!(!history.contains(&current), "replacement must be a new process incarnation");
            history.push(current);
            assert_eq!(spawn_history(&host.history)?, history);
        }
        assert!(setup_started.elapsed() < Duration::from_secs(5), "cohort setup exceeded RPC-timeout margin");
        for (id, process, task) in &pending {
            assert!(process.is_alive()?, "{id} exited before cohort cancellation");
            assert!(!task.is_finished(), "{id} returned before cohort cancellation");
        }
        assert!(current.is_alive()?, "latest incarnation must be alive before cancellation");

        let live_request = invoke_request(connector_id.clone(), &key);
        let live_id = live_request.id.clone();
        let cancellations = futures_util::future::join_all(pending.iter().map(|(id, process, _)| {
            let host = &host;
            async move {
                let request = CancellationRequest {
                    operation_id: id.clone(), reason: CancelReason::UserRequested,
                    cleanup: CleanupBehavior::BestEffort, return_partial: false, capability_token: None,
                };
                let started = Instant::now();
                // Each operation has its own unchanged deadline, measured from
                // before its HTTP request. No serial wait resets another budget.
                let (answer, terminated) = futures_util::future::join(
                    host.post::<CancellationResponse>("/rpc/operations/cancel", &request, true),
                    observe_termination(*process, started),
                ).await;
                assert_eq!(answer?.operation_id, *id);
                Ok::<_, Box<dyn std::error::Error>>((id.clone(), *process, terminated?))
            }
        }));
        let (outcomes, live_response) = futures_util::future::join(
            cancellations, host.post::<InvokeResponse>("/rpc/invoke", &live_request, false),
        ).await;
        assert_eq!(outcomes.len(), OLD_INCARNATIONS);
        for outcome in outcomes {
            let (id, process, elapsed) = outcome?;
            eprintln!("ISSUE-59 COHORT: operation={id}; original={process:?}; terminated_after={elapsed:?}; budget={KILL_BUDGET:?}");
        }
        let live_response = live_response?;
        assert_eq!(live_response.id, live_id);
        assert_eq!(live_response.status, InvokeStatus::Ok);
        assert!(current.is_alive()?, "old cancellations killed the latest incarnation");
        assert_eq!(spawn_history(&host.history)?, history, "concurrent follow-up must not respawn");

        for (id, process, task) in pending {
            let result = fcp_async_core::time::timeout(Duration::from_secs(3), task)
                .await.map_err(|_| io::Error::other("cohort invoke did not return after termination"))?
                .map_err(io::Error::other)?;
            assert!(!matches!(&result, Ok(response) if response.status == InvokeStatus::Ok),
                "terminated cohort invoke {id} reported success: {result:?}");
            assert!(!process.is_alive()?, "original incarnation {id} is still live");
            host.wait_for_forced_audit(&id).await?;
        }
        // Cross additional reaper sweeps, then prove service from the exact same
        // replacement again. A kill followed by an automatic respawn cannot pass.
        fcp_async_core::time::sleep(Duration::from_secs(1)).await;
        let request = invoke_request(connector_id, &key);
        let response: InvokeResponse = host.post("/rpc/invoke", &request, false).await?;
        assert_eq!(response.id, request.id);
        assert_eq!(response.status, InvokeStatus::Ok);
        assert!(current.is_alive()?);
        assert_eq!(spawn_history(&host.history)?, history, "late cancellation must not trigger respawn");
        Ok(())
    }

    #[test]
    fn process_stat_handles_parentheses_and_spaces_in_comm() {
        let mut fields = vec!["0"; 20];
        fields[0] = "S";
        fields[19] = "987654";
        let process = parse_process_stat(&format!("123 (fixture ) with spaces) {}", fields.join(" ")))
            .expect("valid process stat");
        assert_eq!(process.identity, ProcessIdentity { pid: 123, start_ticks: 987654 });
        assert_eq!(process.state, b'S');
    }

    #[test]
    fn malformed_process_evidence_is_an_error() {
        for text in ["", "123", "123 (fixture) S", "0 (fixture) S", "123 (fixture) XX"] {
            assert!(parse_process_stat(text).is_err(), "accepted malformed stat: {text}");
        }
    }

    #[test]
    fn reused_pids_and_zombies_are_not_live_original_incarnations() {
        let expected = ProcessIdentity { pid: 123, start_ticks: 1 };
        assert!(!ProcessSnapshot { identity: expected, state: b'Z' }.is_live_incarnation(expected));
        assert!(!ProcessSnapshot {
            identity: ProcessIdentity { pid: 123, start_ticks: 2 }, state: b'S',
        }.is_live_incarnation(expected));
        assert!(ProcessSnapshot { identity: expected, state: b'S' }.is_live_incarnation(expected));
    }
}
