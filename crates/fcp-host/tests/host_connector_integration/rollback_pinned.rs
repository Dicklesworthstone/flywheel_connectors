//! Verified rollback must replace the executable and survive host restart.

use std::io::Write as _;

use fcp_host::ManagedConnectorConfig;
use fcp_manifest::ConnectorManifest;
use sha2::{Digest as _, Sha256};

use super::*;

const CURRENT_VERSION: &str = "1.0.1";
const TARGET_VERSION: &str = "1.0.0";
const ROLLBACK_ROUTE: &str = "/rpc/rollout/rollback/pinned";

struct RollbackFixture {
    directory: tempfile::TempDir,
    connector_id: ConnectorId,
    signing_key: Ed25519SigningKey,
    current: Value,
    target: Value,
    current_marker: PathBuf,
    target_marker: PathBuf,
}

fn write_manifest(
    path: &Path,
    connector_id: &ConnectorId,
    version: &str,
    model: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Match TestConnectorProfile::operation_info for the explicitly selected
    // request_response/reversible profile, including its entire operation set.
    let raw = format!(
        r#"[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"
min_mesh_version = "2.0.0"
min_protocol = "fcp2-sym/2.0"
protocol_features = []
max_datagram_bytes = 1200
interface_hash = "blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000"

[connector]
id = {connector_id:?}
name = "Pinned rollback test connector"
version = {version:?}
description = "Real subprocess connector used to verify deployment restoration"
archetypes = ["operational"]
format = "native"

[connector.state]
model = {model:?}
state_schema_version = "1"

[zones]
home = "z:work"
allowed_sources = ["z:work"]
allowed_targets = ["z:work"]
forbidden = ["z:public"]

[capabilities]
required = ["cap.test.echo"]
optional = []
forbidden = []

[provides.operations."test.echo"]
description = "Returns the input payload as output."
capability = "cap.test.echo"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "best_effort"
input_schema = {{ type = "object" }}
output_schema = {{ type = "object" }}

[provides.operations."test.echo".ai_hints]
when_to_use = "Use for request_response subprocess integration testing."
common_mistakes = []
examples = []
related = []

[sandbox]
profile = "strict"
memory_mb = 256
cpu_percent = 50
wall_clock_timeout_ms = 30000
fs_readonly_paths = []
fs_writable_paths = []
deny_exec = true
deny_ptrace = true
"#,
        connector_id = connector_id.as_str(),
    );
    let manifest = ConnectorManifest::parse_str_unchecked(&raw)?;
    let interface_hash = manifest.compute_interface_hash()?;
    let raw = raw.replace(
        &manifest.manifest.interface_hash.to_string(),
        &interface_hash.to_string(),
    );
    ConnectorManifest::parse_str(&raw)?;
    std::fs::write(path, raw)?;
    Ok(())
}

fn executable_digest(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    Ok(hex::encode(Sha256::digest(std::fs::read(path)?)))
}

impl RollbackFixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let connector_id = ConnectorId::from_static("fcp.test.pinned-rollback:utility:1.0.0");
        let current_marker = directory.path().join("current-invoke.json");
        let target_marker = directory.path().join("target-invoke.json");
        let mut configs = Vec::new();
        for (name, version, marker) in [
            ("current", CURRENT_VERSION, &current_marker),
            ("target", TARGET_VERSION, &target_marker),
        ] {
            let binary = directory.path().join(format!("{name}-connector"));
            std::fs::copy(env!("CARGO_BIN_EXE_fcp-test-connector"), &binary)?;
            // ELF ignores trailing data. Distinct fixture identities make the
            // actual sealed process images distinguishable by their SHA pins,
            // without replacing the real connector protocol with a mock.
            std::fs::OpenOptions::new()
                .append(true)
                .open(&binary)?
                .write_all(format!("\nfcp-pinned-rollback-fixture:{name}\n").as_bytes())?;
            let manifest = directory.path().join(format!("{name}-manifest.toml"));
            write_manifest(&manifest, &connector_id, version, "stateless")?;
            let mut config = test_connector_config(&connector_id, name, &["test", "rollback"]);
            config["binary"] = json!(binary);
            config["binary_sha256"] = json!(executable_digest(&binary)?);
            config["manifest_path"] = json!(manifest);
            config["version"] = json!(version);
            config["config"] = json!({ "deployment": name });
            config["env"]["FCP_TEST_CONNECTOR_ARCHETYPE"] = json!("request_response");
            config["env"]["FCP_TEST_CONNECTOR_OPERATION_MODE"] = json!("reversible");
            config["env"]["FCP_TEST_INVOKE_STARTED_FILE"] = json!(marker);
            configs.push(config);
        }
        let target = configs.pop().unwrap();
        let current = configs.pop().unwrap();
        assert_ne!(current["binary_sha256"], target["binary_sha256"]);
        Ok(Self {
            directory,
            connector_id,
            signing_key: Ed25519SigningKey::generate(),
            current,
            target,
            current_marker,
            target_marker,
        })
    }

    fn request(&self) -> Value {
        json!({
            "connector_id": self.connector_id.as_str(),
            "to_version": TARGET_VERSION,
            "connector": self.target,
            "reason": "restore the explicitly verified prior deployment",
        })
    }

    async fn spawn(&self) -> Result<HttpHostProcess, Box<dyn std::error::Error>> {
        let public_key = capability_public_key_hex(&self.signing_key);
        let mut host = HttpHostProcess::spawn_with_connectors_file(
            vec![self.current.clone()],
            &[("FCP_HOST_CAPABILITY_PUBLIC_KEY", public_key.as_str())],
        )
        .await?;
        host.client =
            build_http_client(reqwest::Client::builder().timeout(Duration::from_secs(20)))?;
        let _: PinStateResponse = http_put_json(
            host.client.clone(),
            format!("{}/rpc/rollout/pin/{}", host.base_url, self.connector_id),
            json!({ "version": CURRENT_VERSION }),
        )
        .await?;
        let scheduled: RolloutOutcome = http_post_json(
            host.client.clone(),
            format!("{}/rpc/rollout/schedule", host.base_url),
            json!({
                "connector_id": self.connector_id.as_str(),
                "version": CURRENT_VERSION,
                "previous_version": TARGET_VERSION,
                "policy": test_rollout_policy(),
                "observed_at": Utc::now() - ChronoDuration::seconds(5),
            }),
        )
        .await?;
        assert_eq!(scheduled.record.state, LifecycleState::Canary);
        Ok(host)
    }

    async fn invoke_image(
        &self,
        host: &HttpHostProcess,
        target: bool,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let (marker, config) = if target {
            (&self.target_marker, &self.target)
        } else {
            (&self.current_marker, &self.current)
        };
        let pid =
            invoke_rollout_runtime_pid(host, &self.connector_id, &self.signing_key, marker).await?;
        let actual = executable_digest(Path::new(&format!("/proc/{pid}/exe")))?;
        assert_eq!(
            Some(actual.as_str()),
            config["binary_sha256"].as_str(),
            "the responding process must execute the admitted sealed image"
        );
        Ok(pid)
    }
}

async fn restart_from_inventory(
    host: &mut HttpHostProcess,
    signing_key: &Ed25519SigningKey,
) -> Result<(), Box<dyn std::error::Error>> {
    send_sigterm(&host.child)?;
    let status =
        wait_for_host_exit(&mut host.child, Duration::from_secs(10), &host.stderr_logs).await?;
    assert!(
        status.success(),
        "host must stop cleanly before restart: {status}"
    );
    if let Some(thread) = host.stderr_thread.take() {
        thread
            .join()
            .expect("stderr reader should exit with the host");
    }
    let listener = StdTcpListener::bind("127.0.0.1:0")?;
    let bind = listener.local_addr()?;
    drop(listener);
    let public_key = capability_public_key_hex(signing_key);
    let directory = host.lifecycle_state_dir.path();
    host.child = Command::new(env!("CARGO_BIN_EXE_fcp-host"))
        .env("FCP_HOST_BIND", bind.to_string())
        .env(
            "FCP_HOST_CONNECTORS_FILE",
            directory.join("connectors.json"),
        )
        .env(
            "FCP_HOST_LIFECYCLE_STATE_FILE",
            directory.join("lifecycle-state.json"),
        )
        .env(
            "FCP_HOST_ZONE_POLICIES_FILE",
            directory.join("zone-policies.json"),
        )
        .env("FCP_HOST_ADMIN_BEARER_TOKEN", TEST_ADMIN_BEARER_TOKEN)
        .env("FCP_HOST_CAPABILITY_PUBLIC_KEY", public_key)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let (logs, thread) = spawn_stderr_capture(&mut host.child)?;
    host.stderr_logs = logs;
    host.stderr_thread = Some(thread);
    host.base_url = format!("http://{bind}");
    wait_for_host_readiness(
        &mut host.child,
        &host.client,
        &host.base_url,
        &host.stderr_logs,
    )
    .await
}

async fn assert_rollout_metadata(
    host: &HttpHostProcess,
    fixture: &RollbackFixture,
    version: &str,
    state: LifecycleState,
    desired: DesiredRuntimeState,
) -> Result<(), Box<dyn std::error::Error>> {
    let status: ConnectorAdminStatus = http_get_json(
        host.client.clone(),
        format!("{}/rpc/lifecycle/{}", host.base_url, fixture.connector_id),
    )
    .await?;
    assert_eq!(status.desired_state, desired);
    let lifecycle = status
        .lifecycle
        .expect("rollout record should remain present");
    assert_eq!(lifecycle.version, semver::Version::parse(version)?);
    assert_eq!(lifecycle.state, state);
    let pin: PinStateResponse = http_get_json(
        host.client.clone(),
        format!("{}/rpc/rollout/pin/{}", host.base_url, fixture.connector_id),
    )
    .await?;
    assert!(pin.pinned);
    assert_eq!(pin.version, Some(semver::Version::parse(version)?));
    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn pinned_rollback_replaces_the_process_and_persists_the_exact_target_for_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = RollbackFixture::new()?;
    let mut host = fixture.spawn().await?;
    let original_pid = fixture.invoke_image(&host, false).await?;
    let response: Value = http_post_json(
        host.client.clone(),
        format!("{}{ROLLBACK_ROUTE}", host.base_url),
        fixture.request(),
    )
    .await?;
    assert_eq!(response["connector_id"], fixture.connector_id.as_str());
    assert_eq!(response["from_version"], CURRENT_VERSION);
    assert_eq!(response["to_version"], TARGET_VERSION);
    assert_eq!(response["state"], "rolled_back");
    assert_eq!(response["desired_state"], "enabled");
    assert_eq!(response["runtime_restored"], true);
    assert!(
        response["registry_version"]
            .as_u64()
            .is_some_and(|value| value > 0)
    );
    assert!(!Path::new(&format!("/proc/{original_pid}/exe")).exists());
    let target_pid = fixture.invoke_image(&host, true).await?;
    assert_ne!(original_pid, target_pid);
    let persisted: Vec<ManagedConnectorConfig> = serde_json::from_slice(&std::fs::read(
        host.lifecycle_state_dir.path().join("connectors.json"),
    )?)?;
    let expected: ManagedConnectorConfig = serde_json::from_value(fixture.target.clone())?;
    assert_eq!(persisted, vec![expected]);
    assert_rollout_metadata(
        &host,
        &fixture,
        TARGET_VERSION,
        LifecycleState::RolledBack,
        DesiredRuntimeState::Enabled,
    )
    .await?;

    restart_from_inventory(&mut host, &fixture.signing_key).await?;
    let restarted_pid = fixture.invoke_image(&host, true).await?;
    assert_ne!(target_pid, restarted_pid);
    assert_rollout_metadata(
        &host,
        &fixture,
        TARGET_VERSION,
        LifecycleState::RolledBack,
        DesiredRuntimeState::Enabled,
    )
    .await?;
    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn pinned_rollback_rejects_unverified_targets_before_mutating_the_live_deployment()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = RollbackFixture::new()?;
    let host = fixture.spawn().await?;
    let original_pid = fixture.invoke_image(&host, false).await?;
    let mut cases = Vec::new();
    let mut missing_pin = fixture.request();
    missing_pin["connector"]
        .as_object_mut()
        .unwrap()
        .remove("binary_sha256");
    cases.push(("missing pin", missing_pin));
    let mut wrong_pin = fixture.request();
    wrong_pin["connector"]["binary_sha256"] = json!("00".repeat(32));
    cases.push(("wrong executable digest", wrong_pin));
    let mut wrong_version = fixture.request();
    wrong_version["connector"]["version"] = json!("9.0.0");
    cases.push(("wrong config version", wrong_version));
    let mut wrong_target = fixture.request();
    wrong_target["to_version"] = json!("9.0.0");
    cases.push(("wrong rollout target", wrong_target));
    let mut wrong_identity = fixture.request();
    wrong_identity["connector"]["id"] = json!("fcp.test.other:utility:1.0.0");
    cases.push(("wrong connector identity", wrong_identity));
    let mut wrong_manifest_version = fixture.request();
    wrong_manifest_version["connector"]["manifest_path"] = fixture.current["manifest_path"].clone();
    cases.push(("wrong manifest version", wrong_manifest_version));
    let mut wrong_zone = fixture.request();
    wrong_zone["connector"]["allowed_zones"] = json!(["z:work", "z:private"]);
    cases.push(("target broadens the current zone envelope", wrong_zone));
    let stateful_manifest = fixture.directory.path().join("stateful-manifest.toml");
    write_manifest(
        &stateful_manifest,
        &fixture.connector_id,
        TARGET_VERSION,
        "singleton_writer",
    )?;
    let mut stateful = fixture.request();
    stateful["connector"]["manifest_path"] = json!(stateful_manifest);
    cases.push(("stateful target without a canonical handoff", stateful));
    let mut wrong_catalog = fixture.request();
    wrong_catalog["connector"]["env"]["FCP_TEST_CONNECTOR_ARCHETYPE"] = json!("polling");
    cases.push((
        "target runtime advertises an undeclared operation",
        wrong_catalog,
    ));
    let mut wrong_contract = fixture.request();
    wrong_contract["connector"]["env"]["FCP_TEST_CONNECTOR_OPERATION_MODE"] = json!("irreversible");
    cases.push((
        "target runtime changes the admitted operation contract",
        wrong_contract,
    ));
    let mut unknown_field = fixture.request();
    unknown_field["skip_verification"] = json!(true);
    cases.push(("unknown request field", unknown_field));

    for (case, request) in cases {
        let inventory_path = host.lifecycle_state_dir.path().join("connectors.json");
        let lifecycle_path = host.lifecycle_state_dir.path().join("lifecycle-state.json");
        let inventory_before = std::fs::read(&inventory_path)?;
        let lifecycle_before = std::fs::read(&lifecycle_path)?;
        let (status, error) = request_status_text(
            host.client.clone(),
            reqwest::Method::POST,
            format!("{}{ROLLBACK_ROUTE}", host.base_url),
            Some(request),
            Some(admin_auth_headers()),
        )
        .await?;
        assert!(
            !status.is_success(),
            "{case} unexpectedly succeeded: {error}"
        );
        assert_ne!(
            status,
            reqwest::StatusCode::NOT_FOUND,
            "missing pinned rollback route"
        );
        assert_eq!(std::fs::read(&inventory_path)?, inventory_before, "{case}");
        assert_eq!(std::fs::read(&lifecycle_path)?, lifecycle_before, "{case}");
        assert!(!fixture.target_marker.exists(), "{case} invoked the target");
        assert_rollout_metadata(
            &host,
            &fixture,
            CURRENT_VERSION,
            LifecycleState::Canary,
            DesiredRuntimeState::Enabled,
        )
        .await?;
        assert_eq!(
            fixture.invoke_image(&host, false).await?,
            original_pid,
            "{case}"
        );
    }
    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn pinned_rollback_recovers_an_unavailable_process_without_inheriting_its_failure_gate()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = RollbackFixture::new()?;
    let host = fixture.spawn().await?;
    let original_pid = fixture.invoke_image(&host, false).await?;
    // Fault only the real connector child whose identity this test observed.
    // The host remains up, owns its retired actor, and records genuine failed
    // health RPCs through the production resilience layer.
    let killed = Command::new("kill")
        .args(["-TERM", &original_pid.to_string()])
        .status()?;
    assert!(
        killed.success(),
        "could not terminate the fixture connector"
    );
    let mut failure_gate = None;
    for _ in 0..12 {
        let health: HostHealthResponse =
            http_get_json(host.client.clone(), format!("{}/rpc/health", host.base_url)).await?;
        if let Some(ConnectorHealth::Unavailable { reason, .. }) =
            health.connectors.get(&fixture.connector_id)
            && (reason.contains("circuit open") || reason.contains("unhealthy"))
        {
            failure_gate = Some(reason.clone());
            break;
        }
    }
    assert!(
        failure_gate.is_some(),
        "the real failed child must trip a circuit or unhealthy routing gate before rollback"
    );

    let restored: Value = http_post_json(
        host.client.clone(),
        format!("{}{ROLLBACK_ROUTE}", host.base_url),
        fixture.request(),
    )
    .await?;
    assert_eq!(restored["runtime_restored"], true);
    assert_ne!(fixture.invoke_image(&host, true).await?, original_pid);
    assert_rollout_metadata(
        &host,
        &fixture,
        TARGET_VERSION,
        LifecycleState::RolledBack,
        DesiredRuntimeState::Enabled,
    )
    .await?;
    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn pinned_rollback_of_a_disabled_connector_retains_the_target_until_explicit_enable()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = RollbackFixture::new()?;
    let host = fixture.spawn().await?;
    let original_pid = fixture.invoke_image(&host, false).await?;
    let lifecycle_url = format!("{}/rpc/lifecycle/{}", host.base_url, fixture.connector_id);
    let disabled: Value = http_post_json(
        host.client.clone(),
        lifecycle_url.clone(),
        json!({ "action": "disable" }),
    )
    .await?;
    assert_eq!(disabled["current_desired_state"], "disabled");
    assert_eq!(disabled["observed_state"], "stopped");
    assert!(!Path::new(&format!("/proc/{original_pid}/exe")).exists());

    let restored: Value = http_post_json(
        host.client.clone(),
        format!("{}{ROLLBACK_ROUTE}", host.base_url),
        fixture.request(),
    )
    .await?;
    assert_eq!(restored["runtime_restored"], true);
    assert_eq!(restored["desired_state"], "disabled");
    assert!(!fixture.target_marker.exists());
    assert_rollout_metadata(
        &host,
        &fixture,
        TARGET_VERSION,
        LifecycleState::RolledBack,
        DesiredRuntimeState::Disabled,
    )
    .await?;

    // Explicit Enable must use the exact already-admitted target, not reopen
    // a mutable path after a dormant restoration was acknowledged.
    std::fs::write(
        fixture.target["binary"].as_str().unwrap(),
        b"replaced source must never become an executable",
    )?;
    let enabled: Value = http_post_json(
        host.client.clone(),
        lifecycle_url,
        json!({ "action": "enable" }),
    )
    .await?;
    assert_eq!(enabled["current_desired_state"], "enabled");
    assert_eq!(enabled["observed_state"], "running");
    assert_ne!(fixture.invoke_image(&host, true).await?, original_pid);
    assert_rollout_metadata(
        &host,
        &fixture,
        TARGET_VERSION,
        LifecycleState::RolledBack,
        DesiredRuntimeState::Enabled,
    )
    .await?;
    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn pinned_rollback_inventory_write_failure_stays_disabled_after_host_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = RollbackFixture::new()?;
    let mut host = fixture.spawn().await?;
    let original_pid = fixture.invoke_image(&host, false).await?;
    let directory = host.lifecycle_state_dir.path();
    let inventory_before = std::fs::read(directory.join("connectors.json"))?;
    let marker_before = std::fs::read(&fixture.current_marker)?;
    // The inventory remains readable and target admission succeeds. Publication
    // must fail after retirement even when the test runs as root: chmod would
    // not provide a reliable write-failure fixture in that environment.
    std::fs::create_dir(directory.join("connectors.json.tmp"))?;
    let (status, error) = request_status_text(
        host.client.clone(),
        reqwest::Method::POST,
        format!("{}{ROLLBACK_ROUTE}", host.base_url),
        Some(fixture.request()),
        Some(admin_auth_headers()),
    )
    .await?;
    assert!(
        status.is_server_error(),
        "unexpected failure {status}: {error}"
    );
    assert!(
        error.contains("connectors file"),
        "unexpected failure: {error}"
    );
    assert_eq!(
        std::fs::read(directory.join("connectors.json"))?,
        inventory_before
    );
    assert!(!Path::new(&format!("/proc/{original_pid}/exe")).exists());
    let durable: Value =
        serde_json::from_slice(&std::fs::read(directory.join("lifecycle-state.json"))?)?;
    assert_eq!(
        durable["connectors"][fixture.connector_id.as_str()]["desired_state"],
        "disabled"
    );
    assert_rollout_metadata(
        &host,
        &fixture,
        CURRENT_VERSION,
        LifecycleState::Canary,
        DesiredRuntimeState::Disabled,
    )
    .await?;

    restart_from_inventory(&mut host, &fixture.signing_key).await?;
    assert_rollout_metadata(
        &host,
        &fixture,
        CURRENT_VERSION,
        LifecycleState::Canary,
        DesiredRuntimeState::Disabled,
    )
    .await?;
    let (mut request, _) = build_invoke_request(fixture.connector_id.clone(), &fixture.signing_key);
    request.input = json!({ "delay_ms": 0 });
    let (status, error) = request_status_text(
        host.client.clone(),
        reqwest::Method::POST,
        format!("{}/rpc/invoke", host.base_url),
        Some(serde_json::to_value(request)?),
        None,
    )
    .await?;
    assert!(
        !status.is_success(),
        "failed rollback resumed a connector: {error}"
    );
    assert_eq!(std::fs::read(&fixture.current_marker)?, marker_before);
    assert!(!fixture.target_marker.exists());
    Ok(())
}
