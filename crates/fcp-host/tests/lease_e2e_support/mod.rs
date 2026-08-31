#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::net::TcpListener as StdTcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use chrono::{Duration as ChronoDuration, Utc};
use fcp_core::{
    CapabilityConstraints, CapabilityToken, CapabilityVerifier, ConnectorStateAppendOutcome,
    ConnectorStateStore, CorrelationId, DecisionReceiptPolicy, EvictionPolicy, InstanceId,
    Lease as CoreLease, LeasePurpose as CoreLeasePurpose, NodeSignature, ObjectHeader, ObjectId,
    ObjectIdKey, Provenance, SignatureSet, StorageMeta, StoredObject, TailscaleNodeId, ZoneId,
    ZonePolicyObject, ZoneTransportPolicy,
};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_kernel::{ConnectorId, InvokeRequest, OperationId, RequestId};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

pub const TEST_ADMIN_BEARER_TOKEN: &str = "host-test-admin-bearer";

const TEST_PRINCIPAL: &str = "agent:test";
const TEST_OPERATION: &str = "test.echo";
const TEST_CAPABILITY_ID: &str = "cap.test.echo";
const CONNECTOR_STATE_DIR_ENV: &str = "FCP_CONNECTOR_STATE";
const CONNECTOR_STATE_OBJECT_ID_KEY_ENV: &str = "FCP_CONNECTOR_STATE_OBJECT_ID_KEY";

type StderrLogs = Arc<StdMutex<Vec<String>>>;
static HOST_E2E_LOCK: OnceLock<fcp_async_core::sync::Mutex<()>> = OnceLock::new();

pub async fn host_e2e_lock() -> impl Drop {
    HOST_E2E_LOCK
        .get_or_init(|| fcp_async_core::sync::Mutex::new(()))
        .lock()
        .await
}

pub struct HttpHostProcess {
    child: Child,
    pub client: reqwest::Client,
    pub base_url: String,
    #[allow(dead_code)]
    lifecycle_state_dir: tempfile::TempDir,
    #[allow(dead_code)]
    stderr_logs: StderrLogs,
    stderr_thread: Option<JoinHandle<()>>,
}

impl HttpHostProcess {
    pub async fn spawn_with_env(
        connector_configs: Vec<Value>,
        extra_env: &[(&str, &str)],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let bind_listener = StdTcpListener::bind("127.0.0.1:0")?;
        let bind_addr = bind_listener.local_addr()?;
        drop(bind_listener);

        let base_url = format!("http://{bind_addr}");
        let lifecycle_state_dir = tempfile::tempdir()?;
        let lifecycle_state_path = lifecycle_state_dir.path().join("lifecycle-state.json");
        let zone_policies_path = write_test_zone_policies_file(&lifecycle_state_dir)?;
        let mut command = Command::new(env!("CARGO_BIN_EXE_fcp-host"));
        command
            .env("FCP_HOST_BIND", bind_addr.to_string())
            .env(
                "FCP_HOST_CONNECTORS",
                serde_json::to_string(&connector_configs)?,
            )
            .env("FCP_HOST_ADMIN_BEARER_TOKEN", TEST_ADMIN_BEARER_TOKEN)
            .env("FCP_HOST_LIFECYCLE_STATE_FILE", &lifecycle_state_path)
            .env("FCP_HOST_ZONE_POLICIES_FILE", &zone_policies_path)
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        for (name, value) in extra_env {
            command.env(name, value);
        }
        let mut child = command.spawn()?;
        let (stderr_logs, stderr_thread) = spawn_stderr_capture(&mut child)?;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()?;
        wait_for_host_readiness(&mut child, &client, &base_url, &stderr_logs).await?;

        Ok(Self {
            child,
            client,
            base_url,
            lifecycle_state_dir,
            stderr_logs,
            stderr_thread: Some(stderr_thread),
        })
    }
}

impl Drop for HttpHostProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(stderr_thread) = self.stderr_thread.take() {
            let _ = stderr_thread.join();
        }
    }
}

pub struct SeededConnectorState {
    pub root_object_id: ObjectId,
    pub head_object_id: ObjectId,
    pub lease_object_id: ObjectId,
    pub lease_seq: u64,
    pub lease_expiry_unix_secs: u64,
}

pub fn capability_public_key_hex(signing_key: &Ed25519SigningKey) -> String {
    hex::encode(signing_key.verifying_key().to_bytes())
}

pub fn build_invoke_request(
    connector_id: ConnectorId,
    capability_signing_key: &Ed25519SigningKey,
) -> (InvokeRequest, CorrelationId) {
    let correlation_id = CorrelationId::new();
    let zone_id = ZoneId::work();
    let request = InvokeRequest {
        r#type: "invoke".to_string(),
        id: RequestId::random(),
        connector_id,
        operation: OperationId::from_static(TEST_OPERATION),
        zone_id: zone_id.clone(),
        input: json!({ "message": "hello" }),
        capability_token: build_live_capability_token(
            capability_signing_key,
            TEST_CAPABILITY_ID,
            TEST_PRINCIPAL,
            TEST_OPERATION,
            &zone_id,
        ),
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: None,
        correlation_id: Some(correlation_id.clone()),
        provenance: None,
        approval_tokens: Vec::new(),
    };
    (request, correlation_id)
}

pub async fn http_get_json<T>(
    client: reqwest::Client,
    url: String,
) -> Result<T, Box<dyn std::error::Error>>
where
    T: DeserializeOwned + Send + 'static,
{
    let headers = with_admin_auth_if_needed(&reqwest::Method::GET, &url);
    let response = client
        .get(url)
        .headers(headers)
        .send()
        .await?
        .error_for_status()?;
    Ok(response.json::<T>().await?)
}

pub async fn http_post_json<B, T>(
    client: reqwest::Client,
    url: String,
    body: B,
) -> Result<T, Box<dyn std::error::Error>>
where
    B: serde::Serialize + Send + 'static,
    T: DeserializeOwned + Send + 'static,
{
    let headers = with_admin_auth_if_needed(&reqwest::Method::POST, &url);
    let response = client
        .post(url)
        .headers(headers)
        .json(&body)
        .send()
        .await?
        .error_for_status()?;
    Ok(response.json::<T>().await?)
}

pub fn singleton_writer_test_connector_config(connector_id: &ConnectorId, name: &str) -> Value {
    let mut config = test_connector_config(connector_id, name, &["test", "hrw"]);
    let config_object = config
        .as_object_mut()
        .expect("test connector config should be a JSON object");
    config_object.insert(
        "config".to_string(),
        json!({ "state": { "model": "singleton_writer" } }),
    );
    config_object.insert(
        "allowed_zones".to_string(),
        json!([ZoneId::work().as_str()]),
    );
    config
}

pub fn singleton_writer_test_connector_config_with_state(
    connector_id: &ConnectorId,
    name: &str,
    state_root: &Path,
    object_id_key: &ObjectIdKey,
) -> Value {
    let mut config = singleton_writer_test_connector_config(connector_id, name);
    let config_object = config
        .as_object_mut()
        .expect("test connector config should be a JSON object");
    let env = config_object
        .entry("env")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .expect("test connector env should be a JSON object");
    env.insert(
        CONNECTOR_STATE_DIR_ENV.to_string(),
        json!(state_root.display().to_string()),
    );
    env.insert(
        CONNECTOR_STATE_OBJECT_ID_KEY_ENV.to_string(),
        json!(hex::encode(object_id_key.as_bytes())),
    );
    env.insert(
        "FCP_CONNECTOR_STATE_MODEL".to_string(),
        json!("singleton_writer"),
    );
    config
}

pub fn singleton_writer_connector_lease_subject_id_for_test(
    connector_id: &ConnectorId,
    zone_id: &ZoneId,
) -> ObjectId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"FCP-HOST-SINGLETON-WRITER-HRW-LEASE-V2");
    update_len_prefixed_for_test(&mut hasher, connector_id.as_str().as_bytes());
    update_len_prefixed_for_test(&mut hasher, zone_id.as_str().as_bytes());
    ObjectId::from_bytes(*hasher.finalize().as_bytes())
}

pub async fn seed_singleton_writer_connector_state(
    state_root: &Path,
    connector_id: &ConnectorId,
    zone_id: &ZoneId,
    object_id_key: ObjectIdKey,
    lease_object_id: ObjectId,
) -> Result<SeededConnectorState, Box<dyn std::error::Error>> {
    let object_store_dir = connector_state_canonical_object_store_dir(state_root, connector_id);
    let object_store: Arc<dyn fcp_store::ObjectStore> =
        Arc::new(fcp_store::DurableObjectStore::open(
            fcp_store::DurableObjectStoreConfig::new(&object_store_dir),
        )?);
    let state_store = fcp_store::FcpStoreConnectorStateStore::new(
        Arc::clone(&object_store),
        object_id_key,
        connector_id.clone(),
        zone_id.clone(),
    )
    .with_snapshot_every_entries(0)
    .with_snapshot_every_secs(0);
    let (authorization, signing_key) =
        connector_state_write_authorization_for_test_with_key(connector_id, zone_id);
    let state_object = sign_durable_connector_state_object_for_test(
        durable_connector_state_object_for_test(connector_id, zone_id, 0, None, lease_object_id),
        &signing_key,
    );
    let lease_seq = state_object.lease_seq;
    let append = ConnectorStateStore::append_object(
        &state_store,
        connector_id,
        &authorization,
        state_object,
    )
    .await?;

    match append {
        ConnectorStateAppendOutcome::Committed {
            object_id,
            root_object_id,
            seq,
            snapshot_object_id,
        } => {
            assert_eq!(seq, 0);
            assert_eq!(snapshot_object_id, None);
            Ok(SeededConnectorState {
                root_object_id,
                head_object_id: object_id,
                lease_object_id,
                lease_seq,
                lease_expiry_unix_secs: 0,
            })
        }
        ConnectorStateAppendOutcome::Conflict { .. } => {
            Err("initial durable connector-state append should not conflict".into())
        }
    }
}

pub async fn seed_singleton_writer_connector_state_with_durable_lease(
    state_root: &Path,
    connector_id: &ConnectorId,
    zone_id: &ZoneId,
    object_id_key: ObjectIdKey,
    holder: TailscaleNodeId,
) -> Result<SeededConnectorState, Box<dyn std::error::Error>> {
    seed_singleton_writer_connector_state_with_durable_lease_signers(
        state_root,
        connector_id,
        zone_id,
        object_id_key,
        holder,
        &["node-a", "node-b"],
    )
    .await
}

pub async fn seed_singleton_writer_connector_state_with_durable_lease_signers(
    state_root: &Path,
    connector_id: &ConnectorId,
    zone_id: &ZoneId,
    object_id_key: ObjectIdKey,
    holder: TailscaleNodeId,
    quorum_signers: &[&str],
) -> Result<SeededConnectorState, Box<dyn std::error::Error>> {
    let object_store_dir = connector_state_canonical_object_store_dir(state_root, connector_id);
    let object_store: Arc<dyn fcp_store::ObjectStore> =
        Arc::new(fcp_store::DurableObjectStore::open(
            fcp_store::DurableObjectStoreConfig::new(&object_store_dir),
        )?);
    let subject_object_id =
        singleton_writer_connector_lease_subject_id_for_test(connector_id, zone_id);
    let lease = durable_core_lease_for_test(
        zone_id,
        subject_object_id,
        holder,
        10,
        1_800_200_300,
        host_integration_signature_set(quorum_signers),
    );
    let lease_expiry_unix_secs = lease.exp;
    let lease_object = stored_core_lease_for_test(&lease, &object_id_key);
    let lease_object_id = lease_object.object_id;
    object_store.put(lease_object).await?;

    let state_store = fcp_store::FcpStoreConnectorStateStore::new(
        Arc::clone(&object_store),
        object_id_key,
        connector_id.clone(),
        zone_id.clone(),
    )
    .with_snapshot_every_entries(0)
    .with_snapshot_every_secs(0);
    let (authorization, signing_key) =
        connector_state_write_authorization_for_test_with_key(connector_id, zone_id);
    let state_object = sign_durable_connector_state_object_for_test(
        durable_connector_state_object_for_test(connector_id, zone_id, 0, None, lease_object_id),
        &signing_key,
    );
    let lease_seq = state_object.lease_seq;
    let append = ConnectorStateStore::append_object(
        &state_store,
        connector_id,
        &authorization,
        state_object,
    )
    .await?;

    match append {
        ConnectorStateAppendOutcome::Committed {
            object_id,
            root_object_id,
            seq,
            snapshot_object_id,
        } => {
            assert_eq!(seq, 0);
            assert_eq!(snapshot_object_id, None);
            Ok(SeededConnectorState {
                root_object_id,
                head_object_id: object_id,
                lease_object_id,
                lease_seq,
                lease_expiry_unix_secs,
            })
        }
        ConnectorStateAppendOutcome::Conflict { .. } => {
            Err("initial durable connector-state append should not conflict".into())
        }
    }
}

fn test_connector_config(connector_id: &ConnectorId, name: &str, categories: &[&str]) -> Value {
    let categories = categories
        .iter()
        .map(|category| (*category).to_string())
        .collect::<Vec<_>>();
    test_connector_config_with_env(connector_id, name, &categories, &[])
}

fn test_connector_config_with_env(
    connector_id: &ConnectorId,
    name: &str,
    categories: &[String],
    extra_env: &[(&str, &str)],
) -> Value {
    let mut env = serde_json::Map::new();
    env.insert(
        "FCP_TEST_CONNECTOR_ID".to_string(),
        json!(connector_id.as_str()),
    );
    for (key, value) in extra_env {
        env.insert((*key).to_string(), json!(*value));
    }

    json!({
        "id": connector_id.as_str(),
        "binary": env!("CARGO_BIN_EXE_fcp-test-connector"),
        "name": name,
        "description": "Binary-level host integration test connector",
        "config": {},
        "categories": categories,
        "allowed_zones": [ZoneId::work().as_str()],
        "env": env,
    })
}

fn build_live_capability_token(
    signing_key: &Ed25519SigningKey,
    capability_id: &str,
    principal: &str,
    operation: &str,
    zone_id: &ZoneId,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability_id)
        .zone_id(zone_id.as_str())
        .principal(principal)
        .operations(&[operation])
        .issuer("node:test")
        .audience("*")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("test constraints CBOR should be valid")
        .sign(signing_key)
        .expect("capability token signing should succeed");
    CapabilityToken::from_raw(raw)
}

fn test_zone_policy(zone_id: ZoneId) -> ZonePolicyObject {
    ZonePolicyObject {
        header: ObjectHeader {
            encryption_kind: Default::default(),
            schema: fcp_cbor::SchemaId::new(
                "fcp.core",
                "ZonePolicyObject",
                semver::Version::new(1, 0, 0),
            ),
            zone_id: zone_id.clone(),
            created_at: u64::try_from(Utc::now().timestamp()).unwrap_or(0),
            provenance: Provenance::new(zone_id.clone()),
            refs: Vec::new(),
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        },
        zone_id,
        principal_allow: Vec::new(),
        principal_deny: Vec::new(),
        connector_allow: Vec::new(),
        connector_deny: Vec::new(),
        capability_allow: Vec::new(),
        capability_deny: Vec::new(),
        capability_ceiling: Vec::new(),
        transport_policy: ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: true,
        },
        decision_receipts: DecisionReceiptPolicy::default(),
        usage_budget: None,
        requires_posture: None,
    }
}

fn write_test_zone_policies_file(
    dir: &tempfile::TempDir,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let policy = test_zone_policy(ZoneId::work());
    let mut policies = HashMap::new();
    policies.insert(policy.zone_id.as_str().to_string(), policy);
    let path = dir.path().join("zone-policies.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&policies)?)?;
    Ok(path)
}

fn with_admin_auth_if_needed(method: &reqwest::Method, url: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    let Some(path) = reqwest::Url::parse(url)
        .ok()
        .map(|parsed| parsed.path().to_string())
    else {
        return headers;
    };
    if !protected_route_request(method, &path) {
        return headers;
    }

    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {TEST_ADMIN_BEARER_TOKEN}"))
            .expect("test admin bearer token should be a valid header"),
    );
    headers.insert("x-fcp-zone", HeaderValue::from_static("z:owner"));
    headers
}

fn protected_route_request(method: &reqwest::Method, path: &str) -> bool {
    let connector_admin_path = path.starts_with("/rpc/connectors/")
        && (path.contains("/config")
            || (*method == reqwest::Method::POST && path.ends_with("/artifact")));

    path.starts_with("/rpc/admin/")
        || path.starts_with("/rpc/rollout/")
        || path.starts_with("/rpc/lifecycle/")
        || path == "/rpc/cancel"
        || path == "/rpc/operations/cancel"
        || (*method == reqwest::Method::POST && path.starts_with("/rpc/connectors/apply"))
        || connector_admin_path
        || (*method == reqwest::Method::POST && path.starts_with("/rpc/supply-chain/verify"))
}

async fn http_get_status(
    client: reqwest::Client,
    url: String,
) -> Result<reqwest::StatusCode, Box<dyn std::error::Error>> {
    let headers = with_admin_auth_if_needed(&reqwest::Method::GET, &url);
    let status = client.get(url).headers(headers).send().await?.status();
    Ok(status)
}

async fn wait_for_host_readiness(
    child: &mut Child,
    client: &reqwest::Client,
    base_url: &str,
    stderr_logs: &StderrLogs,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut last_error = None;
    let deadline = Instant::now() + Duration::from_secs(45);

    while Instant::now() < deadline {
        if let Some(status) = child.try_wait()? {
            let raw_stderr = stderr_logs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            return Err(
                format!("fcp-host exited early with {status}; stderr: {raw_stderr:?}").into(),
            );
        }

        match fcp_async_core::time::timeout(
            Duration::from_millis(250),
            http_get_status(client.clone(), format!("{base_url}/rpc/health")),
        )
        .await
        {
            Ok(Ok(status)) if status.is_success() || status == reqwest::StatusCode::FORBIDDEN => {
                return Ok(());
            }
            Ok(Ok(status)) => {
                last_error = Some(format!("health returned {status}"));
                fcp_async_core::time::sleep(Duration::from_millis(50)).await;
            }
            Ok(Err(err)) => {
                last_error = Some(err.to_string());
                fcp_async_core::time::sleep(Duration::from_millis(50)).await;
            }
            Err(_) => {
                last_error = Some("health request timed out".to_string());
                fcp_async_core::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }

    let _ = child.kill();
    let _ = child.wait();
    let raw_stderr = stderr_logs
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    Err(format!(
        "timed out waiting for fcp-host readiness; last_error: {}; stderr: {raw_stderr:?}",
        last_error.unwrap_or_else(|| "none".to_string())
    )
    .into())
}

fn spawn_stderr_capture(
    child: &mut Child,
) -> Result<(StderrLogs, JoinHandle<()>), Box<dyn std::error::Error>> {
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| std::io::Error::other("fcp-host stderr pipe unavailable"))?;
    let logs = Arc::new(StdMutex::new(Vec::new()));
    let logs_for_thread = Arc::clone(&logs);
    let handle = std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            match line {
                Ok(line) => logs_for_thread
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(line),
                Err(_) => break,
            }
        }
    });
    Ok((logs, handle))
}

fn sanitize_connector_state_path_segment(value: &str) -> String {
    let segment = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    if segment.is_empty() || segment == "." || segment == ".." {
        "_".to_string()
    } else {
        segment
    }
}

fn connector_state_canonical_object_store_dir(
    root: &Path,
    connector_id: &ConnectorId,
) -> std::path::PathBuf {
    root.join(sanitize_connector_state_path_segment(connector_id.as_str()))
        .join("store")
        .join("objects")
}

fn connector_state_write_authorization_for_test_with_key(
    connector_id: &ConnectorId,
    zone_id: &ZoneId,
) -> (
    fcp_core::ConnectorStateWriteAuthorization,
    Ed25519SigningKey,
) {
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    let constraints = CapabilityConstraints {
        resource_allow: vec![fcp_core::connector_state_resource_uri(connector_id)],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor)
        .expect("test connector-state constraints should serialize");
    let now = Utc::now();
    let token = CapabilityToken::from_raw(
        CapabilityTokenBuilder::new()
            .capability_id(fcp_core::CONNECTOR_STATE_WRITE_CAPABILITY_ID)
            .zone_id(zone_id.as_str())
            .target_instance(instance_id.as_str())
            .principal("principal:test")
            .operations(&[fcp_core::CONNECTOR_STATE_APPEND_OPERATION_ID])
            .issuer("node:test")
            .validity(now, now + ChronoDuration::hours(1))
            .try_constraints_cbor(&constraints_cbor)
            .expect("test connector-state constraints should be accepted")
            .sign(&signing_key)
            .expect("test connector-state token should sign"),
    );
    let verifier = CapabilityVerifier::new(
        signing_key.verifying_key().to_bytes(),
        zone_id.clone(),
        instance_id,
    );

    let authorization = fcp_core::ConnectorStateWriteAuthorization::verify_append_token(
        &verifier,
        token,
        connector_id,
        zone_id,
    )
    .expect("test connector-state write token should authorize append");
    (authorization, signing_key)
}

fn durable_connector_state_object_for_test(
    connector_id: &ConnectorId,
    zone_id: &ZoneId,
    seq: u64,
    prev: Option<ObjectId>,
    lease_object_id: ObjectId,
) -> fcp_core::ConnectorStateObject {
    let seq_byte = u8::try_from(seq).expect("test sequence should fit in CBOR byte");
    fcp_core::ConnectorStateObject {
        header: ObjectHeader {
            encryption_kind: Default::default(),
            schema: fcp_store::FcpStoreConnectorStateStore::state_object_schema_id(),
            zone_id: zone_id.clone(),
            created_at: 1_800_200_000 + seq,
            provenance: Provenance::new(zone_id.clone()),
            refs: vec![lease_object_id],
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        },
        connector_id: connector_id.clone(),
        instance_id: None,
        zone_id: zone_id.clone(),
        prev,
        seq,
        state_cbor: vec![0xa1, 0x61, b'n', seq_byte],
        updated_at: 1_800_200_000 + seq,
        lease_seq: seq + 10,
        lease_object_id,
        writer_public_key: [0u8; 32],
        signature: fcp_core::Signature::zero(),
    }
}

fn sign_durable_connector_state_object_for_test(
    mut state: fcp_core::ConnectorStateObject,
    signing_key: &Ed25519SigningKey,
) -> fcp_core::ConnectorStateObject {
    state
        .sign_with(signing_key)
        .expect("test connector state should sign");
    state
}

fn update_len_prefixed_for_test(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(bytes);
}

fn host_integration_signature_set(signers: &[&str]) -> SignatureSet {
    let mut signatures = SignatureSet::new();
    for (idx, signer) in signers.iter().enumerate() {
        let signature_byte = u8::try_from(idx).unwrap_or(u8::MAX);
        signatures.add(NodeSignature::new(
            fcp_core::NodeId::new(*signer),
            [signature_byte; 64],
            1_800_200_000 + u64::try_from(idx).unwrap_or(u64::MAX),
        ));
    }
    signatures
}

fn durable_core_lease_for_test(
    zone_id: &ZoneId,
    subject_object_id: ObjectId,
    holder: TailscaleNodeId,
    lease_seq: u64,
    exp: u64,
    quorum_signatures: SignatureSet,
) -> CoreLease {
    CoreLease {
        header: ObjectHeader {
            encryption_kind: Default::default(),
            schema: fcp_cbor::SchemaId::new("fcp.lease", "lease", semver::Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: exp.saturating_sub(300),
            provenance: Provenance::new(zone_id.clone()),
            refs: vec![subject_object_id],
            foreign_refs: Vec::new(),
            ttl_secs: Some(300),
            placement: None,
        },
        holder,
        lease_seq,
        exp,
        subject_object_id,
        purpose: CoreLeasePurpose::ConnectorStateWrite,
        quorum_signatures,
    }
}

fn stored_core_lease_for_test(lease: &CoreLease, object_id_key: &ObjectIdKey) -> StoredObject {
    let body = fcp_cbor::CanonicalSerializer::serialize(lease, &lease.header.schema)
        .expect("test core lease should serialize");
    let object_id =
        StoredObject::derive_id(&lease.header, &body, object_id_key).expect("derive lease id");
    StoredObject {
        object_id,
        header: lease.header.clone(),
        body,
        storage: StorageMeta {
            retention: EvictionPolicy::Lease {
                expires_at: lease.exp,
            },
        },
    }
}
