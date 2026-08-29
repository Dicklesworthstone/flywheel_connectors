//! Integration tests: fcp-host discovery/introspection against real subprocess connectors.
//!
//! Bead: bd-219o

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader};
use std::net::TcpListener as StdTcpListener;
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex as StdMutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use chrono::{Duration as ChronoDuration, TimeZone, Utc};
use fcp_async_core::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as AsyncBufReader};
use fcp_async_core::process::{
    Child as AsyncChild, ChildStdin as AsyncChildStdin, ChildStdout as AsyncChildStdout,
    Command as AsyncCommand, Stdio as AsyncStdio,
};
use fcp_async_core::sync::Mutex;
use fcp_async_core::task::JoinHandle as AsyncJoinHandle;
use fcp_core::{
    AttestationMaterial, AttestationMetadata, AttestationPredicateType, CapabilityConstraints,
    CapabilityToken, CapabilityVerifier, ConnectorStateAppendOutcome, ConnectorStateStore,
    CorrelationId, DecisionReceiptPolicy, EvictionPolicy, InstanceId, Lease as CoreLease,
    LeasePurpose as CoreLeasePurpose, NodeSignature, ObjectHeader, ObjectId, ObjectIdKey,
    Provenance, RollbackRules, RolloutPolicy, SBOM_SIGNED_FIELDS,
    SUPPLY_CHAIN_ATTESTATION_SIGNED_FIELDS, SbomComponent, SbomDependency, SignatureSet,
    StorageMeta, StoredObject, SuccessThresholds, TailscaleNodeId, TransitionReason, ZoneId,
    ZonePolicyObject, ZoneTransportPolicy,
};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_evidence::{
    SbomFormat, SoftwareBillOfMaterials, SupplyChainAttestation, SupplyChainSignature,
    TrustRootBinding, VerificationReasonCode,
};
use fcp_host::{
    BatchInvokeResponse, BatchStatus, CancelReason, CancellationOutcome, CancellationRequest,
    CancellationResponse, CleanupBehavior, ConfigDiffKind, ConfigRevisionRecord,
    ConnectorAdminStatus, ConnectorArchetype, ConnectorConfigApplyRequest,
    ConnectorConfigApplyResponse, ConnectorConfigDiffRequest, ConnectorConfigDiffResponse,
    ConnectorConfigRevisionsResponse, ConnectorConfigRollbackRequest, ConnectorConfigSnapshot,
    ConnectorConfigSnapshotSource, ConnectorConfigValidateRequest, ConnectorConfigValidateResponse,
    ConnectorDriftKind, ConnectorInventoryResponse, ConnectorRegistry, ConnectorSummary,
    DesiredRuntimeState, DiscoveryEndpoint, DiscoveryResponse, GateOutcome, HostAdminStateStore,
    HostHealthResponse, HostHealthStatus, HostPreflightRequest, HostSimulateRequest,
    HostSimulateResponse, IntrospectionResponse, ObservedRuntimeState, OperationResultStatus,
    PolicyEngine, PreflightRequest, PreflightResponse, ReceiptQueryRequest, ReceiptQueryResponse,
    RecoveryAction, RolloutDecision, RolloutOutcome, SimulatePhase, SimulateReceiptQueryRequest,
    SimulateReceiptQueryResponse,
};
use fcp_kernel::{
    ApprovalMode, ConnectorHealth, ConnectorId, HandshakeRequest, HealthSnapshot, IdempotencyClass,
    Introspection, InvokeRequest, InvokeResponse, InvokeStatus, LifecycleManager, LifecycleRecord,
    LifecycleState, LifecycleStatus, OperationId, RequestId, SelfCheckReport, SelfCheckStatus,
};
use fcp_testkit::LogCapture;
use reqwest::header::{
    AUTHORIZATION, CACHE_CONTROL, ETAG, HeaderMap, HeaderValue, IF_NONE_MATCH, LAST_MODIFIED,
};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

#[derive(Debug, Deserialize)]
struct PinStateResponse {
    connector_id: String,
    pinned: bool,
    version: Option<semver::Version>,
}

#[derive(Debug, Deserialize)]
struct RolloutStatusResponse {
    #[serde(flatten)]
    status: LifecycleStatus,
    pinned: bool,
    pinned_version: Option<semver::Version>,
    canary_percent: u8,
}

#[derive(Debug, Deserialize)]
struct ManualRollbackResponse {
    connector_id: String,
    state: LifecycleState,
    from_version: semver::Version,
    to_version: semver::Version,
    message: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CapabilityPreflightVectorTokenMode {
    Missing,
    Signed,
}

#[derive(Debug, Deserialize)]
struct CapabilityPreflightVectorCase {
    name: String,
    principal_override: String,
    token_mode: CapabilityPreflightVectorTokenMode,
    signing_key_hex: Option<String>,
    token_principal: Option<String>,
    not_before_offset_secs: Option<i64>,
    expires_offset_secs: Option<i64>,
    expected_allowed: bool,
    expected_reason_contains: Option<String>,
}

fn test_time() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 3, 7, 12, 0, 0).unwrap()
}

const TEST_PRINCIPAL: &str = "agent:test";
const TEST_OPERATION: &str = "test.echo";
const TEST_CAPABILITY_ID: &str = "cap.test.echo";
const TEST_ADMIN_BEARER_TOKEN: &str = "host-test-admin-bearer";
const TRUSTED_CAPABILITY_SIGNING_KEY_HEX: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";
const CONNECTOR_STATE_DIR_ENV: &str = "FCP_CONNECTOR_STATE";
const CONNECTOR_STATE_OBJECT_ID_KEY_ENV: &str = "FCP_CONNECTOR_STATE_OBJECT_ID_KEY";

fn test_zone_policy(zone_id: ZoneId) -> ZonePolicyObject {
    ZonePolicyObject {
        header: ObjectHeader {
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

struct ConnectorProcessRunner {
    child: AsyncChild,
    stdin: AsyncChildStdin,
    stdout: AsyncBufReader<AsyncChildStdout>,
    _stderr_task: AsyncJoinHandle<()>,
}

impl ConnectorProcessRunner {
    async fn spawn(command: &str, args: &[&str], env: &[(&str, &str)]) -> std::io::Result<Self> {
        let mut cmd = AsyncCommand::new(command);
        cmd.args(args)
            .stdin(AsyncStdio::piped())
            .stdout(AsyncStdio::piped())
            .stderr(AsyncStdio::piped())
            .kill_on_drop(true);

        for (key, value) in env {
            cmd.env(key, value);
        }

        let mut child = cmd.spawn()?;
        let stdin = child
            .stdin()
            .ok_or_else(|| std::io::Error::other("connector stdin unavailable"))?;
        let stdout = child
            .stdout()
            .ok_or_else(|| std::io::Error::other("connector stdout unavailable"))?;
        let stderr = child
            .stderr()
            .ok_or_else(|| std::io::Error::other("connector stderr unavailable"))?;

        let stderr_task = fcp_async_core::task::spawn(async move {
            let mut reader = AsyncBufReader::new(stderr);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        });

        Ok(Self {
            child,
            stdin,
            stdout: AsyncBufReader::new(stdout),
            _stderr_task: stderr_task,
        })
    }

    async fn send_json(&mut self, value: &serde_json::Value) -> std::io::Result<()> {
        let line = serde_json::to_string(value)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
        self.stdin.write_all(line.as_bytes()).await?;
        self.stdin.write_all(b"\n").await?;
        self.stdin.flush().await?;
        Ok(())
    }

    async fn read_json(&mut self) -> std::io::Result<serde_json::Value> {
        let mut line = String::new();
        let bytes = self.stdout.read_line(&mut line).await?;
        if bytes == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connector closed stdout",
            ));
        }
        serde_json::from_str::<serde_json::Value>(line.trim())
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
    }

    async fn request(&mut self, value: &serde_json::Value) -> std::io::Result<serde_json::Value> {
        self.send_json(value).await?;
        let response = self.read_json().await?;
        validate_jsonrpc_response(value, response)
    }

    fn terminate(&mut self) -> std::io::Result<()> {
        self.child.kill().map_err(Into::into)
    }
}

fn validate_jsonrpc_response(
    request: &serde_json::Value,
    response: serde_json::Value,
) -> std::io::Result<serde_json::Value> {
    let response_object = response.as_object().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "connector response must be a JSON object",
        )
    })?;

    match response_object
        .get("jsonrpc")
        .and_then(serde_json::Value::as_str)
    {
        Some("2.0") => {}
        Some(version) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("connector response used unsupported jsonrpc version '{version}'"),
            ));
        }
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "connector response missing jsonrpc version",
            ));
        }
    }

    if let Some(expected_id) = request.get("id") {
        match response_object.get("id") {
            Some(actual_id) if actual_id == expected_id => {}
            Some(actual_id) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "connector response id mismatch: expected {expected_id}, got {actual_id}"
                    ),
                ));
            }
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "connector response missing id",
                ));
            }
        }
    }

    let has_result = response_object.contains_key("result");
    let has_error = response_object.contains_key("error");
    if has_result == has_error {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "connector response must contain exactly one of result or error",
        ));
    }

    Ok(response)
}

fn valid_digest() -> String {
    format!("blake3-256:{}", "a".repeat(64))
}

fn valid_attestation(digest: &str) -> SupplyChainAttestation {
    SupplyChainAttestation {
        format: "fcp-supply-chain-attestation".to_string(),
        schema_version: "1.0".to_string(),
        subject_digest: digest.to_string(),
        predicate_type: AttestationPredicateType::SlsaProvenanceV1,
        builder_id: "ci.example.com/builder".to_string(),
        build_type: "container".to_string(),
        materials: vec![AttestationMaterial {
            uri: "https://github.com/example/repo".to_string(),
            digest: format!("blake3-256:{}", "e".repeat(64)),
        }],
        metadata: AttestationMetadata {
            build_started_at: test_time(),
            build_finished_at: test_time(),
            invocation_id: Some("inv-001".to_string()),
        },
        slsa_level: 2,
        provenance_hash: format!("blake3-256:{}", "b".repeat(64)),
        trust_root: TrustRootBinding {
            root_type: "sigstore".to_string(),
            root_id: "root-001".to_string(),
        },
        builder_allowlist: vec!["ci.example.com/builder".to_string()],
        signature: SupplyChainSignature {
            algorithm: "ed25519".to_string(),
            key_id: "key-001".to_string(),
            signature: "f".repeat(128),
            signed_fields: SUPPLY_CHAIN_ATTESTATION_SIGNED_FIELDS
                .iter()
                .map(|field| (*field).to_string())
                .collect(),
        },
    }
}

fn valid_sbom() -> SoftwareBillOfMaterials {
    SoftwareBillOfMaterials {
        format: "fcp-sbom".to_string(),
        schema_version: "1.0".to_string(),
        bom_format: SbomFormat::Cyclonedx,
        bom_version: "1.0.0".to_string(),
        tool_chain: vec!["cargo".to_string()],
        components: vec![SbomComponent {
            component_id: "comp-001".to_string(),
            name: "fcp-core".to_string(),
            version: "0.1.0".to_string(),
            hashes: vec![format!("blake3-256:{}", "c".repeat(64))],
            licenses: vec!["Apache-2.0".to_string()],
        }],
        dependencies: vec![SbomDependency {
            component_id: "comp-001".to_string(),
            depends_on: vec![],
        }],
        trust_root: TrustRootBinding {
            root_type: "sigstore".to_string(),
            root_id: "root-002".to_string(),
        },
        signature: SupplyChainSignature {
            algorithm: "ed25519".to_string(),
            key_id: "key-002".to_string(),
            signature: "f".repeat(128),
            signed_fields: SBOM_SIGNED_FIELDS
                .iter()
                .map(|field| (*field).to_string())
                .collect(),
        },
    }
}

struct AllowAllPolicy;

#[async_trait::async_trait]
impl PolicyEngine for AllowAllPolicy {
    async fn evaluate_preflight(&self, _request: &PreflightRequest) -> PreflightResponse {
        PreflightResponse::allowed()
    }
}

struct SubprocessConnector {
    summary: ConnectorSummary,
    runner: Mutex<ConnectorProcessRunner>,
}

impl SubprocessConnector {
    async fn spawn(id: ConnectorId, name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let binary = env!("CARGO_BIN_EXE_fcp-test-connector");
        let env = [("FCP_TEST_CONNECTOR_ID", id.as_str())];
        let runner = ConnectorProcessRunner::spawn(binary, &[], &env).await?;

        let summary = ConnectorSummary {
            id,
            name: name.to_string(),
            description: Some("Subprocess test connector".to_string()),
            version: semver::Version::new(1, 0, 0),
            categories: vec!["test".to_string()],
            tool_count: 1,
            max_safety_tier: fcp_core::SafetyTier::Safe,
            enabled: true,
            health: ConnectorHealth::healthy(),
            last_health_check: None,
        };

        Ok(Self {
            summary,
            runner: Mutex::new(runner),
        })
    }

    async fn rpc(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> std::io::Result<serde_json::Value> {
        let mut runner = self.runner.lock().await;
        let request = json!({
            "jsonrpc": "2.0",
            "id": RequestId::random().0,
            "method": method,
            "params": params,
        });
        let response = runner.request(&request).await?;
        if let Some(error) = response.get("error") {
            return Err(std::io::Error::other(format!("connector error: {error}")));
        }
        Ok(response.get("result").cloned().unwrap_or(json!({})))
    }

    async fn handshake(&self) -> std::io::Result<()> {
        let request = HandshakeRequest {
            protocol_version: "2.0".to_string(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0_u8; 32],
            nonce: [42_u8; 32],
            capabilities_requested: Vec::new(),
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        };
        let params = serde_json::to_value(request)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
        let _ = self.rpc("handshake", params).await?;
        Ok(())
    }

    async fn introspect(&self) -> std::io::Result<Introspection> {
        let result = self.rpc("introspect", json!({})).await?;
        serde_json::from_value(result)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
    }

    async fn health(&self) -> std::io::Result<HealthSnapshot> {
        let result = self.rpc("health", json!({})).await?;
        serde_json::from_value(result)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
    }

    async fn self_check(&self) -> std::io::Result<SelfCheckReport> {
        let result = self.rpc("self_check", json!({})).await?;
        serde_json::from_value(result)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
    }

    async fn invoke(&self, request: InvokeRequest) -> std::io::Result<InvokeResponse> {
        let params = serde_json::to_value(request)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
        let result = self.rpc("invoke", params).await?;
        serde_json::from_value(result)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
    }

    async fn terminate(&self) -> std::io::Result<()> {
        let mut runner = self.runner.lock().await;
        runner.terminate()
    }

    async fn summary_with_health(&self) -> ConnectorSummary {
        let mut summary = self.summary.clone();
        match self.health().await {
            Ok(snapshot) => {
                summary.health = ConnectorHealth::from(&snapshot.status);
                summary.last_health_check = Some(chrono::Utc::now());
            }
            Err(err) => {
                summary.health =
                    ConnectorHealth::unavailable(format!("health check failed: {err}"));
                summary.last_health_check = Some(chrono::Utc::now());
            }
        }
        summary
    }
}

struct SubprocessRegistry {
    connectors: HashMap<ConnectorId, Arc<SubprocessConnector>>,
    version: u64,
}

impl SubprocessRegistry {
    fn new(connectors: Vec<SubprocessConnector>) -> Self {
        let mut map = HashMap::new();
        for connector in connectors {
            map.insert(connector.summary.id.clone(), Arc::new(connector));
        }
        Self {
            connectors: map,
            version: 1,
        }
    }

    async fn invoke(
        &self,
        id: &ConnectorId,
        request: InvokeRequest,
    ) -> std::io::Result<InvokeResponse> {
        let connector = self.connectors.get(id).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "connector missing")
        })?;
        connector.invoke(request).await
    }

    async fn terminate_all(&self) -> std::io::Result<()> {
        for connector in self.connectors.values() {
            let _ = connector.terminate().await;
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl ConnectorRegistry for SubprocessRegistry {
    async fn list(&self) -> Vec<ConnectorSummary> {
        let mut results = Vec::new();
        for connector in self.connectors.values() {
            results.push(connector.summary_with_health().await);
        }
        results
    }

    async fn get(&self, id: &ConnectorId) -> Option<ConnectorSummary> {
        self.connectors
            .get(id)
            .map(|connector| connector.summary.clone())
    }

    async fn get_introspection(&self, id: &ConnectorId) -> Option<Introspection> {
        let connector = self.connectors.get(id)?;
        connector.introspect().await.ok()
    }

    async fn get_archetype(&self, id: &ConnectorId) -> Option<ConnectorArchetype> {
        self.connectors.get(id)?;
        Some(ConnectorArchetype::Unknown)
    }

    async fn get_rate_limits(&self, id: &ConnectorId) -> Option<fcp_kernel::RateLimitDeclarations> {
        self.connectors.get(id)?;
        None
    }

    async fn self_check(&self, id: &ConnectorId) -> Option<SelfCheckReport> {
        let connector = self.connectors.get(id)?;
        connector.self_check().await.ok()
    }

    fn version(&self) -> u64 {
        self.version
    }
}

fn capability_public_key_hex(signing_key: &Ed25519SigningKey) -> String {
    hex::encode(signing_key.verifying_key().to_bytes())
}

fn signing_key_from_hex(hex_key: &str) -> Ed25519SigningKey {
    let bytes = hex::decode(hex_key).expect("signing key hex must decode");
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .expect("signing key hex must decode to 32 bytes");
    Ed25519SigningKey::from_bytes(&key_bytes).expect("signing key bytes must be valid")
}

fn constraints_cbor_bytes() -> Vec<u8> {
    // C3.4: tokens MUST include constraints (default-deny)
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    cbor
}

fn build_live_capability_token(
    signing_key: &Ed25519SigningKey,
    capability_id: &str,
    principal: &str,
    operation: &str,
    zone_id: &ZoneId,
) -> CapabilityToken {
    let now = Utc::now();
    let cbor = constraints_cbor_bytes();
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability_id)
        .zone_id(zone_id.as_str())
        .principal(principal)
        .operations(&[operation])
        .issuer("node:test")
        .audience("*")
        .validity(now, now + chrono::Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("test constraints CBOR should be valid")
        .sign(signing_key)
        .expect("capability token signing should succeed");
    CapabilityToken::from_raw(raw)
}

fn build_live_capability_token_with_validity(
    signing_key: &Ed25519SigningKey,
    capability_id: &str,
    principal: &str,
    operation: &str,
    zone_id: &ZoneId,
    not_before: chrono::DateTime<Utc>,
    expires: chrono::DateTime<Utc>,
) -> CapabilityToken {
    let cbor = constraints_cbor_bytes();
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability_id)
        .zone_id(zone_id.as_str())
        .principal(principal)
        .operations(&[operation])
        .issuer("node:test")
        .audience("*")
        .validity(not_before, expires)
        .try_constraints_cbor(&cbor)
        .expect("test constraints CBOR should be valid")
        .sign(signing_key)
        .expect("capability token signing should succeed");
    CapabilityToken::from_raw(raw)
}

fn build_invoke_request(
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

fn build_host_preflight_request(
    request: &InvokeRequest,
    principal: Option<&str>,
) -> HostPreflightRequest {
    HostPreflightRequest {
        request_id: request.id.clone(),
        connector_id: request.connector_id.clone(),
        operation: request.operation.to_string(),
        params: Some(request.input.clone()),
        principal: principal.map(str::to_owned),
        zone_id: Some(request.zone_id.clone()),
        capability_token: Some(request.capability_token.clone()),
        approval_tokens: request.approval_tokens.clone(),
    }
}

fn build_vector_preflight_request(
    connector_id: ConnectorId,
    principal_override: &str,
    capability_token: Option<CapabilityToken>,
) -> HostPreflightRequest {
    HostPreflightRequest {
        request_id: RequestId::random(),
        connector_id,
        operation: TEST_OPERATION.to_string(),
        params: Some(json!({ "message": "hello" })),
        principal: Some(principal_override.to_owned()),
        zone_id: Some(ZoneId::work()),
        capability_token,
        approval_tokens: Vec::new(),
    }
}

fn batch_operation_json(
    id: &str,
    request: InvokeRequest,
    depends_on: &[&str],
) -> serde_json::Value {
    json!({
        "id": id,
        "request": request,
        "depends_on": depends_on,
    })
}

fn scheduled_batch_operation_json(
    id: &str,
    request: InvokeRequest,
    estimated_duration_ms: u64,
) -> serde_json::Value {
    let mut operation = batch_operation_json(id, request, &[]);
    operation
        .as_object_mut()
        .expect("batch operation json object")
        .insert(
            "scheduler".to_string(),
            json!({
                "estimated_duration_ms": estimated_duration_ms,
                "fairness_key": "z:work",
            }),
        );
    operation
}

#[fcp_async_core::runtime::test]
async fn host_discovery_with_subprocess_connectors() -> Result<(), Box<dyn std::error::Error>> {
    let connector_a_id = ConnectorId::from_static("fcp.test.echo:utility:1.0.0");
    let connector_b_id = ConnectorId::from_static("fcp.test.ping:utility:1.0.0");

    let connector_a = SubprocessConnector::spawn(connector_a_id.clone(), "Test Echo").await?;
    let connector_b = SubprocessConnector::spawn(connector_b_id.clone(), "Test Ping").await?;

    connector_a.handshake().await?;
    connector_b.handshake().await?;

    let registry = Arc::new(SubprocessRegistry::new(vec![connector_a, connector_b]));
    let endpoint = DiscoveryEndpoint::new(Arc::clone(&registry), Arc::new(AllowAllPolicy));

    let response = endpoint.discover(None).await;
    assert_eq!(response.connectors.len(), 2);
    assert!(response.connectors.iter().any(|c| c.id == connector_a_id));
    assert!(response.connectors.iter().any(|c| c.id == connector_b_id));

    let mut logs = Vec::new();
    logs.push(json!({
        "step": "discover",
        "correlation_id": CorrelationId::new().to_string(),
        "connector_count": response.connectors.len(),
    }));

    let introspection_a = endpoint.introspect(&connector_a_id).await?;
    assert_eq!(
        introspection_a.archetype,
        ConnectorArchetype::Unknown,
        "subprocess integration registry must preserve unknown archetype metadata"
    );
    assert!(
        introspection_a.rate_limits.is_none(),
        "subprocess integration registry must preserve unknown rate-limit declarations"
    );
    assert!(
        introspection_a
            .introspection
            .operations
            .iter()
            .any(|op| op.id == OperationId::from_static("test.echo"))
    );
    logs.push(json!({
        "step": "introspect",
        "correlation_id": CorrelationId::new().to_string(),
        "connector_id": connector_a_id.as_str(),
    }));

    let introspection_b = endpoint.introspect(&connector_b_id).await?;
    assert_eq!(
        introspection_b.archetype,
        ConnectorArchetype::Unknown,
        "subprocess integration registry must preserve unknown archetype metadata"
    );
    assert!(
        introspection_b.rate_limits.is_none(),
        "subprocess integration registry must preserve unknown rate-limit declarations"
    );
    assert!(
        introspection_b
            .introspection
            .operations
            .iter()
            .any(|op| op.id == OperationId::from_static("test.echo"))
    );
    logs.push(json!({
        "step": "introspect",
        "correlation_id": CorrelationId::new().to_string(),
        "connector_id": connector_b_id.as_str(),
    }));

    let capability_signing_key = Ed25519SigningKey::generate();
    let (invoke_request, correlation_id) =
        build_invoke_request(connector_a_id.clone(), &capability_signing_key);
    let invoke_response = registry.invoke(&connector_a_id, invoke_request).await?;
    assert_eq!(invoke_response.status, InvokeStatus::Ok);
    assert!(invoke_response.receipt_id.is_some());
    logs.push(json!({
        "step": "invoke",
        "correlation_id": correlation_id.to_string(),
        "connector_id": connector_a_id.as_str(),
        "receipt_id": invoke_response
            .receipt_id
            .as_ref()
            .map(|id| id.to_string()),
    }));

    let self_check = endpoint.self_check(&connector_a_id).await?;
    assert_eq!(self_check.report.status, SelfCheckStatus::Ok);
    logs.push(json!({
        "step": "self_check",
        "correlation_id": CorrelationId::new().to_string(),
        "connector_id": connector_a_id.as_str(),
        "status": format!("{:?}", self_check.report.status),
    }));

    for entry in &logs {
        assert!(entry.get("correlation_id").is_some());
    }

    registry.terminate_all().await?;

    Ok(())
}

type StderrLogs = Arc<StdMutex<Vec<String>>>;

fn build_http_client(builder: reqwest::ClientBuilder) -> Result<reqwest::Client, reqwest::Error> {
    builder.build()
}

async fn http_get_status(
    client: reqwest::Client,
    url: String,
) -> Result<reqwest::StatusCode, Box<dyn std::error::Error>> {
    let headers = with_admin_auth_if_needed(&reqwest::Method::GET, &url, None).unwrap_or_default();
    let status = client.get(url).headers(headers).send().await?.status();
    Ok(status)
}

async fn http_get_json<T>(
    client: reqwest::Client,
    url: String,
) -> Result<T, Box<dyn std::error::Error>>
where
    T: DeserializeOwned + Send + 'static,
{
    Ok(http_get_json_response(client, url, None).await?.body)
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

fn admin_auth_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {TEST_ADMIN_BEARER_TOKEN}"))
            .expect("test admin bearer token should be a valid header"),
    );
    headers.insert("x-fcp-zone", HeaderValue::from_static("z:owner"));
    headers
}

fn cancel_admin_headers(principal: &str) -> HeaderMap {
    let mut headers = admin_auth_headers();
    headers.insert(
        "x-principal",
        HeaderValue::from_str(principal).expect("test principal should be a valid header"),
    );
    headers
}

fn with_admin_auth_if_needed(
    method: &reqwest::Method,
    url: &str,
    headers: Option<HeaderMap>,
) -> Option<HeaderMap> {
    let path = reqwest::Url::parse(url)
        .ok()
        .map(|parsed| parsed.path().to_string())?;
    if !protected_route_request(method, &path) {
        return headers;
    }

    let mut headers = headers.unwrap_or_default();
    headers.entry(AUTHORIZATION).or_insert_with(|| {
        HeaderValue::from_str(&format!("Bearer {TEST_ADMIN_BEARER_TOKEN}"))
            .expect("test admin bearer token should be a valid header")
    });
    headers
        .entry("x-fcp-zone")
        .or_insert_with(|| HeaderValue::from_static("z:owner"));
    Some(headers)
}

async fn http_post_json<B, T>(
    client: reqwest::Client,
    url: String,
    body: B,
) -> Result<T, Box<dyn std::error::Error>>
where
    B: serde::Serialize + Send + 'static,
    T: DeserializeOwned + Send + 'static,
{
    Ok(http_post_json_response(client, url, body, None).await?.body)
}

async fn http_put_json<B, T>(
    client: reqwest::Client,
    url: String,
    body: B,
) -> Result<T, Box<dyn std::error::Error>>
where
    B: serde::Serialize + Send + 'static,
    T: DeserializeOwned + Send + 'static,
{
    let headers = with_admin_auth_if_needed(&reqwest::Method::PUT, &url, None).unwrap_or_default();
    let response = client
        .put(url.as_str())
        .headers(headers)
        .json(&body)
        .send()
        .await?;
    let (_, _, body) = read_json_response(&reqwest::Method::PUT, &url, response).await?;
    Ok(body)
}

async fn http_delete_json<T>(
    client: reqwest::Client,
    url: String,
) -> Result<T, Box<dyn std::error::Error>>
where
    T: DeserializeOwned + Send + 'static,
{
    let headers =
        with_admin_auth_if_needed(&reqwest::Method::DELETE, &url, None).unwrap_or_default();
    let response = client.delete(url.as_str()).headers(headers).send().await?;
    let (_, _, body) = read_json_response(&reqwest::Method::DELETE, &url, response).await?;
    Ok(body)
}

struct HttpJsonResponse<T> {
    status: reqwest::StatusCode,
    headers: HeaderMap,
    body: T,
}

/// Read a response as JSON, preserving the status line and a body excerpt in
/// every failure.
///
/// br-mvl7c: `error_for_status()` and `response.json()` both discard the
/// body, which made the rare loaded-suite host-process failures nearly
/// impossible to diagnose.
async fn read_json_response<T>(
    method: &reqwest::Method,
    url: &str,
    response: reqwest::Response,
) -> Result<(reqwest::StatusCode, HeaderMap, T), Box<dyn std::error::Error>>
where
    T: DeserializeOwned,
{
    let status = response.status();
    let headers = response.headers().clone();
    let body_text = response.text().await?;
    if !status.is_success() {
        let excerpt: String = body_text.chars().take(512).collect();
        return Err(format!("{method} {url} failed with {status}; body excerpt: {excerpt}").into());
    }
    let body = serde_json::from_str::<T>(&body_text).map_err(|error| {
        let excerpt: String = body_text.chars().take(512).collect();
        format!("{method} {url} returned unparseable JSON: {error}; body excerpt: {excerpt}")
    })?;
    Ok((status, headers, body))
}

async fn http_get_json_response<T>(
    client: reqwest::Client,
    url: String,
    headers: Option<HeaderMap>,
) -> Result<HttpJsonResponse<T>, Box<dyn std::error::Error>>
where
    T: DeserializeOwned + Send + 'static,
{
    let auth_headers = with_admin_auth_if_needed(&reqwest::Method::GET, &url, headers);
    let mut request = client.get(url.as_str());
    if let Some(hdrs) = auth_headers {
        request = request.headers(hdrs);
    }
    let response = request.send().await?;
    let (status, resp_headers, body) =
        read_json_response(&reqwest::Method::GET, &url, response).await?;
    Ok(HttpJsonResponse {
        status,
        headers: resp_headers,
        body,
    })
}

async fn http_post_json_response<B, T>(
    client: reqwest::Client,
    url: String,
    body: B,
    headers: Option<HeaderMap>,
) -> Result<HttpJsonResponse<T>, Box<dyn std::error::Error>>
where
    B: serde::Serialize + Send + 'static,
    T: DeserializeOwned + Send + 'static,
{
    let auth_headers = with_admin_auth_if_needed(&reqwest::Method::POST, &url, headers);
    let mut request = client.post(url.as_str()).json(&body);
    if let Some(hdrs) = auth_headers {
        request = request.headers(hdrs);
    }
    let response = request.send().await?;
    let (status, resp_headers, body) =
        read_json_response(&reqwest::Method::POST, &url, response).await?;
    Ok(HttpJsonResponse {
        status,
        headers: resp_headers,
        body,
    })
}

async fn request_status_text(
    client: reqwest::Client,
    method: reqwest::Method,
    url: String,
    body: Option<serde_json::Value>,
    headers: Option<HeaderMap>,
) -> Result<(reqwest::StatusCode, String), Box<dyn std::error::Error>> {
    let mut request = client.request(method, url);
    if let Some(hdrs) = headers {
        request = request.headers(hdrs);
    }
    if let Some(payload) = body {
        request = request.json(&payload);
    }
    let response = request.send().await?;
    let status = response.status();
    let body = response.text().await?;
    Ok((status, body))
}

#[test]
fn protected_route_request_distinguishes_public_artifact_metadata() {
    let artifact_path = "/rpc/connectors/fcp.test.echo:utility:1.0.0/artifact";
    assert!(!protected_route_request(
        &reqwest::Method::GET,
        artifact_path
    ));
    assert!(protected_route_request(
        &reqwest::Method::POST,
        artifact_path
    ));
    assert!(protected_route_request(
        &reqwest::Method::GET,
        "/rpc/connectors/fcp.test.echo:utility:1.0.0/config"
    ));
}

fn assert_cache_headers(
    headers: &HeaderMap,
    cache: &fcp_host::CacheMetadata,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        headers.get(ETAG).and_then(|value| value.to_str().ok()),
        Some(cache.etag.as_str())
    );

    let cache_control = headers
        .get(CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .expect("cache-control header should be present");
    let mut expected_cache_control = format!("max-age={}", cache.max_age_seconds);
    if let Some(stale) = cache.stale_while_revalidate_seconds {
        expected_cache_control.push_str(&format!(", stale-while-revalidate={stale}"));
    }
    assert_eq!(cache_control, expected_cache_control);

    let last_modified = headers
        .get(LAST_MODIFIED)
        .and_then(|value| value.to_str().ok())
        .expect("last-modified header should be present");
    let parsed_last_modified = chrono::DateTime::parse_from_rfc2822(last_modified)?;
    assert_eq!(
        parsed_last_modified.timestamp(),
        cache.last_modified.timestamp()
    );

    Ok(())
}

struct HttpHostProcess {
    child: Child,
    client: reqwest::Client,
    base_url: String,
    #[allow(dead_code)]
    lifecycle_state_dir: tempfile::TempDir,
    #[allow(dead_code)]
    stderr_logs: StderrLogs,
    stderr_thread: Option<JoinHandle<()>>,
}

async fn wait_for_host_readiness(
    child: &mut Child,
    client: &reqwest::Client,
    base_url: &str,
    stderr_logs: &StderrLogs,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut last_error = None;
    let deadline = Instant::now() + Duration::from_secs(15);

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

async fn wait_for_host_exit(
    child: &mut Child,
    timeout: Duration,
    stderr_logs: &StderrLogs,
) -> Result<ExitStatus, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let raw_stderr = stderr_logs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            return Err(format!(
                "timed out waiting for fcp-host exit after {timeout:?}; stderr: {raw_stderr:?}"
            )
            .into());
        }
        fcp_async_core::time::sleep(Duration::from_millis(25)).await;
    }
}

#[cfg(unix)]
fn send_sigterm(child: &Child) -> Result<(), Box<dyn std::error::Error>> {
    let pid = child.id().to_string();
    let status = Command::new("kill").args(["-TERM", &pid]).status()?;
    if !status.success() {
        return Err(format!("failed to send SIGTERM to fcp-host pid {pid}: {status}").into());
    }
    Ok(())
}

impl HttpHostProcess {
    async fn spawn(
        connector_configs: Vec<serde_json::Value>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::spawn_with_env(connector_configs, &[]).await
    }

    async fn spawn_with_env(
        connector_configs: Vec<serde_json::Value>,
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

        let client = build_http_client(reqwest::Client::builder().timeout(Duration::from_secs(2)))?;
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

    async fn spawn_with_connectors_file(
        connector_configs: Vec<serde_json::Value>,
        extra_env: &[(&str, &str)],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let bind_listener = StdTcpListener::bind("127.0.0.1:0")?;
        let bind_addr = bind_listener.local_addr()?;
        drop(bind_listener);

        let base_url = format!("http://{bind_addr}");
        let lifecycle_state_dir = tempfile::tempdir()?;
        let lifecycle_state_path = lifecycle_state_dir.path().join("lifecycle-state.json");
        let connectors_file_path = lifecycle_state_dir.path().join("connectors.json");
        let zone_policies_path = write_test_zone_policies_file(&lifecycle_state_dir)?;
        std::fs::write(
            &connectors_file_path,
            serde_json::to_vec_pretty(&connector_configs)?,
        )?;

        let mut command = Command::new(env!("CARGO_BIN_EXE_fcp-host"));
        command
            .env("FCP_HOST_BIND", bind_addr.to_string())
            .env("FCP_HOST_CONNECTORS_FILE", &connectors_file_path)
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

        let client = build_http_client(reqwest::Client::builder().timeout(Duration::from_secs(2)))?;
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

#[cfg(unix)]
struct UnixHostProcess {
    child: Child,
    client: reqwest::Client,
    base_url: String,
    #[allow(dead_code)]
    lifecycle_state_dir: tempfile::TempDir,
    #[allow(dead_code)]
    stderr_logs: StderrLogs,
    stderr_thread: Option<JoinHandle<()>>,
}

#[cfg(unix)]
impl UnixHostProcess {
    #[allow(dead_code)]
    async fn spawn(
        connector_configs: Vec<serde_json::Value>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::spawn_with_env(connector_configs, &[]).await
    }

    async fn spawn_with_env(
        connector_configs: Vec<serde_json::Value>,
        extra_env: &[(&str, &str)],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let socket_path = unique_unix_socket_path()?;
        let base_url = "http://localhost".to_string();
        let lifecycle_state_dir = tempfile::tempdir()?;
        let lifecycle_state_path = lifecycle_state_dir.path().join("lifecycle-state.json");
        let zone_policies_path = write_test_zone_policies_file(&lifecycle_state_dir)?;
        let mut command = Command::new(env!("CARGO_BIN_EXE_fcp-host"));
        command
            .env("FCP_HOST_BIND", format!("unix://{}", socket_path.display()))
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

        let client = build_http_client(
            reqwest::Client::builder()
                .timeout(Duration::from_secs(2))
                .unix_socket(socket_path),
        )?;
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

#[cfg(unix)]
impl Drop for UnixHostProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(stderr_thread) = self.stderr_thread.take() {
            let _ = stderr_thread.join();
        }
    }
}

#[cfg(unix)]
fn unique_unix_socket_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
    for _ in 0..16 {
        let path = PathBuf::from("/tmp").join(format!("fcp-host-{}.sock", CorrelationId::new()));
        if !path.exists() {
            return Ok(path);
        }
    }

    Err("failed to allocate unique unix socket path".into())
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

async fn wait_for_log_events(
    stderr_logs: &Arc<StdMutex<Vec<String>>>,
    events: &[&str],
) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let raw_lines = stderr_logs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let parsed_logs: Vec<Value> = raw_lines
            .iter()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .collect();
        let saw_all_events = events.iter().all(|event| {
            parsed_logs
                .iter()
                .any(|entry| entry.get("event").and_then(Value::as_str) == Some(*event))
        });
        if saw_all_events {
            return Ok(parsed_logs);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for log events {events:?}; raw stderr lines: {raw_lines:?}"
            )
            .into());
        }
        fcp_async_core::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn wait_for_log_entry(
    stderr_logs: &Arc<StdMutex<Vec<String>>>,
    description: &str,
    predicate: impl Fn(&Value) -> bool,
) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let raw_lines = stderr_logs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let parsed_logs: Vec<Value> = raw_lines
            .iter()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .collect();
        if parsed_logs.iter().any(&predicate) {
            return Ok(parsed_logs);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for log entry {description}; raw stderr lines: {raw_lines:?}"
            )
            .into());
        }
        fcp_async_core::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn assert_discovery_routes(
    client: &reqwest::Client,
    base_url: &str,
    connector_a_id: &ConnectorId,
    connector_b_id: &ConnectorId,
    capability_signing_key: &Ed25519SigningKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let url = |path: &str| format!("{base_url}{path}");

    let health: HostHealthResponse = http_get_json(client.clone(), url("/rpc/health")).await?;
    assert_eq!(health.status, HostHealthStatus::Healthy);
    assert_eq!(health.connectors.len(), 2);
    assert!(health.connectors.contains_key(connector_a_id));
    assert!(health.connectors.contains_key(connector_b_id));

    let discover_all = http_post_json_response::<_, DiscoveryResponse>(
        client.clone(),
        url("/rpc/discover"),
        json!({}),
        None,
    )
    .await?;
    assert_eq!(discover_all.status, reqwest::StatusCode::OK);
    let discover_all_headers = discover_all.headers.clone();
    let discover_all = discover_all.body;
    assert_eq!(discover_all.connectors.len(), 2);
    let discover_all_cache = discover_all
        .cache
        .as_ref()
        .expect("discover response should expose cache metadata");
    assert!(!discover_all_cache.etag.is_empty());
    assert!(discover_all.meta.is_none());
    assert_cache_headers(&discover_all_headers, discover_all_cache)?;
    assert!(
        discover_all
            .connectors
            .iter()
            .all(|connector| connector.tool_count == 1)
    );
    assert!(
        discover_all
            .connectors
            .iter()
            .all(|connector| { matches!(connector.max_safety_tier, fcp_core::SafetyTier::Safe) })
    );
    assert!(
        discover_all
            .connectors
            .iter()
            .all(|connector| connector.health.is_healthy())
    );

    let discover_filtered = http_post_json_response::<_, DiscoveryResponse>(
        client.clone(),
        url("/rpc/discover"),
        json!({ "category": "primary" }),
        None,
    )
    .await?;
    assert_eq!(discover_filtered.status, reqwest::StatusCode::OK);
    let discover_filtered_headers = discover_filtered.headers.clone();
    let discover_filtered = discover_filtered.body;
    assert_eq!(discover_filtered.connectors.len(), 1);
    let discover_filtered_cache = discover_filtered
        .cache
        .as_ref()
        .expect("filtered discover response should expose cache metadata");
    assert_ne!(discover_all_cache.etag, discover_filtered_cache.etag);
    assert_cache_headers(&discover_filtered_headers, discover_filtered_cache)?;
    assert_eq!(discover_filtered.connectors[0].id, *connector_a_id);
    assert_eq!(discover_filtered.connectors[0].tool_count, 1);
    assert!(matches!(
        discover_filtered.connectors[0].max_safety_tier,
        fcp_core::SafetyTier::Safe
    ));
    assert!(discover_filtered.connectors[0].health.is_healthy());

    let connector_summary = http_get_json_response::<ConnectorInventoryResponse>(
        client.clone(),
        url(&format!("/rpc/connectors/{}", connector_a_id.as_str())),
        None,
    )
    .await?;
    assert_eq!(connector_summary.status, reqwest::StatusCode::OK);
    let connector_summary_headers = connector_summary.headers.clone();
    let connector_summary = connector_summary.body;
    assert_eq!(connector_summary.connector.id, *connector_a_id);
    assert_eq!(connector_summary.connector.tool_count, 1);
    assert!(matches!(
        connector_summary.connector.max_safety_tier,
        fcp_core::SafetyTier::Safe
    ));
    assert!(connector_summary.connector.health.is_healthy());
    let connector_summary_cache = connector_summary
        .cache
        .as_ref()
        .expect("connector inventory response should expose cache metadata");
    assert_cache_headers(&connector_summary_headers, connector_summary_cache)?;

    let mut connector_not_modified_headers = HeaderMap::new();
    connector_not_modified_headers.insert(
        IF_NONE_MATCH,
        HeaderValue::from_str(&connector_summary_cache.etag)?,
    );
    let connector_not_modified = http_get_json_response::<ConnectorInventoryResponse>(
        client.clone(),
        url(&format!("/rpc/connectors/{}", connector_a_id.as_str())),
        Some(connector_not_modified_headers),
    )
    .await?;
    assert_eq!(connector_not_modified.status, reqwest::StatusCode::OK);
    let connector_not_modified_headers = connector_not_modified.headers.clone();
    let connector_not_modified = connector_not_modified.body;
    assert_eq!(
        connector_not_modified.meta.as_ref().map(|meta| meta.status),
        Some(304)
    );
    assert_eq!(connector_not_modified.connector.id, *connector_a_id);
    assert_cache_headers(
        &connector_not_modified_headers,
        connector_not_modified
            .cache
            .as_ref()
            .expect("not-modified connector inventory should expose cache metadata"),
    )?;

    let mut discover_not_modified_headers = HeaderMap::new();
    discover_not_modified_headers.insert(
        IF_NONE_MATCH,
        HeaderValue::from_str(&discover_all_cache.etag)?,
    );
    let discover_not_modified = http_post_json_response::<_, DiscoveryResponse>(
        client.clone(),
        url("/rpc/discover"),
        json!({}),
        Some(discover_not_modified_headers),
    )
    .await?;
    assert_eq!(discover_not_modified.status, reqwest::StatusCode::OK);
    let discover_not_modified_response_headers = discover_not_modified.headers.clone();
    let discover_not_modified = discover_not_modified.body;
    // 304 responses now preserve the cached connector list (commit 0fa56967).
    assert!(!discover_not_modified.connectors.is_empty());
    assert_eq!(
        discover_not_modified.meta.as_ref().map(|meta| meta.status),
        Some(304)
    );
    assert_eq!(
        discover_not_modified
            .cache
            .as_ref()
            .map(|cache| cache.etag.as_str()),
        Some(discover_all_cache.etag.as_str())
    );
    assert_cache_headers(
        &discover_not_modified_response_headers,
        discover_not_modified
            .cache
            .as_ref()
            .expect("not-modified discover should still expose cache metadata"),
    )?;

    let introspection = http_get_json_response::<IntrospectionResponse>(
        client.clone(),
        url(&format!("/rpc/introspect/{}", connector_a_id.as_str())),
        None,
    )
    .await?;
    assert_eq!(introspection.status, reqwest::StatusCode::OK);
    let introspection_headers = introspection.headers.clone();
    let introspection = introspection.body;
    assert_eq!(introspection.connector.id, *connector_a_id);
    assert_eq!(introspection.connector.tool_count, 1);
    assert!(matches!(
        introspection.connector.max_safety_tier,
        fcp_core::SafetyTier::Safe
    ));
    assert!(introspection.connector.health.is_healthy());
    assert_eq!(introspection.tools.len(), 1);
    assert_eq!(introspection.tools[0].name, "test.echo");
    assert_cache_headers(
        &introspection_headers,
        introspection
            .cache
            .as_ref()
            .expect("introspection should expose cache metadata"),
    )?;

    let introspection_cache = introspection
        .cache
        .as_ref()
        .expect("introspection cache metadata");
    let mut introspect_not_modified_headers = HeaderMap::new();
    introspect_not_modified_headers.insert(
        IF_NONE_MATCH,
        HeaderValue::from_str(&introspection_cache.etag)?,
    );
    let introspect_not_modified = http_get_json_response::<IntrospectionResponse>(
        client.clone(),
        url(&format!("/rpc/introspect/{}", connector_a_id.as_str())),
        Some(introspect_not_modified_headers),
    )
    .await?;
    assert_eq!(introspect_not_modified.status, reqwest::StatusCode::OK);
    let introspect_not_modified_headers = introspect_not_modified.headers.clone();
    let introspect_not_modified = introspect_not_modified.body;
    assert_eq!(
        introspect_not_modified
            .meta
            .as_ref()
            .map(|meta| meta.status),
        Some(304)
    );
    // 304 responses now preserve the cached tool list (commit 0fa56967).
    assert!(!introspect_not_modified.tools.is_empty());
    assert_cache_headers(
        &introspect_not_modified_headers,
        introspect_not_modified
            .cache
            .as_ref()
            .expect("not-modified introspection should expose cache metadata"),
    )?;

    let (preflight_request, _) =
        build_invoke_request(connector_a_id.clone(), capability_signing_key);
    let preflight: PreflightResponse = http_post_json(
        client.clone(),
        url("/rpc/preflight"),
        build_host_preflight_request(&preflight_request, Some(TEST_PRINCIPAL)),
    )
    .await?;
    assert!(preflight.allowed);
    assert!(preflight.reason.is_none());

    let (mut invoke_request, correlation_id) =
        build_invoke_request(connector_a_id.clone(), capability_signing_key);
    invoke_request.idempotency_key = Some("it-receipt-query".to_string());
    let invoke_response: InvokeResponse =
        http_post_json(client.clone(), url("/rpc/invoke"), invoke_request).await?;
    assert_eq!(invoke_response.status, InvokeStatus::Ok);
    assert!(invoke_response.receipt_id.is_some());
    assert_eq!(
        invoke_response
            .result
            .as_ref()
            .and_then(|result| result.get("echo"))
            .and_then(|echo| echo.get("message"))
            .and_then(Value::as_str),
        Some("hello")
    );
    assert!(
        correlation_id.to_string().len() > 10,
        "correlation id should be propagated from the request helper"
    );
    let receipts: ReceiptQueryResponse = http_post_json(
        client.clone(),
        url("/rpc/admin/receipts"),
        ReceiptQueryRequest {
            connector_id: connector_a_id.to_string(),
            operation: Some(TEST_OPERATION.to_string()),
            after: None,
            limit: 10,
        },
    )
    .await?;
    assert_eq!(receipts.receipts.len(), 1);
    assert_eq!(receipts.total_receipts, 1);
    assert_eq!(
        receipts.receipts[0].receipt_id,
        invoke_response
            .receipt_id
            .as_ref()
            .expect("invoke response should include a receipt id")
            .to_string()
    );
    assert_eq!(receipts.receipts[0].operation, TEST_OPERATION);
    assert!(receipts.receipts[0].success);
    assert_eq!(
        receipts.receipts[0].idempotency_key.as_deref(),
        Some("it-receipt-query")
    );

    let doctor: serde_json::Value = http_post_json(
        client.clone(),
        url("/doctor"),
        json!({
            "zone_id": "z:work",
            "connectors": [connector_b_id.as_str()],
            "self_check": true,
        }),
    )
    .await?;
    assert_eq!(doctor["overall_status"], "OK");
    assert_eq!(
        doctor["connector_self_checks"]
            .as_array()
            .map_or(0, Vec::len),
        1
    );

    Ok(())
}

fn test_connector_config_with_env(
    connector_id: &ConnectorId,
    name: &str,
    categories: &[String],
    extra_env: &[(&str, &str)],
) -> serde_json::Value {
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

fn test_connector_config(
    connector_id: &ConnectorId,
    name: &str,
    categories: &[&str],
) -> serde_json::Value {
    let categories = categories
        .iter()
        .map(|category| (*category).to_string())
        .collect::<Vec<_>>();
    test_connector_config_with_env(connector_id, name, &categories, &[])
}

fn singleton_writer_test_connector_config(
    connector_id: &ConnectorId,
    name: &str,
) -> serde_json::Value {
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

fn singleton_writer_test_connector_config_with_state(
    connector_id: &ConnectorId,
    name: &str,
    state_root: &Path,
    object_id_key: &ObjectIdKey,
) -> serde_json::Value {
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

struct SeededConnectorState {
    root_object_id: ObjectId,
    head_object_id: ObjectId,
    lease_object_id: ObjectId,
    lease_seq: u64,
    lease_expiry_unix_secs: u64,
}

fn update_len_prefixed_for_test(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(bytes);
}

fn singleton_writer_connector_lease_subject_id_for_test(
    connector_id: &ConnectorId,
    zone_id: &ZoneId,
) -> ObjectId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"FCP-HOST-SINGLETON-WRITER-HRW-LEASE-V2");
    update_len_prefixed_for_test(&mut hasher, connector_id.as_str().as_bytes());
    update_len_prefixed_for_test(&mut hasher, zone_id.as_str().as_bytes());
    ObjectId::from_bytes(*hasher.finalize().as_bytes())
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

async fn seed_singleton_writer_connector_state(
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

async fn seed_singleton_writer_connector_state_with_durable_lease(
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

async fn seed_singleton_writer_connector_state_with_durable_lease_signers(
    state_root: &Path,
    connector_id: &ConnectorId,
    zone_id: &ZoneId,
    object_id_key: ObjectIdKey,
    holder: TailscaleNodeId,
    quorum_signers: &[&str],
) -> Result<SeededConnectorState, Box<dyn std::error::Error>> {
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
    seed_singleton_writer_connector_state_with_durable_core_lease(
        state_root,
        connector_id,
        zone_id,
        object_id_key,
        lease,
    )
    .await
}

async fn seed_singleton_writer_connector_state_with_durable_core_lease(
    state_root: &Path,
    connector_id: &ConnectorId,
    zone_id: &ZoneId,
    object_id_key: ObjectIdKey,
    lease: CoreLease,
) -> Result<SeededConnectorState, Box<dyn std::error::Error>> {
    let object_store_dir = connector_state_canonical_object_store_dir(state_root, connector_id);
    let object_store: Arc<dyn fcp_store::ObjectStore> =
        Arc::new(fcp_store::DurableObjectStore::open(
            fcp_store::DurableObjectStoreConfig::new(&object_store_dir),
        )?);
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MatrixFixtureFlavor {
    RequestResponse,
    Streaming,
    Polling,
    Webhook,
    Browser,
    Database,
    LifecycleHeavy,
}

impl MatrixFixtureFlavor {
    const fn as_tag(self) -> &'static str {
        match self {
            Self::RequestResponse => "request-response",
            Self::Streaming => "streaming",
            Self::Polling => "polling",
            Self::Webhook => "webhook",
            Self::Browser => "browser",
            Self::Database => "database",
            Self::LifecycleHeavy => "lifecycle-heavy",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MatrixFixtureAuthState {
    None,
    OAuth,
    MultiProfileTenant,
}

impl MatrixFixtureAuthState {
    const fn as_tag(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::OAuth => "oauth",
            Self::MultiProfileTenant => "multi-profile-tenant",
        }
    }

    const fn env_value(self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::OAuth => Some("oauth"),
            Self::MultiProfileTenant => Some("multi_profile_tenant"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MatrixFixtureHealthState {
    Ready,
    Degraded,
    Error,
}

impl MatrixFixtureHealthState {
    const fn as_tag(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Degraded => "degraded",
            Self::Error => "error",
        }
    }

    const fn env_value(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Degraded => "degraded",
            Self::Error => "error",
        }
    }

    fn assert_matches(
        self,
        actual: &ConnectorHealth,
        connector_id: &ConnectorId,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match (self, actual) {
            (Self::Ready, ConnectorHealth::Healthy) => Ok(()),
            (Self::Degraded, ConnectorHealth::Degraded { reason })
                if reason == "fixture degraded" =>
            {
                Ok(())
            }
            (Self::Error, ConnectorHealth::Unavailable { reason, .. })
                if reason == "fixture unavailable" =>
            {
                Ok(())
            }
            (expected, actual) => Err(format!(
                "connector {} health mismatch: expected {:?}, got {:?}",
                connector_id.as_str(),
                expected,
                actual
            )
            .into()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MatrixArtifactProvenance {
    LiveHost,
    ReceiptBacked,
    RejectFakeArtifact,
}

impl MatrixArtifactProvenance {
    const fn as_tag(self) -> &'static str {
        match self {
            Self::LiveHost => "live-host",
            Self::ReceiptBacked => "receipt-backed",
            Self::RejectFakeArtifact => "reject-fake-artifact",
        }
    }

    const fn env_value(self) -> Option<&'static str> {
        match self {
            Self::RejectFakeArtifact => Some("reject_fake"),
            Self::LiveHost | Self::ReceiptBacked => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MatrixFixtureOperationMode {
    Reversible,
    Irreversible,
}

impl MatrixFixtureOperationMode {
    const fn as_tag(self) -> &'static str {
        match self {
            Self::Reversible => "reversible",
            Self::Irreversible => "irreversible",
        }
    }

    const fn env_value(self) -> &'static str {
        match self {
            Self::Reversible => "reversible",
            Self::Irreversible => "irreversible",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct HostIntegrationFixture {
    connector_id: &'static str,
    name: &'static str,
    runtime_archetype: ConnectorArchetype,
    flavor: MatrixFixtureFlavor,
    auth_state: MatrixFixtureAuthState,
    health_state: MatrixFixtureHealthState,
    artifact_provenance: MatrixArtifactProvenance,
    operation_mode: MatrixFixtureOperationMode,
    profile_scope: Option<&'static str>,
    tenant_scope: Option<&'static str>,
}

impl HostIntegrationFixture {
    fn connector_id(self) -> ConnectorId {
        ConnectorId::from_static(self.connector_id)
    }

    const fn runtime_archetype_env(self) -> &'static str {
        match self.runtime_archetype {
            ConnectorArchetype::RequestResponse => "request_response",
            ConnectorArchetype::Streaming => "streaming",
            ConnectorArchetype::Bidirectional => "bidirectional",
            ConnectorArchetype::Polling => "polling",
            ConnectorArchetype::Webhook => "webhook",
            ConnectorArchetype::Unknown => "unknown",
        }
    }

    const fn expected_operation_name(self) -> &'static str {
        match self.runtime_archetype {
            ConnectorArchetype::RequestResponse | ConnectorArchetype::Unknown => "test.echo",
            ConnectorArchetype::Streaming => "test.subscribe",
            ConnectorArchetype::Bidirectional => "test.send",
            ConnectorArchetype::Polling => "test.poll",
            ConnectorArchetype::Webhook => "test.receive",
        }
    }

    const fn expected_capability_id(self) -> &'static str {
        match self.runtime_archetype {
            ConnectorArchetype::RequestResponse | ConnectorArchetype::Unknown => "cap.test.echo",
            ConnectorArchetype::Streaming => "cap.test.subscribe",
            ConnectorArchetype::Bidirectional => "cap.test.send",
            ConnectorArchetype::Polling => "cap.test.poll",
            ConnectorArchetype::Webhook => "cap.test.receive",
        }
    }

    fn categories(self) -> Vec<String> {
        let mut categories = vec![
            "test".to_string(),
            format!("matrix:{}", self.flavor.as_tag()),
            format!("auth:{}", self.auth_state.as_tag()),
            format!("health:{}", self.health_state.as_tag()),
            format!("artifact:{}", self.artifact_provenance.as_tag()),
            format!("operation:{}", self.operation_mode.as_tag()),
        ];
        if let Some(profile_scope) = self.profile_scope {
            categories.push(format!("profile:{profile_scope}"));
        }
        if let Some(tenant_scope) = self.tenant_scope {
            categories.push(format!("tenant:{tenant_scope}"));
        }
        categories
    }

    fn extra_env(self) -> Vec<(&'static str, &'static str)> {
        let mut env = vec![
            ("FCP_TEST_CONNECTOR_ARCHETYPE", self.runtime_archetype_env()),
            ("FCP_TEST_CONNECTOR_HEALTH", self.health_state.env_value()),
            (
                "FCP_TEST_CONNECTOR_OPERATION_MODE",
                self.operation_mode.env_value(),
            ),
        ];
        if let Some(auth_mode) = self.auth_state.env_value() {
            env.push(("FCP_TEST_CONNECTOR_AUTH_MODE", auth_mode));
        }
        if let Some(artifact_policy) = self.artifact_provenance.env_value() {
            env.push(("FCP_TEST_CONNECTOR_ARTIFACT_POLICY", artifact_policy));
        }
        env
    }
}

const HOST_INTEGRATION_FIXTURES: [HostIntegrationFixture; 7] = [
    HostIntegrationFixture {
        connector_id: "fcp.test.matrix-request:utility:1.0.0",
        name: "Matrix Request",
        runtime_archetype: ConnectorArchetype::RequestResponse,
        flavor: MatrixFixtureFlavor::RequestResponse,
        auth_state: MatrixFixtureAuthState::None,
        health_state: MatrixFixtureHealthState::Ready,
        artifact_provenance: MatrixArtifactProvenance::ReceiptBacked,
        operation_mode: MatrixFixtureOperationMode::Reversible,
        profile_scope: None,
        tenant_scope: None,
    },
    HostIntegrationFixture {
        connector_id: "fcp.test.matrix-stream:messaging:1.0.0",
        name: "Matrix Stream",
        runtime_archetype: ConnectorArchetype::Streaming,
        flavor: MatrixFixtureFlavor::Streaming,
        auth_state: MatrixFixtureAuthState::None,
        health_state: MatrixFixtureHealthState::Ready,
        artifact_provenance: MatrixArtifactProvenance::LiveHost,
        operation_mode: MatrixFixtureOperationMode::Reversible,
        profile_scope: None,
        tenant_scope: None,
    },
    HostIntegrationFixture {
        connector_id: "fcp.test.matrix-poll:content:1.0.0",
        name: "Matrix Poll",
        runtime_archetype: ConnectorArchetype::Polling,
        flavor: MatrixFixtureFlavor::Polling,
        auth_state: MatrixFixtureAuthState::None,
        health_state: MatrixFixtureHealthState::Degraded,
        artifact_provenance: MatrixArtifactProvenance::LiveHost,
        operation_mode: MatrixFixtureOperationMode::Reversible,
        profile_scope: None,
        tenant_scope: None,
    },
    HostIntegrationFixture {
        connector_id: "fcp.test.matrix-webhook:devtools:1.0.0",
        name: "Matrix Webhook",
        runtime_archetype: ConnectorArchetype::Webhook,
        flavor: MatrixFixtureFlavor::Webhook,
        auth_state: MatrixFixtureAuthState::OAuth,
        health_state: MatrixFixtureHealthState::Ready,
        artifact_provenance: MatrixArtifactProvenance::RejectFakeArtifact,
        operation_mode: MatrixFixtureOperationMode::Reversible,
        profile_scope: None,
        tenant_scope: None,
    },
    HostIntegrationFixture {
        connector_id: "fcp.test.matrix-browser:automation:1.0.0",
        name: "Matrix Browser",
        runtime_archetype: ConnectorArchetype::RequestResponse,
        flavor: MatrixFixtureFlavor::Browser,
        auth_state: MatrixFixtureAuthState::MultiProfileTenant,
        health_state: MatrixFixtureHealthState::Ready,
        artifact_provenance: MatrixArtifactProvenance::LiveHost,
        operation_mode: MatrixFixtureOperationMode::Reversible,
        profile_scope: Some("work"),
        tenant_scope: Some("acme-browser"),
    },
    HostIntegrationFixture {
        connector_id: "fcp.test.matrix-database:data:1.0.0",
        name: "Matrix Database",
        runtime_archetype: ConnectorArchetype::RequestResponse,
        flavor: MatrixFixtureFlavor::Database,
        auth_state: MatrixFixtureAuthState::MultiProfileTenant,
        health_state: MatrixFixtureHealthState::Error,
        artifact_provenance: MatrixArtifactProvenance::ReceiptBacked,
        operation_mode: MatrixFixtureOperationMode::Reversible,
        profile_scope: Some("work"),
        tenant_scope: Some("acme-data"),
    },
    HostIntegrationFixture {
        connector_id: "fcp.test.matrix-lifecycle:utility:1.0.0",
        name: "Matrix Lifecycle",
        runtime_archetype: ConnectorArchetype::RequestResponse,
        flavor: MatrixFixtureFlavor::LifecycleHeavy,
        auth_state: MatrixFixtureAuthState::OAuth,
        health_state: MatrixFixtureHealthState::Ready,
        artifact_provenance: MatrixArtifactProvenance::ReceiptBacked,
        operation_mode: MatrixFixtureOperationMode::Irreversible,
        profile_scope: Some("ops"),
        tenant_scope: None,
    },
];

fn matrix_fixture_config(fixture: HostIntegrationFixture) -> serde_json::Value {
    let connector_id = fixture.connector_id();
    let categories = fixture.categories();
    let extra_env = fixture.extra_env();
    test_connector_config_with_env(&connector_id, fixture.name, &categories, &extra_env)
}

fn test_rollout_policy() -> RolloutPolicy {
    RolloutPolicy::builder()
        .canary_percent(10)
        .min_canary_duration_secs(1)
        .success_thresholds(SuccessThresholds::new(9000, 1000, 3, 60))
        .rollback_rules(RollbackRules::new(5000, 3, 3, 60, true))
        .build()
}

fn test_rollout_rollback_policy() -> RolloutPolicy {
    RolloutPolicy::builder()
        .canary_percent(10)
        .min_canary_duration_secs(0)
        .success_thresholds(SuccessThresholds::new(10_000, 0, 1, 60))
        .rollback_rules(RollbackRules::new(0, 1, 1, 60, true))
        .build()
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_exposes_discovery_routes() -> Result<(), Box<dyn std::error::Error>> {
    let connector_a_id = ConnectorId::from_static("fcp.test.http-echo:utility:1.0.0");
    let connector_b_id = ConnectorId::from_static("fcp.test.http-ping:utility:1.0.0");
    let capability_signing_key = Ed25519SigningKey::generate();
    let capability_public_key = capability_public_key_hex(&capability_signing_key);

    let host = HttpHostProcess::spawn_with_env(
        vec![
            test_connector_config(&connector_a_id, "HTTP Echo", &["test", "primary"]),
            test_connector_config(&connector_b_id, "HTTP Ping", &["test", "secondary"]),
        ],
        &[(
            "FCP_HOST_CAPABILITY_PUBLIC_KEY",
            capability_public_key.as_str(),
        )],
    )
    .await?;

    assert_discovery_routes(
        &host.client,
        &host.base_url,
        &connector_a_id,
        &connector_b_id,
        &capability_signing_key,
    )
    .await?;

    Ok(())
}

#[test]
fn host_integration_fixture_matrix_covers_required_dimensions() {
    for required in [
        "request-response",
        "streaming",
        "polling",
        "webhook",
        "browser",
        "database",
        "lifecycle-heavy",
    ] {
        assert!(
            HOST_INTEGRATION_FIXTURES
                .iter()
                .any(|fixture| { fixture.flavor.as_tag() == required })
        );
    }

    for required in ["ready", "degraded", "error"] {
        assert!(
            HOST_INTEGRATION_FIXTURES
                .iter()
                .any(|fixture| { fixture.health_state.as_tag() == required })
        );
    }

    for required in ["none", "oauth", "multi-profile-tenant"] {
        assert!(
            HOST_INTEGRATION_FIXTURES
                .iter()
                .any(|fixture| { fixture.auth_state.as_tag() == required })
        );
    }

    for required in ["live-host", "receipt-backed", "reject-fake-artifact"] {
        assert!(
            HOST_INTEGRATION_FIXTURES
                .iter()
                .any(|fixture| { fixture.artifact_provenance.as_tag() == required })
        );
    }

    assert!(HOST_INTEGRATION_FIXTURES.iter().any(|fixture| {
        fixture.auth_state == MatrixFixtureAuthState::MultiProfileTenant
            && fixture.profile_scope.is_some()
            && fixture.tenant_scope.is_some()
    }));
    assert!(
        HOST_INTEGRATION_FIXTURES
            .iter()
            .any(|fixture| { fixture.operation_mode == MatrixFixtureOperationMode::Reversible })
    );
    assert!(
        HOST_INTEGRATION_FIXTURES
            .iter()
            .any(|fixture| { fixture.operation_mode == MatrixFixtureOperationMode::Irreversible })
    );
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_fixture_matrix_surfaces_discovery_and_introspection_metadata()
-> Result<(), Box<dyn std::error::Error>> {
    let host = HttpHostProcess::spawn(
        HOST_INTEGRATION_FIXTURES
            .iter()
            .copied()
            .map(matrix_fixture_config)
            .collect(),
    )
    .await?;
    let url = |path: &str| format!("{}{path}", host.base_url);

    let discovery: DiscoveryResponse =
        http_post_json(host.client.clone(), url("/rpc/discover"), json!({})).await?;
    assert_eq!(discovery.connectors.len(), HOST_INTEGRATION_FIXTURES.len());

    for fixture in HOST_INTEGRATION_FIXTURES {
        let connector_id = fixture.connector_id();
        let Some(connector) = discovery
            .connectors
            .iter()
            .find(|connector| connector.id == connector_id)
        else {
            return Err(format!("missing fixture {}", connector_id.as_str()).into());
        };
        fixture
            .health_state
            .assert_matches(&connector.health, &connector_id)?;

        for tag in fixture.categories() {
            assert!(
                connector.categories.iter().any(|category| category == &tag),
                "connector {} missing category tag {tag}",
                connector_id.as_str()
            );
        }

        let introspection: IntrospectionResponse = http_get_json(
            host.client.clone(),
            url(&format!("/rpc/introspect/{}", connector_id.as_str())),
        )
        .await?;
        assert_eq!(introspection.archetype, fixture.runtime_archetype);
        assert_eq!(introspection.tools.len(), 1);
        assert_eq!(
            introspection.tools[0].name,
            fixture.expected_operation_name()
        );

        let expects_streaming = matches!(
            fixture.runtime_archetype,
            ConnectorArchetype::Streaming | ConnectorArchetype::Bidirectional
        );
        assert_eq!(
            introspection
                .introspection
                .event_caps
                .as_ref()
                .map(|caps| caps.streaming)
                .unwrap_or(false),
            expects_streaming
        );

        let expects_auth = fixture.auth_state != MatrixFixtureAuthState::None;
        assert_eq!(
            introspection.introspection.auth_caps.is_some(),
            expects_auth
        );
        if expects_auth {
            let auth_caps = introspection
                .introspection
                .auth_caps
                .as_ref()
                .expect("auth-heavy fixture should expose auth caps");
            assert!(auth_caps.methods.iter().any(|method| method == "oauth2"));
        }

        match fixture.operation_mode {
            MatrixFixtureOperationMode::Reversible => {
                assert_eq!(
                    introspection.tools[0].approval_mode,
                    Some(ApprovalMode::None)
                );
                // ApprovalMode::None does not require confirmation.
                assert!(!introspection.tools[0].requires_confirmation);
                assert_eq!(
                    introspection.tools[0].idempotency,
                    IdempotencyClass::BestEffort
                );
            }
            MatrixFixtureOperationMode::Irreversible => {
                assert!(introspection.tools[0].requires_confirmation);
                assert_eq!(
                    introspection.tools[0].approval_mode,
                    Some(ApprovalMode::Interactive)
                );
                assert_eq!(introspection.tools[0].idempotency, IdempotencyClass::None);
            }
        }
    }

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_webhook_fixture_rejects_fake_artifact_input()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = HOST_INTEGRATION_FIXTURES
        .iter()
        .copied()
        .find(|fixture| fixture.artifact_provenance == MatrixArtifactProvenance::RejectFakeArtifact)
        .expect("fixture matrix should include fake-artifact rejection case");
    let capability_signing_key = Ed25519SigningKey::generate();
    let capability_public_key = capability_public_key_hex(&capability_signing_key);
    let host = HttpHostProcess::spawn_with_env(
        vec![matrix_fixture_config(fixture)],
        &[(
            "FCP_HOST_CAPABILITY_PUBLIC_KEY",
            capability_public_key.as_str(),
        )],
    )
    .await?;
    let url = |path: &str| format!("{}{path}", host.base_url);
    let zone_id = ZoneId::work();

    let response = host
        .client
        .post(url("/rpc/invoke"))
        .json(&InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::random(),
            connector_id: fixture.connector_id(),
            operation: OperationId::from_static(fixture.expected_operation_name()),
            zone_id: zone_id.clone(),
            input: json!({
                "message": "reject this payload",
                "artifact_provenance": "fake",
            }),
            capability_token: build_live_capability_token(
                &capability_signing_key,
                fixture.expected_capability_id(),
                TEST_PRINCIPAL,
                fixture.expected_operation_name(),
                &zone_id,
            ),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        })
        .send()
        .await?;
    let status = response.status();
    let body = response.text().await?;

    assert_eq!(status, reqwest::StatusCode::INTERNAL_SERVER_ERROR);
    assert!(body.contains("fake artifact provenance rejected"));

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_hrw_lease_coordination_allows_one_singleton_writer_launch()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_id = ConnectorId::from_static("fcp.test.hrw-binary-launch:utility:1.0.0");
    let connector_config =
        singleton_writer_test_connector_config(&connector_id, "HRW Binary Launch");
    let eligible_nodes = "node-a,node-b";
    let mut admitted_host: Option<(String, HttpHostProcess)> = None;
    let mut refusal_messages = Vec::new();

    for local_node in ["node-a", "node-b"] {
        match HttpHostProcess::spawn_with_env(
            vec![connector_config.clone()],
            &[
                ("FCP_HOST_HRW_LEASE_LOCAL_NODE", local_node),
                ("FCP_HOST_HRW_LEASE_NODES", eligible_nodes),
            ],
        )
        .await
        {
            Ok(host) => {
                assert!(
                    admitted_host.is_none(),
                    "HRW admitted more than one singleton_writer host launch"
                );
                admitted_host = Some((local_node.to_string(), host));
            }
            Err(error) => refusal_messages.push((local_node.to_string(), error.to_string())),
        }
    }

    assert!(
        admitted_host.is_some(),
        "HRW should admit exactly one singleton_writer host launch; refusals: {refusal_messages:?}"
    );
    assert_eq!(
        refusal_messages.len(),
        1,
        "HRW should refuse exactly one competing singleton_writer host launch"
    );

    let (refused_node, refusal) = &refusal_messages[0];
    assert!(
        refusal.contains("HRW lease routing refused singleton_writer launch"),
        "refusal for {refused_node} should identify the HRW launch gate: {refusal}"
    );
    assert!(
        refusal.contains("NotSelectedCoordinator"),
        "refusal for {refused_node} should preserve the typed HRW error: {refusal}"
    );
    assert!(
        refusal.contains("wrong_holder"),
        "refusal for {refused_node} should report the wrong-holder transfer reason: {refusal}"
    );
    assert!(
        refusal.contains(refused_node),
        "refusal should name the refused local node {refused_node}: {refusal}"
    );

    let (admitted_node, host) = admitted_host.expect("one HRW host should be admitted");
    let url = |path: &str| format!("{}{path}", host.base_url);
    let discovery: DiscoveryResponse =
        http_post_json(host.client.clone(), url("/rpc/discover"), json!({})).await?;
    assert!(
        discovery
            .connectors
            .iter()
            .any(|connector| connector.id == connector_id),
        "admitted HRW host {admitted_node} should serve the singleton_writer connector"
    );

    let lease_status: serde_json::Value = http_get_json(
        host.client.clone(),
        url(&format!(
            "/rpc/admin/connectors/{}/lease/status?zone=z%3Awork",
            connector_id.as_str()
        )),
    )
    .await?;
    assert_eq!(lease_status["source"], "host-hrw-routing");
    assert_eq!(lease_status["local_is_holder"], true);
    assert!(lease_status["holder_node_id_hash"].as_str().is_some());
    assert_eq!(
        lease_status["ranked_holders"]
            .as_array()
            .expect("lease status should include ranked holders")
            .len(),
        2
    );

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_hrw_lease_rejects_launch_without_quorum_config()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_id = ConnectorId::from_static("fcp.test.hrw-binary-quorum:utility:1.0.0");
    let connector_config =
        singleton_writer_test_connector_config(&connector_id, "HRW Binary Quorum");
    let launch_error = match HttpHostProcess::spawn_with_env(
        vec![connector_config],
        &[
            ("FCP_HOST_HRW_LEASE_LOCAL_NODE", "node-solo"),
            ("FCP_HOST_HRW_LEASE_NODES", "node-solo"),
            ("FCP_HOST_HRW_LEASE_CURRENT_SEQ", "1"),
        ],
    )
    .await
    {
        Ok(_) => {
            return Err(
                "singleton_writer launch must refuse HRW configs below lease quorum".into(),
            );
        }
        Err(error) => error,
    };
    let message = launch_error.to_string();
    let unescaped_message = message.replace('\\', "");

    assert!(
        message.contains("HRW lease routing refused singleton_writer launch"),
        "quorum refusal should identify the HRW launch gate: {message}"
    );
    assert!(
        unescaped_message.contains(r#""code":"LeaseQuorumConfigInvalid""#),
        "quorum refusal should preserve the typed HRW configuration error: {message}"
    );
    assert!(
        unescaped_message.contains(r#""configured_eligible_nodes_count":1"#),
        "quorum refusal should report the configured node count: {message}"
    );
    assert!(
        unescaped_message.contains(r#""required_quorum_signers_count":2"#),
        "quorum refusal should report the required signer count: {message}"
    );
    assert!(
        message.contains("FCP_HOST_HRW_LEASE_NODES"),
        "quorum refusal should point operators at the node-set env var: {message}"
    );

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_hrw_lease_status_reports_invalid_below_quorum_durable_lease()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_id =
        ConnectorId::from_static("fcp.test.hrw-binary-invalid-lease-status:utility:1.0.0");
    let zone_id = ZoneId::work();
    let state_dir = tempfile::tempdir()?;
    let state_root = state_dir.path().join("managed-state");
    let object_id_key = ObjectIdKey::from_bytes([0xD7; 32]);
    let all_nodes = ["node-a", "node-b", "node-c"];
    let eligible_nodes = all_nodes.join(",");
    let eligible_node_ids = all_nodes
        .iter()
        .map(|node| TailscaleNodeId::new(*node))
        .collect::<Vec<_>>();
    let subject_id = singleton_writer_connector_lease_subject_id_for_test(&connector_id, &zone_id);
    let expected_holder =
        fcp_mesh::planner::select_lease_holder(&zone_id, &subject_id, &eligible_node_ids)
            .expect("HRW holder should be selected");
    let seeded_state = seed_singleton_writer_connector_state_with_durable_lease_signers(
        &state_root,
        &connector_id,
        &zone_id,
        object_id_key,
        expected_holder.clone(),
        &["node-a"],
    )
    .await?;
    let connector_config = singleton_writer_test_connector_config_with_state(
        &connector_id,
        "HRW Binary Invalid Lease Status",
        &state_root,
        &object_id_key,
    );
    let mut admitted_host: Option<(String, HttpHostProcess)> = None;
    let mut refusal_messages = Vec::new();

    for local_node in all_nodes {
        match HttpHostProcess::spawn_with_env(
            vec![connector_config.clone()],
            &[
                ("FCP_HOST_HRW_LEASE_LOCAL_NODE", local_node),
                ("FCP_HOST_HRW_LEASE_NODES", eligible_nodes.as_str()),
                ("FCP_HOST_HRW_LEASE_CURRENT_SEQ", "10"),
            ],
        )
        .await
        {
            Ok(host) => {
                assert!(
                    admitted_host.is_none(),
                    "HRW admitted more than one singleton_writer host launch"
                );
                admitted_host = Some((local_node.to_string(), host));
            }
            Err(error) => refusal_messages.push((local_node.to_string(), error.to_string())),
        }
    }

    assert!(
        admitted_host.is_some(),
        "HRW should admit one holder even when durable lease evidence is invalid; refusals: {refusal_messages:?}"
    );
    assert_eq!(
        refusal_messages.len(),
        2,
        "three-node HRW routing should refuse both non-holder launches"
    );
    let (admitted_node, host) = admitted_host.expect("one HRW host should be admitted");
    assert_eq!(
        admitted_node,
        expected_holder.as_str(),
        "real fcp-host launch should admit the HRW-selected holder"
    );

    let lease_status: Value = http_get_json(
        host.client.clone(),
        format!(
            "{}/rpc/admin/connectors/{}/lease/status?zone=z%3Awork",
            host.base_url,
            connector_id.as_str()
        ),
    )
    .await?;
    assert_eq!(lease_status["source"], "host-hrw-routing");
    assert_eq!(lease_status["local_is_holder"], true);
    assert_eq!(
        lease_status["lease_evidence_source"],
        "canonical-fcp-store-lease-object"
    );
    assert_eq!(
        lease_status["lease_object_id"],
        seeded_state.lease_object_id.to_string()
    );
    assert_eq!(lease_status["fencing_token"], seeded_state.lease_seq);
    assert_eq!(lease_status["durable_lease_seq"], seeded_state.lease_seq);
    assert_eq!(lease_status["quorum_signers_count"], 1);
    assert_eq!(lease_status["required_quorum_signers_count"], 2);
    assert_eq!(lease_status["quorum_satisfied"], false);
    assert_eq!(lease_status["durable_validation"]["status"], "invalid");
    assert!(
        lease_status["durable_validation"]["error"]
            .as_str()
            .is_some_and(|error| error.contains("insufficient quorum")),
        "below-quorum durable lease should expose validation error: {lease_status}"
    );
    assert!(
        lease_status["durable_validation"]["validated_at_unix_secs"]
            .as_u64()
            .is_some()
    );
    assert_eq!(
        lease_status["ranked_holders"]
            .as_array()
            .expect("lease status should include ranked holders")
            .len(),
        3
    );
    let warnings = lease_status
        .get("warnings")
        .and_then(Value::as_array)
        .expect("lease status warnings should be an array");
    assert!(
        warnings.iter().any(|warning| warning
            .as_str()
            .is_some_and(|warning| warning.contains("below the required 2"))),
        "operator status should warn on below-quorum durable lease evidence: {lease_status}"
    );
    assert!(
        warnings.iter().any(|warning| warning
            .as_str()
            .is_some_and(|warning| warning.contains("failed live lease validation"))),
        "operator status should retain the durable validation failure warning: {lease_status}"
    );

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_hrw_lease_status_reports_invalid_wrong_subject_durable_lease()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_id =
        ConnectorId::from_static("fcp.test.hrw-binary-wrong-subject-lease-status:utility:1.0.0");
    let zone_id = ZoneId::work();
    let state_dir = tempfile::tempdir()?;
    let state_root = state_dir.path().join("managed-state");
    let object_id_key = ObjectIdKey::from_bytes([0xD8; 32]);
    let all_nodes = ["node-a", "node-b", "node-c"];
    let eligible_nodes = all_nodes.join(",");
    let eligible_node_ids = all_nodes
        .iter()
        .map(|node| TailscaleNodeId::new(*node))
        .collect::<Vec<_>>();
    let expected_subject =
        singleton_writer_connector_lease_subject_id_for_test(&connector_id, &zone_id);
    let wrong_subject = ObjectId::from_bytes([0xE1; 32]);
    assert_ne!(wrong_subject, expected_subject);
    let expected_holder =
        fcp_mesh::planner::select_lease_holder(&zone_id, &expected_subject, &eligible_node_ids)
            .expect("HRW holder should be selected");
    let lease = durable_core_lease_for_test(
        &zone_id,
        wrong_subject,
        expected_holder.clone(),
        10,
        1_800_200_300,
        host_integration_signature_set(&["node-a", "node-b"]),
    );
    let seeded_state = seed_singleton_writer_connector_state_with_durable_core_lease(
        &state_root,
        &connector_id,
        &zone_id,
        object_id_key,
        lease,
    )
    .await?;
    let connector_config = singleton_writer_test_connector_config_with_state(
        &connector_id,
        "HRW Binary Wrong Subject Lease Status",
        &state_root,
        &object_id_key,
    );
    let mut admitted_host: Option<(String, HttpHostProcess)> = None;
    let mut refusal_messages = Vec::new();

    for local_node in all_nodes {
        match HttpHostProcess::spawn_with_env(
            vec![connector_config.clone()],
            &[
                ("FCP_HOST_HRW_LEASE_LOCAL_NODE", local_node),
                ("FCP_HOST_HRW_LEASE_NODES", eligible_nodes.as_str()),
                ("FCP_HOST_HRW_LEASE_CURRENT_SEQ", "10"),
            ],
        )
        .await
        {
            Ok(host) => {
                assert!(
                    admitted_host.is_none(),
                    "HRW admitted more than one singleton_writer host launch"
                );
                admitted_host = Some((local_node.to_string(), host));
            }
            Err(error) => refusal_messages.push((local_node.to_string(), error.to_string())),
        }
    }

    assert!(
        admitted_host.is_some(),
        "HRW should admit one holder even when durable lease evidence has the wrong subject; refusals: {refusal_messages:?}"
    );
    assert_eq!(
        refusal_messages.len(),
        2,
        "three-node HRW routing should refuse both non-holder launches"
    );
    let (admitted_node, host) = admitted_host.expect("one HRW host should be admitted");
    assert_eq!(
        admitted_node,
        expected_holder.as_str(),
        "real fcp-host launch should admit the HRW-selected holder"
    );

    let lease_status: Value = http_get_json(
        host.client.clone(),
        format!(
            "{}/rpc/admin/connectors/{}/lease/status?zone=z%3Awork",
            host.base_url,
            connector_id.as_str()
        ),
    )
    .await?;
    assert_eq!(lease_status["source"], "host-hrw-routing");
    assert_eq!(lease_status["local_is_holder"], true);
    assert_eq!(
        lease_status["lease_evidence_source"],
        "canonical-fcp-store-lease-object"
    );
    assert_eq!(
        lease_status["lease_object_id"],
        seeded_state.lease_object_id.to_string()
    );
    assert_eq!(lease_status["fencing_token"], seeded_state.lease_seq);
    assert_eq!(lease_status["durable_lease_seq"], seeded_state.lease_seq);
    assert_eq!(lease_status["quorum_signers_count"], 2);
    assert_eq!(lease_status["required_quorum_signers_count"], 2);
    assert_eq!(lease_status["quorum_satisfied"], true);
    assert_eq!(lease_status["durable_validation"]["status"], "invalid");
    assert!(
        lease_status["durable_validation"]["error"]
            .as_str()
            .is_some_and(|error| error.contains("subject mismatch")),
        "wrong-subject durable lease should expose validation error: {lease_status}"
    );
    assert!(
        lease_status["durable_validation"]["validated_at_unix_secs"]
            .as_u64()
            .is_some()
    );
    assert_eq!(
        lease_status["ranked_holders"]
            .as_array()
            .expect("lease status should include ranked holders")
            .len(),
        3
    );
    let warnings = lease_status
        .get("warnings")
        .and_then(Value::as_array)
        .expect("lease status warnings should be an array");
    assert!(
        warnings.iter().any(|warning| warning
            .as_str()
            .is_some_and(|warning| warning.contains("failed live lease validation"))),
        "operator status should warn on wrong-subject durable lease evidence: {lease_status}"
    );
    assert!(
        warnings.iter().any(|warning| warning
            .as_str()
            .is_some_and(|warning| warning.contains("subject mismatch"))),
        "operator status should retain the subject mismatch reason: {lease_status}"
    );

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_hrw_lease_status_reports_invalid_stale_durable_lease_seq()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_id =
        ConnectorId::from_static("fcp.test.hrw-binary-stale-lease-status:utility:1.0.0");
    let zone_id = ZoneId::work();
    let state_dir = tempfile::tempdir()?;
    let state_root = state_dir.path().join("managed-state");
    let object_id_key = ObjectIdKey::from_bytes([0xD9; 32]);
    let all_nodes = ["node-a", "node-b", "node-c"];
    let eligible_nodes = all_nodes.join(",");
    let eligible_node_ids = all_nodes
        .iter()
        .map(|node| TailscaleNodeId::new(*node))
        .collect::<Vec<_>>();
    let subject_id = singleton_writer_connector_lease_subject_id_for_test(&connector_id, &zone_id);
    let expected_holder =
        fcp_mesh::planner::select_lease_holder(&zone_id, &subject_id, &eligible_node_ids)
            .expect("HRW holder should be selected");
    let stale_lease_seq = 9;
    let lease = durable_core_lease_for_test(
        &zone_id,
        subject_id,
        expected_holder.clone(),
        stale_lease_seq,
        1_800_200_300,
        host_integration_signature_set(&["node-a", "node-b"]),
    );
    let seeded_state = seed_singleton_writer_connector_state_with_durable_core_lease(
        &state_root,
        &connector_id,
        &zone_id,
        object_id_key,
        lease,
    )
    .await?;
    assert_eq!(
        seeded_state.lease_seq, 10,
        "test fixture expects the connector-state head to advance past the durable lease"
    );
    let connector_config = singleton_writer_test_connector_config_with_state(
        &connector_id,
        "HRW Binary Stale Lease Status",
        &state_root,
        &object_id_key,
    );
    let current_lease_seq = seeded_state.lease_seq.to_string();
    let mut admitted_host: Option<(String, HttpHostProcess)> = None;
    let mut refusal_messages = Vec::new();

    for local_node in all_nodes {
        match HttpHostProcess::spawn_with_env(
            vec![connector_config.clone()],
            &[
                ("FCP_HOST_HRW_LEASE_LOCAL_NODE", local_node),
                ("FCP_HOST_HRW_LEASE_NODES", eligible_nodes.as_str()),
                ("FCP_HOST_HRW_LEASE_CURRENT_SEQ", current_lease_seq.as_str()),
            ],
        )
        .await
        {
            Ok(host) => {
                assert!(
                    admitted_host.is_none(),
                    "HRW admitted more than one singleton_writer host launch"
                );
                admitted_host = Some((local_node.to_string(), host));
            }
            Err(error) => refusal_messages.push((local_node.to_string(), error.to_string())),
        }
    }

    assert!(
        admitted_host.is_some(),
        "HRW should admit one holder even when durable lease evidence is stale; refusals: {refusal_messages:?}"
    );
    assert_eq!(
        refusal_messages.len(),
        2,
        "three-node HRW routing should refuse both non-holder launches"
    );
    let (admitted_node, host) = admitted_host.expect("one HRW host should be admitted");
    assert_eq!(
        admitted_node,
        expected_holder.as_str(),
        "real fcp-host launch should admit the HRW-selected holder"
    );

    let lease_status: Value = http_get_json(
        host.client.clone(),
        format!(
            "{}/rpc/admin/connectors/{}/lease/status?zone=z%3Awork",
            host.base_url,
            connector_id.as_str()
        ),
    )
    .await?;
    assert_eq!(lease_status["source"], "host-hrw-routing");
    assert_eq!(lease_status["local_is_holder"], true);
    assert_eq!(
        lease_status["lease_evidence_source"],
        "canonical-fcp-store-lease-object"
    );
    assert_eq!(
        lease_status["lease_object_id"],
        seeded_state.lease_object_id.to_string()
    );
    assert_eq!(lease_status["fencing_token"], seeded_state.lease_seq);
    assert_eq!(lease_status["durable_lease_seq"], stale_lease_seq);
    assert_eq!(lease_status["quorum_signers_count"], 2);
    assert_eq!(lease_status["required_quorum_signers_count"], 2);
    assert_eq!(lease_status["quorum_satisfied"], true);
    assert_eq!(lease_status["durable_validation"]["status"], "invalid");
    assert!(
        lease_status["durable_validation"]["error"]
            .as_str()
            .is_some_and(|error| error.contains("lease sequence mismatch")),
        "stale durable lease should expose validation error: {lease_status}"
    );
    assert!(
        lease_status["durable_validation"]["validated_at_unix_secs"]
            .as_u64()
            .is_some()
    );
    let warnings = lease_status
        .get("warnings")
        .and_then(Value::as_array)
        .expect("lease status warnings should be an array");
    assert!(
        warnings.iter().any(|warning| warning
            .as_str()
            .is_some_and(|warning| warning.contains("failed live lease validation"))),
        "operator status should warn on stale durable lease evidence: {lease_status}"
    );
    assert!(
        warnings.iter().any(|warning| warning
            .as_str()
            .is_some_and(|warning| warning.contains("lease sequence mismatch"))),
        "operator status should retain the lease sequence mismatch reason: {lease_status}"
    );

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_hrw_lease_fence_rejects_stale_singleton_writer_invoke()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_id = ConnectorId::from_static("fcp.test.hrw-binary-fence:utility:1.0.0");
    let connector_config =
        singleton_writer_test_connector_config(&connector_id, "HRW Binary Fence");
    let capability_signing_key = Ed25519SigningKey::generate();
    let capability_public_key = capability_public_key_hex(&capability_signing_key);
    let eligible_nodes = "node-a,node-b,node-c";
    let current_lease_seq = "11";
    let mut admitted_host: Option<(String, HttpHostProcess)> = None;
    let mut refusal_messages = Vec::new();

    for local_node in ["node-a", "node-b", "node-c"] {
        match HttpHostProcess::spawn_with_env(
            vec![connector_config.clone()],
            &[
                ("FCP_HOST_HRW_LEASE_LOCAL_NODE", local_node),
                ("FCP_HOST_HRW_LEASE_NODES", eligible_nodes),
                ("FCP_HOST_HRW_LEASE_CURRENT_SEQ", current_lease_seq),
                (
                    "FCP_HOST_CAPABILITY_PUBLIC_KEY",
                    capability_public_key.as_str(),
                ),
            ],
        )
        .await
        {
            Ok(host) => {
                assert!(
                    admitted_host.is_none(),
                    "HRW admitted more than one singleton_writer host launch"
                );
                admitted_host = Some((local_node.to_string(), host));
            }
            Err(error) => refusal_messages.push((local_node.to_string(), error.to_string())),
        }
    }

    assert!(
        admitted_host.is_some(),
        "HRW should admit exactly one singleton_writer host launch; refusals: {refusal_messages:?}"
    );
    assert_eq!(
        refusal_messages.len(),
        2,
        "three-node HRW routing should refuse both non-holder launches"
    );
    for (refused_node, refusal) in &refusal_messages {
        assert!(
            refusal.contains("NotSelectedCoordinator"),
            "refusal for {refused_node} should preserve the typed HRW error: {refusal}"
        );
    }

    let (admitted_node, host) = admitted_host.expect("one HRW host should be admitted");
    let url = |path: &str| format!("{}{path}", host.base_url);
    let mut stale_request = build_invoke_request(connector_id.clone(), &capability_signing_key).0;
    stale_request.input = json!({
        "message": "stale write must be fenced before dispatch",
        "lease_seq": 10_u64,
    });
    stale_request.lease_seq = Some(10);

    let stale_response = host
        .client
        .post(url("/rpc/invoke"))
        .json(&stale_request)
        .send()
        .await?;
    let stale_status = stale_response.status();
    let stale_body = stale_response.text().await?;
    assert_eq!(stale_status, reqwest::StatusCode::FORBIDDEN);
    assert!(
        stale_body.contains(r#""code":"LeaseFenced""#),
        "stale invoke should be fenced with typed HRW evidence: {stale_body}"
    );
    assert!(
        stale_body.contains(r#""current_lease_seq":11"#),
        "stale invoke should report the current fence: {stale_body}"
    );
    assert!(
        stale_body.contains(r#""provided_lease_seq":10"#),
        "stale invoke should report the provided stale fence: {stale_body}"
    );
    assert!(
        !stale_body.contains("stale write must be fenced before dispatch"),
        "stale invoke body should not include connector echo output: {stale_body}"
    );

    let mut current_request = build_invoke_request(connector_id.clone(), &capability_signing_key).0;
    current_request.input = json!({
        "message": "current fence may dispatch",
        "lease_seq": 11_u64,
    });
    current_request.lease_seq = Some(11);
    let current_response: InvokeResponse =
        http_post_json(host.client.clone(), url("/rpc/invoke"), current_request).await?;
    assert_eq!(current_response.status, InvokeStatus::Ok);
    assert_eq!(
        current_response
            .result
            .as_ref()
            .and_then(|result| result.get("echo"))
            .and_then(|echo| echo.get("message"))
            .and_then(Value::as_str),
        Some("current fence may dispatch")
    );

    let lease_status: serde_json::Value = http_get_json(
        host.client.clone(),
        url(&format!(
            "/rpc/admin/connectors/{}/lease/status?zone=z%3Awork",
            connector_id.as_str()
        )),
    )
    .await?;
    assert_eq!(lease_status["source"], "host-hrw-routing");
    assert_eq!(lease_status["local_is_holder"], true);
    assert_eq!(lease_status["fencing_token"], 11);
    assert_eq!(
        lease_status["ranked_holders"]
            .as_array()
            .expect("lease status should include ranked holders")
            .len(),
        3
    );
    assert!(
        lease_status["ranked_holders"]
            .as_array()
            .expect("lease status should include ranked holders")
            .iter()
            .any(|holder| holder["is_local_node"].as_bool() == Some(true)),
        "admitted HRW host {admitted_node} should appear in the holder ladder"
    );

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_hrw_lease_flush_before_yield_reports_durable_state_barrier()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_id = ConnectorId::from_static("fcp.test.hrw-binary-flush:utility:1.0.0");
    let zone_id = ZoneId::work();
    let state_dir = tempfile::tempdir()?;
    let state_root = state_dir.path().join("managed-state");
    let object_id_key = ObjectIdKey::from_bytes([0xB5; 32]);
    let seeded_state = seed_singleton_writer_connector_state(
        &state_root,
        &connector_id,
        &zone_id,
        object_id_key,
        ObjectId::from_bytes([0x92; 32]),
    )
    .await?;
    let connector_config = singleton_writer_test_connector_config_with_state(
        &connector_id,
        "HRW Binary Flush",
        &state_root,
        &object_id_key,
    );
    let eligible_nodes = "node-a,node-b,node-c";
    let mut admitted_host: Option<(String, HttpHostProcess)> = None;
    let mut refusal_messages = Vec::new();

    for local_node in ["node-a", "node-b", "node-c"] {
        match HttpHostProcess::spawn_with_env(
            vec![connector_config.clone()],
            &[
                ("FCP_HOST_HRW_LEASE_LOCAL_NODE", local_node),
                ("FCP_HOST_HRW_LEASE_NODES", eligible_nodes),
                ("FCP_HOST_HRW_LEASE_CURRENT_SEQ", "10"),
            ],
        )
        .await
        {
            Ok(host) => {
                assert!(
                    admitted_host.is_none(),
                    "HRW admitted more than one singleton_writer host launch"
                );
                admitted_host = Some((local_node.to_string(), host));
            }
            Err(error) => refusal_messages.push((local_node.to_string(), error.to_string())),
        }
    }

    assert!(
        admitted_host.is_some(),
        "HRW should admit exactly one singleton_writer host launch; refusals: {refusal_messages:?}"
    );
    assert_eq!(
        refusal_messages.len(),
        2,
        "three-node HRW routing should refuse both non-holder launches"
    );
    for (refused_node, refusal) in &refusal_messages {
        assert!(
            refusal.contains("NotSelectedCoordinator"),
            "refusal for {refused_node} should preserve the typed HRW error: {refusal}"
        );
    }

    let (admitted_node, host) = admitted_host.expect("one HRW host should be admitted");
    let url = |path: &str| format!("{}{path}", host.base_url);
    let flush_response = host
        .client
        .post(url(&format!(
            "/rpc/admin/connectors/{}/lease/flush-before-yield?zone=z%3Awork",
            connector_id.as_str()
        )))
        .bearer_auth(TEST_ADMIN_BEARER_TOKEN)
        .header("x-fcp-zone", "z:owner")
        .json(&json!({}))
        .send()
        .await?;
    let flush_status = flush_response.status();
    let flush_body = flush_response.text().await?;
    let flush_payload: Value = serde_json::from_str(&flush_body).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "flush-before-yield response should be JSON, got {flush_status}: {flush_body}: {error}"
            ),
        )
    })?;

    assert_eq!(
        flush_status,
        reqwest::StatusCode::OK,
        "admitted HRW host {admitted_node} should expose live flush-before-yield payload: {flush_payload}"
    );
    assert_eq!(flush_payload["schema_version"], "1.0.0");
    assert_eq!(flush_payload["source"], "host-canonical-state-flush");
    assert_eq!(flush_payload["connector_id"], connector_id.to_string());
    assert_eq!(flush_payload["zone_id"], zone_id.as_str());
    assert_eq!(flush_payload["flush"]["root_present"], true);
    assert_eq!(
        flush_payload["flush"]["root_object_id"],
        seeded_state.root_object_id.to_string()
    );
    assert_eq!(
        flush_payload["flush"]["head_object_id"],
        seeded_state.head_object_id.to_string()
    );
    assert_eq!(flush_payload["flush"]["last_canonical_seq"], 0);
    assert_eq!(flush_payload["flush"]["lease_seq"], seeded_state.lease_seq);
    assert_eq!(
        flush_payload["flush"]["lease_object_id"],
        seeded_state.lease_object_id.to_string()
    );
    assert_eq!(
        flush_payload["telemetry"]["event_name"],
        "fcp.lease.flushed_on_yield"
    );

    let explain_response = host
        .client
        .get(url(&format!(
            "/rpc/admin/connectors/{}/state/explain?zone=z%3Awork",
            connector_id.as_str()
        )))
        .bearer_auth(TEST_ADMIN_BEARER_TOKEN)
        .header("x-fcp-zone", "z:owner")
        .send()
        .await?;
    let explain_status = explain_response.status();
    let explain_body = explain_response.text().await?;
    let explain_payload: Value = serde_json::from_str(&explain_body).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "state explain response should be JSON, got {explain_status}: {explain_body}: {error}"
            ),
        )
    })?;
    assert_eq!(
        explain_status,
        reqwest::StatusCode::OK,
        "admitted HRW host {admitted_node} should expose canonical state after flush: {explain_payload}"
    );
    assert_eq!(explain_payload["source"], "host-canonical-state");
    assert_eq!(explain_payload["canonical_state"]["root_present"], true);
    assert_eq!(
        explain_payload["canonical_state"]["root_object_id"],
        seeded_state.root_object_id.to_string()
    );
    assert_eq!(
        explain_payload["canonical_state"]["head_object_id"],
        seeded_state.head_object_id.to_string()
    );
    assert_eq!(explain_payload["last_canonical_seq"], 0);
    assert_eq!(
        explain_payload["canonical_state"]["model"],
        "singleton_writer"
    );

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_hrw_lease_reselects_holder_after_departure()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_id = ConnectorId::from_static("fcp.test.hrw-binary-failover:utility:1.0.0");
    let zone_id = ZoneId::work();
    let state_dir = tempfile::tempdir()?;
    let state_root = state_dir.path().join("managed-state");
    let object_id_key = ObjectIdKey::from_bytes([0xC6; 32]);
    let all_nodes = ["node-a", "node-b", "node-c"];
    let initial_eligible_nodes = all_nodes.join(",");
    let initial_eligible_node_ids = all_nodes
        .iter()
        .map(|node| TailscaleNodeId::new(*node))
        .collect::<Vec<_>>();
    let subject_id = singleton_writer_connector_lease_subject_id_for_test(&connector_id, &zone_id);
    let expected_initial_holder =
        fcp_mesh::planner::select_lease_holder(&zone_id, &subject_id, &initial_eligible_node_ids)
            .expect("initial HRW holder should be selected");
    let seeded_state = seed_singleton_writer_connector_state_with_durable_lease(
        &state_root,
        &connector_id,
        &zone_id,
        object_id_key,
        expected_initial_holder.clone(),
    )
    .await?;
    let connector_config = singleton_writer_test_connector_config_with_state(
        &connector_id,
        "HRW Binary Failover",
        &state_root,
        &object_id_key,
    );
    let capability_signing_key = Ed25519SigningKey::generate();
    let capability_public_key = capability_public_key_hex(&capability_signing_key);
    let mut initial_holder: Option<(String, HttpHostProcess)> = None;
    let mut initial_refusals = Vec::new();

    for local_node in all_nodes {
        match HttpHostProcess::spawn_with_env(
            vec![connector_config.clone()],
            &[
                ("FCP_HOST_HRW_LEASE_LOCAL_NODE", local_node),
                ("FCP_HOST_HRW_LEASE_NODES", initial_eligible_nodes.as_str()),
                ("FCP_HOST_HRW_LEASE_CURRENT_SEQ", "10"),
                (
                    "FCP_HOST_CAPABILITY_PUBLIC_KEY",
                    capability_public_key.as_str(),
                ),
            ],
        )
        .await
        {
            Ok(host) => {
                assert!(
                    initial_holder.is_none(),
                    "initial HRW routing admitted more than one singleton_writer host launch"
                );
                initial_holder = Some((local_node.to_string(), host));
            }
            Err(error) => initial_refusals.push((local_node.to_string(), error.to_string())),
        }
    }

    assert!(
        initial_holder.is_some(),
        "initial HRW routing should admit one holder; refusals: {initial_refusals:?}"
    );
    assert_eq!(
        initial_refusals.len(),
        2,
        "initial three-node HRW routing should refuse both non-holders"
    );

    let (departed_node, departed_host) =
        initial_holder.expect("initial HRW routing should admit one holder");
    assert_eq!(
        departed_node,
        expected_initial_holder.as_str(),
        "real fcp-host launch should admit the same HRW holder as the durable lease fixture"
    );
    let departed_base_url = departed_host.base_url.clone();
    let lease_status: Value = http_get_json(
        departed_host.client.clone(),
        format!(
            "{}/rpc/admin/connectors/{}/lease/status?zone=z%3Awork",
            departed_base_url,
            connector_id.as_str()
        ),
    )
    .await?;
    assert_eq!(lease_status["source"], "host-hrw-routing");
    assert_eq!(
        lease_status["lease_evidence_source"],
        "canonical-fcp-store-lease-object"
    );
    assert_eq!(
        lease_status["lease_object_id"],
        seeded_state.lease_object_id.to_string()
    );
    assert_eq!(lease_status["fencing_token"], seeded_state.lease_seq);
    assert_eq!(lease_status["durable_lease_seq"], seeded_state.lease_seq);
    assert_eq!(
        lease_status["expiry_unix_secs"],
        seeded_state.lease_expiry_unix_secs
    );
    assert!(
        lease_status["expiry"]
            .as_str()
            .is_some_and(|expiry| expiry.ends_with('Z')),
        "real binary lease status should expose RFC3339 expiry: {lease_status}"
    );
    assert_eq!(lease_status["quorum_signers_count"], 2);
    assert_eq!(lease_status["required_quorum_signers_count"], 2);
    assert_eq!(lease_status["quorum_satisfied"], true);
    assert_eq!(lease_status["durable_validation"]["status"], "valid");
    assert!(
        lease_status["durable_validation"]["validated_at_unix_secs"]
            .as_u64()
            .is_some()
    );
    assert_eq!(lease_status["local_is_holder"], true);

    let flush_response = departed_host
        .client
        .post(format!(
            "{}/rpc/admin/connectors/{}/lease/flush-before-yield?zone=z%3Awork",
            departed_base_url,
            connector_id.as_str()
        ))
        .bearer_auth(TEST_ADMIN_BEARER_TOKEN)
        .header("x-fcp-zone", "z:owner")
        .json(&json!({}))
        .send()
        .await?;
    let flush_status = flush_response.status();
    let flush_body = flush_response.text().await?;
    let flush_payload: Value = serde_json::from_str(&flush_body).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "departing holder flush-before-yield response should be JSON, got {flush_status}: {flush_body}: {error}"
            ),
        )
    })?;
    assert_eq!(
        flush_status,
        reqwest::StatusCode::OK,
        "departing holder {departed_node} should flush canonical state before removal: {flush_payload}"
    );
    assert_eq!(
        flush_payload["flush"]["root_object_id"],
        seeded_state.root_object_id.to_string()
    );
    assert_eq!(flush_payload["flush"]["lease_seq"], seeded_state.lease_seq);
    drop(departed_host);

    let remaining_nodes = all_nodes
        .into_iter()
        .filter(|node| *node != departed_node.as_str())
        .collect::<Vec<_>>();
    assert_eq!(remaining_nodes.len(), 2);
    let remaining_eligible_nodes = remaining_nodes.join(",");
    let mut new_holder: Option<(String, HttpHostProcess)> = None;
    let mut new_refusals = Vec::new();

    for local_node in &remaining_nodes {
        match HttpHostProcess::spawn_with_env(
            vec![connector_config.clone()],
            &[
                ("FCP_HOST_HRW_LEASE_LOCAL_NODE", *local_node),
                (
                    "FCP_HOST_HRW_LEASE_NODES",
                    remaining_eligible_nodes.as_str(),
                ),
                ("FCP_HOST_HRW_LEASE_CURRENT_SEQ", "11"),
                (
                    "FCP_HOST_CAPABILITY_PUBLIC_KEY",
                    capability_public_key.as_str(),
                ),
            ],
        )
        .await
        {
            Ok(host) => {
                assert!(
                    new_holder.is_none(),
                    "post-departure HRW routing admitted more than one singleton_writer host launch"
                );
                new_holder = Some(((*local_node).to_string(), host));
            }
            Err(error) => new_refusals.push(((*local_node).to_string(), error.to_string())),
        }
    }

    assert!(
        new_holder.is_some(),
        "post-departure HRW routing should admit one replacement holder; refusals: {new_refusals:?}"
    );
    assert_eq!(
        new_refusals.len(),
        1,
        "two-node post-departure HRW routing should refuse one non-holder"
    );
    for (refused_node, refusal) in &new_refusals {
        assert!(
            refusal.contains("NotSelectedCoordinator"),
            "post-departure refusal for {refused_node} should preserve the typed HRW error: {refusal}"
        );
    }

    let (new_holder_node, new_host) =
        new_holder.expect("post-departure HRW routing should admit one replacement holder");
    assert_ne!(
        new_holder_node, departed_node,
        "replacement holder must come from the eligible set after removing the departed node"
    );
    let url = |path: &str| format!("{}{path}", new_host.base_url);
    let mut stale_request = build_invoke_request(connector_id.clone(), &capability_signing_key).0;
    stale_request.input = json!({
        "message": "post-failover stale write must be fenced",
        "lease_seq": 10_u64,
    });
    stale_request.lease_seq = Some(10);
    let stale_response = new_host
        .client
        .post(url("/rpc/invoke"))
        .json(&stale_request)
        .send()
        .await?;
    let stale_status = stale_response.status();
    let stale_body = stale_response.text().await?;
    assert_eq!(stale_status, reqwest::StatusCode::FORBIDDEN);
    assert!(
        stale_body.contains(r#""code":"LeaseFenced""#),
        "replacement holder should fence stale pre-handoff writes: {stale_body}"
    );
    assert!(
        stale_body.contains(r#""current_lease_seq":11"#),
        "replacement holder should report the post-departure fence: {stale_body}"
    );

    let explain_response = new_host
        .client
        .get(url(&format!(
            "/rpc/admin/connectors/{}/state/explain?zone=z%3Awork",
            connector_id.as_str()
        )))
        .bearer_auth(TEST_ADMIN_BEARER_TOKEN)
        .header("x-fcp-zone", "z:owner")
        .send()
        .await?;
    let explain_status = explain_response.status();
    let explain_body = explain_response.text().await?;
    let explain_payload: Value = serde_json::from_str(&explain_body).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "replacement holder state explain response should be JSON, got {explain_status}: {explain_body}: {error}"
            ),
        )
    })?;
    assert_eq!(
        explain_status,
        reqwest::StatusCode::OK,
        "replacement holder {new_holder_node} should expose canonical state after failover: {explain_payload}"
    );
    assert_eq!(
        explain_payload["canonical_state"]["root_object_id"],
        seeded_state.root_object_id.to_string()
    );
    assert_eq!(
        explain_payload["canonical_state"]["head_object_id"],
        seeded_state.head_object_id.to_string()
    );
    assert_eq!(
        explain_payload["canonical_state"]["model"],
        "singleton_writer"
    );

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_config_routes_are_live_revision_aware()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_id = ConnectorId::from_static("fcp.test.config-http:utility:1.0.0");
    let host = HttpHostProcess::spawn_with_connectors_file(
        vec![test_connector_config(
            &connector_id,
            "Config HTTP",
            &["test", "config"],
        )],
        &[],
    )
    .await?;
    let url = |path: &str| format!("{}{path}", host.base_url);

    let snapshot_url = url(&format!("/rpc/connectors/{}/config", connector_id.as_str()));
    let revisions_url = url(&format!(
        "/rpc/connectors/{}/config/revisions",
        connector_id.as_str()
    ));
    let diff_url = url(&format!(
        "/rpc/connectors/{}/config/diff",
        connector_id.as_str()
    ));
    let validate_url = url(&format!(
        "/rpc/connectors/{}/config/validate",
        connector_id.as_str()
    ));
    let apply_url = url(&format!(
        "/rpc/connectors/{}/config/apply",
        connector_id.as_str()
    ));
    let rollback_url = url(&format!(
        "/rpc/connectors/{}/config/rollback",
        connector_id.as_str()
    ));

    let initial_snapshot: ConnectorConfigSnapshot =
        http_get_json(host.client.clone(), snapshot_url.clone()).await?;
    assert_eq!(initial_snapshot.connector_id, connector_id);
    assert_eq!(
        initial_snapshot.source,
        ConnectorConfigSnapshotSource::ManagedInventory
    );
    assert_eq!(initial_snapshot.active_revision_id, None);
    assert_eq!(initial_snapshot.revision_count, 0);
    assert_eq!(initial_snapshot.current.payload, json!({}));

    let config_v1 = json!({
        "profile": "work",
        "region": "us-east-1",
    });
    let validate_v1: ConnectorConfigValidateResponse = http_post_json(
        host.client.clone(),
        validate_url.clone(),
        ConnectorConfigValidateRequest {
            payload: config_v1.clone(),
            expected_active_revision_id: None,
        },
    )
    .await?;
    assert!(validate_v1.valid);
    assert_eq!(validate_v1.current_active_revision_id, None);
    assert_eq!(validate_v1.current.payload, json!({}));
    assert_eq!(validate_v1.candidate.payload, config_v1);
    assert!(validate_v1.preview.is_some());
    assert!(
        validate_v1
            .diff
            .iter()
            .any(|entry| entry.path == "/profile" && entry.kind == ConfigDiffKind::Added)
    );
    assert!(
        validate_v1
            .diff
            .iter()
            .any(|entry| entry.path == "/region" && entry.kind == ConfigDiffKind::Added)
    );
    assert!(
        validate_v1
            .preview
            .as_ref()
            .is_some_and(|report| report.updated.iter().any(|id| id == connector_id.as_str()))
    );

    let apply_v1: ConnectorConfigApplyResponse = http_post_json(
        host.client.clone(),
        apply_url.clone(),
        ConnectorConfigApplyRequest {
            payload: config_v1.clone(),
            expected_active_revision_id: None,
            created_by: Some("integration-test".to_string()),
            change_reason: Some("seed config".to_string()),
        },
    )
    .await?;
    let revision_v1 = apply_v1
        .current_active_revision_id
        .expect("apply should create the first revision");
    assert!(apply_v1.changed);
    assert_eq!(apply_v1.previous_active_revision_id, None);
    assert_eq!(apply_v1.current.payload, config_v1);
    assert_eq!(
        apply_v1
            .revision
            .as_ref()
            .map(|revision| revision.revision_id),
        Some(revision_v1)
    );
    assert_eq!(
        apply_v1
            .revision
            .as_ref()
            .and_then(|revision| revision.created_by.as_deref()),
        Some("integration-test")
    );
    assert!(
        apply_v1
            .apply
            .as_ref()
            .is_some_and(|report| report.updated.iter().any(|id| id == connector_id.as_str()))
    );
    assert!(apply_v1.admin_state.is_some());

    let snapshot_after_v1: ConnectorConfigSnapshot =
        http_get_json(host.client.clone(), snapshot_url.clone()).await?;
    assert_eq!(snapshot_after_v1.active_revision_id, Some(revision_v1));
    assert_eq!(
        snapshot_after_v1.source,
        ConnectorConfigSnapshotSource::ActiveRevision
    );
    assert_eq!(snapshot_after_v1.revision_count, 1);
    assert_eq!(snapshot_after_v1.current.payload, config_v1);

    let revisions_after_v1: ConnectorConfigRevisionsResponse =
        http_get_json(host.client.clone(), revisions_url.clone()).await?;
    assert_eq!(revisions_after_v1.active_revision_id, Some(revision_v1));
    assert_eq!(revisions_after_v1.revision_count, 1);
    assert_eq!(revisions_after_v1.revisions.len(), 1);

    let revision_v1_record: ConfigRevisionRecord = http_get_json(
        host.client.clone(),
        url(&format!(
            "/rpc/connectors/{}/config/revisions/{}",
            connector_id.as_str(),
            revision_v1
        )),
    )
    .await?;
    assert_eq!(revision_v1_record.revision_id, revision_v1);
    assert_eq!(revision_v1_record.payload, config_v1);
    assert_eq!(
        revision_v1_record.created_by.as_deref(),
        Some("integration-test")
    );

    let config_v2 = json!({
        "profile": "work",
        "region": "eu-west-1",
        "features": {
            "alpha": true,
        },
    });
    let diff_v2: ConnectorConfigDiffResponse = http_post_json(
        host.client.clone(),
        diff_url.clone(),
        ConnectorConfigDiffRequest {
            payload: config_v2.clone(),
            revision_id: Some(revision_v1),
        },
    )
    .await?;
    assert_eq!(diff_v2.base_revision_id, Some(revision_v1));
    assert!(diff_v2.changed);
    assert_eq!(diff_v2.base.payload, config_v1);
    assert_eq!(diff_v2.candidate.payload, config_v2);
    assert!(
        diff_v2
            .entries
            .iter()
            .any(|entry| entry.path == "/region" && entry.kind == ConfigDiffKind::Changed)
    );
    assert!(
        diff_v2
            .entries
            .iter()
            .any(|entry| entry.path == "/features" && entry.kind == ConfigDiffKind::Added)
    );

    let validate_v2: ConnectorConfigValidateResponse = http_post_json(
        host.client.clone(),
        validate_url.clone(),
        ConnectorConfigValidateRequest {
            payload: config_v2.clone(),
            expected_active_revision_id: Some(revision_v1),
        },
    )
    .await?;
    assert!(validate_v2.valid);
    assert_eq!(validate_v2.current_active_revision_id, Some(revision_v1));
    assert_eq!(validate_v2.current.payload, config_v1);
    assert_eq!(validate_v2.candidate.payload, config_v2);

    let apply_v2: ConnectorConfigApplyResponse = http_post_json(
        host.client.clone(),
        apply_url.clone(),
        ConnectorConfigApplyRequest {
            payload: config_v2.clone(),
            expected_active_revision_id: Some(revision_v1),
            created_by: Some("integration-test".to_string()),
            change_reason: Some("switch region".to_string()),
        },
    )
    .await?;
    let revision_v2 = apply_v2
        .current_active_revision_id
        .expect("second apply should advance the active revision");
    assert!(apply_v2.changed);
    assert_eq!(apply_v2.previous_active_revision_id, Some(revision_v1));
    assert_eq!(apply_v2.current.payload, config_v2);
    assert!(revision_v2 > revision_v1);

    let revisions_after_v2: ConnectorConfigRevisionsResponse =
        http_get_json(host.client.clone(), revisions_url.clone()).await?;
    assert_eq!(revisions_after_v2.active_revision_id, Some(revision_v2));
    assert_eq!(revisions_after_v2.revision_count, 2);

    let rollback: ConnectorConfigApplyResponse = http_post_json(
        host.client.clone(),
        rollback_url.clone(),
        ConnectorConfigRollbackRequest {
            revision_id: revision_v1,
            expected_active_revision_id: Some(revision_v2),
            created_by: Some("integration-test".to_string()),
            change_reason: Some("rollback to baseline".to_string()),
        },
    )
    .await?;
    let revision_v3 = rollback
        .current_active_revision_id
        .expect("rollback should record a new active revision");
    assert!(rollback.changed);
    assert_eq!(rollback.previous_active_revision_id, Some(revision_v2));
    assert_eq!(rollback.current.payload, config_v1);
    assert_eq!(
        rollback
            .revision
            .as_ref()
            .and_then(|revision| revision.previous_revision_id),
        Some(revision_v2)
    );
    assert!(revision_v3 > revision_v2);

    let final_snapshot: ConnectorConfigSnapshot =
        http_get_json(host.client.clone(), snapshot_url.clone()).await?;
    assert_eq!(final_snapshot.active_revision_id, Some(revision_v3));
    assert_eq!(
        final_snapshot.source,
        ConnectorConfigSnapshotSource::ActiveRevision
    );
    assert_eq!(final_snapshot.revision_count, 3);
    assert_eq!(final_snapshot.current.payload, config_v1);

    let stale_response = host
        .client
        .post(apply_url)
        .headers(admin_auth_headers())
        .json(&ConnectorConfigApplyRequest {
            payload: config_v2,
            expected_active_revision_id: Some(revision_v2),
            created_by: Some("integration-test".to_string()),
            change_reason: Some("stale write".to_string()),
        })
        .send()
        .await?;
    assert_eq!(stale_response.status(), reqwest::StatusCode::BAD_REQUEST);
    let stale_body = stale_response.text().await?;
    assert!(stale_body.contains(&format!(
        "config revision {revision_v3}, expected {revision_v2}"
    )));

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_preflight_route_denies_missing_capability_token()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_id = ConnectorId::from_static("fcp.test.preflight-auth:utility:1.0.0");
    let capability_signing_key = Ed25519SigningKey::generate();
    let capability_public_key = capability_public_key_hex(&capability_signing_key);
    let host = HttpHostProcess::spawn_with_env(
        vec![test_connector_config(
            &connector_id,
            "Preflight Auth",
            &["test", "auth"],
        )],
        &[(
            "FCP_HOST_CAPABILITY_PUBLIC_KEY",
            capability_public_key.as_str(),
        )],
    )
    .await?;
    let url = |path: &str| format!("{}{path}", host.base_url);

    let denied: PreflightResponse = http_post_json(
        host.client.clone(),
        url("/rpc/preflight"),
        HostPreflightRequest {
            request_id: RequestId::random(),
            connector_id,
            operation: TEST_OPERATION.to_string(),
            params: Some(json!({ "message": "hello" })),
            principal: Some(TEST_PRINCIPAL.to_string()),
            zone_id: Some(ZoneId::work()),
            capability_token: None,
            approval_tokens: Vec::new(),
        },
    )
    .await?;

    assert!(!denied.allowed);
    assert!(
        denied
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("capability token is required"))
    );

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_preflight_route_matches_capability_verification_vectors()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_id = ConnectorId::from_static("fcp.test.preflight-vectors:utility:1.0.0");
    let trusted_signing_key = signing_key_from_hex(TRUSTED_CAPABILITY_SIGNING_KEY_HEX);
    let capability_public_key = capability_public_key_hex(&trusted_signing_key);
    let host = HttpHostProcess::spawn_with_env(
        vec![test_connector_config(
            &connector_id,
            "Preflight Vector Auth",
            &["test", "auth", "vectors"],
        )],
        &[(
            "FCP_HOST_CAPABILITY_PUBLIC_KEY",
            capability_public_key.as_str(),
        )],
    )
    .await?;
    let url = |path: &str| format!("{}{path}", host.base_url);

    let cases: Vec<CapabilityPreflightVectorCase> = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/host/capability_verification.json"
    )))
    .expect("capability verification vectors should parse");
    let mut seen_names = HashSet::new();
    for case in &cases {
        assert!(
            seen_names.insert(case.name.clone()),
            "duplicate capability vector name: {}",
            case.name
        );
    }

    let now = Utc::now();
    for case in cases {
        let capability = match case.token_mode {
            CapabilityPreflightVectorTokenMode::Missing => None,
            CapabilityPreflightVectorTokenMode::Signed => {
                let signing_key = signing_key_from_hex(
                    case.signing_key_hex
                        .as_deref()
                        .expect("signed vectors require a signing key"),
                );
                let not_before = now
                    + ChronoDuration::seconds(
                        case.not_before_offset_secs
                            .expect("signed vectors require not_before_offset_secs"),
                    );
                let expires = now
                    + ChronoDuration::seconds(
                        case.expires_offset_secs
                            .expect("signed vectors require expires_offset_secs"),
                    );
                Some(build_live_capability_token_with_validity(
                    &signing_key,
                    TEST_CAPABILITY_ID,
                    case.token_principal
                        .as_deref()
                        .expect("signed vectors require token_principal"),
                    TEST_OPERATION,
                    &ZoneId::work(),
                    not_before,
                    expires,
                ))
            }
        };

        let response: PreflightResponse = http_post_json(
            host.client.clone(),
            url("/rpc/preflight"),
            build_vector_preflight_request(
                connector_id.clone(),
                &case.principal_override,
                capability,
            ),
        )
        .await?;

        assert_eq!(
            response.allowed, case.expected_allowed,
            "vector case `{}` had unexpected allow/deny result: {response:?}",
            case.name
        );
        match case.expected_reason_contains {
            Some(fragment) => assert!(
                response
                    .reason
                    .as_deref()
                    .is_some_and(|reason| reason.to_lowercase().contains(&fragment.to_lowercase())),
                "vector case `{}` expected reason containing `{fragment}`, got {:?}",
                case.name,
                response.reason
            ),
            None => assert!(
                response.reason.is_none(),
                "vector case `{}` unexpectedly returned denial reason {:?}",
                case.name,
                response.reason
            ),
        }
    }

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_simulate_route_denies_missing_capability_token()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_id = ConnectorId::from_static("fcp.test.simulate-auth:utility:1.0.0");
    let capability_signing_key = Ed25519SigningKey::generate();
    let capability_public_key = capability_public_key_hex(&capability_signing_key);
    let host = HttpHostProcess::spawn_with_env(
        vec![test_connector_config(
            &connector_id,
            "Simulate Auth",
            &["test", "simulate"],
        )],
        &[(
            "FCP_HOST_CAPABILITY_PUBLIC_KEY",
            capability_public_key.as_str(),
        )],
    )
    .await?;
    let url = |path: &str| format!("{}{path}", host.base_url);

    let response: HostSimulateResponse = http_post_json(
        host.client.clone(),
        url("/rpc/simulate"),
        HostSimulateRequest {
            request_id: "simulate-denied-1".to_string(),
            connector_id: connector_id.to_string(),
            operation: TEST_OPERATION.to_string(),
            input: Some(json!({ "message": "hello" })),
            zone_id: Some(ZoneId::work().to_string()),
            principal: Some(TEST_PRINCIPAL.to_string()),
            capability_token: None,
            approval_tokens: Vec::new(),
            estimate_cost: false,
            check_availability: false,
            deadline_ms: 5_000,
        },
    )
    .await?;

    assert_eq!(response.request_id, "simulate-denied-1");
    assert!(!response.would_succeed);
    assert_eq!(response.phase, SimulatePhase::PreflightOnly);
    assert!(!response.preflight_allowed);
    assert!(
        response
            .failure_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("capability token is required"))
    );
    assert_eq!(response.receipt.connector_id, connector_id.as_str());
    assert_eq!(response.receipt.operation, TEST_OPERATION);
    assert_eq!(response.receipt.phase, SimulatePhase::PreflightOnly);
    assert!(!response.receipt.would_succeed);
    assert!(response.receipt.input_digest.is_some());

    let receipts: SimulateReceiptQueryResponse = http_post_json(
        host.client.clone(),
        url("/rpc/admin/simulate-receipts"),
        SimulateReceiptQueryRequest {
            connector_id: connector_id.to_string(),
            operation: Some(TEST_OPERATION.to_string()),
            after: None,
            limit: 10,
        },
    )
    .await?;
    assert_eq!(receipts.receipts.len(), 1);
    assert_eq!(receipts.total_receipts, 1);
    assert_eq!(receipts.receipts[0].receipt_id, response.receipt.receipt_id);
    assert_eq!(receipts.receipts[0].phase, SimulatePhase::PreflightOnly);
    assert!(!receipts.receipts[0].would_succeed);

    let logs = wait_for_log_events(
        &host.stderr_logs,
        &[
            "simulate_request",
            "simulate_response",
            "simulate_receipt_query_request",
        ],
    )
    .await?;
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("simulate_request")
            && entry.get("connector_id").and_then(Value::as_str) == Some(connector_id.as_str())
            && entry.get("request_id").and_then(Value::as_str) == Some("simulate-denied-1")
    }));
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("simulate_response")
            && entry.get("connector_id").and_then(Value::as_str) == Some(connector_id.as_str())
            && entry.get("request_id").and_then(Value::as_str) == Some("simulate-denied-1")
            && entry.get("phase").and_then(Value::as_str) == Some("PreflightOnly")
            && entry.get("preflight_allowed").and_then(Value::as_bool) == Some(false)
            && entry.get("would_succeed").and_then(Value::as_bool) == Some(false)
    }));

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_simulate_route_reaches_connector_and_records_receipt()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_id = ConnectorId::from_static("fcp.test.simulate-live:utility:1.0.0");
    let capability_signing_key = Ed25519SigningKey::generate();
    let capability_public_key = capability_public_key_hex(&capability_signing_key);
    let host = HttpHostProcess::spawn_with_env(
        vec![test_connector_config(
            &connector_id,
            "Simulate Live",
            &["test", "simulate"],
        )],
        &[(
            "FCP_HOST_CAPABILITY_PUBLIC_KEY",
            capability_public_key.as_str(),
        )],
    )
    .await?;
    let url = |path: &str| format!("{}{path}", host.base_url);
    let (invoke_request, _) = build_invoke_request(connector_id.clone(), &capability_signing_key);
    let preflight: PreflightResponse = http_post_json(
        host.client.clone(),
        url("/rpc/preflight"),
        HostPreflightRequest {
            request_id: RequestId::new("simulate-live-preflight"),
            connector_id: connector_id.clone(),
            operation: invoke_request.operation.to_string(),
            params: Some(json!({ "message": "hello" })),
            principal: Some(TEST_PRINCIPAL.to_string()),
            zone_id: Some(invoke_request.zone_id.clone()),
            capability_token: Some(invoke_request.capability_token.clone()),
            approval_tokens: Vec::new(),
        },
    )
    .await?;
    assert!(preflight.allowed, "{preflight:?}");

    let response: HostSimulateResponse = http_post_json(
        host.client.clone(),
        url("/rpc/simulate"),
        HostSimulateRequest {
            request_id: "simulate-live-1".to_string(),
            connector_id: connector_id.to_string(),
            operation: invoke_request.operation.to_string(),
            input: Some(json!({ "message": "hello" })),
            zone_id: Some(invoke_request.zone_id.to_string()),
            principal: Some(TEST_PRINCIPAL.to_string()),
            capability_token: Some(invoke_request.capability_token),
            approval_tokens: Vec::new(),
            estimate_cost: false,
            check_availability: false,
            deadline_ms: 5_000,
        },
    )
    .await?;

    assert_eq!(response.request_id, "simulate-live-1");
    assert!(response.would_succeed, "{response:?}");
    assert_eq!(response.phase, SimulatePhase::ConnectorReached);
    assert!(response.preflight_allowed);
    assert!(response.failure_reason.is_none());
    assert!(response.denial_code.is_none());
    assert!(response.missing_capabilities.is_empty());
    assert_eq!(response.receipt.connector_id, connector_id.as_str());
    assert_eq!(response.receipt.operation, TEST_OPERATION);
    assert_eq!(response.receipt.phase, SimulatePhase::ConnectorReached);
    assert!(response.receipt.would_succeed);
    assert!(response.receipt.input_digest.is_some());

    let receipts: SimulateReceiptQueryResponse = http_post_json(
        host.client.clone(),
        url("/rpc/admin/simulate-receipts"),
        SimulateReceiptQueryRequest {
            connector_id: connector_id.to_string(),
            operation: Some(TEST_OPERATION.to_string()),
            after: None,
            limit: 10,
        },
    )
    .await?;
    assert_eq!(receipts.receipts.len(), 1);
    assert_eq!(receipts.total_receipts, 1);
    assert_eq!(receipts.receipts[0].receipt_id, response.receipt.receipt_id);
    assert_eq!(receipts.receipts[0].phase, SimulatePhase::ConnectorReached);
    assert!(receipts.receipts[0].would_succeed);

    let logs = wait_for_log_events(
        &host.stderr_logs,
        &[
            "simulate_request",
            "simulate_response",
            "simulate_receipt_query_request",
        ],
    )
    .await?;
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("simulate_request")
            && entry.get("connector_id").and_then(Value::as_str) == Some(connector_id.as_str())
            && entry.get("request_id").and_then(Value::as_str) == Some("simulate-live-1")
    }));
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("simulate_response")
            && entry.get("connector_id").and_then(Value::as_str) == Some(connector_id.as_str())
            && entry.get("request_id").and_then(Value::as_str) == Some("simulate-live-1")
            && entry.get("phase").and_then(Value::as_str) == Some("ConnectorReached")
            && entry.get("preflight_allowed").and_then(Value::as_bool) == Some(true)
            && entry.get("would_succeed").and_then(Value::as_bool) == Some(true)
            && entry.get("receipt_id").and_then(Value::as_str)
                == Some(response.receipt.receipt_id.as_str())
    }));

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_supply_chain_verify_route_allows_and_caches()
-> Result<(), Box<dyn std::error::Error>> {
    let host = HttpHostProcess::spawn(vec![]).await?;
    let url = |path: &str| format!("{}{path}", host.base_url);
    let connector_id = ConnectorId::from_static("fcp.test.supply-chain:utility:1.0.0");
    let digest = valid_digest();
    let attestation = valid_attestation(&digest);
    let sbom = valid_sbom();
    let request = json!({
        "connector_id": connector_id.as_str(),
        "version": "1.0.0",
        "artifact_digest": digest,
        "attestation": attestation,
        "sbom": sbom,
    });

    let first: GateOutcome = http_post_json(
        host.client.clone(),
        url("/rpc/supply-chain/verify"),
        request.clone(),
    )
    .await?;
    assert!(first.allowed);
    assert!(!first.cached);
    assert!(!first.audit_event.cached);
    assert_eq!(first.evidence.reason_code, VerificationReasonCode::Verified);

    let second: GateOutcome = http_post_json(
        host.client.clone(),
        url("/rpc/supply-chain/verify"),
        request,
    )
    .await?;
    assert!(second.allowed);
    assert!(second.cached);
    assert!(second.audit_event.cached);
    assert_eq!(
        second.evidence.reason_code,
        VerificationReasonCode::Verified
    );
    assert_eq!(first.evidence, second.evidence);
    assert_eq!(
        first.audit_event.evidence_digest,
        second.audit_event.evidence_digest
    );
    assert_eq!(
        first.audit_event.verified_at,
        second.audit_event.verified_at
    );

    let logs = wait_for_log_events(
        &host.stderr_logs,
        &[
            "supply_chain_verify_request",
            "supply_chain_verify_response",
        ],
    )
    .await?;
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("supply_chain_verify_request")
            && entry.get("connector_id").and_then(Value::as_str) == Some(connector_id.as_str())
    }));
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("supply_chain_verify_response")
            && entry.get("connector_id").and_then(Value::as_str) == Some(connector_id.as_str())
            && entry.get("cached").and_then(Value::as_bool) == Some(false)
            && entry.get("reason_code").and_then(Value::as_str) == Some("VERIFIED")
    }));
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("supply_chain_verify_response")
            && entry.get("connector_id").and_then(Value::as_str) == Some(connector_id.as_str())
            && entry.get("cached").and_then(Value::as_bool) == Some(true)
            && entry.get("reason_code").and_then(Value::as_str) == Some("VERIFIED")
    }));

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_supply_chain_verify_route_denies_missing_attestation()
-> Result<(), Box<dyn std::error::Error>> {
    let host = HttpHostProcess::spawn(vec![]).await?;
    let url = |path: &str| format!("{}{path}", host.base_url);
    let connector_id = ConnectorId::from_static("fcp.test.supply-chain-missing:utility:1.0.0");

    let outcome: GateOutcome = http_post_json(
        host.client.clone(),
        url("/rpc/supply-chain/verify"),
        json!({
            "connector_id": connector_id.as_str(),
            "version": "1.0.0",
            "artifact_digest": valid_digest(),
            "sbom": valid_sbom(),
        }),
    )
    .await?;

    assert!(!outcome.allowed);
    assert!(!outcome.cached);
    assert_eq!(
        outcome.evidence.reason_code,
        VerificationReasonCode::AttestationMissing
    );

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_supply_chain_verify_route_honors_dev_override_env()
-> Result<(), Box<dyn std::error::Error>> {
    let host = HttpHostProcess::spawn_with_env(
        vec![],
        &[("FCP_HOST_SUPPLY_CHAIN_ALLOW_DEV_OVERRIDES", "true")],
    )
    .await?;
    let url = |path: &str| format!("{}{path}", host.base_url);
    let connector_id = ConnectorId::from_static("fcp.test.supply-chain-dev:utility:0.1.0");

    let outcome: GateOutcome = http_post_json(
        host.client.clone(),
        url("/rpc/supply-chain/verify"),
        json!({
            "connector_id": connector_id.as_str(),
            "version": "0.1.0",
            "artifact_digest": valid_digest(),
        }),
    )
    .await?;

    assert!(outcome.allowed);
    assert_eq!(
        outcome.evidence.reason_code,
        VerificationReasonCode::AllowedUnsigned
    );

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_batch_route_executes_multiple_invokes()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_id = ConnectorId::from_static("fcp.test.batch-http:utility:1.0.0");
    let capability_signing_key = Ed25519SigningKey::generate();
    let capability_public_key = capability_public_key_hex(&capability_signing_key);
    let host = HttpHostProcess::spawn_with_env(
        vec![test_connector_config(
            &connector_id,
            "Batch Echo",
            &["test", "batch"],
        )],
        &[(
            "FCP_HOST_CAPABILITY_PUBLIC_KEY",
            capability_public_key.as_str(),
        )],
    )
    .await?;
    let url = |path: &str| format!("{}{path}", host.base_url);

    let (mut first_request, _) =
        build_invoke_request(connector_id.clone(), &capability_signing_key);
    first_request.input = json!({ "message": "first" });
    let (mut second_request, _) =
        build_invoke_request(connector_id.clone(), &capability_signing_key);
    second_request.input = json!({ "message": "second" });

    let response: BatchInvokeResponse = http_post_json(
        host.client.clone(),
        url("/rpc/batch"),
        json!({
            "operations": [
                batch_operation_json("op1", first_request, &[]),
                batch_operation_json("op2", second_request, &[]),
            ],
            "options": {
                "max_parallelism": 2,
                "stop_on_first_error": false,
                "timeout_ms": 30_000,
            }
        }),
    )
    .await?;

    assert_eq!(response.status, BatchStatus::Success);
    assert_eq!(response.completed, 2);
    assert_eq!(response.failed, 0);
    assert_eq!(response.skipped, 0);
    assert_eq!(response.results.len(), 2);
    assert_eq!(response.results[0].id, "op1");
    assert_eq!(response.results[1].id, "op2");
    assert_eq!(response.results[0].status, OperationResultStatus::Success);
    assert_eq!(response.results[1].status, OperationResultStatus::Success);
    assert_eq!(
        response.results[0]
            .output
            .as_ref()
            .and_then(|output| output.get("result"))
            .and_then(|result| result.get("echo"))
            .and_then(|echo| echo.get("message"))
            .and_then(Value::as_str),
        Some("first")
    );
    assert_eq!(
        response.results[1]
            .output
            .as_ref()
            .and_then(|output| output.get("result"))
            .and_then(|result| result.get("echo"))
            .and_then(|echo| echo.get("message"))
            .and_then(Value::as_str),
        Some("second")
    );

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_batch_route_returns_adaptive_scheduler_replay_summary()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_id = ConnectorId::from_static("fcp.test.batch-adaptive-http:utility:1.0.0");
    let capability_signing_key = Ed25519SigningKey::generate();
    let capability_public_key = capability_public_key_hex(&capability_signing_key);
    let host = HttpHostProcess::spawn_with_env(
        vec![test_connector_config(
            &connector_id,
            "Batch Adaptive Echo",
            &["test", "batch"],
        )],
        &[(
            "FCP_HOST_CAPABILITY_PUBLIC_KEY",
            capability_public_key.as_str(),
        )],
    )
    .await?;
    let url = |path: &str| format!("{}{path}", host.base_url);

    let (mut long_request, _) = build_invoke_request(connector_id.clone(), &capability_signing_key);
    long_request.input = json!({ "message": "long" });
    let (mut short_a_request, _) =
        build_invoke_request(connector_id.clone(), &capability_signing_key);
    short_a_request.input = json!({ "message": "short-a" });
    let (mut short_b_request, _) =
        build_invoke_request(connector_id.clone(), &capability_signing_key);
    short_b_request.input = json!({ "message": "short-b" });
    let (mut short_c_request, _) =
        build_invoke_request(connector_id.clone(), &capability_signing_key);
    short_c_request.input = json!({ "message": "short-c" });

    let response: BatchInvokeResponse = http_post_json(
        host.client.clone(),
        url("/rpc/batch"),
        json!({
            "operations": [
                scheduled_batch_operation_json("long", long_request, 1_000),
                scheduled_batch_operation_json("short-a", short_a_request, 1),
                scheduled_batch_operation_json("short-b", short_b_request, 1),
                scheduled_batch_operation_json("short-c", short_c_request, 1),
            ],
            "options": {
                "max_parallelism": 1,
                "stop_on_first_error": false,
                "timeout_ms": 30_000,
                "scheduler": {
                    "mode": "adaptive",
                    "max_consecutive_per_fairness_key": 8,
                },
            }
        }),
    )
    .await?;

    assert_eq!(response.status, BatchStatus::Success);
    assert_eq!(response.completed, 4);
    assert_eq!(response.failed, 0);
    assert_eq!(response.skipped, 0);

    let report = response
        .schedule_report
        .expect("adaptive batch response should include schedule report");
    assert!(!report.fallback);
    assert_eq!(report.total_operations, 4);
    assert_eq!(
        report.original_tiers,
        vec![vec![
            "long".to_string(),
            "short-a".to_string(),
            "short-b".to_string(),
            "short-c".to_string(),
        ]]
    );
    assert_eq!(
        report.scheduled_tiers,
        vec![vec![
            "short-a".to_string(),
            "short-b".to_string(),
            "short-c".to_string(),
            "long".to_string(),
        ]]
    );
    let summary = report
        .queueing_summary
        .expect("adaptive schedule report should include queueing summary");
    assert_eq!(summary.sample_count, 4);
    assert!(summary.p99_wait_improvement_ms >= 999);
    assert!(summary.p999_wait_improvement_ms >= 999);
    assert_eq!(summary.max_wait_increase_ms, 3);
    assert_eq!(summary.promoted_operations, 3);
    assert_eq!(summary.delayed_operations, 1);
    assert_eq!(report.decisions.len(), 4);

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_batch_route_skips_dependents_after_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_id = ConnectorId::from_static("fcp.test.batch-failure:utility:1.0.0");
    let capability_signing_key = Ed25519SigningKey::generate();
    let capability_public_key = capability_public_key_hex(&capability_signing_key);
    let host = HttpHostProcess::spawn_with_env(
        vec![test_connector_config(
            &connector_id,
            "Batch Failure Echo",
            &["test", "batch"],
        )],
        &[(
            "FCP_HOST_CAPABILITY_PUBLIC_KEY",
            capability_public_key.as_str(),
        )],
    )
    .await?;
    let url = |path: &str| format!("{}{path}", host.base_url);

    let unknown_connector_id = ConnectorId::from_static("fcp.test.missing:utility:1.0.0");
    let (mut failing_request, _) =
        build_invoke_request(unknown_connector_id, &capability_signing_key);
    failing_request.input = json!({ "message": "missing" });
    let (mut dependent_request, _) =
        build_invoke_request(connector_id.clone(), &capability_signing_key);
    dependent_request.input = json!({ "message": "dependent" });
    let (mut independent_request, _) =
        build_invoke_request(connector_id.clone(), &capability_signing_key);
    independent_request.input = json!({ "message": "independent" });

    let response: BatchInvokeResponse = http_post_json(
        host.client.clone(),
        url("/rpc/batch"),
        json!({
            "operations": [
                batch_operation_json("op1", failing_request, &[]),
                batch_operation_json("op2", dependent_request, &["op1"]),
                batch_operation_json("op3", independent_request, &[]),
            ],
            "options": {
                "max_parallelism": 3,
                "stop_on_first_error": false,
                "timeout_ms": 30_000,
            }
        }),
    )
    .await?;

    assert_eq!(response.status, BatchStatus::PartialSuccess);
    assert_eq!(response.completed, 1);
    assert_eq!(response.failed, 1);
    assert_eq!(response.skipped, 1);
    assert_eq!(response.results.len(), 3);
    assert_eq!(response.results[0].status, OperationResultStatus::Error);
    assert_eq!(response.results[1].status, OperationResultStatus::Skipped);
    assert_eq!(response.results[2].status, OperationResultStatus::Success);
    assert_eq!(
        response.results[0]
            .error
            .as_ref()
            .map(|error| error.code.as_str()),
        Some("PREFLIGHT_DENIED")
    );
    assert_eq!(
        response.results[1]
            .error
            .as_ref()
            .map(|error| error.code.as_str()),
        Some("DEP_FAILED")
    );
    assert_eq!(
        response.results[2]
            .output
            .as_ref()
            .and_then(|output| output.get("result"))
            .and_then(|result| result.get("echo"))
            .and_then(|echo| echo.get("message"))
            .and_then(Value::as_str),
        Some("independent")
    );

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_batch_route_stop_on_first_error_short_circuits_same_tier()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_id = ConnectorId::from_static("fcp.test.batch-stop-first:utility:1.0.0");
    let capability_signing_key = Ed25519SigningKey::generate();
    let capability_public_key = capability_public_key_hex(&capability_signing_key);
    let host = HttpHostProcess::spawn_with_env(
        vec![test_connector_config(
            &connector_id,
            "Batch Stop First Echo",
            &["test", "batch"],
        )],
        &[(
            "FCP_HOST_CAPABILITY_PUBLIC_KEY",
            capability_public_key.as_str(),
        )],
    )
    .await?;
    let url = |path: &str| format!("{}{path}", host.base_url);

    let unknown_connector_id = ConnectorId::from_static("fcp.test.missing:utility:1.0.0");
    let (mut failing_request, _) =
        build_invoke_request(unknown_connector_id, &capability_signing_key);
    failing_request.input = json!({ "message": "missing" });
    let (mut second_request, _) =
        build_invoke_request(connector_id.clone(), &capability_signing_key);
    second_request.input = json!({ "message": "second" });
    let (mut third_request, _) =
        build_invoke_request(connector_id.clone(), &capability_signing_key);
    third_request.input = json!({ "message": "third" });

    // All three operations are independent (one tier); max_parallelism = 1
    // splits the tier into three sequential chunks. With stop_on_first_error
    // the failure in the first chunk must short-circuit the REMAINING CHUNKS
    // OF THE SAME TIER, not just subsequent tiers.
    let response: BatchInvokeResponse = http_post_json(
        host.client.clone(),
        url("/rpc/batch"),
        json!({
            "operations": [
                batch_operation_json("op1", failing_request, &[]),
                batch_operation_json("op2", second_request, &[]),
                batch_operation_json("op3", third_request, &[]),
            ],
            "options": {
                "max_parallelism": 1,
                "stop_on_first_error": true,
                "timeout_ms": 30_000,
            }
        }),
    )
    .await?;

    assert_eq!(response.status, BatchStatus::Aborted);
    assert_eq!(response.completed, 0);
    assert_eq!(response.failed, 1);
    assert_eq!(response.skipped, 2);
    assert_eq!(response.results.len(), 3);
    assert_eq!(response.results[0].id, "op1");
    assert_eq!(response.results[0].status, OperationResultStatus::Error);
    assert_eq!(response.results[1].id, "op2");
    assert_eq!(response.results[1].status, OperationResultStatus::Skipped);
    assert_eq!(response.results[2].id, "op3");
    assert_eq!(response.results[2].status, OperationResultStatus::Skipped);

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_cancel_route_cancels_in_flight_invoke()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_id = ConnectorId::from_static("fcp.test.cancel-http:utility:1.0.0");
    let capability_signing_key = Ed25519SigningKey::generate();
    let capability_public_key = capability_public_key_hex(&capability_signing_key);
    let host = HttpHostProcess::spawn_with_env(
        vec![test_connector_config(
            &connector_id,
            "Cancel Echo",
            &["test", "cancel"],
        )],
        &[(
            "FCP_HOST_CAPABILITY_PUBLIC_KEY",
            capability_public_key.as_str(),
        )],
    )
    .await?;
    let url = |path: &str| format!("{}{path}", host.base_url);

    let (mut invoke_request, _) =
        build_invoke_request(connector_id.clone(), &capability_signing_key);
    invoke_request.input = json!({
        "message": "slow",
        "delay_ms": 300_u64,
    });
    let operation_id = invoke_request.id.to_string();

    let invoke_task = fcp_async_core::task::spawn({
        let client = host.client.clone();
        let invoke_url = url("/rpc/invoke");
        async move {
            http_post_json::<_, InvokeResponse>(client, invoke_url, invoke_request)
                .await
                .map_err(|err| err.to_string())
        }
    });

    let logs = wait_for_log_events(&host.stderr_logs, &["invoke_request"]).await?;
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("invoke_request")
            && entry.get("connector_id").and_then(Value::as_str) == Some(connector_id.as_str())
            && entry.get("operation_id").and_then(Value::as_str) == Some(operation_id.as_str())
    }));

    fcp_async_core::time::sleep(Duration::from_millis(50)).await;

    let cancel_response: CancellationResponse = http_post_json_response(
        host.client.clone(),
        url("/rpc/operations/cancel"),
        CancellationRequest {
            operation_id: operation_id.clone(),
            reason: CancelReason::UserRequested,
            cleanup: CleanupBehavior::BestEffort,
            return_partial: true,
            capability_token: None,
        },
        Some(cancel_admin_headers(TEST_PRINCIPAL)),
    )
    .await?
    .body;

    assert_eq!(cancel_response.operation_id, operation_id);
    assert_eq!(cancel_response.outcome, CancellationOutcome::Cancelled);
    assert!(cancel_response.partial_result.is_none());
    assert!(cancel_response.checkpoint.is_none());
    assert!(cancel_response.cleanup_result.is_some());

    let invoke_response = invoke_task
        .await
        .map_err(std::io::Error::other)?
        .map_err(std::io::Error::other)?;
    assert_eq!(invoke_response.status, InvokeStatus::Ok);

    let logs = wait_for_log_events(
        &host.stderr_logs,
        &[
            "invoke_request",
            "cancel_request",
            "cancel_response",
            "invoke_response",
        ],
    )
    .await?;
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("cancel_request")
            && entry.get("operation_id").and_then(Value::as_str) == Some(operation_id.as_str())
    }));
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("cancel_response")
            && entry.get("operation_id").and_then(Value::as_str) == Some(operation_id.as_str())
            && entry.get("outcome").and_then(Value::as_str) == Some("Cancelled")
    }));
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("invoke_response")
            && entry.get("operation_id").and_then(Value::as_str) == Some(operation_id.as_str())
            && entry.get("status").and_then(Value::as_str) == Some("Ok")
    }));

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_cancel_route_allows_follow_up_invoke_after_cleanup()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_id = ConnectorId::from_static("fcp.test.cancel-follow-up:utility:1.0.0");
    let capability_signing_key = Ed25519SigningKey::generate();
    let capability_public_key = capability_public_key_hex(&capability_signing_key);
    let host = HttpHostProcess::spawn_with_env(
        vec![test_connector_config(
            &connector_id,
            "Cancel Follow Up Echo",
            &["test", "cancel"],
        )],
        &[(
            "FCP_HOST_CAPABILITY_PUBLIC_KEY",
            capability_public_key.as_str(),
        )],
    )
    .await?;
    let url = |path: &str| format!("{}{path}", host.base_url);

    let (mut slow_request, _) = build_invoke_request(connector_id.clone(), &capability_signing_key);
    slow_request.input = json!({
        "message": "slow",
        "delay_ms": 300_u64,
    });
    let cancelled_operation_id = slow_request.id.to_string();

    let invoke_task = fcp_async_core::task::spawn({
        let client = host.client.clone();
        let invoke_url = url("/rpc/invoke");
        async move {
            http_post_json::<_, InvokeResponse>(client, invoke_url, slow_request)
                .await
                .map_err(|err| err.to_string())
        }
    });

    let logs = wait_for_log_events(&host.stderr_logs, &["invoke_request"]).await?;
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("invoke_request")
            && entry.get("operation_id").and_then(Value::as_str)
                == Some(cancelled_operation_id.as_str())
    }));

    fcp_async_core::time::sleep(Duration::from_millis(50)).await;

    let cancel_response: CancellationResponse = http_post_json_response(
        host.client.clone(),
        url("/rpc/operations/cancel"),
        CancellationRequest {
            operation_id: cancelled_operation_id.clone(),
            reason: CancelReason::UserRequested,
            cleanup: CleanupBehavior::BestEffort,
            return_partial: true,
            capability_token: None,
        },
        Some(cancel_admin_headers(TEST_PRINCIPAL)),
    )
    .await?
    .body;

    assert_eq!(cancel_response.operation_id, cancelled_operation_id);
    assert_eq!(cancel_response.outcome, CancellationOutcome::Cancelled);
    assert!(cancel_response.cleanup_result.is_some());

    let cancelled_response = invoke_task
        .await
        .map_err(std::io::Error::other)?
        .map_err(std::io::Error::other)?;
    assert_eq!(cancelled_response.status, InvokeStatus::Ok);

    let (mut follow_up_request, _) =
        build_invoke_request(connector_id.clone(), &capability_signing_key);
    follow_up_request.input = json!({ "message": "after-cancel" });
    let follow_up_operation_id = follow_up_request.id.to_string();

    let follow_up_response: InvokeResponse =
        http_post_json(host.client.clone(), url("/rpc/invoke"), follow_up_request).await?;
    assert_eq!(follow_up_response.status, InvokeStatus::Ok);
    assert_eq!(
        follow_up_response
            .result
            .as_ref()
            .and_then(|result| result.get("echo"))
            .and_then(|echo| echo.get("message"))
            .and_then(Value::as_str),
        Some("after-cancel")
    );

    let logs = wait_for_log_entry(&host.stderr_logs, "follow-up invoke_response", |entry| {
        entry.get("event").and_then(Value::as_str) == Some("invoke_response")
            && entry.get("operation_id").and_then(Value::as_str)
                == Some(follow_up_operation_id.as_str())
            && entry.get("status").and_then(Value::as_str) == Some("Ok")
    })
    .await?;
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("cancel_response")
            && entry.get("operation_id").and_then(Value::as_str)
                == Some(cancelled_operation_id.as_str())
            && entry.get("outcome").and_then(Value::as_str) == Some("Cancelled")
    }));
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("invoke_request")
            && entry.get("operation_id").and_then(Value::as_str)
                == Some(follow_up_operation_id.as_str())
    }));
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("invoke_response")
            && entry.get("operation_id").and_then(Value::as_str)
                == Some(follow_up_operation_id.as_str())
            && entry.get("status").and_then(Value::as_str) == Some("Ok")
    }));

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_cancel_route_returns_too_late_for_completed_invoke()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_id = ConnectorId::from_static("fcp.test.cancel-too-late:utility:1.0.0");
    let capability_signing_key = Ed25519SigningKey::generate();
    let capability_public_key = capability_public_key_hex(&capability_signing_key);
    let host = HttpHostProcess::spawn_with_env(
        vec![test_connector_config(
            &connector_id,
            "Cancel Too Late Echo",
            &["test", "cancel"],
        )],
        &[(
            "FCP_HOST_CAPABILITY_PUBLIC_KEY",
            capability_public_key.as_str(),
        )],
    )
    .await?;
    let url = |path: &str| format!("{}{path}", host.base_url);

    let (invoke_request, _) = build_invoke_request(connector_id.clone(), &capability_signing_key);
    let operation_id = invoke_request.id.to_string();

    let invoke_response: InvokeResponse =
        http_post_json(host.client.clone(), url("/rpc/invoke"), invoke_request).await?;
    assert_eq!(invoke_response.status, InvokeStatus::Ok);

    let cancel_response: CancellationResponse = http_post_json_response(
        host.client.clone(),
        url("/rpc/cancel"),
        CancellationRequest {
            operation_id: operation_id.clone(),
            reason: CancelReason::UserRequested,
            cleanup: CleanupBehavior::BestEffort,
            return_partial: false,
            capability_token: None,
        },
        Some(cancel_admin_headers(TEST_PRINCIPAL)),
    )
    .await?
    .body;

    assert_eq!(cancel_response.operation_id, operation_id);
    assert_eq!(cancel_response.outcome, CancellationOutcome::TooLate);
    assert!(cancel_response.partial_result.is_none());
    assert!(cancel_response.checkpoint.is_none());
    assert!(cancel_response.cleanup_result.is_none());

    let logs = wait_for_log_events(
        &host.stderr_logs,
        &[
            "invoke_request",
            "invoke_response",
            "cancel_request",
            "cancel_response",
        ],
    )
    .await?;
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("cancel_response")
            && entry.get("operation_id").and_then(Value::as_str) == Some(operation_id.as_str())
            && entry.get("outcome").and_then(Value::as_str) == Some("TooLate")
    }));

    Ok(())
}

#[cfg(unix)]
#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_sigterm_shutdown_exits_cleanly_and_stops_serving_http()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_id = ConnectorId::from_static("fcp.test.shutdown-http:utility:1.0.0");
    let mut host = HttpHostProcess::spawn(vec![test_connector_config(
        &connector_id,
        "Shutdown Echo",
        &["test", "shutdown"],
    )])
    .await?;
    let url = |path: &str| format!("{}{path}", host.base_url);

    send_sigterm(&host.child)?;

    let status =
        wait_for_host_exit(&mut host.child, Duration::from_secs(2), &host.stderr_logs).await?;
    assert!(
        status.success(),
        "expected graceful shutdown exit, got {status}"
    );

    let logs = wait_for_log_events(
        &host.stderr_logs,
        &[
            "sigterm_received",
            "shutdown_signal",
            "host_shutdown_complete",
        ],
    )
    .await?;
    let sigterm_index = logs
        .iter()
        .position(|entry| entry.get("event").and_then(Value::as_str) == Some("sigterm_received"))
        .expect("sigterm_received log should be present");
    let shutdown_index = logs
        .iter()
        .position(|entry| entry.get("event").and_then(Value::as_str) == Some("shutdown_signal"))
        .expect("shutdown_signal log should be present");
    let complete_index = logs
        .iter()
        .position(|entry| {
            entry.get("event").and_then(Value::as_str) == Some("host_shutdown_complete")
        })
        .expect("host_shutdown_complete log should be present");
    assert!(sigterm_index < shutdown_index);
    assert!(shutdown_index < complete_index);

    let shutdown_probe = fcp_async_core::time::timeout(
        Duration::from_millis(500),
        http_get_status(host.client.clone(), url("/rpc/health")),
    )
    .await
    .expect("post-shutdown health probe should not hang");
    let shutdown_err = shutdown_probe.expect_err("health request should fail after SIGTERM");
    let shutdown_err = shutdown_err.to_string();
    assert!(
        shutdown_err.contains("connection")
            || shutdown_err.contains("refused")
            || shutdown_err.contains("closed")
            || shutdown_err.contains("error sending request"),
        "unexpected post-shutdown reqwest error: {shutdown_err}"
    );

    Ok(())
}

#[cfg(unix)]
#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_sigterm_shutdown_aborts_in_flight_http_invoke_without_hanging()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_id = ConnectorId::from_static("fcp.test.shutdown-in-flight-http:utility:1.0.0");
    let capability_signing_key = Ed25519SigningKey::generate();
    let capability_public_key = capability_public_key_hex(&capability_signing_key);
    let mut host = HttpHostProcess::spawn_with_env(
        vec![test_connector_config(
            &connector_id,
            "Shutdown In Flight Echo",
            &["test", "shutdown"],
        )],
        &[(
            "FCP_HOST_CAPABILITY_PUBLIC_KEY",
            capability_public_key.as_str(),
        )],
    )
    .await?;
    let url = |path: &str| format!("{}{path}", host.base_url);

    let (mut invoke_request, _) =
        build_invoke_request(connector_id.clone(), &capability_signing_key);
    invoke_request.input = json!({
        "message": "shutdown-mid-flight",
        "delay_ms": 1_000_u64,
    });
    let operation_id = invoke_request.id.to_string();

    let invoke_task = fcp_async_core::task::spawn({
        let client = host.client.clone();
        let invoke_url = url("/rpc/invoke");
        async move {
            http_post_json::<_, InvokeResponse>(client, invoke_url, invoke_request)
                .await
                .map_err(|err| err.to_string())
        }
    });

    let logs = wait_for_log_events(&host.stderr_logs, &["invoke_request"]).await?;
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("invoke_request")
            && entry.get("connector_id").and_then(Value::as_str) == Some(connector_id.as_str())
            && entry.get("operation_id").and_then(Value::as_str) == Some(operation_id.as_str())
    }));

    fcp_async_core::time::sleep(Duration::from_millis(50)).await;
    send_sigterm(&host.child)?;

    let status =
        wait_for_host_exit(&mut host.child, Duration::from_secs(2), &host.stderr_logs).await?;
    assert!(
        status.success(),
        "expected graceful shutdown exit, got {status}"
    );

    let invoke_result = fcp_async_core::time::timeout(Duration::from_secs(1), async {
        invoke_task
            .await
            .map_err(std::io::Error::other)?
            .map_err(std::io::Error::other)
    })
    .await
    .expect("in-flight invoke should not hang after shutdown");
    let invoke_err = invoke_result.expect_err("in-flight invoke should fail after SIGTERM");
    let invoke_err = invoke_err.to_string();
    assert!(
        invoke_err.contains("connection")
            || invoke_err.contains("refused")
            || invoke_err.contains("closed")
            || invoke_err.contains("error sending request"),
        "unexpected in-flight reqwest error after SIGTERM: {invoke_err}"
    );

    let logs = wait_for_log_events(
        &host.stderr_logs,
        &[
            "invoke_request",
            "sigterm_received",
            "shutdown_signal",
            "host_shutdown_complete",
        ],
    )
    .await?;
    assert!(!logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("invoke_response")
            && entry.get("operation_id").and_then(Value::as_str) == Some(operation_id.as_str())
    }));

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_rollout_routes_schedule_and_promote_canary()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_id = ConnectorId::from_static("fcp.test.rollout-http:utility:1.0.0");
    let host = HttpHostProcess::spawn(vec![test_connector_config(
        &connector_id,
        "Rollout Echo",
        &["test", "rollout"],
    )])
    .await?;
    let url = |path: &str| format!("{}{path}", host.base_url);

    let policy = test_rollout_policy();
    let previous_version = semver::Version::new(1, 0, 0);
    let canary_version = semver::Version::new(1, 0, 1);
    let schedule_observed_at = chrono::Utc::now() - chrono::Duration::seconds(5);

    let scheduled: RolloutOutcome = http_post_json(
        host.client.clone(),
        url("/rpc/rollout/schedule"),
        json!({
            "connector_id": connector_id.as_str(),
            "version": canary_version.clone(),
            "previous_version": previous_version.clone(),
            "policy": policy.clone(),
            "observed_at": schedule_observed_at,
        }),
    )
    .await?;
    assert_eq!(scheduled.decision, RolloutDecision::Scheduled);
    assert_eq!(scheduled.record.state, LifecycleState::Canary);
    assert_eq!(scheduled.record.version, canary_version);
    assert_eq!(
        scheduled.record.previous_version,
        Some(previous_version.clone())
    );
    assert_eq!(scheduled.audit_event.reason_code, "canary_scheduled");

    let status: LifecycleStatus = http_get_json(
        host.client.clone(),
        url(&format!("/rpc/rollout/{}", connector_id.as_str())),
    )
    .await?;
    assert_eq!(status.state, LifecycleState::Canary);
    assert_eq!(status.version, canary_version);
    assert_eq!(
        status.rollback_target_version,
        Some(previous_version.clone())
    );

    let first: RolloutOutcome = http_post_json(
        host.client.clone(),
        url("/rpc/rollout/evaluate"),
        json!({
            "connector_id": connector_id.as_str(),
            "invocation_succeeded": true,
            "latency_ms": 20,
            "uptime_secs": 120,
            "pinned": false,
            "crashed": false,
            "policy": policy.clone(),
            "observed_at": chrono::Utc::now(),
        }),
    )
    .await?;
    assert_eq!(first.decision, RolloutDecision::Hold);
    assert_eq!(first.record.state, LifecycleState::Canary);
    assert_eq!(first.audit_event.reason_code, "insufficient_samples");

    let second: RolloutOutcome = http_post_json(
        host.client.clone(),
        url("/rpc/rollout/evaluate"),
        json!({
            "connector_id": connector_id.as_str(),
            "invocation_succeeded": true,
            "latency_ms": 25,
            "uptime_secs": 120,
            "pinned": false,
            "crashed": false,
            "policy": policy.clone(),
            "observed_at": chrono::Utc::now(),
        }),
    )
    .await?;
    assert_eq!(second.decision, RolloutDecision::Hold);
    assert_eq!(second.record.state, LifecycleState::Canary);
    assert_eq!(second.audit_event.reason_code, "insufficient_samples");

    let promoted: RolloutOutcome = http_post_json(
        host.client.clone(),
        url("/rpc/rollout/evaluate"),
        json!({
            "connector_id": connector_id.as_str(),
            "invocation_succeeded": true,
            "latency_ms": 30,
            "uptime_secs": 120,
            "pinned": false,
            "crashed": false,
            "policy": policy,
            "observed_at": chrono::Utc::now(),
        }),
    )
    .await?;
    assert_eq!(promoted.decision, RolloutDecision::Promote);
    assert_eq!(promoted.record.state, LifecycleState::Production);
    assert_eq!(promoted.audit_event.reason_code, "promotion_thresholds_met");

    let final_status: LifecycleStatus = http_get_json(
        host.client.clone(),
        url(&format!("/rpc/rollout/{}", connector_id.as_str())),
    )
    .await?;
    assert_eq!(final_status.state, LifecycleState::Production);
    assert_eq!(final_status.version, canary_version);
    assert!(!final_status.auto_promote_pending);
    assert_eq!(final_status.rollback_target_version, Some(previous_version));

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_connector_status_route_reports_live_connector_state()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_id = ConnectorId::from_static("fcp.test.status-live:utility:1.0.0");
    let host = HttpHostProcess::spawn(vec![test_connector_config(
        &connector_id,
        "Status Live Connector",
        &["test", "status"],
    )])
    .await?;
    let url = |path: &str| format!("{}{}", host.base_url, path);

    let status: ConnectorAdminStatus = http_get_json(
        host.client.clone(),
        url(&format!("/rpc/connectors/{}/status", connector_id.as_str())),
    )
    .await?;

    assert_eq!(status.connector_id, connector_id);
    assert_eq!(status.desired_state, DesiredRuntimeState::Enabled);
    assert_eq!(status.observed_state, ObservedRuntimeState::Running);
    assert!(status.lifecycle.is_none());
    assert!(status.drift.is_none());
    assert!(status.last_journal_sequence >= 2);

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_connector_status_route_reports_missing_persisted_connector_state()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_id = ConnectorId::from_static("fcp.test.status-missing:utility:1.0.0");
    let state_dir = tempfile::tempdir()?;
    let state_path = state_dir.path().join("lifecycle-state.json");
    let store = HostAdminStateStore::with_state_path(state_path.clone())?;
    let mut record = LifecycleRecord::new(connector_id.clone(), semver::Version::new(1, 0, 0));
    record
        .transition(
            LifecycleState::Installing,
            TransitionReason::InstallComplete,
        )
        .expect("pending -> installing");
    record
        .transition(
            LifecycleState::Canary,
            TransitionReason::NewVersion {
                from_version: "0.9.0".to_string(),
                to_version: "1.0.0".to_string(),
            },
        )
        .expect("installing -> canary");
    store.save(&record).await?;
    drop(store);

    let state_path_string = state_path.to_string_lossy().into_owned();
    let host = HttpHostProcess::spawn_with_env(
        Vec::new(),
        &[("FCP_HOST_LIFECYCLE_STATE_FILE", state_path_string.as_str())],
    )
    .await?;
    let url = |path: &str| format!("{}{}", host.base_url, path);

    let status: ConnectorAdminStatus = http_get_json(
        host.client.clone(),
        url(&format!("/rpc/connectors/{}/status", connector_id.as_str())),
    )
    .await?;

    assert_eq!(status.connector_id, connector_id);
    assert_eq!(status.desired_state, DesiredRuntimeState::Enabled);
    assert_eq!(status.observed_state, ObservedRuntimeState::Missing);
    assert_eq!(
        status
            .drift
            .as_ref()
            .expect("missing persisted connector should report drift")
            .recovery_action,
        RecoveryAction::ReinstallConnector
    );
    assert_eq!(
        status
            .drift
            .as_ref()
            .expect("missing persisted connector should report drift")
            .kind,
        ConnectorDriftKind::EnabledButMissing
    );
    assert_eq!(
        status.lifecycle.as_ref().map(|lifecycle| lifecycle.state),
        Some(LifecycleState::Canary)
    );

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_rollout_pin_route_pins_baseline_version()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_id = ConnectorId::from_static("fcp.test.rollout-pin-baseline:utility:1.0.0");
    let host = HttpHostProcess::spawn(vec![test_connector_config(
        &connector_id,
        "Rollout Pin Baseline",
        &["test", "rollout"],
    )])
    .await?;
    let url = |path: &str| format!("{}{path}", host.base_url);

    let baseline_version = semver::Version::new(1, 0, 0);

    let pinned: PinStateResponse = http_put_json(
        host.client.clone(),
        url(&format!("/rpc/rollout/pin/{}", connector_id.as_str())),
        json!({ "version": baseline_version.clone() }),
    )
    .await?;
    assert_eq!(pinned.connector_id, connector_id.as_str());
    assert!(pinned.pinned);
    assert_eq!(pinned.version, Some(baseline_version.clone()));

    let pin_status: PinStateResponse = http_get_json(
        host.client.clone(),
        url(&format!("/rpc/rollout/pin/{}", connector_id.as_str())),
    )
    .await?;
    assert!(pin_status.pinned);
    assert_eq!(pin_status.version, Some(baseline_version));

    let logs = wait_for_log_events(
        &host.stderr_logs,
        &[
            "rollout_pin_request",
            "rollout_pin_response",
            "rollout_pin_status_request",
            "rollout_pin_status_response",
        ],
    )
    .await?;

    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("rollout_pin_response")
            && entry.get("connector_id").and_then(Value::as_str) == Some(connector_id.as_str())
            && entry.get("pinned").and_then(Value::as_bool) == Some(true)
    }));
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("rollout_pin_status_response")
            && entry.get("connector_id").and_then(Value::as_str) == Some(connector_id.as_str())
            && entry.get("pinned").and_then(Value::as_bool) == Some(true)
    }));

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_rollout_routes_rollback_and_emit_transition_logs()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_id = ConnectorId::from_static("fcp.test.rollout-rollback:utility:1.0.0");
    let host = HttpHostProcess::spawn(vec![test_connector_config(
        &connector_id,
        "Rollout Rollback",
        &["test", "rollout"],
    )])
    .await?;
    let url = |path: &str| format!("{}{path}", host.base_url);

    let policy = test_rollout_rollback_policy();
    let previous_version = semver::Version::new(1, 0, 0);
    let canary_version = semver::Version::new(1, 0, 1);

    let pinned_baseline: PinStateResponse = http_put_json(
        host.client.clone(),
        url(&format!("/rpc/rollout/pin/{}", connector_id.as_str())),
        json!({ "version": previous_version.clone() }),
    )
    .await?;
    assert_eq!(pinned_baseline.connector_id, connector_id.as_str());
    assert!(pinned_baseline.pinned);
    assert_eq!(pinned_baseline.version, Some(previous_version.clone()));

    let pin_status_before_rollout: PinStateResponse = http_get_json(
        host.client.clone(),
        url(&format!("/rpc/rollout/pin/{}", connector_id.as_str())),
    )
    .await?;
    assert!(pin_status_before_rollout.pinned);
    assert_eq!(
        pin_status_before_rollout.version,
        Some(previous_version.clone())
    );

    let scheduled: RolloutOutcome = http_post_json(
        host.client.clone(),
        url("/rpc/rollout/schedule"),
        json!({
            "connector_id": connector_id.as_str(),
            "version": canary_version.clone(),
            "previous_version": previous_version.clone(),
            "policy": policy.clone(),
            "observed_at": chrono::Utc::now() - chrono::Duration::seconds(5),
        }),
    )
    .await?;
    assert_eq!(scheduled.decision, RolloutDecision::Scheduled);
    assert_eq!(scheduled.record.state, LifecycleState::Canary);
    assert_eq!(scheduled.audit_event.reason_code, "canary_scheduled");

    let rolled_back: RolloutOutcome = http_post_json(
        host.client.clone(),
        url("/rpc/rollout/evaluate"),
        json!({
            "connector_id": connector_id.as_str(),
            "invocation_succeeded": false,
            "latency_ms": 15,
            "uptime_secs": 120,
            "pinned": false,
            "crashed": false,
            "policy": policy,
            "observed_at": chrono::Utc::now(),
        }),
    )
    .await?;
    assert_eq!(rolled_back.decision, RolloutDecision::Rollback);
    assert_eq!(rolled_back.record.state, LifecycleState::RolledBack);
    assert_eq!(
        rolled_back.audit_event.reason_code,
        "consecutive_failures_exceeded"
    );
    assert!(
        rolled_back
            .audit_event
            .evidence_digest
            .starts_with("blake3-256:")
    );

    let final_status: LifecycleStatus = http_get_json(
        host.client.clone(),
        url(&format!("/rpc/rollout/{}", connector_id.as_str())),
    )
    .await?;
    assert_eq!(final_status.state, LifecycleState::RolledBack);
    assert_eq!(final_status.version, canary_version);
    assert_eq!(
        final_status.rollback_target_version,
        Some(previous_version.clone())
    );
    assert!(!final_status.auto_rollback_pending);

    let restored_pin_status: PinStateResponse = http_get_json(
        host.client.clone(),
        url(&format!("/rpc/rollout/pin/{}", connector_id.as_str())),
    )
    .await?;
    assert!(restored_pin_status.pinned);
    assert_eq!(restored_pin_status.version, Some(previous_version));

    let logs = wait_for_log_events(
        &host.stderr_logs,
        &[
            "rollout_pin_request",
            "rollout_pin_response",
            "rollout_pin_status_request",
            "rollout_pin_status_response",
            "rollout_schedule_request",
            "rollout_schedule_response",
            "rollout_evaluate_request",
            "rollout_evaluate_response",
            "rollout_status_request",
            "rollout_status_response",
        ],
    )
    .await?;

    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("rollout_pin_response")
            && entry.get("connector_id").and_then(Value::as_str) == Some(connector_id.as_str())
            && entry.get("pinned").and_then(Value::as_bool) == Some(true)
    }));
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("rollout_pin_status_response")
            && entry.get("connector_id").and_then(Value::as_str) == Some(connector_id.as_str())
            && entry.get("pinned").and_then(Value::as_bool) == Some(true)
    }));
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("rollout_schedule_response")
            && entry.get("connector_id").and_then(Value::as_str) == Some(connector_id.as_str())
            && entry.get("reason_code").and_then(Value::as_str) == Some("canary_scheduled")
            && entry.get("duration_ms").and_then(Value::as_u64).is_some()
    }));
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("rollout_evaluate_response")
            && entry.get("connector_id").and_then(Value::as_str) == Some(connector_id.as_str())
            && entry.get("reason_code").and_then(Value::as_str)
                == Some("consecutive_failures_exceeded")
            && entry.get("duration_ms").and_then(Value::as_u64).is_some()
    }));
    assert!(logs.iter().any(|entry| {
        entry.get("message").and_then(Value::as_str) == Some("rollout decision")
            && entry.get("connector_id").and_then(Value::as_str) == Some(connector_id.as_str())
            && entry.get("decision").and_then(Value::as_str) == Some("scheduled")
            && entry.get("state_before").and_then(Value::as_str) == Some("pending")
            && entry.get("state_after").and_then(Value::as_str) == Some("canary")
    }));
    assert!(logs.iter().any(|entry| {
        entry.get("message").and_then(Value::as_str) == Some("rollout decision")
            && entry.get("connector_id").and_then(Value::as_str) == Some(connector_id.as_str())
            && entry.get("decision").and_then(Value::as_str) == Some("rollback")
            && entry.get("state_before").and_then(Value::as_str) == Some("canary")
            && entry.get("state_after").and_then(Value::as_str) == Some("rolled_back")
            && entry
                .get("evidence_digest")
                .and_then(Value::as_str)
                .is_some_and(|digest| digest.starts_with("blake3-256:"))
    }));

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_pin_status_and_manual_rollback_routes_emit_logs()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_id = ConnectorId::from_static("fcp.test.rollout-pin:utility:1.0.0");
    let host = HttpHostProcess::spawn(vec![test_connector_config(
        &connector_id,
        "Rollout Pin",
        &["test", "rollout"],
    )])
    .await?;
    let url = |path: &str| format!("{}{path}", host.base_url);

    let previous_version = semver::Version::new(1, 0, 0);
    let canary_version = semver::Version::new(1, 0, 1);
    let policy = test_rollout_policy();

    let pinned: PinStateResponse = http_put_json(
        host.client.clone(),
        url(&format!("/rpc/rollout/pin/{}", connector_id.as_str())),
        json!({ "version": canary_version.clone() }),
    )
    .await?;
    assert_eq!(pinned.connector_id, connector_id.as_str());
    assert!(pinned.pinned);
    assert_eq!(pinned.version, Some(canary_version.clone()));

    let pin_status: PinStateResponse = http_get_json(
        host.client.clone(),
        url(&format!("/rpc/rollout/pin/{}", connector_id.as_str())),
    )
    .await?;
    assert!(pin_status.pinned);
    assert_eq!(pin_status.version, Some(canary_version.clone()));

    let _scheduled: RolloutOutcome = http_post_json(
        host.client.clone(),
        url("/rpc/rollout/schedule"),
        json!({
            "connector_id": connector_id.as_str(),
            "version": canary_version.clone(),
            "previous_version": previous_version.clone(),
            "policy": policy.clone(),
            "observed_at": chrono::Utc::now() - chrono::Duration::seconds(5),
        }),
    )
    .await?;

    let status: RolloutStatusResponse = http_get_json(
        host.client.clone(),
        url(&format!("/rpc/rollout/{}", connector_id.as_str())),
    )
    .await?;
    assert_eq!(status.status.state, LifecycleState::Canary);
    assert!(status.pinned);
    assert_eq!(status.pinned_version, Some(canary_version.clone()));
    assert_eq!(status.canary_percent, policy.canary_percent);

    let rollback: ManualRollbackResponse = http_post_json(
        host.client.clone(),
        url("/rpc/rollout/rollback"),
        json!({
            "connector_id": connector_id.as_str(),
            "to_version": previous_version.clone(),
        }),
    )
    .await?;
    assert_eq!(rollback.connector_id, connector_id.as_str());
    assert_eq!(rollback.state, LifecycleState::RolledBack);
    assert_eq!(rollback.from_version, canary_version.clone());
    assert_eq!(rollback.to_version, previous_version.clone());
    assert!(rollback.message.contains("rolled back"));

    let repinned: PinStateResponse = http_get_json(
        host.client.clone(),
        url(&format!("/rpc/rollout/pin/{}", connector_id.as_str())),
    )
    .await?;
    assert!(repinned.pinned);
    assert_eq!(repinned.version, Some(previous_version.clone()));

    let unpinned: PinStateResponse = http_delete_json(
        host.client.clone(),
        url(&format!("/rpc/rollout/pin/{}", connector_id.as_str())),
    )
    .await?;
    assert!(!unpinned.pinned);
    assert_eq!(unpinned.version, None);

    let logs = wait_for_log_events(
        &host.stderr_logs,
        &[
            "rollout_pin_request",
            "rollout_pin_response",
            "rollout_pin_status_request",
            "rollout_pin_status_response",
            "rollout_manual_rollback_request",
            "rollout_manual_rollback_response",
            "rollout_unpin_request",
            "rollout_unpin_response",
        ],
    )
    .await?;

    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("rollout_pin_response")
            && entry.get("connector_id").and_then(Value::as_str) == Some(connector_id.as_str())
            && entry.get("pinned").and_then(Value::as_bool) == Some(true)
    }));
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("rollout_manual_rollback_response")
            && entry.get("connector_id").and_then(Value::as_str) == Some(connector_id.as_str())
            && entry.get("from_version").and_then(Value::as_str) == Some("1.0.1")
            && entry.get("to_version").and_then(Value::as_str) == Some("1.0.0")
            && entry.get("state").and_then(Value::as_str) == Some("rolled_back")
    }));
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("rollout_unpin_response")
            && entry.get("connector_id").and_then(Value::as_str) == Some(connector_id.as_str())
    }));

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_emits_structured_endpoint_logs() -> Result<(), Box<dyn std::error::Error>>
{
    let connector_a_id = ConnectorId::from_static("fcp.test.log-echo:utility:1.0.0");
    let connector_b_id = ConnectorId::from_static("fcp.test.log-ping:utility:1.0.0");
    let capability_signing_key = Ed25519SigningKey::generate();
    let capability_public_key = capability_public_key_hex(&capability_signing_key);

    let host = HttpHostProcess::spawn_with_env(
        vec![
            test_connector_config(&connector_a_id, "Log Echo", &["test", "primary"]),
            test_connector_config(&connector_b_id, "Log Ping", &["test", "secondary"]),
        ],
        &[(
            "FCP_HOST_CAPABILITY_PUBLIC_KEY",
            capability_public_key.as_str(),
        )],
    )
    .await?;

    assert_discovery_routes(
        &host.client,
        &host.base_url,
        &connector_a_id,
        &connector_b_id,
        &capability_signing_key,
    )
    .await?;

    let logs = wait_for_log_events(
        &host.stderr_logs,
        &[
            "discover_request",
            "discover_response",
            "introspect_request",
            "introspect_response",
            "invoke_request",
            "invoke_response",
            "preflight_check",
            "doctor_request",
            "doctor_response",
            "health_response",
        ],
    )
    .await?;

    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("discover_response")
            && entry.get("connector_count").and_then(Value::as_u64) == Some(2)
            && entry.get("registry_version").and_then(Value::as_u64) == Some(1)
            && entry.get("cache_hit").and_then(Value::as_bool) == Some(false)
    }));
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("discover_response")
            && entry.get("connector_count").and_then(Value::as_u64) == Some(1)
            && entry.get("registry_version").and_then(Value::as_u64) == Some(1)
            && entry.get("cache_hit").and_then(Value::as_bool) == Some(true)
    }));
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("introspect_response")
            && entry.get("connector_id").and_then(Value::as_str) == Some(connector_a_id.as_str())
            && entry.get("tool_count").and_then(Value::as_u64) == Some(1)
    }));
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("preflight_check")
            && entry.get("connector_id").and_then(Value::as_str) == Some(connector_a_id.as_str())
            && entry.get("operation").and_then(Value::as_str) == Some("test.echo")
            && entry.get("allowed").and_then(Value::as_bool) == Some(true)
    }));
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("invoke_request")
            && entry.get("connector_id").and_then(Value::as_str) == Some(connector_a_id.as_str())
            && entry.get("operation").and_then(Value::as_str) == Some("test.echo")
    }));
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("invoke_response")
            && entry.get("connector_id").and_then(Value::as_str) == Some(connector_a_id.as_str())
            && entry.get("operation").and_then(Value::as_str) == Some("test.echo")
            && entry.get("status").and_then(Value::as_str) == Some("Ok")
    }));
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("doctor_response")
            && entry.get("overall_status").and_then(Value::as_str) == Some("Ok")
    }));
    assert!(logs.iter().any(|entry| {
        entry.get("event").and_then(Value::as_str) == Some("health_response")
            && entry.get("connector_count").and_then(Value::as_u64) == Some(2)
    }));

    Ok(())
}

#[cfg(unix)]
#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_exposes_discovery_routes_over_unix_socket()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_a_id = ConnectorId::from_static("fcp.test.unix-echo:utility:1.0.0");
    let connector_b_id = ConnectorId::from_static("fcp.test.unix-ping:utility:1.0.0");
    let capability_signing_key = Ed25519SigningKey::generate();
    let capability_public_key = capability_public_key_hex(&capability_signing_key);

    let host = UnixHostProcess::spawn_with_env(
        vec![
            test_connector_config(&connector_a_id, "Unix Echo", &["test", "primary"]),
            test_connector_config(&connector_b_id, "Unix Ping", &["test", "secondary"]),
        ],
        &[(
            "FCP_HOST_CAPABILITY_PUBLIC_KEY",
            capability_public_key.as_str(),
        )],
    )
    .await?;

    assert_discovery_routes(
        &host.client,
        &host.base_url,
        &connector_a_id,
        &connector_b_id,
        &capability_signing_key,
    )
    .await?;

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_invoke_route_rejects_invalid_capability_signature()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_id = ConnectorId::from_static("fcp.test.invoke-auth:utility:1.0.0");
    let trusted_signing_key = Ed25519SigningKey::generate();
    let trusted_public_key = capability_public_key_hex(&trusted_signing_key);
    let untrusted_signing_key = Ed25519SigningKey::generate();
    let host = HttpHostProcess::spawn_with_env(
        vec![test_connector_config(
            &connector_id,
            "Invoke Auth",
            &["test", "auth"],
        )],
        &[(
            "FCP_HOST_CAPABILITY_PUBLIC_KEY",
            trusted_public_key.as_str(),
        )],
    )
    .await?;
    let url = |path: &str| format!("{}{path}", host.base_url);

    let (invoke_request, _) = build_invoke_request(connector_id, &untrusted_signing_key);
    let response = host
        .client
        .post(url("/rpc/invoke"))
        .json(&invoke_request)
        .send()
        .await?;
    let status = response.status();
    let body = response.text().await?;

    assert_eq!(status, reqwest::StatusCode::FORBIDDEN);
    assert!(body.contains("capability token rejected"));

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn fcp_host_binary_protected_routes_require_admin_bearer()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_id = ConnectorId::from_static("fcp.test.admin-auth:utility:1.0.0");
    let host = HttpHostProcess::spawn_with_env(
        vec![test_connector_config(
            &connector_id,
            "Admin Auth",
            &["test", "admin-auth"],
        )],
        &[],
    )
    .await?;
    let url = |path: &str| format!("{}{path}", host.base_url);

    let public_health = host.client.get(url("/rpc/health")).send().await?;
    assert!(public_health.status().is_success());

    let policy = test_rollout_policy();
    let rollout_seed: RolloutOutcome = http_post_json(
        host.client.clone(),
        url("/rpc/rollout/schedule"),
        json!({
            "connector_id": connector_id.as_str(),
            "version": "1.0.1",
            "previous_version": "1.0.0",
            "policy": policy.clone(),
            "observed_at": chrono::Utc::now(),
        }),
    )
    .await?;
    assert_eq!(rollout_seed.decision, RolloutDecision::Scheduled);

    let protected_cases: Vec<(&str, reqwest::Method, String, Option<Value>)> = vec![
        (
            "config snapshot",
            reqwest::Method::GET,
            url(&format!("/rpc/connectors/{}/config", connector_id.as_str())),
            None,
        ),
        (
            "config validate",
            reqwest::Method::POST,
            url(&format!(
                "/rpc/connectors/{}/config/validate",
                connector_id.as_str()
            )),
            Some(json!({
                "payload": {
                    "profile": "work",
                    "region": "us-east-1",
                },
                "expected_active_revision_id": null,
            })),
        ),
        (
            "lifecycle status",
            reqwest::Method::GET,
            url(&format!("/rpc/lifecycle/{}", connector_id.as_str())),
            None,
        ),
        (
            "lifecycle transition",
            reqwest::Method::POST,
            url(&format!("/rpc/lifecycle/{}", connector_id.as_str())),
            Some(json!({
                "action": "restart",
                "reason": "admin auth matrix",
                "dry_run": true,
            })),
        ),
        (
            "rollout pin",
            reqwest::Method::GET,
            url(&format!("/rpc/rollout/pin/{}", connector_id.as_str())),
            None,
        ),
        (
            "rollout status",
            reqwest::Method::GET,
            url(&format!("/rpc/rollout/{}", connector_id.as_str())),
            None,
        ),
        (
            "rollout schedule",
            reqwest::Method::POST,
            url("/rpc/rollout/schedule"),
            Some(json!({
                "connector_id": connector_id.as_str(),
                "version": "1.0.1",
                "previous_version": "1.0.0",
                "policy": policy.clone(),
                "observed_at": chrono::Utc::now(),
            })),
        ),
        (
            "rollout evaluate",
            reqwest::Method::POST,
            url("/rpc/rollout/evaluate"),
            Some(json!({
                "connector_id": connector_id.as_str(),
                "invocation_succeeded": true,
                "latency_ms": 20,
                "uptime_secs": 120,
                "pinned": false,
                "crashed": false,
                "policy": policy.clone(),
                "observed_at": chrono::Utc::now(),
            })),
        ),
        (
            "admin journal query",
            reqwest::Method::POST,
            url("/rpc/admin/journal"),
            Some(json!({
                "connector_id": connector_id.as_str(),
                "after_sequence": 0,
                "limit": 10,
            })),
        ),
        (
            "admin journal by connector",
            reqwest::Method::GET,
            url(&format!("/rpc/admin/journal/{}", connector_id.as_str())),
            None,
        ),
        (
            "admin logs",
            reqwest::Method::POST,
            url("/rpc/admin/logs"),
            Some(json!({
                "connector_id": connector_id.as_str(),
                "after_sequence": 0,
                "limit": 10,
            })),
        ),
        (
            "admin receipts",
            reqwest::Method::POST,
            url("/rpc/admin/receipts"),
            Some(json!({
                "connector_id": connector_id.as_str(),
                "operation": TEST_OPERATION,
                "after": null,
                "limit": 10,
            })),
        ),
        (
            "admin simulate receipts",
            reqwest::Method::POST,
            url("/rpc/admin/simulate-receipts"),
            Some(json!({
                "connector_id": connector_id.as_str(),
                "operation": TEST_OPERATION,
                "after": null,
                "limit": 10,
            })),
        ),
        (
            "admin events",
            reqwest::Method::POST,
            url("/rpc/admin/events"),
            Some(json!({
                "connector_id": connector_id.as_str(),
                "limit": 10,
                "unacknowledged_only": false,
            })),
        ),
        (
            "admin events acknowledge",
            reqwest::Method::POST,
            url("/rpc/admin/events/acknowledge"),
            Some(json!({
                "event_ids": [],
            })),
        ),
    ];

    for (name, method, endpoint, body) in protected_cases {
        let (status, body_text) = request_status_text(
            host.client.clone(),
            method.clone(),
            endpoint.clone(),
            body.clone(),
            None,
        )
        .await?;
        assert_eq!(
            status,
            reqwest::StatusCode::FORBIDDEN,
            "{name} should reject missing admin auth, got {status}: {body_text}"
        );
        assert!(
            body_text.contains("Authorization header"),
            "{name} missing-auth response should mention Authorization header: {body_text}"
        );

        let (status, body_text) = request_status_text(
            host.client.clone(),
            method,
            endpoint,
            body,
            Some(admin_auth_headers()),
        )
        .await?;
        assert!(
            status.is_success(),
            "{name} should succeed with admin auth, got {status}: {body_text}"
        );
    }

    // Supply-chain provenance GET is now part of the admin-gated surface
    // (bead flywheel_connectors-qeapt). Unauthenticated callers MUST get
    // 403 with the same "Authorization header" hint as every other
    // protected route. With the admin bearer header, the same GET must
    // return 200 and the existing JSON body.
    let (artifact_status, artifact_body) = request_status_text(
        host.client.clone(),
        reqwest::Method::GET,
        url(&format!(
            "/rpc/connectors/{}/artifact",
            connector_id.as_str()
        )),
        None,
        None,
    )
    .await?;
    assert_eq!(
        artifact_status,
        reqwest::StatusCode::FORBIDDEN,
        "artifact metadata GET must now require admin bearer (qeapt), \
         got {artifact_status}: {artifact_body}"
    );
    assert!(
        artifact_body.contains("Authorization header"),
        "unauth artifact GET must mention Authorization header in error body: {artifact_body}"
    );

    let (artifact_status, artifact_body) = request_status_text(
        host.client.clone(),
        reqwest::Method::GET,
        url(&format!(
            "/rpc/connectors/{}/artifact",
            connector_id.as_str()
        )),
        None,
        Some(admin_auth_headers()),
    )
    .await?;
    assert!(
        artifact_status.is_success(),
        "artifact metadata GET with admin bearer must succeed, \
         got {artifact_status}: {artifact_body}"
    );

    Ok(())
}

/// Regression for bead flywheel_connectors-qeapt: the artifact
/// metadata GET route used to sit OUTSIDE the `protected_routes`
/// group, so any reachable caller could enumerate every installed
/// connector's binary hash, SLSA level, builder identity,
/// `SupplyChainSignature` (algorithm + key_id + signature), trust
/// root id, and source URI. That is a free reconnaissance channel
/// against the zone's supply-chain trust anchors. The fix moves the
/// GET into `protected_routes`, alongside the register/install/
/// update/rollback POSTs; this test pins the two outcomes (401/403
/// without auth, 200 with admin bearer) so a future route-table
/// refactor cannot silently re-expose the provenance surface.
#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn artifact_metadata_get_requires_admin_bearer_qeapt()
-> Result<(), Box<dyn std::error::Error>> {
    let connector_id = ConnectorId::from_static("fcp.test.qeapt:utility:1.0.0");
    let host = HttpHostProcess::spawn_with_env(
        vec![test_connector_config(
            &connector_id,
            "qeapt artifact GET",
            &["test", "qeapt"],
        )],
        &[],
    )
    .await?;
    let artifact_url = format!(
        "{}/rpc/connectors/{}/artifact",
        host.base_url,
        connector_id.as_str()
    );

    // (a) Unauthenticated GET must be refused. The middleware surfaces
    // a 403 with "Authorization header" in the body — matching the
    // shape every other protected endpoint uses.
    let (status, body) = request_status_text(
        host.client.clone(),
        reqwest::Method::GET,
        artifact_url.clone(),
        None,
        None,
    )
    .await?;
    assert_eq!(
        status,
        reqwest::StatusCode::FORBIDDEN,
        "unauthenticated artifact GET must return 403, got {status}: {body}"
    );
    assert!(
        body.contains("Authorization header"),
        "unauth response must name the Authorization header: {body}"
    );

    // Defensive: body MUST NOT leak provenance fields even though the
    // handler was not invoked. If a future refactor accidentally
    // routes the unauth error path through the handler, this catches
    // it.
    for field in [
        "supply_chain_signature",
        "trust_root",
        "builder_identity",
        "artifact_hash",
        "slsa_level",
    ] {
        assert!(
            !body.contains(field),
            "unauth 403 body must not leak field `{field}`: {body}"
        );
    }

    // (b) With the admin bearer header the same GET returns the full
    // provenance body — proves the route is gated at the middleware,
    // not broken outright.
    let (status, body) = request_status_text(
        host.client.clone(),
        reqwest::Method::GET,
        artifact_url,
        None,
        Some(admin_auth_headers()),
    )
    .await?;
    assert!(
        status.is_success(),
        "admin-bearer artifact GET must return 2xx, got {status}: {body}"
    );

    Ok(())
}

#[test]
fn host_log_schema_example() {
    let correlation_id = CorrelationId::new().to_string();
    let payload = serde_json::to_string(&json!({
        "timestamp": Utc::now(),
        "log_version": "v1",
        "level": "info",
        "test_name": "host_connector_integration",
        "module": "fcp-host",
        "phase": "execute",
        "correlation_id": correlation_id,
        "result": "pass",
        "duration_ms": 5,
        "assertions": {
            "passed": 1,
            "failed": 0,
        },
        "context": {
            "connector_count": 2,
        },
    }))
    .expect("serialize host log schema example");
    let capture = LogCapture::new();
    capture.push_line(&payload);
    capture.assert_valid();
}
