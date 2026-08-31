//! Conformance coverage for the `/rpc/preflight` and `/rpc/simulate` handler
//! surfaces.
//!
//! These tests live in `fcp-conformance` so the route contract is checked from
//! the conformance lane, not only from the host crate's own suite.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::{Body, to_bytes};
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use base64::Engine;
use fcp_async_core::sync::RwLock;
use fcp_crypto::cose::CoseToken;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_crypto::ed25519::Ed25519VerifyingKey;
use fcp_host::{
    BudgetPolicyEngine, CapabilityIssuanceRequest, CapabilityTokenVerifyRequest,
    ConnectorArchetype, ConnectorRegistry, ConnectorSummary, DiscoveryEndpoint,
    HostAdminStateStore, HostError, HostPreflightRequest, HostSimulateRequest,
    HostSimulateResponse, PreflightRequest, PreflightResponse, SimulatePhase, SimulateReceipt,
    ToolDescriptor,
};
use fcp_prelude::{
    AgentHint, ApprovalMode, CapabilityToken, ConnectorHealth, ConnectorId, Decision,
    DecisionReceiptPolicy, IdempotencyClass, Introspection, InvokeRequest, ObjectHeader,
    OperationId, OperationInfo, PolicySimulationInput, Provenance, RequestId, RiskLevel,
    SafetyTier, SelfCheckReport, SimulateRequest, SimulateResponse, TransportMode, ZoneId,
    ZonePolicyObject, ZoneTransportPolicy, simulate_policy_decision,
};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tower::util::ServiceExt;

const TEST_PRINCIPAL: &str = "user:test";
const TEST_FORGED_PRINCIPAL: &str = "user:other";
const TEST_OPERATION: &str = "test.echo";
const TEST_CAPABILITY_ID: &str = "cap.test.echo";
const PRINCIPAL_HEADER: &str = "x-principal";

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Clone)]
struct TestRegistry {
    summary: ConnectorSummary,
    introspection: Introspection,
    allowed_zones: Vec<String>,
}

impl TestRegistry {
    fn new(connector_id: ConnectorId) -> Self {
        let operation = OperationInfo {
            id: OperationId::from_static(TEST_OPERATION),
            summary: "Echo a message".to_string(),
            description: Some("Mock operation used by conformance handler tests".to_string()),
            input_schema: json!({
                "type": "object",
                "properties": { "message": { "type": "string" } }
            }),
            output_schema: json!({
                "type": "object",
                "properties": { "ok": { "type": "boolean" } }
            }),
            capability: TEST_CAPABILITY_ID.parse().expect("capability id"),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint::default(),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        };
        let introspection = Introspection {
            operations: vec![operation],
            events: Vec::new(),
            resource_types: Vec::new(),
            auth_caps: None,
            event_caps: None,
        };
        let summary = ConnectorSummary {
            id: connector_id,
            name: "Conformance Surface Connector".to_string(),
            description: Some("Mock connector used by conformance route tests".to_string()),
            version: semver::Version::new(1, 0, 0),
            categories: vec!["conformance".to_string()],
            tool_count: 1,
            max_safety_tier: SafetyTier::Safe,
            enabled: true,
            health: ConnectorHealth::healthy(),
            last_health_check: None,
        };
        Self {
            summary,
            introspection,
            allowed_zones: vec![ZoneId::work().as_str().to_string()],
        }
    }

    fn with_allowed_zones(mut self, allowed_zones: Vec<String>) -> Self {
        self.allowed_zones = allowed_zones;
        self
    }

    fn allowed_zones(&self, id: &ConnectorId) -> Option<Vec<String>> {
        (id == &self.summary.id).then(|| self.allowed_zones.clone())
    }

    fn simulate(&self, request: SimulateRequest) -> Result<SimulateResponse, HostError> {
        if request.connector_id != self.summary.id {
            return Err(HostError::RegistryError(format!(
                "unknown connector `{}`",
                request.connector_id
            )));
        }
        if request.operation.as_str() != TEST_OPERATION {
            return Err(HostError::RegistryError(format!(
                "unknown operation `{}`",
                request.operation
            )));
        }
        Ok(SimulateResponse::allowed(request.id))
    }
}

#[async_trait::async_trait]
impl ConnectorRegistry for TestRegistry {
    async fn list(&self) -> Vec<ConnectorSummary> {
        vec![self.summary.clone()]
    }

    async fn get(&self, id: &ConnectorId) -> Option<ConnectorSummary> {
        (id == &self.summary.id).then(|| self.summary.clone())
    }

    async fn get_introspection(&self, id: &ConnectorId) -> Option<Introspection> {
        (id == &self.summary.id).then(|| self.introspection.clone())
    }

    async fn get_archetype(&self, id: &ConnectorId) -> Option<ConnectorArchetype> {
        (id == &self.summary.id).then_some(ConnectorArchetype::RequestResponse)
    }

    async fn get_rate_limits(&self, _id: &ConnectorId) -> Option<fcp_core::RateLimitDeclarations> {
        None
    }

    async fn self_check(&self, _id: &ConnectorId) -> Option<SelfCheckReport> {
        None
    }

    fn version(&self) -> u64 {
        1
    }
}

struct TestAppState {
    registry: Arc<TestRegistry>,
    discovery: Arc<DiscoveryEndpoint<TestRegistry, BudgetPolicyEngine>>,
    lifecycle: Arc<HostAdminStateStore>,
    capability_verifying_key: Option<Ed25519VerifyingKey>,
    zone_policies: Arc<RwLock<HashMap<ZoneId, ZonePolicyObject>>>,
}

impl TestAppState {
    async fn lookup_zone_policy(&self, zone_id: &ZoneId) -> Result<ZonePolicyObject, HostError> {
        let policies = self.zone_policies.read().await;
        if let Some(policy) = policies.get(zone_id) {
            return Ok(policy.clone());
        }
        Err(HostError::PreflightFailed(format!(
            "no zone policy configured for live request zone `{}`",
            zone_id.as_str()
        )))
    }
}

#[derive(Debug, Clone)]
struct VerifiedLiveRequest {
    principal: String,
    approval_required: bool,
    safety_tier: SafetyTier,
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
            created_at: u64::try_from(fcp_core::Utc::now().timestamp()).unwrap_or(0),
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

fn map_host_error(error: &HostError) -> (StatusCode, String) {
    let message = error.to_string();
    let status = match error {
        HostError::InvalidFilter(_) | HostError::PreflightFailed(_) => StatusCode::BAD_REQUEST,
        HostError::ZoneEnvelopeRequired(_) => StatusCode::FORBIDDEN,
        HostError::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
        HostError::RegistryError(_) => StatusCode::BAD_GATEWAY,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, message)
}

fn extract_principal_header(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(PRINCIPAL_HEADER)?.to_str().ok()?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn invoke_request_from_preflight(
    request: &HostPreflightRequest,
) -> Result<InvokeRequest, HostError> {
    let capability_token = request.capability_token.clone().ok_or_else(|| {
        HostError::PreflightFailed("capability token is required for live preflight".to_string())
    })?;
    let zone_id = request.zone_id.clone().ok_or_else(|| {
        HostError::PreflightFailed("zone_id is required for live preflight".to_string())
    })?;
    let operation = request.operation.parse().map_err(|error| {
        HostError::InvalidFilter(format!(
            "invalid preflight operation '{}': {error}",
            request.operation
        ))
    })?;

    Ok(InvokeRequest {
        r#type: "invoke".to_owned(),
        id: request.request_id.clone(),
        connector_id: request.connector_id.clone(),
        operation,
        zone_id,
        input: request.params.clone().unwrap_or(Value::Null),
        capability_token,
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: None,
        correlation_id: None,
        provenance: None,
        approval_tokens: request.approval_tokens.clone(),
    })
}

fn simulate_request_from_host(request: &HostSimulateRequest) -> Result<SimulateRequest, HostError> {
    let capability_token = request.capability_token.clone().ok_or_else(|| {
        HostError::PreflightFailed("capability token is required for live simulate".to_string())
    })?;
    let connector_id = request.connector_id.parse().map_err(|error| {
        HostError::InvalidFilter(format!(
            "invalid simulate connector id '{}': {error}",
            request.connector_id
        ))
    })?;
    let zone_raw = request.zone_id.as_deref().ok_or_else(|| {
        HostError::PreflightFailed("zone_id is required for live simulate".to_string())
    })?;
    let zone_id = zone_raw.parse().map_err(|error| {
        HostError::InvalidFilter(format!("invalid simulate zone_id '{zone_raw}': {error}"))
    })?;
    let operation = request.operation.parse().map_err(|error| {
        HostError::InvalidFilter(format!(
            "invalid simulate operation '{}': {error}",
            request.operation
        ))
    })?;

    Ok(SimulateRequest {
        r#type: "simulate".to_owned(),
        id: RequestId::new(request.request_id.clone()),
        connector_id,
        operation,
        zone_id,
        input: request.input.clone().unwrap_or(Value::Null),
        capability_token,
        estimate_cost: request.estimate_cost,
        check_availability: request.check_availability,
        context: None,
        correlation_id: None,
    })
}

fn invoke_request_from_simulate(request: &HostSimulateRequest) -> Result<InvokeRequest, HostError> {
    let simulate_request = simulate_request_from_host(request)?;
    Ok(InvokeRequest {
        r#type: "invoke".to_owned(),
        id: simulate_request.id.clone(),
        connector_id: simulate_request.connector_id.clone(),
        operation: simulate_request.operation.clone(),
        zone_id: simulate_request.zone_id.clone(),
        input: simulate_request.input.clone(),
        capability_token: simulate_request.capability_token.clone(),
        holder_proof: None,
        context: simulate_request.context.clone(),
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: Some(request.deadline_ms),
        correlation_id: simulate_request.correlation_id,
        provenance: None,
        approval_tokens: request.approval_tokens.clone(),
    })
}

fn request_input_hash(input: &Value) -> Result<[u8; 32], HostError> {
    let bytes = fcp_cbor::to_canonical_cbor(input).map_err(|error| {
        HostError::Internal(format!("failed to canonicalize input payload: {error}"))
    })?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

fn claims_principal(claims: &fcp_crypto::cose::CwtClaims) -> Option<&str> {
    claims.get_subject()
}

fn capability_token_b64(token: &CapabilityToken) -> Result<String, HostError> {
    let bytes = token.raw().to_cbor().map_err(|error| {
        HostError::Internal(format!(
            "failed to serialize capability token for verification: {error}"
        ))
    })?;
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}

fn simulate_receipt_for_request(
    request: &HostSimulateRequest,
    input: &Value,
    phase: SimulatePhase,
    would_succeed: bool,
    duration_ms: u64,
) -> Result<SimulateReceipt, HostError> {
    Ok(SimulateReceipt {
        receipt_id: format!("sim_{}", RequestId::random()),
        connector_id: request.connector_id.clone(),
        operation: request.operation.clone(),
        phase,
        would_succeed,
        input_digest: Some(hex::encode(request_input_hash(input)?)),
        duration_ms,
        simulated_at: fcp_core::Utc::now(),
    })
}

async fn record_simulate_receipt_summary(
    lifecycle: &HostAdminStateStore,
    receipt: &SimulateReceipt,
) {
    let _ = lifecycle.record_simulate_receipt(receipt.clone()).await;
}

fn elapsed_millis(started_at: Instant) -> u64 {
    u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn ensure_connector_zone_allowed(
    registry: &TestRegistry,
    request: &InvokeRequest,
) -> Result<(), HostError> {
    if let Some(allowed) = registry.allowed_zones(&request.connector_id) {
        if allowed.is_empty() {
            return Err(HostError::ZoneEnvelopeRequired(format!(
                "connector `{}` has no `allowed_zones`; configure at least one explicit zone before host RPC",
                request.connector_id
            )));
        }
        if !allowed.iter().any(|zone| zone == request.zone_id.as_str()) {
            return Err(HostError::PreflightFailed(format!(
                "connector `{}` is not bound to zone `{}` (allowed: [{}])",
                request.connector_id,
                request.zone_id.as_str(),
                allowed.join(", ")
            )));
        }
    }
    Ok(())
}

async fn verified_capability_principal(
    state: &TestAppState,
    request: &InvokeRequest,
    tool: &ToolDescriptor,
) -> Result<String, HostError> {
    let capability_key = state.capability_verifying_key.as_ref().ok_or_else(|| {
        HostError::PreflightFailed(
            "FCP_HOST_CAPABILITY_PUBLIC_KEY[_FILE] is not configured, so live auth checks cannot be verified"
                .to_string(),
        )
    })?;
    let verifier = fcp_core::CapabilityVerifier::without_instance_binding(
        capability_key.to_bytes(),
        request.zone_id.clone(),
    );
    let verified_token = verifier
        .verify_unbound(
            request.capability_token.clone(),
            &tool.capability,
            &request.operation,
            &[],
        )
        .map_err(|error| {
            HostError::PreflightFailed(format!("capability token rejected: {error}"))
        })?;
    let verified_claims = verified_token.claims();

    let persisted_verify = state
        .lifecycle
        .verify_capability_token(&CapabilityTokenVerifyRequest {
            token_cbor_b64: capability_token_b64(&request.capability_token)?,
            operation_id: Some(request.operation.to_string()),
            connector_id: Some(request.connector_id.to_string()),
        })
        .await
        .map_err(|error| {
            HostError::PreflightFailed(format!("persisted capability verification failed: {error}"))
        })?;
    if !persisted_verify.valid {
        let reason = persisted_verify
            .rejection_reasons
            .first()
            .cloned()
            .unwrap_or_else(|| {
                "persisted capability verification rejected the live request".to_string()
            });
        return Err(HostError::PreflightFailed(format!(
            "capability token rejected by host state: {reason}"
        )));
    }

    let principal = claims_principal(verified_claims).ok_or_else(|| {
        HostError::PreflightFailed(
            "capability token is missing the subject or principal_id claim required for live execution".to_string(),
        )
    })?;
    Ok(principal.to_owned())
}

async fn enforce_live_policy(
    state: &TestAppState,
    request: &InvokeRequest,
    tool: &ToolDescriptor,
    principal: &str,
    approval_required: bool,
) -> Result<(), HostError> {
    let zone_policy = state.lookup_zone_policy(&request.zone_id).await?;
    let receipt = simulate_policy_decision(&PolicySimulationInput {
        zone_policy,
        invoke_request: request.clone(),
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: approval_required,
        sanitizer_receipts: Vec::new(),
        related_object_ids: Vec::new(),
        request_object_id: None,
        request_input_hash: Some(request_input_hash(&request.input)?),
        safety_tier: tool.safety_tier,
        principal: Some(principal.to_owned()),
        capability_id: Some(tool.capability.to_string()),
        provenance_record: None,
        now_ms: None,
        posture_attestation: None,
    })
    .map_err(|error| HostError::PreflightFailed(format!("policy evaluation failed: {error}")))?;
    if receipt.decision == Decision::Deny {
        return Err(HostError::PreflightFailed(format!(
            "policy denied live request: {}",
            receipt.reason_code
        )));
    }
    Ok(())
}

async fn verify_live_request(
    state: &TestAppState,
    request: &InvokeRequest,
    principal_override: Option<&str>,
) -> Result<VerifiedLiveRequest, HostError> {
    ensure_connector_zone_allowed(&state.registry, request)?;

    let introspection = state.discovery.introspect(&request.connector_id).await?;
    let tool = introspection
        .tools
        .iter()
        .find(|tool| tool.name == request.operation.as_str())
        .ok_or_else(|| {
            HostError::InvalidFilter(format!(
                "connector `{}` does not expose operation `{}`",
                request.connector_id, request.operation
            ))
        })?;

    let principal = verified_capability_principal(state, request, tool).await?;
    if let Some(expected) = principal_override
        && expected != principal.as_str()
    {
        return Err(HostError::PreflightFailed(format!(
            "request principal `{expected}` does not match capability token subject/principal_id `{principal}`"
        )));
    }

    let approval_required = tool
        .approval_mode
        .is_some_and(|mode| !matches!(mode, ApprovalMode::None));
    enforce_live_policy(state, request, tool, &principal, approval_required).await?;

    Ok(VerifiedLiveRequest {
        principal,
        approval_required,
        safety_tier: tool.safety_tier,
    })
}

fn preflight_response_from_error(error: &HostError) -> PreflightResponse {
    let reason = error.to_string();
    let mut response = PreflightResponse::denied(&reason);
    response.reason = Some(reason);
    response
}

async fn evaluate_live_preflight(
    state: &TestAppState,
    request: &InvokeRequest,
    principal_override: Option<&str>,
) -> PreflightResponse {
    let mut response = state
        .discovery
        .preflight(PreflightRequest {
            connector_id: request.connector_id.clone(),
            operation: request.operation.to_string(),
            params: Some(request.input.clone()),
            principal: principal_override.map(ToOwned::to_owned),
            zone_id: Some(request.zone_id.clone()),
        })
        .await;
    if !response.allowed {
        return response;
    }

    match verify_live_request(state, request, principal_override).await {
        Ok(verified) => {
            let _ = (
                &verified.principal,
                verified.approval_required,
                verified.safety_tier,
            );
            response
        }
        Err(error) => {
            response.allowed = false;
            response.reason = Some(error.to_string());
            response
        }
    }
}

async fn preflight_handler(
    State(state): State<Arc<TestAppState>>,
    headers: HeaderMap,
    Json(request): Json<HostPreflightRequest>,
) -> Json<PreflightResponse> {
    let asserted_principal =
        extract_principal_header(&headers).or_else(|| request.principal.clone());
    let response = match invoke_request_from_preflight(&request) {
        Ok(invoke_request) => {
            evaluate_live_preflight(&state, &invoke_request, asserted_principal.as_deref()).await
        }
        Err(error) => preflight_response_from_error(&error),
    };
    Json(response)
}

fn simulate_failure_response(
    request: &HostSimulateRequest,
    input: &Value,
    phase: SimulatePhase,
    preflight_allowed: bool,
    failure_reason: String,
    duration_ms: u64,
) -> Result<HostSimulateResponse, HostError> {
    Ok(HostSimulateResponse {
        request_id: request.request_id.clone(),
        would_succeed: false,
        phase,
        preflight_allowed,
        failure_reason: Some(failure_reason),
        denial_code: None,
        missing_capabilities: Vec::new(),
        cost_estimate: None,
        availability: None,
        duration_ms,
        receipt: simulate_receipt_for_request(request, input, phase, false, duration_ms)?,
    })
}

fn connector_reached_response(
    request: &HostSimulateRequest,
    input: &Value,
    simulate_response: SimulateResponse,
    duration_ms: u64,
) -> Result<HostSimulateResponse, HostError> {
    Ok(HostSimulateResponse {
        request_id: request.request_id.clone(),
        would_succeed: simulate_response.would_succeed,
        phase: SimulatePhase::ConnectorReached,
        preflight_allowed: true,
        failure_reason: simulate_response.failure_reason,
        denial_code: simulate_response.denial_code,
        missing_capabilities: simulate_response.missing_capabilities,
        cost_estimate: None,
        availability: None,
        duration_ms,
        receipt: simulate_receipt_for_request(
            request,
            input,
            SimulatePhase::ConnectorReached,
            simulate_response.would_succeed,
            duration_ms,
        )?,
    })
}

async fn simulate_handler(
    State(state): State<Arc<TestAppState>>,
    headers: HeaderMap,
    Json(request): Json<HostSimulateRequest>,
) -> Result<Json<HostSimulateResponse>, (StatusCode, String)> {
    let asserted_principal =
        extract_principal_header(&headers).or_else(|| request.principal.clone());
    let started_at = Instant::now();

    let preflight_request = match invoke_request_from_simulate(&request) {
        Ok(preflight_request) => preflight_request,
        Err(error) => {
            let input = request.input.clone().unwrap_or(Value::Null);
            let duration_ms = elapsed_millis(started_at);
            let response = simulate_failure_response(
                &request,
                &input,
                SimulatePhase::PreflightOnly,
                false,
                error.to_string(),
                duration_ms,
            )
            .map_err(|error| map_host_error(&error))?;
            record_simulate_receipt_summary(state.lifecycle.as_ref(), &response.receipt).await;
            return Ok(Json(response));
        }
    };

    let preflight =
        evaluate_live_preflight(&state, &preflight_request, asserted_principal.as_deref()).await;
    if !preflight.allowed {
        let input = request.input.clone().unwrap_or(Value::Null);
        let duration_ms = elapsed_millis(started_at);
        let response = simulate_failure_response(
            &request,
            &input,
            SimulatePhase::PreflightOnly,
            false,
            preflight
                .reason
                .unwrap_or_else(|| "preflight denied live simulate request".to_string()),
            duration_ms,
        )
        .map_err(|error| map_host_error(&error))?;
        record_simulate_receipt_summary(state.lifecycle.as_ref(), &response.receipt).await;
        return Ok(Json(response));
    }

    let simulate_request =
        simulate_request_from_host(&request).map_err(|error| map_host_error(&error))?;
    let simulate_input = simulate_request.input.clone();
    let simulate_result = fcp_async_core::time::timeout(
        Duration::from_millis(request.deadline_ms),
        std::future::ready(state.registry.simulate(simulate_request)),
    )
    .await;
    let duration_ms = elapsed_millis(started_at);

    let response = match simulate_result {
        Ok(Ok(simulate_response)) => {
            connector_reached_response(&request, &simulate_input, simulate_response, duration_ms)
                .map_err(|error| map_host_error(&error))?
        }
        Ok(Err(error)) => return Err(map_host_error(&error)),
        Err(_) => simulate_failure_response(
            &request,
            &simulate_input,
            SimulatePhase::TimedOut,
            true,
            "simulation deadline exceeded".to_string(),
            duration_ms,
        )
        .map_err(|error| map_host_error(&error))?,
    };

    record_simulate_receipt_summary(state.lifecycle.as_ref(), &response.receipt).await;
    Ok(Json(response))
}

fn principal_header(value: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        PRINCIPAL_HEADER,
        HeaderValue::from_str(value).expect("principal header value should be valid"),
    );
    headers
}

fn preflight_request(
    connector_id: ConnectorId,
    capability_token: Option<CapabilityToken>,
) -> HostPreflightRequest {
    HostPreflightRequest {
        request_id: RequestId::random(),
        connector_id,
        operation: TEST_OPERATION.to_string(),
        params: Some(json!({ "message": "hello" })),
        principal: Some(TEST_PRINCIPAL.to_string()),
        zone_id: Some(ZoneId::work()),
        capability_token,
        approval_tokens: Vec::new(),
    }
}

fn simulate_request(
    connector_id: &ConnectorId,
    capability_token: Option<CapabilityToken>,
    request_id: &str,
) -> HostSimulateRequest {
    HostSimulateRequest {
        request_id: request_id.to_string(),
        connector_id: connector_id.to_string(),
        operation: TEST_OPERATION.to_string(),
        input: Some(json!({ "message": "hello" })),
        zone_id: Some(ZoneId::work().to_string()),
        principal: Some(TEST_PRINCIPAL.to_string()),
        capability_token,
        approval_tokens: Vec::new(),
        estimate_cost: false,
        check_availability: false,
        deadline_ms: 5_000,
    }
}

fn route_test_connector_id(suffix: &str) -> ConnectorId {
    format!("fcp.test.conformance.{suffix}:utility:1.0.0")
        .parse()
        .expect("test connector id should be canonical")
}

async fn issue_live_capability_token(
    lifecycle: &HostAdminStateStore,
    signing_key: &Ed25519SigningKey,
    connector_id: &ConnectorId,
    capability_id: &str,
    principal: &str,
    operation: &str,
    zone_id: &ZoneId,
) -> TestResult<CapabilityToken> {
    let issued = lifecycle
        .issue_capability_token(
            &CapabilityIssuanceRequest {
                connector_id: connector_id.to_string(),
                capability_id: capability_id.to_string(),
                zone_id: zone_id.to_string(),
                principal_id: principal.to_string(),
                operations: vec![operation.to_string()],
                ttl_secs: 3_600,
                not_before_delay_secs: None,
                holder_node: None,
                max_delegation_depth: 0,
                resource_allow: vec!["*".to_string()],
                resource_deny: Vec::new(),
                max_calls: None,
                max_bytes: None,
                credential_allow: Vec::new(),
                dry_run: false,
            },
            signing_key,
        )
        .await?;
    let token_cbor_b64 = issued
        .token_cbor_b64
        .ok_or_else(|| "issued capability token missing raw token bytes".to_string())?;
    let token_bytes = base64::engine::general_purpose::STANDARD.decode(token_cbor_b64)?;
    let raw = CoseToken::from_cbor(&token_bytes)?;
    Ok(CapabilityToken::from_raw(raw))
}

fn test_router(state: Arc<TestAppState>) -> Router {
    Router::new()
        .route("/rpc/preflight", post(preflight_handler))
        .route("/rpc/simulate", post(simulate_handler))
        .with_state(state)
}

async fn post_json_response<B, T>(
    app: &Router,
    path: &str,
    body: B,
    headers: Option<HeaderMap>,
) -> TestResult<(StatusCode, T)>
where
    B: serde::Serialize,
    T: DeserializeOwned,
{
    let body = serde_json::to_vec(&body)?;
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(body))?;
    if let Some(headers) = headers {
        request.headers_mut().extend(headers);
    }
    let response = app.clone().oneshot(request).await?;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await?;
    if !status.is_success() {
        return Err(format!(
            "request to {path} failed with {status}: {}",
            String::from_utf8_lossy(&bytes)
        )
        .into());
    }
    Ok((status, serde_json::from_slice(&bytes)?))
}

fn test_state(connector_id: ConnectorId, signing_key: &Ed25519SigningKey) -> Arc<TestAppState> {
    test_state_with_allowed_zones(
        connector_id,
        signing_key,
        vec![ZoneId::work().as_str().to_string()],
    )
}

fn test_state_with_allowed_zones(
    connector_id: ConnectorId,
    signing_key: &Ed25519SigningKey,
    allowed_zones: Vec<String>,
) -> Arc<TestAppState> {
    let registry = Arc::new(TestRegistry::new(connector_id).with_allowed_zones(allowed_zones));
    let budget = Arc::new(BudgetPolicyEngine::new());
    let discovery = Arc::new(DiscoveryEndpoint::new(
        Arc::clone(&registry),
        Arc::clone(&budget),
    ));
    let mut zone_policies = HashMap::new();
    zone_policies.insert(ZoneId::work(), test_zone_policy(ZoneId::work()));
    Arc::new(TestAppState {
        registry,
        discovery,
        lifecycle: Arc::new(HostAdminStateStore::new()),
        capability_verifying_key: Some(signing_key.verifying_key()),
        zone_policies: Arc::new(RwLock::new(zone_policies)),
    })
}

async fn deny_test_capability_in_work_zone(state: &Arc<TestAppState>) {
    let mut policies = state.zone_policies.write().await;
    let policy = policies
        .get_mut(&ZoneId::work())
        .expect("work zone policy should be present in test state");
    policy.capability_deny = vec![fcp_core::PolicyPattern {
        pattern: TEST_CAPABILITY_ID.to_string(),
    }];
}

async fn deny_test_principal_in_work_zone(state: &Arc<TestAppState>) {
    let mut policies = state.zone_policies.write().await;
    let policy = policies
        .get_mut(&ZoneId::work())
        .expect("work zone policy should be present in test state");
    policy.principal_deny = vec![fcp_core::PolicyPattern {
        pattern: TEST_PRINCIPAL.to_string(),
    }];
}

async fn deny_test_connector_in_work_zone(state: &Arc<TestAppState>, connector_id: &ConnectorId) {
    let mut policies = state.zone_policies.write().await;
    let policy = policies
        .get_mut(&ZoneId::work())
        .expect("work zone policy should be present in test state");
    policy.connector_deny = vec![fcp_core::PolicyPattern {
        pattern: connector_id.to_string(),
    }];
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn conformance_preflight_surface_covers_allow_missing_capability_and_principal_mismatch()
-> TestResult<()> {
    let connector_id = route_test_connector_id("preflight-surface");
    let signing_key = Ed25519SigningKey::generate();
    let state = test_state(connector_id.clone(), &signing_key);
    let valid_token = issue_live_capability_token(
        state.lifecycle.as_ref(),
        &signing_key,
        &connector_id,
        TEST_CAPABILITY_ID,
        TEST_PRINCIPAL,
        TEST_OPERATION,
        &ZoneId::work(),
    )
    .await?;
    let app = test_router(state);

    let (_, allowed): (_, PreflightResponse) = post_json_response(
        &app,
        "/rpc/preflight",
        preflight_request(connector_id.clone(), Some(valid_token.clone())),
        None,
    )
    .await?;
    assert!(allowed.allowed, "{allowed:?}");
    assert!(allowed.reason.is_none(), "{allowed:?}");

    let (_, missing_capability): (_, PreflightResponse) = post_json_response(
        &app,
        "/rpc/preflight",
        preflight_request(connector_id.clone(), None),
        None,
    )
    .await?;
    assert!(!missing_capability.allowed, "{missing_capability:?}");
    assert!(
        missing_capability
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("capability token is required")),
        "{missing_capability:?}"
    );

    let (_, forged_principal): (_, PreflightResponse) = post_json_response(
        &app,
        "/rpc/preflight",
        preflight_request(connector_id, Some(valid_token)),
        Some(principal_header(TEST_FORGED_PRINCIPAL)),
    )
    .await?;
    assert!(!forged_principal.allowed, "{forged_principal:?}");
    assert!(
        forged_principal
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains(TEST_FORGED_PRINCIPAL)),
        "{forged_principal:?}"
    );

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn conformance_live_surfaces_reject_empty_allowed_zones() -> TestResult<()> {
    let connector_id = route_test_connector_id("empty-zone-envelope");
    let signing_key = Ed25519SigningKey::generate();
    let state = test_state_with_allowed_zones(connector_id.clone(), &signing_key, Vec::new());
    let valid_token = issue_live_capability_token(
        state.lifecycle.as_ref(),
        &signing_key,
        &connector_id,
        TEST_CAPABILITY_ID,
        TEST_PRINCIPAL,
        TEST_OPERATION,
        &ZoneId::work(),
    )
    .await?;
    let app = test_router(state);

    let (_, preflight_denied): (_, PreflightResponse) = post_json_response(
        &app,
        "/rpc/preflight",
        preflight_request(connector_id.clone(), Some(valid_token.clone())),
        None,
    )
    .await?;
    assert!(!preflight_denied.allowed, "{preflight_denied:?}");
    assert!(
        preflight_denied.reason.as_deref().is_some_and(|reason| {
            reason.contains("zone envelope required") && reason.contains("allowed_zones")
        }),
        "{preflight_denied:?}"
    );

    let (_, simulate_denied): (_, HostSimulateResponse) = post_json_response(
        &app,
        "/rpc/simulate",
        simulate_request(
            &connector_id,
            Some(valid_token),
            "simulate-empty-zone-envelope",
        ),
        None,
    )
    .await?;
    assert!(!simulate_denied.preflight_allowed, "{simulate_denied:?}");
    assert!(!simulate_denied.would_succeed, "{simulate_denied:?}");
    assert_eq!(simulate_denied.phase, SimulatePhase::PreflightOnly);
    assert!(
        simulate_denied
            .failure_reason
            .as_deref()
            .is_some_and(|reason| {
                reason.contains("zone envelope required") && reason.contains("allowed_zones")
            }),
        "{simulate_denied:?}"
    );

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn conformance_simulate_surface_covers_allow_missing_capability_and_principal_mismatch()
-> TestResult<()> {
    let connector_id = route_test_connector_id("simulate-surface");
    let signing_key = Ed25519SigningKey::generate();
    let state = test_state(connector_id.clone(), &signing_key);
    let valid_token = issue_live_capability_token(
        state.lifecycle.as_ref(),
        &signing_key,
        &connector_id,
        TEST_CAPABILITY_ID,
        TEST_PRINCIPAL,
        TEST_OPERATION,
        &ZoneId::work(),
    )
    .await?;
    let app = test_router(state);

    let (status, allowed): (_, HostSimulateResponse) = post_json_response(
        &app,
        "/rpc/simulate",
        simulate_request(&connector_id, Some(valid_token.clone()), "simulate-allowed"),
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert!(allowed.preflight_allowed, "{allowed:?}");
    assert!(allowed.would_succeed, "{allowed:?}");
    assert_eq!(allowed.phase, SimulatePhase::ConnectorReached);
    assert!(allowed.failure_reason.is_none(), "{allowed:?}");
    assert_eq!(allowed.receipt.phase, SimulatePhase::ConnectorReached);
    assert!(allowed.receipt.would_succeed);

    let (_, missing_capability): (_, HostSimulateResponse) = post_json_response(
        &app,
        "/rpc/simulate",
        simulate_request(&connector_id, None, "simulate-missing-cap"),
        None,
    )
    .await?;
    assert!(
        !missing_capability.preflight_allowed,
        "{missing_capability:?}"
    );
    assert!(!missing_capability.would_succeed, "{missing_capability:?}");
    assert_eq!(missing_capability.phase, SimulatePhase::PreflightOnly);
    assert!(
        missing_capability
            .failure_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("capability token is required")),
        "{missing_capability:?}"
    );
    assert_eq!(
        missing_capability.receipt.phase,
        SimulatePhase::PreflightOnly
    );
    assert!(!missing_capability.receipt.would_succeed);

    let (_, forged_principal): (_, HostSimulateResponse) = post_json_response(
        &app,
        "/rpc/simulate",
        simulate_request(
            &connector_id,
            Some(valid_token),
            "simulate-forged-principal",
        ),
        Some(principal_header(TEST_FORGED_PRINCIPAL)),
    )
    .await?;
    assert!(!forged_principal.preflight_allowed, "{forged_principal:?}");
    assert!(!forged_principal.would_succeed, "{forged_principal:?}");
    assert_eq!(forged_principal.phase, SimulatePhase::PreflightOnly);
    assert!(
        forged_principal
            .failure_reason
            .as_deref()
            .is_some_and(|reason| reason.contains(TEST_FORGED_PRINCIPAL)),
        "{forged_principal:?}"
    );
    assert_eq!(forged_principal.receipt.phase, SimulatePhase::PreflightOnly);
    assert!(!forged_principal.receipt.would_succeed);

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn conformance_host_surfaces_fail_closed_on_zone_policy_capability_deny() -> TestResult<()> {
    let connector_id = route_test_connector_id("policy-denied-surface");
    let signing_key = Ed25519SigningKey::generate();
    let state = test_state(connector_id.clone(), &signing_key);
    let valid_token = issue_live_capability_token(
        state.lifecycle.as_ref(),
        &signing_key,
        &connector_id,
        TEST_CAPABILITY_ID,
        TEST_PRINCIPAL,
        TEST_OPERATION,
        &ZoneId::work(),
    )
    .await?;
    deny_test_capability_in_work_zone(&state).await;
    let app = test_router(state);

    let (_, preflight_denied): (_, PreflightResponse) = post_json_response(
        &app,
        "/rpc/preflight",
        preflight_request(connector_id.clone(), Some(valid_token.clone())),
        None,
    )
    .await?;
    assert!(!preflight_denied.allowed, "{preflight_denied:?}");
    assert!(
        preflight_denied.reason.as_deref().is_some_and(|reason| {
            reason.contains("policy denied live request")
                && reason.contains("zone_policy.capability_denied")
        }),
        "{preflight_denied:?}"
    );

    let (_, simulate_denied): (_, HostSimulateResponse) = post_json_response(
        &app,
        "/rpc/simulate",
        simulate_request(
            &connector_id,
            Some(valid_token),
            "simulate-zone-policy-capability-denied",
        ),
        None,
    )
    .await?;
    assert!(!simulate_denied.preflight_allowed, "{simulate_denied:?}");
    assert!(!simulate_denied.would_succeed, "{simulate_denied:?}");
    assert_eq!(simulate_denied.phase, SimulatePhase::PreflightOnly);
    assert!(
        simulate_denied
            .failure_reason
            .as_deref()
            .is_some_and(|reason| {
                reason.contains("policy denied live request")
                    && reason.contains("zone_policy.capability_denied")
            }),
        "{simulate_denied:?}"
    );
    assert_eq!(simulate_denied.receipt.phase, SimulatePhase::PreflightOnly);
    assert!(!simulate_denied.receipt.would_succeed);

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn conformance_host_surfaces_fail_closed_on_zone_policy_principal_deny() -> TestResult<()> {
    let connector_id = route_test_connector_id("principal-denied-surface");
    let signing_key = Ed25519SigningKey::generate();
    let state = test_state(connector_id.clone(), &signing_key);
    let valid_token = issue_live_capability_token(
        state.lifecycle.as_ref(),
        &signing_key,
        &connector_id,
        TEST_CAPABILITY_ID,
        TEST_PRINCIPAL,
        TEST_OPERATION,
        &ZoneId::work(),
    )
    .await?;
    deny_test_principal_in_work_zone(&state).await;
    let app = test_router(state);

    let (_, preflight_denied): (_, PreflightResponse) = post_json_response(
        &app,
        "/rpc/preflight",
        preflight_request(connector_id.clone(), Some(valid_token.clone())),
        None,
    )
    .await?;
    assert!(!preflight_denied.allowed, "{preflight_denied:?}");
    assert!(
        preflight_denied.reason.as_deref().is_some_and(|reason| {
            reason.contains("policy denied live request")
                && reason.contains("zone_policy.principal_denied")
        }),
        "{preflight_denied:?}"
    );

    let (_, simulate_denied): (_, HostSimulateResponse) = post_json_response(
        &app,
        "/rpc/simulate",
        simulate_request(
            &connector_id,
            Some(valid_token),
            "simulate-zone-policy-principal-denied",
        ),
        None,
    )
    .await?;
    assert!(!simulate_denied.preflight_allowed, "{simulate_denied:?}");
    assert!(!simulate_denied.would_succeed, "{simulate_denied:?}");
    assert_eq!(simulate_denied.phase, SimulatePhase::PreflightOnly);
    assert!(
        simulate_denied
            .failure_reason
            .as_deref()
            .is_some_and(|reason| {
                reason.contains("policy denied live request")
                    && reason.contains("zone_policy.principal_denied")
            }),
        "{simulate_denied:?}"
    );
    assert_eq!(simulate_denied.receipt.phase, SimulatePhase::PreflightOnly);
    assert!(!simulate_denied.receipt.would_succeed);

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn conformance_host_surfaces_fail_closed_on_zone_policy_connector_deny() -> TestResult<()> {
    let connector_id = route_test_connector_id("connector-denied-surface");
    let signing_key = Ed25519SigningKey::generate();
    let state = test_state(connector_id.clone(), &signing_key);
    let valid_token = issue_live_capability_token(
        state.lifecycle.as_ref(),
        &signing_key,
        &connector_id,
        TEST_CAPABILITY_ID,
        TEST_PRINCIPAL,
        TEST_OPERATION,
        &ZoneId::work(),
    )
    .await?;
    deny_test_connector_in_work_zone(&state, &connector_id).await;
    let app = test_router(state);

    let (_, preflight_denied): (_, PreflightResponse) = post_json_response(
        &app,
        "/rpc/preflight",
        preflight_request(connector_id.clone(), Some(valid_token.clone())),
        None,
    )
    .await?;
    assert!(!preflight_denied.allowed, "{preflight_denied:?}");
    assert!(
        preflight_denied.reason.as_deref().is_some_and(|reason| {
            reason.contains("policy denied live request")
                && reason.contains("zone_policy.connector_denied")
        }),
        "{preflight_denied:?}"
    );

    let (_, simulate_denied): (_, HostSimulateResponse) = post_json_response(
        &app,
        "/rpc/simulate",
        simulate_request(
            &connector_id,
            Some(valid_token),
            "simulate-zone-policy-connector-denied",
        ),
        None,
    )
    .await?;
    assert!(!simulate_denied.preflight_allowed, "{simulate_denied:?}");
    assert!(!simulate_denied.would_succeed, "{simulate_denied:?}");
    assert_eq!(simulate_denied.phase, SimulatePhase::PreflightOnly);
    assert!(
        simulate_denied
            .failure_reason
            .as_deref()
            .is_some_and(|reason| {
                reason.contains("policy denied live request")
                    && reason.contains("zone_policy.connector_denied")
            }),
        "{simulate_denied:?}"
    );
    assert_eq!(simulate_denied.receipt.phase, SimulatePhase::PreflightOnly);
    assert!(!simulate_denied.receipt.would_succeed);

    Ok(())
}
