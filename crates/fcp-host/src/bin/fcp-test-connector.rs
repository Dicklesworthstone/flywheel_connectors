//! Minimal FCP connector binary for subprocess integration tests.
//!
//! This connector is intentionally simple and deterministic. It implements the
//! JSON-RPC loop used by other connectors and supports configure/handshake/
//! health/introspect/invoke/simulate so host integration tests can exercise
//! real subprocess flows without external dependencies.

#![forbid(unsafe_code)]

use std::io::{BufRead, Write};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use fcp_host::ConnectorArchetype;
use fcp_kernel::{
    AgentHint, ApprovalMode, AuthCaps, ConnectorId, EventCaps, FcpError, HandshakeRequest,
    HandshakeResponse, HealthSnapshot, HealthState, IdempotencyClass, Introspection, InvokeRequest,
    InvokeResponse, OperationId, OperationInfo, SelfCheckReport, SessionId, ShutdownRequest,
    SimulateRequest, SimulateResponse,
};
use fcp_prelude::{CapabilityId, OAuthConfig, ObjectId, RiskLevel, SafetyTier, ZoneId};
use serde_json::json;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FixtureArchetype {
    Unknown,
    RequestResponse,
    Streaming,
    Bidirectional,
    Polling,
    Webhook,
}

impl FixtureArchetype {
    fn from_env_value(value: Option<&str>) -> Self {
        match value {
            Some("request_response" | "request-response" | "requestresponse") => {
                Self::RequestResponse
            }
            Some("streaming") => Self::Streaming,
            Some("bidirectional") => Self::Bidirectional,
            Some("polling") => Self::Polling,
            Some("webhook") => Self::Webhook,
            _ => Self::Unknown,
        }
    }

    fn from_env() -> Self {
        Self::from_env_value(
            std::env::var("FCP_TEST_CONNECTOR_ARCHETYPE")
                .ok()
                .as_deref(),
        )
    }

    const fn as_env(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::RequestResponse => "request_response",
            Self::Streaming => "streaming",
            Self::Bidirectional => "bidirectional",
            Self::Polling => "polling",
            Self::Webhook => "webhook",
        }
    }

    const fn connector_archetype(self) -> ConnectorArchetype {
        match self {
            Self::Unknown => ConnectorArchetype::Unknown,
            Self::RequestResponse => ConnectorArchetype::RequestResponse,
            Self::Streaming => ConnectorArchetype::Streaming,
            Self::Bidirectional => ConnectorArchetype::Bidirectional,
            Self::Polling => ConnectorArchetype::Polling,
            Self::Webhook => ConnectorArchetype::Webhook,
        }
    }

    const fn operation_id(self) -> &'static str {
        match self {
            Self::Unknown | Self::RequestResponse => "test.echo",
            Self::Streaming => "test.subscribe",
            Self::Bidirectional => "test.send",
            Self::Polling => "test.poll",
            Self::Webhook => "test.receive",
        }
    }

    const fn capability_id(self) -> &'static str {
        match self {
            Self::Unknown | Self::RequestResponse => "cap.test.echo",
            Self::Streaming => "cap.test.subscribe",
            Self::Bidirectional => "cap.test.send",
            Self::Polling => "cap.test.poll",
            Self::Webhook => "cap.test.receive",
        }
    }

    const fn summary(self) -> &'static str {
        match self {
            Self::Unknown => "Exercise generic connector behavior",
            Self::RequestResponse => "Echo request payloads",
            Self::Streaming => "Subscribe to a live event feed",
            Self::Bidirectional => "Send a chat-style message",
            Self::Polling => "Poll for the next available item",
            Self::Webhook => "Receive and validate inbound webhook payloads",
        }
    }

    const fn description(self) -> &'static str {
        match self {
            Self::Unknown => "Generic subprocess fixture with unspecified archetype metadata.",
            Self::RequestResponse => "Returns the input payload as output.",
            Self::Streaming => "Represents a long-lived streaming subscription fixture.",
            Self::Bidirectional => "Represents a bidirectional chat-style connector fixture.",
            Self::Polling => "Represents a cursor-based polling connector fixture.",
            Self::Webhook => "Represents a webhook receiver fixture with provenance checks.",
        }
    }

    fn event_caps(self) -> Option<EventCaps> {
        match self {
            Self::Streaming => Some(EventCaps {
                streaming: true,
                replay: true,
                min_buffer_events: 32,
                requires_ack: false,
            }),
            Self::Bidirectional => Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: 16,
                requires_ack: true,
            }),
            Self::Unknown | Self::Polling | Self::Webhook | Self::RequestResponse => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FixtureAuthMode {
    None,
    OAuth,
    MultiProfileTenant,
}

impl FixtureAuthMode {
    fn from_env() -> Self {
        match std::env::var("FCP_TEST_CONNECTOR_AUTH_MODE")
            .ok()
            .as_deref()
        {
            Some("oauth") => Self::OAuth,
            Some("multi_profile_tenant") => Self::MultiProfileTenant,
            _ => Self::None,
        }
    }

    const fn as_env(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::OAuth => "oauth",
            Self::MultiProfileTenant => "multi_profile_tenant",
        }
    }

    fn auth_caps(self) -> Option<AuthCaps> {
        match self {
            Self::None => None,
            Self::OAuth => Some(AuthCaps {
                methods: vec!["oauth2".to_string()],
                oauth: Some(OAuthConfig {
                    authorize_url: "https://fixtures.example.test/oauth/authorize".to_string(),
                    token_url: "https://fixtures.example.test/oauth/token".to_string(),
                    scopes: vec!["fixtures.read".to_string()],
                }),
            }),
            Self::MultiProfileTenant => Some(AuthCaps {
                methods: vec!["oauth2".to_string(), "profile_switch".to_string()],
                oauth: Some(OAuthConfig {
                    authorize_url: "https://fixtures.example.test/oauth/authorize".to_string(),
                    token_url: "https://fixtures.example.test/oauth/token".to_string(),
                    scopes: vec![
                        "fixtures.read".to_string(),
                        "fixtures.write".to_string(),
                        "tenant.admin".to_string(),
                    ],
                }),
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FixtureHealthMode {
    Ready,
    Degraded,
    Error,
}

impl FixtureHealthMode {
    fn from_env() -> Self {
        match std::env::var("FCP_TEST_CONNECTOR_HEALTH").ok().as_deref() {
            Some("degraded") => Self::Degraded,
            Some("error") => Self::Error,
            _ => Self::Ready,
        }
    }

    const fn as_env(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Degraded => "degraded",
            Self::Error => "error",
        }
    }

    fn snapshot(
        self,
        uptime_ms: u64,
        configured: bool,
        profile: &TestConnectorProfile,
    ) -> HealthSnapshot {
        let status = match self {
            Self::Ready => HealthState::Ready,
            Self::Degraded => HealthState::Degraded {
                reason: "fixture degraded".to_string(),
            },
            Self::Error => HealthState::Error {
                reason: "fixture unavailable".to_string(),
            },
        };
        HealthSnapshot {
            status,
            uptime_ms,
            load: None,
            details: Some(json!({
                "configured": configured,
                "archetype": profile.archetype.as_env(),
                "runtime_archetype": profile.archetype.connector_archetype(),
                "auth_mode": profile.auth_mode.as_env(),
                "health_mode": profile.health_mode.as_env(),
                "operation_mode": profile.operation_mode.as_env(),
                "simulate_mode": profile.simulate_mode.as_env(),
                "artifact_policy": profile.artifact_policy.as_env(),
            })),
            rate_limit: None,
        }
    }

    fn self_check(self) -> SelfCheckReport {
        match self {
            Self::Ready => SelfCheckReport::ok(),
            Self::Degraded => {
                SelfCheckReport::degraded("fixture_degraded", "fixture running in degraded mode")
            }
            Self::Error => {
                SelfCheckReport::failed("fixture_unavailable", "fixture failed readiness checks")
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FixtureOperationMode {
    Reversible,
    Irreversible,
}

impl FixtureOperationMode {
    fn from_env() -> Self {
        match std::env::var("FCP_TEST_CONNECTOR_OPERATION_MODE")
            .ok()
            .as_deref()
        {
            Some("irreversible") => Self::Irreversible,
            _ => Self::Reversible,
        }
    }

    const fn as_env(self) -> &'static str {
        match self {
            Self::Reversible => "reversible",
            Self::Irreversible => "irreversible",
        }
    }

    const fn risk_level(self) -> RiskLevel {
        match self {
            Self::Reversible => RiskLevel::Low,
            Self::Irreversible => RiskLevel::Medium,
        }
    }

    const fn safety_tier(self) -> SafetyTier {
        match self {
            Self::Reversible => SafetyTier::Safe,
            Self::Irreversible => SafetyTier::Risky,
        }
    }

    const fn idempotency(self) -> IdempotencyClass {
        match self {
            Self::Reversible => IdempotencyClass::BestEffort,
            Self::Irreversible => IdempotencyClass::None,
        }
    }

    const fn approval_mode(self) -> ApprovalMode {
        match self {
            Self::Reversible => ApprovalMode::None,
            Self::Irreversible => ApprovalMode::Interactive,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FixtureSimulateMode {
    Allowed,
    Denied,
}

impl FixtureSimulateMode {
    fn from_env() -> Self {
        match std::env::var("FCP_TEST_CONNECTOR_SIMULATE_MODE")
            .ok()
            .as_deref()
        {
            Some("denied") => Self::Denied,
            _ => Self::Allowed,
        }
    }

    const fn as_env(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FixtureArtifactPolicy {
    Echo,
    RejectFake,
}

impl FixtureArtifactPolicy {
    fn from_env() -> Self {
        match std::env::var("FCP_TEST_CONNECTOR_ARTIFACT_POLICY")
            .ok()
            .as_deref()
        {
            Some("reject_fake") => Self::RejectFake,
            _ => Self::Echo,
        }
    }

    const fn as_env(self) -> &'static str {
        match self {
            Self::Echo => "echo",
            Self::RejectFake => "reject_fake",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FixtureHandshakeMode {
    Accepted,
    Rejected,
    BadNonce,
}

impl FixtureHandshakeMode {
    fn from_env() -> Self {
        match std::env::var("FCP_TEST_CONNECTOR_HANDSHAKE_MODE")
            .ok()
            .as_deref()
        {
            Some("rejected") => Self::Rejected,
            Some("bad_nonce") => Self::BadNonce,
            _ => Self::Accepted,
        }
    }
}

#[derive(Clone, Debug)]
struct TestConnectorProfile {
    archetype: FixtureArchetype,
    auth_mode: FixtureAuthMode,
    health_mode: FixtureHealthMode,
    operation_mode: FixtureOperationMode,
    simulate_mode: FixtureSimulateMode,
    artifact_policy: FixtureArtifactPolicy,
    handshake_mode: FixtureHandshakeMode,
    require_handshake: bool,
}

impl TestConnectorProfile {
    fn from_env() -> Self {
        Self {
            archetype: FixtureArchetype::from_env(),
            auth_mode: FixtureAuthMode::from_env(),
            health_mode: FixtureHealthMode::from_env(),
            operation_mode: FixtureOperationMode::from_env(),
            simulate_mode: FixtureSimulateMode::from_env(),
            artifact_policy: FixtureArtifactPolicy::from_env(),
            handshake_mode: FixtureHandshakeMode::from_env(),
            require_handshake: std::env::var("FCP_TEST_CONNECTOR_REQUIRE_HANDSHAKE")
                .is_ok_and(|value| value == "1"),
        }
    }

    fn operation_info(&self) -> Result<OperationInfo, FcpError> {
        Ok(OperationInfo {
            id: OperationId::from_static(self.archetype.operation_id()),
            summary: self.archetype.summary().to_string(),
            description: Some(self.archetype.description().to_string()),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::new(self.archetype.capability_id()).map_err(|err| {
                FcpError::Internal {
                    message: format!("Invalid capability id: {err}"),
                }
            })?,
            risk_level: self.operation_mode.risk_level(),
            safety_tier: self.operation_mode.safety_tier(),
            idempotency: self.operation_mode.idempotency(),
            ai_hints: AgentHint {
                when_to_use: format!(
                    "Use for {} subprocess integration testing.",
                    self.archetype.as_env()
                ),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(self.operation_mode.approval_mode()),
        })
    }
}

struct TestConnector {
    id: ConnectorId,
    start_time: Instant,
    configured: bool,
    handshaken_zone: Option<ZoneId>,
    handshake_count: Mutex<u32>,
    profile: TestConnectorProfile,
}

impl TestConnector {
    fn new(id: ConnectorId) -> Self {
        Self {
            id,
            start_time: Instant::now(),
            configured: false,
            handshaken_zone: None,
            handshake_count: Mutex::new(0),
            profile: TestConnectorProfile::from_env(),
        }
    }

    fn handshake_count(&self) -> u32 {
        *self
            .handshake_count
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn handle_configure(
        &mut self,
        _params: serde_json::Value,
    ) -> Result<serde_json::Value, FcpError> {
        self.configured = true;
        self.handshaken_zone = None;
        Ok(json!({ "status": "ok" }))
    }

    fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, FcpError> {
        *self
            .handshake_count
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) += 1;

        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|err| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid handshake request: {err}"),
            })?;

        let (status, nonce, handshaken) = match self.profile.handshake_mode {
            FixtureHandshakeMode::Accepted => ("accepted".to_string(), req.nonce, true),
            FixtureHandshakeMode::Rejected => ("rejected".to_string(), req.nonce, false),
            FixtureHandshakeMode::BadNonce => {
                let mut nonce = req.nonce;
                nonce[0] ^= 0xFF;
                ("accepted".to_string(), nonce, true)
            }
        };
        let response = HandshakeResponse {
            status,
            capabilities_granted: Vec::new(),
            session_id: SessionId::new(),
            manifest_hash: "sha256:fcp-test-connector".to_string(),
            nonce,
            event_caps: self.profile.archetype.event_caps(),
            auth_caps: self.profile.auth_mode.auth_caps(),
            op_catalog_hash: None,
        };
        self.handshaken_zone = handshaken.then_some(req.zone.clone());

        serde_json::to_value(response).map_err(|err| FcpError::Internal {
            message: format!("Failed to serialize handshake response: {err}"),
        })
    }

    fn handle_health(&self) -> Result<serde_json::Value, FcpError> {
        let snapshot = self.profile.health_mode.snapshot(
            self.start_time.elapsed().as_millis() as u64,
            self.configured,
            &self.profile,
        );

        serde_json::to_value(snapshot).map_err(|err| FcpError::Internal {
            message: format!("Failed to serialize health snapshot: {err}"),
        })
    }

    fn handle_self_check(&self) -> Result<serde_json::Value, FcpError> {
        let mut report = self.profile.health_mode.self_check();
        let mut details = report.details.take().unwrap_or_else(|| json!({}));
        if let Some(object) = details.as_object_mut() {
            object.insert("handshake_count".to_string(), json!(self.handshake_count()));
        } else {
            details = json!({
                "handshake_count": self.handshake_count(),
                "report_details": details,
            });
        }
        report.details = Some(details);
        serde_json::to_value(report).map_err(|err| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {err}"),
        })
    }

    fn handle_introspect(&self) -> Result<serde_json::Value, FcpError> {
        let introspection = Introspection {
            operations: vec![self.profile.operation_info()?],
            events: Vec::new(),
            resource_types: Vec::new(),
            auth_caps: self.profile.auth_mode.auth_caps(),
            event_caps: self.profile.archetype.event_caps(),
        };

        serde_json::to_value(introspection).map_err(|err| FcpError::Internal {
            message: format!("Failed to serialize introspection: {err}"),
        })
    }

    fn handle_invoke(&self, params: serde_json::Value) -> Result<serde_json::Value, FcpError> {
        let req: InvokeRequest =
            serde_json::from_value(params).map_err(|err| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid invoke request: {err}"),
            })?;

        if self.profile.require_handshake {
            let Some(handshaken_zone) = self.handshaken_zone.as_ref() else {
                return Err(FcpError::NotHandshaken);
            };
            if handshaken_zone != &req.zone_id {
                return Err(FcpError::InvalidRequest {
                    code: 1007,
                    message: format!(
                        "Zone mismatch: handshaken for {}, got {}",
                        handshaken_zone.as_str(),
                        req.zone_id.as_str()
                    ),
                });
            }
        }

        if req.connector_id != self.id {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: format!(
                    "Connector id mismatch: expected {}, got {}",
                    self.id.as_str(),
                    req.connector_id.as_str()
                ),
            });
        }

        if req.operation.as_str() != self.profile.archetype.operation_id() {
            return Err(FcpError::InvalidRequest {
                code: 1006,
                message: format!(
                    "Operation mismatch: expected {}, got {}",
                    self.profile.archetype.operation_id(),
                    req.operation.as_str()
                ),
            });
        }

        if self.profile.artifact_policy == FixtureArtifactPolicy::RejectFake
            && req
                .input
                .get("artifact_provenance")
                .and_then(serde_json::Value::as_str)
                == Some("fake")
        {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: "fake artifact provenance rejected".to_string(),
            });
        }

        if let Some(delay_ms) = req
            .input
            .get("delay_ms")
            .and_then(serde_json::Value::as_u64)
        {
            thread::sleep(Duration::from_millis(delay_ms));
        }

        let mut response = InvokeResponse::ok(
            req.id,
            json!({
                "echo": req.input,
                "archetype": self.profile.archetype.as_env(),
                "auth_mode": self.profile.auth_mode.as_env(),
                "operation_mode": self.profile.operation_mode.as_env(),
            }),
        );
        response.receipt_id = Some(ObjectId::from_unscoped_bytes(b"test-receipt"));

        serde_json::to_value(response).map_err(|err| FcpError::Internal {
            message: format!("Failed to serialize invoke response: {err}"),
        })
    }

    fn handle_simulate(&self, params: serde_json::Value) -> Result<serde_json::Value, FcpError> {
        let req: SimulateRequest =
            serde_json::from_value(params).map_err(|err| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid simulate request: {err}"),
            })?;

        if self.profile.require_handshake {
            let Some(handshaken_zone) = self.handshaken_zone.as_ref() else {
                return Err(FcpError::NotHandshaken);
            };
            if handshaken_zone != &req.zone_id {
                return Err(FcpError::InvalidRequest {
                    code: 1007,
                    message: format!(
                        "Zone mismatch: handshaken for {}, got {}",
                        handshaken_zone.as_str(),
                        req.zone_id.as_str()
                    ),
                });
            }
        }

        if req.connector_id != self.id {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: format!(
                    "Connector id mismatch: expected {}, got {}",
                    self.id.as_str(),
                    req.connector_id.as_str()
                ),
            });
        }

        if req.operation.as_str() != self.profile.archetype.operation_id() {
            return Err(FcpError::InvalidRequest {
                code: 1006,
                message: format!(
                    "Operation mismatch: expected {}, got {}",
                    self.profile.archetype.operation_id(),
                    req.operation.as_str()
                ),
            });
        }

        let response = match self.profile.simulate_mode {
            FixtureSimulateMode::Allowed => SimulateResponse::allowed(req.id),
            FixtureSimulateMode::Denied => SimulateResponse::denied(
                req.id,
                "simulate disabled by fixture profile",
                "FCP-TEST-SIMULATE",
            ),
        };
        serde_json::to_value(response).map_err(|err| FcpError::Internal {
            message: format!("Failed to serialize simulate response: {err}"),
        })
    }

    fn handle_shutdown(&self, params: serde_json::Value) -> Result<serde_json::Value, FcpError> {
        let _req: ShutdownRequest =
            serde_json::from_value(params).map_err(|err| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid shutdown request: {err}"),
            })?;
        Ok(json!({ "status": "ok" }))
    }
}

fn default_connector_id() -> ConnectorId {
    let default_id = "fcp.test.echo:utility:1.0.0";
    let id = std::env::var("FCP_TEST_CONNECTOR_ID").unwrap_or_else(|_| default_id.to_string());
    id.parse()
        .unwrap_or_else(|_| ConnectorId::from_static(default_id))
}

fn handle_message(connector: &mut TestConnector, message: &str) -> serde_json::Value {
    let request: serde_json::Value = match serde_json::from_str(message) {
        Ok(value) => value,
        Err(err) => {
            return json!({
                "error": {
                    "code": "FCP-1001",
                    "message": format!("Invalid JSON: {err}")
                }
            });
        }
    };

    let method = request.get("method").and_then(|v| v.as_str()).unwrap_or("");
    let id = request.get("id").cloned();
    let params = request.get("params").cloned().unwrap_or(json!({}));

    let result = match method {
        "configure" => connector.handle_configure(params),
        "handshake" => connector.handle_handshake(params),
        "health" => connector.handle_health(),
        "self_check" => connector.handle_self_check(),
        "introspect" => connector.handle_introspect(),
        "invoke" => connector.handle_invoke(params),
        "simulate" => connector.handle_simulate(params),
        "shutdown" => connector.handle_shutdown(params),
        _ => Err(FcpError::InvalidRequest {
            code: 1002,
            message: format!("Unknown method: {method}"),
        }),
    };

    match result {
        Ok(value) => {
            let mut response = json!({
                "jsonrpc": "2.0",
                "result": value,
            });
            if let Some(id) = id {
                response["id"] = id;
            }
            response
        }
        Err(err) => {
            let err_response = err.to_response();
            let mut response = json!({
                "jsonrpc": "2.0",
                "error": err_response,
            });
            if let Some(id) = id {
                response["id"] = id;
            }
            response
        }
    }
}

fn run_loop(mut connector: TestConnector) -> std::io::Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let response = handle_message(&mut connector, &line);
        let response_json = serde_json::to_string(&response)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
        writeln!(stdout, "{response_json}")?;
        stdout.flush()?;
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let connector_id = default_connector_id();
    let connector = TestConnector::new(connector_id);
    run_loop(connector)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_kernel::RequestId;
    use fcp_prelude::{CapabilityToken, ZoneId};

    fn test_profile(require_handshake: bool) -> TestConnectorProfile {
        TestConnectorProfile {
            archetype: FixtureArchetype::Unknown,
            auth_mode: FixtureAuthMode::None,
            health_mode: FixtureHealthMode::Ready,
            operation_mode: FixtureOperationMode::Reversible,
            simulate_mode: FixtureSimulateMode::Allowed,
            artifact_policy: FixtureArtifactPolicy::Echo,
            handshake_mode: FixtureHandshakeMode::Accepted,
            require_handshake,
        }
    }

    fn simulate_request(connector_id: &ConnectorId, operation: &str) -> serde_json::Value {
        serde_json::to_value(SimulateRequest {
            r#type: "simulate".into(),
            id: RequestId::new("sim_fixture"),
            connector_id: connector_id.clone(),
            operation: OperationId::new(operation).expect("valid operation id"),
            zone_id: ZoneId::work(),
            input: serde_json::json!({}),
            capability_token: CapabilityToken::test_token(),
            estimate_cost: false,
            check_availability: false,
            context: None,
            correlation_id: None,
        })
        .expect("simulate request should serialize")
    }

    fn handshake_request() -> serde_json::Value {
        serde_json::to_value(HandshakeRequest {
            protocol_version: "1.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0_u8; 32],
            nonce: [7_u8; 32],
            capabilities_requested: Vec::new(),
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        })
        .expect("handshake request should serialize")
    }

    #[test]
    fn unset_archetype_env_defaults_to_unknown() {
        assert_eq!(
            FixtureArchetype::from_env_value(None),
            FixtureArchetype::Unknown
        );
    }

    #[test]
    fn request_response_env_remains_explicit() {
        assert_eq!(
            FixtureArchetype::from_env_value(Some("request_response")),
            FixtureArchetype::RequestResponse
        );
    }

    #[test]
    fn unknown_archetype_preserves_generic_echo_operation_metadata() {
        let profile = TestConnectorProfile {
            archetype: FixtureArchetype::Unknown,
            auth_mode: FixtureAuthMode::None,
            health_mode: FixtureHealthMode::Ready,
            operation_mode: FixtureOperationMode::Reversible,
            simulate_mode: FixtureSimulateMode::Allowed,
            artifact_policy: FixtureArtifactPolicy::Echo,
            handshake_mode: FixtureHandshakeMode::from_env(),
            require_handshake: false,
        };
        let operation = profile
            .operation_info()
            .expect("operation info should build");

        assert_eq!(
            profile.archetype.connector_archetype(),
            ConnectorArchetype::Unknown
        );
        assert_eq!(profile.archetype.as_env(), "unknown");
        assert_eq!(operation.id.as_str(), "test.echo");
        assert_eq!(operation.capability.as_str(), "cap.test.echo");
        assert_eq!(operation.summary, "Exercise generic connector behavior");
        assert!(profile.archetype.event_caps().is_none());
    }

    #[test]
    fn simulate_requires_handshake_when_profile_demands_it() {
        let connector_id = ConnectorId::from_static("fcp.test.simulate:utility:1.0.0");
        let connector = TestConnector {
            id: connector_id.clone(),
            start_time: Instant::now(),
            configured: true,
            handshaken_zone: None,
            handshake_count: Mutex::new(0),
            profile: test_profile(true),
        };

        let err = connector
            .handle_simulate(simulate_request(&connector_id, "test.echo"))
            .expect_err("simulate should require handshake");
        assert!(matches!(err, FcpError::NotHandshaken));
    }

    #[test]
    fn simulate_rejects_operation_mismatch() {
        let connector_id = ConnectorId::from_static("fcp.test.simulate:utility:1.0.0");
        let connector = TestConnector {
            id: connector_id.clone(),
            start_time: Instant::now(),
            configured: true,
            handshaken_zone: Some(ZoneId::work()),
            handshake_count: Mutex::new(0),
            profile: test_profile(false),
        };

        let err = connector
            .handle_simulate(simulate_request(&connector_id, "test.other"))
            .expect_err("simulate should reject mismatched operation");
        assert!(matches!(err, FcpError::InvalidRequest { code: 1006, .. }));
    }

    #[test]
    fn handshake_counter_probe_tracks_calls_and_self_check_exposes_it() {
        let connector_id = ConnectorId::from_static("fcp.test.handshake:utility:1.0.0");
        let mut connector = TestConnector {
            id: connector_id,
            start_time: Instant::now(),
            configured: true,
            handshaken_zone: None,
            handshake_count: Mutex::new(0),
            profile: test_profile(true),
        };

        assert_eq!(connector.handshake_count(), 0);
        connector
            .handle_handshake(handshake_request())
            .expect("handshake should succeed");
        connector
            .handle_handshake(handshake_request())
            .expect("second handshake should succeed");
        assert_eq!(connector.handshake_count(), 2);

        let report: SelfCheckReport = serde_json::from_value(
            connector
                .handle_self_check()
                .expect("self-check should serialize"),
        )
        .expect("self-check response should deserialize");
        assert_eq!(
            report.details,
            Some(json!({
                "handshake_count": 2
            }))
        );
    }
}
