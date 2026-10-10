//! Authorized FCP process boundary for the MCP bridge.
//!
//! The provider connector is an operation implementation, not an authorization
//! boundary. Standalone transports must dispatch through this server. Handshake,
//! invoke and simulate use the canonical typed FCP requests; a caller-supplied
//! `operation_id` alone never authorizes an upstream MCP request.
//!
//! Configure/handshake are trusted host control-plane messages on the private
//! subprocess channel. Host policy, revocation, holder-proof and lease checks
//! remain required upstream; instance-bound verification here is defense in depth.

use std::time::{Duration, Instant};

use fcp_core::{BoundVerified, CapabilityToken, FcpError, FcpResult, HandshakeRequest,
    InvokeRequest, InvokeResponse, OperationId, RequestId, SimulateRequest, SimulateResponse};
use fcp_sdk::prelude::StandaloneSession;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

use crate::connector::McpBridgeConnector;

const MANIFEST: &str = include_str!("../manifest.toml");
const MAX_INVOKE_TIMEOUT: Duration = Duration::from_secs(120);

/// Owns the provider and its private-channel capability authority.
///
/// Construct once per standalone process and call [`Self::dispatch`] for every
/// message. Do not route untrusted invoke/simulate messages to the provider's
/// lower-level `handle_*` methods, which assume authorization has already run.
pub struct McpBridgeServer {
    connector: McpBridgeConnector,
    session: StandaloneSession,
    configured: bool,
}

impl McpBridgeServer {
    /// Construct the process boundary from the strictly validated manifest.
    pub fn new() -> FcpResult<Self> {
        Ok(Self {
            connector: McpBridgeConnector::new(),
            session: StandaloneSession::new(MANIFEST)?,
            configured: false,
        })
    }

    /// Dispatch a framing-validated request on the private host control channel.
    pub async fn dispatch(&mut self, method: &str, params: Value) -> FcpResult<Value> {
        match method {
            "configure" => {
                self.session.invalidate();
                self.configured = false;
                // Cancel and release the old client's runtime before replacing
                // credentials. A failed configure leaves no old live authority.
                self.connector.handle_shutdown(json!({})).await?;
                let result = self.connector.handle_configure(params).await?;
                self.configured = true;
                Ok(result)
            }
            "handshake" => self.handshake(params).await,
            "invoke" => self.invoke(params).await,
            "simulate" => self.simulate(params),
            "shutdown" => {
                self.session.invalidate();
                self.configured = false;
                self.connector.handle_shutdown(params).await
            }
            "health" => {
                let mut result = self.connector.handle_health().await?;
                result["configured"] = json!(self.configured);
                result["handshaken"] = json!(self.session.is_established());
                result["instance_id"] = json!(self.session.instance_id());
                result["status"] = json!(if !self.configured {
                    "unconfigured"
                } else if self.session.is_established() {
                    "healthy"
                } else {
                    "degraded"
                });
                Ok(result)
            }
            "doctor" => {
                let mut result = self.connector.handle_doctor().await?;
                if let Some(checks) = result.get_mut("checks").and_then(Value::as_array_mut) {
                    for check in checks {
                        if check["name"] == "handshake" {
                            check["passed"] = json!(self.session.is_established());
                            check["message"] = if self.session.is_established() {
                                Value::Null
                            } else {
                                json!("No negotiated capability authority")
                            };
                        }
                    }
                }
                result["status"] = json!(if !self.configured {
                    "unhealthy"
                } else if self.session.is_established() {
                    "healthy"
                } else {
                    "degraded"
                });
                Ok(result)
            }
            "self_check" => self.connector.handle_self_check().await,
            "introspect" => self.connector.handle_introspect().await,
            _ => Err(FcpError::InvalidRequest {
                code: 1002,
                message: "Unknown standalone FCP method".into(),
            }),
        }
    }

    async fn handshake(&mut self, params: Value) -> FcpResult<Value> {
        // Decode failures must invalidate the preceding handshake too.
        self.session.invalidate();
        if !self.configured {
            return Err(FcpError::NotConfigured);
        }
        let request: HandshakeRequest = decode(params, "Invalid FCP handshake request")?;
        let response = self.session.handshake(request)?;
        let mut result = encode(&response)?;
        let provider_handshake = self.connector.handle_handshake(json!({
            "session_id": result["session_id"].clone(),
        })).await;
        if let Err(error) = provider_handshake {
            self.session.invalidate();
            return Err(error);
        }
        // Host tokens must target this actual instance, not a requested guess.
        result["instance_id"] = json!(self.session.instance_id());
        result["connector_id"] = json!("fcp.mcp-bridge");
        result["protocol_version"] = json!("2.0");
        Ok(result)
    }

    fn check_ready(&self) -> FcpResult<()> {
        if !self.configured {
            Err(FcpError::NotConfigured)
        } else if !self.session.is_established() {
            Err(FcpError::NotHandshaken)
        } else {
            Ok(())
        }
    }

    async fn invoke(&self, params: Value) -> FcpResult<Value> {
        let started = Instant::now();
        self.check_ready()?;
        let request: InvokeRequest = decode(params, "Invalid FCP invoke request")?;
        validate_request(&request.r#type, "invoke", &request.id, &request.input)?;
        request.validate_idempotency_key().map_err(|_| invalid("Invalid idempotency key"))?;
        let resource_uris = resource_uris(&request.operation, &request.input)?;
        let witness = self.session.authorize(
            &request.connector_id, &request.zone_id, &request.operation,
            request.capability_token, &resource_uris,
        )?;
        let budget = request.deadline_ms.map(Duration::from_millis)
            .unwrap_or(MAX_INVOKE_TIMEOUT).min(MAX_INVOKE_TIMEOUT)
            .saturating_sub(started.elapsed());
        if budget.is_zero() {
            return Err(invalid("Invocation deadline elapsed before MCP dispatch"));
        }
        self.invoke_verified(witness, request.id, request.operation, request.input, budget).await
    }

    /// The only process-boundary path that can execute a provider operation.
    async fn invoke_verified(
        &self,
        _witness: CapabilityToken<BoundVerified>,
        id: RequestId,
        operation: OperationId,
        input: Value,
        budget: Duration,
    ) -> FcpResult<Value> {
        let result = await_invocation(self.connector.handle_invoke(json!({
            "operation_id": operation.as_str(),
            "input": input,
        })), budget).await?;
        encode(&InvokeResponse::ok(id, result))
    }

    fn simulate(&self, params: Value) -> FcpResult<Value> {
        self.check_ready()?;
        let request: SimulateRequest = decode(params, "Invalid FCP simulate request")?;
        validate_request(&request.r#type, "simulate", &request.id, &request.input)?;
        let resources = resource_uris(&request.operation, &request.input)?;
        let response = match self.session.authorize(
            &request.connector_id, &request.zone_id, &request.operation,
            request.capability_token, &resources,
        ) {
            Ok(_) => SimulateResponse::allowed(request.id),
            Err(error) => SimulateResponse::denied(request.id, error.to_string(), error.error_code()),
        };
        // Authorization simulation is local; it neither invokes a provider nor
        // fabricates availability, cost estimates or guarantees of API success.
        encode(&response)
    }
}

fn invalid(message: &str) -> FcpError {
    FcpError::InvalidRequest { code: 1003, message: message.to_owned() }
}

fn decode<T: DeserializeOwned>(value: Value, message: &str) -> FcpResult<T> {
    // Do not echo token bytes, credentials or arbitrary payloads in parse errors.
    serde_json::from_value(value).map_err(|_| invalid(message))
}

fn encode<T: Serialize>(value: &T) -> FcpResult<Value> {
    serde_json::to_value(value).map_err(|_| FcpError::Internal {
        message: "Failed to serialize FCP response".into(),
    })
}

fn validate_request(kind: &str, expected: &str, id: &RequestId, input: &Value) -> FcpResult<()> {
    if kind != expected || id.0.is_empty() || !input.is_object() {
        return Err(invalid("Invalid request type, request ID or operation input"));
    }
    Ok(())
}

fn resource_uris(operation: &OperationId, input: &Value) -> FcpResult<Vec<String>> {
    if operation.as_str() != "mcp.resources.read" {
        return Ok(Vec::new());
    }
    let uri = input.get("uri").and_then(Value::as_str)
        .filter(|uri| !uri.is_empty())
        .ok_or_else(|| invalid("mcp.resources.read requires a non-empty uri"))?;
    // Preserve the exact MCP resource identifier. This is not an egress URL,
    // and no link is resolved or fetched by the authorization layer.
    Ok(vec![uri.to_owned()])
}

fn interrupted_invoke() -> FcpError {
    FcpError::External {
        service: "mcp-bridge".into(),
        message: "MCP invocation interrupted after admission; outcome is unknown; reconcile external effects before retry".into(),
        status_code: None,
        retryable: false,
        retry_after: None,
    }
}

async fn await_invocation(
    future: impl std::future::Future<Output = FcpResult<Value>>,
    budget: Duration,
) -> FcpResult<Value> {
    fcp_async_core::time::timeout(budget, future).await.map_err(|_| interrupted_invoke())?
}

#[cfg(test)]
mod tests {
    use fcp_async_core::runtime::Builder;

    use super::*;

    macro_rules! run {
        ($future:expr) => {{
            let runtime = Builder::new_multi_thread().enable_all().build().unwrap();
            runtime.block_on($future)
        }};
    }

    fn handshake() -> Value {
        json!({
            "protocol_version": "2.0.0", "zone": "z:work",
            "host_public_key": vec![1_u8; 32], "nonce": vec![9_u8; 32],
            "capabilities_requested": ["mcp.tools.read", "mcp.tools.write", "mcp.resources.read",
                "mcp.prompts.read", "mcp.sampling.handle", "mcp.server.metrics"],
        })
    }

    async fn configured() -> McpBridgeServer {
        let mut server = McpBridgeServer::new().unwrap();
        server.dispatch("configure", json!({"mcp_url": "http://127.0.0.1:1"})).await.unwrap();
        server.dispatch("handshake", handshake()).await.unwrap();
        server
    }

    fn untrusted_invoke(operation: &str) -> Value {
        json!({
            "type": "invoke", "id": "request-1", "connector_id": "fcp.mcp-bridge",
            "operation": operation, "zone_id": "z:work", "input": {"uri": "urn:private"},
            "capability_token": CapabilityToken::test_token(),
        })
    }

    #[test]
    fn handshake_without_configuration_is_denied() {
        run!(async {
            let mut server = McpBridgeServer::new().unwrap();
            assert!(matches!(server.dispatch("handshake", handshake()).await, Err(FcpError::NotConfigured)));
            assert!(!server.session.is_established());
        });
    }

    #[test]
    fn canonical_handshake_returns_grants_nonce_and_actual_instance() {
        run!(async {
            let mut server = configured().await;
            let response = server.dispatch("handshake", handshake()).await.unwrap();
            assert_eq!(response["status"], "accepted");
            assert_eq!(response["nonce"], json!(vec![9_u8; 32]));
            assert_eq!(response["capabilities_granted"].as_array().unwrap().len(), 6);
            assert_eq!(response["instance_id"], json!(server.session.instance_id()));
            assert!(response["manifest_hash"].as_str().unwrap().starts_with("sha256:"));
        });
    }

    #[test]
    fn legacy_keyless_handshake_cannot_authorize_operations() {
        run!(async {
            let mut server = configured().await;
            assert!(server.dispatch("handshake", json!({"session_id": "claimed"})).await.is_err());
            let health = server.dispatch("health", json!({})).await.unwrap();
            assert_eq!(health["handshaken"], false);
            assert_eq!(health["status"], "degraded");
            assert!(matches!(server.dispatch("invoke", untrusted_invoke("mcp.tools.call")).await,
                Err(FcpError::NotHandshaken)));
        });
    }

    #[test]
    fn every_declared_operation_rejects_untyped_and_foreign_tokens_before_dispatch() {
        run!(async {
            let mut server = configured().await;
            let catalog = server.dispatch("introspect", json!({})).await.unwrap();
            let operations = catalog["operations"].as_array().unwrap();
            assert_eq!(operations.len(), 9);
            for operation in operations {
                let id = operation["id"].as_str().unwrap();
                assert!(server.dispatch("invoke", json!({"operation_id": id, "input": {}})).await.is_err());
                assert!(server.dispatch("invoke", untrusted_invoke(id)).await.is_err());
            }
            let health = server.dispatch("health", json!({})).await.unwrap();
            assert_eq!(health["requests"], 0);
        });
    }

    #[test]
    fn unsuccessful_reconfiguration_revokes_authority_and_old_credentials() {
        run!(async {
            let mut server = configured().await;
            assert!(server.dispatch("configure", json!({})).await.is_err());
            let health = server.dispatch("health", json!({})).await.unwrap();
            assert_eq!(health["configured"], false);
            assert_eq!(health["handshaken"], false);
            assert_eq!(health["status"], "unconfigured");
            assert!(server.dispatch("invoke", untrusted_invoke("mcp.tools.call")).await.is_err());
        });
    }

    #[test]
    fn successful_reconfiguration_requires_a_new_handshake() {
        run!(async {
            let mut server = configured().await;
            let original = server.session.instance_id().clone();
            server.dispatch("configure", json!({"mcp_url": "http://127.0.0.1:2"})).await.unwrap();
            assert_ne!(server.session.instance_id(), &original);
            assert!(!server.session.is_established());
            assert!(matches!(server.dispatch("invoke", untrusted_invoke("mcp.tools.call")).await,
                Err(FcpError::NotHandshaken)));
        });
    }

    #[test]
    fn failed_version_negotiation_clears_health_and_doctor_authority() {
        run!(async {
            let mut server = configured().await;
            let mut request = handshake();
            request["protocol_version"] = json!("0.1");
            assert!(server.dispatch("handshake", request).await.is_err());
            let doctor = server.dispatch("doctor", json!({})).await.unwrap();
            assert_eq!(doctor["status"], "degraded");
            let check = doctor["checks"].as_array().unwrap().iter()
                .find(|check| check["name"] == "handshake").unwrap();
            assert_eq!(check["passed"], false);
        });
    }

    #[test]
    fn shutdown_clears_authority_and_reported_readiness() {
        run!(async {
            let mut server = configured().await;
            assert_eq!(server.dispatch("shutdown", json!({})).await.unwrap(), json!({}));
            let health = server.dispatch("health", json!({})).await.unwrap();
            assert_eq!(health["configured"], false);
            assert_eq!(health["handshaken"], false);
            assert!(server.dispatch("invoke", untrusted_invoke("mcp.tools.call")).await.is_err());
        });
    }

    #[test]
    fn simulation_denies_foreign_tokens_without_provider_io() {
        run!(async {
            let mut server = configured().await;
            let mut request = untrusted_invoke("mcp.tools.call");
            request["type"] = json!("simulate");
            request["estimate_cost"] = json!(false);
            request["check_availability"] = json!(false);
            let result = server.dispatch("simulate", request).await.unwrap();
            assert_eq!(result["id"], "request-1");
            assert_eq!(result["would_succeed"], false);
            let health = server.dispatch("health", json!({})).await.unwrap();
            assert_eq!(health["requests"], 0);
        });
    }

    #[test]
    fn typed_request_failures_do_not_echo_credentials_or_tokens() {
        run!(async {
            let mut server = configured().await;
            let error = server.dispatch("invoke", json!({
                "capability_token": "secret-token-marker", "input": {"key": "secret-key-marker"},
            })).await.unwrap_err();
            let message = error.to_string();
            assert!(!message.contains("secret-token-marker"));
            assert!(!message.contains("secret-key-marker"));
        });
    }

    #[test]
    fn resource_authorization_uses_exact_input_uri_not_an_alternate_list() {
        let operation = OperationId::from_static("mcp.resources.read");
        assert_eq!(resource_uris(&operation, &json!({
            "uri": "urn:actual", "resource_uris": ["urn:decoy"],
        })).unwrap(), vec!["urn:actual".to_owned()]);
        for input in [json!({}), json!({"uri": ""}), json!({"uri": 42})] {
            assert!(resource_uris(&operation, &input).is_err());
        }
    }

    #[test]
    fn admitted_interruption_never_advertises_safe_replay() {
        let error = interrupted_invoke();
        let FcpError::External { retryable, retry_after, message, .. } = error else {
            panic!("expected external outcome-unknown error");
        };
        assert!(!retryable);
        assert!(retry_after.is_none());
        assert!(message.contains("outcome is unknown"));
    }

    #[test]
    fn typed_envelopes_reject_wrong_kind_empty_id_and_non_object_input() {
        assert!(validate_request("invoke", "invoke", &RequestId::new("r"), &json!({})).is_ok());
        assert!(validate_request("simulate", "invoke", &RequestId::new("r"), &json!({})).is_err());
        assert!(validate_request("invoke", "invoke", &RequestId::new(""), &json!({})).is_err());
        assert!(validate_request("invoke", "invoke", &RequestId::new("r"), &Value::Null).is_err());
    }

    #[test]
    fn in_flight_deadline_drops_pending_work_and_returns_unknown_outcome() {
        use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

        struct Release(Arc<AtomicBool>);
        impl Drop for Release {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        run!(async {
            let dropped = Arc::new(AtomicBool::new(false));
            let release = Release(Arc::clone(&dropped));
            let pending = async move {
                let _release = release;
                std::future::pending::<FcpResult<Value>>().await
            };
            let error = await_invocation(pending, Duration::from_millis(1)).await.unwrap_err();
            assert!(dropped.load(Ordering::SeqCst));
            assert!(matches!(error, FcpError::External { retryable: false, retry_after: None, .. }));
        });
    }

    #[test]
    fn admitted_success_and_provider_failure_are_not_rewritten_or_retried() {
        run!(async {
            let value = json!({"content": [], "extension": {"opaque": true}});
            assert_eq!(await_invocation(std::future::ready(Ok(value.clone())), Duration::from_secs(1)).await.unwrap(), value);
            let error = await_invocation(std::future::ready(Err(invalid("provider validation"))), Duration::from_secs(1)).await.unwrap_err();
            assert!(matches!(error, FcpError::InvalidRequest { code: 1003, .. }));
        });
    }
}
