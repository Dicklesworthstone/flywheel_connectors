//! Integration tests for the FCP Webhook Receiver connector.

#![allow(
    clippy::cast_possible_truncation,
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use serde_json::json;

use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{Duration, Utc};
use fcp_crypto::{
    canonicalize::to_deterministic_cbor, cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey,
};
use fcp_prelude::{
    ApprovalScope, ApprovalToken, CapabilityConstraints, CapabilityId, CapabilityToken,
    ConnectorId, ExecutionScope, FcpError, FcpResult, HandshakeRequest, HealthSnapshot,
    InvokeRequest, ObjectId, OperationId, RequestId, SimulateRequest, ZoneId,
};
use fcp_webhook_receiver::connector::WebhookReceiverConnector;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;
type HmacSha1 = Hmac<Sha1>;

/// Provider-contract fixtures use real signed FCP requests. Authority tests below
/// call `inner` directly so malformed and unsigned requests never get repaired.
struct SignedConnector {
    inner: WebhookReceiverConnector,
    key: Ed25519SigningKey,
    approval_key: Ed25519SigningKey,
    instance_id: String,
}

impl std::ops::Deref for SignedConnector {
    type Target = WebhookReceiverConnector;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl std::ops::DerefMut for SignedConnector {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

fn handshake_request(key: &Ed25519SigningKey) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key: key.verifying_key().to_bytes(),
        nonce: [42; 32],
        capabilities_requested: [
            "webhook.endpoints.read",
            "webhook.endpoints.write",
            "webhook.events.read",
            "webhook.events.write",
        ]
        .into_iter()
        .map(CapabilityId::from_static)
        .collect(),
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

impl SignedConnector {
    async fn handshake(&mut self) -> serde_json::Value {
        let response = self
            .inner
            .handle_handshake(json!(handshake_request(&self.key)))
            .await
            .unwrap();
        self.instance_id = response["instance_id"].as_str().unwrap().to_owned();
        response
    }

    fn request(&self, params: serde_json::Value) -> FcpResult<InvokeRequest> {
        let operation =
            params["operation_id"]
                .as_str()
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "Test request requires an operation".into(),
                })?;
        let capability = match operation {
            "webhook.endpoints.create"
            | "webhook.endpoints.delete"
            | "webhook.endpoints.rotate_secret" => "webhook.endpoints.write",
            "webhook.endpoints.list" | "webhook.health" => "webhook.endpoints.read",
            "webhook.events.recent" | "webhook.events.poll" => "webhook.events.read",
            "webhook.events.ingest" => "webhook.events.write",
            _ => operation,
        };
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let now = Utc::now();
        let raw = CapabilityTokenBuilder::new()
            .capability_id(capability)
            .zone_id("z:work")
            .principal("user:webhook-test")
            .operations(&[operation])
            .issuer("node:webhook-test")
            .target_instance(&self.instance_id)
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&fcp_cbor::to_canonical_cbor(&constraints).unwrap())
            .unwrap()
            .sign(&self.key)
            .unwrap();
        let mut request = InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::random(),
            connector_id: ConnectorId::from_static("fcp.webhook-receiver"),
            operation: OperationId::new(operation).unwrap(),
            zone_id: ZoneId::work(),
            input: params.get("input").cloned().unwrap_or_else(|| json!({})),
            capability_token: CapabilityToken::from_raw(raw),
            holder_proof: None,
            context: None,
            idempotency_key: Some("webhook-test".into()),
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: vec![],
        };
        if matches!(
            operation,
            "webhook.endpoints.create"
                | "webhook.endpoints.delete"
                | "webhook.endpoints.rotate_secret"
        ) {
            let now_ms = u64::try_from(now.timestamp_millis()).unwrap();
            let input_hash =
                *blake3::hash(&to_deterministic_cbor(&request.input).unwrap()).as_bytes();
            let mut approval = ApprovalToken::approved(
                "test-approval",
                now_ms - 1000,
                now_ms + 60_000,
                "owner:test",
                ApprovalScope::Execution(ExecutionScope {
                    connector_id: request.connector_id.to_string(),
                    method_pattern: operation.into(),
                    request_object_id: Some(ObjectId::from_unscoped_bytes(request.id.0.as_bytes())),
                    input_hash: Some(input_hash),
                    input_constraints: vec![],
                }),
                request.zone_id.clone(),
                None,
            );
            approval.signature = Some(
                self.approval_key
                    .sign(&fcp_cbor::to_canonical_cbor(&approval).unwrap())
                    .to_bytes()
                    .to_vec(),
            );
            request.approval_tokens.push(approval);
        }
        Ok(request)
    }

    async fn handle_invoke(&mut self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let request = self.request(params)?;
        self.inner.handle_invoke(json!(request)).await
    }

    async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let invoke = self.request(params)?;
        let request = SimulateRequest::new(
            invoke.connector_id,
            invoke.operation,
            invoke.zone_id,
            invoke.input,
            invoke.capability_token,
        );
        self.inner.handle_simulate(json!(request)).await
    }
}

async fn setup_connector() -> SignedConnector {
    setup_connector_with_config(json!({"public_base_url": "https://hooks.flywheel.test"})).await
}

async fn setup_connector_with_config(mut config: serde_json::Value) -> SignedConnector {
    let mut c = SignedConnector {
        inner: WebhookReceiverConnector::new(),
        key: Ed25519SigningKey::from_bytes(&[7; 32]).unwrap(),
        approval_key: Ed25519SigningKey::from_bytes(&[8; 32]).unwrap(),
        instance_id: String::new(),
    };
    config["approval_public_key"] = json!(c.approval_key.verifying_key().to_bytes());
    c.inner.handle_configure(config).await.unwrap();
    c.handshake().await;
    c
}

async fn create_endpoint(
    c: &mut SignedConnector,
    path: &str,
    provider: &str,
    signing_secret: &str,
) -> serde_json::Value {
    c.handle_invoke(json!({
        "operation_id": "webhook.endpoints.create",
        "input": {
            "path": path,
            "provider": provider,
            "signing_secret": signing_secret
        }
    }))
    .await
    .unwrap()
}

fn hmac_sha256_hex(secret: &str, data: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(data.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn hmac_sha1_base64(secret: &str, data: &str) -> String {
    let mut mac = HmacSha1::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(data.as_bytes());
    STANDARD.encode(mac.finalize().into_bytes())
}

fn slack_signature_headers(secret: &str, body: &str, timestamp: i64) -> serde_json::Value {
    json!({
        "Content-Type": "application/json",
        "X-Slack-Request-Timestamp": timestamp.to_string(),
        "X-Slack-Signature": format!(
            "v0={}",
            hmac_sha256_hex(secret, &format!("v0:{timestamp}:{body}"))
        )
    })
}

fn unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .try_into()
        .unwrap()
}

async fn ingest(
    c: &mut SignedConnector,
    path: &str,
    headers: serde_json::Value,
    body: &str,
    delivery_id: &str,
) -> Result<serde_json::Value, fcp_prelude::FcpError> {
    c.handle_invoke(json!({
        "operation_id": "webhook.events.ingest",
        "input": {
            "method": "POST",
            "path": path,
            "headers": headers,
            "body": body,
            "delivery_id": delivery_id,
            "source_ip": "203.0.113.10",
            "client_id": "client-a"
        }
    }))
    .await
}

fn assert_external_status(result: Result<serde_json::Value, FcpError>, expected_status: u16) {
    let error = result.expect_err("ingest should fail");
    let actual_status = match &error {
        FcpError::External { status_code, .. } => *status_code,
        _ => None,
    };
    assert_eq!(
        actual_status,
        Some(expected_status),
        "expected external status {expected_status}, got {error:?}"
    );
}

// -- Lifecycle --

#[fcp_async_core::runtime::test]
async fn lifecycle_health_unconfigured() {
    let c = WebhookReceiverConnector::new();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"]["state"], "starting");
    assert_eq!(h["configured"], false);
    assert_eq!(h["handshaken"], false);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_configured_not_handshaken() {
    let mut c = WebhookReceiverConnector::new();
    c.handle_configure(json!({})).await.unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"]["state"], "degraded");
    assert_eq!(h["configured"], true);
    assert_eq!(h["handshaken"], false);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_full() {
    let c = setup_connector().await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"]["state"], "ready");
    assert_eq!(h["configured"], true);
    assert_eq!(h["handshaken"], true);
    assert_eq!(h["ingress_listener_status"], "deferred");
    assert!(
        h["ingress_listener_message"]
            .as_str()
            .unwrap()
            .contains("endpoint URLs are provisioning metadata")
    );
    assert_eq!(h["host_forwarded_ingress_status"], "available");
    assert_eq!(h["gateway_binding_status"], "unbound");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_before_configure_fails() {
    let mut c = WebhookReceiverConnector::new();
    assert!(c.handle_handshake(json!({})).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn lifecycle_shutdown() {
    let mut c = setup_connector().await;
    c.handle_shutdown(json!({})).await.unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"]["state"], "starting");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_self_check_ready() {
    let c = setup_connector().await;
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "degraded");
    assert_eq!(check["reason_code"], "gateway_ingress_unbound");
    assert_eq!(
        check["details"]["provisioning"]["public_base_url"],
        "https://hooks.flywheel.test"
    );
    assert_eq!(
        check["details"]["provisioning"]["ingress_listener_status"],
        "deferred"
    );
}

#[fcp_async_core::runtime::test]
async fn lifecycle_self_check_unconfigured() {
    let c = WebhookReceiverConnector::new();
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "degraded");
    assert_eq!(check["reason_code"], "not_configured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor_healthy() {
    let c = setup_connector().await;
    let doc = c.handle_doctor().await.unwrap();
    assert_eq!(doc["status"], "degraded");
    let checks = doc["checks"].as_array().expect("doctor checks");
    let ingress = checks
        .iter()
        .find(|check| check["name"] == "ingress_listener")
        .expect("ingress listener check");
    assert_eq!(ingress["passed"], false);
    assert_eq!(ingress["critical"], false);
    let host_forwarded = checks
        .iter()
        .find(|check| check["name"] == "host_forwarded_ingress")
        .expect("host-forwarded ingress check");
    assert_eq!(host_forwarded["passed"], true);
    assert_eq!(host_forwarded["critical"], true);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor_unconfigured() {
    let c = WebhookReceiverConnector::new();
    let doc = c.handle_doctor().await.unwrap();
    assert_eq!(doc["status"], "unhealthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_introspect() {
    let c = setup_connector().await;
    let intro = c.handle_introspect().await.unwrap();
    let ops = intro["operations"].as_array().expect("operations array");
    assert!(!ops.is_empty(), "introspect should list operations");
    assert!(ops[0]["id"].is_string());
    assert_eq!(intro["ingress_listener"]["status"], "deferred");
    assert_eq!(intro["host_forwarded_ingress"]["status"], "available");
    assert_eq!(
        intro["event_caps"]["host_forwarded_ingress_operation"],
        "webhook.events.ingest"
    );
}

#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_returns_capabilities() {
    let mut c = WebhookReceiverConnector::new();
    c.handle_configure(json!({"public_base_url": "https://hooks.flywheel.test"}))
        .await
        .unwrap();
    let hs = c
        .handle_handshake(json!(handshake_request(
            &Ed25519SigningKey::from_bytes(&[7; 32]).unwrap()
        )))
        .await
        .unwrap();
    assert_eq!(hs["protocol_version"], "2.0");
    assert_eq!(hs["connector_id"], "fcp.webhook-receiver");
    let caps = hs["capabilities_granted"].as_array().unwrap();
    assert_eq!(caps.len(), 4);
    assert!(
        caps.iter()
            .any(|cap| cap["capability"] == "webhook.events.write")
    );
}

// -- Endpoints Create --

#[fcp_async_core::runtime::test]
async fn endpoints_create_basic() {
    let mut c = setup_connector().await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "webhook.endpoints.create",
            "input": {
                "path": "/hooks/github",
                "signing_secret": "whsec_abc123"
            }
        }))
        .await
        .unwrap();
    assert!(result["endpoint_id"].as_str().unwrap().starts_with("ep_"));
    assert!(result["url"].as_str().unwrap().contains("/hooks/github"));
}

#[fcp_async_core::runtime::test]
async fn endpoints_create_with_allowed_sources() {
    let mut c = setup_connector().await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "webhook.endpoints.create",
            "input": {
                "path": "/hooks/stripe",
                "signing_secret": "whsec_stripe",
                "allowed_sources": ["10.0.0.0/8", "172.16.0.0/12"]
            }
        }))
        .await
        .unwrap();
    assert!(result["endpoint_id"].as_str().is_some());
}

#[fcp_async_core::runtime::test]
async fn endpoints_create_duplicate_path_rejected() {
    let mut c = setup_connector().await;
    c.handle_invoke(json!({
        "operation_id": "webhook.endpoints.create",
        "input": {
            "path": "/hooks/github",
            "signing_secret": "s1"
        }
    }))
    .await
    .unwrap();

    let result = c
        .handle_invoke(json!({
            "operation_id": "webhook.endpoints.create",
            "input": {
                "path": "/hooks/github",
                "signing_secret": "s2"
            }
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn endpoints_create_missing_path() {
    let mut c = setup_connector().await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "webhook.endpoints.create",
            "input": {
                "signing_secret": "s1"
            }
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn endpoints_create_missing_signing_secret_generates_one() {
    let mut c = setup_connector().await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "webhook.endpoints.create",
            "input": {
                "path": "/hooks/test"
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["signing_secret_generated"], true);
    assert!(
        result["signing_secret"]
            .as_str()
            .unwrap()
            .starts_with("whsec_")
    );
}

#[fcp_async_core::runtime::test]
async fn endpoints_create_provider_defaults() {
    let mut c = setup_connector().await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "webhook.endpoints.create",
            "input": {
                "path": "/hooks/github",
                "provider": "github"
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["provider"], "github");
    assert_eq!(result["signature_header"], "X-Hub-Signature-256");
    assert_eq!(result["signature_algorithm"], "hmac-sha256");
    assert_eq!(result["recommended_events"][0], "push");
}

#[fcp_async_core::runtime::test]
async fn endpoints_create_provider_mismatch_rejected() {
    let mut c = setup_connector().await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "webhook.endpoints.create",
            "input": {
                "path": "/hooks/github",
                "provider": "github",
                "signature_header": "Stripe-Signature"
            }
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn endpoints_create_multiple_different_paths() {
    let mut c = setup_connector().await;
    for i in 0..5 {
        c.handle_invoke(json!({
            "operation_id": "webhook.endpoints.create",
            "input": {
                "path": format!("/hooks/ep{i}"),
                "signing_secret": format!("secret_{i}")
            }
        }))
        .await
        .unwrap();
    }

    let list = c
        .handle_invoke(json!({
            "operation_id": "webhook.endpoints.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(list["endpoints"].as_array().unwrap().len(), 5);
}

// -- Endpoints Delete --

#[fcp_async_core::runtime::test]
async fn endpoints_delete_success() {
    let mut c = setup_connector().await;
    let created = c
        .handle_invoke(json!({
            "operation_id": "webhook.endpoints.create",
            "input": {
                "path": "/hooks/test",
                "signing_secret": "s"
            }
        }))
        .await
        .unwrap();
    let ep_id = created["endpoint_id"].as_str().unwrap();

    let result = c
        .handle_invoke(json!({
            "operation_id": "webhook.endpoints.delete",
            "input": {"endpoint_id": ep_id}
        }))
        .await
        .unwrap();
    assert!(result.is_object());

    // Verify it's gone
    let list = c
        .handle_invoke(json!({
            "operation_id": "webhook.endpoints.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(list["endpoints"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn endpoints_delete_not_found() {
    let mut c = setup_connector().await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "webhook.endpoints.delete",
            "input": {"endpoint_id": "ep_nonexistent"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn endpoints_delete_missing_endpoint_id() {
    let mut c = setup_connector().await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "webhook.endpoints.delete",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Endpoints List --

#[fcp_async_core::runtime::test]
async fn endpoints_list_empty() {
    let mut c = setup_connector().await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "webhook.endpoints.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["endpoints"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn endpoints_list_returns_all() {
    let mut c = setup_connector().await;
    c.handle_invoke(json!({
        "operation_id": "webhook.endpoints.create",
        "input": {"path": "/a", "signing_secret": "s1"}
    }))
    .await
    .unwrap();
    c.handle_invoke(json!({
        "operation_id": "webhook.endpoints.create",
        "input": {"path": "/b", "signing_secret": "s2"}
    }))
    .await
    .unwrap();

    let result = c
        .handle_invoke(json!({
            "operation_id": "webhook.endpoints.list",
            "input": {}
        }))
        .await
        .unwrap();
    let endpoints = result["endpoints"].as_array().unwrap();
    assert_eq!(endpoints.len(), 2);

    // Each endpoint should have the expected fields
    for ep in endpoints {
        assert!(ep["endpoint_id"].as_str().is_some());
        assert!(ep["path"].as_str().is_some());
        assert!(ep["url"].as_str().is_some());
        assert!(ep["provider"].as_str().is_some());
        assert!(ep["signature_header"].as_str().is_some());
        assert!(ep["signature_algorithm"].as_str().is_some());
        assert!(ep["signing_secret_configured"].as_bool().is_some());
        assert!(ep["secret_last_rotated_at"].as_str().is_some());
        assert!(ep["active"].as_bool().is_some());
        assert!(ep["created_at"].as_str().is_some());
        assert!(ep["event_count"].as_u64().is_some());
    }
}

// -- Events Recent --

#[fcp_async_core::runtime::test]
async fn events_recent_empty() {
    let mut c = setup_connector().await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "webhook.events.recent",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["events"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn events_recent_after_endpoint_receives_events() {
    let mut c = setup_connector().await;

    // Create endpoint
    let created = c
        .handle_invoke(json!({
            "operation_id": "webhook.endpoints.create",
            "input": {"path": "/hooks/test", "signing_secret": "s"}
        }))
        .await
        .unwrap();
    let ep_id = created["endpoint_id"].as_str().unwrap();

    // Query events for the new endpoint (should be empty since no external
    // events have been received)
    let result = c
        .handle_invoke(json!({
            "operation_id": "webhook.events.recent",
            "input": {"endpoint_id": ep_id}
        }))
        .await
        .unwrap();
    assert!(result["events"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn events_recent_with_limit() {
    let mut c = setup_connector().await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "webhook.events.recent",
            "input": {"limit": 10}
        }))
        .await
        .unwrap();
    assert!(result["events"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn events_recent_with_since_ts() {
    let mut c = setup_connector().await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "webhook.events.recent",
            "input": {"since_ts": "2025-01-01T00:00:00Z"}
        }))
        .await
        .unwrap();
    assert!(result["events"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn events_recent_endpoint_not_found() {
    let mut c = setup_connector().await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "webhook.events.recent",
            "input": {"endpoint_id": "ep_nonexistent"}
        }))
        .await
        .is_err()
    );
}

// -- Events Ingest --

#[fcp_async_core::runtime::test]
async fn events_ingest_github_signature_records_redacted_event() {
    let mut c = setup_connector().await;
    let created = create_endpoint(&mut c, "/hooks/github", "github", "gh_secret").await;
    let endpoint_id = created["endpoint_id"].as_str().unwrap();
    let body = r#"{"zen":"Keep it logically awesome.","id":"evt-github-1"}"#;
    let signature = format!("sha256={}", hmac_sha256_hex("gh_secret", body));

    let accepted = ingest(
        &mut c,
        "/hooks/github",
        json!({
            "Content-Type": "application/json",
            "X-Hub-Signature-256": signature,
            "Authorization": "Bearer secret",
            "X-GitHub-Delivery": "delivery-github-1"
        }),
        body,
        "delivery-github-1",
    )
    .await
    .unwrap();

    assert_eq!(accepted["accepted"], true);
    assert_eq!(accepted["status_code"], 202);
    assert_eq!(accepted["event"]["provider"], "github");
    assert_eq!(accepted["event"]["event_id"], "delivery-github-1");
    assert_eq!(
        accepted["event_caps"]["host_forwarded_ingress_operation"],
        "webhook.events.ingest"
    );
    assert_eq!(
        accepted["ingress_binding"]["host_forwarded_operation"]["status"],
        "available"
    );

    let recent = c
        .handle_invoke(json!({
            "operation_id": "webhook.events.recent",
            "input": {"endpoint_id": endpoint_id}
        }))
        .await
        .unwrap();
    let events = recent["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["event_id"], "delivery-github-1");
    assert_eq!(events[0]["payload"]["id"], "evt-github-1");
    assert_eq!(events[0]["headers"]["content-type"], "application/json");
    assert!(events[0]["headers"].get("authorization").is_none());
    assert!(events[0]["headers"].get("x-hub-signature-256").is_none());
    assert!(events[0]["source_ip_hash"].as_str().is_some());
}

#[fcp_async_core::runtime::test]
async fn events_ingest_duplicate_delivery_is_rejected_without_recording_second_event() {
    let mut c = setup_connector().await;
    let created = create_endpoint(&mut c, "/hooks/dupe", "generic", "secret").await;
    let endpoint_id = created["endpoint_id"].as_str().unwrap();
    let body = r#"{"id":"evt-duplicate"}"#;
    let headers = json!({
        "Content-Type": "application/json",
        "X-Signature": hmac_sha256_hex("secret", body)
    });

    ingest(
        &mut c,
        "/hooks/dupe",
        headers.clone(),
        body,
        "delivery-dupe",
    )
    .await
    .unwrap();
    assert_external_status(
        ingest(&mut c, "/hooks/dupe", headers, body, "delivery-dupe").await,
        409,
    );

    let recent = c
        .handle_invoke(json!({
            "operation_id": "webhook.events.recent",
            "input": {"endpoint_id": endpoint_id}
        }))
        .await
        .unwrap();
    assert_eq!(recent["events"].as_array().unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn events_ingest_authenticated_body_cannot_be_replayed_with_unsigned_ids() {
    let mut c = setup_connector().await;
    let body = r#"{"event_id":"signed-event","type":"changed"}"#;
    let timestamp = unix_seconds();

    for provider in ["generic", "github", "stripe", "slack"] {
        let path = format!("/hooks/replay-{provider}");
        let created = create_endpoint(&mut c, &path, provider, "secret").await;
        let signed_headers = |timestamp: i64| match provider {
            "generic" => json!({
                "Content-Type": "application/json",
                "X-Signature": hmac_sha256_hex("secret", body)
            }),
            "github" => json!({
                "Content-Type": "application/json",
                "X-Hub-Signature-256": format!("sha256={}", hmac_sha256_hex("secret", body))
            }),
            "stripe" => json!({
                "Content-Type": "application/json",
                "Stripe-Signature": format!(
                    "t={timestamp},v1={}",
                    hmac_sha256_hex("secret", &format!("{timestamp}.{body}"))
                )
            }),
            "slack" => json!({
                "Content-Type": "application/json",
                "X-Slack-Request-Timestamp": timestamp.to_string(),
                "X-Slack-Signature": format!(
                    "v0={}",
                    hmac_sha256_hex("secret", &format!("v0:{timestamp}:{body}"))
                )
            }),
            _ => unreachable!(),
        };
        // Failed verification must not claim either replay identity.
        assert_external_status(
            ingest(
                &mut c,
                &path,
                json!({"Content-Type": "application/json"}),
                body,
                "original",
            )
            .await,
            401,
        );
        let accepted = ingest(&mut c, &path, signed_headers(timestamp), body, "original")
            .await
            .unwrap();
        assert_eq!(accepted["event"]["event_id"], "original");
        assert!(
            accepted["ingest_log"]["signature"]
                .get("replay_digest")
                .is_none()
        );

        let input = json!({
            "path": path,
            "headers": signed_headers(timestamp),
            "body": body
        });
        for field in ["delivery_id", "event_id", "request_id"] {
            let mut attempt = input.clone();
            attempt[field] = json!(format!("changed-{field}"));
            assert_external_status(
                c.handle_invoke(json!({
                    "operation_id": "webhook.events.ingest", "input": attempt
                }))
                .await,
                409,
            );
        }
        for header in [
            "X-GitHub-Delivery",
            "X-Request-ID",
            "Stripe-Request-Id",
            "X-Slack-Request-Id",
        ] {
            let mut attempt = input.clone();
            attempt["headers"][header] = json!(format!("changed-{header}"));
            assert_external_status(
                c.handle_invoke(json!({
                    "operation_id": "webhook.events.ingest", "input": attempt
                }))
                .await,
                409,
            );
        }
        // Removing all unsigned aliases must not revive the signed payload ID.
        assert_external_status(
            c.handle_invoke(json!({
                "operation_id": "webhook.events.ingest", "input": input
            }))
            .await,
            409,
        );
        if matches!(provider, "stripe" | "slack") {
            assert_external_status(
                ingest(
                    &mut c,
                    &path,
                    signed_headers(timestamp - 1),
                    body,
                    "resigned-retry",
                )
                .await,
                409,
            );
        }
        let recent = c
            .handle_invoke(json!({
                "operation_id": "webhook.events.recent",
                "input": {"endpoint_id": created["endpoint_id"]}
            }))
            .await
            .unwrap();
        assert_eq!(recent["events"].as_array().unwrap().len(), 1);
        assert_eq!(recent["events"][0]["event_id"], "original");
    }
}

#[fcp_async_core::runtime::test]
async fn events_ingest_missing_signature_is_rejected_without_recording_event() {
    let mut c = setup_connector().await;
    let created = create_endpoint(&mut c, "/hooks/auth", "generic", "secret").await;
    let endpoint_id = created["endpoint_id"].as_str().unwrap();

    assert_external_status(
        ingest(
            &mut c,
            "/hooks/auth",
            json!({"Content-Type": "application/json"}),
            r#"{"id":"evt-auth"}"#,
            "delivery-auth",
        )
        .await,
        401,
    );

    let recent = c
        .handle_invoke(json!({
            "operation_id": "webhook.events.recent",
            "input": {"endpoint_id": endpoint_id}
        }))
        .await
        .unwrap();
    assert!(recent["events"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn events_ingest_source_allowlist_accepts_cidr_and_denies_other_sources() {
    let mut c = setup_connector().await;
    c.handle_invoke(json!({
        "operation_id": "webhook.endpoints.create",
        "input": {
            "path": "/hooks/allow",
            "provider": "github",
            "signing_secret": "allow_secret",
            "allowed_sources": ["203.0.113.0/24"]
        }
    }))
    .await
    .unwrap();
    let body = r#"{"id":"evt-allow"}"#;
    let signature = format!("sha256={}", hmac_sha256_hex("allow_secret", body));

    ingest(
        &mut c,
        "/hooks/allow",
        json!({
            "Content-Type": "application/json",
            "X-Hub-Signature-256": signature.clone()
        }),
        body,
        "delivery-allow",
    )
    .await
    .unwrap();

    assert_external_status(
        c.handle_invoke(json!({
            "operation_id": "webhook.events.ingest",
            "input": {
                "method": "POST",
                "path": "/hooks/allow",
                "headers": {
                    "Content-Type": "application/json",
                    "X-Hub-Signature-256": signature
                },
                "body": body,
                "delivery_id": "delivery-denied",
                "source_ip": "198.51.100.10"
            }
        }))
        .await,
        403,
    );
}

#[fcp_async_core::runtime::test]
async fn events_ingest_mixed_family_source_allowlist_is_order_independent() {
    let mut c = setup_connector().await;
    for (index, sources) in [
        ["203.0.113.0/24", "2001:db8::/32"],
        ["2001:db8::/32", "203.0.113.0/24"],
    ]
    .into_iter()
    .enumerate()
    {
        let path = format!("/hooks/dual-stack-{index}");
        let created = c
            .handle_invoke(json!({
                "operation_id": "webhook.endpoints.create",
                "input": {
                    "path": path,
                    "provider": "github",
                    "signing_secret": "dual-stack-secret",
                    "allowed_sources": sources
                }
            }))
            .await
            .unwrap();
        for (source, denied_source) in [
            ("203.0.113.10", "198.51.100.10"),
            ("2001:db8:1234::10", "2001:db9::10"),
        ] {
            let body = json!({"id": format!("delivery-{source}")}).to_string();
            let mut input = json!({
                "method": "POST",
                "path": path,
                "headers": {
                    "Content-Type": "application/json",
                    "X-Hub-Signature-256": format!(
                        "sha256={}", hmac_sha256_hex("dual-stack-secret", &body)
                    )
                },
                "body": body,
                "source_ip": denied_source
            });
            assert_external_status(
                c.handle_invoke(json!({
                    "operation_id": "webhook.events.ingest", "input": input
                }))
                .await,
                403,
            );
            // A source-policy rejection must not consume the authenticated
            // delivery identity before a permitted retry reaches verification.
            input["source_ip"] = json!(source);
            let accepted = c
                .handle_invoke(json!({
                    "operation_id": "webhook.events.ingest", "input": input
                }))
                .await
                .unwrap();
            assert_eq!(accepted["accepted"], true);
            assert_eq!(accepted["event"]["event_id"], format!("delivery-{source}"));
        }
        let recent = c
            .handle_invoke(json!({
                "operation_id": "webhook.events.recent",
                "input": {"endpoint_id": created["endpoint_id"]}
            }))
            .await
            .unwrap();
        assert_eq!(recent["events"].as_array().unwrap().len(), 2);
        assert!(recent["events"].as_array().unwrap().iter().all(|event| {
            event["signature_valid"] == true && event["source_ip_hash"].is_string()
        }));
    }
}

#[fcp_async_core::runtime::test]
async fn endpoints_create_rejects_invalid_source_policy_without_registering_endpoint() {
    let mut c = setup_connector().await;
    for invalid in [
        "203.0.113.0/33",
        "2001:db8::/129",
        "203.0.113.0/256",
        "203.0.113.0/-1",
        "203.0.113.0/24/1",
        "hooks.example.com",
        "not-an-address",
    ] {
        assert_external_status(
            c.handle_invoke(json!({
                "operation_id": "webhook.endpoints.create",
                "input": {
                    "path": "/hooks/source-policy",
                    "signing_secret": "secret",
                    "allowed_sources": ["203.0.113.0/24", invalid]
                }
            }))
            .await,
            400,
        );
        let listed = c
            .handle_invoke(json!({
                "operation_id": "webhook.endpoints.list", "input": {}
            }))
            .await
            .unwrap();
        assert!(listed["endpoints"].as_array().unwrap().is_empty());
    }
    // Invalid policy must not reserve the endpoint path or any store capacity.
    c.handle_invoke(json!({
        "operation_id": "webhook.endpoints.create",
        "input": {
            "path": "/hooks/source-policy",
            "signing_secret": "secret",
            "allowed_sources": ["203.0.113.0/24", "2001:db8::/32"]
        }
    }))
    .await
    .unwrap();
}

#[fcp_async_core::runtime::test]
async fn events_ingest_rejects_non_post_method() {
    let mut c = setup_connector().await;
    assert_external_status(
        c.handle_invoke(json!({
            "operation_id": "webhook.events.ingest",
            "input": {
                "method": "GET",
                "path": "/hooks/method",
                "headers": {}
            }
        }))
        .await,
        405,
    );
}

#[fcp_async_core::runtime::test]
async fn events_ingest_rejects_unsupported_media_type() {
    let mut c = setup_connector().await;
    create_endpoint(&mut c, "/hooks/media", "generic", "secret").await;
    let body = r#"{"id":"evt-media"}"#;
    assert_external_status(
        ingest(
            &mut c,
            "/hooks/media",
            json!({
                "Content-Type": "text/plain",
                "X-Signature": hmac_sha256_hex("secret", body)
            }),
            body,
            "delivery-media",
        )
        .await,
        415,
    );
}

#[fcp_async_core::runtime::test]
async fn events_ingest_rejects_payload_over_configured_cap() {
    let mut c = setup_connector_with_config(json!({
        "public_base_url": "https://hooks.flywheel.test",
        "max_body_bytes": 8
    }))
    .await;
    create_endpoint(&mut c, "/hooks/large", "generic", "secret").await;
    let body = r#"{"too":"large"}"#;
    assert_external_status(
        ingest(
            &mut c,
            "/hooks/large",
            json!({
                "Content-Type": "application/json",
                "X-Signature": hmac_sha256_hex("secret", body)
            }),
            body,
            "delivery-large",
        )
        .await,
        413,
    );
}

#[fcp_async_core::runtime::test]
async fn events_ingest_maps_request_region_timeout() {
    let mut c = setup_connector().await;
    assert_external_status(
        c.handle_invoke(json!({
            "operation_id": "webhook.events.ingest",
            "input": {
                "deadline_exceeded": true
            }
        }))
        .await,
        408,
    );
}

#[fcp_async_core::runtime::test]
async fn events_ingest_rejects_malformed_json_body() {
    let mut c = setup_connector().await;
    create_endpoint(&mut c, "/hooks/bad-json", "generic", "secret").await;
    let body = "{not-json";
    assert_external_status(
        ingest(
            &mut c,
            "/hooks/bad-json",
            json!({
                "Content-Type": "application/json",
                "X-Signature": hmac_sha256_hex("secret", body)
            }),
            body,
            "delivery-bad-json",
        )
        .await,
        400,
    );
}

#[fcp_async_core::runtime::test]
async fn events_ingest_rejects_deleted_endpoint_path() {
    let mut c = setup_connector().await;
    let created = create_endpoint(&mut c, "/hooks/deleted", "generic", "secret").await;
    let endpoint_id = created["endpoint_id"].as_str().unwrap();
    c.handle_invoke(json!({
        "operation_id": "webhook.endpoints.delete",
        "input": {"endpoint_id": endpoint_id}
    }))
    .await
    .unwrap();

    let body = r#"{"id":"evt-deleted"}"#;
    assert_external_status(
        ingest(
            &mut c,
            "/hooks/deleted",
            json!({
                "Content-Type": "application/json",
                "X-Signature": hmac_sha256_hex("secret", body)
            }),
            body,
            "delivery-deleted",
        )
        .await,
        404,
    );
}

#[fcp_async_core::runtime::test]
async fn events_ingest_applies_fixed_window_rate_limit() {
    let mut c = setup_connector_with_config(json!({
        "public_base_url": "https://hooks.flywheel.test",
        "rate_limit_max": 1,
        "rate_limit_window_ms": 60_000
    }))
    .await;
    create_endpoint(&mut c, "/hooks/rate", "generic", "secret").await;
    let body = r#"{"id":"evt-rate"}"#;
    let headers = json!({
        "Content-Type": "application/json",
        "X-Signature": hmac_sha256_hex("secret", body)
    });

    ingest(
        &mut c,
        "/hooks/rate",
        headers.clone(),
        body,
        "delivery-rate-1",
    )
    .await
    .unwrap();
    assert_external_status(
        ingest(&mut c, "/hooks/rate", headers, body, "delivery-rate-2").await,
        429,
    );
}

#[fcp_async_core::runtime::test]
async fn events_ingest_accepts_stripe_signature() {
    let mut c = setup_connector().await;
    create_endpoint(&mut c, "/hooks/stripe", "stripe", "whsec_stripe").await;
    let body = r#"{"id":"evt_stripe","type":"payment_intent.succeeded"}"#;
    let timestamp = unix_seconds();
    let signed_payload = format!("{timestamp}.{body}");
    let signature = hmac_sha256_hex("whsec_stripe", &signed_payload);

    let accepted = ingest(
        &mut c,
        "/hooks/stripe",
        json!({
            "Content-Type": "application/json",
            "Stripe-Signature": format!("t={timestamp},v1={signature}")
        }),
        body,
        "delivery-stripe",
    )
    .await
    .unwrap();

    assert_eq!(accepted["event"]["provider"], "stripe");
    assert_eq!(accepted["ingest_log"]["signature"]["timestamp"], timestamp);
}

#[fcp_async_core::runtime::test]
async fn events_ingest_accepts_slack_signature() {
    let mut c = setup_connector().await;
    create_endpoint(&mut c, "/hooks/slack", "slack", "slack_secret").await;
    let body = r#"{"event_id":"Ev123","type":"event_callback"}"#;
    let timestamp = unix_seconds();
    let signature = format!(
        "v0={}",
        hmac_sha256_hex("slack_secret", &format!("v0:{timestamp}:{body}"))
    );

    let accepted = ingest(
        &mut c,
        "/hooks/slack",
        json!({
            "Content-Type": "application/json",
            "X-Slack-Request-Timestamp": timestamp.to_string(),
            "X-Slack-Signature": signature
        }),
        body,
        "delivery-slack",
    )
    .await
    .unwrap();

    assert_eq!(accepted["event"]["provider"], "slack");
    assert_eq!(accepted["ingest_log"]["signature"]["timestamp"], timestamp);
}

#[fcp_async_core::runtime::test]
async fn slack_url_verification_retries_do_not_store_events_or_consume_replay_ids() {
    let mut c = setup_connector().await;
    let endpoint = create_endpoint(&mut c, "/hooks/slack", "slack", "slack_secret").await;
    let timestamp = unix_seconds();
    let prior_body = r#"{"event_id":"EvPrior","type":"event_callback"}"#;
    ingest(
        &mut c,
        "/hooks/slack",
        slack_signature_headers("slack_secret", prior_body, timestamp),
        prior_body,
        "prior-delivery",
    )
    .await
    .unwrap();
    let recent_request = json!({
        "operation_id": "webhook.events.recent",
        "input": { "endpoint_id": endpoint["endpoint_id"] }
    });
    let before = c.handle_invoke(recent_request.clone()).await.unwrap();
    let body = r#"{ "token": "deprecated-private-token", "challenge": " exact/challenge+value= ", "type": "url_verification" }"#;

    // The same signed request can be retried, including with a newly signed
    // timestamp. Neither public nor authenticated event identities are spent.
    for attempt_timestamp in [timestamp, timestamp, timestamp - 1] {
        let result = ingest(
            &mut c,
            "/hooks/slack",
            slack_signature_headers("slack_secret", body, attempt_timestamp),
            body,
            "control-delivery",
        )
        .await
        .unwrap();
        assert_eq!(
            result,
            json!({
                "accepted": true,
                "status_code": 200,
                "verification": {
                    "provider": "slack",
                    "kind": "url_verification",
                    "challenge": " exact/challenge+value= "
                }
            })
        );
    }
    assert_eq!(
        c.handle_invoke(recent_request.clone()).await.unwrap(),
        before
    );
    let listed = c
        .handle_invoke(json!({"operation_id": "webhook.endpoints.list"}))
        .await
        .unwrap();
    assert_eq!(listed["endpoints"][0]["event_count"], 1);

    // A normal event can still use the control request's delivery ID, and its
    // authenticated body remains protected from retries under unsigned aliases.
    let body =
        r#"{"event_id":"EvAfter","type":"event_callback","challenge":"not-a-control-exchange"}"#;
    let accepted = ingest(
        &mut c,
        "/hooks/slack",
        slack_signature_headers("slack_secret", body, timestamp),
        body,
        "control-delivery",
    )
    .await
    .unwrap();
    assert_eq!(accepted["status_code"], 202);
    assert_eq!(accepted["event"]["event_id"], "control-delivery");
    assert!(accepted.get("verification").is_none());
    assert_external_status(
        ingest(
            &mut c,
            "/hooks/slack",
            slack_signature_headers("slack_secret", body, timestamp - 1),
            body,
            "different-unsigned-alias",
        )
        .await,
        409,
    );
    let recent = c.handle_invoke(recent_request).await.unwrap();
    assert_eq!(recent["events"].as_array().unwrap().len(), 2);
    assert!(recent["events"].as_array().unwrap().iter().all(|event| {
        event["payload"]["type"] == "event_callback" && event["payload"].get("token").is_none()
    }));
}

#[fcp_async_core::runtime::test]
async fn slack_url_verification_requires_fresh_signature_over_exact_body() {
    let mut c = setup_connector().await;
    create_endpoint(&mut c, "/hooks/slack", "slack", "slack_secret").await;
    let timestamp = unix_seconds();
    let body =
        r#"{ "type": "url_verification", "challenge": "original", "token": "slack_secret" }"#;
    let headers = slack_signature_headers("slack_secret", body, timestamp);
    let reserialized = serde_json::from_str::<serde_json::Value>(body)
        .unwrap()
        .to_string();
    assert_ne!(reserialized, body);
    let attempts = [
        (json!({"Content-Type": "application/json"}), body.to_owned()),
        (headers.clone(), body.replace("original", "tampered")),
        (headers.clone(), reserialized),
        (
            slack_signature_headers("wrong-secret", body, timestamp),
            body.to_owned(),
        ),
        (
            slack_signature_headers("slack_secret", body, timestamp - 3600),
            body.to_owned(),
        ),
        (
            slack_signature_headers("slack_secret", body, timestamp + 3600),
            body.to_owned(),
        ),
        // Malformed challenges are checked only after provider authentication.
        (
            headers.clone(),
            r#"{"type":"url_verification","challenge":null}"#.to_owned(),
        ),
    ];
    for (headers, attempted_body) in attempts {
        assert_external_status(
            ingest(&mut c, "/hooks/slack", headers, &attempted_body, "control").await,
            401,
        );
    }
    assert_eq!(
        ingest(&mut c, "/hooks/slack", headers, body, "control")
            .await
            .unwrap()["verification"]["challenge"],
        "original"
    );
    assert_eq!(
        c.handle_invoke(json!({"operation_id": "webhook.events.recent"}))
            .await
            .unwrap()["events"],
        json!([])
    );
}

#[fcp_async_core::runtime::test]
async fn slack_url_verification_validates_challenge_utf8_bytes_and_controls() {
    let mut c = setup_connector().await;
    create_endpoint(&mut c, "/hooks/slack", "slack", "slack_secret").await;
    let timestamp = unix_seconds();
    let invalid_challenges = [
        None,
        Some(json!(null)),
        Some(json!(42)),
        Some(json!(true)),
        Some(json!(["challenge"])),
        Some(json!({"challenge": "nested"})),
        Some(json!("")),
        Some(json!("line\nbreak")),
        Some(json!("carriage\rreturn")),
        Some(json!("null\u{0}byte")),
        Some(json!("unicode\u{85}control")),
        Some(json!("x".repeat(4097))),
        Some(json!("é".repeat(2049))),
    ];
    for challenge in invalid_challenges {
        let mut payload = json!({"type": "url_verification"});
        if let Some(challenge) = challenge {
            payload["challenge"] = challenge;
        }
        let body = payload.to_string();
        assert_external_status(
            ingest(
                &mut c,
                "/hooks/slack",
                slack_signature_headers("slack_secret", &body, timestamp),
                &body,
                "control",
            )
            .await,
            400,
        );
    }
    for challenge in [" préservé/+ = ".to_owned(), "é".repeat(2048)] {
        let body = json!({"type": "url_verification", "challenge": challenge}).to_string();
        let accepted = ingest(
            &mut c,
            "/hooks/slack",
            slack_signature_headers("slack_secret", &body, timestamp),
            &body,
            "control",
        )
        .await
        .unwrap();
        assert_eq!(accepted["verification"]["challenge"], challenge);
    }
    assert_eq!(
        c.handle_invoke(json!({"operation_id": "webhook.events.recent"}))
            .await
            .unwrap()["events"],
        json!([])
    );
}

#[fcp_async_core::runtime::test]
async fn slack_url_verification_requires_the_configured_slack_provider() {
    let mut c = setup_connector().await;
    // Even the Slack signature scheme does not turn a generic endpoint into
    // Slack. The endpoint's approved provider selects the control semantics.
    c.handle_invoke(json!({
        "operation_id": "webhook.endpoints.create",
        "input": {
            "path": "/hooks/generic-slack-signature",
            "provider": "generic",
            "signing_secret": "shared-secret",
            "signature_header": "X-Slack-Signature",
            "signature_algorithm": "slack-signature-v0"
        }
    }))
    .await
    .unwrap();
    create_endpoint(&mut c, "/hooks/generic", "generic", "shared-secret").await;
    create_endpoint(&mut c, "/hooks/github", "github", "shared-secret").await;
    let timestamp = unix_seconds();
    let body = r#"{"type":"url_verification","challenge":"not-for-slack"}"#;
    for path in [
        "/hooks/generic-slack-signature",
        "/hooks/generic",
        "/hooks/github",
    ] {
        let mut headers = slack_signature_headers("shared-secret", body, timestamp);
        headers["X-Signature"] = json!(hmac_sha256_hex("shared-secret", body));
        headers["X-Hub-Signature-256"] =
            json!(format!("sha256={}", hmac_sha256_hex("shared-secret", body)));
        let accepted = ingest(&mut c, path, headers, body, "delivery")
            .await
            .unwrap();
        assert_eq!(accepted["status_code"], 202);
        assert!(accepted.get("verification").is_none());
        assert!(accepted.get("event").is_some());
    }
    assert_eq!(
        c.handle_invoke(json!({"operation_id": "webhook.events.recent"}))
            .await
            .unwrap()["events"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
}

#[fcp_async_core::runtime::test]
async fn slack_url_verification_preserves_source_and_rate_admission() {
    let mut c = setup_connector_with_config(json!({
        "public_base_url": "https://hooks.flywheel.test",
        "rate_limit_max": 1,
        "rate_limit_window_ms": 60_000
    }))
    .await;
    c.handle_invoke(json!({
        "operation_id": "webhook.endpoints.create",
        "input": {
            "path": "/hooks/slack",
            "provider": "slack",
            "signing_secret": "slack_secret",
            "allowed_sources": ["203.0.113.0/24"]
        }
    }))
    .await
    .unwrap();
    let body = r#"{"type":"url_verification","challenge":"bounded"}"#;
    let mut params = json!({
        "operation_id": "webhook.events.ingest",
        "input": {
            "path": "/hooks/slack",
            "headers": slack_signature_headers("slack_secret", body, unix_seconds()),
            "body": body,
            "source_ip": "198.51.100.10",
            "client_id": "control-client"
        }
    });
    assert_external_status(c.handle_invoke(params.clone()).await, 403);
    params["input"]["source_ip"] = json!("203.0.113.10");
    assert_eq!(
        c.handle_invoke(params.clone()).await.unwrap()["status_code"],
        200
    );
    assert_external_status(c.handle_invoke(params).await, 429);
    assert_eq!(
        c.handle_invoke(json!({"operation_id": "webhook.events.recent"}))
            .await
            .unwrap()["events"],
        json!([])
    );
}

#[fcp_async_core::runtime::test]
async fn slack_url_verification_preserves_fcp_authority_resource_and_usage_limits() {
    let mut c = setup_connector().await;
    let endpoint = create_endpoint(&mut c, "/hooks/slack", "slack", "slack_secret").await;
    let body = r#"{"type":"url_verification","challenge":"authorized"}"#;
    let params = json!({
        "operation_id": "webhook.events.ingest",
        "input": {
            "path": "/hooks/slack",
            "headers": slack_signature_headers("slack_secret", body, unix_seconds()),
            "body": body
        }
    });
    assert!(c.inner.handle_invoke(params.clone()).await.is_err());
    let request = c.request(params.clone()).unwrap();
    let mut unsigned = request.clone();
    unsigned.capability_token = CapabilityToken::from_raw(vec![]);
    assert!(c.inner.handle_invoke(json!(unsigned)).await.is_err());
    let mut wrong_zone = request.clone();
    wrong_zone.zone_id = ZoneId::public();
    assert!(c.inner.handle_invoke(json!(wrong_zone)).await.is_err());

    let now = Utc::now();
    let issue_token = |constraints: &CapabilityConstraints, token_id: &[u8]| {
        CapabilityToken::from_raw(
            CapabilityTokenBuilder::new()
                .capability_id("webhook.events.write")
                .zone_id("z:work")
                .principal("user:webhook-test")
                .operations(&["webhook.events.ingest"])
                .issuer("node:webhook-test")
                .target_instance(&c.instance_id)
                .token_id(token_id)
                .validity(now, now + Duration::hours(1))
                .try_constraints_cbor(&fcp_cbor::to_canonical_cbor(constraints).unwrap())
                .unwrap()
                .sign(&c.key)
                .unwrap(),
        )
    };
    let denied_token = issue_token(
        &CapabilityConstraints {
            resource_allow: vec!["*".into()],
            resource_deny: vec![endpoint["url"].as_str().unwrap().into()],
            ..Default::default()
        },
        b"denied-slack-challenge",
    );
    let limited_token = issue_token(
        &CapabilityConstraints {
            resource_allow: vec![endpoint["url"].as_str().unwrap().into()],
            max_calls: Some(1),
            ..Default::default()
        },
        b"limited-slack-challenge",
    );
    let mut denied = request.clone();
    denied.capability_token = denied_token;
    assert!(c.inner.handle_invoke(json!(denied)).await.is_err());
    let mut limited = request;
    limited.capability_token = limited_token;
    assert_eq!(
        c.inner.handle_invoke(json!(limited.clone())).await.unwrap()["status_code"],
        200
    );
    limited.id = RequestId::random();
    assert!(c.inner.handle_invoke(json!(limited)).await.is_err());
    // Failed authority checks and an exhausted token do not create events or
    // stop a separately authorized fresh retry of the control exchange.
    assert_eq!(c.handle_invoke(params).await.unwrap()["status_code"], 200);
    assert_eq!(
        c.handle_invoke(json!({"operation_id": "webhook.events.recent"}))
            .await
            .unwrap()["events"],
        json!([])
    );
}

#[fcp_async_core::runtime::test]
async fn events_ingest_accepts_twilio_signature() {
    let mut c = setup_connector().await;
    create_endpoint(&mut c, "/hooks/twilio", "twilio", "twilio_auth").await;
    let url = "https://hooks.flywheel.test/hooks/twilio";
    let params = json!({
        "Body": "Hello",
        "From": "+15551234567",
        "MessageSid": "SM123",
        "To": "+15557654321"
    });
    let signature_payload = format!(
        "{url}Body{}From{}MessageSid{}To{}",
        "Hello", "+15551234567", "SM123", "+15557654321"
    );
    let signature = hmac_sha1_base64("twilio_auth", &signature_payload);

    let accepted = c
        .handle_invoke(json!({
            "operation_id": "webhook.events.ingest",
            "input": {
                "method": "POST",
                "path": "/hooks/twilio",
                "headers": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "X-Twilio-Signature": signature
                },
                "url": url,
                "params": params,
                "payload": params,
                "delivery_id": "delivery-twilio",
                "source_ip": "203.0.113.10",
                "client_id": "client-twilio"
            }
        }))
        .await
        .unwrap();

    assert_eq!(accepted["event"]["provider"], "twilio");
    assert_eq!(accepted["event"]["event_id"], "delivery-twilio");
}

#[fcp_async_core::runtime::test]
async fn events_ingest_twilio_raw_form_matches_official_signature_vector() {
    let mut c = setup_connector_with_config(json!({
        "public_base_url": "https://example.com"
    }))
    .await;
    let created = create_endpoint(&mut c, "/myapp.php", "twilio", "12345").await;
    let endpoint_id = created["endpoint_id"].as_str().unwrap();
    // Fixed vector from Twilio's request-validation example, independent of
    // the signing helper used by the other integration fixtures.
    let accepted = c
        .handle_invoke(json!({
            "operation_id": "webhook.events.ingest",
            "input": {
                "method": "POST",
                "path": "/myapp.php",
                "url": "https://example.com/myapp.php?foo=1&bar=2",
                "headers": {
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "X-Twilio-Signature": "L/OH5YylLD5NRKLltdqwSvS0BnU="
                },
                "body": "CallSid=CA1234567890ABCDE&Caller=%2B14158675310&Digits=1234&From=%2B14158675310&To=%2B18005551212"
            }
        }))
        .await
        .unwrap();
    assert_eq!(accepted["accepted"], true);
    assert_eq!(accepted["status_code"], 202);
    assert_eq!(accepted["event"]["provider"], "twilio");

    let recent = c
        .handle_invoke(json!({
            "operation_id": "webhook.events.recent",
            "input": {"endpoint_id": endpoint_id}
        }))
        .await
        .unwrap();
    let events = recent["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["signature_valid"], true);
    assert_eq!(
        events[0]["payload"],
        json!({
            "CallSid": "CA1234567890ABCDE",
            "Caller": "+14158675310",
            "Digits": "1234",
            "From": "+14158675310",
            "To": "+18005551212"
        })
    );
    assert!(events[0]["headers"].get("x-twilio-signature").is_none());
}

#[fcp_async_core::runtime::test]
async fn events_ingest_twilio_rejects_signed_params_for_a_different_payload() {
    let mut c = setup_connector_with_config(json!({
        "public_base_url": "https://example.com"
    }))
    .await;
    let created = create_endpoint(&mut c, "/twilio", "twilio", "12345").await;
    let endpoint_id = created["endpoint_id"].as_str().unwrap();
    let url = "https://example.com/twilio";
    let signature = hmac_sha1_base64("12345", &format!("{url}BodybenignMessageSidSM123"));

    for (field, value) in [
        ("body", json!("Body=malicious&MessageSid=SM123")),
        (
            "payload",
            json!({"Body": "malicious", "MessageSid": "SM123"}),
        ),
    ] {
        let mut request = json!({
            "operation_id": "webhook.events.ingest",
            "input": {
                "method": "POST",
                "path": "/twilio",
                "url": url,
                "headers": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "X-Twilio-Signature": signature
                },
                "params": {"Body": "benign", "MessageSid": "SM123"}
            }
        });
        request["input"][field] = value;
        assert_external_status(c.handle_invoke(request).await, 401);
    }

    let recent = c
        .handle_invoke(json!({
            "operation_id": "webhook.events.recent",
            "input": {"endpoint_id": endpoint_id}
        }))
        .await
        .unwrap();
    assert!(recent["events"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn events_ingest_twilio_json_binds_raw_bytes_and_rejects_content_type_switches() {
    let mut c = setup_connector_with_config(json!({
        "public_base_url": "https://example.com"
    }))
    .await;
    let created = create_endpoint(&mut c, "/twilio", "twilio", "12345").await;
    let endpoint_id = created["endpoint_id"].as_str().unwrap();
    let raw_body = "{\"CallSid\":\"CA123\",\"text\":\"hello\"}\n";
    let url = "https://example.com/twilio?bodySHA256=68a14dcded4795acd68ffbd71343b19bb3d210267a488c66ecb52f41e5cc453b";
    let signature = "IpXwHS3LnYu8UbfkceUMkviFkO4=";
    let accepted = c
        .handle_invoke(json!({
            "operation_id": "webhook.events.ingest",
            "input": {
                "method": "POST",
                "path": "/twilio",
                "url": url,
                "headers": {
                    "Content-Type": "application/json",
                    "X-Twilio-Signature": signature
                },
                "body": raw_body
            }
        }))
        .await
        .unwrap();
    assert_eq!(accepted["status_code"], 202);

    assert_external_status(
        c.handle_invoke(json!({
            "operation_id": "webhook.events.ingest",
            "input": {
                "path": "/twilio",
                "url": url,
                "delivery_id": "changed-unsigned-json-delivery-id",
                "headers": {
                    "Content-Type": "application/json",
                    "X-Twilio-Signature": signature
                },
                "body": raw_body
            }
        }))
        .await,
        409,
    );

    for (content_type, body) in [
        ("application/json", raw_body.trim_end()),
        (
            "application/json",
            "{\"CallSid\":\"CA123\",\"text\":\"tampered\"}\n",
        ),
        ("application/x-www-form-urlencoded", ""),
        ("application/x-www-form-urlencoded", "="),
    ] {
        assert_external_status(
            c.handle_invoke(json!({
                "operation_id": "webhook.events.ingest",
                "input": {
                    "method": "POST",
                    "path": "/twilio",
                    "url": url,
                    "headers": {
                        "Content-Type": content_type,
                        "X-Twilio-Signature": signature
                    },
                    "body": body
                }
            }))
            .await,
            401,
        );
    }

    let recent = c
        .handle_invoke(json!({
            "operation_id": "webhook.events.recent",
            "input": {"endpoint_id": endpoint_id}
        }))
        .await
        .unwrap();
    let events = recent["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0]["payload"],
        json!({"CallSid": "CA123", "text": "hello"})
    );
    assert_eq!(events[0]["event_id"], accepted["event"]["event_id"]);
}

#[fcp_async_core::runtime::test]
async fn events_ingest_twilio_replay_identity_matches_signed_form_bytes_and_url() {
    let mut c = setup_connector_with_config(json!({
        "public_base_url": "https://example.com"
    }))
    .await;
    let created = create_endpoint(&mut c, "/twilio", "twilio", "12345").await;
    let url = "https://example.com/twilio";
    let mut input = json!({
        "path": "/twilio",
        "url": url,
        "delivery_id": "original",
        "headers": {
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Twilio-Signature": hmac_sha1_base64("12345", &format!("{url}ABC"))
        },
        "body": "A=BC"
    });
    c.handle_invoke(json!({"operation_id": "webhook.events.ingest", "input": input}))
        .await
        .unwrap();

    // Both field-boundary changes and equivalent form encodings authenticate
    // the exact same concatenated bytes. Neither may create a new replay key.
    for (index, body) in ["AB=C", "A=%42C&A=BC"].into_iter().enumerate() {
        input["body"] = json!(body);
        input["delivery_id"] = json!(format!("changed-unsigned-id-{index}"));
        assert_external_status(
            c.handle_invoke(json!({"operation_id": "webhook.events.ingest", "input": input}))
                .await,
            409,
        );
    }

    // A different signed query may represent a distinct callback. Public-ID
    // deduplication still applies independently, so give it a distinct ID.
    let other_url = format!("{url}?callback=second");
    input["url"] = json!(other_url);
    input["body"] = json!("A=BC");
    input["delivery_id"] = json!("second-query");
    input["headers"]["X-Twilio-Signature"] =
        json!(hmac_sha1_base64("12345", &format!("{other_url}ABC")));
    c.handle_invoke(json!({"operation_id": "webhook.events.ingest", "input": input}))
        .await
        .unwrap();

    let recent = c
        .handle_invoke(json!({
            "operation_id": "webhook.events.recent",
            "input": {"endpoint_id": created["endpoint_id"]}
        }))
        .await
        .unwrap();
    assert_eq!(recent["events"].as_array().unwrap().len(), 2);
    assert!(
        recent["events"]
            .as_array()
            .unwrap()
            .iter()
            .all(|event| event["payload"] == json!({"A": "BC"}))
    );
}

#[fcp_async_core::runtime::test]
async fn events_ingest_twilio_accepts_status_changes_but_rejects_equivalent_form_retries() {
    let mut c = setup_connector_with_config(json!({
        "public_base_url": "https://example.com"
    }))
    .await;
    let created = create_endpoint(&mut c, "/twilio", "twilio", "12345").await;
    let endpoint_id = created["endpoint_id"].as_str().unwrap();
    let url = "https://example.com/twilio";
    let mut delivery_ids = Vec::new();

    for status in ["sent", "delivered"] {
        let signature = hmac_sha1_base64(
            "12345",
            &format!("{url}MessageSidSM123MessageStatus{status}To+15551234567"),
        );
        let accepted = c
            .handle_invoke(json!({
                "operation_id": "webhook.events.ingest",
                "input": {
                    "method": "POST",
                    "path": "/twilio",
                    "url": url,
                    "headers": {
                        "Content-Type": "application/x-www-form-urlencoded",
                        "X-Twilio-Signature": signature
                    },
                    "body": format!("MessageSid=SM123&MessageStatus={status}&To=%2B15551234567")
                }
            }))
            .await
            .unwrap();
        assert_eq!(accepted["status_code"], 202);
        delivery_ids.push(accepted["event"]["event_id"].as_str().unwrap().to_string());
    }
    assert_ne!(delivery_ids[0], delivery_ids[1]);

    // Parameter order, escape spelling, and duplicate identical values are
    // unsigned distinctions in Twilio's canonical form signature.
    let retry_signature = hmac_sha1_base64(
        "12345",
        &format!("{url}MessageSidSM123MessageStatusdeliveredTo+15551234567"),
    );
    assert_external_status(
        c.handle_invoke(json!({
            "operation_id": "webhook.events.ingest",
            "input": {
                "method": "POST",
                "path": "/twilio",
                "url": url,
                "delivery_id": "changed-unsigned-status-delivery-id",
                "headers": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "X-Twilio-Signature": retry_signature
                },
                "body": "To=%2b15551234567&MessageStatus=delivered&MessageSid=SM123&MessageStatus=delivered"
            }
        }))
        .await,
        409,
    );

    let recent = c
        .handle_invoke(json!({
            "operation_id": "webhook.events.recent",
            "input": {"endpoint_id": endpoint_id}
        }))
        .await
        .unwrap();
    let events = recent["events"].as_array().unwrap();
    assert_eq!(events.len(), 2);
    assert!(
        events
            .iter()
            .all(|event| event["payload"]["MessageSid"] == "SM123")
    );
    let mut statuses = events
        .iter()
        .map(|event| event["payload"]["MessageStatus"].as_str().unwrap())
        .collect::<Vec<_>>();
    statuses.sort_unstable();
    assert_eq!(statuses, vec!["delivered", "sent"]);
}

// -- Authenticated cursor replay --

#[fcp_async_core::runtime::test]
async fn events_poll_pages_verified_events_without_disclosing_other_endpoints_or_secrets() {
    let mut c = setup_connector().await;
    let first = create_endpoint(&mut c, "/poll", "github", "poll-secret").await;
    let second = create_endpoint(&mut c, "/other-poll", "github", "other-secret").await;
    for index in 0..3 {
        let body = json!({"index": index}).to_string();
        ingest(
            &mut c,
            "/poll",
            json!({
                "Content-Type": "application/json",
                "X-Hub-Signature-256": hmac_sha256_hex("poll-secret", &body),
                "Authorization": "Bearer must-not-leak"
            }),
            &body,
            &format!("poll-{index}"),
        )
        .await
        .unwrap();
    }
    let other_body = r#"{"private":"other endpoint"}"#;
    ingest(
        &mut c,
        "/other-poll",
        json!({
            "Content-Type": "application/json",
            "X-Hub-Signature-256": hmac_sha256_hex("other-secret", other_body)
        }),
        other_body,
        "other-poll",
    )
    .await
    .unwrap();
    let first_page = c
        .handle_invoke(json!({
            "operation_id": "webhook.events.poll",
            "input": {"endpoint_id": first["endpoint_id"], "limit": 2}
        }))
        .await
        .unwrap();
    assert_eq!(first_page["endpoint_id"], first["endpoint_id"]);
    assert_eq!(first_page["has_more"], true);
    assert_eq!(first_page["retention"]["history_truncated"], false);
    let events = first_page["events"].as_array().unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["event_id"], "poll-0");
    assert_eq!(events[1]["event_id"], "poll-1");
    assert!(events[0]["sequence"].as_u64() < events[1]["sequence"].as_u64());
    for event in events {
        assert!(event.get("source_ip").is_none());
        assert!(event["source_ip_hash"].as_str().is_some());
        assert!(event["headers"].get("authorization").is_none());
        assert!(event["headers"].get("x-hub-signature-256").is_none());
        assert_eq!(event["signature_valid"], true);
        assert_eq!(event["endpoint_id"], first["endpoint_id"]);
    }
    let resume = json!({
        "operation_id": "webhook.events.poll",
        "input": {
            "endpoint_id": first["endpoint_id"],
            "cursor": first_page["next_cursor"],
            "limit": 2
        }
    });
    let last_page = c.handle_invoke(resume.clone()).await.unwrap();
    assert_eq!(last_page["events"].as_array().unwrap().len(), 1);
    assert_eq!(last_page["events"][0]["event_id"], "poll-2");
    assert_eq!(last_page["has_more"], false);
    assert_eq!(c.handle_invoke(resume).await.unwrap(), last_page);
    assert_external_status(
        c.handle_invoke(json!({
            "operation_id": "webhook.events.poll",
            "input": {"endpoint_id": second["endpoint_id"], "cursor": first_page["next_cursor"]}
        }))
        .await,
        400,
    );
}

#[fcp_async_core::runtime::test]
async fn events_poll_rejects_invalid_parameters_and_tampered_cursors() {
    let mut c = setup_connector().await;
    let endpoint = create_endpoint(&mut c, "/poll-invalid", "github", "poll-secret").await;
    let empty = c
        .handle_invoke(json!({
            "operation_id": "webhook.events.poll",
            "input": {"endpoint_id": endpoint["endpoint_id"]}
        }))
        .await
        .unwrap();
    assert_eq!(empty["events"], json!([]));
    assert_eq!(empty["retention"]["oldest_available_sequence"], json!(null));
    let cursor = empty["next_cursor"].as_str().unwrap();
    let mut tampered = cursor.as_bytes().to_vec();
    let tag_position = tampered.len() - 2;
    tampered[tag_position] = if tampered[tag_position] == b'A' {
        b'B'
    } else {
        b'A'
    };
    for input in [
        json!({}),
        json!({"endpoint_id": ""}),
        json!({"endpoint_id": endpoint["endpoint_id"], "limit": 0}),
        json!({"endpoint_id": endpoint["endpoint_id"], "limit": 101}),
        json!({"endpoint_id": endpoint["endpoint_id"], "limit": -1}),
        json!({"endpoint_id": endpoint["endpoint_id"], "max_bytes": 0}),
        json!({"endpoint_id": endpoint["endpoint_id"], "max_bytes": 16_777_217}),
        json!({"endpoint_id": endpoint["endpoint_id"], "max_bytes": "100"}),
        json!({"endpoint_id": endpoint["endpoint_id"], "start": "yesterday"}),
        json!({"endpoint_id": endpoint["endpoint_id"], "cursor": null}),
        json!({"endpoint_id": endpoint["endpoint_id"], "cursor": cursor, "start": "earliest"}),
        json!({"endpoint_id": endpoint["endpoint_id"], "cursor": String::from_utf8(tampered).unwrap()}),
        json!({"endpoint_id": endpoint["endpoint_id"], "extra": true}),
    ] {
        assert_external_status(
            c.handle_invoke(json!({"operation_id": "webhook.events.poll", "input": input}))
                .await,
            400,
        );
    }
}

#[fcp_async_core::runtime::test]
async fn events_poll_latest_survives_rehandshake_but_expires_after_reconfiguration() {
    let mut c = setup_connector().await;
    let endpoint = create_endpoint(&mut c, "/poll-latest", "github", "poll-secret").await;
    let initial = c
        .handle_invoke(json!({
            "operation_id": "webhook.events.poll",
            "input": {"endpoint_id": endpoint["endpoint_id"], "start": "latest"}
        }))
        .await
        .unwrap();
    assert_eq!(initial["events"], json!([]));
    let body = r#"{"new":true}"#;
    ingest(
        &mut c,
        "/poll-latest",
        json!({
            "Content-Type": "application/json",
            "X-Hub-Signature-256": hmac_sha256_hex("poll-secret", body)
        }),
        body,
        "poll-after-latest",
    )
    .await
    .unwrap();
    let params = json!({
        "operation_id": "webhook.events.poll",
        "input": {"endpoint_id": endpoint["endpoint_id"], "cursor": initial["next_cursor"]}
    });
    let stale_authority = c.request(params.clone()).unwrap();
    c.handshake().await;
    assert!(c.inner.handle_invoke(json!(stale_authority)).await.is_err());
    let resumed = c.handle_invoke(params.clone()).await.unwrap();
    assert_eq!(resumed["events"][0]["event_id"], "poll-after-latest");
    assert_external_status(
        c.handle_invoke(json!({
            "operation_id": "webhook.events.poll",
            "input": {"endpoint_id": endpoint["endpoint_id"], "max_bytes": 1}
        }))
        .await,
        413,
    );
    c.inner
        .handle_configure(json!({"public_base_url": "https://hooks.flywheel.test"}))
        .await
        .unwrap();
    c.handshake().await;
    let error = c.handle_invoke(params).await.unwrap_err();
    assert!(matches!(error, FcpError::External {
        status_code: Some(410), retryable: false, ref message, ..
    } if message == "webhook_cursor_expired"));
}

#[fcp_async_core::runtime::test]
async fn events_poll_reports_unread_retention_gap_and_allows_explicit_restart() {
    let mut c = setup_connector_with_config(json!({
        "public_base_url": "https://hooks.flywheel.test", "rate_limit_max": 10_000
    }))
    .await;
    let endpoint = create_endpoint(&mut c, "/poll-gap", "github", "poll-secret").await;
    let initial = c
        .handle_invoke(json!({
            "operation_id": "webhook.events.poll",
            "input": {"endpoint_id": endpoint["endpoint_id"], "start": "latest"}
        }))
        .await
        .unwrap();
    for index in 0..=fcp_webhook_receiver::client::MAX_EVENTS_PER_ENDPOINT {
        let body = json!({"index": index}).to_string();
        ingest(
            &mut c,
            "/poll-gap",
            json!({
                "Content-Type": "application/json",
                "X-Hub-Signature-256": hmac_sha256_hex("poll-secret", &body)
            }),
            &body,
            &format!("gap-{index}"),
        )
        .await
        .unwrap();
    }
    let error = c
        .handle_invoke(json!({
            "operation_id": "webhook.events.poll",
            "input": {"endpoint_id": endpoint["endpoint_id"], "cursor": initial["next_cursor"]}
        }))
        .await
        .unwrap_err();
    assert!(matches!(error, FcpError::External {
        status_code: Some(410), retryable: false, ref message, ..
    } if message == "webhook_replay_gap"));
    let restarted = c
        .handle_invoke(json!({
            "operation_id": "webhook.events.poll",
            "input": {"endpoint_id": endpoint["endpoint_id"], "start": "earliest", "limit": 1}
        }))
        .await
        .unwrap();
    assert_eq!(restarted["retention"]["history_truncated"], true);
    assert_eq!(restarted["events"][0]["event_id"], "gap-1");
    assert_eq!(restarted["has_more"], true);
}

#[fcp_async_core::runtime::test]
async fn events_poll_binds_signed_authority_to_actual_endpoint_before_cursor_processing() {
    let mut c = setup_connector().await;
    let allowed = create_endpoint(&mut c, "/poll-allowed", "github", "secret-one").await;
    let denied = create_endpoint(&mut c, "/poll-denied", "github", "secret-two").await;
    let constraints = CapabilityConstraints {
        resource_allow: vec![allowed["url"].as_str().unwrap().into()],
        resource_deny: vec![denied["url"].as_str().unwrap().into()],
        ..Default::default()
    };
    let now = Utc::now();
    let token = CapabilityToken::from_raw(
        CapabilityTokenBuilder::new()
            .capability_id("webhook.events.read")
            .zone_id("z:work")
            .principal("user:webhook-test")
            .operations(&["webhook.events.poll"])
            .issuer("node:webhook-test")
            .target_instance(&c.instance_id)
            .token_id(b"scoped-webhook-poll")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&fcp_cbor::to_canonical_cbor(&constraints).unwrap())
            .unwrap()
            .sign(&c.key)
            .unwrap(),
    );
    let mut request = c
        .request(json!({
            "operation_id": "webhook.events.poll",
            "input": {"endpoint_id": denied["endpoint_id"], "cursor": "not-a-cursor"}
        }))
        .unwrap();
    request.capability_token = token;
    let before = c.inner.handle_health().await.unwrap()["requests"].clone();
    assert!(c.inner.handle_invoke(json!(request.clone())).await.is_err());
    assert_eq!(c.inner.handle_health().await.unwrap()["requests"], before);
    request.id = RequestId::random();
    request.input = json!({"endpoint_id": allowed["endpoint_id"]});
    assert!(c.inner.handle_invoke(json!(request.clone())).await.is_ok());
    request.id = RequestId::random();
    request.zone_id = ZoneId::private();
    assert!(c.inner.handle_invoke(json!(request.clone())).await.is_err());
    request.zone_id = ZoneId::work();
    request.operation = OperationId::from_static("webhook.events.recent");
    assert!(c.inner.handle_invoke(json!(request)).await.is_err());
}

// -- Unknown operation / Simulate --

#[fcp_async_core::runtime::test]
async fn unknown_operation() {
    let mut c = setup_connector().await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "webhook.nope",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_operations() {
    let c = setup_connector().await;
    for op_id in [
        "webhook.endpoints.create",
        "webhook.endpoints.rotate_secret",
        "webhook.endpoints.delete",
        "webhook.endpoints.list",
        "webhook.events.recent",
        "webhook.events.poll",
        "webhook.events.ingest",
    ] {
        let result = c
            .handle_simulate(json!({"operation_id": op_id}))
            .await
            .unwrap();
        let needs_approval = matches!(
            op_id,
            "webhook.endpoints.create"
                | "webhook.endpoints.rotate_secret"
                | "webhook.endpoints.delete"
        );
        assert_eq!(
            result["would_succeed"], !needs_approval,
            "endpoint mutation previews must report the missing signed approval"
        );
    }
}

#[fcp_async_core::runtime::test]
async fn simulate_unknown() {
    let c = setup_connector().await;
    assert!(
        !c.handle_simulate(json!({"operation_id": "webhook.nope"}))
            .await
            .unwrap()["would_succeed"]
            .as_bool()
            .unwrap()
    );
}

// -- Invoke before ready --

#[fcp_async_core::runtime::test]
async fn invoke_before_configure_fails() {
    let mut c = WebhookReceiverConnector::new();
    assert!(
        c.handle_invoke(json!({
            "operation_id": "webhook.endpoints.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_missing_operation_id() {
    let mut c = setup_connector().await;
    assert!(c.handle_invoke(json!({"input": {}})).await.is_err());
}

// -- Counters --

#[fcp_async_core::runtime::test]
async fn counters_increment_on_success() {
    let mut c = setup_connector().await;
    c.handle_invoke(json!({
        "operation_id": "webhook.endpoints.list",
        "input": {}
    }))
    .await
    .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 0);
}

#[fcp_async_core::runtime::test]
async fn counters_error_increment() {
    let mut c = setup_connector().await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "webhook.endpoints.delete",
            "input": {"endpoint_id": "ep_nonexistent"}
        }))
        .await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 1);
}

#[fcp_async_core::runtime::test]
async fn counters_multiple_requests() {
    let mut c = setup_connector().await;
    for _ in 0..5 {
        c.handle_invoke(json!({
            "operation_id": "webhook.endpoints.list",
            "input": {}
        }))
        .await
        .unwrap();
    }
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 5);
    assert_eq!(h["errors"], 0);
}

// -- Health shows store stats --

#[fcp_async_core::runtime::test]
async fn health_shows_endpoint_count() {
    let mut c = setup_connector().await;
    c.handle_invoke(json!({
        "operation_id": "webhook.endpoints.create",
        "input": {"path": "/a", "signing_secret": "s"}
    }))
    .await
    .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["endpoints"], 1);
}

#[fcp_async_core::runtime::test]
async fn health_shows_event_count() {
    let c = setup_connector().await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["events"], 0);
}

// -- Shutdown clears store --

#[fcp_async_core::runtime::test]
async fn shutdown_clears_endpoints() {
    let mut c = setup_connector().await;
    c.handle_invoke(json!({
        "operation_id": "webhook.endpoints.create",
        "input": {"path": "/hooks/test", "signing_secret": "s"}
    }))
    .await
    .unwrap();
    c.handle_shutdown(json!({})).await.unwrap();

    // Re-configure and verify empty
    c.handle_configure(json!({})).await.unwrap();
    c.handshake().await;
    let list = c
        .handle_invoke(json!({
            "operation_id": "webhook.endpoints.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(list["endpoints"].as_array().unwrap().is_empty());
}

// -- Full create-list-delete lifecycle --

#[fcp_async_core::runtime::test]
async fn full_endpoint_lifecycle() {
    let mut c = setup_connector().await;

    // Create
    let created = c
        .handle_invoke(json!({
            "operation_id": "webhook.endpoints.create",
            "input": {"path": "/hooks/lifecycle", "signing_secret": "sec"}
        }))
        .await
        .unwrap();
    let ep_id = created["endpoint_id"].as_str().unwrap().to_string();

    // List - should have 1
    let list = c
        .handle_invoke(json!({
            "operation_id": "webhook.endpoints.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(list["endpoints"].as_array().unwrap().len(), 1);

    // Delete
    c.handle_invoke(json!({
        "operation_id": "webhook.endpoints.delete",
        "input": {"endpoint_id": ep_id}
    }))
    .await
    .unwrap();

    // List - should be empty
    let list = c
        .handle_invoke(json!({
            "operation_id": "webhook.endpoints.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(list["endpoints"].as_array().unwrap().is_empty());
}

// -- Double delete --

#[fcp_async_core::runtime::test]
async fn double_delete_fails() {
    let mut c = setup_connector().await;
    let created = c
        .handle_invoke(json!({
            "operation_id": "webhook.endpoints.create",
            "input": {"path": "/hooks/test", "signing_secret": "s"}
        }))
        .await
        .unwrap();
    let ep_id = created["endpoint_id"].as_str().unwrap();

    c.handle_invoke(json!({
        "operation_id": "webhook.endpoints.delete",
        "input": {"endpoint_id": ep_id}
    }))
    .await
    .unwrap();

    // Second delete should fail
    assert!(
        c.handle_invoke(json!({
            "operation_id": "webhook.endpoints.delete",
            "input": {"endpoint_id": ep_id}
        }))
        .await
        .is_err()
    );
}

// -- Reconfigure after shutdown --

#[fcp_async_core::runtime::test]
async fn reconfigure_after_shutdown() {
    let mut c = setup_connector().await;
    c.handle_shutdown(json!({})).await.unwrap();
    c.handle_configure(json!({"public_base_url": "https://hooks.flywheel.test"}))
        .await
        .unwrap();
    c.handshake().await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"]["state"], "ready");
}

#[fcp_async_core::runtime::test]
async fn endpoints_rotate_secret_returns_new_secret() {
    let mut c = setup_connector().await;
    let created = c
        .handle_invoke(json!({
            "operation_id": "webhook.endpoints.create",
            "input": {"path": "/hooks/rotate", "provider": "stripe"}
        }))
        .await
        .unwrap();
    let endpoint_id = created["endpoint_id"].as_str().unwrap();

    let rotated = c
        .handle_invoke(json!({
            "operation_id": "webhook.endpoints.rotate_secret",
            "input": {"endpoint_id": endpoint_id}
        }))
        .await
        .unwrap();
    assert_eq!(rotated["endpoint_id"], endpoint_id);
    assert_eq!(rotated["provider"], "stripe");
    assert_eq!(rotated["signing_secret_generated"], true);
    assert_ne!(created["signing_secret"], rotated["signing_secret"]);
}

#[fcp_async_core::runtime::test]
async fn self_check_degrades_for_local_test_base_url() {
    let mut c = WebhookReceiverConnector::new();
    c.handle_configure(json!({"public_base_url": "http://localhost:8080"}))
        .await
        .unwrap();
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "degraded");
    assert_eq!(check["reason_code"], "public_base_url_not_public");
}

// -- Real session and capability boundary (no fixture request repair) --

fn read_request(c: &SignedConnector) -> InvokeRequest {
    c.request(json!({"operation_id": "webhook.endpoints.list"}))
        .unwrap()
}

fn scoped_token(
    c: &SignedConnector,
    zone: &str,
    operation: &str,
    instance: Option<&str>,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut builder = CapabilityTokenBuilder::new()
        .capability_id("webhook.endpoints.read")
        .zone_id(zone)
        .principal("user:test")
        .operations(&[operation])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&fcp_cbor::to_canonical_cbor(&constraints).unwrap())
        .unwrap();
    if let Some(instance) = instance {
        builder = builder.target_instance(instance);
    }
    CapabilityToken::from_raw(builder.sign(&c.key).unwrap())
}

fn resign_approval(c: &SignedConnector, request: &mut InvokeRequest) {
    let approval = &mut request.approval_tokens[0];
    approval.signature = None;
    approval.signature = Some(
        c.approval_key
            .sign(&fcp_cbor::to_canonical_cbor(approval).unwrap())
            .to_bytes()
            .to_vec(),
    );
}

fn constrained_read_token(
    c: &SignedConnector,
    constraints: &CapabilityConstraints,
) -> CapabilityToken {
    let now = Utc::now();
    CapabilityToken::from_raw(
        CapabilityTokenBuilder::new()
            .capability_id("webhook.endpoints.read")
            .zone_id("z:work")
            .principal("user:test")
            .operations(&["webhook.endpoints.list"])
            .issuer("node:test")
            .target_instance(&c.instance_id)
            .token_id(b"limited-webhook-read")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&fcp_cbor::to_canonical_cbor(constraints).unwrap())
            .unwrap()
            .sign(&c.key)
            .unwrap(),
    )
}

#[fcp_async_core::runtime::test]
async fn authority_resource_constraints_cover_empty_and_aggregate_reads() {
    let mut c = setup_connector().await;
    let mut request = read_request(&c);
    request.capability_token = constrained_read_token(
        &c,
        &CapabilityConstraints {
            resource_allow: vec!["*".into()],
            resource_deny: vec!["*".into()],
            ..Default::default()
        },
    );
    assert!(c.inner.handle_invoke(json!(request.clone())).await.is_err());
    let preview = SimulateRequest::new(
        request.connector_id,
        request.operation,
        request.zone_id,
        request.input,
        request.capability_token,
    );
    assert_eq!(
        c.inner.handle_simulate(json!(preview)).await.unwrap()["would_succeed"],
        false
    );

    let first = create_endpoint(&mut c, "/allowed", "github", "first-secret").await;
    let second = create_endpoint(&mut c, "/restricted", "github", "second-secret").await;
    let mut request = read_request(&c);
    request.capability_token = constrained_read_token(
        &c,
        &CapabilityConstraints {
            resource_allow: vec!["*".into()],
            resource_deny: vec![second["url"].as_str().unwrap().into()],
            ..Default::default()
        },
    );
    assert!(c.inner.handle_invoke(json!(request)).await.is_err());
    let mut request = read_request(&c);
    request.capability_token = constrained_read_token(
        &c,
        &CapabilityConstraints {
            resource_allow: vec![first["url"].as_str().unwrap().into()],
            ..Default::default()
        },
    );
    assert!(c.inner.handle_invoke(json!(request)).await.is_err());
    let mut request = read_request(&c);
    request.capability_token = constrained_read_token(
        &c,
        &CapabilityConstraints {
            resource_allow: vec![
                first["url"].as_str().unwrap().into(),
                second["url"].as_str().unwrap().into(),
            ],
            ..Default::default()
        },
    );
    assert_eq!(
        c.inner.handle_invoke(json!(request)).await.unwrap()["endpoints"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[fcp_async_core::runtime::test]
async fn authority_signed_call_allowance_is_enforced_before_dispatch() {
    let mut c = setup_connector().await;
    let mut request = read_request(&c);
    request.capability_token = constrained_read_token(
        &c,
        &CapabilityConstraints {
            resource_allow: vec!["*".into()],
            max_calls: Some(1),
            ..Default::default()
        },
    );
    let preview = SimulateRequest::new(
        request.connector_id.clone(),
        request.operation.clone(),
        request.zone_id.clone(),
        request.input.clone(),
        request.capability_token.clone(),
    );
    for _ in 0..3 {
        assert_eq!(
            c.inner.handle_simulate(json!(preview)).await.unwrap()["would_succeed"],
            true
        );
    }
    c.inner.handle_invoke(json!(request.clone())).await.unwrap();
    request.id = RequestId::random();
    assert!(c.inner.handle_invoke(json!(request)).await.is_err());
    assert_eq!(c.inner.handle_health().await.unwrap()["requests"], 1);
    assert_eq!(
        c.inner.handle_simulate(json!(preview)).await.unwrap()["would_succeed"],
        false
    );
}

#[fcp_async_core::runtime::test]
async fn authority_typed_health_and_introspection_support_host_preparation() {
    let mut c = setup_connector().await;
    let health = c.inner.handle_health().await.unwrap();
    let typed: HealthSnapshot = serde_json::from_value(health.clone()).unwrap();
    assert!(typed.is_ready());
    assert_eq!(health["details"]["configured"], true);
    assert_eq!(health["details"]["handshaken"], true);
    assert_eq!(health["details"]["instance_id"], c.instance_id);
    assert_eq!(health["instance_id"], health["details"]["instance_id"]);
    let catalog: fcp_prelude::Introspection =
        serde_json::from_value(c.inner.handle_introspect().await.unwrap()).unwrap();
    assert_eq!(catalog.operations.len(), 8);
    let operation = catalog
        .operations
        .iter()
        .find(|op| op.id.as_str() == "webhook.endpoints.delete")
        .unwrap();
    assert_eq!(
        operation.requires_approval,
        Some(fcp_prelude::ApprovalMode::Interactive)
    );
    let request = c
        .request(json!({"operation_id": "webhook.health"}))
        .unwrap();
    let response = c.inner.handle_invoke(json!(request)).await.unwrap();
    assert_eq!(response["details"]["instance_id"], c.instance_id);
}

#[fcp_async_core::runtime::test]
async fn authority_missing_token_cannot_read_events_or_mutate_endpoints() {
    let mut c = setup_connector().await;
    for operation in [
        "webhook.endpoints.list",
        "webhook.events.recent",
        "webhook.events.poll",
        "webhook.endpoints.create",
    ] {
        let request = c
            .request(json!({"operation_id": operation, "input": {"path": "/denied"}}))
            .unwrap();
        let mut params = json!(request);
        params.as_object_mut().unwrap().remove("capability_token");
        assert!(c.inner.handle_invoke(params).await.is_err());
    }
    let health = c.inner.handle_health().await.unwrap();
    assert_eq!(health["requests"], 0);
    assert_eq!(health["endpoints"], 0);
}

#[fcp_async_core::runtime::test]
async fn authority_rejects_wrong_zone_operation_connector_and_instance() {
    let mut c = setup_connector().await;
    let original = read_request(&c);
    let mut bad = original.clone();
    bad.zone_id = ZoneId::private();
    assert!(c.inner.handle_invoke(json!(bad)).await.is_err());
    let mut bad = original.clone();
    bad.operation = OperationId::from_static("webhook.health");
    assert!(c.inner.handle_invoke(json!(bad)).await.is_err());
    let mut bad = original.clone();
    bad.connector_id = ConnectorId::from_static("fcp.other");
    assert!(c.inner.handle_invoke(json!(bad)).await.is_err());
    for (zone, instance) in [
        ("z:private", Some(c.instance_id.as_str())),
        ("z:work", Some("wrong-instance")),
        ("z:work", None),
    ] {
        let mut bad = original.clone();
        bad.capability_token = scoped_token(&c, zone, "webhook.endpoints.list", instance);
        assert!(c.inner.handle_invoke(json!(bad)).await.is_err());
    }
    assert!(c.inner.handle_invoke(json!(original)).await.is_ok());
    assert_eq!(c.inner.handle_health().await.unwrap()["requests"], 1);
}

#[fcp_async_core::runtime::test]
async fn authority_rejects_other_signer_and_unnegotiated_capabilities() {
    let mut c = setup_connector().await;
    let request = read_request(&c);
    let mut handshake = handshake_request(&Ed25519SigningKey::from_bytes(&[9; 32]).unwrap());
    let response = c
        .inner
        .handle_handshake(json!(handshake.clone()))
        .await
        .unwrap();
    c.instance_id = response["instance_id"].as_str().unwrap().to_owned();
    let wrong_signer = read_request(&c);
    assert!(matches!(
        c.inner.handle_invoke(json!(wrong_signer)).await,
        Err(FcpError::InvalidSignature)
    ));
    assert!(c.inner.handle_invoke(json!(request)).await.is_err());
    handshake.host_public_key = c.key.verifying_key().to_bytes();
    handshake.capabilities_requested.clear();
    let response = c.inner.handle_handshake(json!(handshake)).await.unwrap();
    c.instance_id = response["instance_id"].as_str().unwrap().to_owned();
    assert_eq!(response["capabilities_granted"], json!([]));
    let request = read_request(&c);
    assert!(c.inner.handle_invoke(json!(request)).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn authority_failed_handshake_revokes_prior_session() {
    let mut c = setup_connector().await;
    let request = read_request(&c);
    assert!(
        c.inner
            .handle_handshake(json!({"session_id": "untrusted"}))
            .await
            .is_err()
    );
    assert!(c.inner.handle_invoke(json!(request)).await.is_err());
    assert_eq!(
        c.inner.handle_health().await.unwrap()["details"]["handshaken"],
        false
    );
    c.handshake().await;
    let mut handshake = handshake_request(&c.key);
    handshake.zone = ZoneId::public();
    assert!(c.inner.handle_handshake(json!(handshake)).await.is_err());
    assert_eq!(
        c.inner.handle_health().await.unwrap()["details"]["handshaken"],
        false
    );
}

#[fcp_async_core::runtime::test]
async fn authority_rehandshake_rotates_instance_and_rejects_prior_tokens() {
    let mut c = setup_connector().await;
    let request = read_request(&c);
    let previous = c.instance_id.clone();
    c.handshake().await;
    assert_ne!(previous, c.instance_id);
    assert!(c.inner.handle_invoke(json!(request)).await.is_err());
    let request = read_request(&c);
    assert!(c.inner.handle_invoke(json!(request)).await.is_ok());
}

#[fcp_async_core::runtime::test]
async fn authority_reconfiguration_clears_zone_state_and_failed_config_revokes() {
    let mut c = setup_connector().await;
    create_endpoint(&mut c, "/private-state", "github", "secret").await;
    let mut handshake = handshake_request(&c.key);
    handshake.zone = ZoneId::private();
    assert!(
        c.inner
            .handle_handshake(json!(handshake.clone()))
            .await
            .is_err()
    );
    assert_eq!(c.inner.handle_health().await.unwrap()["endpoints"], 1);
    c.inner.handle_configure(json!({})).await.unwrap();
    assert_eq!(c.inner.handle_health().await.unwrap()["endpoints"], 0);
    c.inner.handle_handshake(json!(handshake)).await.unwrap();
    assert!(
        c.inner
            .handle_configure(json!({"approval_public_key": [1, 2]}))
            .await
            .is_err()
    );
    let health = c.inner.handle_health().await.unwrap();
    assert_eq!(health["details"]["configured"], false);
    assert_eq!(health["details"]["handshaken"], false);
}

#[fcp_async_core::runtime::test]
async fn authority_endpoint_mutations_require_independent_signed_approvals() {
    let mut c = setup_connector().await;
    let created = create_endpoint(&mut c, "/approved", "github", "secret").await;
    for (operation, input) in [
        ("webhook.endpoints.create", json!({"path": "/denied"})),
        (
            "webhook.endpoints.rotate_secret",
            json!({"endpoint_id": created["endpoint_id"]}),
        ),
        (
            "webhook.endpoints.delete",
            json!({"endpoint_id": created["endpoint_id"]}),
        ),
    ] {
        let request = c
            .request(json!({"operation_id": operation, "input": input}))
            .unwrap();
        let mut absent = request.clone();
        absent.approval_tokens.clear();
        assert!(c.inner.handle_invoke(json!(absent)).await.is_err());
        let mut unsigned = request.clone();
        unsigned.approval_tokens[0].signature = None;
        assert!(c.inner.handle_invoke(json!(unsigned)).await.is_err());
        let mut wrong_signer = request;
        wrong_signer.approval_tokens[0].signature = None;
        wrong_signer.approval_tokens[0].signature = Some(
            c.key
                .sign(&fcp_cbor::to_canonical_cbor(&wrong_signer.approval_tokens[0]).unwrap())
                .to_bytes()
                .to_vec(),
        );
        assert!(c.inner.handle_invoke(json!(wrong_signer)).await.is_err());
    }
    assert_eq!(c.inner.handle_health().await.unwrap()["endpoints"], 1);
}

#[fcp_async_core::runtime::test]
async fn authority_valid_signatures_do_not_bypass_approval_scope_or_expiry() {
    let mut c = setup_connector().await;
    let request = c
        .request(
            json!({"operation_id": "webhook.endpoints.create", "input": {"path": "/approved"}}),
        )
        .unwrap();
    let mut altered_input = request.clone();
    altered_input.input["path"] = json!("/different");
    assert!(c.inner.handle_invoke(json!(altered_input)).await.is_err());
    let mut altered_id = request.clone();
    altered_id.id = RequestId::random();
    assert!(c.inner.handle_invoke(json!(altered_id)).await.is_err());
    let mut wrong_zone = request.clone();
    wrong_zone.approval_tokens[0].zone_id = ZoneId::private();
    resign_approval(&c, &mut wrong_zone);
    assert!(c.inner.handle_invoke(json!(wrong_zone)).await.is_err());
    let mut expired = request.clone();
    expired.approval_tokens[0].expires_at_ms = 1;
    resign_approval(&c, &mut expired);
    assert!(c.inner.handle_invoke(json!(expired)).await.is_err());
    let mut wrong_op = request.clone();
    if let ApprovalScope::Execution(scope) = &mut wrong_op.approval_tokens[0].scope {
        scope.method_pattern = "webhook.endpoints.delete".into();
    }
    resign_approval(&c, &mut wrong_op);
    assert!(c.inner.handle_invoke(json!(wrong_op)).await.is_err());
    assert_eq!(c.inner.handle_health().await.unwrap()["endpoints"], 0);
    assert!(c.inner.handle_invoke(json!(request)).await.is_ok());
}

#[fcp_async_core::runtime::test]
async fn authority_missing_approval_key_allows_reads_but_denies_mutations() {
    let mut c = setup_connector().await;
    c.inner.handle_configure(json!({})).await.unwrap();
    c.handshake().await;
    let read = read_request(&c);
    assert!(c.inner.handle_invoke(json!(read)).await.is_ok());
    let write = c
        .request(json!({"operation_id": "webhook.endpoints.create", "input": {"path": "/denied"}}))
        .unwrap();
    assert!(c.inner.handle_invoke(json!(write)).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn authority_simulate_verifies_without_mutation_or_call_charge() {
    let mut c = setup_connector().await;
    let request = read_request(&c);
    let preview = SimulateRequest::new(
        request.connector_id.clone(),
        request.operation.clone(),
        request.zone_id.clone(),
        request.input.clone(),
        request.capability_token.clone(),
    );
    let result = c
        .inner
        .handle_simulate(json!(preview.clone()))
        .await
        .unwrap();
    assert_eq!(result["would_succeed"], true);
    assert_eq!(c.inner.handle_health().await.unwrap()["requests"], 0);
    let mut denied = preview;
    denied.zone_id = ZoneId::private();
    assert_eq!(
        c.inner.handle_simulate(json!(denied)).await.unwrap()["would_succeed"],
        false
    );
    c.inner.handle_invoke(json!(request)).await.unwrap();
    assert_eq!(c.inner.handle_health().await.unwrap()["requests"], 1);
}
