//! Host admission proofs using the production webhook receiver.
//!
//! Only the process transport is replaced by an in-process RPC channel. The
//! host's registry, capability verifier, zone policy, retained invocation
//! lifecycle and the receiver's bound authority/signature checks all run.
//!
//! The inventory is the explicit host-first form without a manifest. These
//! tests do not claim to establish the separate quorum-signed state-write lease
//! required when a manifest declares this connector a singleton writer.

#![allow(clippy::too_many_lines)]

use std::sync::atomic::AtomicUsize;

use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_host::SignedDeploymentEvidence;
use fcp_host::webhook_ingress::{WEBHOOK_INGRESS_OPERATION, WebhookIngressConfig, response_for};
use fcp_prelude::{
    ApprovalScope, CapabilityId, ExecutionScope, FcpError, PolicyPattern, TaintLevel,
};
use fcp_webhook_receiver::connector::WebhookReceiverConnector;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::*;

const CONNECTOR: &str = "fcp.webhook-receiver";
const BASE_URL: &str = "https://hooks.host-admission.test/webhooks";
const ENDPOINT_PATH: &str = "/host-admission";
const PROVIDER_SECRET: &str = "host-admission-provider-signing-secret";

struct LiveReceiver {
    host: Arc<AppState>,
    binding: WebhookIngressConfig,
    signing_key: Ed25519SigningKey,
    instance: InstanceId,
    invocations: Arc<AtomicUsize>,
}

impl LiveReceiver {
    async fn new() -> Self {
        Self::with_provider("github").await
    }

    async fn with_provider(provider: &str) -> Self {
        let signing_key = Ed25519SigningKey::generate();
        let approval_key = Ed25519SigningKey::generate();
        let mut receiver = WebhookReceiverConnector::new();
        receiver
            .handle_configure(json!({
                "public_base_url": BASE_URL,
                "approval_public_key": approval_key.verifying_key().to_bytes(),
            }))
            .await
            .expect("configure production receiver");
        let handshake = receiver
            .handle_handshake(json!(HandshakeRequest {
                protocol_version: "2.0".to_owned(),
                zone: ZoneId::work(),
                zone_dir: None,
                host_public_key: signing_key.verifying_key().to_bytes(),
                nonce: [47; 32],
                capabilities_requested: [
                    "webhook.endpoints.write",
                    "webhook.endpoints.read",
                    "webhook.events.write",
                    "webhook.events.read",
                ]
                .into_iter()
                .map(|id| CapabilityId::new(id).expect("capability id"))
                .collect(),
                host: None,
                transport_caps: None,
                requested_instance_id: None,
            }))
            .await
            .expect("receiver establishes its actual bound instance");
        let instance: InstanceId =
            serde_json::from_value(handshake["instance_id"].clone()).expect("receiver instance id");
        provision_endpoint(
            &mut receiver,
            &signing_key,
            &approval_key,
            &instance,
            provider,
        )
        .await;

        let invocations = Arc::new(AtomicUsize::new(0));
        let observed_invocations = Arc::clone(&invocations);
        let (runner_tx, mut runner_rx) =
            mpsc::channel::<ConnectorRpcRequest>(CONNECTOR_RPC_QUEUE_CAPACITY);
        let runner_task = task::spawn(async move {
            while let Some(request) = runner_rx.recv().await {
                if !request.rpc.try_begin() {
                    continue;
                }
                let result = match request.method.as_str() {
                    "health" => receiver.handle_health().await,
                    "introspect" => receiver.handle_introspect().await,
                    "self_check" => receiver.handle_self_check().await,
                    "handshake" => receiver.handle_handshake(request.params).await,
                    "invoke" => {
                        observed_invocations.fetch_add(1, Ordering::SeqCst);
                        let invocation: InvokeRequest =
                            serde_json::from_value(request.params.clone())
                                .expect("host sends canonical InvokeRequest");
                        let response = match receiver.handle_invoke(request.params).await {
                            Ok(output) => InvokeResponse::ok(invocation.id, output),
                            Err(error) => InvokeResponse::error(invocation.id, error),
                        };
                        Ok(json!(response))
                    }
                    "shutdown" => receiver.handle_shutdown(request.params).await,
                    other => panic!("unexpected receiver RPC {other}"),
                };
                // Match the real connector's JSON-RPC framing, including FCP
                // errors inside the canonical invocation response.
                let reply = match result {
                    Ok(result) => json!({"jsonrpc": "2.0", "result": result}),
                    Err(error) => json!({"jsonrpc": "2.0", "error": error.to_response()}),
                };
                if request.rpc.try_settle_reply() {
                    let _ = request.response_tx.send(Ok(reply));
                }
            }
        });

        let connector = Arc::new(SubprocessConnector {
            summary: ConnectorSummary {
                id: ConnectorId::from_static(CONNECTOR),
                name: "Production webhook receiver".to_owned(),
                description: Some("in-process transport, production receiver".to_owned()),
                version: semver::Version::new(0, 1, 0),
                categories: vec!["webhook".to_owned()],
                tool_count: 0,
                max_safety_tier: SafetyTier::Dangerous,
                enabled: true,
                health: ConnectorHealth::healthy(),
                last_health_check: None,
            },
            runner_tx,
            event_transport: None,
            _runner_task: runner_task,
            resilience: Arc::new(ResilienceLayer::default()),
            capability_verifying_key: Some(signing_key.verifying_key().to_bytes()),
            state_root: None,
            // The real handshake above established this zone and instance.
            // Repeating it would intentionally rotate the instance and make
            // the capability stale before the assertion can exercise it.
            handshaken_zone: futures_util::lock::Mutex::new(Some(ZoneId::work())),
        });
        connector.resilience.ensure_connector(&connector.summary.id);
        let inventory: ConnectorConfig = serde_json::from_value(json!({
            "id": CONNECTOR,
            "binary": "in-process-production-webhook-receiver",
            "allowed_zones": ["z:work"],
            "allowed_operations": [WEBHOOK_INGRESS_OPERATION],
            "enforce_empty_allow_lists": true,
        }))
        .expect("narrow host-first inventory");
        let registry = tests::dispatcher_registry_with_connector(CONNECTOR, connector, inventory);
        let mut policy = host_runtime_policy(ZoneId::work());
        policy.principal_allow = vec![PolicyPattern {
            pattern: "user:test".to_owned(),
        }];
        policy.connector_allow = vec![PolicyPattern {
            pattern: CONNECTOR.to_owned(),
        }];
        policy.capability_allow = vec![PolicyPattern {
            pattern: "webhook.events.write".to_owned(),
        }];
        policy.capability_ceiling =
            vec![CapabilityId::new("webhook.events.write").expect("intake capability")];
        let host = tests::dispatcher_app_state(
            registry,
            Arc::new(HostAdminStateStore::default()),
            Some(signing_key.verifying_key()),
            HashMap::from([(ZoneId::work(), policy)]),
        );
        let token = tests::test_capability_token_for_instance(
            &signing_key,
            "webhook.events.write",
            WEBHOOK_INGRESS_OPERATION,
            "z:work",
            &instance,
        );
        let binding = WebhookIngressConfig::new(
            ConnectorId::from_static(CONNECTOR),
            ZoneId::work(),
            token,
            BASE_URL.to_owned(),
            1024 * 1024,
            15_000,
            8,
        )
        .expect("host ingress authority");
        Self {
            host,
            binding,
            signing_key,
            instance,
            invocations,
        }
    }

    fn enable_live_evidence(&mut self) -> tempfile::TempDir {
        let directory = tempfile::tempdir().expect("health evidence directory");
        let evidence_path = directory.path().join("health-evidence.json");
        let health_key = Ed25519SigningKey::generate();
        let service = deployment_evidence::DeploymentEvidenceService::new(
            "webhook-host-admission".to_owned(),
            ZoneId::work(),
            health_key.verifying_key(),
            evidence_path.clone(),
            fcp_host::MIN_HEALTHY_MESH_PEERS_FOR_ACTIVE,
        )
        .expect("real deployment evidence service");
        service
            .validate_key_separation(Some(&self.signing_key.verifying_key()), None)
            .expect("health observer is independent of capability authority");
        let now = u64::try_from(Utc::now().timestamp_millis()).expect("current time");
        let evidence = SignedDeploymentEvidence::sign(
            service.challenge(),
            MeshQuorumSignals::fully_active(2),
            1,
            now,
            now + 30_000,
            &health_key,
        )
        .expect("independently signed bounded health observation");
        std::fs::write(
            evidence_path,
            serde_json::to_vec(&evidence).expect("health evidence JSON"),
        )
        .expect("publish evidence for the actual service challenge");
        Arc::get_mut(&mut self.host)
            .expect("host has not started any owned invocation")
            .deployment_evidence = Some(Arc::new(service));
        directory
    }

    fn request(&self, sequence: u64) -> InvokeRequest {
        let raw = format!("{{ \"sequence\" : {sequence}, \"event\" : \"host-proof\" }}\n");
        self.request_with_signature_for(&raw, &raw)
    }

    fn request_with_signature_for(&self, body: &str, signed_body: &str) -> InvokeRequest {
        let mut hmac =
            Hmac::<Sha256>::new_from_slice(PROVIDER_SECRET.as_bytes()).expect("HMAC key");
        hmac.update(signed_body.as_bytes());
        let signature = format!("sha256={}", hex::encode(hmac.finalize().into_bytes()));
        let headers = HeaderMap::from_iter([
            (
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            ),
            (
                axum::http::HeaderName::from_static("x-hub-signature-256"),
                HeaderValue::from_str(&signature).expect("signature header"),
            ),
        ]);
        self.binding
            .build_request(
                &headers,
                &"/webhooks/host-admission".parse().expect("request URI"),
                body,
                Some("192.0.2.57".parse().expect("observed peer")),
            )
            .expect("translate provider delivery")
    }

    fn slack_request(&self, body: &str, signed_body: &str) -> InvokeRequest {
        let timestamp = Utc::now().timestamp().to_string();
        let mut hmac = Hmac::<Sha256>::new_from_slice(PROVIDER_SECRET.as_bytes()).unwrap();
        hmac.update(format!("v0:{timestamp}:{signed_body}").as_bytes());
        let signature = format!("v0={}", hex::encode(hmac.finalize().into_bytes()));
        let headers = HeaderMap::from_iter([
            (
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            ),
            (
                axum::http::HeaderName::from_static("x-slack-signature"),
                HeaderValue::from_str(&signature).unwrap(),
            ),
            (
                axum::http::HeaderName::from_static("x-slack-request-timestamp"),
                HeaderValue::from_str(&timestamp).unwrap(),
            ),
        ]);
        self.binding
            .build_request(
                &headers,
                &"/webhooks/host-admission".parse().unwrap(),
                body,
                Some("192.0.2.57".parse().unwrap()),
            )
            .expect("translate signed Slack verification")
    }

    async fn dispatch(
        &self,
        request: InvokeRequest,
    ) -> Result<InvokeResponse, (StatusCode, String)> {
        route_invoke_with_deadline(
            &self.host,
            request,
            None,
            Some(Instant::now() + Duration::from_secs(15)),
        )
        .await
    }
}

async fn provision_endpoint(
    receiver: &mut WebhookReceiverConnector,
    signing_key: &Ed25519SigningKey,
    approval_key: &Ed25519SigningKey,
    instance: &InstanceId,
    provider: &str,
) {
    let input = json!({
        "path": ENDPOINT_PATH,
        "provider": provider,
        "signing_secret": PROVIDER_SECRET,
    });
    let id = RequestId::random();
    let now = u64::try_from(Utc::now().timestamp_millis()).expect("timestamp");
    let mut approval = ApprovalToken::approved(
        format!("webhook-host-provision-{}", id.0),
        now - 1000,
        now + 60_000,
        "owner:host-ingress-test",
        ApprovalScope::Execution(ExecutionScope {
            connector_id: CONNECTOR.to_owned(),
            method_pattern: "webhook.endpoints.create".to_owned(),
            request_object_id: Some(ObjectId::from_unscoped_bytes(id.0.as_bytes())),
            input_hash: Some(
                *blake3::hash(&to_deterministic_cbor(&input).expect("input CBOR")).as_bytes(),
            ),
            input_constraints: Vec::new(),
        }),
        ZoneId::work(),
        None,
    );
    approval.signature = Some(
        approval_key
            .sign(&fcp_cbor::to_canonical_cbor(&approval).expect("approval CBOR"))
            .to_bytes()
            .to_vec(),
    );
    let request = InvokeRequest {
        r#type: "invoke".to_owned(),
        id,
        connector_id: ConnectorId::from_static(CONNECTOR),
        operation: OperationId::from_static("webhook.endpoints.create"),
        zone_id: ZoneId::work(),
        input,
        capability_token: tests::test_capability_token_for_instance(
            signing_key,
            "webhook.endpoints.write",
            "webhook.endpoints.create",
            "z:work",
            instance,
        ),
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: Some(15_000),
        correlation_id: None,
        provenance: None,
        approval_tokens: vec![approval],
    };
    receiver
        .handle_invoke(json!(request))
        .await
        .expect("independently approved endpoint provisioning");
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn webhook_ingress_admission_without_live_evidence_retains_evaluation_denial() {
    let fixture = LiveReceiver::new().await;
    let request = fixture.request(1);
    assert_eq!(request.connector_id.as_str(), CONNECTOR);
    assert_eq!(request.operation.as_str(), WEBHOOK_INGRESS_OPERATION);
    assert_eq!(request.zone_id, ZoneId::work());

    let (status, detail) = fixture
        .dispatch(request)
        .await
        .expect_err("a valid provider signature and capability do not prove mesh health");
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (_, refusal) = detail
        .split_once("deployment tier admission denied: ")
        .expect("the real host refuses the receiver's unchanged Risky tier");
    let refusal: DeploymentTierRefusal =
        serde_json::from_str(refusal).expect("structured deployment refusal");
    assert!(matches!(
        refusal,
        DeploymentTierRefusal::TierRequiresMeshActive {
            tier: SafetyTier::Risky,
            mode: fcp_host::DeploymentMode::Evaluation,
            ..
        }
    ));
    assert_eq!(
        fixture.invocations.load(Ordering::SeqCst),
        0,
        "preflight denial must not enter provider execution"
    );
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn webhook_ingress_admission_rejects_untrusted_or_wrong_scope_capabilities() {
    let fixture = LiveReceiver::new().await;
    let unknown_issuer = Ed25519SigningKey::generate();
    let untrusted = tests::test_capability_token_for_instance(
        &unknown_issuer,
        "webhook.events.write",
        WEBHOOK_INGRESS_OPERATION,
        "z:work",
        &fixture.instance,
    );
    let wrong_scope = tests::test_capability_token_for_instance(
        &fixture.signing_key,
        "webhook.events.read",
        "webhook.events.list",
        "z:work",
        &fixture.instance,
    );
    for token in [untrusted, wrong_scope] {
        let mut request = fixture.request(2);
        request.capability_token = token;
        let (status, detail) = fixture
            .dispatch(request)
            .await
            .expect_err("provider authentication cannot substitute for host authority");
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            detail.contains("capability token rejected:"),
            "expected cryptographic/scope rejection before deployment admission: {detail}"
        );
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    }
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn webhook_ingress_admission_verifies_provisioned_holder_against_signed_membership() {
    let mut fixture = LiveReceiver::new().await;
    let _evidence_directory = fixture.enable_live_evidence();
    let holder = Ed25519SigningKey::generate();
    let other_key = Ed25519SigningKey::generate();
    let membership = tempfile::tempdir().expect("signed membership directory");
    Arc::get_mut(&mut fixture.host)
        .expect("host has not started owned invocations")
        .mesh = Some(Arc::new(tests::holder_test_router(membership.path(), &holder)));

    let bearer = tests::test_capability_token_for_instance(
        &fixture.signing_key,
        "webhook.events.write",
        WEBHOOK_INGRESS_OPERATION,
        "z:work",
        &fixture.instance,
    );
    let claims = bearer
        .raw()
        .claims_unverified()
        .unwrap()
        .holder_node("holder-client")
        .token_id(b"webhook-holder-token");
    let token = fcp_core::CapabilityToken::from_raw(
        fcp_crypto::cose::CoseToken::sign(&fixture.signing_key, &claims).unwrap(),
    );

    // Parsing the token selects signing context only. A well-formed but wrong
    // local key must still fail the actual owner-authenticated host admission.
    fixture.binding = fixture
        .binding
        .clone()
        .with_execution_authority(token.clone(), Some(other_key))
        .unwrap();
    let wrong_key = fixture.request(61);
    fixture.binding = fixture
        .binding
        .clone()
        .with_execution_authority(token, Some(holder))
        .unwrap();
    let mut changed_request = fixture.request(62);
    changed_request.id = RequestId::new("public-replayed-holder-proof");
    let mut changed_token = fixture.request(63);
    changed_token.capability_token = fcp_core::CapabilityToken::from_raw(
        fcp_crypto::cose::CoseToken::sign(
            &fixture.signing_key,
            &claims.clone().token_id(b"replacement-webhook-token"),
        )
        .unwrap(),
    );

    for invocation in [wrong_key, changed_request, changed_token] {
        let (status, detail) = fixture
            .dispatch(invocation)
            .await
            .expect_err("a proof cannot authorize another key, request, or token");
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(detail.contains("holder_proof rejected"), "{detail}");
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    }

    let response = fixture
        .dispatch(fixture.request(64))
        .await
        .expect("current holder proof passes the ordinary invocation route");
    let (status, public) = response_for(&response);
    assert_eq!(status, StatusCode::ACCEPTED, "{response:?}");
    assert_eq!(public["accepted"], true);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn webhook_ingress_admission_accepts_fixed_command_with_live_signed_evidence() {
    let mut fixture = LiveReceiver::new().await;
    let _evidence_directory = fixture.enable_live_evidence();
    let request = fixture.request(3);
    let provenance = request.provenance.as_ref().expect("intake provenance");
    assert_eq!(provenance.origin_zone, ZoneId::work());
    assert_eq!(provenance.taint, TaintLevel::Tainted);
    assert!(!provenance.elevated);
    assert!(provenance.elevation_token.is_none());
    assert_eq!(provenance.chain[0].zone, ZoneId::public());
    assert_eq!(provenance.chain[1].zone, ZoneId::work());
    assert!(request.approval_tokens.is_empty());

    let response = fixture
        .dispatch(request)
        .await
        .expect("full host admission accepts the configured bounded intake command");
    assert_eq!(response.status, InvokeStatus::Ok, "{response:?}");
    let output = response.result.as_ref().expect("real receiver output");
    assert_eq!(output["accepted"], true);
    assert_eq!(output["event"]["path"], ENDPOINT_PATH);
    assert_eq!(output["ingest_log"]["decision"], "accepted");
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    let (status, public) = response_for(&response);
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(
        public,
        json!({"accepted": true, "status_code": 202, "reason_code": "accepted"})
    );
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn webhook_ingress_admission_round_trips_authenticated_slack_verification() {
    let mut fixture = LiveReceiver::with_provider("slack").await;
    let body = r#"{"type":"url_verification","challenge":"slack-registration-challenge","token":"private-legacy-token"}"#;
    fixture
        .dispatch(fixture.slack_request(body, body))
        .await
        .expect_err("a provider challenge cannot bypass live deployment admission");
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    let _evidence_directory = fixture.enable_live_evidence();

    for _ in 0..2 {
        let response = fixture
            .dispatch(fixture.slack_request(body, body))
            .await
            .expect("live host admits authenticated verification and retries");
        let (status, public) = response_for(&response);
        assert_eq!(status, StatusCode::OK, "{response:?}");
        assert_eq!(public, json!({"challenge": "slack-registration-challenge"}));
        assert!(!public.to_string().contains("private-legacy-token"));
    }
    let tampered = body.replace("slack-registration-challenge", "attacker-challenge");
    let response = fixture
        .dispatch(fixture.slack_request(&tampered, body))
        .await
        .expect("host forwards authorized command for independent provider verification");
    let (status, public) = response_for(&response);
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(public["reason_code"], "signature_invalid");
    assert!(public.get("challenge").is_none());
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn webhook_ingress_admission_rejects_public_origin_command_despite_live_evidence() {
    let mut fixture = LiveReceiver::new().await;
    let _evidence_directory = fixture.enable_live_evidence();
    let mut request = fixture.request(4);
    request
        .provenance
        .as_mut()
        .expect("intake provenance")
        .origin_zone = ZoneId::public();
    let (status, detail) = fixture
        .dispatch(request)
        .await
        .expect_err("mesh health does not elevate a public command into the work zone");
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(detail.contains("approval.missing_elevation"), "{detail}");
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn webhook_ingress_admission_preserves_actual_receiver_instance_binding() {
    let mut fixture = LiveReceiver::new().await;
    let _evidence_directory = fixture.enable_live_evidence();
    let mut request = fixture.request(5);
    request.capability_token = tests::test_capability_token_for_instance(
        &fixture.signing_key,
        "webhook.events.write",
        WEBHOOK_INGRESS_OPERATION,
        "z:work",
        &InstanceId::new(),
    );
    let response = fixture
        .dispatch(request)
        .await
        .expect("gateway defers the instance check to the actual receiver");
    assert_eq!(response.status, InvokeStatus::Error);
    assert!(matches!(
        response.error.as_ref(),
        Some(FcpError::ZoneViolation { message, .. })
            if message.contains("Token instance mismatch")
    ));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    let (status, public) = response_for(&response);
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(public["accepted"], false);
    assert!(!public.to_string().contains(fixture.instance.as_str()));
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn webhook_ingress_admission_does_not_replace_provider_authentication() {
    let mut fixture = LiveReceiver::new().await;
    let _evidence_directory = fixture.enable_live_evidence();
    // Translate the actual delivered bytes so the host's length and provenance
    // digest are consistent, while retaining a signature for another body.
    let request = fixture.request_with_signature_for("{\"tampered\":true}", "{\"original\":true}");
    assert_eq!(
        request.input["body_size_bytes"],
        "{\"tampered\":true}".len()
    );
    let response = fixture
        .dispatch(request)
        .await
        .expect("authorized host command reaches real receiver verification");
    assert_eq!(response.status, InvokeStatus::Error);
    let (status, public) = response_for(&response);
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(public["reason_code"], "signature_invalid");
    assert_eq!(public["accepted"], false);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn webhook_ingress_dispatch_revalidates_health_after_successful_admission() {
    let mut fixture = LiveReceiver::new().await;
    let evidence_directory = fixture.enable_live_evidence();
    let request = fixture.request(7);
    let verified = verify_live_request(&fixture.host, &request, None)
        .await
        .expect("fresh independently signed health evidence passes real admission");
    assert_eq!(verified.safety_tier, SafetyTier::Risky);
    invoke_jobs::revalidate_dispatch_authority(&fixture.host, &request)
        .await
        .expect("the dispatch fence initially accepts that same authority");
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);

    std::fs::write(
        evidence_directory.path().join("health-evidence.json"),
        b"not signed deployment evidence",
    )
    .expect("replace current evidence after successful admission");
    let error = invoke_jobs::revalidate_dispatch_authority(&fixture.host, &request)
        .await
        .expect_err("dispatch must not retain an earlier healthy classification");
    assert!(matches!(
        error,
        HostError::PreflightFailed(ref reason)
            if reason == "current deployment does not permit this operation tier"
    ));
    assert_eq!(
        fixture.invocations.load(Ordering::SeqCst),
        0,
        "a failed final authority fence precedes provider execution"
    );
}
