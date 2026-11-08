//! Provider-to-receiver proof for the host's generic webhook translation.
//!
//! The fixtures use the production receiver, canonical FCP handshakes, signed
//! capabilities, and independently signed endpoint approvals. The loopback
//! harness exercises real HTTP and the shared host translation module; it does
//! not substitute for the host binary's policy, admission, or subprocess tests.

#![allow(clippy::too_many_lines)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use axum::{
    Extension, Json, Router,
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri},
    routing::post,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::Utc;
use fcp_async_core::{
    hyper_bridge::HyperIo,
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Mutex,
    task, time,
};
use fcp_crypto::{
    canonicalize::to_deterministic_cbor, cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey,
};
use fcp_host::webhook_ingress::{WEBHOOK_INGRESS_ROUTE, WebhookIngressConfig, response_for};
use fcp_prelude::{
    ApprovalScope, ApprovalToken, CapabilityConstraints, CapabilityId, CapabilityToken,
    ConnectorId, ExecutionScope, HandshakeRequest, InvokeRequest, InvokeResponse, InvokeStatus,
    ObjectId, OperationId, RequestId, ZoneId,
};
use fcp_webhook_receiver::connector::WebhookReceiverConnector;
use hmac::{Hmac, Mac};
use hyper_util::service::TowerToHyperService;
use serde_json::{Value, json};
use sha1::Sha1;
use sha2::{Digest as _, Sha256};
use tower::ServiceExt;

const PUBLIC_BASE_URL: &str = "https://hooks.flywheel.test/webhooks";
const PROVIDER_SECRET: &str = "host-ingress-provider-signing-secret";
const INGEST_OPERATION: &str = "webhook.events.ingest";
const CAPABILITIES: &[&str] = &[
    "webhook.endpoints.read",
    "webhook.endpoints.write",
    "webhook.events.read",
    "webhook.events.write",
];

struct SignedReceiver {
    connector: WebhookReceiverConnector,
    capability_key: Ed25519SigningKey,
    approval_key: Ed25519SigningKey,
    instance: String,
}

impl SignedReceiver {
    async fn new() -> Self {
        let mut fixture = Self {
            connector: WebhookReceiverConnector::new(),
            capability_key: Ed25519SigningKey::from_bytes(&[41; 32]).expect("capability key"),
            approval_key: Ed25519SigningKey::from_bytes(&[42; 32]).expect("approval key"),
            instance: String::new(),
        };
        fixture
            .connector
            .handle_configure(json!({
                "public_base_url": PUBLIC_BASE_URL,
                "approval_public_key": fixture.approval_key.verifying_key().to_bytes(),
                "allow_ephemeral_ingest": true,
            }))
            .await
            .expect("configure production receiver");
        fixture.handshake(CAPABILITIES).await;
        fixture
    }

    async fn handshake(&mut self, capabilities: &[&str]) {
        let request = HandshakeRequest {
            protocol_version: "2.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: self.capability_key.verifying_key().to_bytes(),
            nonce: [43; 32],
            capabilities_requested: capabilities
                .iter()
                .map(|capability| CapabilityId::new(*capability).expect("capability id"))
                .collect(),
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        };
        let response = self
            .connector
            .handle_handshake(json!(request))
            .await
            .expect("canonical signed-session handshake");
        self.instance = response["instance_id"]
            .as_str()
            .expect("receiver's actual instance")
            .to_owned();
    }

    fn token(&self, capability: &str, operation: &str) -> CapabilityToken {
        scoped_token(
            &self.capability_key,
            capability,
            operation,
            "z:work",
            Some(&self.instance),
        )
    }

    fn ingress_with(&self, token: CapabilityToken) -> WebhookIngressConfig {
        WebhookIngressConfig::new(
            ConnectorId::from_static("fcp.webhook-receiver"),
            ZoneId::work(),
            token,
            PUBLIC_BASE_URL.to_owned(),
            1024 * 1024,
            15_000,
            8,
        )
        .expect("explicit host ingress binding")
    }

    fn ingress(&self) -> WebhookIngressConfig {
        self.ingress_with(self.token("webhook.events.write", INGEST_OPERATION))
    }

    fn request(&self, capability: &str, operation: &str, input: Value) -> InvokeRequest {
        InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::random(),
            connector_id: ConnectorId::from_static("fcp.webhook-receiver"),
            operation: OperationId::new(operation).expect("operation id"),
            zone_id: ZoneId::work(),
            input,
            capability_token: self.token(capability, operation),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: Some(15_000),
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        }
    }

    async fn create_endpoint(&mut self, path: &str, provider: &str, allowed_sources: &[&str]) {
        let mut request = self.request(
            "webhook.endpoints.write",
            "webhook.endpoints.create",
            json!({
                "path": path,
                "provider": provider,
                "signing_secret": PROVIDER_SECRET,
                "allowed_sources": allowed_sources,
            }),
        );
        let now = u64::try_from(Utc::now().timestamp_millis()).expect("current timestamp");
        let mut approval = ApprovalToken::approved(
            format!("host-ingress-approval-{}", request.id.0),
            now - 1000,
            now + 60_000,
            "owner:host-ingress-test",
            ApprovalScope::Execution(ExecutionScope {
                connector_id: request.connector_id.to_string(),
                method_pattern: request.operation.to_string(),
                request_object_id: Some(ObjectId::from_unscoped_bytes(request.id.0.as_bytes())),
                input_hash: Some(
                    *blake3::hash(&to_deterministic_cbor(&request.input).expect("input CBOR"))
                        .as_bytes(),
                ),
                input_constraints: Vec::new(),
            }),
            request.zone_id.clone(),
            None,
        );
        approval.signature = Some(
            self.approval_key
                .sign(&fcp_cbor::to_canonical_cbor(&approval).expect("approval CBOR"))
                .to_bytes()
                .to_vec(),
        );
        request.approval_tokens.push(approval);
        let response = self.invoke(request).await;
        assert_eq!(response.status, InvokeStatus::Ok, "{response:?}");
    }

    async fn invoke(&mut self, request: InvokeRequest) -> InvokeResponse {
        let id = request.id.clone();
        match self.connector.handle_invoke(json!(request)).await {
            Ok(result) => InvokeResponse::ok(id, result),
            Err(error) => InvokeResponse::error(id, error),
        }
    }

    async fn events(&mut self) -> Vec<Value> {
        let request = self.request("webhook.events.read", "webhook.events.recent", json!({}));
        let response = self.invoke(request).await;
        assert_eq!(response.status, InvokeStatus::Ok, "{response:?}");
        response.result.expect("recent-event result")["events"]
            .as_array()
            .expect("event array")
            .clone()
    }
}

fn scoped_token(
    key: &Ed25519SigningKey,
    capability: &str,
    operation: &str,
    zone: &str,
    instance: Option<&str>,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut builder = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id(zone)
        .principal("user:host-ingress-test")
        .operations(&[operation])
        .issuer("node:host-ingress-test")
        .validity(now, now + chrono::Duration::hours(1))
        .try_constraints_cbor(&fcp_cbor::to_canonical_cbor(&constraints).expect("constraints"))
        .expect("capability constraints");
    if let Some(instance) = instance {
        builder = builder.target_instance(instance);
    }
    CapabilityToken::from_raw(builder.sign(key).expect("signed capability"))
}

fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in pairs {
        headers.insert(
            HeaderName::from_bytes(name.as_bytes()).expect("header name"),
            HeaderValue::from_str(value).expect("header value"),
        );
    }
    headers
}

fn sha256_signature(data: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(PROVIDER_SECRET.as_bytes()).expect("HMAC key");
    mac.update(data.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn sha1_signature(data: &str) -> String {
    let mut mac = Hmac::<Sha1>::new_from_slice(PROVIDER_SECRET.as_bytes()).expect("HMAC key");
    mac.update(data.as_bytes());
    STANDARD.encode(mac.finalize().into_bytes())
}

struct Delivery {
    provider: &'static str,
    endpoint_path: &'static str,
    raw: String,
    headers: HeaderMap,
    payload: Value,
}

fn provider_deliveries() -> Vec<Delivery> {
    let timestamp = Utc::now().timestamp();
    let github = "{\n  \"id\": \"github-event\", \"message\": \"provider-payload-secret\"\n}\n";
    let stripe = " { \"id\":\"stripe-event\", \"type\":\"payment_intent.succeeded\" }\n";
    let slack = "{\"event_id\":\"slack-event\", \"type\":\"event_callback\",\"event\": {\"type\":\"message\"}}\n";
    let form = "MessageSid=SM123&Body=hello+%2B+world&From=%2B15551234567";
    vec![
        Delivery {
            provider: "github",
            endpoint_path: "/github",
            raw: github.into(),
            headers: headers(&[
                ("content-type", "application/json"),
                (
                    "x-hub-signature-256",
                    &format!("sha256={}", sha256_signature(github)),
                ),
                ("x-github-delivery", "github-delivery"),
            ]),
            payload: serde_json::from_str(github).expect("GitHub payload"),
        },
        Delivery {
            provider: "stripe",
            endpoint_path: "/stripe",
            raw: stripe.into(),
            headers: headers(&[
                ("content-type", "application/json"),
                (
                    "stripe-signature",
                    &format!(
                        "t={timestamp},v1={}",
                        sha256_signature(&format!("{timestamp}.{stripe}"))
                    ),
                ),
            ]),
            payload: serde_json::from_str(stripe).expect("Stripe payload"),
        },
        Delivery {
            provider: "slack",
            endpoint_path: "/slack",
            raw: slack.into(),
            headers: headers(&[
                ("content-type", "application/json"),
                ("x-slack-request-timestamp", &timestamp.to_string()),
                (
                    "x-slack-signature",
                    &format!(
                        "v0={}",
                        sha256_signature(&format!("v0:{timestamp}:{slack}"))
                    ),
                ),
            ]),
            payload: serde_json::from_str(slack).expect("Slack payload"),
        },
        Delivery {
            provider: "twilio",
            endpoint_path: "/twilio",
            raw: form.into(),
            headers: headers(&[
                ("content-type", "application/x-www-form-urlencoded"),
                (
                    "x-twilio-signature",
                    &sha1_signature(&format!(
                        "{PUBLIC_BASE_URL}/twilioBodyhello + worldFrom+15551234567MessageSidSM123"
                    )),
                ),
            ]),
            payload: json!({"MessageSid": "SM123", "Body": "hello + world", "From": "+15551234567"}),
        },
    ]
}

fn translated(config: &WebhookIngressConfig, delivery: &Delivery, body: &str) -> InvokeRequest {
    config
        .build_request(
            &delivery.headers,
            &format!("/webhooks{}", delivery.endpoint_path)
                .parse()
                .expect("URI"),
            body,
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        )
        .expect("valid HTTP translation")
}

fn assert_public_response_redacted(value: &Value) {
    let text = value.to_string();
    for forbidden in [
        PROVIDER_SECRET,
        "provider-payload-secret",
        "host-ingress-test",
        "capability_token",
        "endpoint_id",
        "ingest_log",
        "signing_secret",
        "source_ip",
    ] {
        assert!(
            !text.contains(forbidden),
            "public response leaked {forbidden}: {text}"
        );
    }
}

#[fcp_async_core::runtime::test]
async fn provider_signatures_use_exact_http_bodies_and_retries_cannot_duplicate_events() {
    for delivery in provider_deliveries() {
        let mut fixture = SignedReceiver::new().await;
        fixture
            .create_endpoint(delivery.endpoint_path, delivery.provider, &[])
            .await;
        let config = fixture.ingress();
        let request = translated(&config, &delivery, &delivery.raw);
        assert_eq!(request.input["body"], delivery.raw);
        assert_eq!(request.input["path"], delivery.endpoint_path);
        assert_eq!(
            request.input["url"],
            format!("{PUBLIC_BASE_URL}{}", delivery.endpoint_path)
        );
        let first_key = request
            .idempotency_key
            .clone()
            .expect("host-generated identity");
        assert_eq!(request.input["delivery_id"], first_key);
        assert!(first_key.starts_with("webhook-http-"));
        let response = fixture.invoke(request).await;
        let (status, public) = response_for(&response);
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "{}: {response:?}",
            delivery.provider
        );
        assert_eq!(public["accepted"], true);
        assert_public_response_redacted(&public);

        let altered = translated(&config, &delivery, &format!("{} ", delivery.raw));
        let (status, public) = response_for(&fixture.invoke(altered).await);
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{} tampering",
            delivery.provider
        );
        assert_public_response_redacted(&public);

        let retry = translated(&config, &delivery, &delivery.raw);
        assert_ne!(retry.idempotency_key.as_deref(), Some(first_key.as_str()));
        let (status, public) = response_for(&fixture.invoke(retry).await);
        assert_eq!(status, StatusCode::CONFLICT, "{} replay", delivery.provider);
        assert_public_response_redacted(&public);
        let events = fixture.events().await;
        assert_eq!(
            events.len(),
            1,
            "{} must be recorded only once",
            delivery.provider
        );
        assert_eq!(events[0]["payload"], delivery.payload);
        assert_eq!(events[0]["signature_valid"], true);
    }
}

#[fcp_async_core::runtime::test]
async fn twilio_json_authenticates_raw_query_encoding_and_exact_body_hash() {
    let mut fixture = SignedReceiver::new().await;
    fixture.create_endpoint("/twilio-json", "twilio", &[]).await;
    let config = fixture.ingress();
    let body = "{\n \"MessageSid\":\"SM321\", \"MessageStatus\":\"delivered\"\n}\n";
    let query = format!(
        "?campaign=alpha%2Bbeta&bodySHA256={}",
        hex::encode(Sha256::digest(body))
    );
    let uri: Uri = format!("/webhooks/twilio-json{query}")
        .parse()
        .expect("URI");
    let signature = sha1_signature(&format!("{PUBLIC_BASE_URL}/twilio-json{query}"));
    let headers = headers(&[
        ("content-type", "application/json"),
        ("x-twilio-signature", &signature),
    ]);
    let request = config
        .build_request(&headers, &uri, body, None)
        .expect("Twilio JSON request");
    assert_eq!(
        request.input["url"],
        format!("{PUBLIC_BASE_URL}/twilio-json{query}")
    );
    assert_eq!(
        response_for(&fixture.invoke(request).await).0,
        StatusCode::ACCEPTED
    );

    let changed_query: Uri = uri
        .to_string()
        .replace("%2B", "%2b")
        .parse()
        .expect("changed URI");
    let altered = config
        .build_request(&headers, &changed_query, body, None)
        .expect("valid URI");
    assert_eq!(
        response_for(&fixture.invoke(altered).await).0,
        StatusCode::UNAUTHORIZED
    );
    let altered = config
        .build_request(&headers, &uri, &format!("{body} "), None)
        .expect("raw body");
    assert_eq!(
        response_for(&fixture.invoke(altered).await).0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(fixture.events().await.len(), 1);
}

#[fcp_async_core::runtime::test]
async fn signed_provider_data_cannot_replace_fcp_capability_zone_or_instance_authority() {
    let mut fixture = SignedReceiver::new().await;
    fixture.create_endpoint("/github", "github", &[]).await;
    let delivery = provider_deliveries().remove(0);
    let other_key = Ed25519SigningKey::from_bytes(&[44; 32]).expect("other signer");
    let denied = [
        scoped_token(
            &fixture.capability_key,
            "webhook.events.read",
            INGEST_OPERATION,
            "z:work",
            Some(&fixture.instance),
        ),
        scoped_token(
            &fixture.capability_key,
            "webhook.events.write",
            "webhook.events.recent",
            "z:work",
            Some(&fixture.instance),
        ),
        scoped_token(
            &fixture.capability_key,
            "webhook.events.write",
            INGEST_OPERATION,
            "z:private",
            Some(&fixture.instance),
        ),
        scoped_token(
            &fixture.capability_key,
            "webhook.events.write",
            INGEST_OPERATION,
            "z:work",
            Some("another-instance"),
        ),
        scoped_token(
            &fixture.capability_key,
            "webhook.events.write",
            INGEST_OPERATION,
            "z:work",
            None,
        ),
        scoped_token(
            &other_key,
            "webhook.events.write",
            INGEST_OPERATION,
            "z:work",
            Some(&fixture.instance),
        ),
    ];
    for token in denied {
        let config = fixture.ingress_with(token);
        let response = fixture
            .invoke(translated(&config, &delivery, &delivery.raw))
            .await;
        assert_eq!(response.status, InvokeStatus::Error, "{response:?}");
        let (status, public) = response_for(&response);
        assert!(!status.is_success());
        assert_public_response_redacted(&public);
    }
    assert!(fixture.events().await.is_empty());
    let valid = fixture.ingress();
    assert_eq!(
        response_for(
            &fixture
                .invoke(translated(&valid, &delivery, &delivery.raw))
                .await
        )
        .0,
        StatusCode::ACCEPTED,
    );
}

#[fcp_async_core::runtime::test]
async fn rehandshake_rejects_stale_host_capabilities_and_unnegotiated_intake() {
    let mut fixture = SignedReceiver::new().await;
    fixture.create_endpoint("/github", "github", &[]).await;
    let delivery = provider_deliveries().remove(0);
    let stale = fixture.ingress();
    fixture.handshake(CAPABILITIES).await;
    let response = fixture
        .invoke(translated(&stale, &delivery, &delivery.raw))
        .await;
    assert_eq!(response.status, InvokeStatus::Error);
    fixture.handshake(&["webhook.events.read"]).await;
    let unnegotiated = fixture.ingress();
    let response = fixture
        .invoke(translated(&unnegotiated, &delivery, &delivery.raw))
        .await;
    assert_eq!(response.status, InvokeStatus::Error);
    assert!(fixture.events().await.is_empty());
}

#[fcp_async_core::runtime::test]
async fn source_allowlist_uses_only_host_observed_peer_and_unknown_paths_stay_unregistered() {
    let mut fixture = SignedReceiver::new().await;
    fixture
        .create_endpoint("/github", "github", &["127.0.0.0/8"])
        .await;
    let config = fixture.ingress();
    let mut delivery = provider_deliveries().remove(0);
    delivery
        .headers
        .insert("x-forwarded-for", HeaderValue::from_static("127.0.0.1"));
    delivery
        .headers
        .insert("x-real-ip", HeaderValue::from_static("127.0.0.1"));
    let uri = "/webhooks/github".parse().expect("URI");
    for peer in [None, Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77)))] {
        let request = config
            .build_request(&delivery.headers, &uri, &delivery.raw, peer)
            .expect("request");
        assert_eq!(
            response_for(&fixture.invoke(request).await).0,
            StatusCode::FORBIDDEN
        );
    }
    let request = config
        .build_request(
            &delivery.headers,
            &"/webhooks/not-registered".parse().expect("URI"),
            &delivery.raw,
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        )
        .expect("unknown path is still syntactically valid");
    let (status, public) = response_for(&fixture.invoke(request).await);
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_public_response_redacted(&public);
    assert!(fixture.events().await.is_empty());
}

#[derive(Clone)]
struct LoopbackState {
    config: WebhookIngressConfig,
    receiver: Arc<Mutex<Option<SignedReceiver>>>,
}

async fn receiver_loopback_handler(
    State(state): State<LoopbackState>,
    Extension(peer): Extension<IpAddr>,
    headers: HeaderMap,
    uri: Uri,
    body: Bytes,
) -> (StatusCode, Json<Value>) {
    let raw = std::str::from_utf8(&body).expect("test provider uses UTF-8");
    let result = match state.config.build_request(&headers, &uri, raw, Some(peer)) {
        Ok(request) => {
            // Each exchange joins its one connection before the next begins.
            // Move the fixture out so the !Send borrowed mutex guard never
            // crosses the handler's await point.
            let mut receiver = state
                .receiver
                .lock()
                .await
                .take()
                .expect("exclusive loopback receiver");
            let response = receiver.invoke(request).await;
            *state.receiver.lock().await = Some(receiver);
            response_for(&response)
        }
        Err(error) => error.response(),
    };
    (result.0, Json(result.1))
}

/// One owned HTTP connection, joined before returning; no detached server tasks.
async fn loopback_exchange(state: LoopbackState, raw_http: String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let address = listener.local_addr().expect("listener address");
    let server = task::spawn(async move {
        let (stream, peer) = time::timeout(Duration::from_secs(10), listener.accept())
            .await
            .expect("bounded provider accept")
            .expect("accept provider");
        let app = Router::new()
            .route(WEBHOOK_INGRESS_ROUTE, post(receiver_loopback_handler))
            .with_state(state)
            .layer(Extension(peer.ip()));
        let app = app
            .map_request(|request: hyper::Request<hyper::body::Incoming>| request.map(Body::new));
        let builder = hyper::server::conn::http1::Builder::new();
        time::timeout(
            Duration::from_secs(10),
            builder.serve_connection(HyperIo::new(stream), TowerToHyperService::new(app)),
        )
        .await
        .expect("bounded loopback server connection")
        .expect("serve loopback connection");
    });
    let mut stream = time::timeout(Duration::from_secs(10), TcpStream::connect(address))
        .await
        .expect("bounded provider connect")
        .expect("connect provider");
    time::timeout(Duration::from_secs(10), async {
        stream.write_all(raw_http.as_bytes()).await?;
        stream.flush().await
    })
    .await
    .expect("bounded provider request write")
    .expect("write and flush provider request");
    let mut response = Vec::new();
    time::timeout(Duration::from_secs(10), stream.read_to_end(&mut response))
        .await
        .expect("bounded loopback response")
        .expect("read provider response");
    time::timeout(Duration::from_secs(10), server)
        .await
        .expect("bounded owned-server join")
        .expect("join owned server");
    String::from_utf8(response).expect("HTTP response UTF-8")
}

#[fcp_async_core::runtime::test]
async fn real_loopback_http_preserves_signature_bytes_and_ignores_forwarded_authority() {
    let mut receiver = SignedReceiver::new().await;
    receiver
        .create_endpoint("/github", "github", &["127.0.0.1/32"])
        .await;
    let state = LoopbackState {
        config: receiver.ingress(),
        receiver: Arc::new(Mutex::new(Some(receiver))),
    };
    let body = "{\n \"operation\":\"webhook.endpoints.delete\",\"zone_id\":\"z:owner\",\"input\":{\"provider-payload-secret\":true}\n}\n";
    let signature = sha256_signature(body);
    let request = format!(
        "POST /webhooks/github HTTP/1.1\r\nHost: attacker.invalid\r\nContent-Type: application/json\r\nX-Hub-Signature-256: sha256={signature}\r\nX-Forwarded-For: 203.0.113.9\r\nX-Forwarded-Host: attacker.invalid\r\nX-Forwarded-Proto: http\r\nX-Principal: owner:attacker\r\nAuthorization: Bearer attacker-token\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    );
    let response = loopback_exchange(state.clone(), request.clone()).await;
    assert!(response.starts_with("HTTP/1.1 202"), "{response}");
    assert!(!response.contains("provider-payload-secret"));
    assert!(!response.contains("ingest_log"));
    assert!(!response.contains("attacker-token"));
    let retry = loopback_exchange(state.clone(), request).await;
    assert!(retry.starts_with("HTTP/1.1 409"), "{retry}");
    let mut receiver = state
        .receiver
        .lock()
        .await
        .take()
        .expect("receiver restored after completed exchanges");
    let events = receiver.events().await;
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0]["payload"],
        serde_json::from_str::<Value>(body).expect("payload")
    );
    assert_eq!(
        events[0]["source_ip_hash"],
        hex::encode(&Sha256::digest(b"127.0.0.1")[..16])
    );
}

#[fcp_async_core::runtime::test]
async fn real_loopback_http_completes_signed_slack_url_verification() {
    let mut receiver = SignedReceiver::new().await;
    receiver
        .create_endpoint("/slack", "slack", &["127.0.0.1/32"])
        .await;
    let state = LoopbackState {
        config: receiver.ingress(),
        receiver: Arc::new(Mutex::new(Some(receiver))),
    };
    let body = "{\n \"type\":\"url_verification\",\"challenge\":\"challenge-A\",\"token\":\"private-legacy-token\"\n}\n";
    let timestamp = Utc::now().timestamp();
    let signature = sha256_signature(&format!("v0:{timestamp}:{body}"));
    let request_for = |raw: &str| {
        format!(
            "POST /webhooks/slack HTTP/1.1\r\nHost: hooks.flywheel.test\r\nContent-Type: application/json\r\nX-Slack-Signature: v0={signature}\r\nX-Slack-Request-Timestamp: {timestamp}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{raw}",
            raw.len(),
        )
    };
    for _ in 0..2 {
        let response = loopback_exchange(state.clone(), request_for(body)).await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        let (headers, response_body) = response.split_once("\r\n\r\n").expect("HTTP body");
        assert!(
            headers
                .to_ascii_lowercase()
                .contains("content-type: application/json")
        );
        assert_eq!(
            serde_json::from_str::<Value>(response_body).expect("JSON verification response"),
            json!({"challenge": "challenge-A"})
        );
        assert!(!response.contains("private-legacy-token"));
    }

    let tampered = body.replace("challenge-A", "challenge-B");
    let rejected = loopback_exchange(state.clone(), request_for(&tampered)).await;
    assert!(rejected.starts_with("HTTP/1.1 401"), "{rejected}");
    assert!(!rejected.contains("challenge-B"));
    assert!(!rejected.contains("private-legacy-token"));
    let mut receiver = state
        .receiver
        .lock()
        .await
        .take()
        .expect("receiver restored after completed exchanges");
    assert!(receiver.events().await.is_empty());
}
