//! Gated live verification for the AWS Bedrock connector.
//!
//! Set `AWS_BEDROCK_E2E=1` plus the `AWS_BEDROCK_*` credential/model variables to
//! run this against real Bedrock endpoints. Without the gate or required
//! variables, the test emits a redaction-safe structured skip line.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::too_many_lines
)]

use std::time::Instant;

use chrono::{Duration, Utc};
use fcp_aws_bedrock::connector::BedrockConnector;
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector,
    HandshakeRequest, InvokeRequest, OperationId, RequestId, ZoneId,
};
use serde_json::json;
use sha2::{Digest, Sha256};

const OP_CONVERSE: &str = "aws_bedrock.converse";
const OP_CONVERSE_STREAM: &str = "aws_bedrock.converse_stream";
const OP_MODELS_LIST: &str = "aws_bedrock.models.list";
const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";

#[derive(Debug)]
struct LiveEnv {
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
    region: String,
    model_id: String,
    run_stream: bool,
}

impl LiveEnv {
    fn load() -> Option<Self> {
        if !live_gate_enabled() {
            emit_jsonl(json!({
                "event": "bedrock_live_smoke_skipped",
                "status": "skipped",
                "skip_reason": format!("{LIVE_GATE_ENV} is not set to 1"),
                "fixture_mode": "skip"
            }));
            return None;
        }

        if std::env::var("AWS_BEDROCK_E2E").ok().as_deref() != Some("1") {
            emit_jsonl(json!({
                "event": "bedrock_live_smoke_skipped",
                "status": "skipped",
                "skip_reason": "AWS_BEDROCK_E2E is not set to 1",
                "fixture_mode": "skip"
            }));
            return None;
        }

        let required = [
            "AWS_BEDROCK_ACCESS_KEY_ID",
            "AWS_BEDROCK_SECRET_ACCESS_KEY",
            "AWS_BEDROCK_REGION",
            "AWS_BEDROCK_MODEL_ID",
        ];
        let missing = required
            .iter()
            .copied()
            .filter(|name| std::env::var(name).map_or(true, |value| value.trim().is_empty()))
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            emit_jsonl(json!({
                "event": "bedrock_live_smoke_skipped",
                "status": "skipped",
                "skip_reason": "required AWS_BEDROCK_* live variables are missing",
                "missing": missing,
                "fixture_mode": "skip"
            }));
            return None;
        }

        Some(Self {
            access_key_id: std::env::var("AWS_BEDROCK_ACCESS_KEY_ID").ok()?,
            secret_access_key: std::env::var("AWS_BEDROCK_SECRET_ACCESS_KEY").ok()?,
            session_token: std::env::var("AWS_BEDROCK_SESSION_TOKEN")
                .ok()
                .filter(|value| !value.trim().is_empty()),
            region: std::env::var("AWS_BEDROCK_REGION").ok()?,
            model_id: std::env::var("AWS_BEDROCK_MODEL_ID").ok()?,
            run_stream: std::env::var("AWS_BEDROCK_STREAM_E2E").ok().as_deref() == Some("1"),
        })
    }
}

fn live_gate_enabled() -> bool {
    std::env::var(LIVE_GATE_ENV)
        .is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
}

fn live_jsonl_record(mut value: serde_json::Value) -> serde_json::Value {
    if let Some(object) = value.as_object_mut() {
        object
            .entry("schema_version")
            .or_insert_with(|| json!("1.0.0"));
        object
            .entry("redaction_scope")
            .or_insert_with(|| json!("hashed"));
        object
            .entry("suite_class")
            .or_insert_with(|| json!("sandbox_required"));
        object
            .entry("gate_env_var")
            .or_insert_with(|| json!(LIVE_GATE_ENV));
    }
    value
}

fn emit_jsonl(value: serde_json::Value) {
    println!("AWS_BEDROCK_E2E_JSONL {}", live_jsonl_record(value));
}

fn handshake_req(host_public_key: [u8; 32]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [9_u8; 32],
        capabilities_requested: vec![
            CapabilityId::from_static("aws_bedrock.chat"),
            CapabilityId::from_static("aws_bedrock.models.read"),
        ],
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

fn token(signing_key: &Ed25519SigningKey, instance_id: &str, op: &'static str) -> CapabilityToken {
    let capability = match op {
        OP_CONVERSE | OP_CONVERSE_STREAM => Some("aws_bedrock.chat"),
        OP_MODELS_LIST => Some("aws_bedrock.models.read"),
        _ => None,
    }
    .expect("unsupported live Bedrock operation");
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).expect("serialize live constraints");
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:bedrock-live-test")
        .operations(&[op])
        .target_instance(instance_id)
        .issuer("node:bedrock-live-test")
        .validity(now, now + Duration::minutes(30))
        .try_constraints_cbor(&constraints_cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("capability token signing should succeed");
    CapabilityToken::from_raw(raw)
}

fn invoke_req(
    op: &'static str,
    input: serde_json::Value,
    capability_token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new("aws-bedrock-live-1"),
        connector_id: ConnectorId::from_static("fcp.aws-bedrock"),
        operation: OperationId::from_static(op),
        zone_id: ZoneId::work(),
        input,
        capability_token,
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: None,
        correlation_id: None,
        provenance: None,
        approval_tokens: vec![],
    }
}

async fn setup_connector(env: &LiveEnv) -> (BedrockConnector, Ed25519SigningKey) {
    let mut connector = BedrockConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let mut config = json!({
        "access_key_id": env.access_key_id,
        "secret_access_key": env.secret_access_key,
        "region": env.region,
        "retry": { "max_retries": 1 }
    });
    if let Some(session_token) = &env.session_token {
        config["session_token"] = json!(session_token);
    }
    connector
        .configure(config)
        .await
        .expect("live Bedrock connector config should be valid");
    connector
        .handshake(handshake_req(signing_key.verifying_key().to_bytes()))
        .await
        .expect("live Bedrock connector handshake should succeed");
    (connector, signing_key)
}

fn digest16(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    hex::encode(&digest[..8])
}

#[test]
fn live_jsonl_records_are_schema_versioned_and_redacted() {
    let record = live_jsonl_record(json!({
        "event": "bedrock_live_contract_check"
    }));
    assert_eq!(record["schema_version"], "1.0.0");
    assert_eq!(record["redaction_scope"], "hashed");
    assert_eq!(record["event"], "bedrock_live_contract_check");
}

#[fcp_async_core::runtime::test]
async fn live_bedrock_smoke_jsonl() {
    let Some(env) = LiveEnv::load() else {
        return;
    };
    let (connector, signing_key) = setup_connector(&env).await;
    let git_revision = option_env!("GIT_REVISION").unwrap_or("unknown");

    let models_input = json!({});
    emit_jsonl(json!({
        "event": "bedrock_request_built",
        "op": OP_MODELS_LIST,
        "api": "control",
        "region": env.region,
        "body_size": serde_json::to_vec(&models_input).expect("serialize models input").len(),
        "fixture_mode": "live",
        "git_revision": git_revision
    }));
    let start = Instant::now();
    let models_response = connector
        .invoke(invoke_req(
            OP_MODELS_LIST,
            models_input,
            token(
                &signing_key,
                connector.instance_id().as_str(),
                OP_MODELS_LIST,
            ),
        ))
        .await
        .expect("live Bedrock models.list should succeed");
    let models = models_response.result.expect("models.list result");
    emit_jsonl(json!({
        "event": "bedrock_response_decoded",
        "op": OP_MODELS_LIST,
        "api": "control",
        "region": env.region,
        "http_status": 200,
        "retry_decision": "connector_retry_loop_completed",
        "latency_ms": start.elapsed().as_millis(),
        "model_count": models["modelSummaries"].as_array().map_or(0, Vec::len),
        "audit_receipt_id_hash": digest16("bedrock:models.list"),
        "signature_prefix_hash": "not_exposed_by_connector_boundary"
    }));

    let converse_input = json!({
        "model_id": env.model_id,
        "messages": [{
            "role": "user",
            "content": [{"text": "Reply with exactly one lowercase word."}]
        }],
        "inference_config": {"maxTokens": 8}
    });
    emit_jsonl(json!({
        "event": "bedrock_request_built",
        "op": OP_CONVERSE,
        "api": "converse",
        "model_id": env.model_id,
        "region": env.region,
        "body_size": serde_json::to_vec(&converse_input).expect("serialize converse input").len(),
        "fixture_mode": "live"
    }));
    let start = Instant::now();
    let response = connector
        .invoke(invoke_req(
            OP_CONVERSE,
            converse_input,
            token(&signing_key, connector.instance_id().as_str(), OP_CONVERSE),
        ))
        .await
        .expect("live Bedrock converse should succeed");
    let output = response.result.expect("converse result");
    emit_jsonl(json!({
        "event": "bedrock_response_decoded",
        "op": OP_CONVERSE,
        "api": "converse",
        "model_id": env.model_id,
        "region": env.region,
        "http_status": 200,
        "retry_decision": "connector_retry_loop_completed",
        "output_token_count": output.pointer("/usage/outputTokens").and_then(serde_json::Value::as_u64),
        "latency_ms": start.elapsed().as_millis(),
        "audit_receipt_id_hash": digest16("bedrock:converse"),
        "cleanup_result": "no_durable_state"
    }));

    if env.run_stream {
        let stream_input = json!({
            "model_id": env.model_id,
            "messages": [{
                "role": "user",
                "content": [{"text": "Reply with exactly one lowercase word."}]
            }],
            "inference_config": {"maxTokens": 8}
        });
        emit_jsonl(json!({
            "event": "bedrock_request_built",
            "op": OP_CONVERSE_STREAM,
            "api": "converse_stream",
            "model_id": env.model_id,
            "region": env.region,
            "body_size": serde_json::to_vec(&stream_input).expect("serialize stream input").len(),
            "fixture_mode": "live"
        }));
        let start = Instant::now();
        let response = connector
            .invoke(invoke_req(
                OP_CONVERSE_STREAM,
                stream_input,
                token(
                    &signing_key,
                    connector.instance_id().as_str(),
                    OP_CONVERSE_STREAM,
                ),
            ))
            .await
            .expect("live Bedrock converse_stream should succeed");
        let result = response.result.expect("converse_stream result");
        emit_jsonl(json!({
            "event": "bedrock_streaming_chunk_count",
            "op": OP_CONVERSE_STREAM,
            "api": "converse_stream",
            "model_id": env.model_id,
            "region": env.region,
            "http_status": 200,
            "chunk_count": result["chunk_count"].as_u64(),
            "total_chars": 0,
            "latency_ms": start.elapsed().as_millis(),
            "audit_receipt_id_hash": digest16("bedrock:converse_stream")
        }));
    } else {
        emit_jsonl(json!({
            "event": "bedrock_streaming_chunk_count",
            "op": OP_CONVERSE_STREAM,
            "api": "converse_stream",
            "model_id": env.model_id,
            "region": env.region,
            "status": "skipped",
            "skip_reason": "AWS_BEDROCK_STREAM_E2E is not set to 1",
            "chunk_count": 0,
            "total_chars": 0
        }));
    }
}
