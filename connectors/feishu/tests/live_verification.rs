use chrono::{Duration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_feishu::FeishuConnector;
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector, FcpError,
    HandshakeRequest, InvokeRequest, InvokeStatus, OperationId, RequestId, ZoneId,
};
use fcp_sdk::prelude::SelfCheckStatus;
use fcp_testkit::live_suite::{EnvironmentManifest, LiveEnvironment, LiveGate};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const APP_ID_ENV: &str = "FEISHU_SANDBOX_APP_ID";
const APP_SECRET_ENV: &str = "FEISHU_SANDBOX_APP_SECRET";
const TENANT_KEY_ENV: &str = "FEISHU_SANDBOX_TENANT_KEY";
const CHAT_ID_ENV: &str = "FEISHU_SANDBOX_CHAT_ID";
const RUN_NAMESPACE_ENV: &str = "FCP_SANDBOX_RUN_NAMESPACE";
const BASE_URL_ENV: &str = "FEISHU_SANDBOX_BASE_URL";
const OP_HEALTH: &str = "feishu.health";
const OP_CHATS_GET: &str = "feishu.chats.get";
const OP_MESSAGES_SEND: &str = "feishu.messages.send";
const CALL_CEILING: usize = 4;
const LIVE_COMMAND: &str =
    "rch exec -- cargo test -p fcp-feishu --test live_verification -- --nocapture";

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox("feishu", "Feishu/Lark sandbox")
        .with_env_secret(
            "app_id",
            APP_ID_ENV,
            "Feishu or Lark sandbox tenant app ID for a dedicated test tenant",
        )
        .with_env_secret(
            "app_secret",
            APP_SECRET_ENV,
            "Feishu or Lark sandbox tenant app secret for a dedicated test tenant",
        )
        .with_env_var(
            TENANT_KEY_ENV,
            "Feishu or Lark sandbox tenant key for redaction-safe evidence correlation",
        )
        .with_env_var(CHAT_ID_ENV, "Dedicated sandbox chat id for live test messages")
        .with_env_var(
            RUN_NAMESPACE_ENV,
            "Shared namespace embedded in synthetic sandbox message text for this run",
        )
        .with_env_var_default(
            BASE_URL_ENV,
            "https://open.feishu.cn",
            "Feishu/Lark Open Platform base URL",
        )
        .with_account_setup(
            "Use a dedicated Feishu/Lark tenant app and test chat. The bot must be installed in the tenant and allowed to read chat metadata and send messages only to that sandbox chat.",
        )
        .with_budget(0.01)
        .with_rate_limits(0.5, true)
}

fn emit_live_jsonl(
    status: &str,
    reason: &str,
    observed_count: usize,
    cleanup_result: &str,
    auth_denial_verified: bool,
    evidence: &Value,
) {
    eprintln!(
        "FEISHU_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "feishu_live_sandbox_chat_message",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": [APP_ID_ENV, APP_SECRET_ENV],
            "required_env": [TENANT_KEY_ENV, CHAT_ID_ENV, RUN_NAMESPACE_ENV],
            "defaulted_env": [BASE_URL_ENV],
            "command": LIVE_COMMAND,
            "git_revision": option_env!("FCP_LIVE_GIT_REVISION").unwrap_or("unknown"),
            "operation": [
                "auth-denial",
                OP_HEALTH,
                OP_CHATS_GET,
                OP_MESSAGES_SEND
            ],
            "status": status,
            "provider": "Feishu/Lark sandbox",
            "environment": "sandbox",
            "resource_class": "sandbox_chat_message",
            "observed_count": observed_count,
            "call_ceiling": CALL_CEILING,
            "rate_limit_guidance": "Performs one invalid-secret auth probe, one tenant-token health probe, one sandbox chat metadata read, and one sandbox chat message send.",
            "mutation_expected": true,
            "cleanup_strategy": "immutable_provider_message",
            "cleanup_result": cleanup_result,
            "request_category": [
                "auth-denial",
                "tenant_access_token_probe",
                "chat.metadata_read",
                "message.send"
            ],
            "auth_denial_verified": auth_denial_verified,
            "tenant_key_logged": false,
            "chat_id_logged": false,
            "message_id_logged": false,
            "provider_resource_ids_logged": false,
            "secret_values_logged": false,
            "skip_reason": if status == "skipped" { Some(reason) } else { None },
            "fcp_error_mapping": if status == "failed" { Some(reason) } else { None },
            "evidence": evidence,
        })
    );
}

fn skip_reason(gate: &LiveGate, env: &LiveEnvironment) -> String {
    if gate.is_enabled() {
        env.problems().join("; ")
    } else {
        gate.skip_reason()
    }
}

fn handshake_req(host_public_key: [u8; 32]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [23u8; 32],
        capabilities_requested: vec![
            CapabilityId::from_static("feishu.messages.write"),
            CapabilityId::from_static("feishu.chats.read"),
            CapabilityId::from_static("feishu.users.read"),
        ],
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    op: &'static str,
    connector: &FeishuConnector,
) -> CapabilityToken {
    let capability = match op {
        OP_MESSAGES_SEND => "feishu.messages.write",
        OP_CHATS_GET => "feishu.chats.read",
        _ => "feishu.users.read",
    };
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize capability constraints");
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:live-sandbox")
        .operations(&[op])
        .issuer("node:live-sandbox")
        .target_instance(connector.instance_id().as_str())
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
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
        id: RequestId::new(format!("feishu-live-{op}")),
        connector_id: ConnectorId::from_static("fcp.feishu"),
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

async fn configured_connector(
    env: &LiveEnvironment,
    signing_key: &Ed25519SigningKey,
) -> FeishuConnector {
    let mut connector = FeishuConnector::new();
    connector
        .configure(json!({
            "base_url": env
                .env_vars
                .get(BASE_URL_ENV)
                .expect("base URL env is ready"),
            "app_id": env.secrets.require("app_id"),
            "app_secret": env.secrets.require("app_secret"),
            "request_timeout_ms": 10_000,
            "retry": {
                "max_retries": 1,
                "initial_delay_ms": 100,
                "max_delay_ms": 500,
                "jitter_enabled": true
            }
        }))
        .await
        .expect("configure Feishu sandbox credentials");
    connector
        .handshake(handshake_req(signing_key.verifying_key().to_bytes()))
        .await
        .expect("handshake Feishu sandbox connector");
    connector
}

async fn invoke(
    connector: &FeishuConnector,
    signing_key: &Ed25519SigningKey,
    op: &'static str,
    input: serde_json::Value,
) -> Result<Value, FcpError> {
    let response = connector
        .invoke(invoke_req(
            op,
            input,
            generate_valid_token(signing_key, op, connector),
        ))
        .await?;
    if response.status != InvokeStatus::Ok {
        return Err(FcpError::Internal {
            message: format!("Feishu live operation {op} returned {:?}", response.status),
        });
    }
    Ok(response.result.unwrap_or_else(|| json!({})))
}

async fn invalid_secret_is_denied(env: &LiveEnvironment) -> bool {
    let mut connector = FeishuConnector::new();
    connector
        .configure(json!({
            "base_url": env
                .env_vars
                .get(BASE_URL_ENV)
                .expect("base URL env is ready"),
            "app_id": env.secrets.require("app_id"),
            "app_secret": "fcp-invalid-feishu-live-secret",
            "request_timeout_ms": 10_000,
            "retry": {
                "max_retries": 0,
                "initial_delay_ms": 100,
                "max_delay_ms": 500,
                "jitter_enabled": false
            }
        }))
        .await
        .expect("configure invalid Feishu sandbox credentials");
    match connector.self_check().await {
        Ok(report) => report.status != SelfCheckStatus::Ok,
        Err(_) => true,
    }
}

fn redacted_hash(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    let encoded = hex::encode(digest);
    let short_hash = encoded.chars().take(16).collect::<String>();
    format!("sha256:{short_hash}")
}

#[fcp_async_core::runtime::test]
async fn feishu_live_sandbox_chat_message_or_structured_skip_jsonl() {
    let gate = LiveGate::sandbox();
    let env = LiveEnvironment::from_manifest(manifest());
    if !gate.is_enabled() || !env.is_ready() {
        emit_live_jsonl(
            "skipped",
            &skip_reason(&gate, &env),
            0,
            "not_started",
            false,
            &env.evidence_summary(),
        );
        return;
    }

    let chat_id = env.env_vars.get(CHAT_ID_ENV).expect("chat id env is ready");
    let tenant_key = env
        .env_vars
        .get(TENANT_KEY_ENV)
        .expect("tenant key env is ready");
    let run_namespace = env
        .env_vars
        .get(RUN_NAMESPACE_ENV)
        .expect("run namespace env is ready");
    let base_url = env
        .env_vars
        .get(BASE_URL_ENV)
        .expect("base URL env is ready");

    let auth_denial_verified = invalid_secret_is_denied(&env).await;
    assert!(
        auth_denial_verified,
        "Feishu invalid-secret auth probe must be denied"
    );

    let signing_key = Ed25519SigningKey::generate();
    let connector = configured_connector(&env, &signing_key).await;
    let self_check = connector
        .self_check()
        .await
        .expect("Feishu sandbox self-check should return a report");
    assert_eq!(
        self_check.status,
        SelfCheckStatus::Ok,
        "Feishu sandbox self-check should pass before live message proof"
    );

    let chat_meta = invoke(
        &connector,
        &signing_key,
        OP_CHATS_GET,
        json!({ "chat_id": chat_id }),
    )
    .await
    .expect("read sandbox chat metadata");
    let message_nonce = redacted_hash(&format!(
        "{run_namespace}:{}",
        Utc::now().timestamp_millis()
    ));
    let message_content = serde_json::to_string(&json!({
        "text": format!("FCP Feishu live verification {message_nonce}")
    }))
    .expect("serialize Feishu text message content");
    let send_result = invoke(
        &connector,
        &signing_key,
        OP_MESSAGES_SEND,
        json!({
            "receive_id": chat_id,
            "receive_id_type": "chat_id",
            "msg_type": "text",
            "content": message_content,
        }),
    )
    .await
    .expect("send sandbox Feishu message");
    let message_id_hash = send_result
        .get("message_id")
        .and_then(Value::as_str)
        .map(redacted_hash);

    emit_live_jsonl(
        "passed",
        "",
        2,
        "immutable_message_left_in_dedicated_sandbox_chat",
        auth_denial_verified,
        &json!({
            "environment": env.evidence_summary(),
            "base_url_hash": redacted_hash(base_url),
            "tenant_key_hash": redacted_hash(tenant_key),
            "chat_id_hash": redacted_hash(chat_id),
            "namespace_hash": redacted_hash(run_namespace),
            "message_nonce_hash": message_nonce,
            "message_id_hash": message_id_hash,
            "self_check_status": format!("{:?}", self_check.status),
            "self_check_details": self_check.details,
            "chat_metadata_shape": {
                "object": chat_meta.is_object(),
                "has_chat_id": chat_meta.get("chat_id").is_some(),
                "has_name": chat_meta.get("name").is_some(),
            },
            "message_send_shape": {
                "object": send_result.is_object(),
                "has_message_id": send_result.get("message_id").is_some(),
                "has_msg_type": send_result.get("msg_type").is_some(),
            },
        }),
    );
}
