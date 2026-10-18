//! Environment-gated live verification for the `Calendly` connector.

#![allow(
    clippy::expect_used,
    clippy::future_not_send,
    clippy::missing_panics_doc,
    clippy::unwrap_used
)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_calendly::connector::CalendlyConnector;
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector,
    HandshakeRequest, InvokeRequest, InvokeStatus, OperationId, RequestId, ZoneId,
};
use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate};
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const TOKEN_ENV: &str = "CALENDLY_SANDBOX_TOKEN";
const ORG_URI_ENV: &str = "CALENDLY_SANDBOX_ORG_URI";
const EVENT_TYPE_URI_ENV: &str = "CALENDLY_SANDBOX_EVENT_TYPE_URI";
const BASE_URL_ENV: &str = "CALENDLY_SANDBOX_BASE_URL";
const NAMESPACE_ENV: &str = "FCP_SANDBOX_RUN_NAMESPACE";
const CONNECTOR_ID: &str = "fcp.calendly";
const CAP_EVENTS_READ: &str = "calendly.events.read";
const CAP_EVENTS_WRITE: &str = "calendly.events.write";
const CAP_SCHEDULING_READ: &str = "calendly.scheduling.read";
const CAP_SCHEDULING_WRITE: &str = "calendly.scheduling.write";
const CAP_USER_READ: &str = "calendly.user.read";
const OP_EVENTS_LIST: &str = "calendly.events.list";
const OP_EVENT_TYPES_LIST: &str = "calendly.event_types.list";
const OP_USER_GET: &str = "calendly.user.get";
const BEAD_ID: &str = "flywheel_connectors-bky21.4.6.1";

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox("calendly", "Calendly sandbox")
        .with_env_secret(
            "access_token",
            TOKEN_ENV,
            "Calendly personal access token scoped to a dedicated sandbox organization",
        )
        .with_env_var(
            ORG_URI_ENV,
            "Calendly organization URI expected for the authenticated sandbox user",
        )
        .with_env_var(
            EVENT_TYPE_URI_ENV,
            "Calendly event type URI expected to be visible in the sandbox",
        )
        .with_env_var(
            NAMESPACE_ENV,
            "Shared namespace recorded in evidence for sandbox-side artifacts",
        )
        .with_env_var_default(
            BASE_URL_ENV,
            "https://api.calendly.com",
            "Calendly REST API endpoint",
        )
        .with_account_setup(
            "Use a dedicated Calendly sandbox organization and event type. This suite performs read-only user and event-type checks; scheduling-link creation belongs in a separate namespaced mutation flow.",
        )
        .with_budget(0.01)
        .with_cleanup(CleanupStrategy::PrefixDelete)
        .with_rate_limits(0.5, true)
}

fn emit_live_jsonl(status: &str, reason: &str, observed_count: usize, evidence: &Value) {
    eprintln!(
        "CALENDLY_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "calendly_live_sandbox_verification",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": TOKEN_ENV,
            "required_env": [ORG_URI_ENV, EVENT_TYPE_URI_ENV, NAMESPACE_ENV],
            "defaulted_env": BASE_URL_ENV,
            "operation": [OP_USER_GET, OP_EVENT_TYPES_LIST],
            "bead_id": BEAD_ID,
            "status": status,
            "provider": "Calendly sandbox",
            "environment": "sandbox",
            "resource_class": "authenticated_user_and_event_type",
            "observed_count": observed_count,
            "call_ceiling": 2,
            "rate_limit_guidance": "Performs one authenticated user read and one event-type listing.",
            "mutation_expected": false,
            "cleanup_strategy": "prefix_delete",
            "provider_resource_ids_logged": false,
            "secret_values_logged": false,
            "org_uri_logged": false,
            "event_type_uri_logged": false,
            "pii_logged": false,
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

#[fcp_async_core::runtime::test]
async fn calendly_live_sandbox_user_and_event_type_or_structured_skip_jsonl() {
    let gate = LiveGate::sandbox();
    let env = LiveEnvironment::from_manifest(manifest());
    if !gate.is_enabled() || !env.is_ready() {
        emit_live_jsonl(
            "skipped",
            &skip_reason(&gate, &env),
            0,
            &env.evidence_summary(),
        );
        return;
    }

    let signing_key = Ed25519SigningKey::generate();
    let connector = configured_connector(&env, &signing_key).await;
    let user = match invoke(&connector, &signing_key, OP_USER_GET, json!({})).await {
        Ok(value) => value,
        Err(error) => {
            emit_live_jsonl("failed", &error.to_string(), 0, &env.evidence_summary());
            panic!("Calendly sandbox user get failed: {error}");
        }
    };
    env.budget.record_api_call(OP_USER_GET, 0.0);
    let user_uri = user["resource"]["uri"].as_str().unwrap_or_default();
    let org_uri = env
        .env_vars
        .get(ORG_URI_ENV)
        .expect("organization URI env is ready");
    let observed_org_uri = user["resource"]["current_organization"]
        .as_str()
        .unwrap_or_default();
    if observed_org_uri != org_uri {
        emit_live_jsonl(
            "failed",
            "authenticated user organization did not match CALENDLY_SANDBOX_ORG_URI",
            usize::from(!user_uri.is_empty()),
            &env.evidence_summary(),
        );
        panic!("Calendly sandbox organization mismatch");
    }

    let event_types = match invoke(
        &connector,
        &signing_key,
        OP_EVENT_TYPES_LIST,
        json!({
            "user_uri": user_uri,
            "count": 100
        }),
    )
    .await
    {
        Ok(value) => value,
        Err(error) => {
            emit_live_jsonl(
                "failed",
                &error.to_string(),
                usize::from(!user_uri.is_empty()),
                &env.evidence_summary(),
            );
            panic!("Calendly sandbox event type listing failed: {error}");
        }
    };
    env.budget.record_api_call(OP_EVENT_TYPES_LIST, 0.0);
    let event_type_uri = env
        .env_vars
        .get(EVENT_TYPE_URI_ENV)
        .expect("event type URI env is ready");
    let event_type_seen = event_types["collection"].as_array().is_some_and(|items| {
        items
            .iter()
            .any(|item| item["uri"].as_str() == Some(event_type_uri))
    });
    if !event_type_seen {
        emit_live_jsonl(
            "failed",
            "CALENDLY_SANDBOX_EVENT_TYPE_URI was not visible to the sandbox token",
            usize::from(!user_uri.is_empty()),
            &env.evidence_summary(),
        );
        panic!("Calendly sandbox event type was not visible");
    }

    let event_type_count = event_types["collection"].as_array().map_or(0, Vec::len);
    emit_live_jsonl(
        "passed",
        "",
        usize::from(!user_uri.is_empty()) + event_type_count,
        &json!({
            "environment": env.evidence_summary(),
            "operation_result": "user.get and event_types.list completed",
        }),
    );
}

async fn configured_connector(
    env: &LiveEnvironment,
    signing_key: &Ed25519SigningKey,
) -> CalendlyConnector {
    let mut connector = CalendlyConnector::new();
    connector
        .configure(json!({
            "access_token": env.secrets.require("access_token"),
            "base_url": env.env_vars.get(BASE_URL_ENV).expect("base URL env is ready"),
            "request_timeout_ms": 10_000,
            "retry": {
                "max_retries": 1,
                "initial_delay_ms": 250,
                "max_delay_ms": 1_000,
                "jitter_enabled": false
            }
        }))
        .await
        .expect("configure live connector");
    connector
        .handshake(HandshakeRequest {
            protocol_version: "2.0.0".to_string(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: signing_key.verifying_key().to_bytes(),
            nonce: [23_u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_EVENTS_READ),
                CapabilityId::from_static(CAP_EVENTS_WRITE),
                CapabilityId::from_static(CAP_SCHEDULING_READ),
                CapabilityId::from_static(CAP_SCHEDULING_WRITE),
                CapabilityId::from_static(CAP_USER_READ),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        })
        .await
        .expect("handshake live connector");
    connector
}

fn capability_for_operation(operation: &'static str) -> &'static str {
    match operation {
        OP_EVENTS_LIST | OP_EVENT_TYPES_LIST => CAP_EVENTS_READ,
        OP_USER_GET => CAP_USER_READ,
        _ => panic!("unsupported operation {operation}"),
    }
}

fn capability_for(
    connector: &CalendlyConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
) -> CapabilityToken {
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".to_string()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).expect("serialize constraints");
    let now = Utc::now();
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability_for_operation(operation))
        .zone_id("z:work")
        .principal("user:calendly-live")
        .operations(&[operation])
        .issuer("node:live-verification")
        .validity(now, now + ChronoDuration::hours(1))
        .target_instance(connector.instance_id().as_str())
        .try_constraints_cbor(&constraints_cbor)
        .expect("valid constraints cbor")
        .sign(signing_key)
        .expect("sign capability token");
    CapabilityToken::from_raw(cose)
}

async fn invoke(
    connector: &CalendlyConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    input: Value,
) -> Result<Value, fcp_prelude::FcpError> {
    let response = connector
        .invoke(InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::new(format!("calendly-live-{operation}")),
            connector_id: ConnectorId::from_static(CONNECTOR_ID),
            operation: OperationId::from_static(operation),
            zone_id: ZoneId::work(),
            input,
            capability_token: capability_for(connector, signing_key, operation),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        })
        .await?;
    assert_eq!(response.status, InvokeStatus::Ok);
    Ok(response.result.expect("successful response has result"))
}
