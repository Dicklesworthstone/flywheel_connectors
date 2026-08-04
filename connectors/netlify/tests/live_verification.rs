//! Environment-gated live verification for the Netlify connector.

#![allow(
    clippy::expect_used,
    clippy::future_not_send,
    clippy::missing_panics_doc,
    clippy::unwrap_used
)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_netlify::connector::NetlifyConnector;
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector, FcpError,
    HandshakeRequest, InvokeRequest, InvokeStatus, OperationId, RequestId, ZoneId,
};
use fcp_sdk::prelude::SelfCheckStatus;
use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate};
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const TOKEN_ENV: &str = "NETLIFY_SANDBOX_TOKEN";
const SITE_ID_ENV: &str = "NETLIFY_SANDBOX_SITE_ID";
const BASE_URL_ENV: &str = "NETLIFY_SANDBOX_BASE_URL";
const NAMESPACE_ENV: &str = "FCP_SANDBOX_RUN_NAMESPACE";
const CONNECTOR_ID: &str = "fcp.netlify";
const CAP_SITES_READ: &str = "netlify.sites.read";
const CAP_DEPLOYS_READ: &str = "netlify.deploys.read";
const OP_DEPLOYS_LIST: &str = "netlify.deploys.list";

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox("netlify", "Netlify sandbox")
        .with_env_secret(
            "access_token",
            TOKEN_ENV,
            "Netlify personal access token scoped to the sandbox team or site",
        )
        .with_env_var(SITE_ID_ENV, "Netlify sandbox site id used for read-only deploy listing")
        .with_env_var(
            NAMESPACE_ENV,
            "Shared namespace recorded in evidence for any sandbox-side artifacts",
        )
        .with_env_var_default(BASE_URL_ENV, "https://api.netlify.com", "Netlify API endpoint")
        .with_account_setup(
            "Use a dedicated Netlify team/site for connector verification; do not point this suite at a production site.",
        )
        .with_budget(0.01)
        .with_cleanup(CleanupStrategy::PrefixDelete)
        .with_rate_limits(1.0, true)
}

fn emit_live_jsonl(status: &str, reason: &str, observed_count: usize, evidence: &Value) {
    eprintln!(
        "NETLIFY_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "netlify_live_sandbox_verification",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": TOKEN_ENV,
            "required_env": [SITE_ID_ENV, NAMESPACE_ENV],
            "defaulted_env": BASE_URL_ENV,
            "operation": OP_DEPLOYS_LIST,
            "status": status,
            "provider": "Netlify sandbox",
            "environment": "sandbox",
            "resource_class": "site_deploy_listing",
            "observed_count": observed_count,
            "call_ceiling": 2,
            "rate_limit_guidance": "Performs one token health probe and one sandbox site deploy listing.",
            "mutation_expected": false,
            "cleanup_strategy": "prefix_delete",
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

#[fcp_async_core::runtime::test]
async fn netlify_live_sandbox_deploy_listing_or_structured_skip_jsonl() {
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
    let self_check = connector.self_check().await;
    if let Err(error) = &self_check {
        emit_live_jsonl("failed", &error.to_string(), 0, &env.evidence_summary());
    }
    assert!(self_check.is_ok(), "Netlify sandbox self-check should pass");
    let Ok(report) = self_check else {
        return;
    };
    assert_eq!(
        report.status,
        SelfCheckStatus::Ok,
        "Netlify sandbox self-check should pass"
    );

    let site_id = env.env_vars.get(SITE_ID_ENV).expect("site id env is ready");
    let deploy_listing = invoke(
        &connector,
        &signing_key,
        OP_DEPLOYS_LIST,
        json!({ "site_id": site_id }),
    )
    .await;
    if let Err(error) = &deploy_listing {
        emit_live_jsonl("failed", &error.to_string(), 0, &env.evidence_summary());
    }
    assert!(
        deploy_listing.is_ok(),
        "Netlify sandbox deploy listing should pass"
    );
    let Ok(value) = deploy_listing else {
        return;
    };
    let observed_count = value.as_array().map_or(0, Vec::len);
    emit_live_jsonl(
        "passed",
        "",
        observed_count,
        &json!({
            "environment": env.evidence_summary(),
            "operation_result": "deploys.list completed",
        }),
    );
}

async fn configured_connector(
    env: &LiveEnvironment,
    signing_key: &Ed25519SigningKey,
) -> NetlifyConnector {
    let mut connector = NetlifyConnector::new();
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
        .expect("configure Netlify live connector");
    connector
        .handshake(HandshakeRequest {
            protocol_version: "2.0.0".to_string(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: signing_key.verifying_key().to_bytes(),
            nonce: [23_u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_SITES_READ),
                CapabilityId::from_static(CAP_DEPLOYS_READ),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        })
        .await
        .expect("handshake Netlify live connector");
    connector
}

fn capability_for_operation(operation: &'static str) -> &'static str {
    assert_eq!(operation, OP_DEPLOYS_LIST, "unsupported operation");
    CAP_DEPLOYS_READ
}

fn capability_for(
    connector: &NetlifyConnector,
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
        .principal("user:netlify-live")
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
    connector: &NetlifyConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    input: Value,
) -> Result<Value, FcpError> {
    let response = connector
        .invoke(InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::new(format!("netlify-live-{operation}")),
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
