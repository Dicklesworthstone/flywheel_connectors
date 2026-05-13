use fcp_feishu::FeishuConnector;
use fcp_sdk::prelude::{FcpConnector, SelfCheckStatus};
use fcp_testkit::live_suite::{EnvironmentManifest, LiveEnvironment, LiveGate};
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const APP_ID_ENV: &str = "FEISHU_SANDBOX_APP_ID";
const APP_SECRET_ENV: &str = "FEISHU_SANDBOX_APP_SECRET";
const BASE_URL_ENV: &str = "FEISHU_SANDBOX_BASE_URL";
const OPERATION: &str = "feishu.health";

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
        .with_env_var_default(
            BASE_URL_ENV,
            "https://open.feishu.cn",
            "Feishu/Lark Open Platform base URL",
        )
        .with_account_setup(
            "Use a dedicated Feishu/Lark tenant app with tenant_access_token_internal enabled.",
        )
        .with_budget(0.01)
        .with_rate_limits(0.5, true)
}

fn emit_live_jsonl(status: &str, reason: &str, connector_status: &str, evidence: &Value) {
    println!(
        "FEISHU_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "feishu_live_sandbox_self_check",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": [APP_ID_ENV, APP_SECRET_ENV],
            "defaulted_env": [BASE_URL_ENV],
            "operation": OPERATION,
            "status": status,
            "provider": "Feishu/Lark sandbox",
            "environment": "sandbox",
            "resource_class": "tenant_access_token_probe",
            "connector_status": connector_status,
            "call_ceiling": 1,
            "rate_limit_guidance": "Performs one POST /open-apis/auth/v3/tenant_access_token/internal sandbox probe.",
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
async fn feishu_live_sandbox_self_check_or_structured_skip_jsonl() {
    let gate = LiveGate::sandbox();
    let env = LiveEnvironment::from_manifest(manifest());
    if !gate.is_enabled() || !env.is_ready() {
        emit_live_jsonl(
            "skipped",
            &skip_reason(&gate, &env),
            "skipped",
            &env.evidence_summary(),
        );
        return;
    }

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

    match connector.self_check().await {
        Ok(report) => {
            let connector_status = format!("{:?}", report.status);
            assert_eq!(
                report.status,
                SelfCheckStatus::Ok,
                "Feishu sandbox self-check should pass"
            );
            env.budget.record_api_call(OPERATION, 0.0);
            emit_live_jsonl(
                "passed",
                "",
                &connector_status,
                &json!({
                    "environment": env.evidence_summary(),
                    "self_check_details": report.details,
                }),
            );
        }
        Err(error) => {
            emit_live_jsonl(
                "failed",
                &error.to_string(),
                "error",
                &env.evidence_summary(),
            );
            panic!("Feishu sandbox self-check failed: {error}");
        }
    }
}
