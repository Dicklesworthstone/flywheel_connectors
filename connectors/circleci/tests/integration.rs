//! Connector-local no-mock CircleCI integration proof.
//!
//! These tests exercise the real CircleCI client against a local HTTP server.
//! No live CircleCI service is called.

#![allow(
    clippy::missing_errors_doc,
    clippy::too_many_lines,
    clippy::unreadable_literal
)]

use std::sync::Once;
use std::time::Duration;

use fcp_circleci::client::CircleCiClient;
use fcp_circleci::connector::operations_info;
use fcp_circleci::error::Error;
use fcp_prelude::{ApprovalMode, IdempotencyClass, RiskLevel, SafetyTier};
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use serde_json::json;
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_TOKEN: &str = "circleci-token-for-tests";

static LOG_INIT: Once = Once::new();

fn init_logging() {
    LOG_INIT.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("debug")),
            )
            .json()
            .with_test_writer()
            .try_init();
    });
}

fn no_retry_config() -> HttpRetryConfig {
    HttpRetryConfig {
        max_retries: 0,
        initial_delay_ms: 1,
        max_delay_ms: 1,
        jitter_enabled: false,
    }
}

fn test_runtime() -> ConnectorRuntime {
    ConnectorRuntime::new(
        ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_millis(500)),
    )
}

fn client(server: &MockServer) -> CircleCiClient {
    CircleCiClient::new(&server.uri(), TEST_TOKEN, no_retry_config(), 500)
        .expect("wiremock URI should build a CircleCI client")
}

#[fcp_async_core::runtime::test]
async fn project_pipeline_workflow_and_job_success_paths_use_circleci_contracts() {
    init_logging();
    tracing::info!(
        scenario = "circleci_success_contracts",
        "starting CircleCI success-path integration proof",
    );

    let server = MockServer::start().await;
    let runtime = test_runtime();

    Mock::given(method("GET"))
        .and(path("/me/collaborations"))
        .and(query_param("page-token", "projects-next"))
        .and(header("Circle-Token", TEST_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
            "slug": "gh/org/repo",
            "name": "repo",
            "organization_name": "org",
            "vcs_info": {
                "vcs_url": "https://github.com/org/repo",
                "provider": "GitHub",
                "default_branch": "main"
            }
        }])))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/project/gh/org/repo/pipeline"))
        .and(query_param("page-token", "pipelines-next"))
        .and(header("Circle-Token", TEST_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [{
                "id": "pipeline-1",
                "project_slug": "gh/org/repo",
                "number": 42,
                "state": "created",
                "vcs": {
                    "branch": "main",
                    "revision": "abc123",
                    "provider_name": "GitHub"
                }
            }],
            "next_page_token": "pipelines-page-2"
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/pipeline/pipeline-1/workflow"))
        .and(query_param("page-token", "workflows-next"))
        .and(header("Circle-Token", TEST_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [{
                "id": "workflow-1",
                "name": "build-and-test",
                "status": "success",
                "pipeline_id": "pipeline-1",
                "pipeline_number": 42,
                "project_slug": "gh/org/repo"
            }]
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/workflow/workflow-1/job"))
        .and(query_param("page-token", "jobs-next"))
        .and(header("Circle-Token", TEST_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [{
                "id": "job-1",
                "name": "test",
                "status": "success",
                "type": "build",
                "job_number": 7,
                "project_slug": "gh/org/repo"
            }]
        })))
        .mount(&server)
        .await;

    let client = client(&server);

    let projects = client
        .list_projects(&runtime, Some("projects-next"))
        .await
        .expect("project list should decode");
    assert_eq!(projects.items[0].slug, "gh/org/repo");
    assert_eq!(projects.next_page_token, None);

    let pipelines = client
        .list_pipelines(&runtime, "gh/org/repo", Some("pipelines-next"))
        .await
        .expect("pipeline list should decode");
    assert_eq!(pipelines.items[0].id, "pipeline-1");
    assert_eq!(
        pipelines.next_page_token.as_deref(),
        Some("pipelines-page-2")
    );

    let workflows = client
        .list_workflows(&runtime, "pipeline-1", Some("workflows-next"))
        .await
        .expect("workflow list should decode");
    assert_eq!(workflows.items[0].status, "success");

    let jobs = client
        .list_jobs(&runtime, "workflow-1", Some("jobs-next"))
        .await
        .expect("job list should decode");
    assert_eq!(jobs.items[0].name, "test");
    assert_eq!(jobs.items[0].status, "success");
}

#[fcp_async_core::runtime::test]
async fn destructive_workflow_requests_use_expected_post_shapes() {
    init_logging();
    tracing::info!(
        scenario = "circleci_destructive_request_shape",
        "starting CircleCI destructive request-shape proof",
    );

    let server = MockServer::start().await;
    let runtime = test_runtime();

    Mock::given(method("POST"))
        .and(path("/workflow/workflow-1/cancel"))
        .and(header("Circle-Token", TEST_TOKEN))
        .and(body_json(json!({})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "message": "Workflow canceled."
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/workflow/workflow-1/rerun"))
        .and(header("Circle-Token", TEST_TOKEN))
        .and(body_json(json!({ "from_failed": true })))
        .respond_with(ResponseTemplate::new(202).set_body_json(json!({
            "message": "Workflow rerun requested."
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = client(&server);

    let cancel = client
        .cancel_workflow(&runtime, "workflow-1")
        .await
        .expect("cancel request should decode");
    assert_eq!(cancel.message, "Workflow canceled.");

    let rerun = client
        .rerun_workflow(&runtime, "workflow-1", true)
        .await
        .expect("rerun request should decode");
    assert_eq!(rerun.message, "Workflow rerun requested.");
}

#[fcp_async_core::runtime::test]
async fn auth_failure_rate_limit_and_malformed_json_are_typed() {
    init_logging();
    tracing::info!(
        scenario = "circleci_error_taxonomy",
        "starting CircleCI error-taxonomy proof",
    );

    let server = MockServer::start().await;
    let runtime = test_runtime();

    Mock::given(method("GET"))
        .and(path("/pipeline/bad-auth"))
        .and(header("Circle-Token", TEST_TOKEN))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "message": "Invalid API token"
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/project/gh/org/repo/pipeline"))
        .and(header("Circle-Token", TEST_TOKEN))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "2")
                .set_body_json(json!({ "message": "rate limited" })),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/workflow/malformed/job"))
        .and(header("Circle-Token", TEST_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_string("{this is not json"))
        .mount(&server)
        .await;

    let client = client(&server);

    let unauthorized = client.get_pipeline(&runtime, "bad-auth").await.unwrap_err();
    assert!(matches!(unauthorized, Error::Unauthorized(_)));

    let rate_limited = client
        .list_pipelines(&runtime, "gh/org/repo", None)
        .await
        .unwrap_err();
    assert!(matches!(
        rate_limited,
        Error::RateLimited {
            retry_after_ms: 2000
        }
    ));

    let malformed = client
        .list_jobs(&runtime, "malformed", None)
        .await
        .unwrap_err();
    assert!(matches!(malformed, Error::Json(_)));
}

#[fcp_async_core::runtime::test]
async fn request_timeout_surfaces_as_retryable_http_failure() {
    init_logging();
    tracing::info!(
        scenario = "circleci_timeout",
        "starting CircleCI timeout proof",
    );

    let server = MockServer::start().await;
    let runtime = ConnectorRuntime::new(
        ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_millis(50)),
    );

    Mock::given(method("GET"))
        .and(path("/pipeline/slow-pipeline"))
        .and(header("Circle-Token", TEST_TOKEN))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(250))
                .set_body_json(json!({
                    "id": "slow-pipeline",
                    "project_slug": "gh/org/repo",
                    "number": 99,
                    "state": "created"
                })),
        )
        .mount(&server)
        .await;

    let client = CircleCiClient::new(&server.uri(), TEST_TOKEN, no_retry_config(), 50)
        .expect("wiremock URI should build a CircleCI client");
    let err = client
        .get_pipeline(&runtime, "slow-pipeline")
        .await
        .unwrap_err();

    assert!(matches!(err, Error::Http(_)));
    assert!(err.is_retryable());
}

#[test]
fn operation_catalog_preserves_risk_and_approval_metadata() {
    init_logging();

    let operations = operations_info();
    let by_id = |id: &str| {
        operations
            .iter()
            .find(|operation| operation.id.as_str() == id)
            .expect("operation metadata should contain requested id")
    };

    let trigger = by_id("circleci.pipelines.trigger");
    assert_eq!(trigger.risk_level, RiskLevel::High);
    assert_eq!(trigger.safety_tier, SafetyTier::Risky);
    assert_eq!(trigger.idempotency, IdempotencyClass::BestEffort);
    assert_eq!(trigger.requires_approval, Some(ApprovalMode::Policy));

    let cancel = by_id("circleci.workflows.cancel");
    assert_eq!(cancel.risk_level, RiskLevel::Medium);
    assert_eq!(cancel.safety_tier, SafetyTier::Risky);
    assert_eq!(cancel.idempotency, IdempotencyClass::Strict);
    assert_eq!(cancel.requires_approval, Some(ApprovalMode::None));

    let rerun = by_id("circleci.workflows.rerun");
    assert_eq!(rerun.risk_level, RiskLevel::High);
    assert_eq!(rerun.safety_tier, SafetyTier::Risky);
    assert_eq!(rerun.idempotency, IdempotencyClass::BestEffort);
    assert_eq!(rerun.requires_approval, Some(ApprovalMode::Policy));
}

#[test]
fn debug_output_redacts_api_token() {
    init_logging();

    let client = CircleCiClient::new(
        "https://circleci.com/api/v2",
        "super-secret-circleci-token",
        no_retry_config(),
        500,
    )
    .expect("client should build");

    let debug_output = format!("{client:?}");
    assert!(!debug_output.contains("super-secret-circleci-token"));
    assert!(debug_output.contains("[REDACTED]"));
}

// ── Replay safety on retry (br-kxd3e) ────────────────────────────────
//
// The same shape as the confirmed github workflow_dispatch case that opened
// the bead: a 5xx means CircleCI RECEIVED the trigger, so replaying it queues
// a second pipeline — real compute, plus whatever that pipeline deploys.
// CircleCI has no idempotency key, so the fix refuses the unsafe retry.
//
// The assertion is the REQUEST COUNT. "It still errors" would pass with the
// bug present.

fn retrying_client(server: &MockServer) -> CircleCiClient {
    CircleCiClient::new(
        &server.uri(),
        TEST_TOKEN,
        HttpRetryConfig {
            max_retries: 3,
            initial_delay_ms: 1,
            max_delay_ms: 5,
            jitter_enabled: false,
        },
        500,
    )
    .expect("wiremock URI should build a CircleCI client")
}

#[fcp_async_core::runtime::test]
async fn trigger_pipeline_is_not_retried_after_a_5xx() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/project/gh/acme/app/pipeline"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;

    let result = retrying_client(&server)
        .trigger_pipeline(&test_runtime(), "gh/acme/app", &json!({ "branch": "main" }))
        .await;
    assert!(result.is_err());

    let requests = server.received_requests().await.expect("recorded requests");
    assert_eq!(
        requests.len(),
        1,
        "a 503 means CircleCI received the trigger — retrying queues a SECOND \
         pipeline run"
    );
}

#[fcp_async_core::runtime::test]
async fn rerun_workflow_is_not_retried_after_a_5xx() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/workflow/wf-1/rerun"))
        .respond_with(ResponseTemplate::new(502))
        .mount(&server)
        .await;

    let result = retrying_client(&server)
        .rerun_workflow(&test_runtime(), "wf-1", true)
        .await;
    assert!(result.is_err());

    let requests = server.received_requests().await.expect("recorded requests");
    assert_eq!(
        requests.len(),
        1,
        "a rerun creates a NEW workflow run, so a replay costs a second one"
    );
}

#[fcp_async_core::runtime::test]
async fn trigger_pipeline_still_retries_a_429() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/project/gh/acme/app/pipeline"))
        .respond_with(ResponseTemplate::new(429))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/project/gh/acme/app/pipeline"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "pipe-1",
            "state": "created",
            "number": 7
        })))
        .mount(&server)
        .await;

    retrying_client(&server)
        .trigger_pipeline(&test_runtime(), "gh/acme/app", &json!({ "branch": "main" }))
        .await
        .expect("a rate-limited trigger was refused without starting anything");

    let requests = server.received_requests().await.expect("recorded requests");
    assert_eq!(
        requests.len(),
        2,
        "429 means CircleCI did NOT queue the pipeline, so backoff must be preserved"
    );
}

#[fcp_async_core::runtime::test]
async fn cancel_workflow_is_still_retried_after_a_5xx() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/workflow/wf-1/cancel"))
        .respond_with(ResponseTemplate::new(500))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/workflow/wf-1/cancel"))
        .respond_with(ResponseTemplate::new(202).set_body_json(json!({ "message": "cancelled" })))
        .mount(&server)
        .await;

    retrying_client(&server)
        .cancel_workflow(&test_runtime(), "wf-1")
        .await
        .expect("cancel converges on the same state, so the retry is preserved");

    let requests = server.received_requests().await.expect("recorded requests");
    assert_eq!(
        requests.len(),
        2,
        "cancel is idempotent and must stay retryable"
    );
}
