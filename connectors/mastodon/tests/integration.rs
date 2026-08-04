//! Connector-local no-mock Mastodon integration proof.
//!
//! These tests exercise the real Mastodon client against a local HTTP server.
//! No live Mastodon service is called.

#![allow(clippy::missing_errors_doc, clippy::too_many_lines)]

use std::collections::BTreeSet;
use std::sync::Once;
use std::time::Duration;

use fcp_mastodon::client::MastodonClient;
use fcp_mastodon::connector::MastodonConnector;
use fcp_mastodon::error::MastodonError;
use fcp_prelude::{ApprovalMode, FcpConnector, IdempotencyClass, RiskLevel, SafetyTier};
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use serde_json::{Value, json};
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_TOKEN: &str = "mastodon-token-for-tests";
const AUTH_HEADER: &str = "Bearer mastodon-token-for-tests";
const EXPECTED_MANIFEST_SCHEMA_OPS: [(&str, &str); 12] = [
    ("timeline_home", "mastodon.timeline.home"),
    ("timeline_public", "mastodon.timeline.public"),
    ("statuses_get", "mastodon.statuses.get"),
    ("statuses_post", "mastodon.statuses.post"),
    ("statuses_delete", "mastodon.statuses.delete"),
    ("statuses_favourite", "mastodon.statuses.favourite"),
    ("statuses_boost", "mastodon.statuses.boost"),
    ("accounts_get", "mastodon.accounts.get"),
    ("accounts_verify", "mastodon.accounts.verify"),
    ("notifications_list", "mastodon.notifications.list"),
    ("search", "mastodon.search"),
    ("health", "mastodon.health"),
];

static LOG_INIT: Once = Once::new();

fn init_logging() {
    LOG_INIT.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| {
                        tracing_subscriber::EnvFilter::new(
                            "info,asupersync=warn,fcp_sdk=warn,hyper=warn,hyper_util=warn,reqwest=warn,wiremock=warn",
                        )
                    }),
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

fn client(server: &MockServer) -> MastodonClient {
    MastodonClient::new(&server.uri(), TEST_TOKEN, no_retry_config())
        .expect("wiremock URI should build a Mastodon client")
}

fn mastodon_manifest() -> toml::Value {
    toml::from_str(include_str!("../manifest.toml")).expect("Mastodon manifest TOML should parse")
}

fn manifest_operations(manifest: &toml::Value) -> &toml::Table {
    manifest
        .get("provides")
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .expect("manifest should contain provides.operations")
}

fn operation_schema(manifest: &toml::Value, operation_key: &str, schema_key: &str) -> Value {
    let schema = manifest_operations(manifest)
        .get(operation_key)
        .and_then(|operation| operation.get(schema_key))
        .expect("operation should define requested schema");

    serde_json::to_value(schema).expect("manifest schema should convert to JSON")
}

fn operation_network_constraints<'a>(
    manifest: &'a toml::Value,
    operation_key: &str,
) -> &'a toml::Table {
    manifest_operations(manifest)
        .get(operation_key)
        .and_then(|operation| operation.get("network_constraints"))
        .and_then(toml::Value::as_table)
        .unwrap_or_else(|| panic!("{operation_key} should define network_constraints"))
}

fn operation_ai_hints<'a>(manifest: &'a toml::Value, operation_key: &str) -> &'a toml::Table {
    manifest_operations(manifest)
        .get(operation_key)
        .and_then(|operation| operation.get("ai_hints"))
        .and_then(toml::Value::as_table)
        .expect("operation should define ai_hints")
}

fn assert_manifest_operation_inventory(operations: &toml::Table) {
    let expected = EXPECTED_MANIFEST_SCHEMA_OPS
        .iter()
        .map(|(operation_key, _operation_id)| *operation_key)
        .collect::<BTreeSet<_>>();
    let actual = operations
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual, expected,
        "manifest operation set should stay aligned with expected operation coverage"
    );
}

fn network_string_list<'a>(constraints: &'a toml::Table, key: &str) -> Vec<&'a str> {
    constraints
        .get(key)
        .and_then(toml::Value::as_array)
        .unwrap_or_else(|| panic!("{key} should be an array"))
        .iter()
        .map(|value| {
            value
                .as_str()
                .unwrap_or_else(|| panic!("{key} entries should be strings"))
        })
        .collect()
}

fn network_integer_list(constraints: &toml::Table, key: &str) -> Vec<i64> {
    constraints
        .get(key)
        .and_then(toml::Value::as_array)
        .unwrap_or_else(|| panic!("{key} should be an array"))
        .iter()
        .map(|value| {
            value
                .as_integer()
                .unwrap_or_else(|| panic!("{key} entries should be integers"))
        })
        .collect()
}

fn network_bool_field(constraints: &toml::Table, key: &str) -> bool {
    constraints
        .get(key)
        .and_then(toml::Value::as_bool)
        .unwrap_or_else(|| panic!("{key} should be a boolean"))
}

fn network_integer_field(constraints: &toml::Table, key: &str) -> i64 {
    constraints
        .get(key)
        .and_then(toml::Value::as_integer)
        .unwrap_or_else(|| panic!("{key} should be an integer"))
}

fn assert_instance_egress_constraints(constraints: &toml::Table) {
    assert_eq!(
        network_string_list(constraints, "host_allow"),
        ["${mastodon_instance_host}"]
    );
    assert_eq!(network_integer_list(constraints, "port_allow"), [80, 443]);
    assert!(network_bool_field(constraints, "deny_localhost"));
    assert!(network_bool_field(constraints, "deny_private_ranges"));
    assert!(network_bool_field(constraints, "deny_tailnet_ranges"));
    assert!(network_bool_field(constraints, "require_sni"));
    assert!(network_bool_field(constraints, "deny_ip_literals"));
    assert!(network_bool_field(
        constraints,
        "require_host_canonicalization"
    ));
    assert_eq!(network_integer_field(constraints, "dns_max_ips"), 16);
    assert_eq!(network_integer_field(constraints, "max_redirects"), 0);
    assert_eq!(
        network_integer_field(constraints, "connect_timeout_ms"),
        10_000
    );
    assert_eq!(
        network_integer_field(constraints, "total_timeout_ms"),
        60_000
    );
}

fn assert_schema_accepts(schema: &Value, payload: Value) {
    let validator = jsonschema::validator_for(schema).expect("schema should compile");
    let errors = validator
        .iter_errors(&payload)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(
        errors.is_empty(),
        "schema should accept payload {payload:#}: {errors:#?}"
    );
}

fn assert_schema_rejects(schema: &Value, payload: Value) {
    let validator = jsonschema::validator_for(schema).expect("schema should compile");
    let errors = validator
        .iter_errors(&payload)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(
        !errors.is_empty(),
        "schema should reject payload {payload:#}"
    );
}

fn account(account_id: &str, username: &str) -> serde_json::Value {
    json!({
        "id": account_id,
        "username": username,
        "acct": username,
        "display_name": username,
        "note": "",
        "url": format!("https://mastodon.local/@{username}"),
        "avatar": "https://mastodon.local/avatar.png",
        "header": "https://mastodon.local/header.png",
        "followers_count": 12,
        "following_count": 7,
        "statuses_count": 5,
        "locked": false,
        "bot": false,
        "created_at": "2026-05-01T00:00:00.000Z"
    })
}

fn status(status_id: &str, content: &str) -> serde_json::Value {
    json!({
        "id": status_id,
        "uri": format!("https://mastodon.local/users/alice/statuses/{status_id}"),
        "url": format!("https://mastodon.local/@alice/{status_id}"),
        "content": content,
        "created_at": "2026-05-01T12:00:00.000Z",
        "account": account("acct_1", "alice"),
        "reblogs_count": 1,
        "favourites_count": 2,
        "replies_count": 3,
        "visibility": "public",
        "sensitive": false,
        "spoiler_text": "",
        "media_attachments": [],
        "reblog": null,
        "favourited": false,
        "reblogged": false,
        "application": null,
        "in_reply_to_id": null,
        "in_reply_to_account_id": null
    })
}

fn instance() -> serde_json::Value {
    json!({
        "uri": "mastodon.local",
        "domain": "mastodon.local",
        "title": "FCP Mastodon",
        "version": "4.2.12"
    })
}

#[fcp_async_core::runtime::test]
async fn client_health_check_uses_v2_instance_endpoint() {
    init_logging();

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v2/instance"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "title": "Test Instance",
            "version": "4.2.0"
        })))
        .mount(&server)
        .await;

    let client = client(&server);
    let result = client.health_check().await;
    assert!(result.is_ok());
    let instance = result.unwrap();
    assert_eq!(instance.title, "Test Instance");
}

#[fcp_async_core::runtime::test]
async fn client_health_check_falls_back_to_v1_instance_endpoint() {
    init_logging();

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v2/instance"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/instance"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "uri": "test.instance",
            "title": "Test v1 Instance",
            "version": "3.5.0"
        })))
        .mount(&server)
        .await;

    let client = client(&server);
    let result = client.health_check().await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().title, "Test v1 Instance");
}

#[fcp_async_core::runtime::test]
async fn timeline_status_account_search_notifications_and_health_use_mastodon_contracts() {
    init_logging();
    tracing::info!(
        scenario = "mastodon_success_contracts",
        "starting Mastodon success-path integration proof",
    );

    let server = MockServer::start().await;
    let runtime = test_runtime();

    Mock::given(method("GET"))
        .and(path("/api/v1/timelines/home"))
        .and(query_param("limit", "2"))
        .and(header("authorization", AUTH_HEADER))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!([status("status_home", "<p>home</p>")])),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/timelines/public"))
        .and(query_param("local", "true"))
        .and(query_param("limit", "3"))
        .and(header("authorization", AUTH_HEADER))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!([status("status_public", "<p>public</p>")])),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/statuses/status_1"))
        .and(header("authorization", AUTH_HEADER))
        .respond_with(ResponseTemplate::new(200).set_body_json(status("status_1", "<p>one</p>")))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/accounts/acct_1"))
        .and(header("authorization", AUTH_HEADER))
        .respond_with(ResponseTemplate::new(200).set_body_json(account("acct_1", "alice")))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/accounts/verify_credentials"))
        .and(header("authorization", AUTH_HEADER))
        .respond_with(ResponseTemplate::new(200).set_body_json(account("acct_self", "self")))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/notifications"))
        .and(query_param("limit", "1"))
        .and(header("authorization", AUTH_HEADER))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
            "id": "notif_1",
            "type": "favourite",
            "created_at": "2026-05-01T12:01:00.000Z",
            "account": account("acct_2", "bob"),
            "status": status("status_1", "<p>one</p>")
        }])))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v2/search"))
        .and(query_param("q", "rust"))
        .and(query_param("type", "statuses"))
        .and(query_param("limit", "5"))
        .and(header("authorization", AUTH_HEADER))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accounts": [account("acct_3", "rustacean")],
            "statuses": [status("status_search", "<p>rust</p>")],
            "hashtags": [{
                "name": "rust",
                "url": "https://mastodon.local/tags/rust",
                "history": []
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v2/instance"))
        .respond_with(ResponseTemplate::new(200).set_body_json(instance()))
        .expect(1)
        .mount(&server)
        .await;

    let client = client(&server);

    let home = client
        .get_home_timeline(&runtime, Some(2))
        .await
        .expect("home timeline should decode");
    assert_eq!(home[0].id, "status_home");

    let public = client
        .get_public_timeline(&runtime, true, Some(3))
        .await
        .expect("public timeline should decode");
    assert_eq!(public[0].id, "status_public");

    let fetched_status = client
        .get_status(&runtime, "status_1")
        .await
        .expect("status detail should decode");
    assert_eq!(fetched_status.content, "<p>one</p>");

    let fetched_account = client
        .get_account(&runtime, "acct_1")
        .await
        .expect("account detail should decode");
    assert_eq!(fetched_account.username, "alice");

    let self_account = client
        .verify_credentials(&runtime)
        .await
        .expect("credential verification should decode");
    assert_eq!(self_account.username, "self");

    let notifications = client
        .get_notifications(&runtime, Some(1))
        .await
        .expect("notifications should decode");
    assert_eq!(notifications[0].notification_type, "favourite");
    assert_eq!(
        notifications[0].status.as_ref().expect("status").id,
        "status_1"
    );

    let search = client
        .search(&runtime, "rust", Some("statuses"), Some(5))
        .await
        .expect("search should decode");
    assert_eq!(search.hashtags[0].name, "rust");
    assert_eq!(search.statuses[0].id, "status_search");

    let health = client
        .health_check()
        .await
        .expect("instance health should decode");
    assert_eq!(health.title, "FCP Mastodon");
    assert_eq!(health.version, "4.2.12");
}

#[fcp_async_core::runtime::test]
async fn write_and_destructive_requests_use_expected_mastodon_shapes() {
    init_logging();
    tracing::info!(
        scenario = "mastodon_write_contracts",
        "starting Mastodon write/delete request-shape proof",
    );

    let server = MockServer::start().await;
    let runtime = test_runtime();

    Mock::given(method("POST"))
        .and(path("/api/v1/statuses"))
        .and(header("authorization", AUTH_HEADER))
        .and(body_json(json!({
            "status": "hello from fcp",
            "visibility": "unlisted",
            "in_reply_to_id": "status_parent",
            "sensitive": true,
            "spoiler_text": "release notes"
        })))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(status("status_created", "<p>hello from fcp</p>")),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/v1/statuses/status_1/favourite"))
        .and(header("authorization", AUTH_HEADER))
        .and(body_json(json!({})))
        .respond_with(ResponseTemplate::new(200).set_body_json(status("status_1", "<p>fav</p>")))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/v1/statuses/status_1/reblog"))
        .and(header("authorization", AUTH_HEADER))
        .and(body_json(json!({})))
        .respond_with(ResponseTemplate::new(200).set_body_json(status("status_1", "<p>boost</p>")))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("DELETE"))
        .and(path("/api/v1/statuses/status_old"))
        .and(header("authorization", AUTH_HEADER))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(status("status_old", "<p>deleted</p>")),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = client(&server);

    let created = client
        .post_status(
            &runtime,
            "hello from fcp",
            Some("unlisted"),
            Some("status_parent"),
            true,
            Some("release notes"),
        )
        .await
        .expect("status post should decode");
    assert_eq!(created.id, "status_created");

    let favourite = client
        .favourite_status(&runtime, "status_1")
        .await
        .expect("favourite should decode");
    assert_eq!(favourite.content, "<p>fav</p>");

    let boost = client
        .boost_status(&runtime, "status_1")
        .await
        .expect("boost should decode");
    assert_eq!(boost.content, "<p>boost</p>");

    let deleted = client
        .delete_status(&runtime, "status_old")
        .await
        .expect("delete should decode deleted status body");
    assert_eq!(deleted.id, "status_old");
}

#[fcp_async_core::runtime::test]
async fn auth_rate_limit_not_found_malformed_json_and_invalid_input_are_typed() {
    init_logging();
    tracing::info!(
        scenario = "mastodon_error_taxonomy",
        "starting Mastodon error-taxonomy proof",
    );

    let server = MockServer::start().await;
    let runtime = test_runtime();

    Mock::given(method("GET"))
        .and(path("/api/v1/accounts/unauthorized"))
        .and(header("authorization", AUTH_HEADER))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": "invalid token"
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/statuses/rate_limited"))
        .and(header("authorization", AUTH_HEADER))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "5")
                .set_body_json(json!({ "error": "slow down" })),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/statuses/missing"))
        .and(header("authorization", AUTH_HEADER))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": "Record not found"
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/statuses/bad_json"))
        .and(header("authorization", AUTH_HEADER))
        .respond_with(ResponseTemplate::new(200).set_body_string("{this is not json"))
        .expect(1)
        .mount(&server)
        .await;

    let client = client(&server);

    let unauthorized = client
        .get_account(&runtime, "unauthorized")
        .await
        .expect_err("401 should map to unauthorized");
    assert!(matches!(unauthorized, MastodonError::Unauthorized(_)));
    assert!(!unauthorized.is_retryable());

    let rate_limited = client
        .get_status(&runtime, "rate_limited")
        .await
        .expect_err("429 should map to rate limit");
    assert!(matches!(
        rate_limited,
        MastodonError::RateLimited {
            retry_after_ms: 5_000
        }
    ));
    assert_eq!(rate_limited.retry_after(), Some(Duration::from_secs(5)));

    let missing = client
        .get_status(&runtime, "missing")
        .await
        .expect_err("404 should map to API error");
    assert!(matches!(missing, MastodonError::Api { status: 404, .. }));
    assert!(!missing.is_retryable());

    let malformed = client
        .get_status(&runtime, "bad_json")
        .await
        .expect_err("malformed JSON should be a typed decode failure");
    assert!(matches!(malformed, MastodonError::Http(ref source) if source.is_decode()));
    assert!(malformed.is_retryable());

    let traversal = client
        .get_status(&runtime, "../admin")
        .await
        .expect_err("path traversal should be rejected before outbound call");
    assert!(matches!(traversal, MastodonError::Config(_)));
}

#[fcp_async_core::runtime::test]
async fn cancelled_runtime_short_circuits_before_network_io() {
    init_logging();
    tracing::info!(
        scenario = "mastodon_cancellation",
        "starting Mastodon cancellation proof",
    );

    let server = MockServer::start().await;
    let runtime = test_runtime();
    runtime.shutdown();

    let client = client(&server);
    let error = client
        .get_status(&runtime, "status_never_sent")
        .await
        .expect_err("cancelled runtime should fail before HTTP is sent");

    assert!(matches!(
        error,
        MastodonError::Async(message) if message == "operation cancelled"
    ));
}

#[test]
fn operation_catalog_preserves_risk_approval_and_event_metadata() {
    init_logging();

    let introspection = MastodonConnector::new().introspect();
    assert!(introspection.events.is_empty());
    assert!(
        !introspection
            .event_caps
            .as_ref()
            .expect("event caps")
            .streaming
    );

    let operation = |id: &str| {
        introspection
            .operations
            .iter()
            .find(|entry| entry.id.as_str() == id)
            .expect("operation catalog should contain requested Mastodon operation")
    };

    let timeline = operation("mastodon.timeline.home");
    assert_eq!(timeline.risk_level, RiskLevel::Low);
    assert_eq!(timeline.safety_tier, SafetyTier::Safe);
    assert_eq!(timeline.requires_approval, Some(ApprovalMode::None));

    let status_post = operation("mastodon.statuses.post");
    assert_eq!(status_post.risk_level, RiskLevel::Medium);
    assert_eq!(status_post.safety_tier, SafetyTier::Risky);
    assert_eq!(status_post.idempotency, IdempotencyClass::None);
    assert_eq!(status_post.requires_approval, Some(ApprovalMode::None));

    let status_delete = operation("mastodon.statuses.delete");
    assert_eq!(status_delete.risk_level, RiskLevel::High);
    assert_eq!(status_delete.safety_tier, SafetyTier::Dangerous);
    assert_eq!(status_delete.idempotency, IdempotencyClass::Strict);
    assert_eq!(
        status_delete.requires_approval,
        Some(ApprovalMode::Interactive)
    );

    let favourite = operation("mastodon.statuses.favourite");
    assert_eq!(favourite.risk_level, RiskLevel::Low);
    assert_eq!(favourite.safety_tier, SafetyTier::Risky);
    assert_eq!(favourite.idempotency, IdempotencyClass::BestEffort);
}

#[test]
fn manifest_ai_hints_cover_all_operations() {
    init_logging();

    let manifest = mastodon_manifest();
    let operations = manifest_operations(&manifest);
    assert_manifest_operation_inventory(operations);

    for (operation_key, operation_id) in EXPECTED_MANIFEST_SCHEMA_OPS {
        let ai_hints = operation_ai_hints(&manifest, operation_key);
        let when_to_use = ai_hints
            .get("when_to_use")
            .and_then(toml::Value::as_str)
            .expect("ai_hints.when_to_use should be a string");
        assert!(
            !when_to_use.trim().is_empty(),
            "{operation_id} ai_hints.when_to_use should be non-empty"
        );

        let common_mistakes = ai_hints
            .get("common_mistakes")
            .and_then(toml::Value::as_array)
            .expect("ai_hints.common_mistakes should be an array");
        assert!(
            common_mistakes.len() >= 2,
            "{operation_id} should document at least two common mistakes"
        );
        for mistake in common_mistakes {
            let mistake = mistake
                .as_str()
                .expect("ai_hints.common_mistakes entries should be strings");
            assert!(
                !mistake.trim().is_empty(),
                "{operation_id} common mistakes should be non-empty"
            );
        }

        let examples = ai_hints
            .get("examples")
            .and_then(toml::Value::as_array)
            .expect("ai_hints.examples should be an array");
        assert!(
            !examples.is_empty(),
            "{operation_id} should include at least one ai_hints example"
        );
        for example in examples {
            let example = example
                .as_str()
                .expect("ai_hints.examples entries should be strings");
            let lowered = example.to_ascii_lowercase();
            for forbidden in ["api_key", "bearer", "password", "secret", "token"] {
                assert!(
                    !lowered.contains(forbidden),
                    "{operation_id} example should not contain secret-shaped text: {forbidden}"
                );
            }
            let parsed = serde_json::from_str::<Value>(example)
                .expect("ai_hints examples should be valid JSON payloads");
            assert!(
                parsed.is_object(),
                "{operation_id} ai_hints examples should be JSON objects"
            );
        }
    }
}

#[test]
fn manifest_operation_schemas_compile_and_validate_core_payloads() {
    init_logging();

    let manifest = mastodon_manifest();
    let introspection = MastodonConnector::new().introspect();
    assert_eq!(
        introspection.operations.len(),
        EXPECTED_MANIFEST_SCHEMA_OPS.len(),
        "runtime operation catalog should stay aligned with manifest schema coverage"
    );

    for (manifest_key, operation_id) in EXPECTED_MANIFEST_SCHEMA_OPS {
        let operation = introspection
            .operations
            .iter()
            .find(|entry| entry.id.as_str() == operation_id)
            .expect("runtime catalog should include manifest operation");
        let input_schema = operation_schema(&manifest, manifest_key, "input_schema");
        let output_schema = operation_schema(&manifest, manifest_key, "output_schema");

        assert_eq!(
            input_schema, operation.input_schema,
            "{operation_id} manifest input_schema should match runtime OperationInfo"
        );
        assert_eq!(
            output_schema, operation.output_schema,
            "{operation_id} manifest output_schema should match runtime OperationInfo"
        );

        assert!(
            jsonschema::validator_for(&input_schema).is_ok(),
            "{operation_id} manifest input_schema should compile"
        );
        assert!(
            jsonschema::validator_for(&output_schema).is_ok(),
            "{operation_id} manifest output_schema should compile"
        );
    }

    let timeline_input = operation_schema(&manifest, "timeline_home", "input_schema");
    assert_schema_accepts(&timeline_input, json!({}));
    assert_schema_accepts(&timeline_input, json!({ "limit": 40 }));
    assert_schema_rejects(&timeline_input, json!({ "limit": 0 }));
    assert_schema_rejects(&timeline_input, json!({ "limit": 2, "extra": true }));

    let public_timeline_input = operation_schema(&manifest, "timeline_public", "input_schema");
    assert_schema_accepts(&public_timeline_input, json!({ "local": true, "limit": 3 }));
    assert_schema_rejects(&public_timeline_input, json!({ "local": "true" }));

    let id_input = operation_schema(&manifest, "statuses_get", "input_schema");
    assert_schema_accepts(&id_input, json!({ "id": "status_1" }));
    assert_schema_rejects(&id_input, json!({ "id": "" }));
    assert_schema_rejects(&id_input, json!({ "id": "status_1", "extra": true }));

    let post_input = operation_schema(&manifest, "statuses_post", "input_schema");
    assert_schema_accepts(
        &post_input,
        json!({
            "status": "hello from fcp",
            "visibility": "unlisted",
            "in_reply_to_id": "status_parent",
            "sensitive": true,
            "spoiler_text": "release notes"
        }),
    );
    assert_schema_rejects(&post_input, json!({ "status": "" }));
    assert_schema_rejects(
        &post_input,
        json!({ "status": "hello", "visibility": "friends" }),
    );

    let empty_input = operation_schema(&manifest, "health", "input_schema");
    assert_schema_accepts(&empty_input, json!({}));
    assert_schema_rejects(&empty_input, json!({ "probe": true }));

    let search_input = operation_schema(&manifest, "search", "input_schema");
    assert_schema_accepts(
        &search_input,
        json!({ "q": "rust", "type": "statuses", "limit": 5 }),
    );
    assert_schema_rejects(&search_input, json!({ "q": "rust", "type": "mentions" }));

    let status_payload = status("status_1", "<p>one</p>");
    let status_output = operation_schema(&manifest, "statuses_get", "output_schema");
    assert_schema_accepts(&status_output, status_payload.clone());
    assert_schema_rejects(
        &status_output,
        json!({
            "content": "<p>missing id</p>",
            "account": account("acct_1", "alice")
        }),
    );

    let timeline_output = operation_schema(&manifest, "timeline_home", "output_schema");
    assert_schema_accepts(&timeline_output, json!([status_payload.clone()]));
    assert_schema_rejects(&timeline_output, json!({ "id": "not-an-array" }));

    let account_output = operation_schema(&manifest, "accounts_get", "output_schema");
    assert_schema_accepts(&account_output, account("acct_1", "alice"));
    assert_schema_rejects(&account_output, json!({ "username": "alice" }));

    let notification_output = operation_schema(&manifest, "notifications_list", "output_schema");
    assert_schema_accepts(
        &notification_output,
        json!([{
            "id": "notif_1",
            "type": "favourite",
            "created_at": "2026-05-01T12:01:00.000Z",
            "account": account("acct_2", "bob"),
            "status": status_payload.clone()
        }]),
    );

    let search_output = operation_schema(&manifest, "search", "output_schema");
    assert_schema_accepts(
        &search_output,
        json!({
            "accounts": [account("acct_3", "rustacean")],
            "statuses": [status_payload],
            "hashtags": [{
                "name": "rust",
                "url": "https://mastodon.local/tags/rust",
                "history": []
            }]
        }),
    );
    assert_schema_rejects(&search_output, json!({ "accounts": [], "statuses": [] }));

    let health_output = operation_schema(&manifest, "health", "output_schema");
    assert_schema_accepts(&health_output, instance());
    assert_schema_rejects(&health_output, json!({ "title": "FCP Mastodon" }));
}

#[test]
fn manifest_declares_instance_scoped_network_constraints() {
    init_logging();

    let manifest = mastodon_manifest();
    let operations = manifest_operations(&manifest);
    assert_manifest_operation_inventory(operations);
    for (operation_key, _operation_id) in EXPECTED_MANIFEST_SCHEMA_OPS {
        assert_instance_egress_constraints(operation_network_constraints(&manifest, operation_key));
    }
}

#[test]
fn debug_output_redacts_mastodon_secrets() {
    init_logging();

    let client = MastodonClient::new(
        "https://mastodon.local",
        "super-secret-mastodon-token",
        no_retry_config(),
    )
    .expect("redaction proof client should build");

    let debug_client = format!("{client:?}");
    assert!(!debug_client.contains("super-secret-mastodon-token"));
    assert!(debug_client.contains("[REDACTED]"));
}

// ── Replay safety on retry (br-kxd3e) ────────────────────────────────
//
// A 5xx or a timeout can both be reported after Mastodon already created the
// status, so a bare retry posts the toot twice. Mastodon deduplicates on
// `Idempotency-Key` for POST /statuses, which makes the retry genuinely safe
// rather than merely refused.
//
// These pin the DISTINCTION: asserting only "the call succeeds" would pass
// with a per-attempt key, which provides exactly zero protection.

fn retrying_client(server: &MockServer) -> MastodonClient {
    MastodonClient::new(
        &server.uri(),
        TEST_TOKEN,
        HttpRetryConfig {
            max_retries: 3,
            initial_delay_ms: 1,
            max_delay_ms: 5,
            jitter_enabled: false,
        },
    )
    .expect("wiremock URI should build a Mastodon client")
}

fn idempotency_keys_of(requests: &[wiremock::Request]) -> Vec<String> {
    requests
        .iter()
        .map(|r| {
            r.headers
                .get("idempotency-key")
                .map(|v| v.to_str().expect("header is ASCII").to_string())
                .unwrap_or_default()
        })
        .collect()
}

fn status_body() -> Value {
    status("109", "<p>hello</p>")
}

#[fcp_async_core::runtime::test]
async fn post_status_presents_one_stable_idempotency_key_across_attempts() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/statuses"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/statuses"))
        .respond_with(ResponseTemplate::new(200).set_body_json(status_body()))
        .mount(&server)
        .await;

    retrying_client(&server)
        .post_status(&test_runtime(), "hello", None, None, false, None)
        .await
        .expect("the retry should succeed");

    let requests = server.received_requests().await.expect("recorded requests");
    assert_eq!(requests.len(), 2, "the 503 should have been retried");

    let keys = idempotency_keys_of(&requests);
    assert!(
        !keys[0].is_empty(),
        "POST /statuses must carry Idempotency-Key so the retry cannot post twice"
    );
    assert_eq!(
        keys[0], keys[1],
        "both attempts must present the SAME key — a per-attempt key would let \
         Mastodon treat the retry as a new status and publish it twice"
    );
}

#[fcp_async_core::runtime::test]
async fn favourite_sends_no_idempotency_key() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/statuses/109/favourite"))
        .respond_with(ResponseTemplate::new(200).set_body_json(status_body()))
        .mount(&server)
        .await;

    retrying_client(&server)
        .favourite_status(&test_runtime(), "109")
        .await
        .expect("favourite should succeed");

    let requests = server.received_requests().await.expect("recorded requests");
    assert_eq!(
        idempotency_keys_of(&requests)[0],
        "",
        "Mastodon honours Idempotency-Key only on POST /statuses; favourite is \
         safe because the flag is already set on a replay"
    );
}
