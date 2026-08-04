//! Twitter/X connector integration tests.
//!
//! Deterministic integration tests using wiremock to mock the Twitter API v2.
//! No real API calls. Covers:
//! - Happy-path operations (lookups, search, timeline, trends, tweet.create)
//! - Error taxonomy (401/403/429 -> FcpError mapping)
//! - FCP2 default-deny + capability verification
//! - Lifecycle (health, handshake, introspect, shutdown)
//! - Input validation edge cases

#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]

use chrono::{Duration, Utc};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_prelude::CapabilityConstraints;
use fcp_testkit::AsyncTestContext;
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path, path_regex},
};

use fcp_twitter::TwitterConnector;

// ============================================================================
// Helpers
// ============================================================================

/// Map an operation ID to the capability ID that governs it.
fn capability_for_operation(op: &str) -> &str {
    match op {
        "twitter.user.me" | "twitter.user.timeline" | "twitter.user.mentions" => {
            "twitter.read.account"
        }
        "twitter.tweet.retweet"
        | "twitter.tweet.unretweet"
        | "twitter.tweet.like"
        | "twitter.tweet.unlike"
        | "twitter.tweet.create"
        | "twitter.tweet.reply"
        | "twitter.tweet.delete" => "twitter.write.tweets",
        "twitter.dm.send" => "twitter.write.dms",
        "twitter.dm.events" => "twitter.read.dms",
        "twitter.stream.rules.list"
        | "twitter.stream.rules.add"
        | "twitter.stream.rules.delete" => "twitter.stream.read",
        _ => "twitter.read.public",
    }
}

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &str,
    op: &str,
) -> fcp_core::CapabilityToken {
    let cap = capability_for_operation(op);
    let now = Utc::now();
    // C3.4: tokens MUST include constraints (default-deny)
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(cap)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[op])
        .issuer("node:test")
        .target_instance(instance_id)
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .unwrap()
        .sign(signing_key)
        .unwrap();
    fcp_core::CapabilityToken::from_raw(cose)
}

/// Mock the `/2/users/me` endpoint required by handshake.
async fn mount_get_me_mock(mock_server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/2/users/me"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "id": "12345",
                "name": "Test Bot",
                "username": "test_bot_fcp"
            }
        })))
        .mount(mock_server)
        .await;
}

async fn setup_configure(connector: &mut TwitterConnector, base_url: &str) {
    connector
        .handle_configure(json!({
            "consumer_key": "test-ck",
            "consumer_secret": "test-cs",
            "access_token": "test-at",
            "access_token_secret": "test-ats",
            "bearer_token": "test-bt",
            "api_url": base_url
        }))
        .await
        .expect("configure should succeed");
}

async fn setup_handshake(
    connector: &mut TwitterConnector,
    mock_server: &MockServer,
    caps: &[&str],
) -> Ed25519SigningKey {
    mount_get_me_mock(mock_server).await;

    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let mapped: Vec<&str> = caps.iter().map(|c| capability_for_operation(c)).collect();

    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": mapped
        }))
        .await
        .expect("handshake should succeed");

    signing_key
}

// ============================================================================
// Happy-path operation tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn user_me_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twitter.user.me.happy_path");
    let mock_server = MockServer::start().await;

    // get_me is called both during handshake and during invoke
    Mock::given(method("GET"))
        .and(path("/2/users/me"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "id": "12345",
                "name": "Test Bot",
                "username": "test_bot_fcp"
            }
        })))
        .expect(2..)
        .mount(&mock_server)
        .await;

    let mut connector = TwitterConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &mock_server, &["twitter.user.me"]).await;
    let token = generate_valid_token(&signing_key, connector.instance_id(), "twitter.user.me");

    let result = connector
        .handle_invoke(json!({
            "operation": "twitter.user.me",
            "args": {},
            "capability_token": token
        }))
        .await
        .expect("user.me invoke should succeed");

    assert_eq!(result["user"]["username"], "test_bot_fcp");
}

#[fcp_async_core::runtime::test]
async fn user_get_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twitter.user.get.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/2/users/67890"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "id": "67890",
                "name": "Other User",
                "username": "other_user"
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = TwitterConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &mock_server, &["twitter.user.get"]).await;
    let token = generate_valid_token(&signing_key, connector.instance_id(), "twitter.user.get");

    let result = connector
        .handle_invoke(json!({
            "operation": "twitter.user.get",
            "args": { "user_id": "67890" },
            "capability_token": token
        }))
        .await
        .expect("user.get invoke should succeed");

    assert_eq!(result["user"]["id"], "67890");
    assert_eq!(result["user"]["username"], "other_user");
}

#[fcp_async_core::runtime::test]
async fn tweet_get_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twitter.tweet.get.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/2/tweets/111222333"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "id": "111222333",
                "text": "Hello from FCP integration test!",
                "author_id": "12345"
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = TwitterConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &mock_server, &["twitter.tweet.get"]).await;
    let token = generate_valid_token(&signing_key, connector.instance_id(), "twitter.tweet.get");

    let result = connector
        .handle_invoke(json!({
            "operation": "twitter.tweet.get",
            "args": { "tweet_id": "111222333" },
            "capability_token": token
        }))
        .await
        .expect("tweet.get invoke should succeed");

    assert_eq!(result["tweet"]["id"], "111222333");
    assert_eq!(result["tweet"]["text"], "Hello from FCP integration test!");
}

#[fcp_async_core::runtime::test]
async fn tweet_search_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twitter.tweet.search.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/2/tweets/search/recent.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {
                    "id": "t1",
                    "text": "Rust is great!",
                    "author_id": "u1"
                },
                {
                    "id": "t2",
                    "text": "Learning Rust today",
                    "author_id": "u2"
                }
            ],
            "meta": {
                "result_count": 2,
                "newest_id": "t1",
                "oldest_id": "t2"
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = TwitterConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &mock_server, &["twitter.tweet.search"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twitter.tweet.search",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "twitter.tweet.search",
            "args": { "query": "rust programming", "max_results": 10 },
            "capability_token": token
        }))
        .await
        .expect("tweet.search invoke should succeed");

    let tweets = result["tweets"].as_array().expect("tweets array");
    assert_eq!(tweets.len(), 2);
}

#[fcp_async_core::runtime::test]
async fn tweet_create_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twitter.tweet.create.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/2/tweets"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "data": {
                "id": "new-tweet-1",
                "text": "Hello world from FCP!"
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = TwitterConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &mock_server, &["twitter.tweet.create"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twitter.tweet.create",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "twitter.tweet.create",
            "args": { "text": "Hello world from FCP!" },
            "capability_token": token
        }))
        .await
        .expect("tweet.create invoke should succeed");

    assert_eq!(result["tweet"]["id"], "new-tweet-1");
}

#[fcp_async_core::runtime::test]
async fn user_timeline_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twitter.user.timeline.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/2/users/67890/tweets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {
                    "id": "tl-1",
                    "text": "Timeline tweet one",
                    "author_id": "67890"
                }
            ],
            "meta": {
                "result_count": 1
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = TwitterConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &mock_server, &["twitter.user.timeline"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twitter.user.timeline",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "twitter.user.timeline",
            "args": { "user_id": "67890", "max_results": 10 },
            "capability_token": token
        }))
        .await
        .expect("user.timeline invoke should succeed");

    let tweets = result["tweets"].as_array().expect("tweets array");
    assert_eq!(tweets.len(), 1);
    assert_eq!(tweets[0]["id"], "tl-1");
}

#[fcp_async_core::runtime::test]
async fn trends_place_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twitter.trends.place.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/1.1/trends/place.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {
                "trends": [
                    {
                        "name": "#rustlang",
                        "url": "https://twitter.com/search?q=%23rustlang",
                        "query": "%23rustlang",
                        "tweet_volume": 12345
                    }
                ],
                "as_of": "2026-03-02T00:00:00Z",
                "created_at": "2026-03-02T00:00:00Z",
                "locations": [
                    { "name": "Worldwide", "woeid": 1 }
                ]
            }
        ])))
        .mount(&mock_server)
        .await;

    let mut connector = TwitterConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &mock_server, &["twitter.trends.place"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twitter.trends.place",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "twitter.trends.place",
            "args": { "woeid": 1 },
            "capability_token": token
        }))
        .await
        .expect("trends.place invoke should succeed");

    let locations = result["locations"].as_array().expect("locations array");
    assert_eq!(locations.len(), 1);
    assert_eq!(locations[0]["locations"][0]["name"], "Worldwide");
    assert_eq!(locations[0]["trends"][0]["name"], "#rustlang");
}

// ============================================================================
// Error taxonomy tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn unauthorized_maps_to_fcp_error() {
    let _ctx = AsyncTestContext::for_scenario("twitter.error.unauthorized");
    let mock_server = MockServer::start().await;

    // Mount get_me for handshake (succeeds), then user.get fails with 401
    Mock::given(method("GET"))
        .and(path("/2/users/bad-id"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "title": "Unauthorized",
            "detail": "Invalid or expired token",
            "type": "about:blank",
            "status": 401
        })))
        .mount(&mock_server)
        .await;

    let mut connector = TwitterConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &mock_server, &["twitter.user.get"]).await;
    let token = generate_valid_token(&signing_key, connector.instance_id(), "twitter.user.get");

    let result = connector
        .handle_invoke(json!({
            "operation": "twitter.user.get",
            "args": { "user_id": "bad-id" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn rate_limited_maps_to_fcp_error() {
    let _ctx = AsyncTestContext::for_scenario("twitter.error.rate_limited");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/2/tweets/search/recent.*"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({
                    "title": "Too Many Requests",
                    "detail": "Rate limit exceeded",
                    "type": "about:blank",
                    "status": 429
                }))
                .insert_header("retry-after", "1"),
        )
        .mount(&mock_server)
        .await;

    let mut connector = TwitterConnector::new();
    // Use max_attempts=0 in retry config to avoid retrying the 429
    connector
        .handle_configure(json!({
            "consumer_key": "test-ck",
            "consumer_secret": "test-cs",
            "access_token": "test-at",
            "access_token_secret": "test-ats",
            "bearer_token": "test-bt",
            "api_url": mock_server.uri(),
            "retry": { "max_attempts": 0 }
        }))
        .await
        .expect("configure should succeed");
    let signing_key =
        setup_handshake(&mut connector, &mock_server, &["twitter.tweet.search"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twitter.tweet.search",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "twitter.tweet.search",
            "args": { "query": "test" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

// ============================================================================
// FCP2 default-deny + capability verification
// ============================================================================

#[fcp_async_core::runtime::test]
async fn invoke_without_configure_fails() {
    let _ctx = AsyncTestContext::for_scenario("twitter.deny.not_configured");
    let connector = TwitterConnector::new();

    let signing_key = Ed25519SigningKey::generate();
    let token = generate_valid_token(&signing_key, connector.instance_id(), "twitter.user.me");

    let result = connector
        .handle_invoke(json!({
            "operation": "twitter.user.me",
            "args": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn invoke_with_wrong_capability_denied() {
    let _ctx = AsyncTestContext::for_scenario("twitter.deny.wrong_capability");
    let mock_server = MockServer::start().await;

    let mut connector = TwitterConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    // Handshake grants twitter.tweet.search but we invoke twitter.user.me
    let signing_key =
        setup_handshake(&mut connector, &mock_server, &["twitter.tweet.search"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twitter.tweet.search",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "twitter.user.me",
            "args": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn invoke_unknown_operation_denied() {
    let _ctx = AsyncTestContext::for_scenario("twitter.deny.unknown_operation");
    let mock_server = MockServer::start().await;

    let mut connector = TwitterConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &mock_server, &["twitter.nonexistent"]).await;
    let token = generate_valid_token(&signing_key, connector.instance_id(), "twitter.nonexistent");

    let result = connector
        .handle_invoke(json!({
            "operation": "twitter.nonexistent",
            "args": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

// ============================================================================
// Lifecycle tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn health_not_configured() {
    let _ctx = AsyncTestContext::for_scenario("twitter.lifecycle.health_not_configured");
    let connector = TwitterConnector::new();
    let result = connector
        .handle_health()
        .await
        .expect("health should succeed");
    assert_eq!(result["status"], "not_ready");
}

#[fcp_async_core::runtime::test]
async fn health_configured() {
    let _ctx = AsyncTestContext::for_scenario("twitter.lifecycle.health_configured");
    let mock_server = MockServer::start().await;

    let mut connector = TwitterConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    // Twitter requires handshake (which calls get_me) to become "healthy"
    let _signing_key = setup_handshake(&mut connector, &mock_server, &["twitter.user.me"]).await;
    let result = connector
        .handle_health()
        .await
        .expect("health should succeed");
    assert_eq!(result["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn self_check_ok_with_mock_api() {
    let _ctx = AsyncTestContext::for_scenario("twitter.lifecycle.self_check_ok");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "id": "12345",
                "name": "Test",
                "username": "test"
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = TwitterConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;

    let result = connector
        .handle_self_check()
        .await
        .expect("self-check should succeed");
    assert_eq!(result["status"], "ok");
}

#[fcp_async_core::runtime::test]
async fn introspect_lists_all_operations() {
    let _ctx = AsyncTestContext::for_scenario("twitter.lifecycle.introspect");
    let connector = TwitterConnector::new();
    let result = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    let ops = result["operations"].as_array().expect("operations array");
    let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

    assert!(op_ids.contains(&"twitter.user.me"));
    assert!(op_ids.contains(&"twitter.user.get"));
    assert!(op_ids.contains(&"twitter.tweet.get"));
    assert!(op_ids.contains(&"twitter.tweet.get_many"));
    assert!(op_ids.contains(&"twitter.tweet.search"));
    assert!(op_ids.contains(&"twitter.trends.place"));
    assert!(op_ids.contains(&"twitter.tweet.create"));
    assert!(op_ids.contains(&"twitter.tweet.delete"));
    assert!(op_ids.contains(&"twitter.tweet.retweet"));
    assert!(op_ids.contains(&"twitter.tweet.unretweet"));
    assert!(op_ids.contains(&"twitter.tweet.like"));
    assert!(op_ids.contains(&"twitter.tweet.unlike"));
    assert!(op_ids.contains(&"twitter.dm.send"));
    assert!(op_ids.contains(&"twitter.dm.events"));
    assert_eq!(ops.len(), 21);
}

#[fcp_async_core::runtime::test]
async fn shutdown_succeeds() {
    let _ctx = AsyncTestContext::for_scenario("twitter.lifecycle.shutdown");
    let mut connector = TwitterConnector::new();
    let result = connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should succeed");
    assert_eq!(result["status"], "shutdown");
}

// ============================================================================
// Input validation edge cases
// ============================================================================

#[fcp_async_core::runtime::test]
async fn user_get_missing_user_id_fails() {
    let _ctx = AsyncTestContext::for_scenario("twitter.validation.user_get_missing_id");
    let mock_server = MockServer::start().await;

    let mut connector = TwitterConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &mock_server, &["twitter.user.get"]).await;
    let token = generate_valid_token(&signing_key, connector.instance_id(), "twitter.user.get");

    let result = connector
        .handle_invoke(json!({
            "operation": "twitter.user.get",
            "args": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("user_id"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn tweet_search_missing_query_fails() {
    let _ctx = AsyncTestContext::for_scenario("twitter.validation.tweet_search_missing_query");
    let mock_server = MockServer::start().await;

    let mut connector = TwitterConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &mock_server, &["twitter.tweet.search"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twitter.tweet.search",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "twitter.tweet.search",
            "args": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("query"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn trends_place_missing_woeid_fails() {
    let _ctx = AsyncTestContext::for_scenario("twitter.validation.trends_place_missing_woeid");
    let mock_server = MockServer::start().await;

    let mut connector = TwitterConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &mock_server, &["twitter.trends.place"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twitter.trends.place",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "twitter.trends.place",
            "args": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("woeid"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

// ============================================================================
// Read operation tests — tweet.get_many, user.by_username, user.timeline, user.mentions
// ============================================================================

#[fcp_async_core::runtime::test]
async fn tweet_get_many_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twitter.tweet.get_many.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/2/tweets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                { "id": "111", "text": "First tweet" },
                { "id": "222", "text": "Second tweet" }
            ],
            "meta": { "result_count": 2 }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = TwitterConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &mock_server, &["twitter.tweet.get_many"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twitter.tweet.get_many",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "twitter.tweet.get_many",
            "args": { "tweet_ids": ["111", "222"] },
            "capability_token": token
        }))
        .await
        .expect("tweet.get_many invoke should succeed");

    let tweets = result["tweets"].as_array().expect("tweets array");
    assert_eq!(tweets.len(), 2);
    assert_eq!(tweets[0]["id"], "111");
    assert_eq!(tweets[1]["text"], "Second tweet");
}

#[fcp_async_core::runtime::test]
async fn tweet_get_many_missing_tweet_ids_fails() {
    let _ctx = AsyncTestContext::for_scenario("twitter.validation.tweet_get_many_missing_ids");
    let mock_server = MockServer::start().await;

    let mut connector = TwitterConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &mock_server, &["twitter.tweet.get_many"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twitter.tweet.get_many",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "twitter.tweet.get_many",
            "args": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("tweet_ids"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn tweet_get_many_empty_ids_fails() {
    let _ctx = AsyncTestContext::for_scenario("twitter.validation.tweet_get_many_empty");
    let mock_server = MockServer::start().await;

    let mut connector = TwitterConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &mock_server, &["twitter.tweet.get_many"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twitter.tweet.get_many",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "twitter.tweet.get_many",
            "args": { "tweet_ids": [] },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("empty"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn user_mentions_uses_authenticated_user_by_default() {
    let _ctx = AsyncTestContext::for_scenario("twitter.user.mentions.default_user");
    let mock_server = MockServer::start().await;

    // Mentions endpoint for the authenticated user (id=12345 from handshake mock)
    Mock::given(method("GET"))
        .and(path("/2/users/12345/mentions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                { "id": "777", "text": "@test_bot_fcp hey!" }
            ],
            "meta": { "result_count": 1 }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = TwitterConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &mock_server, &["twitter.user.mentions"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twitter.user.mentions",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "twitter.user.mentions",
            "args": {},
            "capability_token": token
        }))
        .await
        .expect("user.mentions invoke should succeed with default user");

    let tweets = result["tweets"].as_array().expect("tweets array");
    assert_eq!(tweets.len(), 1);
    assert_eq!(tweets[0]["id"], "777");
}

#[fcp_async_core::runtime::test]
async fn introspect_read_ops_are_safe() {
    let _ctx = AsyncTestContext::for_scenario("twitter.introspect.read_ops_safe");
    let connector = TwitterConnector::new();
    let result = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    let ops = result["operations"].as_array().expect("operations array");
    let read_ops = [
        "twitter.user.me",
        "twitter.user.get",
        "twitter.user.by_username",
        "twitter.tweet.get",
        "twitter.tweet.get_many",
        "twitter.tweet.search",
        "twitter.user.timeline",
        "twitter.user.mentions",
        "twitter.trends.place",
    ];

    for op_id in &read_ops {
        let op = ops
            .iter()
            .find(|o| o["id"].as_str() == Some(op_id))
            .unwrap_or_else(|| panic!("missing operation {op_id}"));
        assert_eq!(op["risk_level"], "low", "{op_id} should be low risk");
        assert_eq!(op["safety_tier"], "safe", "{op_id} should be safe tier");
    }
}

#[fcp_async_core::runtime::test]
async fn introspect_write_ops_are_high_risk() {
    let _ctx = AsyncTestContext::for_scenario("twitter.introspect.write_ops_risk");
    let connector = TwitterConnector::new();
    let result = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    let ops = result["operations"].as_array().expect("operations array");
    let write_ops = [
        "twitter.tweet.create",
        "twitter.tweet.reply",
        "twitter.tweet.delete",
        "twitter.tweet.retweet",
    ];

    for op_id in &write_ops {
        let op = ops
            .iter()
            .find(|o| o["id"].as_str() == Some(op_id))
            .unwrap_or_else(|| panic!("missing operation {op_id}"));
        assert_eq!(op["risk_level"], "high", "{op_id} should be high risk");
    }
}

// ============================================================================
// Write operation tests — retweet, unretweet, like, unlike, DM
// ============================================================================

#[fcp_async_core::runtime::test]
async fn tweet_retweet_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twitter.tweet.retweet.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/2/users/12345/retweets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "retweeted": true }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = TwitterConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &mock_server, &["twitter.tweet.retweet"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twitter.tweet.retweet",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "twitter.tweet.retweet",
            "args": { "tweet_id": "999" },
            "capability_token": token
        }))
        .await
        .expect("retweet should succeed");

    assert_eq!(result["retweeted"], true);
}

#[fcp_async_core::runtime::test]
async fn tweet_unretweet_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twitter.tweet.unretweet.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/2/users/12345/retweets/999"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "retweeted": false }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = TwitterConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &mock_server, &["twitter.tweet.unretweet"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twitter.tweet.unretweet",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "twitter.tweet.unretweet",
            "args": { "tweet_id": "999" },
            "capability_token": token
        }))
        .await
        .expect("unretweet should succeed");

    assert_eq!(result["retweeted"], false);
}

#[fcp_async_core::runtime::test]
async fn tweet_like_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twitter.tweet.like.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/2/users/12345/likes"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "liked": true }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = TwitterConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &mock_server, &["twitter.tweet.like"]).await;
    let token = generate_valid_token(&signing_key, connector.instance_id(), "twitter.tweet.like");

    let result = connector
        .handle_invoke(json!({
            "operation": "twitter.tweet.like",
            "args": { "tweet_id": "888" },
            "capability_token": token
        }))
        .await
        .expect("like should succeed");

    assert_eq!(result["liked"], true);
}

#[fcp_async_core::runtime::test]
async fn tweet_unlike_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twitter.tweet.unlike.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/2/users/12345/likes/888"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "liked": false }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = TwitterConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &mock_server, &["twitter.tweet.unlike"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twitter.tweet.unlike",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "twitter.tweet.unlike",
            "args": { "tweet_id": "888" },
            "capability_token": token
        }))
        .await
        .expect("unlike should succeed");

    assert_eq!(result["liked"], false);
}

#[fcp_async_core::runtime::test]
async fn dm_send_to_existing_conversation() {
    let _ctx = AsyncTestContext::for_scenario("twitter.dm.send.existing_conversation");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/2/dm_conversations/1234567890/messages"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "data": {
                "dm_conversation_id": "1234567890",
                "dm_event_id": "evt-456"
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = TwitterConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &mock_server, &["twitter.dm.send"]).await;
    let token = generate_valid_token(&signing_key, connector.instance_id(), "twitter.dm.send");

    let result = connector
        .handle_invoke(json!({
            "operation": "twitter.dm.send",
            "args": { "conversation_id": "1234567890", "text": "Hello via FCP!" },
            "capability_token": token
        }))
        .await
        .expect("dm.send should succeed");

    assert_eq!(result["dm_conversation_id"], "1234567890");
    assert_eq!(result["dm_event_id"], "evt-456");
}

#[fcp_async_core::runtime::test]
async fn dm_send_missing_target_fails() {
    let _ctx = AsyncTestContext::for_scenario("twitter.validation.dm_send_missing_target");
    let mock_server = MockServer::start().await;

    let mut connector = TwitterConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &mock_server, &["twitter.dm.send"]).await;
    let token = generate_valid_token(&signing_key, connector.instance_id(), "twitter.dm.send");

    let result = connector
        .handle_invoke(json!({
            "operation": "twitter.dm.send",
            "args": { "text": "Hello!" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("conversation_id"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn dm_events_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twitter.dm.events.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/2/dm_conversations/1234567890/dm_events"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {
                    "id": "evt-1",
                    "event_type": "MessageCreate",
                    "text": "Hey!",
                    "sender_id": "12345"
                }
            ],
            "meta": { "result_count": 1 }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = TwitterConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &mock_server, &["twitter.dm.events"]).await;
    let token = generate_valid_token(&signing_key, connector.instance_id(), "twitter.dm.events");

    let result = connector
        .handle_invoke(json!({
            "operation": "twitter.dm.events",
            "args": { "conversation_id": "1234567890" },
            "capability_token": token
        }))
        .await
        .expect("dm.events should succeed");

    let events = result["events"].as_array().expect("events array");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["text"], "Hey!");
}

#[fcp_async_core::runtime::test]
async fn retweet_missing_tweet_id_fails() {
    let _ctx = AsyncTestContext::for_scenario("twitter.validation.retweet_missing_id");
    let mock_server = MockServer::start().await;

    let mut connector = TwitterConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &mock_server, &["twitter.tweet.retweet"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twitter.tweet.retweet",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "twitter.tweet.retweet",
            "args": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("tweet_id"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn introspect_dm_ops_are_dangerous_or_risky() {
    let _ctx = AsyncTestContext::for_scenario("twitter.introspect.dm_ops_risk");
    let connector = TwitterConnector::new();
    let result = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    let ops = result["operations"].as_array().expect("operations array");

    let dm_send = ops.iter().find(|o| o["id"] == "twitter.dm.send").unwrap();
    assert_eq!(dm_send["safety_tier"], "dangerous");
    assert_eq!(dm_send["risk_level"], "high");

    let dm_events = ops.iter().find(|o| o["id"] == "twitter.dm.events").unwrap();
    assert_eq!(dm_events["safety_tier"], "risky");
    assert_eq!(dm_events["risk_level"], "medium");
}

// ============================================================================
// Replay safety on retry (br-kxd3e)
// ============================================================================
//
// `request_oauth` classified a transport failure with `is_timeout() ||
// is_connect()`, which is the exact anti-pattern the bead names: the total
// request timeout fires AFTER the body was fully written, so it is not proof
// the request never arrived. X has no idempotency key, so retrying a tweet or
// DM after a 5xx posts it twice.
//
// The assertion is the REQUEST COUNT — "it still errors" would pass with the
// bug present.

/// Same as `setup_configure` but with a fast, non-zero retry budget so the
/// retry behaviour is actually observable.
async fn setup_configure_with_retries(connector: &mut TwitterConnector, base_url: &str) {
    connector
        .handle_configure(json!({
            "consumer_key": "test-ck",
            "consumer_secret": "test-cs",
            "access_token": "test-at",
            "access_token_secret": "test-ats",
            "bearer_token": "test-bt",
            "api_url": base_url,
            "retry": {
                "max_attempts": 3,
                "initial_delay_ms": 1,
                "max_delay_ms": 5
            }
        }))
        .await
        .expect("configure should succeed");
}

async fn count_posts_to(mock_server: &MockServer, suffix: &str) -> usize {
    mock_server
        .received_requests()
        .await
        .expect("recorded requests")
        .iter()
        .filter(|r| r.method == wiremock::http::Method::POST && r.url.path().ends_with(suffix))
        .count()
}

#[fcp_async_core::runtime::test]
async fn tweet_create_is_not_retried_after_a_5xx() {
    let _ctx = AsyncTestContext::for_scenario("twitter.tweet.create.replay_safety");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/2/tweets"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&mock_server)
        .await;

    let mut connector = TwitterConnector::new();
    setup_configure_with_retries(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &mock_server, &["twitter.tweet.create"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twitter.tweet.create",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "twitter.tweet.create",
            "args": { "text": "Hello world from FCP!" },
            "capability_token": token
        }))
        .await;
    assert!(result.is_err(), "the 503 should surface as a failure");

    assert_eq!(
        count_posts_to(&mock_server, "/2/tweets").await,
        1,
        "a 503 means X received the tweet — retrying posts it a SECOND time, \
         and X offers no idempotency key to prevent that"
    );
}

#[fcp_async_core::runtime::test]
async fn retweet_is_still_retried_after_a_5xx() {
    let _ctx = AsyncTestContext::for_scenario("twitter.tweet.retweet.replay_safety");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/2/users/12345/retweets"))
        .respond_with(ResponseTemplate::new(500))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/2/users/12345/retweets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "retweeted": true }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = TwitterConnector::new();
    setup_configure_with_retries(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &mock_server, &["twitter.tweet.retweet"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twitter.tweet.retweet",
    );

    connector
        .handle_invoke(json!({
            "operation": "twitter.tweet.retweet",
            "args": { "user_id": "12345", "tweet_id": "67890" },
            "capability_token": token
        }))
        .await
        .expect("retweet should retry and then succeed");

    assert_eq!(
        count_posts_to(&mock_server, "/retweets").await,
        2,
        "retweeting an already-retweeted post leaves ONE retweet, so the retry \
         is safe and must be preserved"
    );
}
