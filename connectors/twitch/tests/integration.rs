#![allow(clippy::panic_in_result_fn, clippy::too_many_lines)]

use chrono::{Duration, Utc};
use fcp_crypto::{CapabilityTokenBuilder, Ed25519SigningKey};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector, FcpError,
    HandshakeRequest, InstanceId, InvokeRequest, OperationId, RequestId, ShutdownRequest, ZoneId,
};
use fcp_sdk::migration::HttpRetryConfig;
use fcp_twitch::{TwitchConnector, client::TwitchClient, error::TwitchError};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_string_contains, header, method, path, query_param},
};

const CLIENT_ID: &str = "test-client";
const CLIENT_SECRET: &str = "test-secret";
const ACCESS_TOKEN: &str = "fixture-token";
const CONNECTOR_ID: &str = "fcp.twitch";
const READ_CAPABILITY: &str = "twitch.read";
const ZONE: &str = "z:private";

#[fcp_async_core::runtime::test]
async fn client_acquire_token_success() -> Result<(), String> {
    let server = MockServer::start().await;
    mount_token(&server).await;

    let mut client = loopback_client(&server, CLIENT_ID, CLIENT_SECRET)?;

    client
        .acquire_token()
        .await
        .map_err(|error| format!("token acquisition should succeed: {error}"))?;
    assert!(client.has_token());
    Ok(())
}

#[fcp_async_core::runtime::test]
async fn client_acquire_token_failure() -> Result<(), String> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(ResponseTemplate::new(400).set_body_string("invalid_client"))
        .mount(&server)
        .await;

    let mut client = loopback_client(&server, "bad-id", "bad-secret")?;

    let error = client
        .acquire_token()
        .await
        .expect_err("invalid client credentials should fail token acquisition");
    assert!(matches!(error, TwitchError::TokenError(_)));
    Ok(())
}

#[fcp_async_core::runtime::test]
async fn client_validate_token_success() -> Result<(), String> {
    let server = MockServer::start().await;
    mount_token(&server).await;
    mount_validate(&server).await;

    let mut client = loopback_client(&server, CLIENT_ID, CLIENT_SECRET)?;
    client
        .acquire_token()
        .await
        .map_err(|error| format!("token acquisition should succeed: {error}"))?;

    let validated = client
        .validate_token()
        .await
        .map_err(|error| format!("token validation should succeed: {error}"))?;
    assert_eq!(validated.client_id, CLIENT_ID);
    assert_eq!(validated.expires_in, 3600);
    Ok(())
}

#[fcp_async_core::runtime::test]
async fn client_health_check_success() -> Result<(), String> {
    let server = MockServer::start().await;
    mount_token(&server).await;
    mount_validate(&server).await;
    mount_health_probe(&server).await;

    let mut client = loopback_client(&server, CLIENT_ID, CLIENT_SECRET)?;
    client
        .acquire_token()
        .await
        .map_err(|error| format!("token acquisition should succeed: {error}"))?;

    let validated = client
        .health_check()
        .await
        .map_err(|error| format!("health check should succeed: {error}"))?;
    assert_eq!(validated.client_id, CLIENT_ID);
    Ok(())
}

#[fcp_async_core::runtime::test]
async fn client_health_check_401() -> Result<(), String> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "bad-token",
            "expires_in": 3600,
            "token_type": "bearer"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/oauth2/validate"))
        .and(header("authorization", "Bearer bad-token"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let mut client = loopback_client(&server, CLIENT_ID, CLIENT_SECRET)?;
    client
        .acquire_token()
        .await
        .map_err(|error| format!("token acquisition should succeed: {error}"))?;

    let error = client
        .health_check()
        .await
        .expect_err("unauthorized validation should fail health check");
    assert!(matches!(error, TwitchError::Unauthorized(_)));
    Ok(())
}

#[fcp_async_core::runtime::test]
async fn configure_handshake_health_and_shutdown_lifecycle() -> Result<(), String> {
    let server = MockServer::start().await;
    mount_token(&server).await;

    let mut connector = configured_connector(&server).await?;
    let signing_key = handshake(&mut connector).await?;

    let health = connector.health().await;
    assert!(
        health.is_ready(),
        "configured connector should report ready health"
    );

    let introspection = connector.introspect();
    assert_eq!(introspection.operations.len(), 7);
    assert!(introspection.event_caps.is_some_and(|caps| !caps.streaming));

    let token = capability_token(
        &signing_key,
        "twitch.health",
        connector.instance_id(),
        READ_CAPABILITY,
        ZONE,
    )?;
    mount_validate(&server).await;
    mount_health_probe(&server).await;

    let response = connector
        .invoke(invoke_request("twitch.health", json!({}), token))
        .await
        .map_err(|error| format!("health invoke should succeed: {error}"))?;
    let result = response
        .result
        .ok_or("health response should include result")?;
    assert_eq!(result["status"], "ok");
    assert_eq!(result["api_reachable"], true);
    assert_eq!(result["token_valid"], true);

    connector
        .shutdown(ShutdownRequest {
            r#type: "shutdown".into(),
            deadline_ms: 1_000,
            drain: true,
            reason: Some("test complete".into()),
        })
        .await
        .map_err(|error| format!("shutdown should succeed: {error}"))?;

    Ok(())
}

#[fcp_async_core::runtime::test]
async fn streams_clips_and_games_use_helix_loopback_fixtures() -> Result<(), String> {
    let server = MockServer::start().await;
    mount_token(&server).await;
    mount_streams_list(&server).await;
    mount_clips_list(&server).await;
    mount_games_list(&server).await;

    let mut connector = configured_connector(&server).await?;
    let signing_key = handshake(&mut connector).await?;

    let streams = invoke_result(
        &connector,
        &signing_key,
        "twitch.streams.list",
        json!({"game_id": "509658", "user_login": "fixture_login", "first": 2}),
    )
    .await?;
    assert_eq!(streams["count"], 1);
    assert_eq!(streams["streams"][0]["user_login"], "fixture_login");
    assert_eq!(streams["streams"][0]["title"], "Fixture stream");
    assert_eq!(streams["streams"][0]["viewer_count"], 42);

    let clips = invoke_result(
        &connector,
        &signing_key,
        "twitch.clips.list",
        json!({"broadcaster_id": "12345", "first": 2}),
    )
    .await?;
    assert_eq!(clips["count"], 1);
    assert_eq!(clips["clips"][0]["id"], "clip-1");
    assert_eq!(clips["clips"][0]["duration"], 12.5);

    let games = invoke_result(
        &connector,
        &signing_key,
        "twitch.games.list",
        json!({"name": "Just Chatting"}),
    )
    .await?;
    assert_eq!(games["count"], 1);
    assert_eq!(games["games"][0]["id"], "509658");

    Ok(())
}

#[fcp_async_core::runtime::test]
async fn users_channels_and_stream_lookup_cover_found_and_missing_data() -> Result<(), String> {
    let server = MockServer::start().await;
    mount_token(&server).await;
    mount_user_lookup(&server).await;
    mount_missing_user_lookup(&server).await;
    mount_channel_lookup(&server).await;
    mount_stream_lookup(&server).await;

    let mut connector = configured_connector(&server).await?;
    let signing_key = handshake(&mut connector).await?;

    let user = invoke_result(
        &connector,
        &signing_key,
        "twitch.users.get",
        json!({"login": "fixture_login"}),
    )
    .await?;
    assert_eq!(user["id"], "12345");
    assert_eq!(user["login"], "fixture_login");

    let missing = invoke_result(
        &connector,
        &signing_key,
        "twitch.users.get",
        json!({"login": "missing_user"}),
    )
    .await?;
    assert_eq!(missing["error"], "User not found");

    let channel = invoke_result(
        &connector,
        &signing_key,
        "twitch.channels.get",
        json!({"broadcaster_id": "12345"}),
    )
    .await?;
    assert_eq!(channel["broadcaster_id"], "12345");
    assert_eq!(channel["title"], "Fixture channel");

    let stream = invoke_result(
        &connector,
        &signing_key,
        "twitch.streams.get",
        json!({"user_login": "fixture_login"}),
    )
    .await?;
    assert_eq!(stream["is_live"], true);
    assert_eq!(stream["stream"]["id"], "stream-1");

    Ok(())
}

#[fcp_async_core::runtime::test]
async fn malformed_input_and_capability_denial_fail_closed() -> Result<(), String> {
    let server = MockServer::start().await;
    mount_token(&server).await;

    let mut connector = configured_connector(&server).await?;
    let signing_key = handshake(&mut connector).await?;

    let malformed = connector
        .invoke(invoke_request(
            "twitch.streams.get",
            json!({}),
            capability_token(
                &signing_key,
                "twitch.streams.get",
                connector.instance_id(),
                READ_CAPABILITY,
                ZONE,
            )?,
        ))
        .await
        .expect_err("missing user_login should fail validation");
    assert!(matches!(
        malformed,
        FcpError::InvalidRequest {
            code: 1005,
            message
        } if message.contains("user_login")
    ));

    let wrong_instance = InstanceId::new();
    let instance_denial = connector
        .invoke(invoke_request(
            "twitch.streams.list",
            json!({}),
            capability_token(
                &signing_key,
                "twitch.streams.list",
                &wrong_instance,
                READ_CAPABILITY,
                ZONE,
            )?,
        ))
        .await
        .expect_err("wrong instance token should be denied");
    assert!(matches!(instance_denial, FcpError::ZoneViolation { .. }));

    let zone_denial = connector
        .invoke(invoke_request(
            "twitch.streams.list",
            json!({}),
            capability_token(
                &signing_key,
                "twitch.streams.list",
                connector.instance_id(),
                READ_CAPABILITY,
                "z:work",
            )?,
        ))
        .await
        .expect_err("wrong zone token should be denied");
    assert!(matches!(zone_denial, FcpError::ZoneViolation { .. }));

    let capability_denial = connector
        .invoke(invoke_request(
            "twitch.streams.list",
            json!({}),
            capability_token(
                &signing_key,
                "twitch.streams.list",
                connector.instance_id(),
                "twitch.write",
                ZONE,
            )?,
        ))
        .await
        .expect_err("wrong capability token should be denied");
    assert!(matches!(
        capability_denial,
        FcpError::OperationNotGranted { .. }
    ));

    Ok(())
}

#[fcp_async_core::runtime::test]
async fn helix_error_taxonomy_covers_unauthorized_rate_provider_network_and_timeout()
-> Result<(), String> {
    assert_invoke_error(401, FcpErrorMatcher::Unauthorized).await?;
    assert_invoke_error(429, FcpErrorMatcher::RateLimited).await?;
    assert_invoke_error(503, FcpErrorMatcher::ExternalRetryable).await?;
    assert_network_error().await?;
    assert_timeout_error().await?;
    Ok(())
}

#[test]
fn live_verification_skip_evidence_is_structured_and_redaction_safe() -> Result<(), String> {
    let evidence = evidence_record(
        "skip",
        None,
        Some("TWITCH_CLIENT_ID/TWITCH_CLIENT_SECRET unset"),
    );

    for required in [
        "command_line",
        "git_revision",
        "connector_id",
        "operation_id",
        "capability",
        "zone",
        "instance_id",
        "fixture_id",
        "broadcaster_user_id_hash",
        "lifecycle_phase",
        "latency_ms",
        "result",
        "error_code",
        "retry_decision",
        "audit_receipt_id",
        "cleanup_result",
        "skip_reason",
    ] {
        assert!(evidence.get(required).is_some(), "missing {required}");
    }

    let serialized = serde_json::to_string(&evidence)
        .map_err(|error| format!("evidence should serialize: {error}"))?;
    for forbidden in [
        CLIENT_SECRET,
        ACCESS_TOKEN,
        "FixtureBroadcaster",
        "FixtureCreator",
        "Fixture channel",
        "/Users/",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "evidence leaked forbidden fragment {forbidden:?}: {serialized}"
        );
    }

    Ok(())
}

async fn configured_connector(server: &MockServer) -> Result<TwitchConnector, String> {
    let mut connector = TwitchConnector::new();
    connector
        .configure(json!({
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "base_url": server.uri(),
            "token_url": format!("{}/oauth2/token", server.uri()),
            "validate_url": format!("{}/oauth2/validate", server.uri()),
            "request_timeout_ms": 1_000,
            "retry": {
                "max_retries": 0,
                "initial_delay_ms": 1,
                "max_delay_ms": 1,
                "jitter_enabled": false
            }
        }))
        .await
        .map_err(|error| format!("configure should acquire fixture token: {error}"))?;
    Ok(connector)
}

fn loopback_client(
    server: &MockServer,
    client_id: &str,
    client_secret: &str,
) -> Result<TwitchClient, String> {
    TwitchClient::new(
        &server.uri(),
        &format!("{}/oauth2/token", server.uri()),
        &format!("{}/oauth2/validate", server.uri()),
        client_id,
        client_secret,
        HttpRetryConfig::default(),
        std::time::Duration::from_secs(30),
    )
    .map_err(|error| format!("loopback Twitch client should build: {error}"))
}

async fn handshake(connector: &mut TwitchConnector) -> Result<Ed25519SigningKey, String> {
    let signing_key = Ed25519SigningKey::generate();
    let response = connector
        .handshake(HandshakeRequest {
            protocol_version: "1.0.0".into(),
            zone: ZoneId::private(),
            zone_dir: None,
            host_public_key: signing_key.verifying_key().to_bytes(),
            nonce: [7; 32],
            capabilities_requested: vec![CapabilityId::from_static(READ_CAPABILITY)],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        })
        .await
        .map_err(|error| format!("handshake should succeed: {error}"))?;
    assert_eq!(response.status, "accepted");
    assert_eq!(response.nonce, [7; 32]);
    assert_eq!(response.capabilities_granted.len(), 1);
    Ok(signing_key)
}

fn capability_token(
    signing_key: &Ed25519SigningKey,
    operation: &str,
    instance_id: &InstanceId,
    capability: &str,
    zone: &str,
) -> Result<CapabilityToken, String> {
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor)
        .map_err(|error| format!("constraints should serialize: {error}"))?;

    let now = Utc::now();
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id(zone)
        .principal("user:test")
        .operations(&[operation])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&constraints_cbor)
        .map_err(|error| format!("constraints CBOR should be valid: {error}"))?
        .target_instance(instance_id.as_str())
        .sign(signing_key)
        .map_err(|error| format!("token should sign: {error}"))?;

    Ok(CapabilityToken::from_raw(raw))
}

fn invoke_request(
    operation: &str,
    input: Value,
    capability_token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::random(),
        connector_id: ConnectorId::from_static(CONNECTOR_ID),
        operation: OperationId::new(operation).expect("operation id should be canonical"),
        zone_id: ZoneId::private(),
        input,
        capability_token,
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: Some(1_000),
        correlation_id: None,
        provenance: None,
        approval_tokens: Vec::new(),
    }
}

async fn invoke_result(
    connector: &TwitchConnector,
    signing_key: &Ed25519SigningKey,
    operation: &str,
    input: Value,
) -> Result<Value, String> {
    let token = capability_token(
        signing_key,
        operation,
        connector.instance_id(),
        READ_CAPABILITY,
        ZONE,
    )?;
    let response = connector
        .invoke(invoke_request(operation, input, token))
        .await
        .map_err(|error| format!("{operation} invoke should succeed: {error}"))?;
    response
        .result
        .ok_or_else(|| format!("{operation} response should include result"))
}

async fn assert_invoke_error(status: u16, expected: FcpErrorMatcher) -> Result<(), String> {
    let server = MockServer::start().await;
    mount_token(&server).await;
    Mock::given(method("GET"))
        .and(path("/helix/streams"))
        .respond_with(ResponseTemplate::new(status).set_body_json(json!({
            "status": status,
            "message": "fixture provider failure"
        })))
        .mount(&server)
        .await;

    let mut connector = configured_connector(&server).await?;
    let signing_key = handshake(&mut connector).await?;
    let error = connector
        .invoke(invoke_request(
            "twitch.streams.list",
            json!({}),
            capability_token(
                &signing_key,
                "twitch.streams.list",
                connector.instance_id(),
                READ_CAPABILITY,
                ZONE,
            )?,
        ))
        .await
        .expect_err("provider error should fail invocation");

    expected.assert_matches(&error)
}

async fn assert_network_error() -> Result<(), String> {
    let token_server = MockServer::start().await;
    mount_token(&token_server).await;

    let dead_api_listener = std::net::TcpListener::bind("127.0.0.1:0")
        .map_err(|error| format!("reserve dead API port: {error}"))?;
    let dead_api_url = format!(
        "http://{}",
        dead_api_listener
            .local_addr()
            .map_err(|error| format!("read dead API port: {error}"))?
    );
    drop(dead_api_listener);

    let mut connector = TwitchConnector::new();
    connector
        .configure(json!({
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "base_url": dead_api_url,
            "token_url": format!("{}/oauth2/token", token_server.uri()),
            "validate_url": format!("{}/oauth2/validate", token_server.uri()),
            "request_timeout_ms": 1_000,
            "retry": {
                "max_retries": 0,
                "initial_delay_ms": 1,
                "max_delay_ms": 1,
                "jitter_enabled": false
            }
        }))
        .await
        .map_err(|error| format!("configure should use separate token loopback: {error}"))?;
    let signing_key = handshake(&mut connector).await?;
    let error = connector
        .invoke(invoke_request(
            "twitch.streams.list",
            json!({}),
            capability_token(
                &signing_key,
                "twitch.streams.list",
                connector.instance_id(),
                READ_CAPABILITY,
                ZONE,
            )?,
        ))
        .await
        .expect_err("dead API loopback should fail invocation");

    if !matches!(
        &error,
        FcpError::External {
            service,
            retryable: true,
            ..
        } if service == "twitch"
    ) {
        return Err(format!(
            "network error should map to retryable Twitch external error: {error:?}"
        ));
    }
    Ok(())
}

async fn assert_timeout_error() -> Result<(), String> {
    let server = MockServer::start().await;
    mount_token(&server).await;
    Mock::given(method("GET"))
        .and(path("/helix/streams"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(std::time::Duration::from_millis(1_500))
                .set_body_json(json!({"data": []})),
        )
        .mount(&server)
        .await;

    let mut connector = configured_connector(&server).await?;
    let signing_key = handshake(&mut connector).await?;
    let error = connector
        .invoke(invoke_request(
            "twitch.streams.list",
            json!({}),
            capability_token(
                &signing_key,
                "twitch.streams.list",
                connector.instance_id(),
                READ_CAPABILITY,
                ZONE,
            )?,
        ))
        .await
        .expect_err("slow API response should fail invocation");
    assert!(matches!(
        error,
        FcpError::External {
            service,
            retryable: true,
            ..
        } if service == "twitch"
    ));
    Ok(())
}

async fn mount_token(server: &MockServer) {
    // The OAuth client-credentials params must travel in the form-encoded body,
    // never the URL query string (a secret in the query leaks via reqwest's
    // Error Display). Matching on the body enforces that contract.
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .and(body_string_contains(format!("client_id={CLIENT_ID}")))
        .and(body_string_contains(format!(
            "client_secret={CLIENT_SECRET}"
        )))
        .and(body_string_contains("grant_type=client_credentials"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": ACCESS_TOKEN,
            "expires_in": 3600,
            "token_type": "bearer"
        })))
        .mount(server)
        .await;
}

async fn mount_validate(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/oauth2/validate"))
        .and(header("authorization", format!("Bearer {ACCESS_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "client_id": CLIENT_ID,
            "scopes": ["user:read:email"],
            "expires_in": 3600
        })))
        .mount(server)
        .await;
}

async fn mount_health_probe(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/helix/users"))
        .and(query_param("login", "twitch"))
        .and(header("authorization", format!("Bearer {ACCESS_TOKEN}")))
        .and(header("client-id", CLIENT_ID))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .mount(server)
        .await;
}

async fn mount_streams_list(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/helix/streams"))
        .and(query_param("game_id", "509658"))
        .and(query_param("user_login", "fixture_login"))
        .and(query_param("first", "2"))
        .and(header("authorization", format!("Bearer {ACCESS_TOKEN}")))
        .and(header("client-id", CLIENT_ID))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [stream_fixture()],
            "pagination": {"cursor": "next"}
        })))
        .mount(server)
        .await;
}

async fn mount_stream_lookup(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/helix/streams"))
        .and(query_param("user_login", "fixture_login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": [stream_fixture()]})))
        .mount(server)
        .await;
}

async fn mount_user_lookup(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/helix/users"))
        .and(query_param("login", "fixture_login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{
                "id": "12345",
                "login": "fixture_login",
                "display_name": "FixtureBroadcaster",
                "type": "",
                "broadcaster_type": "partner",
                "description": "fixture user",
                "profile_image_url": "https://static-cdn.jtvnw.net/user.png",
                "offline_image_url": "https://static-cdn.jtvnw.net/offline.png",
                "view_count": 99,
                "created_at": "2026-05-08T01:00:00Z"
            }]
        })))
        .mount(server)
        .await;
}

async fn mount_missing_user_lookup(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/helix/users"))
        .and(query_param("login", "missing_user"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .mount(server)
        .await;
}

async fn mount_channel_lookup(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/helix/channels"))
        .and(query_param("broadcaster_id", "12345"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{
                "broadcaster_id": "12345",
                "broadcaster_login": "fixture_login",
                "broadcaster_name": "FixtureBroadcaster",
                "broadcaster_language": "en",
                "game_name": "Just Chatting",
                "game_id": "509658",
                "title": "Fixture channel",
                "delay": 0,
                "tags": ["English"],
                "content_classification_labels": [],
                "is_branded_content": false
            }]
        })))
        .mount(server)
        .await;
}

async fn mount_clips_list(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/helix/clips"))
        .and(query_param("broadcaster_id", "12345"))
        .and(query_param("first", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{
                "id": "clip-1",
                "url": "https://clips.twitch.tv/clip-1",
                "embed_url": "https://clips.twitch.tv/embed?clip=clip-1",
                "broadcaster_id": "12345",
                "broadcaster_name": "FixtureBroadcaster",
                "creator_id": "98765",
                "creator_name": "FixtureCreator",
                "game_id": "509658",
                "language": "en",
                "title": "Fixture clip",
                "view_count": 7,
                "created_at": "2026-05-08T02:10:00Z",
                "duration": 12.5
            }]
        })))
        .mount(server)
        .await;
}

async fn mount_games_list(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/helix/games"))
        .and(query_param("name", "Just Chatting"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{
                "id": "509658",
                "name": "Just Chatting",
                "box_art_url": "https://static-cdn.jtvnw.net/box_art/{width}x{height}.jpg",
                "igdb_id": "0"
            }]
        })))
        .mount(server)
        .await;
}

fn stream_fixture() -> Value {
    json!({
        "id": "stream-1",
        "user_id": "12345",
        "user_login": "fixture_login",
        "user_name": "FixtureBroadcaster",
        "game_id": "509658",
        "game_name": "Just Chatting",
        "type": "live",
        "title": "Fixture stream",
        "viewer_count": 42,
        "started_at": "2026-05-08T02:00:00Z",
        "language": "en",
        "tags": ["English"],
        "is_mature": false
    })
}

fn evidence_record(result: &str, error_code: Option<&str>, skip_reason: Option<&str>) -> Value {
    json!({
        "command_line": "rch exec -- cargo test -p fcp-twitch --tests -- --nocapture",
        "git_revision": "HEAD",
        "connector_id": CONNECTOR_ID,
        "operation_id": "twitch.health",
        "capability": READ_CAPABILITY,
        "zone": ZONE,
        "instance_id": "inst_redacted_fixture",
        "fixture_id": "twitch-helix-loopback-v1",
        "broadcaster_user_id_hash": user_hash("12345"),
        "lifecycle_phase": "live_verification_gate",
        "latency_ms": 0,
        "result": result,
        "error_code": error_code,
        "retry_decision": "not_attempted",
        "audit_receipt_id": "audit_redacted_fixture",
        "cleanup_result": "not_required",
        "skip_reason": skip_reason
    })
}

fn user_hash(user_id: &str) -> String {
    let digest = Sha256::digest(user_id.as_bytes());
    format!("sha256:{}", hex::encode(&digest[..8]))
}

enum FcpErrorMatcher {
    Unauthorized,
    RateLimited,
    ExternalRetryable,
}

impl FcpErrorMatcher {
    fn assert_matches(&self, error: &FcpError) -> Result<(), String> {
        let matched = match self {
            Self::Unauthorized => matches!(error, FcpError::Unauthorized { .. }),
            Self::RateLimited => matches!(error, FcpError::RateLimited { .. }),
            Self::ExternalRetryable => matches!(
                error,
                FcpError::External {
                    service,
                    status_code: Some(503),
                    retryable: true,
                    ..
                } if service == "twitch"
            ),
        };

        if matched {
            Ok(())
        } else {
            Err(format!("unexpected error for matcher: {error:?}"))
        }
    }
}
