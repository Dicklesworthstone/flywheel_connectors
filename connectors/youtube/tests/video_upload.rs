//! Real upload wire contract, authorization, bounds, and uncertain mutations.

use base64::Engine as _;
use chrono::{Duration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_google_discovery::auth::{GoogleAuthSourceKind, GoogleMaterializedAuth};
use fcp_prelude::{
    CapabilityConstraints, ConnectorId, OperationId, SimulateRequest, SimulateResponse,
};
use fcp_youtube::{
    client::{YouTubeAuth, YouTubeClient},
    connector::YouTubeConnector,
    error::YouTubeError,
};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path, query_param},
};

fn video_response() -> Value {
    json!({
        "id": "video_12345",
        "snippet": {"title": "Demo 雪"},
        "status": {"privacyStatus": "private", "uploadStatus": "uploaded"},
    })
}

fn oauth_client(server: &MockServer) -> YouTubeClient {
    YouTubeClient::new_with_auth(YouTubeAuth::GoogleShared(
        GoogleMaterializedAuth::BearerToken {
            access_token: "fixture-oauth-token".into(),
            source: GoogleAuthSourceKind::AccessToken,
            granted_scopes: Vec::new(),
            quota_project_id: None,
        },
    ))
    .unwrap()
    .with_base_url(&format!("{}/youtube/v3", server.uri()))
}

async fn handshake(connector: &mut YouTubeConnector) -> Ed25519SigningKey {
    let key = Ed25519SigningKey::generate();
    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0", "zone": "z:work",
            "host_public_key": key.verifying_key().to_bytes(),
            "nonce": vec![0_u8; 32],
            "capabilities_requested": ["youtube.read", "youtube.write"],
        }))
        .await
        .unwrap();
    key
}

fn token(
    key: &Ed25519SigningKey,
    connector: &YouTubeConnector,
    capability: &str,
) -> fcp_core::CapabilityToken {
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).unwrap();
    let now = Utc::now();
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&["youtube.upload_video"])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .target_instance(connector.instance_id())
        .try_constraints_cbor(&cbor)
        .unwrap()
        .sign(key)
        .unwrap();
    fcp_core::CapabilityToken::from_raw(cose)
}

#[fcp_async_core::runtime::test]
async fn authorized_invocation_sends_real_binary_multipart_with_oauth_or_credential_reference() {
    for credential_mode in [false, true] {
        let server = MockServer::start().await;
        let prefix = if credential_mode {
            "/fixture/youtube/v3"
        } else {
            "/youtube/v3"
        };
        Mock::given(method("POST"))
            .and(path(format!("/upload{prefix}/videos")))
            .and(query_param("part", "snippet,status"))
            .and(query_param("uploadType", "multipart"))
            .respond_with(ResponseTemplate::new(200).set_body_json(video_response()))
            .expect(1)
            .mount(&server)
            .await;
        let credential_id = fcp_core::CredentialId::new();
        let mut config = json!({"base_url": format!("{}{prefix}", server.uri())});
        if credential_mode {
            config["credential_id"] = json!(credential_id.to_string());
        } else {
            config["access_token"] = json!("fixture-oauth-token");
        }
        let mut connector = YouTubeConnector::new();
        connector.handle_configure(config).await.unwrap();
        let key = handshake(&mut connector).await;
        let media = [0_u8, 255, 128, 13, 10, b'-', b'-', 0, b'x'];
        let input = json!({
            "title": "Demo 雪", "description": "A short demo",
            "video_data_base64": base64::engine::general_purpose::STANDARD.encode(media),
            "tags": ["demo", "雪"],
        });
        let denied = connector
            .handle_invoke(json!({
                "operation": "youtube.upload_video", "input": input,
                "capability_token": token(&key, &connector, "youtube.read"),
            }))
            .await
            .unwrap_err();
        assert!(matches!(
            denied,
            fcp_core::FcpError::OperationNotGranted { .. }
                | fcp_core::FcpError::CapabilityDenied { .. }
        ));
        assert!(server.received_requests().await.unwrap().is_empty());
        let output = connector
            .handle_invoke(json!({
                "operation": "youtube.upload_video", "input": input,
                "capability_token": token(&key, &connector, "youtube.write"),
            }))
            .await
            .unwrap();
        assert_eq!(
            output,
            json!({
                "videoId": "video_12345", "title": "Demo 雪",
                "privacyStatus": "private", "uploadStatus": "uploaded",
            })
        );
        let requests = server.received_requests().await.unwrap();
        let request = &requests[0];
        assert_eq!(requests.len(), 1);
        assert!(!request.url.query_pairs().any(|(key, _)| key == "key"));
        assert_eq!(
            request
                .url
                .query_pairs()
                .filter(|(key, _)| key == "uploadType")
                .count(),
            1
        );
        if credential_mode {
            assert_eq!(
                request.headers["x-fcp-credential-id"].to_str().unwrap(),
                credential_id.to_string()
            );
            assert!(!request.headers.contains_key("authorization"));
        } else {
            assert_eq!(
                request.headers["authorization"].to_str().unwrap(),
                "Bearer fixture-oauth-token"
            );
            assert!(!request.headers.contains_key("x-fcp-credential-id"));
        }
        assert_eq!(
            request.headers["content-length"]
                .to_str()
                .unwrap()
                .parse::<usize>()
                .unwrap(),
            request.body.len()
        );
        let boundary = request.headers["content-type"]
            .to_str()
            .unwrap()
            .strip_prefix("multipart/related; boundary=")
            .unwrap();
        let metadata_header =
            format!("--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n");
        let media_header =
            format!("\r\n--{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n");
        let closing = format!("\r\n--{boundary}--\r\n");
        assert!(request.body.starts_with(metadata_header.as_bytes()));
        assert!(request.body.ends_with(closing.as_bytes()));
        let media_start = request
            .body
            .windows(media_header.len())
            .position(|part| part == media_header.as_bytes())
            .unwrap();
        let metadata: Value =
            serde_json::from_slice(&request.body[metadata_header.len()..media_start]).unwrap();
        assert_eq!(
            metadata["snippet"],
            json!({"title":"Demo 雪", "description":"A short demo", "tags":["demo","雪"], "categoryId":"22"})
        );
        assert_eq!(metadata["status"], json!({"privacyStatus":"private"}));
        assert_eq!(
            &request.body[media_start + media_header.len()..request.body.len() - closing.len()],
            media
        );
    }
}

#[fcp_async_core::runtime::test]
async fn invalid_upload_inputs_and_api_key_mode_fail_before_http() {
    let server = MockServer::start().await;
    let mut connector = YouTubeConnector::new();
    connector
        .handle_configure(json!({"access_token":"token", "base_url":server.uri()}))
        .await
        .unwrap();
    let key = handshake(&mut connector).await;
    let base = json!({"title":"Title", "description":"", "video_data_base64":"AA=="});
    for (field, value) in [
        ("video_data_base64", json!("not base64")),
        ("video_data_base64", json!("")),
        ("privacy", json!("friends")),
        ("privacy", json!(false)),
        ("tags", json!(["valid", 1])),
        ("tags", Value::Null),
        ("category_id", json!(22)),
        ("title", json!(" ")),
        ("description", json!("x".repeat(5001))),
    ] {
        let mut input = base.clone();
        input[field] = value;
        let error = connector
            .handle_invoke(json!({
                "operation":"youtube.upload_video", "input":input,
                "capability_token":token(&key, &connector, "youtube.write"),
            }))
            .await
            .unwrap_err();
        assert!(
            matches!(error, fcp_core::FcpError::InvalidRequest { .. }),
            "{field}: {error:?}"
        );
    }
    connector
        .handle_configure(json!({"api_key":"private-api-key", "base_url":server.uri()}))
        .await
        .unwrap();
    let key = handshake(&mut connector).await;
    let error = connector
        .handle_invoke(json!({
            "operation":"youtube.upload_video", "input":base,
            "capability_token":token(&key, &connector, "youtube.write"),
        }))
        .await
        .unwrap_err();
    assert!(matches!(error, fcp_core::FcpError::Unauthorized { .. }));
    assert!(!error.to_string().contains("private-api-key"));
    let request = SimulateRequest::new(
        ConnectorId::from_static("youtube"),
        OperationId::from_static("youtube.upload_video"),
        fcp_core::ZoneId::work(),
        base,
        token(&key, &connector, "youtube.write"),
    );
    let response: SimulateResponse = serde_json::from_value(
        connector
            .handle_simulate(serde_json::to_value(request).unwrap())
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(!response.would_succeed);
    assert_eq!(response.denial_code, Some(error.error_code()));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn uncertain_upload_completion_is_nonretryable_and_never_fabricates_success() {
    let mut missing_status = video_response();
    missing_status["status"]
        .as_object_mut()
        .unwrap()
        .remove("uploadStatus");
    let mut blank_id = video_response();
    blank_id["id"] = json!(" ");
    let mut empty_id = video_response();
    empty_id["id"] = json!("");
    let responses = [
        ResponseTemplate::new(503)
            .set_body_json(json!({"error":{"code":503,"message":"temporarily unavailable"}})),
        ResponseTemplate::new(200).set_body_json(json!({})),
        ResponseTemplate::new(200).set_body_json(blank_id),
        ResponseTemplate::new(200).set_body_json(empty_id),
        ResponseTemplate::new(200).set_body_json(missing_status),
        ResponseTemplate::new(200).set_body_string("not JSON"),
        ResponseTemplate::new(204),
        ResponseTemplate::new(200).set_body_string("x".repeat(10 * 1024 * 1024 + 1)),
    ];
    for response in responses {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/upload/youtube/v3/videos"))
            .respond_with(response)
            .expect(1)
            .mount(&server)
            .await;
        let error = oauth_client(&server)
            .with_retry_config(2)
            .upload_video("Title", "", "private", "AA==", None, None)
            .await
            .unwrap_err();
        assert!(matches!(error, YouTubeError::UploadOutcomeUnknown { .. }));
        assert!(!error.is_retryable());
        assert!(matches!(
            error.to_fcp_error(),
            fcp_core::FcpError::External {
                retryable: false,
                ..
            }
        ));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}

#[fcp_async_core::runtime::test]
async fn explicit_rate_limit_retries_the_same_video_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/upload/youtube/v3/videos"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "0")
                .set_body_json(json!({"error":{"code":429,"message":"rate limited"}})),
        )
        .up_to_n_times(1)
        .expect(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/upload/youtube/v3/videos"))
        .respond_with(ResponseTemplate::new(200).set_body_json(video_response()))
        .expect(1)
        .with_priority(2)
        .mount(&server)
        .await;
    let result = oauth_client(&server)
        .with_retry_config(1)
        .upload_video("Title", "", "private", "AA==", None, None)
        .await
        .unwrap();
    assert_eq!(result.video_id, "video_12345");
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].url, requests[1].url);
    assert_eq!(requests[0].body, requests[1].body);
}

#[fcp_async_core::runtime::test]
async fn cancellation_after_dispatch_reports_unknown_without_replaying() {
    let server = MockServer::start().await;
    let client = std::sync::Arc::new(oauth_client(&server).with_retry_config(2));
    let client_on_request = std::sync::Arc::clone(&client);
    Mock::given(method("POST"))
        .and(path("/upload/youtube/v3/videos"))
        .respond_with(move |_request: &wiremock::Request| {
            client_on_request.shutdown();
            ResponseTemplate::new(200)
                .set_body_json(video_response())
                .set_delay(std::time::Duration::from_secs(1))
        })
        .expect(1)
        .mount(&server)
        .await;
    let error = client
        .upload_video("Title", "", "private", "AA==", None, None)
        .await
        .unwrap_err();
    assert!(matches!(error, YouTubeError::UploadOutcomeUnknown { .. }));
    assert!(!error.is_retryable());
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn upload_refuses_redirects_without_forwarding_credentials_or_video() {
    let server = MockServer::start().await;
    let target = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/upload/youtube/v3/videos"))
        .respond_with(
            ResponseTemplate::new(307)
                .insert_header("location", format!("{}/stolen", target.uri())),
        )
        .expect(1)
        .mount(&server)
        .await;
    assert!(
        oauth_client(&server)
            .upload_video("Title", "", "private", "AA==", None, None)
            .await
            .is_err()
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
    assert!(target.received_requests().await.unwrap().is_empty());
}
