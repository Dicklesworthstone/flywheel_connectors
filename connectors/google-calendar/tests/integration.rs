//! Integration tests for the Google Calendar connector.
//!
//! Covers error taxonomy mapping, credential redaction, client operations
//! (calendars, events CRUD, quick-add), and connector-level invoke routing.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::Utc;
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_google_calendar::{
    client::GoogleCalendarClient, connector::GoogleCalendarConnector, error::GoogleCalendarError,
};
use fcp_prelude::{CapabilityConstraints, CapabilityToken, FcpError, InstanceId};
use serde_json::json;
use wiremock::matchers::{bearer_token, body_json, header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

// ── Helpers ──────────────────────────────────────────────────────────

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    op: &str,
) -> CapabilityToken {
    let cap = match op {
        "gcal.create_event" | "gcal.update_event" | "gcal.quick_add" => "gcal.write",
        "gcal.delete_event" => "gcal.delete",
        _ => "gcal.read",
    };
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
        .target_instance(instance_id.as_str())
        .principal("user:test")
        .operations(&[op])
        .issuer("node:test")
        .validity(now, now + chrono::Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .unwrap()
        .sign(signing_key)
        .unwrap();
    CapabilityToken::from_raw(cose)
}

async fn setup_handshake(
    connector: &mut GoogleCalendarConnector,
    signing_key: &Ed25519SigningKey,
    capabilities: &[&str],
) -> InstanceId {
    let verifying_key = signing_key.verifying_key();
    let instance_id = InstanceId::new();
    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": capabilities,
            "requested_instance_id": instance_id.as_str()
        }))
        .await
        .unwrap();
    instance_id
}

async fn setup_configure(connector: &mut GoogleCalendarConnector, api_url: &str) {
    connector
        .handle_configure(json!({
            "token": "ya29.test-oauth-token",
            "base_url": api_url
        }))
        .await
        .unwrap();
}

fn event_json(id: &str, summary: &str) -> serde_json::Value {
    json!({
        "id": id,
        "summary": summary,
        "status": "confirmed",
        "start": { "dateTime": "2025-06-01T10:00:00Z" },
        "end": { "dateTime": "2025-06-01T11:00:00Z" }
    })
}

// ── Error taxonomy ──────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn error_http_maps_to_external() {
    let err = GoogleCalendarError::Http(
        reqwest::Client::new()
            .get("http://[::ffff:0.0.0.0]:1")
            .send()
            .await
            .unwrap_err(),
    );
    let fcp = err.to_fcp_error();
    assert!(matches!(fcp, FcpError::External { service, .. } if service == "google-calendar"));
    assert!(err.is_retryable());
}

#[fcp_async_core::runtime::test]
async fn error_json_maps_to_internal() {
    let bad: Result<serde_json::Value, _> = serde_json::from_str("not json");
    let err = GoogleCalendarError::Json(bad.unwrap_err());
    let fcp = err.to_fcp_error();
    assert!(matches!(fcp, FcpError::Internal { .. }));
    assert!(!err.is_retryable());
}

#[fcp_async_core::runtime::test]
async fn error_api_auth_maps_to_unauthorized() {
    let err = GoogleCalendarError::Api {
        code: 401,
        message: "Invalid credentials".into(),
    };
    let fcp = err.to_fcp_error();
    assert!(matches!(fcp, FcpError::Unauthorized { .. }));
}

#[fcp_async_core::runtime::test]
async fn error_api_not_found_maps_to_resource_not_found() {
    let err = GoogleCalendarError::Api {
        code: 404,
        message: "Not found".into(),
    };
    let fcp = err.to_fcp_error();
    assert!(matches!(fcp, FcpError::ResourceNotFound { .. }));
}

#[fcp_async_core::runtime::test]
async fn error_api_rate_limited_maps_to_fcp() {
    let err = GoogleCalendarError::Api {
        code: 429,
        message: "Rate limit exceeded".into(),
    };
    let fcp = err.to_fcp_error();
    assert!(matches!(fcp, FcpError::RateLimited { .. }));
    assert!(err.is_retryable());
}

#[fcp_async_core::runtime::test]
async fn error_api_server_error_is_retryable() {
    for code in [500, 502, 503] {
        let err = GoogleCalendarError::Api {
            code,
            message: "Server error".into(),
        };
        assert!(err.is_retryable(), "code {code} should be retryable");
    }
}

#[fcp_async_core::runtime::test]
async fn error_rate_limited_maps_to_fcp_rate_limited() {
    let err = GoogleCalendarError::RateLimited {
        retry_after_secs: 30,
    };
    let fcp = err.to_fcp_error();
    assert!(matches!(
        fcp,
        FcpError::RateLimited {
            retry_after_ms: 30000,
            ..
        }
    ));
    assert!(err.is_retryable());
    assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
}

#[fcp_async_core::runtime::test]
async fn error_unauthorized_maps_to_fcp_unauthorized() {
    let err = GoogleCalendarError::Unauthorized;
    let fcp = err.to_fcp_error();
    assert!(matches!(fcp, FcpError::Unauthorized { .. }));
    assert!(!err.is_retryable());
}

#[fcp_async_core::runtime::test]
async fn error_not_found_variants_map_to_resource_not_found() {
    let event_err = GoogleCalendarError::EventNotFound {
        event_id: "evt123".into(),
    };
    assert!(
        matches!(event_err.to_fcp_error(), FcpError::ResourceNotFound { resource } if resource.contains("evt123"))
    );

    let cal_err = GoogleCalendarError::CalendarNotFound {
        calendar_id: "cal456".into(),
    };
    assert!(
        matches!(cal_err.to_fcp_error(), FcpError::ResourceNotFound { resource } if resource.contains("cal456"))
    );
}

// ── Redaction ───────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn error_display_does_not_leak_token() {
    let err = GoogleCalendarError::Unauthorized;
    let msg = err.to_string();
    assert!(!msg.contains("ya29.test-oauth-token"));
}

#[fcp_async_core::runtime::test]
async fn api_error_display_does_not_leak_token() {
    let err = GoogleCalendarError::Api {
        code: 401,
        message: "Invalid token".into(),
    };
    let msg = err.to_string();
    assert!(!msg.contains("ya29.test-oauth-token"));
}

// ── Client operations ───────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn manifest_and_runtime_publish_sparse_event_update_contract() {
    let manifest = fcp_manifest::ConnectorManifest::parse_str(include_str!("../manifest.toml"))
        .expect("manifest and interface hash must validate");
    let declared = &manifest.provides.operations["gcal.update_event"];
    let connector = GoogleCalendarConnector::new();
    let introspection = connector.handle_introspect().await.unwrap();
    let runtime = introspection["operations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|operation| operation["id"] == "gcal.update_event")
        .unwrap();
    assert_eq!(runtime["idempotency"], "best_effort");
    assert_eq!(
        declared.input_schema["anyOf"],
        runtime["input_schema"]["anyOf"]
    );
    for field in [
        "summary",
        "description",
        "location",
        "start",
        "end",
        "attendees",
    ] {
        assert_eq!(
            declared.input_schema["properties"][field]["type"],
            runtime["input_schema"]["properties"][field]["type"],
            "schema mismatch for {field}"
        );
    }
}

#[fcp_async_core::runtime::test]
async fn manifest_and_runtime_publish_keyed_create_contract() {
    let manifest = fcp_manifest::ConnectorManifest::parse_str(include_str!("../manifest.toml"))
        .expect("manifest and interface hash must validate");
    let declared = &manifest.provides.operations["gcal.create_event"];
    let introspection = GoogleCalendarConnector::new()
        .handle_introspect()
        .await
        .unwrap();
    let runtime = introspection["operations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|operation| operation["id"] == "gcal.create_event")
        .unwrap();
    assert_eq!(runtime["idempotency"], "none");
    assert_eq!(serde_json::to_value(declared.idempotency).unwrap(), "none");
    assert_eq!(
        declared.input_schema["properties"]["event_id"],
        runtime["input_schema"]["properties"]["event_id"]
    );
    assert_eq!(
        declared.input_schema["required"],
        runtime["input_schema"]["required"]
    );
    assert!(
        !declared.input_schema["required"]
            .as_array()
            .unwrap()
            .contains(&json!("event_id"))
    );
    for field in [
        "summary",
        "description",
        "location",
        "start",
        "end",
        "attendees",
    ] {
        assert_eq!(
            declared.input_schema["properties"][field]["type"],
            runtime["input_schema"]["properties"][field]["type"],
            "schema mismatch for {field}"
        );
    }
}

#[fcp_async_core::runtime::test]
async fn client_list_calendars() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/users/me/calendarList"))
        .and(bearer_token("test_tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [
                { "id": "primary", "summary": "Main Calendar" },
                { "id": "work@example.com", "summary": "Work" }
            ]
        })))
        .mount(&server)
        .await;

    let client = GoogleCalendarClient::new("test_tok")
        .unwrap()
        .with_base_url(server.uri());
    let result = client.list_calendars().await.unwrap();
    assert_eq!(result.items.len(), 2);
}

#[fcp_async_core::runtime::test]
async fn client_get_event() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/calendars/primary/events/evt001"))
        .and(bearer_token("test_tok"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(event_json("evt001", "Team standup")),
        )
        .mount(&server)
        .await;

    let client = GoogleCalendarClient::new("test_tok")
        .unwrap()
        .with_base_url(server.uri());
    let event = client.get_event("primary", "evt001").await.unwrap();
    assert_eq!(event.id.as_deref(), Some("evt001"));
}

#[fcp_async_core::runtime::test]
async fn client_list_events() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/calendars/primary/events"))
        .and(bearer_token("test_tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [
                event_json("evt001", "Meeting A"),
                event_json("evt002", "Meeting B")
            ],
            "summary": "Main Calendar"
        })))
        .mount(&server)
        .await;

    let client = GoogleCalendarClient::new("test_tok")
        .unwrap()
        .with_base_url(server.uri());
    let result = client
        .list_events("primary", None, None, None, None)
        .await
        .unwrap();
    assert_eq!(result.items.len(), 2);
}

#[fcp_async_core::runtime::test]
async fn client_create_event() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/calendars/primary/events"))
        .and(bearer_token("test_tok"))
        .and(header("content-type", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(event_json("evtNEW", "New Meeting")))
        .mount(&server)
        .await;

    let client = GoogleCalendarClient::new("test_tok")
        .unwrap()
        .with_base_url(server.uri());
    let mut event: fcp_google_calendar::types::Event =
        serde_json::from_value(event_json("", "New Meeting")).unwrap();
    event.id = None;
    let created = client.create_event("primary", &event).await.unwrap();
    assert_eq!(created.id.as_deref(), Some("evtNEW"));
}

#[fcp_async_core::runtime::test]
async fn client_keyed_create_reuses_payload_and_recovers_committed_event() {
    let server = MockServer::start().await;
    let committed = Arc::new(Mutex::new(None::<serde_json::Value>));
    let post_state = Arc::clone(&committed);
    Mock::given(method("POST"))
        .and(path("/calendars/primary/events"))
        .and(bearer_token("test_tok"))
        .respond_with(move |request: &Request| {
            let mut state = post_state.lock().unwrap();
            if state.is_none() {
                *state = Some(request.body_json::<serde_json::Value>().unwrap());
                // The provider committed the event but its response was lost.
                ResponseTemplate::new(503)
                    .set_body_json(json!({ "error": { "message": "temporary failure" } }))
            } else {
                ResponseTemplate::new(409)
                    .set_body_json(json!({ "error": { "message": "ID already exists" } }))
            }
        })
        .expect(3)
        .mount(&server)
        .await;
    let get_state = Arc::clone(&committed);
    Mock::given(method("GET"))
        .and(path("/calendars/primary/events/abc123"))
        .and(bearer_token("test_tok"))
        .respond_with(move |_: &Request| {
            ResponseTemplate::new(200).set_body_json(get_state.lock().unwrap().as_ref().unwrap())
        })
        .expect(2)
        .mount(&server)
        .await;

    let client = GoogleCalendarClient::new("test_tok")
        .unwrap()
        .with_base_url(server.uri())
        .with_retry_config(2, 1, 1);
    let event = serde_json::from_value(event_json("abc123", "One meeting")).unwrap();
    for _ in 0..2 {
        let created = client.create_event("primary", &event).await.unwrap();
        assert_eq!(created.id.as_deref(), Some("abc123"));
    }

    let requests = server.received_requests().await.unwrap();
    let posts: Vec<_> = requests
        .iter()
        .filter(|request| request.method == "POST")
        .collect();
    assert_eq!(posts.len(), 3);
    assert!(posts.iter().all(|request| request.body == posts[0].body));
    let body = posts[0].body_json::<serde_json::Value>().unwrap();
    let marker = body["extendedProperties"]["private"]["fcpCreateFingerprint"]
        .as_str()
        .unwrap();
    assert_eq!(marker.len(), 64);
    assert!(marker.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(requests.len(), 5);
}

#[fcp_async_core::runtime::test]
async fn client_keyed_create_rejects_same_id_with_different_payload() {
    let server = MockServer::start().await;
    let committed = Arc::new(Mutex::new(None::<serde_json::Value>));
    let post_state = Arc::clone(&committed);
    Mock::given(method("POST"))
        .and(path("/calendars/primary/events"))
        .respond_with(move |request: &Request| {
            let mut state = post_state.lock().unwrap();
            if state.is_none() {
                *state = Some(request.body_json::<serde_json::Value>().unwrap());
                ResponseTemplate::new(200).set_body_json(state.as_ref().unwrap())
            } else {
                ResponseTemplate::new(409)
                    .set_body_json(json!({ "error": { "message": "ID already exists" } }))
            }
        })
        .expect(2)
        .mount(&server)
        .await;
    let get_state = Arc::clone(&committed);
    Mock::given(method("GET"))
        .and(path("/calendars/primary/events/abc123"))
        .respond_with(move |_: &Request| {
            ResponseTemplate::new(200).set_body_json(get_state.lock().unwrap().as_ref().unwrap())
        })
        .expect(1)
        .mount(&server)
        .await;

    let client = GoogleCalendarClient::new("test_tok")
        .unwrap()
        .with_base_url(server.uri())
        .with_retry_config(2, 1, 1);
    let mut event = serde_json::from_value(event_json("abc123", "Original")).unwrap();
    client.create_event("primary", &event).await.unwrap();
    event.summary = Some("Changed".to_owned());
    let error = client.create_event("primary", &event).await.unwrap_err();
    assert!(matches!(
        error,
        GoogleCalendarError::Api { code: 409, ref message } if message == "ID already exists"
    ));
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 3);
    let first = requests[0].body_json::<serde_json::Value>().unwrap();
    let second = requests[1].body_json::<serde_json::Value>().unwrap();
    assert_ne!(first["extendedProperties"], second["extendedProperties"]);
}

#[fcp_async_core::runtime::test]
async fn client_keyed_create_recovery_requires_matching_active_resource() {
    for failure in [
        "missing_marker",
        "wrong_id",
        "cancelled",
        "missing_status",
        "invalid_resource",
        "unavailable",
        "invalid_json",
    ] {
        let server = MockServer::start().await;
        let attempted = Arc::new(Mutex::new(None::<serde_json::Value>));
        let post_state = Arc::clone(&attempted);
        Mock::given(method("POST"))
            .and(path("/calendars/primary/events"))
            .respond_with(move |request: &Request| {
                *post_state.lock().unwrap() =
                    Some(request.body_json::<serde_json::Value>().unwrap());
                ResponseTemplate::new(409)
                    .set_body_json(json!({ "error": { "message": "ID already exists" } }))
            })
            .expect(1)
            .mount(&server)
            .await;
        let get_state = Arc::clone(&attempted);
        Mock::given(method("GET"))
            .and(path("/calendars/primary/events/abc123"))
            .respond_with(move |_: &Request| {
                let mut existing = get_state.lock().unwrap().as_ref().unwrap().clone();
                match failure {
                    "missing_marker" => {
                        existing
                            .as_object_mut()
                            .unwrap()
                            .remove("extendedProperties");
                    }
                    "wrong_id" => existing["id"] = json!("other123"),
                    "cancelled" => existing["status"] = json!("cancelled"),
                    "missing_status" => {
                        existing.as_object_mut().unwrap().remove("status");
                    }
                    "invalid_resource" => existing["attendees"] = json!("invalid"),
                    "unavailable" => return ResponseTemplate::new(404),
                    _ => return ResponseTemplate::new(200).set_body_string("invalid json"),
                }
                ResponseTemplate::new(200).set_body_json(existing)
            })
            .expect(1)
            .mount(&server)
            .await;
        let client = GoogleCalendarClient::new("test_tok")
            .unwrap()
            .with_base_url(server.uri())
            .with_retry_config(0, 1, 1);
        let event = serde_json::from_value(event_json("abc123", "Meeting")).unwrap();
        let error = client.create_event("primary", &event).await.unwrap_err();
        assert!(
            matches!(
                error,
                GoogleCalendarError::Api { code: 409, ref message } if message == "ID already exists"
            ),
            "recovery must preserve the conflict for {failure}"
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }
}

#[fcp_async_core::runtime::test]
async fn client_unkeyed_create_does_not_retry_ambiguous_results() {
    for (status, response_body) in [
        (503, r#"{"error":{"message":"temporary failure"}}"#),
        (200, "invalid json"),
        (200, "{}"),
        (200, r#"{"unrelated":"resource"}"#),
        (200, r#"{"id":""}"#),
        (200, r#"{"id":"   "}"#),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/calendars/primary/events"))
            .respond_with(ResponseTemplate::new(status).set_body_string(response_body))
            .expect(1)
            .mount(&server)
            .await;
        let client = GoogleCalendarClient::new("test_tok")
            .unwrap()
            .with_base_url(server.uri())
            .with_retry_config(3, 1, 1);
        let mut event: fcp_google_calendar::types::Event =
            serde_json::from_value(event_json("", "One meeting")).unwrap();
        event.id = None;
        let error = client.create_event("primary", &event).await.unwrap_err();
        assert!(matches!(error, GoogleCalendarError::AmbiguousWrite { .. }));
        assert!(!error.is_retryable());
        assert!(matches!(
            error.to_fcp_error(),
            FcpError::External {
                retryable: false,
                ..
            }
        ));
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let body = requests[0].body_json::<serde_json::Value>().unwrap();
        assert!(body["id"].is_null());
        assert!(body.get("extendedProperties").is_none());
    }
}

#[fcp_async_core::runtime::test]
async fn client_keyed_create_rejects_success_without_matching_identity() {
    for response_body in [
        "invalid json",
        "{}",
        r#"{"unrelated":"resource"}"#,
        r#"{"id":""}"#,
        r#"{"id":"   "}"#,
        r#"{"id":"other123","status":"confirmed"}"#,
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/calendars/primary/events"))
            .respond_with(ResponseTemplate::new(200).set_body_string(response_body))
            .expect(1)
            .mount(&server)
            .await;
        let client = GoogleCalendarClient::new("test_tok")
            .unwrap()
            .with_base_url(server.uri())
            .with_retry_config(3, 1, 1);
        let event = serde_json::from_value(event_json("abc123", "Meeting")).unwrap();
        let error = client.create_event("primary", &event).await.unwrap_err();
        assert!(matches!(error, GoogleCalendarError::AmbiguousWrite { .. }));
        assert!(matches!(
            error.to_fcp_error(),
            FcpError::External {
                retryable: false,
                ..
            }
        ));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}

#[fcp_async_core::runtime::test]
async fn client_quick_add_does_not_retry_ambiguous_write() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/calendars/primary/events/quickAdd"))
        .respond_with(
            ResponseTemplate::new(503)
                .set_body_json(json!({ "error": { "message": "temporary failure" } })),
        )
        .expect(1)
        .mount(&server)
        .await;
    let client = GoogleCalendarClient::new("test_tok")
        .unwrap()
        .with_base_url(server.uri())
        .with_retry_config(3, 1, 1);
    let error = client
        .quick_add("primary", "Lunch tomorrow")
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        GoogleCalendarError::AmbiguousWrite {
            status_code: Some(503)
        }
    ));
    assert!(!error.is_retryable());
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn client_quick_add_requires_successful_event_identity() {
    for response_body in [
        "{}",
        r#"{"unrelated":"resource"}"#,
        r#"{"id":""}"#,
        r#"{"id":"   "}"#,
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/calendars/primary/events/quickAdd"))
            .respond_with(ResponseTemplate::new(200).set_body_string(response_body))
            .expect(1)
            .mount(&server)
            .await;
        let client = GoogleCalendarClient::new("test_tok")
            .unwrap()
            .with_base_url(server.uri())
            .with_retry_config(3, 1, 1);
        let error = client
            .quick_add("primary", "Lunch tomorrow")
            .await
            .unwrap_err();
        assert!(matches!(error, GoogleCalendarError::AmbiguousWrite { .. }));
        assert!(matches!(
            error.to_fcp_error(),
            FcpError::External {
                retryable: false,
                ..
            }
        ));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}

#[fcp_async_core::runtime::test]
async fn client_create_rejects_invalid_event_ids_without_writes() {
    let server = MockServer::start().await;
    let client = GoogleCalendarClient::new("test_tok")
        .unwrap()
        .with_base_url(server.uri());
    for id in [
        "".to_owned(),
        "abcd".to_owned(),
        "ABCDE".to_owned(),
        "abc-w".to_owned(),
        "abc_w".to_owned(),
        "abc/z".to_owned(),
        "w0000".to_owned(),
        "é0000".to_owned(),
        "a".repeat(1025),
    ] {
        let event = serde_json::from_value(event_json(&id, "Meeting")).unwrap();
        let error = client.create_event("primary", &event).await.unwrap_err();
        assert!(matches!(error, GoogleCalendarError::InvalidEventId));
        assert!(matches!(
            error.to_fcp_error(),
            FcpError::InvalidRequest { .. }
        ));
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn client_delete_event() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/calendars/primary/events/evtDEL"))
        .and(bearer_token("test_tok"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let client = GoogleCalendarClient::new("test_tok")
        .unwrap()
        .with_base_url(server.uri());
    client.delete_event("primary", "evtDEL").await.unwrap();
}

#[fcp_async_core::runtime::test]
async fn client_quick_add() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/calendars/primary/events/quickAdd"))
        .and(bearer_token("test_tok"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(event_json("evtQA", "Lunch at noon")),
        )
        .mount(&server)
        .await;

    let client = GoogleCalendarClient::new("test_tok")
        .unwrap()
        .with_base_url(server.uri());
    let event = client.quick_add("primary", "Lunch at noon").await.unwrap();
    assert_eq!(event.id.as_deref(), Some("evtQA"));
}

#[fcp_async_core::runtime::test]
async fn client_unauthorized() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/users/me/calendarList"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": { "code": 401, "message": "Invalid Credentials" }
        })))
        .mount(&server)
        .await;

    let client = GoogleCalendarClient::new("bad_token")
        .unwrap()
        .with_base_url(server.uri());
    let result = client.list_calendars().await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        GoogleCalendarError::Unauthorized
    ));
}

#[fcp_async_core::runtime::test]
async fn client_rate_limited_no_retry() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/users/me/calendarList"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "60"))
        .mount(&server)
        .await;

    let client = GoogleCalendarClient::new("test_tok")
        .unwrap()
        .with_base_url(server.uri())
        .with_retry_config(0, 100, 100);
    let result = client.list_calendars().await;
    assert!(result.is_err(), "rate-limited request must fail");
    // With RetryLoop and zero retries, the error surfaces as either
    // RateLimited (if the policy exhausts immediately) or Api/timeout
    // (if the backoff sleep is interrupted by the request context deadline).
    let err = result.unwrap_err();
    assert!(
        matches!(
            err,
            GoogleCalendarError::RateLimited { .. } | GoogleCalendarError::Api { .. }
        ),
        "expected RateLimited or Api error, got: {err:?}"
    );
}

// ── Connector-level invoke ──────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn invoke_list_calendars_through_connector() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/users/me/calendarList"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [{ "id": "primary", "summary": "Main" }]
        })))
        .mount(&server)
        .await;

    let mut connector = GoogleCalendarConnector::new();
    let signing_key = Ed25519SigningKey::generate();

    let instance_id = setup_handshake(&mut connector, &signing_key, &["gcal.list_calendars"]).await;
    setup_configure(&mut connector, &server.uri()).await;

    let token = generate_valid_token(&signing_key, &instance_id, "gcal.list_calendars");
    let result = connector
        .handle_invoke(json!({
            "operation": "gcal.list_calendars",
            "input": {},
            "capability_token": token
        }))
        .await
        .unwrap();

    assert!(result["calendars"].as_array().is_some());
}

#[fcp_async_core::runtime::test]
async fn invoke_get_event_through_connector() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/calendars/primary/events/evt001"))
        .respond_with(ResponseTemplate::new(200).set_body_json(event_json("evt001", "Standup")))
        .mount(&server)
        .await;

    let mut connector = GoogleCalendarConnector::new();
    let signing_key = Ed25519SigningKey::generate();

    let instance_id = setup_handshake(&mut connector, &signing_key, &["gcal.get_event"]).await;
    setup_configure(&mut connector, &server.uri()).await;

    let token = generate_valid_token(&signing_key, &instance_id, "gcal.get_event");
    let result = connector
        .handle_invoke(json!({
            "operation": "gcal.get_event",
            "input": {
                "calendar_id": "primary",
                "event_id": "evt001"
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["event"]["id"], "evt001");
}

#[fcp_async_core::runtime::test]
async fn invoke_keyed_create_sends_event_id_and_private_marker() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/calendars/primary/events"))
        .respond_with(|request: &Request| {
            let mut event = request.body_json::<serde_json::Value>().unwrap();
            event["status"] = json!("confirmed");
            ResponseTemplate::new(200).set_body_json(event)
        })
        .expect(1)
        .mount(&server)
        .await;
    let mut connector = GoogleCalendarConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = setup_handshake(&mut connector, &signing_key, &["gcal.create_event"]).await;
    setup_configure(&mut connector, &server.uri()).await;
    let token = generate_valid_token(&signing_key, &instance_id, "gcal.create_event");
    let result = connector
        .handle_invoke(json!({
            "operation": "gcal.create_event",
            "input": {
                "calendar_id": "primary", "event_id": "a0v09", "summary": "Meeting",
                "start": "2025-06-01T10:00:00Z", "end": "2025-06-01T11:00:00Z"
            },
            "capability_token": token
        }))
        .await
        .unwrap();
    assert_eq!(result["event"]["id"], "a0v09");
    let requests = server.received_requests().await.unwrap();
    let body = requests[0].body_json::<serde_json::Value>().unwrap();
    assert_eq!(body["id"], "a0v09");
    assert!(body["extendedProperties"]["private"]["fcpCreateFingerprint"].is_string());
}

#[fcp_async_core::runtime::test]
async fn invoke_create_rejects_invalid_event_ids_without_writes() {
    let server = MockServer::start().await;
    let mut connector = GoogleCalendarConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = setup_handshake(&mut connector, &signing_key, &["gcal.create_event"]).await;
    setup_configure(&mut connector, &server.uri()).await;
    for event_id in [
        json!(null),
        json!(42),
        json!(""),
        json!("invalid-id"),
        json!("a".repeat(1025)),
    ] {
        let token = generate_valid_token(&signing_key, &instance_id, "gcal.create_event");
        let error = connector
            .handle_invoke(json!({
                "operation": "gcal.create_event",
                "input": {
                    "calendar_id": "primary", "event_id": event_id, "summary": "Meeting",
                    "start": "2025-06-01T10:00:00Z", "end": "2025-06-01T11:00:00Z"
                },
                "capability_token": token
            }))
            .await
            .unwrap_err();
        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn invoke_create_rejects_invalid_event_fields_without_writes() {
    let server = MockServer::start().await;
    let mut connector = GoogleCalendarConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = setup_handshake(&mut connector, &signing_key, &["gcal.create_event"]).await;
    setup_configure(&mut connector, &server.uri()).await;
    for invalid in [
        json!({"summary": null}),
        json!({"description": 42}),
        json!({"location": null}),
        json!({"attendees": "invalid"}),
        json!({"attendees": [[]]}),
        json!({"attendees": [{"email": 42}]}),
        json!({"start": "tomorrow"}),
        json!({"end": {"dateTime": "2025-06-01T11:00:00Z"}}),
    ] {
        let mut input = json!({
            "calendar_id": "primary", "event_id": "abc123", "summary": "Meeting",
            "start": "2025-06-01T10:00:00Z", "end": "2025-06-01T11:00:00Z"
        });
        input
            .as_object_mut()
            .unwrap()
            .extend(invalid.as_object().unwrap().clone());
        let token = generate_valid_token(&signing_key, &instance_id, "gcal.create_event");
        let error = connector
            .handle_invoke(json!({
                "operation": "gcal.create_event", "input": input, "capability_token": token
            }))
            .await
            .unwrap_err();
        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn invoke_update_event_preserves_unspecified_fields() {
    let server = MockServer::start().await;
    let mut existing = event_json("evt123", "Renamed meeting");
    existing["description"] = json!("Keep this description");
    existing["attendees"] = json!([{ "email": "guest@example.com" }]);
    existing["recurrence"] = json!(["RRULE:FREQ=WEEKLY"]);
    Mock::given(method("PATCH"))
        .and(path("/calendars/primary/events/evt123"))
        .and(body_json(json!({ "summary": "Renamed meeting" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(&existing))
        .expect(1)
        .mount(&server)
        .await;

    let mut connector = GoogleCalendarConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = setup_handshake(&mut connector, &signing_key, &["gcal.update_event"]).await;
    setup_configure(&mut connector, &server.uri()).await;
    let token = generate_valid_token(&signing_key, &instance_id, "gcal.update_event");
    let result = connector
        .handle_invoke(json!({
            "operation": "gcal.update_event",
            "input": {
                "calendar_id": "primary", "event_id": "evt123",
                "summary": "Renamed meeting"
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["event"]["summary"], "Renamed meeting");
    assert_eq!(result["event"]["description"], existing["description"]);
    assert_eq!(
        result["event"]["attendees"][0]["email"],
        "guest@example.com"
    );
    assert_eq!(result["event"]["recurrence"], existing["recurrence"]);
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1, "a patch needs no read-modify-write race");
}

#[fcp_async_core::runtime::test]
async fn invoke_update_event_can_explicitly_clear_attendees() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/calendars/primary/events/evt123"))
        .and(body_json(json!({ "attendees": [], "description": "" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(event_json("evt123", "Meeting")))
        .expect(1)
        .mount(&server)
        .await;

    let mut connector = GoogleCalendarConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = setup_handshake(&mut connector, &signing_key, &["gcal.update_event"]).await;
    setup_configure(&mut connector, &server.uri()).await;
    let token = generate_valid_token(&signing_key, &instance_id, "gcal.update_event");
    connector
        .handle_invoke(json!({
            "operation": "gcal.update_event",
            "input": {
                "calendar_id": "primary", "event_id": "evt123",
                "attendees": [], "description": ""
            },
            "capability_token": token
        }))
        .await
        .unwrap();
}

#[fcp_async_core::runtime::test]
async fn invoke_update_event_rejects_invalid_fields_without_writes() {
    let server = MockServer::start().await;
    let mut connector = GoogleCalendarConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = setup_handshake(&mut connector, &signing_key, &["gcal.update_event"]).await;
    setup_configure(&mut connector, &server.uri()).await;

    for invalid in [
        json!({}),
        json!({ "summary": null }),
        json!({ "location": 42 }),
        json!({ "start": "tomorrow" }),
        json!({ "end": { "dateTime": "2026-10-23T10:00:00Z" } }),
        json!({ "attendees": "guest@example.com" }),
        json!({ "attendees": [{ "email": 42 }] }),
        json!({ "attendees": [[]] }),
    ] {
        let mut input = invalid;
        input["calendar_id"] = json!("primary");
        input["event_id"] = json!("evt123");
        let token = generate_valid_token(&signing_key, &instance_id, "gcal.update_event");
        let error = connector
            .handle_invoke(json!({
                "operation": "gcal.update_event", "input": input,
                "capability_token": token
            }))
            .await
            .unwrap_err();
        assert!(
            matches!(error, FcpError::InvalidRequest { .. }),
            "{error:?}"
        );
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn invoke_delete_event_through_connector() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/calendars/primary/events/evtDEL"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let mut connector = GoogleCalendarConnector::new();
    let signing_key = Ed25519SigningKey::generate();

    let instance_id = setup_handshake(&mut connector, &signing_key, &["gcal.delete_event"]).await;
    setup_configure(&mut connector, &server.uri()).await;

    let token = generate_valid_token(&signing_key, &instance_id, "gcal.delete_event");
    let result = connector
        .handle_invoke(json!({
            "operation": "gcal.delete_event",
            "input": {
                "calendar_id": "primary",
                "event_id": "evtDEL"
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["status"], "deleted");
}

#[fcp_async_core::runtime::test]
async fn invoke_wrong_capability_rejected() {
    let mut connector = GoogleCalendarConnector::new();
    let signing_key = Ed25519SigningKey::generate();

    let instance_id = setup_handshake(&mut connector, &signing_key, &["gcal.read"]).await;
    setup_configure(&mut connector, "http://localhost:1").await;

    let token = generate_valid_token(&signing_key, &instance_id, "gcal.read");
    let result = connector
        .handle_invoke(json!({
            "operation": "gcal.create_event",
            "input": {
                "calendar_id": "primary",
                "event": { "summary": "Test" }
            },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn invoke_unknown_operation_rejected() {
    let mut connector = GoogleCalendarConnector::new();
    let signing_key = Ed25519SigningKey::generate();

    let instance_id = setup_handshake(&mut connector, &signing_key, &["gcal.nonexistent"]).await;
    setup_configure(&mut connector, "http://localhost:1").await;

    let token = generate_valid_token(&signing_key, &instance_id, "gcal.nonexistent");
    let result = connector
        .handle_invoke(json!({
            "operation": "gcal.nonexistent",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        FcpError::OperationNotGranted { .. }
    ));
}

#[fcp_async_core::runtime::test]
async fn invoke_missing_required_field_rejected() {
    let server = MockServer::start().await;

    let mut connector = GoogleCalendarConnector::new();
    let signing_key = Ed25519SigningKey::generate();

    let instance_id = setup_handshake(&mut connector, &signing_key, &["gcal.get_event"]).await;
    setup_configure(&mut connector, &server.uri()).await;

    let token = generate_valid_token(&signing_key, &instance_id, "gcal.get_event");
    // Missing event_id
    let result = connector
        .handle_invoke(json!({
            "operation": "gcal.get_event",
            "input": { "calendar_id": "primary" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("event_id"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

// ── FreeBusy client ─────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn client_freebusy() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/freeBusy"))
        .and(bearer_token("test_tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "calendar#freeBusy",
            "calendars": {
                "primary": {
                    "busy": [
                        { "start": "2026-03-02T10:00:00Z", "end": "2026-03-02T11:00:00Z" }
                    ]
                }
            }
        })))
        .mount(&server)
        .await;

    let client = GoogleCalendarClient::new("test_tok")
        .unwrap()
        .with_base_url(server.uri());

    let request = fcp_google_calendar::types::FreeBusyRequest {
        time_min: "2026-03-02T00:00:00Z".into(),
        time_max: "2026-03-03T00:00:00Z".into(),
        items: vec![fcp_google_calendar::types::FreeBusyRequestItem {
            id: "primary".into(),
        }],
    };
    let result = client.freebusy(&request).await.unwrap();
    assert!(result.calendars.contains_key("primary"));
    assert_eq!(result.calendars["primary"].busy.len(), 1);
}

// ── FreeBusy connector-level ────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn invoke_freebusy_through_connector() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/freeBusy"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "calendars": {
                "primary": {
                    "busy": [
                        { "start": "2026-03-02T10:00:00Z", "end": "2026-03-02T11:00:00Z" }
                    ]
                }
            }
        })))
        .mount(&server)
        .await;

    let mut connector = GoogleCalendarConnector::new();
    let signing_key = Ed25519SigningKey::generate();

    let instance_id = setup_handshake(&mut connector, &signing_key, &["gcal.freebusy"]).await;
    setup_configure(&mut connector, &server.uri()).await;

    let token = generate_valid_token(&signing_key, &instance_id, "gcal.freebusy");
    let result = connector
        .handle_invoke(json!({
            "operation": "gcal.freebusy",
            "input": {
                "time_min": "2026-03-02T00:00:00Z",
                "time_max": "2026-03-03T00:00:00Z",
                "items": [{ "id": "primary" }]
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert!(result["calendars"].is_object());
}

#[fcp_async_core::runtime::test]
async fn invoke_freebusy_missing_fields() {
    let server = MockServer::start().await;

    let mut connector = GoogleCalendarConnector::new();
    let signing_key = Ed25519SigningKey::generate();

    let instance_id = setup_handshake(&mut connector, &signing_key, &["gcal.freebusy"]).await;
    setup_configure(&mut connector, &server.uri()).await;

    let token = generate_valid_token(&signing_key, &instance_id, "gcal.freebusy");
    let result = connector
        .handle_invoke(json!({
            "operation": "gcal.freebusy",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("time_min"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

// ── Event instances client ──────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn client_list_event_instances() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/calendars/primary/events/recurring001/instances"))
        .and(bearer_token("test_tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [
                event_json("recurring001_20260301", "Weekly standup"),
                event_json("recurring001_20260308", "Weekly standup")
            ]
        })))
        .mount(&server)
        .await;

    let client = GoogleCalendarClient::new("test_tok")
        .unwrap()
        .with_base_url(server.uri());
    let result = client
        .list_event_instances("primary", "recurring001", None, None, None, None)
        .await
        .unwrap();
    assert_eq!(result.items.len(), 2);
}

// ── Event instances connector-level ─────────────────────────────

#[fcp_async_core::runtime::test]
async fn invoke_list_event_instances_through_connector() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/calendars/primary/events/recurring001/instances"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [
                event_json("recurring001_20260301", "Weekly standup")
            ]
        })))
        .mount(&server)
        .await;

    let mut connector = GoogleCalendarConnector::new();
    let signing_key = Ed25519SigningKey::generate();

    let instance_id =
        setup_handshake(&mut connector, &signing_key, &["gcal.list_event_instances"]).await;
    setup_configure(&mut connector, &server.uri()).await;

    let token = generate_valid_token(&signing_key, &instance_id, "gcal.list_event_instances");
    let result = connector
        .handle_invoke(json!({
            "operation": "gcal.list_event_instances",
            "input": {
                "calendar_id": "primary",
                "event_id": "recurring001"
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert!(result["events"].as_array().is_some());
}

// ── Get calendar client ─────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn client_get_calendar() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/users/me/calendarList/primary"))
        .and(bearer_token("test_tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "primary",
            "summary": "My Calendar",
            "timeZone": "America/New_York",
            "primary": true
        })))
        .mount(&server)
        .await;

    let client = GoogleCalendarClient::new("test_tok")
        .unwrap()
        .with_base_url(server.uri());
    let result: serde_json::Value = client.get_calendar("primary").await.unwrap();
    assert_eq!(result["id"], "primary");
    assert_eq!(result["summary"], "My Calendar");
}

#[fcp_async_core::runtime::test]
async fn client_get_calendar_unauthorized() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/users/me/calendarList/nonexistent"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": { "code": 401, "message": "Invalid Credentials" }
        })))
        .mount(&server)
        .await;

    let client = GoogleCalendarClient::new("bad_token")
        .unwrap()
        .with_base_url(server.uri())
        .with_retry_config(0, 100, 100);
    let result: Result<serde_json::Value, _> = client.get_calendar("nonexistent").await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        GoogleCalendarError::Unauthorized
    ));
}

// ── Get calendar connector-level ────────────────────────────────

#[fcp_async_core::runtime::test]
async fn invoke_get_calendar_through_connector() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/users/me/calendarList/primary"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "primary",
            "summary": "My Calendar",
            "timeZone": "America/New_York"
        })))
        .mount(&server)
        .await;

    let mut connector = GoogleCalendarConnector::new();
    let signing_key = Ed25519SigningKey::generate();

    let instance_id = setup_handshake(&mut connector, &signing_key, &["gcal.get_calendar"]).await;
    setup_configure(&mut connector, &server.uri()).await;

    let token = generate_valid_token(&signing_key, &instance_id, "gcal.get_calendar");
    let result = connector
        .handle_invoke(json!({
            "operation": "gcal.get_calendar",
            "input": { "calendar_id": "primary" },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert!(result["calendar"].is_object());
    assert_eq!(result["calendar"]["id"], "primary");
}

#[fcp_async_core::runtime::test]
async fn invoke_get_calendar_missing_field() {
    let server = MockServer::start().await;

    let mut connector = GoogleCalendarConnector::new();
    let signing_key = Ed25519SigningKey::generate();

    let instance_id = setup_handshake(&mut connector, &signing_key, &["gcal.get_calendar"]).await;
    setup_configure(&mut connector, &server.uri()).await;

    let token = generate_valid_token(&signing_key, &instance_id, "gcal.get_calendar");
    let result = connector
        .handle_invoke(json!({
            "operation": "gcal.get_calendar",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("calendar_id"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}

// ── Quick-add connector-level ───────────────────────────────────

#[fcp_async_core::runtime::test]
async fn invoke_quick_add_through_connector() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/calendars/primary/events/quickAdd"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(event_json("evtQA2", "Dinner at 7pm")),
        )
        .mount(&server)
        .await;

    let mut connector = GoogleCalendarConnector::new();
    let signing_key = Ed25519SigningKey::generate();

    let instance_id = setup_handshake(&mut connector, &signing_key, &["gcal.quick_add"]).await;
    setup_configure(&mut connector, &server.uri()).await;

    let token = generate_valid_token(&signing_key, &instance_id, "gcal.quick_add");
    let result = connector
        .handle_invoke(json!({
            "operation": "gcal.quick_add",
            "input": {
                "calendar_id": "primary",
                "text": "Dinner at 7pm"
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["event"]["id"], "evtQA2");
}

// ── Risk level verification ─────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn introspect_risk_levels() {
    let connector = GoogleCalendarConnector::new();
    let result = connector.handle_introspect().await.unwrap();
    let ops = result["operations"].as_array().unwrap();

    for op in ops {
        let id = op["id"].as_str().unwrap();
        let risk = op["risk_level"].as_str().unwrap();
        match id {
            "gcal.list_calendars"
            | "gcal.get_event"
            | "gcal.list_events"
            | "gcal.freebusy"
            | "gcal.list_event_instances"
            | "gcal.get_calendar"
            | "gcal.sync_events" => {
                assert_eq!(risk, "low", "Read op {id} should be low risk");
            }
            "gcal.create_event" | "gcal.update_event" | "gcal.quick_add" => {
                assert_eq!(risk, "medium", "Write op {id} should be medium risk");
            }
            "gcal.delete_event" => {
                assert_eq!(risk, "high", "Delete op {id} should be high risk");
            }
            _ => panic!("Unknown operation: {id}"),
        }
    }
}

// ── Sync events client ──────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn client_sync_events_initial() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/calendars/primary/events"))
        .and(bearer_token("test_tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [
                event_json("evt001", "Meeting A"),
                event_json("evt002", "Meeting B")
            ],
            "nextSyncToken": "CPDAlvXkExample123"
        })))
        .mount(&server)
        .await;

    let client = GoogleCalendarClient::new("test_tok")
        .unwrap()
        .with_base_url(server.uri());
    let result = client
        .sync_events("primary", None, None, None)
        .await
        .unwrap();
    assert_eq!(result.items.len(), 2);
    assert_eq!(
        result.next_sync_token.as_deref(),
        Some("CPDAlvXkExample123")
    );
    assert!(result.next_page_token.is_none());
}

#[fcp_async_core::runtime::test]
async fn client_sync_events_incremental() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/calendars/primary/events"))
        .and(bearer_token("test_tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [
                {
                    "id": "evt003",
                    "summary": "New meeting",
                    "status": "confirmed",
                    "start": { "dateTime": "2026-03-03T10:00:00Z" },
                    "end": { "dateTime": "2026-03-03T11:00:00Z" }
                },
                {
                    "id": "evt001",
                    "status": "cancelled"
                }
            ],
            "nextSyncToken": "CPDAlvXkUpdated456"
        })))
        .mount(&server)
        .await;

    let client = GoogleCalendarClient::new("test_tok")
        .unwrap()
        .with_base_url(server.uri());
    let result = client
        .sync_events("primary", Some("CPDAlvXkExample123"), None, None)
        .await
        .unwrap();
    assert_eq!(result.items.len(), 2);
    assert_eq!(
        result.next_sync_token.as_deref(),
        Some("CPDAlvXkUpdated456")
    );
    // Verify cancelled event is present (incremental sync includes deleted events)
    let cancelled = result
        .items
        .iter()
        .find(|e| e.id.as_deref() == Some("evt001"));
    assert_eq!(cancelled.unwrap().status.as_deref(), Some("cancelled"));
}

// ── Sync events connector-level ─────────────────────────────────

#[fcp_async_core::runtime::test]
async fn invoke_sync_events_initial_through_connector() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/calendars/primary/events"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [event_json("evt001", "Standup")],
            "nextSyncToken": "sync-token-abc"
        })))
        .mount(&server)
        .await;

    let mut connector = GoogleCalendarConnector::new();
    let signing_key = Ed25519SigningKey::generate();

    let instance_id = setup_handshake(&mut connector, &signing_key, &["gcal.sync_events"]).await;
    setup_configure(&mut connector, &server.uri()).await;

    let token = generate_valid_token(&signing_key, &instance_id, "gcal.sync_events");
    let result = connector
        .handle_invoke(json!({
            "operation": "gcal.sync_events",
            "input": { "calendar_id": "primary" },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert!(result["events"].as_array().is_some());
    assert_eq!(result["next_sync_token"], "sync-token-abc");
}

#[fcp_async_core::runtime::test]
async fn invoke_sync_events_incremental_through_connector() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/calendars/primary/events"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [{ "id": "evt002", "status": "cancelled" }],
            "nextSyncToken": "sync-token-def"
        })))
        .mount(&server)
        .await;

    let mut connector = GoogleCalendarConnector::new();
    let signing_key = Ed25519SigningKey::generate();

    let instance_id = setup_handshake(&mut connector, &signing_key, &["gcal.sync_events"]).await;
    setup_configure(&mut connector, &server.uri()).await;

    let token = generate_valid_token(&signing_key, &instance_id, "gcal.sync_events");
    let result = connector
        .handle_invoke(json!({
            "operation": "gcal.sync_events",
            "input": {
                "calendar_id": "primary",
                "sync_token": "sync-token-abc"
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["events"].as_array().unwrap().len(), 1);
    assert_eq!(result["next_sync_token"], "sync-token-def");
}

#[fcp_async_core::runtime::test]
async fn invoke_sync_events_missing_calendar_id() {
    let server = MockServer::start().await;

    let mut connector = GoogleCalendarConnector::new();
    let signing_key = Ed25519SigningKey::generate();

    let instance_id = setup_handshake(&mut connector, &signing_key, &["gcal.sync_events"]).await;
    setup_configure(&mut connector, &server.uri()).await;

    let token = generate_valid_token(&signing_key, &instance_id, "gcal.sync_events");
    let result = connector
        .handle_invoke(json!({
            "operation": "gcal.sync_events",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("calendar_id"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}
