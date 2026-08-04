//! Integration tests for the FCP `Home Assistant` connector.

#![allow(
    clippy::cast_possible_truncation,
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use asupersync::io::{AsyncRead, ReadBuf};
use asupersync::net::websocket::{
    CloseReason, Message as ServerWsMessage, ServerWebSocket, WebSocketAcceptor,
};
use fcp_async_core::net::{TcpListener, TcpStream};
use serde_json::json;
use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::Poll;
use wiremock::matchers::{header, method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_homeassistant::connector::HomeAssistantConnector;

async fn setup_connector(mock_url: &str) -> HomeAssistantConnector {
    let mut c = HomeAssistantConnector::new();
    c.handle_configure(json!({ "access_token": "test-token", "base_url": mock_url }))
        .await
        .unwrap();
    c.handle_handshake(json!({"session_id": "test"}))
        .await
        .unwrap();
    c
}

type TestServerWebSocket = ServerWebSocket<TcpStream>;

async fn read_http_headers<IO: AsyncRead + Unpin>(io: &mut IO) -> io::Result<Vec<u8>> {
    const MAX_HEADERS: usize = 16 * 1024;

    let mut buf = Vec::with_capacity(1024);
    let mut temp = [0u8; 256];

    loop {
        let read = poll_fn(|cx| {
            let mut read_buf = ReadBuf::new(&mut temp);
            match Pin::new(&mut *io).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await?;

        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF before websocket handshake completed",
            ));
        }

        buf.extend_from_slice(&temp[..read]);
        if buf.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(buf);
        }
        if buf.len() > MAX_HEADERS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "websocket handshake headers too large",
            ));
        }
    }
}

async fn accept_test_websocket(mut stream: TcpStream) -> TestServerWebSocket {
    let request = read_http_headers(&mut stream)
        .await
        .expect("read websocket handshake");
    WebSocketAcceptor::new()
        .accept(&fcp_async_core::compatibility_cx(), &request, stream)
        .await
        .expect("accept websocket")
}

async fn send_json_frame(ws: &mut TestServerWebSocket, value: serde_json::Value, context: &str) {
    ws.send(
        &fcp_async_core::compatibility_cx(),
        ServerWsMessage::text(value.to_string()),
    )
    .await
    .expect(context);
}

async fn recv_text_frame(ws: &mut TestServerWebSocket, context: &str) -> Option<String> {
    match ws.recv(&fcp_async_core::compatibility_cx()).await {
        Ok(Some(ServerWsMessage::Text(text))) => Some(text),
        Ok(Some(other)) => panic!("expected text frame for {context}, got {other:?}"),
        Ok(None) => None,
        Err(err) => panic!("{context}: {err}"),
    }
}

async fn close_test_websocket(ws: &mut TestServerWebSocket) {
    let _ = ws
        .close(&fcp_async_core::compatibility_cx(), CloseReason::normal())
        .await;
}

// -- Lifecycle --

#[fcp_async_core::runtime::test]
async fn lifecycle_health_unconfigured() {
    let c = HomeAssistantConnector::new();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "unconfigured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_full() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_before_configure_fails() {
    let mut c = HomeAssistantConnector::new();
    assert!(c.handle_handshake(json!({})).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn lifecycle_shutdown() {
    let server = MockServer::start().await;
    let mut c = setup_connector(&server.uri()).await;
    c.handle_shutdown(json!({})).await.unwrap();
    assert_eq!(c.handle_health().await.unwrap()["status"], "unconfigured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_self_check() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"message": "API running."})))
        .mount(&server)
        .await;
    let c = setup_connector(&server.uri()).await;
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "ok");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert_eq!(c.handle_doctor().await.unwrap()["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_introspect() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    assert_eq!(intro["operations"].as_array().unwrap().len(), 15);
    assert_eq!(intro["event_caps"]["streaming"], true);
    assert_eq!(intro["events"].as_array().unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_configured_but_not_handshaken() {
    let server = MockServer::start().await;
    let mut c = HomeAssistantConnector::new();
    c.handle_configure(json!({ "access_token": "test-token", "base_url": server.uri() }))
        .await
        .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "degraded");
}

// -- List States --

#[fcp_async_core::runtime::test]
async fn list_states() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/states"))
        .and(header("Authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"entity_id": "light.living_room", "state": "on", "attributes": {"brightness": 255}},
            {"entity_id": "sensor.temp", "state": "22.5", "attributes": {}},
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "homeassistant.list_states",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["states"].as_array().unwrap().len(), 2);
}

// -- Get State --

#[fcp_async_core::runtime::test]
async fn get_state() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/states/light.living_room"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "entity_id": "light.living_room",
            "state": "on",
            "attributes": {"brightness": 255, "friendly_name": "Living Room Light"},
            "last_changed": "2026-03-01T10:00:00Z",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "homeassistant.get_state",
            "input": {"entity_id": "light.living_room"}
        }))
        .await
        .unwrap();
    assert_eq!(result["state"]["state"], "on");
    assert_eq!(result["state"]["entity_id"], "light.living_room");
}

#[fcp_async_core::runtime::test]
async fn get_state_missing_entity_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "homeassistant.get_state",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Set State --

#[fcp_async_core::runtime::test]
async fn set_state() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/states/input_boolean.guest_mode"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "entity_id": "input_boolean.guest_mode",
            "state": "on",
            "attributes": {},
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "homeassistant.set_state",
            "input": {"entity_id": "input_boolean.guest_mode", "state": "on"}
        }))
        .await
        .unwrap();
    assert_eq!(result["state"]["state"], "on");
}

#[fcp_async_core::runtime::test]
async fn set_state_with_attributes() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/states/sensor.custom"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "entity_id": "sensor.custom",
            "state": "42",
            "attributes": {"unit_of_measurement": "C"},
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "homeassistant.set_state",
            "input": {
                "entity_id": "sensor.custom",
                "state": "42",
                "attributes": {"unit_of_measurement": "C"}
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["state"]["attributes"]["unit_of_measurement"], "C");
}

#[fcp_async_core::runtime::test]
async fn set_state_missing_state() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "homeassistant.set_state",
            "input": {"entity_id": "light.test"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn set_state_missing_entity_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "homeassistant.set_state",
            "input": {"state": "on"}
        }))
        .await
        .is_err()
    );
}

// -- Call Service --

#[fcp_async_core::runtime::test]
async fn call_service() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/services/light/turn_on"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"entity_id": "light.living_room", "state": "on"}
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "homeassistant.call_service",
            "input": {
                "domain": "light",
                "service": "turn_on",
                "target": {"entity_id": "light.living_room"},
                "service_data": {"brightness_pct": 75}
            }
        }))
        .await
        .unwrap();
    assert!(result.get("result").is_some());
}

#[fcp_async_core::runtime::test]
async fn call_service_missing_domain() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "homeassistant.call_service",
            "input": {"service": "turn_on"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn call_service_missing_service() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "homeassistant.call_service",
            "input": {"domain": "light"}
        }))
        .await
        .is_err()
    );
}

// -- List Services --

#[fcp_async_core::runtime::test]
async fn list_services() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/services"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"domain": "light", "services": {"turn_on": {}, "turn_off": {}, "toggle": {}}},
            {"domain": "switch", "services": {"turn_on": {}, "turn_off": {}}},
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "homeassistant.list_services",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["services"].as_array().unwrap().len(), 2);
}

// -- List Automations --

#[fcp_async_core::runtime::test]
async fn list_automations() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/states"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"entity_id": "automation.night_mode", "state": "on", "attributes": {"friendly_name": "Night Mode"}},
            {"entity_id": "automation.morning_routine", "state": "off", "attributes": {}},
            {"entity_id": "light.test", "state": "on", "attributes": {}},
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "homeassistant.list_automations",
            "input": {}
        }))
        .await
        .unwrap();
    let automations = result["automations"].as_array().unwrap();
    assert_eq!(automations.len(), 2);
}

// -- Trigger Automation --

#[fcp_async_core::runtime::test]
async fn trigger_automation() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/services/automation/trigger"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "homeassistant.trigger_automation",
            "input": {"entity_id": "automation.night_mode"}
        }))
        .await
        .unwrap();
    assert!(result.get("result").is_some());
}

#[fcp_async_core::runtime::test]
async fn trigger_automation_with_skip_condition() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/services/automation/trigger"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "homeassistant.trigger_automation",
            "input": {"entity_id": "automation.night_mode", "skip_condition": true}
        }))
        .await
        .unwrap();
    assert!(result.get("result").is_some());
}

#[fcp_async_core::runtime::test]
async fn trigger_automation_missing_entity_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "homeassistant.trigger_automation",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Toggle Automation --

#[fcp_async_core::runtime::test]
async fn toggle_automation_enable() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/services/automation/turn_on"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "homeassistant.toggle_automation",
            "input": {"entity_id": "automation.night_mode", "enabled": true}
        }))
        .await
        .unwrap();
    assert!(result.get("result").is_some());
}

#[fcp_async_core::runtime::test]
async fn toggle_automation_disable() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/services/automation/turn_off"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "homeassistant.toggle_automation",
            "input": {"entity_id": "automation.night_mode", "enabled": false}
        }))
        .await
        .unwrap();
    assert!(result.get("result").is_some());
}

#[fcp_async_core::runtime::test]
async fn toggle_automation_missing_enabled() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "homeassistant.toggle_automation",
            "input": {"entity_id": "automation.night_mode"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn toggle_automation_missing_entity_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "homeassistant.toggle_automation",
            "input": {"enabled": true}
        }))
        .await
        .is_err()
    );
}

// -- List Scenes --

#[fcp_async_core::runtime::test]
async fn list_scenes() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/states"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"entity_id": "scene.movie_night", "state": "scening", "attributes": {"friendly_name": "Movie Night"}},
            {"entity_id": "scene.bedtime", "state": "scening", "attributes": {}},
            {"entity_id": "light.test", "state": "on", "attributes": {}},
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "homeassistant.list_scenes",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["scenes"].as_array().unwrap().len(), 2);
}

// -- Activate Scene --

#[fcp_async_core::runtime::test]
async fn activate_scene() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/services/scene/turn_on"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "homeassistant.activate_scene",
            "input": {"entity_id": "scene.movie_night"}
        }))
        .await
        .unwrap();
    assert!(result.get("result").is_some());
}

#[fcp_async_core::runtime::test]
async fn activate_scene_missing_entity_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "homeassistant.activate_scene",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Get History --

#[fcp_async_core::runtime::test]
async fn get_history() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/history/period/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            [
                {"entity_id": "sensor.temp", "state": "22", "last_changed": "2026-03-01T00:00:00Z"},
                {"entity_id": "sensor.temp", "state": "23", "last_changed": "2026-03-01T01:00:00Z"},
            ]
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "homeassistant.get_history",
            "input": {
                "timestamp": "2026-03-01T00:00:00Z",
                "filter_entity_id": "sensor.temp"
            }
        }))
        .await
        .unwrap();
    assert!(result.get("history").is_some());
    assert_eq!(result["history"].as_array().unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn get_history_missing_timestamp() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "homeassistant.get_history",
            "input": {"filter_entity_id": "sensor.temp"}
        }))
        .await
        .is_err()
    );
}

// -- Get Statistics --

#[fcp_async_core::runtime::test]
async fn get_statistics() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/history/period/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            [
                {"entity_id": "sensor:energy", "state": "100"},
                {"entity_id": "sensor:energy", "state": "200"},
            ]
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "homeassistant.get_statistics",
            "input": {
                "start_time": "2026-02-01T00:00:00Z",
                "statistic_ids": "sensor:energy",
                "period": "day"
            }
        }))
        .await
        .unwrap();
    assert!(result.get("statistics").is_some());
    assert_eq!(result["period"], "day");
}

#[fcp_async_core::runtime::test]
async fn get_statistics_missing_start_time() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "homeassistant.get_statistics",
            "input": {"statistic_ids": "sensor:energy"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn get_statistics_missing_statistic_ids() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "homeassistant.get_statistics",
            "input": {"start_time": "2026-02-01T00:00:00Z"}
        }))
        .await
        .is_err()
    );
}

// -- Subscribe Events --

#[fcp_async_core::runtime::test]
async fn subscribe_events_websocket_filters_and_redacts() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind websocket listener");
    let base_url = format!(
        "http://{}",
        listener.local_addr().expect("listener local addr")
    );

    let ws_task = fcp_async_core::task::spawn(async move {
        let (tcp_stream, _) = listener.accept().await.expect("accept websocket client");
        let mut ws = accept_test_websocket(tcp_stream).await;

        send_json_frame(
            &mut ws,
            json!({"type": "auth_required"}),
            "send auth_required",
        )
        .await;
        let auth = recv_text_frame(&mut ws, "receive auth frame")
            .await
            .expect("auth frame");
        let auth: serde_json::Value = serde_json::from_str(&auth).expect("auth json");
        assert_eq!(auth["type"], "auth");
        assert_eq!(auth["access_token"], "test-token");

        send_json_frame(&mut ws, json!({"type": "auth_ok"}), "send auth_ok").await;
        let subscribe = recv_text_frame(&mut ws, "receive subscribe frame")
            .await
            .expect("subscribe frame");
        let subscribe: serde_json::Value =
            serde_json::from_str(&subscribe).expect("subscribe json");
        assert_eq!(subscribe["type"], "subscribe_events");
        assert_eq!(subscribe["event_type"], "state_changed");

        send_json_frame(
            &mut ws,
            json!({"id": 1, "type": "result", "success": true}),
            "send subscribe ack",
        )
        .await;
        send_json_frame(
            &mut ws,
            json!({"type": "event", "event": {"data": {"entity_id": "light.secret"}, "event_type": "state_changed"}}),
            "send ignored event",
        )
        .await;
        send_json_frame(
            &mut ws,
            json!({"type": "event", "event": {"data": {"entity_id": "sensor.temp"}, "event_type": "state_changed"}}),
            "send filtered event",
        )
        .await;
        send_json_frame(
            &mut ws,
            json!({
                "type": "event",
                "event": {
                    "event_type": "state_changed",
                    "data": {
                        "entity_id": "light.kitchen",
                        "old_state": {"state": "off"},
                        "new_state": {
                            "state": "on",
                            "attributes": {"access_token": "should-not-leak"}
                        }
                    },
                    "origin": "LOCAL",
                    "time_fired": "2026-05-05T12:00:00Z",
                    "context": {"id": "ctx-1"}
                }
            }),
            "send matching event",
        )
        .await;
        close_test_websocket(&mut ws).await;
    });

    let c = setup_connector(&base_url).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "homeassistant.subscribe_events",
            "input": {
                "watch_domains": ["light"],
                "ignore_entities": ["light.secret"],
                "max_events": 1,
                "timeout_ms": 500,
                "max_reconnect_attempts": 0
            }
        }))
        .await
        .unwrap();

    assert_eq!(result["event"]["entity_id"], "light.kitchen");
    assert_eq!(result["event"]["domain"], "light");
    assert_eq!(result["events"].as_array().unwrap().len(), 1);
    assert_eq!(result["stats"]["received"], 3);
    assert_eq!(result["stats"]["dropped_ignored"], 1);
    assert_eq!(result["stats"]["dropped_filter"], 1);
    assert_eq!(
        result["event"]["new_state"]["attributes"]["access_token"],
        "[REDACTED]"
    );
    ws_task.await.expect("websocket task");
}

#[fcp_async_core::runtime::test]
async fn subscribe_events_ack_failure_is_reported() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind websocket listener");
    let base_url = format!(
        "http://{}",
        listener.local_addr().expect("listener local addr")
    );

    let ws_task = fcp_async_core::task::spawn(async move {
        let (tcp_stream, _) = listener.accept().await.expect("accept websocket client");
        let mut ws = accept_test_websocket(tcp_stream).await;
        send_json_frame(
            &mut ws,
            json!({"type": "auth_required"}),
            "send auth_required",
        )
        .await;
        let _ = recv_text_frame(&mut ws, "receive auth frame").await;
        send_json_frame(&mut ws, json!({"type": "auth_ok"}), "send auth_ok").await;
        let _ = recv_text_frame(&mut ws, "receive subscribe frame").await;
        send_json_frame(
            &mut ws,
            json!({"id": 1, "type": "result", "success": false, "error": {"message": "bad event type"}}),
            "send subscribe nack",
        )
        .await;
        close_test_websocket(&mut ws).await;
    });

    let c = setup_connector(&base_url).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "homeassistant.subscribe_events",
            "input": {
                "watch_all": true,
                "timeout_ms": 500,
                "max_reconnect_attempts": 0
            }
        }))
        .await
        .is_err()
    );
    ws_task.await.expect("websocket task");
}

// -- Error handling --

#[fcp_async_core::runtime::test]
async fn error_401() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/states"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({"message": "Unauthorized"})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "homeassistant.list_states",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_404() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/states/.*"))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(json!({"message": "Entity not found"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "homeassistant.get_state",
            "input": {"entity_id": "light.nonexistent"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/states"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({"message": "Too many requests"}))
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "homeassistant.list_states",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_503() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/states"))
        .respond_with(
            ResponseTemplate::new(503).set_body_json(json!({"message": "Home Assistant starting"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "homeassistant.list_states",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_200_empty_body_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/states"))
        .respond_with(ResponseTemplate::new(200).set_body_string(""))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "homeassistant.list_states",
            "input": {}
        }))
        .await
        .is_ok()
    );
}

// -- Unknown op / Simulate --

#[fcp_async_core::runtime::test]
async fn unknown_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "homeassistant.nope",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "homeassistant.list_states"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_unknown() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        !c.handle_simulate(json!({"operation_id": "homeassistant.nope"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_subscribe_events() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "homeassistant.subscribe_events"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

// -- Counters --

#[fcp_async_core::runtime::test]
async fn counters_increment() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/states"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "homeassistant.list_states",
        "input": {}
    }))
    .await
    .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 0);
}

#[fcp_async_core::runtime::test]
async fn counters_error_increment() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/states"))
        .respond_with(
            ResponseTemplate::new(500).set_body_json(json!({"message": "Internal error"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "homeassistant.list_states",
            "input": {}
        }))
        .await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 1);
}

// -- List Areas / Devices --

#[fcp_async_core::runtime::test]
async fn list_areas() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/states"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"entity_id": "input_select.area_kitchen", "state": "Kitchen", "attributes": {}},
            {"entity_id": "input_select.area_bedroom", "state": "Bedroom", "attributes": {}},
            {"entity_id": "light.test", "state": "on", "attributes": {}},
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "homeassistant.list_areas",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["areas"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn list_devices() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/states"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"entity_id": "light.living_room", "state": "on", "attributes": {}},
            {"entity_id": "sensor.temp", "state": "22", "attributes": {}},
            {"entity_id": "automation.test", "state": "on", "attributes": {}},
            {"entity_id": "scene.movie", "state": "scening", "attributes": {}},
            {"entity_id": "script.test", "state": "off", "attributes": {}},
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "homeassistant.list_devices",
            "input": {}
        }))
        .await
        .unwrap();
    // Should filter out automation, scene, script
    assert_eq!(result["devices"].as_array().unwrap().len(), 2);
}
