//! Exercise the real dispatcher using the types fcp-host actually consumes.

use fcp_async_core::runtime::Builder;
use fcp_core::{HandshakeResponse, Introspection, SelfCheckReport};

use super::*;

fn run<T>(future: impl std::future::Future<Output = T>) -> T {
    Builder::new_multi_thread().enable_all().build().unwrap().block_on(future)
}

fn handshake() -> Value {
    json!({
        "protocol_version": "2.0.0", "zone": "z:work",
        "host_public_key": vec![1_u8; 32], "nonce": vec![9_u8; 32],
        "capabilities_requested": ["mcp.server.metrics"],
    })
}

async fn configure(server: &mut McpBridgeServer) {
    // Construction is local. No test needs a running upstream MCP server.
    server.dispatch("configure", json!({"mcp_url": "http://127.0.0.1:1"})).await.unwrap();
}

async fn health(server: &mut McpBridgeServer) -> (HealthSnapshot, Value) {
    let value = server.dispatch("health", json!({})).await.unwrap();
    let snapshot = serde_json::from_value::<HealthSnapshot>(value.clone())
        .expect("the real host must be able to decode every lifecycle state");
    (snapshot, value)
}

#[test]
fn initial_health_is_canonical_starting_not_a_legacy_status_string() {
    run(async {
        let mut server = McpBridgeServer::new().unwrap();
        let (snapshot, value) = health(&mut server).await;
        assert!(matches!(snapshot.status, HealthState::Starting));
        assert_eq!(value["configured"], false);
        assert_eq!(value["handshaken"], false);
        assert_eq!(value["requests"], 0);
        assert!(!snapshot.is_ready());
        assert_eq!(snapshot.details.as_ref().unwrap()["instance_id"], value["instance_id"]);
    });
}

#[test]
fn configuration_without_handshake_is_degraded_and_does_not_grant_authority() {
    run(async {
        let mut server = McpBridgeServer::new().unwrap();
        configure(&mut server).await;
        let (snapshot, value) = health(&mut server).await;
        assert!(matches!(snapshot.status, HealthState::Degraded { .. }));
        assert_eq!(value["configured"], true);
        assert_eq!(value["handshaken"], false);
        assert_eq!(value["requests"], 0);
    });
}

#[test]
fn accepted_handshake_and_health_report_the_same_actual_instance() {
    run(async {
        let mut server = McpBridgeServer::new().unwrap();
        configure(&mut server).await;
        let reply = server.dispatch("handshake", handshake()).await.unwrap();
        let typed: HandshakeResponse = serde_json::from_value(reply.clone()).unwrap();
        assert_eq!(typed.status, "accepted");
        assert_eq!(typed.nonce, [9_u8; 32]);
        assert_eq!(typed.capabilities_granted.len(), 1);
        let (snapshot, value) = health(&mut server).await;
        assert!(snapshot.is_ready());
        assert_eq!(value["instance_id"], reply["instance_id"]);
        assert_eq!(snapshot.details.unwrap()["instance_id"], reply["instance_id"]);
        assert_eq!(value["requests"], 0);
    });
}

#[test]
fn invalid_rehandshake_revokes_readiness_and_rotates_the_reported_instance() {
    run(async {
        let mut server = McpBridgeServer::new().unwrap();
        configure(&mut server).await;
        let old = server.dispatch("handshake", handshake()).await.unwrap();
        let mut bad = handshake();
        bad["protocol_version"] = json!("1.0.0");
        assert!(server.dispatch("handshake", bad).await.is_err());
        let (snapshot, value) = health(&mut server).await;
        assert!(matches!(snapshot.status, HealthState::Degraded { .. }));
        assert_eq!(value["handshaken"], false);
        assert_ne!(value["instance_id"], old["instance_id"]);
        assert_eq!(value["requests"], 0);
    });
}

#[test]
fn shutdown_and_reconfiguration_never_report_old_authority_as_ready() {
    run(async {
        let mut server = McpBridgeServer::new().unwrap();
        configure(&mut server).await;
        let old = server.dispatch("handshake", handshake()).await.unwrap();
        server.dispatch("shutdown", json!({})).await.unwrap();
        let (snapshot, value) = health(&mut server).await;
        assert!(matches!(snapshot.status, HealthState::Stopping));
        assert_eq!(value["configured"], false);
        assert_eq!(value["handshaken"], false);
        assert_ne!(value["instance_id"], old["instance_id"]);
        configure(&mut server).await;
        let (snapshot, _) = health(&mut server).await;
        assert!(matches!(snapshot.status, HealthState::Degraded { .. }));
    });
}

#[test]
fn failed_reconfiguration_is_starting_and_cannot_preserve_ready_status() {
    run(async {
        let mut server = McpBridgeServer::new().unwrap();
        configure(&mut server).await;
        server.dispatch("handshake", handshake()).await.unwrap();
        assert!(server.dispatch("configure", json!({})).await.is_err());
        let (snapshot, value) = health(&mut server).await;
        assert!(matches!(snapshot.status, HealthState::Starting));
        assert_eq!(value["configured"], false);
        assert_eq!(value["handshaken"], false);
    });
}

#[test]
fn uptime_is_process_lifetime_not_time_since_last_configure_or_handshake() {
    run(async {
        let mut server = McpBridgeServer::new().unwrap();
        server.started_at = Instant::now().checked_sub(Duration::from_secs(2)).unwrap();
        let before = health(&mut server).await.0.uptime_ms;
        assert!(before >= 2_000);
        configure(&mut server).await;
        server.dispatch("handshake", handshake()).await.unwrap();
        assert!(health(&mut server).await.0.uptime_ms >= before);
    });
}

#[test]
fn host_control_plane_types_round_trip_without_invoking_the_provider() {
    run(async {
        let mut server = McpBridgeServer::new().unwrap();
        let catalog: Introspection = serde_json::from_value(
            server.dispatch("introspect", json!({})).await.unwrap(),
        ).unwrap();
        assert_eq!(catalog.operations.len(), 9);
        let report: SelfCheckReport = serde_json::from_value(
            server.dispatch("self_check", json!({})).await.unwrap(),
        ).unwrap();
        assert!(matches!(report.status, fcp_core::SelfCheckStatus::Degraded));
        let (_, value) = health(&mut server).await;
        assert_eq!(value["requests"], 0);
        assert_eq!(value["errors"], 0);
    });
}

#[test]
fn embedded_manifest_forbidden_zones_cannot_establish_provider_authority() {
    run(async {
        let mut server = McpBridgeServer::new().unwrap();
        configure(&mut server).await;
        for zone in ["z:public", "z:community"] {
            let mut request = handshake();
            request["zone"] = json!(zone);
            assert!(matches!(server.dispatch("handshake", request).await,
                Err(FcpError::CapabilityDenied { .. })));
            let (snapshot, value) = health(&mut server).await;
            assert!(matches!(snapshot.status, HealthState::Degraded { .. }));
            assert_eq!(value["configured"], true);
            assert_eq!(value["handshaken"], false);
            assert_eq!(value["requests"], 0);
        }
    });
}

#[test]
fn forbidden_zone_rehandshake_revokes_old_health_identity_and_can_recover() {
    run(async {
        let mut server = McpBridgeServer::new().unwrap();
        configure(&mut server).await;
        let old = server.dispatch("handshake", handshake()).await.unwrap();
        let mut request = handshake();
        request["zone"] = json!("z:public");
        request["requested_instance_id"] = old["instance_id"].clone();
        assert!(server.dispatch("handshake", request).await.is_err());
        let (snapshot, value) = health(&mut server).await;
        assert!(!snapshot.is_ready());
        assert_eq!(value["handshaken"], false);
        assert_ne!(value["instance_id"], old["instance_id"]);
        let recovered = server.dispatch("handshake", handshake()).await.unwrap();
        let (snapshot, value) = health(&mut server).await;
        assert!(snapshot.is_ready());
        assert_eq!(value["instance_id"], recovered["instance_id"]);
        assert_ne!(value["instance_id"], old["instance_id"]);
        assert_eq!(value["requests"], 0);
    });
}

#[test]
fn empty_grants_cannot_bypass_embedded_manifest_zone_veto() {
    run(async {
        let mut server = McpBridgeServer::new().unwrap();
        configure(&mut server).await;
        let mut request = handshake();
        request["zone"] = json!("z:community");
        request["capabilities_requested"] = json!([]);
        assert!(matches!(server.dispatch("handshake", request).await,
            Err(FcpError::CapabilityDenied { .. })));
        let (snapshot, value) = health(&mut server).await;
        assert!(!snapshot.is_ready());
        assert_eq!(value["handshaken"], false);
        assert_eq!(value["requests"], 0);
    });
}
