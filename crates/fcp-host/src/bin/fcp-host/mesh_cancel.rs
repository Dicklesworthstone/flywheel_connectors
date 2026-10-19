//! Owner cancellation follows the retained original executor registration.
//! Placement changes and transport failures never authorize cancellation on
//! another peer or justify claiming that an operation has stopped.

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use chrono::Utc;
use fcp_core::TailscaleNodeId;
use fcp_host::{
    CancellationRequest, CancellationResponse, MeshInvocationIdentity, MeshInvocationObservation,
    MeshInvocationRecord, RelayCancellationBinding,
};
use fcp_mesh::invoke_route::{
    MAX_MESH_CANCELLATION_BODY_BYTES, MeshForwardBody, MeshForwardEnvelope, MeshForwardReply,
};

use super::{AppState, map_host_error, verified_cancellation_principal};

type CancelResult = Result<CancellationResponse, (StatusCode, String)>;

fn unavailable(detail: &str) -> (StatusCode, String) {
    (StatusCode::BAD_GATEWAY, detail.to_owned())
}

/// Return only the final possibly delivered target from retained operation evidence.
fn original_executor(
    record: &MeshInvocationRecord,
    operation_id: &str,
    principal: &str,
    local_node: &str,
) -> Result<TailscaleNodeId, (StatusCode, String)> {
    match &record.intent.identity {
        MeshInvocationIdentity::VerifiedPrincipal { principal: owner } if owner == principal => {}
        MeshInvocationIdentity::VerifiedPrincipal { .. } => {
            return Err((
                StatusCode::FORBIDDEN,
                "cancellation principal does not own the retained mesh invocation".to_owned(),
            ));
        }
        MeshInvocationIdentity::TokenBoundRelay { .. } => {
            // The opaque record selects routing custody only. Its token digest
            // and asserted principal never establish cancellation ownership.
            // The executor verifies the current cancel-self capability and
            // atomically matches its actual owner, origin, and invocation.
        }
    }
    if record.ticket.operation_id != operation_id
        || record.intent.operation_id != operation_id
        || record.ticket.attempt_id == 0
        || record.intent.origin_node != local_node
    {
        return Err(unavailable(
            "retained mesh cancellation identity is inconsistent",
        ));
    }
    let Some((last, previous)) = record.attempts.split_last() else {
        return Err(unavailable("no original mesh executor was retained"));
    };
    if record.attempts[0].target_node != record.intent.target_node
        || previous
            .iter()
            .any(|attempt| attempt.observation != Some(MeshInvocationObservation::NotDelivered))
        || last.target_node.trim().is_empty()
        || last.target_node == local_node
    {
        return Err(unavailable(
            "retained mesh executor selection is inconsistent",
        ));
    }
    if last.observation == Some(MeshInvocationObservation::NotDelivered) {
        return Err((
            StatusCode::CONFLICT,
            "the retained invocation was not delivered to any executor".to_owned(),
        ));
    }
    Ok(TailscaleNodeId::new(last.target_node.clone()))
}

/// The HTTP handler has already verified the current cancel-self capability.
pub(super) async fn route(
    state: &Arc<AppState>,
    request: &CancellationRequest,
    verified_principal: &str,
) -> CancelResult {
    // One snapshot selects the greatest shared generation across local and
    // mesh records. Never fall back to an older remote record after ID reuse.
    let observed = state
        .lifecycle
        .invocation_observation(&request.operation_id, None)
        .await;
    let Some(record) = observed.mesh_invocation else {
        return state
            .cancellation
            .cancel(request, Some(verified_principal), Utc::now())
            .map_err(map_host_error);
    };
    let router = state.mesh.as_ref().ok_or_else(|| {
        unavailable("the original mesh executor cannot be reached without a configured router")
    })?;
    let target = original_executor(
        &record,
        &request.operation_id,
        verified_principal,
        router.local_node().as_str(),
    )?;
    let request_json = serde_json::to_string(request)
        .map_err(|_| unavailable("cancellation request could not be encoded"))?;
    if request_json.len() > MAX_MESH_CANCELLATION_BODY_BYTES {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            "mesh cancellation request exceeds its bounded body limit".to_owned(),
        ));
    }
    let body = MeshForwardBody::Cancel {
        request_json,
        origin_attempt_id: record.ticket.attempt_id,
    };
    // One target, one attempt, and a small independent admission lane. A failed
    // or unverified exchange cannot establish that the remote work stopped.
    let reply =
        fcp_async_core::time::timeout(Duration::from_secs(5), router.forward(&target, body))
            .await
            .map_err(|_| unavailable("remote cancellation timed out; its outcome is unknown"))?
            .map_err(|_| {
                unavailable("remote cancellation could not be verified; its outcome is unknown")
            })?;
    validate_reply(request, &reply)
}

fn validate_reply(request: &CancellationRequest, reply: &MeshForwardReply) -> CancelResult {
    if reply.status != StatusCode::OK.as_u16() {
        let status = StatusCode::from_u16(reply.status)
            .ok()
            .filter(|status| status.is_client_error() || status.is_server_error())
            .unwrap_or(StatusCode::BAD_GATEWAY);
        // Signed peer errors can contain sensitive details. Preserve their
        // status without copying the body into the public entry-host response.
        return Err((
            status,
            "original executor did not accept owner cancellation".to_owned(),
        ));
    }
    let response: CancellationResponse = serde_json::from_str(&reply.body_json)
        .map_err(|_| unavailable("remote cancellation reply is invalid; its outcome is unknown"))?;
    if response.operation_id != request.operation_id {
        return Err(unavailable(
            "remote cancellation reply names a different operation; its outcome is unknown",
        ));
    }
    Ok(response)
}

/// Execute only after the outer mesh handler authenticates and consumes the nonce.
pub(super) async fn execute(
    state: &Arc<AppState>,
    envelope: &MeshForwardEnvelope,
    request_json: &str,
    origin_attempt_id: u64,
) -> CancelResult {
    if !matches!(
        &envelope.body,
        MeshForwardBody::Cancel {
            request_json: signed_request,
            origin_attempt_id: signed_attempt,
        } if signed_request == request_json
            && *signed_attempt == origin_attempt_id
            && origin_attempt_id != 0
    ) {
        return Err((
            StatusCode::BAD_REQUEST,
            "cancellation arguments do not match the signed request".to_owned(),
        ));
    }
    let router = state
        .mesh
        .as_ref()
        .ok_or_else(|| unavailable("mesh cancellation executor has no configured router"))?;
    let origin = router.cancellation_origin(envelope).map_err(|error| {
        (
            super::mesh_forward_error_status(&error),
            "cancellation origin is not authorized".to_owned(),
        )
    })?;
    let request: CancellationRequest = serde_json::from_str(request_json).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "forwarded cancellation request is invalid".to_owned(),
        )
    })?;
    let principal = verified_cancellation_principal(state.as_ref(), &request)
        .await
        .map_err(map_host_error)?;
    // Capability verification may wait for storage. Recheck the same signed
    // request and continuous origin authority immediately before the atomic
    // owner + original-registration check in the cancellation controller.
    router
        .check_cancellation_origin(&origin, envelope)
        .map_err(|error| {
            (
                super::mesh_forward_error_status(&error),
                "cancellation origin authority changed".to_owned(),
            )
        })?;
    state
        .cancellation
        .cancel_relay(
            &request,
            &principal,
            &RelayCancellationBinding {
                origin_node: envelope.origin_node.as_str().to_owned(),
                origin_attempt_id,
            },
            Utc::now(),
        )
        .map_err(map_host_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, extract::State};
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_host::{
        CancelReason, CancellationController, CancellationOutcome, CancellationScope,
        CleanupBehavior, ConnectorArchetype, InvocationTicket, MeshInvocationAttempt,
        MeshInvocationIntent, MeshRouter, MeshRoutingSettings,
    };
    use fcp_mesh::invoke_route::MeshPeerDirectory;

    fn request(operation_id: &str) -> CancellationRequest {
        CancellationRequest {
            operation_id: operation_id.to_owned(),
            reason: CancelReason::UserRequested,
            cleanup: CleanupBehavior::BestEffort,
            return_partial: false,
            capability_token: None,
        }
    }

    fn record() -> MeshInvocationRecord {
        let now = Utc::now();
        MeshInvocationRecord {
            ticket: InvocationTicket {
                operation_id: "remote-op".to_owned(),
                attempt_id: 7,
            },
            intent: MeshInvocationIntent {
                operation_id: "remote-op".to_owned(),
                connector_id: "fcp.test:utility:1.0.0".to_owned(),
                operation: "test.echo".to_owned(),
                zone_id: "z:work".to_owned(),
                origin_node: "origin".to_owned(),
                target_node: "executor-a".to_owned(),
                identity: MeshInvocationIdentity::VerifiedPrincipal {
                    principal: "alice".to_owned(),
                },
                correlation_id: None,
                deadline_at: now + chrono::Duration::seconds(60),
                idempotency: None,
                transport_idempotency: None,
            },
            admitted_at: now,
            attempts: vec![MeshInvocationAttempt {
                target_node: "executor-a".to_owned(),
                selected_at: now,
                observation: None,
            }],
            terminal: None,
            finished_at: None,
            durable: false,
        }
    }

    #[test]
    fn cancellation_selects_only_original_possibly_delivered_executor() {
        let mut retained = record();
        assert_eq!(
            original_executor(&retained, "remote-op", "alice", "origin")
                .unwrap()
                .as_str(),
            "executor-a",
        );
        assert_eq!(
            original_executor(&retained, "remote-op", "bob", "origin")
                .unwrap_err()
                .0,
            StatusCode::FORBIDDEN,
        );
        retained.attempts.push(MeshInvocationAttempt {
            target_node: "executor-b".to_owned(),
            selected_at: Utc::now(),
            observation: Some(MeshInvocationObservation::OutcomeUnknown),
        });
        assert!(original_executor(&retained, "remote-op", "alice", "origin").is_err());
        retained.attempts[0].observation = Some(MeshInvocationObservation::NotDelivered);
        assert_eq!(
            original_executor(&retained, "remote-op", "alice", "origin")
                .unwrap()
                .as_str(),
            "executor-b",
        );
        assert!(original_executor(&retained, "remote-op", "alice", "other-origin").is_err());
        assert!(original_executor(&retained, "other-op", "alice", "origin").is_err());
        retained.attempts[1].observation = Some(MeshInvocationObservation::NotDelivered);
        assert_eq!(
            original_executor(&retained, "remote-op", "alice", "origin")
                .unwrap_err()
                .0,
            StatusCode::CONFLICT,
        );
    }

    #[test]
    fn transparent_relay_retains_routing_without_claiming_an_owner() {
        let mut retained = record();
        retained.intent.identity = MeshInvocationIdentity::TokenBoundRelay {
            capability_digest: "opaque-token-digest".to_owned(),
            asserted_principal: Some("mallory".to_owned()),
        };
        // Neither the opaque digest nor the asserted identity grants ownership.
        // Both authenticated callers reach the same retained executor, where
        // the actual owner is checked against the newly verified capability.
        for principal in ["alice", "mallory"] {
            assert_eq!(
                original_executor(&retained, "remote-op", principal, "origin")
                    .unwrap()
                    .as_str(),
                "executor-a",
            );
        }
    }

    #[fcp_async_core::test]
    #[allow(clippy::too_many_lines)]
    async fn transparent_relay_cancellation_reaches_signed_executor_and_enforces_actual_owner() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        use axum::{Json, Router, extract::State, routing::post};
        use fcp_async_core::{net::TcpListener, task};
        use fcp_crypto::ed25519::Ed25519SigningKey;
        use fcp_host::mesh_routing::{MESH_FORWARD_ROUTE, MeshRouter, MeshRoutingSettings};
        use fcp_host::{CancellationOutcome, CancellationScope, ConnectorArchetype};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let origin_key = Ed25519SigningKey::generate();
        let executor_key = Ed25519SigningKey::generate();
        let origin_key_hex = hex::encode(origin_key.verifying_key().to_bytes());
        let executor_key_hex = hex::encode(executor_key.verifying_key().to_bytes());
        let origin_router = Arc::new(
            MeshRouter::new(MeshRoutingSettings {
                node_id: TailscaleNodeId::new("origin"),
                signing_key: origin_key,
                peers_json: serde_json::json!([{
                    "node_id": "executor-a",
                    "endpoint": endpoint,
                    "public_key_hex": executor_key_hex,
                }])
                .to_string(),
                forward_timeout: Duration::from_secs(5),
            })
            .unwrap(),
        );
        let executor_router = Arc::new(
            MeshRouter::new(MeshRoutingSettings {
                node_id: TailscaleNodeId::new("executor-a"),
                signing_key: executor_key,
                peers_json: serde_json::json!([{
                    "node_id": "origin",
                    "endpoint": "http://127.0.0.1:1",
                    "public_key_hex": origin_key_hex,
                }])
                .to_string(),
                forward_timeout: Duration::from_secs(5),
            })
            .unwrap(),
        );
        let base = super::super::tests::cancel_route_test_state();
        let origin = Arc::new(AppState {
            mesh: Some(origin_router),
            ..(*base).clone()
        });
        let executor_base = super::super::tests::cancel_route_test_state();
        let executor = Arc::new(AppState {
            // Both hosts consult the same fixture issuer ledger, and each
            // independently verifies the current capability through its route.
            lifecycle: Arc::clone(&origin.lifecycle),
            mesh: Some(executor_router),
            ..(*executor_base).clone()
        });
        let mut intent = record().intent;
        intent.identity = MeshInvocationIdentity::TokenBoundRelay {
            capability_digest: "ab".repeat(32),
            asserted_principal: Some("mallory".to_owned()),
        };
        let ticket = origin
            .lifecycle
            .reserve_mesh_invocation(intent)
            .await
            .unwrap();
        let mut scope = CancellationScope::new(
            "fcp.test:utility:1.0.0",
            ConnectorArchetype::RequestResponse,
        );
        scope.relay = Some(RelayCancellationBinding {
            origin_node: "origin".to_owned(),
            origin_attempt_id: ticket.attempt_id,
        });
        executor
            .cancellation
            .track_operation("remote-op", Some("alice"), scope)
            .unwrap();

        let received = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&received);
        let expected_attempt = ticket.attempt_id;
        let app = Router::new()
            .route(
                MESH_FORWARD_ROUTE,
                post(
                    move |state: State<Arc<AppState>>, envelope: Json<MeshForwardEnvelope>| {
                        let observed = Arc::clone(&observed);
                        async move {
                            assert_eq!(envelope.0.origin_node.as_str(), "origin");
                            assert!(matches!(
                                &envelope.0.body,
                                MeshForwardBody::Cancel { origin_attempt_id, .. }
                                    if *origin_attempt_id == expected_attempt
                            ));
                            observed.fetch_add(1, Ordering::SeqCst);
                            super::super::mesh_forward_handler(state, envelope).await
                        }
                    },
                ),
            )
            .with_state(Arc::clone(&executor));
        let (shutdown_tx, shutdown_rx) = fcp_async_core::channel::watch::channel(false);
        let server =
            task::spawn(async move { super::super::serve_tcp(listener, app, shutdown_rx).await });

        let mut denied_request = request("remote-op");
        denied_request.capability_token = Some(
            super::super::tests::issue_cancel_self_test_token(&origin.lifecycle, "mallory").await,
        );
        let denial =
            super::super::cancel_self_handler(State(Arc::clone(&origin)), Json(denied_request))
                .await
                .unwrap_err();
        assert_eq!(denial.0, StatusCode::FORBIDDEN);
        assert_eq!(received.load(Ordering::SeqCst), 1);
        assert!(!executor.cancellation.is_cancel_requested("remote-op"));
        assert!(executor.cancellation.audit_events().is_empty());

        let mut owner_request = request("remote-op");
        owner_request.capability_token = Some(
            super::super::tests::issue_cancel_self_test_token(&origin.lifecycle, "alice").await,
        );
        let Json(response) =
            super::super::cancel_self_handler(State(Arc::clone(&origin)), Json(owner_request))
                .await
                .unwrap();
        assert_eq!(response.outcome, CancellationOutcome::Cancelled);
        assert_eq!(received.load(Ordering::SeqCst), 2);
        assert!(executor.cancellation.is_cancel_requested("remote-op"));
        let retained = origin
            .lifecycle
            .invocation_observation("remote-op", None)
            .await
            .mesh_invocation
            .unwrap();
        assert!(matches!(
            retained.intent.identity,
            MeshInvocationIdentity::TokenBoundRelay {
                asserted_principal: Some(principal), ..
            } if principal == "mallory"
        ));

        shutdown_tx.send(true).unwrap();
        fcp_async_core::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("executor server must stop")
            .expect("executor server task")
            .expect("executor server");
    }

    fn signed_cancel(
        key: &Ed25519SigningKey,
        origin: &str,
        request: &CancellationRequest,
        attempt: u64,
    ) -> MeshForwardEnvelope {
        MeshForwardEnvelope::sign(
            key,
            TailscaleNodeId::new(origin),
            TailscaleNodeId::new("executor"),
            fcp_host::unix_now_ms(),
            MeshForwardBody::Cancel {
                request_json: serde_json::to_string(request).unwrap(),
                origin_attempt_id: attempt,
            },
        )
        .unwrap()
    }

    async fn signed_response(
        state: &Arc<AppState>,
        envelope: &MeshForwardEnvelope,
        executor_key: &Ed25519SigningKey,
    ) -> MeshForwardReply {
        let Json(reply) =
            super::super::mesh_forward_handler(State(Arc::clone(state)), Json(envelope.clone()))
                .await
                .unwrap();
        let directory = MeshPeerDirectory::from_json(
            envelope.origin_node.clone(),
            &serde_json::json!([{
                "node_id": "executor",
                "endpoint": "http://127.0.0.1:19001",
                "public_key_hex": hex::encode(executor_key.verifying_key().to_bytes()),
            }])
            .to_string(),
        )
        .unwrap();
        reply.verify_for(envelope, &directory).unwrap();
        reply
    }

    #[fcp_async_core::runtime::test]
    async fn signed_cancel_handler_checks_capability_owner_and_origin_attempt() {
        let mut state = super::super::tests::cancel_route_test_state();
        let origin_key = Ed25519SigningKey::generate();
        let other_key = Ed25519SigningKey::generate();
        let executor_key = Ed25519SigningKey::generate();
        let peers = serde_json::json!([
            {
                "node_id": "origin",
                "endpoint": "http://127.0.0.1:19002",
                "public_key_hex": hex::encode(origin_key.verifying_key().to_bytes()),
            },
            {
                "node_id": "other-origin",
                "endpoint": "http://127.0.0.1:19003",
                "public_key_hex": hex::encode(other_key.verifying_key().to_bytes()),
            },
        ])
        .to_string();
        Arc::get_mut(&mut state).unwrap().mesh = Some(Arc::new(
            MeshRouter::new(MeshRoutingSettings {
                node_id: TailscaleNodeId::new("executor"),
                signing_key: executor_key.clone(),
                peers_json: peers,
                forward_timeout: Duration::from_secs(5),
            })
            .unwrap(),
        ));
        let mut scope = CancellationScope::new("test", ConnectorArchetype::RequestResponse);
        scope.relay = Some(RelayCancellationBinding {
            origin_node: "origin".to_owned(),
            origin_attempt_id: 7,
        });
        let registration = state
            .cancellation
            .track_operation("remote-op", Some("alice"), scope.clone())
            .unwrap();
        let mut alice = request("remote-op");
        alice.capability_token = Some(
            super::super::tests::issue_cancel_self_test_token(state.lifecycle.as_ref(), "alice")
                .await,
        );
        let mut bob = request("remote-op");
        bob.capability_token = Some(
            super::super::tests::issue_cancel_self_test_token(state.lifecycle.as_ref(), "bob")
                .await,
        );

        for envelope in [
            signed_cancel(&origin_key, "origin", &request("remote-op"), 7),
            signed_cancel(&origin_key, "origin", &bob, 7),
            signed_cancel(&origin_key, "origin", &alice, 8),
            signed_cancel(&other_key, "other-origin", &alice, 7),
        ] {
            assert_eq!(
                signed_response(&state, &envelope, &executor_key)
                    .await
                    .status,
                403
            );
            assert!(!state.cancellation.is_cancel_requested("remote-op"));
        }

        let mut forged = signed_cancel(&origin_key, "origin", &alice, 7);
        forged.body = MeshForwardBody::Cancel {
            request_json: "{}".to_owned(),
            origin_attempt_id: 7,
        };
        let rejected = super::super::mesh_forward_handler(State(Arc::clone(&state)), Json(forged))
            .await
            .unwrap_err();
        assert_eq!(rejected.0, StatusCode::UNAUTHORIZED);
        assert!(!state.cancellation.is_cancel_requested("remote-op"));

        let accepted = signed_cancel(&origin_key, "origin", &alice, 7);
        let reply = signed_response(&state, &accepted, &executor_key).await;
        assert_eq!(
            validate_reply(&alice, &reply).unwrap().outcome,
            CancellationOutcome::Cancelled
        );
        assert!(state.cancellation.is_cancel_requested("remote-op"));
        let replay = super::super::mesh_forward_handler(State(Arc::clone(&state)), Json(accepted))
            .await
            .unwrap_err();
        assert_eq!(replay.0, StatusCode::CONFLICT);

        state.cancellation.complete_registration(&registration);
        let finished = signed_cancel(&origin_key, "origin", &alice, 7);
        let reply = signed_response(&state, &finished, &executor_key).await;
        assert_eq!(
            validate_reply(&alice, &reply).unwrap().outcome,
            CancellationOutcome::TooLate
        );
        scope.relay.as_mut().unwrap().origin_attempt_id = 8;
        state
            .cancellation
            .track_operation("remote-op", Some("alice"), scope)
            .unwrap();
        let stale = signed_cancel(&origin_key, "origin", &alice, 7);
        assert_eq!(
            signed_response(&state, &stale, &executor_key).await.status,
            403
        );
        assert!(!state.cancellation.is_cancel_requested("remote-op"));
    }

    #[test]
    fn malformed_or_mismatched_cancellation_reply_never_reports_success() {
        let request = request("remote-op");
        let controller = CancellationController::new();
        controller.track_with_owner("remote-op", Some("alice"));
        let response = controller
            .cancel(&request, Some("alice"), Utc::now())
            .unwrap();
        let key = Ed25519SigningKey::generate();
        let envelope = signed_cancel(&key, "origin", &request, 7);
        let mut reply = MeshForwardReply::sign(
            &key,
            TailscaleNodeId::new("executor"),
            &envelope,
            200,
            serde_json::to_string(&response).unwrap(),
        );
        assert!(validate_reply(&request, &reply).is_ok());
        let mut mismatched = response;
        mismatched.operation_id = "another-operation".to_owned();
        reply.body_json = serde_json::to_string(&mismatched).unwrap();
        assert_eq!(
            validate_reply(&request, &reply).unwrap_err().0,
            StatusCode::BAD_GATEWAY
        );
        reply.body_json = "not-json".to_owned();
        assert_eq!(
            validate_reply(&request, &reply).unwrap_err().0,
            StatusCode::BAD_GATEWAY
        );
        reply.status = 403;
        reply.body_json = "private-error-canary".to_owned();
        let error = validate_reply(&request, &reply).unwrap_err();
        assert_eq!(error.0, StatusCode::FORBIDDEN);
        assert!(!error.1.contains("private-error-canary"));
        reply.status = 201;
        assert_eq!(
            validate_reply(&request, &reply).unwrap_err().0,
            StatusCode::BAD_GATEWAY
        );
    }
}
