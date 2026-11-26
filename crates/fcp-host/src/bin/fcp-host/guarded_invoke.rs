//! Caller-imposed safety ceilings carried through ordinary host execution.
//!
//! A separate RPC route makes support mandatory: an older host must reject the
//! request instead of silently ignoring a new JSON field or request tag. The
//! tag is retained in the owned invocation and its effect digest, then checked
//! against live operation metadata at admission and dispatch. Mesh forwarding
//! uses distinct signed methods, so older peers reject guarded requests before
//! execution and an intermediary cannot downgrade their safety contract.

use std::sync::Arc;
use std::time::Instant;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use fcp_core::SafetyTier;
use fcp_host::{HostError, HostGuardedInvokeRequest, HostResult, PreflightResponse, SafetyTierExt};
use fcp_kernel::{InvokeRequest, InvokeResponse};

use super::AppState;
use super::mesh_forward_intake::RpcJson;

const MAX_SAFETY_TIER_TAG: &str = "fcp.host.max_safety_tier";

fn refusal(message: &str) -> HostError {
    HostError::PreflightFailed(message.to_owned())
}

fn ceiling_label(ceiling: SafetyTier) -> HostResult<&'static str> {
    match ceiling {
        SafetyTier::Safe => Ok("safe"),
        SafetyTier::Risky => Ok("risky"),
        SafetyTier::Dangerous => Ok("dangerous"),
        SafetyTier::Critical => Ok("critical"),
        SafetyTier::Forbidden => Err(refusal("forbidden is not a permitted invocation ceiling")),
    }
}

fn parse_ceiling(raw: Option<&str>) -> HostResult<Option<SafetyTier>> {
    match raw {
        None => Ok(None),
        Some("safe") => Ok(Some(SafetyTier::Safe)),
        Some("risky") => Ok(Some(SafetyTier::Risky)),
        Some("dangerous") => Ok(Some(SafetyTier::Dangerous)),
        Some("critical") => Ok(Some(SafetyTier::Critical)),
        Some(_) => Err(refusal("invalid invocation safety ceiling")),
    }
}

fn requested_ceiling(request: &InvokeRequest) -> HostResult<Option<SafetyTier>> {
    parse_ceiling(
        request
            .context
            .as_ref()
            .and_then(|context| context.request_tags.get(MAX_SAFETY_TIER_TAG))
            .map(String::as_str),
    )
}

fn constrain_request(envelope: HostGuardedInvokeRequest) -> HostResult<InvokeRequest> {
    let ceiling = envelope.max_safety_tier;
    let label = ceiling_label(ceiling)?;
    let mut request = envelope.request;
    if let Some(existing) = requested_ceiling(&request)?
        && existing != ceiling
    {
        return Err(refusal(
            "guarded invocation contains conflicting safety ceilings",
        ));
    }
    request
        .context
        .get_or_insert_with(Default::default)
        .request_tags
        .insert(MAX_SAFETY_TIER_TAG.to_owned(), label.to_owned());
    Ok(request)
}

/// Reused by normal admission and the final authority revalidation, so the
/// restriction survives durable ownership and every ordinary runtime path.
pub(super) fn enforce_tier(request: &InvokeRequest, actual: SafetyTier) -> HostResult<()> {
    if let Some(ceiling) = requested_ceiling(request)?
        && !actual.is_at_most(ceiling)
    {
        return Err(refusal(
            "operation exceeds the caller's invocation safety ceiling",
        ));
    }
    Ok(())
}

/// Select a distinct signed method whenever a caller carries a safety ceiling.
/// A tag alone is insufficient: older peers may ignore it on ordinary invokes.
pub(super) fn is_guarded(request: &InvokeRequest) -> HostResult<bool> {
    requested_ceiling(request).map(|ceiling| ceiling.is_some())
}

/// Guarded wire methods require their constraint even when a trusted peer signs
/// a malformed request. Peer authentication never substitutes for this contract.
pub(super) fn require_ceiling(request: &InvokeRequest) -> HostResult<()> {
    if !is_guarded(request)? {
        return Err(refusal(
            "guarded mesh request requires an explicit invocation safety ceiling",
        ));
    }
    Ok(())
}

pub(super) fn forward_invoke_body(
    request: &InvokeRequest,
    asserted_principal: Option<&str>,
    origin_attempt_id: u64,
) -> HostResult<fcp_mesh::invoke_route::MeshForwardBody> {
    use fcp_mesh::invoke_route::MeshForwardBody;

    let guarded = is_guarded(request)?;
    let request_json = serde_json::to_string(request).map_err(|error| {
        HostError::Internal(format!(
            "invoke request could not be encoded for mesh forwarding: {error}"
        ))
    })?;
    let asserted_principal = asserted_principal.map(str::to_owned);
    let origin_attempt_id = Some(origin_attempt_id);
    Ok(if guarded {
        MeshForwardBody::InvokeGuarded {
            request_json,
            asserted_principal,
            origin_attempt_id,
        }
    } else {
        MeshForwardBody::Invoke {
            request_json,
            asserted_principal,
            origin_attempt_id,
        }
    })
}

/// The executor runs the complete local preflight under the budget captured
/// before signature/replay admission. No connector invocation occurs here.
pub(super) async fn local_preflight(
    state: &AppState,
    request: &InvokeRequest,
    asserted_principal: Option<&str>,
    deadline: Instant,
) -> PreflightResponse {
    let result = super::before_invoke_route_deadline(
        deadline,
        async {
            require_ceiling(request)?;
            request.validate_idempotency_key().map_err(|error| {
                HostError::InvalidFilter(format!("invalid guarded invoke request: {error}"))
            })?;
            let fence = state
                .lifecycle
                .connector_execution_fence(&request.connector_id)
                .await?;
            let response = super::evaluate_live_preflight(state, request, asserted_principal).await;
            fence.require_current()?;
            Ok(response)
        },
        "guarded preflight",
    )
    .await
    .and_then(std::convert::identity);
    result.unwrap_or_else(super::preflight_response_from_error)
}

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/rpc/preflight/guarded", post(preflight_handler))
        .route("/rpc/invoke/guarded", post(invoke_handler))
}

async fn preflight_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    RpcJson {
        value: envelope,
        permit: _permit,
    }: RpcJson<HostGuardedInvokeRequest>,
) -> Json<PreflightResponse> {
    let request = match constrain_request(envelope) {
        Ok(request) => request,
        Err(error) => return Json(super::preflight_response_from_error(error)),
    };
    let asserted_principal = super::extract_principal_header(&headers);
    let deadline = super::http_batch::route_deadline(Instant::now(), request.deadline_ms, None);
    let result = super::before_invoke_route_deadline(
        deadline,
        async {
            request.validate_idempotency_key().map_err(|error| {
                HostError::InvalidFilter(format!("invalid guarded invoke request: {error}"))
            })?;
            let fence = state
                .lifecycle
                .connector_execution_fence(&request.connector_id)
                .await?;
            if let Some(router) = state.mesh.as_ref() {
                let decision = super::mesh_route_decision(
                    &state,
                    router,
                    &request.connector_id,
                    Some(&request.zone_id),
                    Some(request.operation.as_str()),
                )
                .await?;
                if let fcp_mesh::invoke_route::InvokeRouteDecision::Forward { target, .. } =
                    &decision
                {
                    if state
                        .registry
                        .allow_list_snapshot(&request.connector_id)
                        .await
                        .is_some()
                    {
                        let admission = super::evaluate_live_admission(
                            &state,
                            &request,
                            asserted_principal.as_deref(),
                            Some(target),
                            super::RateLimitMode::Inspect,
                        )
                        .await;
                        if !admission.allowed {
                            return Ok(admission);
                        }
                    }
                    let mut forwarded = request.clone();
                    super::constrain_invoke_deadline(&mut forwarded, deadline);
                    let request_json = serde_json::to_string(&forwarded).map_err(|error| {
                        HostError::Internal(format!(
                            "guarded preflight could not be encoded: {error}"
                        ))
                    })?;
                    fence.require_current()?;
                    let response = super::mesh_forward_query::<PreflightResponse>(
                        router,
                        decision,
                        fcp_mesh::invoke_route::MeshForwardBody::PreflightGuarded {
                            request_json,
                            asserted_principal: asserted_principal.clone(),
                        },
                    )
                    .await
                    .map_err(|(_, message)| HostError::Unavailable(message))?;
                    fence.require_current()?;
                    return Ok(response.response);
                }
            }
            let response =
                local_preflight(&state, &request, asserted_principal.as_deref(), deadline).await;
            fence.require_current()?;
            Ok(response)
        },
        "guarded preflight",
    )
    .await
    .and_then(std::convert::identity);
    Json(result.unwrap_or_else(super::preflight_response_from_error))
}

async fn invoke_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    RpcJson {
        value: envelope,
        permit,
    }: RpcJson<HostGuardedInvokeRequest>,
) -> Result<Json<InvokeResponse>, (StatusCode, String)> {
    let request = constrain_request(envelope).map_err(super::map_host_error)?;
    let asserted_principal = super::extract_principal_header(&headers);
    Box::pin(super::route_invoke_with_intake(
        &state,
        request,
        asserted_principal,
        None,
        Some(permit),
    ))
    .await
    .map(Json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_core::{ConnectorId, OperationId, RequestId, ZoneId};
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    fn request() -> InvokeRequest {
        let key = fcp_crypto::ed25519::Ed25519SigningKey::generate();
        InvokeRequest {
            r#type: "invoke".to_owned(),
            id: RequestId::random(),
            connector_id: ConnectorId::from_static("fcp.test.guarded:utility:1.0.0"),
            operation: OperationId::from_static("test.echo"),
            zone_id: ZoneId::work(),
            input: json!({"message": "guarded test"}),
            capability_token: crate::tests::test_capability_token(
                &key,
                "cap.test.echo",
                "test.echo",
                ZoneId::work().as_str(),
            ),
            holder_proof: None,
            context: None,
            idempotency_key: Some("guarded-test-effect".to_owned()),
            lease_seq: None,
            deadline_ms: Some(10_000),
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        }
    }

    #[test]
    fn guarded_ceiling_parser_rejects_unknown_or_ambiguous_values() {
        assert_eq!(parse_ceiling(None).unwrap(), None);
        for (raw, tier) in [
            ("safe", SafetyTier::Safe),
            ("risky", SafetyTier::Risky),
            ("dangerous", SafetyTier::Dangerous),
            ("critical", SafetyTier::Critical),
        ] {
            assert_eq!(parse_ceiling(Some(raw)).unwrap(), Some(tier));
            assert_eq!(ceiling_label(tier).unwrap(), raw);
        }
        for raw in ["", "Safe", " safe", "safe ", "forbidden", "unknown", "0"] {
            assert!(parse_ceiling(Some(raw)).is_err(), "{raw:?}");
        }
        assert!(ceiling_label(SafetyTier::Forbidden).is_err());
    }

    #[test]
    fn guarded_envelope_requires_an_explicit_known_ceiling() {
        let value = serde_json::to_value(HostGuardedInvokeRequest {
            request: request(),
            max_safety_tier: SafetyTier::Safe,
        })
        .unwrap();
        let parsed: HostGuardedInvokeRequest = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(parsed.max_safety_tier, SafetyTier::Safe);
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove("max_safety_tier");
        assert!(serde_json::from_value::<HostGuardedInvokeRequest>(missing).is_err());
        let mut misspelled = value;
        misspelled["max_safety_tire"] = json!("risky");
        assert!(serde_json::from_value::<HostGuardedInvokeRequest>(misspelled).is_err());
    }

    #[test]
    fn guarded_request_stamps_the_ceiling_without_rewriting_the_effect() {
        let mut input = request();
        let context = input.context.get_or_insert_with(Default::default);
        context.trace_id = Some("trace-id".to_owned());
        context
            .request_tags
            .insert("customer.region".to_owned(), "eu".to_owned());
        let original = serde_json::to_value(&input).unwrap();
        let constrained = constrain_request(HostGuardedInvokeRequest {
            request: input,
            max_safety_tier: SafetyTier::Safe,
        })
        .unwrap();
        let mut expected = original;
        expected["context"]["request_tags"][MAX_SAFETY_TIER_TAG] = json!("safe");
        assert_eq!(serde_json::to_value(&constrained).unwrap(), expected);
        assert_eq!(
            requested_ceiling(&constrained).unwrap(),
            Some(SafetyTier::Safe)
        );
    }

    #[test]
    fn guarded_request_rejects_conflicting_or_malformed_existing_restrictions() {
        for raw in ["risky", "critical", "forbidden", " safe", ""] {
            let mut input = request();
            input
                .context
                .get_or_insert_with(Default::default)
                .request_tags
                .insert(MAX_SAFETY_TIER_TAG.to_owned(), raw.to_owned());
            assert!(
                constrain_request(HostGuardedInvokeRequest {
                    request: input,
                    max_safety_tier: SafetyTier::Safe,
                })
                .is_err(),
                "{raw:?}"
            );
        }
        let constrained = constrain_request(HostGuardedInvokeRequest {
            request: request(),
            max_safety_tier: SafetyTier::Safe,
        })
        .unwrap();
        assert!(
            constrain_request(HostGuardedInvokeRequest {
                request: constrained,
                max_safety_tier: SafetyTier::Safe,
            })
            .is_ok()
        );
        assert!(
            constrain_request(HostGuardedInvokeRequest {
                request: request(),
                max_safety_tier: SafetyTier::Forbidden,
            })
            .is_err()
        );
    }

    #[test]
    fn guarded_request_enforces_every_tier_ceiling_and_rechecks_upgrades() {
        let tiers = [
            SafetyTier::Safe,
            SafetyTier::Risky,
            SafetyTier::Dangerous,
            SafetyTier::Critical,
            SafetyTier::Forbidden,
        ];
        for (maximum, ceiling) in tiers[..4].iter().copied().enumerate() {
            let constrained = constrain_request(HostGuardedInvokeRequest {
                request: request(),
                max_safety_tier: ceiling,
            })
            .unwrap();
            for (level, tier) in tiers.iter().copied().enumerate() {
                assert_eq!(enforce_tier(&constrained, tier).is_ok(), level <= maximum);
            }
        }
        let constrained = constrain_request(HostGuardedInvokeRequest {
            request: request(),
            max_safety_tier: SafetyTier::Safe,
        })
        .unwrap();
        enforce_tier(&constrained, SafetyTier::Safe).expect("initial catalog");
        assert!(
            enforce_tier(&constrained, SafetyTier::Risky).is_err(),
            "upgraded catalog must be denied at dispatch"
        );
    }

    #[test]
    fn guarded_forwarding_selects_a_distinct_signed_method_and_preserves_authority() {
        let plain = request();
        assert!(!is_guarded(&plain).unwrap());
        assert!(require_ceiling(&plain).is_err());
        let ordinary = forward_invoke_body(&plain, Some("agent:test"), 7).unwrap();
        assert_eq!(ordinary.method(), "invoke");

        let guarded = constrain_request(HostGuardedInvokeRequest {
            request: plain,
            max_safety_tier: SafetyTier::Safe,
        })
        .unwrap();
        assert!(is_guarded(&guarded).unwrap());
        require_ceiling(&guarded).expect("guarded local and remote execution");
        let body = forward_invoke_body(&guarded, Some("agent:test"), 7).unwrap();
        assert_eq!(body.method(), "invoke_guarded");
        let encoded = serde_json::to_value(body).unwrap();
        assert_eq!(encoded["asserted_principal"], "agent:test");
        assert_eq!(encoded["origin_attempt_id"], 7);
        let forwarded: InvokeRequest =
            serde_json::from_str(encoded["request_json"].as_str().unwrap()).unwrap();
        assert_eq!(
            serde_json::to_value(forwarded).unwrap(),
            serde_json::to_value(guarded).unwrap()
        );

        let mut malformed = request();
        malformed
            .context
            .get_or_insert_with(Default::default)
            .request_tags
            .insert(MAX_SAFETY_TIER_TAG.to_owned(), "garbage".to_owned());
        assert!(is_guarded(&malformed).is_err());
        assert!(require_ceiling(&malformed).is_err());
        assert!(forward_invoke_body(&malformed, None, 7).is_err());
        assert!(enforce_tier(&malformed, SafetyTier::Safe).is_err());
    }

    struct LiveFixture {
        state: Arc<AppState>,
        request: InvokeRequest,
        upgraded: Arc<AtomicBool>,
        invoke_count: Arc<AtomicUsize>,
    }

    fn live_fixture() -> LiveFixture {
        use crate::tests::{
            dispatcher_app_state, dispatcher_introspection, dispatcher_registry_with_connector,
            dispatcher_test_config, dispatcher_test_connector, test_capability_token,
        };

        const CONNECTOR: &str = "fcp.test.guarded:utility:1.0.0";
        const OPERATION: &str = "test.echo";
        const CAPABILITY: &str = "cap.test.echo";
        let key = fcp_crypto::ed25519::Ed25519SigningKey::generate();
        let upgraded = Arc::new(AtomicBool::new(false));
        let live_tier = Arc::clone(&upgraded);
        let invoke_count = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&invoke_count);
        let (sender, mut receiver) =
            fcp_async_core::channel::mpsc::channel::<crate::ConnectorRpcRequest>(8);
        let actor = fcp_async_core::task::spawn(async move {
            while let Some(call) = receiver.recv().await {
                if !call.rpc.try_begin() {
                    let _ = call.response_tx.send(Err(call.rpc.stop_error()));
                    continue;
                }
                let result = match call.method.as_str() {
                    "introspect" => serde_json::to_value(dispatcher_introspection(
                        OPERATION,
                        CAPABILITY,
                        if live_tier.load(Ordering::SeqCst) {
                            SafetyTier::Risky
                        } else {
                            SafetyTier::Safe
                        },
                    ))
                    .unwrap(),
                    "health" => json!({"status": {"state": "ready"}, "uptime_ms": 0}),
                    "invoke" => {
                        count.fetch_add(1, Ordering::SeqCst);
                        let received: InvokeRequest = serde_json::from_value(call.params).unwrap();
                        assert_eq!(
                            requested_ceiling(&received).unwrap(),
                            Some(SafetyTier::Safe)
                        );
                        serde_json::to_value(InvokeResponse::ok(
                            received.id,
                            json!({"accepted": true}),
                        ))
                        .unwrap()
                    }
                    method => panic!("unexpected guarded fixture method {method}"),
                };
                assert!(call.rpc.try_settle_reply());
                let _ = call.response_tx.send(Ok(json!({"result": result})));
            }
        });
        let connector = dispatcher_test_connector(CONNECTOR, sender, actor);
        let registry = dispatcher_registry_with_connector(
            CONNECTOR,
            connector,
            dispatcher_test_config(CONNECTOR),
        );
        let state = dispatcher_app_state(
            registry,
            Arc::new(fcp_host::HostAdminStateStore::new()),
            Some(key.verifying_key()),
            HashMap::from([(ZoneId::work(), crate::host_runtime_policy(ZoneId::work()))]),
        );
        let mut request = request();
        request.capability_token =
            test_capability_token(&key, CAPABILITY, OPERATION, ZoneId::work().as_str());
        LiveFixture {
            state,
            request,
            upgraded,
            invoke_count,
        }
    }

    #[fcp_async_core::runtime::test]
    async fn guarded_preflight_and_invoke_use_normal_authorized_execution() {
        let fixture = live_fixture();
        let envelope = HostGuardedInvokeRequest {
            request: fixture.request,
            max_safety_tier: SafetyTier::Safe,
        };
        let Json(preflight) = preflight_handler(
            State(Arc::clone(&fixture.state)),
            HeaderMap::new(),
            RpcJson::for_test(envelope.clone()),
        )
        .await;
        assert!(preflight.allowed, "{:?}", preflight.reason);
        assert_eq!(fixture.invoke_count.load(Ordering::SeqCst), 0);
        let Json(response) = invoke_handler(
            State(fixture.state),
            HeaderMap::new(),
            RpcJson::for_test(envelope),
        )
        .await
        .expect("safe guarded invocation");
        assert_eq!(response.status, fcp_kernel::InvokeStatus::Ok);
        assert_eq!(fixture.invoke_count.load(Ordering::SeqCst), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn guarded_invoke_rejects_a_tier_upgrade_after_successful_preflight() {
        let fixture = live_fixture();
        let envelope = HostGuardedInvokeRequest {
            request: fixture.request,
            max_safety_tier: SafetyTier::Safe,
        };
        let Json(preflight) = preflight_handler(
            State(Arc::clone(&fixture.state)),
            HeaderMap::new(),
            RpcJson::for_test(envelope.clone()),
        )
        .await;
        assert!(preflight.allowed, "{:?}", preflight.reason);
        fixture.upgraded.store(true, Ordering::SeqCst);
        let error = invoke_handler(
            State(Arc::clone(&fixture.state)),
            HeaderMap::new(),
            RpcJson::for_test(envelope.clone()),
        )
        .await
        .expect_err("a ceiling cannot be widened by metadata changes");
        assert!(error.1.contains("safety ceiling"), "{error:?}");
        let Json(rechecked) = preflight_handler(
            State(fixture.state),
            HeaderMap::new(),
            RpcJson::for_test(envelope),
        )
        .await;
        assert!(!rechecked.allowed);
        assert!(rechecked.reason.unwrap().contains("safety ceiling"));
        assert_eq!(fixture.invoke_count.load(Ordering::SeqCst), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn guarded_ceiling_never_substitutes_for_capability_authority() {
        let fixture = live_fixture();
        // The structural request uses an independently generated signing key.
        let envelope = HostGuardedInvokeRequest {
            request: request(),
            max_safety_tier: SafetyTier::Safe,
        };
        let Json(preflight) = preflight_handler(
            State(Arc::clone(&fixture.state)),
            HeaderMap::new(),
            RpcJson::for_test(envelope.clone()),
        )
        .await;
        assert!(!preflight.allowed);
        assert!(
            preflight
                .reason
                .unwrap()
                .contains("capability token rejected")
        );
        assert!(
            invoke_handler(
                State(fixture.state),
                HeaderMap::new(),
                RpcJson::for_test(envelope)
            )
            .await
            .is_err()
        );
        assert_eq!(fixture.invoke_count.load(Ordering::SeqCst), 0);
    }
}
