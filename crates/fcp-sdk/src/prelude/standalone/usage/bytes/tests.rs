use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{Duration, Utc};
use fcp_core::{CapabilityConstraints, CapabilityId, ConnectorId, InstanceId};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use serde_json::json;

use super::*;

const LIMIT: u64 = 100_000;

fn handshake(session: &mut StandaloneSession, key: &Ed25519SigningKey) {
    session
        .handshake(
            serde_json::from_value(json!({
                "protocol_version": "2.0.0", "zone": "z:work",
                "host_public_key": key.verifying_key().to_bytes().to_vec(),
                "nonce": vec![7_u8; 32], "capabilities_requested": ["fixture.read"],
            }))
            .unwrap(),
        )
        .unwrap();
}

fn signed_request(
    session: &StandaloneSession,
    key: &Ed25519SigningKey,
    calls: Option<u32>,
    bytes: Option<u64>,
    id: &[u8],
    key_scope: Option<&str>,
) -> InvokeRequest {
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        max_calls: calls,
        max_bytes: bytes,
        idempotency_key: key_scope.map(str::to_owned),
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).unwrap();
    let now = Utc::now();
    let token = CapabilityToken::from_raw(
        CapabilityTokenBuilder::new()
            .capability_id("fixture.read")
            .zone_id("z:work")
            .principal("user:test")
            .operations(&["fixture.get"])
            .issuer("node:test")
            .target_instance(session.instance_id().as_str())
            .token_id(id)
            .validity(now - Duration::minutes(1), now + Duration::hours(1))
            .try_constraints_cbor(&cbor)
            .unwrap()
            .sign(key)
            .unwrap(),
    );
    serde_json::from_value(json!({
        "type": "invoke", "id": "request-1", "connector_id": "fcp.fixture",
        "operation": "fixture.get", "zone_id": "z:work", "input": {},
        "capability_token": token, "idempotency_key": key_scope,
    }))
    .unwrap()
}

fn fixture(
    calls: Option<u32>,
    bytes: Option<u64>,
) -> (StandaloneSession, Ed25519SigningKey, InvokeRequest) {
    let mut session = StandaloneSession {
        connector_id: ConnectorId::from_static("fcp.fixture"),
        instance_id: InstanceId::new(),
        manifest_hash: "fixture".into(),
        operations: BTreeMap::from([(
            "fixture.get".into(),
            CapabilityId::from_static("fixture.read"),
        )]),
        forbidden_zones: Default::default(),
        authority: None,
    };
    let key = Ed25519SigningKey::from_bytes(&[43; 32]).unwrap();
    handshake(&mut session, &key);
    let request = signed_request(&session, &key, calls, bytes, b"byte-grant", None);
    (session, key, request)
}

fn ledger(session: &StandaloneSession) -> &UsageLedger {
    &session.authority.as_ref().unwrap().usage
}

fn totals(session: &StandaloneSession) -> (u32, u64) {
    let entries = ledger(session).lock().unwrap();
    (
        entries.values().map(|a| a.spent).sum(),
        entries.values().map(|a| a.bytes).sum(),
    )
}

fn response(request: &InvokeRequest) -> InvokeResponse {
    InvokeResponse::ok(request.id.clone(), json!({"content": "hello"}))
}

fn scope(session: &StandaloneSession, request: &InvokeRequest) -> Scope {
    let token = session
        .authorize(
            &request.connector_id,
            &request.zone_id,
            &request.operation,
            request.capability_token.clone(),
            &[],
        )
        .unwrap();
    Scope::from_verified(&token).unwrap()
}

fn remaining(session: &StandaloneSession, request: &InvokeRequest, bytes: u64) {
    let scope = scope(session, request);
    ledger(session).lock().unwrap().insert(
        scope.key.unwrap(),
        Account {
            grant: scope.grant,
            spent: 0,
            bytes: scope.constraints.max_bytes.unwrap() - bytes,
        },
    );
}

fn assert_unknown(error: FcpError) {
    let text = error.to_string();
    assert!(text.contains("outcome is unknown"));
    assert!(!text.contains("private-payload"));
    assert!(matches!(
        error,
        FcpError::External {
            retryable: false,
            retry_after: None,
            ..
        }
    ));
}

#[test]
fn counter_matches_complete_compact_json_including_utf8_and_escaping() {
    for value in [
        json!(null),
        json!({"text": "é\n\"\\雪"}),
        json!([0, u64::MAX, true]),
    ] {
        let expected = u64::try_from(serde_json::to_vec(&value).unwrap().len()).unwrap();
        assert_eq!(json_bytes(&value, expected), Ok(expected));
        assert!(json_bytes(&value, expected - 1).is_err());
    }
    let (_, _, request) = fixture(Some(2), Some(LIMIT));
    assert_eq!(
        json_bytes(&request, LIMIT).unwrap(),
        u64::try_from(serde_json::to_vec(&request).unwrap().len()).unwrap()
    );
}

#[test]
fn completion_charges_full_messages_and_only_releases_unused_response_bytes() {
    let (session, _, request) = fixture(Some(3), Some(LIMIT));
    let reply = response(&request);
    let request_bytes = json_bytes(&request, LIMIT).unwrap();
    let response_bytes = json_bytes(&reply, LIMIT).unwrap();
    for count in 1..=3_u32 {
        let permit = session.admit_bounded(&request, &[], 1_000).unwrap();
        assert_eq!(permit.response_byte_limit(), Some(1_000));
        permit.finish_response(&reply).unwrap();
        assert_eq!(
            totals(&session),
            (count, u64::from(count) * (request_bytes + response_bytes))
        );
    }
    assert!(session.admit_bounded(&request, &[], 1_000).is_err());
}

#[test]
fn exact_remaining_ceiling_allows_one_complete_response_then_denies() {
    let (session, _, request) = fixture(None, Some(LIMIT));
    let reply = response(&request);
    let request_bytes = json_bytes(&request, LIMIT).unwrap();
    let response_bytes = json_bytes(&reply, LIMIT).unwrap();
    remaining(&session, &request, request_bytes + response_bytes);
    let permit = session.admit_bounded(&request, &[], LIMIT).unwrap();
    assert_eq!(permit.response_byte_limit(), Some(response_bytes));
    permit.finish_response(&reply).unwrap();
    assert_eq!(totals(&session).1, LIMIT);
    assert!(session.admit_bounded(&request, &[], LIMIT).is_err());
}

#[test]
fn oversized_response_is_withheld_without_refund_or_replay_permission() {
    let (session, _, request) = fixture(Some(2), Some(LIMIT));
    let reply = InvokeResponse::ok(request.id.clone(), json!({"data": "private-payload"}));
    let cap = json_bytes(&reply, LIMIT).unwrap() - 1;
    let permit = session.admit_bounded(&request, &[], cap).unwrap();
    let charged = totals(&session);
    assert_unknown(permit.finish_response(&reply).unwrap_err());
    assert_eq!(totals(&session), charged);
}

#[test]
fn wrong_response_id_or_kind_cannot_release_a_reservation() {
    let (session, _, request) = fixture(None, Some(LIMIT));
    for wrong_kind in [false, true] {
        let permit = session.admit_bounded(&request, &[], 1_000).unwrap();
        let charged = totals(&session);
        let mut reply = response(&request);
        if wrong_kind {
            reply.r#type = "invoke".into();
        } else {
            reply.id = RequestId::new("another-request");
        }
        assert_unknown(permit.finish_response(&reply).unwrap_err());
        assert_eq!(totals(&session), charged);
    }
}

#[test]
fn drop_or_missing_destructor_never_restores_an_unknown_outcome() {
    for leak in [false, true] {
        let (session, _, request) = fixture(None, Some(LIMIT));
        let permit = session.admit_bounded(&request, &[], LIMIT).unwrap();
        assert_eq!(totals(&session).1, LIMIT);
        if leak {
            std::mem::forget(permit);
        } else {
            drop(permit);
        }
        assert!(session.admit_bounded(&request, &[], LIMIT).is_err());
    }
}

#[test]
fn legacy_admission_cannot_silently_ignore_finite_bytes() {
    let (session, _, request) = fixture(Some(1), Some(LIMIT));
    assert!(session.admit(&request, &[]).is_err());
    assert!(ledger(&session).lock().unwrap().is_empty());
    session.admit_bounded(&request, &[], 1_000).unwrap();
}

#[test]
fn zero_caps_and_missing_signed_byte_identity_fail_without_spending() {
    let (session, key, request) = fixture(Some(1), Some(LIMIT));
    for cap in [0, 1] {
        assert!(session.admit_bounded(&request, &[], cap).is_err());
    }
    for (bytes, id) in [(Some(0), b"zero".as_slice()), (Some(LIMIT), b"".as_slice())] {
        let request = signed_request(&session, &key, None, bytes, id, None);
        assert!(session.admit_bounded(&request, &[], 1_000).is_err());
    }
    assert!(ledger(&session).lock().unwrap().is_empty());
}

#[test]
fn byte_denial_does_not_spend_call_allowance_or_accept_alternate_counters() {
    let (session, _, mut request) = fixture(Some(1), Some(LIMIT));
    request.input = json!({"observed_bytes": 0, "request_bytes": 0, "data": "x".repeat(1_000)});
    let input_bytes = json_bytes(&request, LIMIT).unwrap();
    remaining(&session, &request, input_bytes);
    let charged = totals(&session);
    assert!(session.admit_bounded(&request, &[], 1_000).is_err());
    assert_eq!(totals(&session), charged);
    assert_eq!(charged.0, 0);
}

#[test]
fn invalid_signature_target_zone_and_key_scope_never_spend() {
    let (session, key, request) = fixture(Some(1), Some(LIMIT));
    let foreign = Ed25519SigningKey::from_bytes(&[44; 32]).unwrap();
    let mut rejected = vec![signed_request(
        &session,
        &foreign,
        Some(1),
        Some(LIMIT),
        b"foreign",
        None,
    )];
    let mut wrong_target = request.clone();
    wrong_target.connector_id = ConnectorId::from_static("fcp.other");
    rejected.push(wrong_target);
    let mut wrong_zone = request.clone();
    wrong_zone.zone_id = fcp_core::ZoneId::private();
    rejected.push(wrong_zone);
    let mut wrong_key = signed_request(
        &session,
        &key,
        Some(1),
        Some(LIMIT),
        b"key",
        Some("private-key"),
    );
    wrong_key.idempotency_key = Some("different".into());
    rejected.push(wrong_key);
    for request in rejected {
        assert!(session.admit_bounded(&request, &[], 1_000).is_err());
    }
    assert!(ledger(&session).lock().unwrap().is_empty());
}

#[test]
fn previews_neither_allocate_nor_reserve_bytes() {
    let (session, _, request) = fixture(None, Some(LIMIT));
    for _ in 0..20 {
        let _ = scope(&session, &request);
    }
    assert!(ledger(&session).lock().unwrap().is_empty());
    drop(session.admit_bounded(&request, &[], LIMIT).unwrap());
    assert!(
        session
            .authorize(
                &request.connector_id,
                &request.zone_id,
                &request.operation,
                request.capability_token.clone(),
                &[]
            )
            .is_err()
    );
}

#[test]
fn capacity_applies_to_byte_only_grants_without_eviction() {
    let (mut session, key, request) = fixture(None, Some(LIMIT));
    session.authority.as_mut().unwrap().usage.capacity = 1;
    session.admit_bounded(&request, &[], 1_000).unwrap();
    let second = signed_request(&session, &key, None, Some(LIMIT), b"second", None);
    assert!(matches!(
        session.admit_bounded(&second, &[], 1_000),
        Err(FcpError::ResourceExhausted { .. })
    ));
    let changed = signed_request(&session, &key, None, Some(LIMIT + 1), b"byte-grant", None);
    assert!(session.admit_bounded(&changed, &[], 1_000).is_err());
    assert_eq!(ledger(&session).lock().unwrap().len(), 1);
}

#[test]
fn concurrent_reservations_cannot_spend_the_same_remaining_bytes() {
    let (session, _, request) = fixture(None, Some(LIMIT));
    let token = session
        .authorize(
            &request.connector_id,
            &request.zone_id,
            &request.operation,
            request.capability_token.clone(),
            &[],
        )
        .unwrap();
    let scope = Scope::from_verified(&token).unwrap();
    let cost = json_bytes(&request, LIMIT).unwrap() + 1_000;
    let ledger = Arc::new(UsageLedger::default());
    ledger.lock().unwrap().insert(
        scope.key.unwrap(),
        Account {
            grant: scope.grant,
            spent: 0,
            bytes: LIMIT - 3 * cost,
        },
    );
    let admitted = std::thread::scope(|threads| {
        let handles: Vec<_> = (0..32)
            .map(|_| {
                let ledger = Arc::clone(&ledger);
                let token = token.clone();
                let request = &request;
                threads.spawn(move || ledger.admit_bounded(token, request, 1_000).is_ok())
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| usize::from(handle.join().unwrap()))
            .sum::<usize>()
    });
    assert_eq!(admitted, 3);
    assert_eq!(ledger.lock().unwrap().values().next().unwrap().bytes, LIMIT);
}

#[test]
fn maximum_byte_counter_cannot_wrap_into_new_allowance() {
    let (session, _, request) = fixture(None, Some(u64::MAX));
    let scope = scope(&session, &request);
    ledger(&session).lock().unwrap().insert(
        scope.key.unwrap(),
        Account {
            grant: scope.grant,
            spent: 0,
            bytes: u64::MAX,
        },
    );
    assert!(session.admit_bounded(&request, &[], u64::MAX).is_err());
    assert_eq!(totals(&session).1, u64::MAX);
}

#[test]
fn old_generation_completion_cannot_refund_into_rehandshaken_authority() {
    let (mut session, key, old_request) = fixture(None, Some(LIMIT));
    let old_permit = session.admit_bounded(&old_request, &[], 1_000).unwrap();
    handshake(&mut session, &key);
    let new_request = signed_request(&session, &key, None, Some(LIMIT), b"byte-grant", None);
    let new_permit = session.admit_bounded(&new_request, &[], 1_000).unwrap();
    let new_charged = totals(&session);
    old_permit.finish_response(&response(&old_request)).unwrap();
    assert_eq!(totals(&session), new_charged);
    assert!(session.admit_bounded(&old_request, &[], 1_000).is_err());
    new_permit.finish_response(&response(&new_request)).unwrap();
}

#[test]
fn poisoned_settlement_is_non_retryable_and_future_admission_fails_closed() {
    let (session, _, request) = fixture(None, Some(LIMIT));
    let permit = session.admit_bounded(&request, &[], 1_000).unwrap();
    let entries = Arc::clone(&ledger(&session).entries);
    let _ = std::thread::spawn(move || {
        let _guard = entries.lock().unwrap();
        panic!("test poison");
    })
    .join();
    assert_unknown(permit.finish_response(&response(&request)).unwrap_err());
    assert!(session.admit_bounded(&request, &[], 1_000).is_err());
}

#[test]
fn unmetered_grants_still_obey_runtime_response_cap_without_accounts() {
    let (mut session, _, request) = fixture(None, None);
    session.authority.as_mut().unwrap().usage.capacity = 0;
    let cap = json_bytes(&InvokeResponse::ok(request.id.clone(), json!(0)), LIMIT).unwrap();
    let permit = session.admit_bounded(&request, &[], cap).unwrap();
    assert_unknown(permit.finish_response(&response(&request)).unwrap_err());
    assert!(ledger(&session).lock().unwrap().is_empty());
    let permit = session.admit_bounded(&request, &[], 1_000).unwrap();
    permit.finish_response(&response(&request)).unwrap();
    assert!(ledger(&session).lock().unwrap().is_empty());
}

#[test]
fn request_metadata_and_response_metadata_are_not_free_bytes() {
    let (session, _, mut request) = fixture(None, Some(LIMIT));
    let baseline = json_bytes(&request, LIMIT).unwrap();
    request.context = Some(fcp_core::InvokeContext {
        locale: Some("en-US".into()),
        trace_id: Some("trace".repeat(100)),
        ..Default::default()
    });
    let request_bytes = json_bytes(&request, LIMIT).unwrap();
    assert!(request_bytes > baseline + 500);
    let mut reply = response(&request);
    reply.next_cursor = Some("cursor".repeat(100));
    let response_bytes = json_bytes(&reply, LIMIT).unwrap();
    let permit = session.admit_bounded(&request, &[], 10_000).unwrap();
    permit.finish_response(&reply).unwrap();
    assert_eq!(totals(&session).1, request_bytes + response_bytes);
}

#[test]
fn complete_error_response_is_bounded_but_never_refunds_failure() {
    let (session, _, request) = fixture(None, Some(LIMIT));
    let reply = InvokeResponse::error(request.id.clone(), invalid("provider failed"));
    let permit = session.admit_bounded(&request, &[], 1_000).unwrap();
    let charged = totals(&session);
    permit.finish_response(&reply).unwrap();
    assert_eq!(totals(&session), charged);
    let cap = json_bytes(&reply, LIMIT).unwrap() - 1;
    let permit = session.admit_bounded(&request, &[], cap).unwrap();
    let charged = totals(&session);
    assert_unknown(permit.finish_response(&reply).unwrap_err());
    assert_eq!(totals(&session), charged);
}

#[test]
fn malformed_success_or_error_envelopes_cannot_refund_reservations() {
    let (session, _, request) = fixture(None, Some(LIMIT));
    let mut reply = response(&request);
    reply.result = None;
    let permit = session.admit_bounded(&request, &[], 1_000).unwrap();
    let charged = totals(&session);
    assert_unknown(permit.finish_response(&reply).unwrap_err());
    assert_eq!(totals(&session), charged);
    let mut reply = response(&request);
    reply.status = InvokeStatus::Error;
    let permit = session.admit_bounded(&request, &[], 1_000).unwrap();
    let charged = totals(&session);
    assert_unknown(permit.finish_response(&reply).unwrap_err());
    assert_eq!(totals(&session), charged);
}

#[test]
fn settling_one_response_does_not_release_another_in_flight_reservation() {
    let (session, _, request) = fixture(None, Some(LIMIT));
    let first = session.admit_bounded(&request, &[], 1_000).unwrap();
    let second = session.admit_bounded(&request, &[], 1_000).unwrap();
    let request_bytes = json_bytes(&request, LIMIT).unwrap();
    let reply = response(&request);
    let response_bytes = json_bytes(&reply, LIMIT).unwrap();
    first.finish_response(&reply).unwrap();
    assert_eq!(
        totals(&session).1,
        2 * request_bytes + response_bytes + 1_000
    );
    drop(second);
    assert_eq!(
        totals(&session).1,
        2 * request_bytes + response_bytes + 1_000
    );
}
