use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use chrono::Utc;
use fcp_cbor::{CanonicalSerializer, SchemaId};
use fcp_crypto::Ed25519SigningKey;
use fcp_evidence::{ObjectHeader, ObjectIdKey, RetentionClass, StorageMeta, StoredObject};
use fcp_kernel::{
    ConnectorId, ConnectorStateModel, ConnectorStateObject, ConnectorStateRoot, ObjectId, ZoneId,
};
use fcp_policy::Provenance;
use fcp_prelude::Signature;
use fcp_store::{
    FcpStoreConnectorStateStore, MemoryObjectStore, MemoryObjectStoreConfig, ObjectStore,
};
use futures_util::future::pending;
use serde_json::{Value, json};

use super::*;
use crate::{
    ConnectorStateExportRequest, ConnectorStateTransferDirection, ConnectorStateTransferGrant,
    ConnectorStateTransferLimits, ConnectorStateTransferScope,
};

fn run<F: Future>(future: F) -> F::Output {
    fcp_async_core::runtime::block_on_sync(future).expect("test runtime")
}

fn scope() -> ConnectorStateTransferScope {
    ConnectorStateTransferScope {
        connector_id: ConnectorId::from_static("slack:chat:v1"),
        zone_id: ZoneId::work(),
        instance_id: None,
    }
}

fn key() -> ObjectIdKey {
    ObjectIdKey::from_bytes([42; 32])
}

fn writer() -> Ed25519SigningKey {
    Ed25519SigningKey::from_bytes(&[0x5a; 32]).unwrap()
}

fn adapter(objects: Arc<dyn ObjectStore>) -> Arc<FcpStoreConnectorStateStore> {
    Arc::new(
        FcpStoreConnectorStateStore::new(objects, key(), scope().connector_id, scope().zone_id)
            .with_trusted_writer_keys([writer().verifying_key().to_bytes()]),
    )
}

fn header(schema: SchemaId, refs: Vec<ObjectId>) -> ObjectHeader {
    ObjectHeader {
        encryption_kind: Default::default(),
        schema,
        zone_id: scope().zone_id,
        created_at: 1_700_000_000,
        provenance: Provenance::new(scope().zone_id),
        refs,
        foreign_refs: Vec::new(),
        ttl_secs: None,
        placement: None,
    }
}

fn stored(header: &ObjectHeader, value: &impl Serialize) -> StoredObject {
    let body = CanonicalSerializer::serialize(value, &header.schema).unwrap();
    StoredObject {
        object_id: StoredObject::derive_id(header, &body, &key()).unwrap(),
        header: header.clone(),
        body,
        storage: StorageMeta {
            retention: RetentionClass::Pinned,
        },
    }
}

struct Fixture {
    donors: Vec<ConnectorStateReplicationService>,
    recipient: ConnectorStateReplicationService,
    replica: Arc<FcpStoreConnectorStateStore>,
    request: ConnectorStateRecoveryRequest,
}

fn fixture(large: bool) -> Fixture {
    let source_objects = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
    let lease_id = ObjectId::from_bytes([0x17; 32]);
    // A canonical 48 KiB CBOR byte string requires multiple JSON wire pages.
    let state_cbor = if large {
        let mut bytes = vec![0x59, 0xc0, 0x00];
        bytes.extend(std::iter::repeat_n(b'x', 48 * 1024));
        bytes
    } else {
        vec![0xa1, 0x61, b'n', 0x00]
    };
    let mut state = ConnectorStateObject {
        header: header(
            FcpStoreConnectorStateStore::state_object_schema_id(),
            vec![lease_id],
        ),
        connector_id: scope().connector_id,
        instance_id: None,
        zone_id: scope().zone_id,
        prev: None,
        seq: 0,
        state_cbor,
        updated_at: 1_700_000_000,
        lease_seq: 17,
        lease_object_id: lease_id,
        writer_public_key: [0; 32],
        signature: Signature::zero(),
    };
    state.sign_with(&writer()).unwrap();
    let state_object = stored(&state.header, &state);
    let root = ConnectorStateRoot {
        header: header(
            FcpStoreConnectorStateStore::root_schema_id(),
            vec![state_object.object_id],
        ),
        connector_id: scope().connector_id,
        instance_id: None,
        zone_id: scope().zone_id,
        model: ConnectorStateModel::SingletonWriter,
        head: Some(state_object.object_id),
        state_schema_version: 1,
    };
    let root_object = stored(&root.header, &root);
    let root_id = root_object.object_id;
    run(source_objects.put(state_object)).unwrap();
    run(source_objects.put(root_object)).unwrap();
    let source = adapter(source_objects);
    let replica = adapter(Arc::new(MemoryObjectStore::new(
        MemoryObjectStoreConfig::default(),
    )));
    let mut recipient = ConnectorStateReplicationService::new();
    recipient
        .register_store(
            ConnectorStateTransferDirection::Import,
            scope(),
            Arc::clone(&replica),
        )
        .unwrap();
    let limits = ConnectorStateTransferLimits {
        max_objects: 16,
        max_canonical_bytes: 128 * 1024,
        max_wire_bytes: 512 * 1024,
    };
    let mut donors = Vec::new();
    let mut candidates = Vec::new();
    for index in 0..2 {
        let peer = format!("donor-{index}");
        let grant = ConnectorStateTransferGrant {
            grant_id: format!("restore-{index}"),
            direction: ConnectorStateTransferDirection::Export,
            peer_node: "recipient".to_owned(),
            scope: scope(),
            root_object_id: root_id,
            expires_at: Utc::now() + chrono::Duration::hours(1),
            limits,
        };
        let mut donor = ConnectorStateReplicationService::new();
        donor
            .register_store(
                ConnectorStateTransferDirection::Export,
                scope(),
                Arc::clone(&source),
            )
            .unwrap();
        donor.add_grant(grant.clone()).unwrap();
        candidates.push(ConnectorStatePullRequest {
            peer_node: peer.clone(),
            request: ConnectorStateExportRequest {
                grant_id: grant.grant_id.clone(),
                scope: scope(),
                root_object_id: root_id,
                limits,
            },
        });
        recipient
            .add_grant(ConnectorStateTransferGrant {
                direction: ConnectorStateTransferDirection::Import,
                peer_node: peer,
                ..grant
            })
            .unwrap();
        donors.push(donor);
    }
    Fixture {
        donors,
        recipient,
        replica,
        request: ConnectorStateRecoveryRequest {
            candidates,
            attempt_timeout_ms: 1_000,
            total_timeout_ms: 5_000,
        },
    }
}

fn unavailable() -> HostError {
    HostError::Unavailable("private donor diagnostic: secret-state".to_owned())
}

fn assert_retained(fixture: &Fixture, response: &ConnectorStateRecoveryResponse, donor: usize) {
    assert_eq!(
        response.schema_version,
        CONNECTOR_STATE_RECOVERY_SCHEMA_VERSION
    );
    assert_eq!(response.replica.peer_node, format!("donor-{donor}"));
    assert_eq!(response.replica.grant_id, format!("restore-{donor}"));
    assert_eq!(
        response.replica.root_object_id,
        fixture.request.candidates[donor].request.root_object_id
    );
    assert!(response.replica.replica_only);
    assert!(response.replica.replica_root_published);
    assert_eq!(
        run(fixture.replica.read_root()).unwrap().unwrap().0,
        response.replica.root_object_id
    );
}

#[test]
fn recovery_plan_rejects_scope_root_limits_and_duplicate_changes() {
    let fixture = fixture(false);
    let original = fixture.request;
    original.validate().unwrap();
    for change in 0..9 {
        let mut request = original.clone();
        match change {
            0 => request.candidates.clear(),
            1 => request.candidates[1].peer_node = request.candidates[0].peer_node.clone(),
            2 => {
                request.candidates[1].request.grant_id =
                    request.candidates[0].request.grant_id.clone()
            }
            3 => request.candidates[1].request.scope.zone_id = ZoneId::private(),
            4 => request.candidates[1].request.root_object_id = ObjectId::from_bytes([0xee; 32]),
            5 => request.candidates[1].request.limits.max_objects += 1,
            6 => request.candidates[1].request.limits.max_wire_bytes -= 1,
            7 => request.candidates[1].peer_node = " bad-peer ".into(),
            _ => request.candidates[1].request.grant_id.clear(),
        }
        assert!(request.validate().is_err(), "change {change} accepted");
    }
}

#[test]
fn recovery_plan_bounds_donors_and_all_deadlines() {
    let fixture = fixture(false);
    let mut request = fixture.request;
    let candidate = request.candidates[0].clone();
    request.candidates = (0..MAX_CONNECTOR_STATE_RECOVERY_CANDIDATES)
        .map(|index| {
            let mut candidate = candidate.clone();
            candidate.peer_node = format!("peer-{index}");
            candidate.request.grant_id = format!("grant-{index}");
            candidate
        })
        .collect();
    request.validate().unwrap();
    request.candidates.push(candidate);
    assert!(request.validate().is_err());
    request.candidates.pop();
    for (attempt, total) in [(0, 1), (1, 0), (2, 1), (1, 60_001), (u64::MAX, u64::MAX)] {
        request.attempt_timeout_ms = attempt;
        request.total_timeout_ms = total;
        assert!(request.validate().is_err());
    }
    request.attempt_timeout_ms = 60_000;
    request.total_timeout_ms = 60_000;
    request.validate().unwrap();
}

#[test]
fn recovery_wire_defaults_are_bounded_and_unknown_fields_rejected() {
    let fixture = fixture(false);
    let wire = json!({"candidates": fixture.request.candidates});
    let decoded: ConnectorStateRecoveryRequest = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(decoded.attempt_timeout_ms, 10_000);
    assert_eq!(decoded.total_timeout_ms, 60_000);
    decoded.validate().unwrap();
    assert!(
        serde_json::to_vec(&decoded).unwrap().len() <= MAX_CONNECTOR_STATE_RECOVERY_REQUEST_BYTES
    );
    let mut unknown = wire;
    unknown["allow_untrusted_donors"] = json!(true);
    assert!(serde_json::from_value::<ConnectorStateRecoveryRequest>(unknown).is_err());
}

#[test]
fn missing_later_grant_prevents_even_the_first_network_call() {
    let mut fixture = fixture(false);
    fixture.request.candidates[1].request.grant_id = "not-configured".into();
    let result = run(fixture.recipient.recover_from_peers(
        &fixture.request,
        |_, _| async { panic!("unvalidated plan reached network") },
        |_| Ok(()),
    ));
    assert!(result.is_err());
    assert!(run(fixture.replica.read_root()).unwrap().is_none());
}

#[test]
fn unreachable_primary_recovers_from_independently_granted_alternate() {
    let fixture = fixture(false);
    let donors = &fixture.donors;
    let response = run(fixture.recipient.recover_from_peers(
        &fixture.request,
        |index, wire| async move {
            if index == 0 {
                return Err(unavailable());
            }
            donors[index]
                .export_transfer_for_peer("recipient", &wire, || Ok(()))
                .await
        },
        |_| Ok(()),
    ))
    .unwrap();
    assert_retained(&fixture, &response, 1);
    assert_eq!(response.attempts.len(), 2);
    assert_eq!(
        response.attempts[0].outcome,
        ConnectorStateRecoveryOutcome::DownloadFailed
    );
    assert_eq!(
        response.attempts[1].outcome,
        ConnectorStateRecoveryOutcome::Retained
    );
    assert!(
        !serde_json::to_string(&response)
            .unwrap()
            .contains("secret-state")
    );
}

#[test]
fn interrupted_history_is_discarded_and_alternate_starts_at_zero() {
    let fixture = fixture(true);
    let donors = &fixture.donors;
    let replica = &fixture.replica;
    let offsets = Mutex::new(Vec::new());
    let seen = &offsets;
    let response = run(fixture.recipient.recover_from_peers(
        &fixture.request,
        |index, wire| async move {
            assert!(
                replica.read_root().await.unwrap().is_none(),
                "published before download finished"
            );
            let page: Value = serde_json::from_str(&wire).unwrap();
            let offset = page["offset"].as_u64().unwrap();
            seen.lock().unwrap().push((index, offset));
            if index == 0 && offset > 0 {
                return Err(unavailable());
            }
            if index == 1 && offset == 0 {
                assert!(page["wire_digest"].is_null());
            }
            donors[index]
                .export_transfer_for_peer("recipient", &wire, || Ok(()))
                .await
        },
        |_| Ok(()),
    ))
    .unwrap();
    assert_retained(&fixture, &response, 1);
    let offsets = offsets.into_inner().unwrap();
    assert_eq!(&offsets[..3], &[(0, 0), (0, 48 * 1024), (1, 0)]);
    assert!(
        offsets
            .iter()
            .any(|(index, offset)| *index == 1 && *offset > 0)
    );
}

#[test]
fn changed_transport_discards_download_but_does_not_authorize_a_new_incarnation() {
    let fixture = fixture(false);
    let donors = &fixture.donors;
    let revoked = AtomicBool::new(false);
    let changed = &revoked;
    let response = run(fixture.recipient.recover_from_peers(
        &fixture.request,
        |index, wire| async move {
            let reply = donors[index]
                .export_transfer_for_peer("recipient", &wire, || Ok(()))
                .await?;
            if index == 0 {
                changed.store(true, Ordering::SeqCst);
            }
            Ok(reply)
        },
        |index| {
            if index == 0 && revoked.load(Ordering::SeqCst) {
                Err(unavailable())
            } else {
                Ok(())
            }
        },
    ))
    .unwrap();
    assert_retained(&fixture, &response, 1);
    assert_eq!(
        response.attempts[0].outcome,
        ConnectorStateRecoveryOutcome::DownloadFailed
    );
}

#[test]
fn tampered_download_digest_can_fall_back_before_import() {
    let fixture = fixture(false);
    let donors = &fixture.donors;
    let response = run(fixture.recipient.recover_from_peers(
        &fixture.request,
        |index, wire| async move {
            let reply = donors[index]
                .export_transfer_for_peer("recipient", &wire, || Ok(()))
                .await?;
            if index == 0 {
                let mut value: Value = serde_json::from_str(&reply).unwrap();
                let length = value["data_hex"].as_str().unwrap().len();
                value["data_hex"] = json!("00".repeat(length / 2));
                return Ok(value.to_string());
            }
            Ok(reply)
        },
        |_| Ok(()),
    ))
    .unwrap();
    assert_retained(&fixture, &response, 1);
}

#[test]
fn complete_export_import_failure_is_terminal_even_with_a_healthy_alternate() {
    let fixture = fixture(false);
    let calls = AtomicUsize::new(0);
    let result = run(fixture.recipient.recover_from_peers(
        &fixture.request,
        |index, wire| {
            calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(index, 0, "import failure incorrectly retried another donor");
            // A complete, digest-valid download is NOT necessarily valid state.
            // The ordinary import validator rejects this; it must be terminal.
            let page: Value = serde_json::from_str(&wire).unwrap();
            async move {
                Ok(json!({
                    "schema_version": "fcp.host.state-transfer-page.v1",
                    "request": page,
                    "total_bytes": 2,
                    "wire_digest": blake3::hash(b"{}").to_hex().to_string(),
                    "data_hex": hex::encode(b"{}"),
                })
                .to_string())
            }
        },
        |_| Ok(()),
    ));
    assert!(result.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(run(fixture.replica.read_root()).unwrap().is_none());
}

struct MarkDropped<'a>(&'a AtomicBool);
impl Drop for MarkDropped<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[test]
fn stalled_download_is_cancelled_before_next_donor_starts() {
    let mut fixture = fixture(false);
    fixture.request.attempt_timeout_ms = 10;
    let donors = &fixture.donors;
    let dropped = AtomicBool::new(false);
    let was_dropped = &dropped;
    let response = run(fixture.recipient.recover_from_peers(
        &fixture.request,
        |index, wire| async move {
            if index == 0 {
                let _guard = MarkDropped(was_dropped);
                return pending::<HostResult<String>>().await;
            }
            assert!(was_dropped.load(Ordering::SeqCst));
            donors[index]
                .export_transfer_for_peer("recipient", &wire, || Ok(()))
                .await
        },
        |_| Ok(()),
    ))
    .unwrap();
    assert_retained(&fixture, &response, 1);
    assert_eq!(
        response.attempts[0].outcome,
        ConnectorStateRecoveryOutcome::DownloadDeadline
    );
}

#[test]
fn exhausting_donors_is_redacted_and_never_imports() {
    let fixture = fixture(false);
    let calls = AtomicUsize::new(0);
    let error = run(fixture.recipient.recover_from_peers(
        &fixture.request,
        |_, _| {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Err(unavailable()) }
        },
        |_| Ok(()),
    ))
    .unwrap_err();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(!error.to_string().contains("secret-state"));
    assert!(
        error
            .to_string()
            .contains("no replica import was attempted")
    );
    assert!(run(fixture.replica.read_root()).unwrap().is_none());
}

#[test]
fn total_deadline_is_shared_across_donors() {
    let mut fixture = fixture(false);
    fixture.request.attempt_timeout_ms = 10;
    fixture.request.total_timeout_ms = 15;
    let error = run(fixture.recipient.recover_from_peers(
        &fixture.request,
        |_, _| pending::<HostResult<String>>(),
        |_| Ok(()),
    ))
    .unwrap_err();
    assert!(error.to_string().contains("total deadline"));
    assert!(run(fixture.replica.read_root()).unwrap().is_none());
}

#[test]
fn ready_download_cannot_bypass_total_deadline_before_import() {
    let mut fixture = fixture(false);
    fixture.request.attempt_timeout_ms = 20;
    fixture.request.total_timeout_ms = 20;
    let donors = &fixture.donors;
    let error = run(fixture.recipient.recover_from_peers(
        &fixture.request,
        |index, wire| async move {
            assert_eq!(index, 0, "expired total budget admitted another donor");
            let reply = donors[index]
                .export_transfer_for_peer("recipient", &wire, || Ok(()))
                .await?;
            std::thread::sleep(Duration::from_millis(30));
            Ok(reply)
        },
        |_| Ok(()),
    ))
    .unwrap_err();
    assert!(error.to_string().contains("total deadline"));
    assert!(run(fixture.replica.read_root()).unwrap().is_none());
}

#[test]
fn ready_download_cannot_bypass_attempt_deadline() {
    let mut fixture = fixture(false);
    fixture.request.attempt_timeout_ms = 50;
    let donors = &fixture.donors;
    let response = run(fixture.recipient.recover_from_peers(
        &fixture.request,
        |index, wire| async move {
            let reply = donors[index]
                .export_transfer_for_peer("recipient", &wire, || Ok(()))
                .await?;
            if index == 0 {
                std::thread::sleep(Duration::from_millis(75));
            }
            Ok(reply)
        },
        |_| Ok(()),
    ))
    .unwrap();
    assert_retained(&fixture, &response, 1);
    assert_eq!(
        response.attempts[0].outcome,
        ConnectorStateRecoveryOutcome::DownloadDeadline
    );
}

#[test]
fn cancellation_releases_admission_and_saturation_is_not_a_failover_hint() {
    let fixture = fixture(false);
    run(async {
        let mut first = Box::pin(fixture.recipient.recover_from_peers(
            &fixture.request,
            |_, _| pending::<HostResult<String>>(),
            |_| Ok(()),
        ));
        let mut second = Box::pin(fixture.recipient.recover_from_peers(
            &fixture.request,
            |_, _| pending::<HostResult<String>>(),
            |_| Ok(()),
        ));
        assert!(futures_util::poll!(first.as_mut()).is_pending());
        assert!(futures_util::poll!(second.as_mut()).is_pending());
        let refused = fixture
            .recipient
            .recover_from_peers(
                &fixture.request,
                |_, _| async { panic!("shared admission refusal must not try another peer") },
                |_| Ok(()),
            )
            .await;
        assert!(refused.is_err());
        drop(first);
        drop(second);
        assert!(fixture.replica.read_root().await.unwrap().is_none());
    });
    let donors = &fixture.donors;
    let response = run(fixture.recipient.recover_from_peers(
        &fixture.request,
        |index, wire| async move {
            donors[index]
                .export_transfer_for_peer("recipient", &wire, || Ok(()))
                .await
        },
        |_| Ok(()),
    ))
    .unwrap();
    assert_retained(&fixture, &response, 0);
    assert_eq!(response.attempts.len(), 1);
}

#[test]
fn recovery_future_is_send_with_send_transport() {
    fn assert_send<T: Send>(_: T) {}
    let service = ConnectorStateReplicationService::new();
    let request = ConnectorStateRecoveryRequest {
        candidates: Vec::new(),
        attempt_timeout_ms: 1,
        total_timeout_ms: 1,
    };
    assert_send(service.recover_from_peers(
        &request,
        |_, _| async { Err(unavailable()) },
        |_| Ok(()),
    ));
}
