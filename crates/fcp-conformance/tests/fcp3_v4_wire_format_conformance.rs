//! FCP3/V4 wire-format conformance coverage not covered by the PQ KAT harnesses.
//!
//! Coverage matrix:
//!
//! | Clause | Level | Test |
//! | --- | --- | --- |
//! | FCPC envelope decode/open/re-encode is byte-stable while a V3 payload migrates to V4 | MUST | `fcpc_frame_envelope_preserves_v3_to_v4_schema_migration_determinism` |
//! | Capability-token COSE verification survives every negotiated suite at/above `MINIMUM_SUITE` | MUST | `capability_cose_envelope_verifies_after_responder_picks_floor_negotiation` |
//! | Audit-chain reorganization is per-zone; merged cross-zone replay is rejected as a fork | MUST | `audit_chain_reorganization_keeps_cross_zone_hash_links_independent` |
//! | Zone-key V3 to V4 rotation cutover replays to the same active keys | MUST | `zone_key_rotation_v3_to_v4_cutover_replay_is_deterministic` |

use chrono::{TimeZone, Utc};
use fcp_audit::{Severity, VerifyStatus, verify_chain};
use fcp_auth_schema::claims::CURRENT_SCHEMA_VERSION;
use fcp_core::{
    NodeId, NodeSignature, ObjectHeader, ObjectIdKey, ObjectIdKeyId, Provenance, TailscaleNodeId,
    WrappedZoneKeyV4, ZoneId, ZoneKemAlgorithm, ZoneKey, ZoneKeyAlgorithm, ZoneKeyId,
    ZoneKeyManifest, ZoneKeyRing, wrap_object_id_key, wrap_zone_key,
};
use fcp_crypto::{
    Ed25519SigningKey, X25519SecretKey as X25519NodeKey, XWingKem, XWingProvider,
    cose::{CapabilityTokenBuilder as CapabilityEnvelopeBuilder, CoseToken, fcp2_claims},
};
use fcp_host::{InvokeAuditChain, InvokeAuditContext, InvokePhase};
use fcp_protocol::{
    FCPC_VERSION, FcpcFrame, FcpcFrameFlags, MeshSessionId, SessionCryptoSuite, SessionDirection,
    session::{MINIMUM_SUITE, negotiate_suite},
};
use semver::Version;
use serde::{Deserialize, Serialize};

const FCPC_SCHEMA_V3: u16 = 3;
const FCPC_SCHEMA_V4: u16 = 4;
const SESSION_ID: MeshSessionId = MeshSessionId([
    0xF3, 0xC3, 0x00, 0x04, 0xAA, 0x55, 0x90, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
]);
const K_CTX: [u8; 32] = [
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FcpcSchemaPayload {
    schema_version: u16,
    request_id: String,
    zone_id: String,
    operation: String,
    capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    v4_cutover_epoch: Option<u64>,
}

fn migrate_fcpc_payload_to_v4(mut payload: FcpcSchemaPayload) -> FcpcSchemaPayload {
    if payload.schema_version == FCPC_SCHEMA_V3 {
        payload.schema_version = FCPC_SCHEMA_V4;
        payload.v4_cutover_epoch = Some(4);
        payload.capabilities.sort();
        payload.capabilities.dedup();
    }
    payload
}

fn decode_fcpc_payload(bytes: &[u8]) -> FcpcSchemaPayload {
    ciborium::from_reader(bytes).expect("FCPC schema payload decodes")
}

#[test]
fn fcpc_frame_envelope_preserves_v3_to_v4_schema_migration_determinism() {
    let v3_payload = FcpcSchemaPayload {
        schema_version: FCPC_SCHEMA_V3,
        request_id: "req-fcpc-v3-v4".to_owned(),
        zone_id: "z:work".to_owned(),
        operation: "connector.invoke".to_owned(),
        capabilities: vec![
            "cap.invoke".to_owned(),
            "cap.audit".to_owned(),
            "cap.invoke".to_owned(),
        ],
        v4_cutover_epoch: None,
    };
    let v3_bytes = fcp_cbor::to_canonical_cbor(&v3_payload).expect("V3 payload encodes");
    let frame = FcpcFrame::seal(
        SESSION_ID,
        44,
        SessionDirection::InitiatorToResponder,
        FcpcFrameFlags::default(),
        &v3_bytes,
        &K_CTX,
    )
    .expect("FCPC V3 payload seals");
    let encoded = frame.encode();
    let decoded = FcpcFrame::decode(&encoded).expect("FCPC frame decodes");

    assert_eq!(
        decoded.encode(),
        encoded,
        "FCPC envelope decode->encode MUST be byte-stable before payload migration"
    );
    assert_eq!(decoded.header.version, FCPC_VERSION);

    let opened = decoded
        .open(SessionDirection::InitiatorToResponder, &K_CTX)
        .expect("FCPC frame opens");
    assert_eq!(
        opened, v3_bytes,
        "FCPC envelope MUST preserve the exact V3 payload bytes"
    );

    let migrated = migrate_fcpc_payload_to_v4(decode_fcpc_payload(&opened));
    let migrated_again = migrate_fcpc_payload_to_v4(v3_payload);
    assert_eq!(
        migrated, migrated_again,
        "V3->V4 migration MUST be deterministic from the same wire payload"
    );
    assert_eq!(migrated.schema_version, FCPC_SCHEMA_V4);
    assert_eq!(migrated.v4_cutover_epoch, Some(4));
    assert_eq!(
        migrated.capabilities,
        vec!["cap.audit".to_owned(), "cap.invoke".to_owned()],
        "V4 migration MUST canonicalize duplicate capability entries"
    );

    let first_v4_bytes = fcp_cbor::to_canonical_cbor(&migrated).expect("V4 payload encodes");
    let second_v4_bytes =
        fcp_cbor::to_canonical_cbor(&migrated_again).expect("second V4 payload encodes");
    assert_eq!(
        first_v4_bytes, second_v4_bytes,
        "canonical V4 payload bytes MUST be stable across migration runs"
    );
}

#[test]
fn capability_cose_envelope_verifies_after_responder_picks_floor_negotiation() {
    let issuer = Ed25519SigningKey::generate();
    let now = Utc
        .timestamp_opt(1_700_030_000, 0)
        .single()
        .expect("fixed timestamp is valid");
    let signed_capability = CapabilityEnvelopeBuilder::new()
        .capability_id("cap.fcp3.v4.invoke")
        .zone_id("z:work")
        .principal("user:violetpine")
        .issuer("node:conformance-responder")
        .operations(&["connector.invoke"])
        .validity(now, now + chrono::Duration::minutes(10))
        .sign(&issuer)
        .expect("capability token signs");
    let signed_capability_bytes = signed_capability.to_cbor().expect("COSE token serializes");

    let cases: &[(&str, &[SessionCryptoSuite], &[SessionCryptoSuite])] = &[
        (
            "floor-only",
            &[SessionCryptoSuite::Suite1],
            &[SessionCryptoSuite::Suite1],
        ),
        (
            "above-floor-only",
            &[SessionCryptoSuite::Suite2],
            &[SessionCryptoSuite::Suite2],
        ),
        (
            "responder-prefers-stronger",
            &[SessionCryptoSuite::Suite1, SessionCryptoSuite::Suite2],
            &[SessionCryptoSuite::Suite2, SessionCryptoSuite::Suite1],
        ),
    ];

    for (index, (name, initiator, responder)) in cases.iter().enumerate() {
        let negotiated = negotiate_suite(initiator, responder);
        assert!(negotiated.is_some(), "{name}: expected a negotiated suite");
        let Some(selected) = negotiated else {
            continue;
        };
        assert!(
            selected.id() >= MINIMUM_SUITE.id(),
            "{name}: responder-picks negotiated below MINIMUM_SUITE"
        );

        let seq = u64::try_from(index + 1).expect("case index fits u64");
        let frame = FcpcFrame::seal(
            SESSION_ID,
            seq,
            SessionDirection::ResponderToInitiator,
            FcpcFrameFlags::default(),
            &signed_capability_bytes,
            &K_CTX,
        );
        assert!(frame.is_ok(), "{name}: COSE token FCPC seal failed");
        let Ok(frame) = frame else {
            continue;
        };
        let opened = FcpcFrame::decode(&frame.encode())
            .and_then(|decoded| decoded.open(SessionDirection::ResponderToInitiator, &K_CTX));
        assert!(opened.is_ok(), "{name}: COSE token FCPC open failed");
        let Ok(opened) = opened else {
            continue;
        };
        let parsed = CoseToken::from_cbor(&opened);
        assert!(parsed.is_ok(), "{name}: COSE token parses after FCPC open");
        let Ok(parsed) = parsed else {
            continue;
        };
        let claims = parsed.verify(&issuer.verifying_key());
        assert!(
            claims.is_ok(),
            "{name}: COSE token verifies after negotiation"
        );
        let Ok(claims) = claims else {
            continue;
        };

        assert_eq!(claims.get_capability_id(), Some("cap.fcp3.v4.invoke"));
        assert_eq!(claims.get_zone_id(), Some("z:work"));
        assert_eq!(claims.get_principal_id(), Some("user:violetpine"));
        assert_eq!(
            claims.get(fcp2_claims::SCHEMA_VERSION),
            Some(&ciborium::Value::Integer(
                i64::from(CURRENT_SCHEMA_VERSION).into()
            )),
            "{name}: COSE verification MUST preserve the current auth schema_version"
        );
    }
}

fn invoke_ctx(zone_id: &str, operation_id: &str, occurred_at: u64) -> InvokeAuditContext {
    InvokeAuditContext {
        zone_id: zone_id.to_owned(),
        actor: "user:violetpine".to_owned(),
        connector_id: "fcp.test.connector".to_owned(),
        operation: "connector.invoke".to_owned(),
        operation_id: operation_id.to_owned(),
        correlation_id: Some(format!("corr-{operation_id}")),
        occurred_at,
    }
}

#[test]
fn audit_chain_reorganization_keeps_cross_zone_hash_links_independent() {
    let chain = InvokeAuditChain::new();
    let program = [
        ("z:work", "op-work-0", InvokePhase::PreflightAllow),
        (
            "z:project:alpha",
            "op-alpha-0",
            InvokePhase::DispatchResult {
                receipt_id: Some("receipt-alpha-0".to_owned()),
                success: true,
                duration_ms: 9,
            },
        ),
        (
            "z:work",
            "op-work-1",
            InvokePhase::PreflightDeny {
                reason: "policy denied".to_owned(),
            },
        ),
        (
            "z:project:alpha",
            "op-alpha-1",
            InvokePhase::DispatchError {
                error: "connector exited".to_owned(),
                duration_ms: 11,
            },
        ),
    ];

    for (offset, (zone_id, operation_id, phase)) in program.into_iter().enumerate() {
        let occurred_at = 1_700_040_000 + u64::try_from(offset).expect("offset fits u64");
        chain
            .append(&invoke_ctx(zone_id, operation_id, occurred_at), phase)
            .expect("invoke audit append succeeds");
    }

    let work_entries = chain.entries_for_zone("z:work");
    let alpha_entries = chain.entries_for_zone("z:project:alpha");
    assert_eq!(work_entries.len(), 2);
    assert_eq!(alpha_entries.len(), 2);
    assert!(work_entries[0].is_genesis());
    assert!(alpha_entries[0].is_genesis());
    assert!(work_entries[1].follows(&work_entries[0]));
    assert!(alpha_entries[1].follows(&alpha_entries[0]));
    assert_eq!(work_entries[1].severity, Severity::Warning);
    assert_eq!(alpha_entries[1].severity, Severity::Error);

    let work_report = verify_chain(&work_entries, None, Some("z:work"));
    let alpha_report = verify_chain(&alpha_entries, None, Some("z:project:alpha"));
    assert_eq!(work_report.status, VerifyStatus::Ok);
    assert_eq!(alpha_report.status, VerifyStatus::Ok);

    let merged_reorg = vec![
        work_entries[0].clone(),
        alpha_entries[0].clone(),
        work_entries[1].clone(),
        alpha_entries[1].clone(),
    ];
    let merged_report = verify_chain(&merged_reorg, None, None);
    assert_eq!(
        merged_report.status,
        VerifyStatus::Fail,
        "cross-zone reorg replay MUST NOT validate as one hash chain"
    );
    assert!(
        merged_report
            .issues
            .iter()
            .any(|issue| issue.code == "audit.fork_detected"),
        "merged replay must surface duplicate per-zone seq as fork: {merged_report:?}"
    );
    assert!(
        merged_report
            .issues
            .iter()
            .any(|issue| issue.code == "audit.zone_mismatch"),
        "merged replay must surface cross-zone bleed: {merged_report:?}"
    );
}

fn test_header(zone_id: &ZoneId) -> ObjectHeader {
    ObjectHeader {
        encryption_kind: Default::default(),
        schema: fcp_cbor::SchemaId::new("fcp.zone", "ZoneKeyManifest", Version::new(1, 0, 0)),
        zone_id: zone_id.clone(),
        created_at: 1_700_050_000,
        provenance: Provenance::new(zone_id.clone()),
        refs: Vec::new(),
        foreign_refs: Vec::new(),
        ttl_secs: None,
        placement: None,
    }
}

fn test_signature() -> NodeSignature {
    NodeSignature::new(NodeId::new("owner-node"), [0xA5; 64], 1_700_050_000)
}

struct ManifestInput<'a> {
    zone_id: &'a ZoneId,
    node_id: &'a TailscaleNodeId,
    node_key: &'a X25519NodeKey,
    issued_at: u64,
    zone_key_id: ZoneKeyId,
    object_key_id: ObjectIdKeyId,
    previous_zone_key_id: Option<ZoneKeyId>,
    zone_key: ZoneKey,
    object_key: ObjectIdKey,
}

fn hpke_manifest(input: &ManifestInput<'_>) -> ZoneKeyManifest {
    let wrapped_zone = wrap_zone_key(
        &input.node_key.public_key(),
        input.zone_id,
        input.node_id,
        input.issued_at,
        &input.zone_key,
    )
    .expect("zone key wraps");
    let wrapped_object = wrap_object_id_key(
        &input.node_key.public_key(),
        input.zone_id,
        input.node_id,
        input.issued_at,
        &input.object_key,
    )
    .expect("object id key wraps");

    ZoneKeyManifest {
        header: test_header(input.zone_id),
        zone_id: input.zone_id.clone(),
        zone_key_id: input.zone_key_id,
        object_id_key_id: input.object_key_id,
        algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
        valid_from: input.issued_at,
        valid_until: None,
        prev_zone_key_id: input.previous_zone_key_id,
        wrapped_keys: vec![wrapped_zone],
        wrapped_object_id_keys: vec![wrapped_object],
        rekey_policy: None,
        signature: test_signature(),
        kem: ZoneKemAlgorithm::HpkeX25519,
        wrapped_keys_v4: Vec::<WrappedZoneKeyV4>::new(),
    }
}

#[derive(Debug, PartialEq, Eq)]
struct KeyReplaySnapshot {
    zone_key_id: Option<ZoneKeyId>,
    zone_key_hash: Option<[u8; 32]>,
    object_key_id: Option<ObjectIdKeyId>,
    object_key_hash: Option<[u8; 32]>,
}

fn replay_manifests(
    zone_id: &ZoneId,
    node_id: &TailscaleNodeId,
    node_key: &X25519NodeKey,
    manifests: &[ZoneKeyManifest],
) -> Vec<KeyReplaySnapshot> {
    let xwing = XWingProvider::new();
    let (_, throwaway_xwing_secret) = xwing.generate().expect("throwaway X-Wing keypair");
    let mut ring = ZoneKeyRing::new(zone_id.clone());
    let mut snapshots = Vec::with_capacity(manifests.len());

    for manifest in manifests {
        ring.apply_manifest_v4(manifest, node_id, node_key, &throwaway_xwing_secret, &xwing)
            .expect("manifest applies through V4-aware cutover path");
        snapshots.push(KeyReplaySnapshot {
            zone_key_id: ring.active_zone_key_id,
            zone_key_hash: ring
                .active_zone_key()
                .map(|key| *blake3::hash(key.as_bytes()).as_bytes()),
            object_key_id: ring.active_object_id_key_id,
            object_key_hash: ring
                .active_object_id_key()
                .map(|key| *blake3::hash(key.as_bytes()).as_bytes()),
        });
    }

    snapshots
}

#[test]
fn zone_key_rotation_v3_to_v4_cutover_replay_is_deterministic() {
    let zone_id = ZoneId::work();
    let node_id = TailscaleNodeId::new("node-v3-v4-cutover");
    let node_key = X25519NodeKey::generate();
    let object_key = ObjectIdKey::from_bytes([0xC0; 32]);
    let v3_zone_key_id = ZoneKeyId::from_bytes([0x31; 8]);
    let v4_zone_key_id = ZoneKeyId::from_bytes([0x44; 8]);
    let object_key_id = ObjectIdKeyId::from_bytes([0xA0; 8]);

    let v3_manifest = hpke_manifest(&ManifestInput {
        zone_id: &zone_id,
        node_id: &node_id,
        node_key: &node_key,
        issued_at: 1_700_050_001,
        zone_key_id: v3_zone_key_id,
        object_key_id,
        previous_zone_key_id: None,
        zone_key: ZoneKey::from_bytes([0x31; 32]),
        object_key,
    });
    let v4_source = hpke_manifest(&ManifestInput {
        zone_id: &zone_id,
        node_id: &node_id,
        node_key: &node_key,
        issued_at: 1_700_050_002,
        zone_key_id: v4_zone_key_id,
        object_key_id,
        previous_zone_key_id: Some(v3_zone_key_id),
        zone_key: ZoneKey::from_bytes([0x44; 32]),
        object_key,
    });
    let v4_manifest = v4_source
        .migrated_to_v4(ZoneKemAlgorithm::XWing)
        .sign(test_signature());
    let v4_manifest_again = v4_source
        .migrated_to_v4(ZoneKemAlgorithm::XWing)
        .sign(test_signature());

    assert_eq!(v4_manifest.prev_zone_key_id, Some(v3_zone_key_id));
    assert_eq!(v4_manifest.kem, ZoneKemAlgorithm::XWing);
    assert_eq!(v4_manifest.wrapped_keys_v4.len(), 1);
    assert_eq!(
        fcp_cbor::to_canonical_cbor(&v4_manifest).expect("first V4 manifest encodes"),
        fcp_cbor::to_canonical_cbor(&v4_manifest_again).expect("second V4 manifest encodes"),
        "V3->V4 cutover manifest migration MUST be byte-deterministic for the same source"
    );

    let manifests = vec![v3_manifest, v4_manifest];
    let first_replay = replay_manifests(&zone_id, &node_id, &node_key, &manifests);
    let second_replay = replay_manifests(&zone_id, &node_id, &node_key, &manifests);
    assert_eq!(
        first_replay, second_replay,
        "V3 then V4 cutover replay MUST converge to identical active keys"
    );
    assert_eq!(
        first_replay.last().map(|snapshot| snapshot.zone_key_id),
        Some(Some(v4_zone_key_id)),
        "final replay state MUST activate the V4 zone key"
    );
    assert_ne!(
        first_replay[0].zone_key_hash, first_replay[1].zone_key_hash,
        "rotation replay MUST switch the effective zone-key bytes"
    );
    assert_eq!(
        first_replay[0].object_key_hash, first_replay[1].object_key_hash,
        "zone-key rotation without object-key rotation MUST preserve ObjectIdKey bytes"
    );
}
