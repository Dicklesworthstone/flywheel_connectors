//! Mesh-stored policy object E2E proof (flywheel_connectors-o9t0e, E.4).
//!
//! This is intentionally not a mock of the mesh path. The scenario uses
//! real in-memory object stores with keyed content-id verification, real
//! mesh gossip summaries, real owner signatures, real policy evaluation,
//! and the m8j0q revocation-cascade/audit primitives.

#![allow(clippy::unnecessary_literal_unwrap)]

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use chrono::Utc;
use serde::Serialize;
use serde_json::{Value, json};

use fcp_audit::{
    AuditEntryBuilder, CapabilityConstraintDenied as AuditDenialPayload, Severity,
    capability_constraint_request_descriptor_hash, event_types,
};
use fcp_crypto::{Ed25519Signature, Ed25519SigningKey, kid::KeyId};
use fcp_evidence::{
    AttestationChain, CascadeConfig, CascadeHop, CascadeRejection, RevocationRecord,
    check_revocation_chain,
};
use fcp_mesh::{DeviceProfile, GossipMessage, MeshNode, MeshNodeConfig, ObjectAdmissionClass};
use fcp_prelude::{
    CapabilityId, ConnectorId, Decision, DecisionReasonCode, DecisionReceiptPolicy, EpochId,
    NodeId as CoreNodeId, NodeSignature, ObjectHeader, ObjectId, ObjectIdKey, OperationId,
    POLICY_BUNDLE_SIGNED_FIELDS, PolicyBundle, PolicyBundleObject, PolicyBundlePolicyRef,
    PolicyBundleResolved, PolicyBundleSignature, PolicyDecisionInput, PolicyEngine, PolicyPattern,
    PrincipalId, Provenance, ProvenanceRecord, RetentionClass, RevocationObject,
    RevocationRegistry, RevocationScope, SafetyTier, StorageMeta, StoredObject, TailscaleNodeId,
    TransportMode, ZoneId, ZonePolicyObject, ZoneTransportPolicy, compute_policy_bundle_hash,
};
use fcp_store::{
    KeyedObjectIdVerifier, MemoryObjectStore, MemoryObjectStoreConfig, MemorySymbolStore,
    MemorySymbolStoreConfig, ObjectAdmissionPolicy, ObjectStore, QuarantineStore,
};
use fcp_tailscale::NodeId as MeshNodeId;

const SCENARIO_ID: &str = "o9t0e.mesh_policy_object_lifecycle";
const NODE_A: &str = "mesh-policy-node-a";
const NODE_B: &str = "mesh-policy-node-b";
const POLICY_BUNDLE_ID: &str = "bundle-o9t0e-zone-work";
const OWNER_KEY_ID: &str = "owner-o9t0e";
const NOW_SECS: u64 = 1_700_000_000;
const NOW_MS: u64 = NOW_SECS * 1000;

fn log_event(phase: &str, outcome: &str, details: &Value) {
    let entry = json!({
        "ts": Utc::now().to_rfc3339(),
        "scenario_id": SCENARIO_ID,
        "bead": "flywheel_connectors-o9t0e",
        "phase": phase,
        "outcome": outcome,
        "details": details,
    });
    println!("{entry}");
}

fn object_id_key() -> ObjectIdKey {
    ObjectIdKey::from_bytes([0xE4; 32])
}

fn schema_header(schema_name: &str, zone: &ZoneId, refs: &[ObjectId]) -> ObjectHeader {
    serde_json::from_value(json!({
        "schema": {
            "namespace": "fcp.core",
            "name": schema_name,
            "version": "1.0.0",
        },
        "zone_id": zone.as_str(),
        "created_at": NOW_SECS,
        "provenance": serde_json::to_value(Provenance::new(zone.clone()))
            .expect("provenance serializes"),
        "refs": refs,
        "foreign_refs": [],
        "ttl_secs": null,
        "placement": null,
    }))
    .expect("object header schema fixture deserializes")
}

fn policy_bytes(policy: &ZonePolicyObject) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(policy, &mut bytes).expect("zone policy encodes to CBOR");
    bytes
}

fn bundle_bytes(bundle: &PolicyBundle) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(bundle, &mut bytes).expect("policy bundle encodes to CBOR");
    bytes
}

fn object_hash(body: &[u8]) -> String {
    format!("blake3-256:{}", ObjectId::from_unscoped_bytes(body))
}

fn signed_fields() -> Vec<String> {
    POLICY_BUNDLE_SIGNED_FIELDS
        .iter()
        .map(|field| (*field).to_string())
        .collect()
}

fn decode_signature(signature: &str) -> [u8; 64] {
    let bytes = STANDARD_NO_PAD
        .decode(signature)
        .expect("policy bundle signature is base64");
    let mut out = [0_u8; 64];
    out.copy_from_slice(&bytes);
    out
}

fn stored_object(header: ObjectHeader, body: Vec<u8>, object_id_key: &ObjectIdKey) -> StoredObject {
    let object_id =
        StoredObject::derive_id(&header, &body, object_id_key).expect("object id derives");
    StoredObject {
        object_id,
        header,
        body,
        storage: StorageMeta {
            retention: RetentionClass::Pinned,
        },
    }
}

fn verify_stored_object_integrity(object: &StoredObject, object_id_key: &ObjectIdKey) {
    let derived = StoredObject::derive_id(&object.header, &object.body, object_id_key)
        .expect("stored object canonical bytes derive");
    assert_eq!(
        derived, object.object_id,
        "object_id must bind to policy bytes and header"
    );
}

fn zone_policy(zone: &ZoneId) -> ZonePolicyObject {
    ZonePolicyObject {
        header: schema_header("ZonePolicyObject", zone, &[]),
        zone_id: zone.clone(),
        principal_allow: vec![PolicyPattern {
            pattern: "user:alice".to_string(),
        }],
        principal_deny: Vec::new(),
        connector_allow: vec![PolicyPattern {
            pattern: "mesh:policy:1.0.0".to_string(),
        }],
        connector_deny: Vec::new(),
        capability_allow: vec![PolicyPattern {
            pattern: "cap.mesh.policy.apply".to_string(),
        }],
        capability_deny: Vec::new(),
        capability_ceiling: vec![
            CapabilityId::new("cap.mesh.policy.apply").expect("valid capability"),
        ],
        transport_policy: ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: false,
            allow_funnel: false,
        },
        decision_receipts: DecisionReceiptPolicy::default(),
        usage_budget: None,
        requires_posture: None,
    }
}

fn signed_policy_bundle(
    zone: &ZoneId,
    policy_object: &StoredObject,
    owner_key: &Ed25519SigningKey,
) -> PolicyBundle {
    let policy_ref = PolicyBundlePolicyRef {
        object_id: policy_object.object_id.to_prefixed_string(),
        schema_id: "fcp.core:ZonePolicyObject@1.0.0".to_string(),
        object_hash: object_hash(&policy_object.body),
    };
    let created_at = Some(Utc::now());
    let bundle_hash = compute_policy_bundle_hash(
        POLICY_BUNDLE_ID,
        zone,
        1,
        created_at,
        None,
        std::slice::from_ref(&policy_ref),
    )
    .expect("policy bundle hash computes");

    let placeholder = PolicyBundle::builder(POLICY_BUNDLE_ID, zone.clone(), 1)
        .created_at(created_at.expect("created_at is set"))
        .bundle_hash(bundle_hash.clone())
        .policies(vec![policy_ref.clone()])
        .signature(PolicyBundleSignature::new(
            OWNER_KEY_ID,
            "pending",
            signed_fields(),
        ))
        .build()
        .expect("placeholder bundle validates");
    let signature = owner_key.sign(&placeholder.signing_bytes().expect("signing bytes"));
    let signature_b64 = STANDARD_NO_PAD.encode(signature.to_bytes());

    let bundle = PolicyBundle::builder(POLICY_BUNDLE_ID, zone.clone(), 1)
        .created_at(created_at.expect("created_at is set"))
        .bundle_hash(bundle_hash)
        .policies(vec![policy_ref])
        .signature(PolicyBundleSignature::new(
            OWNER_KEY_ID,
            signature_b64,
            signed_fields(),
        ))
        .build()
        .expect("signed policy bundle validates");

    let observed_signature =
        Ed25519Signature::from_bytes(&decode_signature(&bundle.signature.signature));
    owner_key
        .verifying_key()
        .verify(
            &bundle.signing_bytes().expect("bundle signing bytes"),
            &observed_signature,
        )
        .expect("owner signature verifies over policy bundle bytes");

    bundle
}

fn mesh_node(node_id: &str, object_store: Arc<MemoryObjectStore>) -> MeshNode {
    let object_store: Arc<dyn ObjectStore> = object_store;
    let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
    let symbol_store: Arc<dyn fcp_store::SymbolStore> = symbol_store;
    let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));
    MeshNode::new(
        MeshNodeConfig::new(node_id).with_sender_instance_id(42),
        object_store,
        symbol_store,
        quarantine_store,
    )
}

fn verified_store(zone: &ZoneId, object_id_key: ObjectIdKey) -> Arc<MemoryObjectStore> {
    let mut verifier = KeyedObjectIdVerifier::default();
    verifier.insert(zone.clone(), object_id_key);
    Arc::new(
        MemoryObjectStore::new(MemoryObjectStoreConfig::default())
            .with_verifier(verifier.into_arc()),
    )
}

fn zone_set(zone: ZoneId) -> HashSet<ZoneId> {
    HashSet::from([zone])
}

fn device_profile(node_id: &str) -> DeviceProfile {
    DeviceProfile::builder(MeshNodeId::new(node_id)).build()
}

fn sign_gossip_summary(
    node: &mut MeshNode,
    zone: &ZoneId,
    signing_key: &Ed25519SigningKey,
) -> fcp_mesh::GossipSummary {
    let template = node
        .gossip_mut()
        .create_summary(zone, EpochId::new("o9t0e-epoch-1"))
        .expect("policy objects were announced into the zone");
    fcp_mesh::GossipSummary {
        signature: Some(NodeSignature::new(
            CoreNodeId::new(NODE_A),
            signing_key.sign(&template.signing_bytes()).to_bytes(),
            NOW_SECS,
        )),
        ..template
    }
}

fn policy_decision_input<'a>(
    zone: &ZoneId,
    related_object_ids: &'a [ObjectId],
    revocation_fresh: bool,
) -> PolicyDecisionInput<'a> {
    PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"o9t0e-policy-apply-request"),
        zone_id: zone.clone(),
        principal: PrincipalId::new("user:alice").expect("valid principal"),
        connector_id: ConnectorId::from_static("mesh:policy:1.0.0"),
        operation_id: OperationId::from_static("op.mesh.policy.apply"),
        capability_id: CapabilityId::new("cap.mesh.policy.apply").expect("valid capability"),
        safety_tier: SafetyTier::Safe,
        provenance: ProvenanceRecord::new(zone.clone()),
        approval_tokens: &[],
        sanitizer_receipts: &[],
        request_input: None,
        request_input_hash: None,
        related_object_ids,
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh,
        execution_approval_required: false,
        now_ms: NOW_MS,
        posture_attestation: None,
    }
}

fn kid_from_label(label: &str) -> KeyId {
    KeyId::derive_from_public_key(label.as_bytes())
}

fn revocation_record(at_unix_ms: u64) -> RevocationRecord {
    RevocationRecord {
        revoked_at_unix_ms: at_unix_ms,
    }
}

fn policy_revocation_object(
    zone: &ZoneId,
    policy_object_id: ObjectId,
    owner_key: &Ed25519SigningKey,
) -> RevocationObject {
    let mut signable = Vec::new();
    signable.extend_from_slice(b"fcp:e2e:o9t0e:policy-revocation");
    signable.extend_from_slice(policy_object_id.as_bytes());
    signable.extend_from_slice(zone.as_bytes());
    signable.extend_from_slice(&NOW_SECS.to_be_bytes());

    RevocationObject {
        header: schema_header("RevocationObject", zone, &[policy_object_id]),
        revoked: vec![policy_object_id],
        scope: RevocationScope::ZoneKey,
        reason: "mesh-stored policy object superseded by owner revocation".to_string(),
        effective_at: NOW_SECS,
        expires_at: None,
        signature: owner_key.sign(&signable).to_bytes(),
    }
}

fn audit_policy_denial(
    policy_object_id: ObjectId,
    cascade_error: &CascadeRejection,
) -> fcp_audit::AuditEntry {
    #[derive(Serialize)]
    struct RedactedDescriptor {
        policy_object_id: String,
        attempted_operation: &'static str,
    }

    let descriptor_hash = capability_constraint_request_descriptor_hash(&RedactedDescriptor {
        policy_object_id: policy_object_id.to_string(),
        attempted_operation: "op.mesh.policy.apply",
    })
    .expect("descriptor hash computes");

    let (constraint_kind, observed_value, occurred_at) = match cascade_error {
        CascadeRejection::HopRevoked {
            scope,
            kid,
            revoked_at_unix_ms,
            ..
        } => (
            format!("{scope}_revoked"),
            format!("kid={}", kid.to_hex()),
            *revoked_at_unix_ms / 1000,
        ),
        CascadeRejection::TokenRevoked {
            token_id,
            revoked_at_unix_ms,
        } => (
            "policy_object_revoked".to_string(),
            format!("object_id={token_id}"),
            *revoked_at_unix_ms / 1000,
        ),
        other => panic!("unexpected cascade rejection for policy object: {other:?}"),
    };

    AuditEntryBuilder::new()
        .id("audit-entry-o9t0e-policy-denial")
        .actor("system:mesh-policy-admission")
        .zone_id(ZoneId::work())
        .seq(1)
        .occurred_at(occurred_at)
        .capability_constraint_denied(AuditDenialPayload::new(
            constraint_kind,
            observed_value,
            descriptor_hash,
            NODE_B,
            occurred_at,
        ))
        .build()
        .expect("audit denial entry builds")
}

#[fcp_async_core::runtime::test]
async fn mesh_policy_object_lifecycle_gossip_admission_revocation_and_integrity() {
    let zone = ZoneId::work();
    let object_id_key = object_id_key();
    let owner_key = Ed25519SigningKey::generate();
    let node_a_key = Ed25519SigningKey::generate();

    let store_a = verified_store(&zone, object_id_key);
    let store_b = verified_store(&zone, object_id_key);
    let mut node_a = mesh_node(NODE_A, store_a.clone());
    let mut node_b = mesh_node(NODE_B, store_b.clone());

    node_a.update_peer_state(
        MeshNodeId::new(NODE_B),
        device_profile(NODE_B),
        HashSet::new(),
        Vec::new(),
        NOW_MS,
    );
    node_a.update_peer_zones(&MeshNodeId::new(NODE_B), zone_set(zone.clone()));
    node_b.register_peer_signing_key(MeshNodeId::new(NODE_A), node_a_key.verifying_key());
    node_b.update_peer_state(
        MeshNodeId::new(NODE_A),
        device_profile(NODE_A),
        HashSet::new(),
        Vec::new(),
        NOW_MS,
    );
    node_b.update_peer_zones(&MeshNodeId::new(NODE_A), zone_set(zone.clone()));
    node_a.update_local_zones(zone_set(zone.clone()));
    node_b.update_local_zones(zone_set(zone.clone()));

    log_event(
        "setup",
        "started",
        &json!({"node_a": NODE_A, "node_b": NODE_B}),
    );

    let policy = zone_policy(&zone);
    let policy_body = policy_bytes(&policy);
    let expected_policy_hash = object_hash(&policy_body);
    let policy_object = stored_object(policy.header.clone(), policy_body, &object_id_key);
    verify_stored_object_integrity(&policy_object, &object_id_key);

    let bundle = signed_policy_bundle(&zone, &policy_object, &owner_key);
    let bundle_body = bundle_bytes(&bundle);
    let bundle_object = stored_object(
        schema_header("PolicyBundle", &zone, &[policy_object.object_id]),
        bundle_body,
        &object_id_key,
    );
    verify_stored_object_integrity(&bundle_object, &object_id_key);

    store_a
        .put(policy_object.clone())
        .await
        .expect("node A stores verified policy object");
    store_a
        .put(bundle_object.clone())
        .await
        .expect("node A stores signed policy bundle");
    let observer_anchor = stored_object(
        schema_header("MeshPolicyObserverAnchor", &zone, &[]),
        b"node-b-observed-policy-gossip".to_vec(),
        &object_id_key,
    );
    verify_stored_object_integrity(&observer_anchor, &object_id_key);
    store_b
        .put(observer_anchor.clone())
        .await
        .expect("node B stores observer anchor object");
    node_a.announce_object(
        &zone,
        &policy_object.object_id,
        ObjectAdmissionClass::Admitted,
        NOW_MS,
    );
    node_b.announce_object(
        &zone,
        &observer_anchor.object_id,
        ObjectAdmissionClass::Admitted,
        NOW_MS,
    );
    node_a.announce_object(
        &zone,
        &bundle_object.object_id,
        ObjectAdmissionClass::Admitted,
        NOW_MS,
    );
    log_event(
        "write_mesh_store",
        "stored",
        &json!({
            "policy_object_id": policy_object.object_id.to_string(),
            "bundle_object_id": bundle_object.object_id.to_string(),
            "policy_hash": expected_policy_hash,
        }),
    );

    let summary = sign_gossip_summary(&mut node_a, &zone, &node_a_key);
    assert_eq!(summary.object_count, 2);
    let summary_outcome = node_b
        .handle_gossip_message(GossipMessage::Summary(summary), NOW_SECS)
        .expect("peer accepts signed gossip summary from authorized node A");
    assert!(
        summary_outcome.response.is_none(),
        "summary dispatch records peer state without an immediate transport response"
    );
    let node_a_iblt = node_a
        .gossip_mut()
        .build_zone_iblt(&zone, 3)
        .expect("node A builds policy-object reconciliation sketch");
    let reconciliation = node_b
        .gossip_mut()
        .reconcile_zone_iblt(
            &zone,
            &TailscaleNodeId::new(NODE_A),
            &node_a_iblt,
            3,
            NOW_SECS,
        )
        .expect("node B reconciles policy-object gossip against node A");
    assert!(
        reconciliation
            .we_missing_objects
            .contains(&policy_object.object_id),
        "node B must observe that it is missing the policy object advertised by node A"
    );
    assert!(
        reconciliation
            .we_missing_objects
            .contains(&bundle_object.object_id),
        "node B must observe that it is missing the signed policy bundle advertised by node A"
    );
    let request = node_b.gossip_mut().create_request(
        &zone,
        reconciliation.we_missing_objects.clone(),
        NOW_SECS,
    );
    let response = node_a
        .handle_gossip_message(GossipMessage::Request(request), NOW_SECS)
        .expect("node A accepts node B's policy-object gossip request")
        .response
        .expect("gossip request returns immediate object availability response");
    assert_eq!(response.from, TailscaleNodeId::new(NODE_A));
    assert_eq!(response.to, TailscaleNodeId::new(NODE_B));
    assert!(
        response.have_objects.contains(&policy_object.object_id),
        "node A confirms it can serve the policy object"
    );
    assert!(
        response.have_objects.contains(&bundle_object.object_id),
        "node A confirms it can serve the signed policy bundle"
    );
    assert_eq!(node_b.metrics().gossip_updates, 1);
    log_event(
        "gossip_propagation_and_reconciliation",
        "observed",
        &json!({
            "missing_objects": reconciliation
                .we_missing_objects
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            "servable_objects": response
                .have_objects
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        }),
    );

    let transferred_policy = store_a
        .get(&policy_object.object_id)
        .await
        .expect("node A serves policy object");
    let transferred_bundle = store_a
        .get(&bundle_object.object_id)
        .await
        .expect("node A serves bundle object");
    verify_stored_object_integrity(&transferred_policy, &object_id_key);
    verify_stored_object_integrity(&transferred_bundle, &object_id_key);

    let mut tampered_policy = transferred_policy.clone();
    tampered_policy.body[0] ^= 0x01;
    assert_ne!(
        StoredObject::derive_id(
            &tampered_policy.header,
            &tampered_policy.body,
            &object_id_key
        )
        .expect("tampered object remains encodable"),
        tampered_policy.object_id,
        "tampered policy bytes must not match the content-addressed id"
    );
    assert!(
        store_b.put(tampered_policy).await.is_err(),
        "peer store with keyed verifier must reject tampered policy bytes"
    );

    store_b
        .put(transferred_policy.clone())
        .await
        .expect("node B stores verified policy object");
    store_b
        .put(transferred_bundle.clone())
        .await
        .expect("node B stores verified policy bundle");
    log_event(
        "peer_transfer",
        "verified",
        &json!({"content_id_verified": true}),
    );

    let peer_policy_object = store_b
        .get(&policy_object.object_id)
        .await
        .expect("peer has policy object after transfer");
    let peer_bundle_object = store_b
        .get(&bundle_object.object_id)
        .await
        .expect("peer has bundle object after transfer");
    assert_eq!(object_hash(&peer_policy_object.body), expected_policy_hash);
    assert_eq!(
        bundle.policies[0].object_hash, expected_policy_hash,
        "bundle ref must bind to policy bytes hash"
    );

    let peer_policy: ZonePolicyObject =
        ciborium::from_reader(peer_policy_object.body.as_slice()).expect("peer decodes policy");
    let peer_bundle: PolicyBundle =
        ciborium::from_reader(peer_bundle_object.body.as_slice()).expect("peer decodes bundle");
    let observed_signature =
        Ed25519Signature::from_bytes(&decode_signature(&peer_bundle.signature.signature));
    owner_key
        .verifying_key()
        .verify(
            &peer_bundle
                .signing_bytes()
                .expect("peer bundle signing bytes"),
            &observed_signature,
        )
        .expect("peer verifies owner signature on propagated bundle");

    let mut resolved_objects = BTreeMap::new();
    resolved_objects.insert(
        "zone-policy".to_string(),
        PolicyBundleObject::ZonePolicy(peer_policy.clone()),
    );
    let resolved = PolicyBundleResolved::new(peer_bundle, resolved_objects);
    assert_eq!(resolved.bundle.bundle_id, POLICY_BUNDLE_ID);
    assert!(
        matches!(
            resolved.objects.get("zone-policy"),
            Some(PolicyBundleObject::ZonePolicy(policy)) if policy.zone_id == zone
        ),
        "resolved policy bundle must carry the propagated zone policy object"
    );

    let related = [policy_object.object_id, bundle_object.object_id];
    let engine = PolicyEngine {
        zone_policy: peer_policy,
    };
    let allow_decision = engine.evaluate_invoke(&policy_decision_input(&zone, &related, true));
    assert_eq!(allow_decision.decision, Decision::Allow);
    assert_eq!(allow_decision.reason_code, DecisionReasonCode::Allow);
    log_event(
        "peer_admission",
        "allowed",
        &json!({"reason": allow_decision.reason_code.as_str()}),
    );

    let revocation = policy_revocation_object(&zone, policy_object.object_id, &owner_key);
    let mut registry = RevocationRegistry::new();
    registry.add_revocation(&revocation);
    assert!(registry.is_revoked_at(&policy_object.object_id, NOW_SECS));

    let issuer_kid = kid_from_label("o9t0e-policy-issuer");
    let node_kid = kid_from_label("o9t0e-policy-node");
    let owner_kid = kid_from_label("o9t0e-owner");
    let mut chain = AttestationChain::rooted_at(owner_kid.clone());
    chain
        .attest_issuance(issuer_kid.clone(), node_kid.clone())
        .expect("issuance edge");
    chain.attest_node(node_kid, owner_kid).expect("node edge");

    let direct_revocation = check_revocation_chain(
        policy_object.object_id,
        issuer_kid.clone(),
        &chain,
        &CascadeConfig::default(),
        0,
        |object_id| {
            registry
                .get_revocation(object_id)
                .map(|revocation| revocation_record(revocation.effective_at.saturating_mul(1000)))
        },
        |_, _| panic!("direct policy-object revocation must stop before hop lookup"),
    )
    .expect_err("direct policy-object revocation must reject");
    assert!(matches!(
        direct_revocation,
        CascadeRejection::TokenRevoked { token_id, .. } if token_id == policy_object.object_id
    ));

    let cascade_revocation = check_revocation_chain(
        policy_object.object_id,
        issuer_kid.clone(),
        &chain,
        &CascadeConfig::default(),
        0,
        |_| None,
        |kid_at_hop, scope| {
            if scope == CascadeHop::IssuerKey && *kid_at_hop == issuer_kid {
                Some(revocation_record(NOW_MS))
            } else {
                None
            }
        },
    )
    .expect_err("issuer-key cascade must reject policy object use");
    assert!(matches!(
        cascade_revocation,
        CascadeRejection::HopRevoked {
            scope: CascadeHop::IssuerKey,
            hop_index: 0,
            ..
        }
    ));

    let denial = engine.evaluate_invoke(&policy_decision_input(&zone, &related, false));
    assert_eq!(denial.decision, Decision::Deny);
    assert_eq!(
        denial.reason_code,
        DecisionReasonCode::RevocationStaleFrontier
    );

    let audit_entry = audit_policy_denial(policy_object.object_id, &cascade_revocation);
    assert_eq!(
        audit_entry.event_type,
        event_types::CAPABILITY_CONSTRAINT_DENIED
    );
    assert_eq!(audit_entry.severity, Severity::Warning);
    assert_eq!(
        audit_entry
            .metadata
            .get("constraint_kind")
            .and_then(Value::as_str),
        Some("issuer_key_revoked")
    );
    log_event(
        "revocation_cascade",
        "denied_and_audited",
        &json!({
            "direct_revocation": "policy_object_revoked",
            "cascade_revocation": "issuer_key_revoked",
            "admission_reason": denial.reason_code.as_str(),
            "audit_event_type": audit_entry.event_type,
        }),
    );
}
