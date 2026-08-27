//! Revocation timing integration tests [MOR/C1.6]
//!
//! Proves bounded enforcement windows for the revocation pipeline:
//! - Seal pattern (C1.1): check → use → validate atomicity
//! - Exact membership (C1.2): zero false positives under load
//! - Freshness class (C1.3): Critical/Risky/Safe enforcement
//! - SLA checking (C1.4): zone-wide revocation freshness SLA
//! - Priority gossip (C1.5): push latency bounds

use fcp_cbor::SchemaId;
use fcp_mesh::gossip::{
    GossipConfig, GossipMessage, MeshGossip, PriorityGossipPolicy, RevocationPushMessage,
};
use fcp_prelude::{
    FreshnessPolicy, ObjectHeader, ObjectId, Provenance, RevocationDecision,
    RevocationFreshnessClass, RevocationObject, RevocationRegistry, RevocationScope,
    RevocationSlaChecker, RevocationSlaStatus, TailscaleNodeId, ZoneId,
};
use semver::Version;

fn test_header() -> ObjectHeader {
    ObjectHeader {
        schema: SchemaId::new("fcp.core", "Revocation", Version::new(1, 0, 0)),
        zone_id: ZoneId::work(),
        created_at: 1_700_000_000,
        provenance: Provenance::new(ZoneId::work()),
        refs: vec![],
        foreign_refs: vec![],
        ttl_secs: None,
        placement: None,
    }
}

fn test_object_id(label: &str) -> ObjectId {
    ObjectId::from_unscoped_bytes(label.as_bytes())
}

fn make_id_from_u32(i: u32) -> ObjectId {
    let mut b = [0u8; 32];
    b[..4].copy_from_slice(&i.to_le_bytes());
    ObjectId::from_bytes(b)
}

fn test_peer(name: &str) -> TailscaleNodeId {
    TailscaleNodeId::new(name)
}

fn make_revocation(revoked_ids: &[ObjectId]) -> RevocationObject {
    RevocationObject {
        header: test_header(),
        revoked: revoked_ids.to_vec(),
        scope: RevocationScope::Capability,
        reason: "Test revocation".into(),
        effective_at: 1_700_000_000,
        expires_at: None,
        signature: [0u8; 64],
    }
}

// ── Scenario 1: Issue → Use → Revoke → Reject ─────────────────────────────

#[test]
fn scenario_issue_use_revoke_reject() {
    let mut registry = RevocationRegistry::new();
    let token_id = test_object_id("capability-token-1");
    registry.update_head(test_object_id("head-0"), 0, 100);

    // Phase 1: issue — token is not revoked
    let seal = registry.check_with_seal(&token_id, 101);
    assert_eq!(seal.decision, RevocationDecision::NotRevoked);
    assert!(registry.validate_seal(&seal, &token_id).is_valid());

    // Phase 2: use — operation proceeds with valid seal (simulated)

    // Phase 3: revoke — add revocation
    registry.add_revocation(&make_revocation(&[token_id]));
    registry.update_head(test_object_id("head-1"), 1, 200);

    // Phase 4: reject — new check shows revoked
    let new_seal = registry.check_with_seal(&token_id, 201);
    assert_eq!(new_seal.decision, RevocationDecision::Revoked);
}

// ── Scenario 2: TOCTOU with seal ───────────────────────────────────────────

#[test]
fn scenario_toctou_concurrent_revocation_detected_by_seal() {
    let mut registry = RevocationRegistry::new();
    let token_id = test_object_id("toctou-token");
    registry.update_head(test_object_id("head-0"), 5, 500);

    // Check: token not revoked
    let seal = registry.check_with_seal(&token_id, 501);
    assert_eq!(seal.decision, RevocationDecision::NotRevoked);

    // Between check and commit: revocation arrives
    registry.add_revocation(&make_revocation(&[token_id]));
    registry.update_head(test_object_id("head-1"), 6, 502);

    // Commit: seal validation catches the race
    let validation = registry.validate_seal(&seal, &token_id);
    assert!(!validation.is_valid());

    // Re-check: now sees revocation
    let fresh_seal = registry.check_with_seal(&token_id, 503);
    assert_eq!(fresh_seal.decision, RevocationDecision::Revoked);
}

// ── Scenario 3: 3-node simulated mesh propagation ──────────────────────────

#[test]
fn scenario_revocation_propagation_across_3_nodes() {
    let mut node_a = RevocationRegistry::new();
    let mut node_b = RevocationRegistry::new();
    let mut node_c = RevocationRegistry::new();

    let token_id = test_object_id("mesh-token");
    let head = test_object_id("head-0");
    node_a.update_head(head, 10, 1000);
    node_b.update_head(head, 10, 1000);
    node_c.update_head(head, 10, 1000);

    // Node A issues revocation
    let revocation = make_revocation(&[token_id]);
    node_a.add_revocation(&revocation);
    node_a.update_head(test_object_id("head-1"), 11, 1001);

    // Node A creates push message (C1.5)
    let push = RevocationPushMessage::new(
        TailscaleNodeId::new("node-a"),
        ZoneId::work(),
        vec![token_id],
        11,
        1001,
    );
    assert_eq!(push.revoked_ids.len(), 1);
    assert_eq!(push.revoked_ids[0], token_id);

    // Node B receives push
    node_b.add_revocation(&revocation);
    node_b.update_head(test_object_id("head-1"), 11, 1002);

    // Node C receives push
    node_c.add_revocation(&revocation);
    node_c.update_head(test_object_id("head-1"), 11, 1003);

    // All nodes agree: token is revoked
    assert!(node_a.is_revoked(&token_id));
    assert!(node_b.is_revoked(&token_id));
    assert!(node_c.is_revoked(&token_id));
}

// ── Scenario 4: Degraded mode — stale cache ───────────────────────────────

#[test]
fn scenario_degraded_mode_stale_revocation_cache() {
    let checker = RevocationSlaChecker::new(10, 1_700_000_000, 300);

    // Within SLA: operations proceed
    assert!(checker.check_sla(1_700_000_200).is_fresh());

    // SLA breached
    assert!(!checker.check_sla(1_700_000_500).is_fresh());

    // Critical ops MUST abort on breach
    assert!(!checker.may_proceed(1_700_000_500, RevocationFreshnessClass::Critical));

    // Risky/Safe may proceed
    assert!(checker.may_proceed(1_700_000_500, RevocationFreshnessClass::Risky));
    assert!(checker.may_proceed(1_700_000_500, RevocationFreshnessClass::Safe));
}

// ── Scenario 5: Freshness class enforcement ────────────────────────────────

#[test]
fn scenario_freshness_class_enforcement() {
    let critical = RevocationFreshnessClass::Critical;
    assert!(critical.allows_policy(FreshnessPolicy::Strict));
    assert!(!critical.allows_policy(FreshnessPolicy::Warn));
    assert!(!critical.allows_policy(FreshnessPolicy::BestEffort));

    let risky = RevocationFreshnessClass::Risky;
    assert!(risky.allows_policy(FreshnessPolicy::Strict));
    assert!(risky.allows_policy(FreshnessPolicy::Warn));
    assert!(!risky.allows_policy(FreshnessPolicy::BestEffort));

    let safe = RevocationFreshnessClass::Safe;
    assert!(safe.allows_policy(FreshnessPolicy::BestEffort));
}

// ── Scenario 6: Priority push wire format ──────────────────────────────────

#[test]
fn scenario_priority_push_wire_format_roundtrip() {
    let push = RevocationPushMessage::new(
        TailscaleNodeId::new("node-1"),
        ZoneId::work(),
        vec![test_object_id("tok-1"), test_object_id("tok-2")],
        42,
        1_700_000_000,
    );

    let msg = GossipMessage::RevocationPush(push);
    let json = serde_json::to_string(&msg).unwrap();
    let roundtripped: GossipMessage = serde_json::from_str(&json).unwrap();

    match roundtripped {
        GossipMessage::RevocationPush(m) => {
            assert_eq!(m.revoked_ids.len(), 2);
            assert_eq!(m.new_rev_seq, 42);
        }
        _ => panic!("expected RevocationPush"),
    }
}

// ── Scenario 7: Zero false positives under load ────────────────────────────

#[test]
fn scenario_zero_false_positives_10k_revocations() {
    let mut registry = RevocationRegistry::new();

    for i in 0u32..10_000 {
        registry.add_revocation(&make_revocation(&[make_id_from_u32(i)]));
    }

    // Zero false positives on non-revoked IDs
    for i in 10_000u32..20_000 {
        assert!(
            !registry.is_revoked(&make_id_from_u32(i)),
            "false positive for id {i}"
        );
    }

    // All revoked IDs found
    for i in 0u32..10_000 {
        assert!(
            registry.is_revoked(&make_id_from_u32(i)),
            "missed revocation for id {i}"
        );
    }
}

// ── Scenario 8: Bounded enforcement window ────────────────────────────────

#[test]
fn scenario_bounded_enforcement_window() {
    let mut registry = RevocationRegistry::new();
    let token_id = test_object_id("bounded-token");
    registry.update_head(test_object_id("head-0"), 0, 100);

    // Token is usable
    assert!(!registry.is_revoked(&token_id));

    // Revocation applied: enforcement is IMMEDIATE (zero lag)
    registry.add_revocation(&make_revocation(&[token_id]));
    assert!(registry.is_revoked(&token_id));

    // Seal check also immediate
    let seal = registry.check_with_seal(&token_id, 101);
    assert_eq!(seal.decision, RevocationDecision::Revoked);
}

// ── Scenario 9: SLA boundary precision ─────────────────────────────────────

#[test]
fn scenario_sla_boundary_precision() {
    let checker = RevocationSlaChecker::new(100, 1000, 5);

    // Exactly at boundary: still fresh
    assert!(checker.check_sla(1005).is_fresh());

    // One second past: breached
    assert_eq!(
        checker.check_sla(1006),
        RevocationSlaStatus::Breached { overdue_secs: 1 }
    );

    // Well past: large overdue
    assert_eq!(
        checker.check_sla(2000),
        RevocationSlaStatus::Breached { overdue_secs: 995 }
    );
}

// ── Scenario 10: Priority policy configuration ─────────────────────────────

#[test]
fn scenario_priority_policy_interval_comparison() {
    let config = GossipConfig::default();

    let direct = PriorityGossipPolicy::DirectPush;
    let standard = PriorityGossipPolicy::Standard;

    assert!(direct.interval_ms(&config) < standard.interval_ms(&config));
    assert_eq!(direct.interval_ms(&config), 100);
    assert_eq!(standard.interval_ms(&config), 300);
    assert!(direct.uses_direct_push());
    assert!(!standard.uses_direct_push());
}

// ── Scenario 11: Direct revocation push fanout rate-limit ──────────────────

#[test]
fn scenario_priority_push_fanout_caps_peers_and_preserves_order() {
    let mut gossip = MeshGossip::new(
        test_peer("local-node"),
        GossipConfig {
            max_revocation_push_peers: 2,
            ..GossipConfig::default()
        },
    );
    let peers = vec![
        test_peer("peer-a"),
        test_peer("peer-b"),
        test_peer("peer-c"),
    ];

    let plan = gossip.plan_revocation_push_fanout(
        &ZoneId::work(),
        &peers,
        PriorityGossipPolicy::DirectPush,
        1_000,
    );

    assert_eq!(plan.selected_peers, peers[..2].to_vec());
    assert_eq!(plan.next_allowed_at_ms, Some(1_100));
}

#[test]
fn scenario_priority_push_fanout_collapses_within_interval() {
    let mut gossip = MeshGossip::new(test_peer("local-node"), GossipConfig::default());
    let peers = vec![test_peer("peer-a"), test_peer("peer-b")];

    let first = gossip.plan_revocation_push_fanout(
        &ZoneId::work(),
        &peers,
        PriorityGossipPolicy::DirectPush,
        1_000,
    );
    assert_eq!(first.selected_peers, peers);

    let collapsed = gossip.plan_revocation_push_fanout(
        &ZoneId::work(),
        &peers,
        PriorityGossipPolicy::DirectPush,
        1_050,
    );
    assert_eq!(
        collapsed.selected_peers,
        [] as [fcp_prelude::TailscaleNodeId; 0]
    );
    assert_eq!(collapsed.next_allowed_at_ms, Some(1_100));
}

#[test]
fn scenario_priority_push_fanout_resumes_after_interval() {
    let mut gossip = MeshGossip::new(test_peer("local-node"), GossipConfig::default());
    let peers = vec![test_peer("peer-a"), test_peer("peer-b")];

    let _ = gossip.plan_revocation_push_fanout(
        &ZoneId::work(),
        &peers,
        PriorityGossipPolicy::DirectPush,
        1_000,
    );
    let resumed = gossip.plan_revocation_push_fanout(
        &ZoneId::work(),
        &peers,
        PriorityGossipPolicy::DirectPush,
        1_100,
    );

    assert_eq!(resumed.selected_peers, peers);
    assert_eq!(resumed.next_allowed_at_ms, Some(1_200));
}
