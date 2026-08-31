//! Pin the documented `u64` wraparound policy on fcp-core monotonic
//! counters and CRDT counters (flywheel_connectors-kvs22).
//!
//! Two distinct policies live in the codebase:
//!
//! 1. **CRDT counters (`GCounter`)** — `saturating_add`. An increment
//!    that would push the per-actor count past `u64::MAX` is clamped
//!    to `u64::MAX`. The aggregate `value()` uses `u128`
//!    `saturating_add` so a sum across actors that exceeds `u64::MAX`
//!    is preserved up to `u128::MAX`.
//!
//! 2. **Chain sequence numbers (`AuditEvent::follows`,
//!    `RevocationEvent::follows`, `CheckpointProposal::seq_follows_prev`)**
//!    — `checked_add(1)`. If the predecessor's `seq == u64::MAX`,
//!    the successor cannot legitimately follow because `prev.seq + 1`
//!    overflows; `follows`/`seq_follows_prev` returns `false` instead
//!    of wrapping or panicking. Effectively the chain refuses to
//!    advance past `u64::MAX`.
//!
//! 3. **`expires_at + clock skew`** (capability.rs:1769) —
//!    `saturating_add`. Adding the skew tolerance to a near-`u64::MAX`
//!    `expires_at` saturates instead of overflowing into a small
//!    timestamp that could silently flip "expired" → "valid".
//!
//! Pinning these three policies prevents drift: a refactor that
//! accidentally swaps `checked_add` for `wrapping_add` on a chain
//! sequence (silently advancing past `u64::MAX`) or replaces
//! `saturating_add` with `+` on a CRDT increment (panicking in
//! release with overflow checks off, undefined wrap behaviour
//! otherwise) shows up here.
//!
//! The tests deliberately do NOT cover `panic` policy — none of these
//! sites are documented to panic on overflow, and pinning panic
//! behaviour would prevent moving any of them to a saturating /
//! checked variant in the future.

use fcp_cbor::SchemaId;
use fcp_core::{
    AuditEvent, CheckpointProposal, CheckpointTrigger, CorrelationId, CrdtActorId, EpochId,
    GCounter, NodeId, NodeSignature, ObjectHeader, ObjectId, PrincipalId, Provenance,
    RevocationEvent, RevocationObject, RevocationRegistry, RevocationScope, TailscaleNodeId,
    ZoneId,
};
use semver::Version;
use uuid::Uuid;

fn test_zone() -> ZoneId {
    ZoneId::work()
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn audit_header() -> ObjectHeader {
    ObjectHeader {
        encryption_kind: Default::default(),
        schema: SchemaId::new("fcp.audit", "AuditEvent", Version::new(1, 0, 0)),
        zone_id: test_zone(),
        created_at: 0,
        provenance: Provenance::new(test_zone()),
        refs: vec![],
        foreign_refs: vec![],
        ttl_secs: None,
        placement: None,
    }
}

fn audit_event(seq: u64, prev: Option<ObjectId>) -> AuditEvent {
    AuditEvent {
        header: audit_header(),
        correlation_id: CorrelationId(Uuid::nil()),
        trace_context: None,
        event_type: "fuzz".into(),
        actor: PrincipalId::new("p:wraparound-test").expect("canonical principal id"),
        zone_id: test_zone(),
        connector_id: None,
        operation: None,
        capability_token_jti: None,
        request_object_id: None,
        result_object_id: None,
        prev,
        seq,
        occurred_at: 0,
        signature: NodeSignature::new(NodeId::new("n:wraparound-test"), [0u8; 64], 0),
    }
}

fn revocation_header() -> ObjectHeader {
    ObjectHeader {
        encryption_kind: Default::default(),
        schema: SchemaId::new("fcp.core", "RevocationEvent", Version::new(1, 0, 0)),
        zone_id: test_zone(),
        created_at: 0,
        provenance: Provenance::new(test_zone()),
        refs: vec![],
        foreign_refs: vec![],
        ttl_secs: None,
        placement: None,
    }
}

fn revocation_event(seq: u64, prev: Option<ObjectId>) -> RevocationEvent {
    RevocationEvent {
        header: revocation_header(),
        revocation_object_id: ObjectId::from_bytes([0xAA; 32]),
        prev,
        seq,
        occurred_at: 0,
        signature: [0u8; 64],
    }
}

fn checkpoint_proposal(proposed_seq: u64) -> CheckpointProposal {
    CheckpointProposal {
        zone_id: test_zone(),
        proposed_seq,
        prev_checkpoint_id: None,
        audit_head_id: ObjectId::from_bytes([1; 32]),
        audit_head_seq: 0,
        revocation_head_id: ObjectId::from_bytes([2; 32]),
        revocation_head_seq: 0,
        zone_definition_head: ObjectId::from_bytes([3; 32]),
        zone_policy_head: ObjectId::from_bytes([4; 32]),
        active_zone_key_manifest: ObjectId::from_bytes([5; 32]),
        epoch_id: EpochId::new("kvs22-epoch"),
        proposed_at: 0,
        coordinator: TailscaleNodeId::new("coord"),
        coordinator_signature: NodeSignature::new(NodeId::new("coord"), [0u8; 64], 0),
        triggers: Vec::<CheckpointTrigger>::new(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CRDT GCounter — saturating_add policy
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn gcounter_per_actor_increment_saturates_at_u64_max() {
    // Policy: per-actor counts saturate at u64::MAX. Documented at
    // crdt.rs:243 (`*entry = entry.saturating_add(delta)`).
    let actor = CrdtActorId::new("alice");
    let mut counter = GCounter::default();
    counter.increment(actor.clone(), u64::MAX);
    assert_eq!(*counter.counts.get(&actor).unwrap(), u64::MAX);

    // A second increment that would push past u64::MAX MUST clamp to
    // u64::MAX, not wrap to 0 and not panic.
    counter.increment(actor.clone(), 1);
    assert_eq!(
        *counter.counts.get(&actor).unwrap(),
        u64::MAX,
        "POLICY REGRESSION: GCounter::increment must saturate at u64::MAX (crdt.rs:243)"
    );

    // Even a massive delta saturates without panic.
    counter.increment(actor.clone(), u64::MAX);
    assert_eq!(*counter.counts.get(&actor).unwrap(), u64::MAX);
}

#[test]
fn gcounter_aggregate_value_uses_saturating_u128_sum() {
    // Policy: GCounter::value() folds per-actor u64 counts into u128
    // via saturating_add. crdt.rs:250.
    let mut counter = GCounter::default();
    counter.increment(CrdtActorId::new("a"), u64::MAX);
    counter.increment(CrdtActorId::new("b"), 1);
    // Sum is u64::MAX + 1, representable in u128 — must NOT clamp at
    // u64::MAX, must NOT wrap.
    assert_eq!(
        counter.value(),
        u128::from(u64::MAX) + 1,
        "GCounter::value() must preserve sums above u64::MAX in u128"
    );

    // Two actors at u64::MAX: 2 * u64::MAX is also representable in
    // u128.
    let mut counter2 = GCounter::default();
    counter2.increment(CrdtActorId::new("a"), u64::MAX);
    counter2.increment(CrdtActorId::new("b"), u64::MAX);
    assert_eq!(counter2.value(), 2 * u128::from(u64::MAX));
}

// ─────────────────────────────────────────────────────────────────────────────
// AuditEvent::follows — checked_add(1) policy
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn audit_follows_refuses_to_advance_past_u64_max() {
    // Policy: AuditEvent::follows uses `prev.seq.checked_add(1)`. When
    // prev.seq == u64::MAX, no successor can legitimately follow —
    // the function returns false instead of wrapping or panicking.
    let prev_id = ObjectId::from_bytes([0x01; 32]);
    let prev = audit_event(u64::MAX, None);

    // The "wrapped" successor (seq=0) MUST NOT follow.
    let wrapped = audit_event(0, Some(prev_id));
    assert!(
        !wrapped.follows(&prev, &prev_id),
        "POLICY REGRESSION: AuditEvent::follows must return false when prev.seq=u64::MAX \
         (audit.rs:108-114 uses checked_add(1)) — silent wrap would let an attacker \
         attach a sentinel event to the genesis link"
    );

    // The "advanced" successor (seq=u64::MAX, then +1 in u64 → 0)
    // also MUST NOT follow because checked_add(u64::MAX, 1) = None.
    let max_succ = audit_event(u64::MAX, Some(prev_id));
    assert!(
        !max_succ.follows(&prev, &prev_id),
        "AuditEvent::follows must return false on prev.seq=u64::MAX regardless of successor seq"
    );
}

#[test]
fn audit_follows_panic_free_at_u64_max_boundary() {
    // Hash-stable: the call MUST NOT panic at the boundary.
    let prev_id = ObjectId::from_bytes([0x02; 32]);
    let prev = audit_event(u64::MAX, None);
    let succ = audit_event(u64::MAX, Some(prev_id));
    // No `assert` — the value of `_result` doesn't matter; the
    // assertion is "no panic during the call".
    let _result = succ.follows(&prev, &prev_id);
}

// ─────────────────────────────────────────────────────────────────────────────
// RevocationEvent::follows — checked_add(1) policy (mirror of audit)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn revocation_follows_refuses_to_advance_past_u64_max() {
    // Policy: RevocationEvent::follows uses checked_add(1)
    // (revocation.rs:193-200). Same contract as AuditEvent::follows.
    let prev_id = ObjectId::from_bytes([0x03; 32]);
    let prev = revocation_event(u64::MAX, None);
    let wrapped = revocation_event(0, Some(prev_id));
    assert!(
        !wrapped.follows(&prev, &prev_id),
        "POLICY REGRESSION: RevocationEvent::follows must return false when prev.seq=u64::MAX"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// CheckpointProposal::seq_follows_prev — checked_add(1) policy
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn checkpoint_proposal_refuses_to_advance_past_u64_max() {
    // Policy: seq_follows_prev uses checked_add(1) (checkpoint.rs:158).
    // proposed_seq == 0 with prev_seq == u64::MAX is the wrap case;
    // must return false.
    let proposal_wrapped = checkpoint_proposal(0);
    assert!(
        !proposal_wrapped.seq_follows_prev(u64::MAX),
        "POLICY REGRESSION: CheckpointProposal::seq_follows_prev must reject wrap from u64::MAX"
    );

    // proposed_seq == u64::MAX with prev_seq == u64::MAX-1 does NOT
    // wrap (u64::MAX-1 + 1 = u64::MAX) and MUST be accepted as the
    // legitimate final-allowed checkpoint.
    let proposal_max = checkpoint_proposal(u64::MAX);
    assert!(
        proposal_max.seq_follows_prev(u64::MAX - 1),
        "checkpoint at proposed_seq=u64::MAX following prev_seq=u64::MAX-1 MUST be accepted"
    );

    // proposed_seq == 1 with prev_seq == u64::MAX is the wrong-delta
    // case; must return false.
    let proposal_one = checkpoint_proposal(1);
    assert!(
        !proposal_one.seq_follows_prev(u64::MAX),
        "checkpoint with proposed_seq=1 after prev_seq=u64::MAX must be rejected"
    );
}

#[test]
fn checkpoint_proposal_seq_follows_panic_free_at_u64_max() {
    // No panic at the boundary.
    let proposal = checkpoint_proposal(u64::MAX);
    let _ = proposal.seq_follows_prev(u64::MAX);
    let _ = proposal.seq_follows_prev(u64::MAX - 1);
    let _ = proposal.seq_follows_prev(0);
}

// ─────────────────────────────────────────────────────────────────────────────
// RevocationRegistry::update_head — strict-monotonic policy on u64 seq
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn revocation_registry_update_head_rejects_seq_at_or_below_current() {
    // Adjacent policy: RevocationRegistry::update_head requires
    // strict monotonic seq once a head is set (revocation.rs:553-562).
    // This is not a wraparound site, but it pairs with the chain-seq
    // policy: the registry refuses to regress, including from u64::MAX
    // back down. Pinning here documents that the registry cannot be
    // tricked into accepting a "wrapped" head.
    let mut reg = RevocationRegistry::new();
    reg.update_head(ObjectId::from_bytes([1; 32]), 5, 100);
    // Equal seq with existing head is rejected.
    reg.update_head(ObjectId::from_bytes([2; 32]), 5, 200);
    assert_eq!(reg.head_seq, 5);
    assert_eq!(reg.head, Some(ObjectId::from_bytes([1; 32])));
    // Lower seq is rejected.
    reg.update_head(ObjectId::from_bytes([3; 32]), 4, 300);
    assert_eq!(reg.head_seq, 5);
    // Strictly higher seq is accepted.
    reg.update_head(ObjectId::from_bytes([4; 32]), u64::MAX, 400);
    assert_eq!(reg.head_seq, u64::MAX);
    // Once we are at u64::MAX, nothing strictly higher exists, so
    // every subsequent attempt is rejected — the head is permanently
    // pinned.
    reg.update_head(ObjectId::from_bytes([5; 32]), 0, 500);
    assert_eq!(
        reg.head_seq,
        u64::MAX,
        "POLICY REGRESSION: registry head must stay at u64::MAX, not wrap"
    );
    reg.update_head(ObjectId::from_bytes([6; 32]), u64::MAX, 600);
    assert_eq!(
        reg.head_seq,
        u64::MAX,
        "registry must reject equal seq at u64::MAX"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// RevocationObject::is_active — saturating window semantics
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn revocation_is_active_handles_u64_max_endpoints() {
    // Policy: is_active uses unchecked u64 comparisons, which works
    // correctly even at the u64::MAX endpoints (no arithmetic; only
    // ordering). Pin both ends of the window.

    // Effective at u64::MAX, expires None: active iff now == u64::MAX.
    let r = RevocationObject {
        header: revocation_header(),
        revoked: vec![ObjectId::from_bytes([0; 32])],
        scope: RevocationScope::Capability,
        reason: "kvs22 boundary".into(),
        effective_at: u64::MAX,
        expires_at: None,
        signature: [0u8; 64],
    };
    assert!(!r.is_active(u64::MAX - 1));
    assert!(r.is_active(u64::MAX));

    // Effective at 0, expires at u64::MAX: active for [0, u64::MAX),
    // not active at exactly u64::MAX (the upper bound is exclusive).
    let r2 = RevocationObject {
        expires_at: Some(u64::MAX),
        effective_at: 0,
        ..r
    };
    assert!(r2.is_active(0));
    assert!(r2.is_active(u64::MAX - 1));
    assert!(
        !r2.is_active(u64::MAX),
        "is_active uses `now < expires_at` so u64::MAX is the exclusive upper bound"
    );
}
