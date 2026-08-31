//! Conformance: `ZoneCheckpoint` revocation freshness SLA evaluator
//! (flywheel_connectors-pf6vc — references C1.4).
//!
//! `ZoneCheckpoint::revocation_freshness_sla_secs` declares the
//! per-zone SLA window for revocation-frontier freshness. When the
//! frontier is older than the SLA, the zone enters DEGRADED revocation
//! state and `Critical` operations MUST abort. `Risky` and `Safe`
//! operations may always proceed.
//!
//! `RevocationSlaChecker::check_sla` is the NORMATIVE evaluator:
//!
//!   - `age = now.saturating_sub(checkpoint_updated_at)`
//!   - `age <= sla_secs` → `Fresh`
//!   - otherwise → `Breached { overdue_secs: age - sla_secs }`
//!
//! `ZoneCheckpoint::default_revocation_sla()` (audit.rs:148) returns
//! 300 seconds — that's the sealed default every checkpoint serialized
//! without `revocation_freshness_sla_secs` falls back to.
//!
//! Properties pinned (NORMATIVE):
//!
//! 1. **300 s default**: a checkpoint produced via the `serde(default)`
//!    fallback has `revocation_freshness_sla_secs == 300`.
//! 2. **Stale rejection at the default**: a 300 s SLA breaches at age
//!    301 s; `Critical` MUST abort, `Risky` and `Safe` MAY proceed.
//! 3. **Custom SLA value**: an explicit 60 s SLA breaches at 61 s.
//! 4. **Exactly-at-boundary**: `age == sla_secs` → `Fresh` (the gate is
//!    `<=`, not `<`).
//! 5. **Boundary + 1 second**: `age == sla_secs + 1` → `Breached { 1 }`.
//! 6. **Future-dated checkpoint**: `now < checkpoint_updated_at`
//!    saturates `age` to 0 → `Fresh`. No panic, no negative wrap.
//! 7. **Zero-second SLA**: `sla_secs == 0` is the strictest gate; only
//!    `age == 0` is Fresh, `age == 1` is `Breached { 1 }`.
//! 8. **`is_fresh` ⇔ `Fresh`** variant.
//!
//! Reference inputs deliberately use the integer second values from the
//! production code paths (300 for the default SLA) so any drift in
//! `default_revocation_sla()` shows up here.

use fcp_cbor::SchemaId;
use fcp_prelude::{
    EpochId, ObjectHeader, ObjectId, Provenance, RevocationFreshnessClass, RevocationSlaChecker,
    RevocationSlaStatus, SignatureSet, ZoneCheckpoint, ZoneId,
};
use semver::Version;

const DEFAULT_SLA_SECS: u64 = 300;

fn test_zone() -> ZoneId {
    ZoneId::work()
}

const fn test_object_id(seed: u8) -> ObjectId {
    ObjectId::from_bytes([seed; 32])
}

fn checkpoint_header() -> ObjectHeader {
    ObjectHeader {
        encryption_kind: Default::default(),
        schema: SchemaId::new("fcp.audit", "ZoneCheckpoint", Version::new(1, 0, 0)),
        zone_id: test_zone(),
        created_at: 0,
        provenance: Provenance::new(test_zone()),
        refs: vec![],
        foreign_refs: vec![],
        ttl_secs: None,
        placement: None,
    }
}

/// A minimal `ZoneCheckpoint` with placeholder heads. The values that
/// matter for these tests are `revocation_freshness_sla_secs` and
/// `rev_seq`.
fn test_checkpoint(rev_seq: u64, sla_secs: u64) -> ZoneCheckpoint {
    ZoneCheckpoint {
        header: checkpoint_header(),
        zone_id: test_zone(),
        rev_head: test_object_id(0xA1),
        rev_seq,
        audit_head: test_object_id(0xA2),
        audit_seq: 0,
        zone_definition_head: test_object_id(0xA3),
        zone_policy_head: test_object_id(0xA4),
        active_zone_key_manifest: test_object_id(0xA5),
        checkpoint_seq: 0,
        as_of_epoch: EpochId::new("conformance-epoch-0"),
        quorum_signatures: SignatureSet::new(),
        revocation_freshness_sla_secs: sla_secs,
    }
}

const fn checker(checkpoint_updated_at: u64, sla_secs: u64) -> RevocationSlaChecker {
    RevocationSlaChecker::new(0, checkpoint_updated_at, sla_secs)
}

#[test]
fn zone_checkpoint_default_revocation_sla_is_300_seconds() {
    // Pin the audit.rs:148 `default_revocation_sla` constant via the
    // serde(default) path: a `ZoneCheckpoint` serialized WITHOUT
    // `revocation_freshness_sla_secs` and re-deserialized MUST resolve
    // to 300.
    let mut cp = test_checkpoint(0, DEFAULT_SLA_SECS);
    let mut value = serde_json::to_value(&cp).expect("serialize checkpoint");
    let obj = value
        .as_object_mut()
        .expect("ZoneCheckpoint serializes as a JSON object");
    assert!(
        obj.remove("revocation_freshness_sla_secs").is_some(),
        "expected revocation_freshness_sla_secs in serialized form"
    );
    let json_without_sla = serde_json::to_string(&value).expect("re-encode without sla");

    cp = serde_json::from_str(&json_without_sla)
        .expect("ZoneCheckpoint without sla_secs MUST deserialize via serde(default)");

    assert_eq!(
        cp.revocation_freshness_sla_secs, DEFAULT_SLA_SECS,
        "DEFAULT REGRESSION: revocation_freshness_sla_secs default must be 300 seconds (audit.rs:148)"
    );
}

#[test]
fn stale_checkpoint_at_default_sla_blocks_critical_only() {
    // 300 s SLA, checkpoint at t=1000, now=1301 ⇒ age=301 ⇒ Breached{1}.
    let chk = checker(1_000, DEFAULT_SLA_SECS);
    let now = 1_301;
    let status = chk.check_sla(now);
    match status {
        RevocationSlaStatus::Breached { overdue_secs } => {
            assert_eq!(
                overdue_secs, 1,
                "default SLA breach must carry overdue_secs = age - sla = 1"
            );
        }
        RevocationSlaStatus::Fresh => panic!("age=301, sla=300 expected Breached{{1}}, got Fresh"),
    }
    assert!(!status.is_fresh(), "is_fresh must be false on Breached");

    // Critical MUST abort.
    assert!(
        !chk.may_proceed(now, RevocationFreshnessClass::Critical),
        "Critical MUST abort under Breached SLA"
    );
    // Risky / Safe MAY proceed.
    assert!(
        chk.may_proceed(now, RevocationFreshnessClass::Risky),
        "Risky MAY proceed under Breached SLA"
    );
    assert!(
        chk.may_proceed(now, RevocationFreshnessClass::Safe),
        "Safe MAY proceed under Breached SLA"
    );
}

#[test]
fn custom_sla_value_breach_pinned() {
    // 60 s SLA, age=61 ⇒ Breached{1}. Demonstrates the evaluator does
    // not hardcode 300 anywhere — the SLA value is honoured verbatim.
    let chk = checker(1_000, 60);
    match chk.check_sla(1_061) {
        RevocationSlaStatus::Breached { overdue_secs: 1 } => {}
        RevocationSlaStatus::Breached { overdue_secs } => {
            panic!(
                "custom 60s SLA at age=61 expected Breached{{1}}, got overdue_secs={overdue_secs}"
            )
        }
        RevocationSlaStatus::Fresh => {
            panic!("custom 60s SLA at age=61 expected Breached{{1}}, got Fresh")
        }
    }

    // Just inside the window.
    match chk.check_sla(1_060) {
        RevocationSlaStatus::Fresh => {}
        RevocationSlaStatus::Breached { overdue_secs } => panic!(
            "custom 60s SLA at age=60 (exactly at SLA) expected Fresh, got overdue_secs={overdue_secs}"
        ),
    }
}

#[test]
fn exactly_at_boundary_is_fresh() {
    // RFC contract: the gate is `age <= sla_secs`. Verify that
    // age == sla_secs is Fresh on multiple SLA values.
    for sla in [0u64, 1, 60, DEFAULT_SLA_SECS, 3_600, u64::MAX / 2] {
        let chk = checker(0, sla);
        let now = sla;
        match chk.check_sla(now) {
            RevocationSlaStatus::Fresh => {}
            RevocationSlaStatus::Breached { overdue_secs } => panic!(
                "BOUNDARY REGRESSION: age == sla_secs ({sla}) expected Fresh, got overdue_secs={overdue_secs}"
            ),
        }
    }
}

#[test]
fn boundary_plus_one_breaches_with_overdue_one() {
    // age == sla_secs + 1 → Breached{1} for every SLA we pick.
    for sla in [0u64, 1, 60, DEFAULT_SLA_SECS, 3_600] {
        let chk = checker(0, sla);
        let now = sla + 1;
        match chk.check_sla(now) {
            RevocationSlaStatus::Breached { overdue_secs: 1 } => {}
            RevocationSlaStatus::Breached { overdue_secs } => panic!(
                "age=={sla}+1, sla={sla} expected Breached{{1}}, got overdue_secs={overdue_secs}"
            ),
            RevocationSlaStatus::Fresh => {
                panic!("age=={sla}+1, sla={sla} expected Breached{{1}}, got Fresh")
            }
        }
    }
}

#[test]
fn future_dated_checkpoint_saturates_to_fresh() {
    // Clock skew: `now < checkpoint_updated_at` MUST saturate the
    // subtraction to 0 → Fresh. No panic, no wrap to a huge `age`.
    let chk = checker(/* checkpoint_updated_at = */ 10_000, DEFAULT_SLA_SECS);
    for now in [0u64, 1, 5_000, 9_999] {
        match chk.check_sla(now) {
            RevocationSlaStatus::Fresh => {}
            RevocationSlaStatus::Breached { overdue_secs } => panic!(
                "SATURATION REGRESSION: future-dated checkpoint (now={now}, checkpoint_updated_at=10000) \
                 expected Fresh, got overdue_secs={overdue_secs}"
            ),
        }
        // Critical proceeds when the checkpoint is in the future.
        assert!(
            chk.may_proceed(now, RevocationFreshnessClass::Critical),
            "Critical MUST proceed under saturated-to-Fresh state"
        );
    }
}

#[test]
fn zero_second_sla_is_strictest_gate() {
    // sla_secs = 0 is the tightest gate: only `age == 0` is Fresh.
    let chk = checker(1_000, 0);
    match chk.check_sla(1_000) {
        RevocationSlaStatus::Fresh => {}
        RevocationSlaStatus::Breached { overdue_secs } => {
            panic!("sla=0, age=0 expected Fresh, got overdue_secs={overdue_secs}")
        }
    }
    match chk.check_sla(1_001) {
        RevocationSlaStatus::Breached { overdue_secs: 1 } => {}
        RevocationSlaStatus::Breached { overdue_secs } => {
            panic!("sla=0, age=1 expected Breached{{1}}, got overdue_secs={overdue_secs}")
        }
        RevocationSlaStatus::Fresh => panic!("sla=0, age=1 expected Breached{{1}}, got Fresh"),
    }
    // Critical must abort the moment age > 0 under sla=0.
    assert!(
        !chk.may_proceed(1_001, RevocationFreshnessClass::Critical),
        "Critical MUST abort under sla=0 with age>0"
    );
}

#[test]
fn is_fresh_iff_fresh_variant() {
    assert!(RevocationSlaStatus::Fresh.is_fresh());
    assert!(
        !RevocationSlaStatus::Breached { overdue_secs: 1 }.is_fresh(),
        "Breached.is_fresh must be false"
    );
    assert!(
        !RevocationSlaStatus::Breached {
            overdue_secs: u64::MAX
        }
        .is_fresh(),
        "Breached with arbitrary overdue must remain not-fresh"
    );
}

#[test]
fn checkpoint_field_drives_evaluator_pipeline() {
    // The end-to-end story: a `ZoneCheckpoint` carries
    // `revocation_freshness_sla_secs`; the host wires that field +
    // `last_updated` time into `RevocationSlaChecker::new`. Pin the
    // value-flow with both default and explicit SLAs.
    let cp_default = test_checkpoint(/* rev_seq */ 7, DEFAULT_SLA_SECS);
    let chk_default = RevocationSlaChecker::new(
        cp_default.rev_seq,
        /* checkpoint_updated_at */ 0,
        cp_default.revocation_freshness_sla_secs,
    );
    // age=200 < 300 ⇒ Fresh.
    assert!(chk_default.check_sla(200).is_fresh());
    // age=400 > 300 ⇒ Breached{100}.
    match chk_default.check_sla(400) {
        RevocationSlaStatus::Breached { overdue_secs: 100 } => {}
        other => panic!("age=400 sla=300 expected Breached{{100}}, got {other:?}"),
    }

    // Same flow with an explicit non-default SLA value.
    let cp_explicit = test_checkpoint(/* rev_seq */ 7, 600);
    assert_eq!(cp_explicit.revocation_freshness_sla_secs, 600);
    let chk_explicit = RevocationSlaChecker::new(
        cp_explicit.rev_seq,
        0,
        cp_explicit.revocation_freshness_sla_secs,
    );
    assert!(
        chk_explicit.check_sla(600).is_fresh(),
        "exactly-at boundary 600s"
    );
    match chk_explicit.check_sla(601) {
        RevocationSlaStatus::Breached { overdue_secs: 1 } => {}
        other => panic!("explicit 600s SLA at age=601 expected Breached{{1}}, got {other:?}"),
    }

    // Round-trip through serde to exercise the field's serde plumbing.
    let json = serde_json::to_string(&cp_explicit).expect("serialize");
    let deserialized: ZoneCheckpoint = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        deserialized.revocation_freshness_sla_secs, 600,
        "explicit SLA value MUST round-trip through serde"
    );
}
