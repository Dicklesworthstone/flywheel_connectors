//! `fcp_mesh::TransportSelector` routing-decision conformance.
//!
//! `TransportSelector` is the NORMATIVE primitive every `MeshNode`
//! consults to pick a transport for a peer-bound symbol. Three
//! contracts matter:
//!
//! 1. **Priority order** — Direct(4) > Mesh(3) > Derp(2) > Funnel(1).
//!    Drift here would silently change which transport class wins
//!    for every routing decision in the system.
//! 2. **Policy filtering and reason codes** — `ZoneTransportPolicy`
//!    flags drop ineligible paths AND attach a specific
//!    `DecisionReasonCode` (`TransportLanForbidden` /
//!    `TransportDerpForbidden` / `TransportFunnelForbidden`). Operator
//!    tooling reads these reason codes to explain refusals.
//! 3. **Deterministic multipath fan-out** — `select_multipath`
//!    uses `blake3(object_id || symbol_index_le || path_id)` as the
//!    intra-priority-group tie-break, so two `MeshNodes` seeing the
//!    same (object, symbol) pick the same fan-out paths in the same
//!    order. Without determinism, replication would race-fan and
//!    waste bandwidth (or drop messages).
//!
//! Properties pinned (NORMATIVE):
//!
//! - Priority constants: Direct=4, Mesh=3, Derp=2, Funnel=1
//!   (encoded via the observable rank-order, since `priority` is
//!   private — RankedPath.priority field is the public surface).
//! - `transport_mode` mapping: Direct/Mesh→Lan, Derp→Derp,
//!   Funnel→Funnel.
//! - `rank_paths` deterministic sort keys: eligible desc → priority
//!   desc → `estimated_rtt_ms` asc (None = `u32::MAX`) → `path_id` asc →
//!   peer asc.
//! - `best_path` returns the first eligible `RankedPath` or None.
//! - Ineligible paths carry the documented `DecisionReasonCode`.
//! - `select_multipath(fanout=0)` returns empty.
//! - `select_multipath` filters ineligible paths entirely.
//! - `select_multipath` is deterministic across calls with the same
//!   inputs.
//! - `select_multipath` exhausts a higher-priority group before
//!   moving to lower ones.

use fcp_cbor::SchemaId;
use fcp_mesh::{TransportPath, TransportPathKind, TransportSelector};
use fcp_prelude::{
    DecisionReasonCode, ObjectId, ObjectIdKey, TransportMode, ZoneId, ZoneTransportPolicy,
};
use fcp_tailscale::NodeId;
use semver::Version;

const fn allow_all() -> ZoneTransportPolicy {
    ZoneTransportPolicy {
        allow_lan: true,
        allow_derp: true,
        allow_funnel: true,
    }
}

const fn lan_only() -> ZoneTransportPolicy {
    ZoneTransportPolicy {
        allow_lan: true,
        allow_derp: false,
        allow_funnel: false,
    }
}

fn peer(name: &str) -> NodeId {
    NodeId::new(name)
}

fn test_object_id() -> ObjectId {
    let zone = ZoneId::work();
    let schema = SchemaId::new("fcp.test", "MultipathProbe", Version::new(1, 0, 0));
    let key = ObjectIdKey::from_bytes([7u8; 32]);
    ObjectId::new(b"multipath-probe", &zone, &schema, &key)
}

// ─── Priority ordering (NORMATIVE) ──────────────────────────────────

#[test]
fn rank_paths_orders_kinds_direct_mesh_derp_funnel_with_uniform_policy() {
    // With every transport allowed and identical RTTs, the only
    // tie-break is priority. The order MUST be Direct→Mesh→Derp→Funnel.
    let policy = allow_all();
    let paths = vec![
        TransportPath::new(TransportPathKind::Funnel, peer("p4"), "f", Some(5)),
        TransportPath::new(TransportPathKind::Derp, peer("p3"), "d", Some(5)),
        TransportPath::new(TransportPathKind::Mesh, peer("p2"), "m", Some(5)),
        TransportPath::new(TransportPathKind::Direct, peer("p1"), "x", Some(5)),
    ];
    let ranked = TransportSelector::rank_paths(&paths, &policy);
    let kinds: Vec<TransportPathKind> = ranked.iter().map(|r| r.path.kind).collect();
    assert_eq!(
        kinds,
        vec![
            TransportPathKind::Direct,
            TransportPathKind::Mesh,
            TransportPathKind::Derp,
            TransportPathKind::Funnel,
        ],
        "priority order MUST be Direct(4) > Mesh(3) > Derp(2) > Funnel(1)"
    );
}

#[test]
fn ranked_path_priority_field_encodes_documented_constants() {
    // The priority field on RankedPath is the public surface that
    // downstream tooling can inspect — pin the constants.
    let policy = allow_all();
    let paths = vec![
        TransportPath::new(TransportPathKind::Direct, peer("p1"), "x", None),
        TransportPath::new(TransportPathKind::Mesh, peer("p2"), "x", None),
        TransportPath::new(TransportPathKind::Derp, peer("p3"), "x", None),
        TransportPath::new(TransportPathKind::Funnel, peer("p4"), "x", None),
    ];
    let ranked = TransportSelector::rank_paths(&paths, &policy);
    let priority_for = |k: TransportPathKind| -> u8 {
        ranked
            .iter()
            .find(|r| r.path.kind == k)
            .expect("path of kind exists")
            .priority
    };
    assert_eq!(priority_for(TransportPathKind::Direct), 4);
    assert_eq!(priority_for(TransportPathKind::Mesh), 3);
    assert_eq!(priority_for(TransportPathKind::Derp), 2);
    assert_eq!(priority_for(TransportPathKind::Funnel), 1);
}

// ─── Policy filtering + reason codes (NORMATIVE) ────────────────────

#[test]
fn rank_paths_marks_lan_forbidden_paths_ineligible_with_reason() {
    let policy = ZoneTransportPolicy {
        allow_lan: false,
        allow_derp: true,
        allow_funnel: true,
    };
    let paths = vec![
        TransportPath::new(TransportPathKind::Direct, peer("p1"), "x", None),
        TransportPath::new(TransportPathKind::Mesh, peer("p2"), "x", None),
    ];
    let ranked = TransportSelector::rank_paths(&paths, &policy);
    for r in &ranked {
        assert!(
            !r.eligible,
            "{:?} MUST be ineligible under !allow_lan",
            r.path.kind
        );
        assert_eq!(
            r.reason,
            Some(DecisionReasonCode::TransportLanForbidden),
            "reason MUST be TransportLanForbidden for {:?}",
            r.path.kind
        );
    }
}

#[test]
fn rank_paths_marks_derp_forbidden_path_with_reason() {
    let policy = ZoneTransportPolicy {
        allow_lan: true,
        allow_derp: false,
        allow_funnel: true,
    };
    let paths = vec![TransportPath::new(
        TransportPathKind::Derp,
        peer("p1"),
        "x",
        None,
    )];
    let ranked = TransportSelector::rank_paths(&paths, &policy);
    assert!(!ranked[0].eligible);
    assert_eq!(
        ranked[0].reason,
        Some(DecisionReasonCode::TransportDerpForbidden)
    );
}

#[test]
fn rank_paths_marks_funnel_forbidden_path_with_reason() {
    let policy = ZoneTransportPolicy {
        allow_lan: true,
        allow_derp: true,
        allow_funnel: false,
    };
    let paths = vec![TransportPath::new(
        TransportPathKind::Funnel,
        peer("p1"),
        "x",
        None,
    )];
    let ranked = TransportSelector::rank_paths(&paths, &policy);
    assert!(!ranked[0].eligible);
    assert_eq!(
        ranked[0].reason,
        Some(DecisionReasonCode::TransportFunnelForbidden)
    );
}

#[test]
fn rank_paths_eligible_paths_have_no_reason_code() {
    let policy = allow_all();
    let paths = vec![TransportPath::new(
        TransportPathKind::Direct,
        peer("p1"),
        "x",
        None,
    )];
    let ranked = TransportSelector::rank_paths(&paths, &policy);
    assert!(ranked[0].eligible);
    assert!(
        ranked[0].reason.is_none(),
        "eligible path MUST carry None reason code; got {:?}",
        ranked[0].reason
    );
}

#[test]
fn rank_paths_groups_eligible_before_ineligible_regardless_of_priority() {
    // Eligibility-first sort key: an ineligible Direct (priority 4)
    // MUST sort BELOW an eligible Funnel (priority 1).
    let _ = lan_only(); // (unused; use mixed_policy below)
    let paths = vec![
        TransportPath::new(TransportPathKind::Direct, peer("p1"), "x", None),
        TransportPath::new(TransportPathKind::Funnel, peer("p2"), "x", None),
    ];
    // Override: allow_funnel=true so funnel is eligible. Direct is
    // also eligible. Test the overall ordering with mixed eligibility.
    let mixed_policy = ZoneTransportPolicy {
        allow_lan: false, // Direct/Mesh forbidden
        allow_derp: false,
        allow_funnel: true, // Funnel eligible
    };
    let ranked = TransportSelector::rank_paths(&paths, &mixed_policy);
    assert_eq!(
        ranked[0].path.kind,
        TransportPathKind::Funnel,
        "eligible Funnel MUST sort BEFORE ineligible Direct"
    );
    assert!(ranked[0].eligible);
    assert!(!ranked[1].eligible);
}

// ─── Tie-break chain (NORMATIVE) ────────────────────────────────────

#[test]
fn rank_paths_tie_breaks_by_rtt_when_priority_equal() {
    let policy = allow_all();
    let paths = vec![
        TransportPath::new(TransportPathKind::Direct, peer("p1"), "a", Some(50)),
        TransportPath::new(TransportPathKind::Direct, peer("p2"), "b", Some(10)),
        TransportPath::new(TransportPathKind::Direct, peer("p3"), "c", Some(30)),
    ];
    let ranked = TransportSelector::rank_paths(&paths, &policy);
    let rtts: Vec<u32> = ranked
        .iter()
        .map(|r| r.path.estimated_rtt_ms.unwrap())
        .collect();
    assert_eq!(
        rtts,
        vec![10, 30, 50],
        "ties MUST resolve by estimated_rtt_ms ascending"
    );
}

#[test]
fn rank_paths_treats_none_rtt_as_worst() {
    // None RTT → u32::MAX → sorts after all known-RTT paths.
    let policy = allow_all();
    let paths = vec![
        TransportPath::new(TransportPathKind::Direct, peer("p1"), "a", None),
        TransportPath::new(TransportPathKind::Direct, peer("p2"), "b", Some(100)),
    ];
    let ranked = TransportSelector::rank_paths(&paths, &policy);
    assert_eq!(
        ranked[0].path.estimated_rtt_ms,
        Some(100),
        "Some(rtt) MUST sort BEFORE None (None == u32::MAX in tie-break)"
    );
    assert!(ranked[1].path.estimated_rtt_ms.is_none());
}

#[test]
fn rank_paths_tie_breaks_by_path_id_when_priority_and_rtt_equal() {
    let policy = allow_all();
    let paths = vec![
        TransportPath::new(TransportPathKind::Direct, peer("p1"), "z", Some(10)),
        TransportPath::new(TransportPathKind::Direct, peer("p2"), "a", Some(10)),
        TransportPath::new(TransportPathKind::Direct, peer("p3"), "m", Some(10)),
    ];
    let ranked = TransportSelector::rank_paths(&paths, &policy);
    let ids: Vec<&str> = ranked.iter().map(|r| r.path.path_id.as_str()).collect();
    assert_eq!(
        ids,
        vec!["a", "m", "z"],
        "after priority + rtt ties, path_id ascending breaks the tie"
    );
}

#[test]
fn rank_paths_tie_breaks_by_peer_when_everything_else_equal() {
    let policy = allow_all();
    let paths = vec![
        TransportPath::new(TransportPathKind::Direct, peer("zeta"), "x", Some(10)),
        TransportPath::new(TransportPathKind::Direct, peer("alpha"), "x", Some(10)),
    ];
    let ranked = TransportSelector::rank_paths(&paths, &policy);
    assert_eq!(
        ranked[0].path.peer.as_str(),
        "alpha",
        "final tie-break MUST be peer ascending"
    );
}

#[test]
fn rank_paths_is_deterministic_across_repeated_calls() {
    let policy = allow_all();
    let paths = vec![
        TransportPath::new(TransportPathKind::Direct, peer("p1"), "a", Some(10)),
        TransportPath::new(TransportPathKind::Mesh, peer("p2"), "b", Some(10)),
        TransportPath::new(TransportPathKind::Derp, peer("p3"), "c", Some(10)),
        TransportPath::new(TransportPathKind::Funnel, peer("p4"), "d", Some(10)),
    ];
    let r1 = TransportSelector::rank_paths(&paths, &policy);
    for _ in 0..16 {
        let rn = TransportSelector::rank_paths(&paths, &policy);
        let ids_1: Vec<&str> = r1.iter().map(|r| r.path.path_id.as_str()).collect();
        let ids_n: Vec<&str> = rn.iter().map(|r| r.path.path_id.as_str()).collect();
        assert_eq!(ids_1, ids_n, "rank_paths MUST be deterministic");
    }
}

// ─── best_path ──────────────────────────────────────────────────────

#[test]
fn best_path_returns_first_eligible_ranked_path() {
    let policy = ZoneTransportPolicy {
        allow_lan: false, // Direct/Mesh forbidden
        allow_derp: true,
        allow_funnel: true,
    };
    let paths = vec![
        TransportPath::new(TransportPathKind::Direct, peer("p1"), "a", Some(5)),
        TransportPath::new(TransportPathKind::Derp, peer("p2"), "b", Some(50)),
        TransportPath::new(TransportPathKind::Funnel, peer("p3"), "c", Some(80)),
    ];
    let best = TransportSelector::best_path(&paths, &policy).expect("at least one eligible");
    assert_eq!(
        best.path.kind,
        TransportPathKind::Derp,
        "Direct is ineligible — Derp (priority 2) MUST win over Funnel (priority 1)"
    );
}

#[test]
fn best_path_returns_none_when_all_paths_ineligible() {
    let policy = ZoneTransportPolicy {
        allow_lan: false,
        allow_derp: false,
        allow_funnel: false,
    };
    let paths = vec![
        TransportPath::new(TransportPathKind::Direct, peer("p1"), "a", None),
        TransportPath::new(TransportPathKind::Derp, peer("p2"), "b", None),
    ];
    assert!(
        TransportSelector::best_path(&paths, &policy).is_none(),
        "all-ineligible MUST return None"
    );
}

#[test]
fn best_path_returns_none_when_paths_empty() {
    let policy = allow_all();
    let paths: Vec<TransportPath> = vec![];
    assert!(TransportSelector::best_path(&paths, &policy).is_none());
}

// ─── select_multipath ───────────────────────────────────────────────

#[test]
fn select_multipath_with_zero_fanout_returns_empty() {
    let policy = allow_all();
    let paths = vec![TransportPath::new(
        TransportPathKind::Direct,
        peer("p1"),
        "x",
        None,
    )];
    let oid = test_object_id();
    let selected = TransportSelector::select_multipath(&paths, &policy, &oid, 0, 0);
    assert!(selected.is_empty(), "fanout=0 MUST return empty Vec");
}

#[test]
fn select_multipath_filters_ineligible_paths() {
    let policy = ZoneTransportPolicy {
        allow_lan: true,
        allow_derp: false,
        allow_funnel: false,
    };
    let paths = vec![
        TransportPath::new(TransportPathKind::Direct, peer("p1"), "a", None),
        TransportPath::new(TransportPathKind::Derp, peer("p2"), "b", None),
        TransportPath::new(TransportPathKind::Funnel, peer("p3"), "c", None),
    ];
    let oid = test_object_id();
    let selected = TransportSelector::select_multipath(&paths, &policy, &oid, 0, 5);
    assert_eq!(selected.len(), 1, "only the Direct path is eligible");
    assert_eq!(selected[0].kind, TransportPathKind::Direct);
}

#[test]
fn select_multipath_returns_empty_when_no_eligible_paths() {
    let policy = ZoneTransportPolicy {
        allow_lan: false,
        allow_derp: false,
        allow_funnel: false,
    };
    let paths = vec![TransportPath::new(
        TransportPathKind::Direct,
        peer("p1"),
        "x",
        None,
    )];
    let oid = test_object_id();
    let selected = TransportSelector::select_multipath(&paths, &policy, &oid, 0, 5);
    assert_eq!(selected, [] as [fcp_mesh::TransportPath; 0]);
}

#[test]
fn select_multipath_caps_at_fanout() {
    let policy = allow_all();
    let paths = vec![
        TransportPath::new(TransportPathKind::Direct, peer("p1"), "a", None),
        TransportPath::new(TransportPathKind::Direct, peer("p2"), "b", None),
        TransportPath::new(TransportPathKind::Direct, peer("p3"), "c", None),
        TransportPath::new(TransportPathKind::Direct, peer("p4"), "d", None),
    ];
    let oid = test_object_id();
    let selected = TransportSelector::select_multipath(&paths, &policy, &oid, 0, 2);
    assert_eq!(
        selected.len(),
        2,
        "select_multipath MUST cap at fanout, not exceed"
    );
}

#[test]
fn select_multipath_exhausts_high_priority_group_before_lower() {
    // Two priority groups: Direct (priority 4) + Funnel (priority 1).
    // With fanout=2 and two Direct paths available, MUST pick from
    // Direct only.
    let policy = allow_all();
    let paths = vec![
        TransportPath::new(TransportPathKind::Direct, peer("p1"), "a", None),
        TransportPath::new(TransportPathKind::Direct, peer("p2"), "b", None),
        TransportPath::new(TransportPathKind::Funnel, peer("p3"), "c", None),
        TransportPath::new(TransportPathKind::Funnel, peer("p4"), "d", None),
    ];
    let oid = test_object_id();
    let selected = TransportSelector::select_multipath(&paths, &policy, &oid, 0, 2);
    assert_eq!(selected.len(), 2);
    for p in &selected {
        assert_eq!(
            p.kind,
            TransportPathKind::Direct,
            "fanout=2 MUST prefer Direct over Funnel until Direct exhausted; got {:?}",
            p.kind
        );
    }
}

#[test]
fn select_multipath_descends_to_lower_priority_when_higher_exhausted() {
    // fanout=3 with 2 Direct + 2 Funnel: MUST pick both Directs and
    // ONE Funnel.
    let policy = allow_all();
    let paths = vec![
        TransportPath::new(TransportPathKind::Direct, peer("p1"), "a", None),
        TransportPath::new(TransportPathKind::Direct, peer("p2"), "b", None),
        TransportPath::new(TransportPathKind::Funnel, peer("p3"), "c", None),
        TransportPath::new(TransportPathKind::Funnel, peer("p4"), "d", None),
    ];
    let oid = test_object_id();
    let selected = TransportSelector::select_multipath(&paths, &policy, &oid, 0, 3);
    assert_eq!(selected.len(), 3);
    let direct_count = selected
        .iter()
        .filter(|p| p.kind == TransportPathKind::Direct)
        .count();
    let funnel_count = selected
        .iter()
        .filter(|p| p.kind == TransportPathKind::Funnel)
        .count();
    assert_eq!(direct_count, 2, "both Directs MUST be picked first");
    assert_eq!(funnel_count, 1, "one Funnel MUST round out the fanout");
}

#[test]
fn select_multipath_is_deterministic_for_same_inputs() {
    // Determinism is the whole point of the blake3 tie-break — two
    // calls with the same (object_id, symbol_index) MUST yield the
    // same path order.
    let policy = allow_all();
    let paths = vec![
        TransportPath::new(TransportPathKind::Direct, peer("p1"), "a", None),
        TransportPath::new(TransportPathKind::Direct, peer("p2"), "b", None),
        TransportPath::new(TransportPathKind::Direct, peer("p3"), "c", None),
        TransportPath::new(TransportPathKind::Direct, peer("p4"), "d", None),
    ];
    let oid = test_object_id();
    let s1 = TransportSelector::select_multipath(&paths, &policy, &oid, 7, 3);
    for _ in 0..16 {
        let sn = TransportSelector::select_multipath(&paths, &policy, &oid, 7, 3);
        let ids_1: Vec<&str> = s1.iter().map(|p| p.path_id.as_str()).collect();
        let ids_n: Vec<&str> = sn.iter().map(|p| p.path_id.as_str()).collect();
        assert_eq!(
            ids_1, ids_n,
            "select_multipath MUST be deterministic for fixed inputs"
        );
    }
}

#[test]
fn select_multipath_differs_across_symbol_indices_in_general() {
    // With four paths in the same priority group, two different
    // symbol_index values SHOULD yield at least one different
    // ordering across many indices — otherwise the blake3 mix isn't
    // doing anything and replication wouldn't actually balance.
    let policy = allow_all();
    let paths = vec![
        TransportPath::new(TransportPathKind::Direct, peer("p1"), "a", None),
        TransportPath::new(TransportPathKind::Direct, peer("p2"), "b", None),
        TransportPath::new(TransportPathKind::Direct, peer("p3"), "c", None),
        TransportPath::new(TransportPathKind::Direct, peer("p4"), "d", None),
    ];
    let oid = test_object_id();
    let baseline: Vec<String> = TransportSelector::select_multipath(&paths, &policy, &oid, 0, 4)
        .iter()
        .map(|p| p.path_id.clone())
        .collect();

    let mut saw_difference = false;
    for sym in 1..32_u32 {
        let other: Vec<String> = TransportSelector::select_multipath(&paths, &policy, &oid, sym, 4)
            .iter()
            .map(|p| p.path_id.clone())
            .collect();
        if other != baseline {
            saw_difference = true;
            break;
        }
    }
    assert!(
        saw_difference,
        "select_multipath MUST yield different orderings for at least some symbol_index values \
         (otherwise replication is degenerate)"
    );
}

// ─── transport_mode mapping (NORMATIVE) ─────────────────────────────

#[test]
fn lan_policy_maps_direct_and_mesh_eligibility_together() {
    // Direct + Mesh share TransportMode::Lan — disabling allow_lan
    // MUST drop both, enabling MUST allow both.
    let lan_off = ZoneTransportPolicy {
        allow_lan: false,
        allow_derp: true,
        allow_funnel: true,
    };
    let paths = vec![
        TransportPath::new(TransportPathKind::Direct, peer("p1"), "a", None),
        TransportPath::new(TransportPathKind::Mesh, peer("p2"), "b", None),
    ];
    let ranked = TransportSelector::rank_paths(&paths, &lan_off);
    for r in ranked {
        assert!(
            !r.eligible,
            "{:?} maps to Lan and MUST be dropped when allow_lan=false",
            r.path.kind
        );
    }

    let lan_on = ZoneTransportPolicy {
        allow_lan: true,
        allow_derp: false,
        allow_funnel: false,
    };
    let paths2 = vec![
        TransportPath::new(TransportPathKind::Direct, peer("p1"), "a", None),
        TransportPath::new(TransportPathKind::Mesh, peer("p2"), "b", None),
    ];
    let ranked2 = TransportSelector::rank_paths(&paths2, &lan_on);
    for r in ranked2 {
        assert!(
            r.eligible,
            "{:?} maps to Lan and MUST be eligible when allow_lan=true",
            r.path.kind
        );
    }
}

#[test]
fn zone_transport_policy_default_allows_lan_only() {
    // The Default of ZoneTransportPolicy leaks into routing. Pin it.
    let p = ZoneTransportPolicy::default();
    assert!(p.allows(TransportMode::Lan));
    assert!(!p.allows(TransportMode::Derp));
    assert!(!p.allows(TransportMode::Funnel));
}
