//! `BudgetPolicyEngine` async-wrapper conformance.
//!
//! `fcp_host::BudgetPolicyEngine` is the async `PolicyEngine`
//! integration that backs invoke-budget admission via the host
//! preflight pipeline. It wraps the synchronous `BudgetTracker`
//! pinned in br-55yv3 and adds:
//!
//! - per-zone policy lifecycle (`upsert_policy` / `remove_policy`),
//! - opt-in evaluation: `record_usage` and `snapshot` return
//!   `HostResult<Option<...>>` so a zone WITHOUT a configured policy is silently
//!   a no-op (admins must explicitly enable enforcement),
//! - sorted multi-zone reporting (`report` orders snapshots by
//!   `zone_id` so CLI output is deterministic), and
//! - optional zone filtering on report.
//!
//! These tests pin the lifecycle + reporting contract callers
//! depend on. A regression that, e.g., made `record_usage` create
//! an implicit zero-cap policy for un-configured zones would
//! suddenly start denying every previously-unrestricted invoke.

use std::collections::HashMap;

use fcp_async_core::runtime::test as runtime_test;
use fcp_host::{BudgetAction, BudgetPolicyEngine};
use fcp_prelude::{
    BudgetEnforcement, BudgetStatus, UsageBudgetLimit, UsageBudgetPolicy, UsageMetric,
    UsageMetricKind, ZoneId,
};

fn token_policy(limit: u64) -> UsageBudgetPolicy {
    UsageBudgetPolicy {
        enforcement: BudgetEnforcement::Deny,
        budgets: vec![UsageBudgetLimit {
            metric: UsageMetricKind::Tokens,
            limit,
            window_seconds: 3600,
        }],
    }
}

#[runtime_test]
async fn record_usage_on_unconfigured_zone_returns_none() {
    let engine = BudgetPolicyEngine::new();
    let zone = ZoneId::work();

    let eval = engine
        .record_usage(&zone, &[UsageMetric::tokens(50)])
        .await
        .unwrap();
    assert!(
        eval.is_none(),
        "un-configured zone MUST return None — no policy means no enforcement, NOT implicit zero-cap"
    );
}

#[runtime_test]
async fn snapshot_on_unconfigured_zone_returns_none() {
    let engine = BudgetPolicyEngine::new();
    let zone = ZoneId::work();

    let snap = engine.snapshot(&zone).await.unwrap();
    assert!(
        snap.is_none(),
        "un-configured zone MUST snapshot as None — no policy means nothing to snapshot"
    );
}

#[runtime_test]
async fn record_usage_on_configured_zone_evaluates_and_returns_some() {
    let engine = BudgetPolicyEngine::new();
    let zone = ZoneId::work();

    engine.upsert_policy(zone.clone(), token_policy(100)).await;

    let eval = engine
        .record_usage(&zone, &[UsageMetric::tokens(50)])
        .await
        .expect("usage storage succeeds")
        .expect("configured zone must produce a BudgetEvaluation");
    assert_eq!(eval.action, BudgetAction::Allow);
    let entry = eval
        .snapshot
        .budgets
        .iter()
        .find(|b| b.metric == UsageMetricKind::Tokens)
        .expect("entry");
    assert_eq!(entry.used, 50);
    assert_eq!(entry.status, BudgetStatus::Ok);
}

#[runtime_test]
async fn upsert_policy_replaces_prior_policy() {
    let engine = BudgetPolicyEngine::new();
    let zone = ZoneId::work();

    // Install a tight policy first.
    engine.upsert_policy(zone.clone(), token_policy(10)).await;
    let eval_strict = engine
        .record_usage(&zone, &[UsageMetric::tokens(50)])
        .await
        .expect("usage storage succeeds")
        .expect("evaluation");
    assert_eq!(
        eval_strict.action,
        BudgetAction::Deny,
        "fixture sanity: 50 tokens against a 10-cap is Deny"
    );

    // Replace with a permissive policy. The new policy MUST take
    // effect on the next record_usage. (Note: usage state persists
    // in the tracker — this test doesn't assert a state reset, only
    // that the new LIMIT applies.)
    engine
        .upsert_policy(zone.clone(), token_policy(10_000))
        .await;
    let eval_relaxed = engine
        .record_usage(&zone, &[UsageMetric::tokens(50)])
        .await
        .expect("usage storage succeeds")
        .expect("evaluation");
    let entry = eval_relaxed
        .snapshot
        .budgets
        .iter()
        .find(|b| b.metric == UsageMetricKind::Tokens)
        .expect("entry");
    assert_eq!(
        entry.limit, 10_000,
        "after upsert, the new limit MUST be reflected in the snapshot"
    );
}

#[runtime_test]
async fn remove_policy_returns_prior_and_makes_zone_unconfigured() {
    let engine = BudgetPolicyEngine::new();
    let zone = ZoneId::work();
    engine.upsert_policy(zone.clone(), token_policy(100)).await;

    let removed = engine
        .remove_policy(&zone)
        .await
        .expect("remove_policy must return the prior policy");
    assert_eq!(removed.budgets.len(), 1);
    assert_eq!(removed.budgets[0].limit, 100);

    // After removal the zone is un-configured again.
    let eval = engine
        .record_usage(&zone, &[UsageMetric::tokens(1)])
        .await
        .unwrap();
    assert!(
        eval.is_none(),
        "after remove_policy, record_usage MUST return None — the policy is gone"
    );
}

#[runtime_test]
async fn remove_policy_on_unknown_zone_returns_none() {
    let engine = BudgetPolicyEngine::new();
    let zone = ZoneId::work();
    let removed = engine.remove_policy(&zone).await;
    assert!(
        removed.is_none(),
        "remove_policy on a zone with no policy MUST return None — caller can detect the no-op"
    );
}

#[runtime_test]
async fn with_policies_constructor_seeds_initial_state() {
    // The bulk-load constructor must produce a working engine for
    // every preconfigured zone.
    let mut policies = HashMap::new();
    policies.insert(ZoneId::work(), token_policy(100));
    policies.insert(ZoneId::private(), token_policy(50));

    let engine = BudgetPolicyEngine::with_policies(policies);

    let work_eval = engine
        .record_usage(&ZoneId::work(), &[UsageMetric::tokens(60)])
        .await
        .expect("usage storage succeeds")
        .expect("work configured");
    assert_eq!(work_eval.action, BudgetAction::Allow);

    let private_eval = engine
        .record_usage(&ZoneId::private(), &[UsageMetric::tokens(60)])
        .await
        .expect("usage storage succeeds")
        .expect("private configured");
    assert_eq!(
        private_eval.action,
        BudgetAction::Deny,
        "private has a 50-cap — 60 tokens MUST exceed it"
    );

    let unknown = engine
        .record_usage(&ZoneId::owner(), &[UsageMetric::tokens(1)])
        .await
        .unwrap();
    assert!(
        unknown.is_none(),
        "owner has no policy — record_usage returns None"
    );
}

#[runtime_test]
async fn report_returns_snapshots_sorted_by_zone_id() {
    // CLI / admin tooling depends on a deterministic order so
    // diffs across reports are stable.
    let engine = BudgetPolicyEngine::new();
    // Insert in deliberately scrambled order.
    engine
        .upsert_policy(ZoneId::work(), token_policy(100))
        .await;
    engine
        .upsert_policy(ZoneId::owner(), token_policy(200))
        .await;
    engine
        .upsert_policy(ZoneId::private(), token_policy(300))
        .await;

    let report = engine.report(None).await.unwrap();
    assert_eq!(report.zones.len(), 3);
    let ids: Vec<&str> = report.zones.iter().map(|z| z.zone_id.as_str()).collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(
        ids, sorted,
        "report MUST return zones sorted by zone_id; got {ids:?}"
    );
}

#[runtime_test]
async fn report_with_zone_filter_narrows_to_single_zone() {
    let engine = BudgetPolicyEngine::new();
    engine
        .upsert_policy(ZoneId::work(), token_policy(100))
        .await;
    engine
        .upsert_policy(ZoneId::private(), token_policy(200))
        .await;

    let work = ZoneId::work();
    let report = engine.report(Some(&work)).await.unwrap();
    assert_eq!(
        report.zones.len(),
        1,
        "report with zone_filter MUST return only the matching zone"
    );
    assert_eq!(report.zones[0].zone_id.as_str(), "z:work");
}

#[runtime_test]
async fn report_with_unknown_zone_filter_returns_empty() {
    let engine = BudgetPolicyEngine::new();
    engine
        .upsert_policy(ZoneId::work(), token_policy(100))
        .await;

    let owner = ZoneId::owner();
    let report = engine.report(Some(&owner)).await.unwrap();
    assert!(
        report.zones.is_empty(),
        "report filtered to a zone with no policy MUST return zero entries"
    );
}
