//! Zone usage windows shared by live admission, reports, and outcome settlement.
//!
//! The lifecycle snapshot is the transaction boundary: request allowance and
//! invocation identity commit together. Reserved requests are never refunded.
//! Provider-reported metrics are observed after execution, not reserved spend
//! guarantees. These counters belong to one executor and are not mesh quotas.

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;

use chrono::Utc;
use fcp_kernel::{
    BudgetEnforcement, BudgetStatus, LifecycleError, UsageBudgetPolicy, UsageBudgetSnapshot,
    UsageMetric, UsageMetricKind,
};
use fcp_policy::ZoneId;

use super::{HostAdminStateStore, InvocationTicket};
use crate::budget::{BudgetAction, BudgetEvaluation, validate_usage_budget_policy};
use crate::{HostError, HostResult};

fn budget_error(error: LifecycleError) -> HostError {
    match error {
        LifecycleError::InvalidPolicy { reason } => HostError::PreflightFailed(reason),
        other => HostError::Unavailable(other.to_string()),
    }
}

fn invalid(reason: &str) -> LifecycleError {
    LifecycleError::InvalidPolicy {
        reason: reason.to_owned(),
    }
}

fn now_secs() -> u64 {
    u64::try_from(Utc::now().timestamp()).unwrap_or(0)
}

fn usage_digest(metrics: &[UsageMetric]) -> String {
    // Labels do not create additional budget dimensions. Hash the exact
    // aggregated metric kinds the tracker charges, without retaining labels.
    // Requests are host-owned admission counts, never provider assertions.
    let mut totals = BTreeMap::<&str, u64>::new();
    for metric in metrics
        .iter()
        .filter(|metric| metric.kind != UsageMetricKind::Requests)
    {
        let amount = totals.entry(metric.kind.as_str()).or_default();
        *amount = amount.saturating_add(metric.amount);
    }
    let mut hash = blake3::Hasher::new();
    hash.update(b"FCP-HOST-ZONE-BUDGET-SETTLEMENT-V1");
    for (kind, amount) in totals {
        hash.update(kind.as_bytes());
        hash.update(&[0]);
        hash.update(&amount.to_be_bytes());
    }
    hash.finalize().to_hex().to_string()
}

fn evaluation(snapshot: UsageBudgetSnapshot) -> BudgetEvaluation {
    let exceeded = snapshot
        .budgets
        .iter()
        .any(|entry| entry.status == BudgetStatus::Exceeded);
    let action = match (exceeded, snapshot.enforcement) {
        (true, BudgetEnforcement::Deny) => BudgetAction::Deny,
        (true, BudgetEnforcement::Warn) => BudgetAction::Warn,
        (false, _) => BudgetAction::Allow,
    };
    BudgetEvaluation { action, snapshot }
}

impl HostAdminStateStore {
    fn check_budget_storage(&self) -> HostResult<()> {
        if self.persistence_failed.load(Ordering::Acquire) {
            return Err(HostError::Unavailable(
                "zone budget authority is unavailable after an admin-state persistence failure"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    pub(crate) async fn snapshot_zone_budget(
        &self,
        zone_id: &ZoneId,
        policy: &UsageBudgetPolicy,
    ) -> HostResult<UsageBudgetSnapshot> {
        validate_usage_budget_policy(policy).map_err(budget_error)?;
        let state = self.state.read().await;
        self.check_budget_storage()?;
        state
            .zone_budget_usage
            .check_capacity(zone_id)
            .map_err(budget_error)?;
        // Preview rollover on a copy. Reports never consume allowance or
        // rewrite storage; actual admission repeats rollover transactionally.
        let mut tracker = state.zone_budget_usage.clone();
        Ok(tracker.snapshot_at(zone_id, policy, now_secs()))
    }

    pub(crate) async fn report_zone_budgets(
        &self,
        policies: &[(ZoneId, UsageBudgetPolicy)],
    ) -> HostResult<Vec<UsageBudgetSnapshot>> {
        for (_, policy) in policies {
            validate_usage_budget_policy(policy).map_err(budget_error)?;
        }
        let state = self.state.read().await;
        self.check_budget_storage()?;
        let mut tracker = state.zone_budget_usage.clone();
        let now = now_secs();
        let mut snapshots = Vec::with_capacity(policies.len());
        for (zone_id, policy) in policies {
            tracker.check_capacity(zone_id).map_err(budget_error)?;
            snapshots.push(tracker.snapshot_at(zone_id, policy, now));
        }
        Ok(snapshots)
    }

    pub(crate) async fn record_zone_budget_usage(
        &self,
        zone_id: &ZoneId,
        policy: &UsageBudgetPolicy,
        metrics: &[UsageMetric],
    ) -> HostResult<BudgetEvaluation> {
        validate_usage_budget_policy(policy).map_err(budget_error)?;
        self.apply_mutation(|snapshot| {
            snapshot.zone_budget_usage.check_capacity(zone_id)?;
            Ok(snapshot
                .zone_budget_usage
                .record_usage_at(zone_id, policy, metrics, now_secs()))
        })
        .await
        .map_err(budget_error)
    }

    pub(crate) async fn settle_invocation_budget(
        &self,
        ticket: &InvocationTicket,
        zone_id: &ZoneId,
        policy: &UsageBudgetPolicy,
        metrics: &[UsageMetric],
    ) -> HostResult<BudgetEvaluation> {
        validate_usage_budget_policy(policy).map_err(budget_error)?;
        let digest = usage_digest(metrics);
        self.apply_mutation(|snapshot| {
            let index = snapshot
                .invocations
                .iter()
                .position(|record| record.ticket == *ticket)
                .ok_or_else(|| invalid("unknown invocation budget settlement ticket"))?;
            let record = &snapshot.invocations[index];
            if record.admission.zone_id != zone_id.as_str() {
                return Err(invalid(
                    "invocation budget settlement zone does not match admission",
                ));
            }
            if record.terminal.is_none() {
                return Err(invalid(
                    "invocation budget settlement requires a terminal observation",
                ));
            }
            if let Some(previous) = &record.budget_usage_digest {
                if previous != &digest {
                    return Err(invalid(
                        "invocation budget settlement conflicts with retained usage",
                    ));
                }
                return Ok(evaluation(snapshot.zone_budget_usage.snapshot_at(
                    zone_id,
                    policy,
                    now_secs(),
                )));
            }
            let mut observed: Vec<UsageMetric> = metrics
                .iter()
                .filter(|metric| metric.kind != UsageMetricKind::Requests)
                .cloned()
                .collect();
            if !record.budget_requests_reserved {
                observed.push(UsageMetric::requests(1));
            }
            snapshot.zone_budget_usage.check_capacity(zone_id)?;
            let result =
                snapshot
                    .zone_budget_usage
                    .record_usage_at(zone_id, policy, &observed, now_secs());
            snapshot.invocations[index].budget_usage_digest = Some(digest);
            Ok(result)
        })
        .await
        .map_err(budget_error)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use chrono::Duration;
    use fcp_kernel::{ConnectorId, UsageBudgetLimit};

    use super::*;
    use crate::{
        BudgetPolicyEngine, InvocationAdmission, InvocationOutcome, InvocationTerminal,
        PolicyEngine, PreflightRequest,
    };

    fn policy(enforcement: BudgetEnforcement) -> UsageBudgetPolicy {
        UsageBudgetPolicy {
            enforcement,
            budgets: vec![
                UsageBudgetLimit {
                    metric: UsageMetricKind::Requests,
                    limit: 1,
                    window_seconds: 3_600,
                },
                UsageBudgetLimit {
                    metric: UsageMetricKind::Tokens,
                    limit: 100,
                    window_seconds: 3_600,
                },
                UsageBudgetLimit {
                    metric: UsageMetricKind::Bytes,
                    limit: 128,
                    window_seconds: 3_600,
                },
            ],
        }
    }

    fn admission(id: &str, zone: &ZoneId) -> InvocationAdmission {
        InvocationAdmission {
            operation_id: id.to_owned(),
            connector_id: "fcp.test.zone-budget:utility:1.0.0".to_owned(),
            operation: "fixture.get".to_owned(),
            zone_id: zone.to_string(),
            principal: "user:test".to_owned(),
            correlation_id: None,
            deadline_at: Utc::now() + Duration::minutes(1),
            idempotency: None,
            transport_idempotency: None,
        }
    }

    fn terminal(outcome: InvocationOutcome) -> InvocationTerminal {
        InvocationTerminal {
            outcome,
            receipt_id: None,
            duration_ms: 4,
            http_status: 200,
        }
    }

    fn used(snapshot: &UsageBudgetSnapshot, metric: UsageMetricKind) -> u64 {
        snapshot
            .budgets
            .iter()
            .find(|entry| entry.metric == metric)
            .unwrap()
            .used
    }

    #[fcp_async_core::runtime::test]
    async fn restart_and_duplicate_settlement_never_refund_or_double_count_admission() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("zone-budget-state.json");
        let store = HostAdminStateStore::with_state_path(path.clone()).unwrap();
        let zone = ZoneId::work();
        let policy = policy(BudgetEnforcement::Deny);
        let ticket = store
            .admit_invocation_with_usage(
                admission("pending-before-restart", &zone),
                None,
                Some(&policy),
            )
            .await
            .unwrap();
        assert!(
            store
                .settle_invocation_budget(&ticket, &zone, &policy, &[])
                .await
                .is_err()
        );
        drop(store);

        let store = HostAdminStateStore::with_state_path(path.clone()).unwrap();
        let record = store
            .invocation_record(&ticket.operation_id, None)
            .await
            .unwrap();
        assert_eq!(record.ticket, ticket);
        assert!(record.budget_requests_reserved);
        assert_eq!(
            record.terminal.unwrap().outcome,
            InvocationOutcome::OutcomeUnknown
        );
        assert!(
            store
                .admit_invocation_with_usage(
                    admission("after-unknown-restart", &zone),
                    None,
                    Some(&policy),
                )
                .await
                .unwrap_err()
                .to_string()
                .contains("zone usage budget exhausted")
        );
        let evaluation = store
            .settle_invocation_budget(
                &ticket,
                &zone,
                &policy,
                &[
                    UsageMetric::requests(999),
                    UsageMetric::tokens(23),
                    UsageMetric::bytes(41),
                ],
            )
            .await
            .unwrap();
        assert_eq!(used(&evaluation.snapshot, UsageMetricKind::Requests), 1);
        assert_eq!(used(&evaluation.snapshot, UsageMetricKind::Tokens), 23);
        assert_eq!(used(&evaluation.snapshot, UsageMetricKind::Bytes), 41);
        let duplicate = store
            .settle_invocation_budget(
                &ticket,
                &zone,
                &policy,
                &[
                    UsageMetric::bytes(41),
                    UsageMetric::tokens(20),
                    UsageMetric::tokens(3),
                ],
            )
            .await
            .unwrap();
        assert_eq!(used(&duplicate.snapshot, UsageMetricKind::Tokens), 23);
        assert_eq!(used(&duplicate.snapshot, UsageMetricKind::Requests), 1);
        assert!(
            store
                .settle_invocation_budget(
                    &ticket,
                    &zone,
                    &policy,
                    &[UsageMetric::tokens(24), UsageMetric::bytes(41)],
                )
                .await
                .unwrap_err()
                .to_string()
                .contains("conflicts with retained usage")
        );
        drop(store);

        let reopened = HostAdminStateStore::with_state_path(path).unwrap();
        let after_restart = reopened
            .settle_invocation_budget(
                &ticket,
                &zone,
                &policy,
                &[UsageMetric::tokens(23), UsageMetric::bytes(41)],
            )
            .await
            .unwrap();
        assert_eq!(used(&after_restart.snapshot, UsageMetricKind::Requests), 1);
        assert_eq!(used(&after_restart.snapshot, UsageMetricKind::Tokens), 23);
        assert_eq!(used(&after_restart.snapshot, UsageMetricKind::Bytes), 41);
        assert!(
            reopened
                .settle_invocation_budget(&ticket, &ZoneId::private(), &policy, &[],)
                .await
                .is_err(),
            "a retained ticket cannot settle another zone"
        );
        let wrong_ticket = InvocationTicket {
            attempt_id: ticket.attempt_id + 1,
            ..ticket
        };
        assert!(
            reopened
                .settle_invocation_budget(&wrong_ticket, &zone, &policy, &[])
                .await
                .is_err()
        );
    }

    #[fcp_async_core::runtime::test]
    async fn deadline_and_unknown_outcomes_keep_requests_while_zones_remain_independent() {
        let store = HostAdminStateStore::new();
        let policy = policy(BudgetEnforcement::Deny);
        for (index, outcome) in [
            InvocationOutcome::DeadlineExceeded,
            InvocationOutcome::OutcomeUnknown,
        ]
        .into_iter()
        .enumerate()
        {
            let zone = if index == 0 {
                ZoneId::work()
            } else {
                ZoneId::private()
            };
            let ticket = store
                .admit_invocation_with_usage(
                    admission(&format!("terminal-{index}"), &zone),
                    None,
                    Some(&policy),
                )
                .await
                .unwrap();
            store
                .finish_invocation(&ticket, terminal(outcome))
                .await
                .unwrap();
            let evaluation = store
                .settle_invocation_budget(&ticket, &zone, &policy, &[])
                .await
                .unwrap();
            assert_eq!(used(&evaluation.snapshot, UsageMetricKind::Requests), 1);
            assert_eq!(used(&evaluation.snapshot, UsageMetricKind::Tokens), 0);
            assert!(
                store
                    .admit_invocation_with_usage(
                        admission(&format!("retry-{index}"), &zone),
                        None,
                        Some(&policy),
                    )
                    .await
                    .is_err(),
                "terminal failure must not refund admission"
            );
        }
        let mut warn = policy.clone();
        warn.enforcement = BudgetEnforcement::Warn;
        for index in 0..2 {
            store
                .admit_invocation_with_usage(
                    admission(&format!("warn-{index}"), &ZoneId::owner()),
                    None,
                    Some(&warn),
                )
                .await
                .unwrap();
        }
        let snapshot = store
            .snapshot_zone_budget(&ZoneId::owner(), &warn)
            .await
            .unwrap();
        assert_eq!(used(&snapshot, UsageMetricKind::Requests), 2);
        assert_eq!(snapshot.budgets[0].status, BudgetStatus::Exceeded);
    }

    #[fcp_async_core::runtime::test]
    async fn zone_budget_previews_are_read_only_and_invalid_policies_fail_closed() {
        let store = Arc::new(HostAdminStateStore::new());
        let zone = ZoneId::work();
        let policy = policy(BudgetEnforcement::Deny);
        let engine = BudgetPolicyEngine::with_state_store(
            HashMap::from([(zone.clone(), policy.clone())]),
            Arc::clone(&store),
        );
        let request = PreflightRequest {
            connector_id: ConnectorId::from_static("fcp.test.zone-budget:utility:1.0.0"),
            operation: "fixture.get".to_owned(),
            params: None,
            principal: None,
            zone_id: Some(zone.clone()),
        };
        let before = store.export_snapshot_json().await.unwrap();
        for _ in 0..3 {
            assert!(engine.evaluate_preflight(&request).await.allowed);
            assert_eq!(
                engine.report(None).await.unwrap().zones[0].budgets[0].used,
                0
            );
        }
        assert_eq!(store.export_snapshot_json().await.unwrap(), before);
        store
            .admit_invocation_with_usage(admission("last-request", &zone), None, Some(&policy))
            .await
            .unwrap();
        assert!(!engine.evaluate_preflight(&request).await.allowed);
        for duplicate in [false, true] {
            let mut invalid_policy = policy.clone();
            if duplicate {
                invalid_policy
                    .budgets
                    .push(invalid_policy.budgets[0].clone());
            } else {
                invalid_policy.budgets[0].window_seconds = 0;
            }
            engine.upsert_policy(zone.clone(), invalid_policy).await;
            assert!(engine.snapshot(&zone).await.is_err());
            assert!(!engine.evaluate_preflight(&request).await.allowed);
        }
    }

    #[fcp_async_core::runtime::test]
    async fn failed_persistence_publishes_neither_zone_debit_nor_ticket_and_fences_reports() {
        let directory = tempfile::tempdir().unwrap();
        let blocked_parent = directory.path().join("ordinary-file");
        std::fs::write(&blocked_parent, b"not a directory").unwrap();
        let store = Arc::new(
            HostAdminStateStore::with_state_path(blocked_parent.join("state.json")).unwrap(),
        );
        let zone = ZoneId::work();
        let policy = policy(BudgetEnforcement::Deny);
        let engine = BudgetPolicyEngine::with_state_store(
            HashMap::from([(zone.clone(), policy.clone())]),
            Arc::clone(&store),
        );
        assert!(
            store
                .admit_invocation_with_usage(admission("unpersisted", &zone), None, Some(&policy),)
                .await
                .is_err()
        );
        {
            let retained = store.state.read().await;
            assert!(retained.invocations.is_empty());
            assert!(retained.zone_budget_usage.is_empty());
        }
        assert!(store.persistence_failed.load(Ordering::Acquire));
        assert!(engine.snapshot(&zone).await.is_err());
        assert!(engine.report(None).await.is_err());
        assert!(
            engine
                .record_usage(&zone, &[UsageMetric::tokens(1)])
                .await
                .is_err()
        );
        assert!(
            store
                .admit_invocation_with_usage(
                    admission("after-persistence-failure", &zone),
                    None,
                    Some(&policy),
                )
                .await
                .is_err()
        );
    }

    #[fcp_async_core::runtime::test]
    async fn malformed_persisted_zone_windows_or_settlement_cannot_silently_reset_usage() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("corrupt-zone-budget.json");
        let store = HostAdminStateStore::with_state_path(path.clone()).unwrap();
        let zone = ZoneId::work();
        store
            .admit_invocation_with_usage(
                admission("retained-zone-budget", &zone),
                None,
                Some(&policy(BudgetEnforcement::Deny)),
            )
            .await
            .unwrap();
        let original = store.export_snapshot_json().await.unwrap();
        for corruption in ["clock", "window", "settlement"] {
            let mut snapshot = original.clone();
            match corruption {
                "clock" => snapshot["zone_budget_usage"]["observed_at_unix_secs"] = 0.into(),
                "window" => {
                    let metrics = snapshot["zone_budget_usage"]["zones"][zone.as_str()]["metrics"]
                        .as_object_mut()
                        .unwrap();
                    metrics.values_mut().next().unwrap()["window_seconds"] = 0.into();
                }
                "settlement" => {
                    snapshot["invocations"][0]["budget_usage_digest"] = "invalid".into()
                }
                _ => unreachable!(),
            }
            std::fs::write(&path, serde_json::to_vec(&snapshot).unwrap()).unwrap();
            assert!(
                HostAdminStateStore::with_state_path(path.clone()).is_err(),
                "{corruption}"
            );
        }
    }
}
