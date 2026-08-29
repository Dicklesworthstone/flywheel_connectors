//! Credential-pool E2E evidence harness for `flywheel_connectors-4kw5f.7.9`.
//!
//! This deterministic harness exercises the real `fcp-host` credential-pool
//! registry and emits redaction-safe JSONL evidence for the connector-boundary
//! gap still tracked by parent bead `flywheel_connectors-4kw5f.7`. It does not
//! claim live `fcp-host` + Groq process spawning; instead it records that live
//! boundary as a structured skip unless that runner is added later.

use std::collections::{BTreeMap, HashMap};
use std::io::Write as _;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration as StdDuration;

use async_trait::async_trait;
use chrono::{Duration as ChronoDuration, Utc};
use fcp_host::{
    CredentialCooldown, CredentialErrorKind as HostCredentialErrorKind, CredentialLeaseToken,
    CredentialMutationOutcome, CredentialPoolAuditOperation, CredentialPoolError,
    CredentialPoolKey, CredentialPoolRegistry, CredentialPoolStrategy, CredentialSource,
    CredentialUpsertMode, PoolExhaustedBehavior, PooledCredential, ProviderKey,
};
use fcp_prelude::{CredentialId, ZoneId};
use fcp_sdk::{
    CredentialErrorKind as SdkCredentialErrorKind, CredentialErrorReport,
    CredentialLease as SdkCredentialLease, CredentialLeaseClient, CredentialLeaseClientError,
    CredentialLeaseCxExt, CredentialLeaseRelease, CredentialLeaseRequest, LeaseToken,
};
use serde_json::{Value, json};

const SCHEMA: &str = "fcp.credential_pool.e2e.v1";
const BOUNDARY_SCHEMA: &str = "fcp.credential_pool.boundary.v1";
const ARTIFACT_PATH: &str = "target/fcp-credential-pool/credential-pool-e2e.jsonl";
const BOUNDARY_ARTIFACT_PATH: &str =
    "target/fcp-credential-pool/credential-pool-boundary-e2e.jsonl";
const REQUEST_COUNT: usize = 100;
const BOUNDARY_COMMAND_LINE: &str = "cargo test -p fcp-e2e --no-default-features --test \
    credential_pool_e2e credential_pool_boundary_exercises_sdk_host_and_structured_skip -- \
    --nocapture";

const MATERIAL_ALPHA: &str = "pool-material-alpha";
const MATERIAL_BETA: &str = "pool-material-beta";
const MATERIAL_GAMMA: &str = "pool-material-gamma";

#[derive(Debug)]
struct RegistryBackedCredentialLeaseClient {
    registry: Arc<Mutex<CredentialPoolRegistry>>,
    key: CredentialPoolKey,
    token_map: Mutex<HashMap<LeaseToken, CredentialLeaseToken>>,
    records: Arc<Mutex<Vec<Value>>>,
}

impl RegistryBackedCredentialLeaseClient {
    fn new(
        key: CredentialPoolKey,
        registry: CredentialPoolRegistry,
        records: Arc<Mutex<Vec<Value>>>,
    ) -> Self {
        Self {
            registry: Arc::new(Mutex::new(registry)),
            key,
            token_map: Mutex::new(HashMap::new()),
            records,
        }
    }

    fn push_event(
        &self,
        event: &str,
        phase: &str,
        result: &str,
        credential_id: Option<CredentialId>,
        details: Value,
    ) -> Result<(), CredentialLeaseClientError> {
        let record = boundary_event(event, phase, result, &self.key, credential_id, details);
        self.records
            .lock()
            .map_err(|_| CredentialLeaseClientError::unavailable("boundary record lock poisoned"))?
            .push(record);
        Ok(())
    }

    fn set_all_cooldowns(
        &self,
        until: chrono::DateTime<Utc>,
    ) -> Result<(), CredentialLeaseClientError> {
        let mut registry = self.registry_lock()?;
        for credential_id in [credential_id(1), credential_id(2), credential_id(3)] {
            registry
                .set_cooldown(
                    &self.key,
                    credential_id,
                    Some(CredentialCooldown::Until { until }),
                )
                .map_err(|error| map_pool_client_error(&error))?;
        }
        drop(registry);
        self.push_event(
            "credential_pool_exhaustion_fixture_applied",
            "fixture",
            "pass",
            None,
            json!({
                "cooldown_class": "all_pool_exhausted",
                "retry_decision": "wait",
                "available_at_unix": until.timestamp()
            }),
        )
    }

    fn clear_all_cooldowns(&self) -> Result<(), CredentialLeaseClientError> {
        let mut registry = self.registry_lock()?;
        for credential_id in [credential_id(1), credential_id(2), credential_id(3)] {
            registry
                .set_cooldown(&self.key, credential_id, None)
                .map_err(|error| map_pool_client_error(&error))?;
        }
        Ok(())
    }

    fn shutdown_cleanup(&self, request_id: &str) -> Result<usize, CredentialLeaseClientError> {
        let outstanding = {
            let mut token_map = self.token_map.lock().map_err(|_| {
                CredentialLeaseClientError::unavailable("credential lease token map lock poisoned")
            })?;
            token_map.drain().collect::<Vec<_>>()
        };
        let mut registry = self.registry_lock()?;
        let mut released = 0_usize;
        for (_sdk_token, host_token) in outstanding {
            match registry.release(&self.key, host_token) {
                Ok(_) => released += 1,
                Err(CredentialPoolError::UnknownLease { .. }) => {}
                Err(error) => return Err(map_pool_client_error(&error)),
            }
        }
        drop(registry);
        self.push_event(
            "shutdown_cleanup_completed",
            "cleanup",
            "pass",
            None,
            json!({
                "request_id": request_id,
                "shutdown_cleanup_result": "released_outstanding_leases",
                "released_lease_count": released
            }),
        )?;
        Ok(released)
    }

    fn append_audit_receipts(&self) -> Result<(), CredentialLeaseClientError> {
        let audit_events = self.registry_lock()?.audit_events().to_vec();
        for audit in audit_events {
            let audit_value = serde_json::to_value(&audit).map_err(|_| {
                CredentialLeaseClientError::unavailable("credential pool audit event serialize")
            })?;
            self.push_event(
                "audit_receipt",
                "verify",
                "pass",
                audit.credential_id,
                json!({
                    "audit_receipt_id": audit_receipt_id(&audit_value),
                    "op": audit_operation_label(audit.operation),
                    "capability_decision": "allowed"
                }),
            )?;
        }
        Ok(())
    }

    fn registry_lock(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, CredentialPoolRegistry>, CredentialLeaseClientError> {
        self.registry.lock().map_err(|_| {
            CredentialLeaseClientError::unavailable("credential registry lock poisoned")
        })
    }

    fn host_token_for(
        &self,
        lease_token: &LeaseToken,
    ) -> Result<CredentialLeaseToken, CredentialLeaseClientError> {
        self.token_map
            .lock()
            .map_err(|_| {
                CredentialLeaseClientError::unavailable("credential lease token map lock poisoned")
            })?
            .remove(lease_token)
            .ok_or_else(|| CredentialLeaseClientError::invalid("unknown credential lease token"))
    }
}

#[async_trait]
impl CredentialLeaseClient for RegistryBackedCredentialLeaseClient {
    async fn get_credential_lease(
        &self,
        _cx: &fcp_async_core::Cx,
        request: CredentialLeaseRequest,
    ) -> Result<SdkCredentialLease, CredentialLeaseClientError> {
        let request_id = request
            .operation
            .as_deref()
            .map_or_else(|| "req-boundary-unspecified".to_owned(), |operation| {
                format!("req-boundary-{operation}")
            });
        let provider = request.provider.as_deref().unwrap_or("groq");
        if provider != self.key.provider.as_str() {
            self.push_event(
                "credential_lease_denied",
                "authorize",
                "pass",
                None,
                json!({
                    "request_id": request_id,
                    "capability_decision": "denied",
                    "requested_provider": provider,
                    "retry_decision": "none"
                }),
            )?;
            return Err(CredentialLeaseClientError::rejected(
                "provider not allowed by deterministic credential lease fixture",
            ));
        }

        let now = Utc::now();
        let mut registry = self.registry_lock()?;
        let host_lease = match registry.acquire(&self.key, now) {
            Ok(lease) => lease,
            Err(CredentialPoolError::PoolWaitRequired { available_at, .. }) => {
                drop(registry);
                self.push_event(
                    "credential_pool_exhausted",
                    "authorize",
                    "pass",
                    None,
                    json!({
                        "request_id": request_id,
                        "capability_decision": "allowed",
                        "retry_decision": "wait",
                        "cooldown_class": "all_pool_exhausted",
                        "available_at_unix": available_at.timestamp()
                    }),
                )?;
                return Err(CredentialLeaseClientError::rejected(
                    "credential pool exhausted; wait required",
                ));
            }
            Err(CredentialPoolError::PoolExhausted { .. }) => {
                drop(registry);
                self.push_event(
                    "credential_pool_exhausted",
                    "authorize",
                    "pass",
                    None,
                    json!({
                        "request_id": request_id,
                        "capability_decision": "allowed",
                        "retry_decision": "fail_fast",
                        "cooldown_class": "all_pool_exhausted"
                    }),
                )?;
                return Err(CredentialLeaseClientError::rejected(
                    "credential pool exhausted",
                ));
            }
            Err(error) => return Err(map_pool_client_error(&error)),
        };
        let active_lease_count = active_lease_count(&registry, &self.key, host_lease.credential_id);
        let sdk_handle = format!("lease:credential-pool:{}", host_lease.token.as_u64());
        let sdk =
            LeaseToken::new(sdk_handle) // ubs:ignore - synthetic display-safe lease handle, not credential material
                .map_err(|_| {
                    CredentialLeaseClientError::invalid("invalid generated lease token")
                })?;
        self.token_map
            .lock()
            .map_err(|_| {
                CredentialLeaseClientError::unavailable("credential lease token map lock poisoned")
            })?
            .insert(sdk.clone(), host_lease.token);
        let sdk_lease =
            SdkCredentialLease::new(host_lease.credential_id, sdk).with_provider(provider);
        drop(registry);
        self.push_event(
            "credential_lease_acquired",
            "execute",
            "pass",
            Some(sdk_lease.credential_id),
            json!({
                "request_id": request_id,
                "capability_decision": "allowed",
                "active_lease_count": active_lease_count,
                "operation": request.operation.unwrap_or_else(|| "unspecified".to_owned())
            }),
        )?;
        Ok(sdk_lease)
    }

    async fn release_credential_lease(
        &self,
        _cx: &fcp_async_core::Cx,
        release: CredentialLeaseRelease,
    ) -> Result<(), CredentialLeaseClientError> {
        let host_token = self.host_token_for(&release.lease_token)?; // ubs:ignore - display-safe lease handle, not credential material
        let mut registry = self.registry_lock()?;
        let released_id = registry
            .release(&self.key, host_token)
            .map_err(|error| map_pool_client_error(&error))?;
        if released_id != release.credential_id {
            return Err(CredentialLeaseClientError::invalid(
                "credential lease release id mismatch",
            ));
        }
        drop(registry);
        self.push_event(
            "credential_lease_released",
            "execute",
            "pass",
            Some(release.credential_id),
            json!({
                "request_id": "req-boundary-release",
                "outcome": "success",
                "active_lease_count": 0
            }),
        )
    }

    async fn report_credential_error(
        &self,
        _cx: &fcp_async_core::Cx,
        report: CredentialErrorReport,
    ) -> Result<(), CredentialLeaseClientError> {
        let host_token = self.host_token_for(&report.lease_token)?; // ubs:ignore - display-safe lease handle, not credential material
        let kind = map_sdk_error_kind(report.kind);
        let retry_after = report.retry_after_seconds.map(StdDuration::from_secs);
        let now = Utc::now();
        let mut registry = self.registry_lock()?;
        let reported_id = registry
            .report_error(&self.key, host_token, kind, retry_after, now)
            .map_err(|error| map_pool_client_error(&error))?;
        if reported_id != report.credential_id {
            return Err(CredentialLeaseClientError::invalid(
                "credential error report id mismatch",
            ));
        }
        let cooldown_class = cooldown_class_for(&registry, &self.key, reported_id, now);
        drop(registry);
        self.push_event(
            "credential_lease_released",
            "execute",
            "pass",
            Some(report.credential_id),
            json!({
                "request_id": "req-boundary-error-report",
                "outcome": "error",
                "error_kind": sdk_error_kind_label(report.kind),
                "retry_decision": if report.kind == SdkCredentialErrorKind::RateLimited {
                    "cooldown_then_reroute"
                } else {
                    "cooldown"
                },
                "cooldown_class": cooldown_class,
                "active_lease_count": 0,
                "provider_error_body_logged": false
            }),
        )
    }
}

#[test]
fn credential_pool_e2e_emits_redacted_round_robin_cooldown_and_exhaustion_evidence() {
    let started = Utc::now();
    let key = pool_key();
    let mut registry = registry_with_three_groq_credentials(&key);
    registry
        .set_exhausted_behavior(&key, PoolExhaustedBehavior::Wait)
        .expect("pool exhausted behavior should update");

    let mut records = Vec::new();
    records.push(scenario_event(
        "scenario_started",
        "setup",
        "pass",
        &json!({
            "scenario_id": "credential-pool-groq-round-robin-cooldown",
            "operation": "chat.completions",
            "request_count": REQUEST_COUNT,
            "parallel_threads": REQUEST_COUNT,
            "strategy": "round_robin",
            "live_boundary": "structured_skip_recorded"
        }),
    ));

    let (distribution, mut lease_records) =
        run_parallel_round_robin_requests(registry, &key);
    records.append(&mut lease_records);

    assert_eq!(
        distribution.len(),
        3,
        "all 3 credentials must receive traffic"
    );
    assert_eq!(distribution[&credential_id(1)], 34);
    assert_eq!(distribution[&credential_id(2)], 33);
    assert_eq!(distribution[&credential_id(3)], 33);
    records.push(scenario_event(
        "round_robin_distribution_verified",
        "verify",
        "pass",
        &json!({
            "distribution": distribution
                .iter()
                .map(|(credential_id, count)| json!({
                    "credential_id": credential_id.to_string(),
                    "count": count
                }))
                .collect::<Vec<_>>(),
            "assertion": "100 requests distributed 34/33/33 across 3 credentials"
        }),
    ));

    let mut registry = registry_with_three_groq_credentials(&key);
    registry
        .set_exhausted_behavior(&key, PoolExhaustedBehavior::Wait)
        .expect("pool exhausted behavior should update");
    advance_round_robin_cursor(&mut registry, &key, REQUEST_COUNT);
    append_cooldown_reroute_and_recovery_records(&mut registry, &key, &mut records);
    append_pool_exhaustion_record(&mut registry, &key, &mut records);
    append_audit_receipts(&registry, &mut records);
    records.push(live_boundary_skip_record());
    records.push(scenario_event(
        "scenario_completed",
        "verify",
        "pass",
        &json!({
            "duration_ms": (Utc::now() - started).num_milliseconds().max(0),
            "artifact_path": ARTIFACT_PATH
        }),
    ));

    let jsonl = write_jsonl_artifact(&records);
    assert_required_events_present(&jsonl);
    assert_redaction_invariants(&jsonl);
    assert_eq!(fcp_e2e::scan_log_jsonl(&jsonl).error_count, 0);
}

#[allow(clippy::too_many_lines)]
#[test]
fn credential_pool_boundary_exercises_sdk_host_and_structured_skip() {
    let started = Utc::now();
    let key = pool_key();
    let mut registry = registry_with_three_groq_credentials(&key);
    registry
        .set_exhausted_behavior(&key, PoolExhaustedBehavior::Wait)
        .expect("pool exhausted behavior should update");
    let records = Arc::new(Mutex::new(vec![boundary_event(
        "scenario_started",
        "setup",
        "pass",
        &key,
        None,
        json!({
            "request_id": "req-boundary-start",
            "scenario_id": "credential-pool-sdk-host-boundary",
            "host_mode": "in_process_host_registry",
            "connector_id": "fcp-groq-deterministic-fixture",
            "provider_fixture_id": "groq-no-live-provider",
            "strategy": "round_robin"
        }),
    )]));
    let client =
        RegistryBackedCredentialLeaseClient::new(key.clone(), registry, Arc::clone(&records));
    // asupersync 0.3.2 gates `Cx::for_testing` out of non-test builds; obtain
    // the ambient runtime context inside each `block_on_sync` future (where it
    // is installed) via `compatibility_cx()` rather than eagerly outside it.
    let rate_limited = fcp_async_core::runtime::block_on_sync(async {
        fcp_async_core::compatibility_cx()
            .get_credential_lease_with(
                &client,
                CredentialLeaseRequest::new(pool_reference_id())
                    .with_provider("groq")
                    .with_operation("chat.completions"),
            )
            .await
    })
    .unwrap()
    .unwrap();
    fcp_async_core::runtime::block_on_sync(async {
        fcp_async_core::compatibility_cx()
            .report_credential_error(
                &client,
                CredentialErrorReport::new(
                    rate_limited.credential_id,
                    rate_limited.lease_token.clone(),
                    SdkCredentialErrorKind::RateLimited,
                )
                .with_retry_after_seconds(2),
            )
            .await
    })
    .unwrap()
    .unwrap();

    let rerouted = fcp_async_core::runtime::block_on_sync(async {
        fcp_async_core::compatibility_cx()
            .get_credential_lease_with(
                &client,
                CredentialLeaseRequest::new(pool_reference_id())
                    .with_provider("groq")
                    .with_operation("chat.completions"),
            )
            .await
    })
    .unwrap()
    .unwrap();
    assert_ne!(
        rerouted.credential_id, rate_limited.credential_id,
        "SDK-backed host client must route around a rate-limited credential"
    );
    fcp_async_core::runtime::block_on_sync(async {
        fcp_async_core::compatibility_cx()
            .release_credential_lease(&client, rerouted.release_request())
            .await
    })
    .unwrap()
    .unwrap();

    let auth_failed = fcp_async_core::runtime::block_on_sync(async {
        fcp_async_core::compatibility_cx()
            .get_credential_lease_with(
                &client,
                CredentialLeaseRequest::new(pool_reference_id())
                    .with_provider("groq")
                    .with_operation("chat.completions"),
            )
            .await
    })
    .unwrap()
    .unwrap();
    fcp_async_core::runtime::block_on_sync(async {
        fcp_async_core::compatibility_cx()
            .report_credential_error(
                &client,
                CredentialErrorReport::new(
                    auth_failed.credential_id,
                    auth_failed.lease_token.clone(),
                    SdkCredentialErrorKind::AuthFailed,
                ),
            )
            .await
    })
    .unwrap()
    .unwrap();

    let denied = fcp_async_core::runtime::block_on_sync(async {
        fcp_async_core::compatibility_cx()
            .get_credential_lease_with(
                &client,
                CredentialLeaseRequest::new(pool_reference_id())
                    .with_provider("forbidden-provider")
                    .with_operation("chat.completions"),
            )
            .await
    })
    .unwrap();
    assert!(matches!(
        denied,
        Err(CredentialLeaseClientError::Rejected { .. })
    ));

    let exhausted_until = Utc::now() + ChronoDuration::seconds(5);
    client.set_all_cooldowns(exhausted_until).unwrap();
    let exhausted = fcp_async_core::runtime::block_on_sync(async {
        fcp_async_core::compatibility_cx()
            .get_credential_lease_with(
                &client,
                CredentialLeaseRequest::new(pool_reference_id())
                    .with_provider("groq")
                    .with_operation("chat.completions"),
            )
            .await
    })
    .unwrap();
    assert!(matches!(
        exhausted,
        Err(CredentialLeaseClientError::Rejected { .. })
    ));

    client.clear_all_cooldowns().unwrap();
    let leaked_for_cleanup = fcp_async_core::runtime::block_on_sync(async {
        fcp_async_core::compatibility_cx()
            .get_credential_lease_with(
                &client,
                CredentialLeaseRequest::new(pool_reference_id())
                    .with_provider("groq")
                    .with_operation("chat.completions"),
            )
            .await
    })
    .unwrap()
    .unwrap();
    assert!(credential_id_hash(leaked_for_cleanup.credential_id).starts_with("blake3:"));
    assert_eq!(client.shutdown_cleanup("req-boundary-shutdown").unwrap(), 1);

    client.append_audit_receipts().unwrap();
    {
        let mut guard = records.lock().expect("boundary records lock");
        guard.push(boundary_live_skip_record(&key));
        guard.push(boundary_event(
            "scenario_completed",
            "verify",
            "pass",
            &key,
            None,
            json!({
                "request_id": "req-boundary-complete",
                "duration_ms": (Utc::now() - started).num_milliseconds().max(0),
                "artifact_path": BOUNDARY_ARTIFACT_PATH,
                "shutdown_cleanup_result": "verified"
            }),
        ));
    }

    let final_records = records.lock().expect("boundary records lock").clone();
    let jsonl = write_jsonl_artifact_to(BOUNDARY_ARTIFACT_PATH, &final_records);
    assert_boundary_required_events_present(&jsonl);
    assert_boundary_records_have_required_fields(&final_records);
    assert_boundary_redaction_invariants(&jsonl);
    assert_eq!(fcp_e2e::scan_log_jsonl(&jsonl).error_count, 0);
}

fn run_parallel_round_robin_requests(
    registry: CredentialPoolRegistry,
    key: &CredentialPoolKey,
) -> (BTreeMap<CredentialId, u32>, Vec<Value>) {
    let registry = Arc::new(Mutex::new(registry));
    let handles = (0..REQUEST_COUNT)
        .map(|request_index| {
            let registry = Arc::clone(&registry);
            let key = CredentialPoolKey::clone(key);
            thread::spawn(move || {
                let now = Utc::now();
                let mut registry = registry.lock().expect("credential pool registry lock");
                let lease = registry.acquire(&key, now).expect("lease should acquire");
                let view = registry
                    .redacted_view(&key, now)
                    .expect("redacted view should exist");
                let active_leases_for_cred = view
                    .entries
                    .iter()
                    .find(|entry| entry.credential_id == lease.credential_id)
                    .map(|entry| entry.active_leases)
                    .expect("leased credential should be in redacted view");
                let acquired = lease_event(
                    "credential_lease_acquired",
                    "execute",
                    "pass",
                    &key,
                    lease.credential_id,
                    &json!({
                        "request_index": request_index,
                        "operation": "chat.completions",
                        "strategy": "round_robin",
                        "active_leases_for_cred": active_leases_for_cred
                    }),
                );
                let released_id = registry
                    .release(&key, lease.token)
                    .expect("lease should release");
                assert_eq!(released_id, lease.credential_id);
                let released = lease_event(
                    "credential_lease_released",
                    "execute",
                    "pass",
                    &key,
                    released_id,
                    &json!({
                        "request_index": request_index,
                        "operation": "chat.completions",
                        "outcome": "success"
                    }),
                );
                (released_id, vec![acquired, released])
            })
        })
        .collect::<Vec<_>>();

    let mut distribution = BTreeMap::new();
    let mut records = Vec::new();
    for handle in handles {
        let (credential_id, mut events) = handle.join().expect("request thread should not panic");
        *distribution.entry(credential_id).or_insert(0) += 1;
        records.append(&mut events);
    }

    (distribution, records)
}

fn append_cooldown_reroute_and_recovery_records(
    registry: &mut CredentialPoolRegistry,
    key: &CredentialPoolKey,
    records: &mut Vec<Value>,
) {
    let now = Utc::now();
    let rate_limited = registry
        .acquire(key, now)
        .expect("next lease should target credential 2 after 100 round-robin requests");
    assert_eq!(rate_limited.credential_id, credential_id(2));
    records.push(lease_event(
        "credential_lease_acquired",
        "execute",
        "pass",
        key,
        rate_limited.credential_id,
        &json!({
            "operation": "chat.completions",
            "strategy": "round_robin",
            "injected_provider_status": 429
        }),
    ));
    let cooldowned_id = registry
        .report_error(
            key,
            rate_limited.token,
            HostCredentialErrorKind::RateLimited,
            Some(StdDuration::from_secs(2)),
            now,
        )
        .expect("rate limit should report and release");
    assert_eq!(cooldowned_id, credential_id(2));
    records.push(lease_event(
        "credential_lease_released",
        "execute",
        "pass",
        key,
        cooldowned_id,
        &json!({
            "operation": "chat.completions",
            "outcome": "error",
            "error_kind": "rate_limited",
            "provider_error_body_logged": false
        }),
    ));

    let cooldown_until = cooldown_until_for(registry, key, cooldowned_id, now);
    records.push(lease_event(
        "credential_cooldown_set",
        "verify",
        "pass",
        key,
        cooldowned_id,
        &json!({
            "until_unix": cooldown_until.timestamp(),
            "reason": "rate_limited",
            "retry_after_seconds": 2
        }),
    ));

    let rerouted = registry
        .acquire(key, now)
        .expect("pool should route around cooldowned credential");
    assert_ne!(
        rerouted.credential_id, cooldowned_id,
        "cooldowned credential must not receive the next request"
    );
    let rerouted_id = registry
        .release(key, rerouted.token)
        .expect("rerouted lease should release");
    records.push(lease_event(
        "credential_lease_released",
        "verify",
        "pass",
        key,
        rerouted_id,
        &json!({
            "operation": "chat.completions",
            "outcome": "success",
            "rerouted_around_credential_id": cooldowned_id.to_string()
        }),
    ));

    let recovered_ids = acquire_three_after(
        registry,
        key,
        cooldown_until + ChronoDuration::milliseconds(1),
    );
    assert!(
        recovered_ids.contains(&cooldowned_id),
        "credential 2 should be selectable again after retry-after cooldown"
    );
    records.push(lease_event(
        "credential_cooldown_recovered",
        "verify",
        "pass",
        key,
        cooldowned_id,
        &json!({
            "operation": "chat.completions",
            "recovery_window_checked": true
        }),
    ));
}

fn append_pool_exhaustion_record(
    registry: &mut CredentialPoolRegistry,
    key: &CredentialPoolKey,
    records: &mut Vec<Value>,
) {
    let now = Utc::now();
    let until = now + ChronoDuration::seconds(5);
    for id in [credential_id(1), credential_id(2), credential_id(3)] {
        registry
            .set_cooldown(key, id, Some(CredentialCooldown::Until { until }))
            .expect("manual cooldown should apply");
    }

    let error = registry
        .acquire(key, now)
        .expect_err("wait-mode exhausted pool should surface deterministic wait advice");
    let available_at = match error {
        CredentialPoolError::PoolWaitRequired { available_at, .. } => available_at,
        other => {
            assert!(
                matches!(other, CredentialPoolError::PoolWaitRequired { .. }),
                "expected PoolWaitRequired"
            );
            now
        }
    };
    assert_eq!(available_at, until);
    records.push(scenario_event(
        "credential_pool_exhausted",
        "verify",
        "pass",
        &json!({
            "provider": key.provider.as_str(),
            "zone_id": key.zone_id.as_str(),
            "behavior": "wait",
            "available_at_unix": available_at.timestamp(),
            "credential_count": 3
        }),
    ));
}

fn append_audit_receipts(registry: &CredentialPoolRegistry, records: &mut Vec<Value>) {
    for audit in registry.audit_events() {
        let audit_value = serde_json::to_value(audit).expect("audit event should serialize");
        records.push(scenario_event(
            "audit_receipt",
            "verify",
            "pass",
            &json!({
                "receipt_id": audit_receipt_id(&audit_value),
                "kind": "credential_pool.admin_mutation",
                "op": audit_operation_label(audit.operation),
                "provider": audit.pool_key.provider.as_str(),
                "zone_id": audit.pool_key.zone_id.as_str(),
                "credential_id": audit.credential_id.map(|id| id.to_string()),
                "outcome": audit.outcome.map(mutation_outcome_label)
            }),
        ));
    }
}

fn advance_round_robin_cursor(
    registry: &mut CredentialPoolRegistry,
    key: &CredentialPoolKey,
    acquisitions: usize,
) {
    for _ in 0..acquisitions {
        let lease = registry
            .acquire(key, Utc::now())
            .expect("cursor advance lease should acquire");
        registry
            .release(key, lease.token)
            .expect("cursor advance lease should release");
    }
}

fn acquire_three_after(
    registry: &mut CredentialPoolRegistry,
    key: &CredentialPoolKey,
    now: chrono::DateTime<Utc>,
) -> Vec<CredentialId> {
    let mut ids = Vec::new();
    for _ in 0..3 {
        let lease = registry
            .acquire(key, now)
            .expect("post-cooldown lease should acquire");
        ids.push(lease.credential_id);
        registry
            .release(key, lease.token)
            .expect("post-cooldown lease should release");
    }
    ids
}

fn cooldown_until_for(
    registry: &CredentialPoolRegistry,
    key: &CredentialPoolKey,
    credential_id: CredentialId,
    now: chrono::DateTime<Utc>,
) -> chrono::DateTime<Utc> {
    let view = registry
        .redacted_view(key, now)
        .expect("redacted view should exist");
    let cooldown = view
        .entries
        .iter()
        .find(|entry| entry.credential_id == credential_id)
        .and_then(|entry| entry.cooldown.clone())
        .expect("cooldown should be set");
    let cooldown_is_time_bound = matches!(&cooldown, CredentialCooldown::Until { .. });
    match cooldown {
        CredentialCooldown::Until { until } => until,
        CredentialCooldown::Permanent => {
            assert!(
                cooldown_is_time_bound,
                "rate-limit cooldown should be time-bound"
            );
            now
        }
    }
}

fn registry_with_three_groq_credentials(key: &CredentialPoolKey) -> CredentialPoolRegistry {
    let mut registry = CredentialPoolRegistry::new();
    for (index, material) in [
        (1_u8, MATERIAL_ALPHA),
        (2_u8, MATERIAL_BETA),
        (3_u8, MATERIAL_GAMMA),
    ] {
        registry
            .add_credential(
                key.clone(),
                CredentialPoolStrategy::RoundRobin,
                PooledCredential::new(
                    credential_id(index),
                    CredentialSource::Manual,
                    u32::from(index),
                    format!("groq-key-{index}"),
                    json!({ "material": material }),
                ),
                CredentialUpsertMode::RejectExisting,
            )
            .expect("credential should insert");
    }
    registry
}

fn pool_key() -> CredentialPoolKey {
    CredentialPoolKey::new(
        ProviderKey::new("groq").expect("provider key should validate"),
        ZoneId::work(),
    )
}

fn credential_id(index: u8) -> CredentialId {
    let raw = match index {
        1 => "11111111-1111-1111-1111-111111111111",
        2 => "22222222-2222-2222-2222-222222222222",
        3 => "33333333-3333-3333-3333-333333333333",
        _ => {
            assert!(
                (1..=3).contains(&index),
                "unsupported test credential index {index}"
            );
            "00000000-0000-0000-0000-000000000000"
        }
    };
    CredentialId::parse(raw).expect("static credential id should parse")
}

fn lease_event(
    event: &str,
    phase: &str,
    result: &str,
    key: &CredentialPoolKey,
    credential_id: CredentialId,
    details: &Value,
) -> Value {
    scenario_event(
        event,
        phase,
        result,
        &json!({
            "provider": key.provider.as_str(),
            "zone_id": key.zone_id.as_str(),
            "credential_id": credential_id.to_string(),
            "source_label": "manual",
            "details": details
        }),
    )
}

fn scenario_event(event: &str, phase: &str, result: &str, details: &Value) -> Value {
    json!({
        "schema": SCHEMA,
        "event": event,
        "timestamp": Utc::now().to_rfc3339(),
        "bead": "flywheel_connectors-4kw5f.7.9",
        "phase": phase,
        "result": result,
        "command_line": "cargo test -p fcp-e2e --no-default-features --test credential_pool_e2e -- --nocapture",
        "git_revision": git_revision(),
        "details": details
    })
}

fn live_boundary_skip_record() -> Value {
    let enabled = std::env::var("FCP_E2E_LIVE_CREDENTIAL_POOL_GROQ")
        .is_ok_and(|value| !value.trim().is_empty());
    scenario_event(
        "live_boundary_status",
        "verify",
        if enabled { "degraded" } else { "skip" },
        &json!({
            "live_fcp_host_spawned": false,
            "live_groq_connector_spawned": false,
            "skip_reason": if enabled {
                "live_boundary_runner_not_wired"
            } else {
                "live_boundary_not_enabled_in_deterministic_ci"
            },
            "required_env": "FCP_E2E_LIVE_CREDENTIAL_POOL_GROQ"
        }),
    )
}

fn boundary_live_skip_record(key: &CredentialPoolKey) -> Value {
    let enabled = std::env::var("FCP_E2E_LIVE_CREDENTIAL_POOL_GROQ")
        .is_ok_and(|value| !value.trim().is_empty());
    boundary_event(
        "live_boundary_status",
        "verify",
        if enabled { "degraded" } else { "skip" },
        key,
        None,
        json!({
            "request_id": "req-boundary-live-status",
            "live_fcp_host_spawned": false,
            "live_groq_connector_spawned": false,
            "skip_reason": if enabled {
                "live_boundary_runner_not_wired"
            } else {
                "live_boundary_not_enabled_in_deterministic_ci"
            },
            "required_env": "FCP_E2E_LIVE_CREDENTIAL_POOL_GROQ"
        }),
    )
}

fn boundary_event(
    event: &str,
    phase: &str,
    result: &str,
    key: &CredentialPoolKey,
    credential_id: Option<CredentialId>,
    details: Value,
) -> Value {
    let mut merged = serde_json::Map::new();
    merged.insert("pool_id_hash".to_owned(), json!(pool_id_hash(key)));
    merged.insert(
        "credential_id_hash".to_owned(),
        credential_id
            .map(credential_id_hash)
            .map_or(Value::Null, Value::String),
    );
    merged.insert("strategy".to_owned(), json!("round_robin"));
    merged.insert("active_lease_count".to_owned(), json!(0));
    merged.insert("request_id".to_owned(), json!("not_applicable"));
    merged.insert(
        "correlation_id".to_owned(),
        json!("corr-credential-pool-boundary"),
    );
    merged.insert("capability_decision".to_owned(), json!("allowed"));
    merged.insert("retry_decision".to_owned(), json!("none"));
    merged.insert("cooldown_class".to_owned(), json!("none"));
    merged.insert("audit_receipt_id".to_owned(), Value::Null);
    merged.insert(
        "shutdown_cleanup_result".to_owned(),
        json!("not_applicable"),
    );
    merged.insert("skip_reason".to_owned(), Value::Null);
    if let Some(extra) = details.as_object() {
        for (key, value) in extra {
            merged.insert(key.clone(), value.clone());
        }
    } else {
        merged.insert("extra".to_owned(), details);
    }

    json!({
        "schema": BOUNDARY_SCHEMA,
        "event": event,
        "timestamp": Utc::now().to_rfc3339(),
        "bead": "flywheel_connectors-4kw5f.7.10",
        "phase": phase,
        "result": result,
        "command_line": BOUNDARY_COMMAND_LINE,
        "git_revision": git_revision(),
        "host_mode": "in_process_host_registry",
        "connector_id": "fcp-groq-deterministic-fixture",
        "provider_fixture_id": "groq-no-live-provider",
        "details": Value::Object(merged)
    })
}

fn active_lease_count(
    registry: &CredentialPoolRegistry,
    key: &CredentialPoolKey,
    credential_id: CredentialId,
) -> u32 {
    registry
        .redacted_view(key, Utc::now())
        .ok()
        .and_then(|view| {
            view.entries
                .into_iter()
                .find(|entry| entry.credential_id == credential_id)
                .map(|entry| entry.active_leases)
        })
        .unwrap_or_default()
}

fn cooldown_class_for(
    registry: &CredentialPoolRegistry,
    key: &CredentialPoolKey,
    credential_id: CredentialId,
    now: chrono::DateTime<Utc>,
) -> &'static str {
    registry
        .redacted_view(key, now)
        .ok()
        .and_then(|view| {
            view.entries
                .into_iter()
                .find(|entry| entry.credential_id == credential_id)
                .and_then(|entry| entry.cooldown)
        })
        .map_or("none", |cooldown| match cooldown {
            CredentialCooldown::Until { .. } => "rate_limited",
            CredentialCooldown::Permanent => "permanent_auth",
        })
}

fn pool_reference_id() -> CredentialId {
    CredentialId::parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        .expect("static pool reference id should parse")
}

fn map_sdk_error_kind(kind: SdkCredentialErrorKind) -> HostCredentialErrorKind {
    match kind {
        SdkCredentialErrorKind::RateLimited => HostCredentialErrorKind::RateLimited,
        SdkCredentialErrorKind::QuotaExhausted => HostCredentialErrorKind::QuotaExhausted,
        SdkCredentialErrorKind::AuthFailed => HostCredentialErrorKind::AuthFailed,
        SdkCredentialErrorKind::RetryableProviderError => {
            HostCredentialErrorKind::RetryableProviderError
        }
    }
}

fn sdk_error_kind_label(kind: SdkCredentialErrorKind) -> &'static str {
    match kind {
        SdkCredentialErrorKind::RateLimited => "rate_limited",
        SdkCredentialErrorKind::QuotaExhausted => "quota_exhausted",
        SdkCredentialErrorKind::AuthFailed => "auth_failed",
        SdkCredentialErrorKind::RetryableProviderError => "retryable_provider_error",
    }
}

fn map_pool_client_error(error: &CredentialPoolError) -> CredentialLeaseClientError {
    match error {
        CredentialPoolError::DuplicateCredential { .. }
        | CredentialPoolError::InvalidMaxConcurrentPerCredential { .. }
        | CredentialPoolError::InvalidStickyMaxUses { .. }
        | CredentialPoolError::SelectionIndexInvalid { .. } => {
            CredentialLeaseClientError::invalid(error.to_string())
        }
        CredentialPoolError::InvalidProviderKey
        | CredentialPoolError::PoolNotFound { .. }
        | CredentialPoolError::CredentialNotFound { .. }
        | CredentialPoolError::UnknownLease { .. }
        | CredentialPoolError::PoolExhausted { .. }
        | CredentialPoolError::PoolWaitRequired { .. } => {
            CredentialLeaseClientError::rejected(error.to_string())
        }
    }
}

fn pool_id_hash(key: &CredentialPoolKey) -> String {
    hash_for_log(&format!(
        "{}:{}",
        key.provider.as_str(),
        key.zone_id.as_str()
    ))
}

fn credential_id_hash(credential_id: CredentialId) -> String {
    hash_for_log(&credential_id.to_string())
}

fn hash_for_log(value: &str) -> String {
    format!("blake3:{}", blake3::hash(value.as_bytes()).to_hex())
}

fn audit_operation_label(operation: CredentialPoolAuditOperation) -> &'static str {
    match operation {
        CredentialPoolAuditOperation::CredentialUpsert => "credential_upsert",
        CredentialPoolAuditOperation::CredentialRemove => "credential_remove",
        CredentialPoolAuditOperation::StrategySet => "strategy_set",
        CredentialPoolAuditOperation::MaxConcurrentSet => "max_concurrent_set",
        CredentialPoolAuditOperation::StickyPolicySet => "sticky_policy_set",
        CredentialPoolAuditOperation::ExhaustedBehaviorSet => "exhausted_behavior_set",
        CredentialPoolAuditOperation::CooldownSet => "cooldown_set",
    }
}

fn mutation_outcome_label(outcome: CredentialMutationOutcome) -> &'static str {
    match outcome {
        CredentialMutationOutcome::Added => "added",
        CredentialMutationOutcome::Replaced => "replaced",
        CredentialMutationOutcome::Removed => "removed",
    }
}

fn audit_receipt_id(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).expect("audit receipt input should serialize");
    format!("blake3:{}", blake3::hash(&bytes).to_hex())
}

fn git_revision() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|revision| revision.trim().to_string())
        .filter(|revision| !revision.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn write_jsonl_artifact(records: &[Value]) -> String {
    write_jsonl_artifact_to(ARTIFACT_PATH, records)
}

fn write_jsonl_artifact_to(path: &str, records: &[Value]) -> String {
    let jsonl = records
        .iter()
        .map(|record| serde_json::to_string(record).expect("evidence record should serialize"))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::create_dir_all("target/fcp-credential-pool")
        .expect("artifact directory should be writable");
    let mut file = std::fs::File::create(path).expect("artifact should be writable");
    file.write_all(jsonl.as_bytes())
        .expect("artifact should write");
    file.write_all(b"\n")
        .expect("artifact newline should write");
    jsonl
}

fn assert_required_events_present(jsonl: &str) {
    for event in [
        "credential_lease_acquired",
        "credential_lease_released",
        "credential_cooldown_set",
        "credential_pool_exhausted",
        "audit_receipt",
        "live_boundary_status",
    ] {
        assert!(jsonl.contains(event), "missing required event {event}");
    }
}

fn assert_redaction_invariants(jsonl: &str) {
    for forbidden in [
        MATERIAL_ALPHA,
        MATERIAL_BETA,
        MATERIAL_GAMMA,
        "Bearer ",
        "api_key",
        "provider error body",
        "private prompt",
    ] {
        assert!(
            !jsonl.contains(forbidden),
            "credential-pool evidence leaked forbidden payload fragment {forbidden:?}"
        );
    }
}

fn assert_boundary_required_events_present(jsonl: &str) {
    for event in [
        "credential_lease_acquired",
        "credential_lease_released",
        "credential_lease_denied",
        "credential_pool_exhausted",
        "shutdown_cleanup_completed",
        "audit_receipt",
        "live_boundary_status",
    ] {
        assert!(jsonl.contains(event), "missing boundary event {event}");
    }
}

fn assert_boundary_records_have_required_fields(records: &[Value]) {
    for record in records {
        for field in [
            "command_line",
            "git_revision",
            "host_mode",
            "connector_id",
            "provider_fixture_id",
        ] {
            assert!(
                record.get(field).is_some(),
                "boundary record missing top-level field {field}: {record}"
            );
        }
        let details = record
            .get("details")
            .and_then(Value::as_object)
            .expect("boundary record details must be an object");
        for field in [
            "pool_id_hash",
            "credential_id_hash",
            "strategy",
            "active_lease_count",
            "request_id",
            "correlation_id",
            "capability_decision",
            "retry_decision",
            "cooldown_class",
            "audit_receipt_id",
            "shutdown_cleanup_result",
            "skip_reason",
        ] {
            assert!(
                details.contains_key(field),
                "boundary record missing details field {field}: {record}"
            );
        }
    }
}

fn assert_boundary_redaction_invariants(jsonl: &str) {
    assert_redaction_invariants(jsonl);
    for raw_id in [
        pool_reference_id(),
        credential_id(1),
        credential_id(2),
        credential_id(3),
    ] {
        assert!(
            !jsonl.contains(&raw_id.to_string()),
            "boundary evidence leaked raw credential id {raw_id}"
        );
    }
}
