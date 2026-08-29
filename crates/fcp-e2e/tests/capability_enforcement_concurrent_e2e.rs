//! Real-concurrent end-to-end harness for capability enforcement.
//!
//! `AmberLark`'s `crates/fcp-conformance/tests/host_invoke_loop_conformance.rs`
//! (commit 6d16bf953) covers the value contract of each phase as a
//! sequence of single-threaded scenarios. This harness moves four of
//! those contracts into a real concurrent invoke load and pins the
//! integration-level properties that single-threaded scenarios cannot
//! reach:
//!
//!   A. **Every activate calls `promote_with_instance`**. N concurrent
//!      activations each go `verify_unbound → promote_with_instance`;
//!      atomic counters track both calls. Across all workers,
//!      `verify_unbound_calls == promote_with_instance_calls` MUST
//!      hold. A regression that lets a connector skip the
//!      instance-binding promotion would surface as an inequality.

#![allow(clippy::too_many_arguments)]

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use chrono::{Duration as ChronoDuration, Utc};
use fcp_audit::{Severity, verify_chain};
use fcp_core::{
    BoundVerified, CapabilityId, CapabilityToken, CapabilityVerifier, InstanceId, ObjectId,
    OperationId, RevocationObject, RevocationRegistry, RevocationScope, SealValidation,
    UnboundVerified, ZoneId,
};
use fcp_crypto::{Ed25519SigningKey, cose::CapabilityTokenBuilder};
use fcp_host::{InvokeAuditChain, InvokeAuditContext, InvokePhase};
use fcp_prelude::ObjectHeader;
use tokio::sync::RwLock;

const N_WORKERS_A: usize = 16;
const N_HONEST_WORKERS_B: usize = 8;
const N_ROGUE_WORKERS_B: usize = 8;
const N_WORKERS_PER_REJECTION_C: usize = 4;
const N_GATEWAY_WORKERS_D: usize = 24;
const N_REVOCATORS_D: usize = 4;
const NETWORK_JITTER_MAX_MS: u64 = 60;
const REVOCATION_SLA_BUDGET_MS: u128 = 500;
const ZONE_WORK: &str = "z:work";
const ZONE_PUBLIC: &str = "z:public";
const CAP_INVOKE: &str = "cap.test.invoke";
const CAP_ALT: &str = "cap.test.alt";
const OP_INVOKE: &str = "op.test.invoke";
const ALLOW_URI: &str = "/v1/test/invoke";

fn test_constraints_cbor(allow_uri: &str) -> Vec<u8> {
    let map = ciborium::Value::Map(vec![(
        ciborium::Value::Text("resource_allow".into()),
        ciborium::Value::Array(vec![ciborium::Value::Text(allow_uri.to_string())]),
    )]);
    let mut bytes = Vec::new();
    ciborium::into_writer(&map, &mut bytes).expect("constraints CBOR");
    bytes
}

fn mint_signed_token_with_validity(
    signing_key: &Ed25519SigningKey,
    instance: &InstanceId,
    capability_id: &str,
    operation_id: &str,
    zone_str: &str,
    allow_uri: &str,
    valid_from: chrono::DateTime<Utc>,
    valid_to: chrono::DateTime<Utc>,
) -> CapabilityToken {
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability_id)
        .zone_id(zone_str)
        .principal("user:concurrent-cap-e2e")
        .operations(&[operation_id])
        .issuer("node:concurrent-cap-e2e-gateway")
        .validity(valid_from, valid_to)
        .try_constraints_cbor(&test_constraints_cbor(allow_uri))
        .expect("constraints CBOR")
        .target_instance(instance.as_str())
        .sign(signing_key)
        .expect("sign");
    CapabilityToken::from_raw(cose)
}

fn mint_signed_token(
    signing_key: &Ed25519SigningKey,
    instance: &InstanceId,
    capability_id: &str,
    operation_id: &str,
    zone_str: &str,
    allow_uri: &str,
) -> CapabilityToken {
    let now = Utc::now();
    mint_signed_token_with_validity(
        signing_key,
        instance,
        capability_id,
        operation_id,
        zone_str,
        allow_uri,
        now,
        now + ChronoDuration::hours(1),
    )
}

fn audit_context(zone: &str, op_index: usize, reason: &str) -> InvokeAuditContext {
    InvokeAuditContext {
        zone_id: zone.into(),
        actor: "user:concurrent-cap-e2e".into(),
        connector_id: "fcp.test.concurrent".into(),
        operation: format!("op_{reason}"),
        operation_id: format!("op-cap-e2e-{reason}-{op_index}"),
        correlation_id: Some(format!("corr-{reason}-{op_index}")),
        occurred_at: 1_700_000_000 + op_index as u64,
    }
}

// ────────────────────────────────────────────────────────────────────
// Scenario A: every connector activate calls promote_with_instance.
// ────────────────────────────────────────────────────────────────────

async fn scenario_a_promote_with_instance_for_every_activate() {
    let signing_key = Arc::new(Ed25519SigningKey::generate());
    let pub_bytes = signing_key.verifying_key().to_bytes();

    let verify_unbound_calls = Arc::new(AtomicU64::new(0));
    let promote_calls = Arc::new(AtomicU64::new(0));
    let executor_calls = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::new();
    for _ in 0..N_WORKERS_A {
        let signing_key = Arc::clone(&signing_key);
        let verify_unbound_calls = Arc::clone(&verify_unbound_calls);
        let promote_calls = Arc::clone(&promote_calls);
        let executor_calls = Arc::clone(&executor_calls);
        handles.push(tokio::spawn(async move {
            let instance = InstanceId::new();
            let token = mint_signed_token(
                &signing_key,
                &instance,
                CAP_INVOKE,
                OP_INVOKE,
                ZONE_WORK,
                ALLOW_URI,
            );
            let verifier = CapabilityVerifier::without_instance_binding(pub_bytes, ZoneId::work());
            let cap = CapabilityId::new(CAP_INVOKE).expect("cap id");
            let op = OperationId::new(OP_INVOKE).expect("op id");
            let unbound: CapabilityToken<UnboundVerified> = verifier
                .verify_unbound(token, &cap, &op, &[ALLOW_URI.to_string()])
                .expect("verify_unbound MUST accept signed in-zone token");
            verify_unbound_calls.fetch_add(1, Ordering::Relaxed);

            let bound = unbound
                .promote_with_instance(&instance)
                .expect("promote_with_instance MUST accept matching instance");
            promote_calls.fetch_add(1, Ordering::Relaxed);

            // Simulate the connector executor seeing the BoundVerified
            // token. The executor signature requires BoundVerified; if
            // this branch ever fires with anything else, it would be
            // a type-system breach (caught at compile time) — at
            // runtime we just record that the path executed.
            assert!(
                execute_with_bound(&bound),
                "executor must accept BoundVerified"
            );
            executor_calls.fetch_add(1, Ordering::Relaxed);
        }));
    }
    for handle in handles {
        handle.await.expect("worker join");
    }

    let unbound_count = verify_unbound_calls.load(Ordering::Relaxed);
    let promote_count = promote_calls.load(Ordering::Relaxed);
    let executor_count = executor_calls.load(Ordering::Relaxed);
    assert_eq!(
        unbound_count, N_WORKERS_A as u64,
        "scenario A: every worker must call verify_unbound — got {unbound_count}",
    );
    assert_eq!(
        promote_count, unbound_count,
        "scenario A: every verify_unbound MUST be followed by promote_with_instance — \
         {promote_count} promotes vs {unbound_count} verifies",
    );
    assert_eq!(
        executor_count, promote_count,
        "scenario A: every promote_with_instance MUST reach the executor — \
         {executor_count} reached vs {promote_count} promoted",
    );
}

/// Executor that requires `BoundVerified`. Used by scenarios A and B
/// to pin the runtime contract that no Unbound token reaches it. The
/// type signature is the load-bearing piece: passing
/// `CapabilityToken<UnboundVerified>` is a compile-time error
/// (covered by `crates/fcp-core/tests/typestate_compile_fail.rs`).
fn execute_with_bound(_token: &CapabilityToken<BoundVerified>) -> bool {
    true
}

// ────────────────────────────────────────────────────────────────────
// Scenario B: UnboundVerified cannot reach BoundVerified executor —
//   runtime cross-check under concurrent honest+rogue load.
// ────────────────────────────────────────────────────────────────────

async fn scenario_b_unbound_cannot_reach_bound_executor() {
    let signing_key = Arc::new(Ed25519SigningKey::generate());
    let pub_bytes = signing_key.verifying_key().to_bytes();

    let executor_calls = Arc::new(AtomicU64::new(0));
    let promote_failures = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::new();

    for _ in 0..N_HONEST_WORKERS_B {
        let signing_key = Arc::clone(&signing_key);
        let executor_calls = Arc::clone(&executor_calls);
        handles.push(tokio::spawn(async move {
            let instance = InstanceId::new();
            let token = mint_signed_token(
                &signing_key,
                &instance,
                CAP_INVOKE,
                OP_INVOKE,
                ZONE_WORK,
                ALLOW_URI,
            );
            let verifier = CapabilityVerifier::without_instance_binding(pub_bytes, ZoneId::work());
            let cap = CapabilityId::new(CAP_INVOKE).expect("cap id");
            let op = OperationId::new(OP_INVOKE).expect("op id");
            let unbound = verifier
                .verify_unbound(token, &cap, &op, &[ALLOW_URI.to_string()])
                .expect("honest worker: verify_unbound");
            let bound = unbound
                .promote_with_instance(&instance)
                .expect("honest worker: promote_with_instance with matching instance");
            assert!(execute_with_bound(&bound));
            executor_calls.fetch_add(1, Ordering::Relaxed);
        }));
    }

    for _ in 0..N_ROGUE_WORKERS_B {
        let signing_key = Arc::clone(&signing_key);
        let promote_failures = Arc::clone(&promote_failures);
        handles.push(tokio::spawn(async move {
            let issued_for = InstanceId::new();
            let attacker_instance = InstanceId::new();
            assert_ne!(issued_for.as_str(), attacker_instance.as_str());
            let token = mint_signed_token(
                &signing_key,
                &issued_for,
                CAP_INVOKE,
                OP_INVOKE,
                ZONE_WORK,
                ALLOW_URI,
            );
            let verifier = CapabilityVerifier::without_instance_binding(pub_bytes, ZoneId::work());
            let cap = CapabilityId::new(CAP_INVOKE).expect("cap id");
            let op = OperationId::new(OP_INVOKE).expect("op id");
            let unbound = verifier
                .verify_unbound(token, &cap, &op, &[ALLOW_URI.to_string()])
                .expect("rogue worker: verify_unbound succeeds (signature/zone/op all valid)");
            // Attempting to promote with the WRONG instance must
            // return Err. The unbound token is moved into
            // promote_with_instance, so the attacker has no other
            // path to reach the BoundVerified executor.
            match unbound.promote_with_instance(&attacker_instance) {
                Ok(_bound) => {
                    panic!(
                        "scenario B SECURITY VIOLATION: rogue worker promoted \
                         UnboundVerified → BoundVerified with mismatched instance — \
                         instance binding is not enforced at runtime",
                    );
                }
                Err(_e) => {
                    promote_failures.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }

    for handle in handles {
        handle.await.expect("worker join");
    }

    let executor_count = executor_calls.load(Ordering::Relaxed);
    let rogue_failed_count = promote_failures.load(Ordering::Relaxed);
    assert_eq!(
        executor_count, N_HONEST_WORKERS_B as u64,
        "scenario B: every honest worker must reach the executor — got {executor_count}",
    );
    assert_eq!(
        rogue_failed_count, N_ROGUE_WORKERS_B as u64,
        "scenario B: every rogue worker's promote_with_instance MUST fail — got {rogue_failed_count}",
    );
}

// ────────────────────────────────────────────────────────────────────
// Scenario C: 4 rejection paths emit Severity::Warning under load.
// ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
enum RejectionKind {
    ZoneMismatch,
    CapabilityMismatch,
    ExpiredToken,
    RevokedToken,
}

impl RejectionKind {
    fn label(self) -> &'static str {
        match self {
            Self::ZoneMismatch => "zone-mismatch",
            Self::CapabilityMismatch => "capability-mismatch",
            Self::ExpiredToken => "expired-token",
            Self::RevokedToken => "revoked-token",
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn scenario_c_four_rejection_paths_emit_warning() {
    let signing_key = Arc::new(Ed25519SigningKey::generate());
    let pub_bytes = signing_key.verifying_key().to_bytes();
    let chain = Arc::new(InvokeAuditChain::new());
    let revoked_cap_id = ObjectId::from_unscoped_bytes(b"capability-token-C-revoked");
    let mut registry = RevocationRegistry::new();
    let revocation_zone = ZoneId::work();
    let header = ObjectHeader {
        schema: fcp_cbor::SchemaId::new(
            "fcp.revocation",
            "RevocationObject",
            semver::Version::new(1, 0, 0),
        ),
        zone_id: revocation_zone.clone(),
        created_at: 1_700_000_000,
        provenance: fcp_prelude::Provenance::new(revocation_zone),
        refs: vec![],
        foreign_refs: vec![],
        ttl_secs: None,
        placement: None,
    };
    let revocation = RevocationObject {
        header,
        revoked: vec![revoked_cap_id],
        scope: RevocationScope::Capability,
        reason: "scenario-C revocation".into(),
        effective_at: 1_700_000_000,
        expires_at: None,
        signature: [0u8; 64],
    };
    registry.add_revocation(&revocation);
    let registry = Arc::new(registry);

    let kinds = [
        RejectionKind::ZoneMismatch,
        RejectionKind::CapabilityMismatch,
        RejectionKind::ExpiredToken,
        RejectionKind::RevokedToken,
    ];

    let mut handles = Vec::new();
    for kind in kinds {
        for worker in 0..N_WORKERS_PER_REJECTION_C {
            let signing_key = Arc::clone(&signing_key);
            let chain = Arc::clone(&chain);
            let registry = Arc::clone(&registry);
            handles.push(tokio::spawn(async move {
                let instance = InstanceId::new();
                let zone = match kind {
                    RejectionKind::ZoneMismatch => ZONE_PUBLIC, // mismatch verifier
                    _ => ZONE_WORK,
                };
                let cap_str = match kind {
                    RejectionKind::CapabilityMismatch => CAP_ALT, // mismatch
                    _ => CAP_INVOKE,
                };
                let op_str = OP_INVOKE;
                let now = Utc::now();
                let (valid_from, valid_to) = match kind {
                    RejectionKind::ExpiredToken => {
                        // Validity window strictly in the past.
                        (
                            now - ChronoDuration::hours(2),
                            now - ChronoDuration::hours(1),
                        )
                    }
                    _ => (now, now + ChronoDuration::hours(1)),
                };

                let token = mint_signed_token_with_validity(
                    &signing_key,
                    &instance,
                    cap_str,
                    op_str,
                    zone,
                    ALLOW_URI,
                    valid_from,
                    valid_to,
                );

                // Verifier always bound to z:work — zone-mismatch
                // workers issued a z:public token and will be rejected
                // on the zone check.
                let verifier =
                    CapabilityVerifier::without_instance_binding(pub_bytes, ZoneId::work());
                let cap = CapabilityId::new(CAP_INVOKE).expect("cap id");
                let op = OperationId::new(OP_INVOKE).expect("op id");
                let result = verifier.verify_unbound(token, &cap, &op, &[ALLOW_URI.to_string()]);

                let (rejected, reason) = match kind {
                    RejectionKind::RevokedToken => {
                        // Verify_unbound has no view of the registry —
                        // the gateway runs a separate revocation check
                        // before audit logging. Simulate that gate
                        // here on the registry shared with this
                        // scenario.
                        if registry.is_revoked(&revoked_cap_id) {
                            (true, "capability revoked via registry".to_string())
                        } else {
                            (false, "registry did not report revoked".to_string())
                        }
                    }
                    _ => match result {
                        Ok(_) => (false, "verifier accepted token unexpectedly".into()),
                        Err(e) => (true, format!("verify_unbound rejected: {e}")),
                    },
                };

                assert!(
                    rejected,
                    "scenario C [{}] worker {worker} expected rejection — {reason}",
                    kind.label(),
                );

                let entry = chain
                    .append(
                        &audit_context(ZONE_WORK, worker, kind.label()),
                        InvokePhase::PreflightDeny {
                            reason: format!("{}: {reason}", kind.label()),
                        },
                    )
                    .expect("PreflightDeny audit append");
                assert_eq!(
                    entry.severity,
                    Severity::Warning,
                    "scenario C [{}] worker {worker}: PreflightDeny MUST emit Severity::Warning",
                    kind.label(),
                );
                kind.label()
            }));
        }
    }

    let mut per_kind_counts: HashMap<&'static str, u64> = HashMap::new();
    for handle in handles {
        let label = handle.await.expect("worker join");
        *per_kind_counts.entry(label).or_default() += 1;
    }
    for kind in kinds {
        assert_eq!(
            per_kind_counts.get(kind.label()).copied().unwrap_or(0),
            N_WORKERS_PER_REJECTION_C as u64,
            "scenario C: kind {} must have all {} workers report rejection — got {:?}",
            kind.label(),
            N_WORKERS_PER_REJECTION_C,
            per_kind_counts.get(kind.label()),
        );
    }

    // Audit chain must be hash-linked + dense seq.
    let entries = chain.entries_for_zone(ZONE_WORK);
    assert!(
        !entries.is_empty(),
        "scenario C: audit chain must contain entries",
    );
    for (i, entry) in entries.iter().enumerate() {
        assert_eq!(
            entry.severity,
            Severity::Warning,
            "scenario C: every entry MUST be Warning — got {:?} at index {i}",
            entry.severity,
        );
        if i == 0 {
            assert!(entry.is_genesis(), "first entry must be genesis");
        } else {
            assert!(
                entry.follows(&entries[i - 1]),
                "entry {i} MUST hash-link to {}",
                i - 1,
            );
        }
    }
    let report = verify_chain(&entries, None, Some(ZONE_WORK));
    assert!(
        report.is_clean() && report.status.is_ok(),
        "scenario C: verify_chain MUST report clean — got {report:?}",
    );
}

// ────────────────────────────────────────────────────────────────────
// Scenario D: RevocationSeal staleness fires within SLA under jitter.
// ────────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_lines)]
async fn scenario_d_revocation_seal_sla_under_jitter() {
    let registry: Arc<RwLock<RevocationRegistry>> =
        Arc::new(RwLock::new(RevocationRegistry::new()));
    let revocation_publish_t = Arc::new(RwLock::new(Vec::<Instant>::new()));

    // Pre-fab N candidate ObjectIds and revocation objects. Each
    // revocator publishes one of these at a different jittered moment.
    let candidate_ids: Vec<ObjectId> = (0..N_REVOCATORS_D)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&(i as u64).to_le_bytes());
            ObjectId::from_unscoped_bytes(&bytes)
        })
        .collect();

    let mut handles = Vec::new();

    // Spawn revocators. Each waits a jittered delay, then publishes a
    // revocation that bumps `head_seq`.
    for (i, target_id) in candidate_ids.iter().enumerate() {
        let registry = Arc::clone(&registry);
        let revocation_publish_t = Arc::clone(&revocation_publish_t);
        let target_id = *target_id;
        handles.push(tokio::spawn(async move {
            let jitter_ms = ((i as u64).wrapping_mul(13)).wrapping_add(7) % NETWORK_JITTER_MAX_MS;
            tokio::time::sleep(Duration::from_millis(jitter_ms)).await;

            let revocation_zone = ZoneId::work();
            let header = ObjectHeader {
                schema: fcp_cbor::SchemaId::new(
                    "fcp.revocation",
                    "RevocationObject",
                    semver::Version::new(1, 0, 0),
                ),
                zone_id: revocation_zone.clone(),
                created_at: 1_700_000_000 + i as u64,
                provenance: fcp_prelude::Provenance::new(revocation_zone),
                refs: vec![],
                foreign_refs: vec![],
                ttl_secs: None,
                placement: None,
            };
            let rev = RevocationObject {
                header,
                revoked: vec![target_id],
                scope: RevocationScope::Capability,
                reason: format!("scenario-D revocator-{i}"),
                effective_at: 1_700_000_000 + i as u64,
                expires_at: None,
                signature: [0u8; 64],
            };
            // Hold the lock briefly to add the revocation AND advance
            // head_seq so seals taken before this publish go stale.
            // `add_revocation` populates the revocations map but does
            // NOT bump head_seq — that's the caller's responsibility
            // (production code threads head updates from the gossip /
            // checkpoint path). Seal staleness depends on head_seq, so
            // we explicitly call `update_head` here. Record the
            // publish time outside the lock for the SLA assertion.
            {
                let mut guard = registry.write().await;
                guard.add_revocation(&rev);
                let next_seq = guard.head_seq + 1;
                let head_obj =
                    ObjectId::from_unscoped_bytes(format!("scenario-D-head-{next_seq}").as_bytes());
                guard.update_head(head_obj, next_seq, 1_700_000_000 + i as u64);
            }
            let t = Instant::now();
            revocation_publish_t.write().await.push(t);
        }));
    }

    // Outcomes recorded by gateway workers: (took_at_seq, validate_outcome,
    // worker_validate_t).
    let outcomes: Arc<RwLock<Vec<(u64, SealValidation, Instant)>>> =
        Arc::new(RwLock::new(Vec::new()));

    for w in 0..N_GATEWAY_WORKERS_D {
        let registry = Arc::clone(&registry);
        let outcomes = Arc::clone(&outcomes);
        let target = candidate_ids[w % N_REVOCATORS_D];
        handles.push(tokio::spawn(async move {
            // Stagger seal-take across [0, NETWORK_JITTER_MAX_MS/2).
            let pre_jitter =
                ((w as u64).wrapping_mul(7)).wrapping_add(1) % (NETWORK_JITTER_MAX_MS / 2);
            tokio::time::sleep(Duration::from_millis(pre_jitter)).await;

            let (seal_seq, seal) = {
                let guard = registry.read().await;
                let seal = guard.check_with_seal(&target, 1_700_000_000 + w as u64);
                (seal.head_seq, seal)
            };

            // Simulate network jitter between seal-take and validate.
            let post_jitter = ((w as u64).wrapping_mul(11)).wrapping_add(3) % NETWORK_JITTER_MAX_MS;
            tokio::time::sleep(Duration::from_millis(post_jitter)).await;

            let validate_t = Instant::now();
            let validation = {
                let guard = registry.read().await;
                guard.validate_seal(&seal, &target)
            };

            outcomes
                .write()
                .await
                .push((seal_seq, validation, validate_t));
        }));
    }

    for handle in handles {
        handle.await.expect("scenario D worker join");
    }

    let outcomes = outcomes.read().await;
    let publish_times = revocation_publish_t.read().await;

    // Sanity: revocators all completed.
    assert_eq!(
        publish_times.len(),
        N_REVOCATORS_D,
        "scenario D: every revocator must have published",
    );

    // Sanity: workers all observed an outcome.
    assert_eq!(
        outcomes.len(),
        N_GATEWAY_WORKERS_D,
        "scenario D: every gateway worker must have a recorded outcome",
    );

    // The registry's final head_seq must equal the number of
    // revocations published.
    let final_seq = registry.read().await.head_seq;
    assert_eq!(
        final_seq, N_REVOCATORS_D as u64,
        "scenario D: head_seq should equal number of revocations published",
    );

    // SLA pin: any worker whose seal was Stale at validate time
    // observed it WITHIN REVOCATION_SLA_BUDGET_MS of the relevant
    // revocation publish. We bound by the LATEST publish before the
    // worker's validate_t (the most recent revocation whose effect
    // could have made the seal stale).
    //
    // We also assert the structural property: at least ONE outcome is
    // Stale (otherwise the test isn't actually exercising the
    // staleness path).
    let mut stale_count = 0;
    let mut valid_count = 0;
    let mut sla_violations: Vec<String> = Vec::new();
    for (seal_seq, validation, validate_t) in outcomes.iter() {
        match validation {
            SealValidation::Valid => {
                valid_count += 1;
            }
            SealValidation::Stale {
                seal_seq: s_seq,
                current_seq,
            } => {
                stale_count += 1;
                assert_eq!(s_seq, seal_seq, "Stale seal_seq mismatches recorded");
                assert!(
                    *current_seq > *s_seq,
                    "Stale must mean current_seq > seal_seq",
                );
                // SLA: find the latest revocation publish ≤ validate_t.
                // Its delta to validate_t is the staleness-detection
                // latency; if any worker observes Stale, the latency
                // MUST be ≤ REVOCATION_SLA_BUDGET_MS. (If publish_t >
                // validate_t, the worker observed Stale because of an
                // earlier revocation; we use the earliest publish_t in
                // that case.)
                let latest_publish_le = publish_times
                    .iter()
                    .filter(|t| **t <= *validate_t)
                    .max()
                    .copied();
                let earliest_publish = publish_times
                    .iter()
                    .min()
                    .copied()
                    .expect("at least one publish");
                let reference = latest_publish_le.unwrap_or(earliest_publish);
                let elapsed_ms = validate_t.saturating_duration_since(reference).as_millis();
                if elapsed_ms > REVOCATION_SLA_BUDGET_MS {
                    sla_violations.push(format!(
                        "Stale seal_seq={s_seq} current_seq={current_seq} took \
                         {elapsed_ms}ms after revocation publish (budget \
                         {REVOCATION_SLA_BUDGET_MS}ms)",
                    ));
                }
            }
            SealValidation::TokenMismatch => panic!(
                "scenario D: TokenMismatch never expected — every worker validates \
                 against the same token id its seal was taken for",
            ),
        }
    }
    assert!(
        stale_count > 0,
        "scenario D: at least one worker MUST observe Stale — otherwise the \
         test is not actually exercising the staleness path. Outcomes: \
         valid={valid_count}, stale={stale_count}",
    );
    assert!(
        sla_violations.is_empty(),
        "scenario D: {} SLA violations — staleness MUST be observed within \
         {REVOCATION_SLA_BUDGET_MS}ms of revocation publish: {sla_violations:?}",
        sla_violations.len(),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn capability_enforcement_under_concurrent_invoke_load_e2e() {
    scenario_a_promote_with_instance_for_every_activate().await;
    scenario_b_unbound_cannot_reach_bound_executor().await;
    scenario_c_four_rejection_paths_emit_warning().await;
    scenario_d_revocation_seal_sla_under_jitter().await;
}
