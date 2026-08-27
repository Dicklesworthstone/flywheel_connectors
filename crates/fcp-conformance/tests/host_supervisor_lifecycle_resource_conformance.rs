//! `fcp_host::supervisor` lifecycle + resource-limit conformance.
//!
//! Complement to `host_supervisor_restart_contract_conformance.rs`
//! (TEST-CONFORMANCE-52) which pinned `RestartPolicy` / `ProcessExit` /
//! `RestartTracker` / `ExponentialBackoff`. This test pins the rest of
//! the supervisor module:
//!
//! Properties pinned (NORMATIVE):
//!
//! 1. **`ShutdownPhase` state machine** — `NotStarted` → `GracefulWait`
//!    (`start_graceful`) → `ForceKill` (escalate after timeout) →
//!    Complete (`record_exit`). `start_graceful` MUST NOT
//!    re-trigger from non-NotStarted; `record_force_kill` only
//!    transitions from `GracefulWait`.
//! 2. **`should_force_kill` boundary** — true only after
//!    `now - sent_at >= graceful_timeout` (inclusive ≥ boundary,
//!    not strict >).
//! 3. **`is_shutting_down` ⇔ {`GracefulWait`, `ForceKill`}**;
//!    `is_complete` ⇔ Complete.
//! 4. **`HealthCheckScheduler::is_due`** is true on first call (no
//!    `last_check`) and after `interval` elapses. `record_success`
//!    resets `consecutive_failures`; `record_failure` saturating-adds.
//! 5. **`is_unhealthy` ⇔ `consecutive_failures` ≥ `max_consecutive_failures`**
//!    (default 3, configurable via `with_max_failures`).
//! 6. **`time_until_next` saturates at zero** when overdue (saturating
//!    sub).
//! 7. **`ResourceLimits::default`** — memory=512 MiB, `max_fds=1024`,
//!    `max_processes=64`; `cpu_seconds` and `max_file_size` unset by default.
//! 8. **`ResourceLimits::unlimited`** — every field None.
//! 9. **`merge_strict`** takes the LOWER (stricter) value per field;
//!    None | Some(x) → Some(x); None | None → None.
//! 10. **`ResourceUsage::violations`** emits `ResourceViolation` per
//!     exceeded limit with correct `ResourceKind` and STRICT > limit
//!     semantics (≤ limit is NOT a violation).
//! 11. **`ResourceKind` Display** — `snake_case` strings ("memory" /
//!     "`cpu_time`" / "`file_descriptors`" / "processes" / "`file_size`").
//! 12. **`ConnectionTracker`**: `try_acquire` succeeds before drain,
//!     returns None after `start_drain`; `active_count` tracks live
//!     guards; `ConnectionGuard` Drop decrements; `is_drained` ⇔ draining
//!     AND `active_count==0`.

use fcp_host::{
    ConnectionTracker, HealthCheckScheduler, ProcessExit, ResourceKind, ResourceLimits,
    ResourceUsage, ResourceViolation, ShutdownCoordinator, ShutdownPhase,
};
use std::time::{Duration, Instant};

// ─── ShutdownCoordinator ────────────────────────────────────────────

#[test]
fn shutdown_coordinator_starts_in_not_started_phase() {
    let c = ShutdownCoordinator::new(Duration::from_secs(30));
    assert_eq!(*c.phase(), ShutdownPhase::NotStarted);
    assert!(!c.is_shutting_down());
    assert!(!c.is_complete());
}

#[test]
fn start_graceful_transitions_to_graceful_wait() {
    let mut c = ShutdownCoordinator::new(Duration::from_secs(30));
    let t = Instant::now();
    c.start_graceful(t);
    assert!(c.is_shutting_down());
    match c.phase() {
        ShutdownPhase::GracefulWait { sent_at } => assert_eq!(*sent_at, t),
        other => panic!("expected GracefulWait, got {other:?}"),
    }
}

#[test]
fn start_graceful_is_idempotent_for_non_not_started_phases() {
    let mut c = ShutdownCoordinator::new(Duration::from_secs(30));
    let t1 = Instant::now();
    c.start_graceful(t1);
    let t2 = t1 + Duration::from_secs(5);
    c.start_graceful(t2);
    match c.phase() {
        ShutdownPhase::GracefulWait { sent_at } => assert_eq!(
            *sent_at, t1,
            "second start_graceful MUST NOT overwrite the original sent_at"
        ),
        other => panic!("expected GracefulWait, got {other:?}"),
    }
}

#[test]
fn should_force_kill_is_false_before_timeout_elapses() {
    let timeout = Duration::from_secs(10);
    let c = ShutdownCoordinator::new(timeout);
    let t = Instant::now();
    let mut c = c;
    c.start_graceful(t);
    let halfway = t + Duration::from_secs(5);
    assert!(!c.should_force_kill(halfway));
}

#[test]
fn should_force_kill_is_true_at_or_after_timeout() {
    let timeout = Duration::from_millis(100);
    let mut c = ShutdownCoordinator::new(timeout);
    let t = Instant::now();
    c.start_graceful(t);
    // Use saturating `now`: 200ms past start.
    let after = t + Duration::from_millis(200);
    assert!(
        c.should_force_kill(after),
        "after 2× the timeout, should_force_kill MUST be true"
    );
    // Inclusive ≥ boundary: at exactly the timeout, MUST be true.
    let at_boundary = t + timeout;
    assert!(
        c.should_force_kill(at_boundary),
        "at exact timeout boundary, should_force_kill MUST be true (≥, not strict >)"
    );
}

#[test]
fn should_force_kill_is_false_in_other_phases() {
    let c = ShutdownCoordinator::new(Duration::from_secs(1));
    assert!(
        !c.should_force_kill(Instant::now()),
        "NotStarted phase MUST NOT force-kill"
    );
}

#[test]
fn record_force_kill_transitions_only_from_graceful_wait() {
    let mut c = ShutdownCoordinator::new(Duration::from_millis(10));
    let t = Instant::now();
    c.start_graceful(t);
    c.record_force_kill(t);
    assert!(matches!(c.phase(), ShutdownPhase::ForceKill { .. }));

    // From NotStarted, record_force_kill is a no-op.
    let mut c2 = ShutdownCoordinator::new(Duration::from_millis(10));
    c2.record_force_kill(Instant::now());
    assert_eq!(*c2.phase(), ShutdownPhase::NotStarted);
}

#[test]
fn record_exit_completes_the_phase() {
    let mut c = ShutdownCoordinator::new(Duration::from_millis(10));
    c.start_graceful(Instant::now());
    c.record_exit(ProcessExit::clean());
    assert!(c.is_complete());
    assert!(!c.is_shutting_down());
    match c.phase() {
        ShutdownPhase::Complete { exit } => assert!(exit.is_clean()),
        other => panic!("expected Complete, got {other:?}"),
    }
}

#[test]
fn is_shutting_down_covers_graceful_and_force_kill_phases() {
    let mut c = ShutdownCoordinator::new(Duration::from_millis(10));
    let t = Instant::now();
    assert!(!c.is_shutting_down());
    c.start_graceful(t);
    assert!(c.is_shutting_down());
    c.record_force_kill(t);
    assert!(
        c.is_shutting_down(),
        "ForceKill is still mid-shutdown — is_shutting_down MUST stay true"
    );
    c.record_exit(ProcessExit::clean());
    assert!(!c.is_shutting_down());
}

// ─── HealthCheckScheduler ───────────────────────────────────────────

#[test]
fn health_check_scheduler_is_due_on_first_call() {
    let s = HealthCheckScheduler::new(Duration::from_secs(30), Duration::from_secs(10));
    assert!(
        s.is_due(Instant::now()),
        "fresh scheduler with no last_check MUST be due immediately"
    );
}

#[test]
fn health_check_scheduler_is_due_after_interval_elapses() {
    let mut s = HealthCheckScheduler::new(Duration::from_millis(50), Duration::from_secs(10));
    let t = Instant::now();
    s.record_success(t);
    assert!(!s.is_due(t), "just after a check, MUST NOT be due");
    let later = t + Duration::from_millis(100);
    assert!(s.is_due(later), "after 2×interval, MUST be due again");
}

#[test]
fn record_success_resets_consecutive_failures() {
    let mut s = HealthCheckScheduler::new(Duration::from_secs(30), Duration::from_secs(10));
    let t = Instant::now();
    s.record_failure(t);
    s.record_failure(t);
    assert_eq!(s.consecutive_failures(), 2);
    s.record_success(t);
    assert_eq!(
        s.consecutive_failures(),
        0,
        "record_success MUST reset consecutive_failures to 0"
    );
}

#[test]
fn is_unhealthy_at_or_above_max_consecutive_failures() {
    let mut s = HealthCheckScheduler::new(Duration::from_secs(30), Duration::from_secs(10))
        .with_max_failures(3);
    assert!(!s.is_unhealthy());
    let t = Instant::now();
    s.record_failure(t);
    assert!(!s.is_unhealthy(), "1/3 failures: not yet unhealthy");
    s.record_failure(t);
    assert!(!s.is_unhealthy(), "2/3 failures: not yet unhealthy");
    s.record_failure(t);
    assert!(
        s.is_unhealthy(),
        "3/3 failures: MUST be unhealthy (≥ threshold)"
    );
}

#[test]
fn time_until_next_saturates_at_zero_when_overdue() {
    let mut s = HealthCheckScheduler::new(Duration::from_millis(50), Duration::from_secs(10));
    let t = Instant::now();
    s.record_success(t);
    let way_later = t + Duration::from_secs(60);
    let until = s.time_until_next(way_later);
    assert_eq!(
        until,
        Duration::ZERO,
        "overdue interval MUST saturate at zero, not panic / underflow"
    );
}

#[test]
fn time_until_next_returns_zero_for_fresh_scheduler() {
    let s = HealthCheckScheduler::new(Duration::from_secs(30), Duration::from_secs(10));
    assert_eq!(
        s.time_until_next(Instant::now()),
        Duration::ZERO,
        "scheduler with no last_check MUST report zero time-until-next (immediately due)"
    );
}

// ─── ResourceLimits ─────────────────────────────────────────────────

#[test]
fn resource_limits_default_caps_memory_fds_and_processes() {
    let l = ResourceLimits::default();
    assert_eq!(
        l.memory_bytes,
        Some(512 * 1024 * 1024),
        "default memory_bytes MUST be 512 MiB"
    );
    assert_eq!(l.max_fds, Some(1024));
    assert_eq!(l.max_processes, Some(64));
    assert!(l.cpu_seconds.is_none());
    assert!(l.max_file_size_bytes.is_none());
}

#[test]
fn resource_limits_unlimited_has_no_constraints() {
    let l = ResourceLimits::unlimited();
    assert!(l.memory_bytes.is_none());
    assert!(l.cpu_seconds.is_none());
    assert!(l.max_fds.is_none());
    assert!(l.max_processes.is_none());
    assert!(l.max_file_size_bytes.is_none());
    assert!(!l.has_any_limits());
    assert_eq!(l.active_limit_count(), 0);
}

#[test]
fn resource_limits_default_has_three_active_limits() {
    let l = ResourceLimits::default();
    assert!(l.has_any_limits());
    assert_eq!(
        l.active_limit_count(),
        3,
        "default has 3 active limits (memory + fds + processes)"
    );
}

#[test]
fn merge_strict_takes_lower_value_when_both_set() {
    let a = ResourceLimits {
        memory_bytes: Some(1024),
        cpu_seconds: Some(60),
        max_fds: Some(512),
        max_processes: Some(8),
        max_file_size_bytes: Some(1_000_000),
    };
    let b = ResourceLimits {
        memory_bytes: Some(2048),
        cpu_seconds: Some(30),
        max_fds: Some(256),
        max_processes: Some(16),
        max_file_size_bytes: Some(500_000),
    };
    let merged = a.merge_strict(&b);
    assert_eq!(merged.memory_bytes, Some(1024), "min(1024, 2048)");
    assert_eq!(merged.cpu_seconds, Some(30), "min(60, 30)");
    assert_eq!(merged.max_fds, Some(256), "min(512, 256)");
    assert_eq!(merged.max_processes, Some(8), "min(8, 16)");
    assert_eq!(merged.max_file_size_bytes, Some(500_000));
}

#[test]
fn merge_strict_propagates_some_when_other_is_none() {
    let a = ResourceLimits::unlimited();
    let b = ResourceLimits {
        memory_bytes: Some(2048),
        ..ResourceLimits::unlimited()
    };
    let merged = a.merge_strict(&b);
    assert_eq!(
        merged.memory_bytes,
        Some(2048),
        "None|Some(x) MUST yield Some(x) — the only constraint wins"
    );
}

#[test]
fn merge_strict_yields_none_when_both_unconstrained() {
    let merged = ResourceLimits::unlimited().merge_strict(&ResourceLimits::unlimited());
    assert!(!merged.has_any_limits());
}

// ─── ResourceUsage::violations ─────────────────────────────────────

#[test]
fn violations_empty_when_within_limits() {
    let limits = ResourceLimits::default();
    let usage = ResourceUsage {
        memory_bytes: 100 * 1024 * 1024, // 100 MiB ≤ 512 MiB
        cpu_millis: 0,
        open_fds: 100,     // ≤ 1024
        process_count: 10, // ≤ 64
        file_size_bytes: 0,
    };
    assert_eq!(usage.violations(&limits), [] as [fcp_host::ResourceViolation; 0]);
    assert!(usage.within_limits(&limits));
}

#[test]
fn violations_use_strict_greater_than_limit() {
    let limits = ResourceLimits {
        memory_bytes: Some(1000),
        ..ResourceLimits::unlimited()
    };
    let at_limit = ResourceUsage {
        memory_bytes: 1000,
        ..ResourceUsage::default()
    };
    assert!(
        at_limit.within_limits(&limits),
        "at exactly the limit MUST NOT be a violation (strict >, not ≥)"
    );
    let over = ResourceUsage {
        memory_bytes: 1001,
        ..ResourceUsage::default()
    };
    assert!(!over.within_limits(&limits));
    let v = over.violations(&limits);
    assert_eq!(v.len(), 1);
    assert_eq!(
        v[0],
        ResourceViolation {
            resource: ResourceKind::Memory,
            current: 1001,
            limit: 1000,
        }
    );
}

#[test]
fn violations_emit_one_per_exceeded_resource() {
    let limits = ResourceLimits {
        memory_bytes: Some(100),
        max_fds: Some(50),
        ..ResourceLimits::unlimited()
    };
    let bad = ResourceUsage {
        memory_bytes: 200,
        cpu_millis: 0,
        open_fds: 100,
        process_count: 0,
        file_size_bytes: 0,
    };
    let v = bad.violations(&limits);
    assert_eq!(v.len(), 2, "two limits exceeded MUST yield two violations");
    let kinds: Vec<_> = v.iter().map(|v| v.resource).collect();
    assert!(kinds.contains(&ResourceKind::Memory));
    assert!(kinds.contains(&ResourceKind::FileDescriptors));
}

#[test]
fn violations_skip_unlimited_resources() {
    let usage = ResourceUsage {
        memory_bytes: u64::MAX,
        cpu_millis: u64::MAX,
        open_fds: u64::MAX,
        process_count: u64::MAX,
        file_size_bytes: u64::MAX,
    };
    let v = usage.violations(&ResourceLimits::unlimited());
    assert!(
        v.is_empty(),
        "unlimited limits MUST NOT generate violations even at u64::MAX usage"
    );
}

// ─── ResourceKind Display ──────────────────────────────────────────

#[test]
fn resource_kind_display_uses_snake_case_strings() {
    assert_eq!(format!("{}", ResourceKind::Memory), "memory");
    assert_eq!(format!("{}", ResourceKind::CpuTime), "cpu_time");
    assert_eq!(
        format!("{}", ResourceKind::FileDescriptors),
        "file_descriptors"
    );
    assert_eq!(format!("{}", ResourceKind::Processes), "processes");
    assert_eq!(format!("{}", ResourceKind::FileSize), "file_size");
}

#[test]
fn resource_kind_serde_uses_snake_case_wire_form() {
    let json = serde_json::to_string(&ResourceKind::FileDescriptors).expect("serialize");
    assert_eq!(json, "\"file_descriptors\"");
    let parsed: ResourceKind = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed, ResourceKind::FileDescriptors);
}

#[test]
fn resource_violation_display_includes_keyword_current_and_limit() {
    let v = ResourceViolation {
        resource: ResourceKind::Memory,
        current: 1024,
        limit: 512,
    };
    let s = format!("{v}");
    assert!(s.contains("memory"), "got {s}");
    assert!(s.contains("limit exceeded"), "got {s}");
    assert!(s.contains("1024"), "got {s}");
    assert!(s.contains("512"), "got {s}");
}

// ─── ConnectionTracker ──────────────────────────────────────────────

#[test]
fn connection_tracker_starts_idle() {
    let t = ConnectionTracker::new();
    assert_eq!(t.active_count(), 0);
    assert!(!t.is_draining());
    assert!(!t.is_drained());
}

#[test]
fn try_acquire_succeeds_before_drain() {
    let t = ConnectionTracker::new();
    let g = t.try_acquire().expect("not draining MUST grant slot");
    assert_eq!(t.active_count(), 1);
    drop(g);
    assert_eq!(t.active_count(), 0, "Drop guard MUST decrement");
}

#[test]
fn try_acquire_returns_none_after_start_drain() {
    let t = ConnectionTracker::new();
    t.start_drain();
    assert!(
        t.try_acquire().is_none(),
        "after start_drain, try_acquire MUST return None"
    );
}

#[test]
fn active_count_tracks_multiple_concurrent_guards() {
    let t = ConnectionTracker::new();
    let g1 = t.try_acquire().expect("first");
    let g2 = t.try_acquire().expect("second");
    let g3 = t.try_acquire().expect("third");
    assert_eq!(t.active_count(), 3);
    drop(g2); // drop middle guard
    assert_eq!(t.active_count(), 2);
    drop(g1);
    drop(g3);
    assert_eq!(t.active_count(), 0);
}

#[test]
fn is_drained_requires_both_draining_and_zero_active() {
    let t = ConnectionTracker::new();
    let guard = t.try_acquire().expect("acquire");
    assert!(!t.is_drained(), "not draining: not drained");
    t.start_drain();
    assert!(
        !t.is_drained(),
        "draining + active>0: not yet drained — MUST wait for active to clear"
    );
    drop(guard);
    assert!(t.is_drained(), "draining + active=0: MUST be drained");
}
