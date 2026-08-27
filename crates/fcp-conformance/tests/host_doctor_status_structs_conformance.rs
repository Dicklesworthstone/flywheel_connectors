//! `fcp_host::doctor` status struct wire-format conformance.
//!
//! `host_doctor_enums_conformance.rs` already pinned the 4 enums.
//! This file pins the 7 status / result structs that compose the
//! `DoctorReport` body — every operator self-check JSON consumer
//! depends on these field names + skip-when-None semantics.
//!
//! Properties pinned (NORMATIVE):
//!
//! 1. **`CheckpointStatus` / `RevocationStatus` / `AuditStatus`**
//!    each carry a `freshness: FreshnessLevel` field; default uses
//!    `FreshnessLevel::default == Fresh`.
//! 2. **`TransportPolicyStatus`** carries 3 booleans
//!    (`allow_lan`/`allow_derp`/`allow_funnel`); default is all-false.
//! 3. **`StoreCoverageStatus::store_healthy`** boolean; default false.
//! 4. **`DegradedModeStatus::is_degraded`** boolean; default false.
//! 5. **`CheckResult`** — full 7-field contract:
//!    - `name` (required)
//!    - `connector_id` (optional, skip-when-None, default-when-absent)
//!    - `code` (optional, skip-when-None, default-when-absent)
//!    - `status` (required, embeds `CheckStatus` UPPERCASE)
//!    - `severity` (required, embeds `CheckSeverity` lowercase)
//!    - `message` (required)
//!    - `repair_hints` (Vec<String>, skip-when-empty,
//!      default-when-absent)
//! 6. **Each struct round-trips through serde without data loss.**

use fcp_host::{
    AuditStatus, CheckResult, CheckSeverity, CheckStatus, CheckpointStatus, DegradedModeStatus,
    FreshnessLevel, RevocationStatus, StoreCoverageStatus, TransportPolicyStatus,
};
use fcp_prelude::ZoneId;
use serde_json::json;

// ─── CheckpointStatus ─────────────────────────────────────────────

#[test]
fn checkpoint_status_default_freshness_is_fresh() {
    let s = CheckpointStatus::default();
    assert_eq!(s.freshness, FreshnessLevel::Fresh);
}

#[test]
fn checkpoint_status_serde_roundtrip_with_each_freshness() {
    for f in [
        FreshnessLevel::Fresh,
        FreshnessLevel::Stale,
        FreshnessLevel::TooStale,
        FreshnessLevel::Missing,
    ] {
        let s = CheckpointStatus { freshness: f };
        let json_str = serde_json::to_string(&s).expect("serialize");
        let parsed: CheckpointStatus = serde_json::from_str(&json_str).expect("deserialize");
        assert_eq!(parsed.freshness, f);
    }
}

#[test]
fn checkpoint_status_serializes_freshness_as_snake_case() {
    let s = CheckpointStatus {
        freshness: FreshnessLevel::TooStale,
    };
    let v = serde_json::to_value(&s).expect("serialize");
    assert_eq!(
        v["freshness"], "too_stale",
        "freshness MUST embed as snake_case wire form"
    );
}

// ─── RevocationStatus ─────────────────────────────────────────────

#[test]
fn revocation_status_default_freshness_is_fresh() {
    assert_eq!(RevocationStatus::default().freshness, FreshnessLevel::Fresh);
}

#[test]
fn revocation_status_serde_roundtrip() {
    let s = RevocationStatus {
        freshness: FreshnessLevel::Stale,
    };
    let json_str = serde_json::to_string(&s).expect("serialize");
    let parsed: RevocationStatus = serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(parsed.freshness, FreshnessLevel::Stale);
}

// ─── AuditStatus ───────────────────────────────────────────────────

#[test]
fn audit_status_default_freshness_is_fresh() {
    assert_eq!(AuditStatus::default().freshness, FreshnessLevel::Fresh);
}

#[test]
fn audit_status_serde_roundtrip() {
    let s = AuditStatus {
        freshness: FreshnessLevel::Missing,
    };
    let json_str = serde_json::to_string(&s).expect("serialize");
    let parsed: AuditStatus = serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(parsed.freshness, FreshnessLevel::Missing);
}

// ─── TransportPolicyStatus ────────────────────────────────────────

#[test]
fn transport_policy_status_default_is_all_false() {
    let s = TransportPolicyStatus::default();
    assert!(
        !s.allow_lan,
        "default allow_lan MUST be false (fail-closed)"
    );
    assert!(!s.allow_derp);
    assert!(!s.allow_funnel);
}

#[test]
fn transport_policy_status_serde_roundtrip_preserves_three_booleans() {
    let s = TransportPolicyStatus {
        allow_lan: true,
        allow_derp: false,
        allow_funnel: true,
    };
    let json_str = serde_json::to_string(&s).expect("serialize");
    let parsed: TransportPolicyStatus = serde_json::from_str(&json_str).expect("deserialize");
    assert!(parsed.allow_lan);
    assert!(!parsed.allow_derp);
    assert!(parsed.allow_funnel);
}

#[test]
fn transport_policy_status_serializes_with_documented_field_names() {
    let s = TransportPolicyStatus {
        allow_lan: true,
        allow_derp: true,
        allow_funnel: false,
    };
    let v = serde_json::to_value(&s).expect("serialize");
    assert_eq!(v["allow_lan"], true);
    assert_eq!(v["allow_derp"], true);
    assert_eq!(v["allow_funnel"], false);
}

// ─── StoreCoverageStatus ─────────────────────────────────────────

#[test]
fn store_coverage_status_default_is_unhealthy() {
    let s = StoreCoverageStatus::default();
    assert!(
        !s.store_healthy,
        "default store_healthy MUST be false (fail-safe — assume not healthy until proven)"
    );
}

#[test]
fn store_coverage_status_serde_roundtrip() {
    let s = StoreCoverageStatus {
        store_healthy: true,
    };
    let json_str = serde_json::to_string(&s).expect("serialize");
    let parsed: StoreCoverageStatus = serde_json::from_str(&json_str).expect("deserialize");
    assert!(parsed.store_healthy);
}

// ─── DegradedModeStatus ──────────────────────────────────────────

#[test]
fn degraded_mode_status_default_is_not_degraded() {
    let s = DegradedModeStatus::default();
    assert!(!s.is_degraded, "default is_degraded MUST be false");
}

#[test]
fn degraded_mode_status_serde_roundtrip() {
    let s = DegradedModeStatus { is_degraded: true };
    let json_str = serde_json::to_string(&s).expect("serialize");
    let parsed: DegradedModeStatus = serde_json::from_str(&json_str).expect("deserialize");
    assert!(parsed.is_degraded);
}

// ─── CheckResult full 7-field contract ───────────────────────────

#[test]
fn check_result_minimal_construction_with_required_fields() {
    let r = CheckResult {
        name: "auth_check".into(),
        connector_id: None,
        code: None,
        status: CheckStatus::Ok,
        severity: CheckSeverity::Info,
        message: "passed".into(),
        repair_hints: vec![],
    };
    let json_str = serde_json::to_string(&r).expect("serialize");
    let parsed: CheckResult = serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(parsed.name, "auth_check");
    assert!(parsed.connector_id.is_none());
    assert!(parsed.code.is_none());
    assert_eq!(parsed.status, CheckStatus::Ok);
    assert_eq!(parsed.severity, CheckSeverity::Info);
    assert_eq!(parsed.message, "passed");
    assert_eq!(parsed.repair_hints, [] as [std::string::String; 0]);
}

#[test]
fn check_result_omits_optional_fields_when_none_or_empty() {
    let r = CheckResult {
        name: "noop".into(),
        connector_id: None,
        code: None,
        status: CheckStatus::Ok,
        severity: CheckSeverity::Info,
        message: "ok".into(),
        repair_hints: vec![],
    };
    let s = serde_json::to_string(&r).expect("serialize");
    assert!(
        !s.contains("connector_id"),
        "connector_id=None MUST be omitted; got {s}"
    );
    assert!(
        !s.contains("\"code\""),
        "code=None MUST be omitted; got {s}"
    );
    assert!(
        !s.contains("repair_hints"),
        "empty repair_hints MUST be omitted; got {s}"
    );
}

#[test]
fn check_result_serializes_status_and_severity_in_their_documented_case() {
    // status uses CheckStatus UPPERCASE; severity uses lowercase.
    let r = CheckResult {
        name: "x".into(),
        connector_id: None,
        code: None,
        status: CheckStatus::Warn,
        severity: CheckSeverity::Warning,
        message: "warning".into(),
        repair_hints: vec![],
    };
    let v = serde_json::to_value(&r).expect("serialize");
    assert_eq!(
        v["status"], "WARN",
        "status MUST embed as UPPERCASE (CheckStatus rename)"
    );
    assert_eq!(
        v["severity"], "warning",
        "severity MUST embed as lowercase (CheckSeverity rename — NOT 'warn')"
    );
}

#[test]
fn check_result_with_all_optional_fields_populated_round_trips() {
    let r = CheckResult {
        name: "policy_check".into(),
        connector_id: Some("github:saas:v1".parse().expect("connector id")),
        code: Some("POLICY_DENIED".into()),
        status: CheckStatus::Fail,
        severity: CheckSeverity::Critical,
        message: "policy denied".into(),
        repair_hints: vec!["check capability grant".into(), "verify zone".into()],
    };
    let json_str = serde_json::to_string(&r).expect("serialize");
    let parsed: CheckResult = serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(parsed.name, "policy_check");
    assert!(parsed.connector_id.is_some());
    assert_eq!(parsed.code.as_deref(), Some("POLICY_DENIED"));
    assert_eq!(parsed.status, CheckStatus::Fail);
    assert_eq!(parsed.severity, CheckSeverity::Critical);
    assert_eq!(parsed.repair_hints.len(), 2);
}

#[test]
fn check_result_default_when_optionals_absent_in_json() {
    // Per `serde(default)`, optional fields and Vec field MUST
    // default-on-absence so older client JSON still parses.
    let json_str = json!({
        "name": "minimal",
        "status": "OK",
        "severity": "info",
        "message": "passed"
    })
    .to_string();
    let parsed: CheckResult =
        serde_json::from_str(&json_str).expect("deserialize minimal CheckResult");
    assert!(parsed.connector_id.is_none());
    assert!(parsed.code.is_none());
    assert_eq!(parsed.repair_hints, [] as [std::string::String; 0]);
}

#[test]
fn check_result_repair_hints_preserve_order() {
    let r = CheckResult {
        name: "x".into(),
        connector_id: None,
        code: None,
        status: CheckStatus::Warn,
        severity: CheckSeverity::Warning,
        message: "x".into(),
        repair_hints: vec!["first".into(), "second".into(), "third".into()],
    };
    let json_str = serde_json::to_string(&r).expect("serialize");
    let parsed: CheckResult = serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(
        parsed.repair_hints,
        vec!["first", "second", "third"],
        "repair_hints MUST preserve order — operators read smallest-first"
    );
}

// ─── Cross-struct sanity: defaults match enum defaults ───────────

#[test]
fn freshness_status_structs_default_freshness_aligns_with_freshness_level_default() {
    // CheckpointStatus / RevocationStatus / AuditStatus all default
    // their freshness to FreshnessLevel::default() — which is Fresh.
    let cp = CheckpointStatus::default();
    let rv = RevocationStatus::default();
    let au = AuditStatus::default();
    assert_eq!(cp.freshness, FreshnessLevel::default());
    assert_eq!(rv.freshness, FreshnessLevel::default());
    assert_eq!(au.freshness, FreshnessLevel::default());
}

#[test]
fn zone_id_field_on_doctor_payloads_round_trips_canonical_form() {
    // ZoneId serde is the same canonical-id wire format the rest of
    // FCP uses. Pin via a direct ZoneId roundtrip — the doctor
    // structs that carry zone_id (DoctorReport) inherit this contract.
    let z = ZoneId::work();
    let json_str = serde_json::to_string(&z).expect("serialize");
    let parsed: ZoneId = serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(parsed, z);
}
