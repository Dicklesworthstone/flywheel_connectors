//! No-mock integration tests for fcp-conformance.
//!
//! These tests exercise cross-module interactions without mocking frameworks,
//! verifying that compliance, schemas, interop, reqcheck, and vector modules
//! compose correctly across boundaries.

use base64::Engine;
use fcp_conformance::compliance::{
    CheckStatus, ComplianceFinding, ComplianceReport, DynamicCompliance, StaticCompliance,
};
use fcp_conformance::interop::{InteropTestSummary, TestFailure};
use fcp_conformance::reqcheck::{
    RequirementEntry, RequirementsIndexParser, ValidationError, ValidationReport, ValidationWarning,
};
use fcp_conformance::schemas::{self, ForensicsRuleDiagnostic, ForensicsValidationError};
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_manifest::{Base64Bytes, ConnectorManifest};
use fcp_prelude::{ObjectIdKey, ZoneId};
use fcp_raptorq::RaptorQConfig;
use fcp_registry::{
    ConnectorBinaryObject, ConnectorBinarySymbolSet, ConnectorBundle, ConnectorManifestObject,
    ConnectorTarget, RegistryError, RegistryTrustPolicy, RegistryVerifier,
};
use fcp_store::{
    MemoryObjectStore, MemoryObjectStoreConfig, MemorySymbolStore, MemorySymbolStoreConfig,
    ObjectStore,
};
use serde_json::json;
use sha2::{Digest, Sha256};

// ═══════════════════════════════════════════════════════════════
// 1. CheckStatus + ComplianceFinding construction
// ═══════════════════════════════════════════════════════════════

#[test]
fn check_status_serde_roundtrip() {
    for status in [CheckStatus::Pass, CheckStatus::Fail, CheckStatus::Skipped] {
        let json = serde_json::to_string(&status).unwrap();
        let back: CheckStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, back);
    }
}

#[test]
fn check_status_snake_case_serialization() {
    assert_eq!(
        serde_json::to_string(&CheckStatus::Pass).unwrap(),
        "\"pass\""
    );
    assert_eq!(
        serde_json::to_string(&CheckStatus::Fail).unwrap(),
        "\"fail\""
    );
    assert_eq!(
        serde_json::to_string(&CheckStatus::Skipped).unwrap(),
        "\"skipped\""
    );
}

#[test]
fn compliance_finding_serde_roundtrip() {
    let finding = ComplianceFinding {
        check: "manifest.parse".into(),
        status: CheckStatus::Pass,
        message: "manifest parsed ok".into(),
    };
    let json = serde_json::to_string(&finding).unwrap();
    let back: ComplianceFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(back.check, "manifest.parse");
    assert_eq!(back.status, CheckStatus::Pass);
    assert_eq!(back.message, "manifest parsed ok");
}

// ═══════════════════════════════════════════════════════════════
// 2. StaticCompliance manifest validation
// ═══════════════════════════════════════════════════════════════

#[test]
fn static_compliance_invalid_manifest() {
    let result = StaticCompliance::run_manifest("not valid toml {{{");
    assert!(!result.passed);
    assert!(!result.findings.is_empty());
    assert_eq!(result.findings[0].status, CheckStatus::Fail);
    assert_eq!(result.findings[0].check, "manifest.parse_validate");
}

#[test]
fn static_compliance_empty_manifest() {
    let result = StaticCompliance::run_manifest("");
    assert!(!result.passed);
    assert_eq!(result.findings[0].status, CheckStatus::Fail);
}

#[test]
fn static_compliance_serde_roundtrip() {
    let compliance = StaticCompliance {
        passed: true,
        findings: vec![ComplianceFinding {
            check: "test".into(),
            status: CheckStatus::Pass,
            message: "ok".into(),
        }],
    };
    let json = serde_json::to_string(&compliance).unwrap();
    let back: StaticCompliance = serde_json::from_str(&json).unwrap();
    assert!(back.passed);
    assert_eq!(back.findings.len(), 1);
}

// ═══════════════════════════════════════════════════════════════
// 3. ComplianceReport aggregation
// ═══════════════════════════════════════════════════════════════

#[test]
fn compliance_report_passes_when_both_pass() {
    let report = ComplianceReport {
        static_checks: StaticCompliance {
            passed: true,
            findings: vec![],
        },
        dynamic_checks: DynamicCompliance {
            passed: true,
            findings: vec![],
        },
    };
    assert!(report.passed());
}

#[test]
fn compliance_report_fails_when_static_fails() {
    let report = ComplianceReport {
        static_checks: StaticCompliance {
            passed: false,
            findings: vec![ComplianceFinding {
                check: "manifest.parse_validate".into(),
                status: CheckStatus::Fail,
                message: "bad manifest".into(),
            }],
        },
        dynamic_checks: DynamicCompliance {
            passed: true,
            findings: vec![],
        },
    };
    assert!(!report.passed());
}

#[test]
fn compliance_report_fails_when_dynamic_fails() {
    let report = ComplianceReport {
        static_checks: StaticCompliance {
            passed: true,
            findings: vec![],
        },
        dynamic_checks: DynamicCompliance {
            passed: false,
            findings: vec![ComplianceFinding {
                check: "configure".into(),
                status: CheckStatus::Fail,
                message: "configure failed".into(),
            }],
        },
    };
    assert!(!report.passed());
}

#[test]
fn compliance_report_serde_roundtrip() {
    let report = ComplianceReport {
        static_checks: StaticCompliance {
            passed: true,
            findings: vec![ComplianceFinding {
                check: "a".into(),
                status: CheckStatus::Pass,
                message: "ok".into(),
            }],
        },
        dynamic_checks: DynamicCompliance {
            passed: false,
            findings: vec![ComplianceFinding {
                check: "b".into(),
                status: CheckStatus::Fail,
                message: "err".into(),
            }],
        },
    };
    let json = serde_json::to_string(&report).unwrap();
    let back: ComplianceReport = serde_json::from_str(&json).unwrap();
    assert!(!back.passed());
    assert!(back.static_checks.passed);
    assert!(!back.dynamic_checks.passed);
}

#[test]
fn dynamic_compliance_skipped() {
    let dynamic = DynamicCompliance::skipped("no config available");
    assert!(!dynamic.passed);
    assert_eq!(dynamic.findings.len(), 1);
    assert_eq!(dynamic.findings[0].status, CheckStatus::Skipped);
    assert_eq!(dynamic.findings[0].check, "dynamic.skip");
}

// ═══════════════════════════════════════════════════════════════
// 4. InteropTestSummary cross-category merge
// ═══════════════════════════════════════════════════════════════

#[test]
fn interop_summary_merge_multiple_categories() {
    let mut session = InteropTestSummary {
        total: 5,
        passed: 5,
        failed: 0,
        failures: vec![],
    };
    let fcps = InteropTestSummary {
        total: 3,
        passed: 2,
        failed: 1,
        failures: vec![TestFailure {
            name: "mac_suite1".into(),
            category: "fcps".into(),
            message: "MAC mismatch".into(),
        }],
    };
    let framing = InteropTestSummary {
        total: 4,
        passed: 3,
        failed: 1,
        failures: vec![TestFailure {
            name: "frame_order".into(),
            category: "fcpc".into(),
            message: "out of order".into(),
        }],
    };

    session.merge(fcps);
    session.merge(framing);

    assert_eq!(session.total, 12);
    assert_eq!(session.passed, 10);
    assert_eq!(session.failed, 2);
    assert!(!session.all_passed());
    assert_eq!(session.failures.len(), 2);
    assert_eq!(session.failures[0].category, "fcps");
    assert_eq!(session.failures[1].category, "fcpc");
}

#[test]
fn interop_summary_all_passed_zero_total() {
    let summary = InteropTestSummary::default();
    assert!(summary.all_passed());
    assert_eq!(summary.total, 0);
}

#[test]
fn interop_summary_clone_preserves_failures() {
    let summary = InteropTestSummary {
        total: 2,
        passed: 1,
        failed: 1,
        failures: vec![TestFailure {
            name: "test1".into(),
            category: "session".into(),
            message: "transcript mismatch".into(),
        }],
    };
    #[allow(clippy::redundant_clone)]
    let cloned = summary.clone();
    assert_eq!(cloned.total, 2);
    assert_eq!(cloned.failures.len(), 1);
    assert_eq!(cloned.failures[0].name, "test1");
}

// ═══════════════════════════════════════════════════════════════
// 5. Forensics validation + error diagnostics
// ═══════════════════════════════════════════════════════════════

fn valid_forensics_entry() -> serde_json::Value {
    json!({
        "schema_version": "asupersync-forensics/v1",
        "run_id": "run-001",
        "scenario_id": "scen-1",
        "trace_id": "trace-1",
        "correlation_id": "corr-1",
        "connector": "test-connector",
        "zone": "z:test",
        "operation": "invoke",
        "attempt": 1,
        "timeout_budget_ms": 5000,
        "cancellation_reason": null,
        "queue_depth": null,
        "decode_budget": null,
        "outcome": "pass",
        "elapsed_ms": 42
    })
}

#[test]
fn forensics_valid_entry_passes() {
    let entry = valid_forensics_entry();
    let result = schemas::validate_asupersync_forensics_entry(&entry, Some("run-001"));
    assert!(result.is_ok());
}

#[test]
fn forensics_valid_entry_without_run_id_check() {
    let entry = valid_forensics_entry();
    let result = schemas::validate_asupersync_forensics_entry(&entry, None);
    assert!(result.is_ok());
}

#[test]
fn forensics_wrong_run_id_fails() {
    let entry = valid_forensics_entry();
    let result = schemas::validate_asupersync_forensics_entry(&entry, Some("run-999"));
    match result {
        Err(ForensicsValidationError::RuleViolation { diagnostic, .. }) => {
            assert_eq!(diagnostic.rule_id, "asupersync.forensics.v1.run_id.match");
            assert_eq!(diagnostic.field, "run_id");
            assert!(diagnostic.message.contains("run-999"));
        }
        other => panic!("expected RuleViolation, got {other:?}"),
    }
}

#[test]
fn forensics_missing_schema_version() {
    let mut entry = valid_forensics_entry();
    entry.as_object_mut().unwrap().remove("schema_version");
    let result = schemas::validate_asupersync_forensics_entry(&entry, None);
    match result {
        Err(ForensicsValidationError::RuleViolation { diagnostic, .. }) => {
            assert_eq!(diagnostic.rule_id, "asupersync.forensics.v1.schema_version");
            assert_eq!(diagnostic.field, "schema_version");
        }
        other => panic!("expected RuleViolation, got {other:?}"),
    }
}

#[test]
fn forensics_wrong_schema_version() {
    let mut entry = valid_forensics_entry();
    entry["schema_version"] = json!("wrong/v2");
    let result = schemas::validate_asupersync_forensics_entry(&entry, None);
    match result {
        Err(ForensicsValidationError::RuleViolation { diagnostic, .. }) => {
            assert_eq!(diagnostic.rule_id, "asupersync.forensics.v1.schema_version");
            assert!(diagnostic.message.contains("wrong/v2"));
        }
        other => panic!("expected RuleViolation, got {other:?}"),
    }
}

#[test]
fn forensics_attempt_zero_fails() {
    let mut entry = valid_forensics_entry();
    entry["attempt"] = json!(0);
    let result = schemas::validate_asupersync_forensics_entry(&entry, None);
    match result {
        Err(ForensicsValidationError::RuleViolation { diagnostic, .. }) => {
            assert_eq!(diagnostic.rule_id, "asupersync.forensics.v1.attempt");
            assert!(diagnostic.message.contains("greater than"));
        }
        other => panic!("expected RuleViolation, got {other:?}"),
    }
}

#[test]
fn forensics_invalid_outcome() {
    let mut entry = valid_forensics_entry();
    entry["outcome"] = json!("unknown");
    let result = schemas::validate_asupersync_forensics_entry(&entry, None);
    match result {
        Err(ForensicsValidationError::RuleViolation { diagnostic, .. }) => {
            assert_eq!(diagnostic.rule_id, "asupersync.forensics.v1.outcome");
            assert!(diagnostic.message.contains("unknown"));
        }
        other => panic!("expected RuleViolation, got {other:?}"),
    }
}

#[test]
fn forensics_not_object_fails() {
    let result = schemas::validate_asupersync_forensics_entry(&json!([1, 2, 3]), None);
    match result {
        Err(ForensicsValidationError::RuleViolation { diagnostic, .. }) => {
            assert_eq!(diagnostic.rule_id, "asupersync.forensics.v1.record.object");
        }
        other => panic!("expected RuleViolation, got {other:?}"),
    }
}

#[test]
fn forensics_missing_identity_field_fails() {
    let mut entry = valid_forensics_entry();
    entry.as_object_mut().unwrap().remove("connector");
    let result = schemas::validate_asupersync_forensics_entry(&entry, None);
    match result {
        Err(ForensicsValidationError::RuleViolation { diagnostic, .. }) => {
            assert_eq!(diagnostic.rule_id, "asupersync.forensics.v1.connector");
            assert_eq!(diagnostic.field, "connector");
        }
        other => panic!("expected RuleViolation, got {other:?}"),
    }
}

#[test]
fn forensics_empty_string_field_fails() {
    let mut entry = valid_forensics_entry();
    entry["zone"] = json!("  ");
    let result = schemas::validate_asupersync_forensics_entry(&entry, None);
    match result {
        Err(ForensicsValidationError::RuleViolation { diagnostic, .. }) => {
            assert_eq!(diagnostic.rule_id, "asupersync.forensics.v1.zone");
            assert!(diagnostic.message.contains("non-empty"));
        }
        other => panic!("expected RuleViolation, got {other:?}"),
    }
}

// ═══════════════════════════════════════════════════════════════
// 6. Forensics JSONL multi-line validation
// ═══════════════════════════════════════════════════════════════

#[test]
fn forensics_jsonl_valid_multi_line() {
    let line1 = serde_json::to_string(&valid_forensics_entry()).unwrap();
    let mut entry2 = valid_forensics_entry();
    entry2["attempt"] = json!(2);
    entry2["outcome"] = json!("fail");
    let line2 = serde_json::to_string(&entry2).unwrap();

    let input = format!("{line1}\n{line2}\n");
    let result = schemas::validate_asupersync_forensics_jsonl(&input, Some("run-001"));
    assert!(result.is_ok());
}

#[test]
fn forensics_jsonl_skips_empty_lines() {
    let line = serde_json::to_string(&valid_forensics_entry()).unwrap();
    let input = format!("\n{line}\n\n");
    let result = schemas::validate_asupersync_forensics_jsonl(&input, None);
    assert!(result.is_ok());
}

#[test]
fn forensics_jsonl_invalid_json_line() {
    let input = "not valid json\n";
    let result = schemas::validate_asupersync_forensics_jsonl(input, None);
    match result {
        Err(ForensicsValidationError::InvalidJsonLine { line, message }) => {
            assert_eq!(line, 1);
            assert_ne!(message, "");
        }
        other => panic!("expected InvalidJsonLine, got {other:?}"),
    }
}

#[test]
fn forensics_jsonl_second_line_fails() {
    let line1 = serde_json::to_string(&valid_forensics_entry()).unwrap();
    let input = format!("{line1}\n{{\"bad\": true}}\n");
    let result = schemas::validate_asupersync_forensics_jsonl(&input, None);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.line(), Some(2));
}

// ═══════════════════════════════════════════════════════════════
// 7. ForensicsValidationError + ForensicsRuleDiagnostic
// ═══════════════════════════════════════════════════════════════

#[test]
fn forensics_rule_diagnostic_display() {
    let diag = ForensicsRuleDiagnostic {
        rule_id: "asupersync.forensics.v1.run_id",
        field: "run_id",
        message: "missing required field".into(),
    };
    let display = format!("{diag}");
    assert!(display.contains("asupersync.forensics.v1.run_id"));
    assert!(display.contains("[run_id]"));
    assert!(display.contains("missing required field"));
}

#[test]
fn forensics_validation_error_display_with_line() {
    let err = ForensicsValidationError::RuleViolation {
        line: Some(42),
        diagnostic: ForensicsRuleDiagnostic {
            rule_id: "asupersync.forensics.v1.outcome",
            field: "outcome",
            message: "invalid value".into(),
        },
    };
    let display = format!("{err}");
    assert!(display.contains("line 42"));
    assert!(display.contains("outcome"));
}

#[test]
fn forensics_validation_error_display_without_line() {
    let err = ForensicsValidationError::RuleViolation {
        line: None,
        diagnostic: ForensicsRuleDiagnostic {
            rule_id: "asupersync.forensics.v1.run_id",
            field: "run_id",
            message: "missing".into(),
        },
    };
    let display = format!("{err}");
    assert!(!display.contains("line"));
    assert!(display.contains("run_id"));
}

#[test]
fn forensics_validation_error_invalid_json_line_display() {
    let err = ForensicsValidationError::InvalidJsonLine {
        line: 5,
        message: "unexpected EOF".into(),
    };
    let display = format!("{err}");
    assert!(display.contains("line 5"));
    assert!(display.contains("invalid JSON"));
    assert!(display.contains("unexpected EOF"));
}

#[test]
fn forensics_validation_error_rule_id_accessor() {
    let err = ForensicsValidationError::RuleViolation {
        line: None,
        diagnostic: ForensicsRuleDiagnostic {
            rule_id: "asupersync.forensics.v1.zone",
            field: "zone",
            message: "bad".into(),
        },
    };
    assert_eq!(err.rule_id(), Some("asupersync.forensics.v1.zone"));

    let json_err = ForensicsValidationError::InvalidJsonLine {
        line: 1,
        message: "bad json".into(),
    };
    assert_eq!(json_err.rule_id(), None);
}

#[test]
fn forensics_validation_error_line_accessor() {
    let err_with_line = ForensicsValidationError::RuleViolation {
        line: Some(10),
        diagnostic: ForensicsRuleDiagnostic {
            rule_id: "test",
            field: "f",
            message: "m".into(),
        },
    };
    assert_eq!(err_with_line.line(), Some(10));

    let err_no_line = ForensicsValidationError::RuleViolation {
        line: None,
        diagnostic: ForensicsRuleDiagnostic {
            rule_id: "test",
            field: "f",
            message: "m".into(),
        },
    };
    assert_eq!(err_no_line.line(), None);
}

#[test]
fn forensics_validation_error_equality() {
    let a = ForensicsValidationError::RuleViolation {
        line: Some(1),
        diagnostic: ForensicsRuleDiagnostic {
            rule_id: "rule.a",
            field: "field_a",
            message: "msg".into(),
        },
    };
    let b = ForensicsValidationError::RuleViolation {
        line: Some(1),
        diagnostic: ForensicsRuleDiagnostic {
            rule_id: "rule.a",
            field: "field_a",
            message: "msg".into(),
        },
    };
    assert_eq!(a, b);
}

// ═══════════════════════════════════════════════════════════════
// 8. Schema constants availability
// ═══════════════════════════════════════════════════════════════

#[test]
fn schema_constants_are_non_empty() {
    assert_ne!(schemas::FZPF_V01_SCHEMA, "");
    assert_ne!(schemas::E2E_LOG_V1_SCHEMA, "");
    assert_ne!(schemas::E2E_LOG_V2_SCHEMA, "");
    assert_ne!(schemas::POLICY_BUNDLE_V1_SCHEMA, "");
    assert_ne!(schemas::RELEASE_MANIFEST_V1_SCHEMA, "");
    assert_ne!(schemas::ROLLOUT_POLICY_V1_SCHEMA, "");
    assert_ne!(schemas::TRACE_V1_SCHEMA, "");
    assert_ne!(schemas::CAPABILITY_USAGE_V1_SCHEMA, "");
    assert_ne!(schemas::SUPPLY_CHAIN_ATTESTATION_V1_SCHEMA, "");
    assert_ne!(schemas::SBOM_V1_SCHEMA, "");
    assert_ne!(schemas::ASUPERSYNC_FORENSICS_V1_SCHEMA, "");
}

#[test]
fn schema_constants_are_valid_json() {
    let schemas = [
        ("FZPF_V01", schemas::FZPF_V01_SCHEMA),
        ("E2E_LOG_V1", schemas::E2E_LOG_V1_SCHEMA),
        ("E2E_LOG_V2", schemas::E2E_LOG_V2_SCHEMA),
        ("POLICY_BUNDLE_V1", schemas::POLICY_BUNDLE_V1_SCHEMA),
        ("RELEASE_MANIFEST_V1", schemas::RELEASE_MANIFEST_V1_SCHEMA),
        ("ROLLOUT_POLICY_V1", schemas::ROLLOUT_POLICY_V1_SCHEMA),
        ("TRACE_V1", schemas::TRACE_V1_SCHEMA),
        ("CAPABILITY_USAGE_V1", schemas::CAPABILITY_USAGE_V1_SCHEMA),
        (
            "SUPPLY_CHAIN_V1",
            schemas::SUPPLY_CHAIN_ATTESTATION_V1_SCHEMA,
        ),
        ("SBOM_V1", schemas::SBOM_V1_SCHEMA),
        (
            "ASUPERSYNC_FORENSICS_V1",
            schemas::ASUPERSYNC_FORENSICS_V1_SCHEMA,
        ),
    ];

    for (name, schema) in schemas {
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(schema);
        assert!(
            parsed.is_ok(),
            "{name} schema is not valid JSON: {}",
            parsed.unwrap_err()
        );
    }
}

#[test]
fn asupersync_forensics_version_marker() {
    assert_eq!(schemas::ASUPERSYNC_FORENSICS_V1, "asupersync-forensics/v1");
}

// ═══════════════════════════════════════════════════════════════
// 9. Reqcheck types + parser
// ═══════════════════════════════════════════════════════════════

#[test]
fn requirement_entry_serde_roundtrip() {
    let entry = RequirementEntry {
        section: "§1: Introduction".into(),
        line_number: 42,
        owners: vec!["fc-1n78.21".into(), "bd-3frf".into()],
        tests: vec!["fc-1n78.21.1".into()],
        notes: Some("golden vectors".into()),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: RequirementEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back.section, "§1: Introduction");
    assert_eq!(back.owners.len(), 2);
    assert_eq!(back.tests.len(), 1);
    assert_eq!(back.notes.as_deref(), Some("golden vectors"));
}

#[test]
fn validation_error_serde_roundtrip() {
    let err = ValidationError {
        section: "§3: Protocol".into(),
        line_number: Some(100),
        error_type: "missing_bead".into(),
        value: "fc-nonexist".into(),
        message: "bead not found".into(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: ValidationError = serde_json::from_str(&json).unwrap();
    assert_eq!(back.section, "§3: Protocol");
    assert_eq!(back.error_type, "missing_bead");
}

#[test]
fn validation_warning_serde_roundtrip() {
    let warn = ValidationWarning {
        section: "§2: Overview".into(),
        line_number: Some(50),
        warning_type: "empty_owners".into(),
        message: "no owners specified".into(),
    };
    let json = serde_json::to_string(&warn).unwrap();
    let back: ValidationWarning = serde_json::from_str(&json).unwrap();
    assert_eq!(back.warning_type, "empty_owners");
}

#[test]
fn validation_report_is_valid_when_no_errors() {
    let report = ValidationReport {
        total_entries: 10,
        unique_beads: 5,
        missing_beads: vec![],
        errors: vec![],
        warnings: vec![],
        entries: None,
    };
    assert!(report.is_valid());
}

#[test]
fn validation_report_is_invalid_when_errors_present() {
    let report = ValidationReport {
        total_entries: 10,
        unique_beads: 5,
        missing_beads: vec!["fc-missing".into()],
        errors: vec![ValidationError {
            section: "§1".into(),
            line_number: Some(10),
            error_type: "missing_bead".into(),
            value: "fc-missing".into(),
            message: "not found".into(),
        }],
        warnings: vec![],
        entries: None,
    };
    assert!(!report.is_valid());
}

#[test]
fn validation_report_serde_none_entries() {
    let report = ValidationReport {
        total_entries: 0,
        unique_beads: 0,
        missing_beads: vec![],
        errors: vec![],
        warnings: vec![],
        entries: None,
    };
    let json = serde_json::to_string(&report).unwrap();
    // entries field should serialize as null or be omitted depending on serde config
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    let entries = parsed.get("entries");
    assert!(
        entries.is_none() || entries == Some(&serde_json::Value::Null),
        "entries should be null or absent when None"
    );
}

#[test]
fn validation_report_serde_includes_some_entries() {
    let report = ValidationReport {
        total_entries: 1,
        unique_beads: 1,
        missing_beads: vec![],
        errors: vec![],
        warnings: vec![],
        entries: Some(vec![RequirementEntry {
            section: "§1".into(),
            line_number: 1,
            owners: vec!["fc-abc".into()],
            tests: vec![],
            notes: None,
        }]),
    };
    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains("entries"));
}

#[test]
fn requirements_parser_default() {
    let parser = RequirementsIndexParser::new();
    let debug = format!("{parser:?}");
    assert!(debug.contains("RequirementsIndexParser"));
}

// ═══════════════════════════════════════════════════════════════
// 10. Reqcheck parser + validation report types
// ═══════════════════════════════════════════════════════════════

#[test]
fn requirements_parser_new_is_default() {
    let parser = RequirementsIndexParser::new();
    let default_parser = RequirementsIndexParser::default();
    // Both should produce equivalent debug output
    let d1 = format!("{parser:?}");
    let d2 = format!("{default_parser:?}");
    assert_eq!(d1, d2);
}

#[test]
fn validation_report_with_warnings_but_no_errors_is_valid() {
    let report = ValidationReport {
        total_entries: 5,
        unique_beads: 3,
        missing_beads: vec![],
        errors: vec![],
        warnings: vec![ValidationWarning {
            section: "§1".into(),
            line_number: None,
            warning_type: "empty_tests".into(),
            message: "no tests specified".into(),
        }],
        entries: None,
    };
    assert!(report.is_valid());
    assert_eq!(report.warnings.len(), 1);
}

// ═══════════════════════════════════════════════════════════════
// 11. Cross-module: forensics + compliance report
// ═══════════════════════════════════════════════════════════════

#[test]
fn forensics_entry_validates_all_outcomes() {
    for outcome in ["pass", "fail", "planned"] {
        let mut entry = valid_forensics_entry();
        entry["outcome"] = json!(outcome);
        let result = schemas::validate_asupersync_forensics_entry(&entry, None);
        assert!(result.is_ok(), "outcome '{outcome}' should be valid");
    }
}

#[test]
fn forensics_entry_with_optional_fields() {
    let mut entry = valid_forensics_entry();
    entry["span_id"] = json!("0123456789abcdef");
    entry["result_code"] = json!("SUCCESS");
    entry["cancellation_reason"] = json!("timeout");
    entry["queue_depth"] = json!(5);
    entry["decode_budget"] = json!(1024.5);
    let result = schemas::validate_asupersync_forensics_entry(&entry, None);
    assert!(result.is_ok());
}

#[test]
fn forensics_invalid_span_id() {
    let mut entry = valid_forensics_entry();
    entry["span_id"] = json!("short");
    let result = schemas::validate_asupersync_forensics_entry(&entry, None);
    match result {
        Err(ForensicsValidationError::RuleViolation { diagnostic, .. }) => {
            assert_eq!(diagnostic.rule_id, "asupersync.forensics.v1.span_id");
        }
        other => panic!("expected RuleViolation, got {other:?}"),
    }
}

#[test]
fn forensics_empty_result_code() {
    let mut entry = valid_forensics_entry();
    entry["result_code"] = json!("  ");
    let result = schemas::validate_asupersync_forensics_entry(&entry, None);
    match result {
        Err(ForensicsValidationError::RuleViolation { diagnostic, .. }) => {
            assert_eq!(diagnostic.rule_id, "asupersync.forensics.v1.result_code");
        }
        other => panic!("expected RuleViolation, got {other:?}"),
    }
}

// ═══════════════════════════════════════════════════════════════
// 12. Cross-module: compliance finding aggregation
// ═══════════════════════════════════════════════════════════════

#[test]
fn static_compliance_finding_flow_to_report() {
    let static_result = StaticCompliance::run_manifest("invalid toml");
    assert!(!static_result.passed);

    let report = ComplianceReport {
        static_checks: static_result,
        dynamic_checks: DynamicCompliance::skipped("not applicable"),
    };

    assert!(!report.passed());
    assert_eq!(report.static_checks.findings[0].status, CheckStatus::Fail);
    assert_eq!(
        report.dynamic_checks.findings[0].status,
        CheckStatus::Skipped
    );
}

// ═══════════════════════════════════════════════════════════════
// 13. E2E log validation
// ═══════════════════════════════════════════════════════════════

#[test]
fn e2e_log_empty_input_passes() {
    let result = schemas::validate_e2e_log_jsonl("");
    assert!(result.is_ok());
}

#[test]
fn e2e_log_blank_lines_only_passes() {
    let result = schemas::validate_e2e_log_jsonl("\n\n  \n");
    assert!(result.is_ok());
}

#[test]
fn e2e_log_invalid_json_fails() {
    let result = schemas::validate_e2e_log_jsonl("not json\n");
    assert!(result.is_err());
}

// ═══════════════════════════════════════════════════════════════
// 14. SchemaValidationError display
// ═══════════════════════════════════════════════════════════════

#[test]
fn schema_validation_error_from_invalid_json() {
    // Schema validation errors occur naturally from validate functions
    let result = schemas::validate_e2e_log_entry(&json!("not an object"));
    assert!(result.is_err());
    let err = result.unwrap_err();
    let display = format!("{err}");
    assert_ne!(display, "");
}

#[test]
fn schema_validation_error_is_std_error() {
    fn assert_error<E: std::error::Error>(_: &E) {}
    let err = schemas::validate_e2e_log_entry(&json!("bad")).unwrap_err();
    assert_error(&err);
}

// ═══════════════════════════════════════════════════════════════
// 15. Interop + compliance summary integration
// ═══════════════════════════════════════════════════════════════

#[test]
fn interop_summary_to_compliance_findings() {
    let summary = InteropTestSummary {
        total: 3,
        passed: 2,
        failed: 1,
        failures: vec![TestFailure {
            name: "mac_suite1".into(),
            category: "fcps".into(),
            message: "MAC mismatch on vector 3".into(),
        }],
    };

    // Convert interop failures to compliance findings
    let findings: Vec<ComplianceFinding> = summary
        .failures
        .iter()
        .map(|f| ComplianceFinding {
            check: format!("interop.{}.{}", f.category, f.name),
            status: CheckStatus::Fail,
            message: f.message.clone(),
        })
        .collect();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].check, "interop.fcps.mac_suite1");
    assert_eq!(findings[0].status, CheckStatus::Fail);
}

// ═══════════════════════════════════════════════════════════════
// 16. Forensics + compliance pipeline
// ═══════════════════════════════════════════════════════════════

#[test]
fn forensics_validation_produces_deterministic_diagnostics() {
    let mut entry = valid_forensics_entry();
    entry.as_object_mut().unwrap().remove("trace_id");

    let result = schemas::validate_asupersync_forensics_entry(&entry, None);
    let err = result.unwrap_err();

    // Verify error has deterministic rule_id and field
    match &err {
        ForensicsValidationError::RuleViolation { diagnostic, .. } => {
            assert_eq!(diagnostic.rule_id, "asupersync.forensics.v1.trace_id");
            assert_eq!(diagnostic.field, "trace_id");
        }
        ForensicsValidationError::InvalidJsonLine { .. } => {
            panic!("expected RuleViolation, got {err:?}")
        }
    }

    // Convert to compliance finding for reporting
    let finding = ComplianceFinding {
        check: format!("forensics.{}", err.rule_id().unwrap_or("unknown")),
        status: CheckStatus::Fail,
        message: format!("{err}"),
    };
    assert_eq!(finding.check, "forensics.asupersync.forensics.v1.trace_id");
    assert_eq!(finding.status, CheckStatus::Fail);
}

const REGISTRY_PLACEHOLDER_HASH: &str =
    "blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000";

fn registry_base_manifest_toml() -> String {
    let raw = include_str!("../../../tests/vectors/manifest/manifest_minimal.toml");
    let unchecked = ConnectorManifest::parse_str_unchecked(raw).expect("manifest");
    let hash = unchecked.compute_interface_hash().expect("interface hash");
    raw.replace(REGISTRY_PLACEHOLDER_HASH, &hash.to_string())
}

fn registry_sign_manifest(
    manifest_toml: &str,
    signing_key: &Ed25519SigningKey,
    binary_hash: &str,
) -> Base64Bytes {
    let manifest = ConnectorManifest::parse_str(manifest_toml).expect("manifest");
    let signing_bytes = fcp_registry::manifest_signing_bytes(&manifest).expect("signing bytes");
    let message = fcp_registry::signature_message(&signing_bytes, binary_hash);
    let signature =
        signing_key.sign_with_context(fcp_registry::MANIFEST_SIGNATURE_CONTEXT, &message);
    Base64Bytes::try_from(format!(
        "base64:{}",
        base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
    ))
    .expect("base64 sig")
}

fn registry_publisher_sig_toml(kid: &str, sig: &Base64Bytes) -> String {
    format!(
        r#"[signatures]
publisher_threshold = "1-of-1"

[[signatures.publisher_signatures]]
kid = "{kid}"
sig = "{sig}"
"#,
        sig = String::from(sig.clone())
    )
}

fn registry_binary_hash(binary: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(binary);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn registry_symbol_config() -> RaptorQConfig {
    RaptorQConfig {
        symbol_size: 128,
        repair_ratio_bps: 10_000,
        ..RaptorQConfig::default()
    }
}

fn registry_signed_bundle(binary: Vec<u8>) -> (ConnectorBundle, RegistryTrustPolicy) {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let binary_hash = registry_binary_hash(&binary);
    let unsigned = registry_base_manifest_toml();
    let sig = registry_sign_manifest(&unsigned, &signing_key, &binary_hash);
    let manifest_toml = format!("{unsigned}\n{}", registry_publisher_sig_toml("pub1", &sig));

    let bundle = ConnectorBundle {
        manifest_toml,
        binary,
        target: ConnectorTarget {
            os: "linux".to_string(),
            arch: "amd64".to_string(),
        },
    };

    let mut trust = RegistryTrustPolicy::default();
    trust
        .publisher_keys
        .insert("pub1".to_string(), verifying_key);
    (bundle, trust)
}

fn registry_patterned_binary(size: usize) -> Vec<u8> {
    (0..size)
        .map(|idx| u8::try_from(idx % 251).expect("pattern byte fits u8"))
        .collect()
}

// ═══════════════════════════════════════════════════════════════
// 17. Registry/store/manifest durability conformance
// ═══════════════════════════════════════════════════════════════

#[fcp_async_core::runtime::test]
async fn fcps_registry_reconstruction_roundtrip_remains_manifest_compliant() {
    let binary = registry_patterned_binary(4096);
    let (bundle, trust) = registry_signed_bundle(binary.clone());
    let verifier = RegistryVerifier::new(trust);
    let verified = verifier
        .verify_bundle(&bundle, None, None, None)
        .expect("verify");

    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    let symbol_store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
    let zone = ZoneId::work();
    let object_id_key = ObjectIdKey::from_bytes([7u8; 32]);

    let mirror = verifier
        .mirror_bundle(&verified, &bundle, zone.clone(), &object_id_key, &store)
        .await
        .expect("mirror");
    let symbol_result = verifier
        .mirror_bundle_symbols(
            &verified,
            &bundle,
            &mirror,
            zone,
            &object_id_key,
            &store,
            &symbol_store,
            &registry_symbol_config(),
            Some(21),
        )
        .await
        .expect("mirror symbols");

    let manifest = store
        .get(&mirror.manifest_object_id)
        .await
        .expect("manifest");
    let mirrored_binary = store.get(&mirror.binary_object_id).await.expect("binary");
    let descriptor = store
        .get(&symbol_result.descriptor_object_id)
        .await
        .expect("descriptor");

    assert_eq!(manifest.header.schema, ConnectorManifestObject::schema());
    assert_eq!(
        mirrored_binary.header.schema,
        ConnectorBinaryObject::schema()
    );
    assert_eq!(descriptor.header.schema, ConnectorBinarySymbolSet::schema());
    assert_eq!(manifest.header.schema.namespace, "fcp.core");
    assert_eq!(mirrored_binary.header.schema.namespace, "fcp.core");
    assert_eq!(descriptor.header.schema.namespace, "fcp.core");

    store
        .delete(&mirror.binary_object_id)
        .await
        .expect("delete mirrored binary");

    let recovered = verifier
        .reconstruct_bundle_from_symbol_descriptor(
            &symbol_result.descriptor_object_id,
            &store,
            &symbol_store,
            &registry_symbol_config(),
        )
        .await
        .expect("reconstruct bundle");

    assert_eq!(recovered.binary, binary);
    assert_eq!(recovered.target, bundle.target);
    ConnectorManifest::parse_str(&recovered.manifest_toml).expect("parse recovered manifest");

    let static_checks = StaticCompliance::run_manifest(&recovered.manifest_toml);
    assert!(
        static_checks.passed,
        "recovered manifest should remain statically compliant: {:?}",
        static_checks.findings
    );

    let reverified = verifier
        .verify_bundle(&recovered, None, None, None)
        .expect("reverify recovered bundle");
    assert_eq!(reverified.manifest_hash, verified.manifest_hash);
    assert_eq!(reverified.binary_hash, verified.binary_hash);
}

#[fcp_async_core::runtime::test]
async fn fcps_registry_reconstruction_rejects_tampered_manifest_object() {
    let binary = registry_patterned_binary(4096);
    let (bundle, trust) = registry_signed_bundle(binary);
    let verifier = RegistryVerifier::new(trust);
    let verified = verifier
        .verify_bundle(&bundle, None, None, None)
        .expect("verify");

    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    let symbol_store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
    let zone = ZoneId::work();
    let object_id_key = ObjectIdKey::from_bytes([9u8; 32]);

    let mirror = verifier
        .mirror_bundle(&verified, &bundle, zone.clone(), &object_id_key, &store)
        .await
        .expect("mirror");
    let symbol_result = verifier
        .mirror_bundle_symbols(
            &verified,
            &bundle,
            &mirror,
            zone,
            &object_id_key,
            &store,
            &symbol_store,
            &registry_symbol_config(),
            Some(23),
        )
        .await
        .expect("mirror symbols");

    let mut manifest_record = store
        .get(&mirror.manifest_object_id)
        .await
        .expect("get manifest");
    let replacement_hash = format!("sha256:{}", "0".repeat(64));
    let original_hash = verified.manifest_hash.as_bytes();
    let replacement_hash_bytes = replacement_hash.as_bytes();
    let position = manifest_record
        .body
        .windows(original_hash.len())
        .position(|window| window == original_hash)
        .expect("manifest hash bytes present");
    manifest_record.body[position..position + original_hash.len()]
        .copy_from_slice(replacement_hash_bytes);

    store
        .delete(&mirror.manifest_object_id)
        .await
        .expect("delete manifest");
    store
        .put(manifest_record)
        .await
        .expect("put tampered manifest");

    let err = verifier
        .reconstruct_bundle_from_symbol_descriptor(
            &symbol_result.descriptor_object_id,
            &store,
            &symbol_store,
            &registry_symbol_config(),
        )
        .await
        .expect_err("tampered manifest hash should fail reconstruction");
    assert!(matches!(
        err,
        RegistryError::ReconstructedManifestHashMismatch { .. }
    ));
}
