use std::path::Path;
use std::process::Command;

use fwc::doctor::self_test::{CheckVerdict, SelfTestStatus, run_self_test};

const HEALTHY_ENV: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/healthy_env");
const BROKEN_ENV: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/broken_env");

#[test]
fn test_healthy_fixture_scores_800_plus() {
    let report = run_self_test(Path::new(HEALTHY_ENV)).expect("healthy fixture should run");

    assert_eq!(report.fixture_name, "healthy_env");
    assert_eq!(report.status, SelfTestStatus::Ok);
    assert!(report.score >= 800, "score was {}", report.score);
    assert_eq!(report.remediation_messages, [] as [std::string::String; 0]);
    assert_eq!(report.executed_commands, [] as [std::string::String; 0]);
}

#[test]
fn test_broken_fixture_scores_within_degradation_curve() {
    let report = run_self_test(Path::new(BROKEN_ENV)).expect("broken fixture should run");

    assert_eq!(report.fixture_name, "broken_env");
    assert_eq!(report.status, SelfTestStatus::Fail);
    assert!(report.score < 500, "score was {}", report.score);
    for subsystem in ["agent-mail", "beads-wal", "pubkey", "otlp"] {
        assert!(
            report
                .remediation_messages
                .iter()
                .any(|message| message.contains(subsystem)),
            "missing remediation for {subsystem}: {:?}",
            report.remediation_messages
        );
    }
}

#[test]
fn test_doctor_never_restarts_agent_mail() {
    let report = run_self_test(Path::new(BROKEN_ENV)).expect("broken fixture should run");

    assert_eq!(report.executed_commands, [] as [std::string::String; 0]);
    let agent_mail = report
        .checks
        .iter()
        .find(|check| check.subsystem == "agent-mail")
        .expect("broken fixture should include agent-mail check");
    assert_eq!(agent_mail.verdict, CheckVerdict::Fail);
    assert!(!agent_mail.auto_repair);
    assert!(
        agent_mail
            .remediation
            .as_deref()
            .is_some_and(|message| message.contains("do not restart"))
    );
}

#[test]
fn test_doctor_warns_but_does_not_repair_beads_wal() {
    let report = run_self_test(Path::new(BROKEN_ENV)).expect("broken fixture should run");
    let beads_wal = report
        .checks
        .iter()
        .find(|check| check.subsystem == "beads-wal")
        .expect("broken fixture should include beads WAL check");

    assert_eq!(beads_wal.verdict, CheckVerdict::Fail);
    assert_eq!(
        beads_wal.remediation.as_deref(),
        Some("br doctor --repair (operator-gated)")
    );
    assert!(!beads_wal.auto_repair);
    assert_eq!(report.executed_commands, [] as [std::string::String; 0]);
}

#[test]
fn test_doctor_self_test_command_surfaces_in_help_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_fwc"))
        .args(["doctor", "--help"])
        .output()
        .expect("fwc doctor help should run");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("help output should be UTF-8");
    assert!(stdout.contains("self-test"), "{stdout}");
}
