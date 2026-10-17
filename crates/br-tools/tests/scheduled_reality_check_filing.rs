use std::fs;

use br_tools::scheduled_reality_check::{
    ExistingBead, check_monthly_cadence, check_monthly_cadence_with_existing,
    check_quarterly_cadence, check_quarterly_cadence_with_existing,
    check_reality_cadence_with_existing,
};
use chrono::NaiveDate;
use tempfile::tempdir;

const fn date(year: i32, month: u32, day: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(year, month, day).expect("test date is valid")
}

#[test]
fn test_files_bead_when_month_missing() {
    let tmp = tempdir().expect("tempdir");
    let proposed = check_monthly_cadence(date(2026, 6, 1), tmp.path());

    assert_eq!(proposed.len(), 1);
    assert_eq!(
        proposed[0].title,
        "[reality-check] 2026-06 reality-check pass overdue"
    );
    assert_eq!(proposed[0].priority, 2);
}

#[test]
fn test_no_bead_when_month_present() {
    let tmp = tempdir().expect("tempdir");
    fs::write(
        tmp.path().join("2026-06-15-reality-check.md"),
        "# June reality check\n",
    )
    .expect("write fixture");

    let proposed = check_monthly_cadence(date(2026, 6, 1), tmp.path());

    assert!(proposed.is_empty());
}

#[test]
fn test_idempotency_skips_when_open_bead_exists() {
    let tmp = tempdir().expect("tempdir");
    let title = "[reality-check] 2026-06 reality-check pass overdue";
    let existing = [ExistingBead::open(title)];

    let proposed = check_monthly_cadence_with_existing(date(2026, 6, 1), tmp.path(), &existing);

    assert!(proposed.is_empty());
}

#[test]
fn test_reissue_after_close() {
    let tmp = tempdir().expect("tempdir");
    let title = "[reality-check] 2026-06 reality-check pass overdue";
    let existing = [ExistingBead::closed(title, true)];

    let proposed = check_monthly_cadence_with_existing(date(2026, 6, 1), tmp.path(), &existing);

    assert_eq!(proposed.len(), 1);
    assert_eq!(proposed[0].title, title);
}

#[test]
fn test_double_run_same_day_no_duplicates() {
    let tmp = tempdir().expect("tempdir");
    let first = check_monthly_cadence(date(2026, 6, 1), tmp.path());
    assert_eq!(first.len(), 1);

    let existing = [ExistingBead::open(first[0].title.clone())];
    let second = check_monthly_cadence_with_existing(date(2026, 6, 1), tmp.path(), &existing);

    assert!(second.is_empty());
}

#[test]
fn test_files_quarterly_bead_when_artifact_missing() {
    let tmp = tempdir().expect("tempdir");
    let proposed = check_quarterly_cadence(date(2026, 7, 1), tmp.path());

    assert_eq!(proposed.len(), 1);
    assert_eq!(
        proposed[0].title,
        "[reality-check] 2026-Q3 claims-vs-reality pass overdue"
    );
    assert_eq!(proposed[0].priority, 2);
    assert_eq!(
        proposed[0].labels,
        ["reality-check", "cadence", "quarterly", "claims-vs-reality"]
    );
}

#[test]
fn test_no_quarterly_bead_when_artifact_present() {
    let tmp = tempdir().expect("tempdir");
    fs::write(
        tmp.path().join("2026-Q3-claims-vs-reality.md"),
        "# 2026 Q3 claims vs reality\n",
    )
    .expect("write fixture");

    let proposed = check_quarterly_cadence(date(2026, 7, 1), tmp.path());

    assert!(proposed.is_empty());
}

#[test]
fn test_quarterly_idempotency_skips_when_open_bead_exists() {
    let tmp = tempdir().expect("tempdir");
    let title = "[reality-check] 2026-Q3 claims-vs-reality pass overdue";
    let existing = [ExistingBead::open(title)];

    let proposed = check_quarterly_cadence_with_existing(date(2026, 7, 1), tmp.path(), &existing);

    assert!(proposed.is_empty());
}

#[test]
fn test_quarterly_reissue_after_stale_close() {
    let tmp = tempdir().expect("tempdir");
    let title = "[reality-check] 2026-Q3 claims-vs-reality pass overdue";
    let existing = [ExistingBead::closed(title, true)];

    let proposed = check_quarterly_cadence_with_existing(date(2026, 7, 1), tmp.path(), &existing);

    assert_eq!(proposed.len(), 1);
    assert_eq!(proposed[0].title, title);
}

#[test]
fn test_quarterly_fires_on_first_business_day_after_weekend_boundary() {
    let tmp = tempdir().expect("tempdir");
    let proposed = check_quarterly_cadence(date(2028, 1, 3), tmp.path());

    assert_eq!(proposed.len(), 1);
    assert_eq!(
        proposed[0].title,
        "[reality-check] 2028-Q1 claims-vs-reality pass overdue"
    );
}

#[test]
fn test_quarterly_skips_non_boundary_month() {
    let tmp = tempdir().expect("tempdir");
    let proposed = check_quarterly_cadence(date(2026, 8, 1), tmp.path());

    assert!(proposed.is_empty());
}

#[test]
fn test_combined_cadence_files_monthly_and_quarterly_beads() {
    let reality = tempdir().expect("reality tempdir");
    let quarterly = tempdir().expect("quarterly tempdir");

    let proposed = check_reality_cadence_with_existing(
        date(2026, 7, 1),
        reality.path(),
        quarterly.path(),
        &[],
    );

    assert_eq!(proposed.len(), 2);
    assert_eq!(
        proposed[0].title,
        "[reality-check] 2026-07 reality-check pass overdue"
    );
    assert_eq!(
        proposed[1].title,
        "[reality-check] 2026-Q3 claims-vs-reality pass overdue"
    );
}

#[test]
fn test_mid_month_replay_detects_missing_monthly_and_quarterly_artifacts() {
    let reality = tempdir().expect("reality tempdir");
    let quarterly = tempdir().expect("quarterly tempdir");

    let proposed = check_reality_cadence_with_existing(
        date(2026, 10, 13),
        reality.path(),
        quarterly.path(),
        &[],
    );

    assert_eq!(proposed.len(), 2);
    assert_eq!(
        proposed[0].title,
        "[reality-check] 2026-10 reality-check pass overdue"
    );
    assert_eq!(
        proposed[1].title,
        "[reality-check] 2026-Q4 claims-vs-reality pass overdue"
    );
}

#[test]
fn test_quarterly_skips_weekend_before_first_business_day() {
    let tmp = tempdir().expect("tempdir");
    let proposed = check_quarterly_cadence(date(2028, 1, 1), tmp.path());

    assert!(proposed.is_empty());
}
