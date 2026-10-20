//! Conformance gate for the Phase Q.K alien-graveyard 2026-Q3 EV-scoring
//! artifact (`flywheel_connectors-angoc.11.3`).
//!
//! Asserts that:
//!   1. The committed artifact exists at the canonical path.
//!   2. The Top-5 commitment names exactly five buckets, none repeated.
//!   3. The artifact references the bridge plan's Phase Q (`Q.A`..`Q.J`).
//!   4. The methodology version is captured.
//!   5. The score.sh harness exists and is executable.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("CARGO_MANIFEST_DIR has a parent")
        .parent()
        .expect("workspace root exists")
        .to_path_buf()
}

fn artifact_path() -> PathBuf {
    repo_root()
        .join("docs")
        .join("architecture")
        .join("alien_graveyard_q3_2026.md")
}

#[test]
fn test_artifact_exists() {
    let path = artifact_path();
    assert!(
        path.exists(),
        "alien-graveyard Q3 artifact must exist at {}; \
         regenerate via `bash scripts/alien-graveyard/score.sh`",
        path.display()
    );
    let content = fs::read_to_string(&path).expect("artifact readable");
    assert!(
        content.len() > 500,
        "artifact at {} is suspiciously small ({} bytes); \
         expected a full Top-5 commitment table",
        path.display(),
        content.len()
    );
}

#[test]
fn test_artifact_names_top5_commitment() {
    let content = fs::read_to_string(artifact_path()).expect("artifact readable");
    let lower = content.to_lowercase();
    assert!(
        lower.contains("top-5"),
        "artifact must contain a 'Top-5' header/commitment section"
    );

    // Extract every bucket id Q.A..Q.J that appears in the artifact.
    let mut buckets_present: BTreeSet<String> = BTreeSet::new();
    for ch in 'A'..='J' {
        let needle = format!("Q.{ch}");
        if content.contains(&needle) {
            buckets_present.insert(needle);
        }
    }
    assert_eq!(
        buckets_present.len(),
        10,
        "artifact must reference all 10 buckets Q.A..Q.J; found {}: {:?}",
        buckets_present.len(),
        buckets_present
    );
}

#[test]
fn test_artifact_declares_methodology_version() {
    let content = fs::read_to_string(artifact_path()).expect("artifact readable");
    assert!(
        content.contains("Methodology version") || content.contains("methodology version"),
        "artifact must declare a methodology version line for cross-quarter \
         comparability"
    );
    // The current methodology version is pinned to 2026.Q3.v1. If we change
    // methodologies, both the artifact and this test must update.
    assert!(
        content.contains("2026.Q3.v1"),
        "artifact must pin methodology version `2026.Q3.v1`; \
         change the version in the artifact AND here when methodology evolves"
    );
}

#[test]
fn test_score_harness_executable() {
    let harness = repo_root()
        .join("scripts")
        .join("alien-graveyard")
        .join("score.sh");
    assert!(
        harness.exists(),
        "scripts/alien-graveyard/score.sh must exist at {}",
        harness.display()
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(&harness).expect("score.sh metadata");
        let mode = metadata.permissions().mode();
        // At least the owner-execute bit must be set.
        assert!(
            mode & 0o100 != 0,
            "score.sh at {} must be executable (mode = {:#o})",
            harness.display(),
            mode
        );
    }
}

#[test]
fn test_top5_bucket_set_matches_score_pipeline() {
    // The committed artifact says Top-5 = {Q.B, Q.J, Q.I, Q.H, Q.G}. Anchor
    // that set here so a future agent who edits the artifact's prose without
    // updating the score matrix (or vice versa) gets caught.
    let content = fs::read_to_string(artifact_path()).expect("artifact readable");
    let expected_top5 = ["Q.B", "Q.J", "Q.I", "Q.H", "Q.G"];
    let lower = content.to_lowercase();
    // Look for the commitment block under the "Top-5 commitment" header.
    let header = "## top-5 commitment";
    let start = lower
        .find(header)
        .unwrap_or_else(|| panic!("artifact must contain a `## Top-5 commitment` section"));
    // Bound the search to JUST the Top-5 commitment section: from the header
    // line to the next top-level `## ` header. Without this bound, a future
    // edit that demotes (say) Q.G to the Q4-deferred section would still
    // leave "Q.G" present somewhere in `content[start..]` and the test would
    // pass falsely — the very desynchronization this test is meant to catch.
    let after_header = start + header.len();
    let section_end = lower[after_header..]
        .find("\n## ")
        .map_or(content.len(), |relative| after_header + relative);
    let section = &content[start..section_end];
    for bucket in &expected_top5 {
        assert!(
            section.contains(bucket),
            "`## Top-5 commitment` section must reference {bucket} (not just elsewhere \
             in the artifact); keep artifact and scoring matrix aligned"
        );
    }
    // Cross-check: the ranked-table BEFORE the Top-5 section must have
    // exactly 5 rows marked `**Top-5 (Q3)**`. The deferred set must NOT have
    // any such marker. The ranked table appears BEFORE the Top-5 commitment
    // section, so scan `content[..start]`. A mismatch here means the ranking
    // and the commitment are out of sync.
    let pre_section = &content[..start];
    let top5_marker_count = pre_section.matches("**Top-5 (Q3)**").count();
    assert_eq!(
        top5_marker_count, 5,
        "ranked-table must contain exactly 5 `**Top-5 (Q3)**` annotations \
         (one per Top-5 row); found {top5_marker_count} — either the artifact \
         has been edited out of sync or the ranking changed"
    );
    // For each expected Top-5 bucket, verify it appears on the SAME LINE as
    // a `**Top-5 (Q3)**` annotation in the ranked-table region.
    for bucket in &expected_top5 {
        let found_on_top5_row = pre_section
            .lines()
            .any(|line| line.contains(&format!("**{bucket}**")) && line.contains("**Top-5 (Q3)**"));
        assert!(
            found_on_top5_row,
            "ranked-table has no row with both `**{bucket}**` and `**Top-5 (Q3)**`; \
             the ranking is inconsistent with the Top-5 commitment"
        );
    }
}

#[test]
fn test_every_bucket_has_research_proof_or_deferral_doc() {
    let research_root = repo_root().join("docs").join("research");
    for ch in 'a'..='j' {
        let bucket_readme = research_root.join(format!("q.{ch}")).join("README.md");
        assert!(
            bucket_readme.is_file(),
            "Phase Q bucket Q.{} must have a proof/fallback artifact at {}",
            ch.to_ascii_uppercase(),
            bucket_readme.display()
        );
        let content = fs::read_to_string(&bucket_readme).expect("bucket README readable");
        assert!(
            content.contains(&format!("Phase Q.{}", ch.to_ascii_uppercase()))
                && content.contains("Fallback"),
            "bucket artifact {} must document its Phase Q.<bucket> identity and fallback contract",
            bucket_readme.display()
        );
    }
}
