//! Soft connector README coverage check.
//!
//! `flywheel_connectors-4kw5f.12` tracks the workspace-wide README convention.
//! All manifest-backed connectors now carry READMEs, but the operator contract
//! sections still have drift. The enforcement test is ignored by default until
//! the wave work finishes. Running it explicitly gives a deterministic,
//! redaction-safe inventory of the remaining section gaps.

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::json;

const MIN_README_BYTES: u64 = 500;

const ALLOWED_OPERATION_INVENTORY_HEADING_GAPS: &[&str] = &[
    "apple-notes",
    "apple-reminders",
    "azure-speech",
    "bluebubbles",
    "imessage",
    "mastodon",
    "mattermost",
    "netlify",
    "openrouter",
    "roam",
    "twilio",
    "twitter",
    "zoom",
];

const ALLOWED_BACKTICKED_TABLE_ROW_GAPS: &[&str] = &[
    "anthropic-vertex",
    "azure-speech",
    "matrix",
    "microsoft-foundry",
    "plivo",
    "roam",
    "telnyx",
];

#[derive(Debug)]
struct RequiredReadmeSection {
    name: &'static str,
    accepted_headings: &'static [&'static str],
}

const REQUIRED_SECTIONS: &[RequiredReadmeSection] = &[
    RequiredReadmeSection {
        name: "Purpose",
        accepted_headings: &["## Purpose"],
    },
    RequiredReadmeSection {
        name: "Current Runtime Snapshot",
        accepted_headings: &["## Current Runtime Snapshot"],
    },
    RequiredReadmeSection {
        name: "Auth And Scope Boundary",
        accepted_headings: &["## Auth And Scope Boundary"],
    },
    RequiredReadmeSection {
        name: "Operation Inventory",
        accepted_headings: &[
            "## Operation Inventory",
            "## Accepted Operation Inventory",
            "## Operations",
        ],
    },
    RequiredReadmeSection {
        name: "Readiness And Verification Surface",
        accepted_headings: &["## Readiness And Verification Surface"],
    },
    RequiredReadmeSection {
        name: "Operator Guidance",
        accepted_headings: &["## Operator Guidance"],
    },
];

#[derive(Debug)]
struct ConnectorReadmeRecord {
    connector: String,
    readme_path: String,
    exists: bool,
    byte_len: u64,
    missing_sections: Vec<String>,
    backticked_table_row_count: usize,
}

impl ConnectorReadmeRecord {
    fn is_complete(&self) -> bool {
        self.exists && self.byte_len >= MIN_README_BYTES && self.missing_sections.is_empty()
    }
}

fn workspace_root() -> Result<PathBuf, String> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| "cannot derive workspace root from CARGO_MANIFEST_DIR".to_owned())
}

fn display_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root).map_or_else(
        |_| path.display().to_string(),
        |relative| relative.display().to_string(),
    )
}

fn is_backticked_identifier_table_row(line: &str) -> bool {
    let Some(rest) = line.trim_start().strip_prefix("| `") else {
        return false;
    };
    let Some((identifier, after_identifier)) = rest.split_once('`') else {
        return false;
    };
    !identifier.trim().is_empty() && after_identifier.trim_start().starts_with('|')
}

fn backticked_table_row_count(contents: &str) -> usize {
    contents
        .lines()
        .filter(|line| is_backticked_identifier_table_row(line))
        .count()
}

fn discover_connector_readmes(root: &Path) -> Result<Vec<ConnectorReadmeRecord>, String> {
    let manifests_parent = root.join("connectors");
    let entries = fs::read_dir(&manifests_parent)
        .map_err(|error| format!("cannot read {}: {error}", manifests_parent.display()))?;
    let mut records = Vec::new();

    for entry_result in entries {
        let entry = entry_result
            .map_err(|error| format!("cannot read connector directory entry: {error}"))?;
        let candidate = entry.path();
        if !candidate.is_dir() || !candidate.join("manifest.toml").is_file() {
            continue;
        }

        let Some(name) = candidate
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_owned)
        else {
            continue;
        };

        let readme = candidate.join("README.md");
        let readme_path = display_path(root, &readme);
        let contents = fs::read_to_string(&readme).unwrap_or_default();
        let exists = readme.is_file();
        let byte_len = if exists {
            fs::metadata(&readme)
                .map(|metadata| metadata.len())
                .map_err(|error| format!("cannot stat {readme_path}: {error}"))?
        } else {
            0
        };
        let missing_sections = if exists {
            REQUIRED_SECTIONS
                .iter()
                .filter(|section| {
                    !section
                        .accepted_headings
                        .iter()
                        .any(|heading| contents.contains(heading))
                })
                .map(|section| section.name.to_owned())
                .collect()
        } else {
            Vec::new()
        };

        records.push(ConnectorReadmeRecord {
            connector: name,
            readme_path,
            exists,
            byte_len,
            missing_sections,
            backticked_table_row_count: backticked_table_row_count(&contents),
        });
    }

    records.sort_by(|left, right| left.connector.cmp(&right.connector));
    Ok(records)
}

#[test]
fn connector_readme_template_documents_required_operator_contract() -> Result<(), String> {
    let root = workspace_root()?;
    let template_path = root.join("docs/connector-readme-template.md");
    let template = fs::read_to_string(&template_path)
        .map_err(|error| format!("cannot read {}: {error}", template_path.display()))?;

    for heading in [
        "## Purpose",
        "## Current Runtime Snapshot",
        "## Auth And Scope Boundary",
        "## Operation Inventory",
        "## Readiness And Verification Surface",
        "## Operator Guidance",
    ] {
        assert!(
            template.contains(heading),
            "connector README template must include `{heading}`"
        );
    }
    Ok(())
}

#[test]
fn connector_readme_operation_inventory_heading_gaps_do_not_grow() -> Result<(), String> {
    let root = workspace_root()?;
    let records = discover_connector_readmes(&root)?;
    let allowed_gaps = ALLOWED_OPERATION_INVENTORY_HEADING_GAPS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let current_gaps = records
        .iter()
        .filter(|record| {
            record
                .missing_sections
                .iter()
                .any(|section| section == "Operation Inventory")
        })
        .map(|record| record.connector.as_str())
        .collect::<Vec<_>>();
    let unexpected_gaps = current_gaps
        .iter()
        .copied()
        .filter(|connector| !allowed_gaps.contains(connector))
        .collect::<Vec<_>>();

    assert!(
        unexpected_gaps.is_empty(),
        "new connector README operation inventory heading gaps: {unexpected_gaps:?}; allowed gaps: {ALLOWED_OPERATION_INVENTORY_HEADING_GAPS:?}"
    );
    assert!(
        current_gaps.len() <= ALLOWED_OPERATION_INVENTORY_HEADING_GAPS.len(),
        "connector README operation inventory gap count grew from {} to {}: {current_gaps:?}",
        ALLOWED_OPERATION_INVENTORY_HEADING_GAPS.len(),
        current_gaps.len()
    );
    Ok(())
}

#[test]
fn connector_readme_backticked_table_row_gaps_do_not_grow() -> Result<(), String> {
    let root = workspace_root()?;
    let records = discover_connector_readmes(&root)?;
    let allowed_gaps = ALLOWED_BACKTICKED_TABLE_ROW_GAPS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let current_gaps = records
        .iter()
        .filter(|record| record.backticked_table_row_count == 0)
        .map(|record| record.connector.as_str())
        .collect::<Vec<_>>();
    let unexpected_gaps = current_gaps
        .iter()
        .copied()
        .filter(|connector| !allowed_gaps.contains(connector))
        .collect::<Vec<_>>();

    assert!(
        unexpected_gaps.is_empty(),
        "new connector README backticked table-row gaps: {unexpected_gaps:?}; allowed gaps: {ALLOWED_BACKTICKED_TABLE_ROW_GAPS:?}"
    );
    assert!(
        current_gaps.len() <= ALLOWED_BACKTICKED_TABLE_ROW_GAPS.len(),
        "connector README backticked table-row gap count grew from {} to {}: {current_gaps:?}",
        ALLOWED_BACKTICKED_TABLE_ROW_GAPS.len(),
        current_gaps.len()
    );
    Ok(())
}

#[test]
#[ignore = "soft convention ratchet: enable after README wave work closes flywheel_connectors-4kw5f.12"]
fn all_manifest_backed_connectors_have_operator_readmes() -> Result<(), String> {
    let root = workspace_root()?;
    let records = discover_connector_readmes(&root)?;
    let incomplete = records
        .iter()
        .filter(|record| !record.is_complete())
        .collect::<Vec<_>>();

    for record in &incomplete {
        println!(
            "{}",
            json!({
                "event": "connector_readme_presence",
                "connector": record.connector,
                "readme_path": record.readme_path,
                "exists": record.exists,
                "byte_len": record.byte_len,
                "missing_sections": record.missing_sections,
                "backticked_table_row_count": record.backticked_table_row_count,
                "min_readme_bytes": MIN_README_BYTES,
                "redaction_decision": "connector names and repository-relative README paths only; no credentials, payloads, prompts, transcripts, or PII read",
            })
        );
    }

    assert!(
        incomplete.is_empty(),
        "connector README convention gaps remain: {} of {} manifest-backed connectors incomplete",
        incomplete.len(),
        records.len()
    );
    Ok(())
}
