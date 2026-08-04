//! Redaction-safe proof request bundle rendering.
//!
//! This module is pure: it consumes a validated proof-readiness manifest plus a
//! readiness report and returns deterministic JSON/Markdown payloads. It never
//! executes the rendered commands and never inspects live host state.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::proof_readiness::{
    MissingPrerequisite, ProofReadinessReport, ProofReadinessStatus, ProofReadinessTarget,
    ProofReadinessTargetReport, ProofReadinessTargetsManifest,
};

pub const PROOF_REQUEST_BUNDLE_SCHEMA_VERSION: &str = "fcp.fwc.proof-request-bundle.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofRequestBundle {
    pub schema_version: String,
    pub status: ProofRequestBundleStatus,
    pub generated_at: String,
    pub target_count: usize,
    pub requests: Vec<ProofRequestTargetBundle>,
    pub redaction_summary: ProofRequestRedactionSummary,
    pub markdown: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProofRequestBundleStatus {
    Ready,
    MissingRequests,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofRequestTargetBundle {
    pub target_id: String,
    pub title: String,
    pub blocked_beads: Vec<String>,
    pub status: ProofReadinessStatus,
    pub missing: Vec<MissingPrerequisite>,
    pub command_template: Vec<String>,
    pub artifact_requirements: ProofRequestArtifactRequirements,
    pub redaction_checklist: Vec<String>,
    pub follow_up_commands: Vec<String>,
    pub message_markdown: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofRequestArtifactRequirements {
    pub artifact_schema: String,
    pub artifact_globs: Vec<String>,
    pub freshness_days: u32,
    pub required_fields: Vec<String>,
    pub machine_classes: Vec<String>,
    pub host_roles: Vec<String>,
    pub thresholds: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofRequestRedactionSummary {
    pub safe_for_agent_mail: bool,
    pub safe_for_beads_comment: bool,
    pub forbidden_material_checked: Vec<String>,
}

/// Builds a deterministic proof request bundle for all non-ready targets in a
/// proof-readiness report.
///
/// # Errors
///
/// Returns an error if the report references a target absent from the manifest,
/// or if rendered output would contain a raw endpoint, private IP, credential
/// material, or user-home path.
pub fn build_proof_request_bundle(
    manifest: &ProofReadinessTargetsManifest,
    report: &ProofReadinessReport,
) -> Result<ProofRequestBundle> {
    let requests = report
        .targets
        .iter()
        .filter(|target| target.status != ProofReadinessStatus::Ready)
        .map(|target_report| request_for_target(manifest, target_report))
        .collect::<Result<Vec<_>>>()?;

    let status = if requests.is_empty() {
        ProofRequestBundleStatus::Ready
    } else {
        ProofRequestBundleStatus::MissingRequests
    };
    let redaction_summary = ProofRequestRedactionSummary {
        safe_for_agent_mail: true,
        safe_for_beads_comment: true,
        forbidden_material_checked: vec![
            "raw_urls".to_owned(),
            "private_ips".to_owned(),
            "bearer_tokens".to_owned(),
            "cookies".to_owned(),
            "credential_assignments".to_owned(),
            "user_home_paths".to_owned(),
        ],
    };
    let markdown = render_bundle_markdown(report, &requests);
    ensure_redaction_safe(&markdown)?;
    let bundle = ProofRequestBundle {
        schema_version: PROOF_REQUEST_BUNDLE_SCHEMA_VERSION.to_owned(),
        status,
        generated_at: report.generated_at.clone(),
        target_count: requests.len(),
        requests,
        redaction_summary,
        markdown,
    };
    ensure_redaction_safe(&serde_json::to_string(&bundle)?)?;
    Ok(bundle)
}

fn request_for_target(
    manifest: &ProofReadinessTargetsManifest,
    target_report: &ProofReadinessTargetReport,
) -> Result<ProofRequestTargetBundle> {
    let target = manifest
        .targets
        .iter()
        .find(|target| target.target_id == target_report.target_id)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "report references unknown target `{}`",
                target_report.target_id
            )
        })?;
    let artifact_requirements = ProofRequestArtifactRequirements {
        artifact_schema: target.artifact_schema.clone(),
        artifact_globs: target.artifact_globs.clone(),
        freshness_days: target.freshness_days,
        required_fields: target.required_artifact_fields.clone(),
        machine_classes: target.machine_classes.clone(),
        host_roles: target.host_roles.clone(),
        thresholds: target.thresholds.clone(),
    };
    let redaction_checklist = redaction_checklist(target);
    let follow_up_commands = follow_up_commands(target, target_report);
    let message_markdown = render_target_markdown(
        target,
        target_report,
        &artifact_requirements,
        &redaction_checklist,
        &follow_up_commands,
    );
    ensure_redaction_safe(&message_markdown)?;
    Ok(ProofRequestTargetBundle {
        target_id: target.target_id.clone(),
        title: target.title.clone(),
        blocked_beads: target.blocked_beads.clone(),
        status: target_report.status.clone(),
        missing: target_report.missing.clone(),
        command_template: target_report.command.argv_template.clone(),
        artifact_requirements,
        redaction_checklist,
        follow_up_commands,
        message_markdown,
    })
}

fn redaction_checklist(target: &ProofReadinessTarget) -> Vec<String> {
    let mut checklist = vec![
        "Use role names, machine classes, and stable hashes instead of raw hostnames or endpoints."
            .to_owned(),
        "Omit credential headers, cookies, credential values, and request headers from committed output."
            .to_owned(),
        "Use repo-relative artifact paths only; omit user-home paths and machine-local directories."
            .to_owned(),
        "Summarize sample counts, thresholds, and pass/fail state without including raw service payloads."
            .to_owned(),
    ];
    checklist.extend(
        target
            .redaction_policy
            .iter()
            .map(|policy| format!("Apply manifest redaction policy `{policy}`.")),
    );
    checklist.extend(target.evidence_notes.iter().cloned());
    checklist
}

fn follow_up_commands(
    target: &ProofReadinessTarget,
    target_report: &ProofReadinessTargetReport,
) -> Vec<String> {
    let mut commands = vec![format!(
        "fwc proof readiness --target {} --json",
        target.target_id
    )];
    commands.extend(target.blocked_beads.iter().map(|bead| {
        format!("br comments add {bead} --message '<redaction-safe artifact summary and path>'")
    }));
    if target_report.command.requires_remote {
        commands.push(
            "RCH_REQUIRE_REMOTE=1 RCH_QUEUE_WHEN_BUSY=1 rch exec -- <redaction-safe command>"
                .to_owned(),
        );
    }
    commands
}

fn render_bundle_markdown(
    report: &ProofReadinessReport,
    requests: &[ProofRequestTargetBundle],
) -> String {
    let mut markdown = String::new();
    markdown.push_str("# Proof Request Bundle\n\n");
    let _ = writeln!(markdown, "- Generated at: `{}`", report.generated_at);
    let _ = writeln!(markdown, "- Request count: `{}`", requests.len());
    markdown.push_str("- Scope: non-ready proof-readiness targets only\n\n");
    if requests.is_empty() {
        markdown.push_str("No proof requests are needed; every selected target is ready.\n");
    } else {
        for request in requests {
            markdown.push_str(&request.message_markdown);
            markdown.push('\n');
        }
    }
    markdown
}

/// Backslash-escape inline-markdown metacharacters so manifest- and
/// artifact-derived text cannot inject links, code spans, or structure into
/// the paste-safe bundle markdown (the redaction guard only blocks
/// `scheme://` URLs, so protocol-relative `[text](//host)` links would
/// otherwise survive). Newlines collapse to spaces so a multi-line value
/// cannot break out of its heading or list item.
fn escape_markdown_text(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' | '`' | '*' | '_' | '[' | ']' | '(' | ')' | '#' | '<' | '>' | '|' => {
                escaped.push('\\');
                escaped.push(ch);
            }
            '\r' => {}
            '\n' => escaped.push(' '),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn render_target_markdown(
    target: &ProofReadinessTarget,
    target_report: &ProofReadinessTargetReport,
    artifact_requirements: &ProofRequestArtifactRequirements,
    redaction_checklist: &[String],
    follow_up_commands: &[String],
) -> String {
    let mut markdown = String::new();
    let _ = write!(
        markdown,
        "## `{}` - {}\n\n",
        target.target_id,
        escape_markdown_text(&target.title)
    );
    let _ = writeln!(markdown, "- Status: `{:?}`", target_report.status);
    let _ = writeln!(
        markdown,
        "- Blocked beads: `{}`",
        target.blocked_beads.join("`, `")
    );
    markdown.push_str("- Missing prerequisites:\n");
    for missing in &target_report.missing {
        // `missing.id` is filesystem-derived (a discovered artifact's
        // repo-relative path for Schema/Freshness/read failures), so it must be
        // markdown-escaped like `missing.message` beside it — an unescaped
        // backtick would close the surrounding code span and let a
        // `[text](//host)` protocol-relative link survive `ensure_redaction_safe`
        // into the "safe for agent mail" bundle.
        let _ = writeln!(
            markdown,
            "  - `{:?}` {}: {}",
            missing.kind,
            escape_markdown_text(&missing.id),
            escape_markdown_text(&missing.message)
        );
    }
    markdown.push_str("\nCommand template:\n\n```text\n");
    markdown.push_str(&target_report.command.argv_template.join(" "));
    markdown.push_str("\n```\n\n");
    markdown.push_str("Artifact requirements:\n");
    let _ = writeln!(
        markdown,
        "- Schema version: `{}`",
        artifact_requirements.artifact_schema
    );
    let _ = writeln!(
        markdown,
        "- Artifact globs: `{}`",
        artifact_requirements.artifact_globs.join("`, `")
    );
    let _ = writeln!(
        markdown,
        "- Freshness window days: `{}`",
        artifact_requirements.freshness_days
    );
    let _ = writeln!(
        markdown,
        "- Required fields: `{}`",
        artifact_requirements.required_fields.join("`, `")
    );
    if !artifact_requirements.machine_classes.is_empty() {
        let _ = writeln!(
            markdown,
            "- Machine classes: `{}`",
            artifact_requirements.machine_classes.join("`, `")
        );
    }
    if !artifact_requirements.host_roles.is_empty() {
        let _ = writeln!(
            markdown,
            "- Host roles: `{}`",
            artifact_requirements.host_roles.join("`, `")
        );
    }
    if artifact_requirements.thresholds.is_empty() {
        markdown.push_str("- Thresholds: none declared in manifest\n");
    } else {
        markdown.push_str("- Thresholds:\n");
        for (name, value) in &artifact_requirements.thresholds {
            let _ = writeln!(markdown, "  - `{name}` = `{value}`");
        }
    }
    markdown.push_str("\nRedaction checklist:\n");
    for item in redaction_checklist {
        let _ = writeln!(markdown, "- {item}");
    }
    markdown.push_str("\nFollow-up commands:\n");
    for command in follow_up_commands {
        let _ = writeln!(markdown, "- `{command}`");
    }
    markdown
}

fn ensure_redaction_safe(text: &str) -> Result<()> {
    let lower = text.to_ascii_lowercase();
    for needle in forbidden_text_markers() {
        if lower.contains(&needle) {
            bail!("proof request bundle contains forbidden material marker `{needle}`");
        }
    }
    if text.contains(&unix_home_marker("Users"))
        || lower.contains(&unix_home_marker("home"))
        || lower.contains(&windows_home_marker())
    {
        bail!("proof request bundle contains a user-home path");
    }
    for token in
        text.split(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '.' | ':' | '[' | ']')))
    {
        if token.is_empty() {
            continue;
        }
        if is_forbidden_ip_literal(token) {
            bail!("proof request bundle contains a private or local IP literal");
        }
    }
    Ok(())
}

fn forbidden_text_markers() -> Vec<String> {
    [
        scheme_marker("http"),
        scheme_marker("https"),
        scheme_marker("ssh"),
        scheme_marker("postgres"),
        scheme_marker("mysql"),
        header_marker("author", "ization"),
        spaced_marker("bear", "er"),
        header_marker("cook", "ie"),
        assignment_marker("pass", "word"),
        assignment_marker("tok", "en"),
    ]
    .into()
}

fn scheme_marker(scheme: &str) -> String {
    format!("{scheme}:{}", "//")
}

fn header_marker(prefix: &str, suffix: &str) -> String {
    format!("{prefix}{suffix}:")
}

fn spaced_marker(prefix: &str, suffix: &str) -> String {
    format!("{prefix}{suffix} ")
}

fn assignment_marker(prefix: &str, suffix: &str) -> String {
    format!("{prefix}{suffix}=")
}

fn unix_home_marker(segment: &str) -> String {
    format!("/{segment}/")
}

fn windows_home_marker() -> String {
    format!("{}{}{}{}{}", "c", ":", "\\", "users", "\\")
}

fn is_forbidden_ip_literal(value: &str) -> bool {
    if let Ok(ip) = Ipv4Addr::from_str(value) {
        return ip.is_private()
            || ip.is_loopback()
            || ip.is_link_local()
            || ip.is_unspecified()
            || (ip.octets()[0] == 100 && (64..=127).contains(&ip.octets()[1]));
    }
    if let Ok(ip) = Ipv6Addr::from_str(value) {
        return ip.is_loopback() || ip.is_unspecified() || is_unique_local_ipv6(&ip);
    }
    false
}

const fn is_unique_local_ipv6(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}
