//! Proof-readiness target inventory loading.
//!
//! This is the fail-closed source of truth for live proof prerequisites. It
//! deliberately validates redaction and blocked-bead links at load time so a
//! later reporting command cannot accidentally treat ambiguous evidence as
//! actionable proof.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const PROOF_READINESS_TARGETS_SCHEMA_VERSION: &str = "fcp.fwc.proof-readiness-targets.v1";
pub const PROOF_READINESS_REPORT_SCHEMA_VERSION: &str = "fcp.fwc.proof-readiness.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofReadinessTargetsManifest {
    pub schema_version: String,
    pub targets: Vec<ProofReadinessTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofReadinessTarget {
    pub target_id: String,
    pub title: String,
    pub blocked_beads: Vec<String>,
    pub artifact_schema: String,
    pub artifact_root: String,
    pub artifact_globs: Vec<String>,
    pub freshness_days: u32,
    pub machine_classes: Vec<String>,
    pub host_roles: Vec<String>,
    pub required_artifact_fields: Vec<String>,
    pub command_template: String,
    pub redaction_policy: Vec<String>,
    pub evidence_notes: Vec<String>,
    #[serde(default)]
    pub thresholds: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct ProofReadinessReportOptions {
    pub repo_root: PathBuf,
    pub now: SystemTime,
    pub generated_at: Option<String>,
    pub target_filter: Option<String>,
    pub only_missing: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProofReadinessStatus {
    Ready,
    MissingPrerequisites,
    PartiallyReady,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofReadinessReport {
    pub schema_version: String,
    pub status: ProofReadinessStatus,
    pub generated_at: String,
    pub targets: Vec<ProofReadinessTargetReport>,
    pub summary: ProofReadinessSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofReadinessTargetReport {
    pub target_id: String,
    pub blocked_beads: Vec<String>,
    pub status: ProofReadinessStatus,
    pub missing: Vec<MissingPrerequisite>,
    pub satisfied_artifacts: Vec<SatisfiedArtifact>,
    pub command: ProofReadinessCommand,
    pub redaction_notes: Vec<String>,
    pub next_actions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissingPrerequisite {
    pub kind: MissingPrerequisiteKind,
    pub id: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MissingPrerequisiteKind {
    Artifact,
    MachineClass,
    HostRole,
    Schema,
    Freshness,
    Threshold,
    Environment,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SatisfiedArtifact {
    pub path: String,
    pub schema_version: String,
    pub digest: String,
    pub machine_class: Option<String>,
    pub host_role: Option<String>,
    pub redacted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofReadinessCommand {
    pub argv_template: Vec<String>,
    pub requires_remote: bool,
    pub proof_class: ProofClass,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProofClass {
    RemoteCargo,
    LiveHost,
    OperatorScript,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofReadinessSummary {
    pub target_count: usize,
    pub ready_count: usize,
    pub missing_prerequisites_count: usize,
    pub partially_ready_count: usize,
    pub error_count: usize,
}

#[derive(Debug)]
struct ArtifactEvaluation {
    artifact: Option<SatisfiedArtifact>,
    missing: Vec<MissingPrerequisite>,
    host_roles: Vec<String>,
}

/// Loads and validates a proof-readiness target manifest from disk.
///
/// # Errors
///
/// Returns an error if the file cannot be read, the TOML cannot be parsed, or
/// the manifest fails proof-readiness validation.
pub fn load_targets_manifest(path: impl AsRef<Path>) -> Result<ProofReadinessTargetsManifest> {
    let path = path.as_ref();
    let text = fs::read_to_string(path).with_context(|| {
        format!(
            "reading proof-readiness target manifest `{}`",
            path.display()
        )
    })?;
    parse_targets_manifest_str(&text).with_context(|| {
        format!(
            "validating proof-readiness target manifest `{}`",
            path.display()
        )
    })
}

/// Parses and validates a proof-readiness target manifest from TOML text.
///
/// # Errors
///
/// Returns an error if the TOML cannot be parsed or the manifest fails
/// proof-readiness validation.
pub fn parse_targets_manifest_str(text: &str) -> Result<ProofReadinessTargetsManifest> {
    let manifest: ProofReadinessTargetsManifest =
        toml::from_str(text).context("parsing proof-readiness target TOML")?;
    validate_targets_manifest(&manifest)?;
    Ok(manifest)
}

/// Validates a parsed proof-readiness target manifest.
///
/// # Errors
///
/// Returns an error if the schema version, target inventory, blocked-bead
/// mapping, artifact paths, or redaction policy is invalid.
pub fn validate_targets_manifest(manifest: &ProofReadinessTargetsManifest) -> Result<()> {
    if manifest.schema_version != PROOF_READINESS_TARGETS_SCHEMA_VERSION {
        bail!(
            "unsupported proof-readiness target schema `{}`; expected `{}`",
            manifest.schema_version,
            PROOF_READINESS_TARGETS_SCHEMA_VERSION
        );
    }
    if manifest.targets.is_empty() {
        bail!("proof-readiness target manifest must contain at least one target");
    }

    let mut target_ids = BTreeSet::new();
    for target in &manifest.targets {
        validate_target(target)?;
        if !target_ids.insert(target.target_id.as_str()) {
            bail!("duplicate proof-readiness target `{}`", target.target_id);
        }
    }

    Ok(())
}

/// Builds a read-only proof-readiness report for a validated target manifest.
///
/// # Errors
///
/// Returns an error if a target filter names no configured target, or if the
/// filesystem scan cannot inspect a directory that exists under the configured
/// artifact root.
pub fn build_readiness_report(
    manifest: &ProofReadinessTargetsManifest,
    options: &ProofReadinessReportOptions,
) -> Result<ProofReadinessReport> {
    if let Some(target_filter) = &options.target_filter {
        if !manifest
            .targets
            .iter()
            .any(|target| target.target_id == *target_filter)
        {
            bail!("unknown proof-readiness target `{target_filter}`");
        }
    }

    let mut reports = Vec::new();
    for target in &manifest.targets {
        if options
            .target_filter
            .as_ref()
            .is_some_and(|filter| filter != &target.target_id)
        {
            continue;
        }
        reports.push(evaluate_target(target, options)?);
    }

    // Summary and aggregate status always describe the full evaluated set;
    // `only_missing` narrows only the listed targets. Filtering before
    // summarizing would report `ready_count: 0` for a fleet that is in fact
    // ready, misrepresenting overall readiness.
    let summary = summarize_targets(&reports);
    let status = aggregate_status(&summary);
    if options.only_missing {
        reports.retain(|report| report.status != ProofReadinessStatus::Ready);
    }
    Ok(ProofReadinessReport {
        schema_version: PROOF_READINESS_REPORT_SCHEMA_VERSION.to_owned(),
        status,
        generated_at: options
            .generated_at
            .clone()
            .unwrap_or_else(|| format_system_time(options.now)),
        targets: reports,
        summary,
    })
}

fn evaluate_target(
    target: &ProofReadinessTarget,
    options: &ProofReadinessReportOptions,
) -> Result<ProofReadinessTargetReport> {
    let mut missing = Vec::new();
    let mut satisfied_artifacts = Vec::new();
    let mut satisfied_machine_classes = BTreeSet::new();
    let mut satisfied_host_roles = BTreeSet::new();
    let mut artifact_failures = Vec::new();
    let mut matched_any_artifact = false;

    for path in matching_artifact_paths(&options.repo_root, target)? {
        matched_any_artifact = true;
        let evaluation = evaluate_artifact(target, &options.repo_root, &path, options.now);
        if let Some(artifact) = evaluation.artifact {
            if let Some(machine_class) = &artifact.machine_class {
                satisfied_machine_classes.insert(machine_class.clone());
            }
            for role in evaluation.host_roles {
                satisfied_host_roles.insert(role);
            }
            satisfied_artifacts.push(artifact);
        } else {
            artifact_failures.extend(evaluation.missing);
        }
    }

    if !matched_any_artifact {
        for glob in &target.artifact_globs {
            push_missing_once(
                &mut missing,
                MissingPrerequisiteKind::Artifact,
                glob.clone(),
                format!("No artifact matches `{glob}`."),
            );
        }
    } else if satisfied_artifacts.is_empty() {
        for failure in artifact_failures {
            push_missing_once(&mut missing, failure.kind, failure.id, failure.message);
        }
    }

    for machine_class in &target.machine_classes {
        if !satisfied_machine_classes.contains(machine_class) {
            push_missing_once(
                &mut missing,
                MissingPrerequisiteKind::MachineClass,
                machine_class.clone(),
                format!("No fresh artifact satisfies machine_class `{machine_class}`."),
            );
        }
    }

    for host_role in &target.host_roles {
        if !satisfied_host_roles.contains(host_role) {
            push_missing_once(
                &mut missing,
                MissingPrerequisiteKind::HostRole,
                host_role.clone(),
                format!("No fresh artifact covers host role `{host_role}`."),
            );
        }
    }

    let status = if missing.is_empty() {
        ProofReadinessStatus::Ready
    } else if satisfied_artifacts.is_empty() {
        ProofReadinessStatus::MissingPrerequisites
    } else {
        ProofReadinessStatus::PartiallyReady
    };

    let next_actions = next_actions(target, &status, &missing, &satisfied_artifacts);
    Ok(ProofReadinessTargetReport {
        target_id: target.target_id.clone(),
        blocked_beads: target.blocked_beads.clone(),
        status,
        missing,
        satisfied_artifacts,
        command: command_from_template(target),
        redaction_notes: redaction_notes(target),
        next_actions,
    })
}

fn matching_artifact_paths(
    repo_root: &Path,
    target: &ProofReadinessTarget,
) -> Result<Vec<PathBuf>> {
    let root = repo_root.join(&target.artifact_root);
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut candidates = Vec::new();
    collect_files(&root, &mut candidates)
        .with_context(|| format!("scanning proof artifact root `{}`", root.display()))?;
    candidates.sort();
    Ok(candidates
        .into_iter()
        .filter(|path| {
            let relative = repo_relative_path(repo_root, path);
            target
                .artifact_globs
                .iter()
                .any(|pattern| glob_matches(pattern, &relative))
        })
        .collect())
}

fn collect_files(root: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(root).with_context(|| format!("reading `{}`", root.display()))? {
        let entry = entry.with_context(|| format!("reading entry under `{}`", root.display()))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .with_context(|| format!("reading file type for `{}`", path.display()))?;
        if file_type.is_dir() {
            collect_files(&path, files)?;
        } else if file_type.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

struct ArtifactLoadFailure {
    kind: MissingPrerequisiteKind,
    id: String,
    message: String,
}

impl ArtifactLoadFailure {
    fn new(
        kind: MissingPrerequisiteKind,
        id: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            id: id.into(),
            message: message.into(),
        }
    }

    fn into_evaluation(self) -> ArtifactEvaluation {
        ArtifactEvaluation {
            artifact: None,
            missing: vec![missing(self.kind, self.id, self.message)],
            host_roles: Vec::new(),
        }
    }
}

fn load_redacted_artifact_json(
    path: &Path,
    display_path: &str,
) -> std::result::Result<(Vec<u8>, Value), ArtifactLoadFailure> {
    let bytes = fs::read(path).map_err(|error| {
        ArtifactLoadFailure::new(
            MissingPrerequisiteKind::Artifact,
            display_path,
            format!("Artifact could not be read: {error}."),
        )
    })?;

    let text = String::from_utf8_lossy(&bytes);
    if validate_redacted_string("artifact", &text).is_err() {
        return Err(ArtifactLoadFailure::new(
            MissingPrerequisiteKind::Artifact,
            display_path,
            "Artifact contains raw endpoint, credential-shaped, or user-local material.",
        ));
    }

    let value = serde_json::from_slice(&bytes).map_err(|error| {
        ArtifactLoadFailure::new(
            MissingPrerequisiteKind::Schema,
            display_path,
            format!("Artifact is not valid JSON: {error}."),
        )
    })?;
    Ok((bytes, value))
}

struct ArtifactRequirementEvaluation {
    missing_items: Vec<MissingPrerequisite>,
    schema_version: Option<String>,
    machine_class: Option<String>,
    host_roles: Vec<String>,
}

fn evaluate_artifact_requirements(
    target: &ProofReadinessTarget,
    path: &Path,
    display_path: &str,
    value: &Value,
    now: SystemTime,
) -> ArtifactRequirementEvaluation {
    let mut missing_items = Vec::new();
    for field in &target.required_artifact_fields {
        if !json_field_present(value, field) {
            missing_items.push(missing(
                MissingPrerequisiteKind::Schema,
                format!("{display_path}:{field}"),
                format!("Artifact is missing required field `{field}`."),
            ));
        }
    }

    let schema_version = json_string(value, "schema_version");
    if schema_version.as_deref() != Some(target.artifact_schema.as_str()) {
        missing_items.push(missing(
            MissingPrerequisiteKind::Schema,
            format!("{display_path}:schema_version"),
            format!(
                "Artifact schema must be `{}`; found `{}`.",
                target.artifact_schema,
                schema_version.as_deref().unwrap_or("<missing>")
            ),
        ));
    }

    if artifact_is_stale(path, now, target.freshness_days) {
        missing_items.push(missing(
            MissingPrerequisiteKind::Freshness,
            display_path.to_owned(),
            format!(
                "Artifact is older than the {} day freshness window.",
                target.freshness_days
            ),
        ));
    }

    let machine_class = json_string(value, "machine_class");
    if !target.machine_classes.is_empty()
        && machine_class
            .as_ref()
            .is_none_or(|class| !target.machine_classes.contains(class))
    {
        missing_items.push(missing(
            MissingPrerequisiteKind::MachineClass,
            format!("{display_path}:machine_class"),
            format!(
                "Artifact machine_class must be one of [{}].",
                target.machine_classes.join(", ")
            ),
        ));
    }

    let host_roles = json_string_array(value, "host_roles")
        .or_else(|| json_string(value, "host_role").map(|role| vec![role]))
        .unwrap_or_default();
    if !target.host_roles.is_empty() && host_roles.is_empty() {
        missing_items.push(missing(
            MissingPrerequisiteKind::HostRole,
            format!("{display_path}:host_roles"),
            "Artifact must name redacted host roles covered by the proof.".to_owned(),
        ));
    }

    for (name, expected) in &target.thresholds {
        match json_scalar_string(value, name) {
            Some(actual) if actual == *expected => {}
            Some(actual) => missing_items.push(missing(
                MissingPrerequisiteKind::Threshold,
                format!("{display_path}:{name}"),
                format!("Threshold `{name}` must be `{expected}`; found `{actual}`."),
            )),
            None => missing_items.push(missing(
                MissingPrerequisiteKind::Threshold,
                format!("{display_path}:{name}"),
                format!("Artifact is missing threshold field `{name}`."),
            )),
        }
    }

    ArtifactRequirementEvaluation {
        missing_items,
        schema_version,
        machine_class,
        host_roles,
    }
}

fn evaluate_artifact(
    target: &ProofReadinessTarget,
    repo_root: &Path,
    path: &Path,
    now: SystemTime,
) -> ArtifactEvaluation {
    let display_path = repo_relative_path(repo_root, path);
    let (bytes, value) = match load_redacted_artifact_json(path, &display_path) {
        Ok(loaded) => loaded,
        Err(failure) => return failure.into_evaluation(),
    };

    let requirement = evaluate_artifact_requirements(target, path, &display_path, &value, now);

    if !requirement.missing_items.is_empty() {
        return ArtifactEvaluation {
            artifact: None,
            missing: requirement.missing_items,
            host_roles: requirement.host_roles,
        };
    }

    ArtifactEvaluation {
        artifact: Some(SatisfiedArtifact {
            path: display_path,
            schema_version: requirement
                .schema_version
                .unwrap_or_else(|| target.artifact_schema.clone()),
            digest: format!("blake3:{}", hex::encode(blake3::hash(&bytes).as_bytes())),
            machine_class: requirement.machine_class,
            host_role: single_host_role_for_schema(&requirement.host_roles, target),
            redacted: true,
        }),
        missing: Vec::new(),
        host_roles: requirement.host_roles,
    }
}

fn artifact_is_stale(path: &Path, now: SystemTime, freshness_days: u32) -> bool {
    let max_age = Duration::from_secs(u64::from(freshness_days) * 24 * 60 * 60);

    // Prefer the generation date committed into the artifact path — proof
    // artifacts follow the `<class>-YYYY-MM-DD-<sha>.json` (and dated-directory)
    // convention. Filesystem mtime is not committed provenance: a fresh clone or
    // CI checkout resets every file's mtime to the checkout time, which would
    // make an arbitrarily old committed proof look freshly generated and
    // silently defeat the freshness gate. The path date travels with the
    // committed file and is immune to checkout.
    if let Some(generated) = generation_time_from_path(path) {
        // A future generation date cannot be trusted (skew/tamper); fail closed.
        return now
            .duration_since(generated)
            .map_or(true, |age| age > max_age);
    }

    // Fall back to filesystem mtime only when the path carries no date token.
    let Ok(metadata) = fs::metadata(path) else {
        return true;
    };
    let Ok(modified) = metadata.modified() else {
        return true;
    };
    // A modification time in the future means the artifact's timestamp cannot
    // be trusted (clock skew, copied or tampered file); fail closed like the
    // metadata-read failures above instead of treating it as fresh.
    now.duration_since(modified)
        .map_or(true, |age| age > max_age)
}

/// Extracts the generation date committed into a proof artifact's path,
/// returning the instant at UTC midnight of that day.
///
/// Proof/StatPack artifacts encode their generation date in the committed path
/// — either in the filename (`csd-2026-06-20-<sha>.json`) or in a dated parent
/// directory (`.../2026-06-20/...`). Unlike filesystem mtime, this survives a
/// git checkout unchanged. Path components are scanned from the filename
/// outward so the most specific date wins. Returns `None` when no `YYYY-MM-DD`
/// token is present.
fn generation_time_from_path(path: &Path) -> Option<SystemTime> {
    let mut components: Vec<String> = path
        .components()
        .filter_map(|component| component.as_os_str().to_str().map(str::to_owned))
        .collect();
    components.reverse();
    components
        .iter()
        .find_map(|component| date_token_to_time(component))
}

/// Parses the first `YYYY-MM-DD` token found in a single path component (after
/// splitting on `-`, `_`, and `.`) into a UTC-midnight instant.
fn date_token_to_time(component: &str) -> Option<SystemTime> {
    let parts: Vec<&str> = component.split(['-', '_', '.']).collect();
    for window in parts.windows(3) {
        let (year, month, day) = (window[0], window[1], window[2]);
        if year.len() == 4
            && month.len() == 2
            && day.len() == 2
            && [year, month, day]
                .iter()
                .all(|token| token.bytes().all(|byte| byte.is_ascii_digit()))
        {
            if let Ok(date) =
                chrono::NaiveDate::parse_from_str(&format!("{year}-{month}-{day}"), "%Y-%m-%d")
            {
                let seconds = date.and_hms_opt(0, 0, 0)?.and_utc().timestamp();
                let seconds = u64::try_from(seconds).ok()?;
                return Some(UNIX_EPOCH + Duration::from_secs(seconds));
            }
        }
    }
    None
}

fn json_field_present(value: &Value, field: &str) -> bool {
    field
        .split('.')
        .try_fold(value, |cursor, part| cursor.get(part))
        .is_some_and(|found| !found.is_null())
}

fn json_string(value: &Value, field: &str) -> Option<String> {
    value.get(field)?.as_str().map(ToOwned::to_owned)
}

fn json_string_array(value: &Value, field: &str) -> Option<Vec<String>> {
    Some(
        value
            .get(field)?
            .as_array()?
            .iter()
            .filter_map(|item| item.as_str().map(ToOwned::to_owned))
            .collect(),
    )
}

fn json_scalar_string(value: &Value, field: &str) -> Option<String> {
    let value = field
        .split('.')
        .try_fold(value, |cursor, part| cursor.get(part))?;
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn single_host_role_for_schema(
    host_roles: &[String],
    target: &ProofReadinessTarget,
) -> Option<String> {
    if host_roles.len() == 1 {
        return host_roles.first().cloned();
    }
    if target.host_roles.len() == 1 && host_roles.contains(&target.host_roles[0]) {
        return Some(target.host_roles[0].clone());
    }
    None
}

fn repo_relative_path(repo_root: &Path, path: &Path) -> String {
    path.strip_prefix(repo_root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn glob_matches(pattern: &str, text: &str) -> bool {
    glob_match_bytes(pattern.as_bytes(), text.as_bytes())
}

fn glob_match_bytes(pattern: &[u8], text: &[u8]) -> bool {
    match (pattern.first(), text.first()) {
        (None, None) => true,
        (Some(b'*'), _) => {
            glob_match_bytes(&pattern[1..], text)
                || (!text.is_empty() && glob_match_bytes(pattern, &text[1..]))
        }
        (Some(expected), Some(actual)) if expected == actual => {
            glob_match_bytes(&pattern[1..], &text[1..])
        }
        _ => false,
    }
}

fn command_from_template(target: &ProofReadinessTarget) -> ProofReadinessCommand {
    let proof_class = proof_class_for(target);
    let requires_remote = matches!(&proof_class, ProofClass::RemoteCargo);
    ProofReadinessCommand {
        argv_template: split_command_template(&target.command_template),
        requires_remote,
        proof_class,
    }
}

fn proof_class_for(target: &ProofReadinessTarget) -> ProofClass {
    if target.command_template.starts_with("cargo ")
        || target.command_template.contains(" cargo ")
        || target.command_template.starts_with("rch exec")
    {
        ProofClass::RemoteCargo
    } else if !target.host_roles.is_empty() {
        ProofClass::LiveHost
    } else {
        ProofClass::OperatorScript
    }
}

fn split_command_template(template: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut chars = template.chars().peekable();
    let mut quote: Option<char> = None;
    let mut in_angle_placeholder = false;

    while let Some(ch) = chars.next() {
        if let Some(quote_ch) = quote {
            if ch == quote_ch {
                quote = None;
            } else {
                current.push(ch);
            }
            continue;
        }

        match ch {
            '"' | '\'' => quote = Some(ch),
            '<' => {
                in_angle_placeholder = true;
                current.push(ch);
            }
            '>' if in_angle_placeholder => {
                in_angle_placeholder = false;
                current.push(ch);
            }
            c if c.is_whitespace() && !in_angle_placeholder => {
                if !current.is_empty() {
                    args.push(std::mem::take(&mut current));
                }
                while chars.peek().is_some_and(|next| next.is_whitespace()) {
                    chars.next();
                }
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        args.push(current);
    }
    args
}

fn redaction_notes(target: &ProofReadinessTarget) -> Vec<String> {
    let mut notes = target.redaction_policy.clone();
    notes.extend(target.evidence_notes.clone());
    notes
}

fn next_actions(
    target: &ProofReadinessTarget,
    status: &ProofReadinessStatus,
    missing: &[MissingPrerequisite],
    satisfied_artifacts: &[SatisfiedArtifact],
) -> Vec<String> {
    match status {
        ProofReadinessStatus::Ready => vec![format!(
            "Cite {} satisfied artifact(s) for `{}` before unblocking {}.",
            satisfied_artifacts.len(),
            target.target_id,
            target.blocked_beads.join(", ")
        )],
        ProofReadinessStatus::PartiallyReady => vec![
            format!(
                "Keep the satisfied artifacts and collect the remaining {} prerequisite(s).",
                missing.len()
            ),
            format!(
                "Run or request the redaction-safe proof command for `{}`.",
                target.target_id
            ),
        ],
        ProofReadinessStatus::MissingPrerequisites => vec![format!(
            "Create a redaction-safe artifact matching `{}`.",
            target.artifact_globs.join("` or `")
        )],
        ProofReadinessStatus::Error => vec![format!(
            "Fix the proof-readiness target configuration for `{}`.",
            target.target_id
        )],
    }
}

fn summarize_targets(targets: &[ProofReadinessTargetReport]) -> ProofReadinessSummary {
    ProofReadinessSummary {
        target_count: targets.len(),
        ready_count: targets
            .iter()
            .filter(|target| target.status == ProofReadinessStatus::Ready)
            .count(),
        missing_prerequisites_count: targets
            .iter()
            .filter(|target| target.status == ProofReadinessStatus::MissingPrerequisites)
            .count(),
        partially_ready_count: targets
            .iter()
            .filter(|target| target.status == ProofReadinessStatus::PartiallyReady)
            .count(),
        error_count: targets
            .iter()
            .filter(|target| target.status == ProofReadinessStatus::Error)
            .count(),
    }
}

const fn aggregate_status(summary: &ProofReadinessSummary) -> ProofReadinessStatus {
    if summary.error_count > 0 {
        ProofReadinessStatus::Error
    } else if summary.partially_ready_count > 0 {
        ProofReadinessStatus::PartiallyReady
    } else if summary.missing_prerequisites_count > 0 {
        ProofReadinessStatus::MissingPrerequisites
    } else {
        ProofReadinessStatus::Ready
    }
}

fn push_missing_once(
    missing_items: &mut Vec<MissingPrerequisite>,
    kind: MissingPrerequisiteKind,
    id: String,
    message: String,
) {
    if !missing_items
        .iter()
        .any(|item| item.kind == kind && item.id == id)
    {
        missing_items.push(MissingPrerequisite { kind, id, message });
    }
}

fn missing(
    kind: MissingPrerequisiteKind,
    id: impl Into<String>,
    message: impl Into<String>,
) -> MissingPrerequisite {
    MissingPrerequisite {
        kind,
        id: id.into(),
        message: message.into(),
    }
}

fn format_system_time(time: SystemTime) -> String {
    let datetime: DateTime<Utc> = time.into();
    datetime.to_rfc3339_opts(SecondsFormat::Secs, true)
}

#[must_use]
pub fn system_time_from_unix_secs(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

fn validate_target(target: &ProofReadinessTarget) -> Result<()> {
    validate_identifier("target_id", &target.target_id)?;
    validate_non_empty_string("title", &target.title)?;
    validate_non_empty_string("artifact_schema", &target.artifact_schema)?;
    validate_relative_artifact_path("artifact_root", &target.artifact_root)?;
    validate_non_empty_string("command_template", &target.command_template)?;
    validate_redacted_string("command_template", &target.command_template)?;

    if target.blocked_beads.is_empty() {
        bail!(
            "proof-readiness target `{}` must name at least one blocked bead",
            target.target_id
        );
    }
    for bead in &target.blocked_beads {
        validate_blocked_bead(&target.target_id, bead)?;
    }

    if target.artifact_globs.is_empty() {
        bail!(
            "proof-readiness target `{}` must name at least one artifact glob",
            target.target_id
        );
    }
    for glob in &target.artifact_globs {
        validate_relative_artifact_path("artifact_globs", glob)?;
        validate_redacted_string("artifact_globs", glob)?;
    }

    if target.freshness_days == 0 {
        bail!(
            "proof-readiness target `{}` must require a positive freshness window",
            target.target_id
        );
    }

    if target.required_artifact_fields.is_empty() {
        bail!(
            "proof-readiness target `{}` must name required artifact fields",
            target.target_id
        );
    }
    for field in &target.required_artifact_fields {
        validate_non_empty_string("required_artifact_fields", field)?;
    }

    if target.redaction_policy.is_empty() {
        bail!(
            "proof-readiness target `{}` must declare a redaction policy",
            target.target_id
        );
    }
    for policy in &target.redaction_policy {
        validate_non_empty_string("redaction_policy", policy)?;
    }

    for machine_class in &target.machine_classes {
        validate_non_empty_string("machine_classes", machine_class)?;
        validate_redacted_string("machine_classes", machine_class)?;
    }
    for host_role in &target.host_roles {
        validate_non_empty_string("host_roles", host_role)?;
        validate_redacted_string("host_roles", host_role)?;
    }
    for note in &target.evidence_notes {
        validate_non_empty_string("evidence_notes", note)?;
        validate_redacted_string("evidence_notes", note)?;
    }
    for (name, value) in &target.thresholds {
        validate_identifier("threshold name", name)?;
        validate_non_empty_string("threshold value", value)?;
        validate_redacted_string("threshold value", value)?;
    }

    Ok(())
}

fn validate_identifier(field: &str, value: &str) -> Result<()> {
    validate_non_empty_string(field, value)?;
    let valid = value
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
        && value
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    if !valid {
        bail!("{field} `{value}` must be lowercase ASCII, digits, '_' or '-'");
    }
    Ok(())
}

fn validate_blocked_bead(target_id: &str, bead: &str) -> Result<()> {
    validate_non_empty_string("blocked_beads", bead)?;
    if !bead.starts_with("flywheel_connectors-") {
        bail!("target `{target_id}` has invalid blocked bead `{bead}`");
    }
    if !bead
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!("target `{target_id}` has blocked bead with invalid characters `{bead}`");
    }
    Ok(())
}

fn validate_relative_artifact_path(field: &str, value: &str) -> Result<()> {
    validate_non_empty_string(field, value)?;
    if value.starts_with('/') || value.starts_with('~') || value.contains("..") {
        bail!("{field} `{value}` must be a repo-relative artifact path");
    }
    Ok(())
}

fn validate_non_empty_string(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("{field} must not be empty");
    }
    validate_redacted_string(field, value)
}

fn validate_redacted_string(field: &str, value: &str) -> Result<()> {
    let lower = value.to_ascii_lowercase();
    if lower.contains("http://")
        || lower.contains("https://")
        || lower.contains("ssh://")
        || lower.contains("postgres://")
        || lower.contains("mysql://")
    {
        bail!("{field} contains a raw endpoint; use a placeholder or hash instead");
    }
    if lower.contains("localhost") || lower.contains("authorization:") || lower.contains("bearer ")
    {
        bail!("{field} contains sensitive runtime material; redact it before committing");
    }
    if lower.contains("cookie:") || lower.contains("password=") || lower.contains("token=") {
        bail!("{field} contains credential-shaped material; redact it before committing");
    }
    if lower.contains("/users/") || lower.contains("/home/") || lower.contains("\\users\\") {
        bail!("{field} contains a user-home path; use a repo-relative placeholder");
    }
    for candidate in ip_candidates(value) {
        if let Ok(ip) = candidate.parse::<IpAddr>() {
            if disallowed_ip(ip) {
                bail!("{field} contains raw private or local endpoint `{candidate}`");
            }
        }
    }
    Ok(())
}

fn ip_candidates(value: &str) -> impl Iterator<Item = &str> {
    value
        .split(|c: char| !(c.is_ascii_hexdigit() || matches!(c, '.' | ':')))
        .map(|part| part.trim_matches(':'))
        .filter(|part| part.contains('.') || part.contains(':'))
}

fn disallowed_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(addr) => disallowed_ipv4(addr),
        IpAddr::V6(addr) => disallowed_ipv6(addr),
    }
}

fn disallowed_ipv4(addr: Ipv4Addr) -> bool {
    let [first, second, _, _] = addr.octets();
    addr.is_private()
        || addr.is_loopback()
        || addr.is_link_local()
        || addr.is_unspecified()
        || (first == 100 && (64..=127).contains(&second))
}

const fn disallowed_ipv6(addr: Ipv6Addr) -> bool {
    addr.is_loopback()
        || addr.is_unspecified()
        || addr.is_unique_local()
        || addr.is_unicast_link_local()
}
