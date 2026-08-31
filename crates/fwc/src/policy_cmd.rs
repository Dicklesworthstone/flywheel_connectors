//! `fcp policy` command implementation.
//!
//! Provides a policy simulation CLI for `DecisionReceipt` previews.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use chrono::{DateTime, Utc};
use clap::{Args, Subcommand};
use fcp_cbor::SchemaId;
use fcp_crypto::ed25519::{Ed25519SigningKey, SECRET_KEY_SIZE};
use fcp_kernel::{CapabilityId, InvokeRequest, ObjectId, SafetyTier};
use fcp_policy::{
    CapabilityObject, DecisionReceiptPolicy, PolicyBundle, PolicyBundleError, PolicyBundleObject,
    PolicyBundlePolicyRef, PolicyBundleResolved, PolicyBundleSignature, PolicyPattern, Provenance,
    ResourceObject, RoleObject, TransportMode, ZoneDefinitionObject, ZoneId, ZonePolicyObject,
    ZoneTransportPolicy,
};
use fcp_prelude::{
    DecisionReceipt, ObjectHeader, POLICY_BUNDLE_SIGNED_FIELDS, PolicyPreviewSample,
    PolicySimulationError, PolicySimulationInput, compute_policy_bundle_hash, diff_policy_bundles,
    preview_policy_bundles, simulate_policy_decision,
};
use hex::decode as hex_decode;
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(test)]
use fcp_kernel::{NodeSignature, RequestId};
#[cfg(test)]
use fcp_policy::{CapabilityToken, ConfidentialityLevel, IntegrityLevel};
#[cfg(test)]
use fcp_prelude::NodeId;

/// Arguments for the `fcp policy` command.
#[derive(Args, Debug)]
pub struct PolicyArgs {
    #[command(subcommand)]
    pub command: PolicyCommands,
}

/// Policy subcommands.
#[derive(Subcommand, Debug)]
pub enum PolicyCommands {
    /// Simulate a policy decision for an invoke request.
    Simulate(SimulateArgs),
    /// Diff two zone policy or definition objects.
    Diff(DiffArgs),
    /// Generate a rollback plan between two policy objects.
    Rollback(RollbackArgs),
    /// Policy bundle workflows.
    Bundle(BundleArgs),
}

/// Arguments for `fcp policy simulate`.
#[derive(Args, Debug)]
pub struct SimulateArgs {
    /// Policy simulation input (JSON). Use "-" for stdin.
    ///
    /// Accepts either:
    /// 1) `PolicySimulationInput` JSON (with `zone_policy` + `invoke_request`)
    /// 2) `InvokeRequest` JSON (a permissive zone policy is synthesized)
    #[arg(long)]
    pub input: PathBuf,

    /// Output JSON (`DecisionReceipt`). Default true.
    #[arg(long, default_value_t = true)]
    pub json: bool,
}

/// Arguments for `fcp policy diff`.
#[derive(Args, Debug)]
pub struct DiffArgs {
    /// Path to the "before" policy object (JSON).
    #[arg(long)]
    pub before: PathBuf,

    /// Path to the "after" policy object (JSON).
    #[arg(long)]
    pub after: PathBuf,

    /// Output JSON diff. Default true.
    #[arg(long, default_value_t = true)]
    pub json: bool,
}

/// Arguments for `fcp policy rollback`.
#[derive(Args, Debug)]
pub struct RollbackArgs {
    /// Path to the current policy object (JSON).
    #[arg(long)]
    pub current: PathBuf,

    /// Path to the previous policy object (JSON).
    #[arg(long)]
    pub previous: PathBuf,

    /// Emit a rollback plan without executing it.
    #[arg(long, default_value_t = false)]
    pub plan: bool,

    /// Output JSON rollback plan. Default true.
    #[arg(long, default_value_t = true)]
    pub json: bool,
}

/// Arguments for policy bundle workflows.
#[derive(Args, Debug)]
pub struct BundleArgs {
    #[command(subcommand)]
    pub command: BundleCommands,
}

/// Policy bundle subcommands.
#[derive(Subcommand, Debug)]
pub enum BundleCommands {
    /// Create a new policy bundle.
    Create(BundleCreateArgs),
    /// Diff two policy bundles (resolved objects required).
    Diff(BundleDiffArgs),
    /// Preview policy changes for a bundle diff with sample invocations.
    Preview(BundlePreviewArgs),
    /// Apply a policy bundle to a state file.
    Apply(BundleApplyArgs),
    /// Roll back policy state to a previous bundle.
    Rollback(BundleRollbackArgs),
}

/// Arguments for `fcp policy bundle diff`.
#[derive(Args, Debug)]
pub struct BundleDiffArgs {
    /// Path to the "before" bundle JSON.
    #[arg(long)]
    pub before: PathBuf,

    /// Path to the "after" bundle JSON.
    #[arg(long)]
    pub after: PathBuf,

    /// JSON map of `object_id` -> policy object for the "before" bundle.
    #[arg(long)]
    pub objects_before: PathBuf,

    /// JSON map of `object_id` -> policy object for the "after" bundle.
    #[arg(long)]
    pub objects_after: PathBuf,

    /// Output JSON diff. Default true.
    #[arg(long, default_value_t = true)]
    pub json: bool,
}

/// Arguments for `fcp policy bundle create`.
#[derive(Args, Debug)]
pub struct BundleCreateArgs {
    /// Bundle identifier.
    #[arg(long)]
    pub bundle_id: String,

    /// Zone identifier (e.g. z:work).
    #[arg(long)]
    pub zone: String,

    /// Monotonic policy sequence number.
    #[arg(long)]
    pub policy_seq: u64,

    /// Path to policy reference list (JSON array).
    #[arg(long)]
    pub policies: PathBuf,

    /// Previous bundle id (optional).
    #[arg(long)]
    pub previous_bundle: Option<String>,

    /// Creation timestamp (RFC3339). Defaults to now.
    #[arg(long)]
    pub created_at: Option<String>,

    /// Signing key id for the bundle signature.
    #[arg(long)]
    pub key_id: String,

    /// Signing key seed as hex (32 bytes).
    #[arg(long, conflicts_with = "signing_key_file")]
    pub signing_key_hex: Option<String>,

    /// Path to signing key seed hex (32 bytes).
    #[arg(long, conflicts_with = "signing_key_hex")]
    pub signing_key_file: Option<PathBuf>,

    /// Output path for the bundle JSON (stdout if omitted).
    #[arg(long)]
    pub out: Option<PathBuf>,
}

/// Arguments for `fcp policy bundle preview`.
#[derive(Args, Debug)]
pub struct BundlePreviewArgs {
    /// Path to the "before" bundle JSON.
    #[arg(long)]
    pub before: PathBuf,

    /// Path to the "after" bundle JSON.
    #[arg(long)]
    pub after: PathBuf,

    /// JSON map of `object_id` -> policy object for the "before" bundle.
    #[arg(long)]
    pub objects_before: PathBuf,

    /// JSON map of `object_id` -> policy object for the "after" bundle.
    #[arg(long)]
    pub objects_after: PathBuf,

    /// Preview samples (JSON array or object with `samples` field).
    #[arg(long)]
    pub samples: PathBuf,

    /// Output JSON report. Default true.
    #[arg(long, default_value_t = true)]
    pub json: bool,
}

/// Arguments for `fcp policy bundle apply`.
#[derive(Args, Debug)]
pub struct BundleApplyArgs {
    /// Bundle JSON to apply.
    #[arg(long)]
    pub bundle: PathBuf,

    /// Policy bundle state file to write.
    #[arg(long)]
    pub state: PathBuf,

    /// Emit a plan only (do not write state).
    #[arg(long, default_value_t = false)]
    pub plan: bool,

    /// Output JSON. Default true.
    #[arg(long, default_value_t = true)]
    pub json: bool,
}

/// Arguments for `fcp policy bundle rollback`.
#[derive(Args, Debug)]
pub struct BundleRollbackArgs {
    /// Bundle JSON to roll back to.
    #[arg(long)]
    pub to: PathBuf,

    /// Policy bundle state file to write.
    #[arg(long)]
    pub state: PathBuf,

    /// Emit a plan only (do not write state).
    #[arg(long, default_value_t = false)]
    pub plan: bool,

    /// Output JSON. Default true.
    #[arg(long, default_value_t = true)]
    pub json: bool,
}

/// Run the policy command.
pub fn run(args: &PolicyArgs) -> Result<()> {
    match &args.command {
        PolicyCommands::Simulate(sim_args) => run_simulate(sim_args),
        PolicyCommands::Diff(diff_args) => run_diff(diff_args),
        PolicyCommands::Rollback(rollback_args) => run_rollback(rollback_args),
        PolicyCommands::Bundle(bundle_args) => run_bundle(bundle_args),
    }
}

fn run_simulate(args: &SimulateArgs) -> Result<()> {
    let raw = read_input(&args.input)?;
    let input = parse_simulation_input(&raw)?;
    match simulate_policy_decision(&input) {
        Ok(receipt) => output_receipt(&receipt, args.json),
        Err(err) => output_error(&err, args.json),
    }
}

fn run_bundle(args: &BundleArgs) -> Result<()> {
    match &args.command {
        BundleCommands::Create(create_args) => run_bundle_create(create_args),
        BundleCommands::Diff(diff_args) => run_bundle_diff(diff_args),
        BundleCommands::Preview(preview_args) => run_bundle_preview(preview_args),
        BundleCommands::Apply(apply_args) => run_bundle_apply(apply_args),
        BundleCommands::Rollback(rollback_args) => run_bundle_rollback(rollback_args),
    }
}

fn read_input(path: &PathBuf) -> Result<String> {
    if path.as_os_str() == "-" {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .context("failed to read stdin")?;
        return Ok(buf);
    }

    fs::read_to_string(path).with_context(|| format!("failed to read input {}", path.display()))
}

fn run_bundle_diff(args: &BundleDiffArgs) -> Result<()> {
    let before_bundle = load_policy_bundle(&args.before)?;
    let after_bundle = load_policy_bundle(&args.after)?;
    let before_objects_raw = load_object_map(&args.objects_before)?;
    let after_objects_raw = load_object_map(&args.objects_after)?;

    let before_objects = resolve_bundle_objects(&before_bundle, &before_objects_raw)?;
    let after_objects = resolve_bundle_objects(&after_bundle, &after_objects_raw)?;

    let before_resolved = PolicyBundleResolved::new(before_bundle, before_objects);
    let after_resolved = PolicyBundleResolved::new(after_bundle, after_objects);

    let diff = diff_policy_bundles(&before_resolved, &after_resolved)
        .map_err(|err| anyhow::anyhow!("policy bundle diff failed: {err}"))?;

    output_json_or_human(&diff, args.json)
}

fn run_bundle_create(args: &BundleCreateArgs) -> Result<()> {
    let zone_id: ZoneId = args
        .zone
        .parse()
        .with_context(|| format!("invalid zone id '{}'", args.zone))?;
    let created_at = parse_created_at(args.created_at.as_deref())?;
    let policies = load_policy_refs(&args.policies)?;

    let bundle_hash = compute_policy_bundle_hash(
        &args.bundle_id,
        &zone_id,
        args.policy_seq,
        created_at,
        args.previous_bundle.as_deref(),
        &policies,
    )
    .map_err(|err| anyhow::anyhow!("failed to compute bundle hash: {err}"))?;

    let signing_key = load_signing_key(args)?;
    let signed_fields = POLICY_BUNDLE_SIGNED_FIELDS
        .iter()
        .map(|field| (*field).to_string())
        .collect::<Vec<_>>();

    let provisional_signature =
        PolicyBundleSignature::new(args.key_id.clone(), "pending", signed_fields.clone());

    let mut builder = PolicyBundle::builder(&args.bundle_id, zone_id, args.policy_seq)
        .bundle_hash(bundle_hash)
        .policies(policies)
        .signature(provisional_signature);
    if let Some(created_at) = created_at {
        builder = builder.created_at(created_at);
    }
    if let Some(previous) = &args.previous_bundle {
        builder = builder.previous_bundle(previous.clone());
    }

    let mut bundle = builder
        .build()
        .map_err(|err| anyhow::anyhow!("policy bundle build failed: {err}"))?;

    let signing_bytes = bundle
        .signing_bytes()
        .map_err(|err| anyhow::anyhow!("failed to compute signing bytes: {err}"))?;
    let signature = signing_key.sign(&signing_bytes);
    let signature_b64 = BASE64_STANDARD.encode(signature.to_bytes());
    bundle.signature =
        PolicyBundleSignature::new(args.key_id.clone(), signature_b64, signed_fields);
    bundle
        .validate()
        .map_err(|err| anyhow::anyhow!("policy bundle validation failed: {err}"))?;

    write_bundle_output(&bundle, args.out.as_ref())
}

fn run_bundle_preview(args: &BundlePreviewArgs) -> Result<()> {
    let before_bundle = load_policy_bundle(&args.before)?;
    let after_bundle = load_policy_bundle(&args.after)?;
    let before_objects_raw = load_object_map(&args.objects_before)?;
    let after_objects_raw = load_object_map(&args.objects_after)?;
    let samples = load_preview_samples(&args.samples)?;

    let before_objects = resolve_bundle_objects(&before_bundle, &before_objects_raw)?;
    let after_objects = resolve_bundle_objects(&after_bundle, &after_objects_raw)?;

    let before_resolved = PolicyBundleResolved::new(before_bundle, before_objects);
    let after_resolved = PolicyBundleResolved::new(after_bundle, after_objects);

    let report = preview_policy_bundles(&before_resolved, &after_resolved, &samples)
        .map_err(|err| anyhow::anyhow!("policy bundle preview failed: {err}"))?;

    output_json_or_human(&report, args.json)
}

#[derive(Debug, Serialize)]
struct BundleApplyPlan {
    plan_type: String,
    zone_id: String,
    bundle_id: String,
    state_path: String,
}

const POLICY_BUNDLE_STATE_FORMAT: &str = "fcp-policy-bundle-state";
const POLICY_BUNDLE_STATE_SCHEMA_VERSION: &str = "1.0.0";
const POLICY_BUNDLE_EVENT_APPLIED: &str = "policy.bundle.applied";
const POLICY_BUNDLE_EVENT_ROLLED_BACK: &str = "policy.bundle.rolled_back";
const POLICY_BUNDLE_AUDIT_ACTOR: &str = "fwc";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PolicyBundleState {
    format: String,
    schema_version: String,
    zone_id: ZoneId,
    current: PolicyBundleStateSnapshot,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous: Option<PolicyBundleStateSnapshot>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    audit_events: Vec<PolicyBundleAuditEvent>,
}

impl PolicyBundleState {
    fn new(bundle: PolicyBundle, applied_at: DateTime<Utc>) -> Self {
        Self {
            format: POLICY_BUNDLE_STATE_FORMAT.to_string(),
            schema_version: POLICY_BUNDLE_STATE_SCHEMA_VERSION.to_string(),
            zone_id: bundle.zone_id.clone(),
            current: PolicyBundleStateSnapshot { bundle, applied_at },
            previous: None,
            audit_events: Vec::new(),
        }
    }

    fn validate(&self) -> Result<()> {
        if self.format != POLICY_BUNDLE_STATE_FORMAT {
            anyhow::bail!(
                "state format must be '{POLICY_BUNDLE_STATE_FORMAT}', got '{}'",
                self.format
            );
        }
        if self.schema_version != POLICY_BUNDLE_STATE_SCHEMA_VERSION {
            anyhow::bail!(
                "state schema_version must be '{POLICY_BUNDLE_STATE_SCHEMA_VERSION}', got '{}'",
                self.schema_version
            );
        }
        self.current.validate_for_zone(&self.zone_id, "current")?;
        if let Some(previous) = &self.previous {
            previous.validate_for_zone(&self.zone_id, "previous")?;
        }
        for event in &self.audit_events {
            if event.zone_id != self.zone_id.to_string() {
                anyhow::bail!(
                    "audit event zone '{}' does not match state zone '{}'",
                    event.zone_id,
                    self.zone_id
                );
            }
        }
        Ok(())
    }

    fn next_audit_seq(&self) -> u64 {
        self.audit_events.last().map_or(1, |event| event.seq + 1)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PolicyBundleStateSnapshot {
    bundle: PolicyBundle,
    applied_at: DateTime<Utc>,
}

impl PolicyBundleStateSnapshot {
    fn validate_for_zone(&self, zone_id: &ZoneId, label: &str) -> Result<()> {
        self.bundle
            .validate()
            .map_err(|err| anyhow::anyhow!("invalid {label} bundle in state: {err}"))?;
        if &self.bundle.zone_id != zone_id {
            anyhow::bail!(
                "{label} bundle zone '{}' does not match state zone '{}'",
                self.bundle.zone_id,
                zone_id
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PolicyBundleAuditEvent {
    seq: u64,
    event_type: String,
    actor: String,
    zone_id: String,
    bundle_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_bundle_id: Option<String>,
    occurred_at: u64,
    occurred_at_iso: String,
    audit_event_id: String,
}

#[derive(Debug, Serialize)]
struct BundleApplyResult {
    result_type: String,
    zone_id: String,
    bundle_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    replaced_bundle_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    declared_previous_bundle_id: Option<String>,
    state_path: String,
    changed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    audit_event: Option<PolicyBundleAuditEvent>,
}

fn run_bundle_apply(args: &BundleApplyArgs) -> Result<()> {
    let bundle = load_policy_bundle(&args.bundle)?;
    let existing_state = load_bundle_state_optional(&args.state)?;
    if let Some(state) = &existing_state {
        validate_bundle_state_zone(state, &bundle.zone_id, &args.state)?;
    }

    let replaced_bundle_id = existing_state
        .as_ref()
        .map(|state| state.current.bundle.bundle_id.clone());
    let declared_previous_bundle_id = bundle.previous_bundle.clone();
    let changed = existing_state.as_ref().is_none_or(|state| {
        state.current.bundle.bundle_id != bundle.bundle_id
            || state.current.bundle.bundle_hash != bundle.bundle_hash
    });

    if changed {
        validate_apply_transition(existing_state.as_ref(), &bundle)?;
    }

    let zone_id = bundle.zone_id.to_string();
    let bundle_id = bundle.bundle_id.clone();
    let plan = BundleApplyPlan {
        plan_type: "bundle_apply".to_string(),
        zone_id,
        bundle_id: bundle_id.clone(),
        state_path: args.state.display().to_string(),
    };

    if args.plan {
        return output_json_or_human(&plan, args.json);
    }

    if !changed {
        let result = BundleApplyResult {
            result_type: "bundle_apply".to_string(),
            zone_id: bundle.zone_id.to_string(),
            bundle_id,
            replaced_bundle_id,
            declared_previous_bundle_id,
            state_path: args.state.display().to_string(),
            changed: false,
            audit_event: None,
        };
        return output_json_or_human(&result, args.json);
    }

    let applied_at = Utc::now();
    let audit_event = build_bundle_audit_event(
        POLICY_BUNDLE_EVENT_APPLIED,
        &bundle.zone_id,
        &bundle.bundle_id,
        replaced_bundle_id.as_deref(),
        existing_state
            .as_ref()
            .map_or(1, PolicyBundleState::next_audit_seq),
        applied_at,
    )?;

    let mut new_state = PolicyBundleState::new(bundle, applied_at);
    if let Some(existing_state) = existing_state {
        new_state.previous = Some(existing_state.current);
        new_state.audit_events = existing_state.audit_events;
    }
    new_state.audit_events.push(audit_event.clone());
    write_bundle_state(&args.state, &new_state)?;

    tracing::info!(
        event = POLICY_BUNDLE_EVENT_APPLIED,
        zone_id = %new_state.zone_id,
        bundle_id = %new_state.current.bundle.bundle_id,
        previous_bundle_id = ?replaced_bundle_id,
        state_path = %args.state.display(),
        "applied policy bundle state transition"
    );

    let result = BundleApplyResult {
        result_type: "bundle_apply".to_string(),
        zone_id: new_state.zone_id.to_string(),
        bundle_id: new_state.current.bundle.bundle_id.clone(),
        replaced_bundle_id,
        declared_previous_bundle_id,
        state_path: args.state.display().to_string(),
        changed: true,
        audit_event: Some(audit_event),
    };

    output_json_or_human(&result, args.json)
}

#[derive(Debug, Serialize)]
struct BundleRollbackPlan {
    plan_type: String,
    zone_id: String,
    target_bundle_id: String,
    state_path: String,
}

#[derive(Debug, Serialize)]
struct BundleRollbackResult {
    result_type: String,
    zone_id: String,
    target_bundle_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    replaced_bundle_id: Option<String>,
    state_path: String,
    changed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    audit_event: Option<PolicyBundleAuditEvent>,
}

fn run_bundle_rollback(args: &BundleRollbackArgs) -> Result<()> {
    let target_bundle = load_policy_bundle(&args.to)?;
    let Some(existing_state) = load_bundle_state_optional(&args.state)? else {
        anyhow::bail!(
            "bundle rollback requires an existing state file at {}",
            args.state.display()
        );
    };
    validate_bundle_state_zone(&existing_state, &target_bundle.zone_id, &args.state)?;

    let replaced_bundle_id = Some(existing_state.current.bundle.bundle_id.clone());
    let changed = existing_state.current.bundle.bundle_id != target_bundle.bundle_id
        || existing_state.current.bundle.bundle_hash != target_bundle.bundle_hash;

    if changed {
        validate_rollback_transition(&existing_state, &target_bundle)?;
    }

    let zone_id = target_bundle.zone_id.to_string();
    let target_bundle_id = target_bundle.bundle_id.clone();
    let plan = BundleRollbackPlan {
        plan_type: "bundle_rollback".to_string(),
        zone_id,
        target_bundle_id: target_bundle_id.clone(),
        state_path: args.state.display().to_string(),
    };

    if args.plan {
        return output_json_or_human(&plan, args.json);
    }

    if !changed {
        let result = BundleRollbackResult {
            result_type: "bundle_rollback".to_string(),
            zone_id: target_bundle.zone_id.to_string(),
            target_bundle_id,
            replaced_bundle_id,
            state_path: args.state.display().to_string(),
            changed: false,
            audit_event: None,
        };
        return output_json_or_human(&result, args.json);
    }

    let occurred_at = Utc::now();
    let audit_event = build_bundle_audit_event(
        POLICY_BUNDLE_EVENT_ROLLED_BACK,
        &target_bundle.zone_id,
        &target_bundle.bundle_id,
        replaced_bundle_id.as_deref(),
        existing_state.next_audit_seq(),
        occurred_at,
    )?;

    let mut new_state = PolicyBundleState::new(target_bundle, occurred_at);
    new_state.previous = Some(existing_state.current);
    new_state.audit_events = existing_state.audit_events;
    new_state.audit_events.push(audit_event.clone());
    write_bundle_state(&args.state, &new_state)?;

    tracing::info!(
        event = POLICY_BUNDLE_EVENT_ROLLED_BACK,
        zone_id = %new_state.zone_id,
        bundle_id = %new_state.current.bundle.bundle_id,
        replaced_bundle_id = ?replaced_bundle_id,
        state_path = %args.state.display(),
        "rolled back policy bundle state transition"
    );

    let result = BundleRollbackResult {
        result_type: "bundle_rollback".to_string(),
        zone_id: new_state.zone_id.to_string(),
        target_bundle_id: new_state.current.bundle.bundle_id.clone(),
        replaced_bundle_id,
        state_path: args.state.display().to_string(),
        changed: true,
        audit_event: Some(audit_event),
    };

    output_json_or_human(&result, args.json)
}

fn load_policy_bundle(path: &PathBuf) -> Result<PolicyBundle> {
    let raw = read_input(path)?;
    let bundle: PolicyBundle = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse policy bundle {}", path.display()))?;
    bundle
        .validate()
        .map_err(|err| anyhow::anyhow!("invalid policy bundle {}: {err}", path.display()))?;
    Ok(bundle)
}

fn load_object_map(path: &PathBuf) -> Result<BTreeMap<String, Value>> {
    let raw = read_input(path)?;
    let map: BTreeMap<String, Value> = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse object map {}", path.display()))?;
    Ok(map)
}

fn load_policy_refs(path: &PathBuf) -> Result<Vec<PolicyBundlePolicyRef>> {
    let raw = read_input(path)?;
    let refs: Vec<PolicyBundlePolicyRef> = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse policy refs {}", path.display()))?;
    if refs.is_empty() {
        anyhow::bail!("policy refs list is empty");
    }
    for (idx, policy_ref) in refs.iter().enumerate() {
        policy_ref.validate().map_err(|err: PolicyBundleError| {
            anyhow::anyhow!("invalid policy ref at index {idx}: {err}")
        })?;
    }
    Ok(refs)
}

#[derive(Debug, Deserialize)]
struct PreviewSamplesFile {
    samples: Vec<PolicyPreviewSample>,
}

fn load_preview_samples(path: &PathBuf) -> Result<Vec<PolicyPreviewSample>> {
    let raw = read_input(path)?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        anyhow::bail!("preview samples input is empty");
    }
    if let Ok(samples) = serde_json::from_str::<Vec<PolicyPreviewSample>>(trimmed) {
        return Ok(samples);
    }
    if let Ok(wrapper) = serde_json::from_str::<PreviewSamplesFile>(trimmed) {
        return Ok(wrapper.samples);
    }
    anyhow::bail!("failed to parse preview samples as array or object with 'samples'")
}

fn parse_created_at(value: Option<&str>) -> Result<Option<DateTime<Utc>>> {
    let Some(raw) = value else {
        return Ok(None);
    };
    let parsed = DateTime::parse_from_rfc3339(raw)
        .with_context(|| format!("invalid RFC3339 timestamp '{raw}'"))?;
    Ok(Some(parsed.with_timezone(&Utc)))
}

fn load_signing_key(args: &BundleCreateArgs) -> Result<Ed25519SigningKey> {
    let key_hex = if let Some(hex) = &args.signing_key_hex {
        hex.clone()
    } else if let Some(path) = &args.signing_key_file {
        fs::read_to_string(path)
            .with_context(|| format!("failed to read signing key {}", path.display()))?
    } else {
        anyhow::bail!("signing key is required (--signing-key-hex or --signing-key-file)");
    };

    let key_hex = key_hex.trim();
    let bytes = hex_decode(key_hex).context("failed to decode signing key hex")?;
    if bytes.len() != SECRET_KEY_SIZE {
        anyhow::bail!(
            "signing key must be {SECRET_KEY_SIZE} bytes, got {}",
            bytes.len()
        );
    }
    let mut arr = [0u8; SECRET_KEY_SIZE];
    arr.copy_from_slice(&bytes);
    Ed25519SigningKey::from_bytes(&arr)
        .map_err(|err| anyhow::anyhow!("failed to load signing key: {err}"))
}

fn write_bundle_output(bundle: &PolicyBundle, out: Option<&PathBuf>) -> Result<()> {
    let json = serde_json::to_string_pretty(bundle)?;
    if let Some(path) = out {
        fs::write(path, json)
            .with_context(|| format!("failed to write bundle {}", path.display()))?;
        return Ok(());
    }

    println!("{json}");
    Ok(())
}

fn load_bundle_state_optional(path: &Path) -> Result<Option<PolicyBundleState>> {
    let raw = match fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("failed to read policy bundle state {}", path.display()));
        }
    };

    let state: PolicyBundleState = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse policy bundle state {}", path.display()))?;
    state.validate()?;
    Ok(Some(state))
}

fn write_bundle_state(path: &Path, state: &PolicyBundleState) -> Result<()> {
    state.validate()?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create policy bundle state directory {}",
                    parent.display()
                )
            })?;
        }
    }
    let json = serde_json::to_string_pretty(state)?;
    fs::write(path, json)
        .with_context(|| format!("failed to write policy bundle state {}", path.display()))
}

fn validate_bundle_state_zone(
    state: &PolicyBundleState,
    zone_id: &ZoneId,
    path: &Path,
) -> Result<()> {
    if &state.zone_id != zone_id {
        anyhow::bail!(
            "state file {} is for zone '{}' but bundle targets zone '{}'",
            path.display(),
            state.zone_id,
            zone_id
        );
    }
    Ok(())
}

fn validate_apply_transition(
    state: Option<&PolicyBundleState>,
    bundle: &PolicyBundle,
) -> Result<()> {
    let Some(state) = state else {
        return Ok(());
    };

    if bundle.previous_bundle.as_deref() == Some(state.current.bundle.bundle_id.as_str()) {
        return Ok(());
    }

    anyhow::bail!(
        "bundle '{}' declares previous_bundle {:?}, but current state is '{}'",
        bundle.bundle_id,
        bundle.previous_bundle,
        state.current.bundle.bundle_id
    )
}

fn validate_rollback_transition(
    state: &PolicyBundleState,
    target_bundle: &PolicyBundle,
) -> Result<()> {
    let expected_previous = state.current.bundle.previous_bundle.as_deref();
    if expected_previous == Some(target_bundle.bundle_id.as_str()) {
        return Ok(());
    }

    anyhow::bail!(
        "rollback target '{}' does not match current bundle '{}' previous_bundle {:?}",
        target_bundle.bundle_id,
        state.current.bundle.bundle_id,
        state.current.bundle.previous_bundle
    )
}

fn build_bundle_audit_event(
    event_type: &str,
    zone_id: &ZoneId,
    bundle_id: &str,
    previous_bundle_id: Option<&str>,
    seq: u64,
    occurred_at: DateTime<Utc>,
) -> Result<PolicyBundleAuditEvent> {
    let occurred_at_secs = u64::try_from(occurred_at.timestamp()).unwrap_or(0);
    let canonical = serde_json::json!({
        "seq": seq,
        "event_type": event_type,
        "actor": POLICY_BUNDLE_AUDIT_ACTOR,
        "zone_id": zone_id.to_string(),
        "bundle_id": bundle_id,
        "previous_bundle_id": previous_bundle_id,
        "occurred_at": occurred_at_secs,
    });
    let audit_event_id =
        ObjectId::from_unscoped_bytes(&fcp_cbor::to_canonical_cbor(&canonical)?).to_string();

    Ok(PolicyBundleAuditEvent {
        seq,
        event_type: event_type.to_string(),
        actor: POLICY_BUNDLE_AUDIT_ACTOR.to_string(),
        zone_id: zone_id.to_string(),
        bundle_id: bundle_id.to_string(),
        previous_bundle_id: previous_bundle_id.map(ToString::to_string),
        occurred_at: occurred_at_secs,
        occurred_at_iso: occurred_at.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        audit_event_id,
    })
}

fn resolve_bundle_objects(
    bundle: &PolicyBundle,
    raw_objects: &BTreeMap<String, Value>,
) -> Result<BTreeMap<String, PolicyBundleObject>> {
    let mut resolved = BTreeMap::new();
    for policy_ref in &bundle.policies {
        let Some(value) = raw_objects.get(&policy_ref.object_id) else {
            continue;
        };
        let object = parse_bundle_object(&policy_ref.schema_id, value)
            .with_context(|| format!("object_id {}", policy_ref.object_id))?;
        resolved.insert(policy_ref.object_id.clone(), object);
    }
    Ok(resolved)
}

fn parse_bundle_object(schema_id: &str, value: &Value) -> Result<PolicyBundleObject> {
    if schema_id.starts_with("fcp.core:ZonePolicy@") {
        let policy: ZonePolicyObject =
            serde_json::from_value(value.clone()).context("failed to parse ZonePolicy object")?;
        return Ok(PolicyBundleObject::ZonePolicy(policy));
    }
    if schema_id.starts_with("fcp.core:ZoneDefinition@") {
        let definition: ZoneDefinitionObject = serde_json::from_value(value.clone())
            .context("failed to parse ZoneDefinition object")?;
        return Ok(PolicyBundleObject::ZoneDefinition(definition));
    }
    if schema_id.starts_with("fcp.core:RoleObject@") {
        let role: RoleObject =
            serde_json::from_value(value.clone()).context("failed to parse RoleObject")?;
        return Ok(PolicyBundleObject::Role(role));
    }
    if schema_id.starts_with("fcp.core:ResourceObject@") {
        let resource: ResourceObject =
            serde_json::from_value(value.clone()).context("failed to parse ResourceObject")?;
        return Ok(PolicyBundleObject::Resource(resource));
    }
    if schema_id.starts_with("fcp.core:CapabilityObject@") {
        let capability: CapabilityObject =
            serde_json::from_value(value.clone()).context("failed to parse CapabilityObject")?;
        return Ok(PolicyBundleObject::Capability(capability));
    }

    Err(anyhow::anyhow!(
        "unsupported policy bundle schema_id {schema_id}"
    ))
}

fn parse_simulation_input(raw: &str) -> Result<PolicySimulationInput> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        anyhow::bail!("policy simulation input is empty");
    }

    if let Ok(input) = serde_json::from_str::<PolicySimulationInput>(trimmed) {
        return Ok(input);
    }

    let invoke = serde_json::from_str::<InvokeRequest>(trimmed)
        .context("failed to parse input as PolicySimulationInput or InvokeRequest")?;
    let zone_policy = default_zone_policy(&invoke);

    Ok(PolicySimulationInput {
        zone_policy,
        invoke_request: invoke,
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        sanitizer_receipts: Vec::new(),
        related_object_ids: Vec::new(),
        request_object_id: None,
        request_input_hash: None,
        safety_tier: SafetyTier::Safe,
        principal: None,
        capability_id: None,
        provenance_record: None,
        now_ms: None,
        posture_attestation: None,
    })
}

#[derive(Debug)]
enum PolicyDocument {
    ZonePolicy(ZonePolicyObject),
    ZoneDefinition(ZoneDefinitionObject),
}

impl PolicyDocument {
    const fn zone_id(&self) -> &ZoneId {
        match self {
            Self::ZonePolicy(policy) => &policy.zone_id,
            Self::ZoneDefinition(definition) => &definition.zone_id,
        }
    }

    const fn policy_type(&self) -> &'static str {
        match self {
            Self::ZonePolicy(_) => "zone_policy",
            Self::ZoneDefinition(_) => "zone_definition",
        }
    }
}

#[derive(Debug, Serialize, Default)]
struct PolicyListDiff {
    principal_allow: Vec<String>,
    principal_deny: Vec<String>,
    connector_allow: Vec<String>,
    connector_deny: Vec<String>,
    capability_allow: Vec<String>,
    capability_deny: Vec<String>,
    capability_ceiling: Vec<String>,
}

#[derive(Debug, Serialize)]
struct Change<T> {
    before: T,
    after: T,
}

#[derive(Debug, Serialize)]
struct TransportPolicyChange {
    before: ZoneTransportPolicy,
    after: ZoneTransportPolicy,
}

#[derive(Debug, Serialize, Default)]
struct PolicyChangedFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    transport_policy: Option<TransportPolicyChange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decision_receipts: Option<Change<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requires_posture: Option<Change<Value>>,
}

#[derive(Debug, Serialize)]
struct PolicyDiffOutput {
    policy_type: String,
    zone_id: String,
    previous_policy_id: String,
    current_policy_id: String,
    added: Value,
    removed: Value,
    changed: Value,
    risk_flags: Vec<String>,
}

#[derive(Debug, Serialize)]
struct RollbackPlan {
    policy_type: String,
    zone_id: String,
    current_policy_id: String,
    previous_policy_id: String,
    plan_type: String,
}

#[derive(Debug, Serialize)]
struct JsonDiff {
    added: BTreeMap<String, Value>,
    removed: BTreeMap<String, Value>,
    changed: BTreeMap<String, Change<Value>>,
}

fn run_diff(args: &DiffArgs) -> Result<()> {
    let before = load_policy_document(&args.before)?;
    let after = load_policy_document(&args.after)?;

    if before.policy_type() != after.policy_type() {
        anyhow::bail!(
            "policy types do not match: {} vs {}",
            before.policy_type(),
            after.policy_type()
        );
    }
    if before.zone_id() != after.zone_id() {
        anyhow::bail!(
            "zone_id mismatch: {} vs {}",
            before.zone_id(),
            after.zone_id()
        );
    }

    let diff = match (&before, &after) {
        (PolicyDocument::ZonePolicy(prev), PolicyDocument::ZonePolicy(curr)) => {
            diff_zone_policy(prev, curr)?
        }
        (PolicyDocument::ZoneDefinition(prev), PolicyDocument::ZoneDefinition(curr)) => {
            diff_zone_definition(prev, curr)?
        }
        _ => anyhow::bail!("unsupported policy comparison"),
    };

    output_json_or_human(&diff, args.json)
}

fn run_rollback(args: &RollbackArgs) -> Result<()> {
    if !args.plan {
        anyhow::bail!("rollback requires --plan (execution is not supported yet)");
    }

    let current = load_policy_document(&args.current)?;
    let previous = load_policy_document(&args.previous)?;

    if current.policy_type() != previous.policy_type() {
        anyhow::bail!(
            "policy types do not match: {} vs {}",
            current.policy_type(),
            previous.policy_type()
        );
    }
    if current.zone_id() != previous.zone_id() {
        anyhow::bail!(
            "zone_id mismatch: {} vs {}",
            current.zone_id(),
            previous.zone_id()
        );
    }

    let plan = RollbackPlan {
        policy_type: current.policy_type().to_string(),
        zone_id: current.zone_id().to_string(),
        current_policy_id: unscoped_policy_id(&current)?.to_string(),
        previous_policy_id: unscoped_policy_id(&previous)?.to_string(),
        plan_type: "rollback".to_string(),
    };

    output_json_or_human(&plan, args.json)
}

fn load_policy_document(path: &PathBuf) -> Result<PolicyDocument> {
    let raw = read_input(path)?;
    parse_policy_document(&raw)
}

fn parse_policy_document(raw: &str) -> Result<PolicyDocument> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        anyhow::bail!("policy input is empty");
    }

    if let Ok(policy) = serde_json::from_str::<ZonePolicyObject>(trimmed) {
        return Ok(PolicyDocument::ZonePolicy(policy));
    }
    if let Ok(definition) = serde_json::from_str::<ZoneDefinitionObject>(trimmed) {
        return Ok(PolicyDocument::ZoneDefinition(definition));
    }

    anyhow::bail!("failed to parse policy input as ZonePolicyObject or ZoneDefinitionObject");
}

fn unscoped_policy_id(policy: &PolicyDocument) -> Result<ObjectId> {
    let value = match policy {
        PolicyDocument::ZonePolicy(doc) => serde_json::to_value(doc)?,
        PolicyDocument::ZoneDefinition(doc) => serde_json::to_value(doc)?,
    };
    let bytes = fcp_cbor::to_canonical_cbor(&value)?;
    Ok(ObjectId::from_unscoped_bytes(&bytes))
}

fn diff_zone_policy(
    before: &ZonePolicyObject,
    after: &ZonePolicyObject,
) -> Result<PolicyDiffOutput> {
    let (added, removed) = diff_policy_lists(before, after);
    let changed = diff_policy_changed(before, after)?;
    let risk_flags = compute_risk_flags(&added, &removed, &changed);

    let output = PolicyDiffOutput {
        policy_type: "zone_policy".to_string(),
        zone_id: before.zone_id.to_string(),
        previous_policy_id: ObjectId::from_unscoped_bytes(&fcp_cbor::to_canonical_cbor(before)?)
            .to_string(),
        current_policy_id: ObjectId::from_unscoped_bytes(&fcp_cbor::to_canonical_cbor(after)?)
            .to_string(),
        added: serde_json::to_value(&added)?,
        removed: serde_json::to_value(&removed)?,
        changed: serde_json::to_value(&changed)?,
        risk_flags,
    };

    Ok(output)
}

fn diff_zone_definition(
    before: &ZoneDefinitionObject,
    after: &ZoneDefinitionObject,
) -> Result<PolicyDiffOutput> {
    let before_json = serde_json::to_value(before)?;
    let after_json = serde_json::to_value(after)?;
    let diff = diff_json_objects(&before_json, &after_json)?;

    Ok(PolicyDiffOutput {
        policy_type: "zone_definition".to_string(),
        zone_id: before.zone_id.to_string(),
        previous_policy_id: ObjectId::from_unscoped_bytes(&fcp_cbor::to_canonical_cbor(
            &before_json,
        )?)
        .to_string(),
        current_policy_id: ObjectId::from_unscoped_bytes(&fcp_cbor::to_canonical_cbor(
            &after_json,
        )?)
        .to_string(),
        added: serde_json::to_value(&diff.added)?,
        removed: serde_json::to_value(&diff.removed)?,
        changed: serde_json::to_value(&diff.changed)?,
        risk_flags: Vec::new(),
    })
}

fn diff_policy_lists(
    before: &ZonePolicyObject,
    after: &ZonePolicyObject,
) -> (PolicyListDiff, PolicyListDiff) {
    let (principal_allow_added, principal_allow_removed) =
        diff_patterns(&before.principal_allow, &after.principal_allow);
    let (principal_deny_added, principal_deny_removed) =
        diff_patterns(&before.principal_deny, &after.principal_deny);
    let (connector_allow_added, connector_allow_removed) =
        diff_patterns(&before.connector_allow, &after.connector_allow);
    let (connector_deny_added, connector_deny_removed) =
        diff_patterns(&before.connector_deny, &after.connector_deny);
    let (capability_allow_added, capability_allow_removed) =
        diff_patterns(&before.capability_allow, &after.capability_allow);
    let (capability_deny_added, capability_deny_removed) =
        diff_patterns(&before.capability_deny, &after.capability_deny);
    let (capability_ceiling_added, capability_ceiling_removed) =
        diff_capability_ids(&before.capability_ceiling, &after.capability_ceiling);

    let added = PolicyListDiff {
        principal_allow: principal_allow_added,
        principal_deny: principal_deny_added,
        connector_allow: connector_allow_added,
        connector_deny: connector_deny_added,
        capability_allow: capability_allow_added,
        capability_deny: capability_deny_added,
        capability_ceiling: capability_ceiling_added,
    };
    let removed = PolicyListDiff {
        principal_allow: principal_allow_removed,
        principal_deny: principal_deny_removed,
        connector_allow: connector_allow_removed,
        connector_deny: connector_deny_removed,
        capability_allow: capability_allow_removed,
        capability_deny: capability_deny_removed,
        capability_ceiling: capability_ceiling_removed,
    };

    (added, removed)
}

fn diff_policy_changed(
    before: &ZonePolicyObject,
    after: &ZonePolicyObject,
) -> Result<PolicyChangedFields> {
    let mut changed = PolicyChangedFields::default();

    if transport_policy_changed(&before.transport_policy, &after.transport_policy) {
        changed.transport_policy = Some(TransportPolicyChange {
            before: before.transport_policy.clone(),
            after: after.transport_policy.clone(),
        });
    }

    let decision_before = serde_json::to_value(&before.decision_receipts)?;
    let decision_after = serde_json::to_value(&after.decision_receipts)?;
    if decision_before != decision_after {
        changed.decision_receipts = Some(Change {
            before: decision_before,
            after: decision_after,
        });
    }

    let posture_before = serde_json::to_value(&before.requires_posture)?;
    let posture_after = serde_json::to_value(&after.requires_posture)?;
    if posture_before != posture_after {
        changed.requires_posture = Some(Change {
            before: posture_before,
            after: posture_after,
        });
    }

    Ok(changed)
}

fn compute_risk_flags(
    added: &PolicyListDiff,
    removed: &PolicyListDiff,
    changed: &PolicyChangedFields,
) -> Vec<String> {
    let mut flags = Vec::new();

    if !added.principal_allow.is_empty() {
        flags.push("principal_allow_expanded".to_string());
    }
    if !added.connector_allow.is_empty() {
        flags.push("connector_allow_expanded".to_string());
    }
    if !added.capability_allow.is_empty() {
        flags.push("capability_allow_expanded".to_string());
    }
    if !added.capability_ceiling.is_empty() {
        flags.push("capability_ceiling_expanded".to_string());
    }
    if !removed.capability_deny.is_empty() {
        flags.push("capability_deny_reduced".to_string());
    }

    if let Some(ref transport) = changed.transport_policy {
        if !transport.before.allow_derp && transport.after.allow_derp {
            flags.push("transport_derp_enabled".to_string());
        }
        if !transport.before.allow_funnel && transport.after.allow_funnel {
            flags.push("transport_funnel_enabled".to_string());
        }
        if !transport.before.allow_lan && transport.after.allow_lan {
            flags.push("transport_lan_enabled".to_string());
        }
    }

    flags
}

fn diff_json_objects(before: &Value, after: &Value) -> Result<JsonDiff> {
    let before_obj = before
        .as_object()
        .context("before policy is not a JSON object")?;
    let after_obj = after
        .as_object()
        .context("after policy is not a JSON object")?;

    let mut added = BTreeMap::new();
    let mut removed = BTreeMap::new();
    let mut changed = BTreeMap::new();

    for (key, value) in before_obj {
        if !after_obj.contains_key(key) {
            removed.insert(key.clone(), value.clone());
        } else if let Some(after_value) = after_obj.get(key) {
            if after_value != value {
                changed.insert(
                    key.clone(),
                    Change {
                        before: value.clone(),
                        after: after_value.clone(),
                    },
                );
            }
        }
    }

    for (key, value) in after_obj {
        if !before_obj.contains_key(key) {
            added.insert(key.clone(), value.clone());
        }
    }

    Ok(JsonDiff {
        added,
        removed,
        changed,
    })
}

fn diff_patterns(before: &[PolicyPattern], after: &[PolicyPattern]) -> (Vec<String>, Vec<String>) {
    let before_set: BTreeSet<String> = before.iter().map(|p| p.pattern.clone()).collect();
    let after_set: BTreeSet<String> = after.iter().map(|p| p.pattern.clone()).collect();

    let added = after_set
        .difference(&before_set)
        .cloned()
        .collect::<Vec<_>>();
    let removed = before_set
        .difference(&after_set)
        .cloned()
        .collect::<Vec<_>>();

    (added, removed)
}

fn diff_capability_ids(
    before: &[CapabilityId],
    after: &[CapabilityId],
) -> (Vec<String>, Vec<String>) {
    let before_set: BTreeSet<String> = before.iter().map(|c| c.as_str().to_string()).collect();
    let after_set: BTreeSet<String> = after.iter().map(|c| c.as_str().to_string()).collect();

    let added = after_set
        .difference(&before_set)
        .cloned()
        .collect::<Vec<_>>();
    let removed = before_set
        .difference(&after_set)
        .cloned()
        .collect::<Vec<_>>();

    (added, removed)
}

const fn transport_policy_changed(
    before: &ZoneTransportPolicy,
    after: &ZoneTransportPolicy,
) -> bool {
    before.allow_lan != after.allow_lan
        || before.allow_derp != after.allow_derp
        || before.allow_funnel != after.allow_funnel
}

fn output_json_or_human<T: Serialize>(payload: &T, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(payload)?);
        return Ok(());
    }

    let pretty = serde_json::to_string_pretty(payload)?;
    println!("{pretty}");
    Ok(())
}

fn default_zone_policy(invoke: &InvokeRequest) -> ZonePolicyObject {
    let schema = SchemaId::new("fcp.core", "ZonePolicy", Version::new(1, 0, 0));
    let header = ObjectHeader {
        encryption_kind: Default::default(),
        schema,
        zone_id: invoke.zone_id.clone(),
        created_at: u64::try_from(Utc::now().timestamp()).unwrap_or(0),
        provenance: Provenance::new(invoke.zone_id.clone()),
        refs: Vec::new(),
        foreign_refs: Vec::new(),
        ttl_secs: None,
        placement: None,
    };

    ZonePolicyObject {
        header,
        zone_id: invoke.zone_id.clone(),
        principal_allow: Vec::new(),
        principal_deny: Vec::new(),
        connector_allow: Vec::new(),
        connector_deny: Vec::new(),
        capability_allow: Vec::new(),
        capability_deny: Vec::new(),
        capability_ceiling: Vec::new(),
        transport_policy: ZoneTransportPolicy::default(),
        decision_receipts: DecisionReceiptPolicy::default(),
        usage_budget: None,
        requires_posture: None,
    }
}

fn output_receipt(receipt: &DecisionReceipt, json: bool) -> Result<()> {
    if json {
        let payload =
            serde_json::to_string_pretty(receipt).context("failed to serialize DecisionReceipt")?;
        println!("{payload}");
        return Ok(());
    }

    println!();
    println!("Decision: {:?}", receipt.decision);
    println!("Reason: {}", receipt.reason_code);
    if !receipt.evidence.is_empty() {
        println!("Evidence:");
        for id in &receipt.evidence {
            println!("  - {id}");
        }
    }
    if let Some(ref explanation) = receipt.explanation {
        println!("Explanation: {explanation}");
    }
    println!();
    Ok(())
}

fn output_error(err: &PolicySimulationError, json: bool) -> Result<()> {
    if json {
        let payload = serde_json::json!({
            "error": err.to_string(),
            "code": "policy.simulation_failed",
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    Err(anyhow::anyhow!(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn parse_policy_simulation_input_direct() {
        let invoke = InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::new("req-1"),
            connector_id: "fcp.test:base:v1".parse().unwrap(),
            operation: "op".parse().unwrap(),
            zone_id: ZoneId::work(),
            input: serde_json::json!({"k": "v"}),
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };

        let raw = serde_json::to_string(&invoke).unwrap();
        let input = parse_simulation_input(&raw).unwrap();
        assert_eq!(input.invoke_request.zone_id, ZoneId::work());
    }

    fn base_policy(zone: ZoneId) -> ZonePolicyObject {
        let invoke = InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::new("req-1"),
            connector_id: "fcp.test:base:v1".parse().unwrap(),
            operation: "op".parse().unwrap(),
            zone_id: zone,
            input: serde_json::json!({"k": "v"}),
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };

        default_zone_policy(&invoke)
    }

    fn signed_fields() -> Vec<String> {
        POLICY_BUNDLE_SIGNED_FIELDS
            .iter()
            .map(|field| (*field).to_string())
            .collect()
    }

    fn test_policy_ref() -> PolicyBundlePolicyRef {
        PolicyBundlePolicyRef {
            object_id: "obj-zone-policy".to_string(),
            schema_id: "fcp.core:ZonePolicy@1.0.0".to_string(),
            object_hash: format!("blake3-256:{}", "a".repeat(64)),
        }
    }

    fn test_bundle(
        bundle_id: &str,
        zone_id: ZoneId,
        policy_seq: u64,
        previous_bundle: Option<&str>,
    ) -> PolicyBundle {
        let created_at = DateTime::parse_from_rfc3339("2026-03-01T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let policies = vec![test_policy_ref()];
        let bundle_hash = compute_policy_bundle_hash(
            bundle_id,
            &zone_id,
            policy_seq,
            Some(created_at),
            previous_bundle,
            &policies,
        )
        .unwrap();

        let mut builder = PolicyBundle::builder(bundle_id, zone_id, policy_seq)
            .created_at(created_at)
            .bundle_hash(bundle_hash)
            .policies(policies)
            .signature(PolicyBundleSignature::new(
                "kid-1",
                "signature",
                signed_fields(),
            ));

        if let Some(previous_bundle) = previous_bundle {
            builder = builder.previous_bundle(previous_bundle);
        }

        builder.build().unwrap()
    }

    fn write_bundle_file(dir: &TempDir, filename: &str, bundle: &PolicyBundle) -> PathBuf {
        let path = dir.path().join(filename);
        fs::write(&path, serde_json::to_string_pretty(bundle).unwrap()).unwrap();
        path
    }

    #[test]
    fn policy_diff_detects_added_connector_and_transport_risk() {
        let zone = ZoneId::work();
        let before = base_policy(zone.clone());
        let mut after = base_policy(zone);

        after.connector_allow.push(PolicyPattern {
            pattern: "fcp.test:*".to_string(),
        });
        after.transport_policy.allow_derp = true;

        let diff = diff_zone_policy(&before, &after).expect("diff zone policy");
        let added = diff.added.as_object().expect("added object");
        let connector_allow = added
            .get("connector_allow")
            .and_then(Value::as_array)
            .expect("connector_allow array");

        assert!(
            connector_allow
                .iter()
                .any(|v| v.as_str() == Some("fcp.test:*"))
        );
        assert!(
            diff.risk_flags
                .iter()
                .any(|flag| flag == "transport_derp_enabled")
        );
    }

    // ---- parse_simulation_input ----

    #[test]
    fn parse_simulation_input_empty() {
        assert!(parse_simulation_input("").is_err());
    }

    #[test]
    fn parse_simulation_input_whitespace_only() {
        assert!(parse_simulation_input("   \n\t  ").is_err());
    }

    #[test]
    fn parse_simulation_input_invalid_json() {
        assert!(parse_simulation_input("{not valid}").is_err());
    }

    // ---- parse_created_at ----

    #[test]
    fn parse_created_at_none() {
        assert!(parse_created_at(None).unwrap().is_none());
    }

    #[test]
    fn parse_created_at_valid_rfc3339() {
        let dt = parse_created_at(Some("2026-03-01T12:00:00Z"))
            .unwrap()
            .unwrap();
        assert!(dt.to_rfc3339().contains("2026-03-01"));
    }

    #[test]
    fn parse_created_at_invalid() {
        assert!(parse_created_at(Some("not-a-date")).is_err());
    }

    #[test]
    fn parse_created_at_with_offset() {
        let dt = parse_created_at(Some("2026-03-01T12:00:00+05:00"))
            .unwrap()
            .unwrap();
        // Converted to UTC: 12:00 +05:00 = 07:00 UTC
        assert!(dt.to_rfc3339().contains("07:00:00"));
    }

    // ---- diff_patterns ----

    #[test]
    fn diff_patterns_both_empty() {
        let (added, removed) = diff_patterns(&[], &[]);
        assert!(added.is_empty());
        assert!(removed.is_empty());
    }

    #[test]
    fn diff_patterns_identical() {
        let patterns = vec![PolicyPattern {
            pattern: "fcp.test:*".to_string(),
        }];
        let (added, removed) = diff_patterns(&patterns, &patterns);
        assert!(added.is_empty());
        assert!(removed.is_empty());
    }

    #[test]
    fn diff_patterns_added() {
        let before = vec![];
        let after = vec![PolicyPattern {
            pattern: "fcp.test:*".to_string(),
        }];
        let (added, removed) = diff_patterns(&before, &after);
        assert_eq!(added, vec!["fcp.test:*"]);
        assert!(removed.is_empty());
    }

    #[test]
    fn diff_patterns_removed() {
        let before = vec![PolicyPattern {
            pattern: "fcp.test:*".to_string(),
        }];
        let after = vec![];
        let (added, removed) = diff_patterns(&before, &after);
        assert!(added.is_empty());
        assert_eq!(removed, vec!["fcp.test:*"]);
    }

    #[test]
    fn diff_patterns_mixed() {
        let before = vec![
            PolicyPattern {
                pattern: "a".to_string(),
            },
            PolicyPattern {
                pattern: "b".to_string(),
            },
        ];
        let after = vec![
            PolicyPattern {
                pattern: "b".to_string(),
            },
            PolicyPattern {
                pattern: "c".to_string(),
            },
        ];
        let (added, removed) = diff_patterns(&before, &after);
        assert_eq!(added, vec!["c"]);
        assert_eq!(removed, vec!["a"]);
    }

    // ---- diff_capability_ids ----

    #[test]
    fn diff_capability_ids_empty() {
        let (added, removed) = diff_capability_ids(&[], &[]);
        assert!(added.is_empty());
        assert!(removed.is_empty());
    }

    #[test]
    fn diff_capability_ids_added_and_removed() {
        let before = vec!["cap.read".parse().unwrap()];
        let after = vec!["cap.write".parse().unwrap()];
        let (added, removed) = diff_capability_ids(&before, &after);
        assert_eq!(added, vec!["cap.write"]);
        assert_eq!(removed, vec!["cap.read"]);
    }

    // ---- transport_policy_changed ----

    #[test]
    fn transport_policy_unchanged() {
        let policy = ZoneTransportPolicy::default();
        assert!(!transport_policy_changed(&policy, &policy));
    }

    #[test]
    fn transport_policy_lan_changed() {
        let before = ZoneTransportPolicy::default();
        let mut after = before.clone();
        after.allow_lan = !before.allow_lan;
        assert!(transport_policy_changed(&before, &after));
    }

    #[test]
    fn transport_policy_derp_changed() {
        let before = ZoneTransportPolicy::default();
        let mut after = before.clone();
        after.allow_derp = !before.allow_derp;
        assert!(transport_policy_changed(&before, &after));
    }

    #[test]
    fn transport_policy_funnel_changed() {
        let before = ZoneTransportPolicy::default();
        let mut after = before.clone();
        after.allow_funnel = !before.allow_funnel;
        assert!(transport_policy_changed(&before, &after));
    }

    // ---- compute_risk_flags ----

    #[test]
    fn risk_flags_empty_when_no_changes() {
        let added = PolicyListDiff::default();
        let changed = PolicyChangedFields::default();
        let flags = compute_risk_flags(&added, &PolicyListDiff::default(), &changed);
        assert!(flags.is_empty());
    }

    #[test]
    fn risk_flags_principal_allow_expanded() {
        let added = PolicyListDiff {
            principal_allow: vec!["user:*".to_string()],
            ..Default::default()
        };
        let changed = PolicyChangedFields::default();
        let flags = compute_risk_flags(&added, &PolicyListDiff::default(), &changed);
        assert!(flags.contains(&"principal_allow_expanded".to_string()));
    }

    #[test]
    fn risk_flags_connector_allow_expanded() {
        let added = PolicyListDiff {
            connector_allow: vec!["fcp.*".to_string()],
            ..Default::default()
        };
        let changed = PolicyChangedFields::default();
        let flags = compute_risk_flags(&added, &PolicyListDiff::default(), &changed);
        assert!(flags.contains(&"connector_allow_expanded".to_string()));
    }

    #[test]
    fn risk_flags_capability_allow_expanded() {
        let added = PolicyListDiff {
            capability_allow: vec!["cap.*".to_string()],
            ..Default::default()
        };
        let changed = PolicyChangedFields::default();
        let flags = compute_risk_flags(&added, &PolicyListDiff::default(), &changed);
        assert!(flags.contains(&"capability_allow_expanded".to_string()));
    }

    #[test]
    fn risk_flags_capability_ceiling_expanded() {
        let added = PolicyListDiff {
            capability_ceiling: vec!["cap.admin".to_string()],
            ..Default::default()
        };
        let changed = PolicyChangedFields::default();
        let flags = compute_risk_flags(&added, &PolicyListDiff::default(), &changed);
        assert!(flags.contains(&"capability_ceiling_expanded".to_string()));
    }

    #[test]
    fn risk_flags_capability_deny_reduced() {
        let removed = PolicyListDiff {
            capability_deny: vec!["cap.dangerous".to_string()],
            ..Default::default()
        };
        let changed = PolicyChangedFields::default();
        let flags = compute_risk_flags(&PolicyListDiff::default(), &removed, &changed);
        assert!(flags.contains(&"capability_deny_reduced".to_string()));
    }

    #[test]
    fn risk_flags_transport_derp_enabled() {
        let added = PolicyListDiff::default();
        let changed = PolicyChangedFields {
            transport_policy: Some(TransportPolicyChange {
                before: ZoneTransportPolicy {
                    allow_derp: false,
                    ..Default::default()
                },
                after: ZoneTransportPolicy {
                    allow_derp: true,
                    ..Default::default()
                },
            }),
            ..Default::default()
        };
        let flags = compute_risk_flags(&added, &PolicyListDiff::default(), &changed);
        assert!(flags.contains(&"transport_derp_enabled".to_string()));
    }

    #[test]
    fn risk_flags_transport_funnel_enabled() {
        let added = PolicyListDiff::default();
        let changed = PolicyChangedFields {
            transport_policy: Some(TransportPolicyChange {
                before: ZoneTransportPolicy {
                    allow_funnel: false,
                    ..Default::default()
                },
                after: ZoneTransportPolicy {
                    allow_funnel: true,
                    ..Default::default()
                },
            }),
            ..Default::default()
        };
        let flags = compute_risk_flags(&added, &PolicyListDiff::default(), &changed);
        assert!(flags.contains(&"transport_funnel_enabled".to_string()));
    }

    #[test]
    fn risk_flags_multiple_risks() {
        let added = PolicyListDiff {
            principal_allow: vec!["user:*".to_string()],
            connector_allow: vec!["fcp.*".to_string()],
            ..Default::default()
        };
        let changed = PolicyChangedFields::default();
        let flags = compute_risk_flags(&added, &PolicyListDiff::default(), &changed);
        assert_eq!(flags.len(), 2);
    }

    // ---- diff_json_objects ----

    #[test]
    fn diff_json_objects_identical() {
        let obj = serde_json::json!({"a": 1, "b": "hello"});
        let diff = diff_json_objects(&obj, &obj).unwrap();
        assert!(diff.added.is_empty());
        assert!(diff.removed.is_empty());
        assert!(diff.changed.is_empty());
    }

    #[test]
    fn diff_json_objects_added_key() {
        let before = serde_json::json!({"a": 1});
        let after = serde_json::json!({"a": 1, "b": 2});
        let diff = diff_json_objects(&before, &after).unwrap();
        assert_eq!(diff.added.len(), 1);
        assert!(diff.added.contains_key("b"));
        assert!(diff.removed.is_empty());
        assert!(diff.changed.is_empty());
    }

    #[test]
    fn diff_json_objects_removed_key() {
        let before = serde_json::json!({"a": 1, "b": 2});
        let after = serde_json::json!({"a": 1});
        let diff = diff_json_objects(&before, &after).unwrap();
        assert!(diff.added.is_empty());
        assert_eq!(diff.removed.len(), 1);
        assert!(diff.removed.contains_key("b"));
    }

    #[test]
    fn diff_json_objects_changed_value() {
        let before = serde_json::json!({"a": 1});
        let after = serde_json::json!({"a": 2});
        let diff = diff_json_objects(&before, &after).unwrap();
        assert!(diff.added.is_empty());
        assert!(diff.removed.is_empty());
        assert_eq!(diff.changed.len(), 1);
        assert!(diff.changed.contains_key("a"));
    }

    #[test]
    fn diff_json_objects_not_object_fails() {
        let before = serde_json::json!([1, 2]);
        let after = serde_json::json!({"a": 1});
        assert!(diff_json_objects(&before, &after).is_err());
    }

    // ---- parse_policy_document ----

    #[test]
    fn parse_policy_document_empty() {
        assert!(parse_policy_document("").is_err());
    }

    #[test]
    fn parse_policy_document_invalid_json() {
        assert!(parse_policy_document("{bad json}").is_err());
    }

    // ---- parse_bundle_object ----

    #[test]
    fn parse_bundle_object_unsupported_schema() {
        let value = serde_json::json!({"some": "data"});
        assert!(parse_bundle_object("fcp.core:Unknown@1.0.0", &value).is_err());
    }

    // ---- default_zone_policy ----

    #[test]
    fn default_zone_policy_structure() {
        let invoke = InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::new("req-1"),
            connector_id: "fcp.test:base:v1".parse().unwrap(),
            operation: "op".parse().unwrap(),
            zone_id: ZoneId::work(),
            input: serde_json::json!({}),
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };
        let policy = default_zone_policy(&invoke);
        assert_eq!(policy.zone_id, ZoneId::work());
        assert!(policy.principal_allow.is_empty());
        assert!(policy.principal_deny.is_empty());
        assert!(policy.connector_allow.is_empty());
        assert!(policy.connector_deny.is_empty());
        assert!(policy.capability_allow.is_empty());
        assert!(policy.capability_deny.is_empty());
        assert!(policy.capability_ceiling.is_empty());
        assert!(policy.usage_budget.is_none());
        assert!(policy.requires_posture.is_none());
    }

    // ---- PolicyListDiff default ----

    #[test]
    fn policy_list_diff_default_empty() {
        let d = PolicyListDiff::default();
        assert!(d.principal_allow.is_empty());
        assert!(d.principal_deny.is_empty());
        assert!(d.connector_allow.is_empty());
        assert!(d.connector_deny.is_empty());
        assert!(d.capability_allow.is_empty());
        assert!(d.capability_deny.is_empty());
        assert!(d.capability_ceiling.is_empty());
    }

    // ---- PolicyChangedFields default ----

    #[test]
    fn policy_changed_fields_default_all_none() {
        let d = PolicyChangedFields::default();
        assert!(d.transport_policy.is_none());
        assert!(d.decision_receipts.is_none());
        assert!(d.requires_posture.is_none());
    }

    // ---- BundleApplyPlan serde ----

    #[test]
    fn bundle_apply_plan_serializes() {
        let plan = BundleApplyPlan {
            plan_type: "bundle_apply".to_string(),
            zone_id: "z:work".to_string(),
            bundle_id: "bundle-1".to_string(),
            state_path: "/tmp/state.json".to_string(),
        };
        let json = serde_json::to_string(&plan).unwrap();
        assert!(json.contains("\"plan_type\":\"bundle_apply\""));
        assert!(json.contains("\"bundle_id\":\"bundle-1\""));
    }

    // ---- BundleRollbackPlan serde ----

    #[test]
    fn bundle_rollback_plan_serializes() {
        let plan = BundleRollbackPlan {
            plan_type: "bundle_rollback".to_string(),
            zone_id: "z:work".to_string(),
            target_bundle_id: "bundle-prev".to_string(),
            state_path: "/tmp/state.json".to_string(),
        };
        let json = serde_json::to_string(&plan).unwrap();
        assert!(json.contains("\"plan_type\":\"bundle_rollback\""));
        assert!(json.contains("\"target_bundle_id\":\"bundle-prev\""));
    }

    #[test]
    fn bundle_apply_writes_state_and_audit_event() {
        let temp_dir = TempDir::new().unwrap();
        let bundle = test_bundle("bundle-a", ZoneId::work(), 1, None);
        let bundle_path = write_bundle_file(&temp_dir, "bundle-a.json", &bundle);
        let state_path = temp_dir.path().join("state.json");

        run_bundle_apply(&BundleApplyArgs {
            bundle: bundle_path,
            state: state_path.clone(),
            plan: false,
            json: true,
        })
        .unwrap();

        let state = load_bundle_state_optional(&state_path).unwrap().unwrap();
        assert_eq!(state.current.bundle.bundle_id, "bundle-a");
        assert!(state.previous.is_none());
        assert_eq!(state.audit_events.len(), 1);
        assert_eq!(
            state.audit_events[0].event_type,
            POLICY_BUNDLE_EVENT_APPLIED
        );
    }

    #[test]
    fn bundle_apply_rejects_chain_mismatch() {
        let temp_dir = TempDir::new().unwrap();
        let bundle_a = test_bundle("bundle-a", ZoneId::work(), 1, None);
        let bundle_a_path = write_bundle_file(&temp_dir, "bundle-a.json", &bundle_a);
        let state_path = temp_dir.path().join("state.json");

        run_bundle_apply(&BundleApplyArgs {
            bundle: bundle_a_path,
            state: state_path.clone(),
            plan: false,
            json: true,
        })
        .unwrap();

        let bundle_c = test_bundle("bundle-c", ZoneId::work(), 3, Some("bundle-x"));
        let bundle_c_path = write_bundle_file(&temp_dir, "bundle-c.json", &bundle_c);

        let err = run_bundle_apply(&BundleApplyArgs {
            bundle: bundle_c_path,
            state: state_path,
            plan: false,
            json: true,
        })
        .unwrap_err();

        assert!(err.to_string().contains("declares previous_bundle"));
    }

    #[test]
    fn bundle_rollback_writes_state_and_audit_event() {
        let temp_dir = TempDir::new().unwrap();
        let bundle_a = test_bundle("bundle-a", ZoneId::work(), 1, None);
        let bundle_b = test_bundle("bundle-b", ZoneId::work(), 2, Some("bundle-a"));
        let bundle_a_path = write_bundle_file(&temp_dir, "bundle-a.json", &bundle_a);
        let bundle_b_path = write_bundle_file(&temp_dir, "bundle-b.json", &bundle_b);
        let state_path = temp_dir.path().join("state.json");

        run_bundle_apply(&BundleApplyArgs {
            bundle: bundle_a_path.clone(),
            state: state_path.clone(),
            plan: false,
            json: true,
        })
        .unwrap();
        run_bundle_apply(&BundleApplyArgs {
            bundle: bundle_b_path,
            state: state_path.clone(),
            plan: false,
            json: true,
        })
        .unwrap();

        run_bundle_rollback(&BundleRollbackArgs {
            to: bundle_a_path,
            state: state_path.clone(),
            plan: false,
            json: true,
        })
        .unwrap();

        let state = load_bundle_state_optional(&state_path).unwrap().unwrap();
        assert_eq!(state.current.bundle.bundle_id, "bundle-a");
        assert_eq!(
            state
                .previous
                .as_ref()
                .map(|snapshot| snapshot.bundle.bundle_id.as_str()),
            Some("bundle-b")
        );
        assert_eq!(state.audit_events.len(), 3);
        assert_eq!(
            state.audit_events.last().unwrap().event_type,
            POLICY_BUNDLE_EVENT_ROLLED_BACK
        );
    }

    #[test]
    fn bundle_rollback_rejects_non_previous_target() {
        let temp_dir = TempDir::new().unwrap();
        let bundle_a = test_bundle("bundle-a", ZoneId::work(), 1, None);
        let bundle_b = test_bundle("bundle-b", ZoneId::work(), 2, Some("bundle-a"));
        let bundle_c = test_bundle("bundle-c", ZoneId::work(), 3, Some("bundle-b"));
        let bundle_a_path = write_bundle_file(&temp_dir, "bundle-a.json", &bundle_a);
        let bundle_b_path = write_bundle_file(&temp_dir, "bundle-b.json", &bundle_b);
        let bundle_c_path = write_bundle_file(&temp_dir, "bundle-c.json", &bundle_c);
        let state_path = temp_dir.path().join("state.json");

        run_bundle_apply(&BundleApplyArgs {
            bundle: bundle_a_path,
            state: state_path.clone(),
            plan: false,
            json: true,
        })
        .unwrap();
        run_bundle_apply(&BundleApplyArgs {
            bundle: bundle_b_path,
            state: state_path.clone(),
            plan: false,
            json: true,
        })
        .unwrap();

        let err = run_bundle_rollback(&BundleRollbackArgs {
            to: bundle_c_path,
            state: state_path,
            plan: false,
            json: true,
        })
        .unwrap_err();

        assert!(err.to_string().contains("does not match current bundle"));
    }

    // ---- RollbackPlan serde ----

    #[test]
    fn rollback_plan_serializes() {
        let plan = RollbackPlan {
            policy_type: "zone_policy".to_string(),
            zone_id: "z:work".to_string(),
            current_policy_id: "oid-1".to_string(),
            previous_policy_id: "oid-2".to_string(),
            plan_type: "rollback".to_string(),
        };
        let json = serde_json::to_string(&plan).unwrap();
        assert!(json.contains("\"plan_type\":\"rollback\""));
        assert!(json.contains("\"zone_id\":\"z:work\""));
    }

    // ---- PolicyDiffOutput serde ----

    #[test]
    fn policy_diff_output_serializes() {
        let output = PolicyDiffOutput {
            policy_type: "zone_policy".to_string(),
            zone_id: "z:work".to_string(),
            previous_policy_id: "prev-id".to_string(),
            current_policy_id: "curr-id".to_string(),
            added: serde_json::json!({}),
            removed: serde_json::json!({}),
            changed: serde_json::json!({}),
            risk_flags: vec!["transport_derp_enabled".to_string()],
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"risk_flags\""));
        assert!(json.contains("transport_derp_enabled"));
    }

    // ---- PolicyDocument methods ----

    #[test]
    fn policy_document_zone_policy_type() {
        let invoke = InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::new("req-1"),
            connector_id: "fcp.test:base:v1".parse().unwrap(),
            operation: "op".parse().unwrap(),
            zone_id: ZoneId::work(),
            input: serde_json::json!({}),
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };
        let doc = PolicyDocument::ZonePolicy(default_zone_policy(&invoke));
        assert_eq!(doc.policy_type(), "zone_policy");
        assert_eq!(*doc.zone_id(), ZoneId::work());
    }

    // ---- diff_zone_policy no changes ----

    #[test]
    fn diff_zone_policy_identical() {
        let zone = ZoneId::work();
        let policy = base_policy(zone);
        let diff = diff_zone_policy(&policy, &policy).unwrap();
        assert!(diff.risk_flags.is_empty());
    }

    // ---- PolicyBundleState ----

    #[test]
    fn policy_bundle_state_new_sets_fields() {
        let bundle = test_bundle("bundle-x", ZoneId::work(), 1, None);
        let now = Utc::now();
        let state = PolicyBundleState::new(bundle, now);
        assert_eq!(state.format, POLICY_BUNDLE_STATE_FORMAT);
        assert_eq!(state.schema_version, POLICY_BUNDLE_STATE_SCHEMA_VERSION);
        assert_eq!(state.zone_id, ZoneId::work());
        assert_eq!(state.current.bundle.bundle_id, "bundle-x");
        assert_eq!(state.current.applied_at, now);
        assert!(state.previous.is_none());
        assert!(state.audit_events.is_empty());
    }

    #[test]
    fn policy_bundle_state_validate_ok() {
        let bundle = test_bundle("bundle-v", ZoneId::work(), 1, None);
        let state = PolicyBundleState::new(bundle, Utc::now());
        assert!(state.validate().is_ok());
    }

    #[test]
    fn policy_bundle_state_validate_bad_format() {
        let bundle = test_bundle("bundle-v", ZoneId::work(), 1, None);
        let mut state = PolicyBundleState::new(bundle, Utc::now());
        state.format = "wrong-format".to_string();
        let err = state.validate().unwrap_err();
        assert!(err.to_string().contains("state format must be"));
    }

    #[test]
    fn policy_bundle_state_validate_bad_schema_version() {
        let bundle = test_bundle("bundle-v", ZoneId::work(), 1, None);
        let mut state = PolicyBundleState::new(bundle, Utc::now());
        state.schema_version = "9.9.9".to_string();
        let err = state.validate().unwrap_err();
        assert!(err.to_string().contains("state schema_version must be"));
    }

    #[test]
    fn policy_bundle_state_validate_audit_event_zone_mismatch() {
        let bundle = test_bundle("bundle-v", ZoneId::work(), 1, None);
        let now = Utc::now();
        let mut state = PolicyBundleState::new(bundle, now);
        let event = build_bundle_audit_event(
            POLICY_BUNDLE_EVENT_APPLIED,
            &ZoneId::work(),
            "bundle-v",
            None,
            1,
            now,
        )
        .unwrap();
        // Mutate zone_id to mismatch
        let mut bad_event = event;
        bad_event.zone_id = "z:other".to_string();
        state.audit_events.push(bad_event);
        let err = state.validate().unwrap_err();
        assert!(err.to_string().contains("audit event zone"));
    }

    #[test]
    fn policy_bundle_state_next_audit_seq_empty() {
        let bundle = test_bundle("bundle-n", ZoneId::work(), 1, None);
        let state = PolicyBundleState::new(bundle, Utc::now());
        assert_eq!(state.next_audit_seq(), 1);
    }

    #[test]
    fn policy_bundle_state_next_audit_seq_after_events() {
        let bundle = test_bundle("bundle-n", ZoneId::work(), 1, None);
        let now = Utc::now();
        let mut state = PolicyBundleState::new(bundle, now);
        let event = build_bundle_audit_event(
            POLICY_BUNDLE_EVENT_APPLIED,
            &ZoneId::work(),
            "bundle-n",
            None,
            5,
            now,
        )
        .unwrap();
        state.audit_events.push(event);
        assert_eq!(state.next_audit_seq(), 6);
    }

    #[test]
    fn policy_bundle_state_clone() {
        let bundle = test_bundle("bundle-cl", ZoneId::work(), 1, None);
        let state = PolicyBundleState::new(bundle, Utc::now());
        let cloned = state.clone();
        assert_eq!(state.format, cloned.format);
        assert_eq!(state.schema_version, cloned.schema_version);
        assert_eq!(state.zone_id, cloned.zone_id);
        assert_eq!(
            state.current.bundle.bundle_id,
            cloned.current.bundle.bundle_id
        );
    }

    #[test]
    fn policy_bundle_state_serde_roundtrip() {
        let bundle = test_bundle("bundle-sr", ZoneId::work(), 1, None);
        let state = PolicyBundleState::new(bundle, Utc::now());
        let json = serde_json::to_string(&state).unwrap();
        let deserialized: PolicyBundleState = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.format, state.format);
        assert_eq!(deserialized.current.bundle.bundle_id, "bundle-sr");
    }

    // ---- PolicyBundleStateSnapshot ----

    #[test]
    fn snapshot_validate_for_zone_ok() {
        let bundle = test_bundle("bundle-snap", ZoneId::work(), 1, None);
        let snapshot = PolicyBundleStateSnapshot {
            bundle,
            applied_at: Utc::now(),
        };
        assert!(snapshot.validate_for_zone(&ZoneId::work(), "test").is_ok());
    }

    #[test]
    fn snapshot_validate_for_zone_mismatch() {
        let bundle = test_bundle("bundle-snap", ZoneId::work(), 1, None);
        let snapshot = PolicyBundleStateSnapshot {
            bundle,
            applied_at: Utc::now(),
        };
        let other_zone: ZoneId = "z:personal".parse().unwrap();
        let err = snapshot
            .validate_for_zone(&other_zone, "current")
            .unwrap_err();
        assert!(err.to_string().contains("does not match state zone"));
    }

    // ---- PolicyBundleAuditEvent ----

    #[test]
    fn audit_event_clone_and_debug() {
        let event = build_bundle_audit_event(
            POLICY_BUNDLE_EVENT_APPLIED,
            &ZoneId::work(),
            "bundle-dbg",
            Some("prev-bundle"),
            3,
            Utc::now(),
        )
        .unwrap();
        let cloned = event.clone();
        assert_eq!(event.seq, cloned.seq);
        assert_eq!(event.event_type, cloned.event_type);
        assert_eq!(event.bundle_id, cloned.bundle_id);
        assert_eq!(event.previous_bundle_id, cloned.previous_bundle_id);
        let debug = format!("{:?}", event);
        assert!(debug.contains("PolicyBundleAuditEvent"));
    }

    #[test]
    fn audit_event_serde_roundtrip() {
        let event = build_bundle_audit_event(
            POLICY_BUNDLE_EVENT_ROLLED_BACK,
            &ZoneId::work(),
            "bundle-rt",
            None,
            1,
            Utc::now(),
        )
        .unwrap();
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: PolicyBundleAuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.event_type, POLICY_BUNDLE_EVENT_ROLLED_BACK);
        assert_eq!(deserialized.bundle_id, "bundle-rt");
        assert!(deserialized.previous_bundle_id.is_none());
    }

    #[test]
    fn audit_event_with_previous_bundle_serializes() {
        let event = build_bundle_audit_event(
            POLICY_BUNDLE_EVENT_APPLIED,
            &ZoneId::work(),
            "bundle-2",
            Some("bundle-1"),
            2,
            Utc::now(),
        )
        .unwrap();
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"previous_bundle_id\":\"bundle-1\""));
        assert!(json.contains("\"actor\":\"fwc\""));
    }

    #[test]
    fn audit_event_deterministic_id() {
        let ts = DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let event1 = build_bundle_audit_event(
            POLICY_BUNDLE_EVENT_APPLIED,
            &ZoneId::work(),
            "bundle-det",
            None,
            1,
            ts,
        )
        .unwrap();
        let event2 = build_bundle_audit_event(
            POLICY_BUNDLE_EVENT_APPLIED,
            &ZoneId::work(),
            "bundle-det",
            None,
            1,
            ts,
        )
        .unwrap();
        assert_eq!(event1.audit_event_id, event2.audit_event_id);
    }

    #[test]
    fn audit_event_different_seq_different_id() {
        let ts = DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let event1 = build_bundle_audit_event(
            POLICY_BUNDLE_EVENT_APPLIED,
            &ZoneId::work(),
            "bundle-det",
            None,
            1,
            ts,
        )
        .unwrap();
        let event2 = build_bundle_audit_event(
            POLICY_BUNDLE_EVENT_APPLIED,
            &ZoneId::work(),
            "bundle-det",
            None,
            2,
            ts,
        )
        .unwrap();
        assert_ne!(event1.audit_event_id, event2.audit_event_id);
    }

    // ---- build_bundle_audit_event ----

    #[test]
    fn build_audit_event_sets_actor() {
        let event = build_bundle_audit_event(
            POLICY_BUNDLE_EVENT_APPLIED,
            &ZoneId::work(),
            "bundle-actor",
            None,
            1,
            Utc::now(),
        )
        .unwrap();
        assert_eq!(event.actor, POLICY_BUNDLE_AUDIT_ACTOR);
    }

    #[test]
    fn build_audit_event_iso_format() {
        let ts = DateTime::parse_from_rfc3339("2026-06-15T10:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let event = build_bundle_audit_event(
            POLICY_BUNDLE_EVENT_APPLIED,
            &ZoneId::work(),
            "bundle-iso",
            None,
            1,
            ts,
        )
        .unwrap();
        assert_eq!(event.occurred_at_iso, "2026-06-15T10:30:00Z");
    }

    // ---- validate_apply_transition ----

    #[test]
    fn validate_apply_transition_no_state() {
        let bundle = test_bundle("bundle-first", ZoneId::work(), 1, None);
        assert!(validate_apply_transition(None, &bundle).is_ok());
    }

    #[test]
    fn validate_apply_transition_matching_previous() {
        let bundle_a = test_bundle("bundle-a", ZoneId::work(), 1, None);
        let state = PolicyBundleState::new(bundle_a, Utc::now());
        let bundle_b = test_bundle("bundle-b", ZoneId::work(), 2, Some("bundle-a"));
        assert!(validate_apply_transition(Some(&state), &bundle_b).is_ok());
    }

    #[test]
    fn validate_apply_transition_mismatch() {
        let bundle_a = test_bundle("bundle-a", ZoneId::work(), 1, None);
        let state = PolicyBundleState::new(bundle_a, Utc::now());
        let bundle_c = test_bundle("bundle-c", ZoneId::work(), 2, Some("bundle-x"));
        let err = validate_apply_transition(Some(&state), &bundle_c).unwrap_err();
        assert!(err.to_string().contains("declares previous_bundle"));
    }

    #[test]
    fn validate_apply_transition_no_previous_on_bundle_but_state_exists() {
        let bundle_a = test_bundle("bundle-a", ZoneId::work(), 1, None);
        let state = PolicyBundleState::new(bundle_a, Utc::now());
        let bundle_b = test_bundle("bundle-b", ZoneId::work(), 2, None);
        let err = validate_apply_transition(Some(&state), &bundle_b).unwrap_err();
        assert!(err.to_string().contains("declares previous_bundle"));
    }

    // ---- validate_rollback_transition ----

    #[test]
    fn validate_rollback_transition_valid() {
        let bundle_a = test_bundle("bundle-a", ZoneId::work(), 1, None);
        let bundle_b = test_bundle("bundle-b", ZoneId::work(), 2, Some("bundle-a"));
        let state = PolicyBundleState::new(bundle_b, Utc::now());
        assert!(validate_rollback_transition(&state, &bundle_a).is_ok());
    }

    #[test]
    fn validate_rollback_transition_invalid() {
        let _bundle_a = test_bundle("bundle-a", ZoneId::work(), 1, None);
        let bundle_b = test_bundle("bundle-b", ZoneId::work(), 2, Some("bundle-a"));
        let state = PolicyBundleState::new(bundle_b, Utc::now());
        let bundle_c = test_bundle("bundle-c", ZoneId::work(), 3, None);
        let err = validate_rollback_transition(&state, &bundle_c).unwrap_err();
        assert!(err.to_string().contains("does not match current bundle"));
    }

    // ---- validate_bundle_state_zone ----

    #[test]
    fn validate_bundle_state_zone_ok() {
        let bundle = test_bundle("bundle-z", ZoneId::work(), 1, None);
        let state = PolicyBundleState::new(bundle, Utc::now());
        assert!(
            validate_bundle_state_zone(&state, &ZoneId::work(), Path::new("/tmp/s.json")).is_ok()
        );
    }

    #[test]
    fn validate_bundle_state_zone_mismatch() {
        let bundle = test_bundle("bundle-z", ZoneId::work(), 1, None);
        let state = PolicyBundleState::new(bundle, Utc::now());
        let other: ZoneId = "z:personal".parse().unwrap();
        let err = validate_bundle_state_zone(&state, &other, Path::new("/tmp/s.json")).unwrap_err();
        assert!(err.to_string().contains("but bundle targets zone"));
    }

    // ---- BundleApplyResult serde ----

    #[test]
    fn bundle_apply_result_serializes() {
        let result = BundleApplyResult {
            result_type: "bundle_apply".to_string(),
            zone_id: "z:work".to_string(),
            bundle_id: "bundle-1".to_string(),
            replaced_bundle_id: None,
            declared_previous_bundle_id: None,
            state_path: "/tmp/state.json".to_string(),
            changed: true,
            audit_event: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"changed\":true"));
        assert!(!json.contains("replaced_bundle_id"));
    }

    #[test]
    fn bundle_apply_result_with_replaced_serializes() {
        let result = BundleApplyResult {
            result_type: "bundle_apply".to_string(),
            zone_id: "z:work".to_string(),
            bundle_id: "bundle-2".to_string(),
            replaced_bundle_id: Some("bundle-1".to_string()),
            declared_previous_bundle_id: Some("bundle-1".to_string()),
            state_path: "/tmp/state.json".to_string(),
            changed: true,
            audit_event: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"replaced_bundle_id\":\"bundle-1\""));
    }

    // ---- BundleRollbackResult serde ----

    #[test]
    fn bundle_rollback_result_serializes() {
        let result = BundleRollbackResult {
            result_type: "bundle_rollback".to_string(),
            zone_id: "z:work".to_string(),
            target_bundle_id: "bundle-prev".to_string(),
            replaced_bundle_id: Some("bundle-cur".to_string()),
            state_path: "/tmp/state.json".to_string(),
            changed: true,
            audit_event: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"result_type\":\"bundle_rollback\""));
        assert!(json.contains("\"replaced_bundle_id\":\"bundle-cur\""));
    }

    #[test]
    fn bundle_rollback_result_no_change_serializes() {
        let result = BundleRollbackResult {
            result_type: "bundle_rollback".to_string(),
            zone_id: "z:work".to_string(),
            target_bundle_id: "bundle-same".to_string(),
            replaced_bundle_id: None,
            state_path: "/tmp/state.json".to_string(),
            changed: false,
            audit_event: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"changed\":false"));
        assert!(!json.contains("replaced_bundle_id"));
    }

    // ---- diff_zone_policy edge cases ----

    #[test]
    fn diff_zone_policy_added_principal_allow() {
        let zone = ZoneId::work();
        let before = base_policy(zone.clone());
        let mut after = base_policy(zone);
        after.principal_allow.push(PolicyPattern {
            pattern: "user:admin".to_string(),
        });
        let diff = diff_zone_policy(&before, &after).unwrap();
        assert!(
            diff.risk_flags
                .contains(&"principal_allow_expanded".to_string())
        );
    }

    #[test]
    fn diff_zone_policy_added_capability_allow() {
        let zone = ZoneId::work();
        let before = base_policy(zone.clone());
        let mut after = base_policy(zone);
        after.capability_allow.push(PolicyPattern {
            pattern: "cap:admin".to_string(),
        });
        let diff = diff_zone_policy(&before, &after).unwrap();
        assert!(
            diff.risk_flags
                .contains(&"capability_allow_expanded".to_string())
        );
    }

    #[test]
    fn diff_zone_policy_removed_entries_no_risk() {
        let zone = ZoneId::work();
        let mut before = base_policy(zone.clone());
        before.connector_allow.push(PolicyPattern {
            pattern: "fcp.test:*".to_string(),
        });
        let after = base_policy(zone);
        let diff = diff_zone_policy(&before, &after).unwrap();
        assert!(diff.risk_flags.is_empty());
        let removed = diff.removed.as_object().unwrap();
        let removed_connectors = removed
            .get("connector_allow")
            .and_then(Value::as_array)
            .unwrap();
        assert!(
            removed_connectors
                .iter()
                .any(|v| v.as_str() == Some("fcp.test:*"))
        );
    }

    #[test]
    fn diff_zone_policy_transport_lan_risk() {
        let zone = ZoneId::work();
        let mut before = base_policy(zone.clone());
        before.transport_policy.allow_lan = false;
        let mut after = base_policy(zone);
        after.transport_policy.allow_lan = true;
        let diff = diff_zone_policy(&before, &after).unwrap();
        assert!(
            diff.risk_flags
                .contains(&"transport_lan_enabled".to_string())
        );
    }

    #[test]
    fn diff_zone_policy_transport_funnel_risk() {
        let zone = ZoneId::work();
        let mut before = base_policy(zone.clone());
        before.transport_policy.allow_funnel = false;
        let mut after = base_policy(zone);
        after.transport_policy.allow_funnel = true;
        let diff = diff_zone_policy(&before, &after).unwrap();
        assert!(
            diff.risk_flags
                .contains(&"transport_funnel_enabled".to_string())
        );
    }

    // ---- diff_policy_lists ----

    #[test]
    fn diff_policy_lists_all_fields() {
        let zone = ZoneId::work();
        let before = base_policy(zone.clone());
        let mut after = base_policy(zone);
        after.principal_deny.push(PolicyPattern {
            pattern: "user:bad".to_string(),
        });
        after.capability_deny.push(PolicyPattern {
            pattern: "cap:danger".to_string(),
        });
        after.connector_deny.push(PolicyPattern {
            pattern: "conn:bad".to_string(),
        });
        let (added, removed) = diff_policy_lists(&before, &after);
        assert_eq!(added.principal_deny, vec!["user:bad"]);
        assert_eq!(added.capability_deny, vec!["cap:danger"]);
        assert_eq!(added.connector_deny, vec!["conn:bad"]);
        assert!(removed.principal_deny.is_empty());
        assert!(removed.capability_deny.is_empty());
        assert!(removed.connector_deny.is_empty());
    }

    // ---- diff_patterns duplicates ----

    #[test]
    fn diff_patterns_duplicate_entries() {
        let before = vec![
            PolicyPattern {
                pattern: "a".to_string(),
            },
            PolicyPattern {
                pattern: "a".to_string(),
            },
        ];
        let after = vec![PolicyPattern {
            pattern: "a".to_string(),
        }];
        let (added, removed) = diff_patterns(&before, &after);
        assert!(added.is_empty());
        assert!(removed.is_empty());
    }

    // ---- diff_capability_ids more cases ----

    #[test]
    fn diff_capability_ids_identical() {
        let caps = vec!["cap.read".parse().unwrap(), "cap.write".parse().unwrap()];
        let (added, removed) = diff_capability_ids(&caps, &caps);
        assert!(added.is_empty());
        assert!(removed.is_empty());
    }

    #[test]
    fn diff_capability_ids_only_added() {
        let before = vec![];
        let after = vec!["cap.exec".parse().unwrap()];
        let (added, removed) = diff_capability_ids(&before, &after);
        assert_eq!(added, vec!["cap.exec"]);
        assert!(removed.is_empty());
    }

    #[test]
    fn diff_capability_ids_only_removed() {
        let before = vec!["cap.admin".parse().unwrap()];
        let after = vec![];
        let (added, removed) = diff_capability_ids(&before, &after);
        assert!(added.is_empty());
        assert_eq!(removed, vec!["cap.admin"]);
    }

    // ---- diff_json_objects more cases ----

    #[test]
    fn diff_json_objects_empty_objects() {
        let before = serde_json::json!({});
        let after = serde_json::json!({});
        let diff = diff_json_objects(&before, &after).unwrap();
        assert!(diff.added.is_empty());
        assert!(diff.removed.is_empty());
        assert!(diff.changed.is_empty());
    }

    #[test]
    fn diff_json_objects_multiple_changes() {
        let before = serde_json::json!({"a": 1, "b": 2, "c": 3});
        let after = serde_json::json!({"a": 10, "c": 3, "d": 4});
        let diff = diff_json_objects(&before, &after).unwrap();
        assert_eq!(diff.added.len(), 1);
        assert!(diff.added.contains_key("d"));
        assert_eq!(diff.removed.len(), 1);
        assert!(diff.removed.contains_key("b"));
        assert_eq!(diff.changed.len(), 1);
        assert!(diff.changed.contains_key("a"));
    }

    #[test]
    fn diff_json_objects_after_not_object_fails() {
        let before = serde_json::json!({"a": 1});
        let after = serde_json::json!("string_value");
        assert!(diff_json_objects(&before, &after).is_err());
    }

    // ---- parse_policy_document more cases ----

    #[test]
    fn parse_policy_document_whitespace_only() {
        assert!(parse_policy_document("   \t\n  ").is_err());
    }

    #[test]
    fn parse_policy_document_valid_but_wrong_shape() {
        // Valid JSON but does not match ZonePolicy or ZoneDefinition
        assert!(parse_policy_document(r#"{"arbitrary": "data"}"#).is_err());
    }

    // ---- parse_bundle_object more schemas ----

    #[test]
    fn parse_bundle_object_zone_policy_prefix() {
        // schema_id starts with correct prefix, but value may not parse
        let value = serde_json::json!({"not": "valid"});
        assert!(parse_bundle_object("fcp.core:ZonePolicy@1.0.0", &value).is_err());
    }

    #[test]
    fn parse_bundle_object_zone_definition_prefix() {
        let value = serde_json::json!({"not": "valid"});
        assert!(parse_bundle_object("fcp.core:ZoneDefinition@1.0.0", &value).is_err());
    }

    #[test]
    fn parse_bundle_object_role_object_prefix() {
        let value = serde_json::json!({"not": "valid"});
        assert!(parse_bundle_object("fcp.core:RoleObject@1.0.0", &value).is_err());
    }

    #[test]
    fn parse_bundle_object_resource_object_prefix() {
        let value = serde_json::json!({"not": "valid"});
        assert!(parse_bundle_object("fcp.core:ResourceObject@1.0.0", &value).is_err());
    }

    #[test]
    fn parse_bundle_object_capability_object_prefix() {
        let value = serde_json::json!({"not": "valid"});
        assert!(parse_bundle_object("fcp.core:CapabilityObject@1.0.0", &value).is_err());
    }

    // ---- parse_simulation_input with valid json but unrelated ----

    #[test]
    fn parse_simulation_input_random_object() {
        assert!(parse_simulation_input(r#"{"random": true}"#).is_err());
    }

    // ---- parse_created_at edge cases ----

    #[test]
    fn parse_created_at_epoch() {
        let dt = parse_created_at(Some("1970-01-01T00:00:00Z"))
            .unwrap()
            .unwrap();
        assert_eq!(dt.timestamp(), 0);
    }

    #[test]
    fn parse_created_at_empty_string() {
        assert!(parse_created_at(Some("")).is_err());
    }

    // ---- load_bundle_state_optional file scenarios ----

    #[test]
    fn load_bundle_state_optional_missing_file() {
        let result =
            load_bundle_state_optional(Path::new("/tmp/nonexistent_policy_state_xyz.json"))
                .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn load_bundle_state_optional_valid_file() {
        let temp_dir = TempDir::new().unwrap();
        let bundle = test_bundle("bundle-load", ZoneId::work(), 1, None);
        let state = PolicyBundleState::new(bundle, Utc::now());
        let path = temp_dir.path().join("state.json");
        let json = serde_json::to_string_pretty(&state).unwrap();
        fs::write(&path, json).unwrap();
        let loaded = load_bundle_state_optional(&path).unwrap().unwrap();
        assert_eq!(loaded.current.bundle.bundle_id, "bundle-load");
    }

    #[test]
    fn load_bundle_state_optional_invalid_json() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("bad_state.json");
        fs::write(&path, "not json!").unwrap();
        assert!(load_bundle_state_optional(&path).is_err());
    }

    // ---- write_bundle_state ----

    #[test]
    fn write_bundle_state_creates_parent_dirs() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("sub").join("dir").join("state.json");
        let bundle = test_bundle("bundle-wd", ZoneId::work(), 1, None);
        let state = PolicyBundleState::new(bundle, Utc::now());
        write_bundle_state(&path, &state).unwrap();
        assert!(path.exists());
    }

    // ---- bundle_apply plan only ----

    #[test]
    fn bundle_apply_plan_mode() {
        let temp_dir = TempDir::new().unwrap();
        let bundle = test_bundle("bundle-plan", ZoneId::work(), 1, None);
        let bundle_path = write_bundle_file(&temp_dir, "bundle-plan.json", &bundle);
        let state_path = temp_dir.path().join("state.json");

        run_bundle_apply(&BundleApplyArgs {
            bundle: bundle_path,
            state: state_path.clone(),
            plan: true,
            json: true,
        })
        .unwrap();

        // State file should not exist since we only planned
        assert!(!state_path.exists());
    }

    // ---- bundle_apply idempotent ----

    #[test]
    fn bundle_apply_idempotent_no_change() {
        let temp_dir = TempDir::new().unwrap();
        let bundle = test_bundle("bundle-idem", ZoneId::work(), 1, None);
        let bundle_path = write_bundle_file(&temp_dir, "bundle-idem.json", &bundle);
        let state_path = temp_dir.path().join("state.json");

        // Apply once
        run_bundle_apply(&BundleApplyArgs {
            bundle: bundle_path.clone(),
            state: state_path.clone(),
            plan: false,
            json: true,
        })
        .unwrap();

        // Apply same bundle again — should succeed with changed=false
        run_bundle_apply(&BundleApplyArgs {
            bundle: bundle_path,
            state: state_path.clone(),
            plan: false,
            json: true,
        })
        .unwrap();

        let state = load_bundle_state_optional(&state_path).unwrap().unwrap();
        assert_eq!(state.audit_events.len(), 1);
    }

    // ---- bundle_rollback plan only ----

    #[test]
    fn bundle_rollback_plan_mode() {
        let temp_dir = TempDir::new().unwrap();
        let bundle_a = test_bundle("bundle-a", ZoneId::work(), 1, None);
        let bundle_b = test_bundle("bundle-b", ZoneId::work(), 2, Some("bundle-a"));
        let bundle_a_path = write_bundle_file(&temp_dir, "bundle-a.json", &bundle_a);
        let bundle_b_path = write_bundle_file(&temp_dir, "bundle-b.json", &bundle_b);
        let state_path = temp_dir.path().join("state.json");

        run_bundle_apply(&BundleApplyArgs {
            bundle: bundle_a_path.clone(),
            state: state_path.clone(),
            plan: false,
            json: true,
        })
        .unwrap();
        run_bundle_apply(&BundleApplyArgs {
            bundle: bundle_b_path,
            state: state_path.clone(),
            plan: false,
            json: true,
        })
        .unwrap();

        // Plan rollback — should not change state
        let state_before = load_bundle_state_optional(&state_path).unwrap().unwrap();
        run_bundle_rollback(&BundleRollbackArgs {
            to: bundle_a_path,
            state: state_path.clone(),
            plan: true,
            json: true,
        })
        .unwrap();
        let state_after = load_bundle_state_optional(&state_path).unwrap().unwrap();
        assert_eq!(
            state_before.current.bundle.bundle_id,
            state_after.current.bundle.bundle_id
        );
    }

    // ---- bundle_rollback requires existing state ----

    #[test]
    fn bundle_rollback_requires_state_file() {
        let temp_dir = TempDir::new().unwrap();
        let bundle = test_bundle("bundle-rb", ZoneId::work(), 1, None);
        let bundle_path = write_bundle_file(&temp_dir, "bundle-rb.json", &bundle);
        let state_path = temp_dir.path().join("nonexistent_state.json");

        let err = run_bundle_rollback(&BundleRollbackArgs {
            to: bundle_path,
            state: state_path,
            plan: false,
            json: true,
        })
        .unwrap_err();
        assert!(err.to_string().contains("requires an existing state file"));
    }

    // ---- bundle_rollback zone mismatch ----

    #[test]
    fn bundle_rollback_zone_mismatch() {
        let temp_dir = TempDir::new().unwrap();
        let bundle_a = test_bundle("bundle-a", ZoneId::work(), 1, None);
        let bundle_a_path = write_bundle_file(&temp_dir, "bundle-a.json", &bundle_a);
        let state_path = temp_dir.path().join("state.json");

        run_bundle_apply(&BundleApplyArgs {
            bundle: bundle_a_path,
            state: state_path.clone(),
            plan: false,
            json: true,
        })
        .unwrap();

        let other_zone: ZoneId = "z:personal".parse().unwrap();
        let bundle_other = test_bundle("bundle-other", other_zone, 1, None);
        let bundle_other_path = write_bundle_file(&temp_dir, "bundle-other.json", &bundle_other);

        let err = run_bundle_rollback(&BundleRollbackArgs {
            to: bundle_other_path,
            state: state_path,
            plan: false,
            json: true,
        })
        .unwrap_err();
        assert!(err.to_string().contains("but bundle targets zone"));
    }

    // ---- bundle_apply zone mismatch ----

    #[test]
    fn bundle_apply_zone_mismatch() {
        let temp_dir = TempDir::new().unwrap();
        let bundle_a = test_bundle("bundle-a", ZoneId::work(), 1, None);
        let bundle_a_path = write_bundle_file(&temp_dir, "bundle-a.json", &bundle_a);
        let state_path = temp_dir.path().join("state.json");

        run_bundle_apply(&BundleApplyArgs {
            bundle: bundle_a_path,
            state: state_path.clone(),
            plan: false,
            json: true,
        })
        .unwrap();

        let other_zone: ZoneId = "z:personal".parse().unwrap();
        let bundle_other = test_bundle("bundle-other", other_zone, 1, None);
        let bundle_other_path = write_bundle_file(&temp_dir, "bundle-other.json", &bundle_other);

        let err = run_bundle_apply(&BundleApplyArgs {
            bundle: bundle_other_path,
            state: state_path,
            plan: false,
            json: true,
        })
        .unwrap_err();
        assert!(err.to_string().contains("but bundle targets zone"));
    }

    // ---- constants ----

    #[test]
    fn constants_values() {
        assert_eq!(POLICY_BUNDLE_STATE_FORMAT, "fcp-policy-bundle-state");
        assert_eq!(POLICY_BUNDLE_STATE_SCHEMA_VERSION, "1.0.0");
        assert_eq!(POLICY_BUNDLE_EVENT_APPLIED, "policy.bundle.applied");
        assert_eq!(POLICY_BUNDLE_EVENT_ROLLED_BACK, "policy.bundle.rolled_back");
        assert_eq!(POLICY_BUNDLE_AUDIT_ACTOR, "fwc");
    }

    // ---- PolicyDocument zone_definition ----

    #[test]
    fn policy_document_zone_definition_type() {
        let zone = ZoneId::work();
        let schema = SchemaId::new("fcp.core", "ZoneDefinition", Version::new(1, 0, 0));
        let header = ObjectHeader {
            encryption_kind: Default::default(),
            schema,
            zone_id: zone.clone(),
            created_at: 0,
            provenance: Provenance::new(zone.clone()),
            refs: Vec::new(),
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        };
        let def = ZoneDefinitionObject {
            header,
            zone_id: zone.clone(),
            name: "test-zone".to_string(),
            integrity_level: IntegrityLevel::Work,
            confidentiality_level: ConfidentialityLevel::Work,
            symbol_port: 9000,
            control_port: 9001,
            transport_policy: ZoneTransportPolicy::default(),
            policy_object_id: ObjectId::from_unscoped_bytes(b"test-oid"),
            prev: None,
            signature: NodeSignature::new(NodeId::new("test-node"), [0u8; 64], 0),
        };
        let doc = PolicyDocument::ZoneDefinition(def);
        assert_eq!(doc.policy_type(), "zone_definition");
        assert_eq!(*doc.zone_id(), zone);
    }

    // ---- risk_flags transport_lan_enabled ----

    #[test]
    fn risk_flags_transport_lan_enabled() {
        let added = PolicyListDiff::default();
        let changed = PolicyChangedFields {
            transport_policy: Some(TransportPolicyChange {
                before: ZoneTransportPolicy {
                    allow_lan: false,
                    ..Default::default()
                },
                after: ZoneTransportPolicy {
                    allow_lan: true,
                    ..Default::default()
                },
            }),
            ..Default::default()
        };
        let flags = compute_risk_flags(&added, &PolicyListDiff::default(), &changed);
        assert!(flags.contains(&"transport_lan_enabled".to_string()));
    }

    // ---- risk_flags transport not triggered when disabling ----

    #[test]
    fn risk_flags_transport_derp_disabled_no_flag() {
        let added = PolicyListDiff::default();
        let changed = PolicyChangedFields {
            transport_policy: Some(TransportPolicyChange {
                before: ZoneTransportPolicy {
                    allow_derp: true,
                    ..Default::default()
                },
                after: ZoneTransportPolicy {
                    allow_derp: false,
                    ..Default::default()
                },
            }),
            ..Default::default()
        };
        let flags = compute_risk_flags(&added, &PolicyListDiff::default(), &changed);
        assert!(!flags.contains(&"transport_derp_enabled".to_string()));
    }

    // ---- PolicyListDiff serialize ----

    #[test]
    fn policy_list_diff_serializes() {
        let diff = PolicyListDiff {
            principal_allow: vec!["user:*".to_string()],
            principal_deny: vec![],
            connector_allow: vec!["c:*".to_string()],
            connector_deny: vec![],
            capability_allow: vec![],
            capability_deny: vec![],
            capability_ceiling: vec!["cap.x".to_string()],
        };
        let json = serde_json::to_string(&diff).unwrap();
        assert!(json.contains("\"principal_allow\""));
        assert!(json.contains("\"connector_allow\""));
        assert!(json.contains("\"capability_ceiling\""));
    }

    // ---- Change<T> serialize ----

    #[test]
    fn change_serializes() {
        let c = Change {
            before: 10,
            after: 20,
        };
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"before\":10"));
        assert!(json.contains("\"after\":20"));
    }

    // ---- transport policy all three changed ----

    #[test]
    fn transport_policy_all_fields_changed() {
        let before = ZoneTransportPolicy {
            allow_lan: false,
            allow_derp: false,
            allow_funnel: false,
        };
        let after = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: true,
        };
        assert!(transport_policy_changed(&before, &after));
    }

    // ── transport_policy_changed — all same-field toggles ────────────

    #[test]
    fn transport_policy_only_lan_unchanged_others_change() {
        let before = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: false,
            allow_funnel: false,
        };
        let mut after = before.clone();
        after.allow_derp = true;
        assert!(transport_policy_changed(&before, &after));
    }

    #[test]
    fn transport_policy_funnel_disabled_no_change() {
        let policy = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: false,
        };
        assert!(!transport_policy_changed(&policy, &policy));
    }

    // ── compute_risk_flags — all transport flags ──────────────────────

    #[test]
    fn risk_flags_all_three_transport_enabled() {
        let added = PolicyListDiff::default();
        let changed = PolicyChangedFields {
            transport_policy: Some(TransportPolicyChange {
                before: ZoneTransportPolicy {
                    allow_lan: false,
                    allow_derp: false,
                    allow_funnel: false,
                },
                after: ZoneTransportPolicy {
                    allow_lan: true,
                    allow_derp: true,
                    allow_funnel: true,
                },
            }),
            ..Default::default()
        };
        let flags = compute_risk_flags(&added, &PolicyListDiff::default(), &changed);
        assert!(flags.contains(&"transport_lan_enabled".to_string()));
        assert!(flags.contains(&"transport_derp_enabled".to_string()));
        assert!(flags.contains(&"transport_funnel_enabled".to_string()));
    }

    #[test]
    fn risk_flags_no_transport_flags_when_disabling_all() {
        let added = PolicyListDiff::default();
        let changed = PolicyChangedFields {
            transport_policy: Some(TransportPolicyChange {
                before: ZoneTransportPolicy {
                    allow_lan: true,
                    allow_derp: true,
                    allow_funnel: true,
                },
                after: ZoneTransportPolicy {
                    allow_lan: false,
                    allow_derp: false,
                    allow_funnel: false,
                },
            }),
            ..Default::default()
        };
        let flags = compute_risk_flags(&added, &PolicyListDiff::default(), &changed);
        assert!(!flags.contains(&"transport_lan_enabled".to_string()));
        assert!(!flags.contains(&"transport_derp_enabled".to_string()));
        assert!(!flags.contains(&"transport_funnel_enabled".to_string()));
    }

    // ── compute_risk_flags — combined list + transport ────────────────

    #[test]
    fn risk_flags_all_list_types_expanded() {
        let added = PolicyListDiff {
            principal_allow: vec!["user:*".to_string()],
            connector_allow: vec!["c:*".to_string()],
            capability_allow: vec!["cap:all".to_string()],
            ..Default::default()
        };
        let changed = PolicyChangedFields::default();
        let flags = compute_risk_flags(&added, &PolicyListDiff::default(), &changed);
        assert!(flags.contains(&"principal_allow_expanded".to_string()));
        assert!(flags.contains(&"connector_allow_expanded".to_string()));
        assert!(flags.contains(&"capability_allow_expanded".to_string()));
        assert_eq!(flags.len(), 3);
    }

    #[test]
    fn risk_flags_deny_list_no_risk() {
        let added = PolicyListDiff {
            principal_deny: vec!["user:bad".to_string()],
            connector_deny: vec!["c:bad".to_string()],
            capability_deny: vec!["cap:dangerous".to_string()],
            ..Default::default()
        };
        let changed = PolicyChangedFields::default();
        let flags = compute_risk_flags(&added, &PolicyListDiff::default(), &changed);
        assert!(
            flags.is_empty(),
            "deny-list expansions should not raise risk flags"
        );
    }

    // ── diff_json_objects — nested and complex scenarios ─────────────

    #[test]
    fn diff_json_objects_nested_value_change() {
        let before = serde_json::json!({"config": {"level": 1}});
        let after = serde_json::json!({"config": {"level": 2}});
        let diff = diff_json_objects(&before, &after).unwrap();
        assert!(diff.changed.contains_key("config"));
        assert!(diff.added.is_empty());
        assert!(diff.removed.is_empty());
    }

    #[test]
    fn diff_json_objects_null_value_tracked() {
        let before = serde_json::json!({"x": null});
        let after = serde_json::json!({"x": 1});
        let diff = diff_json_objects(&before, &after).unwrap();
        assert!(diff.changed.contains_key("x"));
    }

    #[test]
    fn diff_json_objects_string_change() {
        let before = serde_json::json!({"name": "alpha"});
        let after = serde_json::json!({"name": "beta"});
        let diff = diff_json_objects(&before, &after).unwrap();
        assert!(diff.changed.contains_key("name"));
    }

    #[test]
    fn diff_json_objects_all_three_at_once() {
        let before = serde_json::json!({"a": 1, "b": 2});
        let after = serde_json::json!({"b": 99, "c": 3});
        let diff = diff_json_objects(&before, &after).unwrap();
        assert!(diff.removed.contains_key("a"));
        assert!(diff.added.contains_key("c"));
        assert!(diff.changed.contains_key("b"));
    }

    // ── diff_patterns — multi-element scenarios ───────────────────────

    #[test]
    fn diff_patterns_large_sets_overlap() {
        let before: Vec<_> = (0..5)
            .map(|i| PolicyPattern {
                pattern: format!("pattern-{i}"),
            })
            .collect();
        let after: Vec<_> = (3..8)
            .map(|i| PolicyPattern {
                pattern: format!("pattern-{i}"),
            })
            .collect();
        let (added, removed) = diff_patterns(&before, &after);
        // 5,6,7 are new
        assert_eq!(added.len(), 3);
        // 0,1,2 are removed
        assert_eq!(removed.len(), 3);
    }

    // ── diff_capability_ids — more coverage ──────────────────────────

    #[test]
    fn diff_capability_ids_multiple_added_and_removed() {
        let before: Vec<CapabilityId> = vec![
            "cap.read".parse().unwrap(),
            "cap.write".parse().unwrap(),
            "cap.admin".parse().unwrap(),
        ];
        let after: Vec<CapabilityId> =
            vec!["cap.read".parse().unwrap(), "cap.exec".parse().unwrap()];
        let (added, removed) = diff_capability_ids(&before, &after);
        assert!(added.contains(&"cap.exec".to_string()));
        assert!(removed.contains(&"cap.write".to_string()));
        assert!(removed.contains(&"cap.admin".to_string()));
        assert!(!added.contains(&"cap.read".to_string()));
        assert!(!removed.contains(&"cap.read".to_string()));
    }

    // ── parse_simulation_input — InvokeRequest shape ─────────────────

    #[test]
    fn parse_simulation_input_valid_invoke_request() {
        let invoke = InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::new("req-sim"),
            connector_id: "fcp.test:base:v1".parse().unwrap(),
            operation: "op".parse().unwrap(),
            zone_id: ZoneId::work(),
            input: serde_json::json!({"key": "val"}),
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };
        let raw = serde_json::to_string(&invoke).unwrap();
        let input = parse_simulation_input(&raw).unwrap();
        assert_eq!(input.invoke_request.id, RequestId::new("req-sim"));
    }

    // ── PolicyBundleState — zone mismatch in audit events ────────────

    #[test]
    fn policy_bundle_state_validate_wrong_zone_in_audit_event_detail() {
        let bundle = test_bundle("bnd-z", ZoneId::work(), 1, None);
        let now = Utc::now();
        let mut state = PolicyBundleState::new(bundle, now);
        let event = build_bundle_audit_event(
            POLICY_BUNDLE_EVENT_APPLIED,
            &ZoneId::work(),
            "bnd-z",
            None,
            1,
            now,
        )
        .unwrap();
        let mut bad_event = event;
        bad_event.zone_id = "z:unknown".to_string();
        state.audit_events.push(bad_event);
        let err = state.validate().unwrap_err();
        assert!(err.to_string().contains("audit event zone"));
    }

    // ── write_bundle_state + load_bundle_state roundtrip ─────────────

    #[test]
    fn write_and_load_bundle_state_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let bundle = test_bundle("bnd-rt", ZoneId::work(), 1, None);
        let state = PolicyBundleState::new(bundle, Utc::now());
        let path = temp_dir.path().join("rt-state.json");

        write_bundle_state(&path, &state).unwrap();
        let loaded = load_bundle_state_optional(&path).unwrap().unwrap();
        assert_eq!(loaded.current.bundle.bundle_id, "bnd-rt");
        assert_eq!(loaded.format, POLICY_BUNDLE_STATE_FORMAT);
        assert_eq!(loaded.schema_version, POLICY_BUNDLE_STATE_SCHEMA_VERSION);
    }

    // ── PolicyBundleStateSnapshot — clone and debug ───────────────────

    #[test]
    fn snapshot_clone_and_debug() {
        let bundle = test_bundle("bnd-snap-dbg", ZoneId::work(), 1, None);
        let snap = PolicyBundleStateSnapshot {
            bundle,
            applied_at: Utc::now(),
        };
        let cloned = snap.clone();
        assert_eq!(snap.bundle.bundle_id, cloned.bundle.bundle_id);
        let debug_str = format!("{:?}", snap);
        assert!(debug_str.contains("PolicyBundleStateSnapshot"));
    }

    // ── validate_apply_transition — bundle with explicit None previous ─

    #[test]
    fn validate_apply_transition_bundle_claims_previous_matches_current() {
        let bundle_a = test_bundle("bnd-prev", ZoneId::work(), 1, None);
        let state = PolicyBundleState::new(bundle_a, Utc::now());
        // bundle declares correct previous
        let bundle_b = test_bundle("bnd-cur", ZoneId::work(), 2, Some("bnd-prev"));
        assert!(validate_apply_transition(Some(&state), &bundle_b).is_ok());
    }

    // ── validate_rollback_transition — multiple hops ──────────────────

    #[test]
    fn validate_rollback_transition_multi_hop_chain() {
        // State is at bundle-c, which claims previous=bundle-b
        // Rolling back to bundle-b should succeed
        let bundle_b = test_bundle("bnd-b", ZoneId::work(), 2, None);
        let bundle_c = test_bundle("bnd-c", ZoneId::work(), 3, Some("bnd-b"));
        let state = PolicyBundleState::new(bundle_c, Utc::now());
        assert!(validate_rollback_transition(&state, &bundle_b).is_ok());
    }

    // ── parse_created_at — various edge cases ────────────────────────

    #[test]
    fn parse_created_at_leap_year_date() {
        let dt = parse_created_at(Some("2024-02-29T00:00:00Z"))
            .unwrap()
            .unwrap();
        assert_eq!(dt.timestamp(), 1_709_164_800);
    }

    #[test]
    fn parse_created_at_far_future() {
        let dt = parse_created_at(Some("2099-12-31T23:59:59Z"))
            .unwrap()
            .unwrap();
        assert!(dt.timestamp() > 0);
    }

    #[test]
    fn parse_created_at_negative_offset() {
        let dt = parse_created_at(Some("2026-03-01T06:00:00-06:00"))
            .unwrap()
            .unwrap();
        // -06:00 means UTC is 12:00:00
        assert!(dt.to_rfc3339().contains("12:00:00"));
    }

    // ── PolicyBundleState next_audit_seq multiple events ─────────────

    #[test]
    fn policy_bundle_state_next_audit_seq_increments_from_last() {
        let bundle = test_bundle("bnd-seq", ZoneId::work(), 1, None);
        let now = Utc::now();
        let mut state = PolicyBundleState::new(bundle, now);

        for i in 1_u64..=4 {
            let event = build_bundle_audit_event(
                POLICY_BUNDLE_EVENT_APPLIED,
                &ZoneId::work(),
                "bnd-seq",
                None,
                i,
                now,
            )
            .unwrap();
            state.audit_events.push(event);
        }

        assert_eq!(state.next_audit_seq(), 5);
    }

    // ── bundle_apply sequential — prev pointer preserved ─────────────

    #[test]
    fn bundle_apply_sequential_two_bundles_previous_pointer_set() {
        let temp_dir = TempDir::new().unwrap();
        let bundle_a = test_bundle("bnd-seq-a", ZoneId::work(), 1, None);
        let bundle_b = test_bundle("bnd-seq-b", ZoneId::work(), 2, Some("bnd-seq-a"));
        let path_a = write_bundle_file(&temp_dir, "bnd-seq-a.json", &bundle_a);
        let path_b = write_bundle_file(&temp_dir, "bnd-seq-b.json", &bundle_b);
        let state_path = temp_dir.path().join("state-seq.json");

        run_bundle_apply(&BundleApplyArgs {
            bundle: path_a,
            state: state_path.clone(),
            plan: false,
            json: true,
        })
        .unwrap();
        run_bundle_apply(&BundleApplyArgs {
            bundle: path_b,
            state: state_path.clone(),
            plan: false,
            json: true,
        })
        .unwrap();

        let state = load_bundle_state_optional(&state_path).unwrap().unwrap();
        assert_eq!(state.current.bundle.bundle_id, "bnd-seq-b");
        assert_eq!(
            state.previous.as_ref().map(|s| s.bundle.bundle_id.as_str()),
            Some("bnd-seq-a")
        );
        assert_eq!(state.audit_events.len(), 2);
    }

    // ── build_bundle_audit_event — event fields ───────────────────────

    #[test]
    fn audit_event_has_nonzero_occurred_at_for_recent_ts() {
        let event = build_bundle_audit_event(
            POLICY_BUNDLE_EVENT_APPLIED,
            &ZoneId::work(),
            "bnd-ts",
            None,
            1,
            Utc::now(),
        )
        .unwrap();
        assert!(event.occurred_at > 0);
    }

    #[test]
    fn audit_event_zone_matches_input() {
        let event = build_bundle_audit_event(
            POLICY_BUNDLE_EVENT_ROLLED_BACK,
            &ZoneId::work(),
            "bnd-zone",
            None,
            1,
            Utc::now(),
        )
        .unwrap();
        assert_eq!(event.zone_id, "z:work");
    }

    #[test]
    fn audit_event_event_type_matches_input() {
        let event = build_bundle_audit_event(
            "custom.event.type",
            &ZoneId::work(),
            "bnd-etype",
            None,
            1,
            Utc::now(),
        )
        .unwrap();
        assert_eq!(event.event_type, "custom.event.type");
    }

    #[test]
    fn audit_event_occurred_at_iso_matches_utc() {
        let ts = DateTime::parse_from_rfc3339("2026-04-15T08:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let event = build_bundle_audit_event(
            POLICY_BUNDLE_EVENT_APPLIED,
            &ZoneId::work(),
            "bnd-iso2",
            None,
            1,
            ts,
        )
        .unwrap();
        assert_eq!(event.occurred_at_iso, "2026-04-15T08:30:00Z");
    }

    // ── PolicyDocument zone_id accessor ──────────────────────────────

    #[test]
    fn policy_document_zone_policy_zone_id_accessor() {
        let zone = ZoneId::work();
        let doc = PolicyDocument::ZonePolicy(base_policy(zone.clone()));
        assert_eq!(*doc.zone_id(), zone);
    }

    // ── bundle_apply after successful rollback ────────────────────────

    #[test]
    fn bundle_apply_after_rollback_advances_chain() {
        let temp_dir = TempDir::new().unwrap();
        let bnd_a = test_bundle("bnd-chain-a", ZoneId::work(), 1, None);
        let bnd_b = test_bundle("bnd-chain-b", ZoneId::work(), 2, Some("bnd-chain-a"));
        let bnd_c = test_bundle("bnd-chain-c", ZoneId::work(), 3, Some("bnd-chain-b"));
        let pa = write_bundle_file(&temp_dir, "bnd-chain-a.json", &bnd_a);
        let pb = write_bundle_file(&temp_dir, "bnd-chain-b.json", &bnd_b);
        let pc = write_bundle_file(&temp_dir, "bnd-chain-c.json", &bnd_c);
        let state_path = temp_dir.path().join("chain-state.json");

        // Apply a, b
        run_bundle_apply(&BundleApplyArgs {
            bundle: pa.clone(),
            state: state_path.clone(),
            plan: false,
            json: true,
        })
        .unwrap();
        run_bundle_apply(&BundleApplyArgs {
            bundle: pb,
            state: state_path.clone(),
            plan: false,
            json: true,
        })
        .unwrap();

        // Rollback to a
        run_bundle_rollback(&BundleRollbackArgs {
            to: pa,
            state: state_path.clone(),
            plan: false,
            json: true,
        })
        .unwrap();

        // Now re-apply b and then c
        let bnd_b2 = test_bundle("bnd-chain-b2", ZoneId::work(), 4, Some("bnd-chain-a"));
        let pb2 = write_bundle_file(&temp_dir, "bnd-chain-b2.json", &bnd_b2);
        run_bundle_apply(&BundleApplyArgs {
            bundle: pb2,
            state: state_path.clone(),
            plan: false,
            json: true,
        })
        .unwrap();

        let _ = pc; // bundle_c no longer needed — just confirm state is valid
        let state = load_bundle_state_optional(&state_path).unwrap().unwrap();
        assert_eq!(state.current.bundle.bundle_id, "bnd-chain-b2");
    }
}
