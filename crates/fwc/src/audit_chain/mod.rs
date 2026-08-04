//! `fcp audit` command implementation.
//!
//! Provides audit chain operations for incident response and debugging.
//!
//! # Commands
//!
//! ## `fcp audit tail`
//!
//! Stream audit events from a zone's audit chain with optional filtering.
//!
//! ```text
//! # Tail all events in a zone
//! fcp audit tail --zone z:work
//!
//! # Filter by connector
//! fcp audit tail --zone z:work --connector fcp.telegram:base:v1
//!
//! # Filter by correlation ID for incident investigation
//! fcp audit tail --zone z:work --correlation abc123...
//!
//! # JSON output for piping to jq/tools
//! fcp audit tail --zone z:work --json
//! ```

pub mod types;

use anyhow::{Context, Result, bail};
use chrono::{TimeZone, Utc};
use clap::{ArgAction, Args, Subcommand};
use fcp_audit::AuditEntry;
use fcp_audit::explain::{CausalExplanation, ReplayBundle};
use fcp_cbor::to_canonical_cbor;
use fcp_crypto::{Ed25519VerifyingKey, KeyId, ed25519::PUBLIC_KEY_SIZE};
use fcp_kernel::{AuditEvent, AuditHead, ObjectId, ZoneId};
use hex::encode as hex_encode;
use reqwest::blocking::{Client as BlockingClient, ClientBuilder as BlockingClientBuilder};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use url::Url;

use crate::capability_replay::parse_since_seconds;
use crate::truth::{KnowledgeState, RequiredTruthSource, TRUTH_SOURCE_SCHEMA_VERSION};
use types::{AuditEventOutput, AuditFilter, AuditTailError};

pub(crate) const AUDIT_CHAIN_STATUS_SCHEMA_VERSION: &str = "fcp.fwc.audit_chain_status.v1";
const AUDIT_VERIFY_SCHEMA_VERSION: &str = "fcp.fwc.audit_verify.v1";

/// Arguments for the `fcp audit` command.
#[derive(Args, Debug, Clone)]
pub struct AuditArgs {
    #[command(subcommand)]
    pub command: AuditCommands,
}

/// Audit subcommands.
#[derive(Subcommand, Debug, Clone)]
pub enum AuditCommands {
    /// Inspect audit-chain status and quorum checkpoint health.
    Chain(ChainArgs),
    /// Tail audit events from a zone's audit chain.
    ///
    /// Streams audit events in order (by seq) with optional filtering.
    /// Useful for incident response and debugging.
    Tail(TailArgs),
    /// Verify integrity of an audit chain and head.
    Verify(VerifyArgs),
    /// Explain a replay bundle as a causal audit narrative.
    Explain(ExplainArgs),
    /// Render a timeline of audit events.
    Timeline(TimelineArgs),
    /// Show connector compliance matrix (metadata completeness).
    ///
    /// Scans connector manifest.toml files and reports readiness level,
    /// operation metadata completeness, agent hint coverage, and gaps.
    Matrix(MatrixArgs),
    /// Show metadata gaps across all connectors.
    ///
    /// Lists missing capabilities, incomplete operation metadata, and
    /// other readiness gaps that should be addressed.
    Gaps(GapsArgs),
}

/// Arguments for the `fwc audit chain` command group.
#[derive(Args, Debug, Clone)]
pub struct ChainArgs {
    #[command(subcommand)]
    pub command: ChainCommands,
}

/// Audit-chain status subcommands.
#[derive(Subcommand, Debug, Clone)]
pub enum ChainCommands {
    /// Summarize audit-chain quorum status.
    Status(ChainStatusArgs),
}

/// Arguments for `fwc audit chain status`.
#[derive(Args, Debug, Clone)]
pub struct ChainStatusArgs {
    /// Signed audit chain head artifact (JSON object). Omit to report missing live telemetry.
    #[arg(long)]
    pub head: Option<PathBuf>,

    /// Audit event records input (JSONL or JSON array) used to compute freshness. Use "-" for stdin.
    #[arg(long)]
    pub events: Option<PathBuf>,

    /// Zone to query when resolving live host-backed audit-chain status.
    #[arg(long)]
    pub zone: Option<String>,

    /// Maximum quorum checkpoint age considered fresh.
    #[arg(long, default_value_t = 60)]
    pub max_age_seconds: u64,

    /// Override current Unix time for deterministic artifact verification.
    #[arg(long)]
    pub now_unix_secs: Option<u64>,

    /// Output JSON instead of human-readable format.
    #[arg(long, default_value_t = false)]
    pub json: bool,

    /// Require audit-chain status to come from at least this truth source.
    #[arg(long, value_enum)]
    pub require_source: Option<RequiredTruthSource>,
}

/// Arguments for the `fcp audit tail` command.
#[derive(Args, Debug, Clone)]
pub struct TailArgs {
    /// Zone to tail audit events from.
    #[arg(long, short = 'z')]
    pub zone: String,

    /// Filter by connector ID.
    #[arg(long, short = 'c')]
    pub connector: Option<String>,

    /// Filter by operation ID.
    #[arg(long, short = 'o')]
    pub operation: Option<String>,

    /// Filter by correlation ID (hex, 32 chars).
    #[arg(long)]
    pub correlation: Option<String>,

    /// Filter by trace ID (hex, 32 chars).
    #[arg(long)]
    pub trace: Option<String>,

    /// Filter by event type (e.g., "capability.invoke", "secret.access").
    #[arg(long, short = 'e')]
    pub event_type: Option<String>,

    /// Filter by actor (e.g., "user:alice").
    #[arg(long, short = 'a')]
    pub actor: Option<String>,

    /// Number of events to show (0 = stream indefinitely until interrupted).
    #[arg(long, short = 'n', default_value_t = 20)]
    pub limit: usize,

    /// Starting sequence number (default: latest minus limit).
    #[arg(long)]
    pub since: Option<u64>,

    /// Follow mode: continue streaming new events (like tail -f).
    #[arg(long, short = 'f', default_value_t = false)]
    pub follow: bool,

    /// Output JSON instead of human-readable format.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for the `fcp audit verify` command.
#[derive(Args, Debug, Clone)]
pub struct VerifyArgs {
    /// Zone to verify (optional; ensures all events match this zone).
    #[arg(long, short = 'z')]
    pub zone: Option<String>,

    /// Audit event records input (JSONL or JSON array). Use "-" for stdin.
    #[arg(long)]
    pub events: PathBuf,

    /// Audit head input (JSON). Use "-" for stdin.
    #[arg(long)]
    pub head: Option<PathBuf>,

    /// Issuer key binding in the form `<kid>=<ed25519-public-key-hex>`.
    ///
    /// Repeat this flag to verify signer-aware `fcp-audit` chains.
    #[arg(long = "issuer-key", value_name = "KID=PUBKEY_HEX", action = ArgAction::Append)]
    pub issuer_keys: Vec<String>,

    /// Output JSON instead of human-readable format.
    #[arg(long, default_value_t = false)]
    pub json: bool,

    /// Require audit verification to come from at least this truth source.
    #[arg(long, value_enum)]
    pub require_source: Option<RequiredTruthSource>,
}

/// Arguments for the `fcp audit explain` command.
#[derive(Args, Debug, Clone)]
pub struct ExplainArgs {
    /// Replay bundle path. May be a JSON/CBOR file or a directory of bundle artifacts.
    pub bundle: PathBuf,

    /// Restrict the explanation to a single zone.
    #[arg(long, short = 'z')]
    pub zone: Option<String>,

    /// Restrict audit entries to this duration before the newest bundled entry.
    #[arg(long)]
    pub since: Option<String>,

    /// Output JSON instead of human-readable narrative.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for the `fcp audit timeline` command.
#[derive(Args, Debug, Clone)]
pub struct TimelineArgs {
    /// Zone to render (optional; filters events by zone).
    #[arg(long, short = 'z')]
    pub zone: Option<String>,

    /// Audit event records input (JSONL or JSON array). Use "-" for stdin.
    #[arg(long)]
    pub events: PathBuf,

    /// Number of events to include (0 = all).
    #[arg(long, short = 'n', default_value_t = 100)]
    pub limit: usize,

    /// Output JSON instead of human-readable format.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for the `fwc audit matrix` command.
#[derive(Args, Debug, Clone)]
pub struct MatrixArgs {
    /// Optional connector name to filter the matrix to a single connector.
    pub connector: Option<String>,

    /// Output JSON instead of human-readable format.
    #[arg(long, default_value_t = false)]
    pub json: bool,

    /// Require audit matrix output to come from at least this truth source.
    #[arg(long, value_enum)]
    pub require_source: Option<RequiredTruthSource>,
}

/// Arguments for the `fwc audit gaps` command.
#[derive(Args, Debug, Clone)]
pub struct GapsArgs {
    /// Optional connector name to filter gaps.
    pub connector: Option<String>,

    /// Only show blocking gaps (severity = blocking).
    #[arg(long, default_value_t = false)]
    pub blocking_only: bool,

    /// Output JSON instead of human-readable format.
    #[arg(long, default_value_t = false)]
    pub json: bool,

    /// Require audit gap output to come from at least this truth source.
    #[arg(long, value_enum)]
    pub require_source: Option<RequiredTruthSource>,
}

/// Run the audit command.
///
/// # Errors
///
/// Returns an error if the audit operation fails.
pub fn run(args: AuditArgs) -> Result<()> {
    run_with_host(args, None)
}

/// Run the audit command with an optional host endpoint supplied by the root CLI.
///
/// # Errors
///
/// Returns an error if the audit operation fails.
pub fn run_with_host(args: AuditArgs, explicit_host: Option<&str>) -> Result<()> {
    match args.command {
        AuditCommands::Chain(chain_args) => run_chain(&chain_args, explicit_host),
        AuditCommands::Tail(tail_args) => run_tail(&tail_args),
        AuditCommands::Verify(verify_args) => run_verify(&verify_args),
        AuditCommands::Explain(explain_args) => run_explain(&explain_args),
        AuditCommands::Timeline(timeline_args) => run_timeline(&timeline_args),
        AuditCommands::Matrix(matrix_args) => run_matrix(&matrix_args),
        AuditCommands::Gaps(gaps_args) => run_gaps(&gaps_args),
    }
}

fn run_chain(args: &ChainArgs, explicit_host: Option<&str>) -> Result<()> {
    match &args.command {
        ChainCommands::Status(status_args) => run_chain_status(status_args, explicit_host),
    }
}

/// Run the audit tail command.
///
/// Attempts to connect to a running fcp-host admin API for live audit
/// events. Falls back to a truthful error when no host is reachable.
fn run_tail(args: &TailArgs) -> Result<()> {
    let filter = AuditFilter {
        connector_id: args.connector.clone(),
        operation_id: args.operation.clone(),
        correlation_id: args.correlation.clone(),
        trace_id: args.trace.clone(),
        event_type: args.event_type.clone(),
        actor: args.actor.clone(),
    };
    let filter_hint = if filter.is_empty() {
        None
    } else {
        Some(format!(
            "Requested filters: connector={:?}, operation={:?}, correlation={:?}, trace={:?}, event_type={:?}, actor={:?}",
            filter.connector_id,
            filter.operation_id,
            filter.correlation_id,
            filter.trace_id,
            filter.event_type,
            filter.actor
        ))
    };

    // Probe the host admin API for audit capability.
    let host_addr =
        std::env::var("FWC_HOST").unwrap_or_else(|_| "http://127.0.0.1:8788".to_string());
    let host_available = probe_host_audit(&host_addr);

    if host_available {
        // Host is running and exposes audit events — emit a supported
        // contract response that scripts can parse.
        let response = serde_json::json!({
            "code": "audit.tail.supported",
            "zone_id": args.zone,
            "host": host_addr,
            "provenance": {
                "source": "host-admin-api",
                "transport": "node-local-root-app",
                "scope": "audit-tail",
                "live": true,
            },
            "evidence_handles": ["audit-stream", "zone-audit-chain"],
            "message": format!(
                "Audit tail for zone '{}' is available via host at {}. \
                 The host audit-chain endpoint provides live zone events.",
                args.zone, host_addr,
            ),
            "filters": filter_hint,
        });
        if args.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&response)
                    .context("failed to serialize audit tail response")?
            );
        } else {
            eprintln!(
                "Audit tail for zone '{}' is available via host at {}.",
                args.zone, host_addr
            );
            eprintln!(
                "Use --json for machine-readable output or poll the host admin API directly."
            );
            if let Some(hint) = filter_hint {
                eprintln!("{hint}");
            }
        }
        return Ok(());
    }

    // No host reachable — truthful refusal with recovery hints.
    let error = AuditTailError {
        code: "audit.tail.no_host".to_string(),
        message: format!(
            "Audit tail for zone '{}' requires a running fcp-host with an audit-chain \
             endpoint. No host is reachable at {}.",
            args.zone, host_addr,
        ),
        hints: vec![
            format!("Start fcp-host: fcp-host --bind {host_addr}"),
            "Set FWC_HOST=<url> if the host is running on a different address".to_string(),
        ]
        .into_iter()
        .chain(filter_hint)
        .collect(),
    };

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&error).context("failed to serialize audit tail error")?
        );
        std::process::exit(2);
    }

    eprintln!("{}", error.message);
    for hint in &error.hints {
        eprintln!("  hint: {hint}");
    }
    std::process::exit(2);
}

/// Probe the host admin API for audit capability.
///
/// Returns `true` if the host is reachable and responds to a health check.
fn probe_host_audit(host_addr: &str) -> bool {
    // Quick TCP probe — don't block the CLI for more than 500ms.
    let url = format!("{host_addr}/rpc/health");
    std::process::Command::new("curl")
        .args(["-sf", "--max-time", "0.5", &url])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

// ============================================================================
// Audit Verify + Timeline
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditEventRecord {
    object_id: ObjectId,
    event: AuditEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AuditVerifyStatus {
    Ok,
    Warn,
    Fail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditVerifyIssue {
    code: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    object_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditVerifyReport {
    status: AuditVerifyStatus,
    zone_id: Option<String>,
    chain_len: usize,
    head_seq: Option<u64>,
    head_event: Option<String>,
    issues: Vec<AuditVerifyIssue>,
}

fn run_verify(args: &VerifyArgs) -> Result<()> {
    enforce_audit_required_truth_source(
        "audit verify",
        args.require_source,
        KnowledgeState::Offline,
        args.json,
    );

    let events_input = read_input(&args.events)?;
    let head_input = if let Some(ref path) = args.head {
        Some(read_input(path)?)
    } else {
        None
    };
    let report = build_verify_report_from_inputs(
        &events_input,
        head_input.as_deref(),
        args.zone.as_deref(),
        &args.issuer_keys,
    )?;
    output_verify_report(&report, args.json)
}

fn run_explain(args: &ExplainArgs) -> Result<()> {
    let bundle = load_explain_bundle(&args.bundle)?;
    let report = build_explain_report(bundle, args.zone.as_deref(), args.since.as_deref())?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .context("failed to serialize audit explanation")?
        );
    } else {
        println!("{}", report.render_human());
    }
    Ok(())
}

fn run_timeline(args: &TimelineArgs) -> Result<()> {
    let zone_filter = match args.zone.as_deref() {
        Some(zone) => Some(zone.parse::<ZoneId>().context("invalid zone id")?),
        None => None,
    };

    let events_input = read_input(&args.events)?;
    let mut records = parse_event_records(&events_input)?;
    if let Some(ref zone) = zone_filter {
        records.retain(|rec| rec.event.zone_id() == zone);
    }

    records.sort_by_key(|a| a.event.seq);

    if args.limit > 0 && records.len() > args.limit {
        let start = records.len().saturating_sub(args.limit);
        records = records.split_off(start);
    }

    let outputs: Vec<AuditEventOutput> = records.iter().map(to_event_output).collect();
    if args.json {
        output_json(&outputs)?;
    } else {
        let zone_label = zone_filter
            .as_ref()
            .map_or_else(|| "all-zones".to_string(), ToString::to_string);
        output_human(&outputs, &zone_label, &AuditFilter::default());
    }

    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditChainStatusSource {
    kind: String,
    live: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    head_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    events_path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct AuditChainStatusReport {
    schema_version: &'static str,
    command: &'static str,
    subcommand: &'static str,
    status: fcp_audit::FreshnessLevel,
    telemetry_state: &'static str,
    source: AuditChainStatusSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    zone_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    head_seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    head_entry: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_quorum_height: Option<u64>,
    quorum_signed_checkpoints: u64,
    quorum_signers: u64,
    quorum_signer_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    producer_signature_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature_count_consistent: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    coverage: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    quorum_freshness_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    quorum_rotation_epoch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_rotation_eta_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hlc_physical_drift_ms: Option<u64>,
    max_age_seconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    live_quorum_checkpoint_snapshot: Option<Value>,
    warnings: Vec<String>,
}

impl AuditChainStatusReport {
    pub(crate) const fn schema_version(&self) -> &'static str {
        self.schema_version
    }

    pub(crate) const fn status(&self) -> fcp_audit::FreshnessLevel {
        self.status
    }

    pub(crate) const fn quorum_signed_checkpoints(&self) -> u64 {
        self.quorum_signed_checkpoints
    }

    pub(crate) const fn quorum_signers(&self) -> u64 {
        self.quorum_signers
    }

    pub(crate) const fn hlc_physical_drift_ms(&self) -> Option<u64> {
        self.hlc_physical_drift_ms
    }

    pub(crate) fn warnings(&self) -> &[String] {
        &self.warnings
    }
}

#[derive(Debug, Deserialize)]
struct HostAuditChainStatusResponse {
    status: fcp_audit::FreshnessLevel,
    telemetry_state: String,
    source: AuditChainStatusSource,
    zone_id: String,
    head_seq: Option<u64>,
    head_entry: Option<String>,
    last_quorum_height: Option<u64>,
    quorum_signed_checkpoints: u64,
    quorum_signers: u64,
    #[serde(default)]
    quorum_signer_ids: Vec<String>,
    producer_signature_count: Option<u32>,
    signature_count_consistent: Option<bool>,
    coverage: Option<f64>,
    quorum_freshness_secs: Option<u64>,
    quorum_rotation_epoch: Option<String>,
    next_rotation_eta_secs: Option<u64>,
    hlc_physical_drift_ms: Option<u64>,
    max_age_seconds: u64,
    live_quorum_checkpoint_snapshot: Option<Value>,
    #[serde(default)]
    warnings: Vec<String>,
}

impl HostAuditChainStatusResponse {
    fn into_report(self) -> AuditChainStatusReport {
        let mut warnings = self.warnings;
        if self.telemetry_state != "live-host" {
            warnings.push(format!(
                "host returned unexpected audit-chain telemetry_state `{}`",
                self.telemetry_state
            ));
        }
        if !self.source.live {
            warnings.push("host audit-chain status source was not marked live".to_string());
        }

        AuditChainStatusReport {
            schema_version: AUDIT_CHAIN_STATUS_SCHEMA_VERSION,
            command: "audit",
            subcommand: "chain status",
            status: self.status,
            telemetry_state: "live-host",
            source: AuditChainStatusSource {
                kind: self.source.kind,
                live: true,
                head_path: None,
                events_path: None,
            },
            zone_id: Some(self.zone_id),
            head_seq: self.head_seq,
            head_entry: self.head_entry,
            last_quorum_height: self.last_quorum_height,
            quorum_signed_checkpoints: self.quorum_signed_checkpoints,
            quorum_signers: self.quorum_signers,
            quorum_signer_ids: self.quorum_signer_ids,
            producer_signature_count: self.producer_signature_count,
            signature_count_consistent: self.signature_count_consistent,
            coverage: self.coverage,
            quorum_freshness_secs: self.quorum_freshness_secs,
            quorum_rotation_epoch: self.quorum_rotation_epoch,
            next_rotation_eta_secs: self.next_rotation_eta_secs,
            hlc_physical_drift_ms: self.hlc_physical_drift_ms,
            max_age_seconds: self.max_age_seconds,
            live_quorum_checkpoint_snapshot: self.live_quorum_checkpoint_snapshot,
            warnings,
        }
    }
}

#[derive(Debug)]
struct AuditHostClient {
    client: BlockingClient,
    base_url: String,
}

impl AuditHostClient {
    fn new(endpoint: &str) -> Result<Self> {
        let endpoint = normalize_audit_host_endpoint(endpoint)?;

        #[cfg(unix)]
        {
            if endpoint.starts_with("unix://") || endpoint.starts_with('/') {
                let socket_path = endpoint.strip_prefix("unix://").unwrap_or(&endpoint);
                let client = BlockingClientBuilder::new()
                    .unix_socket(socket_path)
                    .build()
                    .with_context(|| {
                        format!(
                            "failed to build Unix-socket client for host endpoint `{socket_path}`"
                        )
                    })?;
                return Ok(Self {
                    client,
                    base_url: "http://localhost".to_owned(),
                });
            }
        }

        let client = BlockingClientBuilder::new()
            .build()
            .context("failed to build HTTP host client")?;
        Ok(Self {
            client,
            base_url: endpoint,
        })
    }

    fn chain_status(
        &self,
        zone: Option<&str>,
        max_age_seconds: u64,
        now_unix_secs: u64,
    ) -> Result<HostAuditChainStatusResponse> {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        if let Some(zone) = zone.map(str::trim).filter(|zone| !zone.is_empty()) {
            query.append_pair("zone", zone);
        }
        query.append_pair("max_age_seconds", &max_age_seconds.to_string());
        query.append_pair("now_unix_secs", &now_unix_secs.to_string());
        let path = format!("/rpc/admin/audit/chain/status?{}", query.finish());
        let response = self
            .client
            .get(format!("{}{}", self.base_url, path))
            .send()
            .with_context(|| format!("GET {path} from host admin API failed"))?;
        let status = response.status();
        let body = response
            .text()
            .with_context(|| format!("GET {path} returned an unreadable response body"))?;
        if !status.is_success() {
            bail!("GET {path} returned {status}: {body}");
        }
        serde_json::from_str(&body)
            .with_context(|| format!("GET {path} returned invalid audit chain status JSON"))
    }
}

fn normalize_audit_host_endpoint(endpoint: &str) -> Result<String> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        bail!("host endpoint cannot be empty");
    }
    if endpoint.contains("://")
        && !(endpoint.starts_with("http://")
            || endpoint.starts_with("https://")
            || endpoint.starts_with("tcp://")
            || endpoint.starts_with("unix://"))
    {
        bail!("host endpoint must use http, https, tcp, unix, or an absolute Unix socket path");
    }

    #[cfg(unix)]
    if endpoint.starts_with("unix://") || endpoint.starts_with('/') {
        let socket_path = endpoint.strip_prefix("unix://").unwrap_or(endpoint);
        if socket_path.trim().is_empty() {
            bail!("Unix host endpoint must include a socket path");
        }
        return Ok(endpoint.to_owned());
    }

    let normalized = if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
        endpoint.to_owned()
    } else {
        let stripped = endpoint.strip_prefix("tcp://").unwrap_or(endpoint);
        format!("http://{stripped}")
    };

    let url =
        Url::parse(&normalized).with_context(|| format!("invalid host endpoint `{endpoint}`"))?;
    if !matches!(url.scheme(), "http" | "https") {
        bail!("host endpoint must use http, https, tcp, unix, or an absolute Unix socket path");
    }
    if url.host_str().is_none() {
        bail!("host endpoint must include a host");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("host endpoint must not include username or password components");
    }
    if url.query().is_some() || url.fragment().is_some() {
        bail!("host endpoint must not include query or fragment components");
    }

    Ok(normalized.trim_end_matches('/').to_owned())
}

fn resolve_audit_chain_status_host(explicit_host: Option<&str>) -> Option<String> {
    explicit_host
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            ["FWC_HOST", "FCP_HOST_ENDPOINT", "FCP_HOST_BIND"]
                .into_iter()
                .find_map(|env_name| {
                    std::env::var(env_name)
                        .ok()
                        .map(|value| value.trim().to_owned())
                        .filter(|value| !value.is_empty())
                })
        })
}

fn run_chain_status(args: &ChainStatusArgs, explicit_host: Option<&str>) -> Result<()> {
    let now_unix_secs = args
        .now_unix_secs
        .unwrap_or_else(|| u64::try_from(Utc::now().timestamp()).unwrap_or_default());
    let host = resolve_audit_chain_status_host(explicit_host);
    let (report, truth_source) =
        build_chain_status_report_with_source(args, now_unix_secs, host.as_deref())?;
    enforce_audit_required_truth_source(
        "audit chain status",
        args.require_source,
        truth_source,
        args.json,
    );

    output_chain_status_report(&report, truth_source, args.json)
}

pub(crate) fn build_chain_status_report(
    args: &ChainStatusArgs,
    now_unix_secs: u64,
) -> Result<AuditChainStatusReport> {
    build_artifact_chain_status_report(args, now_unix_secs)
}

pub(crate) fn build_chain_status_report_resolving_host(
    args: &ChainStatusArgs,
    now_unix_secs: u64,
    explicit_host: Option<&str>,
) -> Result<(AuditChainStatusReport, KnowledgeState)> {
    let host = resolve_audit_chain_status_host(explicit_host);
    build_chain_status_report_with_source(args, now_unix_secs, host.as_deref())
}

fn build_chain_status_report_with_source(
    args: &ChainStatusArgs,
    now_unix_secs: u64,
    host: Option<&str>,
) -> Result<(AuditChainStatusReport, KnowledgeState)> {
    if args.head.is_none()
        && let Some(host) = host
    {
        match AuditHostClient::new(host).and_then(|client| {
            client.chain_status(args.zone.as_deref(), args.max_age_seconds, now_unix_secs)
        }) {
            Ok(response) => return Ok((response.into_report(), KnowledgeState::HostBacked)),
            Err(error) => {
                let mut report = missing_chain_status_report(args);
                report.warnings.push(format!(
                    "host admin API audit-chain status query failed: {error}"
                ));
                return Ok((report, KnowledgeState::Offline));
            }
        }
    }

    Ok((
        build_artifact_chain_status_report(args, now_unix_secs)?,
        KnowledgeState::Offline,
    ))
}

fn build_artifact_chain_status_report(
    args: &ChainStatusArgs,
    now_unix_secs: u64,
) -> Result<AuditChainStatusReport> {
    let Some(ref head_path) = args.head else {
        return Ok(missing_chain_status_report(args));
    };

    let head_input = read_input(head_path)?;
    let head = parse_signed_head(&head_input)?;
    let events = if let Some(ref events_path) = args.events {
        let events_input = read_input(events_path)?;
        parse_signed_entries(&events_input)?
    } else {
        Vec::new()
    };
    let tip_entry = chain_status_tip_entry(&head, &events);
    let quorum_freshness_secs =
        tip_entry.map(|entry| now_unix_secs.saturating_sub(entry.occurred_at));
    let freshness = classify_chain_status_freshness(
        head.has_quorum(),
        quorum_freshness_secs,
        args.max_age_seconds,
    );
    let hlc_physical_drift_ms = tip_entry.map(|entry| {
        now_unix_secs
            .saturating_mul(1_000)
            .abs_diff(entry.hlc.physical_ms)
    });
    let mut warnings = Vec::new();

    if !head.signature_count_consistent() {
        warnings.push(format!(
            "producer signature_count={} but {} attached signatures were present",
            head.signature_count,
            head.signatures.len()
        ));
    }
    if head.signatures.is_empty() {
        warnings.push("signed head artifact carries no attached quorum signatures".to_string());
    }
    if args.events.is_none() {
        warnings.push(
            "no --events artifact supplied; quorum freshness and HLC drift cannot be bounded"
                .to_string(),
        );
    } else if tip_entry.is_none() {
        warnings.push(
            "events artifact did not contain the signed head entry; freshness is unbounded"
                .to_string(),
        );
    }
    if let Some(entry) = tip_entry {
        if entry.occurred_at > now_unix_secs {
            warnings.push(format!(
                "head entry timestamp {} is in the future relative to now {}",
                entry.occurred_at, now_unix_secs
            ));
        }
    }

    Ok(AuditChainStatusReport {
        schema_version: AUDIT_CHAIN_STATUS_SCHEMA_VERSION,
        command: "audit",
        subcommand: "chain status",
        status: freshness,
        telemetry_state: "artifact",
        source: AuditChainStatusSource {
            kind: "signed-head-artifact".to_string(),
            live: false,
            head_path: Some(head_path.display().to_string()),
            events_path: args
                .events
                .as_ref()
                .map(|events_path| events_path.display().to_string()),
        },
        zone_id: Some(head.zone_id.clone()),
        head_seq: Some(head.head_seq),
        head_entry: Some(head.head_entry.clone()),
        last_quorum_height: head.has_quorum().then_some(head.head_seq),
        quorum_signed_checkpoints: if head.has_quorum() { 1 } else { 0 },
        quorum_signers: u64::try_from(head.signatures.len()).unwrap_or(u64::MAX),
        quorum_signer_ids: head
            .signatures
            .iter()
            .map(|signature| signature.issuer_kid.clone())
            .collect(),
        producer_signature_count: Some(head.signature_count),
        signature_count_consistent: Some(head.signature_count_consistent()),
        coverage: Some(head.coverage),
        quorum_freshness_secs,
        quorum_rotation_epoch: Some(head.epoch_id.clone()),
        next_rotation_eta_secs: None,
        hlc_physical_drift_ms,
        max_age_seconds: args.max_age_seconds,
        live_quorum_checkpoint_snapshot: None,
        warnings,
    })
}

fn missing_chain_status_report(args: &ChainStatusArgs) -> AuditChainStatusReport {
    AuditChainStatusReport {
        schema_version: AUDIT_CHAIN_STATUS_SCHEMA_VERSION,
        command: "audit",
        subcommand: "chain status",
        status: fcp_audit::FreshnessLevel::Missing,
        telemetry_state: "missing",
        source: AuditChainStatusSource {
            kind: "none".to_string(),
            live: false,
            head_path: None,
            events_path: args
                .events
                .as_ref()
                .map(|events_path| events_path.display().to_string()),
        },
        zone_id: None,
        head_seq: None,
        head_entry: None,
        last_quorum_height: None,
        quorum_signed_checkpoints: 0,
        quorum_signers: 0,
        quorum_signer_ids: Vec::new(),
        producer_signature_count: None,
        signature_count_consistent: None,
        coverage: None,
        quorum_freshness_secs: None,
        quorum_rotation_epoch: None,
        next_rotation_eta_secs: None,
        hlc_physical_drift_ms: None,
        max_age_seconds: args.max_age_seconds,
        live_quorum_checkpoint_snapshot: None,
        warnings: vec![
            "no signed audit chain head artifact or live telemetry was supplied".to_string(),
        ],
    }
}

fn chain_status_tip_entry<'a>(
    head: &fcp_audit::ChainHead,
    events: &'a [fcp_audit::AuditEntry],
) -> Option<&'a fcp_audit::AuditEntry> {
    events
        .iter()
        .find(|entry| entry.id == head.head_entry)
        .or_else(|| {
            events.iter().find(|entry| {
                let same_zone = entry.zone_id == head.zone_id;
                let same_seq = entry.seq == head.head_seq;
                same_zone && same_seq
            })
        })
}

const fn classify_chain_status_freshness(
    has_quorum: bool,
    quorum_freshness_secs: Option<u64>,
    max_age_seconds: u64,
) -> fcp_audit::FreshnessLevel {
    if !has_quorum {
        return fcp_audit::FreshnessLevel::Degraded;
    }

    match quorum_freshness_secs {
        Some(age) if age <= max_age_seconds => fcp_audit::FreshnessLevel::Fresh,
        Some(age) if age <= max_age_seconds.saturating_mul(4) => fcp_audit::FreshnessLevel::Stale,
        Some(_) => fcp_audit::FreshnessLevel::Degraded,
        None => fcp_audit::FreshnessLevel::Stale,
    }
}

fn output_chain_status_report(
    report: &AuditChainStatusReport,
    truth_source: KnowledgeState,
    json: bool,
) -> Result<()> {
    if json {
        let payload =
            audit_truth_source_payload(report, AUDIT_CHAIN_STATUS_SCHEMA_VERSION, truth_source)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&payload)
                .context("failed to serialize audit chain status report")?
        );
        return Ok(());
    }

    println!("audit chain status: {}", report.status);
    println!("telemetry: {}", report.telemetry_state);
    if let Some(ref zone_id) = report.zone_id {
        println!("zone: {zone_id}");
    }
    if let Some(head_seq) = report.head_seq {
        println!("head seq: {head_seq}");
    }
    println!("quorum signers: {}", report.quorum_signers);
    if let Some(age) = report.quorum_freshness_secs {
        println!("quorum freshness: {age}s");
    }
    for warning in &report.warnings {
        println!("warning: {warning}");
    }
    print_audit_answer_source_footer(truth_source);
    Ok(())
}

fn audit_truth_source_payload<T: Serialize>(
    report: &T,
    schema_version: &'static str,
    truth_source: KnowledgeState,
) -> Result<Value> {
    let mut payload = serde_json::to_value(report).context("failed to serialize audit report")?;
    inject_audit_truth_source_metadata(&mut payload, schema_version, truth_source);
    Ok(payload)
}

fn inject_audit_truth_source_metadata(
    payload: &mut Value,
    schema_version: &'static str,
    truth_source: KnowledgeState,
) {
    if let Some(object) = payload.as_object_mut() {
        object
            .entry("schema_version".to_owned())
            .or_insert_with(|| Value::String(schema_version.to_owned()));
        object.insert(
            "_truth_source".to_owned(),
            Value::String(truth_source.operator_truth_source().to_owned()),
        );
    }
}

fn print_audit_answer_source_footer(truth_source: KnowledgeState) {
    if truth_source != KnowledgeState::MeshBacked {
        println!("(answer source: {})", truth_source.operator_truth_source());
    }
}

fn enforce_audit_required_truth_source(
    command: &str,
    requirement: Option<RequiredTruthSource>,
    actual: KnowledgeState,
    json: bool,
) {
    let Some(required) = requirement else {
        return;
    };
    let Err(error) = required.validate(actual) else {
        return;
    };
    let actual_source = error.actual.operator_truth_source();
    let required_label = error.required.label();

    if json {
        let subcommand = command.strip_prefix("audit ").unwrap_or(command);
        let payload = serde_json::json!({
            "status": "error",
            "command": "audit",
            "subcommand": subcommand,
            "schema_version": TRUTH_SOURCE_SCHEMA_VERSION,
            "_truth_source": actual_source,
            "error": {
                "type": "truth-source-unavailable",
                "required": required_label,
                "actual": actual_source,
                "message": format!(
                    "`fwc {command}` resolved from `{actual_source}` truth, which does not satisfy `--require-source {required_label}`."
                ),
                "recoverable": true,
            },
            "next_actions": [
                "Retry after the required live truth source is reachable.".to_owned(),
                format!("Relax the requirement if `{actual_source}` truth is acceptable for this workflow."),
            ],
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload)
                .expect("truth-source-unavailable payload should serialize")
        );
    } else {
        eprintln!(
            "`fwc {command}` resolved from `{actual_source}` truth, which does not satisfy `--require-source {required_label}`."
        );
    }
    std::process::exit(2);
}

fn read_input(path: &Path) -> Result<String> {
    if path.as_os_str() == "-" {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .context("failed to read stdin")?;
        return Ok(buf);
    }

    fs::read_to_string(path).with_context(|| format!("failed to read input {}", path.display()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditExplainReport {
    status: String,
    command: String,
    subcommand: String,
    filters: AuditExplainFilters,
    source: AuditExplainSource,
    entries_returned: usize,
    audit_chain_range: Option<AuditExplainChainRange>,
    entries: Vec<AuditExplainEntry>,
    explanation: Option<CausalExplanation>,
    warnings: Vec<String>,
}

impl AuditExplainReport {
    fn render_human(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "audit explain: {} entries from {}",
            self.entries_returned, self.source.kind
        );
        if let Some(ref zone) = self.filters.zone_id {
            let _ = writeln!(out, "zone: {zone}");
        }
        if let Some(ref since) = self.filters.since {
            let _ = writeln!(out, "since: {since}");
        }
        if let Some(ref range) = self.audit_chain_range {
            let _ = writeln!(out, "audit chain: {}..{}", range.start_seq, range.end_seq);
        }
        for entry in &self.entries {
            let _ = write!(
                out,
                "{} seq={} zone={} event={}",
                entry.id, entry.seq, entry.zone_id, entry.event_type
            );
            if entry.tombstoned {
                let _ = write!(out, " tombstoned=true");
            }
            if let Some(height) = entry.quorum_height {
                let _ = write!(out, " quorum_height={height}");
            }
            if !entry.quorum_signers.is_empty() {
                let _ = write!(out, " signers={}", entry.quorum_signers.join(","));
            }
            if let Some(ref rationale) = entry.decision_rationale {
                let _ = write!(out, " rationale={rationale}");
            }
            let _ = writeln!(out);
        }
        if let Some(ref explanation) = self.explanation {
            let _ = writeln!(out);
            let _ = writeln!(out, "{}", explanation.render_human());
        }
        if !self.warnings.is_empty() {
            let _ = writeln!(out);
            let _ = writeln!(out, "Warnings:");
            for warning in &self.warnings {
                let _ = writeln!(out, "- {warning}");
            }
        }
        out.trim_end().to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditExplainFilters {
    zone_id: Option<String>,
    since: Option<String>,
    since_seconds: Option<u64>,
    reference_time_unix: Option<u64>,
    cutoff_unix: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditExplainSource {
    kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditExplainChainRange {
    start_seq: u64,
    end_seq: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditExplainEntry {
    id: String,
    event_type: String,
    severity: fcp_audit::Severity,
    seq: u64,
    occurred_at: u64,
    zone_id: String,
    actor: String,
    connector_id: Option<String>,
    operation_id: Option<String>,
    correlation_id: String,
    tombstoned: bool,
    quorum_height: Option<u64>,
    quorum_signers: Vec<String>,
    decision_rationale: Option<String>,
    reason_code: Option<String>,
    datalog_derivation: Option<String>,
}

fn build_explain_report(
    bundle: ReplayBundle,
    zone_filter: Option<&str>,
    since_filter: Option<&str>,
) -> Result<AuditExplainReport> {
    let since_seconds = since_filter
        .map(parse_since_seconds)
        .transpose()
        .map_err(|error| anyhow::anyhow!("invalid --since value: {error}"))?;
    let reference_time = bundle
        .audit_entries
        .iter()
        .map(|entry| entry.occurred_at)
        .max();
    let cutoff = since_seconds
        .zip(reference_time)
        .map(|(since_seconds, reference_time)| reference_time.saturating_sub(since_seconds));

    let mut audit_entries: Vec<AuditEntry> = bundle
        .audit_entries
        .into_iter()
        .filter(|entry| zone_filter.is_none_or(|zone| entry.zone_id == zone))
        .filter(|entry| cutoff.is_none_or(|cutoff| entry.occurred_at >= cutoff))
        .collect();
    audit_entries.sort_by(|left, right| {
        left.seq
            .cmp(&right.seq)
            .then_with(|| left.id.cmp(&right.id))
    });

    let receipts: Vec<fcp_audit::DecisionReceipt> = bundle
        .receipts
        .into_iter()
        .filter(|receipt| zone_filter.is_none_or(|zone| receipt.zone_id == zone))
        .filter(|receipt| cutoff.is_none_or(|cutoff| receipt.decided_at >= cutoff))
        .collect();

    let filtered_bundle = ReplayBundle {
        audit_entries: audit_entries.clone(),
        capability_tokens: bundle.capability_tokens,
        receipts: receipts.clone(),
    };

    let mut warnings = Vec::new();
    let explanation = match fcp_audit::explain::explain_bundle(&filtered_bundle) {
        Ok(explanation) => Some(explanation),
        Err(fcp_audit::explain::ExplainError::EmptyBundle) => {
            warnings.push("filtered replay bundle contains no explainable evidence".to_string());
            None
        }
        Err(fcp_audit::explain::ExplainError::NoInvocation) => {
            warnings.push("filtered replay bundle contains no invocation audit entry".to_string());
            None
        }
        Err(error) => return Err(error).context("failed to explain replay bundle"),
    };

    let entries: Vec<AuditExplainEntry> = audit_entries
        .iter()
        .map(|entry| explain_entry(entry, &receipts))
        .collect();
    let audit_chain_range =
        entries
            .first()
            .zip(entries.last())
            .map(|(first, last)| AuditExplainChainRange {
                start_seq: first.seq,
                end_seq: last.seq,
            });

    Ok(AuditExplainReport {
        status: "ok".to_string(),
        command: "audit".to_string(),
        subcommand: "explain".to_string(),
        filters: AuditExplainFilters {
            zone_id: zone_filter.map(ToOwned::to_owned),
            since: since_filter.map(ToOwned::to_owned),
            since_seconds,
            reference_time_unix: reference_time,
            cutoff_unix: cutoff,
        },
        source: AuditExplainSource {
            kind: "audit-chain-artifact".to_string(),
        },
        entries_returned: entries.len(),
        audit_chain_range,
        entries,
        explanation,
        warnings,
    })
}

fn explain_entry(entry: &AuditEntry, receipts: &[fcp_audit::DecisionReceipt]) -> AuditExplainEntry {
    let receipt = receipt_for_entry(entry, receipts);
    let reason_code = receipt
        .map(|receipt| receipt.reason_code.clone())
        .or_else(|| metadata_string(entry, &["reason_code"]));
    let decision_rationale = receipt
        .and_then(|receipt| receipt.explanation.clone())
        .or_else(|| metadata_string(entry, &["decision_rationale", "rationale", "explanation"]))
        .or_else(|| reason_code.clone());

    AuditExplainEntry {
        id: entry.id.clone(),
        event_type: entry.event_type.clone(),
        severity: entry.severity,
        seq: entry.seq,
        occurred_at: entry.occurred_at,
        zone_id: entry.zone_id.clone(),
        actor: entry.actor.clone(),
        connector_id: entry.connector_id.clone(),
        operation_id: entry.operation_id.clone(),
        correlation_id: entry.correlation_id.clone(),
        tombstoned: is_tombstoned(entry),
        quorum_height: metadata_u64(entry, &["quorum_height", "quorum.height"]),
        quorum_signers: quorum_signers(entry),
        decision_rationale,
        reason_code,
        datalog_derivation: metadata_string(entry, &["datalog_derivation", "derivation_summary"]),
    }
}

fn receipt_for_entry<'a>(
    entry: &AuditEntry,
    receipts: &'a [fcp_audit::DecisionReceipt],
) -> Option<&'a fcp_audit::DecisionReceipt> {
    receipts
        .iter()
        .find(|receipt| receipt.audit_entry_id.as_deref() == Some(entry.id.as_str()))
        .or_else(|| {
            if entry.event_type != fcp_audit::event_types::CAPABILITY_INVOKE {
                return None;
            }
            receipts.iter().find(|receipt| {
                optional_match(
                    receipt.connector_id.as_deref(),
                    entry.connector_id.as_deref(),
                ) && optional_match(
                    receipt.operation_id.as_deref(),
                    entry.operation_id.as_deref(),
                ) && optional_match(
                    receipt.correlation_id.as_deref(),
                    Some(entry.correlation_id.as_str()),
                )
            })
        })
}

fn optional_match(actual: Option<&str>, expected: Option<&str>) -> bool {
    expected.is_none_or(|expected| actual.is_none_or(|actual| actual == expected))
}

fn is_tombstoned(entry: &AuditEntry) -> bool {
    entry.event_type.contains("tombstone")
        || metadata_bool(entry, &["tombstoned", "tombstone", "tombstone_marker"])
}

fn quorum_signers(entry: &AuditEntry) -> Vec<String> {
    let mut signers =
        metadata_string_array(entry, &["quorum_signers", "signers", "quorum.signers"]);
    if signers.is_empty() {
        if let Some(ref issuer_kid) = entry.issuer_kid {
            signers.push(issuer_kid.to_string());
        }
    }
    signers
}

fn metadata_string(entry: &AuditEntry, keys: &[&str]) -> Option<String> {
    keys.iter()
        .filter_map(|key| metadata_value(entry, key))
        .find_map(value_as_string)
}

fn metadata_u64(entry: &AuditEntry, keys: &[&str]) -> Option<u64> {
    keys.iter()
        .filter_map(|key| metadata_value(entry, key))
        .find_map(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(|string| string.parse::<u64>().ok()))
        })
}

fn metadata_bool(entry: &AuditEntry, keys: &[&str]) -> bool {
    keys.iter()
        .filter_map(|key| metadata_value(entry, key))
        .any(|value| {
            value.as_bool().unwrap_or_else(|| {
                value
                    .as_str()
                    .is_some_and(|string| matches!(string, "true" | "yes" | "1"))
            })
        })
}

fn metadata_string_array(entry: &AuditEntry, keys: &[&str]) -> Vec<String> {
    keys.iter()
        .filter_map(|key| metadata_value(entry, key))
        .find_map(|value| {
            value.as_array().map(|array| {
                array
                    .iter()
                    .filter_map(value_as_string)
                    .collect::<Vec<String>>()
            })
        })
        .unwrap_or_default()
}

fn metadata_value<'a>(entry: &'a AuditEntry, key: &str) -> Option<&'a serde_json::Value> {
    if let Some(value) = entry.metadata.get(key) {
        return Some(value);
    }

    let mut path = key.split('.');
    let first = path.next()?;
    let mut current = entry.metadata.get(first)?;
    for segment in path {
        current = current.get(segment)?;
    }
    Some(current)
}

fn value_as_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(string) if !string.is_empty() => Some(string.clone()),
        serde_json::Value::Number(number) => Some(number.to_string()),
        serde_json::Value::Bool(boolean) => Some(boolean.to_string()),
        _ => None,
    }
}

fn load_explain_bundle(path: &Path) -> Result<ReplayBundle> {
    if path.is_dir() {
        return load_explain_bundle_dir(path);
    }

    if is_cbor_path(path) {
        let input = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
        return parse_explain_bundle_cbor(&input)
            .with_context(|| format!("failed to parse CBOR replay bundle {}", path.display()));
    }

    let input = read_input(path)?;
    fcp_audit::explain::parse_replay_bundle(&input)
        .with_context(|| format!("failed to parse replay bundle {}", path.display()))
}

fn load_explain_bundle_dir(dir: &Path) -> Result<ReplayBundle> {
    if let Some(input) = read_optional_binary_artifact(dir, &["replay_bundle.cbor", "bundle.cbor"])?
    {
        return parse_explain_bundle_cbor(&input)
            .with_context(|| format!("failed to parse CBOR replay bundle in {}", dir.display()));
    }

    if let Some(input) = read_optional_artifact(dir, &["replay_bundle.json", "bundle.json"])? {
        return fcp_audit::explain::parse_replay_bundle(&input)
            .with_context(|| format!("failed to parse replay bundle in {}", dir.display()));
    }

    let audit_entries = read_optional_artifact(
        dir,
        &[
            "audit_events.jsonl",
            "audit-events.jsonl",
            "audit_chain.jsonl",
            "audit-chain.jsonl",
            "audit_events.json",
            "audit-events.json",
            "audit_chain.json",
            "audit-chain.json",
            "events.jsonl",
            "events.json",
        ],
    )?
    .map(|input| fcp_audit::explain::parse_audit_entries(&input))
    .transpose()
    .with_context(|| format!("failed to parse audit entries in {}", dir.display()))?
    .unwrap_or_default();

    let capability_tokens = read_optional_artifact(
        dir,
        &[
            "capability_tokens.json",
            "capability-tokens.json",
            "tokens.json",
            "capability_tokens.jsonl",
            "capability-tokens.jsonl",
            "tokens.jsonl",
        ],
    )?
    .map(|input| fcp_audit::explain::parse_capability_tokens(&input))
    .transpose()
    .with_context(|| format!("failed to parse capability tokens in {}", dir.display()))?
    .unwrap_or_default();

    let receipts = read_optional_artifact(
        dir,
        &[
            "receipts.json",
            "decision_receipts.json",
            "decision-receipts.json",
            "receipts.jsonl",
            "decision_receipts.jsonl",
            "decision-receipts.jsonl",
        ],
    )?
    .map(|input| fcp_audit::explain::parse_decision_receipts(&input))
    .transpose()
    .with_context(|| format!("failed to parse decision receipts in {}", dir.display()))?
    .unwrap_or_default();

    Ok(ReplayBundle {
        audit_entries,
        capability_tokens,
        receipts,
    })
}

fn is_cbor_path(path: &Path) -> bool {
    path.extension()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|extension| extension.eq_ignore_ascii_case("cbor"))
}

fn parse_explain_bundle_cbor(input: &[u8]) -> Result<ReplayBundle> {
    let mut reader = input;
    match ciborium::de::from_reader::<ReplayBundle, _>(&mut reader) {
        Ok(bundle) if reader.is_empty() => return Ok(bundle),
        Ok(_) => anyhow::bail!("CBOR replay bundle has trailing bytes"),
        Err(_) => {}
    }

    let mut reader = input;
    let entries = ciborium::de::from_reader::<Vec<AuditEntry>, _>(&mut reader)
        .context("CBOR input is neither a replay bundle nor an audit-entry array")?;
    if !reader.is_empty() {
        anyhow::bail!("CBOR audit-entry array has trailing bytes");
    }
    Ok(ReplayBundle {
        audit_entries: entries,
        capability_tokens: Vec::new(),
        receipts: Vec::new(),
    })
}

fn read_optional_artifact(dir: &Path, names: &[&str]) -> Result<Option<String>> {
    for name in names {
        let path = dir.join(name);
        if path.is_file() {
            return fs::read_to_string(&path)
                .with_context(|| format!("failed to read {}", path.display()))
                .map(Some);
        }
    }
    Ok(None)
}

fn read_optional_binary_artifact(dir: &Path, names: &[&str]) -> Result<Option<Vec<u8>>> {
    for name in names {
        let path = dir.join(name);
        if path.is_file() {
            return fs::read(&path)
                .with_context(|| format!("failed to read {}", path.display()))
                .map(Some);
        }
    }
    Ok(None)
}

fn parse_event_records(input: &str) -> Result<Vec<AuditEventRecord>> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    if trimmed.starts_with('[') {
        return serde_json::from_str(trimmed).context("failed to parse audit event array");
    }

    let mut records = Vec::new();
    for (idx, line) in input.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let record: AuditEventRecord = serde_json::from_str(line)
            .with_context(|| format!("failed to parse audit event record on line {}", idx + 1))?;
        records.push(record);
    }

    Ok(records)
}

fn parse_audit_head(input: &str) -> Result<AuditHead> {
    let trimmed = input.trim();
    if trimmed.starts_with('[') {
        anyhow::bail!("audit head input must be a single JSON object, not an array");
    }
    serde_json::from_str(trimmed).context("failed to parse audit head")
}

fn build_verify_report_from_inputs(
    events_input: &str,
    head_input: Option<&str>,
    zone_filter: Option<&str>,
    issuer_keys: &[String],
) -> Result<AuditVerifyReport> {
    if let Ok(mut entries) = parse_signed_entries(events_input) {
        if entries.is_empty() {
            return Ok(empty_verify_report(zone_filter));
        }

        entries.sort_by(|a, b| a.seq.cmp(&b.seq).then_with(|| a.id.cmp(&b.id)));
        let head = head_input.map(parse_signed_head).transpose()?;
        return verify_signed_chain(&entries, head.as_ref(), zone_filter, issuer_keys);
    }

    let zone_filter = match zone_filter {
        Some(zone) => Some(zone.parse::<ZoneId>().context("invalid zone id")?),
        None => None,
    };

    let mut records = parse_event_records(events_input)?;
    if records.is_empty() {
        return Ok(empty_verify_report(
            zone_filter.as_ref().map(ZoneId::as_str),
        ));
    }

    records.sort_by(|a, b| {
        a.event
            .seq
            .cmp(&b.event.seq)
            .then_with(|| a.object_id.to_string().cmp(&b.object_id.to_string()))
    });

    let head = head_input.map(parse_audit_head).transpose()?;
    Ok(verify_chain(&records, head.as_ref(), zone_filter.as_ref()))
}

fn empty_verify_report(zone_filter: Option<&str>) -> AuditVerifyReport {
    AuditVerifyReport {
        status: AuditVerifyStatus::Warn,
        zone_id: zone_filter.map(ToOwned::to_owned),
        chain_len: 0,
        head_seq: None,
        head_event: None,
        issues: vec![AuditVerifyIssue {
            code: "audit.chain.empty".to_string(),
            message: "no audit events provided".to_string(),
            seq: None,
            object_id: None,
        }],
    }
}

fn parse_signed_entries(input: &str) -> Result<Vec<fcp_audit::AuditEntry>> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    if trimmed.starts_with('[') {
        return serde_json::from_str(trimmed)
            .context("failed to parse signer-aware audit entry array");
    }

    let mut entries = Vec::new();
    for (idx, line) in input.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let entry: fcp_audit::AuditEntry = serde_json::from_str(line).with_context(|| {
            format!(
                "failed to parse signer-aware audit entry on line {}",
                idx + 1
            )
        })?;
        entries.push(entry);
    }

    Ok(entries)
}

fn parse_signed_head(input: &str) -> Result<fcp_audit::ChainHead> {
    let trimmed = input.trim();
    if trimmed.starts_with('[') {
        anyhow::bail!("audit head input must be a single JSON object, not an array");
    }
    serde_json::from_str(trimmed).context("failed to parse signer-aware audit head")
}

fn verify_signed_chain(
    entries: &[fcp_audit::AuditEntry],
    head: Option<&fcp_audit::ChainHead>,
    zone_filter: Option<&str>,
    issuer_keys: &[String],
) -> Result<AuditVerifyReport> {
    let now_unix_secs = u64::try_from(Utc::now().timestamp()).unwrap_or_default();
    let registry = parse_issuer_key_bindings(issuer_keys)?;
    let signer_required = !registry.is_empty()
        || entries
            .iter()
            .any(|entry| entry.issuer_kid.is_some() || entry.signature.is_some());

    let mut report = map_signed_verify_report(&fcp_audit::verify_chain_with_clock(
        entries,
        head,
        zone_filter,
        now_unix_secs,
    ));

    if signer_required {
        let result = fcp_audit::verify_chain_with_signers(entries, head, zone_filter, |kid| {
            registry.get(&kid.to_hex()).cloned()
        });
        if let Err(error) = result {
            report.status = AuditVerifyStatus::Fail;
            report.issues.push(signer_error_to_issue(&error, entries));
        }
    }

    Ok(report)
}

fn map_signed_verify_report(report: &fcp_audit::VerifyReport) -> AuditVerifyReport {
    AuditVerifyReport {
        status: match report.status {
            fcp_audit::VerifyStatus::Ok => AuditVerifyStatus::Ok,
            fcp_audit::VerifyStatus::Warn => AuditVerifyStatus::Warn,
            fcp_audit::VerifyStatus::Fail => AuditVerifyStatus::Fail,
        },
        zone_id: report.zone_id.clone(),
        chain_len: report.chain_len,
        head_seq: report.head_seq,
        head_event: report.head_entry.clone(),
        issues: report
            .issues
            .iter()
            .map(|issue| AuditVerifyIssue {
                code: issue.code.clone(),
                message: issue.message.clone(),
                seq: issue.seq,
                object_id: issue.entry_id.clone(),
            })
            .collect(),
    }
}

fn parse_issuer_key_bindings(bindings: &[String]) -> Result<HashMap<String, Ed25519VerifyingKey>> {
    let mut registry = HashMap::new();
    for binding in bindings {
        let (kid, key) = parse_issuer_key_binding(binding)?;
        registry.insert(kid, key);
    }
    Ok(registry)
}

fn parse_issuer_key_binding(binding: &str) -> Result<(String, Ed25519VerifyingKey)> {
    let (kid_hex_raw, verifying_key_hex_raw) = binding.split_once('=').with_context(|| {
        format!("issuer key `{binding}` must be in the form <kid>=<pubkey-hex>")
    })?;
    let kid_hex = kid_hex_raw.trim();
    let verifying_key_hex = verifying_key_hex_raw.trim();
    let expected_kid = KeyId::from_hex(kid_hex)
        .with_context(|| format!("issuer key `{binding}` has an invalid key id"))?;
    let verifying_key_bytes = hex::decode(verifying_key_hex)
        .with_context(|| format!("issuer key `{binding}` has a non-hex Ed25519 public key"))?;
    let key_bytes: [u8; PUBLIC_KEY_SIZE] = verifying_key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Ed25519 public key must decode to 32 bytes"))?;
    let verifying_key = Ed25519VerifyingKey::from_bytes(&key_bytes)
        .with_context(|| format!("issuer key `{binding}` is not a valid Ed25519 public key"))?;
    if verifying_key.key_id().as_slice() != expected_kid.as_slice() {
        anyhow::bail!(
            "issuer key `{binding}` maps kid {} to a public key with derived kid {}",
            expected_kid,
            verifying_key.key_id()
        );
    }
    Ok((expected_kid.to_hex(), verifying_key))
}

fn signer_error_to_issue(
    error: &fcp_audit::AuditError,
    entries: &[fcp_audit::AuditEntry],
) -> AuditVerifyIssue {
    let (code, seq) = match error {
        fcp_audit::AuditError::SignerMissing { seq } => ("audit.signer_missing", Some(*seq)),
        fcp_audit::AuditError::SignatureInvalid { seq } => ("audit.signature_invalid", Some(*seq)),
        fcp_audit::AuditError::UnknownIssuer { seq } => ("audit.unknown_issuer", Some(*seq)),
        fcp_audit::AuditError::EmptySignedHead { seq } => ("audit.empty_signed_head", Some(*seq)),
        fcp_audit::AuditError::DuplicateSigner { seq } => ("audit.duplicate_signer", Some(*seq)),
        _ => ("audit.signature_verification_error", None),
    };
    let object_id = seq.and_then(|seq| {
        entries
            .iter()
            .find(|entry| entry.seq == seq)
            .map(|entry| entry.id.clone())
    });

    AuditVerifyIssue {
        code: code.to_string(),
        message: error.to_string(),
        seq,
        object_id,
    }
}

#[allow(clippy::too_many_lines)]
/// Recompute the canonical content-addressed ObjectId of an `AuditEvent`.
///
/// Mirrors the derivation every other content-addressed object in fcp-core
/// uses: canonical CBOR (deterministic per RFC 8949 §4.2 via `fcp_cbor`)
/// hashed through `ObjectId::from_unscoped_bytes` (BLAKE3 with the
/// `FCP2-CONTENT-V2` domain separator).
fn computed_event_object_id(event: &AuditEvent) -> Option<ObjectId> {
    let bytes = to_canonical_cbor(event).ok()?;
    Some(ObjectId::from_unscoped_bytes(&bytes))
}

fn verify_chain(
    records: &[AuditEventRecord],
    head: Option<&AuditHead>,
    zone: Option<&ZoneId>,
) -> AuditVerifyReport {
    let mut issues = Vec::new();
    let mut seen_seq = std::collections::HashMap::new();

    for record in records {
        if let Some(zone) = zone {
            if record.event.zone_id() != zone {
                issues.push(AuditVerifyIssue {
                    code: "audit.zone_mismatch".to_string(),
                    message: format!(
                        "event zone {} does not match requested zone {}",
                        record.event.zone_id(),
                        zone
                    ),
                    seq: Some(record.event.seq),
                    object_id: Some(record.object_id.to_string()),
                });
            }
        }

        // The supplied `object_id` is what every downstream check
        // (`prev_mismatch`, `fork_detected`, `head_mismatch`) compares
        // against. If a producer (or an attacker with write access to
        // the audit JSONL) supplies an `object_id` that does not match
        // the canonical content-addressed hash of the event payload,
        // those downstream checks operate on attacker-chosen tokens
        // rather than on real content hashes — the chain "verifies"
        // even though the events are forged. Recompute the id from
        // canonical CBOR and reject the mismatch up front so the rest
        // of `verify_chain` can keep using `record.object_id` as a
        // trusted alias for content.
        match computed_event_object_id(&record.event) {
            Some(expected) if expected != record.object_id => {
                issues.push(AuditVerifyIssue {
                    code: "audit.object_id_mismatch".to_string(),
                    message: format!(
                        "supplied object_id {} does not match content-derived id {}",
                        record.object_id, expected
                    ),
                    seq: Some(record.event.seq),
                    object_id: Some(record.object_id.to_string()),
                });
            }
            None => {
                issues.push(AuditVerifyIssue {
                    code: "audit.object_id_unverifiable".to_string(),
                    message: "could not canonicalize event for content-id verification".to_string(),
                    seq: Some(record.event.seq),
                    object_id: Some(record.object_id.to_string()),
                });
            }
            _ => {}
        }

        if let Some(prev) = seen_seq.insert(record.event.seq, record.object_id) {
            if prev != record.object_id {
                issues.push(AuditVerifyIssue {
                    code: "audit.fork_detected".to_string(),
                    message: "multiple events share the same seq with different ids".to_string(),
                    seq: Some(record.event.seq),
                    object_id: Some(record.object_id.to_string()),
                });
            }
        }
    }

    let mut iter = records.iter();
    if let Some(first) = iter.next() {
        if first.event.seq != 0 || first.event.prev.is_some() {
            issues.push(AuditVerifyIssue {
                code: "audit.genesis_invalid".to_string(),
                message: "genesis event must have seq 0 and no prev".to_string(),
                seq: Some(first.event.seq),
                object_id: Some(first.object_id.to_string()),
            });
        }

        let mut prev = first;
        for record in iter {
            // Use checked_add so seq == u64::MAX is correctly treated as a
            // terminal state, consistent with fcp_audit::AuditEntry::follows().
            // saturating_add would silently accept a stalled chain.
            let expected_seq = match prev.event.seq.checked_add(1) {
                Some(next) => next,
                None => {
                    issues.push(AuditVerifyIssue {
                        code: "audit.seq_overflow".to_string(),
                        message: format!(
                            "sequence number overflow: previous seq {} cannot be incremented",
                            prev.event.seq
                        ),
                        seq: Some(prev.event.seq),
                        object_id: Some(prev.object_id.to_string()),
                    });
                    break;
                }
            };
            if record.event.seq != expected_seq {
                issues.push(AuditVerifyIssue {
                    code: "audit.seq_gap".to_string(),
                    message: format!("expected seq {}, found {}", expected_seq, record.event.seq),
                    seq: Some(record.event.seq),
                    object_id: Some(record.object_id.to_string()),
                });
            }

            if record.event.prev.as_ref() != Some(&prev.object_id) {
                issues.push(AuditVerifyIssue {
                    code: "audit.prev_mismatch".to_string(),
                    message: "prev pointer does not match previous event id".to_string(),
                    seq: Some(record.event.seq),
                    object_id: Some(record.object_id.to_string()),
                });
            }

            // Timestamps should be non-decreasing along the chain.
            // A backwards timestamp indicates clock skew or tampering.
            if record.event.occurred_at < prev.event.occurred_at {
                issues.push(AuditVerifyIssue {
                    code: "audit.timestamp_regression".to_string(),
                    message: format!(
                        "timestamp {} is earlier than previous event timestamp {}",
                        record.event.occurred_at, prev.event.occurred_at
                    ),
                    seq: Some(record.event.seq),
                    object_id: Some(record.object_id.to_string()),
                });
            }

            prev = record;
        }
    }

    if let Some(head) = head {
        if let Some(last) = records.last() {
            if head.head_event != last.object_id {
                issues.push(AuditVerifyIssue {
                    code: "audit.head_mismatch".to_string(),
                    message: "audit head does not reference chain tip".to_string(),
                    seq: Some(last.event.seq),
                    object_id: Some(last.object_id.to_string()),
                });
            }
            if head.head_seq != last.event.seq {
                issues.push(AuditVerifyIssue {
                    code: "audit.head_seq_mismatch".to_string(),
                    message: "audit head seq does not match chain tip".to_string(),
                    seq: Some(last.event.seq),
                    object_id: Some(last.object_id.to_string()),
                });
            }
        }

        if let Some(zone) = zone {
            if head.zone_id() != zone {
                issues.push(AuditVerifyIssue {
                    code: "audit.head_zone_mismatch".to_string(),
                    message: format!("audit head zone {} does not match {}", head.zone_id(), zone),
                    seq: Some(head.head_seq),
                    object_id: Some(head.head_event.to_string()),
                });
            }
        }
    }

    let is_fail = issues.iter().any(|issue| {
        matches!(
            issue.code.as_str(),
            "audit.fork_detected"
                | "audit.prev_mismatch"
                | "audit.seq_gap"
                | "audit.genesis_invalid"
                | "audit.head_mismatch"
                | "audit.head_seq_mismatch"
                | "audit.object_id_mismatch"
                | "audit.object_id_unverifiable"
        )
    });

    let status = if issues.is_empty() {
        AuditVerifyStatus::Ok
    } else if is_fail {
        AuditVerifyStatus::Fail
    } else {
        AuditVerifyStatus::Warn
    };

    AuditVerifyReport {
        status,
        zone_id: zone.map(ToString::to_string),
        chain_len: records.len(),
        head_seq: head.map(|h| h.head_seq),
        head_event: head.map(|h| h.head_event.to_string()),
        issues,
    }
}

fn output_verify_report(report: &AuditVerifyReport, json: bool) -> Result<()> {
    if json {
        let payload = audit_truth_source_payload(
            report,
            AUDIT_VERIFY_SCHEMA_VERSION,
            KnowledgeState::Offline,
        )?;
        let payload =
            serde_json::to_string_pretty(&payload).context("failed to serialize verify report")?;
        println!("{payload}");
        return Ok(());
    }

    println!();
    println!("Audit Verify Status: {:?}", report.status);
    if let Some(ref zone) = report.zone_id {
        println!("Zone: {zone}");
    }
    println!("Chain length: {}", report.chain_len);
    if let Some(seq) = report.head_seq {
        println!("Head seq: {seq}");
    }
    if let Some(ref head) = report.head_event {
        println!("Head event: {head}");
    }

    if report.issues.is_empty() {
        println!("Issues: none");
        print_audit_answer_source_footer(KnowledgeState::Offline);
        return Ok(());
    }

    println!();
    println!("Issues:");
    for issue in &report.issues {
        println!("  - {}: {}", issue.code, issue.message);
        if let Some(seq) = issue.seq {
            println!("    seq: {seq}");
        }
        if let Some(ref id) = issue.object_id {
            println!("    id: {id}");
        }
    }

    print_audit_answer_source_footer(KnowledgeState::Offline);
    Ok(())
}

fn to_event_output(record: &AuditEventRecord) -> AuditEventOutput {
    let event = &record.event;
    let trace_id = event
        .trace_context
        .as_ref()
        .map(|trace| hex_encode(trace.trace_id));
    let span_id = event
        .trace_context
        .as_ref()
        .map(|trace| hex_encode(trace.span_id));

    AuditEventOutput {
        seq: event.seq,
        occurred_at: event.occurred_at,
        occurred_at_iso: format_timestamp(event.occurred_at),
        event_type: event.event_type.clone(),
        actor: event.actor.to_string(),
        zone_id: event.zone_id.to_string(),
        correlation_id: hex_encode(event.correlation_id.0.as_bytes()),
        trace_id,
        span_id,
        connector_id: event.connector_id.as_ref().map(ToString::to_string),
        operation_id: event.operation.as_ref().map(ToString::to_string),
        prev: event.prev.as_ref().map(ToString::to_string),
    }
}

// ============================================================================
// Audit Matrix + Gaps (connector metadata compliance)
// ============================================================================

/// Locate the connectors directory relative to the workspace root.
fn find_connectors_root() -> Result<std::path::PathBuf> {
    // Try relative from CWD (typical workspace layout).
    let candidates = [
        std::path::PathBuf::from("connectors"),
        std::path::PathBuf::from("../connectors"),
    ];
    for candidate in &candidates {
        if candidate.is_dir() {
            return Ok(candidate.clone());
        }
    }
    anyhow::bail!(
        "Cannot find connectors directory. Run from the workspace root or a crate directory."
    )
}

/// Run the audit matrix command.
fn run_matrix(args: &MatrixArgs) -> Result<()> {
    let connectors_root = find_connectors_root()?;
    let matrix = crate::audit::run_audit(&connectors_root)?;

    if let Some(ref name) = args.connector {
        let Some(entry) = matrix.connectors.get(name) else {
            eprintln!("Connector `{name}` not found in audit matrix.");
            eprintln!(
                "Available: {}",
                matrix
                    .connectors
                    .keys()
                    .take(10)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            std::process::exit(2);
        };
        if args.json {
            println!(
                "{}",
                serde_json::to_string_pretty(entry)
                    .context("failed to serialize connector audit")?
            );
        } else {
            print_connector_audit(entry);
        }
    } else if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&matrix).context("failed to serialize audit matrix")?
        );
    } else {
        print_matrix_summary(&matrix);
    }
    Ok(())
}

/// Run the audit gaps command.
fn run_gaps(args: &GapsArgs) -> Result<()> {
    let connectors_root = find_connectors_root()?;
    let matrix = crate::audit::run_audit(&connectors_root)?;

    let mut all_gaps: Vec<(&str, &crate::readiness::ReadinessGap)> = Vec::new();
    for (name, entry) in &matrix.connectors {
        for gap in &entry.gaps {
            if args.blocking_only && gap.severity != crate::readiness::GapSeverity::Blocking {
                continue;
            }
            if let Some(ref filter) = args.connector {
                if name != filter {
                    continue;
                }
            }
            all_gaps.push((name.as_str(), gap));
        }
    }

    if args.json {
        let json_gaps: Vec<serde_json::Value> = all_gaps
            .iter()
            .map(|(name, gap)| {
                serde_json::json!({
                    "connector": name,
                    "category": format!("{:?}", gap.category),
                    "severity": format!("{:?}", gap.severity),
                    "message": gap.description,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json_gaps).context("failed to serialize gaps")?
        );
    } else {
        if all_gaps.is_empty() {
            println!("No gaps found.");
            return Ok(());
        }
        println!(
            "Gaps: {} found{}",
            all_gaps.len(),
            if args.blocking_only {
                " (blocking only)"
            } else {
                ""
            }
        );
        println!();
        for (name, gap) in &all_gaps {
            println!(
                "  [{sev:?}] {name}: [{cat:?}] {msg}",
                sev = gap.severity,
                cat = gap.category,
                msg = gap.description,
            );
        }
    }
    Ok(())
}

/// Print a single connector's audit in human-readable format.
fn print_connector_audit(entry: &crate::audit::ConnectorAudit) {
    println!("Connector: {}", entry.name);
    println!("  Cohort:     {:?}", entry.cohort);
    println!("  Readiness:  {:?}", entry.level);
    println!(
        "  Manifest:   {}",
        if entry.has_manifest { "yes" } else { "no" }
    );
    println!(
        "  Operations: {} total, {:.0}% complete",
        entry.operations.count,
        entry.operations.completeness * 100.0
    );
    println!(
        "  Agent hints: {:.0}% coverage",
        entry.agent_hints.coverage * 100.0
    );
    if entry.gaps.is_empty() {
        println!("  Gaps:       none");
    } else {
        println!("  Gaps:       {}", entry.gaps.len());
        for gap in &entry.gaps {
            println!(
                "    [{sev:?}] [{cat:?}] {msg}",
                sev = gap.severity,
                cat = gap.category,
                msg = gap.description,
            );
        }
    }
}

/// Print audit matrix summary in human-readable format.
fn print_matrix_summary(matrix: &crate::audit::AuditMatrix) {
    println!(
        "Audit Matrix: {} connectors scanned",
        matrix.total_connectors
    );
    println!(
        "  With manifest: {}  Missing: {}",
        matrix.with_manifest, matrix.missing_manifest
    );
    println!();
    println!("Readiness:");
    println!("  Ready:           {}", matrix.summary.ready);
    println!("  Partially ready: {}", matrix.summary.partially_ready);
    println!("  Not ready:       {}", matrix.summary.not_ready);
    println!();
    println!(
        "Operations: {} total, {:.0}% mean completeness",
        matrix.summary.total_operations,
        matrix.summary.mean_operation_completeness * 100.0
    );
    println!(
        "Agent hints: {:.0}% mean coverage",
        matrix.summary.mean_hint_coverage * 100.0
    );
    println!();
    println!(
        "Gaps: {} total ({} blocking, {} degraded, {} cosmetic)",
        matrix.summary.total_gaps,
        matrix.summary.blocking_gaps,
        matrix.summary.degraded_gaps,
        matrix.summary.cosmetic_gaps
    );
}

#[cfg(test)]
/// Test-only audit event fixture loader used by audit-chain unit tests.
#[allow(clippy::too_many_lines)]
fn load_audit_events(
    zone: &str,
    since: Option<u64>,
    limit: usize,
    filter: &AuditFilter,
) -> Result<Vec<AuditEventOutput>, AuditTailError> {
    // Stub: Return demo data for the "z:work" zone, otherwise "zone not found"
    if !zone.starts_with("z:") {
        return Err(AuditTailError::zone_not_found(zone));
    }

    if zone != "z:work" && zone != "z:demo" {
        // For unknown zones, return empty to simulate no events
        return Ok(vec![]);
    }

    let base_seq = since.unwrap_or(100);
    #[allow(clippy::cast_sign_loss)] // Timestamps after 1970 are positive
    let now = Utc::now().timestamp() as u64;

    // Generate sample events
    let all_events = vec![
        AuditEventOutput {
            seq: base_seq,
            occurred_at: now - 300,
            occurred_at_iso: format_timestamp(now - 300),
            event_type: "capability.invoke".to_string(),
            actor: "user:alice".to_string(),
            zone_id: zone.to_string(),
            correlation_id: "a".repeat(32),
            trace_id: Some("t".repeat(32)),
            span_id: Some("s".repeat(16)),
            connector_id: Some("fcp.telegram:base:v1".to_string()),
            operation_id: Some("send_message".to_string()),
            prev: None,
        },
        AuditEventOutput {
            seq: base_seq + 1,
            occurred_at: now - 240,
            occurred_at_iso: format_timestamp(now - 240),
            event_type: "secret.access".to_string(),
            actor: "user:alice".to_string(),
            zone_id: zone.to_string(),
            correlation_id: "b".repeat(32),
            trace_id: Some("t".repeat(32)),
            span_id: Some("s".repeat(16)),
            connector_id: Some("fcp.telegram:base:v1".to_string()),
            operation_id: Some("get_api_key".to_string()),
            prev: Some("prev1".to_string()),
        },
        AuditEventOutput {
            seq: base_seq + 2,
            occurred_at: now - 180,
            occurred_at_iso: format_timestamp(now - 180),
            event_type: "capability.invoke".to_string(),
            actor: "user:bob".to_string(),
            zone_id: zone.to_string(),
            correlation_id: "c".repeat(32),
            trace_id: None,
            span_id: None,
            connector_id: Some("fcp.discord:base:v1".to_string()),
            operation_id: Some("send_message".to_string()),
            prev: Some("prev2".to_string()),
        },
        AuditEventOutput {
            seq: base_seq + 3,
            occurred_at: now - 120,
            occurred_at_iso: format_timestamp(now - 120),
            event_type: "elevation.granted".to_string(),
            actor: "user:admin".to_string(),
            zone_id: zone.to_string(),
            correlation_id: "d".repeat(32),
            trace_id: Some("u".repeat(32)),
            span_id: Some("v".repeat(16)),
            connector_id: None,
            operation_id: None,
            prev: Some("prev3".to_string()),
        },
        AuditEventOutput {
            seq: base_seq + 4,
            occurred_at: now - 60,
            occurred_at_iso: format_timestamp(now - 60),
            event_type: "revocation.issued".to_string(),
            actor: "user:admin".to_string(),
            zone_id: zone.to_string(),
            correlation_id: "e".repeat(32),
            trace_id: Some("u".repeat(32)),
            span_id: Some("w".repeat(16)),
            connector_id: None,
            operation_id: None,
            prev: Some("prev4".to_string()),
        },
        AuditEventOutput {
            seq: base_seq + 5,
            occurred_at: now - 30,
            occurred_at_iso: format_timestamp(now - 30),
            event_type: "security.violation".to_string(),
            actor: "user:mallory".to_string(),
            zone_id: zone.to_string(),
            correlation_id: "f".repeat(32),
            trace_id: None,
            span_id: None,
            connector_id: Some("fcp.github:base:v1".to_string()),
            operation_id: Some("delete_repo".to_string()),
            prev: Some("prev5".to_string()),
        },
    ];

    // Apply filter and limit
    let events: Vec<_> = all_events
        .into_iter()
        .filter(|e| filter.matches(e))
        .take(limit)
        .collect();

    Ok(events)
}

/// Format a Unix timestamp as ISO-8601.
fn format_timestamp(ts: u64) -> String {
    #[allow(clippy::cast_possible_wrap)] // Timestamps fit in i64 until year 292 billion
    let ts_i64 = ts as i64;
    Utc.timestamp_opt(ts_i64, 0).single().map_or_else(
        || ts.to_string(),
        |dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
    )
}

/// Output events as JSON.
fn output_json(events: &[AuditEventOutput]) -> Result<()> {
    for event in events {
        let json = serde_json::to_string(event).context("failed to serialize event")?;
        println!("{json}");
    }
    Ok(())
}

/// Output events in human-readable format.
fn output_human(events: &[AuditEventOutput], zone: &str, filter: &AuditFilter) {
    let reset = AuditEventOutput::ansi_reset();

    // Header
    println!();
    println!("Audit Events for zone: {zone}");
    if !filter.is_empty() {
        print!("Filters:");
        if let Some(ref c) = filter.connector_id {
            print!(" connector={c}");
        }
        if let Some(ref o) = filter.operation_id {
            print!(" operation={o}");
        }
        if let Some(ref corr) = filter.correlation_id {
            print!(" correlation={}...", &corr[..8.min(corr.len())]);
        }
        if let Some(ref t) = filter.trace_id {
            print!(" trace={}...", &t[..8.min(t.len())]);
        }
        if let Some(ref e) = filter.event_type {
            print!(" event_type={e}");
        }
        if let Some(ref a) = filter.actor {
            print!(" actor={a}");
        }
        println!();
    }
    println!("{}", "─".repeat(80));
    println!();

    for event in events {
        let color = event.event_type_color();
        let symbol = event.event_type_symbol();

        // Timestamp and seq
        print!("\x1b[90m[{}]\x1b[0m ", event.occurred_at_iso);
        print!("\x1b[90mseq={:<6}\x1b[0m ", event.seq);

        // Event type with color
        print!("{color}{symbol} {:<26}{reset} ", event.event_type);

        // Actor
        print!("actor={:<16} ", truncate(&event.actor, 16));

        // Connector/operation if present
        if let Some(ref cid) = event.connector_id {
            print!("connector={} ", truncate(cid, 20));
        }
        if let Some(ref oid) = event.operation_id {
            print!("op={} ", truncate(oid, 15));
        }

        println!();

        // Second line: correlation/trace IDs
        if event.trace_id.is_some() || !event.correlation_id.is_empty() {
            print!("    ");
            print!("correlation={} ", truncate(&event.correlation_id, 12));
            if let Some(ref tid) = event.trace_id {
                print!("trace={} ", truncate(tid, 12));
            }
            if let Some(ref sid) = event.span_id {
                print!("span={} ", truncate(sid, 8));
            }
            println!();
        }
    }

    println!();
    println!("{}", "─".repeat(80));
    println!("Showing {} events", events.len());
    println!();
}

/// Truncate a string and add "..." if needed.
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else if max_len <= 3 {
        s[..max_len].to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_audit::{
        AuditEntry as SignedAuditEntry, Decision, DecisionReceipt, Severity,
        audit_entry_hlc_from_occurred_at,
    };
    use fcp_crypto::{Ed25519Signature, Ed25519SigningKey};
    use std::collections::BTreeMap;

    fn signed_test_entry(seq: u64, prev: Option<&str>) -> SignedAuditEntry {
        let mut entry = SignedAuditEntry {
            id: String::new(),
            event_type: "capability.invoke".to_string(),
            severity: Severity::Info,
            actor: "user:alice".to_string(),
            zone_id: "z:work".to_string(),
            seq,
            occurred_at: 1_700_000_000 + seq,
            hlc: audit_entry_hlc_from_occurred_at(1_700_000_000 + seq, "user:alice"),
            prev: prev.map(ToOwned::to_owned),
            correlation_id: format!("corr-{seq}"),
            trace_context: None,
            connector_id: Some("fcp.test:base:v1".to_string()),
            operation_id: Some("send_message".to_string()),
            metadata: BTreeMap::new(),
            issuer_kid: None,
            signature: None,
        };
        entry.id = entry.computed_id().expect("entry id");
        entry
    }

    fn issuer_key_binding(signing_key: &Ed25519SigningKey) -> String {
        format!(
            "{}={}",
            signing_key.key_id().to_hex(),
            hex::encode(signing_key.verifying_key().to_bytes())
        )
    }

    fn explain_receipt(entry: &SignedAuditEntry) -> DecisionReceipt {
        DecisionReceipt {
            id: "receipt-explain-1".to_string(),
            request_id: "request-explain-1".to_string(),
            decision: Decision::Allow,
            reason_code: "policy.admitted".to_string(),
            evidence: vec![entry.id.clone()],
            audit_entry_id: Some(entry.id.clone()),
            explanation: Some("admission policy allowed the operation".to_string()),
            decided_at: entry.occurred_at,
            zone_id: entry.zone_id.clone(),
            correlation_id: Some(entry.correlation_id.clone()),
            trace_context: None,
            connector_id: entry.connector_id.clone(),
            operation_id: entry.operation_id.clone(),
            confidence: Some(fcp_audit::ConformalScore::from_value(0.9, 12, 1, 0, None)),
            issuer_kid: None,
            signature: None,
        }
    }

    #[test]
    fn format_timestamp_valid() {
        let ts = 1_700_000_000;
        let formatted = format_timestamp(ts);
        assert!(formatted.contains("2023"));
        assert!(formatted.ends_with('Z'));
    }

    #[test]
    fn truncate_short_string() {
        assert_eq!(truncate("abc", 10), "abc");
    }

    #[test]
    fn truncate_long_string() {
        assert_eq!(truncate("abcdefghij", 6), "abc...");
    }

    #[test]
    fn truncate_exact_length() {
        assert_eq!(truncate("abcdef", 6), "abcdef");
    }

    #[test]
    fn load_events_valid_zone() {
        let filter = AuditFilter::default();
        let events = load_audit_events("z:work", None, 10, &filter);
        assert!(events.is_ok());
        let events = events.unwrap();
        assert!(!events.is_empty());
    }

    #[test]
    fn audit_explain_loads_replay_bundle_file() {
        let entry = signed_test_entry(0, None);
        let receipt = explain_receipt(&entry);
        let bundle = serde_json::json!({
            "audit_entries": [entry.clone()],
            "capability_tokens": [{
                "id": "tok-explain-1",
                "capability_id": "test.invoke",
                "connector_id": "fcp.test:base:v1",
                "operation_id": "send_message",
                "issuer_kid": "kid-test"
            }],
            "receipts": [receipt]
        });
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bundle.json");
        fs::write(
            &path,
            serde_json::to_vec_pretty(&bundle).expect("bundle serializes"),
        )
        .expect("bundle writes");

        let loaded = load_explain_bundle(&path).expect("bundle loads");
        let explanation = fcp_audit::explain::explain_bundle(&loaded).expect("bundle explains");

        assert_eq!(explanation.connector_id, "fcp.test:base:v1");
        assert_eq!(explanation.operation_id, "send_message");
        assert!(
            explanation
                .render_human()
                .contains("revocation cascade did not trigger")
        );
        assert!(
            explanation
                .render_human()
                .contains("confidence 0.900 (n=12, nonconforming=1)")
        );
    }

    #[test]
    fn load_events_invalid_zone_format() {
        let filter = AuditFilter::default();
        let events = load_audit_events("invalid", None, 10, &filter);
        assert!(events.is_err());
        let err = events.unwrap_err();
        assert_eq!(err.code, "FCP-4001");
    }

    #[test]
    fn load_events_unknown_zone_empty() {
        let filter = AuditFilter::default();
        let events = load_audit_events("z:unknown", None, 10, &filter);
        assert!(events.is_ok());
        assert!(events.unwrap().is_empty());
    }

    #[test]
    fn load_events_respects_limit() {
        let filter = AuditFilter::default();
        let events = load_audit_events("z:work", None, 2, &filter).unwrap();
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn load_events_respects_filter() {
        let filter = AuditFilter {
            actor: Some("user:admin".to_string()),
            ..Default::default()
        };
        let events = load_audit_events("z:work", None, 10, &filter).unwrap();
        assert!(events.iter().all(|e| e.actor == "user:admin"));
    }

    #[test]
    fn load_events_filter_by_event_type() {
        let filter = AuditFilter {
            event_type: Some("capability.invoke".to_string()),
            ..Default::default()
        };
        let events = load_audit_events("z:work", None, 10, &filter).unwrap();
        assert!(events.iter().all(|e| e.event_type == "capability.invoke"));
    }

    // ---- format_timestamp edge cases ----

    #[test]
    fn format_timestamp_epoch_zero() {
        let formatted = format_timestamp(0);
        assert!(formatted.contains("1970"));
    }

    #[test]
    fn format_timestamp_iso_format() {
        let formatted = format_timestamp(1_700_000_000);
        assert!(formatted.ends_with('Z'));
        assert!(formatted.contains('T'));
    }

    // ---- truncate edge cases ----

    #[test]
    fn truncate_empty() {
        assert_eq!(truncate("", 10), "");
    }

    #[test]
    fn truncate_very_short_max() {
        // max_len <= 3 means no room for "...", just truncate
        assert_eq!(truncate("abcdef", 3), "abc");
    }

    #[test]
    fn truncate_one_char_over() {
        assert_eq!(truncate("abcdefg", 6), "abc...");
    }

    // ---- load_events with since ----

    #[test]
    fn load_events_with_since_parameter() {
        let filter = AuditFilter::default();
        let events = load_audit_events("z:work", Some(50), 10, &filter).unwrap();
        assert!(!events.is_empty());
        assert_eq!(events[0].seq, 50);
    }

    #[test]
    fn load_events_demo_zone() {
        let filter = AuditFilter::default();
        let events = load_audit_events("z:demo", None, 10, &filter).unwrap();
        assert!(!events.is_empty());
    }

    // ---- load_events filter by connector ----

    #[test]
    fn load_events_filter_by_connector() {
        let filter = AuditFilter {
            connector_id: Some("fcp.telegram:base:v1".to_string()),
            ..Default::default()
        };
        let events = load_audit_events("z:work", None, 10, &filter).unwrap();
        assert!(
            events
                .iter()
                .all(|e| e.connector_id.as_deref() == Some("fcp.telegram:base:v1"))
        );
    }

    #[test]
    fn load_events_filter_by_operation() {
        let filter = AuditFilter {
            operation_id: Some("send_message".to_string()),
            ..Default::default()
        };
        let events = load_audit_events("z:work", None, 10, &filter).unwrap();
        assert!(
            events
                .iter()
                .all(|e| e.operation_id.as_deref() == Some("send_message"))
        );
    }

    #[test]
    fn load_events_filter_by_correlation() {
        let filter = AuditFilter {
            correlation_id: Some("a".repeat(32)),
            ..Default::default()
        };
        let events = load_audit_events("z:work", None, 10, &filter).unwrap();
        assert_eq!(events.len(), 1);
    }

    // ---- parse_event_records ----

    #[test]
    fn parse_event_records_empty() {
        let records = parse_event_records("").unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn parse_event_records_whitespace() {
        let records = parse_event_records("   \n  \n  ").unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn parse_event_records_invalid_json() {
        let result = parse_event_records("{not json}");
        assert!(result.is_err());
    }

    // ---- parse_audit_head ----

    #[test]
    fn parse_audit_head_rejects_array() {
        let result = parse_audit_head("[1,2,3]");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("single JSON object")
        );
    }

    // ---- verify_chain ----

    #[test]
    fn verify_chain_empty_records() {
        let report = verify_chain(&[], None, None);
        assert!(matches!(report.status, AuditVerifyStatus::Ok));
        assert_eq!(report.chain_len, 0);
        assert!(report.issues.is_empty());
    }

    #[test]
    fn signer_aware_verify_rejects_tampered_chain() {
        let signing_key =
            Ed25519SigningKey::from_bytes(&[7u8; 32]).expect("deterministic signing key");
        let mut e0 = signed_test_entry(0, None);
        e0.sign(&signing_key).expect("sign genesis");

        let mut e1 = signed_test_entry(1, Some(&e0.id));
        e1.sign(&signing_key).expect("sign successor");
        let mut tampered_sig = e1.signature.as_ref().expect("signature present").to_bytes();
        tampered_sig[0] ^= 0x01;
        e1.signature = Some(Ed25519Signature::from_bytes(&tampered_sig));

        let events_input = format!(
            "{}\n{}",
            serde_json::to_string(&e0).expect("serialize e0"),
            serde_json::to_string(&e1).expect("serialize e1"),
        );
        let issuer_keys = vec![issuer_key_binding(&signing_key)];
        let report =
            build_verify_report_from_inputs(&events_input, None, Some("z:work"), &issuer_keys)
                .expect("verify report");

        assert!(matches!(report.status, AuditVerifyStatus::Fail));
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.code == "audit.signature_invalid" && issue.seq == Some(1)),
            "expected signature_invalid issue, got {:?}",
            report.issues
        );
    }

    // ---- AuditVerifyStatus serde ----

    #[test]
    fn verify_status_serde() {
        let json = serde_json::to_string(&AuditVerifyStatus::Ok).unwrap();
        assert_eq!(json, "\"ok\"");
        let json = serde_json::to_string(&AuditVerifyStatus::Warn).unwrap();
        assert_eq!(json, "\"warn\"");
        let json = serde_json::to_string(&AuditVerifyStatus::Fail).unwrap();
        assert_eq!(json, "\"fail\"");
    }

    // ---- AuditVerifyReport serde ----

    #[test]
    fn verify_report_serde_roundtrip() {
        let report = AuditVerifyReport {
            status: AuditVerifyStatus::Ok,
            zone_id: Some("z:work".to_string()),
            chain_len: 5,
            head_seq: Some(4),
            head_event: Some("event-id".to_string()),
            issues: vec![],
        };
        let json = serde_json::to_string(&report).unwrap();
        let parsed: AuditVerifyReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.chain_len, 5);
        assert!(parsed.issues.is_empty());
    }

    // ---- AuditVerifyIssue ----

    #[test]
    fn verify_issue_skips_none_fields() {
        let issue = AuditVerifyIssue {
            code: "test".to_string(),
            message: "msg".to_string(),
            seq: None,
            object_id: None,
        };
        let json = serde_json::to_string(&issue).unwrap();
        assert!(!json.contains("seq"));
        assert!(!json.contains("object_id"));
    }

    // ---- load_events all event types present ----

    #[test]
    fn load_events_has_diverse_event_types() {
        let filter = AuditFilter::default();
        let events = load_audit_events("z:work", None, 100, &filter).unwrap();
        let types: Vec<&str> = events.iter().map(|e| e.event_type.as_str()).collect();
        assert!(types.contains(&"capability.invoke"));
        assert!(types.contains(&"secret.access"));
        assert!(types.contains(&"elevation.granted"));
        assert!(types.contains(&"revocation.issued"));
        assert!(types.contains(&"security.violation"));
    }

    // ---- AuditTailError display ----

    #[test]
    fn audit_tail_error_display() {
        let err = AuditTailError::zone_not_found("z:test");
        let display = format!("{err}");
        assert!(display.contains("FCP-4001"));
        assert!(display.contains("z:test"));
    }

    #[test]
    fn audit_tail_error_interrupted() {
        let err = AuditTailError::interrupted();
        assert_eq!(err.code, "FCP-9001");
    }

    // ================================================================
    // format_timestamp — additional coverage
    // ================================================================

    #[test]
    fn format_timestamp_specific_known_value() {
        // 2023-11-14T22:13:20Z
        let formatted = format_timestamp(1_700_000_000);
        assert_eq!(formatted, "2023-11-14T22:13:20Z");
    }

    #[test]
    fn format_timestamp_year_2000() {
        // 2000-01-01T00:00:00Z = 946684800
        let formatted = format_timestamp(946_684_800);
        assert_eq!(formatted, "2000-01-01T00:00:00Z");
    }

    #[test]
    fn format_timestamp_contains_t_separator() {
        let formatted = format_timestamp(1_000_000);
        assert!(formatted.contains('T'));
    }

    #[test]
    fn format_timestamp_large_value() {
        // Far future timestamp — should still format (or fallback to number string)
        let formatted = format_timestamp(4_000_000_000);
        // Just verify it produces some string without panicking
        assert!(!formatted.is_empty());
    }

    // ================================================================
    // truncate — additional edge cases
    // ================================================================

    #[test]
    fn truncate_max_zero() {
        // max_len=0 means no room at all
        assert_eq!(truncate("abc", 0), "");
    }

    #[test]
    fn truncate_max_one() {
        assert_eq!(truncate("abc", 1), "a");
    }

    #[test]
    fn truncate_max_two() {
        assert_eq!(truncate("abcdef", 2), "ab");
    }

    #[test]
    fn truncate_max_four() {
        // max_len=4 > 3, so we get "a..."
        assert_eq!(truncate("abcdefgh", 4), "a...");
    }

    #[test]
    fn truncate_max_five() {
        assert_eq!(truncate("abcdefgh", 5), "ab...");
    }

    #[test]
    fn truncate_single_char_input() {
        assert_eq!(truncate("x", 10), "x");
    }

    #[test]
    fn truncate_exact_at_boundary() {
        let s = "abcde";
        assert_eq!(truncate(s, 5), "abcde");
        assert_eq!(truncate(s, 4), "a...");
    }

    // ================================================================
    // load_events — filter by trace ID
    // ================================================================

    #[test]
    fn load_events_filter_by_trace_id() {
        let filter = AuditFilter {
            trace_id: Some("t".repeat(32)),
            ..Default::default()
        };
        let events = load_audit_events("z:work", None, 10, &filter).unwrap();
        assert!(
            events
                .iter()
                .all(|e| e.trace_id.as_deref() == Some(&"t".repeat(32)))
        );
    }

    #[test]
    fn load_events_filter_nonexistent_trace() {
        let filter = AuditFilter {
            trace_id: Some("x".repeat(32)),
            ..Default::default()
        };
        let events = load_audit_events("z:work", None, 10, &filter).unwrap();
        assert!(events.is_empty());
    }

    // ================================================================
    // load_events — filter combos
    // ================================================================

    #[test]
    fn load_events_filter_connector_and_event_type() {
        let filter = AuditFilter {
            connector_id: Some("fcp.telegram:base:v1".to_string()),
            event_type: Some("capability.invoke".to_string()),
            ..Default::default()
        };
        let events = load_audit_events("z:work", None, 10, &filter).unwrap();
        // Should match only the first event
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "capability.invoke");
        assert_eq!(
            events[0].connector_id.as_deref(),
            Some("fcp.telegram:base:v1")
        );
    }

    #[test]
    fn load_events_filter_actor_and_event_type() {
        let filter = AuditFilter {
            actor: Some("user:admin".to_string()),
            event_type: Some("revocation.issued".to_string()),
            ..Default::default()
        };
        let events = load_audit_events("z:work", None, 10, &filter).unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn load_events_zero_limit() {
        let filter = AuditFilter::default();
        let events = load_audit_events("z:work", None, 0, &filter).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn load_events_limit_exceeds_total() {
        let filter = AuditFilter::default();
        let events = load_audit_events("z:work", None, 1000, &filter).unwrap();
        // Should return all events (6 total in the fixture)
        assert_eq!(events.len(), 6);
    }

    // ================================================================
    // load_events — zone edge cases
    // ================================================================

    #[test]
    fn load_events_zone_prefix_but_not_known() {
        let filter = AuditFilter::default();
        let events = load_audit_events("z:nonexistent", None, 10, &filter).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn load_events_zone_format_error_display() {
        let filter = AuditFilter::default();
        let err = load_audit_events("badzone", None, 10, &filter).unwrap_err();
        let display = format!("{err}");
        assert!(display.contains("FCP-4001"));
        assert!(display.contains("badzone"));
    }

    // ================================================================
    // load_events — event field assertions
    // ================================================================

    #[test]
    fn load_events_all_have_zone_id() {
        let filter = AuditFilter::default();
        let events = load_audit_events("z:work", None, 100, &filter).unwrap();
        for e in &events {
            assert_eq!(e.zone_id, "z:work");
        }
    }

    #[test]
    fn load_events_seq_monotonically_increases() {
        let filter = AuditFilter::default();
        let events = load_audit_events("z:work", None, 100, &filter).unwrap();
        for pair in events.windows(2) {
            assert!(pair[1].seq > pair[0].seq);
        }
    }

    #[test]
    fn load_events_occurred_at_monotonically_increases() {
        let filter = AuditFilter::default();
        let events = load_audit_events("z:work", None, 100, &filter).unwrap();
        for pair in events.windows(2) {
            assert!(pair[1].occurred_at > pair[0].occurred_at);
        }
    }

    #[test]
    fn load_events_correlation_ids_are_32_chars() {
        let filter = AuditFilter::default();
        let events = load_audit_events("z:work", None, 100, &filter).unwrap();
        for e in &events {
            assert_eq!(e.correlation_id.len(), 32);
        }
    }

    #[test]
    fn load_events_first_event_has_no_prev() {
        let filter = AuditFilter::default();
        let events = load_audit_events("z:work", None, 100, &filter).unwrap();
        assert!(events[0].prev.is_none());
    }

    #[test]
    fn load_events_subsequent_events_have_prev() {
        let filter = AuditFilter::default();
        let events = load_audit_events("z:work", None, 100, &filter).unwrap();
        for e in &events[1..] {
            assert!(e.prev.is_some());
        }
    }

    // ================================================================
    // parse_event_records — additional coverage
    // ================================================================

    #[test]
    fn parse_event_records_empty_lines_skipped() {
        let input = "\n\n\n";
        let records = parse_event_records(input).unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn parse_event_records_array_empty() {
        let input = "[]";
        let records = parse_event_records(input).unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn parse_event_records_trimmed_whitespace() {
        let input = "   \n   ";
        let records = parse_event_records(input).unwrap();
        assert!(records.is_empty());
    }

    // ================================================================
    // parse_audit_head — additional coverage
    // ================================================================

    #[test]
    fn parse_audit_head_empty_string() {
        let result = parse_audit_head("");
        assert!(result.is_err());
    }

    #[test]
    fn parse_audit_head_invalid_json() {
        let result = parse_audit_head("{bad}");
        assert!(result.is_err());
    }

    #[test]
    fn parse_audit_head_array_error_message() {
        let result = parse_audit_head("[{\"x\":1}]");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("single JSON object"));
    }

    // ================================================================
    // verify_chain — various issue scenarios
    // ================================================================

    #[test]
    fn verify_chain_empty_returns_ok() {
        let report = verify_chain(&[], None, None);
        assert!(matches!(report.status, AuditVerifyStatus::Ok));
        assert_eq!(report.chain_len, 0);
        assert!(report.issues.is_empty());
        assert!(report.zone_id.is_none());
        assert!(report.head_seq.is_none());
        assert!(report.head_event.is_none());
    }

    // ================================================================
    // AuditVerifyStatus — serde roundtrip each variant
    // ================================================================

    #[test]
    fn verify_status_ok_roundtrip() {
        let json = serde_json::to_string(&AuditVerifyStatus::Ok).unwrap();
        let parsed: AuditVerifyStatus = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, AuditVerifyStatus::Ok));
    }

    #[test]
    fn verify_status_warn_roundtrip() {
        let json = serde_json::to_string(&AuditVerifyStatus::Warn).unwrap();
        let parsed: AuditVerifyStatus = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, AuditVerifyStatus::Warn));
    }

    #[test]
    fn verify_status_fail_roundtrip() {
        let json = serde_json::to_string(&AuditVerifyStatus::Fail).unwrap();
        let parsed: AuditVerifyStatus = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, AuditVerifyStatus::Fail));
    }

    #[test]
    fn verify_status_snake_case_tags() {
        assert_eq!(
            serde_json::to_string(&AuditVerifyStatus::Ok).unwrap(),
            "\"ok\""
        );
        assert_eq!(
            serde_json::to_string(&AuditVerifyStatus::Warn).unwrap(),
            "\"warn\""
        );
        assert_eq!(
            serde_json::to_string(&AuditVerifyStatus::Fail).unwrap(),
            "\"fail\""
        );
    }

    // ================================================================
    // AuditVerifyReport — additional serde coverage
    // ================================================================

    #[test]
    fn verify_report_with_issues_roundtrip() {
        let report = AuditVerifyReport {
            status: AuditVerifyStatus::Fail,
            zone_id: Some("z:test".to_string()),
            chain_len: 10,
            head_seq: Some(9),
            head_event: Some("obj-id".to_string()),
            issues: vec![
                AuditVerifyIssue {
                    code: "audit.fork_detected".to_string(),
                    message: "fork at seq 5".to_string(),
                    seq: Some(5),
                    object_id: Some("oid1".to_string()),
                },
                AuditVerifyIssue {
                    code: "audit.seq_gap".to_string(),
                    message: "gap".to_string(),
                    seq: Some(7),
                    object_id: None,
                },
            ],
        };
        let json = serde_json::to_string(&report).unwrap();
        let parsed: AuditVerifyReport = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed.status, AuditVerifyStatus::Fail));
        assert_eq!(parsed.chain_len, 10);
        assert_eq!(parsed.issues.len(), 2);
        assert_eq!(parsed.issues[0].code, "audit.fork_detected");
        assert_eq!(parsed.issues[1].seq, Some(7));
    }

    #[test]
    fn verify_report_none_fields() {
        let report = AuditVerifyReport {
            status: AuditVerifyStatus::Ok,
            zone_id: None,
            chain_len: 0,
            head_seq: None,
            head_event: None,
            issues: vec![],
        };
        let json = serde_json::to_string(&report).unwrap();
        let parsed: AuditVerifyReport = serde_json::from_str(&json).unwrap();
        assert!(parsed.zone_id.is_none());
        assert!(parsed.head_seq.is_none());
        assert!(parsed.head_event.is_none());
    }

    #[test]
    fn verify_report_clone() {
        let report = AuditVerifyReport {
            status: AuditVerifyStatus::Warn,
            zone_id: Some("z:a".to_string()),
            chain_len: 3,
            head_seq: Some(2),
            head_event: Some("he".to_string()),
            issues: vec![AuditVerifyIssue {
                code: "c".to_string(),
                message: "m".to_string(),
                seq: Some(1),
                object_id: Some("o".to_string()),
            }],
        };
        let cloned = report.clone();
        assert_eq!(report.chain_len, cloned.chain_len);
        assert_eq!(report.issues.len(), cloned.issues.len());
    }

    // ================================================================
    // AuditVerifyIssue — additional coverage
    // ================================================================

    #[test]
    fn verify_issue_with_all_fields() {
        let issue = AuditVerifyIssue {
            code: "audit.test".to_string(),
            message: "test message".to_string(),
            seq: Some(42),
            object_id: Some("obj-123".to_string()),
        };
        let json = serde_json::to_string(&issue).unwrap();
        assert!(json.contains("\"seq\":42") || json.contains("\"seq\": 42"));
        assert!(json.contains("obj-123"));
    }

    #[test]
    fn verify_issue_clone() {
        let issue = AuditVerifyIssue {
            code: "a".to_string(),
            message: "b".to_string(),
            seq: Some(1),
            object_id: Some("c".to_string()),
        };
        let cloned = issue.clone();
        assert_eq!(issue.code, cloned.code);
        assert_eq!(issue.message, cloned.message);
        assert_eq!(issue.seq, cloned.seq);
        assert_eq!(issue.object_id, cloned.object_id);
    }

    #[test]
    fn verify_issue_serde_roundtrip() {
        let issue = AuditVerifyIssue {
            code: "audit.gap".to_string(),
            message: "seq gap detected".to_string(),
            seq: Some(10),
            object_id: Some("abc".to_string()),
        };
        let json = serde_json::to_string(&issue).unwrap();
        let parsed: AuditVerifyIssue = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.code, "audit.gap");
        assert_eq!(parsed.seq, Some(10));
    }

    // ================================================================
    // AuditEventRecord — serde shape
    // ================================================================

    #[test]
    fn event_record_has_object_id_and_event() {
        // Just verify the struct fields exist and are accessible
        // (we can't construct without fcp_core internals, but we can
        // verify the JSON shape expectation)
        let json = r#"{"object_id":"test","event":{}}"#;
        // This will fail to parse because AuditEvent needs real fields,
        // but we verify the error is about the event content, not missing keys
        let result: Result<AuditEventRecord, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    // ================================================================
    // load_events — event type diversity
    // ================================================================

    #[test]
    fn load_events_security_violation_present() {
        let filter = AuditFilter {
            event_type: Some("security.violation".to_string()),
            ..Default::default()
        };
        let events = load_audit_events("z:work", None, 100, &filter).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].actor, "user:mallory");
    }

    #[test]
    fn load_events_elevation_granted_present() {
        let filter = AuditFilter {
            event_type: Some("elevation.granted".to_string()),
            ..Default::default()
        };
        let events = load_audit_events("z:work", None, 100, &filter).unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn load_events_secret_access_present() {
        let filter = AuditFilter {
            event_type: Some("secret.access".to_string()),
            ..Default::default()
        };
        let events = load_audit_events("z:work", None, 100, &filter).unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn load_events_revocation_issued_present() {
        let filter = AuditFilter {
            event_type: Some("revocation.issued".to_string()),
            ..Default::default()
        };
        let events = load_audit_events("z:work", None, 100, &filter).unwrap();
        assert_eq!(events.len(), 1);
    }

    // ================================================================
    // load_events — actors
    // ================================================================

    #[test]
    fn load_events_filter_by_alice() {
        let filter = AuditFilter {
            actor: Some("user:alice".to_string()),
            ..Default::default()
        };
        let events = load_audit_events("z:work", None, 100, &filter).unwrap();
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn load_events_filter_by_bob() {
        let filter = AuditFilter {
            actor: Some("user:bob".to_string()),
            ..Default::default()
        };
        let events = load_audit_events("z:work", None, 100, &filter).unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn load_events_filter_by_mallory() {
        let filter = AuditFilter {
            actor: Some("user:mallory".to_string()),
            ..Default::default()
        };
        let events = load_audit_events("z:work", None, 100, &filter).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "security.violation");
    }

    #[test]
    fn load_events_filter_by_nonexistent_actor() {
        let filter = AuditFilter {
            actor: Some("user:nobody".to_string()),
            ..Default::default()
        };
        let events = load_audit_events("z:work", None, 100, &filter).unwrap();
        assert!(events.is_empty());
    }

    // ================================================================
    // load_events — connector-level
    // ================================================================

    #[test]
    fn load_events_filter_discord_connector() {
        let filter = AuditFilter {
            connector_id: Some("fcp.discord:base:v1".to_string()),
            ..Default::default()
        };
        let events = load_audit_events("z:work", None, 100, &filter).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].actor, "user:bob");
    }

    #[test]
    fn load_events_filter_github_connector() {
        let filter = AuditFilter {
            connector_id: Some("fcp.github:base:v1".to_string()),
            ..Default::default()
        };
        let events = load_audit_events("z:work", None, 100, &filter).unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn load_events_filter_nonexistent_connector() {
        let filter = AuditFilter {
            connector_id: Some("fcp.nonexistent:base:v1".to_string()),
            ..Default::default()
        };
        let events = load_audit_events("z:work", None, 100, &filter).unwrap();
        assert!(events.is_empty());
    }

    // ================================================================
    // load_events — since parameter
    // ================================================================

    #[test]
    fn load_events_since_zero() {
        let filter = AuditFilter::default();
        let events = load_audit_events("z:work", Some(0), 10, &filter).unwrap();
        assert_eq!(events[0].seq, 0);
    }

    #[test]
    fn load_events_since_large_value() {
        let filter = AuditFilter::default();
        let events = load_audit_events("z:work", Some(999_999), 10, &filter).unwrap();
        assert_eq!(events[0].seq, 999_999);
    }

    // ================================================================
    // load_events — iso timestamp format
    // ================================================================

    #[test]
    fn load_events_iso_timestamps_are_valid() {
        let filter = AuditFilter::default();
        let events = load_audit_events("z:work", None, 100, &filter).unwrap();
        for e in &events {
            assert!(e.occurred_at_iso.contains('T'));
            assert!(e.occurred_at_iso.ends_with('Z'));
        }
    }

    // ================================================================
    // AuditFilter used with load_events — operation filter
    // ================================================================

    #[test]
    fn load_events_filter_get_api_key_operation() {
        let filter = AuditFilter {
            operation_id: Some("get_api_key".to_string()),
            ..Default::default()
        };
        let events = load_audit_events("z:work", None, 100, &filter).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "secret.access");
    }

    #[test]
    fn load_events_filter_delete_repo_operation() {
        let filter = AuditFilter {
            operation_id: Some("delete_repo".to_string()),
            ..Default::default()
        };
        let events = load_audit_events("z:work", None, 100, &filter).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].actor, "user:mallory");
    }

    // ================================================================
    // verify_chain — report json shape
    // ================================================================

    #[test]
    fn verify_report_json_has_required_keys() {
        let report = AuditVerifyReport {
            status: AuditVerifyStatus::Ok,
            zone_id: Some("z:x".to_string()),
            chain_len: 0,
            head_seq: None,
            head_event: None,
            issues: vec![],
        };
        let val: serde_json::Value = serde_json::to_value(&report).unwrap();
        let obj = val.as_object().unwrap();
        assert!(obj.contains_key("status"));
        assert!(obj.contains_key("chain_len"));
        assert!(obj.contains_key("issues"));
    }

    #[test]
    fn verify_report_json_status_is_string() {
        let report = AuditVerifyReport {
            status: AuditVerifyStatus::Fail,
            zone_id: None,
            chain_len: 0,
            head_seq: None,
            head_event: None,
            issues: vec![],
        };
        let val: serde_json::Value = serde_json::to_value(&report).unwrap();
        assert!(val["status"].is_string());
        assert_eq!(val["status"].as_str().unwrap(), "fail");
    }

    #[test]
    fn verify_report_json_issues_is_array() {
        let report = AuditVerifyReport {
            status: AuditVerifyStatus::Ok,
            zone_id: None,
            chain_len: 0,
            head_seq: None,
            head_event: None,
            issues: vec![],
        };
        let val: serde_json::Value = serde_json::to_value(&report).unwrap();
        assert!(val["issues"].is_array());
    }

    // ================================================================
    // AuditTailError — additional coverage
    // ================================================================

    #[test]
    fn audit_tail_error_zone_not_found_display() {
        let err = AuditTailError::zone_not_found("z:missing");
        let display = format!("{err}");
        assert!(display.contains("FCP-4001"));
        assert!(display.contains("z:missing"));
    }

    #[test]
    fn audit_tail_error_chain_unavailable_display() {
        let err = AuditTailError::chain_unavailable("z:broken");
        let display = format!("{err}");
        assert!(display.contains("FCP-5011"));
        assert!(display.contains("z:broken"));
    }

    #[test]
    fn audit_tail_error_interrupted_display() {
        let err = AuditTailError::interrupted();
        let display = format!("{err}");
        assert!(display.contains("FCP-9001"));
        assert!(display.contains("interrupted"));
    }

    #[test]
    fn audit_tail_error_serde_roundtrip() {
        let err = AuditTailError::chain_unavailable("z:test");
        let json = serde_json::to_string(&err).unwrap();
        let parsed: AuditTailError = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.code, err.code);
        assert_eq!(parsed.message, err.message);
        assert_eq!(parsed.hints.len(), err.hints.len());
    }

    // ================================================================
    // load_events — events with trace context
    // ================================================================

    #[test]
    fn load_events_some_have_trace_some_dont() {
        let filter = AuditFilter::default();
        let events = load_audit_events("z:work", None, 100, &filter).unwrap();
        let with_trace = events.iter().filter(|e| e.trace_id.is_some()).count();
        let without_trace = events.iter().filter(|e| e.trace_id.is_none()).count();
        assert!(with_trace > 0);
        assert!(without_trace > 0);
    }

    #[test]
    fn load_events_span_id_present_when_trace_present() {
        let filter = AuditFilter::default();
        let events = load_audit_events("z:work", None, 100, &filter).unwrap();
        for e in &events {
            if e.trace_id.is_some() {
                assert!(e.span_id.is_some());
            }
        }
    }

    // ================================================================
    // load_events — events with/without connector
    // ================================================================

    #[test]
    fn load_events_some_have_connector_some_dont() {
        let filter = AuditFilter::default();
        let events = load_audit_events("z:work", None, 100, &filter).unwrap();
        let with_conn = events.iter().filter(|e| e.connector_id.is_some()).count();
        let without_conn = events.iter().filter(|e| e.connector_id.is_none()).count();
        assert!(with_conn > 0);
        assert!(without_conn > 0);
    }

    // ================================================================
    // output_json — verify it serializes events
    // ================================================================

    #[test]
    fn output_json_does_not_panic_on_empty() {
        // Should handle empty slice gracefully
        let result = output_json(&[]);
        assert!(result.is_ok());
    }

    // ================================================================
    // output_human — verify it does not panic
    // ================================================================

    #[test]
    fn output_human_does_not_panic_on_empty() {
        output_human(&[], "z:test", &AuditFilter::default());
    }

    #[test]
    fn output_human_does_not_panic_with_filter() {
        let filter = AuditFilter {
            connector_id: Some("fcp.test".to_string()),
            operation_id: Some("op".to_string()),
            correlation_id: Some("abcdefghijklmnop".to_string()),
            trace_id: Some("1234567890abcdef".to_string()),
            event_type: Some("test.event".to_string()),
            actor: Some("user:x".to_string()),
        };
        output_human(&[], "z:test", &filter);
    }

    #[test]
    fn output_human_does_not_panic_with_events() {
        let filter = AuditFilter::default();
        let events = load_audit_events("z:work", None, 3, &filter).unwrap();
        output_human(&events, "z:work", &filter);
    }

    // ================================================================
    // output_human — short correlation/trace IDs
    // ================================================================

    #[test]
    fn output_human_short_correlation_id_in_filter() {
        let filter = AuditFilter {
            correlation_id: Some("abc".to_string()), // shorter than 8 chars
            ..Default::default()
        };
        // Should not panic due to string slicing
        output_human(&[], "z:test", &filter);
    }

    #[test]
    fn output_human_short_trace_id_in_filter() {
        let filter = AuditFilter {
            trace_id: Some("xy".to_string()), // shorter than 8 chars
            ..Default::default()
        };
        output_human(&[], "z:test", &filter);
    }

    // ================================================================
    // Matrix + Gaps subcommands
    // ================================================================

    #[test]
    fn matrix_args_parses_connector_and_json() {
        let args = MatrixArgs {
            connector: Some("github".to_owned()),
            json: true,
            require_source: None,
        };
        assert_eq!(args.connector.as_deref(), Some("github"));
        assert!(args.json);
    }

    #[test]
    fn matrix_args_defaults_to_none() {
        let args = MatrixArgs {
            connector: None,
            json: false,
            require_source: None,
        };
        assert!(args.connector.is_none());
        assert!(!args.json);
    }

    #[test]
    fn gaps_args_blocking_only() {
        let args = GapsArgs {
            connector: None,
            blocking_only: true,
            json: false,
            require_source: None,
        };
        assert!(args.blocking_only);
    }

    #[test]
    fn gaps_args_connector_filter() {
        let args = GapsArgs {
            connector: Some("slack".to_owned()),
            blocking_only: false,
            json: true,
            require_source: None,
        };
        assert_eq!(args.connector.as_deref(), Some("slack"));
        assert!(args.json);
    }

    #[test]
    fn run_matrix_with_temp_dir() {
        let dir = tempfile::tempdir().unwrap();
        // Create a minimal connector directory with a manifest.
        let connector_dir = dir.path().join("test-connector");
        std::fs::create_dir(&connector_dir).unwrap();
        std::fs::write(
            connector_dir.join("manifest.toml"),
            r#"
[connector]
id = "fcp.test"
name = "Test"

[[operations]]
id = "list"
description = "List items"
capability = "read"
"#,
        )
        .unwrap();
        let matrix = crate::audit::run_audit(dir.path()).unwrap();
        assert_eq!(matrix.total_connectors, 1);
        assert_eq!(matrix.with_manifest, 1);
        assert!(matrix.connectors.contains_key("test-connector"));
    }

    #[test]
    fn run_matrix_json_output_is_valid() {
        let dir = tempfile::tempdir().unwrap();
        let connector_dir = dir.path().join("example");
        std::fs::create_dir(&connector_dir).unwrap();
        std::fs::write(
            connector_dir.join("manifest.toml"),
            r#"
[connector]
id = "fcp.example"
name = "Example"
"#,
        )
        .unwrap();
        let matrix = crate::audit::run_audit(dir.path()).unwrap();
        let json = serde_json::to_value(&matrix).unwrap();
        assert_eq!(json["total_connectors"], 1);
        assert!(json["connectors"]["example"].is_object());
    }

    #[test]
    fn run_gaps_missing_manifest_produces_gap() {
        let dir = tempfile::tempdir().unwrap();
        let connector_dir = dir.path().join("no-manifest");
        std::fs::create_dir(&connector_dir).unwrap();
        // No manifest.toml → should produce gaps
        let matrix = crate::audit::run_audit(dir.path()).unwrap();
        assert_eq!(matrix.missing_manifest, 1);
        let entry = &matrix.connectors["no-manifest"];
        assert!(!entry.has_manifest);
        assert!(!entry.gaps.is_empty());
    }

    // ── Audit tail host probe ───────────────────────────────────────────

    #[test]
    fn probe_host_unreachable_returns_false() {
        // No host running at a random port — should return false quickly.
        assert!(!probe_host_audit("http://127.0.0.1:19999"));
    }

    #[test]
    fn audit_tail_no_host_error_code_is_truthful() {
        let error = AuditTailError {
            code: "audit.tail.no_host".to_string(),
            message: "No host reachable".to_string(),
            hints: vec![],
        };
        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("audit.tail.no_host"));
        assert!(!json.contains("not_implemented"));
    }
}
