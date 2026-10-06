//! Live `/rpc/invoke` hash-linked audit chain (br-mvax3).
//!
//! A reality-check audit (br-mvax3) found that the README advertises
//! a "hash-linked audit event on every invoke" but the
//! production `/rpc/invoke` path only ever recorded a flat
//! `ReceiptSummary` (and only when the connector chose to return a
//! `receipt_id`). When the connector failed, denied preflight, or
//! returned no receipt, the chain claim was a lie.
//!
//! This module wires a per-host, per-zone hash-linked audit chain to
//! the four invoke phases — preflight allow, preflight deny, dispatch
//! result, dispatch error — so the README claim becomes literally true.
//!
//! ## Wire form
//!
//! Each appended event is an [`fcp_audit::AuditEntry`] with:
//! - `event_type`: one of [`event_types`].
//! - `seq`: monotonic per zone.
//! - `prev`: the previous entry's canonical id, hash-linked.
//! - `zone_id` / `connector_id` / `operation_id` / `correlation_id`:
//!   populated from the invoke request so an operator tracing a
//!   request can find every related audit row.
//! - `metadata`: phase-specific (see [`InvokePhase`]).
//!
//! The id is the BLAKE3 hash of the canonical CBOR of the entry
//! payload — same derivation `fcp_audit::AuditEntry::computed_id` uses,
//! so chain verification via the existing `verify_chain` helpers
//! continues to work without modification.
//!
//! ## Storage
//!
//! In-memory only for now (per-process). The shape is intentionally
//! retainable behind a trait so a future durable backend can be
//! swapped in without touching the call sites.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, RwLock};

use fcp_audit::{
    AuditEntry, AuditEntryIdFields, AuditError, FreshnessLevel, HybridLogicalClock,
    HybridLogicalTimestamp, Severity, audit_entry_hlc_from_occurred_at, compute_audit_entry_id,
    otlp_export::{AuditOtlpExporterStatus, FireAndForgetExporter},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::warn;

/// Defence-in-depth bound on the optimistic-CAS retry loop.
///
/// Sized so that even with thousands of concurrent same-zone appenders
/// the natural happy path completes well under the bound; hitting it
/// indicates pathological per-zone writer overload (operator response:
/// scale the writer fan-in or shard the per-zone Mutex).
pub const CAS_RETRY_BUDGET: usize = 64;

/// Number of stale-head CAS attempts after which production append
/// switches to a deterministic serialized commit for the current
/// event.
///
/// The optimistic path remains the hot path for uncontended and
/// lightly-contended zones. Under a same-zone storm, repeatedly
/// rebuilding canonical CBOR against stale heads burns CPU and can
/// exhaust [`CAS_RETRY_BUDGET`]. The serialized fallback pays one
/// short critical section for one event, using the fresh chain head
/// already protected by the zone mutex. That preserves chain
/// semantics while guaranteeing progress before the defensive retry
/// budget trips.
pub const SERIALIZED_COMMIT_FALLBACK_ATTEMPTS: usize = 8;

/// Stable schema for host-backed invoke audit-chain status snapshots.
pub const INVOKE_AUDIT_CHAIN_STATUS_SCHEMA_VERSION: &str = "fcp.host.invoke_audit_chain_status.v1";

/// Event type strings for invoke-chain audit entries.
pub mod event_types {
    /// Emitted after preflight (zone, capability, revocation) PASSES,
    /// before the connector subprocess is dispatched.
    pub const INVOKE_ALLOW: &str = "invoke.allow";
    /// Emitted when preflight DENIES the request — the connector is
    /// never dispatched.
    pub const INVOKE_DENY: &str = "invoke.deny";
    /// Emitted after the connector returns successfully.
    pub const INVOKE_RESULT: &str = "invoke.result";
    /// Emitted when the registry/dispatcher returns an error before or
    /// during connector execution.
    pub const INVOKE_ERROR: &str = "invoke.error";
    /// Emitted by the entry node when it relays the request to a mesh peer
    /// (the executing peer appends its own allow/result events).
    pub const INVOKE_MESH_FORWARDED: &str = "invoke.mesh_forwarded";
}

/// Phase-specific payload for an invoke audit append.
#[derive(Debug, Clone)]
pub enum InvokePhase {
    /// Preflight passed. Emitted before connector dispatch.
    PreflightAllow,
    /// Preflight denied. Connector never dispatched.
    PreflightDeny {
        /// Operator-readable reason (sanitized).
        reason: String,
    },
    /// Dispatch returned a response.
    DispatchResult {
        /// Receipt id returned by the connector, if any.
        receipt_id: Option<String>,
        /// `true` if the dispatch's status was `Ok`.
        success: bool,
        /// Wall-clock duration from request enter to dispatch return.
        duration_ms: u64,
    },
    /// Dispatch failed before returning a response.
    DispatchError {
        /// Sanitized error message.
        error: String,
        /// Wall-clock duration from request enter to dispatch failure.
        duration_ms: u64,
    },
    /// The entry node relayed the request to a mesh peer.
    MeshForwarded {
        /// Peer that answered (or the last peer attempted).
        target_node: String,
        /// Stable routing decision code.
        decision: String,
        /// HTTP-equivalent status the executor reported, if it answered.
        executor_status: Option<u16>,
        /// Peers that failed before delivery, in attempt order.
        failed_attempts: Vec<String>,
        /// Wall-clock duration of the relay.
        duration_ms: u64,
    },
}

impl InvokePhase {
    const fn event_type(&self) -> &'static str {
        match self {
            Self::PreflightAllow => event_types::INVOKE_ALLOW,
            Self::PreflightDeny { .. } => event_types::INVOKE_DENY,
            Self::DispatchResult { .. } => event_types::INVOKE_RESULT,
            Self::DispatchError { .. } => event_types::INVOKE_ERROR,
            Self::MeshForwarded { .. } => event_types::INVOKE_MESH_FORWARDED,
        }
    }

    const fn severity(&self) -> Severity {
        match self {
            Self::PreflightAllow => Severity::Info,
            Self::PreflightDeny { .. } => Severity::Warning,
            Self::DispatchResult { success, .. } => {
                if *success {
                    Severity::Info
                } else {
                    Severity::Warning
                }
            }
            Self::DispatchError { .. } => Severity::Error,
            Self::MeshForwarded {
                executor_status, ..
            } => match executor_status {
                Some(status) if *status >= 200 && *status < 300 => Severity::Info,
                Some(_) => Severity::Warning,
                None => Severity::Error,
            },
        }
    }

    fn into_metadata(self) -> Vec<(String, serde_json::Value)> {
        match self {
            Self::PreflightAllow => vec![],
            Self::PreflightDeny { reason } => vec![("reason".into(), json!(reason))],
            Self::DispatchResult {
                receipt_id,
                success,
                duration_ms,
            } => {
                let mut meta = vec![
                    ("success".into(), json!(success)),
                    ("duration_ms".into(), json!(duration_ms)),
                ];
                if let Some(id) = receipt_id {
                    meta.push(("receipt_id".into(), json!(id)));
                }
                meta
            }
            Self::DispatchError { error, duration_ms } => vec![
                ("error".into(), json!(error)),
                ("duration_ms".into(), json!(duration_ms)),
            ],
            Self::MeshForwarded {
                target_node,
                decision,
                executor_status,
                failed_attempts,
                duration_ms,
            } => vec![
                ("target_node".into(), json!(target_node)),
                ("decision".into(), json!(decision)),
                ("executor_status".into(), json!(executor_status)),
                ("failed_attempts".into(), json!(failed_attempts)),
                ("duration_ms".into(), json!(duration_ms)),
            ],
        }
    }
}

/// Stable context carried across the four invoke phases for one
/// request.
#[derive(Debug, Clone)]
pub struct InvokeAuditContext {
    /// Zone the request targets — partitions the chain.
    pub zone_id: String,
    /// Authenticated principal that issued the request.
    pub actor: String,
    /// Connector id being invoked.
    pub connector_id: String,
    /// Connector operation name.
    pub operation: String,
    /// Server-assigned request id (also used as `operation_id` on the
    /// audit entry).
    pub operation_id: String,
    /// Optional client-supplied correlation id for tracing.
    pub correlation_id: Option<String>,
    /// Wall-clock lower bound for when the request entered the host
    /// (Unix seconds). Same-zone commits clamp this to the previous
    /// committed audit timestamp so chain order remains verifiable
    /// when concurrent requests finish out of request-start order.
    pub occurred_at: u64,
}

#[derive(Debug)]
struct InvokeAuditEntryTemplate {
    event_type: &'static str,
    severity: Severity,
    actor: String,
    zone_id: String,
    connector_id: String,
    operation_id: String,
    correlation_id: String,
    metadata: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ClockAnomaly {
    requested: u64,
    previous: u64,
    clamped: u64,
}

impl ClockAnomaly {
    fn detect(requested_occurred_at: u64, previous_occurred_at: Option<u64>) -> Option<Self> {
        let previous_occurred_at = previous_occurred_at?;
        (requested_occurred_at < previous_occurred_at).then_some(Self {
            requested: requested_occurred_at,
            previous: previous_occurred_at,
            clamped: previous_occurred_at,
        })
    }

    const fn skew_secs(self) -> u64 {
        self.previous.saturating_sub(self.requested)
    }
}

impl InvokeAuditEntryTemplate {
    fn new(ctx: &InvokeAuditContext, phase: InvokePhase) -> Self {
        let event_type = phase.event_type();
        let severity = phase.severity();
        let mut metadata = BTreeMap::new();
        metadata.insert("operation".to_string(), json!(&ctx.operation));
        metadata.extend(phase.into_metadata());

        Self {
            event_type,
            severity,
            actor: ctx.actor.clone(),
            zone_id: ctx.zone_id.clone(),
            connector_id: ctx.connector_id.clone(),
            operation_id: ctx.operation_id.clone(),
            correlation_id: ctx.correlation_id.clone().unwrap_or_default(),
            metadata,
        }
    }

    fn compute_id(
        &self,
        seq: u64,
        occurred_at: u64,
        hlc: &HybridLogicalTimestamp,
        prev: Option<&str>,
        metadata: &BTreeMap<String, serde_json::Value>,
    ) -> Result<String, AuditError> {
        compute_audit_entry_id(AuditEntryIdFields {
            event_type: self.event_type,
            severity: self.severity,
            actor: &self.actor,
            zone_id: &self.zone_id,
            seq,
            occurred_at,
            hlc,
            prev,
            correlation_id: &self.correlation_id,
            trace_context: None,
            connector_id: Some(&self.connector_id),
            operation_id: Some(&self.operation_id),
            metadata,
        })
        .map_err(|e| AuditError::SerializationError(format!("invoke audit build: {e}")))
    }

    fn materialize(
        &self,
        seq: u64,
        occurred_at: u64,
        hlc: HybridLogicalTimestamp,
        prev: Option<String>,
        id: String,
        metadata: Option<BTreeMap<String, serde_json::Value>>,
    ) -> AuditEntry {
        AuditEntry {
            id,
            event_type: self.event_type.to_string(),
            severity: self.severity,
            actor: self.actor.clone(),
            zone_id: self.zone_id.clone(),
            seq,
            occurred_at,
            hlc,
            prev,
            correlation_id: self.correlation_id.clone(),
            trace_context: None,
            connector_id: Some(self.connector_id.clone()),
            operation_id: Some(self.operation_id.clone()),
            metadata: metadata.unwrap_or_else(|| self.metadata.clone()),
            issuer_kid: None,
            signature: None,
        }
    }

    fn metadata_with_clock_anomaly(
        &self,
        anomaly: ClockAnomaly,
    ) -> BTreeMap<String, serde_json::Value> {
        let mut metadata = self.metadata.clone();
        metadata.insert("alert".to_string(), json!("clock_anomaly"));
        metadata.insert("clock_anomaly".to_string(), json!(true));
        metadata.insert(
            "clock_anomaly_kind".to_string(),
            json!("wall_clock_regressed"),
        );
        metadata.insert(
            "clock_anomaly_requested_occurred_at".to_string(),
            json!(anomaly.requested),
        );
        metadata.insert(
            "clock_anomaly_previous_occurred_at".to_string(),
            json!(anomaly.previous),
        );
        metadata.insert(
            "clock_anomaly_clamped_occurred_at".to_string(),
            json!(anomaly.clamped),
        );
        metadata.insert(
            "clock_anomaly_skew_secs".to_string(),
            json!(anomaly.skew_secs()),
        );
        metadata
    }
}

#[derive(Debug, Default)]
struct ZoneChain {
    last_seq: Option<u64>,
    last_id: Option<String>,
    last_occurred_at: Option<u64>,
    last_hlc: Option<HybridLogicalTimestamp>,
    entries: Vec<AuditEntry>,
    metrics: InvokeAuditChainMetrics,
}

/// Per-zone append-path counters for [`InvokeAuditChain`].
///
/// These counters are intentionally semantic rather than timing-based:
/// tests and evidence scripts can prove whether an audit storm used the
/// optimistic path, retried stale heads, fell back to serialized commits,
/// or exhausted the retry budget without logging raw request payloads.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvokeAuditChainMetrics {
    /// Entries currently committed in this zone's chain.
    pub entries: usize,
    /// Commits that landed through the optimistic snapshot/CAS path.
    pub optimistic_commits: usize,
    /// Stale-head retries observed before a later commit or failure.
    pub stale_head_retries: usize,
    /// Commits that used the serialized storm fallback.
    pub serialized_fallbacks: usize,
    /// Retry-budget exhaustions surfaced as typed contention errors.
    pub contention_exhaustions: usize,
    /// Entries that detected and annotated wall-clock rollback.
    pub clock_anomalies: usize,
}

impl InvokeAuditChainMetrics {
    /// Number of entries committed through either successful append path.
    #[must_use]
    pub const fn committed_entries(self) -> usize {
        self.optimistic_commits + self.serialized_fallbacks
    }
}

/// Live source descriptor for host-backed invoke audit-chain status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvokeAuditChainStatusSource {
    /// Source kind used by operator JSON.
    pub kind: String,
    /// Whether this source was queried live.
    pub live: bool,
}

/// Live quorum-checkpoint availability attached to host-backed status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveQuorumCheckpointSnapshot {
    /// Whether quorum checkpoint data is available.
    pub available: bool,
    /// Machine-readable reason when checkpoint data is unavailable.
    pub reason_code: String,
    /// Human-readable redaction-safe detail.
    pub detail: String,
}

/// Redaction-safe status snapshot for the host invoke audit chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvokeAuditChainStatusSnapshot {
    /// Stable schema identifier.
    pub schema_version: String,
    /// Freshness classification for the current snapshot.
    pub status: FreshnessLevel,
    /// Operator-facing telemetry state.
    pub telemetry_state: String,
    /// Live source descriptor.
    pub source: InvokeAuditChainStatusSource,
    /// Zone whose chain was queried.
    pub zone_id: String,
    /// Current head sequence for the zone, if any entries exist.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_seq: Option<u64>,
    /// Current head entry id for the zone, if any entries exist.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_entry: Option<String>,
    /// Number of committed audit entries for this zone.
    pub audit_entries: u64,
    /// Last observed audit event time, if any entries exist.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_observed_at: Option<u64>,
    /// Quorum-signed checkpoint count. Zero until checkpoint signing is wired.
    pub quorum_signed_checkpoints: u64,
    /// Number of quorum signers present in the live checkpoint snapshot.
    pub quorum_signers: u64,
    /// Quorum signer ids present in the live checkpoint snapshot.
    pub quorum_signer_ids: Vec<String>,
    /// Last quorum checkpoint height, if a signed checkpoint exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_quorum_height: Option<u64>,
    /// Freshness of the latest quorum checkpoint in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quorum_freshness_secs: Option<u64>,
    /// Current quorum rotation epoch, if checkpoint telemetry provides it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quorum_rotation_epoch: Option<String>,
    /// Seconds until the next rotation, if checkpoint telemetry provides it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_rotation_eta_secs: Option<u64>,
    /// Drift between wall clock and the latest entry HLC physical component.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hlc_physical_drift_ms: Option<u64>,
    /// Maximum age used by the caller for freshness classification.
    pub max_age_seconds: u64,
    /// Explicit checkpoint availability so callers do not infer quorum.
    pub live_quorum_checkpoint_snapshot: LiveQuorumCheckpointSnapshot,
    /// Append-path counters for the queried zone.
    pub append_metrics: InvokeAuditChainMetrics,
    /// Redaction-safe warnings explaining degraded or missing states.
    pub warnings: Vec<String>,
}

/// Per-host hash-linked invoke audit chain.
///
/// Partitioned by zone — each zone has its own monotonic `seq` and
/// `prev`-linked chain so two zones cannot interfere with each other's
/// hash linkage.
///
/// # Concurrency model (br-uwlj5)
///
/// Two-layer locking, sharded by zone:
///
/// - **Outer `RwLock<HashMap<String, Arc<Mutex<ZoneChain>>>>`** —
///   read-locked on the hot path to look up the per-zone Mutex
///   (multiple zones can be looked up concurrently); write-locked
///   only on the COLD path that inserts a new zone (rare, dominated
///   by the lifetime of the host).
/// - **Inner per-zone `Mutex<ZoneChain>`** — held only for the
///   short bookkeeping window: snapshot `(last_seq, last_id)` →
///   drop → encode canonical CBOR + compute id OUTSIDE the lock →
///   re-lock + CAS-style verify the head still matches the
///   snapshot → push.
///
/// Net effect: N concurrent invokes targeting N distinct zones run
/// in parallel (each on its own per-zone Mutex). Same-zone invokes
/// still serialise on the per-zone Mutex but pay only the
/// constant-time bookkeeping cost inside the lock — the dominant
/// canonical-CBOR + BLAKE3 work happens lock-free, with an
/// optimistic-CAS retry on the rare case where another append to
/// the same zone landed between snapshot and commit.
///
/// Pre-uwlj5 design used a single global `Mutex<HashMap<...>>`
/// holding canonical CBOR + BLAKE3 inside the critical section —
/// throughput bottleneck on the per-`/rpc/invoke` audit hot path.
#[derive(Debug, Default)]
pub struct InvokeAuditChain {
    /// Outer map of per-zone chain handles. Read-locked on the
    /// hot path; write-locked only when a new zone is first
    /// observed.
    chains: RwLock<HashMap<String, Arc<Mutex<ZoneChain>>>>,
    /// Optional fire-and-forget OTLP exporter. The audit chain remains
    /// canonical; exporter failure never affects append success.
    otlp_exporter: Option<Arc<FireAndForgetExporter>>,
}

impl InvokeAuditChain {
    /// Construct an empty chain.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct an empty chain with audit OTLP export enabled.
    #[must_use]
    pub fn new_with_otlp_exporter(exporter: Arc<FireAndForgetExporter>) -> Self {
        Self {
            chains: RwLock::new(HashMap::new()),
            otlp_exporter: Some(exporter),
        }
    }

    /// Return the attached exporter, if any.
    #[must_use]
    pub fn otlp_exporter(&self) -> Option<Arc<FireAndForgetExporter>> {
        self.otlp_exporter.as_ref().map(Arc::clone)
    }

    /// Snapshot the attached exporter status.
    #[must_use]
    pub fn otlp_status(&self) -> Option<AuditOtlpExporterStatus> {
        self.otlp_exporter
            .as_ref()
            .map(|exporter| exporter.status())
    }

    /// Get-or-insert the per-zone handle. Optimised for the
    /// already-present case (single read-lock, no allocation).
    fn zone_handle(&self, zone_id: &str) -> Arc<Mutex<ZoneChain>> {
        // Fast path: zone already present, single read-lock.
        if let Some(handle) = self
            .chains
            .read()
            .expect("InvokeAuditChain outer rwlock poisoned")
            .get(zone_id)
        {
            return Arc::clone(handle);
        }
        // Slow path: insert under the write lock. Re-check after
        // upgrading because another writer may have raced us in.
        let mut chains = self
            .chains
            .write()
            .expect("InvokeAuditChain outer rwlock poisoned");
        Arc::clone(
            chains
                .entry(zone_id.to_owned())
                .or_insert_with(|| Arc::new(Mutex::new(ZoneChain::default()))),
        )
    }

    /// Append a phase event for `ctx` and return the resulting entry.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] if canonical-CBOR encoding of the entry
    /// payload fails (cannot happen for normal field values), or
    /// [`AuditError::ContentionExhausted`] if the optimistic-CAS retry
    /// budget [`CAS_RETRY_BUDGET`] is exceeded under per-zone writer
    /// overload.
    pub fn append(
        &self,
        ctx: &InvokeAuditContext,
        phase: InvokePhase,
    ) -> Result<AuditEntry, AuditError> {
        let entry = self.append_with_contention_policy(
            ctx,
            phase,
            CAS_RETRY_BUDGET,
            Some(SERIALIZED_COMMIT_FALLBACK_ATTEMPTS),
        )?;
        self.emit_otlp(&entry);
        Ok(entry)
    }

    /// Same as [`Self::append`] but with a caller-supplied CAS retry
    /// budget and no serialized fallback. Production callers should
    /// always use [`Self::append`] (which passes
    /// [`CAS_RETRY_BUDGET`] and enables
    /// [`SERIALIZED_COMMIT_FALLBACK_ATTEMPTS`]). This entry point
    /// exists so regression tests and benchmarks can drive the
    /// retry-only bound deterministically instead of trying to
    /// construct a real pathological storm.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] if canonical-CBOR encoding of the entry
    /// payload fails, or [`AuditError::ContentionExhausted`] if the
    /// supplied retry budget is exceeded under same-zone contention.
    pub fn append_with_retry_budget(
        &self,
        ctx: &InvokeAuditContext,
        phase: InvokePhase,
        retry_budget: usize,
    ) -> Result<AuditEntry, AuditError> {
        let entry = self.append_with_contention_policy(ctx, phase, retry_budget, None)?;
        self.emit_otlp(&entry);
        Ok(entry)
    }

    fn emit_otlp(&self, entry: &AuditEntry) {
        if let Some(exporter) = &self.otlp_exporter {
            let _ = exporter.try_export_entry(entry);
        }
    }

    fn append_with_contention_policy(
        &self,
        ctx: &InvokeAuditContext,
        phase: InvokePhase,
        retry_budget: usize,
        serialized_fallback_after: Option<usize>,
    ) -> Result<AuditEntry, AuditError> {
        let template = InvokeAuditEntryTemplate::new(ctx, phase);
        let zone = self.zone_handle(&ctx.zone_id);

        // br-uwlj5 optimistic-CAS retry loop. Constant in practice:
        // contention only happens when N appends to the SAME zone
        // race, which is bounded by per-zone request rate.
        let mut attempts: usize = 0;
        loop {
            attempts = attempts.saturating_add(1);
            // 1. Snapshot (last_seq, last_id) under the per-zone
            //    Mutex — short critical section, no allocation
            //    beyond the optional String clone of last_id.
            let (next_seq, prev_snapshot, last_occurred_at, last_hlc) = {
                let z = zone.lock().expect("InvokeAuditChain zone mutex poisoned");
                (
                    z.last_seq.map_or(0u64, |s| s.saturating_add(1)),
                    z.last_id.clone(),
                    z.last_occurred_at,
                    z.last_hlc.clone(),
                )
            };
            let occurred_at = monotonic_occurred_at(ctx.occurred_at, last_occurred_at);
            let hlc = next_audit_hlc(&template.actor, occurred_at, last_hlc.as_ref());
            let clock_anomaly = ClockAnomaly::detect(ctx.occurred_at, last_occurred_at);
            let metadata_override =
                clock_anomaly.map(|anomaly| template.metadata_with_clock_anomaly(anomaly));
            let metadata = metadata_override.as_ref().unwrap_or(&template.metadata);

            // 2. Encode canonical + hash OUTSIDE any lock. This is the
            //    dominant cost; running it lock-free is the load-bearing
            //    perf win. On failed CAS attempts, keep this path borrowed:
            //    the full owned AuditEntry is only materialized after the
            //    snapshot wins the commit race.
            let real_id = template.compute_id(
                next_seq,
                occurred_at,
                &hlc,
                prev_snapshot.as_deref(),
                metadata,
            )?;

            // 3. Re-lock + CAS commit. If another append landed
            //    on this zone between (1) and (3), our prev /
            //    seq snapshot is stale — retry with the fresh
            //    head. In the uncontended case (different zones
            //    or sequential same-zone) this loop runs once.
            {
                let mut z = zone.lock().expect("InvokeAuditChain zone mutex poisoned");
                if z.last_id.as_deref() == prev_snapshot.as_deref() {
                    let entry = template.materialize(
                        next_seq,
                        occurred_at,
                        hlc,
                        prev_snapshot,
                        real_id,
                        metadata_override,
                    );
                    z.last_seq = Some(next_seq);
                    z.last_id = Some(entry.id.clone());
                    z.last_occurred_at = Some(occurred_at);
                    z.last_hlc = Some(entry.hlc.clone());
                    z.entries.push(entry.clone());
                    z.metrics.entries = z.entries.len();
                    z.metrics.optimistic_commits = z.metrics.optimistic_commits.saturating_add(1);
                    if clock_anomaly.is_some() {
                        z.metrics.clock_anomalies = z.metrics.clock_anomalies.saturating_add(1);
                    }
                    drop(z);
                    if let Some(anomaly) = clock_anomaly {
                        emit_clock_anomaly(&entry, anomaly);
                    }
                    return Ok(entry);
                }
                z.metrics.stale_head_retries = z.metrics.stale_head_retries.saturating_add(1);
                // Else: another writer raced us; retry with the
                // fresh head. Drop the lock and loop.
            }

            // Same-zone storms can make every lock-free build race a
            // fresher head. Once that pattern is visible, switch this
            // one event to a serialized commit: take the fresh head
            // under the zone mutex, build the entry once, and append
            // immediately. This is equivalent to a successful retry
            // whose snapshot cannot go stale because the snapshot and
            // commit happen in the same critical section.
            if serialized_fallback_after.is_some_and(|fallback_after| attempts >= fallback_after) {
                return Self::append_serialized(&zone, &template, ctx.occurred_at);
            }

            // Defence in depth against pathological retry storms
            // (should be impossible without thousands of concurrent
            // same-zone appenders): bail with an error after a
            // reasonable bound rather than spinning forever.
            //
            // br-1a73y: bail with the contention-specific variant so
            // operator telemetry attributes the failure to per-zone
            // writer overload (correct response: scale or shard the
            // per-zone Mutex) rather than to a serialisation /
            // canonicalisation bug (which is what the previous
            // `SerializationError` taxonomy implied).
            if attempts > retry_budget {
                {
                    let mut z = zone.lock().expect("InvokeAuditChain zone mutex poisoned");
                    z.metrics.contention_exhaustions =
                        z.metrics.contention_exhaustions.saturating_add(1);
                }
                return Err(AuditError::ContentionExhausted {
                    zone_id: ctx.zone_id.clone(),
                    attempts,
                });
            }
        }
    }

    fn append_serialized(
        zone: &Arc<Mutex<ZoneChain>>,
        template: &InvokeAuditEntryTemplate,
        requested_occurred_at: u64,
    ) -> Result<AuditEntry, AuditError> {
        let mut z = zone.lock().expect("InvokeAuditChain zone mutex poisoned");
        let next_seq = z.last_seq.map_or(0u64, |s| s.saturating_add(1));
        let occurred_at = monotonic_occurred_at(requested_occurred_at, z.last_occurred_at);
        let hlc = next_audit_hlc(&template.actor, occurred_at, z.last_hlc.as_ref());
        let clock_anomaly = ClockAnomaly::detect(requested_occurred_at, z.last_occurred_at);
        let metadata_override =
            clock_anomaly.map(|anomaly| template.metadata_with_clock_anomaly(anomaly));
        let metadata = metadata_override.as_ref().unwrap_or(&template.metadata);
        let prev = z.last_id.clone();
        let id = template.compute_id(next_seq, occurred_at, &hlc, prev.as_deref(), metadata)?;
        let entry = template.materialize(next_seq, occurred_at, hlc, prev, id, metadata_override);
        z.last_seq = Some(next_seq);
        z.last_id = Some(entry.id.clone());
        z.last_occurred_at = Some(occurred_at);
        z.last_hlc = Some(entry.hlc.clone());
        z.entries.push(entry.clone());
        z.metrics.entries = z.entries.len();
        z.metrics.serialized_fallbacks = z.metrics.serialized_fallbacks.saturating_add(1);
        if clock_anomaly.is_some() {
            z.metrics.clock_anomalies = z.metrics.clock_anomalies.saturating_add(1);
        }
        drop(z);
        if let Some(anomaly) = clock_anomaly {
            emit_clock_anomaly(&entry, anomaly);
        }
        Ok(entry)
    }

    /// Snapshot of the entries appended for `zone_id`. Empty if the
    /// zone has had no invokes yet.
    ///
    /// # Panics
    ///
    /// Panics if the chain map or per-zone chain mutex has been poisoned.
    #[must_use]
    pub fn entries_for_zone(&self, zone_id: &str) -> Vec<AuditEntry> {
        let Some(handle) = self
            .chains
            .read()
            .expect("InvokeAuditChain outer rwlock poisoned")
            .get(zone_id)
            .cloned()
        else {
            return Vec::new();
        };
        handle
            .lock()
            .expect("InvokeAuditChain zone mutex poisoned")
            .entries
            .clone()
    }

    /// Number of entries appended for `zone_id`.
    ///
    /// # Panics
    ///
    /// Panics if the chain map or per-zone chain mutex has been poisoned.
    #[must_use]
    pub fn len_for_zone(&self, zone_id: &str) -> usize {
        let Some(handle) = self
            .chains
            .read()
            .expect("InvokeAuditChain outer rwlock poisoned")
            .get(zone_id)
            .cloned()
        else {
            return 0;
        };
        handle
            .lock()
            .expect("InvokeAuditChain zone mutex poisoned")
            .entries
            .len()
    }

    /// Snapshot append-path metrics for `zone_id`.
    ///
    /// # Panics
    ///
    /// Panics if the chain map or per-zone chain mutex has been poisoned.
    #[must_use]
    pub fn metrics_for_zone(&self, zone_id: &str) -> InvokeAuditChainMetrics {
        let Some(handle) = self
            .chains
            .read()
            .expect("InvokeAuditChain outer rwlock poisoned")
            .get(zone_id)
            .cloned()
        else {
            return InvokeAuditChainMetrics::default();
        };
        handle
            .lock()
            .expect("InvokeAuditChain zone mutex poisoned")
            .metrics
    }

    /// Build a redaction-safe live status snapshot for one zone.
    ///
    /// The current invoke audit chain is live host telemetry, but it is not a
    /// quorum-signed checkpoint stream yet. This method therefore reports
    /// committed entries and HLC drift without fabricating quorum signers.
    #[must_use]
    pub fn status_for_zone(
        &self,
        zone_id: &str,
        now_unix_secs: u64,
        max_age_seconds: u64,
    ) -> InvokeAuditChainStatusSnapshot {
        let entries = self.entries_for_zone(zone_id);
        let append_metrics = self.metrics_for_zone(zone_id);
        let tip_entry = entries.last();
        let mut warnings = Vec::new();

        if tip_entry.is_none() {
            warnings.push(format!(
                "live host invoke audit chain has no entries for zone `{zone_id}`"
            ));
        } else {
            warnings.push(
                "live host invoke audit chain is available, but quorum-signed checkpoint telemetry is not wired yet"
                    .to_owned(),
            );
        }
        if append_metrics.clock_anomalies > 0 {
            warnings.push(format!(
                "{} clock anomaly event(s) were recorded in this zone",
                append_metrics.clock_anomalies
            ));
        }
        if let Some(entry) = tip_entry
            && entry.occurred_at > now_unix_secs
        {
            warnings.push(format!(
                "head entry timestamp {} is in the future relative to now {}",
                entry.occurred_at, now_unix_secs
            ));
        }

        let hlc_physical_drift_ms = tip_entry.map(|entry| {
            now_unix_secs
                .saturating_mul(1_000)
                .abs_diff(entry.hlc.physical_ms)
        });

        InvokeAuditChainStatusSnapshot {
            schema_version: INVOKE_AUDIT_CHAIN_STATUS_SCHEMA_VERSION.to_owned(),
            status: if tip_entry.is_some() {
                FreshnessLevel::Degraded
            } else {
                FreshnessLevel::Missing
            },
            telemetry_state: "live-host".to_owned(),
            source: InvokeAuditChainStatusSource {
                kind: "host-invoke-audit-chain".to_owned(),
                live: true,
            },
            zone_id: zone_id.to_owned(),
            head_seq: tip_entry.map(|entry| entry.seq),
            head_entry: tip_entry.map(|entry| entry.id.clone()),
            audit_entries: u64::try_from(entries.len()).unwrap_or(u64::MAX),
            last_observed_at: tip_entry.map(|entry| entry.occurred_at),
            quorum_signed_checkpoints: 0,
            quorum_signers: 0,
            quorum_signer_ids: Vec::new(),
            last_quorum_height: None,
            quorum_freshness_secs: None,
            quorum_rotation_epoch: None,
            next_rotation_eta_secs: None,
            hlc_physical_drift_ms,
            max_age_seconds,
            live_quorum_checkpoint_snapshot: LiveQuorumCheckpointSnapshot {
                available: false,
                reason_code: "quorum-checkpoint-telemetry-unwired".to_owned(),
                detail: "host invoke-chain entries are live, but quorum checkpoint signing is not exposed yet"
                    .to_owned(),
            },
            append_metrics,
            warnings,
        }
    }
}

fn monotonic_occurred_at(requested: u64, previous: Option<u64>) -> u64 {
    previous.map_or(requested, |last| requested.max(last))
}

fn next_audit_hlc(
    node_id: &str,
    occurred_at: u64,
    previous: Option<&HybridLogicalTimestamp>,
) -> HybridLogicalTimestamp {
    let physical_ms = audit_entry_hlc_from_occurred_at(occurred_at, node_id).physical_ms;
    previous.map_or_else(
        || HybridLogicalTimestamp::from_physical(physical_ms, node_id),
        |previous| {
            let mut clock = HybridLogicalClock::new(node_id);
            clock.merge(previous, physical_ms)
        },
    )
}

fn emit_clock_anomaly(entry: &AuditEntry, anomaly: ClockAnomaly) {
    warn!(
        target: "fcp.audit.clock_anomaly",
        entry_id = %entry.id,
        zone_id = %entry.zone_id,
        actor = %entry.actor,
        requested_occurred_at = anomaly.requested,
        previous_occurred_at = anomaly.previous,
        clamped_occurred_at = anomaly.clamped,
        skew_secs = anomaly.skew_secs(),
        "audit append detected wall-clock rollback and advanced HLC logical counter"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(zone: &str, op_id: &str) -> InvokeAuditContext {
        InvokeAuditContext {
            zone_id: zone.into(),
            actor: "agent:test".into(),
            connector_id: "github".into(),
            operation: "list_repos".into(),
            operation_id: op_id.into(),
            correlation_id: Some("cid-42".into()),
            occurred_at: 1_700_000_000,
        }
    }

    #[test]
    fn invoke_audit_chain_single_append_is_genesis() {
        let chain = InvokeAuditChain::new();
        let entry = chain
            .append(&ctx("z:work", "op-1"), InvokePhase::PreflightAllow)
            .unwrap();
        assert!(
            entry.is_genesis(),
            "first entry must be genesis (seq 0, no prev)"
        );
        assert_eq!(entry.event_type, event_types::INVOKE_ALLOW);
        assert_eq!(entry.severity, Severity::Info);
        assert_eq!(entry.zone_id, "z:work");
        assert_eq!(entry.hlc.node_id, "agent:test");
        assert_eq!(
            entry.hlc.physical_ms,
            entry.occurred_at.saturating_mul(1_000)
        );
    }

    #[test]
    fn invoke_audit_chain_status_reports_live_missing_without_entries() {
        let chain = InvokeAuditChain::new();
        let status = chain.status_for_zone("z:work", 1_700_000_030, 60);

        assert_eq!(
            status.schema_version,
            INVOKE_AUDIT_CHAIN_STATUS_SCHEMA_VERSION
        );
        assert_eq!(status.status, FreshnessLevel::Missing);
        assert_eq!(status.telemetry_state, "live-host");
        assert_eq!(status.source.kind, "host-invoke-audit-chain");
        assert!(status.source.live);
        assert_eq!(status.zone_id, "z:work");
        assert_eq!(status.audit_entries, 0);
        assert_eq!(status.quorum_signed_checkpoints, 0);
        assert_eq!(status.quorum_signers, 0);
        assert!(!status.live_quorum_checkpoint_snapshot.available);
        assert!(
            status
                .warnings
                .iter()
                .any(|warning| warning.contains("no entries"))
        );
    }

    #[test]
    fn invoke_audit_chain_status_reports_live_entries_without_fabricating_quorum() {
        let chain = InvokeAuditChain::new();
        let entry = chain
            .append(&ctx("z:work", "op-1"), InvokePhase::PreflightAllow)
            .unwrap();

        let status = chain.status_for_zone("z:work", 1_700_000_030, 60);

        assert_eq!(status.status, FreshnessLevel::Degraded);
        assert_eq!(status.head_seq, Some(entry.seq));
        assert_eq!(status.head_entry.as_deref(), Some(entry.id.as_str()));
        assert_eq!(status.audit_entries, 1);
        assert_eq!(status.last_observed_at, Some(entry.occurred_at));
        assert_eq!(status.quorum_signed_checkpoints, 0);
        assert_eq!(status.quorum_signers, 0);
        assert!(status.quorum_signer_ids.is_empty());
        assert!(status.last_quorum_height.is_none());
        assert_eq!(status.hlc_physical_drift_ms, Some(30_000));
        assert_eq!(status.append_metrics.entries, 1);
        assert!(
            status
                .warnings
                .iter()
                .any(|warning| warning.contains("quorum-signed checkpoint telemetry"))
        );
    }

    #[test]
    fn invoke_audit_chain_consecutive_appends_hash_link() {
        // br-mvax3: the README claim is "hash-linked audit chain". The
        // second entry MUST `follow` the first via prev = first.id and
        // seq = first.seq + 1.
        let chain = InvokeAuditChain::new();
        let first = chain
            .append(&ctx("z:work", "op-1"), InvokePhase::PreflightAllow)
            .unwrap();
        let second = chain
            .append(
                &ctx("z:work", "op-1"),
                InvokePhase::DispatchResult {
                    receipt_id: Some("rcpt-1".into()),
                    success: true,
                    duration_ms: 42,
                },
            )
            .unwrap();
        assert!(
            second.follows(&first),
            "second entry must hash-link to first: prev={:?} expected_prev={:?}, seq={} expected_seq={}",
            second.prev,
            Some(&first.id),
            second.seq,
            first.seq + 1
        );
        assert_eq!(second.event_type, event_types::INVOKE_RESULT);
        assert!(
            second.hlc > first.hlc,
            "second entry HLC must advance even when wall-clock seconds are equal"
        );
    }

    #[test]
    fn invoke_audit_chain_clock_step_back_marks_anomaly_without_hlc_regression() {
        let chain = InvokeAuditChain::new();
        let mut first_ctx = ctx("z:work", "op-rollback-1");
        first_ctx.occurred_at = 1_700_000_010;
        let first = chain
            .append(&first_ctx, InvokePhase::PreflightAllow)
            .unwrap();

        let mut second_ctx = ctx("z:work", "op-rollback-2");
        second_ctx.occurred_at = 1_700_000_000;
        let second = chain
            .append(&second_ctx, InvokePhase::PreflightAllow)
            .unwrap();

        assert_eq!(second.occurred_at, first.occurred_at);
        assert_eq!(second.hlc.physical_ms, first.hlc.physical_ms);
        assert!(
            second.hlc > first.hlc,
            "clock rollback must advance the logical counter instead of regressing HLC"
        );
        assert_eq!(
            second.metadata.get("alert").and_then(|v| v.as_str()),
            Some("clock_anomaly")
        );
        assert_eq!(
            second
                .metadata
                .get("clock_anomaly")
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert_eq!(
            second
                .metadata
                .get("clock_anomaly_kind")
                .and_then(|v| v.as_str()),
            Some("wall_clock_regressed")
        );
        assert_eq!(
            second
                .metadata
                .get("clock_anomaly_requested_occurred_at")
                .and_then(serde_json::Value::as_u64),
            Some(second_ctx.occurred_at)
        );
        assert_eq!(
            second
                .metadata
                .get("clock_anomaly_previous_occurred_at")
                .and_then(serde_json::Value::as_u64),
            Some(first.occurred_at)
        );
        assert_eq!(
            second
                .metadata
                .get("clock_anomaly_clamped_occurred_at")
                .and_then(serde_json::Value::as_u64),
            Some(first.occurred_at)
        );
        assert_eq!(
            second
                .metadata
                .get("clock_anomaly_skew_secs")
                .and_then(serde_json::Value::as_u64),
            Some(10)
        );
        assert_eq!(chain.metrics_for_zone("z:work").clock_anomalies, 1);
    }

    #[test]
    fn invoke_audit_chain_zone_isolation() {
        // Two zones must each have their own seq=0 genesis entry —
        // they cannot interfere with each other's hash linkage.
        let chain = InvokeAuditChain::new();
        let work = chain
            .append(&ctx("z:work", "op-1"), InvokePhase::PreflightAllow)
            .unwrap();
        let home = chain
            .append(&ctx("z:home", "op-2"), InvokePhase::PreflightAllow)
            .unwrap();
        assert!(work.is_genesis());
        assert!(home.is_genesis());
        assert_eq!(work.zone_id, "z:work");
        assert_eq!(home.zone_id, "z:home");
        assert_eq!(chain.len_for_zone("z:work"), 1);
        assert_eq!(chain.len_for_zone("z:home"), 1);
    }

    #[test]
    fn invoke_audit_chain_deny_appends_with_warning_severity() {
        let chain = InvokeAuditChain::new();
        let entry = chain
            .append(
                &ctx("z:work", "op-1"),
                InvokePhase::PreflightDeny {
                    reason: "capability not granted".into(),
                },
            )
            .unwrap();
        assert_eq!(entry.event_type, event_types::INVOKE_DENY);
        assert_eq!(entry.severity, Severity::Warning);
        assert_eq!(
            entry.metadata.get("reason").and_then(|v| v.as_str()),
            Some("capability not granted")
        );
    }

    #[test]
    fn invoke_audit_chain_dispatch_error_carries_message() {
        let chain = InvokeAuditChain::new();
        let entry = chain
            .append(
                &ctx("z:work", "op-1"),
                InvokePhase::DispatchError {
                    error: "connector subprocess crashed".into(),
                    duration_ms: 17,
                },
            )
            .unwrap();
        assert_eq!(entry.event_type, event_types::INVOKE_ERROR);
        assert_eq!(entry.severity, Severity::Error);
        assert_eq!(
            entry.metadata.get("error").and_then(|v| v.as_str()),
            Some("connector subprocess crashed")
        );
        assert_eq!(
            entry
                .metadata
                .get("duration_ms")
                .and_then(serde_json::Value::as_u64),
            Some(17)
        );
    }

    #[test]
    fn invoke_audit_chain_id_is_canonical_recomputable() {
        // br-mvax3: the entry's id MUST match its computed_id (BLAKE3
        // of canonical CBOR of the payload). This is what makes the
        // hash chain verifiable by downstream tooling.
        let chain = InvokeAuditChain::new();
        let entry = chain
            .append(&ctx("z:work", "op-1"), InvokePhase::PreflightAllow)
            .unwrap();
        let recomputed = entry
            .computed_id()
            .expect("computed_id must succeed for a well-formed entry");
        assert_eq!(
            entry.id, recomputed,
            "stored id must match computed_id so the chain is verifiable"
        );
    }

    #[test]
    fn invoke_audit_chain_full_request_lifecycle_produces_chain_of_two_links() {
        // br-mvax3 acceptance: a full successful invoke produces TWO
        // events — allow + result — both linked.
        let chain = InvokeAuditChain::new();
        let c = ctx("z:work", "op-99");
        chain.append(&c, InvokePhase::PreflightAllow).unwrap();
        chain
            .append(
                &c,
                InvokePhase::DispatchResult {
                    receipt_id: Some("rcpt-99".into()),
                    success: true,
                    duration_ms: 100,
                },
            )
            .unwrap();

        let entries = chain.entries_for_zone("z:work");
        assert_eq!(entries.len(), 2);
        assert!(entries[0].is_genesis());
        assert!(entries[1].follows(&entries[0]));
        assert_eq!(entries[0].event_type, event_types::INVOKE_ALLOW);
        assert_eq!(entries[1].event_type, event_types::INVOKE_RESULT);
        // Both share the operation_id so an operator can correlate.
        assert_eq!(entries[0].operation_id.as_deref(), Some("op-99"));
        assert_eq!(entries[1].operation_id.as_deref(), Some("op-99"));
        let metrics = chain.metrics_for_zone("z:work");
        assert_eq!(metrics.entries, 2);
        assert_eq!(metrics.optimistic_commits, 2);
        assert_eq!(metrics.committed_entries(), 2);
        assert_eq!(metrics.stale_head_retries, 0);
        assert_eq!(metrics.serialized_fallbacks, 0);
        assert_eq!(metrics.contention_exhaustions, 0);
    }

    #[test]
    fn invoke_audit_chain_denied_request_still_produces_event() {
        // br-mvax3 acceptance: even when preflight denies, an event
        // must be appended — the README "every operation" claim.
        let chain = InvokeAuditChain::new();
        let c = ctx("z:work", "op-deny");
        chain
            .append(
                &c,
                InvokePhase::PreflightDeny {
                    reason: "out of zone".into(),
                },
            )
            .unwrap();
        let entries = chain.entries_for_zone("z:work");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].event_type, event_types::INVOKE_DENY);
    }

    #[test]
    fn invoke_audit_chain_failed_dispatch_with_no_receipt_still_appends() {
        // br-mvax3 acceptance: the previous bug was that connectors
        // returning no receipt_id silently produced ZERO audit events.
        // The DispatchError phase must always append.
        let chain = InvokeAuditChain::new();
        let c = ctx("z:work", "op-bad");
        chain.append(&c, InvokePhase::PreflightAllow).unwrap();
        chain
            .append(
                &c,
                InvokePhase::DispatchError {
                    error: "boom".into(),
                    duration_ms: 5,
                },
            )
            .unwrap();
        let entries = chain.entries_for_zone("z:work");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].event_type, event_types::INVOKE_ERROR);
        assert!(entries[1].follows(&entries[0]));
    }

    // ── br-uwlj5: per-zone sharding regressions ──────────────────────

    #[test]
    fn invoke_audit_chain_concurrent_appends_to_distinct_zones_do_not_serialise() {
        // br-uwlj5: under per-zone sharding, two threads appending to
        // different zones MUST be able to land their entries
        // independently of each other's lock state. The pre-uwlj5
        // single-Mutex design would force one thread to wait on the
        // other's canonical-CBOR + BLAKE3 critical section.
        //
        // Functional check: spawn N threads each appending APPENDS_PER
        // events to a unique zone, then assert every chain has the
        // expected length and each entry's prev hash-links to the
        // previous one. Concurrency-safety + zone isolation in one
        // test.
        use std::thread;

        const ZONES: usize = 8;
        const APPENDS_PER: usize = 32;

        let chain = std::sync::Arc::new(InvokeAuditChain::new());
        let mut handles = Vec::with_capacity(ZONES);
        for z in 0..ZONES {
            let chain_arc = std::sync::Arc::clone(&chain);
            handles.push(thread::spawn(move || {
                let zone_id = format!("z:zone-{z}");
                for i in 0..APPENDS_PER {
                    let c = InvokeAuditContext {
                        zone_id: zone_id.clone(),
                        actor: format!("agent:t-{z}"),
                        connector_id: "github".into(),
                        operation: "list_repos".into(),
                        operation_id: format!("op-{z}-{i}"),
                        correlation_id: None,
                        occurred_at: 1_700_000_000 + i as u64,
                    };
                    chain_arc
                        .append(&c, InvokePhase::PreflightAllow)
                        .expect("append must not fail under per-zone sharding");
                }
            }));
        }
        for h in handles {
            h.join().expect("worker thread panicked");
        }

        // Each zone got APPENDS_PER entries, each correctly hash-linked.
        for z in 0..ZONES {
            let zone_id = format!("z:zone-{z}");
            let entries = chain.entries_for_zone(&zone_id);
            assert_eq!(
                entries.len(),
                APPENDS_PER,
                "zone {zone_id} must have {APPENDS_PER} entries"
            );
            assert!(
                entries[0].is_genesis(),
                "zone {zone_id}: entry 0 is genesis"
            );
            for i in 1..entries.len() {
                assert!(
                    entries[i].follows(&entries[i - 1]),
                    "zone {zone_id}: entry {i} must hash-link to entry {}: prev={:?} expected={:?}, seq={} expected={}",
                    i - 1,
                    entries[i].prev,
                    Some(&entries[i - 1].id),
                    entries[i].seq,
                    entries[i - 1].seq + 1,
                );
            }
        }
    }

    #[test]
    fn invoke_audit_chain_concurrent_same_zone_appends_preserve_chain_integrity() {
        // br-uwlj5: same-zone appends still serialise on the per-zone
        // Mutex, but the optimistic-CAS retry pattern means concurrent
        // appenders DO retry and DO produce a correctly hash-linked
        // chain. This test pins the property: N threads × M appends to
        // ONE zone produces N×M entries with monotonic seq and
        // pairwise prev-link.
        use std::thread;

        const THREADS: usize = 8;
        const APPENDS_PER: usize = 16;

        let chain = std::sync::Arc::new(InvokeAuditChain::new());
        let mut handles = Vec::with_capacity(THREADS);
        for t in 0..THREADS {
            let chain_arc = std::sync::Arc::clone(&chain);
            handles.push(thread::spawn(move || {
                for i in 0..APPENDS_PER {
                    let c = InvokeAuditContext {
                        zone_id: "z:contended".into(),
                        actor: format!("agent:t-{t}"),
                        connector_id: "github".into(),
                        operation: "list_repos".into(),
                        operation_id: format!("op-{t}-{i}"),
                        correlation_id: None,
                        occurred_at: 1_700_000_000,
                    };
                    chain_arc
                        .append(&c, InvokePhase::PreflightAllow)
                        .expect("same-zone append must succeed via CAS retry");
                }
            }));
        }
        for h in handles {
            h.join().expect("worker thread panicked");
        }

        let entries = chain.entries_for_zone("z:contended");
        assert_eq!(entries.len(), THREADS * APPENDS_PER);
        // Monotonic seq: 0, 1, 2, ..., THREADS*APPENDS_PER - 1.
        for (i, e) in entries.iter().enumerate() {
            assert_eq!(e.seq, i as u64, "monotonic seq broken at index {i}");
        }
        // Pairwise hash links.
        assert!(entries[0].is_genesis());
        for i in 1..entries.len() {
            assert!(
                entries[i].follows(&entries[i - 1]),
                "entry {i} must hash-link under contention"
            );
        }
    }

    #[test]
    fn invoke_audit_chain_same_zone_storm_uses_serialized_fallback_without_dropping_events() {
        // evxvv.8: the retry-only CAS path can exhaust its defensive
        // retry budget under modest same-zone storms. Production
        // append keeps the optimistic path for ordinary traffic but
        // falls back to one serialized commit once stale-head retries
        // show that this event is racing a hot zone. The observable
        // contract is unchanged: every append lands exactly once, seq
        // is monotonic, and prev hash-links to the prior entry.
        use std::thread;

        const THREADS: usize = 64;
        const APPENDS_PER: usize = 16;

        let chain = std::sync::Arc::new(InvokeAuditChain::new());
        let mut handles = Vec::with_capacity(THREADS);
        for t in 0..THREADS {
            let chain_arc = std::sync::Arc::clone(&chain);
            handles.push(thread::spawn(move || {
                for i in 0..APPENDS_PER {
                    let c = InvokeAuditContext {
                        zone_id: "z:storm".into(),
                        actor: format!("agent:t-{t}"),
                        connector_id: "github".into(),
                        operation: "list_repos".into(),
                        operation_id: format!("op-{t}-{i}"),
                        correlation_id: None,
                        occurred_at: 1_700_000_000,
                    };
                    chain_arc
                        .append(&c, InvokePhase::PreflightAllow)
                        .expect("serialized fallback must prevent same-zone audit loss");
                }
            }));
        }
        for h in handles {
            h.join().expect("worker thread panicked");
        }

        let entries = chain.entries_for_zone("z:storm");
        assert_eq!(entries.len(), THREADS * APPENDS_PER);
        let metrics = chain.metrics_for_zone("z:storm");
        assert_eq!(metrics.entries, THREADS * APPENDS_PER);
        assert_eq!(metrics.committed_entries(), THREADS * APPENDS_PER);
        assert_eq!(
            metrics.contention_exhaustions, 0,
            "production fallback must prevent audit loss under same-zone storms"
        );
        assert!(entries[0].is_genesis());
        for (i, entry) in entries.iter().enumerate() {
            assert_eq!(entry.seq, i as u64, "monotonic seq broken at index {i}");
            if i > 0 {
                assert!(
                    entry.follows(&entries[i - 1]),
                    "entry {i} must hash-link after serialized fallback"
                );
            }
        }
    }

    #[test]
    fn invoke_audit_chain_clamps_out_of_order_same_zone_timestamps() {
        // evxvv.8 cross-crate seam: fcp-host commits same-zone audit
        // entries in completion order, while fcp-audit verifies
        // timestamps in chain order. If request A starts before
        // request B but commits after B, using the request-entry
        // timestamp verbatim creates a timestamp regression even
        // though the hash link and sequence are valid.
        let chain = InvokeAuditChain::new();
        let mut later_start = ctx("z:work", "op-later-start");
        later_start.occurred_at = 1_700_000_200;
        let mut earlier_start = ctx("z:work", "op-earlier-start");
        earlier_start.occurred_at = 1_700_000_100;

        chain
            .append(&later_start, InvokePhase::PreflightAllow)
            .unwrap();
        chain
            .append(&earlier_start, InvokePhase::PreflightAllow)
            .unwrap();

        let entries = chain.entries_for_zone("z:work");
        assert_eq!(entries.len(), 2);
        assert!(entries[1].follows(&entries[0]));
        assert_eq!(
            entries[1].occurred_at, entries[0].occurred_at,
            "same-zone commit order must remain non-decreasing for fcp-audit verification"
        );
        assert!(
            entries[1].hlc > entries[0].hlc,
            "HLC must preserve strict causal order when wall-clock seconds are clamped"
        );
        let report = fcp_audit::verify_chain(&entries, None, Some("z:work"));
        assert!(
            report.is_clean() && report.status.is_ok(),
            "timestamp-clamped invoke chain must verify cleanly: {report:?}"
        );
    }

    /// br-1a73y: when the optimistic-CAS retry budget is exhausted
    /// the bail MUST surface as `AuditError::ContentionExhausted`
    /// (not the misleading `SerializationError` the prior taxonomy
    /// used). This regression drives the bail deterministically by
    /// passing a tiny `retry_budget` and racing many concurrent
    /// appenders on a single zone — at least one appender will be
    /// out-CAS'd more times than the budget allows.
    #[test]
    fn br_1a73y_cas_retry_budget_exhaustion_returns_contention_exhausted_variant() {
        use std::sync::Arc as StdArc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::thread;

        // Tiny retry budget so even modest contention trips it.
        const RETRY_BUDGET: usize = 1;
        const THREADS: usize = 32;
        const APPENDS_PER: usize = 8;

        let chain = StdArc::new(InvokeAuditChain::new());
        let contention_failures = StdArc::new(AtomicUsize::new(0));
        let unexpected_errors = StdArc::new(AtomicUsize::new(0));
        let mut handles = Vec::with_capacity(THREADS);
        for t in 0..THREADS {
            let chain_arc = StdArc::clone(&chain);
            let failures = StdArc::clone(&contention_failures);
            let unexpected = StdArc::clone(&unexpected_errors);
            handles.push(thread::spawn(move || {
                for i in 0..APPENDS_PER {
                    let c = InvokeAuditContext {
                        zone_id: "z:contention-storm".into(),
                        actor: format!("agent:t-{t}"),
                        connector_id: "github".into(),
                        operation: "list_repos".into(),
                        operation_id: format!("op-{t}-{i}"),
                        correlation_id: None,
                        occurred_at: 1_700_000_000,
                    };
                    match chain_arc.append_with_retry_budget(
                        &c,
                        InvokePhase::PreflightAllow,
                        RETRY_BUDGET,
                    ) {
                        Ok(_) => {}
                        Err(AuditError::ContentionExhausted { zone_id, attempts }) => {
                            failures.fetch_add(1, Ordering::SeqCst);
                            // Operator-diagnostic fields populated.
                            assert_eq!(zone_id, "z:contention-storm");
                            assert!(
                                attempts > RETRY_BUDGET,
                                "ContentionExhausted must report attempts > budget"
                            );
                        }
                        Err(_) => {
                            unexpected.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                }
            }));
        }
        for h in handles {
            h.join().expect("worker thread panicked");
        }

        let total = contention_failures.load(Ordering::SeqCst);
        let metrics = chain.metrics_for_zone("z:contention-storm");
        assert_eq!(
            metrics.contention_exhaustions, total,
            "contention error telemetry must match observed typed failures"
        );
        assert_eq!(
            unexpected_errors.load(Ordering::SeqCst),
            0,
            "br-1a73y: expected only Ok or ContentionExhausted; any other variant means the bail \
             returned the wrong taxonomy and operator telemetry will mis-route"
        );
        assert!(
            total > 0,
            "br-1a73y: with RETRY_BUDGET={RETRY_BUDGET} and {THREADS} threads racing on one \
             zone, the test scenario must trip the bail at least once — got 0. If this \
             flakes, raise THREADS or APPENDS_PER, do NOT raise RETRY_BUDGET above 1 \
             (the test is asserting that the bail returns the right variant when it \
             fires, not that it must always fire)"
        );
    }
}
