//! Complex-event pattern matching for HLC-ordered audit chains.
//!
//! This module is the core, runtime-agnostic Phase M.4 primitive. It does not
//! append alerts or talk to a streaming engine; callers feed it audit entries and
//! receive deterministic match evidence that higher layers can sign, export, or
//! render.

use crate::{
    AuditEntry, AuditEntryBuilder, AuditError, HybridLogicalTimestamp, Severity, event_types,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable metadata schema for CEP anomaly alert audit entries.
pub const CEP_ANOMALY_ALERT_SCHEMA_VERSION: &str = "fcp.audit.cep_anomaly_alert.v1";

/// A validated audit-chain event pattern.
///
/// Deserialization is routed through [`EventPattern::new`] via `try_from` so a
/// pattern loaded from disk/wire is subject to the same invariants as one built
/// in code (non-empty name and sequence, non-zero window, no empty predicate).
/// Without this, serde would populate the private fields directly and an empty
/// `sequence` would panic [`EventPattern::find_matches`] at `sequence[0]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "EventPatternWire")]
pub struct EventPattern {
    name: String,
    sequence: Vec<EventPredicate>,
    max_window_ms: u64,
}

/// Deserialization shadow for [`EventPattern`]: carries the raw fields so
/// `TryFrom` can enforce the constructor invariants before an `EventPattern`
/// exists.
#[derive(Deserialize)]
struct EventPatternWire {
    name: String,
    sequence: Vec<EventPredicate>,
    max_window_ms: u64,
}

impl TryFrom<EventPatternWire> for EventPattern {
    type Error = EventPatternError;

    fn try_from(wire: EventPatternWire) -> Result<Self, Self::Error> {
        Self::new(wire.name, wire.sequence, wire.max_window_ms)
    }
}

impl EventPattern {
    /// Build a pattern from ordered predicates and a maximum physical-time window.
    ///
    /// # Errors
    /// Returns [`EventPatternError`] when the pattern would be vacuous or
    /// impossible to evaluate safely.
    pub fn new(
        name: impl Into<String>,
        sequence: Vec<EventPredicate>,
        max_window_ms: u64,
    ) -> Result<Self, EventPatternError> {
        let name = name.into();
        if name.trim().is_empty() {
            return Err(EventPatternError::EmptyName);
        }
        if sequence.is_empty() {
            return Err(EventPatternError::EmptySequence);
        }
        if max_window_ms == 0 {
            return Err(EventPatternError::ZeroWindow);
        }
        if sequence.iter().any(EventPredicate::is_empty) {
            return Err(EventPatternError::EmptyPredicate);
        }

        Ok(Self {
            name,
            sequence,
            max_window_ms,
        })
    }

    /// Pattern name carried into match evidence.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Ordered predicates that must match.
    #[must_use]
    pub fn sequence(&self) -> &[EventPredicate] {
        &self.sequence
    }

    /// Maximum span from first matched entry to last matched entry.
    #[must_use]
    pub const fn max_window_ms(&self) -> u64 {
        self.max_window_ms
    }

    /// Match this pattern over an audit stream.
    ///
    /// Entries are sorted by HLC, then sequence, then id before matching so
    /// callers can feed storage-order, network-order, or already-sorted streams
    /// and get identical evidence.
    #[must_use]
    pub fn find_matches<'a>(
        &self,
        entries: impl IntoIterator<Item = &'a AuditEntry>,
    ) -> Vec<PatternMatch> {
        let mut ordered: Vec<&AuditEntry> = entries.into_iter().collect();
        ordered.sort_by(|left, right| {
            left.hlc
                .cmp(&right.hlc)
                .then_with(|| left.seq.cmp(&right.seq))
                .then_with(|| left.id.cmp(&right.id))
        });

        // Defense in depth: `new()`/`try_from` reject an empty sequence, but
        // guard the hot-path index so `find_matches` is total even if a future
        // in-crate construction path ever bypasses the constructor.
        let Some(first_predicate) = self.sequence.first() else {
            return Vec::new();
        };

        let mut matches = Vec::new();
        for start_index in 0..ordered.len() {
            if !first_predicate.matches(ordered[start_index]) {
                continue;
            }
            if let Some(matched) = self.match_from(&ordered, start_index) {
                matches.push(matched);
            }
        }
        matches
    }

    fn match_from(&self, ordered: &[&AuditEntry], start_index: usize) -> Option<PatternMatch> {
        let first = ordered[start_index];
        let mut matched = vec![first];
        let mut search_start = start_index + 1;

        for predicate in &self.sequence[1..] {
            let next = ordered[search_start..]
                .iter()
                .copied()
                .enumerate()
                .find(|(_, entry)| {
                    physical_window_ms(first, entry) <= self.max_window_ms
                        && predicate.matches(entry)
                });

            let (relative_index, entry) = next?;
            matched.push(entry);
            search_start += relative_index + 1;
        }

        let last = *matched.last()?;
        Some(PatternMatch::from_entries(
            &self.name,
            &matched,
            physical_window_ms(first, last),
        ))
    }
}

/// Predicate for one event in an ordered pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventPredicate {
    /// Required audit event type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_type: Option<String>,
    /// Required audit zone id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone_id: Option<String>,
}

impl EventPredicate {
    /// Match an event type.
    #[must_use]
    pub fn event_type(event_type: impl Into<String>) -> Self {
        Self {
            event_type: Some(event_type.into()),
            zone_id: None,
        }
    }

    /// Match a zone id.
    #[must_use]
    pub fn zone(zone_id: impl Into<String>) -> Self {
        Self {
            event_type: None,
            zone_id: Some(zone_id.into()),
        }
    }

    /// Match an event type within one zone.
    #[must_use]
    pub fn event_type_in_zone(event_type: impl Into<String>, zone_id: impl Into<String>) -> Self {
        Self {
            event_type: Some(event_type.into()),
            zone_id: Some(zone_id.into()),
        }
    }

    #[must_use]
    fn is_empty(&self) -> bool {
        self.event_type
            .as_deref()
            .is_some_and(|event_type| event_type.trim().is_empty())
            || self
                .zone_id
                .as_deref()
                .is_some_and(|zone_id| zone_id.trim().is_empty())
            || (self.event_type.is_none() && self.zone_id.is_none())
    }

    #[must_use]
    fn matches(&self, entry: &AuditEntry) -> bool {
        self.event_type
            .as_deref()
            .is_none_or(|event_type| event_type == entry.event_type)
            && self
                .zone_id
                .as_deref()
                .is_none_or(|zone_id| zone_id == entry.zone_id)
    }
}

/// Deterministic evidence for a pattern match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatternMatch {
    /// Pattern that matched.
    pub pattern_name: String,
    /// Matched entry ids in HLC order.
    pub entry_ids: Vec<String>,
    /// Matched zones in HLC order.
    pub zones: Vec<String>,
    /// Matched event types in HLC order.
    pub event_types: Vec<String>,
    /// First matched HLC.
    pub first_hlc: HybridLogicalTimestamp,
    /// Last matched HLC.
    pub last_hlc: HybridLogicalTimestamp,
    /// Physical-time duration between first and last matched entry.
    pub duration_ms: u64,
}

impl PatternMatch {
    fn from_entries(pattern_name: &str, entries: &[&AuditEntry], duration_ms: u64) -> Self {
        let first = entries[0];
        let last = entries[entries.len() - 1];
        Self {
            pattern_name: pattern_name.to_string(),
            entry_ids: entries.iter().map(|entry| entry.id.clone()).collect(),
            zones: entries.iter().map(|entry| entry.zone_id.clone()).collect(),
            event_types: entries
                .iter()
                .map(|entry| entry.event_type.clone())
                .collect(),
            first_hlc: first.hlc.clone(),
            last_hlc: last.hlc.clone(),
            duration_ms,
        }
    }

    /// Materialize this match as a redaction-safe anomaly alert audit entry.
    ///
    /// The alert uses the last matched HLC as its causal timestamp, stores only
    /// stable identifiers and event classifications in metadata, and computes
    /// its audit-entry id from the canonical payload. Higher layers can append
    /// and quorum-sign the returned entry.
    ///
    /// # Errors
    ///
    /// Returns [`AnomalyAlertError`] when the caller supplies an empty alert
    /// context or when canonical audit-entry construction fails.
    pub fn to_anomaly_alert_entry(
        &self,
        actor: impl Into<String>,
        zone_id: impl Into<String>,
        seq: u64,
        prev: Option<&str>,
    ) -> Result<AuditEntry, AnomalyAlertError> {
        let actor = actor.into();
        if actor.trim().is_empty() {
            return Err(AnomalyAlertError::EmptyActor);
        }
        let zone_id = zone_id.into();
        if zone_id.trim().is_empty() {
            return Err(AnomalyAlertError::EmptyZone);
        }

        let mut builder = AuditEntryBuilder::new()
            .event_type(event_types::CEP_ANOMALY_ALERT)
            .severity(Severity::Error)
            .actor(actor)
            .zone_id(zone_id)
            .seq(seq)
            .occurred_at(self.last_hlc.physical_ms / 1_000)
            .hlc(self.last_hlc.clone())
            .meta(
                "schema_version",
                serde_json::json!(CEP_ANOMALY_ALERT_SCHEMA_VERSION),
            )
            .meta("pattern_name", serde_json::json!(self.pattern_name))
            .meta("matched_entry_ids", serde_json::json!(self.entry_ids))
            .meta("matched_zones", serde_json::json!(self.zones))
            .meta("matched_event_types", serde_json::json!(self.event_types))
            .meta("first_hlc", serde_json::json!(self.first_hlc))
            .meta("last_hlc", serde_json::json!(self.last_hlc))
            .meta("duration_ms", serde_json::json!(self.duration_ms))
            .meta("match_count", serde_json::json!(self.entry_ids.len()));

        if let Some(prev) = prev {
            builder = builder.prev(prev);
        }

        builder
            .build_with_computed_id()
            .map_err(AnomalyAlertError::Audit)
    }
}

/// Invalid anomaly-alert materialization context.
#[derive(Debug, Clone, Error)]
pub enum AnomalyAlertError {
    /// Alert actor is empty or whitespace-only.
    #[error("CEP anomaly alert actor must not be empty")]
    EmptyActor,
    /// Alert zone is empty or whitespace-only.
    #[error("CEP anomaly alert zone must not be empty")]
    EmptyZone,
    /// Audit entry construction failed.
    #[error(transparent)]
    Audit(#[from] AuditError),
}

/// Invalid CEP pattern definition.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EventPatternError {
    /// Pattern name is empty or whitespace-only.
    #[error("event pattern name must not be empty")]
    EmptyName,
    /// Pattern has no ordered predicates.
    #[error("event pattern sequence must not be empty")]
    EmptySequence,
    /// Pattern has a zero-length time window.
    #[error("event pattern max_window_ms must be greater than zero")]
    ZeroWindow,
    /// Pattern contains a predicate with no constraints.
    #[error("event pattern predicates must constrain event_type or zone_id")]
    EmptyPredicate,
}

const fn physical_window_ms(first: &AuditEntry, last: &AuditEntry) -> u64 {
    last.hlc.physical_ms.saturating_sub(first.hlc.physical_ms)
}
