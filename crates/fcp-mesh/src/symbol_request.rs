//! Symbol request handling with admission control and targeted repair.
//!
//! This module implements the NORMATIVE symbol request handling from
//! `FCP_Specification_V3.md` §9.1.3 (Symbol Request Bounding), including:
//!
//! - [`SymbolRequestHandler`] - Validates and processes bounded symbol requests
//! - [`SymbolResponseBuilder`] - Builds bounded responses with targeted repair
//! - [`TargetedRepairEngine`] - Uses missing hints for efficient repair
//!
//! # Overview
//!
//! Symbol request handling enforces:
//! - Bounded requests (max_symbols and/or missing-hint proof-of-need)
//! - Anti-amplification rules for unauthenticated peers
//! - Admission control integration (bytes + CPU + inflight decodes)
//! - Stop conditions via SymbolAck
//!
//! # Anti-Amplification Rule (NORMATIVE)
//!
//! `MeshNodes` MUST NOT send more than N symbols in response to a request unless:
//! 1. The requester is authenticated (session MAC or node signature), AND
//! 2. The request includes a bounded missing-hint or proof-of-need

#![forbid(unsafe_code)]

use crate::admission::{AdmissionController, AdmissionError};
use fcp_prelude::{ObjectId, ZoneId, ZoneKeyId};
use fcp_protocol::{
    DEFAULT_MAX_SYMBOLS_UNAUTHENTICATED, DecodeStatus, MAX_MISSING_HINT_ENTRIES, SymbolAck,
    SymbolRequest,
};
use fcp_tailscale::NodeId;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use thiserror::Error;
use tracing::{debug, info, warn};

// ============================================================================
// Constants
// ============================================================================

/// Default maximum response symbols for unauthenticated requests (NORMATIVE).
pub const DEFAULT_RESPONSE_LIMIT_UNAUTHENTICATED: u32 = 32;

/// Default maximum response symbols for authenticated requests (NORMATIVE).
pub const DEFAULT_RESPONSE_LIMIT_AUTHENTICATED: u32 = 1000;

/// Default minimum symbols to send even without proof-of-need (bootstrap).
pub const DEFAULT_MIN_BOOTSTRAP_SYMBOLS: u32 = 8;

// ============================================================================
// Error Types
// ============================================================================

/// Symbol request handling errors.
#[derive(Debug, Error)]
pub enum SymbolRequestError {
    /// Request validation failed.
    #[error("invalid request: {reason}")]
    InvalidRequest { reason: String },

    /// Request exceeded bounds.
    #[error("request exceeds bounds: requested {requested}, max {max_allowed}")]
    BoundsExceeded { requested: u32, max_allowed: u32 },

    /// Missing hint exceeds maximum entries.
    #[error("missing hint exceeds limit: {count} entries, max {max}")]
    HintTooLarge { count: usize, max: usize },

    /// Admission control rejected the request.
    #[error("admission control rejected: {0}")]
    AdmissionRejected(#[from] AdmissionError),

    /// Object not found.
    #[error("object not found: {object_id}")]
    ObjectNotFound { object_id: String },

    /// Peer is not authorized for the requested zone.
    #[error("peer {peer} is not authorized for zone {zone_id}")]
    UnauthorizedZone { peer: String, zone_id: String },

    /// Signature verification failed.
    #[error("signature verification failed")]
    SignatureInvalid,

    /// Request for completed transfer.
    #[error("transfer already complete for object {object_id}")]
    AlreadyComplete { object_id: String },
}

// ============================================================================
// Request Validation Result
// ============================================================================

/// Result of validating a symbol request.
#[derive(Debug, Clone)]
pub struct ValidatedRequest {
    /// The validated request.
    pub request: SymbolRequest,
    /// Whether the requester is authenticated.
    pub is_authenticated: bool,
    /// Maximum symbols allowed in response (computed from policy).
    pub max_response_symbols: u32,
    /// Whether the request has proof-of-need.
    pub has_proof_of_need: bool,
}

// ============================================================================
// Symbol Response
// ============================================================================

/// Response to a symbol request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolResponse {
    /// Object ID being responded to.
    pub object_id: ObjectId,
    /// Zone ID.
    pub zone_id: ZoneId,
    /// Zone key ID.
    pub zone_key_id: ZoneKeyId,
    /// ESIs of symbols being sent.
    pub symbol_esis: Vec<u32>,
    /// Whether this completes the transfer.
    pub is_final: bool,
    /// Response was limited by bounds.
    pub was_bounded: bool,
}

impl SymbolResponse {
    /// Number of symbols in this response.
    #[must_use]
    pub fn symbol_count(&self) -> u32 {
        u32::try_from(self.symbol_esis.len()).unwrap_or(u32::MAX)
    }
}

// ============================================================================
// Symbol Request Handler
// ============================================================================

/// Handler for symbol requests with admission control.
///
/// Validates incoming requests, enforces bounds, and coordinates with
/// admission control to prevent DoS attacks.
pub struct SymbolRequestHandler {
    /// Policy configuration.
    policy: SymbolRequestPolicy,
    /// Active transfers keyed by receiving peer + object.
    active_transfers: HashMap<TransferKey, TransferState>,
    /// Completed transfers awaiting SymbolAck keyed by receiving peer + object.
    completed_awaiting_ack: HashMap<TransferKey, u64>,
    /// Completed transfers (SymbolAck received) keyed by receiving peer + object.
    completed_transfers: HashMap<TransferKey, u64>,
}

/// Policy for symbol request handling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolRequestPolicy {
    /// Max response symbols for unauthenticated requests.
    pub max_unauthenticated_response: u32,
    /// Max response symbols for authenticated requests.
    pub max_authenticated_response: u32,
    /// Min symbols to send without proof-of-need (bootstrap mode).
    pub min_bootstrap_symbols: u32,
    /// Whether to require proof-of-need for large requests.
    pub require_proof_of_need_above: u32,
    /// Whether to allow unauthenticated requests at all.
    pub allow_unauthenticated: bool,
    /// Timeout for stale transfer state in milliseconds (default: 1 hour).
    pub transfer_state_ttl_ms: u64,
}

impl Default for SymbolRequestPolicy {
    fn default() -> Self {
        Self {
            max_unauthenticated_response: DEFAULT_RESPONSE_LIMIT_UNAUTHENTICATED,
            max_authenticated_response: DEFAULT_RESPONSE_LIMIT_AUTHENTICATED,
            min_bootstrap_symbols: DEFAULT_MIN_BOOTSTRAP_SYMBOLS,
            require_proof_of_need_above: 100, // Require hints for large requests
            allow_unauthenticated: true,      // Zone can override
            transfer_state_ttl_ms: 3_600_000, // 1 hour
        }
    }
}

/// State for an active transfer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct TransferKey {
    peer: NodeId,
    object_id: ObjectId,
}

impl TransferKey {
    #[must_use]
    pub(crate) fn new(peer: &NodeId, object_id: &ObjectId) -> Self {
        Self {
            peer: peer.clone(),
            object_id: object_id.clone(),
        }
    }
}

/// State for an active transfer.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields used for full MeshNode handler implementation
struct TransferState {
    /// Object ID.
    object_id: ObjectId,
    /// Total symbols needed for decode.
    total_needed: u32,
    /// ESIs already sent.
    sent_esis: HashSet<u32>,
    /// Last decode status received.
    last_status: Option<DecodeStatusSummary>,
    /// Whether we've been told to stop.
    stopped: bool,
    /// Last activity timestamp (ms).
    last_activity: u64,
}

/// Summary of a decode status for tracking.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields used for full MeshNode handler implementation
struct DecodeStatusSummary {
    /// Unique symbols received.
    received_unique: u32,
    /// Symbols still needed.
    needed: u32,
    /// Is decode complete.
    complete: bool,
}

impl SymbolRequestHandler {
    /// Create a new handler with the given policy.
    #[must_use]
    pub fn new(policy: SymbolRequestPolicy) -> Self {
        Self {
            policy,
            active_transfers: HashMap::new(),
            completed_awaiting_ack: HashMap::new(),
            completed_transfers: HashMap::new(),
        }
    }

    /// Create a handler with default policy.
    #[must_use]
    pub fn with_default_policy() -> Self {
        Self::new(SymbolRequestPolicy::default())
    }

    /// Validate an incoming symbol request.
    ///
    /// # Errors
    ///
    /// Returns `SymbolRequestError` if the request is invalid or exceeds bounds.
    #[allow(clippy::too_many_lines)] // Keep the fail-closed validation gates in request-processing order.
    pub fn validate_request(
        &self,
        request: &SymbolRequest,
        is_authenticated: bool,
        admission: &mut AdmissionController,
        peer: &NodeId,
        now_ms: u64,
        symbol_size: u16,
    ) -> Result<ValidatedRequest, SymbolRequestError> {
        // Check if unauthenticated requests are allowed
        if !is_authenticated && !self.policy.allow_unauthenticated {
            return Err(SymbolRequestError::AdmissionRejected(
                AdmissionError::AuthenticationRequired,
            ));
        }

        if request.zone_id != request.header.zone_id {
            return Err(SymbolRequestError::InvalidRequest {
                reason: "request zone_id does not match header zone_id".to_string(),
            });
        }

        // Validate hint bounds
        if let Some(ref hints) = request.missing_hint {
            if hints.len() > MAX_MISSING_HINT_ENTRIES {
                return Err(SymbolRequestError::HintTooLarge {
                    count: hints.len(),
                    max: MAX_MISSING_HINT_ENTRIES,
                });
            }
            if hints.len() > request.max_symbols as usize {
                return Err(SymbolRequestError::InvalidRequest {
                    reason: "missing hint exceeds max_symbols".to_string(),
                });
            }
        }

        // Compute maximum allowed response
        let base_limit = if is_authenticated {
            self.policy.max_authenticated_response
        } else {
            self.policy.max_unauthenticated_response
        };

        // Request's max_symbols bounds the response
        let max_response_symbols = request.max_symbols.min(base_limit);

        // For unauthenticated requests, enforce stricter limits
        if !is_authenticated && request.max_symbols > DEFAULT_MAX_SYMBOLS_UNAUTHENTICATED {
            warn!(
                peer = %peer,
                requested = request.max_symbols,
                limit = DEFAULT_MAX_SYMBOLS_UNAUTHENTICATED,
                "unauthenticated request exceeds limit"
            );
            return Err(SymbolRequestError::BoundsExceeded {
                requested: request.max_symbols,
                max_allowed: DEFAULT_MAX_SYMBOLS_UNAUTHENTICATED,
            });
        }

        // Check admission control
        let estimated_response_bytes = u64::from(max_response_symbols) * u64::from(symbol_size);
        admission.check_admission(
            peer,
            estimated_response_bytes,
            max_response_symbols,
            is_authenticated,
            now_ms,
        )?;

        // Route all request classes through the shared anti-amplification helper.
        // Without proof-of-need we synthesize the largest request window that
        // still permits responses up to `require_proof_of_need_above`, so helper
        // enforcement stays aligned with the symbol-request threshold semantics.
        let has_proof_of_need = request.has_proof_of_need();
        let amplification_request_symbols = if has_proof_of_need {
            request.missing_hint.as_ref().map_or(1, |hints| {
                u32::try_from(hints.len()).unwrap_or(u32::MAX).max(1)
            })
        } else {
            let max_factor = admission.policy().max_amplification_factor;
            if max_factor == 0 {
                0
            } else {
                self.policy.require_proof_of_need_above.div_ceil(max_factor)
            }
        };
        match admission.check_amplification(
            peer,
            amplification_request_symbols,
            max_response_symbols,
            is_authenticated,
            has_proof_of_need,
        ) {
            Err(AdmissionError::AmplificationViolation { .. })
                if !has_proof_of_need
                    && max_response_symbols > self.policy.require_proof_of_need_above =>
            {
                warn!(
                    peer = %peer,
                    requested = max_response_symbols,
                    authenticated = is_authenticated,
                    "large request without proof-of-need"
                );
                return Err(SymbolRequestError::AdmissionRejected(
                    AdmissionError::ProofOfNeedRequired,
                ));
            }
            Err(err) => return Err(SymbolRequestError::AdmissionRejected(err)),
            Ok(()) => {}
        }

        // Debit the budget only after all post-check_admission policy gates
        // have accepted the request so rejected requests remain side-effect free.
        admission.record_bytes(peer, estimated_response_bytes, now_ms);
        admission.record_symbols(peer, max_response_symbols, now_ms);

        debug!(
            peer = %peer,
            object_id = %hex::encode(request.object_id.as_bytes()),
            max_symbols = max_response_symbols,
            has_proof = has_proof_of_need,
            authenticated = is_authenticated,
            "validated symbol request"
        );

        Ok(ValidatedRequest {
            request: request.clone(),
            is_authenticated,
            max_response_symbols,
            has_proof_of_need,
        })
    }

    /// Process a decode status update from a peer.
    ///
    /// Updates transfer state based on receiver feedback.
    ///
    /// Callers MUST verify `status.signature` against the sending peer's node
    /// key BEFORE invoking this method. The handler only records state for
    /// objects that were actually in `active_transfers`, so a forged status
    /// for a random object_id cannot be used to fill `completed_awaiting_ack`
    /// unboundedly between `prune_stale_state` cycles.
    pub fn process_decode_status(&mut self, peer: &NodeId, status: &DecodeStatus, now_ms: u64) {
        let key = TransferKey::new(peer, &status.object_id);
        // Gate all state writes on "we actually have an active transfer for
        // this object". A complete=true status for an unknown object would
        // otherwise insert into completed_awaiting_ack — bounded only by the
        // prune_stale_state cadence.
        let Some(state) = self.active_transfers.get_mut(&key) else {
            if status.complete {
                warn!(
                    peer = %peer,
                    object_id = %hex::encode(status.object_id.as_bytes()),
                    received = status.received_unique,
                    "DecodeStatus for unknown peer/object transfer — dropped"
                );
            }
            return;
        };

        let summary = DecodeStatusSummary {
            received_unique: status.received_unique,
            needed: status.needed,
            complete: status.complete,
        };

        state.last_status = Some(summary);
        state.last_activity = now_ms;

        if status.complete {
            info!(
                peer = %peer,
                object_id = %hex::encode(status.object_id.as_bytes()),
                received = status.received_unique,
                "decode complete, awaiting SymbolAck"
            );
            state.stopped = true;
            self.completed_awaiting_ack.insert(key, now_ms);
        }
    }

    /// Track symbols sent for a request (starts or updates transfer state).
    pub fn track_transfer(
        &mut self,
        peer: &NodeId,
        request: &SymbolRequest,
        sent_esis: impl IntoIterator<Item = u32>,
        now_ms: u64,
    ) {
        let key = TransferKey::new(peer, &request.object_id);
        let state = self
            .active_transfers
            .entry(key)
            .or_insert_with(|| TransferState {
                object_id: request.object_id,
                total_needed: request.max_symbols,
                sent_esis: HashSet::new(),
                last_status: None,
                stopped: false,
                last_activity: now_ms,
            });

        state.last_activity = now_ms;
        state.total_needed = state.total_needed.max(request.max_symbols);
        state.sent_esis.extend(sent_esis);
    }

    /// Process a symbol acknowledgment (stop condition).
    ///
    /// Stops sending symbols for the acknowledged object.
    ///
    /// Callers MUST verify `ack.signature` against the sending peer's node key
    /// BEFORE invoking this method. The handler itself trusts the ack's
    /// `object_id` field at face value; an unauthenticated peer that reaches
    /// this path could abort arbitrary transfers. Additionally, this method
    /// only records state changes for objects that were actually known
    /// (active transfer or already completed-awaiting-ack), so a fake ack for
    /// a random object_id cannot be used to fill `completed_transfers`
    /// unboundedly between `prune_stale_state` cycles.
    pub fn process_symbol_ack(&mut self, peer: &NodeId, ack: &SymbolAck, now_ms: u64) {
        let key = TransferKey::new(peer, &ack.object_id);
        let was_awaiting_ack = self.completed_awaiting_ack.remove(&key).is_some();
        let had_active = self.active_transfers.contains_key(&key);

        if !was_awaiting_ack && !had_active {
            // An ack for an object we never transferred: either a buggy peer,
            // a stale delivery, or a forged ack from a non-authenticated
            // caller. Log and drop instead of polluting completed_transfers
            // (which is bounded only by prune_stale_state cadence).
            warn!(
                peer = %peer,
                object_id = %hex::encode(ack.object_id.as_bytes()),
                reason = ?ack.reason,
                "SymbolAck for unknown peer/object transfer — dropped"
            );
            return;
        }

        info!(
            peer = %peer,
            object_id = %hex::encode(ack.object_id.as_bytes()),
            reason = ?ack.reason,
            final_count = ack.final_symbol_count,
            "received SymbolAck, stopping transfer"
        );

        self.completed_transfers.insert(key.clone(), now_ms);

        if let Some(state) = self.active_transfers.get_mut(&key) {
            state.stopped = true;
            state.last_activity = now_ms;
        }

        // Can clean up transfer state
        self.active_transfers.remove(&key);
    }

    /// Check if a transfer should stop.
    #[must_use]
    pub fn should_stop(&self, peer: &NodeId, object_id: &ObjectId) -> bool {
        let key = TransferKey::new(peer, object_id);
        if self.completed_transfers.contains_key(&key) {
            return true;
        }
        self.active_transfers.get(&key).is_some_and(|s| s.stopped)
    }

    /// Prune stale transfer state.
    ///
    /// Removes active and completed transfers that have exceeded the TTL.
    /// Returns the count of removed entries (active + completed).
    pub fn prune_stale_state(&mut self, now_ms: u64) -> usize {
        let ttl = self.policy.transfer_state_ttl_ms;
        let expired_threshold = now_ms.saturating_sub(ttl);
        let mut removed = 0;

        self.active_transfers.retain(|_, state| {
            let keep = state.last_activity >= expired_threshold;
            if !keep {
                removed += 1;
            }
            keep
        });

        self.completed_awaiting_ack.retain(|_, timestamp| {
            let keep = *timestamp >= expired_threshold;
            if !keep {
                removed += 1;
            }
            keep
        });

        self.completed_transfers.retain(|_, timestamp| {
            let keep = *timestamp >= expired_threshold;
            if !keep {
                removed += 1;
            }
            keep
        });

        if removed > 0 {
            debug!(removed, "pruned stale transfer state");
        }
        removed
    }

    /// Get the policy.
    #[must_use]
    pub const fn policy(&self) -> &SymbolRequestPolicy {
        &self.policy
    }

    /// Get active transfer count.
    #[must_use]
    pub fn active_transfer_count(&self) -> usize {
        self.active_transfers.len()
    }
}

// ============================================================================
// Targeted Repair Engine
// ============================================================================

/// Engine for targeted repair using missing hints.
///
/// When a peer provides specific ESIs they need, this engine ensures
/// we send exactly those symbols rather than flooding redundant data.
pub struct TargetedRepairEngine {
    /// Available symbols per object (ESI -> available).
    available_symbols: HashMap<ObjectId, HashSet<u32>>,
}

impl TargetedRepairEngine {
    /// Create a new repair engine.
    #[must_use]
    pub fn new() -> Self {
        Self {
            available_symbols: HashMap::new(),
        }
    }

    /// Register available symbols for an object.
    pub fn register_available(&mut self, object_id: ObjectId, esis: impl IntoIterator<Item = u32>) {
        let set = self
            .available_symbols
            .entry(object_id)
            .or_insert_with(HashSet::new);
        set.extend(esis);
    }

    /// Select symbols to send based on request and availability.
    ///
    /// If the request has a missing_hint, prioritizes those ESIs.
    /// Otherwise, selects available symbols up to the limit.
    #[must_use]
    pub fn select_symbols(
        &self,
        request: &ValidatedRequest,
        already_sent: &HashSet<u32>,
    ) -> Vec<u32> {
        let available = match self.available_symbols.get(&request.request.object_id) {
            Some(set) => set,
            None => return vec![],
        };

        let limit = request
            .max_response_symbols
            .try_into()
            .unwrap_or(usize::MAX);

        // If we have a missing hint, prioritize those
        if let Some(ref hints) = request.request.missing_hint {
            let mut seen = HashSet::new();
            let mut selected = Vec::new();
            for esi in hints.iter().copied() {
                if selected.len() >= limit {
                    break;
                }
                if !seen.insert(esi) {
                    continue;
                }
                if available.contains(&esi) && !already_sent.contains(&esi) {
                    selected.push(esi);
                }
            }

            // If we have room and the hint didn't fill it, add more
            if selected.len() < limit {
                let remaining = limit - selected.len();
                let hint_set: HashSet<_> = hints.iter().copied().collect();
                let mut additional: Vec<_> = available
                    .iter()
                    .filter(|esi| !hint_set.contains(esi) && !already_sent.contains(esi))
                    .copied()
                    .collect();
                additional.sort_unstable();
                additional.truncate(remaining);
                selected.extend(additional);
            }

            debug!(
                object_id = %hex::encode(request.request.object_id.as_bytes()),
                requested_hints = hints.len(),
                selected = selected.len(),
                "targeted repair: selected symbols from hints"
            );

            selected
        } else {
            // No hints, select any available symbols
            let mut candidates: Vec<u32> = available
                .iter()
                .filter(|esi| !already_sent.contains(esi))
                .copied()
                .collect();
            candidates.sort_unstable();
            candidates.truncate(limit);
            candidates
        }
    }

    /// Remove an object from tracking.
    pub fn remove_object(&mut self, object_id: &ObjectId) {
        self.available_symbols.remove(object_id);
    }
}

impl Default for TargetedRepairEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Symbol Response Builder
// ============================================================================

/// Builder for bounded symbol responses.
pub struct SymbolResponseBuilder {
    /// Object ID.
    object_id: ObjectId,
    /// Zone ID.
    zone_id: ZoneId,
    /// Zone key ID.
    zone_key_id: ZoneKeyId,
    /// Maximum symbols to include.
    max_symbols: u32,
    /// Selected ESIs.
    selected_esis: Vec<u32>,
    /// Whether response was limited by bounds.
    was_bounded: bool,
}

impl SymbolResponseBuilder {
    /// Create a new response builder.
    #[must_use]
    pub fn new(
        object_id: ObjectId,
        zone_id: ZoneId,
        zone_key_id: ZoneKeyId,
        max_symbols: u32,
    ) -> Self {
        Self {
            object_id,
            zone_id,
            zone_key_id,
            max_symbols,
            selected_esis: Vec::new(),
            was_bounded: false,
        }
    }

    /// Add symbols from the targeted repair engine.
    pub fn add_from_repair_engine(
        mut self,
        engine: &TargetedRepairEngine,
        request: &ValidatedRequest,
        already_sent: &HashSet<u32>,
    ) -> Self {
        let selected = engine.select_symbols(request, already_sent);
        let available_count = selected.len();

        // Apply bounds
        let limited: Vec<_> = selected
            .into_iter()
            .take(self.max_symbols as usize)
            .collect();

        // Response was bounded if the builder truncated the selection
        self.was_bounded = limited.len() < available_count;
        self.selected_esis = limited;
        self
    }

    /// Build the response.
    #[must_use]
    pub fn build(self, total_available: u32, already_sent: usize) -> SymbolResponse {
        let sent_count = u32::try_from(self.selected_esis.len()).unwrap_or(u32::MAX);
        let already_sent = u32::try_from(already_sent).unwrap_or(u32::MAX);
        let total_sent = sent_count.saturating_add(already_sent);
        let is_final = total_sent >= total_available;

        // Response was bounded if we sent fewer new symbols than remain unsent
        let remaining = total_available.saturating_sub(already_sent);
        let was_bounded = self.was_bounded || sent_count < remaining;

        SymbolResponse {
            object_id: self.object_id,
            zone_id: self.zone_id,
            zone_key_id: self.zone_key_id,
            symbol_esis: self.selected_esis,
            is_final,
            was_bounded,
        }
    }
}

// ============================================================================
// Metrics
// ============================================================================

/// Metrics for symbol request handling.
#[derive(Debug, Default, Clone)]
pub struct SymbolRequestMetrics {
    /// Total requests received.
    pub requests_received: u64,
    /// Requests validated successfully.
    pub requests_validated: u64,
    /// Requests rejected by bounds.
    pub requests_rejected_bounds: u64,
    /// Requests rejected by admission control.
    pub requests_rejected_admission: u64,
    /// Total symbols sent in responses.
    pub symbols_sent: u64,
    /// Responses that used targeted repair.
    pub targeted_repairs: u64,
    /// SymbolAcks received.
    pub acks_received: u64,
}

impl SymbolRequestMetrics {
    /// Record a validated request.
    pub fn record_validated(&mut self) {
        self.requests_received += 1;
        self.requests_validated += 1;
    }

    /// Record a bounds rejection.
    pub fn record_bounds_rejection(&mut self) {
        self.requests_received += 1;
        self.requests_rejected_bounds += 1;
    }

    /// Record an admission rejection.
    pub fn record_admission_rejection(&mut self) {
        self.requests_received += 1;
        self.requests_rejected_admission += 1;
    }

    /// Record symbols sent.
    pub fn record_symbols_sent(&mut self, count: u32, was_targeted: bool) {
        self.symbols_sent += u64::from(count);
        if was_targeted {
            self.targeted_repairs += 1;
        }
    }

    /// Record a SymbolAck.
    pub fn record_ack(&mut self) {
        self.acks_received += 1;
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_cbor::SchemaId;
    use fcp_prelude::{ObjectHeader, Provenance};
    use fcp_protocol::SymbolAckReason;
    use proptest::prelude::*;
    use semver::Version;

    fn test_zone_id() -> ZoneId {
        "z:test-zone".parse().expect("zone parse")
    }

    fn test_zone_id_alt() -> ZoneId {
        "z:alt-zone".parse().expect("zone parse")
    }

    fn test_object_header() -> ObjectHeader {
        let zone_id = test_zone_id();
        ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.test", "TestObject", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 1_704_067_200,
            provenance: Provenance::new(zone_id),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        }
    }

    fn test_symbol_request(max_symbols: u32, hint: Option<Vec<u32>>) -> SymbolRequest {
        let zone_id = test_zone_id();
        let mut req = SymbolRequest::new(
            test_object_header(),
            ObjectId::from_bytes([0x11; 32]),
            zone_id,
            ZoneKeyId::from_bytes([0x22; 8]),
            1000,
            max_symbols,
            0,
        );
        if let Some(h) = hint {
            req = req.with_missing_hint(h);
        }
        req
    }

    fn test_peer(name: &str) -> NodeId {
        NodeId::new(name)
    }

    #[test]
    fn validate_authenticated_request() {
        let handler = SymbolRequestHandler::with_default_policy();
        let mut admission = AdmissionController::with_default_policy();
        let peer = NodeId::new("peer-auth");

        let request = test_symbol_request(100, None);
        let result = handler.validate_request(&request, true, &mut admission, &peer, 0, 64);

        assert!(result.is_ok());
        let validated = result.unwrap();
        assert!(validated.is_authenticated);
        assert_eq!(validated.max_response_symbols, 100);
        assert!(!validated.has_proof_of_need);
    }

    #[test]
    fn reject_zone_id_mismatch() {
        let handler = SymbolRequestHandler::with_default_policy();
        let mut admission = AdmissionController::with_default_policy();
        let peer = NodeId::new("peer-zone-mismatch");

        let header = test_object_header();
        let request = SymbolRequest::new(
            header,
            ObjectId::from_bytes([0x11; 32]),
            test_zone_id_alt(),
            ZoneKeyId::from_bytes([0x22; 8]),
            1000,
            10,
            0,
        );

        let result = handler.validate_request(&request, true, &mut admission, &peer, 0, 64);
        assert!(matches!(
            result,
            Err(SymbolRequestError::InvalidRequest { .. })
        ));
    }

    #[test]
    fn validate_unauthenticated_request_bounded() {
        let handler = SymbolRequestHandler::with_default_policy();
        let mut admission = AdmissionController::with_default_policy();
        admission.set_authenticated(&NodeId::new("peer-unauth"), false, 0);

        // Use a lenient policy for unauthenticated requests
        let mut policy = crate::admission::AdmissionPolicy::default();
        policy.require_authenticated_requests = false;
        let mut admission = AdmissionController::new(policy);

        let peer = NodeId::new("peer-unauth");

        // Request within unauthenticated limit should succeed
        let request = test_symbol_request(DEFAULT_MAX_SYMBOLS_UNAUTHENTICATED, None);
        let result = handler.validate_request(&request, false, &mut admission, &peer, 0, 64);
        assert!(result.is_ok());
    }

    #[test]
    fn reject_unauthenticated_over_limit() {
        let handler = SymbolRequestHandler::with_default_policy();
        let mut policy = crate::admission::AdmissionPolicy::default();
        policy.require_authenticated_requests = false;
        let mut admission = AdmissionController::new(policy);

        let peer = NodeId::new("peer-over");

        // Request exceeding unauthenticated limit should fail
        let request = test_symbol_request(DEFAULT_MAX_SYMBOLS_UNAUTHENTICATED + 1, None);
        let result = handler.validate_request(&request, false, &mut admission, &peer, 0, 64);
        assert!(matches!(
            result,
            Err(SymbolRequestError::BoundsExceeded { .. })
        ));
    }

    #[test]
    fn validate_request_with_proof_of_need() {
        let handler = SymbolRequestHandler::with_default_policy();
        let mut admission = AdmissionController::with_default_policy();
        let peer = NodeId::new("peer-pon");

        let request = test_symbol_request(50, Some(vec![1, 2, 3, 4, 5]));
        let result = handler.validate_request(&request, true, &mut admission, &peer, 0, 64);

        assert!(result.is_ok());
        let validated = result.unwrap();
        assert!(validated.has_proof_of_need);
    }

    #[test]
    fn reject_authenticated_large_request_without_proof_of_need() {
        let handler = SymbolRequestHandler::with_default_policy();
        let mut admission = AdmissionController::with_default_policy();
        let peer = NodeId::new("peer-auth-no-proof");

        let request = test_symbol_request(handler.policy().require_proof_of_need_above + 1, None);
        let result = handler.validate_request(&request, true, &mut admission, &peer, 0, 64);

        assert!(matches!(
            result,
            Err(SymbolRequestError::AdmissionRejected(
                AdmissionError::ProofOfNeedRequired
            ))
        ));
    }

    #[test]
    fn reject_authenticated_request_above_custom_proof_threshold_without_hint() {
        let policy = SymbolRequestPolicy {
            max_authenticated_response: 500,
            require_proof_of_need_above: 200,
            ..SymbolRequestPolicy::default()
        };
        let handler = SymbolRequestHandler::new(policy);
        let mut admission = AdmissionController::with_default_policy();
        let peer = NodeId::new("peer-auth-custom-threshold");

        let request = test_symbol_request(201, None);
        let result = handler.validate_request(&request, true, &mut admission, &peer, 0, 64);

        assert!(matches!(
            result,
            Err(SymbolRequestError::AdmissionRejected(
                AdmissionError::ProofOfNeedRequired
            ))
        ));
    }

    #[test]
    fn reject_hint_too_large() {
        let handler = SymbolRequestHandler::with_default_policy();
        let mut admission = AdmissionController::with_default_policy();
        let peer = NodeId::new("peer-large-hint");

        let request = test_symbol_request(50, Some(vec![0; MAX_MISSING_HINT_ENTRIES + 1]));
        let result = handler.validate_request(&request, true, &mut admission, &peer, 0, 64);

        assert!(matches!(
            result,
            Err(SymbolRequestError::HintTooLarge { .. })
        ));
    }

    #[test]
    fn reject_hint_exceeding_max_symbols() {
        let handler = SymbolRequestHandler::with_default_policy();
        let mut admission = AdmissionController::with_default_policy();
        let peer = NodeId::new("peer-hint-max");

        let request = test_symbol_request(2, Some(vec![1, 2, 3]));
        let result = handler.validate_request(&request, true, &mut admission, &peer, 0, 64);

        assert!(matches!(
            result,
            Err(SymbolRequestError::InvalidRequest { .. })
        ));
    }

    #[test]
    fn targeted_repair_selects_from_hints() {
        let mut engine = TargetedRepairEngine::new();
        let object_id = ObjectId::from_bytes([0x11; 32]);

        // Register available symbols
        engine.register_available(object_id.clone(), 0..100);

        let request = ValidatedRequest {
            request: test_symbol_request(10, Some(vec![5, 10, 15, 20, 25])),
            is_authenticated: true,
            max_response_symbols: 10,
            has_proof_of_need: true,
        };

        let selected = engine.select_symbols(&request, &HashSet::new());

        // Should select the hinted ESIs first
        assert!(selected.contains(&5));
        assert!(selected.contains(&10));
        assert!(selected.contains(&15));
        assert!(selected.contains(&20));
        assert!(selected.contains(&25));
    }

    #[test]
    fn targeted_repair_respects_already_sent() {
        let mut engine = TargetedRepairEngine::new();
        let object_id = ObjectId::from_bytes([0x11; 32]);

        engine.register_available(object_id.clone(), 0..50);

        let request = ValidatedRequest {
            request: test_symbol_request(10, Some(vec![5, 10, 15])),
            is_authenticated: true,
            max_response_symbols: 10,
            has_proof_of_need: true,
        };

        // Mark some as already sent
        let already_sent: HashSet<_> = vec![5, 10].into_iter().collect();
        let selected = engine.select_symbols(&request, &already_sent);

        // Should not re-select already sent
        assert!(!selected.contains(&5));
        assert!(!selected.contains(&10));
        assert!(selected.contains(&15));
    }

    #[test]
    fn targeted_repair_dedups_hints_and_orders_additional() {
        let mut engine = TargetedRepairEngine::new();
        let object_id = ObjectId::from_bytes([0x11; 32]);

        engine.register_available(object_id.clone(), 0..20);

        let request = ValidatedRequest {
            request: test_symbol_request(4, Some(vec![10, 5, 10, 3])),
            is_authenticated: true,
            max_response_symbols: 4,
            has_proof_of_need: true,
        };

        let selected = engine.select_symbols(&request, &HashSet::new());

        assert_eq!(selected, vec![10, 5, 3, 0]);
    }

    #[test]
    fn targeted_repair_is_deterministic_without_hints() {
        let mut engine = TargetedRepairEngine::new();
        let object_id = ObjectId::from_bytes([0x11; 32]);

        engine.register_available(object_id.clone(), 0..10);

        let request = ValidatedRequest {
            request: test_symbol_request(5, None),
            is_authenticated: true,
            max_response_symbols: 5,
            has_proof_of_need: false,
        };

        let selected = engine.select_symbols(&request, &HashSet::new());

        assert_eq!(selected, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn process_symbol_ack_stops_transfer() {
        let mut handler = SymbolRequestHandler::with_default_policy();
        let object_id = ObjectId::from_bytes([0x11; 32]);
        let peer = test_peer("peer-ack-stop");

        // Initially not stopped
        assert!(!handler.should_stop(&peer, &object_id));

        // Process ack
        let ack = SymbolAck::new(
            test_object_header(),
            object_id.clone(),
            test_zone_id(),
            ZoneKeyId::from_bytes([0x22; 8]),
            1000,
            fcp_core::TailscaleNodeId::new("node-1"),
            1000,
            SymbolAckReason::Complete,
            500,
        );

        handler.process_symbol_ack(&peer, &ack, 0);

        // Transfer state should be removed
        assert_eq!(handler.active_transfer_count(), 0);
    }

    #[test]
    fn response_builder_respects_bounds() {
        let mut engine = TargetedRepairEngine::new();
        let object_id = ObjectId::from_bytes([0x11; 32]);
        let zone_id = test_zone_id();

        engine.register_available(object_id.clone(), 0..1000);

        let request = ValidatedRequest {
            request: test_symbol_request(50, None),
            is_authenticated: true,
            max_response_symbols: 50,
            has_proof_of_need: false,
        };

        let response = SymbolResponseBuilder::new(
            object_id,
            zone_id,
            ZoneKeyId::from_bytes([0x22; 8]),
            25, // Builder limit smaller than request limit (50) to force bounding
        )
        .add_from_repair_engine(&engine, &request, &HashSet::new())
        .build(1000, 0);

        // Should be bounded to 25
        assert_eq!(response.symbol_count(), 25);
        assert!(response.was_bounded);
        assert!(!response.is_final); // More available
    }

    #[test]
    fn response_builder_marks_bounded_when_request_limit_hits() {
        let mut engine = TargetedRepairEngine::new();
        let object_id = ObjectId::from_bytes([0x11; 32]);
        let zone_id = test_zone_id();

        engine.register_available(object_id.clone(), 0..100);

        let request = ValidatedRequest {
            request: test_symbol_request(10, None),
            is_authenticated: true,
            max_response_symbols: 10,
            has_proof_of_need: false,
        };

        let response = SymbolResponseBuilder::new(
            object_id,
            zone_id,
            ZoneKeyId::from_bytes([0x22; 8]),
            request.max_response_symbols,
        )
        .add_from_repair_engine(&engine, &request, &HashSet::new())
        .build(100, 0);

        assert_eq!(response.symbol_count(), 10);
        assert!(response.was_bounded);
        assert!(!response.is_final);
    }

    #[test]
    fn response_builder_marks_final_when_all_symbols_sent() {
        let mut engine = TargetedRepairEngine::new();
        let object_id = ObjectId::from_bytes([0x11; 32]);
        let zone_id = test_zone_id();

        engine.register_available(object_id.clone(), 0..2);

        let request = ValidatedRequest {
            request: test_symbol_request(1, None),
            is_authenticated: true,
            max_response_symbols: 1,
            has_proof_of_need: false,
        };

        let already_sent: HashSet<_> = vec![0].into_iter().collect();
        let response = SymbolResponseBuilder::new(
            object_id,
            zone_id,
            ZoneKeyId::from_bytes([0x22; 8]),
            request.max_response_symbols,
        )
        .add_from_repair_engine(&engine, &request, &already_sent)
        .build(2, already_sent.len());

        assert_eq!(response.symbol_count(), 1);
        assert!(response.is_final);
    }

    #[test]
    fn decode_status_complete_stops_transfer() {
        let mut handler = SymbolRequestHandler::with_default_policy();
        let object_id = ObjectId::from_bytes([0x11; 32]);
        let peer = test_peer("peer-status-complete");

        // Start a transfer
        let request = test_symbol_request(50, None);
        handler.track_transfer(&peer, &request, 0..10, 0);
        assert_eq!(handler.active_transfer_count(), 1);

        // Process decode status marking transfer complete
        let status = DecodeStatus {
            header: test_object_header(),
            object_id: object_id.clone(),
            zone_id: test_zone_id(),
            zone_key_id: ZoneKeyId::from_bytes([0x22; 8]),
            epoch_id: 1000,
            recipient_node_id: fcp_core::TailscaleNodeId::new("node-1"),
            request_nonce: 1000,
            received_unique: 50,
            needed: 0,
            complete: true,
            missing_hint: None,
            signature: fcp_crypto::Ed25519Signature::from_bytes(&[0u8; 64]),
        };
        handler.process_decode_status(&peer, &status, 0);

        // Transfer should be stopped
        assert!(handler.should_stop(&peer, &object_id));
    }

    #[test]
    fn track_transfer_accumulates_sent_esis() {
        let mut handler = SymbolRequestHandler::with_default_policy();
        let request = test_symbol_request(100, None);
        let peer = test_peer("peer-track");

        handler.track_transfer(&peer, &request, 0..5, 0);
        assert_eq!(handler.active_transfer_count(), 1);

        // Track more symbols for the same object
        handler.track_transfer(&peer, &request, 5..10, 0);
        assert_eq!(handler.active_transfer_count(), 1); // Same transfer
    }

    #[test]
    fn should_stop_after_ack() {
        let mut handler = SymbolRequestHandler::with_default_policy();
        let object_id = ObjectId::from_bytes([0x11; 32]);
        let peer = test_peer("peer-stop-after-ack");

        // Initially not stopped
        assert!(!handler.should_stop(&peer, &object_id));

        // Start tracking then ack
        let request = test_symbol_request(50, None);
        handler.track_transfer(&peer, &request, 0..5, 0);

        let ack = SymbolAck::new(
            test_object_header(),
            object_id.clone(),
            test_zone_id(),
            ZoneKeyId::from_bytes([0x22; 8]),
            1000,
            fcp_core::TailscaleNodeId::new("node-1"),
            1001,
            SymbolAckReason::Complete,
            5,
        );
        handler.process_symbol_ack(&peer, &ack, 0);

        // Should stop and be fully cleaned up
        assert!(handler.should_stop(&peer, &object_id));
        assert_eq!(handler.active_transfer_count(), 0);
    }

    #[test]
    fn policy_disallow_unauthenticated_rejects() {
        let policy = SymbolRequestPolicy {
            allow_unauthenticated: false,
            ..SymbolRequestPolicy::default()
        };
        let handler = SymbolRequestHandler::new(policy);
        let mut admission = AdmissionController::with_default_policy();
        let peer = NodeId::new("peer-no-auth");

        let request = test_symbol_request(10, None);
        let result = handler.validate_request(&request, false, &mut admission, &peer, 0, 64);
        assert!(matches!(
            result,
            Err(SymbolRequestError::AdmissionRejected(_))
        ));
    }

    #[test]
    fn targeted_repair_remove_object() {
        let mut engine = TargetedRepairEngine::new();
        let object_id = ObjectId::from_bytes([0x11; 32]);

        engine.register_available(object_id.clone(), 0..10);

        let request = ValidatedRequest {
            request: test_symbol_request(10, None),
            is_authenticated: true,
            max_response_symbols: 10,
            has_proof_of_need: false,
        };

        // Should have symbols
        let selected = engine.select_symbols(&request, &HashSet::new());
        assert!(!selected.is_empty());

        // Remove and verify gone
        engine.remove_object(&object_id);
        let selected = engine.select_symbols(&request, &HashSet::new());
        assert!(selected.is_empty());
    }

    #[test]
    fn response_builder_empty_availability() {
        let engine = TargetedRepairEngine::new(); // No symbols registered
        let object_id = ObjectId::from_bytes([0x11; 32]);

        let request = ValidatedRequest {
            request: test_symbol_request(50, None),
            is_authenticated: true,
            max_response_symbols: 50,
            has_proof_of_need: false,
        };

        let response = SymbolResponseBuilder::new(
            object_id,
            test_zone_id(),
            ZoneKeyId::from_bytes([0x22; 8]),
            50,
        )
        .add_from_repair_engine(&engine, &request, &HashSet::new())
        .build(0, 0);

        assert_eq!(response.symbol_count(), 0);
        assert!(response.is_final);
    }

    #[test]
    fn authenticated_request_bounded_by_request_max() {
        let handler = SymbolRequestHandler::with_default_policy();
        let mut admission = AdmissionController::with_default_policy();
        let peer = NodeId::new("peer-bounded");

        // Request max_symbols (50) < policy max (1000)
        let request = test_symbol_request(50, None);
        let result = handler.validate_request(&request, true, &mut admission, &peer, 0, 64);

        let validated = result.unwrap();
        // Should be bounded to the request's max, not the policy's max
        assert_eq!(validated.max_response_symbols, 50);
    }

    proptest! {
        #[test]
        fn unauthenticated_requests_enforce_normative_cap(
            requested in 1u32..(DEFAULT_MAX_SYMBOLS_UNAUTHENTICATED + 129)
        ) {
            let handler = SymbolRequestHandler::with_default_policy();
            let mut policy = crate::admission::AdmissionPolicy::default();
            policy.require_authenticated_requests = false;
            let mut admission = AdmissionController::new(policy);
            let peer = NodeId::new("peer-prop-unauth");
            let request = test_symbol_request(requested, None);

            let result = handler.validate_request(&request, false, &mut admission, &peer, 0, 64);

            if requested > DEFAULT_MAX_SYMBOLS_UNAUTHENTICATED {
                match result {
                    Err(SymbolRequestError::BoundsExceeded { .. }) => {}
                    other => prop_assert!(
                        false,
                        "expected bounds rejection for unauthenticated request, got: {:?}",
                        other
                    ),
                }
            } else {
                prop_assert!(result.is_ok());
                let validated = result.expect("validated request");
                prop_assert_eq!(validated.max_response_symbols, requested);
            }
        }

        #[test]
        fn response_builder_never_exceeds_effective_limit(
            available_len in 0u32..256,
            request_max in 1u32..128,
            builder_max in 1u32..128,
            already_sent_len in 0usize..64
        ) {
            let mut engine = TargetedRepairEngine::new();
            let object_id = ObjectId::from_bytes([0x33; 32]);
            let zone_id = test_zone_id();
            engine.register_available(object_id.clone(), 0..available_len);

            let request = ValidatedRequest {
                request: test_symbol_request(request_max, None),
                is_authenticated: true,
                max_response_symbols: request_max,
                has_proof_of_need: false,
            };

            let already_sent_max = u32::try_from(already_sent_len).expect("already_sent_len fits u32");
            let already_sent: HashSet<u32> = (0..already_sent_max).collect();

            let response = SymbolResponseBuilder::new(
                object_id,
                zone_id,
                ZoneKeyId::from_bytes([0x44; 8]),
                builder_max,
            )
            .add_from_repair_engine(&engine, &request, &already_sent)
            .build(available_len, already_sent.len());

            let effective_limit = builder_max.min(request_max);
            prop_assert!(response.symbol_count() <= effective_limit);
        }

        #[test]
        fn targeted_repair_never_resends_already_sent_symbols(
            hinted in proptest::collection::vec(0u32..512, 0..128),
            already_sent in proptest::collection::vec(0u32..512, 0..128),
            request_max in 1u32..128
        ) {
            let mut engine = TargetedRepairEngine::new();
            let object_id = ObjectId::from_bytes([0x55; 32]);
            engine.register_available(object_id.clone(), 0..512);

            let bounded_hint: Vec<u32> = hinted
                .into_iter()
                .take(request_max as usize)
                .collect();
            let request = ValidatedRequest {
                request: test_symbol_request(request_max, Some(bounded_hint)),
                is_authenticated: true,
                max_response_symbols: request_max,
                has_proof_of_need: true,
            };
            let already_sent_set: HashSet<u32> = already_sent.into_iter().collect();

            let selected = engine.select_symbols(&request, &already_sent_set);

            prop_assert!(selected
                .iter()
                .all(|esi| !already_sent_set.contains(esi)));
            prop_assert!(selected.len() <= request_max as usize);
        }
    }

    #[test]
    fn metrics_tracking() {
        let mut metrics = SymbolRequestMetrics::default();

        metrics.record_validated();
        metrics.record_validated();
        metrics.record_bounds_rejection();
        metrics.record_symbols_sent(100, true);
        metrics.record_ack();

        assert_eq!(metrics.requests_received, 3);
        assert_eq!(metrics.requests_validated, 2);
        assert_eq!(metrics.requests_rejected_bounds, 1);
        assert_eq!(metrics.symbols_sent, 100);
        assert_eq!(metrics.targeted_repairs, 1);
        assert_eq!(metrics.acks_received, 1);
    }

    // ── Additional coverage (bead 1ol0k) ──

    #[test]
    fn prune_stale_state_removes_expired() {
        let policy = SymbolRequestPolicy {
            transfer_state_ttl_ms: 1000, // 1s TTL
            ..SymbolRequestPolicy::default()
        };
        let mut handler = SymbolRequestHandler::new(policy);
        let request = test_symbol_request(50, None);
        let peer = test_peer("peer-prune-expired");

        // Track a transfer at time 0
        handler.track_transfer(&peer, &request, 0..5, 0);
        assert_eq!(handler.active_transfer_count(), 1);

        // Prune at time 500 (within TTL) — nothing removed
        let removed = handler.prune_stale_state(500);
        assert_eq!(removed, 0);
        assert_eq!(handler.active_transfer_count(), 1);

        // Prune at time 2000 (past TTL) — should remove
        let removed = handler.prune_stale_state(2000);
        assert_eq!(removed, 1);
        assert_eq!(handler.active_transfer_count(), 0);
    }

    #[test]
    fn prune_stale_state_removes_completed_awaiting_ack() {
        let policy = SymbolRequestPolicy {
            transfer_state_ttl_ms: 1000,
            ..SymbolRequestPolicy::default()
        };
        let mut handler = SymbolRequestHandler::new(policy);
        let object_id = ObjectId::from_bytes([0x11; 32]);
        let peer = test_peer("peer-awaiting-ack");

        // Simulate a decode complete → moves to completed_awaiting_ack
        let request = test_symbol_request(50, None);
        handler.track_transfer(&peer, &request, 0..5, 0);

        let status = DecodeStatus {
            header: test_object_header(),
            object_id: object_id.clone(),
            zone_id: test_zone_id(),
            zone_key_id: ZoneKeyId::from_bytes([0x22; 8]),
            epoch_id: 1000,
            recipient_node_id: fcp_core::TailscaleNodeId::new("node-1"),
            request_nonce: 1002,
            received_unique: 50,
            needed: 0,
            complete: true,
            missing_hint: None,
            signature: fcp_crypto::Ed25519Signature::from_bytes(&[0u8; 64]),
        };
        handler.process_decode_status(&peer, &status, 100);

        // Should have 1 completed_awaiting_ack + 1 stopped active
        // Prune at 2000 (past TTL from activity at 100)
        let removed = handler.prune_stale_state(2000);
        assert!(removed >= 1);
    }

    #[test]
    fn prune_stale_state_removes_completed_transfers() {
        let policy = SymbolRequestPolicy {
            transfer_state_ttl_ms: 500,
            ..SymbolRequestPolicy::default()
        };
        let mut handler = SymbolRequestHandler::new(policy);
        let object_id = ObjectId::from_bytes([0x11; 32]);
        let peer = test_peer("peer-prune-complete");

        // Establish an active transfer first — process_symbol_ack only
        // promotes known transfers into completed_transfers. See the
        // `process_symbol_ack_unknown_object_is_dropped` test for the
        // defensive guard this exercises.
        let request = test_symbol_request(50, None);
        handler.track_transfer(&peer, &request, 0..5, 0);

        // Process ack → moves to completed_transfers
        let ack = SymbolAck::new(
            test_object_header(),
            object_id.clone(),
            test_zone_id(),
            ZoneKeyId::from_bytes([0x22; 8]),
            1000,
            fcp_core::TailscaleNodeId::new("node-1"),
            1003,
            SymbolAckReason::Complete,
            50,
        );
        handler.process_symbol_ack(&peer, &ack, 100);

        // Should stop before pruning
        assert!(handler.should_stop(&peer, &object_id));

        // Prune at 1000 (past TTL from 100)
        let removed = handler.prune_stale_state(1000);
        assert_eq!(removed, 1);

        // No longer should_stop after pruning
        assert!(!handler.should_stop(&peer, &object_id));
    }

    #[test]
    fn process_decode_status_incomplete_updates_state() {
        let mut handler = SymbolRequestHandler::with_default_policy();
        let object_id = ObjectId::from_bytes([0x11; 32]);
        let request = test_symbol_request(50, None);
        let peer = test_peer("peer-incomplete");

        handler.track_transfer(&peer, &request, 0..10, 0);

        // Send incomplete decode status
        let status = DecodeStatus {
            header: test_object_header(),
            object_id: object_id.clone(),
            zone_id: test_zone_id(),
            zone_key_id: ZoneKeyId::from_bytes([0x22; 8]),
            epoch_id: 1000,
            recipient_node_id: fcp_core::TailscaleNodeId::new("node-1"),
            request_nonce: 1004,
            received_unique: 10,
            needed: 40,
            complete: false,
            missing_hint: None,
            signature: fcp_crypto::Ed25519Signature::from_bytes(&[0u8; 64]),
        };
        handler.process_decode_status(&peer, &status, 500);

        // Should NOT stop — transfer still in progress
        assert!(!handler.should_stop(&peer, &object_id));
        assert_eq!(handler.active_transfer_count(), 1);
    }

    #[test]
    fn metrics_record_admission_rejection() {
        let mut metrics = SymbolRequestMetrics::default();
        metrics.record_admission_rejection();
        assert_eq!(metrics.requests_received, 1);
        assert_eq!(metrics.requests_rejected_admission, 1);
        assert_eq!(metrics.requests_validated, 0);
    }

    #[test]
    fn metrics_record_symbols_sent_not_targeted() {
        let mut metrics = SymbolRequestMetrics::default();
        metrics.record_symbols_sent(50, false);
        assert_eq!(metrics.symbols_sent, 50);
        assert_eq!(metrics.targeted_repairs, 0);
    }

    #[test]
    fn symbol_response_symbol_count() {
        let response = SymbolResponse {
            object_id: ObjectId::from_bytes([0x11; 32]),
            zone_id: test_zone_id(),
            zone_key_id: ZoneKeyId::from_bytes([0x22; 8]),
            symbol_esis: vec![1, 2, 3, 4, 5],
            is_final: false,
            was_bounded: false,
        };
        assert_eq!(response.symbol_count(), 5);
    }

    #[test]
    fn symbol_response_empty() {
        let response = SymbolResponse {
            object_id: ObjectId::from_bytes([0x11; 32]),
            zone_id: test_zone_id(),
            zone_key_id: ZoneKeyId::from_bytes([0x22; 8]),
            symbol_esis: vec![],
            is_final: true,
            was_bounded: false,
        };
        assert_eq!(response.symbol_count(), 0);
    }

    #[test]
    fn symbol_request_error_display() {
        let e = SymbolRequestError::InvalidRequest {
            reason: "bad zone".into(),
        };
        assert!(e.to_string().contains("bad zone"));

        let e = SymbolRequestError::BoundsExceeded {
            requested: 500,
            max_allowed: 32,
        };
        let s = e.to_string();
        assert!(s.contains("500"));
        assert!(s.contains("32"));

        let e = SymbolRequestError::HintTooLarge {
            count: 200,
            max: 128,
        };
        let s = e.to_string();
        assert!(s.contains("200"));
        assert!(s.contains("128"));

        let e = SymbolRequestError::ObjectNotFound {
            object_id: "abc123".into(),
        };
        assert!(e.to_string().contains("abc123"));

        let e = SymbolRequestError::SignatureInvalid;
        assert!(e.to_string().contains("signature"));

        let e = SymbolRequestError::AlreadyComplete {
            object_id: "done".into(),
        };
        assert!(e.to_string().contains("done"));
    }

    #[test]
    fn symbol_request_policy_serde_roundtrip() {
        let policy = SymbolRequestPolicy {
            max_unauthenticated_response: 64,
            max_authenticated_response: 2000,
            min_bootstrap_symbols: 16,
            require_proof_of_need_above: 200,
            allow_unauthenticated: false,
            transfer_state_ttl_ms: 7_200_000,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let back: SymbolRequestPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back.max_unauthenticated_response, 64);
        assert_eq!(back.max_authenticated_response, 2000);
        assert!(!back.allow_unauthenticated);
        assert_eq!(back.transfer_state_ttl_ms, 7_200_000);
    }

    #[test]
    fn symbol_request_policy_default() {
        let policy = SymbolRequestPolicy::default();
        assert_eq!(
            policy.max_unauthenticated_response,
            DEFAULT_RESPONSE_LIMIT_UNAUTHENTICATED
        );
        assert_eq!(
            policy.max_authenticated_response,
            DEFAULT_RESPONSE_LIMIT_AUTHENTICATED
        );
        assert_eq!(policy.min_bootstrap_symbols, DEFAULT_MIN_BOOTSTRAP_SYMBOLS);
        assert!(policy.allow_unauthenticated);
    }

    #[test]
    fn handler_policy_accessor() {
        let policy = SymbolRequestPolicy {
            max_authenticated_response: 999,
            ..SymbolRequestPolicy::default()
        };
        let handler = SymbolRequestHandler::new(policy);
        assert_eq!(handler.policy().max_authenticated_response, 999);
    }

    #[test]
    fn targeted_repair_engine_default() {
        let engine = TargetedRepairEngine::default();
        let request = ValidatedRequest {
            request: test_symbol_request(10, None),
            is_authenticated: true,
            max_response_symbols: 10,
            has_proof_of_need: false,
        };
        let selected = engine.select_symbols(&request, &HashSet::new());
        assert!(selected.is_empty());
    }

    #[test]
    fn targeted_repair_hints_with_unavailable_esis() {
        let mut engine = TargetedRepairEngine::new();
        let object_id = ObjectId::from_bytes([0x11; 32]);

        // Only have ESIs 0-9
        engine.register_available(object_id.clone(), 0..10);

        let request = ValidatedRequest {
            request: test_symbol_request(5, Some(vec![100, 200, 300])), // None available
            is_authenticated: true,
            max_response_symbols: 5,
            has_proof_of_need: true,
        };

        let selected = engine.select_symbols(&request, &HashSet::new());
        // Hinted ESIs not available, so should fall back to available ones
        assert!(!selected.is_empty());
        assert!(selected.iter().all(|&esi| esi < 10));
    }

    #[test]
    fn symbol_response_serde_roundtrip() {
        let response = SymbolResponse {
            object_id: ObjectId::from_bytes([0x11; 32]),
            zone_id: test_zone_id(),
            zone_key_id: ZoneKeyId::from_bytes([0x22; 8]),
            symbol_esis: vec![1, 2, 3],
            is_final: false,
            was_bounded: true,
        };
        let json = serde_json::to_string(&response).unwrap();
        let back: SymbolResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.symbol_esis, vec![1, 2, 3]);
        assert!(!back.is_final);
        assert!(back.was_bounded);
    }

    #[test]
    fn symbol_request_metrics_debug() {
        let metrics = SymbolRequestMetrics::default();
        let dbg = format!("{metrics:?}");
        assert!(dbg.contains("requests_received"));
        assert!(dbg.contains("symbols_sent"));
    }

    #[test]
    fn validated_request_debug_clone() {
        let vr = ValidatedRequest {
            request: test_symbol_request(10, None),
            is_authenticated: true,
            max_response_symbols: 10,
            has_proof_of_need: false,
        };
        let dbg = format!("{vr:?}");
        assert!(dbg.contains("max_response_symbols"));
        let moved = vr;
        assert_eq!(moved.max_response_symbols, 10);
    }

    // ── Constants validation ────────────────────────────────────

    #[test]
    fn constants_are_sensible() {
        assert_eq!(DEFAULT_RESPONSE_LIMIT_UNAUTHENTICATED, 32);
        assert_eq!(DEFAULT_RESPONSE_LIMIT_AUTHENTICATED, 1000);
        assert_eq!(DEFAULT_MIN_BOOTSTRAP_SYMBOLS, 8);
        const { assert!(DEFAULT_RESPONSE_LIMIT_AUTHENTICATED > DEFAULT_RESPONSE_LIMIT_UNAUTHENTICATED) };
    }

    // ── SymbolRequestError Display and From ─────────────────────

    #[test]
    fn error_invalid_request_display() {
        let err = SymbolRequestError::InvalidRequest {
            reason: "bad zone".into(),
        };
        assert!(err.to_string().contains("bad zone"));
    }

    #[test]
    fn error_bounds_exceeded_display() {
        let err = SymbolRequestError::BoundsExceeded {
            requested: 200,
            max_allowed: 100,
        };
        let s = err.to_string();
        assert!(s.contains("200"));
        assert!(s.contains("100"));
    }

    #[test]
    fn error_hint_too_large_display() {
        let err = SymbolRequestError::HintTooLarge {
            count: 500,
            max: 256,
        };
        let s = err.to_string();
        assert!(s.contains("500"));
        assert!(s.contains("256"));
    }

    #[test]
    fn error_object_not_found_display() {
        let err = SymbolRequestError::ObjectNotFound {
            object_id: "abc".into(),
        };
        assert!(err.to_string().contains("abc"));
    }

    #[test]
    fn error_already_complete_display() {
        let err = SymbolRequestError::AlreadyComplete {
            object_id: "done".into(),
        };
        assert!(err.to_string().contains("done"));
    }

    #[test]
    fn error_signature_invalid_display() {
        let err = SymbolRequestError::SignatureInvalid;
        assert!(err.to_string().contains("signature"));
    }

    #[test]
    fn error_from_admission_error() {
        let adm = AdmissionError::AuthenticationRequired;
        let err: SymbolRequestError = adm.into();
        assert!(err.to_string().contains("admission"));
    }

    // ── SymbolRequestPolicy edge cases ──────────────────────────

    #[test]
    fn policy_custom_values() {
        let policy = SymbolRequestPolicy {
            max_unauthenticated_response: 16,
            max_authenticated_response: 500,
            min_bootstrap_symbols: 4,
            require_proof_of_need_above: 50,
            allow_unauthenticated: false,
            transfer_state_ttl_ms: 1_800_000,
        };
        assert_eq!(policy.max_unauthenticated_response, 16);
        assert_eq!(policy.max_authenticated_response, 500);
        assert!(!policy.allow_unauthenticated);
    }

    // ── Handler constructor variants ────────────────────────────

    #[test]
    fn handler_with_default_policy_matches_defaults() {
        let handler = SymbolRequestHandler::with_default_policy();
        let policy = handler.policy();
        assert_eq!(
            policy.max_unauthenticated_response,
            DEFAULT_RESPONSE_LIMIT_UNAUTHENTICATED
        );
        assert_eq!(
            policy.max_authenticated_response,
            DEFAULT_RESPONSE_LIMIT_AUTHENTICATED
        );
        assert!(policy.allow_unauthenticated);
    }

    // ── Metrics additional tests ────────────────────────────────

    #[test]
    fn metrics_record_symbols_sent_targeted() {
        let mut metrics = SymbolRequestMetrics::default();
        metrics.record_symbols_sent(10, true);
        assert_eq!(metrics.symbols_sent, 10);
        assert_eq!(metrics.targeted_repairs, 1);
    }

    #[test]
    fn metrics_record_ack() {
        let mut metrics = SymbolRequestMetrics::default();
        metrics.record_ack();
        assert_eq!(metrics.acks_received, 1);
        metrics.record_ack();
        assert_eq!(metrics.acks_received, 2);
    }

    // ── SymbolResponse edge cases ───────────────────────────────

    #[test]
    fn symbol_response_is_final_field() {
        let resp = SymbolResponse {
            object_id: ObjectId::from_bytes([0; 32]),
            zone_id: test_zone_id(),
            zone_key_id: ZoneKeyId::from_bytes([0; 8]),
            symbol_esis: vec![0, 1, 2],
            is_final: true,
            was_bounded: false,
        };
        assert!(resp.is_final);
        assert!(!resp.was_bounded);
        assert_eq!(resp.symbol_count(), 3);
    }

    #[test]
    fn symbol_response_was_bounded_field() {
        let resp = SymbolResponse {
            object_id: ObjectId::from_bytes([0; 32]),
            zone_id: test_zone_id(),
            zone_key_id: ZoneKeyId::from_bytes([0; 8]),
            symbol_esis: vec![0],
            is_final: false,
            was_bounded: true,
        };
        assert!(resp.was_bounded);
        assert!(!resp.is_final);
    }

    // ── Multiple active transfers ────────────────────────────────

    #[test]
    fn handler_tracks_multiple_objects_independently() {
        let mut handler = SymbolRequestHandler::with_default_policy();
        let peer = test_peer("peer-multi-object");

        let req1 = test_symbol_request(50, None);
        let mut header2 = test_object_header();
        header2.created_at = 2_000_000_000;
        let req2 = SymbolRequest::new(
            header2,
            ObjectId::from_bytes([0x22; 32]),
            test_zone_id(),
            ZoneKeyId::from_bytes([0x33; 8]),
            1000,
            50,
            0,
        );

        handler.track_transfer(&peer, &req1, 0..5, 0);
        handler.track_transfer(&peer, &req2, 0..3, 0);

        assert_eq!(handler.active_transfer_count(), 2);

        // Ack first object only
        let ack1 = SymbolAck::new(
            test_object_header(),
            ObjectId::from_bytes([0x11; 32]),
            test_zone_id(),
            ZoneKeyId::from_bytes([0x22; 8]),
            1000,
            fcp_core::TailscaleNodeId::new("node-1"),
            1005,
            SymbolAckReason::Complete,
            5,
        );
        handler.process_symbol_ack(&peer, &ack1, 100);

        assert_eq!(handler.active_transfer_count(), 1);
        assert!(handler.should_stop(&peer, &ObjectId::from_bytes([0x11; 32])));
        assert!(!handler.should_stop(&peer, &ObjectId::from_bytes([0x22; 32])));
    }

    #[test]
    fn handler_scopes_stop_state_per_peer_for_same_object() {
        let mut handler = SymbolRequestHandler::with_default_policy();
        let peer_a = test_peer("peer-a");
        let peer_b = test_peer("peer-b");
        let request = test_symbol_request(50, None);
        let object_id = request.object_id.clone();

        handler.track_transfer(&peer_a, &request, 0..5, 0);
        handler.track_transfer(&peer_b, &request, 0..5, 0);
        assert_eq!(handler.active_transfer_count(), 2);

        let ack = SymbolAck::new(
            test_object_header(),
            object_id,
            test_zone_id(),
            ZoneKeyId::from_bytes([0x22; 8]),
            1000,
            fcp_core::TailscaleNodeId::new("node-1"),
            1009,
            SymbolAckReason::Complete,
            5,
        );
        handler.process_symbol_ack(&peer_a, &ack, 100);

        assert!(handler.should_stop(&peer_a, &object_id));
        assert!(!handler.should_stop(&peer_b, &object_id));
        assert_eq!(handler.active_transfer_count(), 1);
    }

    // ── Prune edge cases ─────────────────────────────────────────

    #[test]
    fn prune_stale_state_no_entries_returns_zero() {
        let mut handler = SymbolRequestHandler::with_default_policy();
        let removed = handler.prune_stale_state(999_999);
        assert_eq!(removed, 0);
    }

    #[test]
    fn prune_stale_state_at_exact_threshold() {
        let policy = SymbolRequestPolicy {
            transfer_state_ttl_ms: 100,
            ..SymbolRequestPolicy::default()
        };
        let mut handler = SymbolRequestHandler::new(policy);
        let request = test_symbol_request(50, None);
        let peer = test_peer("peer-threshold");
        handler.track_transfer(&peer, &request, 0..5, 50);

        // At exactly threshold boundary (now - ttl = activity time)
        let removed = handler.prune_stale_state(150);
        assert_eq!(removed, 0);
        assert_eq!(handler.active_transfer_count(), 1);
    }

    #[test]
    fn prune_stale_state_just_past_threshold() {
        let policy = SymbolRequestPolicy {
            transfer_state_ttl_ms: 100,
            ..SymbolRequestPolicy::default()
        };
        let mut handler = SymbolRequestHandler::new(policy);
        let request = test_symbol_request(50, None);
        let peer = test_peer("peer-past-threshold");
        handler.track_transfer(&peer, &request, 0..5, 49);

        // Just past threshold
        let removed = handler.prune_stale_state(150);
        assert_eq!(removed, 1);
    }

    // ── TargetedRepairEngine edge cases ──────────────────────────

    #[test]
    fn targeted_repair_empty_hints_vec() {
        let mut engine = TargetedRepairEngine::new();
        let object_id = ObjectId::from_bytes([0x11; 32]);
        engine.register_available(object_id.clone(), 0..10);

        let request = ValidatedRequest {
            request: test_symbol_request(5, Some(vec![])),
            is_authenticated: true,
            max_response_symbols: 5,
            has_proof_of_need: true,
        };

        let selected = engine.select_symbols(&request, &HashSet::new());
        // No hinted ESIs, should fill from available pool
        assert_eq!(selected.len(), 5);
        assert_eq!(selected, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn targeted_repair_all_already_sent() {
        let mut engine = TargetedRepairEngine::new();
        let object_id = ObjectId::from_bytes([0x11; 32]);
        engine.register_available(object_id.clone(), 0..5);

        let request = ValidatedRequest {
            request: test_symbol_request(10, None),
            is_authenticated: true,
            max_response_symbols: 10,
            has_proof_of_need: false,
        };

        let already_sent: HashSet<u32> = (0..5).collect();
        let selected = engine.select_symbols(&request, &already_sent);
        assert!(selected.is_empty());
    }

    #[test]
    fn targeted_repair_register_extends_existing() {
        let mut engine = TargetedRepairEngine::new();
        let object_id = ObjectId::from_bytes([0x11; 32]);

        engine.register_available(object_id.clone(), 0..5);
        engine.register_available(object_id.clone(), 10..15);

        let request = ValidatedRequest {
            request: test_symbol_request(20, None),
            is_authenticated: true,
            max_response_symbols: 20,
            has_proof_of_need: false,
        };

        let selected = engine.select_symbols(&request, &HashSet::new());
        assert_eq!(selected.len(), 10);
        assert!(selected.contains(&0));
        assert!(selected.contains(&14));
    }

    #[test]
    fn targeted_repair_remove_nonexistent_is_no_op() {
        let mut engine = TargetedRepairEngine::new();
        engine.remove_object(&ObjectId::from_bytes([0xFF; 32]));
        // Just verify it doesn't panic
    }

    #[test]
    fn targeted_repair_limit_zero() {
        let mut engine = TargetedRepairEngine::new();
        let object_id = ObjectId::from_bytes([0x11; 32]);
        engine.register_available(object_id.clone(), 0..100);

        let request = ValidatedRequest {
            request: test_symbol_request(0, None),
            is_authenticated: true,
            max_response_symbols: 0,
            has_proof_of_need: false,
        };

        let selected = engine.select_symbols(&request, &HashSet::new());
        assert!(selected.is_empty());
    }

    #[test]
    fn targeted_repair_hints_all_duplicates() {
        let mut engine = TargetedRepairEngine::new();
        let object_id = ObjectId::from_bytes([0x11; 32]);
        engine.register_available(object_id.clone(), 0..10);

        let request = ValidatedRequest {
            request: test_symbol_request(5, Some(vec![3, 3, 3, 3, 3])),
            is_authenticated: true,
            max_response_symbols: 5,
            has_proof_of_need: true,
        };

        let selected = engine.select_symbols(&request, &HashSet::new());
        // Only one unique hint (3), then fill remaining from pool
        assert!(selected.contains(&3));
        assert_eq!(selected.len(), 5);
    }

    // ── SymbolResponseBuilder edge cases ─────────────────────────

    #[test]
    fn response_builder_already_sent_equals_total() {
        let engine = TargetedRepairEngine::new();
        let object_id = ObjectId::from_bytes([0x11; 32]);

        let request = ValidatedRequest {
            request: test_symbol_request(50, None),
            is_authenticated: true,
            max_response_symbols: 50,
            has_proof_of_need: false,
        };

        let response = SymbolResponseBuilder::new(
            object_id,
            test_zone_id(),
            ZoneKeyId::from_bytes([0x22; 8]),
            50,
        )
        .add_from_repair_engine(&engine, &request, &HashSet::new())
        .build(100, 100);

        assert_eq!(response.symbol_count(), 0);
        assert!(response.is_final);
    }

    #[test]
    fn response_builder_already_sent_exceeds_total() {
        let engine = TargetedRepairEngine::new();
        let object_id = ObjectId::from_bytes([0x11; 32]);

        let request = ValidatedRequest {
            request: test_symbol_request(50, None),
            is_authenticated: true,
            max_response_symbols: 50,
            has_proof_of_need: false,
        };

        let response = SymbolResponseBuilder::new(
            object_id,
            test_zone_id(),
            ZoneKeyId::from_bytes([0x22; 8]),
            50,
        )
        .add_from_repair_engine(&engine, &request, &HashSet::new())
        .build(50, 200);

        assert_eq!(response.symbol_count(), 0);
        assert!(response.is_final);
    }

    // ── SymbolRequestPolicy serde edge cases ─────────────────────

    #[test]
    fn policy_serde_preserves_all_fields() {
        let policy = SymbolRequestPolicy {
            max_unauthenticated_response: 1,
            max_authenticated_response: u32::MAX,
            min_bootstrap_symbols: 0,
            require_proof_of_need_above: u32::MAX,
            allow_unauthenticated: true,
            transfer_state_ttl_ms: 0,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let back: SymbolRequestPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back.max_unauthenticated_response, 1);
        assert_eq!(back.max_authenticated_response, u32::MAX);
        assert_eq!(back.min_bootstrap_symbols, 0);
        assert_eq!(back.require_proof_of_need_above, u32::MAX);
        assert!(back.allow_unauthenticated);
        assert_eq!(back.transfer_state_ttl_ms, 0);
    }

    #[test]
    fn policy_debug_output() {
        let policy = SymbolRequestPolicy::default();
        let dbg = format!("{policy:?}");
        assert!(dbg.contains("SymbolRequestPolicy"));
        assert!(dbg.contains("allow_unauthenticated"));
    }

    // ── SymbolResponse serde edge cases ──────────────────────────

    #[test]
    fn symbol_response_serde_empty_esis() {
        let response = SymbolResponse {
            object_id: ObjectId::from_bytes([0; 32]),
            zone_id: test_zone_id(),
            zone_key_id: ZoneKeyId::from_bytes([0; 8]),
            symbol_esis: vec![],
            is_final: true,
            was_bounded: false,
        };
        let json = serde_json::to_string(&response).unwrap();
        let back: SymbolResponse = serde_json::from_str(&json).unwrap();
        assert!(back.symbol_esis.is_empty());
        assert!(back.is_final);
    }

    #[test]
    fn symbol_response_debug_output() {
        let response = SymbolResponse {
            object_id: ObjectId::from_bytes([0; 32]),
            zone_id: test_zone_id(),
            zone_key_id: ZoneKeyId::from_bytes([0; 8]),
            symbol_esis: vec![1, 2, 3],
            is_final: false,
            was_bounded: true,
        };
        let dbg = format!("{response:?}");
        assert!(dbg.contains("SymbolResponse"));
        assert!(dbg.contains("was_bounded"));
    }

    #[test]
    fn symbol_response_clone() {
        let response = SymbolResponse {
            object_id: ObjectId::from_bytes([0x99; 32]),
            zone_id: test_zone_id(),
            zone_key_id: ZoneKeyId::from_bytes([0x88; 8]),
            symbol_esis: vec![10, 20, 30],
            is_final: true,
            was_bounded: false,
        };
        let cloned = response.clone();
        assert_eq!(cloned.symbol_esis, vec![10, 20, 30]);
        assert_eq!(cloned.object_id, response.object_id);
        assert!(cloned.is_final);
    }

    // ── Metrics accumulation ─────────────────────────────────────

    #[test]
    fn metrics_multiple_records_accumulate() {
        let mut metrics = SymbolRequestMetrics::default();
        for _ in 0..10 {
            metrics.record_validated();
        }
        for _ in 0..5 {
            metrics.record_bounds_rejection();
        }
        for _ in 0..3 {
            metrics.record_admission_rejection();
        }
        metrics.record_symbols_sent(100, true);
        metrics.record_symbols_sent(200, false);
        metrics.record_ack();
        metrics.record_ack();

        assert_eq!(metrics.requests_received, 18);
        assert_eq!(metrics.requests_validated, 10);
        assert_eq!(metrics.requests_rejected_bounds, 5);
        assert_eq!(metrics.requests_rejected_admission, 3);
        assert_eq!(metrics.symbols_sent, 300);
        assert_eq!(metrics.targeted_repairs, 1);
        assert_eq!(metrics.acks_received, 2);
    }

    #[test]
    fn metrics_default_all_zero() {
        let metrics = SymbolRequestMetrics::default();
        assert_eq!(metrics.requests_received, 0);
        assert_eq!(metrics.requests_validated, 0);
        assert_eq!(metrics.requests_rejected_bounds, 0);
        assert_eq!(metrics.requests_rejected_admission, 0);
        assert_eq!(metrics.symbols_sent, 0);
        assert_eq!(metrics.targeted_repairs, 0);
        assert_eq!(metrics.acks_received, 0);
    }

    #[test]
    fn metrics_clone() {
        let mut metrics = SymbolRequestMetrics::default();
        metrics.record_validated();
        metrics.record_symbols_sent(50, true);
        let cloned = metrics.clone();
        assert_eq!(cloned.requests_received, 1);
        assert_eq!(cloned.symbols_sent, 50);
        assert_eq!(cloned.targeted_repairs, 1);
    }

    // ── SymbolRequestError Debug coverage ────────────────────────

    #[test]
    fn error_debug_all_variants() {
        let errors: Vec<SymbolRequestError> = vec![
            SymbolRequestError::InvalidRequest {
                reason: "test".into(),
            },
            SymbolRequestError::BoundsExceeded {
                requested: 10,
                max_allowed: 5,
            },
            SymbolRequestError::HintTooLarge {
                count: 300,
                max: 128,
            },
            SymbolRequestError::ObjectNotFound {
                object_id: "oid".into(),
            },
            SymbolRequestError::SignatureInvalid,
            SymbolRequestError::AlreadyComplete {
                object_id: "done".into(),
            },
        ];
        for err in &errors {
            let dbg = format!("{err:?}");
            assert!(!dbg.is_empty());
        }
    }

    // ── ValidatedRequest field combinations ──────────────────────

    #[test]
    fn validated_request_unauthenticated_with_proof() {
        let vr = ValidatedRequest {
            request: test_symbol_request(5, Some(vec![1, 2, 3])),
            is_authenticated: false,
            max_response_symbols: 5,
            has_proof_of_need: true,
        };
        assert!(!vr.is_authenticated);
        assert!(vr.has_proof_of_need);
        assert_eq!(vr.max_response_symbols, 5);
    }

    #[test]
    fn validated_request_clone_preserves_all() {
        let vr = ValidatedRequest {
            request: test_symbol_request(20, Some(vec![1, 2])),
            is_authenticated: true,
            max_response_symbols: 20,
            has_proof_of_need: true,
        };
        let cloned = vr.clone();
        assert_eq!(vr.max_response_symbols, 20);
        assert!(cloned.is_authenticated);
        assert_eq!(cloned.max_response_symbols, 20);
        assert!(cloned.has_proof_of_need);
        assert_eq!(cloned.request.missing_hint.as_ref().map(Vec::len), Some(2));
    }

    // ── Handler decode status for unknown object ─────────────────

    #[test]
    fn process_decode_status_unknown_object_is_noop() {
        let mut handler = SymbolRequestHandler::with_default_policy();
        let peer = test_peer("peer-unknown-status");

        let status = DecodeStatus {
            header: test_object_header(),
            object_id: ObjectId::from_bytes([0xFF; 32]),
            zone_id: test_zone_id(),
            zone_key_id: ZoneKeyId::from_bytes([0x22; 8]),
            epoch_id: 1000,
            recipient_node_id: fcp_core::TailscaleNodeId::new("node-1"),
            request_nonce: 1006,
            received_unique: 10,
            needed: 40,
            complete: false,
            missing_hint: None,
            signature: fcp_crypto::Ed25519Signature::from_bytes(&[0u8; 64]),
        };
        handler.process_decode_status(&peer, &status, 0);
        assert_eq!(handler.active_transfer_count(), 0);
    }

    #[test]
    fn process_symbol_ack_unknown_object_is_dropped() {
        // Defensive guard: an ack whose object_id was never in either
        // `active_transfers` or `completed_awaiting_ack` is dropped rather
        // than polluting `completed_transfers`. Without this guard, an
        // unauthenticated/forged ack for a random object_id would fill
        // completed_transfers unboundedly between prune_stale_state cycles
        // and would cause should_stop() to lie about transfer state.
        let mut handler = SymbolRequestHandler::with_default_policy();
        let unknown_id = ObjectId::from_bytes([0xFF; 32]);
        let peer = test_peer("peer-unknown-ack");
        let ack = SymbolAck::new(
            test_object_header(),
            unknown_id,
            test_zone_id(),
            ZoneKeyId::from_bytes([0x22; 8]),
            1000,
            fcp_core::TailscaleNodeId::new("node-1"),
            1007,
            SymbolAckReason::Complete,
            0,
        );
        handler.process_symbol_ack(&peer, &ack, 0);

        // completed_transfers must NOT have been populated for the unknown id.
        assert!(
            !handler.should_stop(&peer, &unknown_id),
            "unknown-object ack must not register a stop condition"
        );
    }

    // ── Track transfer updates total_needed ───────────────────────

    #[test]
    fn track_transfer_updates_total_needed_upward() {
        let mut handler = SymbolRequestHandler::with_default_policy();
        let req1 = test_symbol_request(50, None);
        let peer = test_peer("peer-total-needed");
        handler.track_transfer(&peer, &req1, 0..5, 0);

        // Second track with larger max_symbols
        let req2 = test_symbol_request(100, None);
        handler.track_transfer(&peer, &req2, 5..10, 100);

        // Still 1 transfer (same object_id)
        assert_eq!(handler.active_transfer_count(), 1);
    }

    // ── SymbolAckReason variants ─────────────────────────────────

    #[test]
    fn process_ack_with_cancel_reason() {
        let mut handler = SymbolRequestHandler::with_default_policy();
        let object_id = ObjectId::from_bytes([0x11; 32]);
        let request = test_symbol_request(50, None);
        let peer = test_peer("peer-cancel");
        handler.track_transfer(&peer, &request, 0..5, 0);

        let ack = SymbolAck::new(
            test_object_header(),
            object_id.clone(),
            test_zone_id(),
            ZoneKeyId::from_bytes([0x22; 8]),
            1000,
            fcp_core::TailscaleNodeId::new("node-1"),
            1008,
            SymbolAckReason::Cancelled,
            3,
        );
        handler.process_symbol_ack(&peer, &ack, 100);

        assert!(handler.should_stop(&peer, &object_id));
        assert_eq!(handler.active_transfer_count(), 0);
    }

    // ── Validation with custom policy thresholds ──────────────────

    #[test]
    fn validate_with_custom_max_limits() {
        let policy = SymbolRequestPolicy {
            max_unauthenticated_response: 10,
            max_authenticated_response: 50,
            ..SymbolRequestPolicy::default()
        };
        let handler = SymbolRequestHandler::new(policy);
        let mut admission = AdmissionController::with_default_policy();
        let peer = NodeId::new("peer-custom");

        // Authenticated request capped to policy max (50)
        let request = test_symbol_request(100, None);
        let result = handler.validate_request(&request, true, &mut admission, &peer, 0, 64);
        let validated = result.unwrap();
        assert_eq!(validated.max_response_symbols, 50);
    }

    #[test]
    fn validate_authenticated_below_proof_threshold() {
        let policy = SymbolRequestPolicy {
            require_proof_of_need_above: 200,
            ..SymbolRequestPolicy::default()
        };
        let handler = SymbolRequestHandler::new(policy);
        let mut admission = AdmissionController::with_default_policy();
        let peer = NodeId::new("peer-below");

        // 150 < 200, so no proof needed
        let request = test_symbol_request(150, None);
        let result = handler.validate_request(&request, true, &mut admission, &peer, 0, 64);
        assert!(result.is_ok());
    }

    // ── SymbolResponse serde with large ESI list ─────────────────

    #[test]
    fn symbol_response_serde_large_esi_list() {
        let esis: Vec<u32> = (0..500).collect();
        let response = SymbolResponse {
            object_id: ObjectId::from_bytes([0xAA; 32]),
            zone_id: test_zone_id(),
            zone_key_id: ZoneKeyId::from_bytes([0xBB; 8]),
            symbol_esis: esis,
            is_final: false,
            was_bounded: true,
        };
        let json = serde_json::to_string(&response).unwrap();
        let back: SymbolResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.symbol_esis.len(), 500);
        assert_eq!(back.symbol_count(), 500);
    }

    // ── SymbolRequestPolicy clone ────────────────────────────────

    #[test]
    fn symbol_request_policy_clone() {
        let policy = SymbolRequestPolicy {
            max_unauthenticated_response: 99,
            max_authenticated_response: 999,
            min_bootstrap_symbols: 5,
            require_proof_of_need_above: 50,
            allow_unauthenticated: false,
            transfer_state_ttl_ms: 12345,
        };
        let cloned = policy.clone();
        assert_eq!(policy.max_unauthenticated_response, 99);
        assert_eq!(cloned.max_unauthenticated_response, 99);
        assert_eq!(cloned.max_authenticated_response, 999);
        assert_eq!(cloned.min_bootstrap_symbols, 5);
        assert_eq!(cloned.require_proof_of_need_above, 50);
        assert!(!cloned.allow_unauthenticated);
        assert_eq!(cloned.transfer_state_ttl_ms, 12345);
    }

    // ── Handler initial state ────────────────────────────────────

    #[test]
    fn handler_initial_active_count_zero() {
        let handler = SymbolRequestHandler::with_default_policy();
        assert_eq!(handler.active_transfer_count(), 0);
    }

    #[test]
    fn handler_should_stop_unknown_object_false() {
        let handler = SymbolRequestHandler::with_default_policy();
        let peer = test_peer("peer-empty");
        assert!(!handler.should_stop(&peer, &ObjectId::from_bytes([0xAB; 32])));
    }

    // ── TargetedRepairEngine with single ESI ─────────────────────

    #[test]
    fn targeted_repair_single_available_esi() {
        let mut engine = TargetedRepairEngine::new();
        let object_id = ObjectId::from_bytes([0x11; 32]);
        engine.register_available(object_id.clone(), std::iter::once(42));

        let request = ValidatedRequest {
            request: test_symbol_request(10, None),
            is_authenticated: true,
            max_response_symbols: 10,
            has_proof_of_need: false,
        };

        let selected = engine.select_symbols(&request, &HashSet::new());
        assert_eq!(selected, vec![42]);
    }

    #[test]
    fn targeted_repair_hint_only_unavailable_fills_from_pool() {
        let mut engine = TargetedRepairEngine::new();
        let object_id = ObjectId::from_bytes([0x11; 32]);
        engine.register_available(object_id.clone(), 0..3);

        let request = ValidatedRequest {
            request: test_symbol_request(3, Some(vec![100, 200])),
            is_authenticated: true,
            max_response_symbols: 3,
            has_proof_of_need: true,
        };

        let selected = engine.select_symbols(&request, &HashSet::new());
        // Hints 100/200 aren't available, should fill from 0..3
        assert_eq!(selected.len(), 3);
        assert_eq!(selected, vec![0, 1, 2]);
    }

    // ── SymbolResponseBuilder direct construction ────────────────

    #[test]
    fn response_builder_without_engine() {
        let response = SymbolResponseBuilder::new(
            ObjectId::from_bytes([0x11; 32]),
            test_zone_id(),
            ZoneKeyId::from_bytes([0x22; 8]),
            100,
        )
        .build(0, 0);

        assert_eq!(response.symbol_count(), 0);
        assert!(response.is_final);
    }

    #[test]
    fn response_builder_max_symbols_zero() {
        let response = SymbolResponseBuilder::new(
            ObjectId::from_bytes([0x11; 32]),
            test_zone_id(),
            ZoneKeyId::from_bytes([0x22; 8]),
            0,
        )
        .build(100, 0);

        assert_eq!(response.symbol_count(), 0);
        assert!(!response.is_final);
        assert!(response.was_bounded);
    }

    #[test]
    fn response_builder_zero_budget_with_available_symbols_is_not_final() {
        let mut engine = TargetedRepairEngine::new();
        let object_id = ObjectId::from_bytes([0x11; 32]);
        engine.register_available(object_id, 0..4);

        let request = ValidatedRequest {
            request: test_symbol_request(0, None),
            is_authenticated: true,
            max_response_symbols: 0,
            has_proof_of_need: false,
        };

        let response = SymbolResponseBuilder::new(
            object_id,
            test_zone_id(),
            ZoneKeyId::from_bytes([0x22; 8]),
            0,
        )
        .add_from_repair_engine(&engine, &request, &HashSet::new())
        .build(4, 0);

        assert_eq!(response.symbol_count(), 0);
        assert!(!response.is_final);
        assert!(response.was_bounded);
    }

    // ── Prune with u64::MAX timestamp ────────────────────────────

    #[test]
    fn prune_stale_state_max_timestamp() {
        let mut handler = SymbolRequestHandler::with_default_policy();
        let request = test_symbol_request(50, None);
        let peer = test_peer("peer-max-timestamp");
        handler.track_transfer(&peer, &request, 0..5, 0);

        // Even with u64::MAX all entries should be expired (activity at 0)
        let removed = handler.prune_stale_state(u64::MAX);
        assert_eq!(removed, 1);
    }

    // ── Metrics symbols accumulation ─────────────────────────────

    #[test]
    fn metrics_record_symbols_sent_accumulates() {
        let mut metrics = SymbolRequestMetrics::default();
        metrics.record_symbols_sent(10, false);
        metrics.record_symbols_sent(20, true);
        metrics.record_symbols_sent(30, false);
        assert_eq!(metrics.symbols_sent, 60);
        assert_eq!(metrics.targeted_repairs, 1);
    }

    #[test]
    fn metrics_record_symbols_sent_zero() {
        let mut metrics = SymbolRequestMetrics::default();
        metrics.record_symbols_sent(0, true);
        assert_eq!(metrics.symbols_sent, 0);
        assert_eq!(metrics.targeted_repairs, 1);
    }

    // ── SymbolRequestError debug coverage all variants ───────────

    #[test]
    fn error_admission_rejected_display() {
        let err = SymbolRequestError::AdmissionRejected(AdmissionError::AuthenticationRequired);
        let s = err.to_string();
        assert!(s.contains("admission"));
    }

    // ── Validated request max_response_symbols boundary ──────────

    #[test]
    fn validated_request_max_zero() {
        let vr = ValidatedRequest {
            request: test_symbol_request(0, None),
            is_authenticated: true,
            max_response_symbols: 0,
            has_proof_of_need: false,
        };
        assert_eq!(vr.max_response_symbols, 0);
    }

    #[test]
    fn validated_request_max_u32_max() {
        let vr = ValidatedRequest {
            request: test_symbol_request(u32::MAX, None),
            is_authenticated: true,
            max_response_symbols: u32::MAX,
            has_proof_of_need: false,
        };
        assert_eq!(vr.max_response_symbols, u32::MAX);
    }

    // ── Track transfer with empty iterator ───────────────────────

    #[test]
    fn track_transfer_empty_esi_iterator() {
        let mut handler = SymbolRequestHandler::with_default_policy();
        let request = test_symbol_request(50, None);
        let peer = test_peer("peer-empty-transfer");
        handler.track_transfer(&peer, &request, std::iter::empty(), 0);
        assert_eq!(handler.active_transfer_count(), 1);
    }
}
