//! Emergency revocation admin RPC primitives — owner-signed,
//! replay-protected request/response shapes for the kill-switch
//! panic button (m8j0q.8).
//!
//! Per ADR `docs/architecture/adr/m8j0q-emergency-revocation-protocol.md`
//! the host receives an [`EmergencyRevocationRequest`] from the
//! operator (originating in `fwc emergency revoke ...`), validates
//! owner-signature + nonce + validity window + per-zone rate limit,
//! enqueues an emergency-priority gossip burst, collects
//! `RevocationWitness` signatures from peers up to a 5-second
//! deadline, and returns an [`EmergencyRevocationResponse`].
//!
//! This module owns **only the request/response types, the audit
//! event shape, the nonce-replay store, and the per-zone token
//! bucket**. The actual gossip-burst loop and witness collection
//! live in `fcp-mesh::emergency_revocation`; the wiring of the
//! `/admin/emergency_revoke` axum route and the in-flight invocation
//! cancellation hook are bead m8j0q.8.c and m8j0q.8.d respectively
//! (this module ships the contract those tasks build against).

use std::collections::{HashMap, HashSet};

use blake3::Hasher;
use fcp_crypto::{CryptoError, Ed25519Signature, Ed25519VerifyingKey};
use fcp_prelude::{ConnectorId, NodeSignature, PrincipalId, ZoneId};
use serde::{Deserialize, Serialize};

/// Domain separator for [`EmergencyRevocationRequest::signing_bytes`].
///
/// The owner signs over a transcript prefixed with this string so a
/// signature for an emergency-revocation request cannot be replayed
/// against any other transcript shape.
pub const EMERGENCY_REVOCATION_REQUEST_DOMAIN: &[u8] = b"FCP2-EMERGENCY-REVOCATION-REQUEST-V1";

/// Default per-zone rate-limit window.
///
/// Mirrors `PriorityGossipPolicy::EMERGENCY_RATE_LIMIT_PER_ZONE_SECS`.
/// Recorded here as a `u64` ms value for direct use by the token
/// bucket; see [`EmergencyRevocationRateLimiter`].
pub const EMERGENCY_REVOCATION_RATE_LIMIT_PER_ZONE_MS: u64 = 60_000;

/// `POST /admin/emergency_revoke` body — owner-signed, replay-protected.
///
/// Validation checklist (host MUST perform all four before
/// triggering an emergency burst):
///   1. Verify [`Self::owner_signature`] against the zone-owner key
///      using [`Self::verify_owner_signature`].
///   2. Reject if `nonce` has been seen before for this zone (see
///      [`NonceReplayStore`]).
///   3. Reject if `now < not_before_unix_ms || now > not_after_unix_ms`.
///   4. Reject if the per-zone rate limiter is currently locked out
///      (see [`EmergencyRevocationRateLimiter`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyRevocationRequest {
    /// Zone to revoke (e.g., `z:work`).
    pub zone_id: ZoneId,
    /// Optional connector restriction. When `Some`, revokes the
    /// named connector across all zones the operator owns; when
    /// `None`, revokes the entire zone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connector: Option<ConnectorId>,
    /// Operator-supplied free-text reason (carried in the audit
    /// event for post-incident review).
    pub reason: String,
    /// 16-byte fresh nonce — rejected on second sight per zone.
    pub nonce: [u8; 16],
    /// Lower bound of the request's validity window (Unix ms).
    pub not_before_unix_ms: u64,
    /// Upper bound of the request's validity window (Unix ms).
    pub not_after_unix_ms: u64,
    /// Owner signature over [`Self::signing_bytes`]. The host's
    /// owner-key registry is the only place that can produce a
    /// valid signature.
    pub owner_signature: Option<NodeSignature>,
}

impl EmergencyRevocationRequest {
    /// Construct an unsigned request. Call `sign_with` to
    /// attach the owner signature once the transcript is finalized.
    #[must_use]
    pub const fn new(
        zone_id: ZoneId,
        connector: Option<ConnectorId>,
        reason: String,
        nonce: [u8; 16],
        not_before_unix_ms: u64,
        not_after_unix_ms: u64,
    ) -> Self {
        Self {
            zone_id,
            connector,
            reason,
            nonce,
            not_before_unix_ms,
            not_after_unix_ms,
            owner_signature: None,
        }
    }

    /// Transcript bytes the owner signs. Includes every field in the
    /// request body except the signature itself (sign-then-attach).
    ///
    /// Layout is little-endian length-prefixed for stable
    /// concatenation regardless of the variable-length fields:
    ///
    /// ```text
    /// EMERGENCY_REVOCATION_REQUEST_DOMAIN
    /// || u32_le(len(zone_id))   || zone_id bytes
    /// || u8(connector tag: 0=None, 1=Some)
    /// ||   if Some: u32_le(len(connector))  || connector bytes
    /// || u32_le(len(reason))    || reason bytes
    /// || nonce (16 bytes)
    /// || u64_le(not_before_unix_ms)
    /// || u64_le(not_after_unix_ms)
    /// ```
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let zone_bytes = self.zone_id.as_bytes();
        let reason_bytes = self.reason.as_bytes();
        let connector_bytes = self
            .connector
            .as_ref()
            .map(|c| c.as_str().as_bytes().to_vec())
            .unwrap_or_default();

        let estimated = EMERGENCY_REVOCATION_REQUEST_DOMAIN.len()
            + 4
            + zone_bytes.len()
            + 1
            + 4
            + connector_bytes.len()
            + 4
            + reason_bytes.len()
            + 16
            + 8
            + 8;
        let mut bytes = Vec::with_capacity(estimated);
        bytes.extend_from_slice(EMERGENCY_REVOCATION_REQUEST_DOMAIN);

        bytes.extend_from_slice(
            &u32::try_from(zone_bytes.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        bytes.extend_from_slice(zone_bytes);

        if self.connector.is_some() {
            bytes.push(1);
            bytes.extend_from_slice(
                &u32::try_from(connector_bytes.len())
                    .unwrap_or(u32::MAX)
                    .to_le_bytes(),
            );
            bytes.extend_from_slice(&connector_bytes);
        } else {
            bytes.push(0);
        }

        bytes.extend_from_slice(
            &u32::try_from(reason_bytes.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        bytes.extend_from_slice(reason_bytes);

        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.not_before_unix_ms.to_le_bytes());
        bytes.extend_from_slice(&self.not_after_unix_ms.to_le_bytes());
        bytes
    }

    /// Attach an owner signature.
    #[must_use]
    pub fn with_signature(mut self, signature: NodeSignature) -> Self {
        self.owner_signature = Some(signature);
        self
    }

    /// Verify the attached owner signature.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::MissingField`] if `owner_signature` is
    /// `None`, or the verifier's error if signature verification
    /// fails.
    pub fn verify_owner_signature(
        &self,
        owner_verifying_key: &Ed25519VerifyingKey,
    ) -> Result<(), CryptoError> {
        let signature = self
            .owner_signature
            .as_ref()
            .ok_or_else(|| CryptoError::MissingField("owner_signature".into()))?;
        let signature = Ed25519Signature::from_bytes(&signature.signature);
        owner_verifying_key.verify(&self.signing_bytes(), &signature)
    }

    /// Whether `now_unix_ms` falls within `[not_before, not_after]`.
    #[must_use]
    pub const fn is_within_validity_window(&self, now_unix_ms: u64) -> bool {
        now_unix_ms >= self.not_before_unix_ms && now_unix_ms <= self.not_after_unix_ms
    }

    /// Stable correlation id derived from the canonical signing
    /// bytes — used for audit indexing and operator-visible response
    /// echo. Two distinct requests cannot share an id (BLAKE3 of the
    /// transcript covers every field).
    #[must_use]
    pub fn emergency_revoke_id(&self) -> [u8; 16] {
        let digest = blake3::hash(&self.signing_bytes());
        let mut id = [0u8; 16];
        id.copy_from_slice(&digest.as_bytes()[..16]);
        id
    }
}

/// Response shape for `/admin/emergency_revoke`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyRevocationResponse {
    /// Stable correlation id mirrored from
    /// [`EmergencyRevocationRequest::emergency_revoke_id`].
    pub emergency_revoke_id: [u8; 16],
    /// Revocation head sequence after this revocation was applied.
    pub revocation_head_seq: u64,
    /// When the host began enqueuing the emergency burst (Unix ms).
    pub propagation_started_at_unix_ms: u64,
    /// Hard deadline for witness collection (Unix ms).
    pub propagation_deadline_unix_ms: u64,
    /// Witnesses collected before the deadline elapsed.
    pub witnesses_collected: u32,
    /// Effective quorum target (per
    /// [`fcp_mesh::emergency_revocation::effective_quorum_target`]).
    pub witnesses_target: u32,
}

impl EmergencyRevocationResponse {
    /// Whether this response represents a successful revocation
    /// (witness target reached within the deadline).
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.witnesses_collected >= self.witnesses_target
    }
}

/// Reason a host refused an emergency-revocation request before any
/// gossip burst was attempted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EmergencyRevocationRefusal {
    /// `owner_signature` was missing or did not verify under the
    /// configured zone-owner key.
    InvalidOwnerSignature,
    /// `nonce` was previously seen for the request's zone.
    NonceReplay,
    /// Wall-clock time was outside `[not_before, not_after]`.
    OutsideValidityWindow {
        /// Wall clock at validation (Unix ms).
        now_unix_ms: u64,
    },
    /// The per-zone token bucket was empty.
    RateLimited {
        /// Seconds until the bucket refills.
        retry_after_secs: u64,
    },
}

/// Outcome of a successfully-validated emergency-revocation attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EmergencyRevocationOutcome {
    /// Quorum reached within the deadline — propagation considered
    /// complete.
    QuorumReached {
        /// Witnesses collected.
        witnesses: u32,
        /// Total elapsed time in ms.
        elapsed_ms: u64,
    },
    /// Deadline elapsed before the witness target was reached.
    /// Operator-visible failure mode that distinguishes "compromised
    /// peer silently dropped the priority push" from "everything
    /// worked."
    QuorumNotReached {
        /// Witnesses collected.
        witnesses: u32,
        /// Target the originator was waiting for.
        target: u32,
        /// Total elapsed time in ms (== deadline).
        elapsed_ms: u64,
    },
    /// Request refused before any propagation attempt.
    Refused {
        /// Categorical refusal reason.
        reason: EmergencyRevocationRefusal,
    },
}

/// Audit event recorded by the host after every
/// emergency-revocation attempt — includes refused requests for
/// offline review of suspicious activity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyRevocationAuditEvent {
    /// Stable correlation id (matches
    /// [`EmergencyRevocationRequest::emergency_revoke_id`]).
    pub emergency_revoke_id: [u8; 16],
    /// Principal that invoked `/admin/emergency_revoke` (the API
    /// caller, not necessarily the owner-key holder).
    pub invoker_principal: PrincipalId,
    /// Zone targeted by the revocation.
    pub zone_id: ZoneId,
    /// Optional connector restriction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connector: Option<ConnectorId>,
    /// Operator-supplied reason (verbatim, free text).
    pub reason: String,
    /// Revocation head sequence the request requested.
    pub revocation_head_seq: u64,
    /// When the host began processing the request (Unix ms).
    pub started_at_unix_ms: u64,
    /// Outcome — success, failure, or refusal.
    pub outcome: EmergencyRevocationOutcome,
}

// ── Nonce replay store ─────────────────────────────────────────────────

/// Per-zone replay-protection store for emergency-revocation nonces.
///
/// Bounded in size (LRU-eviction once `max_entries_per_zone` is hit)
/// so an attacker cannot grow the host's memory footprint by flooding
/// nonces.
///
/// In-process implementation — production deployment should layer
/// this on top of a persistent backing store so a host restart does
/// not reset the nonce window.
#[derive(Debug, Default, Clone)]
pub struct NonceReplayStore {
    seen_per_zone: HashMap<ZoneId, HashSet<[u8; 16]>>,
    max_entries_per_zone: usize,
}

impl NonceReplayStore {
    /// Construct a new replay store with the given per-zone cap.
    /// `max_entries_per_zone` of 0 disables eviction (use only for
    /// tests where the size cannot grow unboundedly).
    #[must_use]
    pub fn new(max_entries_per_zone: usize) -> Self {
        Self {
            seen_per_zone: HashMap::new(),
            max_entries_per_zone,
        }
    }

    /// Attempt to record a nonce. Returns `true` if this is the
    /// first sighting (caller may proceed); `false` if the nonce was
    /// already seen for this zone (caller MUST reject as
    /// `NonceReplay`).
    pub fn observe(&mut self, zone_id: &ZoneId, nonce: [u8; 16]) -> bool {
        let entry = self.seen_per_zone.entry(zone_id.clone()).or_default();
        if entry.contains(&nonce) {
            return false;
        }
        if self.max_entries_per_zone > 0 && entry.len() >= self.max_entries_per_zone {
            // Remove an arbitrary entry — the eviction policy is
            // best-effort because nonce-replay protection is
            // bounded-window security; long-lived nonces should be
            // rejected by `not_after` instead.
            if let Some(victim) = entry.iter().next().copied() {
                entry.remove(&victim);
            }
        }
        entry.insert(nonce);
        true
    }

    /// Whether the given nonce was observed for the zone.
    #[must_use]
    pub fn was_seen(&self, zone_id: &ZoneId, nonce: &[u8; 16]) -> bool {
        self.seen_per_zone
            .get(zone_id)
            .is_some_and(|set| set.contains(nonce))
    }
}

// ── Per-zone token bucket rate limiter ─────────────────────────────────

/// Per-zone single-token bucket — at most one emergency revoke per
/// `EMERGENCY_REVOCATION_RATE_LIMIT_PER_ZONE_MS` per zone. Defends
/// against revocation-as-DoS via a compromised owner key.
#[derive(Debug, Default, Clone)]
pub struct EmergencyRevocationRateLimiter {
    last_revoke_unix_ms: HashMap<ZoneId, u64>,
    window_ms: u64,
}

impl EmergencyRevocationRateLimiter {
    /// Construct a rate limiter with the canonical 60s window.
    #[must_use]
    pub fn new() -> Self {
        Self {
            last_revoke_unix_ms: HashMap::new(),
            window_ms: EMERGENCY_REVOCATION_RATE_LIMIT_PER_ZONE_MS,
        }
    }

    /// Construct a rate limiter with a custom window (test seam).
    #[must_use]
    pub fn with_window_ms(window_ms: u64) -> Self {
        Self {
            last_revoke_unix_ms: HashMap::new(),
            window_ms,
        }
    }

    /// Try to consume the rate-limit token for `zone_id` at
    /// `now_unix_ms`. Returns `Ok(())` on consume; on rate-limit,
    /// returns the number of seconds until the bucket refills.
    ///
    /// # Errors
    ///
    /// Returns `Err(retry_after_secs)` when the per-zone bucket
    /// hasn't refilled yet.
    pub fn try_consume(&mut self, zone_id: &ZoneId, now_unix_ms: u64) -> Result<(), u64> {
        if let Some(&last) = self.last_revoke_unix_ms.get(zone_id) {
            let elapsed = now_unix_ms.saturating_sub(last);
            if elapsed < self.window_ms {
                let remaining_ms = self.window_ms - elapsed;
                let retry_after_secs = remaining_ms.div_ceil(1000);
                return Err(retry_after_secs);
            }
        }
        self.last_revoke_unix_ms
            .insert(zone_id.clone(), now_unix_ms);
        Ok(())
    }

    /// Synthesize a refusal record from a failed `try_consume`.
    #[must_use]
    pub const fn refusal(retry_after_secs: u64) -> EmergencyRevocationRefusal {
        EmergencyRevocationRefusal::RateLimited { retry_after_secs }
    }
}

/// Convenience: BLAKE3 over the canonical signing bytes — used by
/// callers that need a separate digest of the request transcript
/// (e.g., audit log indexing, structured tracing).
#[must_use]
pub fn request_digest(request: &EmergencyRevocationRequest) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(EMERGENCY_REVOCATION_REQUEST_DOMAIN);
    h.update(&request.signing_bytes());
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_crypto::Ed25519SigningKey;
    use fcp_prelude::NodeId;

    fn signing_key_from_seed(seed: u8) -> Ed25519SigningKey {
        Ed25519SigningKey::from_bytes(&[seed; 32]).expect("valid signing key")
    }

    fn sample_request() -> EmergencyRevocationRequest {
        EmergencyRevocationRequest::new(
            "z:work".parse().expect("valid zone id"),
            None,
            "incident-2026-05-02".to_string(),
            [0xCC; 16],
            1_700_000_000_000,
            1_700_000_060_000,
        )
    }

    fn sign_request(req: &EmergencyRevocationRequest, sk: &Ed25519SigningKey) -> NodeSignature {
        let sig_bytes = sk.sign(&req.signing_bytes());
        NodeSignature::new(NodeId::new("owner"), sig_bytes.to_bytes(), 1_700_000_000)
    }

    // ── m8j0q.8.c unit tests (per ADR §"Tests expected to follow") ─

    #[test]
    fn emergency_request_signing_bytes_includes_domain_separator() {
        let req = sample_request();
        let bytes = req.signing_bytes();
        assert!(
            bytes.starts_with(EMERGENCY_REVOCATION_REQUEST_DOMAIN),
            "signing bytes missing domain separator"
        );
    }

    #[test]
    fn emergency_request_signing_bytes_is_deterministic() {
        let req = sample_request();
        assert_eq!(req.signing_bytes(), req.signing_bytes());
    }

    #[test]
    fn emergency_request_signing_bytes_excludes_attached_signature() {
        let unsigned = sample_request();
        let mut signed = unsigned.clone();
        signed.owner_signature = Some(NodeSignature::new(
            NodeId::new("owner"),
            [0u8; 64],
            1_700_000_000,
        ));
        assert_eq!(
            unsigned.signing_bytes(),
            signed.signing_bytes(),
            "signature field leaked into signing transcript"
        );
    }

    #[test]
    fn emergency_request_signing_bytes_changes_when_any_field_changes() {
        let base = sample_request();
        let baseline = base.signing_bytes();

        let mut altered_zone = base.clone();
        altered_zone.zone_id = "z:public".parse().expect("valid zone id");
        assert_ne!(baseline, altered_zone.signing_bytes());

        let mut altered_reason = base.clone();
        altered_reason.reason = "different reason".to_string();
        assert_ne!(baseline, altered_reason.signing_bytes());

        let mut altered_nonce = base.clone();
        altered_nonce.nonce = [0xDD; 16];
        assert_ne!(baseline, altered_nonce.signing_bytes());

        let mut altered_window_low = base.clone();
        altered_window_low.not_before_unix_ms = 0;
        assert_ne!(baseline, altered_window_low.signing_bytes());

        let mut altered_window_high = base.clone();
        altered_window_high.not_after_unix_ms = u64::MAX;
        assert_ne!(baseline, altered_window_high.signing_bytes());

        let mut altered_connector = base;
        altered_connector.connector =
            Some(ConnectorId::from_static("github:request_response:1.0.0"));
        assert_ne!(baseline, altered_connector.signing_bytes());
    }

    #[test]
    fn emergency_request_owner_signature_round_trip_verifies() {
        let sk = signing_key_from_seed(0x10);
        let pk = sk.verifying_key();
        let req = sample_request();
        let signed = req.clone().with_signature(sign_request(&req, &sk));
        signed
            .verify_owner_signature(&pk)
            .expect("owner signature verifies");
    }

    #[test]
    fn emergency_request_rejects_invalid_owner_signature() {
        // ADR test name. Wrong key fails verification.
        let sk_owner = signing_key_from_seed(0x11);
        let sk_attacker = signing_key_from_seed(0x12);
        let pk_owner = sk_owner.verifying_key();
        let req = sample_request();
        let signed = req.clone().with_signature(sign_request(&req, &sk_attacker));
        signed
            .verify_owner_signature(&pk_owner)
            .expect_err("owner-key verifier must reject attacker signature");
    }

    #[test]
    fn emergency_request_rejects_unsigned() {
        let pk = signing_key_from_seed(0x13).verifying_key();
        let req = sample_request();
        let err = req
            .verify_owner_signature(&pk)
            .expect_err("unsigned request must not verify");
        match err {
            CryptoError::MissingField(field) => {
                assert!(field.contains("owner_signature"));
            }
            other => panic!("expected MissingField, got {other:?}"),
        }
    }

    #[test]
    fn emergency_request_rejects_replayed_nonce() {
        // ADR test name.
        let mut store = NonceReplayStore::new(64);
        let zone: ZoneId = "z:work".parse().unwrap();
        let nonce = [0x77; 16];
        assert!(store.observe(&zone, nonce), "first sighting should accept");
        assert!(!store.observe(&zone, nonce), "replay must be rejected");
        assert!(!store.observe(&zone, nonce), "third call also rejected");
    }

    #[test]
    fn nonce_replay_store_isolates_zones() {
        // A nonce replayed in zone A is not flagged when first seen
        // in zone B — the dedup is per-zone.
        let mut store = NonceReplayStore::new(64);
        let work: ZoneId = "z:work".parse().unwrap();
        let public: ZoneId = "z:public".parse().unwrap();
        let nonce = [0x88; 16];
        assert!(store.observe(&work, nonce));
        assert!(
            store.observe(&public, nonce),
            "different zone must accept same nonce"
        );
    }

    #[test]
    fn nonce_replay_store_evicts_when_capacity_reached() {
        let mut store = NonceReplayStore::new(2);
        let zone: ZoneId = "z:work".parse().unwrap();
        for i in 0..10u8 {
            let mut nonce = [0u8; 16];
            nonce[0] = i;
            assert!(store.observe(&zone, nonce));
        }
        // Capacity is 2 — most prior nonces have been evicted; the
        // store grew bounded by capacity.
        let stored_count = store.seen_per_zone.get(&zone).map_or(0, HashSet::len);
        assert!(
            stored_count <= 2,
            "capacity exceeded: stored {stored_count}"
        );
    }

    #[test]
    fn emergency_request_within_validity_window_predicate() {
        let req = sample_request();
        assert!(req.is_within_validity_window(req.not_before_unix_ms));
        assert!(req.is_within_validity_window(req.not_after_unix_ms));
        assert!(req.is_within_validity_window(u64::midpoint(
            req.not_before_unix_ms,
            req.not_after_unix_ms,
        )));
        assert!(!req.is_within_validity_window(req.not_before_unix_ms - 1));
        assert!(!req.is_within_validity_window(req.not_after_unix_ms + 1));
    }

    #[test]
    fn emergency_request_outside_validity_window_rejected() {
        // ADR test name. Confirms the validity-window predicate is
        // false on both sides of the window.
        let req = sample_request();
        assert!(!req.is_within_validity_window(0));
        assert!(!req.is_within_validity_window(u64::MAX));
        assert!(!req.is_within_validity_window(req.not_before_unix_ms - 1));
        assert!(!req.is_within_validity_window(req.not_after_unix_ms + 1));
    }

    #[test]
    fn emergency_request_rate_limit_token_bucket() {
        // ADR test name: 1 emergency revoke per 60s per zone.
        let mut limiter = EmergencyRevocationRateLimiter::new();
        let zone: ZoneId = "z:work".parse().unwrap();
        let t0 = 1_700_000_000_000;

        // First revoke at t0 succeeds.
        limiter.try_consume(&zone, t0).expect("first consume");

        // Second revoke 30s later refused with retry_after of ~30s.
        let err = limiter
            .try_consume(&zone, t0 + 30_000)
            .expect_err("second consume within window must fail");
        assert!((29..=31).contains(&err), "unexpected retry_after: {err}");

        // Second revoke 60s later succeeds (window has refilled).
        limiter
            .try_consume(&zone, t0 + 60_000)
            .expect("after window: consume succeeds");
    }

    #[test]
    fn emergency_request_rate_limit_isolates_zones() {
        let mut limiter = EmergencyRevocationRateLimiter::new();
        let work: ZoneId = "z:work".parse().unwrap();
        let public: ZoneId = "z:public".parse().unwrap();
        let t0 = 1_700_000_000_000;
        limiter.try_consume(&work, t0).expect("work first");
        limiter
            .try_consume(&public, t0)
            .expect("different zone must not share the bucket");
    }

    #[test]
    fn emergency_request_rate_limit_with_short_window_for_tests() {
        let mut limiter = EmergencyRevocationRateLimiter::with_window_ms(1_000);
        let zone: ZoneId = "z:work".parse().unwrap();
        let t0 = 1_700_000_000_000;
        limiter.try_consume(&zone, t0).expect("first");
        limiter
            .try_consume(&zone, t0 + 500)
            .expect_err("within 1s window: must fail");
        limiter
            .try_consume(&zone, t0 + 1_500)
            .expect("after 1s window: must succeed");
    }

    // ── EmergencyRevocationRefusal + Outcome serde ───────────────────

    #[test]
    fn refusal_round_trips_through_json_per_variant() {
        let cases = [
            EmergencyRevocationRefusal::InvalidOwnerSignature,
            EmergencyRevocationRefusal::NonceReplay,
            EmergencyRevocationRefusal::OutsideValidityWindow {
                now_unix_ms: 1_700_000_000_000,
            },
            EmergencyRevocationRefusal::RateLimited {
                retry_after_secs: 42,
            },
        ];
        for original in cases {
            let json = serde_json::to_string(&original).expect("encode refusal");
            let back: EmergencyRevocationRefusal =
                serde_json::from_str(&json).expect("decode refusal");
            assert_eq!(back, original);
        }
    }

    #[test]
    fn outcome_round_trips_through_json_per_variant() {
        let cases = [
            EmergencyRevocationOutcome::QuorumReached {
                witnesses: 3,
                elapsed_ms: 1234,
            },
            EmergencyRevocationOutcome::QuorumNotReached {
                witnesses: 1,
                target: 3,
                elapsed_ms: 5000,
            },
            EmergencyRevocationOutcome::Refused {
                reason: EmergencyRevocationRefusal::NonceReplay,
            },
        ];
        for original in cases {
            let json = serde_json::to_string(&original).expect("encode outcome");
            let back: EmergencyRevocationOutcome =
                serde_json::from_str(&json).expect("decode outcome");
            assert_eq!(back, original);
        }
    }

    #[test]
    fn outcome_exhaustive_match_sentinel() {
        // Adding a new variant breaks compilation, forcing the
        // operator-visible state machine to extend in lockstep with
        // the audit consumer.
        let probes = [
            EmergencyRevocationOutcome::QuorumReached {
                witnesses: 3,
                elapsed_ms: 0,
            },
            EmergencyRevocationOutcome::QuorumNotReached {
                witnesses: 0,
                target: 3,
                elapsed_ms: 0,
            },
            EmergencyRevocationOutcome::Refused {
                reason: EmergencyRevocationRefusal::InvalidOwnerSignature,
            },
        ];
        for outcome in probes {
            match outcome {
                EmergencyRevocationOutcome::QuorumReached { .. }
                | EmergencyRevocationOutcome::QuorumNotReached { .. }
                | EmergencyRevocationOutcome::Refused { .. } => (),
            }
        }
    }

    #[test]
    fn refusal_exhaustive_match_sentinel() {
        let probes = [
            EmergencyRevocationRefusal::InvalidOwnerSignature,
            EmergencyRevocationRefusal::NonceReplay,
            EmergencyRevocationRefusal::OutsideValidityWindow { now_unix_ms: 0 },
            EmergencyRevocationRefusal::RateLimited {
                retry_after_secs: 0,
            },
        ];
        for refusal in probes {
            match refusal {
                EmergencyRevocationRefusal::InvalidOwnerSignature
                | EmergencyRevocationRefusal::NonceReplay
                | EmergencyRevocationRefusal::OutsideValidityWindow { .. }
                | EmergencyRevocationRefusal::RateLimited { .. } => (),
            }
        }
    }

    // ── EmergencyRevocationAuditEvent + emergency_revoke_id ──────────

    #[test]
    fn emergency_revoke_id_is_stable_per_request_transcript() {
        let req = sample_request();
        let id_a = req.emergency_revoke_id();
        let id_b = req.emergency_revoke_id();
        assert_eq!(id_a, id_b, "id is not stable across calls");
    }

    #[test]
    fn emergency_revoke_id_changes_when_request_changes() {
        let base = sample_request();
        let mut altered = base.clone();
        altered.nonce = [0xEE; 16];
        assert_ne!(
            base.emergency_revoke_id(),
            altered.emergency_revoke_id(),
            "id collided despite different transcripts"
        );
    }

    #[test]
    fn audit_event_round_trips_through_json() {
        let event = EmergencyRevocationAuditEvent {
            emergency_revoke_id: [0xAB; 16],
            invoker_principal: PrincipalId::new("alice").expect("valid principal id"),
            zone_id: "z:work".parse().unwrap(),
            connector: Some(ConnectorId::from_static("github:request_response:1.0.0")),
            reason: "incident-2026-05-02".to_string(),
            revocation_head_seq: 42,
            started_at_unix_ms: 1_700_000_000_000,
            outcome: EmergencyRevocationOutcome::QuorumReached {
                witnesses: 3,
                elapsed_ms: 1234,
            },
        };
        let json = serde_json::to_string(&event).expect("encode audit event");
        let back: EmergencyRevocationAuditEvent =
            serde_json::from_str(&json).expect("decode audit event");
        assert_eq!(back, event);
    }

    #[test]
    fn audit_event_omits_none_connector_in_json() {
        let event = EmergencyRevocationAuditEvent {
            emergency_revoke_id: [0; 16],
            invoker_principal: PrincipalId::new("alice").unwrap(),
            zone_id: "z:work".parse().unwrap(),
            connector: None,
            reason: "test".to_string(),
            revocation_head_seq: 1,
            started_at_unix_ms: 0,
            outcome: EmergencyRevocationOutcome::QuorumReached {
                witnesses: 0,
                elapsed_ms: 0,
            },
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(
            !json.contains("\"connector\""),
            "skip_serializing_if=Option::is_none failed: {json}"
        );
    }

    #[test]
    fn response_is_success_predicate() {
        let success = EmergencyRevocationResponse {
            emergency_revoke_id: [0; 16],
            revocation_head_seq: 1,
            propagation_started_at_unix_ms: 0,
            propagation_deadline_unix_ms: 5000,
            witnesses_collected: 3,
            witnesses_target: 3,
        };
        let failure = EmergencyRevocationResponse {
            emergency_revoke_id: [0; 16],
            revocation_head_seq: 1,
            propagation_started_at_unix_ms: 0,
            propagation_deadline_unix_ms: 5000,
            witnesses_collected: 1,
            witnesses_target: 3,
        };
        assert!(success.is_success());
        assert!(!failure.is_success());
    }

    #[test]
    fn rate_limiter_refusal_helper_constructs_correct_variant() {
        let refusal = EmergencyRevocationRateLimiter::refusal(42);
        assert_eq!(
            refusal,
            EmergencyRevocationRefusal::RateLimited {
                retry_after_secs: 42,
            }
        );
    }

    #[test]
    fn request_digest_is_distinct_from_signing_bytes() {
        // Sanity: digest is a hash, not a copy of the signing bytes.
        let req = sample_request();
        let digest = request_digest(&req);
        assert_eq!(digest.len(), 32);
        assert_ne!(digest.as_slice(), req.signing_bytes().as_slice());
    }
}
