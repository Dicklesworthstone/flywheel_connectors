//! Wesolowski VDF rate-limit gate for owner-key operations (`flywheel_connectors-angoc.17.5`).
//!
//! Enforces an hourly rate cap (default `100` operations/hour) and requires every
//! owner-key action to carry a valid [`VdfProof`] evaluated at the configured delay
//! parameter $T$. Invalid or mutated proofs trigger an audit-chain alert and route
//! the operation to the manual-approval fallback path.

use std::collections::{BTreeSet, VecDeque};

use fcp_crypto::vdf::{DEFAULT_OWNER_KEY_VDF_ITERATIONS, VdfProof, WesolowskiVdf};
use serde::{Deserialize, Serialize};

/// Default hourly cap on owner-key operations (`100` actions/hour).
pub const DEFAULT_OWNER_KEY_HOURLY_CAP: usize = 100;

/// Sliding window duration in seconds (1 hour).
const ONE_HOUR_SECS: u64 = 3_600;

/// Submission of an owner-key operation protected by a Wesolowski VDF proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnerKeyVdfSubmission {
    /// Owner principal identifier.
    pub owner_id: String,
    /// Owner-key operation name (e.g. `"owner.rotate_zone_key"`).
    pub operation: String,
    /// Unix timestamp (seconds) when the operation was submitted.
    pub timestamp_secs: u64,
    /// Domain-separated challenge bytes bound to the operation payload.
    pub challenge: Vec<u8>,
    /// Attached Wesolowski VDF proof.
    pub proof: VdfProof,
}

/// Audit alert emitted when the owner-key VDF rate gate rejects an operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerKeyRateAuditAlert {
    /// Alert kind (`"rate_cap_exceeded"`, `"invalid_vdf_proof"`, `"stale_or_replayed_vdf"`).
    pub kind: String,
    /// Owner principal identifier.
    pub owner_id: String,
    /// Operation name.
    pub operation: String,
    /// Timestamp (seconds) of the rejected attempt.
    pub timestamp_secs: u64,
    /// Human-readable reason.
    pub detail: String,
    /// Whether the operation falls back to the manual-approval path.
    pub fallback_manual_approve: bool,
}

/// Decision returned by [`OwnerKeyVdfRateGate::submit`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OwnerKeyGateDecision {
    /// VDF proof verified and hourly cap not exceeded.
    Accepted {
        /// Verification latency in microseconds.
        verify_us: u64,
        /// Number of accepted operations in the current 1-hour sliding window.
        ops_in_last_hour: usize,
    },
    /// Rejected because the hourly cap (`hourly_cap`) has been reached.
    RejectedRateCapExceeded {
        /// Current accepted count in the 1-hour window.
        ops_in_last_hour: usize,
        /// Configured hourly cap.
        hourly_cap: usize,
        /// Emitted audit alert.
        alert: OwnerKeyRateAuditAlert,
    },
    /// Rejected because the VDF proof failed verification; falls back to manual approval.
    RejectedInvalidVdf {
        /// Verification failure reason.
        reason: String,
        /// Always `true` — mutated/invalid VDF proofs fall back to manual approval.
        fallback_manual_approve: bool,
        /// Emitted audit alert.
        alert: OwnerKeyRateAuditAlert,
    },
    /// Rejected because the VDF challenge was already consumed or timestamp is stale.
    RejectedStaleOrReplayedVdf {
        /// Rejection reason.
        reason: String,
        /// Emitted audit alert.
        alert: OwnerKeyRateAuditAlert,
    },
}

impl OwnerKeyGateDecision {
    /// Returns `true` if the submission was accepted.
    #[must_use]
    pub const fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted { .. })
    }
}

/// Doctor probe output for `fwc doctor --probe vdf_rate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VdfRateDoctorReport {
    /// Accepted owner-key operations in the last hour.
    pub ops_last_hour: usize,
    /// Required VDF delay parameter $T$.
    #[serde(rename = "vdf_T_required")]
    pub vdf_t_required: u64,
    /// Configured baseline evaluation time in milliseconds.
    pub baseline_eval_ms: u64,
    /// Number of times the rate/proof gate triggered a rejection.
    pub gate_triggered_count: u64,
    /// Whether any warning threshold is active.
    pub warning: bool,
    /// Recommended operator remediation commands.
    pub commands: Vec<String>,
}

/// Sliding-window Wesolowski VDF rate limiter for owner-key operations.
#[derive(Debug, Clone)]
pub struct OwnerKeyVdfRateGate {
    hourly_cap: usize,
    required_iterations: u64,
    baseline_eval_ms: u64,
    accepted_window: VecDeque<(u64, [u8; 32])>,
    seen_challenges: BTreeSet<[u8; 32]>,
    gate_triggered_count: u64,
    audit_alerts: Vec<OwnerKeyRateAuditAlert>,
    last_observed_eval_ms: Option<u64>,
}

impl Default for OwnerKeyVdfRateGate {
    fn default() -> Self {
        Self::new(
            DEFAULT_OWNER_KEY_HOURLY_CAP,
            DEFAULT_OWNER_KEY_VDF_ITERATIONS,
            100,
        )
    }
}

impl OwnerKeyVdfRateGate {
    /// Create a new [`OwnerKeyVdfRateGate`].
    #[must_use]
    pub const fn new(
        hourly_cap: usize,
        required_iterations: u64,
        baseline_eval_ms: u64,
    ) -> Self {
        Self {
            hourly_cap,
            required_iterations,
            baseline_eval_ms,
            accepted_window: VecDeque::new(),
            seen_challenges: BTreeSet::new(),
            gate_triggered_count: 0,
            audit_alerts: Vec::new(),
            last_observed_eval_ms: None,
        }
    }

    /// Borrow all emitted audit alerts.
    #[must_use]
    pub fn audit_alerts(&self) -> &[OwnerKeyRateAuditAlert] {
        &self.audit_alerts
    }

    /// Number of times the gate has rejected an operation.
    #[must_use]
    pub const fn gate_triggered_count(&self) -> u64 {
        self.gate_triggered_count
    }

    fn evict_expired(&mut self, now_secs: u64) {
        let cutoff = now_secs.saturating_sub(ONE_HOUR_SECS);
        while let Some(&(ts, digest)) = self.accepted_window.front() {
            if ts < cutoff {
                self.accepted_window.pop_front();
                self.seen_challenges.remove(&digest);
            } else {
                break;
            }
        }
    }

    /// Verify and admit or reject an [`OwnerKeyVdfSubmission`].
    pub fn submit(&mut self, submission: &OwnerKeyVdfSubmission) -> OwnerKeyGateDecision {
        let now_secs = submission.timestamp_secs;
        self.evict_expired(now_secs);

        let challenge_digest = *blake3::hash(&submission.challenge).as_bytes();
        if self.seen_challenges.contains(&challenge_digest) {
            self.gate_triggered_count += 1;
            let alert = OwnerKeyRateAuditAlert {
                kind: "stale_or_replayed_vdf".to_owned(),
                owner_id: submission.owner_id.clone(),
                operation: submission.operation.clone(),
                timestamp_secs: now_secs,
                detail: "VDF challenge was already consumed within the active window".to_owned(),
                fallback_manual_approve: true,
            };
            self.audit_alerts.push(alert.clone());
            return OwnerKeyGateDecision::RejectedStaleOrReplayedVdf {
                reason: alert.detail.clone(),
                alert,
            };
        }

        if self.accepted_window.len() >= self.hourly_cap {
            self.gate_triggered_count += 1;
            let alert = OwnerKeyRateAuditAlert {
                kind: "rate_cap_exceeded".to_owned(),
                owner_id: submission.owner_id.clone(),
                operation: submission.operation.clone(),
                timestamp_secs: now_secs,
                detail: format!(
                    "owner-key hourly rate cap exceeded ({}/{})",
                    self.accepted_window.len(),
                    self.hourly_cap
                ),
                fallback_manual_approve: true,
            };
            self.audit_alerts.push(alert.clone());
            return OwnerKeyGateDecision::RejectedRateCapExceeded {
                ops_in_last_hour: self.accepted_window.len(),
                hourly_cap: self.hourly_cap,
                alert,
            };
        }

        match WesolowskiVdf::verify(
            &submission.challenge,
            self.required_iterations,
            &submission.proof,
        ) {
            Ok(verify_elapsed) => {
                let verify_us = u64::try_from(verify_elapsed.as_micros()).unwrap_or(u64::MAX);
                self.accepted_window.push_back((now_secs, challenge_digest));
                self.seen_challenges.insert(challenge_digest);
                self.last_observed_eval_ms = Some(submission.proof.eval_ms);
                tracing::info!(
                    op = %submission.operation,
                    T = self.required_iterations,
                    eval_ms = submission.proof.eval_ms,
                    verify_us = verify_us,
                    accepted = true,
                    "accepted owner-key operation with valid Wesolowski VDF proof"
                );
                OwnerKeyGateDecision::Accepted {
                    verify_us,
                    ops_in_last_hour: self.accepted_window.len(),
                }
            }
            Err(err) => {
                self.gate_triggered_count += 1;
                let reason = err.to_string();
                let alert = OwnerKeyRateAuditAlert {
                    kind: "invalid_vdf_proof".to_owned(),
                    owner_id: submission.owner_id.clone(),
                    operation: submission.operation.clone(),
                    timestamp_secs: now_secs,
                    detail: reason.clone(),
                    fallback_manual_approve: true,
                };
                self.audit_alerts.push(alert.clone());
                tracing::warn!(
                    op = %submission.operation,
                    T = self.required_iterations,
                    eval_ms = submission.proof.eval_ms,
                    verify_us = 0u64,
                    accepted = false,
                    "rejected owner-key operation with invalid Wesolowski VDF proof; falling back to manual approve"
                );
                OwnerKeyGateDecision::RejectedInvalidVdf {
                    reason,
                    fallback_manual_approve: true,
                    alert,
                }
            }
        }
    }

    /// Generate a doctor probe report (`fwc doctor --probe vdf_rate`).
    #[must_use]
    pub fn doctor_report(&self) -> VdfRateDoctorReport {
        let ops_last_hour = self.accepted_window.len();
        let drift_warning = self.last_observed_eval_ms.is_some_and(|observed| {
            observed > self.baseline_eval_ms.saturating_mul(2)
                || observed.saturating_mul(2) < self.baseline_eval_ms
        });
        let warning =
            self.gate_triggered_count > 0 || ops_last_hour > self.hourly_cap || drift_warning;
        VdfRateDoctorReport {
            ops_last_hour,
            vdf_t_required: self.required_iterations,
            baseline_eval_ms: self.baseline_eval_ms,
            gate_triggered_count: self.gate_triggered_count,
            warning,
            commands: vec![
                "fwc owner-key audit --since 1h".to_owned(),
                "fwc vdf recalibrate".to_owned(),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use fcp_crypto::vdf::VdfParams;

    use super::*;

    #[test]
    fn test_rate_limit_enforced() {
        let iterations = 64;
        let mut gate = OwnerKeyVdfRateGate::new(100, iterations, 1);
        let mut accepted = 0usize;
        let mut rejected = 0usize;

        for idx in 0..200u64 {
            let challenge = format!("owner-op-burst-{idx}").into_bytes();
            let proof = WesolowskiVdf::eval(
                &challenge,
                VdfParams::new(iterations).with_calibrated_floor_ms(0),
            )
            .expect("eval succeeds");
            let submission = OwnerKeyVdfSubmission {
                owner_id: "owner:alice".to_owned(),
                operation: "owner.rotate_key".to_owned(),
                timestamp_secs: 1_700_000_000 + idx,
                challenge,
                proof,
            };
            match gate.submit(&submission) {
                OwnerKeyGateDecision::Accepted { .. } => accepted += 1,
                OwnerKeyGateDecision::RejectedRateCapExceeded { .. } => rejected += 1,
                other => panic!("unexpected decision: {other:?}"),
            }
        }

        assert_eq!(accepted, 100, "exactly 100 ops/h must be accepted");
        assert_eq!(rejected, 100, "remaining 100 ops in burst must be rejected");
        assert_eq!(gate.gate_triggered_count(), 100);
        assert_eq!(gate.audit_alerts().len(), 100);
        assert!(gate.doctor_report().warning);
    }

    #[test]
    fn test_mutated_proof_rejected_with_manual_approve_fallback() {
        let iterations = 64;
        let mut gate = OwnerKeyVdfRateGate::new(100, iterations, 1);
        let challenge = b"owner-op-tamper-test".to_vec();
        let mut proof = WesolowskiVdf::eval(
            &challenge,
            VdfParams::new(iterations).with_calibrated_floor_ms(0),
        )
        .expect("eval succeeds");
        proof.pi[0] ^= 0x80;

        let submission = OwnerKeyVdfSubmission {
            owner_id: "owner:alice".to_owned(),
            operation: "owner.grant_root".to_owned(),
            timestamp_secs: 1_700_000_100,
            challenge,
            proof,
        };
        let decision = gate.submit(&submission);
        match decision {
            OwnerKeyGateDecision::RejectedInvalidVdf {
                fallback_manual_approve,
                alert,
                ..
            } => {
                assert!(fallback_manual_approve);
                assert_eq!(alert.kind, "invalid_vdf_proof");
            }
            other => panic!("expected RejectedInvalidVdf, got {other:?}"),
        }
    }
}
