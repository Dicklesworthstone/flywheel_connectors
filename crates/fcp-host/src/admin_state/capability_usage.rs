//! Executor-local, durable accounting for signed capability usage ceilings.
//!
//! Invocation admission spends a call and the deterministic-CBOR input size in
//! the same snapshot transaction as its invocation ticket. Stream controls debit
//! the same account before changing custody or dispatching provider work.
//! Nothing refunds these debits: cancellation, a missing reply, or a crash may
//! follow an external effect. Before releasing an invocation response, the host
//! also debits its complete compact-JSON envelope against the same signed byte
//! ceiling. Response settlement is once per exact attempt, including optional
//! sampling enrichment and executor-local routing metadata, and does not refund
//! an admission. Provider traffic, event payloads, remote origin routing metadata
//! and repeated operator recovery reads are not metered here. Accounts are not
//! mesh-wide quotas.
//! Persistence follows the containing store: explicit in-memory stores retain
//! counters only for that store's lifetime. A persisted observed-time high-water
//! allows expired accounts to be reclaimed without allowing a backward clock
//! adjustment to restore their authority. At most 4,096 live limited identities
//! are retained; live grants are never evicted to admit a new grant.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::sync::atomic::Ordering;

use chrono::{DateTime, Utc};
use fcp_crypto::{
    canonicalize::to_deterministic_cbor,
    cose::{cwt_claims, fcp2_claims},
    ed25519::Ed25519VerifyingKey,
};
use fcp_kernel::{InvokeRequest, InvokeResponse, InvokeStatus, LifecycleError, UsageBudgetPolicy};
use fcp_prelude::CapabilityConstraints;
use serde::{Deserialize, Serialize};

use super::{HostAdminStateStore, InvocationAdmission, InvocationOutcome, InvocationTicket};
use crate::{HostError, HostResult};

const MAX_TRACKED_CAPABILITY_GRANTS: usize = 4096;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(super) struct CapabilityUsageLedger {
    observed_at_unix_secs: i64,
    accounts: BTreeMap<String, CapabilityUsageAccount>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CapabilityUsageAccount {
    grant_digest: String,
    calls: u64,
    input_bytes: u64,
    #[serde(default)]
    response_bytes: u64,
    max_calls: Option<u32>,
    max_input_bytes: Option<u64>,
    expires_at_unix_secs: i64,
}

/// Only verified, canonical signed claims can construct an accounting scope.
pub(super) struct CapabilityUsageScope {
    key: Option<String>,
    grant_digest: String,
    input_bytes: u64,
    max_calls: Option<u32>,
    max_input_bytes: Option<u64>,
    expires_at: i64,
    not_before: Option<i64>,
}


/// Signed byte authority captured with an exact invocation admission.
///
/// This contains only opaque grant/account digests and accounting metadata.
/// Absence on a historical record does not establish response accounting. New
/// byte-limited admissions always persist this binding before connector work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationResponseBudget {
    account_key: String,
    grant_digest: String,
    max_bytes: u64,
    expires_at_unix_secs: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    settlement: Option<ResponseSettlement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum ResponseSettlement {
    Allowed { bytes: u64, digest: String },
    Denied,
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn response_denied() -> HostError {
    HostError::RegistryError(
        "invocation response withheld by signed capability byte accounting; connector work may have completed; inspect the exact invocation attempt before retrying"
            .to_owned(),
    )
}

/// Count and bind the actual serialized envelope without allocating a copy of
/// its payload. Stop immediately when even the entire grant cannot cover it.
fn response_measurement(response: &InvokeResponse, limit: u64) -> Option<(u64, String)> {
    struct Meter {
        bytes: u64,
        limit: u64,
        hash: blake3::Hasher,
    }

    impl Write for Meter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            let length = u64::try_from(buffer.len())
                .map_err(|_| io::Error::other("response byte count overflow"))?;
            let next = self
                .bytes
                .checked_add(length)
                .filter(|next| *next <= self.limit)
                .ok_or_else(|| io::Error::other("response byte limit exceeded"))?;
            self.hash.update(buffer);
            self.bytes = next;
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let mut meter = Meter {
        bytes: 0,
        limit,
        hash: blake3::Hasher::new(),
    };
    meter.hash.update(b"FCP-HOST-CAPABILITY-RESPONSE-V1");
    serde_json::to_writer(&mut meter, response).ok()?;
    Some((meter.bytes, meter.hash.finalize().to_hex().to_string()))
}

impl InvocationResponseBudget {
    /// Whether this exact attempt has a persisted, allowed response settlement.
    #[must_use]
    pub const fn is_settled(&self) -> bool {
        matches!(self.settlement, Some(ResponseSettlement::Allowed { .. }))
    }

    /// Verify that response custody contains exactly the envelope charged at
    /// settlement. Reading a retained result does not debit the invocation again.
    ///
    /// # Errors
    /// Rejects unsettled/denied budgets, malformed bindings, or a different
    /// envelope even if the replacement has the same serialized byte count.
    pub fn validate_response(&self, response: &InvokeResponse) -> HostResult<()> {
        self.validate()?;
        if let Some(ResponseSettlement::Allowed { bytes, digest }) = &self.settlement
            && response_measurement(response, *bytes)
                .is_some_and(|(actual, hash)| actual == *bytes && hash == *digest)
        {
            return Ok(());
        }
        Err(response_denied())
    }

    pub(super) fn validate(&self) -> HostResult<()> {
        if !valid_digest(&self.account_key)
            || !valid_digest(&self.grant_digest)
            || self.expires_at_unix_secs <= 0
            || self.settlement.as_ref().is_some_and(|settlement| match settlement {
                ResponseSettlement::Allowed { bytes, digest } => {
                    *bytes == 0 || *bytes > self.max_bytes || !valid_digest(digest)
                }
                ResponseSettlement::Denied => false,
            })
        {
            return Err(response_denied());
        }
        Ok(())
    }
}

fn denied(reason: &str) -> HostError {
    HostError::PreflightFailed(reason.to_owned())
}

fn policy_denied(reason: &str) -> LifecycleError {
    LifecycleError::InvalidPolicy {
        reason: reason.to_owned(),
    }
}

impl CapabilityUsageScope {
    pub(super) fn response_budget(&self) -> Option<InvocationResponseBudget> {
        self.max_input_bytes.map(|max_bytes| InvocationResponseBudget {
            // from_request() refuses byte-limited grants without this identity.
            account_key: self.key.clone().expect("verified limited grant identity"),
            grant_digest: self.grant_digest.clone(),
            max_bytes,
            expires_at_unix_secs: self.expires_at,
            settlement: None,
        })
    }

    fn from_request(
        request: &InvokeRequest,
        verifying_key: &Ed25519VerifyingKey,
        principal: &str,
    ) -> HostResult<Self> {
        // Do not accept caller-supplied limits, unverified claims, an unsigned
        // issuer name, or mutable COSE headers as accounting authority.
        let claims = request
            .capability_token
            .raw()
            .verify(verifying_key)
            .map_err(|_| denied("capability usage requires a valid token signature"))?;
        if claims.get_subject().or_else(|| claims.get_principal_id()) != Some(principal)
            || claims.get_zone_id() != Some(request.zone_id.as_str())
        {
            return Err(denied(
                "capability usage principal or zone does not match the signed grant",
            ));
        }
        let raw_constraints = claims
            .get(fcp2_claims::CONSTRAINTS)
            .ok_or_else(|| denied("capability usage requires signed constraints"))?;
        let mut encoded = Vec::new();
        ciborium::into_writer(raw_constraints, &mut encoded)
            .map_err(|_| denied("cannot decode signed capability usage constraints"))?;
        let constraints: CapabilityConstraints = ciborium::from_reader(encoded.as_slice())
            .map_err(|_| denied("cannot decode signed capability usage constraints"))?;
        let key = claims.get_jti().filter(|id| !id.is_empty()).map(|id| {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"FCP-HOST-CAPABILITY-USAGE-ID-V1");
            hasher.update(&verifying_key.to_bytes());
            hasher.update(id);
            hasher.finalize().to_hex().to_string()
        });
        if (constraints.max_calls.is_some() || constraints.max_bytes.is_some()) && key.is_none() {
            return Err(denied(
                "a usage-limited capability requires a non-empty signed token ID",
            ));
        }
        let canonical = claims
            .to_cbor()
            .map_err(|_| denied("cannot identify the signed capability grant"))?;
        let input = to_deterministic_cbor(&request.input)
            .map_err(|_| denied("cannot meter deterministic-CBOR invocation input"))?;
        let not_before = claims.get_not_before();
        if claims.get(cwt_claims::NBF).is_some() && not_before.is_none() {
            return Err(denied(
                "capability usage not-before claim must be an integer timestamp",
            ));
        }
        Ok(Self {
            key,
            grant_digest: blake3::hash(&canonical).to_hex().to_string(),
            input_bytes: u64::try_from(input.len())
                .map_err(|_| denied("invocation input byte count overflowed"))?,
            max_calls: constraints.max_calls,
            max_input_bytes: constraints.max_bytes,
            expires_at: claims
                .get_expiration()
                .ok_or_else(|| denied("capability usage requires a signed expiration"))?,
            not_before,
        })
    }

    fn check_time(&self, now_unix_secs: i64) -> Result<(), LifecycleError> {
        if now_unix_secs >= self.expires_at
            || self.not_before.is_some_and(|start| now_unix_secs < start)
        {
            return Err(policy_denied(
                "capability validity window elapsed before usage admission",
            ));
        }
        Ok(())
    }
}

impl CapabilityUsageLedger {

    /// A refusal is a successful state transition so it survives restart. An
    /// expired/pruned grant is never recreated, and conflicting repeat calls
    /// cannot replace either an allowed response or a recorded denial.
    fn settle_response(
        &mut self,
        budget: &mut InvocationResponseBudget,
        measurement: Option<&(u64, String)>,
        now: DateTime<Utc>,
    ) -> bool {
        if let Some(previous) = &budget.settlement {
            return match (previous, measurement) {
                (ResponseSettlement::Allowed { bytes, digest }, Some((actual, hash))) => {
                    bytes == actual && digest == hash
                }
                _ => false,
            };
        }
        let effective_now = now.timestamp().max(self.observed_at_unix_secs);
        self.observed_at_unix_secs = effective_now;
        self.accounts
            .retain(|_, account| account.expires_at_unix_secs > effective_now);
        let allowed = measurement.is_some_and(|(bytes, _)| {
            let Some(account) = self.accounts.get_mut(&budget.account_key) else {
                return false;
            };
            if account.grant_digest != budget.grant_digest
                || account.max_input_bytes != Some(budget.max_bytes)
                || account.expires_at_unix_secs != budget.expires_at_unix_secs
                || effective_now >= budget.expires_at_unix_secs
            {
                return false;
            }
            let Some(next_response_bytes) = account.response_bytes.checked_add(*bytes) else {
                return false;
            };
            if account
                .input_bytes
                .checked_add(next_response_bytes)
                .is_none_or(|total| total > budget.max_bytes)
            {
                return false;
            }
            account.response_bytes = next_response_bytes;
            true
        });
        budget.settlement = Some(if allowed {
            let (bytes, digest) = measurement.expect("allowed response was measured");
            ResponseSettlement::Allowed {
                bytes: *bytes,
                digest: digest.clone(),
            }
        } else {
            ResponseSettlement::Denied
        });
        allowed
    }

    pub(super) fn is_empty(&self) -> bool {
        self.accounts.is_empty() && self.observed_at_unix_secs == 0
    }

    pub(super) fn validate(&self) -> HostResult<()> {
        if self.observed_at_unix_secs < 0
            || self.accounts.len() > MAX_TRACKED_CAPABILITY_GRANTS
            || self.accounts.iter().any(|(key, account)| {
                !valid_digest(key)
                    || !valid_digest(&account.grant_digest)
                    || account.calls == 0
                    || account.expires_at_unix_secs <= self.observed_at_unix_secs
                    || (account.max_calls.is_none() && account.max_input_bytes.is_none())
                    || account
                        .max_calls
                        .is_some_and(|limit| account.calls > u64::from(limit))
                    || account
                        .max_input_bytes
                        .is_some_and(|limit| {
                            account
                                .input_bytes
                                .checked_add(account.response_bytes)
                                .is_none_or(|total| total > limit)
                        })
            })
        {
            return Err(HostError::Internal(
                "persisted capability usage ledger is inconsistent".to_owned(),
            ));
        }
        Ok(())
    }

    fn check(
        &self,
        scope: &CapabilityUsageScope,
        now: DateTime<Utc>,
    ) -> Result<(), LifecycleError> {
        let effective_now = now.timestamp().max(self.observed_at_unix_secs);
        scope.check_time(effective_now)?;
        let account = scope
            .key
            .as_ref()
            .and_then(|key| self.accounts.get(key))
            .filter(|account| account.expires_at_unix_secs > effective_now);
        if account.is_some_and(|account| {
            account.grant_digest != scope.grant_digest
                || account.max_calls != scope.max_calls
                || account.max_input_bytes != scope.max_input_bytes
                || account.expires_at_unix_secs != scope.expires_at
        }) {
            return Err(policy_denied(
                "signed token ID was reused for a different grant",
            ));
        }
        let calls = account
            .map_or(0, |account| account.calls)
            .checked_add(1)
            .ok_or_else(|| policy_denied("signed capability call budget exhausted"))?;
        if scope
            .max_calls
            .is_some_and(|limit| calls > u64::from(limit))
        {
            return Err(policy_denied("signed capability call budget exhausted"));
        }
        let input_bytes = account
            .map_or(0, |account| account.input_bytes)
            .checked_add(scope.input_bytes)
            .ok_or_else(|| policy_denied("signed capability input byte budget exhausted"))?;
        let total_bytes = input_bytes
            .checked_add(account.map_or(0, |account| account.response_bytes))
            .ok_or_else(|| policy_denied("signed capability byte budget exhausted"))?;
        if scope
            .max_input_bytes
            .is_some_and(|limit| total_bytes > limit)
        {
            return Err(policy_denied(
                "signed capability input byte budget exhausted",
            ));
        }
        if account.is_none()
            && (scope.max_calls.is_some() || scope.max_input_bytes.is_some())
            && self
                .accounts
                .values()
                .filter(|account| account.expires_at_unix_secs > effective_now)
                .count()
                >= MAX_TRACKED_CAPABILITY_GRANTS
        {
            return Err(policy_denied(
                "durable capability usage ledger capacity exhausted",
            ));
        }
        Ok(())
    }

    pub(super) fn reserve(
        &mut self,
        scope: &CapabilityUsageScope,
        now: DateTime<Utc>,
    ) -> Result<(), LifecycleError> {
        self.check(scope, now)?;
        // This high-water, pruning, quota debit and invocation ticket commit
        // together. After reclaiming an account, every subsequent admission
        // rejects its expired signed authority even if wall time moves back.
        let effective_now = now.timestamp().max(self.observed_at_unix_secs);
        self.observed_at_unix_secs = effective_now;
        self.accounts
            .retain(|_, account| account.expires_at_unix_secs > effective_now);
        if scope.max_calls.is_none() && scope.max_input_bytes.is_none() {
            return Ok(());
        }
        let key = scope
            .key
            .as_ref()
            .ok_or_else(|| policy_denied("usage-limited capability has no token ID"))?;
        let account = self
            .accounts
            .entry(key.clone())
            .or_insert_with(|| CapabilityUsageAccount {
                grant_digest: scope.grant_digest.clone(),
                calls: 0,
                input_bytes: 0,
                response_bytes: 0,
                max_calls: scope.max_calls,
                max_input_bytes: scope.max_input_bytes,
                expires_at_unix_secs: scope.expires_at,
            });
        // check() proved both additions fit and the resulting totals are
        // within the signed limits. History pruning never touches accounts.
        account.calls += 1;
        account.input_bytes += scope.input_bytes;
        Ok(())
    }
}

impl HostAdminStateStore {

    /// Debit the complete final response before returning or retaining it.
    ///
    /// The exact attempt carries its signed grant binding from admission; no
    /// caller-supplied byte count or replacement token is accepted. The charged
    /// unit is the compact JSON envelope, including error details and sampling
    /// enrichment, in addition to previously charged deterministic-CBOR input.
    /// Calls and input bytes are never refunded. A refusal is persisted and
    /// remains refused across restart; a repeated identical allowed settlement
    /// does not spend twice. Provider traffic, remote origin routing annotations
    /// and recovery downloads are outside this once-per-invocation boundary.
    ///
    /// # Errors
    /// Withholds output for an invalid response/ticket, an unknown source
    /// outcome, an exhausted/expired/missing grant, a conflicting settlement, or
    /// unavailable persistence. The recorded source outcome is left intact.
    pub async fn settle_capability_response(
        &self,
        ticket: &InvocationTicket,
        response: &InvokeResponse,
    ) -> HostResult<()> {
        if response.r#type != "response"
            || response.id.0 != ticket.operation_id
            || match response.status {
                InvokeStatus::Ok => response.result.is_none() || response.error.is_some(),
                InvokeStatus::Error => response.error.is_none() || response.result.is_some(),
            }
        {
            return Err(response_denied());
        }
        let binding = {
            let state = self.state.read().await;
            if self.persistence_failed.load(Ordering::Acquire) {
                return Err(response_denied());
            }
            let record = state
                .invocations
                .iter()
                .find(|record| record.ticket == *ticket)
                .ok_or_else(response_denied)?;
            let Some(budget) = &record.capability_response else {
                // Unlimited grants do not need an additional snapshot write.
                return Ok(());
            };
            budget.validate()?;
            if record.terminal.as_ref().is_none_or(|terminal| {
                !matches!(
                    terminal.outcome,
                    InvocationOutcome::Succeeded | InvocationOutcome::ConnectorError
                )
            }) {
                return Err(response_denied());
            }
            budget.clone()
        };
        // Serialization is bounded and outside the snapshot's write lock.
        let measurement = response_measurement(response, binding.max_bytes);
        let allowed = self
            .apply_mutation(|snapshot| {
                let record = snapshot
                    .invocations
                    .iter_mut()
                    .find(|record| record.ticket == *ticket)
                    .ok_or_else(|| policy_denied("unknown response settlement ticket"))?;
                let budget = record
                    .capability_response
                    .as_mut()
                    .ok_or_else(|| policy_denied("response admission binding is missing"))?;
                if budget.account_key != binding.account_key
                    || budget.grant_digest != binding.grant_digest
                    || budget.max_bytes != binding.max_bytes
                    || budget.expires_at_unix_secs != binding.expires_at_unix_secs
                    || record.terminal.as_ref().is_none_or(|terminal| {
                        !matches!(
                            terminal.outcome,
                            InvocationOutcome::Succeeded | InvocationOutcome::ConnectorError
                        )
                    })
                {
                    return Err(policy_denied("response admission binding changed"));
                }
                Ok(snapshot.capability_usage.settle_response(
                    budget,
                    measurement.as_ref(),
                    Utc::now(),
                ))
            })
            .await
            .map_err(|_| response_denied())?;
        if allowed { Ok(()) } else { Err(response_denied()) }
    }

    /// Check cumulative signed call and byte allowances without spending.
    ///
    /// This executor-local preview is not a reservation or complete request
    /// authorization. Live local dispatch repeats it atomically at admission;
    /// an origin that forwards to a peer must not charge its own ledger.
    ///
    /// # Errors
    /// Rejects invalid signed usage authority, exhausted quotas, conflicting
    /// signed token IDs, full accounting capacity, or unavailable persistence.
    pub async fn check_capability_usage(
        &self,
        request: &InvokeRequest,
        verifying_key: &Ed25519VerifyingKey,
        principal: &str,
    ) -> HostResult<()> {
        let scope = CapabilityUsageScope::from_request(request, verifying_key, principal)?;
        self.check_capability_usage_scope(&scope).await
    }

    async fn check_capability_usage_scope(&self, scope: &CapabilityUsageScope) -> HostResult<()> {
        let state = self.state.read().await;
        if self.persistence_failed.load(Ordering::Acquire) {
            return Err(HostError::Unavailable(
                "capability usage authority is unavailable after an admin-state persistence failure"
                    .to_owned(),
            ));
        }
        state
            .capability_usage
            .check(scope, Utc::now())
            .map_err(|error| match error {
                LifecycleError::InvalidPolicy { reason } => denied(&reason),
                other => HostError::Unavailable(other.to_string()),
            })
    }

    /// Reserve one authorized stream control's signed call and input allowance.
    ///
    /// This uses exactly the same executor-local account as invocation
    /// admission. The request input must contain the complete normalized control
    /// payload, without bearer tokens or transport metadata. The caller must
    /// independently authorize its operation, instance and retained ownership
    /// before reserving, then recheck live authority after this await and before
    /// changing custody or dispatching work. A forwarding origin must not debit
    /// its own account on behalf of the executor.
    ///
    /// A successful limited reservation is persisted before returning. It is
    /// never refunded, including when later validation, custody persistence,
    /// cancellation or delivery fails. The quota and event journals are separate
    /// stores: a lost reply can consume allowance without proving any effect.
    /// No invocation-history ticket is invented for a stream control. Ordinary
    /// invokes must use [`Self::admit_capability_invocation`] instead, which
    /// commits their ticket and debit together.
    ///
    /// Grants without a call or input-byte ceiling only read the ledger. An
    /// unlimited poll must not rewrite the entire admin snapshot, while prior
    /// persistence failures and conflicting retained token IDs still deny it.
    ///
    /// # Errors
    /// Rejects invalid signed scope, exhausted allowances, conflicting signed
    /// token IDs, full accounting capacity, or unavailable persistence.
    pub async fn reserve_capability_usage(
        &self,
        request: &InvokeRequest,
        verifying_key: &Ed25519VerifyingKey,
        principal: &str,
    ) -> HostResult<()> {
        let scope = CapabilityUsageScope::from_request(request, verifying_key, principal)?;
        if scope.max_calls.is_none() && scope.max_input_bytes.is_none() {
            return self.check_capability_usage_scope(&scope).await;
        }
        self.apply_mutation(|snapshot| snapshot.capability_usage.reserve(&scope, Utc::now()))
            .await
            .map_err(|error| match error {
                LifecycleError::InvalidPolicy { reason } => denied(&reason),
                other => HostError::Unavailable(other.to_string()),
            })
    }

    /// Persist a local invocation ticket and its signed usage debit atomically.
    ///
    /// The caller must first perform full live authorization. This method
    /// independently verifies the exact request's signature and binds its
    /// principal, zone and metadata before deriving quotas. Calls and canonical
    /// input bytes remain spent after every outcome, including uncertain work
    /// recovered on restart. Response authority is bound to the ticket here and
    /// debited by [`Self::settle_capability_response`] before delivery. Provider
    /// traffic is not metered here.
    /// Expired accounts are reclaimed using a persisted monotonic admission
    /// clock; a backward wall-clock adjustment or invocation-history pruning
    /// cannot refill previously spent authority. Live accounts are never evicted.
    ///
    /// # Errors
    /// Returns the ordinary invocation-admission errors or a preflight denial
    /// for invalid, mismatched, exhausted or conflicting signed usage authority.
    pub async fn admit_capability_invocation(
        &self,
        admission: InvocationAdmission,
        request: &InvokeRequest,
        verifying_key: &Ed25519VerifyingKey,
    ) -> HostResult<InvocationTicket> {
        self.admit_budgeted_capability_invocation(admission, request, verifying_key, None)
            .await
    }

    /// Atomically reserve configured zone requests, signed usage, and the ticket.
    ///
    /// The policy must come from trusted host zone configuration, never the
    /// request or connector. All checks share one snapshot transaction, so a
    /// refusal spends neither allowance. A committed request is never refunded.
    /// Other zone metrics remain once-only post-outcome observations.
    ///
    /// # Errors
    /// Returns invocation/capability admission failures, invalid zone policy,
    /// an exhausted projected request budget, or unavailable persistence.
    pub async fn admit_budgeted_capability_invocation(
        &self,
        admission: InvocationAdmission,
        request: &InvokeRequest,
        verifying_key: &Ed25519VerifyingKey,
        zone_budget: Option<&UsageBudgetPolicy>,
    ) -> HostResult<InvocationTicket> {
        if admission.operation_id != request.id.0.as_str()
            || admission.connector_id != request.connector_id.as_str()
            || admission.operation != request.operation.as_str()
            || admission.zone_id != request.zone_id.as_str()
        {
            return Err(denied(
                "capability usage admission does not match the invocation",
            ));
        }
        let scope =
            CapabilityUsageScope::from_request(request, verifying_key, &admission.principal)?;
        self.admit_invocation_with_usage(admission, Some(scope), zone_budget)
            .await
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
    use fcp_kernel::{ConnectorId, RequestId};
    use fcp_prelude::{CapabilityToken, OperationId, ZoneId};

    use super::*;
    use crate::{InvocationOutcome, InvocationTerminal};

    fn signed_request(
        signing_key: &Ed25519SigningKey,
        token_id: &[u8],
        max_calls: Option<u32>,
        max_bytes: Option<u64>,
    ) -> InvokeRequest {
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".to_owned()],
            max_calls,
            max_bytes,
            ..Default::default()
        };
        let mut encoded = Vec::new();
        ciborium::into_writer(&constraints, &mut encoded).unwrap();
        let now = Utc::now();
        InvokeRequest {
            r#type: "invoke".to_owned(),
            id: RequestId::new("usage-first"),
            connector_id: ConnectorId::from_static("fcp.test.usage:utility:1.0.0"),
            operation: OperationId::from_static("fixture.get"),
            zone_id: ZoneId::work(),
            input: serde_json::json!({ "value": "usage-secret-input" }),
            capability_token: CapabilityToken::from_raw(
                CapabilityTokenBuilder::new()
                    .capability_id("fixture.read")
                    .zone_id("z:work")
                    .principal("user:test")
                    .issuer("node:test")
                    .audience("*")
                    .operations(&["fixture.get", "fixture.list"])
                    .token_id(token_id)
                    .validity(now - Duration::minutes(1), now + Duration::hours(1))
                    .try_constraints_cbor(&encoded)
                    .unwrap()
                    .sign(signing_key)
                    .unwrap(),
            ),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        }
    }

    fn signing_key() -> Ed25519SigningKey {
        Ed25519SigningKey::from_bytes(&[61; 32]).unwrap()
    }

    fn request(max_calls: Option<u32>, max_bytes: Option<u64>) -> InvokeRequest {
        signed_request(
            &signing_key(),
            b"usage-private-token-id",
            max_calls,
            max_bytes,
        )
    }

    fn admission(request: &InvokeRequest) -> InvocationAdmission {
        InvocationAdmission {
            operation_id: request.id.to_string(),
            connector_id: request.connector_id.to_string(),
            operation: request.operation.to_string(),
            zone_id: request.zone_id.to_string(),
            principal: "user:test".to_owned(),
            correlation_id: None,
            deadline_at: Utc::now() + Duration::minutes(1),
            idempotency: None,
            transport_idempotency: None,
        }
    }

    fn scope(request: &InvokeRequest) -> CapabilityUsageScope {
        CapabilityUsageScope::from_request(request, &signing_key().verifying_key(), "user:test")
            .unwrap()
    }

    fn request_expiring_at(mut request: InvokeRequest, expires_at: DateTime<Utc>) -> InvokeRequest {
        let claims = request
            .capability_token
            .raw()
            .verify(&signing_key().verifying_key())
            .unwrap()
            .expiration(expires_at);
        request.capability_token = CapabilityToken::from_raw(
            fcp_crypto::cose::CoseToken::sign(&signing_key(), &claims).unwrap(),
        );
        request
    }


    fn response(request: &InvokeRequest, text: &str) -> InvokeResponse {
        InvokeResponse::ok(request.id.clone(), serde_json::json!({ "text": text }))
    }

    async fn finish_source(store: &HostAdminStateStore, ticket: &InvocationTicket) {
        store
            .finish_invocation(
                ticket,
                InvocationTerminal {
                    outcome: InvocationOutcome::Succeeded,
                    receipt_id: None,
                    duration_ms: 1,
                    http_status: 200,
                },
            )
            .await
            .unwrap();
    }

    #[test]
    fn response_meter_counts_the_complete_json_envelope_and_binds_its_contents() {
        let request = request(None, Some(10_000));
        let response = response(&request, "escaped \"text\" and unicode \u{1f680}");
        let bytes = u64::try_from(serde_json::to_vec(&response).unwrap().len()).unwrap();
        let measured = response_measurement(&response, bytes).unwrap();
        assert_eq!(measured.0, bytes);
        assert!(response_measurement(&response, bytes - 1).is_none());
        let mut budget = scope(&request).response_budget().unwrap();
        assert!(!budget.is_settled());
        assert!(budget.validate_response(&response).is_err());
        budget.settlement = Some(ResponseSettlement::Allowed {
            bytes,
            digest: measured.1,
        });
        budget.validate_response(&response).unwrap();
        let mut changed = response.clone();
        changed.result = Some(serde_json::json!({ "text": "different" }));
        assert!(budget.validate_response(&changed).is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn response_settlement_is_durable_exact_and_once_per_attempt() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("response-usage.json");
        let store = HostAdminStateStore::with_state_path(path.clone()).unwrap();
        let key = signing_key().verifying_key();
        let draft = request(None, None);
        let reply = response(&draft, "private-response-A");
        let bytes = response_measurement(&reply, u64::MAX).unwrap().0;
        let request = request(None, Some(scope(&draft).input_bytes + bytes));
        let ticket = store
            .admit_capability_invocation(admission(&request), &request, &key)
            .await
            .unwrap();
        assert!(
            store.settle_capability_response(&ticket, &reply).await.is_err(),
            "a source response must be observed first"
        );
        finish_source(&store, &ticket).await;
        store.settle_capability_response(&ticket, &reply).await.unwrap();
        store.settle_capability_response(&ticket, &reply).await.unwrap();
        let snapshot = store.export_snapshot_json().await.unwrap();
        let serialized = serde_json::to_string(&snapshot).unwrap();
        assert!(!serialized.contains("private-response-A"));
        assert!(!serialized.contains("usage-private-token-id"));
        let account = snapshot["capability_usage"]["accounts"]
            .as_object().unwrap().values().next().unwrap();
        assert_eq!(account["response_bytes"], bytes);
        assert_eq!(account["calls"], 1);
        drop(store);
        let reopened = HostAdminStateStore::with_state_path(path).unwrap();
        reopened.settle_capability_response(&ticket, &reply).await.unwrap();
        let replacement = response(&request, "private-response-B");
        assert_eq!(
            serde_json::to_vec(&replacement).unwrap().len(),
            serde_json::to_vec(&reply).unwrap().len()
        );
        assert!(reopened.settle_capability_response(&ticket, &replacement).await.is_err());
        let retained = reopened
            .invocation_record(&ticket.operation_id, Some(ticket.attempt_id))
            .await.unwrap();
        retained.capability_response.unwrap().validate_response(&reply).unwrap();
        let mut next = request.clone();
        next.id = RequestId::new("response-exhausted");
        assert!(reopened.check_capability_usage(&next, &key, "user:test").await.is_err());
        assert!(reopened.reserve_capability_usage(&next, &key, "user:test").await.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn concurrent_response_settlements_cannot_spend_the_same_remaining_bytes() {
        let store = HostAdminStateStore::new();
        let key = signing_key().verifying_key();
        let draft = request(None, None);
        let one_reply = response(&draft, "one remaining response");
        let bytes = response_measurement(&one_reply, u64::MAX).unwrap().0;
        let first = request(None, Some(scope(&draft).input_bytes * 2 + bytes));
        let mut second = first.clone();
        second.id = RequestId::new("usage-other");
        assert_eq!(first.id.0.len(), second.id.0.len());
        let first_ticket = store
            .admit_capability_invocation(admission(&first), &first, &key).await.unwrap();
        let second_ticket = store
            .admit_capability_invocation(admission(&second), &second, &key).await.unwrap();
        finish_source(&store, &first_ticket).await;
        finish_source(&store, &second_ticket).await;
        let other_reply = response(&second, "one remaining response");
        let (left, right) = futures_util::future::join(
            store.settle_capability_response(&first_ticket, &one_reply),
            store.settle_capability_response(&second_ticket, &other_reply),
        ).await;
        assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
        let snapshot = store.export_snapshot_json().await.unwrap();
        let account = snapshot["capability_usage"]["accounts"]
            .as_object().unwrap().values().next().unwrap();
        assert_eq!(account["response_bytes"], bytes);
        assert_eq!(account["calls"], 2);
    }

    #[fcp_async_core::runtime::test]
    async fn refused_response_stays_refused_after_restart_and_preserves_source_success() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("response-denied.json");
        let store = HostAdminStateStore::with_state_path(path.clone()).unwrap();
        let key = signing_key().verifying_key();
        let request = request(Some(3), Some(200));
        let ticket = store
            .admit_capability_invocation(admission(&request), &request, &key).await.unwrap();
        finish_source(&store, &ticket).await;
        let oversized = response(&request, &"x".repeat(300));
        assert!(store.settle_capability_response(&ticket, &oversized).await.is_err());
        drop(store);
        let reopened = HostAdminStateStore::with_state_path(path).unwrap();
        assert!(reopened
            .settle_capability_response(&ticket, &response(&request, ""))
            .await.is_err());
        let record = reopened
            .invocation_record(&ticket.operation_id, Some(ticket.attempt_id)).await.unwrap();
        assert_eq!(record.terminal.unwrap().outcome, InvocationOutcome::Succeeded);
        let budget = record.capability_response.unwrap();
        assert_eq!(budget.settlement, Some(ResponseSettlement::Denied));
        assert!(!budget.is_settled());
    }

    #[fcp_async_core::runtime::test]
    async fn response_settlement_refuses_wrong_tickets_and_absent_source_effects() {
        for outcome in [
            InvocationOutcome::OutcomeUnknown,
            InvocationOutcome::HostError,
            InvocationOutcome::DeadlineExceeded,
            InvocationOutcome::Cancelled,
        ] {
            let store = HostAdminStateStore::new();
            let request = request(None, Some(1_000));
            let reply = response(&request, "must remain private");
            let ticket = store
                .admit_capability_invocation(
                    admission(&request), &request, &signing_key().verifying_key(),
                ).await.unwrap();
            store.finish_invocation(&ticket, InvocationTerminal {
                outcome, receipt_id: None, duration_ms: 1, http_status: 503,
            }).await.unwrap();
            assert!(store.settle_capability_response(&ticket, &reply).await.is_err());
            let mut wrong = ticket.clone();
            wrong.attempt_id += 1;
            assert!(store.settle_capability_response(&wrong, &reply).await.is_err());
            assert_eq!(store.state.read().await.capability_usage.accounts
                .values().next().unwrap().response_bytes, 0);
        }
    }

    #[test]
    fn response_settlement_cannot_recreate_an_expired_or_pruned_account() {
        let now = Utc::now();
        let request = request_expiring_at(
            request(None, Some(1_000)), now + Duration::seconds(10),
        );
        let scope = scope(&request);
        let mut ledger = CapabilityUsageLedger::default();
        ledger.reserve(&scope, now).unwrap();
        let mut expired = scope.response_budget().unwrap();
        let reply = response(&request, "payload");
        let measurement = response_measurement(&reply, 1_000).unwrap();
        assert!(!ledger.settle_response(
            &mut expired, Some(&measurement), now + Duration::seconds(11),
        ));
        assert_eq!(
            ledger.observed_at_unix_secs,
            (now + Duration::seconds(11)).timestamp()
        );
        ledger.validate().unwrap();
        let mut pending = scope.response_budget().unwrap();
        assert!(
            !ledger.settle_response(&mut pending, Some(&measurement), now),
            "a backward clock adjustment cannot restore a second pending attempt"
        );
        assert!(ledger.accounts.is_empty());
        let mut pruned_ledger = CapabilityUsageLedger::default();
        let mut pruned = scope.response_budget().unwrap();
        assert!(!pruned_ledger.settle_response(&mut pruned, Some(&measurement), now));
        assert!(pruned_ledger.accounts.is_empty());
    }

    #[test]
    fn response_accounting_preserves_old_input_debt_and_rejects_corrupt_totals() {
        let request = request(None, Some(1_000));
        let mut ledger = CapabilityUsageLedger::default();
        ledger.reserve(&scope(&request), Utc::now()).unwrap();
        let mut old = serde_json::to_value(&ledger).unwrap();
        let account = old["accounts"].as_object_mut().unwrap().values_mut().next().unwrap();
        account.as_object_mut().unwrap().remove("response_bytes");
        let restored: CapabilityUsageLedger = serde_json::from_value(old.clone()).unwrap();
        restored.validate().unwrap();
        let account = restored.accounts.values().next().unwrap();
        assert_eq!(account.input_bytes, scope(&request).input_bytes);
        assert_eq!(account.response_bytes, 0);
        let account = old["accounts"].as_object_mut().unwrap().values_mut().next().unwrap();
        account["response_bytes"] = serde_json::json!(u64::MAX);
        assert!(serde_json::from_value::<CapabilityUsageLedger>(old).unwrap().validate().is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn cumulative_usage_is_shared_across_requests_operations_and_connectors() {
        let store = HostAdminStateStore::new();
        let key = signing_key().verifying_key();
        let mut request = request(Some(2), None);
        for _ in 0..3 {
            store
                .check_capability_usage(&request, &key, "user:test")
                .await
                .unwrap();
        }
        store
            .admit_capability_invocation(admission(&request), &request, &key)
            .await
            .unwrap();
        request.id = RequestId::new("usage-other-operation");
        request.operation = OperationId::from_static("fixture.list");
        request.connector_id = ConnectorId::from_static("fcp.test.other:utility:1.0.0");
        store
            .admit_capability_invocation(admission(&request), &request, &key)
            .await
            .unwrap();
        request.id = RequestId::new("usage-exhausted");
        let error = store
            .admit_capability_invocation(admission(&request), &request, &key)
            .await
            .unwrap_err();
        assert!(
            matches!(error, HostError::PreflightFailed(ref reason) if reason.contains("call budget exhausted"))
        );
        assert!(
            store
                .check_capability_usage(&request, &key, "user:test")
                .await
                .is_err()
        );
        let state = store.state.read().await;
        assert_eq!(state.capability_usage.accounts.len(), 1);
        assert_eq!(state.invocations.len(), 2);
        let serialized = serde_json::to_string(&*state).unwrap();
        assert!(!serialized.contains("usage-secret-input"));
        assert!(!serialized.contains("usage-private-token-id"));
    }

    #[fcp_async_core::runtime::test]
    async fn concurrent_admissions_cannot_overspend_signed_calls() {
        let store = HostAdminStateStore::new();
        let key = signing_key().verifying_key();
        let request = request(Some(3), None);
        let attempts = (0..32).map(|index| {
            let store = &store;
            let key = &key;
            let mut request = request.clone();
            request.id = RequestId::new(format!("usage-concurrent-{index}"));
            async move {
                store
                    .admit_capability_invocation(admission(&request), &request, key)
                    .await
            }
        });
        let results = futures_util::future::join_all(attempts).await;
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 3);
        assert_eq!(store.state.read().await.invocations.len(), 3);
    }

    #[fcp_async_core::runtime::test]
    async fn concurrent_zone_admission_commits_one_request_and_one_signed_debit() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("zone-and-token-usage.json");
        let store = HostAdminStateStore::with_state_path(path.clone()).unwrap();
        let key = signing_key().verifying_key();
        let request = request(Some(2), None);
        let policy = UsageBudgetPolicy {
            enforcement: fcp_kernel::BudgetEnforcement::Deny,
            budgets: vec![fcp_kernel::UsageBudgetLimit {
                metric: fcp_kernel::UsageMetricKind::Requests,
                limit: 1,
                window_seconds: 3_600,
            }],
        };
        let attempts = (0..2).map(|index| {
            let store = &store;
            let key = &key;
            let policy = &policy;
            let mut request = request.clone();
            request.id = RequestId::new(format!("zone-concurrent-{index}"));
            async move {
                store
                    .admit_budgeted_capability_invocation(
                        admission(&request),
                        &request,
                        key,
                        Some(policy),
                    )
                    .await
            }
        });
        let results = futures_util::future::join_all(attempts).await;
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert!(
            results
                .iter()
                .filter_map(|result| result.as_ref().err())
                .all(|error| { error.to_string().contains("zone usage budget exhausted") })
        );
        let snapshot = store.export_snapshot_json().await.unwrap();
        assert_eq!(snapshot["invocations"].as_array().unwrap().len(), 1);
        assert_eq!(
            snapshot["capability_usage"]["accounts"]
                .as_object()
                .unwrap()
                .values()
                .next()
                .unwrap()["calls"],
            1,
            "the rejected zone reservation must not consume the second signed call"
        );
        let ticket = results.into_iter().find_map(Result::ok).unwrap();
        drop(store);
        let reopened = HostAdminStateStore::with_state_path(path).unwrap();
        let retained = reopened
            .invocation_record(&ticket.operation_id, None)
            .await
            .unwrap();
        assert!(retained.budget_requests_reserved);
        assert_eq!(
            retained.terminal.unwrap().outcome,
            InvocationOutcome::OutcomeUnknown
        );
        let mut next = request.clone();
        next.id = RequestId::new("zone-after-restart");
        assert!(
            reopened
                .admit_budgeted_capability_invocation(admission(&next), &next, &key, Some(&policy),)
                .await
                .unwrap_err()
                .to_string()
                .contains("zone usage budget exhausted")
        );
        // Changing the trusted zone limit exposes the one remaining signed
        // call; neither the failed concurrent attempt nor restart spent it.
        let mut expanded = policy;
        expanded.budgets[0].limit = 2;
        reopened
            .admit_budgeted_capability_invocation(admission(&next), &next, &key, Some(&expanded))
            .await
            .unwrap();
        assert!(
            reopened
                .check_capability_usage(&next, &key, "user:test")
                .await
                .is_err()
        );
        assert_eq!(
            reopened
                .snapshot_zone_budget(&ZoneId::work(), &expanded)
                .await
                .unwrap()
                .budgets[0]
                .used,
            2
        );
    }

    #[fcp_async_core::runtime::test]
    async fn stream_controls_and_invocations_share_one_signed_allowance() {
        let store = HostAdminStateStore::new();
        let key = signing_key().verifying_key();
        let mut request = request(Some(3), None);
        store
            .reserve_capability_usage(&request, &key, "user:test")
            .await
            .unwrap();
        request.id = RequestId::new("usage-invoke-after-stream");
        store
            .admit_capability_invocation(admission(&request), &request, &key)
            .await
            .unwrap();
        request.id = RequestId::new("usage-stream-other-operation");
        request.operation = OperationId::from_static("fixture.list");
        request.connector_id = ConnectorId::from_static("fcp.test.other:utility:1.0.0");
        store
            .reserve_capability_usage(&request, &key, "user:test")
            .await
            .unwrap();
        assert!(
            store
                .reserve_capability_usage(&request, &key, "user:test")
                .await
                .unwrap_err()
                .to_string()
                .contains("call budget exhausted")
        );
        let state = store.state.read().await;
        assert_eq!(state.invocations.len(), 1, "controls are not invocations");
        assert_eq!(state.capability_usage.accounts.len(), 1);
        assert_eq!(
            state
                .capability_usage
                .accounts
                .values()
                .next()
                .unwrap()
                .calls,
            3
        );
    }

    #[fcp_async_core::runtime::test]
    async fn concurrent_stream_and_invoke_admission_cannot_split_the_last_allowance() {
        let store = HostAdminStateStore::new();
        let key = signing_key().verifying_key();
        let request = request(Some(3), None);
        let attempts = (0..32).map(|index| {
            let store = &store;
            let key = &key;
            let mut request = request.clone();
            request.id = RequestId::new(format!("usage-mixed-{index}"));
            async move {
                if index % 2 == 0 {
                    store
                        .reserve_capability_usage(&request, key, "user:test")
                        .await
                } else {
                    store
                        .admit_capability_invocation(admission(&request), &request, key)
                        .await
                        .map(|_| ())
                }
            }
        });
        let results = futures_util::future::join_all(attempts).await;
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 3);
        for error in results.into_iter().filter_map(Result::err) {
            assert!(error.to_string().contains("call budget exhausted"));
        }
        let state = store.state.read().await;
        assert_eq!(
            state
                .capability_usage
                .accounts
                .values()
                .next()
                .unwrap()
                .calls,
            3
        );
        assert!(state.invocations.len() <= 3);
    }

    #[fcp_async_core::runtime::test]
    async fn stream_control_bytes_accumulate_with_invocation_input() {
        let store = HostAdminStateStore::new();
        let key = signing_key().verifying_key();
        let poll = serde_json::json!({
            "topic": "fixture.events", "resource_uri": "fixture://events",
            "control": {"method": "poll", "stream_id": "stream-fixture", "limit": 1}
        });
        let ack = serde_json::json!({
            "topic": "fixture.events", "resource_uri": "fixture://events",
            "control": {"method": "ack", "stream_id": "stream-fixture",
                "ack": {"topic": "fixture.events", "seqs": [1, 2, 3],
                    "cursors": ["first", "second", "large-cursor".repeat(32)]}}
        });
        let total = u64::try_from(
            to_deterministic_cbor(&poll).unwrap().len()
                + to_deterministic_cbor(&ack).unwrap().len(),
        )
        .unwrap();
        let mut request = request(None, Some(total));
        request.input = poll;
        store
            .reserve_capability_usage(&request, &key, "user:test")
            .await
            .unwrap();
        request.id = RequestId::new("usage-after-control-bytes");
        request.input = ack;
        store
            .admit_capability_invocation(admission(&request), &request, &key)
            .await
            .unwrap();
        assert!(
            store
                .reserve_capability_usage(&request, &key, "user:test")
                .await
                .unwrap_err()
                .to_string()
                .contains("input byte budget exhausted")
        );
        let state = store.state.read().await;
        let account = state.capability_usage.accounts.values().next().unwrap();
        assert_eq!(account.input_bytes, total);
        assert_eq!(account.calls, 2);
        assert!(
            !serde_json::to_string(&*state)
                .unwrap()
                .contains("large-cursor")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn stream_debit_survives_restart_without_an_invocation_record() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("stream-usage-state.json");
        let key = signing_key().verifying_key();
        let request = request(Some(1), None);
        let store = HostAdminStateStore::with_state_path(path.clone()).unwrap();
        store
            .reserve_capability_usage(&request, &key, "user:test")
            .await
            .unwrap();
        assert!(store.state.read().await.invocations.is_empty());
        drop(store);
        let recovered = HostAdminStateStore::with_state_path(path).unwrap();
        assert!(recovered.state.read().await.invocations.is_empty());
        for result in [
            recovered
                .reserve_capability_usage(&request, &key, "user:test")
                .await,
            recovered
                .admit_capability_invocation(admission(&request), &request, &key)
                .await
                .map(|_| ()),
        ] {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("call budget exhausted")
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn unlimited_controls_do_not_rewrite_admin_state_or_bypass_a_failed_store() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("unlimited-control.json");
        let key = signing_key().verifying_key();
        let unlimited = request(None, None);
        let store = HostAdminStateStore::with_state_path(path.clone()).unwrap();
        for _ in 0..3 {
            store
                .reserve_capability_usage(&unlimited, &key, "user:test")
                .await
                .unwrap();
        }
        assert!(
            !path.exists(),
            "unlimited polls need no quota snapshot write"
        );
        assert!(store.state.read().await.capability_usage.is_empty());
        store.persistence_failed.store(true, Ordering::Release);
        assert!(matches!(
            store
                .reserve_capability_usage(&unlimited, &key, "user:test")
                .await,
            Err(HostError::Unavailable(_))
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn stream_usage_signature_scope_and_persistence_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let blocked_parent = directory.path().join("ordinary-file");
        std::fs::write(&blocked_parent, b"not a directory").unwrap();
        let store =
            HostAdminStateStore::with_state_path(blocked_parent.join("state.json")).unwrap();
        let key = signing_key().verifying_key();
        let wrong_key = Ed25519SigningKey::from_bytes(&[62; 32])
            .unwrap()
            .verifying_key();
        let request = request(Some(1), None);
        assert!(
            store
                .reserve_capability_usage(&request, &wrong_key, "user:test")
                .await
                .is_err()
        );
        assert!(
            store
                .reserve_capability_usage(&request, &key, "user:other")
                .await
                .is_err()
        );
        let mut wrong_zone = request.clone();
        wrong_zone.zone_id = ZoneId::private();
        assert!(
            store
                .reserve_capability_usage(&wrong_zone, &key, "user:test")
                .await
                .is_err()
        );
        assert!(!store.persistence_failed.load(Ordering::Acquire));
        assert!(
            store
                .reserve_capability_usage(&request, &key, "user:test")
                .await
                .is_err()
        );
        assert!(store.persistence_failed.load(Ordering::Acquire));
        assert!(
            store
                .reserve_capability_usage(&request, &key, "user:test")
                .await
                .is_err()
        );
        assert!(store.state.read().await.capability_usage.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn cumulative_input_bytes_use_canonical_payload_size() {
        let store = HostAdminStateStore::new();
        let key = signing_key().verifying_key();
        let input_bytes = u64::try_from(
            to_deterministic_cbor(&request(None, None).input)
                .unwrap()
                .len(),
        )
        .unwrap();
        let mut request = request(None, Some(input_bytes * 2));
        store
            .admit_capability_invocation(admission(&request), &request, &key)
            .await
            .unwrap();
        request.id = RequestId::new("usage-bytes-boundary");
        store
            .admit_capability_invocation(admission(&request), &request, &key)
            .await
            .unwrap();
        request.id = RequestId::new("usage-bytes-exhausted");
        let error = store
            .admit_capability_invocation(admission(&request), &request, &key)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("input byte budget exhausted"));
        assert_eq!(
            store
                .state
                .read()
                .await
                .capability_usage
                .accounts
                .values()
                .next()
                .unwrap()
                .input_bytes,
            input_bytes * 2
        );
    }

    #[fcp_async_core::runtime::test]
    async fn restart_retains_unknown_execution_and_its_spent_allowance() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("usage-state.json");
        let key = signing_key().verifying_key();
        let mut request = request(Some(1), None);
        let store = HostAdminStateStore::with_state_path(path.clone()).unwrap();
        store
            .admit_capability_invocation(admission(&request), &request, &key)
            .await
            .unwrap();
        drop(store);

        let recovered = HostAdminStateStore::with_state_path(path).unwrap();
        let original = recovered
            .invocation_record(&request.id.to_string(), None)
            .await
            .unwrap();
        assert_eq!(
            original.terminal.unwrap().outcome,
            InvocationOutcome::OutcomeUnknown
        );
        request.id = RequestId::new("usage-after-crash");
        assert!(
            recovered
                .admit_capability_invocation(admission(&request), &request, &key)
                .await
                .unwrap_err()
                .to_string()
                .contains("call budget exhausted")
        );
        assert!(
            recovered
                .check_capability_usage(&request, &key, "user:test")
                .await
                .is_err()
        );
    }

    #[fcp_async_core::runtime::test]
    async fn terminal_completion_never_refunds_the_spent_allowance() {
        let store = HostAdminStateStore::new();
        let key = signing_key().verifying_key();
        let mut request = request(Some(1), None);
        let ticket = store
            .admit_capability_invocation(admission(&request), &request, &key)
            .await
            .unwrap();
        store
            .finish_invocation(
                &ticket,
                InvocationTerminal {
                    outcome: InvocationOutcome::Succeeded,
                    receipt_id: None,
                    duration_ms: 1,
                    http_status: 200,
                },
            )
            .await
            .unwrap();
        request.id = RequestId::new("usage-after-success");
        assert!(
            store
                .admit_capability_invocation(admission(&request), &request, &key)
                .await
                .unwrap_err()
                .to_string()
                .contains("call budget exhausted")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn ticket_failure_rolls_back_the_entire_quota_reservation() {
        let store = HostAdminStateStore::new();
        let key = signing_key().verifying_key();
        let request = request(Some(1), None);
        // Generation exhaustion happens after reserving usage in the proposed
        // snapshot. Neither half of the failed transaction may be published.
        store.state.write().await.next_invocation_attempt_id = u64::MAX;
        assert!(
            store
                .admit_capability_invocation(admission(&request), &request, &key)
                .await
                .is_err()
        );
        {
            let mut state = store.state.write().await;
            assert!(state.capability_usage.is_empty());
            assert!(state.invocations.is_empty());
            state.next_invocation_attempt_id = 1;
        }
        store
            .admit_capability_invocation(admission(&request), &request, &key)
            .await
            .unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn uncertain_persistence_blocks_further_quota_checks_and_admissions() {
        let directory = tempfile::tempdir().unwrap();
        let blocked_parent = directory.path().join("ordinary-file");
        std::fs::write(&blocked_parent, b"not a directory").unwrap();
        let store =
            HostAdminStateStore::with_state_path(blocked_parent.join("state.json")).unwrap();
        let key = signing_key().verifying_key();
        let request = request(Some(1), None);
        assert!(
            store
                .admit_capability_invocation(admission(&request), &request, &key)
                .await
                .is_err()
        );
        assert!(store.persistence_failed.load(Ordering::Acquire));
        let error = store
            .check_capability_usage(&request, &key, "user:test")
            .await
            .unwrap_err();
        assert!(matches!(error, HostError::Unavailable(_)));
        assert!(
            store
                .admit_capability_invocation(admission(&request), &request, &key)
                .await
                .is_err()
        );
        assert!(store.state.read().await.capability_usage.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn mismatched_admission_never_consumes_the_valid_grant() {
        let store = HostAdminStateStore::new();
        let key = signing_key().verifying_key();
        let request = request(Some(1), None);
        let mut wrong_request = admission(&request);
        wrong_request.operation_id = "some-other-request".to_owned();
        assert!(
            store
                .admit_capability_invocation(wrong_request, &request, &key)
                .await
                .is_err()
        );
        let mut wrong_principal = admission(&request);
        wrong_principal.principal = "user:other".to_owned();
        assert!(
            store
                .admit_capability_invocation(wrong_principal, &request, &key)
                .await
                .is_err()
        );
        let wrong_key = Ed25519SigningKey::from_bytes(&[62; 32])
            .unwrap()
            .verifying_key();
        assert!(
            store
                .admit_capability_invocation(admission(&request), &request, &wrong_key)
                .await
                .is_err()
        );
        store
            .admit_capability_invocation(admission(&request), &request, &key)
            .await
            .unwrap();
    }

    #[test]
    fn different_signed_grant_cannot_refill_an_existing_token_identity() {
        let mut ledger = CapabilityUsageLedger::default();
        ledger
            .reserve(&scope(&request(Some(1), None)), Utc::now())
            .unwrap();
        for changed in [request(Some(100), None), request(None, None)] {
            let error = ledger.reserve(&scope(&changed), Utc::now()).unwrap_err();
            assert!(error.to_string().contains("reused for a different grant"));
        }
        let other_key = Ed25519SigningKey::from_bytes(&[62; 32]).unwrap();
        let other_request = signed_request(&other_key, b"usage-private-token-id", Some(1), None);
        let other_scope = CapabilityUsageScope::from_request(
            &other_request,
            &other_key.verifying_key(),
            "user:test",
        )
        .unwrap();
        ledger.reserve(&other_scope, Utc::now()).unwrap();
        assert_eq!(
            ledger.accounts.len(),
            2,
            "different signing authorities own independent identities"
        );
    }

    #[test]
    fn changing_unsigned_cose_envelope_cannot_refill_usage() {
        let mut request = request(Some(1), None);
        let mut ledger = CapabilityUsageLedger::default();
        let original = scope(&request);
        ledger.reserve(&original, Utc::now()).unwrap();

        // COSE unprotected headers may legitimately change in transit. They
        // are not signed grant identity and cannot create a fresh account.
        let raw = request.capability_token.raw().to_cbor().unwrap();
        let mut envelope: ciborium::Value = ciborium::from_reader(raw.as_slice()).unwrap();
        let ciborium::Value::Array(parts) = &mut envelope else {
            panic!("expected untagged COSE Sign1 array");
        };
        let ciborium::Value::Map(unprotected) = &mut parts[1] else {
            panic!("expected COSE unprotected headers");
        };
        unprotected.push((
            ciborium::Value::Text("usage-test-label".to_owned()),
            ciborium::Value::Text("another-envelope".to_owned()),
        ));
        let mut altered = Vec::new();
        ciborium::into_writer(&envelope, &mut altered).unwrap();
        request.capability_token =
            CapabilityToken::from_raw(fcp_crypto::cose::CoseToken::from_cbor(&altered).unwrap());
        let altered_scope = scope(&request);
        assert_eq!(original.key, altered_scope.key);
        assert_eq!(original.grant_digest, altered_scope.grant_digest);
        assert!(
            ledger
                .reserve(&altered_scope, Utc::now())
                .unwrap_err()
                .to_string()
                .contains("call budget exhausted")
        );
    }

    #[test]
    fn finite_grants_require_signed_ids_and_current_validity() {
        let no_id = signed_request(&signing_key(), b"", Some(1), None);
        assert!(
            CapabilityUsageScope::from_request(&no_id, &signing_key().verifying_key(), "user:test")
                .is_err()
        );
        let scope = scope(&request(Some(1), None));
        let mut ledger = CapabilityUsageLedger::default();
        let expired = DateTime::from_timestamp(scope.expires_at, 0).unwrap();
        assert!(ledger.reserve(&scope, expired).is_err());
        assert!(ledger.is_empty());
        ledger.reserve(&scope, Utc::now()).unwrap();
        // Even if wall time moves backwards within the validity window, the
        // previously spent grant cannot be resurrected by expiry pruning.
        let earlier = DateTime::from_timestamp(scope.not_before.unwrap(), 0).unwrap();
        assert!(
            ledger
                .reserve(&scope, earlier)
                .unwrap_err()
                .to_string()
                .contains("call budget exhausted")
        );
    }

    #[test]
    fn signed_malformed_not_before_is_rejected_before_usage_admission() {
        let mut request = request(Some(1), None);
        let key = signing_key();
        let claims = request
            .capability_token
            .raw()
            .verify(&key.verifying_key())
            .unwrap()
            .custom(
                cwt_claims::NBF,
                ciborium::Value::Text("invalid-timestamp".to_owned()),
            );
        request.capability_token =
            CapabilityToken::from_raw(fcp_crypto::cose::CoseToken::sign(&key, &claims).unwrap());
        let error = CapabilityUsageScope::from_request(&request, &key.verifying_key(), "user:test")
            .err()
            .expect("a present malformed signed NBF must not become an absent NBF");
        assert!(
            error
                .to_string()
                .contains("not-before claim must be an integer timestamp")
        );
    }

    #[test]
    fn capacity_pressure_never_evicts_or_refills_a_known_grant() {
        let mut ledger = CapabilityUsageLedger::default();
        let known = scope(&request(Some(2), None));
        ledger.reserve(&known, Utc::now()).unwrap();
        for index in 1..MAX_TRACKED_CAPABILITY_GRANTS {
            ledger.accounts.insert(
                format!("{index:064x}"),
                CapabilityUsageAccount {
                    grant_digest: "0".repeat(64),
                    calls: 1,
                    input_bytes: 1,
                    response_bytes: 0,
                    max_calls: Some(1),
                    max_input_bytes: None,
                    expires_at_unix_secs: known.expires_at,
                },
            );
        }
        let newcomer = signed_request(&signing_key(), b"usage-new-id", Some(1), None);
        assert!(
            ledger
                .reserve(&scope(&newcomer), Utc::now())
                .unwrap_err()
                .to_string()
                .contains("capacity exhausted")
        );
        ledger.reserve(&known, Utc::now()).unwrap();
        assert!(
            ledger
                .reserve(&known, Utc::now())
                .unwrap_err()
                .to_string()
                .contains("call budget exhausted")
        );
        assert_eq!(ledger.accounts.len(), MAX_TRACKED_CAPABILITY_GRANTS);
        ledger.validate().unwrap();
    }

    #[test]
    fn expired_capacity_is_reclaimable_without_clock_rollback_refilling_grants() {
        let mut ledger = CapabilityUsageLedger::default();
        let old = scope(&request(Some(1), None));
        let earlier = Utc::now();
        ledger.reserve(&old, earlier).unwrap();
        for index in 1..MAX_TRACKED_CAPABILITY_GRANTS {
            ledger.accounts.insert(
                format!("{index:064x}"),
                CapabilityUsageAccount {
                    grant_digest: "0".repeat(64),
                    calls: 1,
                    input_bytes: 1,
                    response_bytes: 0,
                    max_calls: Some(1),
                    max_input_bytes: None,
                    expires_at_unix_secs: old.expires_at,
                },
            );
        }
        let after_expiry = DateTime::from_timestamp(old.expires_at, 0).unwrap();
        let newcomer = scope(&request_expiring_at(
            signed_request(&signing_key(), b"usage-new-after-expiry", Some(2), None),
            after_expiry + Duration::hours(1),
        ));
        // A read-only preflight sees reclaimable capacity but cannot change
        // counters, prune accounts, or advance the durable high-water.
        let before_preview = serde_json::to_value(&ledger).unwrap();
        ledger.check(&newcomer, after_expiry).unwrap();
        assert_eq!(serde_json::to_value(&ledger).unwrap(), before_preview);
        ledger.reserve(&newcomer, after_expiry).unwrap();
        assert_eq!(ledger.accounts.len(), 1);
        assert_eq!(ledger.observed_at_unix_secs, old.expires_at);
        ledger.validate().unwrap();

        let encoded = serde_json::to_vec(&ledger).unwrap();
        let mut recovered: CapabilityUsageLedger = serde_json::from_slice(&encoded).unwrap();
        // The old identity was physically reclaimed. Its signed expiration
        // still loses to the persisted high-water after a restart and rollback.
        assert!(
            recovered
                .check(&old, earlier)
                .unwrap_err()
                .to_string()
                .contains("validity window")
        );
        assert!(recovered.reserve(&old, earlier).is_err());
        recovered.reserve(&newcomer, earlier).unwrap();
        assert_eq!(recovered.observed_at_unix_secs, old.expires_at);
        assert!(
            recovered
                .reserve(&newcomer, earlier)
                .unwrap_err()
                .to_string()
                .contains("call budget exhausted")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn pruning_the_last_account_persists_high_water_with_the_invocation_ticket() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("usage-expired-state.json");
        let now = Utc::now();
        let old_request = request_expiring_at(request(Some(1), None), now - Duration::seconds(10));
        let old_scope = scope(&old_request);
        let earlier = now - Duration::seconds(20);
        let mut snapshot = super::super::HostAdminStateSnapshot::default();
        snapshot
            .capability_usage
            .reserve(&old_scope, earlier)
            .unwrap();
        std::fs::write(&path, serde_json::to_vec(&snapshot).unwrap()).unwrap();

        let store = HostAdminStateStore::with_state_path(path.clone()).unwrap();
        let unlimited = request(None, None);
        let key = signing_key().verifying_key();
        let ticket = store
            .admit_capability_invocation(admission(&unlimited), &unlimited, &key)
            .await
            .unwrap();
        {
            let state = store.state.read().await;
            assert!(state.capability_usage.accounts.is_empty());
            assert!(state.capability_usage.observed_at_unix_secs >= now.timestamp());
        }
        let persisted: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert!(
            persisted["capability_usage"]["accounts"]
                .as_object()
                .unwrap()
                .is_empty()
        );
        drop(store);
        let reopened = HostAdminStateStore::with_state_path(path).unwrap();
        assert_eq!(
            reopened
                .invocation_record(&ticket.operation_id, Some(ticket.attempt_id))
                .await
                .unwrap()
                .ticket,
            ticket
        );
        let state = reopened.state.read().await;
        assert!(state.capability_usage.check(&old_scope, earlier).is_err());
        assert!(state.capability_usage.accounts.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn corrupt_persisted_usage_is_rejected_instead_of_reset() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("usage-corrupt-state.json");
        let store = HostAdminStateStore::with_state_path(path.clone()).unwrap();
        let request = request(Some(1), None);
        store
            .admit_capability_invocation(
                admission(&request),
                &request,
                &signing_key().verifying_key(),
            )
            .await
            .unwrap();
        let snapshot = store.export_snapshot_json().await.unwrap();
        for corruption in ["zero-calls", "missing-high-water", "missing-accounts"] {
            let mut corrupted = snapshot.clone();
            let ledger = corrupted["capability_usage"].as_object_mut().unwrap();
            match corruption {
                "zero-calls" => {
                    let accounts = ledger.get_mut("accounts").unwrap().as_object_mut().unwrap();
                    accounts.values_mut().next().unwrap()["calls"] = serde_json::json!(0);
                }
                "missing-high-water" => {
                    ledger.remove("observed_at_unix_secs");
                }
                "missing-accounts" => {
                    ledger.remove("accounts");
                }
                _ => unreachable!(),
            }
            std::fs::write(&path, serde_json::to_vec(&corrupted).unwrap()).unwrap();
            assert!(
                HostAdminStateStore::with_state_path(path.clone()).is_err(),
                "{corruption}"
            );
        }
    }
}
