//! Bounded FCP-message accounting for standalone invocation.
//!
//! The metered unit is the compact UTF-8 JSON serialization of the complete
//! typed InvokeRequest plus InvokeResponse, not only input/output values. Outer
//! transport framing, rejected-request errors and provider HTTP traffic are not
//! part of this local counter and still require host/egress enforcement.
//!
//! Reserve before dispatch, settle only a complete response, never refund an
//! unknown outcome. Charging reservations up front makes concurrent admission
//! atomic without holding a lock across provider I/O or relying on Drop to run.

use std::io::{self, Write};
use std::sync::Arc;

use fcp_core::{
    BoundVerified, CapabilityToken, FcpError, FcpResult, InvokeRequest, InvokeResponse,
    InvokeStatus, RequestId,
};
use serde::Serialize;

use super::{Account, Scope, StandaloneInvocation, UsageLedger, denied};
use crate::prelude::StandaloneSession;

pub(super) struct Completion {
    request_id: RequestId,
    limit: u64,
    reservation: Option<Reservation>,
}

struct Reservation {
    // Keep the original generation alive. Completing an old invocation cannot
    // refund capacity into a replacement session, even if token IDs repeat.
    entries: Arc<std::sync::Mutex<std::collections::BTreeMap<[u8; 32], Account>>>,
    key: [u8; 32],
    grant: [u8; 32],
    bytes: u64,
}

impl StandaloneSession {
    /// Admit an invocation with a bounded, metered FCP response.
    ///
    /// Atomically charges one call, the serialized complete request, and a
    /// response reservation no larger than `max_response_bytes` or the signed
    /// grant's remaining bytes. The response cap is a trusted runtime limit,
    /// never an alternative caller-supplied byte counter or a permission grant.
    /// Call [`StandaloneInvocation::finish_response`] on the complete response
    /// before releasing it. A failed, cancelled, leaked or dropped invocation
    /// retains its entire reservation; no destructor must run for safety.
    ///
    /// Bytes are compact JSON FCP message bytes, including IDs, metadata and
    /// token serialization. This is not physical transport/provider-byte or
    /// mesh-global accounting. Concurrent reservations can temporarily deny a
    /// request that would fit after another operation completes. Authorization
    /// previews do not reserve and cannot guarantee subsequent admission.
    ///
    /// # Errors
    /// Rejects invalid requests, authorization/key-scope failures, zero response
    /// caps, missing finite-grant identities, exhausted call/byte allowances,
    /// and unavailable ledger capacity before charging either allowance.
    pub fn admit_bounded(
        &self,
        request: &InvokeRequest,
        resource_uris: &[String],
        max_response_bytes: u64,
    ) -> FcpResult<StandaloneInvocation> {
        if request.r#type != "invoke" || request.id.0.is_empty() {
            return Err(invalid(
                "Bounded admission requires an invoke request with a non-empty ID",
            ));
        }
        request
            .validate_idempotency_key()
            .map_err(|_| invalid("Invalid invocation idempotency key"))?;
        let token = self.authorize(
            &request.connector_id,
            &request.zone_id,
            &request.operation,
            request.capability_token.clone(),
            resource_uris,
        )?;
        self.authority
            .as_ref()
            .ok_or(FcpError::NotHandshaken)?
            .usage
            .admit_bounded(token, request, max_response_bytes)
    }
}

impl StandaloneInvocation {
    /// The maximum serialized complete response this admission can release.
    /// Legacy, unmetered admission returns `None` and rejects byte-limited grants.
    #[must_use]
    pub fn response_byte_limit(&self) -> Option<u64> {
        self.completion.as_ref().map(|completion| completion.limit)
    }

    /// Check the complete response before releasing it and settle unused bytes.
    ///
    /// Consumes this non-Clone witness exactly once. The response must have the
    /// admitted request ID and fit the reservation. Successful settlement only
    /// releases unused response bytes, never request bytes or a charged call.
    /// A valid error response is checked but retains its full reservation.
    /// Legacy admissions without a byte constraint have nothing to settle.
    ///
    /// # Errors
    /// A mismatched, unserializable or oversized response, or unavailable
    /// settlement accounting, returns a non-retryable outcome-unknown error.
    /// Its payload is withheld and the full reservation remains charged.
    pub fn finish_response(self, response: &InvokeResponse) -> FcpResult<()> {
        let Some(completion) = self.completion else {
            return Ok(());
        };
        if response.r#type != "response" || response.id != completion.request_id {
            return Err(output_unknown());
        }
        match response.status {
            InvokeStatus::Ok if response.result.is_none() || response.error.is_some() => {
                return Err(output_unknown());
            }
            InvokeStatus::Error if response.error.is_none() || response.result.is_some() => {
                return Err(output_unknown());
            }
            _ => {}
        }
        let actual = json_bytes(response, completion.limit).map_err(|_| output_unknown())?;
        // A bounded error response may be released, but failure is not proof
        // of zero effects/transfer. Keep its entire reservation charged.
        if response.status == InvokeStatus::Ok
            && let Some(reservation) = completion.reservation
        {
            reservation.settle(actual)?;
        }
        Ok(())
    }
}

impl UsageLedger {
    fn admit_bounded(
        &self,
        token: CapabilityToken<BoundVerified>,
        request: &InvokeRequest,
        max_response_bytes: u64,
    ) -> FcpResult<StandaloneInvocation> {
        if max_response_bytes == 0 {
            return Err(invalid(
                "Bounded admission requires a positive response byte limit",
            ));
        }
        let scope = Scope::from_verified(&token)?;
        scope.check_key(request.idempotency_key.as_deref())?;
        // A result containing the single digit 0 is the smallest successful
        // response envelope. Do not execute work that cannot return even this.
        let minimum_response = json_bytes(
            &InvokeResponse::ok(request.id.clone(), serde_json::Value::from(0)),
            max_response_bytes,
        )
        .map_err(|_| invalid("Response cap cannot fit a complete FCP response"))?;
        // Derive bytes from the actual complete message, not a field supplied
        // by its caller. Counting is allocation-free and outside the ledger lock.
        let request_bytes = match scope.constraints.max_bytes {
            Some(limit) => json_bytes(request, limit)
                .map_err(|_| denied("Invocation request exceeds the signed byte budget"))?,
            None => 0,
        };
        let mut entries = self.lock()?;
        self.check_scope(&entries, &scope)?;
        let mut response_limit = max_response_bytes;
        let mut charge = 0;
        if let Some(limit) = scope.constraints.max_bytes {
            let spent = scope
                .key
                .as_ref()
                .and_then(|key| entries.get(key))
                .map_or(0, |account| account.bytes);
            let available = limit
                .checked_sub(spent)
                .ok_or_else(|| denied("Signed capability byte budget exhausted"))?;
            // Every successful FCP invocation has a non-empty response. Do not
            // dispatch work with an allowance incapable of returning any bytes.
            if request_bytes >= available {
                return Err(denied(
                    "No signed byte allowance remains for an invocation response",
                ));
            }
            response_limit = response_limit.min(available - request_bytes);
            if response_limit < minimum_response {
                return Err(denied(
                    "Signed byte allowance cannot fit a complete FCP response",
                ));
            }
            charge = request_bytes
                .checked_add(response_limit)
                .ok_or_else(|| denied("Signed capability byte budget exhausted"))?;
        }
        let mut reservation = None;
        if scope.constraints.max_calls.is_some() || scope.constraints.max_bytes.is_some() {
            let key = scope
                .key
                .ok_or_else(|| denied("Usage-limited capability has no token ID"))?;
            let account = entries.entry(key).or_insert(Account {
                grant: scope.grant,
                spent: 0,
                bytes: 0,
            });
            // Compute before committing either counter: a byte denial cannot
            // spend a call, nor can a call denial spend or reserve bytes.
            let next_bytes = account
                .bytes
                .checked_add(charge)
                .ok_or_else(|| denied("Signed capability byte budget exhausted"))?;
            let next_calls = if scope.constraints.max_calls.is_some() {
                account
                    .spent
                    .checked_add(1)
                    .ok_or_else(|| denied("Signed capability call budget exhausted"))?
            } else {
                account.spent
            };
            account.bytes = next_bytes;
            account.spent = next_calls;
            if scope.constraints.max_bytes.is_some() {
                reservation = Some(Reservation {
                    entries: Arc::clone(&self.entries),
                    key,
                    grant: scope.grant,
                    bytes: response_limit,
                });
            }
        }
        Ok(StandaloneInvocation {
            token,
            completion: Some(Completion {
                request_id: request.id.clone(),
                limit: response_limit,
                reservation,
            }),
        })
    }
}

impl Reservation {
    fn settle(self, actual: u64) -> FcpResult<()> {
        let unused = self.bytes.checked_sub(actual).ok_or_else(output_unknown)?;
        let mut entries = self.entries.lock().map_err(|_| output_unknown())?;
        let account = entries.get_mut(&self.key).ok_or_else(output_unknown)?;
        if account.grant != self.grant {
            return Err(output_unknown());
        }
        // Each reservation was fully charged at admission. Removing only its
        // own unused portion cannot free another concurrent invocation's bytes.
        account.bytes = account
            .bytes
            .checked_sub(unused)
            .ok_or_else(output_unknown)?;
        Ok(())
    }
}

/// Count the actual serializer output without allocating a second payload.
/// Stop serialization immediately when the limit is exceeded.
fn json_bytes(value: &impl Serialize, limit: u64) -> Result<u64, ()> {
    struct Counter {
        used: u64,
        limit: u64,
    }
    impl Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let length = u64::try_from(bytes.len()).map_err(|_| io::Error::other("byte limit"))?;
            let next = self
                .used
                .checked_add(length)
                .filter(|next| *next <= self.limit)
                .ok_or_else(|| io::Error::other("byte limit"))?;
            self.used = next;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter { used: 0, limit };
    serde_json::to_writer(&mut counter, value).map_err(|_| ())?;
    Ok(counter.used)
}

fn invalid(message: &str) -> FcpError {
    FcpError::InvalidRequest {
        code: 1003,
        message: message.into(),
    }
}

fn output_unknown() -> FcpError {
    FcpError::External {
        service: "standalone".into(),
        message: "Invocation response cannot be released within its admitted byte boundary; outcome is unknown; reconcile external effects before retry".into(),
        status_code: None,
        retryable: false,
        retry_after: None,
    }
}

#[cfg(test)]
mod tests;
