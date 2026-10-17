//! Shared admission control and outage recovery for outbound mesh RPCs.
//!
//! Admission is fail-fast and precedes all network I/O. A refused request is
//! provably not delivered; an admitted request keeps its reservation through
//! reply authentication. Dropping the future releases every reservation, so
//! cancellation cannot strand capacity or create an unbounded waiter queue.
//! Peer circuits affect only future admission, never an already-sent result.
//! Every admitted forward also reserves its maximum wire-reply size before
//! transmission. Reply pressure cannot force us to abandon a delivered write.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Mutex;
use std::time::Instant;

use serde::Serialize;

use super::{MAX_REPLY_BYTES, MeshForwardFailure, MeshForwardReply};
use crate::{HostError, HostResult};

mod circuit;

use circuit::{CircuitBook, CircuitTicket, ForwardOutcome};

/// Maximum simultaneous forwards across one router.
pub const MESH_FORWARD_MAX_IN_FLIGHT_ENV: &str = "FCP_HOST_MESH_FORWARD_MAX_IN_FLIGHT";
/// Maximum simultaneous forwards to one peer.
pub const MESH_FORWARD_MAX_PER_PEER_ENV: &str = "FCP_HOST_MESH_FORWARD_MAX_PER_PEER";
/// Maximum aggregate serialized request bytes held by admitted forwards.
pub const MESH_FORWARD_MAX_REQUEST_BYTES_ENV: &str = "FCP_HOST_MESH_FORWARD_MAX_REQUEST_BYTES";

pub(super) const LIMIT_ENV_KEYS: [&str; 4] = [
    MESH_FORWARD_MAX_IN_FLIGHT_ENV,
    MESH_FORWARD_MAX_PER_PEER_ENV,
    MESH_FORWARD_MAX_REQUEST_BYTES_ENV,
    MeshForwardLimits::RESPONSE_BYTES_ENV,
];

/// Router-wide and per-peer outbound resource ceilings.
///
/// Request bytes and worst-case wire-reply headroom have independent limits.
/// Each forward reserves the transport's full per-reply limit before sending,
/// even when its actual reply is small. This avoids post-delivery resource
/// refusals with ambiguous execution outcomes. These are not process-RSS limits:
/// decoder copies, HTTP buffers, discovery, and caller-owned results are outside
/// this accounting. Reservations last through reply authentication, not through
/// subsequent use of the returned result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MeshForwardLimits {
    /// Maximum number of admitted forwards across all peers.
    pub max_in_flight: usize,
    /// Maximum number of admitted forwards to any one peer.
    pub max_per_peer: usize,
    /// Maximum sum of serialized request lengths for admitted forwards.
    pub max_request_bytes: usize,
    /// Maximum aggregate wire-reply headroom reserved by admitted forwards.
    /// Must accommodate at least one full transport reply (16 MiB).
    pub max_response_bytes: usize,
}

impl Default for MeshForwardLimits {
    fn default() -> Self {
        Self {
            max_in_flight: 32,
            max_per_peer: 4,
            max_request_bytes: 64 * 1024 * 1024,
            // Preserve the default 32-forward capacity while giving operators
            // an independent ceiling when increasing concurrency or reducing
            // the reply-buffer memory allowance.
            max_response_bytes: 32 * MAX_REPLY_BYTES,
        }
    }
}

impl MeshForwardLimits {
    /// Environment variable controlling aggregate reserved wire-reply bytes.
    pub const RESPONSE_BYTES_ENV: &'static str = "FCP_HOST_MESH_FORWARD_MAX_RESPONSE_BYTES";

    /// Load optional limits without reading ambient process state.
    ///
    /// # Errors
    ///
    /// Rejects empty, nonnumeric, zero, overflowing, or inconsistent limits.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> HostResult<Self> {
        let defaults = Self::default();
        let read = |name: &str, default: usize| -> HostResult<usize> {
            match lookup(name) {
                None => Ok(default),
                Some(raw) => raw.trim().parse::<usize>().map_err(|_| {
                    HostError::InvalidFilter(format!("{name} must be a positive integer"))
                }),
            }
        };
        let limits = Self {
            max_in_flight: read(MESH_FORWARD_MAX_IN_FLIGHT_ENV, defaults.max_in_flight)?,
            max_per_peer: read(MESH_FORWARD_MAX_PER_PEER_ENV, defaults.max_per_peer)?,
            max_request_bytes: read(
                MESH_FORWARD_MAX_REQUEST_BYTES_ENV,
                defaults.max_request_bytes,
            )?,
            max_response_bytes: read(Self::RESPONSE_BYTES_ENV, defaults.max_response_bytes)?,
        };
        limits.validate()?;
        Ok(limits)
    }

    /// Check that every ceiling is nonzero and the peer ceiling fits the total.
    ///
    /// # Errors
    ///
    /// Returns a configuration error for an unusable limit set.
    pub fn validate(self) -> HostResult<()> {
        if self.max_in_flight == 0 || self.max_per_peer == 0 || self.max_request_bytes == 0 {
            return Err(HostError::InvalidFilter(
                "mesh forward limits must all be greater than zero".to_owned(),
            ));
        }
        if self.max_per_peer > self.max_in_flight {
            return Err(HostError::InvalidFilter(
                "mesh forward per-peer limit must not exceed the router limit".to_owned(),
            ));
        }
        if self.max_response_bytes < MAX_REPLY_BYTES {
            return Err(HostError::InvalidFilter(format!(
                "{} must be at least {MAX_REPLY_BYTES} bytes (one full mesh reply)",
                Self::RESPONSE_BYTES_ENV
            )));
        }
        Ok(())
    }
}

/// An atomic, redaction-safe snapshot of current outbound reservations.
///
/// These are resource counters, not authenticated quorum or mesh-readiness
/// evidence. Circuit transitions are reported separately in structured logs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct MeshForwardUsage {
    /// Admitted forwards, including those awaiting or verifying a reply.
    pub in_flight: usize,
    /// Aggregate serialized request bytes reserved by those forwards.
    pub request_bytes: usize,
    /// Worst-case wire-reply bytes reserved, not measured response sizes or RSS.
    pub response_bytes_reserved: usize,
    /// Active reservations per peer, in deterministic node-id order.
    pub peers: BTreeMap<String, usize>,
}

#[derive(Debug, Default)]
struct AdmissionState {
    usage: MeshForwardUsage,
    circuits: CircuitBook,
}

#[derive(Debug)]
pub(super) struct ForwardControl {
    limits: MeshForwardLimits,
    state: Mutex<AdmissionState>,
}

impl ForwardControl {
    pub(super) fn new(limits: MeshForwardLimits) -> HostResult<Self> {
        limits.validate()?;
        Ok(Self {
            limits,
            state: Mutex::new(AdmissionState::default()),
        })
    }

    pub(super) const fn limits(&self) -> MeshForwardLimits {
        self.limits
    }

    pub(super) fn snapshot(&self) -> HostResult<MeshForwardUsage> {
        self.state
            .lock()
            .map(|state| state.usage.clone())
            .map_err(|_| HostError::Internal("mesh forward admission state is poisoned".to_owned()))
    }

    /// `send` is not even constructed until all ceilings have been reserved.
    /// No lock is held while it is running, and every exit releases the lease.
    pub(super) async fn execute<F, Fut>(
        &self,
        peer: &str,
        request_bytes: usize,
        send: F,
    ) -> Result<MeshForwardReply, MeshForwardFailure>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<MeshForwardReply, MeshForwardFailure>>,
    {
        self.execute_with_clock(peer, request_bytes, send, Instant::now)
            .await
    }

    async fn execute_with_clock<F, Fut, Clock>(
        &self,
        peer: &str,
        request_bytes: usize,
        send: F,
        clock: Clock,
    ) -> Result<MeshForwardReply, MeshForwardFailure>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<MeshForwardReply, MeshForwardFailure>>,
        Clock: Fn() -> Instant,
    {
        let permit = self.reserve_at(peer, request_bytes, clock())?;
        let result = send().await;
        // forward_transport has already verified signature and request binding
        // before returning Ok. A signed operation error is a healthy transport
        // response, not a reason to retry or mark the peer unavailable.
        let outcome = match &result {
            Ok(_) => ForwardOutcome::AuthenticatedReply,
            Err(MeshForwardFailure::InvalidReply { .. }) => ForwardOutcome::InvalidReply,
            Err(_) => ForwardOutcome::Unavailable,
        };
        permit.complete(outcome, clock());
        result
    }

    #[cfg(test)]
    fn reserve<'a>(
        &'a self,
        peer: &'a str,
        request_bytes: usize,
    ) -> Result<ForwardPermit<'a>, MeshForwardFailure> {
        self.reserve_at(peer, request_bytes, Instant::now())
    }

    fn reserve_at<'a>(
        &'a self,
        peer: &'a str,
        request_bytes: usize,
        now: Instant,
    ) -> Result<ForwardPermit<'a>, MeshForwardFailure> {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(error) => {
                drop(error);
                return Err(admission_refusal(peer, "state_poisoned"));
            }
        };
        let usage = &state.usage;
        let reason = if usage.in_flight >= self.limits.max_in_flight {
            Some("router_in_flight_limit")
        } else if usage.peers.get(peer).copied().unwrap_or(0) >= self.limits.max_per_peer {
            Some("peer_in_flight_limit")
        } else if request_bytes
            > self
                .limits
                .max_request_bytes
                .saturating_sub(usage.request_bytes)
        {
            Some("request_byte_limit")
        } else if MAX_REPLY_BYTES
            > self
                .limits
                .max_response_bytes
                .saturating_sub(usage.response_bytes_reserved)
        {
            Some("response_byte_limit")
        } else {
            None
        };
        if let Some(reason) = reason {
            drop(state);
            return Err(admission_refusal(peer, reason));
        }
        // Resource ceilings and the single-probe claim share this mutex. In
        // particular, a locally saturated router cannot consume a probe slot.
        let ticket = match state.circuits.reserve(peer, now) {
            Ok(ticket) => ticket,
            Err(reason) => {
                drop(state);
                return Err(admission_refusal(peer, reason));
            }
        };
        let usage = &mut state.usage;
        // These additions cannot overflow: each is bounded above by a
        // validated usize ceiling, and byte admission checked the remainder.
        usage.in_flight += 1;
        usage.request_bytes += request_bytes;
        usage.response_bytes_reserved += MAX_REPLY_BYTES;
        *usage.peers.entry(peer.to_owned()).or_default() += 1;
        drop(state);
        Ok(ForwardPermit {
            control: self,
            peer,
            request_bytes,
            ticket,
            outcome: None,
            finished_at: None,
        })
    }
}

fn admission_refusal(peer: &str, reason: &'static str) -> MeshForwardFailure {
    tracing::debug!(
        event = "mesh_forward_admission_refused",
        peer,
        reason,
        "mesh forward refused before transmission"
    );
    MeshForwardFailure::NotDelivered {
        peer: peer.to_owned(),
        detail: format!("mesh forward admission refused before transmission: {reason}"),
    }
}

#[derive(Debug)]
struct ForwardPermit<'a> {
    control: &'a ForwardControl,
    peer: &'a str,
    request_bytes: usize,
    ticket: CircuitTicket,
    outcome: Option<ForwardOutcome>,
    finished_at: Option<Instant>,
}

impl ForwardPermit<'_> {
    fn complete(mut self, outcome: ForwardOutcome, now: Instant) {
        self.outcome = Some(outcome);
        self.finished_at = Some(now);
        // Drop publishes the observation and releases all counters atomically.
    }
}

impl Drop for ForwardPermit<'_> {
    fn drop(&mut self) {
        // A poisoned state refuses all subsequent admission, but existing
        // futures must still be able to release resources during unwinding.
        let mut state = self
            .control
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let usage = &mut state.usage;
        usage.in_flight = usage.in_flight.saturating_sub(1);
        usage.request_bytes = usage.request_bytes.saturating_sub(self.request_bytes);
        usage.response_bytes_reserved = usage
            .response_bytes_reserved
            .saturating_sub(MAX_REPLY_BYTES);
        if let Some(count) = usage.peers.get_mut(self.peer) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                usage.peers.remove(self.peer);
            }
        }
        let transition = state.circuits.complete(
            self.peer,
            &self.ticket,
            self.outcome,
            self.finished_at.unwrap_or_else(Instant::now),
        );
        drop(state);
        if let Some(transition) = transition {
            tracing::info!(
                event = "mesh_forward_peer_circuit",
                peer = self.peer,
                state = transition.state,
                reason = transition.reason,
                cooldown_ms = transition.cooldown_ms,
                "mesh peer transport admission changed"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Context;
    use std::time::Duration;

    use fcp_core::TailscaleNodeId;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_mesh::invoke_route::{
        MeshForwardBody, MeshForwardEnvelope, MeshForwardError, MeshPeerConfig, MeshPeerDirectory,
    };
    use futures_util::FutureExt;
    use futures_util::future::pending;

    use super::*;

    fn control(total: usize, peer: usize, bytes: usize) -> ForwardControl {
        ForwardControl::new(MeshForwardLimits {
            max_in_flight: total,
            max_per_peer: peer,
            max_request_bytes: bytes,
            ..MeshForwardLimits::default()
        })
        .unwrap()
    }

    fn open_peer(control: &ForwardControl, peer: &str, now: Instant) {
        for _ in 0..3 {
            control
                .reserve_at(peer, 1, now)
                .unwrap()
                .complete(ForwardOutcome::Unavailable, now);
        }
    }

    fn verified_reply(status: u16) -> MeshForwardReply {
        let key = Ed25519SigningKey::generate();
        let envelope = MeshForwardEnvelope::sign(
            &key,
            TailscaleNodeId::new("origin"),
            TailscaleNodeId::new("a"),
            0,
            MeshForwardBody::Introspect {
                connector_id: "fcp.test:utility:1.0.0".to_owned(),
            },
        )
        .unwrap();
        let reply = MeshForwardReply::sign(
            &key,
            TailscaleNodeId::new("a"),
            &envelope,
            status,
            "{}".to_owned(),
        );
        let directory = MeshPeerDirectory::from_configs(
            TailscaleNodeId::new("origin"),
            &[MeshPeerConfig {
                node_id: "a".to_owned(),
                endpoint: "http://127.0.0.1:1".to_owned(),
                public_key_hex: hex::encode(key.verifying_key().to_bytes()),
            }],
        )
        .unwrap();
        reply.verify_for(&envelope, &directory).unwrap();
        reply
    }

    #[test]
    fn limits_parse_defaults_and_overrides() {
        assert_eq!(
            MeshForwardLimits::from_lookup(|_| None).unwrap(),
            MeshForwardLimits::default()
        );
        let limits = MeshForwardLimits::from_lookup(|name| match name {
            MESH_FORWARD_MAX_IN_FLIGHT_ENV => Some(" 8 ".to_owned()),
            MESH_FORWARD_MAX_PER_PEER_ENV => Some("2".to_owned()),
            MESH_FORWARD_MAX_REQUEST_BYTES_ENV => Some("4096".to_owned()),
            MeshForwardLimits::RESPONSE_BYTES_ENV => Some((2 * MAX_REPLY_BYTES).to_string()),
            _ => None,
        })
        .unwrap();
        assert_eq!(limits.max_in_flight, 8);
        assert_eq!(limits.max_per_peer, 2);
        assert_eq!(limits.max_request_bytes, 4096);
        assert_eq!(limits.max_response_bytes, 2 * MAX_REPLY_BYTES);
    }

    #[test]
    fn invalid_limits_fail_closed() {
        for name in LIMIT_ENV_KEYS {
            for value in [
                "",
                " ",
                "0",
                "-1",
                "no",
                "999999999999999999999999999999999999",
            ] {
                assert!(
                    MeshForwardLimits::from_lookup(|key| {
                        (key == name).then(|| value.to_owned())
                    })
                    .is_err(),
                    "{name}={value:?}"
                );
            }
        }
        assert!(
            MeshForwardLimits {
                max_in_flight: 1,
                max_per_peer: 2,
                max_request_bytes: 1,
                ..MeshForwardLimits::default()
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn a_busy_peer_cannot_consume_other_peers_capacity() {
        let control = control(2, 1, 100);
        let a = control.reserve("a", 20).unwrap();
        let denied = control.reserve("a", 1).unwrap_err();
        assert!(denied.safe_to_retry());
        assert!(denied.summary().contains("peer_in_flight_limit"));
        let b = control.reserve("b", 30).unwrap();
        assert!(
            control
                .reserve("c", 1)
                .unwrap_err()
                .summary()
                .contains("router_in_flight_limit")
        );
        assert_eq!(control.snapshot().unwrap().request_bytes, 50);
        drop(a);
        let c = control.reserve("c", 1).unwrap();
        assert_eq!(control.snapshot().unwrap().in_flight, 2);
        drop((b, c));
        assert_eq!(control.snapshot().unwrap(), MeshForwardUsage::default());
    }

    #[test]
    fn byte_budget_is_atomic_and_overflow_safe() {
        let control = control(8, 8, usize::MAX);
        let a = control.reserve("a", usize::MAX - 2).unwrap();
        let b = control.reserve("b", 2).unwrap();
        let before = control.snapshot().unwrap();
        assert!(
            control
                .reserve("c", 1)
                .unwrap_err()
                .summary()
                .contains("request_byte_limit")
        );
        assert_eq!(
            control.snapshot().unwrap(),
            before,
            "refusal must not partially reserve"
        );
        drop(a);
        let c = control.reserve("c", usize::MAX - 2).unwrap();
        drop((b, c));
        assert_eq!(control.snapshot().unwrap(), MeshForwardUsage::default());
    }

    #[test]
    fn oversized_single_request_does_not_occupy_a_slot() {
        let control = control(2, 1, 10);
        assert!(control.reserve("a", 11).is_err());
        assert_eq!(control.snapshot().unwrap(), MeshForwardUsage::default());
        assert!(control.reserve("a", 10).is_ok());
    }

    #[test]
    fn refusal_never_constructs_the_transport_future() {
        let control = control(1, 1, 10);
        let _occupied = control.reserve("a", 1).unwrap();
        let called = Cell::new(false);
        let failure = control
            .execute("b", 1, || {
                called.set(true);
                pending()
            })
            .now_or_never()
            .unwrap()
            .unwrap_err();
        assert!(failure.safe_to_retry());
        assert!(!called.get());
    }

    #[test]
    fn cancellation_releases_all_reservations() {
        let control = control(1, 1, 10);
        let mut future = Box::pin(control.execute("a", 10, pending));
        let waker = futures_util::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(future.as_mut().poll(&mut cx).is_pending());
        assert_eq!(control.snapshot().unwrap().request_bytes, 10);
        assert_eq!(
            control.snapshot().unwrap().response_bytes_reserved,
            MAX_REPLY_BYTES
        );
        drop(future);
        assert_eq!(control.snapshot().unwrap(), MeshForwardUsage::default());
        assert!(control.reserve("a", 10).is_ok());
    }

    #[test]
    fn ambiguous_failure_is_preserved_and_capacity_released() {
        let control = control(1, 1, 10);
        let error = MeshForwardFailure::OutcomeUnknown {
            peer: "a".to_owned(),
            detail: "reply lost".to_owned(),
        };
        let result = control
            .execute("a", 10, || async { Err(error.clone()) })
            .now_or_never()
            .unwrap();
        assert_eq!(result.unwrap_err(), error);
        assert!(!error.safe_to_retry());
        assert_eq!(control.snapshot().unwrap(), MeshForwardUsage::default());
    }

    #[test]
    fn panic_in_transport_construction_releases_capacity() {
        let control = control(1, 1, 10);
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = control
                .execute("a", 10, || {
                    panic!("injected construction panic");
                    #[allow(unreachable_code)]
                    pending()
                })
                .now_or_never();
        }));
        assert!(caught.is_err());
        assert_eq!(control.snapshot().unwrap(), MeshForwardUsage::default());
    }

    #[test]
    fn concurrent_admission_never_oversubscribes() {
        let control = control(3, 3, 30);
        let barrier = Barrier::new(16);
        let admitted = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..16 {
                scope.spawn(|| {
                    barrier.wait();
                    let permit = control.reserve("a", 10);
                    if permit.is_ok() {
                        admitted.fetch_add(1, Ordering::SeqCst);
                    }
                    // Keep all successful reservations until every contender
                    // has attempted admission; exactly three can succeed.
                    barrier.wait();
                    drop(permit);
                });
            }
        });
        assert_eq!(admitted.load(Ordering::SeqCst), 3);
        assert_eq!(control.snapshot().unwrap(), MeshForwardUsage::default());
    }

    #[test]
    fn poisoned_state_never_masquerades_as_free_capacity() {
        let control = control(1, 1, 10);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = control.state.lock().unwrap();
            panic!("injected state poison");
        }));
        assert!(control.snapshot().is_err());
        assert!(
            control
                .reserve("a", 1)
                .unwrap_err()
                .summary()
                .contains("state_poisoned")
        );
    }

    #[test]
    fn circuit_refusal_does_not_rewrite_the_failed_request() {
        let control = control(4, 4, 100);
        let now = Instant::now();
        let original = MeshForwardFailure::OutcomeUnknown {
            peer: "a".to_owned(),
            detail: "response disappeared after transmission".to_owned(),
        };
        for _ in 0..3 {
            let error = control
                .execute_with_clock("a", 1, || async { Err(original.clone()) }, || now)
                .now_or_never()
                .unwrap()
                .unwrap_err();
            assert_eq!(error, original);
            assert!(!error.safe_to_retry());
        }
        let called = Cell::new(false);
        let refusal = control
            .execute_with_clock(
                "a",
                1,
                || {
                    called.set(true);
                    pending()
                },
                || now,
            )
            .now_or_never()
            .unwrap()
            .unwrap_err();
        assert!(!called.get());
        assert!(
            refusal.safe_to_retry(),
            "only this later, unsent request can fail over"
        );
        assert!(refusal.summary().contains("peer_circuit_open"));
        assert_eq!(control.snapshot().unwrap(), MeshForwardUsage::default());
    }

    #[test]
    fn invalid_reply_immediately_blocks_later_transmissions() {
        let control = control(1, 1, 100);
        let now = Instant::now();
        let original = MeshForwardFailure::InvalidReply {
            peer: "a".to_owned(),
            error: MeshForwardError::SignatureInvalid {
                what: "reply",
                peer: "a".to_owned(),
            },
        };
        let error = control
            .execute_with_clock("a", 1, || async { Err(original.clone()) }, || now)
            .now_or_never()
            .unwrap()
            .unwrap_err();
        assert_eq!(error, original);
        assert!(!error.safe_to_retry());
        assert!(
            control
                .reserve_at("a", 1, now)
                .unwrap_err()
                .summary()
                .contains("peer_circuit_open")
        );
        assert!(control.reserve_at("b", 1, now).is_ok());
    }

    #[test]
    fn authenticated_executor_error_heals_transport_without_retrying() {
        let control = control(4, 4, 100);
        let now = Instant::now();
        open_peer(&control, "a", now);
        let reply = verified_reply(500);
        let recovered_at = now + Duration::from_secs(5);
        let result = control
            .execute_with_clock("a", 1, || async { Ok(reply.clone()) }, || recovered_at)
            .now_or_never()
            .unwrap()
            .unwrap();
        assert_eq!(
            result, reply,
            "signed operation error must be returned unchanged"
        );
        assert_eq!(control.snapshot().unwrap(), MeshForwardUsage::default());
        assert!(control.reserve_at("a", 1, recovered_at).is_ok());
    }

    #[test]
    fn resource_refusal_cannot_consume_the_recovery_probe() {
        let control = control(2, 1, 100);
        let now = Instant::now();
        open_peer(&control, "a", now);
        let b = control.reserve_at("b", 1, now).unwrap();
        let c = control.reserve_at("c", 1, now).unwrap();
        let retry_at = now + Duration::from_secs(5);
        assert!(control.reserve_at("a", 1, retry_at).is_err());
        drop((b, c));
        let probe = control.reserve_at("a", 1, retry_at).unwrap();
        probe.complete(ForwardOutcome::AuthenticatedReply, retry_at);
        assert!(control.reserve_at("a", 1, retry_at).is_ok());
    }

    #[test]
    fn dropping_a_pending_probe_releases_capacity_and_recovery_ownership() {
        let control = control(1, 1, 100);
        let now = Instant::now();
        open_peer(&control, "a", now);
        let retry_at = now + Duration::from_secs(5);
        let mut future = Box::pin(control.execute_with_clock("a", 1, pending, || retry_at));
        let waker = futures_util::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(future.as_mut().poll(&mut cx).is_pending());
        assert_eq!(control.snapshot().unwrap().in_flight, 1);
        drop(future);
        assert_eq!(control.snapshot().unwrap(), MeshForwardUsage::default());
        // Probe cancellation uses the real drop time; advance from that time
        // rather than depending on wall-clock sleep or executor scheduling.
        assert!(
            control
                .reserve_at("a", 1, Instant::now() + Duration::from_secs(30))
                .is_ok()
        );
    }

    #[test]
    fn stale_completion_releases_resources_without_reopening_traffic() {
        let control = control(4, 4, 100);
        let now = Instant::now();
        let old = control.reserve_at("a", 10, now).unwrap();
        open_peer(&control, "a", now);
        assert_eq!(control.snapshot().unwrap().in_flight, 1);
        old.complete(ForwardOutcome::AuthenticatedReply, now);
        assert_eq!(control.snapshot().unwrap(), MeshForwardUsage::default());
        assert!(control.reserve_at("a", 1, now).is_err());
    }

    #[test]
    fn reply_budget_requires_room_for_one_full_reply() {
        for bytes in [0, 1, MAX_REPLY_BYTES - 1] {
            assert!(
                MeshForwardLimits {
                    max_response_bytes: bytes,
                    ..MeshForwardLimits::default()
                }
                .validate()
                .is_err()
            );
        }
        for bytes in [MAX_REPLY_BYTES, MAX_REPLY_BYTES + 1, usize::MAX] {
            MeshForwardLimits {
                max_response_bytes: bytes,
                ..MeshForwardLimits::default()
            }
            .validate()
            .unwrap();
        }
    }

    #[test]
    fn reply_budget_alone_cannot_silently_select_host_first() {
        assert!(
            crate::mesh_routing::MeshRoutingSettings::from_lookup(|name| {
                (name == MeshForwardLimits::RESPONSE_BYTES_ENV).then(|| MAX_REPLY_BYTES.to_string())
            })
            .is_err()
        );
    }

    #[test]
    fn reply_headroom_is_reserved_before_constructing_transport() {
        let control = ForwardControl::new(MeshForwardLimits {
            // A partial additional reply allowance cannot authorize a send.
            max_response_bytes: 2 * MAX_REPLY_BYTES - 1,
            ..MeshForwardLimits::default()
        })
        .unwrap();
        let first = control.reserve("a", 1).unwrap();
        let before = control.snapshot().unwrap();
        assert_eq!(before.response_bytes_reserved, MAX_REPLY_BYTES);
        let called = Cell::new(false);
        let error = control
            .execute("b", 1, || {
                called.set(true);
                pending()
            })
            .now_or_never()
            .unwrap()
            .unwrap_err();
        assert!(!called.get());
        assert!(error.safe_to_retry());
        assert!(error.summary().contains("response_byte_limit"));
        assert_eq!(control.snapshot().unwrap(), before);
        drop(first);
        let recovered = control.reserve("b", 1).unwrap();
        drop(recovered);
        assert_eq!(control.snapshot().unwrap(), MeshForwardUsage::default());
    }

    #[test]
    fn reply_budget_cannot_consume_or_poison_a_recovery_probe() {
        let control = ForwardControl::new(MeshForwardLimits {
            max_response_bytes: MAX_REPLY_BYTES,
            ..MeshForwardLimits::default()
        })
        .unwrap();
        let now = Instant::now();
        open_peer(&control, "a", now);
        let occupied = control.reserve_at("b", 1, now).unwrap();
        let retry_at = now + Duration::from_secs(5);
        for _ in 0..4 {
            let error = control.reserve_at("a", 1, retry_at).unwrap_err();
            assert!(error.summary().contains("response_byte_limit"));
        }
        drop(occupied);
        let probe = control.reserve_at("a", 1, retry_at).unwrap();
        probe.complete(ForwardOutcome::AuthenticatedReply, retry_at);
        assert!(control.reserve_at("a", 1, retry_at).is_ok());
    }

    #[test]
    fn concurrent_reply_reservations_never_oversubscribe() {
        let control = ForwardControl::new(MeshForwardLimits {
            max_in_flight: 16,
            max_per_peer: 16,
            max_response_bytes: 3 * MAX_REPLY_BYTES,
            ..MeshForwardLimits::default()
        })
        .unwrap();
        let barrier = Barrier::new(16);
        let admitted = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..16 {
                scope.spawn(|| {
                    barrier.wait();
                    let permit = control.reserve("a", 1);
                    if permit.is_ok() {
                        admitted.fetch_add(1, Ordering::SeqCst);
                    }
                    barrier.wait();
                    drop(permit);
                });
            }
        });
        assert_eq!(admitted.load(Ordering::SeqCst), 3);
        assert_eq!(control.snapshot().unwrap(), MeshForwardUsage::default());
    }

    #[test]
    fn reply_budget_remainder_check_cannot_overflow() {
        let control = ForwardControl::new(MeshForwardLimits {
            max_response_bytes: usize::MAX,
            ..MeshForwardLimits::default()
        })
        .unwrap();
        // Exercise the arithmetic boundary without creating billions of jobs.
        control.state.lock().unwrap().usage.response_bytes_reserved = usize::MAX - MAX_REPLY_BYTES;
        let permit = control.reserve("a", 1).unwrap();
        assert_eq!(
            control.snapshot().unwrap().response_bytes_reserved,
            usize::MAX
        );
        let before = control.snapshot().unwrap();
        assert!(
            control
                .reserve("b", 1)
                .unwrap_err()
                .summary()
                .contains("response_byte_limit")
        );
        assert_eq!(control.snapshot().unwrap(), before);
        drop(permit);
        assert_eq!(
            control.snapshot().unwrap().response_bytes_reserved,
            usize::MAX - MAX_REPLY_BYTES
        );
    }
}
